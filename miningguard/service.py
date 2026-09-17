"""Ingest pipeline and detection lifecycle.

The collector is deliberately dumb: it measures, it does not judge. Scoring
happens here so rules and indicators can change centrally without
redeploying agents.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import rules
from .config import Settings, settings as default_settings
from .models import Alert, Detection, Host, NetworkEvent, PersistenceItem, Process, utcnow
from .rules import (
    ALERT_THRESHOLD,
    Assessment,
    ConnectionObservation,
    HostObservation,
    PersistenceObservation,
    ProcessObservation,
)
from .schemas import SnapshotIn

# An open detection whose evidence has not been re-observed for this long is
# closed automatically, which keeps the queue from filling with stale findings.
STALE_DETECTION_SECONDS = 900.0

# A host that has not reported within this window is shown as offline.
OFFLINE_AFTER_SECONDS = 180.0

_last_prune = 0.0
_PRUNE_INTERVAL = 3600.0


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def upsert_host(session: Session, payload: SnapshotIn) -> Host:
    host = session.scalar(select(Host).where(Host.hostname == payload.host.hostname))
    if host is None:
        host = Host(hostname=payload.host.hostname)
        session.add(host)

    host.os = payload.host.os or host.os
    host.os_version = payload.host.os_version or host.os_version
    host.ip_address = payload.host.ip_address or host.ip_address
    host.cpu_count = payload.host.cpu_count or host.cpu_count
    host.agent_version = payload.host.agent_version or host.agent_version
    host.last_seen = utcnow()
    session.flush()
    return host


def _store_processes(session: Session, host: Host, payload: SnapshotIn) -> dict[int, Process]:
    stored: dict[int, Process] = {}
    for item in payload.processes:
        row = Process(host_id=host.id, **item.model_dump())
        session.add(row)
        stored[item.pid] = row
    session.flush()
    return stored


def _store_connections(
    session: Session, host: Host, payload: SnapshotIn, processes: dict[int, Process]
) -> int:
    for item in payload.connections:
        data = item.model_dump()
        process = processes.get(item.pid)
        session.add(
            NetworkEvent(
                host_id=host.id,
                process_id=process.id if process else None,
                **data,
            )
        )
    session.flush()
    return len(payload.connections)


def _store_persistence(session: Session, host: Host, payload: SnapshotIn) -> int:
    if not payload.persistence:
        return 0
    # Persistence is current state rather than an event stream, so the host's
    # entries are replaced wholesale on each report that includes them.
    session.execute(delete(PersistenceItem).where(PersistenceItem.host_id == host.id))
    for item in payload.persistence:
        session.add(PersistenceItem(host_id=host.id, **item.model_dump()))
    session.flush()
    return len(payload.persistence)


def build_observation(payload: SnapshotIn) -> HostObservation:
    connections_by_pid: dict[int, list[ConnectionObservation]] = {}
    for conn in payload.connections:
        observation = ConnectionObservation(
            destination_ip=conn.destination_ip,
            destination_domain=conn.destination_domain,
            destination_port=conn.destination_port,
            protocol=conn.protocol,
            status=conn.status,
            duration_seconds=conn.duration_seconds,
            connection_count=conn.connection_count,
        )
        connections_by_pid.setdefault(conn.pid, []).append(observation)

    processes = [
        ProcessObservation(
            pid=proc.pid,
            name=proc.name,
            path=proc.path,
            command_line=proc.command_line,
            username=proc.username,
            parent_pid=proc.parent_pid,
            parent_name=proc.parent_name,
            cpu_usage=proc.cpu_usage,
            cpu_average=proc.cpu_average,
            cpu_sustained_seconds=proc.cpu_sustained_seconds,
            memory_usage=proc.memory_usage,
            memory_rss_mb=proc.memory_rss_mb,
            gpu_usage=proc.gpu_usage,
            thread_count=proc.thread_count,
            lifetime_seconds=proc.lifetime_seconds,
            is_browser_renderer=proc.is_browser_renderer,
            connections=connections_by_pid.get(proc.pid, []),
        )
        for proc in payload.processes
    ]

    return HostObservation(
        hostname=payload.host.hostname,
        os=payload.host.os,
        processes=processes,
        persistence=[
            PersistenceObservation(
                mechanism=item.mechanism,
                name=item.name,
                target_path=item.target_path,
                command=item.command,
                source=item.source,
                enabled=item.enabled,
            )
            for item in payload.persistence
        ],
        dns_queries=list(payload.dns_queries),
    )


def _record_detection(
    session: Session,
    host: Host,
    assessment: Assessment,
    processes: dict[int, Process],
) -> Detection:
    process_row = processes.get(assessment.process.pid) if assessment.process else None
    subject = (
        assessment.process.name
        if assessment.process and assessment.process.name
        else assessment.signals[0].detail[:120] if assessment.signals else ""
    )

    existing = session.scalar(
        select(Detection)
        .where(
            Detection.host_id == host.id,
            Detection.fingerprint == assessment.fingerprint,
            Detection.status == "open",
        )
        .order_by(Detection.created_at.desc())
    )

    if existing is not None:
        existing.risk_score = assessment.risk_score
        existing.severity = assessment.severity
        existing.reason = assessment.reason
        existing.signals = [s.as_dict() for s in assessment.signals]
        existing.detection_type = assessment.detection_type
        existing.observation_count += 1
        existing.updated_at = utcnow()
        if process_row is not None:
            existing.process_id = process_row.id
            existing.process_name = process_row.name
        session.flush()
        return existing

    detection = Detection(
        host_id=host.id,
        process_id=process_row.id if process_row else None,
        process_name=subject,
        risk_score=assessment.risk_score,
        severity=assessment.severity,
        detection_type=assessment.detection_type,
        reason=assessment.reason,
        signals=[s.as_dict() for s in assessment.signals],
        fingerprint=assessment.fingerprint,
        status="open",
    )
    session.add(detection)
    session.flush()

    session.add(Alert(detection_id=detection.id, status="new"))
    session.flush()
    return detection


def _resolve_stale_detections(session: Session, host: Host, live_fingerprints: set[str]) -> int:
    open_detections = session.scalars(
        select(Detection).where(Detection.host_id == host.id, Detection.status == "open")
    ).all()

    now = utcnow()
    resolved = 0
    for detection in open_detections:
        if detection.fingerprint in live_fingerprints:
            continue
        updated = _aware(detection.updated_at) or now
        if (now - updated).total_seconds() < STALE_DETECTION_SECONDS:
            continue

        detection.status = "resolved"
        detection.updated_at = now
        for alert in detection.alerts:
            if alert.status in {"closed", "false_positive"}:
                continue
            alert.status = "closed"
            alert.closed_at = now
            alert.resolution = alert.resolution or "Auto-closed: indicators no longer observed."
        resolved += 1
    return resolved


def refresh_host_risk(session: Session, host: Host) -> None:
    worst = session.scalar(
        select(func.max(Detection.risk_score)).where(
            Detection.host_id == host.id, Detection.status == "open"
        )
    )
    host.risk_score = int(worst or 0)
    host.severity = rules.severity_for(host.risk_score)
    session.flush()


def prune_old_events(session: Session, cfg: Settings | None = None, *, force: bool = False) -> None:
    """Drop raw telemetry beyond the retention window.

    Detections and alerts are kept; only the high-volume process and network
    rows are pruned.
    """
    global _last_prune
    cfg = cfg or default_settings
    now = time.monotonic()
    if not force and _last_prune and now - _last_prune < _PRUNE_INTERVAL:
        return
    _last_prune = now

    cutoff = utcnow() - timedelta(days=max(1, cfg.retention_days))
    session.execute(delete(NetworkEvent).where(NetworkEvent.timestamp < cutoff))
    session.execute(
        delete(Process).where(
            Process.timestamp < cutoff,
            ~Process.id.in_(select(Detection.process_id).where(Detection.process_id.is_not(None))),
        )
    )


def ingest_snapshot(session: Session, payload: SnapshotIn, cfg: Settings | None = None) -> dict:
    cfg = cfg or default_settings

    host = upsert_host(session, payload)
    processes = _store_processes(session, host, payload)
    connections_stored = _store_connections(session, host, payload, processes)
    persistence_stored = _store_persistence(session, host, payload)

    observation = build_observation(payload)
    assessments = rules.evaluate_host(observation, cfg)

    recorded: list[Detection] = []
    suppressed: list[str] = []
    live_fingerprints: set[str] = set()

    for assessment in assessments:
        if assessment.risk_score >= ALERT_THRESHOLD:
            live_fingerprints.add(assessment.fingerprint)
            recorded.append(_record_detection(session, host, assessment, processes))
        elif assessment.withheld:
            subject = assessment.process.name if assessment.process else "host"
            suppressed.append(
                f"{subject}: high resource usage without corroborating evidence "
                f"({assessment.withheld_reason}, held at {assessment.risk_score})"
            )

    _resolve_stale_detections(session, host, live_fingerprints)
    refresh_host_risk(session, host)
    prune_old_events(session, cfg)
    session.commit()

    return {
        "host_id": host.id,
        "hostname": host.hostname,
        "host_risk_score": host.risk_score,
        "host_severity": host.severity,
        "processes_stored": len(processes),
        "connections_stored": connections_stored,
        "persistence_stored": persistence_stored,
        "detections": recorded,
        "suppressed": suppressed[:10],
    }


def host_is_online(host: Host, now: datetime | None = None) -> bool:
    now = now or utcnow()
    last_seen = _aware(host.last_seen)
    if last_seen is None:
        return False
    return (now - last_seen).total_seconds() <= OFFLINE_AFTER_SECONDS


