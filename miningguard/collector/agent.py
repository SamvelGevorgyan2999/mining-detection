"""Collector agent: builds host snapshots and ships them to the API."""

from __future__ import annotations

import platform
import socket
import time
from dataclasses import dataclass

import httpx  # type: ignore[import-not-found]
import psutil


from .. import intel
from ..config import Settings, settings as default_settings
from . import gpu
from .network import NetworkSampler, collect_dns_cache
from .persistence import collect_persistence
from .processes import ProcessSampler, select_reportable

AGENT_VERSION = "1.0.0"

# Persistence and the DNS cache are comparatively expensive to enumerate and
# rarely change between polls.
_SLOW_COLLECTION_INTERVAL = 300.0


def local_ip_address() -> str:
    """Best-effort primary IPv4 address without sending traffic."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            sock.connect(("198.51.100.1", 9))  # Reserved TEST-NET-2, never routed.
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


@dataclass
class HostFacts:
    hostname: str
    os: str
    os_version: str
    ip_address: str
    cpu_count: int
    agent_version: str = AGENT_VERSION

    @classmethod
    def detect(cls) -> "HostFacts":
        return cls(
            hostname=socket.gethostname(),
            os=platform.system(),
            os_version=platform.platform(),
            ip_address=local_ip_address(),
            cpu_count=psutil.cpu_count(logical=True) or 0,
        )

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "os": self.os,
            "os_version": self.os_version,
            "ip_address": self.ip_address,
            "cpu_count": self.cpu_count,
            "agent_version": self.agent_version,
        }


class Collector:
    """Owns the stateful samplers and produces snapshot payloads."""

    def __init__(self, cfg: Settings | None = None) -> None:
        self.cfg = cfg or default_settings
        self.facts = HostFacts.detect()
        self.processes = ProcessSampler(self.cfg)
        self.network = NetworkSampler(self.cfg)
        self._persistence: list[dict] = []
        self._dns: list[str] = []
        self._slow_collected_at = 0.0
        intel.load_feed(self.cfg.feed_path)

    def prime(self) -> None:
        self.processes.prime()

    def _refresh_slow_sources(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and self._slow_collected_at and now - self._slow_collected_at < _SLOW_COLLECTION_INTERVAL:
            return
        self._persistence = collect_persistence()
        self._dns = collect_dns_cache()
        self._slow_collected_at = now

    def snapshot(self) -> dict:
        self._refresh_slow_sources()

        processes = self.processes.sample()
        if self.cfg.gpu_sampling:
            gpu_usage = gpu.sample_gpu_usage()
            if gpu_usage:
                for proc in processes:
                    proc["gpu_usage"] = gpu_usage.get(proc["pid"], 0.0)

        connections = self.network.sample()
        reportable = select_reportable(processes, self.cfg.collector_top_processes, self.cfg)

        # Keep any process that owns a connection, so network evidence always
        # has a process to attach to.
        kept_pids = {proc["pid"] for proc in reportable}
        connection_pids = {conn["pid"] for conn in connections if conn["pid"]}
        for proc in processes:
            if proc["pid"] in connection_pids and proc["pid"] not in kept_pids:
                reportable.append(proc)
                kept_pids.add(proc["pid"])

        # Memory, thread counts and identity checks are only worth paying for
        # on the processes actually being reported.
        reportable = self.processes.enrich(reportable)

        domains = sorted(
            set(self._dns)
            | set(self.network.observed_domains())
            | {c["destination_domain"] for c in connections if c["destination_domain"]}
        )

        return {
            "host": self.facts.as_dict(),
            "processes": reportable,
            "connections": connections,
            "persistence": self._persistence,
            "dns_queries": domains,
            "collected_at": time.time(),
        }

    def snapshot_once(self, settle_seconds: float = 2.0) -> dict:
        """One-shot snapshot for CLI scans, where no history exists yet."""
        self.prime()
        self.network.sample()  # Queues reverse lookups for the endpoints in use.
        time.sleep(max(0.5, settle_seconds))
        self.network.await_resolution(timeout=min(5.0, max(1.0, settle_seconds)))
        self._refresh_slow_sources(force=True)
        return self.snapshot()


def _headers(cfg: Settings) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if cfg.api_token:
        headers["authorization"] = f"Bearer {cfg.api_token}"
    return headers


def post_snapshot(payload: dict, cfg: Settings | None = None, client: httpx.Client | None = None) -> dict:
    cfg = cfg or default_settings
    url = f"{cfg.api_url.rstrip('/')}/api/v1/ingest"
    owned = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        response = http.post(url, json=payload, headers=_headers(cfg))
        response.raise_for_status()
        return response.json()
    finally:
        if owned:
            http.close()


def run_forever(cfg: Settings | None = None, *, max_iterations: int | None = None) -> None:
    """Collect and ship snapshots on an interval until interrupted."""
    cfg = cfg or default_settings
    collector = Collector(cfg)
    collector.prime()
    collector.network.sample()

    print(f"MiningGuard collector {AGENT_VERSION} on {collector.facts.hostname}")
    print(f"Reporting to {cfg.api_url} every {cfg.collector_interval:.0f}s")

    iteration = 0
    with httpx.Client(timeout=30.0) as client:
        while max_iterations is None or iteration < max_iterations:
            iteration += 1
            time.sleep(cfg.collector_interval)
            try:
                payload = collector.snapshot()
            except Exception as exc:  # A sampling failure must not kill the agent.
                print(f"[collector] snapshot failed: {exc}")
                continue

            try:
                result = post_snapshot(payload, cfg, client=client)
            except httpx.HTTPError as exc:
                print(f"[collector] upload failed: {exc}")
                continue

            severity = result.get("host_severity", "NORMAL")
            score = result.get("host_risk_score", 0)
            findings = result.get("detections", [])
            summary = f"{len(payload['processes'])} processes, {len(payload['connections'])} connections"
            print(f"[collector] {summary} -> risk {score} ({severity}), {len(findings)} finding(s)")


