"""Risk-scoring rule engine.

The engine turns a host snapshot into scored findings. Two properties matter
more than the individual rules:

1. Signals are additive and each one is attributable, so an analyst can see
   exactly which evidence produced a score.
2. Resource usage can never convict on its own. High CPU is the cheapest and
   noisiest signal available, so a finding backed only by CPU/GPU evidence is
   capped inside the NORMAL band regardless of how many resource rules fire.
   Mining verdicts require corroboration from a different evidence class.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import intel
from .config import Settings, settings as default_settings

RESOURCE = "resource"
IDENTITY = "identity"
NETWORK = "network"
PERSISTENCE = "persistence"
COMMAND_LINE = "command_line"
DNS = "dns"
BROWSER = "browser"
MITIGATION = "mitigation"

# Evidence classes that can corroborate a resource signal.
CORROBORATING_CATEGORIES: frozenset[str] = frozenset(
    {IDENTITY, NETWORK, PERSISTENCE, COMMAND_LINE, DNS, BROWSER}
)

# Ceiling applied when only resource evidence is present.
UNCORROBORATED_CEILING = 24

# Scores at or above this become a persisted detection with an alert.
ALERT_THRESHOLD = 25

RULE_POINTS: dict[str, int] = {
    "sustained_cpu": 20,
    "elevated_cpu": 10,
    "sustained_gpu": 15,
    "unknown_executable": 20,
    "known_miner_binary": 30,
    "masquerading_name": 15,
    "mining_infrastructure": 25,
    "stratum_port": 15,
    "long_lived_connection": 10,
    "repeated_connections": 10,
    "suspicious_persistence": 15,
    "unusual_command_line": 10,
    "suspicious_dns": 10,
    "browser_cryptojacking": 20,
    "allowlisted_workload": -25,
    "trusted_system_path": -10,
}

SEVERITY_BANDS: tuple[tuple[int, str], ...] = (
    (90, "CRITICAL"),
    (75, "HIGH"),
    (50, "MEDIUM"),
    (25, "LOW"),
    (0, "NORMAL"),
)

# Ports where a long-lived outbound connection is entirely unremarkable.
COMMON_SERVICE_PORTS: frozenset[int] = frozenset(
    {22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853, 993, 995,
     1935, 3128, 3478, 5222, 5228, 5349, 8080, 8443, 9443}
)

# System binary names worth impersonating. Flagged only outside trusted paths.
MASQUERADE_NAMES: frozenset[str] = frozenset(
    {"svchost", "services", "lsass", "csrss", "winlogon", "explorer", "taskhostw",
     "dwm", "conhost", "spoolsv", "wininit", "smss", "rundll32", "wuauclt",
     "systemd", "systemd-journald", "kworker", "kthreadd", "sshd", "cron",
     "crond", "dbus-daemon", "udevd", "rsyslogd", "nginx", "apache2", "httpd",
     "chrome", "firefox", "msedge", "update", "updater", "system_service",
     "system", "kernel", "init", "networkmanager", "docker"}
)


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def severity_for(score: int) -> str:
    for floor, label in SEVERITY_BANDS:
        if score >= floor:
            return label
    return "NORMAL"

@dataclass
class Signal:
    rule_id: str
    category: str
    points: int
    title: str
    detail: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "points": self.points,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass
class ConnectionObservation:
    destination_ip: str = ""
    destination_domain: str = ""
    destination_port: int = 0
    protocol: str = "tcp"
    status: str = ""
    duration_seconds: float = 0.0
    connection_count: int = 1

    @property
    def endpoint(self) -> str:
        host = self.destination_domain or self.destination_ip or "unknown"
        return f"{host}:{self.destination_port}" if self.destination_port else host


@dataclass
class PersistenceObservation:
    mechanism: str = ""
    name: str = ""
    target_path: str = ""
    command: str = ""
    source: str = ""
    enabled: bool = True

    @property
    def haystack(self) -> str:
        return f"{self.name} {self.target_path} {self.command} {self.source}".lower()


@dataclass
class ProcessObservation:
    pid: int = 0
    name: str = ""
    path: str = ""
    command_line: str = ""
    username: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    cpu_usage: float = 0.0
    cpu_average: float = 0.0
    cpu_sustained_seconds: float = 0.0
    memory_usage: float = 0.0
    memory_rss_mb: float = 0.0
    gpu_usage: float = 0.0
    thread_count: int = 0
    lifetime_seconds: float = 0.0
    is_browser_renderer: bool = False
    connections: list[ConnectionObservation] = field(default_factory=list)


@dataclass
class HostObservation:
    hostname: str = ""
    os: str = ""
    processes: list[ProcessObservation] = field(default_factory=list)
    persistence: list[PersistenceObservation] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)


@dataclass
class Assessment:
    risk_score: int
    severity: str
    reason: str
    detection_type: str
    signals: list[Signal]
    fingerprint: str
    process: ProcessObservation | None = None
    corroborated: bool = False
    # True when the corroboration ceiling actually reduced the score.
    capped: bool = False
    # True when resource evidence was present but the finding is not alertable,
    # whether that was the ceiling or a mitigating signal. These are surfaced to
    # the operator so a deliberate non-alert is visible rather than silent.
    withheld: bool = False
    withheld_reason: str = ""

    @property
    def is_alertable(self) -> bool:
        return self.risk_score >= ALERT_THRESHOLD


def _fingerprint(*parts: str) -> str:
    digest = hashlib.sha1("|".join(p.lower() for p in parts if p).encode("utf-8"))
    return digest.hexdigest()[:16]


def _finalize(
    signals: list[Signal],
    *,
    detection_type: str,
    subject: str,
    hostname: str,
    process: ProcessObservation | None,
) -> Assessment:
    raw = sum(s.points for s in signals)
    categories = {s.category for s in signals if s.points > 0}
    corroborated = bool(categories & CORROBORATING_CATEGORIES)

    score = _clamp(raw)
    capped = False
    if not corroborated and score > UNCORROBORATED_CEILING:
        # Resource pressure without corroborating evidence is a capacity
        # problem, not a security finding.
        score = UNCORROBORATED_CEILING
        capped = True

    score_int = int(round(score))
    severity = severity_for(score_int)
    rule_ids = sorted(s.rule_id for s in signals if s.points > 0)

    resource_positive = any(s.category == RESOURCE and s.points > 0 for s in signals)
    allowlisted = any(s.rule_id == "allowlisted_workload" for s in signals)
    withheld = resource_positive and score_int < ALERT_THRESHOLD
    if not withheld:
        withheld_reason = ""
    elif allowlisted:
        withheld_reason = "known CPU-intensive application"
    elif capped:
        withheld_reason = "corroborating evidence required"
    else:
        withheld_reason = "below alerting threshold"

    return Assessment(
        risk_score=score_int,
        severity=severity,
        reason=_build_reason(
            signals, severity, detection_type, subject, capped, corroborated, allowlisted
        ),
        detection_type=detection_type,
        signals=sorted(signals, key=lambda s: -s.points),
        fingerprint=_fingerprint(hostname, subject, detection_type, *rule_ids),
        process=process,
        corroborated=corroborated,
        capped=capped,
        withheld=withheld,
        withheld_reason=withheld_reason,
    )


def _build_reason(
    signals: list[Signal],
    severity: str,
    detection_type: str,
    subject: str,
    capped: bool,
    corroborated: bool,
    allowlisted: bool = False,
) -> str:
    positives = [s for s in signals if s.points > 0]
    if not positives:
        return f"No mining indicators for {subject}."

    evidence = "; ".join(f"{s.title} ({s.detail})" for s in sorted(positives, key=lambda s: -s.points)[:4])

    if not corroborated and allowlisted:
        return (
            f"{subject} is a known CPU-intensive application, so heavy usage is expected "
            f"and no corroborating mining evidence was found. Evidence: {evidence}."
        )

    if capped or not corroborated:
        return (
            f"{subject} shows heavy resource usage with no corroborating mining evidence. "
            f"Held at {severity} pending a network, identity or persistence signal. Evidence: {evidence}."
        )

    if detection_type == "browser_cryptojacking":
        headline = f"Potential browser cryptojacking in {subject}"
    elif detection_type == "persistence_mining":
        headline = f"Dormant mining persistence entry referencing {subject}"
    else:
        headline = f"Potential cryptocurrency mining by {subject}"
    return f"{headline}. Evidence: {evidence}."


def _network_signals(
    connections: list[ConnectionObservation],
    cfg: Settings,
    *,
    browser_context: bool = False,
) -> list[Signal]:
    signals: list[Signal] = []
    pool_hits: list[str] = []
    cryptojacking_hits: list[str] = []
    feed_hits: list[str] = []
    stratum_hits: list[str] = []
    long_lived: list[str] = []
    repeated: list[str] = []

    for conn in connections:
        domain = conn.destination_domain
        pool = intel.match_mining_domain(domain)
        if pool:
            pool_hits.append(f"{conn.endpoint} matches {pool}")
        cryptojacking = intel.match_cryptojacking_domain(domain)
        if cryptojacking:
            cryptojacking_hits.append(f"{conn.endpoint} matches {cryptojacking}")
        bad_ip = intel.match_bad_ip(conn.destination_ip)
        if bad_ip:
            feed_hits.append(f"{conn.destination_ip} listed in feed ({bad_ip})")
        keyword = intel.match_mining_keyword(domain)
        if keyword and not pool and not cryptojacking:
            feed_hits.append(f"{conn.endpoint} contains '{keyword}'")

        routable = intel.is_routable(conn.destination_ip) or bool(domain)
        if routable and intel.is_stratum_port(conn.destination_port):
            stratum_hits.append(conn.endpoint)
        if (
            routable
            and conn.destination_port not in COMMON_SERVICE_PORTS
            and conn.duration_seconds >= cfg.long_lived_connection_seconds
        ):
            long_lived.append(f"{conn.endpoint} open {conn.duration_seconds / 60:.0f} min")
        if (
            routable
            and conn.destination_port not in COMMON_SERVICE_PORTS
            and conn.connection_count >= 4
        ):
            repeated.append(f"{conn.endpoint} x{conn.connection_count}")

    if pool_hits or feed_hits:
        detail = "; ".join((pool_hits + feed_hits)[:3])
        signals.append(
            Signal(
                "mining_infrastructure",
                NETWORK,
                RULE_POINTS["mining_infrastructure"],
                "Connection to known mining infrastructure",
                detail,
            )
        )
    if cryptojacking_hits and not browser_context:
        signals.append(
            Signal(
                "mining_infrastructure",
                NETWORK,
                RULE_POINTS["mining_infrastructure"],
                "Connection to in-browser mining service",
                "; ".join(cryptojacking_hits[:3]),
            )
        )
    if stratum_hits:
        signals.append(
            Signal(
                "stratum_port",
                NETWORK,
                RULE_POINTS["stratum_port"],
                "Outbound traffic on a stratum mining port",
                "; ".join(sorted(set(stratum_hits))[:3]),
            )
        )
    if long_lived:
        signals.append(
            Signal(
                "long_lived_connection",
                NETWORK,
                RULE_POINTS["long_lived_connection"],
                "Long-lived outbound connection on an unusual port",
                "; ".join(long_lived[:3]),
            )
        )
    if repeated:
        signals.append(
            Signal(
                "repeated_connections",
                NETWORK,
                RULE_POINTS["repeated_connections"],
                "Repeated connections to the same endpoint",
                "; ".join(repeated[:3]),
            )
        )
    return signals


def _dns_signals(domains: list[str]) -> list[Signal]:
    cryptojacking: list[str] = []
    pools: list[str] = []
    generated: list[str] = []

    for domain in domains:
        if intel.match_cryptojacking_domain(domain):
            cryptojacking.append(domain)
        elif intel.match_mining_domain(domain):
            pools.append(domain)
        elif intel.looks_like_dga(domain):
            generated.append(domain)

    findings = cryptojacking + pools
    notes: list[str] = []
    if findings:
        notes.append("resolved mining domains: " + ", ".join(sorted(set(findings))[:3]))
    if generated:
        notes.append("algorithmically generated names: " + ", ".join(sorted(set(generated))[:3]))
    if not notes:
        return []
    return [
        Signal(
            "suspicious_dns",
            DNS,
            RULE_POINTS["suspicious_dns"],
            "Suspicious DNS resolution behaviour",
            "; ".join(notes),
        )
    ]


def _identity_signals(process: ProcessObservation) -> list[Signal]:
    signals: list[Signal] = []
    trust = intel.path_trust(process.path)

    signature = intel.matches_miner_binary(process.name, process.path)
    if signature:
        signals.append(
            Signal(
                "known_miner_binary",
                IDENTITY,
                RULE_POINTS["known_miner_binary"],
                "Executable matches a known miner",
                f"'{process.name}' matches signature '{signature}'",
            )
        )

    if trust == "suspicious":
        signals.append(
            Signal(
                "unknown_executable",
                IDENTITY,
                RULE_POINTS["unknown_executable"],
                "Executable runs from a suspicious location",
                process.path or "path unavailable",
            )
        )
    elif trust == "unknown":
        signals.append(
            Signal(
                "unknown_executable",
                IDENTITY,
                # An unrecognised-but-not-hostile path is weaker evidence.
                RULE_POINTS["unknown_executable"] // 2,
                "Executable is not in a known-good location",
                process.path or "path unavailable",
            )
        )
    else:
        signals.append(
            Signal(
                "trusted_system_path",
                MITIGATION,
                RULE_POINTS["trusted_system_path"],
                "Executable resides in a trusted system path",
                process.path,
            )
        )

    stem = intel.binary_stem(process.name)
    if stem in MASQUERADE_NAMES and trust != "trusted":
        signals.append(
            Signal(
                "masquerading_name",
                IDENTITY,
                RULE_POINTS["masquerading_name"],
                "System-like process name outside a trusted path",
                f"'{process.name}' running from {process.path or 'unknown path'}",
            )
        )

    if intel.is_legitimate_heavy_workload(process.name, process.path):
        signals.append(
            Signal(
                "allowlisted_workload",
                MITIGATION,
                RULE_POINTS["allowlisted_workload"],
                "Known CPU-intensive application",
                f"'{stem}' is expected to consume sustained CPU",
            )
        )
    return signals


def _resource_signals(process: ProcessObservation, cfg: Settings) -> list[Signal]:
    signals: list[Signal] = []
    cpu = max(process.cpu_usage, process.cpu_average)

    if cpu >= cfg.sustained_cpu_percent and process.cpu_sustained_seconds >= cfg.sustained_cpu_seconds:
        signals.append(
            Signal(
                "sustained_cpu",
                RESOURCE,
                RULE_POINTS["sustained_cpu"],
                "Sustained high CPU usage",
                f"{cpu:.0f}% for {process.cpu_sustained_seconds / 60:.0f} min",
            )
        )
    elif cpu >= cfg.elevated_cpu_percent and process.cpu_sustained_seconds >= cfg.sustained_cpu_seconds / 2:
        signals.append(
            Signal(
                "elevated_cpu",
                RESOURCE,
                RULE_POINTS["elevated_cpu"],
                "Elevated CPU usage over time",
                f"{cpu:.0f}% for {process.cpu_sustained_seconds / 60:.0f} min",
            )
        )

    if process.gpu_usage >= cfg.sustained_gpu_percent:
        signals.append(
            Signal(
                "sustained_gpu",
                RESOURCE,
                RULE_POINTS["sustained_gpu"],
                "Sustained high GPU usage",
                f"{process.gpu_usage:.0f}% GPU utilisation",
            )
        )
    return signals


def _command_line_signals(process: ProcessObservation) -> list[Signal]:
    hits = intel.match_command_line(process.command_line)
    if not hits:
        return []
    return [
        Signal(
            "unusual_command_line",
            COMMAND_LINE,
            RULE_POINTS["unusual_command_line"],
            "Command line contains mining arguments",
            ", ".join(hits[:4]),
        )
    ]


def _persistence_is_suspicious(item: PersistenceObservation) -> str:
    if intel.matches_miner_binary(item.name, item.target_path or item.command):
        return "references a known miner binary"
    if intel.path_trust(item.target_path) == "suspicious":
        return f"launches from a suspicious path ({item.target_path})"
    hits = intel.match_command_line(item.command)
    if hits:
        return "command line contains mining arguments: " + ", ".join(hits[:3])
    return ""


def _normalize_path(value: str | None) -> str:
    return (value or "").strip().strip('"').lower().replace("\\", "/")


def _first_token(command: str | None) -> str:
    text = (command or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        closing = text.find('"', 1)
        return text[1:closing] if closing > 0 else text[1:]
    return text.split(maxsplit=1)[0]


def _persistence_links_to(process: ProcessObservation, item: PersistenceObservation) -> bool:
    """Decide whether an autostart entry actually launches this process.

    Matching the process name as a bare substring is far too loose: a process
    called ``System`` would claim every entry whose path contains "System32".
    A link therefore requires either the full executable path or an exact
    match on the autostart target's own filename.
    """
    process_path = _normalize_path(process.path)
    if process_path:
        blob = _normalize_path(f"{item.target_path} {item.command} {item.source}")
        if process_path in blob:
            return True

    stem = intel.binary_stem(process.name)
    if not stem or len(stem) < 4:
        return False
    target_stem = intel.binary_stem(item.target_path) or intel.binary_stem(_first_token(item.command))
    return bool(target_stem) and stem == target_stem


def _persistence_signals(
    process: ProcessObservation, persistence: list[PersistenceObservation]
) -> list[Signal]:
    matches: list[str] = []

    for item in persistence:
        if not item.enabled or not _persistence_links_to(process, item):
            continue
        note = _persistence_is_suspicious(item) or "autostart entry for a flagged process"
        matches.append(f"{item.mechanism}: {item.name} ({note})")

    if not matches:
        return []
    return [
        Signal(
            "suspicious_persistence",
            PERSISTENCE,
            RULE_POINTS["suspicious_persistence"],
            "Process survives reboot via an autostart mechanism",
            "; ".join(matches[:3]),
        )
    ]


def _browser_connection_pool(host: HostObservation) -> list[ConnectionObservation]:
    """Connections seen anywhere in a browser process tree.

    Chromium funnels sockets through its network service, so a renderer that
    is mining usually has no sockets of its own. Pooling browser-family
    connections keeps the domain evidence attached to the tab.
    """
    pool: list[ConnectionObservation] = []
    for process in host.processes:
        if intel.is_browser(process.name):
            pool.extend(process.connections)
    return pool


def evaluate_process(
    process: ProcessObservation,
    host: HostObservation,
    cfg: Settings | None = None,
    *,
    browser_pool: list[ConnectionObservation] | None = None,
) -> Assessment:
    cfg = cfg or default_settings
    subject = process.name or f"pid {process.pid}"

    # The kernel and its threads have no executable, no command line and no
    # owner, and Windows attributes idle time to a fake process. Scoring them
    # would put an unavoidable finding on every host, so they are excluded
    # unless the name matches a miner signature, which is checked inside
    # is_system_pseudo_process.
    if intel.is_system_pseudo_process(process.name) or intel.is_idle_pseudo_process(process.name):
        return _finalize(
            [], detection_type="process_mining", subject=subject,
            hostname=host.hostname, process=process,
        )

    signals: list[Signal] = []
    signals.extend(_resource_signals(process, cfg))
    signals.extend(_identity_signals(process))
    signals.extend(_command_line_signals(process))
    signals.extend(_persistence_signals(process, host.persistence))

    browser_context = process.is_browser_renderer or intel.is_browser(process.name)
    connections = list(process.connections)
    if browser_context and browser_pool:
        connections.extend(browser_pool)

    signals.extend(_network_signals(connections, cfg, browser_context=browser_context))

    detection_type = "process_mining"
    if browser_context:
        cryptojacking = [
            conn for conn in connections if intel.match_cryptojacking_domain(conn.destination_domain)
        ]
        dga = [conn for conn in connections if intel.looks_like_dga(conn.destination_domain)]
        cpu = max(process.cpu_usage, process.cpu_average)
        renderer_busy = cpu >= cfg.browser_cpu_percent and process.cpu_sustained_seconds >= 60

        if (cryptojacking or dga) and renderer_busy:
            detection_type = "browser_cryptojacking"
            endpoints = ", ".join(
                sorted({c.destination_domain for c in (cryptojacking + dga) if c.destination_domain})[:3]
            )
            signals.append(
                Signal(
                    "browser_cryptojacking",
                    BROWSER,
                    RULE_POINTS["browser_cryptojacking"],
                    "Busy browser tab talking to an in-browser mining service",
                    f"{cpu:.0f}% CPU for {process.cpu_sustained_seconds / 60:.0f} min while contacting {endpoints}",
                )
            )
            # The browser binary being legitimately installed says nothing
            # about the page it is executing, so the path mitigation would
            # only mask the finding.
            signals = [s for s in signals if s.rule_id != "trusted_system_path"]
        else:
            # Browsers legitimately sit in trusted paths and burn CPU; without
            # the domain evidence above they should not accrue identity risk.
            signals = [s for s in signals if s.rule_id != "masquerading_name"]

    return _finalize(
        signals,
        detection_type=detection_type,
        subject=subject,
        hostname=host.hostname,
        process=process,
    )


def evaluate_persistence_only(host: HostObservation, cfg: Settings | None = None) -> list[Assessment]:
    """Score autostart entries that look like miners but are not running.

    A miner that reinstalls itself at boot is worth reporting even while the
    process is idle or already dead.
    """
    cfg = cfg or default_settings
    running = {intel.binary_stem(p.name) for p in host.processes}
    assessments: list[Assessment] = []

    for item in host.persistence:
        if not item.enabled:
            continue
        note = _persistence_is_suspicious(item)
        if not note:
            continue
        stem = intel.binary_stem(item.target_path or item.name)
        if stem and stem in running:
            continue  # Already covered by the process-level assessment.

        signals = [
            Signal(
                "suspicious_persistence",
                PERSISTENCE,
                RULE_POINTS["suspicious_persistence"],
                "Suspicious autostart entry",
                f"{item.mechanism}: {item.name} ({note})",
            )
        ]
        if intel.matches_miner_binary(item.name, item.target_path or item.command):
            signals.append(
                Signal(
                    "known_miner_binary",
                    IDENTITY,
                    RULE_POINTS["known_miner_binary"],
                    "Autostart target matches a known miner",
                    item.target_path or item.command or item.name,
                )
            )
        hits = intel.match_command_line(item.command)
        if hits:
            signals.append(
                Signal(
                    "unusual_command_line",
                    COMMAND_LINE,
                    RULE_POINTS["unusual_command_line"],
                    "Autostart command contains mining arguments",
                    ", ".join(hits[:4]),
                )
            )

        assessments.append(
            _finalize(
                signals,
                detection_type="persistence_mining",
                subject=item.name or item.target_path or item.mechanism,
                hostname=host.hostname,
                process=None,
            )
        )
    return assessments


def evaluate_host(host: HostObservation, cfg: Settings | None = None) -> list[Assessment]:
    """Score every process on a host, highest risk first."""
    cfg = cfg or default_settings
    dns_signals = _dns_signals(list(host.dns_queries))
    browser_pool = _browser_connection_pool(host)

    assessments: list[Assessment] = []
    for process in host.processes:
        assessment = evaluate_process(process, host, cfg, browser_pool=browser_pool)
        if dns_signals and assessment.risk_score > 0:
            # Host-wide DNS evidence reinforces an already-suspicious process
            # rather than standing up a finding of its own.
            merged = assessment.signals + dns_signals
            assessment = _finalize(
                merged,
                detection_type=assessment.detection_type,
                subject=process.name or f"pid {process.pid}",
                hostname=host.hostname,
                process=process,
            )
        assessments.append(assessment)

    assessments.extend(evaluate_persistence_only(host, cfg))
    assessments.sort(key=lambda a: -a.risk_score)
    return assessments
