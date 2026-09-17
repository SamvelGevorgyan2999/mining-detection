from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field  # type: ignore[import-not-found]

ALERT_STATUSES = ("new", "acknowledged", "investigating", "closed", "false_positive")
DETECTION_STATUSES = ("open", "resolved", "suppressed")


class HostIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os: str = ""
    os_version: str = ""
    ip_address: str = ""
    cpu_count: int = 0
    agent_version: str = ""


class ProcessIn(BaseModel):
    pid: int = 0
    name: str = ""
    path: str = ""
    command_line: str = ""
    username: str = ""
    parent_pid: int = 0
    parent_name: str = ""
    cpu_usage: float = 0.0
    cpu_share: float = 0.0
    cpu_average: float = 0.0
    cpu_sustained_seconds: float = 0.0
    memory_usage: float = 0.0
    memory_rss_mb: float = 0.0
    gpu_usage: float = 0.0
    thread_count: int = 0
    lifetime_seconds: float = 0.0
    is_browser_renderer: bool = False


class ConnectionIn(BaseModel):
    pid: int = 0
    process_name: str = ""
    destination_ip: str = ""
    destination_domain: str = ""
    destination_port: int = 0
    protocol: str = "tcp"
    status: str = ""
    duration_seconds: float = 0.0
    connection_count: int = 1


class PersistenceIn(BaseModel):
    mechanism: str = ""
    name: str = ""
    target_path: str = ""
    command: str = ""
    source: str = ""
    enabled: bool = True


class SnapshotIn(BaseModel):
    host: HostIn
    processes: list[ProcessIn] = Field(default_factory=list)
    connections: list[ConnectionIn] = Field(default_factory=list)
    persistence: list[PersistenceIn] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    collected_at: float | None = None


class SignalOut(BaseModel):
    rule_id: str
    category: str
    points: int
    title: str
    detail: str


class ProcessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pid: int
    name: str
    path: str
    command_line: str
    username: str
    parent_name: str
    cpu_usage: float
    cpu_share: float
    cpu_average: float
    cpu_sustained_seconds: float
    memory_usage: float
    memory_rss_mb: float
    gpu_usage: float
    lifetime_seconds: float
    is_browser_renderer: bool
    timestamp: datetime


class NetworkEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pid: int
    process_name: str
    destination_ip: str
    destination_domain: str
    destination_port: int
    protocol: str
    status: str
    duration_seconds: float
    connection_count: int
    timestamp: datetime


class PersistenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mechanism: str
    name: str
    target_path: str
    command: str
    source: str
    enabled: bool
    timestamp: datetime


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_id: int
    process_id: int | None
    process_name: str
    risk_score: int
    severity: str
    detection_type: str
    reason: str
    signals: list[SignalOut]
    fingerprint: str
    status: str
    observation_count: int
    created_at: datetime
    updated_at: datetime


class DetectionWithHostOut(DetectionOut):
    hostname: str = ""


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detection_id: int
    assigned_to: str
    status: str
    resolution: str
    created_at: datetime
    closed_at: datetime | None


class AlertDetailOut(AlertOut):
    hostname: str = ""
    process_name: str = ""
    risk_score: int = 0
    severity: str = "NORMAL"
    reason: str = ""
    detection_type: str = ""


class AlertUpdateIn(BaseModel):
    assigned_to: str | None = None
    status: str | None = None
    resolution: str | None = None


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    os: str
    os_version: str
    ip_address: str
    cpu_count: int
    agent_version: str
    risk_score: int
    severity: str
    first_seen: datetime
    last_seen: datetime


class HostSummaryOut(HostOut):
    open_detections: int = 0
    open_alerts: int = 0
    top_process: str = ""
    online: bool = True


class HostDetailOut(BaseModel):
    host: HostSummaryOut
    detections: list[DetectionOut] = Field(default_factory=list)
    processes: list[ProcessOut] = Field(default_factory=list)
    network_events: list[NetworkEventOut] = Field(default_factory=list)
    persistence: list[PersistenceOut] = Field(default_factory=list)


class StatsOut(BaseModel):
    hosts_monitored: int
    hosts_online: int
    active_alerts: int
    severity_counts: dict[str, int]
    detections_24h: int
    top_hosts: list[HostSummaryOut] = Field(default_factory=list)


class IngestResultOut(BaseModel):
    host_id: int
    hostname: str
    host_risk_score: int
    host_severity: str
    processes_stored: int
    connections_stored: int
    persistence_stored: int
    detections: list[DetectionOut] = Field(default_factory=list)
    suppressed: list[str] = Field(default_factory=list)


