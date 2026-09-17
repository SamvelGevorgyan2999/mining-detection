from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SEVERITY_ORDER = ("NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    os: Mapped[str] = mapped_column(String(64), default="")
    os_version: Mapped[str] = mapped_column(String(160), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    cpu_count: Mapped[int] = mapped_column(Integer, default=0)
    # Denormalised rollup of the host's worst open detection, refreshed on
    # every ingest so the host list is a single cheap query.
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="NORMAL", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    processes: Mapped[list["Process"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", passive_deletes=True
    )
    network_events: Mapped[list["NetworkEvent"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", passive_deletes=True
    )
    persistence_items: Mapped[list["PersistenceItem"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", passive_deletes=True
    )
    detections: Mapped[list["Detection"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", passive_deletes=True
    )


class Process(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    pid: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(255), default="", index=True)
    path: Mapped[str] = mapped_column(Text, default="")
    command_line: Mapped[str] = mapped_column(Text, default="")
    username: Mapped[str] = mapped_column(String(160), default="")
    parent_pid: Mapped[int] = mapped_column(Integer, default=0)
    parent_name: Mapped[str] = mapped_column(String(255), default="")
    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    cpu_share: Mapped[float] = mapped_column(Float, default=0.0)
    cpu_average: Mapped[float] = mapped_column(Float, default=0.0)
    cpu_sustained_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    memory_usage: Mapped[float] = mapped_column(Float, default=0.0)
    memory_rss_mb: Mapped[float] = mapped_column(Float, default=0.0)
    gpu_usage: Mapped[float] = mapped_column(Float, default=0.0)
    thread_count: Mapped[int] = mapped_column(Integer, default=0)
    lifetime_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    is_browser_renderer: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    host: Mapped["Host"] = relationship(back_populates="processes")
    network_events: Mapped[list["NetworkEvent"]] = relationship(
        back_populates="process", passive_deletes=True
    )

    __table_args__ = (Index("ix_processes_host_timestamp", "host_id", "timestamp"),)


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL"), nullable=True
    )
    pid: Mapped[int] = mapped_column(Integer, default=0)
    process_name: Mapped[str] = mapped_column(String(255), default="")
    destination_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    destination_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    destination_port: Mapped[int] = mapped_column(Integer, default=0, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    status: Mapped[str] = mapped_column(String(32), default="")
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    connection_count: Mapped[int] = mapped_column(Integer, default=1)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    host: Mapped["Host"] = relationship(back_populates="network_events")
    process: Mapped["Process | None"] = relationship(back_populates="network_events")

    __table_args__ = (Index("ix_network_events_host_timestamp", "host_id", "timestamp"),)


class PersistenceItem(Base):
    """Autostart entry found on a host.

    Not part of the original schema sketch, but the risk model scores
    persistence, so the evidence needs a home.
    """

    __tablename__ = "persistence_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    mechanism: Mapped[str] = mapped_column(String(64), default="")
    name: Mapped[str] = mapped_column(String(255), default="")
    target_path: Mapped[str] = mapped_column(Text, default="")
    command: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    host: Mapped["Host"] = relationship(back_populates="persistence_items")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL"), nullable=True
    )
    process_name: Mapped[str] = mapped_column(String(255), default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="NORMAL", index=True)
    detection_type: Mapped[str] = mapped_column(String(32), default="process_mining")
    reason: Mapped[str] = mapped_column(Text, default="")
    signals: Mapped[list] = mapped_column(JSON, default=list)
    # Stable key for a host/process/evidence combination, used to update an
    # existing finding instead of emitting a new alert on every collection.
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)

    host: Mapped["Host"] = relationship(back_populates="detections")
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="detection", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (Index("ix_detections_host_created", "host_id", "created_at"),)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    detection_id: Mapped[int] = mapped_column(
        ForeignKey("detections.id", ondelete="CASCADE"), index=True
    )
    assigned_to: Mapped[str] = mapped_column(String(160), default="")
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    resolution: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    detection: Mapped["Detection"] = relationship(back_populates="alerts")


