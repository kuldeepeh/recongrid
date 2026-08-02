"""SQLAlchemy ORM models — mirrors Section 5 of the architecture doc."""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ─── Enums ───────────────────────────────────────────────────────────
class ProjectType(str, enum.Enum):
    temporary = "temporary"
    permanent = "permanent"


class TriggeredBy(str, enum.Enum):
    manual = "manual"
    scheduled = "scheduled"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ChangeType(str, enum.Enum):
    new_subdomain = "new_subdomain"
    removed_subdomain = "removed_subdomain"
    new_port = "new_port"
    closed_port = "closed_port"
    cert_change = "cert_change"
    http_change = "http_change"
    new_finding = "new_finding"


# ─── Core tables ─────────────────────────────────────────────────────
class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authorization_note: Mapped[str | None] = mapped_column(Text)
    scope_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    project_type: Mapped[ProjectType] = mapped_column(
        Enum(ProjectType), default=ProjectType.permanent
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    scan_runs: Mapped[list["ScanRun"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # per-tool flags + enabled_stages (see tools/registry.py)
    tool_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="SET NULL")
    )
    cadence_cron: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="SET NULL")
    )
    triggered_by: Mapped[TriggeredBy] = mapped_column(
        Enum(TriggeredBy), default=TriggeredBy.manual
    )
    # Set when this run is a single ad-hoc tool run rather than a full pipeline.
    tool: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.queued
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stage_status: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    target: Mapped["Target"] = relationship(back_populates="scan_runs")
    stage_executions: Mapped[list["StageExecution"]] = relationship(
        back_populates="scan_run", cascade="all, delete-orphan"
    )


class StageExecution(Base):
    __tablename__ = "stage_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE")
    )
    tool: Mapped[str] = mapped_column(String(40))
    command: Mapped[str] = mapped_column(Text)  # literal CLI string executed
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_output_path: Mapped[str | None] = mapped_column(Text)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="stage_executions")


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("target_id", "hostname", name="uq_subdomain"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    source_tool: Mapped[str | None] = mapped_column(String(40))
    first_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    last_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    target: Mapped["Target"] = relationship(back_populates="subdomains")
    http_services: Mapped[list["HttpService"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    dns_records: Mapped[list["DnsRecord"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )


class DnsRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(
        ForeignKey("subdomains.id", ondelete="CASCADE")
    )
    record_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(512))
    scan_run_id: Mapped[int | None] = mapped_column(Integer)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    subdomain: Mapped["Subdomain"] = relationship(back_populates="dns_records")


class HttpService(Base):
    __tablename__ = "http_services"
    __table_args__ = (
        UniqueConstraint("subdomain_id", "normalized_url", name="uq_http_service"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(
        ForeignKey("subdomains.id", ondelete="CASCADE")
    )
    url: Mapped[str] = mapped_column(String(1024))
    normalized_url: Mapped[str] = mapped_column(String(1024), index=True)
    status_code: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(512))
    tech_stack: Mapped[list] = mapped_column(JSONB, default=list)
    server_header: Mapped[str | None] = mapped_column(String(255))
    first_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    last_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    subdomain: Mapped["Subdomain"] = relationship(back_populates="http_services")
    tls_certs: Mapped[list["TlsCert"]] = relationship(
        back_populates="http_service", cascade="all, delete-orphan"
    )
    crawled_endpoints: Mapped[list["CrawledEndpoint"]] = relationship(
        back_populates="http_service", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("target_id", "ip", "port", name="uq_port"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service_guess: Mapped[str | None] = mapped_column(String(64))
    # nmap -sV / -O enrichment (Section: service version detection)
    service_product: Mapped[str | None] = mapped_column(String(128))
    service_version: Mapped[str | None] = mapped_column(String(128))
    os_guess: Mapped[str | None] = mapped_column(String(255))
    first_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    last_seen_run_id: Mapped[int | None] = mapped_column(Integer)


class TlsCert(Base):
    __tablename__ = "tls_certs"

    id: Mapped[int] = mapped_column(primary_key=True)
    http_service_id: Mapped[int] = mapped_column(
        ForeignKey("http_services.id", ondelete="CASCADE")
    )
    fingerprint_sha256: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str | None] = mapped_column(String(512))
    issuer: Mapped[str | None] = mapped_column(String(512))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scan_run_id: Mapped[int | None] = mapped_column(Integer)

    http_service: Mapped["HttpService"] = relationship(back_populates="tls_certs")


class CrawledEndpoint(Base):
    __tablename__ = "crawled_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "http_service_id", "normalized_url", "method", name="uq_crawled_endpoint"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    http_service_id: Mapped[int] = mapped_column(
        ForeignKey("http_services.id", ondelete="CASCADE")
    )
    url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[str] = mapped_column(String(2048), index=True)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer)
    first_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    last_seen_run_id: Mapped[int | None] = mapped_column(Integer)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    http_service: Mapped["HttpService"] = relationship(
        back_populates="crawled_endpoints"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "template_id", "matched_at", name="uq_finding"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_run_id: Mapped[int | None] = mapped_column(Integer)
    template_id: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    matched_at: Mapped[str] = mapped_column(String(2048))
    name: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    raw_output: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen_run_id: Mapped[int | None] = mapped_column(Integer)


class DiffEvent(Base):
    __tablename__ = "diff_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_run_id: Mapped[int | None] = mapped_column(Integer)
    change_type: Mapped[ChangeType] = mapped_column(Enum(ChangeType), index=True)
    entity_ref: Mapped[dict] = mapped_column(JSONB, default=dict)
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
