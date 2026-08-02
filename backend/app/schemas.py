"""Pydantic request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ─── Auth ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    password: str


class LoginResponse(BaseModel):
    ok: bool


# ─── Targets ─────────────────────────────────────────────────────────
class TargetCreate(BaseModel):
    name: str
    root_domain: str
    project_type: Literal["temporary", "permanent"] = "permanent"
    scope_config: dict[str, Any] = Field(default_factory=dict)


class AuthorizationConfirm(BaseModel):
    authorization_note: str = Field(min_length=10)


class ScopeConfigUpdate(BaseModel):
    extra_in_scope: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)


class TargetOut(ORMModel):
    id: int
    name: str
    root_domain: str
    is_authorized: bool
    project_type: str
    expires_at: datetime | None
    last_activity_at: datetime | None
    created_at: datetime


class TargetDetailOut(TargetOut):
    scope_config: dict[str, Any]
    authorization_note: str | None
    subdomain_count: int = 0
    open_finding_count: int = 0
    unacked_diff_count: int = 0


# ─── Scan profiles ───────────────────────────────────────────────────
class ScanProfileCreate(BaseModel):
    name: str
    is_default: bool = False
    tool_config: dict[str, Any] = Field(default_factory=dict)


class ScanProfileOut(ORMModel):
    id: int
    name: str
    is_default: bool
    tool_config: dict[str, Any]


# ─── Scans ───────────────────────────────────────────────────────────
class ScanTriggerRequest(BaseModel):
    scan_profile_id: int | None = None


class SingleToolScanRequest(BaseModel):
    scan_profile_id: int | None = None
    # Nuclei/Katana targeting (Section 3.7).
    target_source: Literal["all_crawled", "selected"] = "all_crawled"
    endpoint_ids: list[int] = Field(default_factory=list)


class StageExecutionOut(ORMModel):
    id: int
    tool: str
    command: str
    started_at: datetime | None
    completed_at: datetime | None
    exit_code: int | None
    result_count: int
    raw_output_path: str | None


class ScanRunOut(ORMModel):
    id: int
    target_id: int
    triggered_by: str
    tool: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    stage_status: dict[str, Any]
    error: str | None
    created_at: datetime


class ScanRunDetailOut(ScanRunOut):
    stage_executions: list[StageExecutionOut] = Field(default_factory=list)


# ─── Assets ──────────────────────────────────────────────────────────
class SubdomainOut(ORMModel):
    id: int
    hostname: str
    source_tool: str | None
    is_active: bool
    first_seen_run_id: int | None
    last_seen_run_id: int | None


class DnsRecordOut(BaseModel):
    id: int
    hostname: str
    record_type: str
    value: str


class PortOut(ORMModel):
    id: int
    ip: str
    port: int
    protocol: str
    service_guess: str | None
    service_product: str | None = None
    service_version: str | None = None
    os_guess: str | None = None


class HttpServiceOut(ORMModel):
    id: int
    url: str
    normalized_url: str
    status_code: int | None
    title: str | None
    tech_stack: list[Any]
    server_header: str | None
    occurrence_count: int


class CrawledEndpointOut(ORMModel):
    id: int
    url: str
    normalized_url: str
    method: str
    status_code: int | None
    occurrence_count: int


class FindingOut(ORMModel):
    id: int
    template_id: str
    severity: str
    matched_at: str
    name: str | None
    description: str | None


class DiffEventOut(ORMModel):
    id: int
    change_type: str
    entity_ref: dict[str, Any]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    severity: str
    acknowledged: bool
    created_at: datetime
