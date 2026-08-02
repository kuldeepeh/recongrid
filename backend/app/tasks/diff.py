"""Diff engine: compare this run's state against the previous completed run.

Runs on normalized DB rows (not raw tool output), so it's tool-agnostic. Emits
DiffEvent rows — this is the data behind the Censys-style "diff over time" timeline.

Detection is based on first_seen / last_seen run bookkeeping:
  * new_subdomain      first_seen_run_id == current run
  * removed_subdomain  last_seen_run_id  == previous run (not seen this run)
  * new_port           first_seen_run_id == current run
  * closed_port        last_seen_run_id  == previous run
  * new_finding        first_seen_run_id == current run
  * cert_change        a TLS cert with a new fingerprint appeared this run
  * http_change        status_code / title changed vs. prior (tracked opportunistically)
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    ChangeType,
    DiffEvent,
    Finding,
    HttpService,
    Port,
    ScanRun,
    ScanStatus,
    Subdomain,
    TlsCert,
)

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _previous_run_id(db: Session, target_id: int, current_run_id: int) -> int | None:
    prev = db.scalar(
        select(ScanRun.id)
        .where(
            ScanRun.target_id == target_id,
            ScanRun.id < current_run_id,
            ScanRun.status == ScanStatus.completed,
            ScanRun.tool.is_(None),  # only full-pipeline runs form the baseline
        )
        .order_by(ScanRun.id.desc())
        .limit(1)
    )
    return prev


def _emit(db: Session, target_id: int, run_id: int, change_type: ChangeType,
          entity_ref: dict, before=None, after=None, severity="info") -> None:
    db.add(
        DiffEvent(
            target_id=target_id,
            scan_run_id=run_id,
            change_type=change_type,
            entity_ref=entity_ref,
            before=before,
            after=after,
            severity=severity,
        )
    )


def run_diff(db: Session, target_id: int, run_id: int) -> int:
    """Compute diff events for `run_id`. Returns number of events emitted."""
    prev_run_id = _previous_run_id(db, target_id, run_id)

    # First-ever run: everything is "new" but we don't spam a baseline diff.
    # We only record new_finding on a first run (security-relevant), skip asset noise.
    events = 0

    # ── Subdomains ──
    new_subs = db.scalars(
        select(Subdomain).where(
            Subdomain.target_id == target_id,
            Subdomain.first_seen_run_id == run_id,
        )
    ).all()
    if prev_run_id is not None:
        for sub in new_subs:
            _emit(db, target_id, run_id, ChangeType.new_subdomain,
                  {"hostname": sub.hostname}, after={"hostname": sub.hostname},
                  severity="info")
            events += 1

        removed_subs = db.scalars(
            select(Subdomain).where(
                Subdomain.target_id == target_id,
                Subdomain.last_seen_run_id == prev_run_id,
                Subdomain.is_active.is_(True),
            )
        ).all()
        for sub in removed_subs:
            sub.is_active = False
            _emit(db, target_id, run_id, ChangeType.removed_subdomain,
                  {"hostname": sub.hostname}, before={"hostname": sub.hostname})
            events += 1

    # ── Ports ──
    if prev_run_id is not None:
        new_ports = db.scalars(
            select(Port).where(
                Port.target_id == target_id, Port.first_seen_run_id == run_id
            )
        ).all()
        for p in new_ports:
            _emit(db, target_id, run_id, ChangeType.new_port,
                  {"ip": p.ip, "port": p.port},
                  after={"ip": p.ip, "port": p.port, "service": p.service_guess},
                  severity="medium")
            events += 1

        closed_ports = db.scalars(
            select(Port).where(
                Port.target_id == target_id, Port.last_seen_run_id == prev_run_id
            )
        ).all()
        for p in closed_ports:
            _emit(db, target_id, run_id, ChangeType.closed_port,
                  {"ip": p.ip, "port": p.port},
                  before={"ip": p.ip, "port": p.port})
            events += 1

    # ── TLS certs (new fingerprint this run == rotation) ──
    if prev_run_id is not None:
        new_certs = db.scalars(
            select(TlsCert).where(TlsCert.scan_run_id == run_id)
        ).all()
        for cert in new_certs:
            prior = db.scalar(
                select(TlsCert).where(
                    TlsCert.http_service_id == cert.http_service_id,
                    TlsCert.fingerprint_sha256 != cert.fingerprint_sha256,
                    TlsCert.id < cert.id,
                ).order_by(TlsCert.id.desc()).limit(1)
            )
            if prior is not None:
                _emit(db, target_id, run_id, ChangeType.cert_change,
                      {"http_service_id": cert.http_service_id},
                      before={"fingerprint": prior.fingerprint_sha256},
                      after={"fingerprint": cert.fingerprint_sha256},
                      severity="medium")
                events += 1

    # ── Findings (always relevant, even on first run) ──
    new_findings = db.scalars(
        select(Finding).where(
            Finding.target_id == target_id, Finding.first_seen_run_id == run_id
        )
    ).all()
    for f in new_findings:
        _emit(db, target_id, run_id, ChangeType.new_finding,
              {"template_id": f.template_id, "matched_at": f.matched_at},
              after={"template_id": f.template_id, "name": f.name},
              severity=_SEV.get(f.severity, "info"))
        events += 1

    db.commit()
    return events
