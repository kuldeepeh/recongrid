"""Scan pipeline orchestration.

A run executes enabled stages in order, feeding each stage's output to the next,
recording the literal command + exit code + timing per stage, then diffing against
the previous run. Stage failures are isolated: one failed tool doesn't abort the
whole run, it's recorded and the pipeline continues where it can.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import celery
from app.config import settings
from app.database import session_scope
from app.models import (
    CrawledEndpoint,
    DnsRecord,
    HttpService,
    Port,
    ScanProfile,
    ScanRun,
    ScanStatus,
    StageExecution,
    Subdomain,
    Target,
)
from app.tasks import persist
from app.tasks.diff import run_diff
from app.tasks.persist import host_in_scope
from app.tools.nmap import run_nmap
from app.tools.registry import STAGES, build_command
from app.tools.runner import run_tool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _write_lines(run_id: int, tool: str, lines: list[str]) -> str | None:
    """Write a stage's input host/url list to shared scratch, return the path."""
    if not lines:
        return None
    os.makedirs(settings.scandata_dir, exist_ok=True)
    path = os.path.join(settings.scandata_dir, f"run{run_id}_{tool}_in.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def _mark_stage(db: Session, run: ScanRun, tool: str, status: str,
                duration: float | None = None) -> None:
    ss = dict(run.stage_status or {})
    ss[tool] = {"status": status, "duration": duration}
    run.stage_status = ss
    db.commit()


def _record_execution(db: Session, run_id: int, result) -> StageExecution:
    ex = StageExecution(
        scan_run_id=run_id,
        tool=result.tool,
        command=result.command,
        started_at=result.started_at,
        completed_at=result.completed_at,
        exit_code=result.exit_code,
        result_count=result.result_count,
    )
    db.add(ex)
    db.commit()
    return ex


def _prune_out_of_scope(db: Session, target: Target) -> int:
    """Delete subdomains that fall outside the target's scope (cascades to their
    services/records). Also drops ports on IPs no longer tied to any in-scope host."""
    subs = db.scalars(
        select(Subdomain).where(Subdomain.target_id == target.id)
    ).all()
    removed = 0
    for sub in subs:
        if not host_in_scope(sub.hostname, target):
            db.delete(sub)
            removed += 1
    if removed:
        db.commit()
    # Drop ports whose IP no longer belongs to any in-scope resolved record.
    in_scope_ips = {
        r.value
        for r in db.scalars(
            select(DnsRecord)
            .join(Subdomain, DnsRecord.subdomain_id == Subdomain.id)
            .where(Subdomain.target_id == target.id,
                   DnsRecord.record_type.in_(["A", "AAAA"]))
        ).all()
    }
    if in_scope_ips:
        for port in db.scalars(select(Port).where(Port.target_id == target.id)).all():
            if port.ip not in in_scope_ips:
                db.delete(port)
        db.commit()
    return removed


def _run_nmap_stage(db: Session, run: ScanRun, target_id: int, run_id: int) -> None:
    """Enrich naabu ports with nmap -sV/-O. Fail-safe: never aborts the pipeline."""
    _mark_stage(db, run, "nmap", "running")
    try:
        ports = db.scalars(select(Port).where(Port.target_id == target_id)).all()
        if not ports:
            _mark_stage(db, run, "nmap", "skipped")
            return

        by_ip: dict[str, list[int]] = {}
        for p in ports:
            by_ip.setdefault(p.ip, []).append(p.port)

        total_updated = 0
        last_cmd = ""
        exit_codes: list[int] = []
        started = _now()
        for ip, plist in by_ip.items():
            res = run_nmap(ip, plist, settings.nmap_os_detect)
            last_cmd = res.command
            exit_codes.append(res.exit_code)
            host = res.hosts.get(ip, {})
            os_guess = host.get("os")
            svc_map = host.get("ports", {})
            for p in ports:
                if p.ip != ip:
                    continue
                info = svc_map.get(p.port)
                if info:
                    if info.get("name"):
                        p.service_guess = info["name"]
                    p.service_product = info.get("product")
                    p.service_version = info.get("version")
                    total_updated += 1
                if os_guess:
                    p.os_guess = os_guess
        db.commit()

        # Record a stage_execution so the command is visible in the UI/log.
        db.add(
            StageExecution(
                scan_run_id=run_id,
                tool="nmap",
                command=last_cmd or "nmap (no hosts)",
                started_at=started,
                completed_at=_now(),
                exit_code=(max(exit_codes) if exit_codes else 0),
                result_count=total_updated,
            )
        )
        db.commit()
        _mark_stage(db, run, "nmap", "completed",
                    (_now() - started).total_seconds())
    except Exception as exc:  # noqa: BLE001 — enrichment must never break the run
        db.rollback()
        _mark_stage(db, run, "nmap", f"error({exc})")


def _target_hosts(db: Session, target_id: int) -> list[str]:
    rows = db.scalars(
        select(Subdomain.hostname).where(
            Subdomain.target_id == target_id, Subdomain.is_active.is_(True)
        )
    ).all()
    return list(rows)


def _live_urls(db: Session, target_id: int) -> list[str]:
    rows = db.scalars(
        select(HttpService.url)
        .join(Subdomain, HttpService.subdomain_id == Subdomain.id)
        .where(Subdomain.target_id == target_id)
    ).all()
    return list(rows)


@celery.task(name="app.tasks.pipeline.run_pipeline")
def run_pipeline(run_id: int) -> dict:
    """Full multi-stage pipeline for a scan run."""
    db = session_scope()
    try:
        run = db.get(ScanRun, run_id)
        if run is None:
            return {"error": "run not found"}
        target = db.get(Target, run.target_id)

        # Safety gate: never scan an unauthorized target.
        if not target or not target.is_authorized:
            run.status = ScanStatus.failed
            run.error = "Target is not authorized for scanning."
            db.commit()
            return {"error": "unauthorized target"}

        profile = (
            db.get(ScanProfile, run.scan_profile_id) if run.scan_profile_id else None
        )
        cfg = profile.tool_config if profile else {}
        enabled = cfg.get("enabled_stages", STAGES)

        run.status = ScanStatus.running
        run.started_at = _now()
        db.commit()

        # Clean up any assets left over from before scope enforcement (or from a
        # scope change): drop subdomains that are no longer in scope. Cascades
        # remove their http services, dns records, endpoints and certs.
        _prune_out_of_scope(db, target)

        seed_root = target.root_domain

        for tool in STAGES:
            if tool not in enabled:
                _mark_stage(db, run, tool, "skipped")
                continue
            _mark_stage(db, run, tool, "running")
            input_path = None

            if tool == "subfinder":
                argv = build_command(tool, cfg.get(tool))
                argv += ["-d", seed_root]
            elif tool in {"dnsx", "httpx", "naabu"}:
                hosts = _target_hosts(db, target.id) or [seed_root]
                input_path = _write_lines(run_id, tool, hosts)
                argv = build_command(tool, cfg.get(tool), input_path=input_path)
            elif tool == "katana":
                urls = _live_urls(db, target.id) or [f"http://{seed_root}"]
                input_path = _write_lines(run_id, tool, urls)
                argv = build_command(tool, cfg.get(tool), input_path=input_path)
            elif tool == "nuclei":
                urls = _live_urls(db, target.id) or [f"http://{seed_root}"]
                tlist = _write_lines(run_id, tool, urls)
                argv = build_command(tool, cfg.get(tool), extra_target_list=tlist)
            else:
                continue

            result = run_tool(tool, argv)
            _record_execution(db, run_id, result)

            if result.exit_code not in (0, None):
                _mark_stage(db, run, tool, f"error(exit={result.exit_code})",
                            (result.completed_at - result.started_at).total_seconds())
                # continue pipeline; a failed stage isn't fatal
                continue

            persist.PERSIST_MAP[tool](db, target.id, run_id, result.records)
            _mark_stage(db, run, tool, "completed",
                        (result.completed_at - result.started_at).total_seconds())

            # After naabu, enrich the discovered ports with nmap -sV/-O (fail-safe).
            if tool == "naabu" and settings.nmap_enabled:
                _run_nmap_stage(db, run, target.id, run_id)

        # Diff against previous run.
        _mark_stage(db, run, "diff", "running")
        events = run_diff(db, target.id, run_id)
        _mark_stage(db, run, "diff", "completed")

        run.status = ScanStatus.completed
        run.completed_at = _now()
        target.last_activity_at = _now()
        db.commit()
        return {"run_id": run_id, "status": "completed", "diff_events": events}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        run = db.get(ScanRun, run_id)
        if run:
            run.status = ScanStatus.failed
            run.error = str(exc)[:2000]
            db.commit()
        return {"run_id": run_id, "status": "failed", "error": str(exc)}
    finally:
        db.close()


@celery.task(name="app.tasks.pipeline.run_single_tool")
def run_single_tool(run_id: int, tool: str, target_source: str = "all_crawled",
                    endpoint_ids: list[int] | None = None) -> dict:
    """Ad-hoc single-tool run (e.g. re-run Nuclei on selected endpoints)."""
    db = session_scope()
    try:
        run = db.get(ScanRun, run_id)
        if run is None:
            return {"error": "run not found"}
        target = db.get(Target, run.target_id)
        if not target or not target.is_authorized:
            run.status = ScanStatus.failed
            run.error = "Target is not authorized for scanning."
            db.commit()
            return {"error": "unauthorized target"}

        profile = (
            db.get(ScanProfile, run.scan_profile_id) if run.scan_profile_id else None
        )
        cfg = profile.tool_config if profile else {}

        run.status = ScanStatus.running
        run.started_at = _now()
        _mark_stage(db, run, tool, "running")
        db.commit()

        input_path = None
        if tool == "subfinder":
            argv = build_command(tool, cfg.get(tool))
            argv += ["-d", target.root_domain]
        elif tool == "nuclei":
            if target_source == "selected" and endpoint_ids:
                urls = db.scalars(
                    select(CrawledEndpoint.url).where(
                        CrawledEndpoint.id.in_(endpoint_ids)
                    )
                ).all()
            else:
                urls = _live_urls(db, target.id) or [f"http://{target.root_domain}"]
            tlist = _write_lines(run_id, tool, list(urls))
            argv = build_command(tool, cfg.get(tool), extra_target_list=tlist)
        else:
            hosts = _target_hosts(db, target.id) or [target.root_domain]
            if tool == "katana":
                hosts = _live_urls(db, target.id) or [f"http://{target.root_domain}"]
            input_path = _write_lines(run_id, tool, hosts)
            argv = build_command(tool, cfg.get(tool), input_path=input_path)

        result = run_tool(tool, argv)
        _record_execution(db, run_id, result)

        if result.exit_code in (0, None):
            persist.PERSIST_MAP[tool](db, target.id, run_id, result.records)
            _mark_stage(db, run, tool, "completed",
                        (result.completed_at - result.started_at).total_seconds())
            run_diff(db, target.id, run_id)
            run.status = ScanStatus.completed
        else:
            _mark_stage(db, run, tool, f"error(exit={result.exit_code})")
            run.status = ScanStatus.failed
            run.error = result.stderr[:2000]

        run.completed_at = _now()
        target.last_activity_at = _now()
        db.commit()
        return {"run_id": run_id, "tool": tool, "status": run.status.value,
                "results": result.result_count}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        run = db.get(ScanRun, run_id)
        if run:
            run.status = ScanStatus.failed
            run.error = str(exc)[:2000]
            db.commit()
        return {"run_id": run_id, "status": "failed", "error": str(exc)}
    finally:
        db.close()
