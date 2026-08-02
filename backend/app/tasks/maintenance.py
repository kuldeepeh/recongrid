"""Scheduled maintenance: retention cleanup, raw-output pruning, due schedules."""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone

from croniter import croniter  # optional; guarded below
from sqlalchemy import select

from app.celery_app import celery
from app.config import settings
from app.database import session_scope
from app.models import (
    ProjectType,
    ScanRun,
    Schedule,
    StageExecution,
    Target,
    TriggeredBy,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@celery.task(name="app.tasks.maintenance.update_nuclei_templates")
def update_nuclei_templates() -> dict:
    """Pull the latest nuclei templates into the worker (runs in the worker
    container, which is where scans execute). Triggered from the maintenance panel.
    """
    try:
        proc = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        tail = (proc.stdout + proc.stderr).strip()[-2000:]
        print(f"[maintenance] nuclei -update-templates exit={proc.returncode}")
        return {"exit_code": proc.returncode, "output": tail}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


@celery.task(name="app.tasks.maintenance.cleanup_expired_targets")
def cleanup_expired_targets() -> dict:
    """Delete temporary projects whose expires_at has passed (cascade)."""
    db = session_scope()
    try:
        now = _now()
        expired = db.scalars(
            select(Target).where(
                Target.project_type == ProjectType.temporary,
                Target.expires_at.is_not(None),
                Target.expires_at < now,
            )
        ).all()
        deleted = []
        for target in expired:
            deleted.append({"id": target.id, "name": target.name})
            db.delete(target)  # cascade removes assets, runs, diffs
        db.commit()
        if deleted:
            print(f"[retention] deleted expired temporary targets: {deleted}")
        return {"deleted": deleted}
    finally:
        db.close()


@celery.task(name="app.tasks.maintenance.prune_old_raw_output")
def prune_old_raw_output() -> dict:
    """Keep raw output files for the most recent N runs per target; delete older."""
    db = session_scope()
    keep = settings.raw_output_keep_runs
    removed = 0
    try:
        target_ids = db.scalars(select(Target.id)).all()
        for tid in target_ids:
            runs = db.scalars(
                select(ScanRun.id)
                .where(ScanRun.target_id == tid)
                .order_by(ScanRun.id.desc())
            ).all()
            old_run_ids = runs[keep:]
            if not old_run_ids:
                continue
            execs = db.scalars(
                select(StageExecution).where(
                    StageExecution.scan_run_id.in_(old_run_ids),
                    StageExecution.raw_output_path.is_not(None),
                )
            ).all()
            for ex in execs:
                try:
                    if ex.raw_output_path and os.path.exists(ex.raw_output_path):
                        os.remove(ex.raw_output_path)
                        removed += 1
                except OSError:
                    pass
                ex.raw_output_path = None
        db.commit()
        return {"files_removed": removed}
    finally:
        db.close()


@celery.task(name="app.tasks.maintenance.enqueue_due_schedules")
def enqueue_due_schedules() -> dict:
    """Enqueue pipeline runs for schedules whose next_run_at is due."""
    from app.tasks.pipeline import run_pipeline

    db = session_scope()
    now = _now()
    enqueued = []
    try:
        due = db.scalars(
            select(Schedule).where(
                Schedule.enabled.is_(True),
                Schedule.next_run_at.is_not(None),
                Schedule.next_run_at <= now,
            )
        ).all()
        for sched in due:
            target = db.get(Target, sched.target_id)
            if not target or not target.is_authorized:
                continue
            run = ScanRun(
                target_id=sched.target_id,
                scan_profile_id=sched.scan_profile_id,
                triggered_by=TriggeredBy.scheduled,
            )
            db.add(run)
            db.commit()
            db.refresh(run)
            run_pipeline.delay(run.id)
            enqueued.append(run.id)

            # Advance next_run_at using the cron expression.
            try:
                sched.next_run_at = croniter(sched.cadence_cron, now).get_next(datetime)
            except Exception:  # noqa: BLE001
                sched.enabled = False  # bad cron -> disable rather than loop
            db.commit()
        return {"enqueued_runs": enqueued}
    finally:
        db.close()
