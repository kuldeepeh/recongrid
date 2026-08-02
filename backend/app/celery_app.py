"""Celery application + Beat schedule."""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery = Celery(
    "recongrid",
    broker=settings.broker_url,
    backend=settings.result_backend,
    include=["app.tasks.pipeline", "app.tasks.maintenance"],
)

celery.conf.update(
    task_track_started=True,
    task_default_queue="default",
    task_routes={
        "app.tasks.pipeline.*": {"queue": "scans"},
        "app.tasks.maintenance.*": {"queue": "default"},
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    timezone="UTC",
)

# ─── Beat: scheduled maintenance ─────────────────────────────────────
celery.conf.beat_schedule = {
    "cleanup-expired-temp-projects": {
        "task": "app.tasks.maintenance.cleanup_expired_targets",
        "schedule": crontab(hour="3", minute="0"),  # daily 03:00 UTC
    },
    "prune-old-raw-output": {
        "task": "app.tasks.maintenance.prune_old_raw_output",
        "schedule": crontab(hour="3", minute="30"),
    },
    "run-due-schedules": {
        "task": "app.tasks.maintenance.enqueue_due_schedules",
        "schedule": crontab(minute="*/5"),  # check every 5 min
    },
}
