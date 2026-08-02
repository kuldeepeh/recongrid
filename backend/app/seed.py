"""Idempotent seed data: default scan profile + a pre-authorized lab target."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ProjectType, ScanProfile, Target
from app.tools.registry import default_tool_config


def seed_default_profile(db: Session) -> ScanProfile:
    existing = db.scalar(select(ScanProfile).where(ScanProfile.is_default.is_(True)))
    if existing:
        return existing
    profile = ScanProfile(
        name="Standard",
        is_default=True,
        tool_config=default_tool_config(),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def seed_lab_target(db: Session) -> Target:
    existing = db.scalar(select(Target).where(Target.root_domain == "localhost"))
    if existing:
        return existing
    target = Target(
        name="Local Lab (DVWA / Juice Shop)",
        root_domain="localhost",
        is_authorized=True,
        authorized_at=datetime.now(timezone.utc),
        authorization_note=(
            "Self-owned lab environment (self-hosted VPS / DVWA / Juice Shop). "
            "Seeded pre-authorized so the default demo requires no extra steps."
        ),
        scope_config={
            "cidrs": ["127.0.0.1/32"],
            "excluded_subdomains": [],
            "rate_limits": {"default": 150},
        },
        project_type=ProjectType.permanent,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def run_seed(db: Session) -> None:
    seed_default_profile(db)
    seed_lab_target(db)
