"""Scan-profile CRUD + tool allowlist introspection (drives the Advanced UI)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_session
from app.database import get_db
from app.models import ScanProfile
from app.schemas import ScanProfileCreate, ScanProfileOut
from app.tools.registry import REGISTRY, STAGES

router = APIRouter(
    prefix="/scan-profiles", tags=["scan-profiles"],
    dependencies=[Depends(require_session)],
)


@router.get("/tool-schema")
def tool_schema() -> dict:
    """Expose the per-tool allowlist so the frontend can render Advanced controls."""
    schema = {"stages": STAGES, "tools": {}}
    for name, spec in REGISTRY.items():
        schema["tools"][name] = {
            "base_flags": spec.base_flags,
            "advanced_keys": list(spec.advanced.keys()),
            "defaults": spec.defaults,
        }
    return schema


@router.get("", response_model=list[ScanProfileOut])
def list_profiles(db: Session = Depends(get_db)):
    return list(db.scalars(select(ScanProfile).order_by(ScanProfile.id)).all())


@router.post("", response_model=ScanProfileOut, status_code=201)
def create_profile(body: ScanProfileCreate, db: Session = Depends(get_db)) -> ScanProfile:
    if body.is_default:
        _clear_default(db)
    profile = ScanProfile(
        name=body.name, is_default=body.is_default, tool_config=body.tool_config
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.put("/{profile_id}", response_model=ScanProfileOut)
def update_profile(
    profile_id: int, body: ScanProfileCreate, db: Session = Depends(get_db)
) -> ScanProfile:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    if body.is_default:
        _clear_default(db)
    profile.name = body.name
    profile.is_default = body.is_default
    profile.tool_config = body.tool_config
    db.commit()
    db.refresh(profile)
    return profile


@router.delete("/{profile_id}", status_code=204)
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    if profile.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete the default profile")
    db.delete(profile)
    db.commit()


def _clear_default(db: Session) -> None:
    for p in db.scalars(select(ScanProfile).where(ScanProfile.is_default.is_(True))):
        p.is_default = False
    db.commit()
