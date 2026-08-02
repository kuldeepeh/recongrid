"""Scan trigger + status routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_session
from app.database import get_db
from app.models import ScanProfile, ScanRun, Target, TriggeredBy
from app.schemas import (
    ScanRunDetailOut,
    ScanRunOut,
    ScanTriggerRequest,
    SingleToolScanRequest,
)
from app.tools.registry import STAGES

router = APIRouter(tags=["scans"], dependencies=[Depends(require_session)])


def _default_profile_id(db: Session) -> int | None:
    return db.scalar(select(ScanProfile.id).where(ScanProfile.is_default.is_(True)))


def _require_authorized_target(db: Session, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is not authorized. Confirm authorization before scanning.",
        )
    return target


@router.post("/targets/{target_id}/scans", response_model=ScanRunOut, status_code=201)
def trigger_scan(
    target_id: int, body: ScanTriggerRequest, db: Session = Depends(get_db)
) -> ScanRun:
    _require_authorized_target(db, target_id)
    profile_id = body.scan_profile_id or _default_profile_id(db)
    run = ScanRun(
        target_id=target_id,
        scan_profile_id=profile_id,
        triggered_by=TriggeredBy.manual,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    from app.tasks.pipeline import run_pipeline

    run_pipeline.delay(run.id)
    return run


@router.post("/targets/{target_id}/scans/{tool}", response_model=ScanRunOut, status_code=201)
def trigger_single_tool(
    target_id: int, tool: str, body: SingleToolScanRequest,
    db: Session = Depends(get_db),
) -> ScanRun:
    if tool not in STAGES:
        raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")
    _require_authorized_target(db, target_id)
    profile_id = body.scan_profile_id or _default_profile_id(db)
    run = ScanRun(
        target_id=target_id,
        scan_profile_id=profile_id,
        triggered_by=TriggeredBy.manual,
        tool=tool,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    from app.tasks.pipeline import run_single_tool

    run_single_tool.delay(
        run.id, tool, body.target_source, body.endpoint_ids
    )
    return run


@router.get("/targets/{target_id}/scans", response_model=list[ScanRunOut])
def list_scans(target_id: int, db: Session = Depends(get_db)):
    return list(
        db.scalars(
            select(ScanRun).where(ScanRun.target_id == target_id)
            .order_by(ScanRun.id.desc())
        ).all()
    )


@router.get("/scans/{run_id}", response_model=ScanRunDetailOut)
def get_scan(run_id: int, db: Session = Depends(get_db)) -> ScanRun:
    run = db.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return run
