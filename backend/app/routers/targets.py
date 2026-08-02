"""Target CRUD + authorization gate + asset read endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import require_session
from app.config import settings
from app.database import get_db
from app.models import (
    CrawledEndpoint,
    DiffEvent,
    DnsRecord,
    Finding,
    HttpService,
    Port,
    ProjectType,
    Subdomain,
    Target,
)
from app.schemas import (
    AuthorizationConfirm,
    CrawledEndpointOut,
    DiffEventOut,
    DnsRecordOut,
    FindingOut,
    HttpServiceOut,
    PortOut,
    ScopeConfigUpdate,
    SubdomainOut,
    TargetCreate,
    TargetDetailOut,
    TargetOut,
)

router = APIRouter(prefix="/targets", tags=["targets"], dependencies=[Depends(require_session)])


def _clean_domain(raw: str) -> str:
    """Normalize user input to a bare hostname.

    Recon tools (subfinder -d, dnsx/httpx -l) expect `example.com`, not
    `https://example.com/`. Strip scheme, path, port, and trailing dots.
    """
    raw = (raw or "").strip()
    if not raw:
        return raw
    if "://" in raw:
        raw = urlsplit(raw).hostname or raw
    else:
        raw = raw.split("/")[0].split(":")[0]
    return raw.strip().strip(".").lower()


def _touch_activity(db: Session, target: Target) -> None:
    """Reset a temporary project's rolling expiry on access."""
    now = datetime.now(timezone.utc)
    target.last_activity_at = now
    if target.project_type == ProjectType.temporary:
        target.expires_at = now + timedelta(days=settings.temp_project_ttl_days)
    db.commit()


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)) -> list[Target]:
    return list(db.scalars(select(Target).order_by(Target.created_at.desc())).all())


@router.post("", response_model=TargetDetailOut, status_code=status.HTTP_201_CREATED)
def create_target(body: TargetCreate, db: Session = Depends(get_db)) -> Target:
    now = datetime.now(timezone.utc)
    expires = (
        now + timedelta(days=settings.temp_project_ttl_days)
        if body.project_type == "temporary"
        else None
    )
    root_domain = _clean_domain(body.root_domain)
    if not root_domain:
        raise HTTPException(status_code=400, detail="Invalid root domain")
    target = Target(
        name=body.name,
        root_domain=root_domain,
        project_type=ProjectType(body.project_type),
        scope_config=body.scope_config,
        is_authorized=False,  # must be confirmed before scanning
        expires_at=expires,
        last_activity_at=now,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return _detail(db, target)


@router.get("/{target_id}", response_model=TargetDetailOut)
def get_target(target_id: int, db: Session = Depends(get_db)) -> TargetDetailOut:
    target = _require_target(db, target_id)
    _touch_activity(db, target)
    return _detail(db, target)


@router.post("/{target_id}/confirm-authorization", response_model=TargetDetailOut)
def confirm_authorization(
    target_id: int, body: AuthorizationConfirm, db: Session = Depends(get_db)
) -> TargetDetailOut:
    """Mandatory gate: a target cannot be scanned until this is called."""
    target = _require_target(db, target_id)
    target.is_authorized = True
    target.authorized_at = datetime.now(timezone.utc)
    target.authorization_note = body.authorization_note
    db.commit()
    return _detail(db, target)


@router.put("/{target_id}/scope", response_model=TargetDetailOut)
def update_scope(
    target_id: int, body: ScopeConfigUpdate, db: Session = Depends(get_db)
) -> TargetDetailOut:
    """Set the in-scope domains, CIDRs, and exclusions for a target.

    Takes effect on the next scan: out-of-scope hosts are pruned and no longer
    tracked or scanned. The root domain is always implicitly in scope.
    """
    import ipaddress

    target = _require_target(db, target_id)
    for c in body.cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {c}")

    target.scope_config = {
        "extra_in_scope": [_clean_domain(d) for d in body.extra_in_scope if d.strip()],
        "cidrs": [c.strip() for c in body.cidrs if c.strip()],
        "excluded_hosts": [_clean_domain(h) for h in body.excluded_hosts if h.strip()],
    }
    db.commit()
    return _detail(db, target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = _require_target(db, target_id)
    db.delete(target)
    db.commit()


# ─── Asset reads ─────────────────────────────────────────────────────
@router.get("/{target_id}/subdomains", response_model=list[SubdomainOut])
def list_subdomains(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return list(
        db.scalars(
            select(Subdomain).where(Subdomain.target_id == target_id)
            .order_by(Subdomain.hostname)
        ).all()
    )


@router.get("/{target_id}/dns-records", response_model=list[DnsRecordOut])
def list_dns_records(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    rows = db.execute(
        select(DnsRecord.id, Subdomain.hostname, DnsRecord.record_type, DnsRecord.value)
        .join(Subdomain, DnsRecord.subdomain_id == Subdomain.id)
        .where(Subdomain.target_id == target_id)
        .order_by(Subdomain.hostname, DnsRecord.record_type)
    ).all()
    return [
        DnsRecordOut(id=r.id, hostname=r.hostname, record_type=r.record_type, value=r.value)
        for r in rows
    ]


@router.get("/{target_id}/ports", response_model=list[PortOut])
def list_ports(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return list(
        db.scalars(
            select(Port).where(Port.target_id == target_id)
            .order_by(Port.ip, Port.port)
        ).all()
    )


@router.get("/{target_id}/http-services", response_model=list[HttpServiceOut])
def list_http_services(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return list(
        db.scalars(
            select(HttpService)
            .join(Subdomain, HttpService.subdomain_id == Subdomain.id)
            .where(Subdomain.target_id == target_id)
            .order_by(HttpService.normalized_url)
        ).all()
    )


@router.get("/{target_id}/endpoints", response_model=list[CrawledEndpointOut])
def list_endpoints(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return list(
        db.scalars(
            select(CrawledEndpoint)
            .join(HttpService, CrawledEndpoint.http_service_id == HttpService.id)
            .join(Subdomain, HttpService.subdomain_id == Subdomain.id)
            .where(Subdomain.target_id == target_id)
            .order_by(CrawledEndpoint.normalized_url)
        ).all()
    )


@router.get("/{target_id}/findings", response_model=list[FindingOut])
def list_findings(
    target_id: int, severity: str | None = None, db: Session = Depends(get_db)
):
    _require_target(db, target_id)
    stmt = select(Finding).where(Finding.target_id == target_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    return list(db.scalars(stmt.order_by(Finding.id.desc())).all())


@router.get("/{target_id}/diffs", response_model=list[DiffEventOut])
def list_diffs(target_id: int, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return list(
        db.scalars(
            select(DiffEvent).where(DiffEvent.target_id == target_id)
            .order_by(DiffEvent.created_at.desc())
        ).all()
    )


# ─── helpers ─────────────────────────────────────────────────────────
def _require_target(db: Session, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


def _detail(db: Session, target: Target) -> TargetDetailOut:
    sub_count = db.scalar(
        select(func.count(Subdomain.id)).where(Subdomain.target_id == target.id)
    ) or 0
    finding_count = db.scalar(
        select(func.count(Finding.id)).where(Finding.target_id == target.id)
    ) or 0
    unacked = db.scalar(
        select(func.count(DiffEvent.id)).where(
            DiffEvent.target_id == target.id, DiffEvent.acknowledged.is_(False)
        )
    ) or 0
    out = TargetDetailOut.model_validate(target)
    out.subdomain_count = sub_count
    out.open_finding_count = finding_count
    out.unacked_diff_count = unacked
    return out
