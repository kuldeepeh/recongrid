"""Normalize raw tool records into DB rows with upsert + dedup semantics.

Each function takes the parsed JSONL records from one tool and reconciles them
against the current-state tables, updating first_seen / last_seen / occurrence_count
so history is preserved without a row-per-run explosion.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    CrawledEndpoint,
    DnsRecord,
    Finding,
    HttpService,
    Port,
    Subdomain,
    Target,
    TlsCert,
)
from app.tools.normalize import normalize_url


def host_in_scope(host: str, target: Target) -> bool:
    """Is `host` part of this target's authorized attack surface?

    Default scope = the target's root domain and its subdomains. This keeps
    third-party hosts that a crawl happens to reference (cdnjs, whatsapp,
    facebook, …) out of the tracked surface — and, importantly, stops the tool
    from port-scanning infrastructure you aren't authorized to touch.

    scope_config may widen or narrow it:
      { "extra_in_scope": ["other-domain.com"],   # additional in-scope apex(es)
        "cidrs": ["10.0.0.0/8"],                   # in-scope IP ranges
        "excluded_hosts": ["staging.example.com"] } # always out of scope
    """
    if not host:
        return False
    host = host.lower().rstrip(".")
    root = (target.root_domain or "").lower()
    cfg = target.scope_config or {}

    if host in {h.lower() for h in cfg.get("excluded_hosts", [])}:
        return False
    if root and (host == root or host.endswith("." + root)):
        return True
    for d in cfg.get("extra_in_scope", []):
        d = d.lower().rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    try:
        ip = ipaddress.ip_address(host)
        for cidr in cfg.get("cidrs", []):
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _get_or_create_subdomain(
    db: Session, target_id: int, hostname: str, run_id: int, source: str
) -> Subdomain | None:
    """Return the (in-scope) subdomain row, creating it if needed. Out-of-scope
    hosts are ignored (returns None) so they never enter the tracked surface."""
    target = db.get(Target, target_id)  # cached by SQLAlchemy identity map
    if target is None or not host_in_scope(hostname, target):
        return None
    sub = db.scalar(
        select(Subdomain).where(
            Subdomain.target_id == target_id, Subdomain.hostname == hostname
        )
    )
    if sub is None:
        sub = Subdomain(
            target_id=target_id,
            hostname=hostname,
            source_tool=source,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
            is_active=True,
        )
        db.add(sub)
        db.flush()
    else:
        sub.last_seen_run_id = run_id
        sub.is_active = True
    return sub


def persist_subfinder(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    count = 0
    for rec in records:
        host = rec.get("host") or rec.get("input") or rec.get("subdomain")
        if not host:
            continue
        if _get_or_create_subdomain(db, target_id, host, run_id, "subfinder"):
            count += 1
    db.commit()
    return count


def persist_dnsx(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    count = 0
    for rec in records:
        host = rec.get("host")
        if not host:
            continue
        sub = _get_or_create_subdomain(db, target_id, host, run_id, "dnsx")
        if sub is None:  # out of scope
            continue
        for rtype in ("a", "aaaa", "cname", "ns", "mx", "txt"):
            for value in rec.get(rtype, []) or []:
                # Dedup: one row per (subdomain, type, value) across all runs.
                exists = db.scalar(
                    select(DnsRecord).where(
                        DnsRecord.subdomain_id == sub.id,
                        DnsRecord.record_type == rtype.upper(),
                        DnsRecord.value == str(value),
                    )
                )
                if exists is not None:
                    continue
                db.add(
                    DnsRecord(
                        subdomain_id=sub.id,
                        record_type=rtype.upper(),
                        value=str(value),
                        scan_run_id=run_id,
                    )
                )
                count += 1
    db.commit()
    return count


def persist_httpx(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    count = 0
    for rec in records:
        url = rec.get("url")
        host = rec.get("input") or rec.get("host")
        if not url or not host:
            continue
        sub = _get_or_create_subdomain(db, target_id, host, run_id, "httpx")
        if sub is None:  # out of scope
            continue
        norm = normalize_url(url)
        svc = db.scalar(
            select(HttpService).where(
                HttpService.subdomain_id == sub.id,
                HttpService.normalized_url == norm,
            )
        )
        tech = rec.get("tech") or rec.get("technologies") or []
        if svc is None:
            svc = HttpService(
                subdomain_id=sub.id,
                url=url,
                normalized_url=norm,
                status_code=rec.get("status_code"),
                title=rec.get("title"),
                tech_stack=tech,
                server_header=rec.get("webserver") or rec.get("server"),
                first_seen_run_id=run_id,
                last_seen_run_id=run_id,
                occurrence_count=1,
            )
            db.add(svc)
            db.flush()
        else:
            svc.status_code = rec.get("status_code")
            svc.title = rec.get("title")
            svc.tech_stack = tech
            svc.server_header = rec.get("webserver") or rec.get("server")
            svc.last_seen_run_id = run_id
            svc.occurrence_count += 1

        # TLS cert (httpx -tls-grab)
        tls = rec.get("tls") or {}
        fp = tls.get("fingerprint_hash", {}).get("sha256") if isinstance(
            tls.get("fingerprint_hash"), dict
        ) else tls.get("fingerprint_sha256")
        if fp:
            existing = db.scalar(
                select(TlsCert).where(
                    TlsCert.http_service_id == svc.id,
                    TlsCert.fingerprint_sha256 == fp,
                )
            )
            if existing is None:
                db.add(
                    TlsCert(
                        http_service_id=svc.id,
                        fingerprint_sha256=fp,
                        subject=tls.get("subject_cn") or tls.get("subject_dn"),
                        issuer=tls.get("issuer_cn") or tls.get("issuer_dn"),
                        not_before=_parse_dt(tls.get("not_before")),
                        not_after=_parse_dt(tls.get("not_after")),
                        scan_run_id=run_id,
                    )
                )
        count += 1
    db.commit()
    return count


# IANA well-known port -> service name. Gives the naabu results a "service"
# column with no extra tooling. Version-level detection (product + version banner)
# is a separate nmap -sV enrichment pass, added when enabled.
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


def _service_for_port(rec: dict, port: int) -> str | None:
    """Prefer any service naabu reported; otherwise map the well-known port."""
    return rec.get("service") or WELL_KNOWN_PORTS.get(int(port))


def persist_naabu(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    count = 0
    for rec in records:
        ip = rec.get("ip") or rec.get("host")
        port = rec.get("port")
        if not ip or port is None:
            continue
        row = db.scalar(
            select(Port).where(
                Port.target_id == target_id, Port.ip == ip, Port.port == port
            )
        )
        if row is None:
            db.add(
                Port(
                    target_id=target_id,
                    ip=ip,
                    port=int(port),
                    protocol=rec.get("protocol", "tcp"),
                    service_guess=_service_for_port(rec, port),
                    first_seen_run_id=run_id,
                    last_seen_run_id=run_id,
                )
            )
        else:
            row.last_seen_run_id = run_id
            if not row.service_guess:
                row.service_guess = _service_for_port(rec, port)
        count += 1
    db.commit()
    return count


def persist_katana(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    """Persist crawled endpoints, deduped at the SUBDOMAIN level.

    A subdomain can have several http_service rows (e.g. an http:// and an https://
    probe from httpx). Endpoints must dedupe across all of them, not per-service —
    otherwise the same URL splits into duplicate rows. So we look up an existing
    endpoint by (subdomain, normalized_url, method) regardless of which service it
    hangs off, and only create a new one against a stable canonical service.
    """
    from urllib.parse import urlsplit

    count = 0
    for rec in records:
        req = rec.get("request", {}) if isinstance(rec.get("request"), dict) else rec
        url = req.get("endpoint") or rec.get("url") or req.get("url")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        norm = normalize_url(url)
        host = urlsplit(norm).hostname or ""
        sub = db.scalar(
            select(Subdomain).where(
                Subdomain.target_id == target_id, Subdomain.hostname == host
            )
        )
        if sub is None:
            sub = _get_or_create_subdomain(db, target_id, host, run_id, "katana")
        if sub is None:  # host is out of scope (e.g. a CDN referenced in a page)
            continue

        # Existing endpoint for this subdomain + url + method, on ANY of its services.
        ep = db.scalar(
            select(CrawledEndpoint)
            .join(HttpService, CrawledEndpoint.http_service_id == HttpService.id)
            .where(
                HttpService.subdomain_id == sub.id,
                CrawledEndpoint.normalized_url == norm,
                CrawledEndpoint.method == method,
            )
            .limit(1)
        )
        if ep is not None:
            ep.last_seen_run_id = run_id
            ep.occurrence_count += 1
            count += 1
            continue

        # New endpoint: attach to a deterministic canonical service (scheme-matched,
        # lowest id), creating one if the subdomain has no service yet.
        scheme = urlsplit(norm).scheme or "http"
        svc = db.scalar(
            select(HttpService)
            .where(
                HttpService.subdomain_id == sub.id,
                HttpService.normalized_url.like(f"{scheme}://%"),
            )
            .order_by(HttpService.id)
            .limit(1)
        ) or db.scalar(
            select(HttpService)
            .where(HttpService.subdomain_id == sub.id)
            .order_by(HttpService.id)
            .limit(1)
        )
        if svc is None:
            svc = HttpService(
                subdomain_id=sub.id,
                url=f"{scheme}://{host}",
                normalized_url=normalize_url(f"{scheme}://{host}"),
                first_seen_run_id=run_id,
                last_seen_run_id=run_id,
            )
            db.add(svc)
            db.flush()

        db.add(
            CrawledEndpoint(
                http_service_id=svc.id,
                url=url,
                normalized_url=norm,
                method=method,
                status_code=(rec.get("response", {}) or {}).get("status_code"),
                first_seen_run_id=run_id,
                last_seen_run_id=run_id,
                occurrence_count=1,
            )
        )
        count += 1
    db.commit()
    return count


def persist_nuclei(db: Session, target_id: int, run_id: int, records: list[dict]) -> int:
    count = 0
    for rec in records:
        template_id = rec.get("template-id") or rec.get("templateID")
        matched = rec.get("matched-at") or rec.get("host") or ""
        if not template_id:
            continue
        info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
        existing = db.scalar(
            select(Finding).where(
                Finding.target_id == target_id,
                Finding.template_id == template_id,
                Finding.matched_at == matched,
            )
        )
        if existing is None:
            db.add(
                Finding(
                    target_id=target_id,
                    scan_run_id=run_id,
                    template_id=template_id,
                    severity=(info.get("severity") or "info").lower(),
                    matched_at=matched,
                    name=info.get("name"),
                    description=info.get("description"),
                    raw_output=rec,
                    first_seen_run_id=run_id,
                )
            )
            count += 1
    db.commit()
    return count


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


PERSIST_MAP = {
    "subfinder": persist_subfinder,
    "dnsx": persist_dnsx,
    "httpx": persist_httpx,
    "naabu": persist_naabu,
    "katana": persist_katana,
    "nuclei": persist_nuclei,
}
