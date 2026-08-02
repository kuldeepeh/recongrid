"""URL normalization + dedup helpers.

Katana (and HTTPX across redirects) re-emit the same effective URL many times.
We compute a canonical `normalized_url` so a UNIQUE constraint collapses repeat
hits into an occurrence_count bump instead of duplicate rows.

Query-parameter *values* are intentionally preserved (?id=1 vs ?id=2 stay distinct);
only ordering/casing/trailing-slash/fragment noise is collapsed.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return raw
    if "://" not in raw:
        raw = "http://" + raw

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()

    host = parts.hostname or ""
    host = host.lower()

    # Drop default port for the scheme.
    port = parts.port
    netloc = host
    if port is not None and str(port) != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"

    # Trim trailing slash on the path (but keep root "/").
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Sort query keys for stable ordering; keep values.
    query_pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    # Fragment dropped entirely.
    return urlunsplit((scheme, netloc, path, query, ""))


def dedupe_endpoints(
    rows: list[dict[str, str]],
) -> dict[tuple[str, str], dict]:
    """Collapse crawled endpoints keyed by (normalized_url, method).

    Returns {key: {url, normalized_url, method, occurrence_count}}.
    """
    out: dict[tuple[str, str], dict] = {}
    for row in rows:
        method = (row.get("method") or "GET").upper()
        norm = normalize_url(row.get("url", ""))
        if not norm:
            continue
        key = (norm, method)
        if key in out:
            out[key]["occurrence_count"] += 1
        else:
            out[key] = {
                "url": row.get("url", ""),
                "normalized_url": norm,
                "method": method,
                "status_code": row.get("status_code"),
                "occurrence_count": 1,
            }
    return out
