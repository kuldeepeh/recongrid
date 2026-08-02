"""One-shot startup: create tables and seed. Run before the API boots.

For Module 1 we use create_all for simplicity; a real migration history via
Alembic is a straightforward later addition (alembic is already a dependency).
"""
from __future__ import annotations

import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.database import Base, engine, session_scope
from app import models  # noqa: F401  (register models on Base metadata)
from app.seed import run_seed


def wait_for_db(retries: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            print(f"[startup] waiting for postgres ({attempt}/{retries})...")
            time.sleep(delay)
    raise RuntimeError("Database never became available")


# Lightweight, idempotent column additions for existing databases. create_all()
# creates missing tables but never ALTERs existing ones, so new columns on already
# existing tables are added here (Postgres supports ADD COLUMN IF NOT EXISTS).
_SCHEMA_UPGRADES = [
    "ALTER TABLE ports ADD COLUMN IF NOT EXISTS service_product varchar(128)",
    "ALTER TABLE ports ADD COLUMN IF NOT EXISTS service_version varchar(128)",
    "ALTER TABLE ports ADD COLUMN IF NOT EXISTS os_guess varchar(255)",
]


def ensure_schema_upgrades() -> None:
    with engine.begin() as conn:
        for stmt in _SCHEMA_UPGRADES:
            conn.execute(text(stmt))


# One-time data cleanups (idempotent, safe to run every boot).
_DATA_CLEANUPS = [
    # Remove duplicate dns_records left over from before dedup existed,
    # keeping the earliest row per (subdomain, record_type, value).
    """
    DELETE FROM dns_records a
    USING dns_records b
    WHERE a.id > b.id
      AND a.subdomain_id = b.subdomain_id
      AND a.record_type = b.record_type
      AND a.value = b.value
    """,
    # Remove duplicate crawled_endpoints that were split across multiple
    # http_service rows of the same subdomain, keeping the earliest per
    # (subdomain, normalized_url, method).
    """
    DELETE FROM crawled_endpoints a
    USING crawled_endpoints b, http_services ha, http_services hb
    WHERE a.http_service_id = ha.id
      AND b.http_service_id = hb.id
      AND ha.subdomain_id = hb.subdomain_id
      AND a.normalized_url = b.normalized_url
      AND a.method = b.method
      AND a.id > b.id
    """,
]


def ensure_data_cleanups() -> None:
    with engine.begin() as conn:
        for stmt in _DATA_CLEANUPS:
            conn.execute(text(stmt))


def main() -> None:
    wait_for_db()
    Base.metadata.create_all(bind=engine)
    ensure_schema_upgrades()
    ensure_data_cleanups()
    db = session_scope()
    try:
        run_seed(db)
        print("[startup] tables created, schema upgraded, data cleaned, seed applied")
    finally:
        db.close()


if __name__ == "__main__":
    main()
