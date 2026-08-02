"""FastAPI application entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.routers import auth, maintenance, scan_profiles, scans, targets

app = FastAPI(
    title="ReconGrid API",
    version=__version__,
    description="Attack Surface Management — Module 1. Orchestrates third-party "
                "ProjectDiscovery recon tools; scanning logic is theirs, orchestration "
                "is ours.",
)

# Local dashboard talks to the API directly. Accept both localhost and 127.0.0.1
# (browsers treat them as distinct origins) on any port, over http/https.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(scan_profiles.router)
app.include_router(maintenance.router)


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "version": __version__}
