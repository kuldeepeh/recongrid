"""Maintenance panel: installed tool versions + nuclei template updates."""
from __future__ import annotations

import re
import subprocess

from fastapi import APIRouter, Depends

from app.auth import require_session
from app.tools.registry import REGISTRY

router = APIRouter(
    prefix="/maintenance", tags=["maintenance"],
    dependencies=[Depends(require_session)],
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")           # strip terminal colour codes
_VERSION = re.compile(r"v?\d+\.\d+\.\d+[\w.\-]*")  # e.g. v2.14.0, 1.2.3, 9.6p1


def _tool_version(binary: str) -> str:
    """Extract just the semantic version from a recon binary's -version output.

    PD tools print banners like `[INF] Current Version: v2.14.0` with ANSI colour
    codes; we clean those and return only the version token.
    """
    try:
        proc = subprocess.run(
            [binary, "-version"], capture_output=True, text=True, timeout=15
        )
        out = _ANSI.sub("", (proc.stdout + proc.stderr))
        match = _VERSION.search(out)
        if match:
            return match.group(0)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return lines[-1] if lines else "unknown"
    except FileNotFoundError:
        return "not installed"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


@router.get("/tools")
def tool_versions() -> dict:
    """Installed version of each recon engine, for the maintenance panel."""
    return {
        "tools": [
            {"name": name, "version": _tool_version(spec.binary)}
            for name, spec in REGISTRY.items()
        ]
    }


@router.post("/update-templates")
def update_templates() -> dict:
    """Kick off a nuclei template update in the worker (async)."""
    from app.tasks.maintenance import update_nuclei_templates

    task = update_nuclei_templates.delay()
    return {"queued": True, "task_id": task.id}
