"""ToolRunner: executes a recon tool and returns parsed JSONL output.

This is the seam between "our code" (arg building, execution, parsing, error
classification) and "their code" (the actual ProjectDiscovery binary).

Two execution modes:
  * sandbox — `docker exec` into the isolated scan-sandbox container (production).
  * local   — run the binary on PATH in-process (dev / CI, if tools are installed).
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.config import settings


@dataclass
class ToolResult:
    tool: str
    command: str            # literal string, stored + shown in the UI
    exit_code: int
    started_at: datetime
    completed_at: datetime
    records: list[dict[str, Any]] = field(default_factory=list)
    stderr: str = ""

    @property
    def result_count(self) -> int:
        return len(self.records)


def _wrap_for_sandbox(argv: list[str]) -> list[str]:
    """Wrap an argv so it runs inside the sandbox container via docker exec."""
    return [
        "docker", "exec", settings.sandbox_container_name,
        *argv,
    ]


def _parse_jsonl(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # Non-JSON line (banner / stray output) — skip, don't crash the run.
            continue
    return records


def run_tool(tool: str, argv: list[str]) -> ToolResult:
    """Execute one tool invocation and return a parsed ToolResult."""
    if settings.tool_execution_mode == "sandbox":
        exec_argv = _wrap_for_sandbox(argv)
    else:
        exec_argv = argv

    command_str = " ".join(shlex.quote(part) for part in argv)
    started = datetime.now(timezone.utc)

    try:
        proc = subprocess.run(
            exec_argv,
            capture_output=True,
            text=True,
            timeout=settings.tool_stage_timeout,
        )
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            tool=tool,
            command=command_str,
            exit_code=124,  # conventional timeout code
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            records=[],
            stderr=f"timeout after {settings.tool_stage_timeout}s: {exc}",
        )
    except FileNotFoundError as exc:
        return ToolResult(
            tool=tool,
            command=command_str,
            exit_code=127,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            records=[],
            stderr=f"binary not found: {exc}",
        )

    return ToolResult(
        tool=tool,
        command=command_str,
        exit_code=exit_code,
        started_at=started,
        completed_at=datetime.now(timezone.utc),
        records=_parse_jsonl(stdout),
        stderr=stderr[-4000:] if stderr else "",
    )
