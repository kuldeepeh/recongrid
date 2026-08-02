"""Per-tool flag allowlist and CLI-command builder.

This module is the crux of the project's "orchestration, not scanning" positioning.
It defines, per tool:

  * the fixed BASE command that Default mode always runs (lab-safe), and
  * an ADVANCED allowlist mapping safe option keys -> how they translate to CLI flags.

Anything not in the allowlist can never reach the command line, so the UI cannot be
used to inject arbitrary arguments (no `-o`, `-proxy`, custom resolver, etc.).

Each tool always emits JSONL to stdout so the normalizer can parse it uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

STAGES = ["subfinder", "dnsx", "httpx", "naabu", "katana", "nuclei"]


@dataclass
class ToolSpec:
    name: str
    binary: str
    # Flags always present (Default mode = base only).
    base_flags: list[str]
    # Advanced allowlist: option_key -> builder(value) -> list[str] of CLI tokens.
    advanced: dict[str, Callable[[Any], list[str]]] = field(default_factory=dict)
    # Sane defaults for a fresh "Standard" profile's advanced block.
    defaults: dict[str, Any] = field(default_factory=dict)


def _flag(flag: str) -> Callable[[Any], list[str]]:
    """Boolean flag: emit `flag` when the value is truthy."""
    return lambda v: [flag] if v else []


def _valued(flag: str) -> Callable[[Any], list[str]]:
    """Valued flag: emit `flag value` when a value is present."""
    return lambda v: [flag, str(v)] if v not in (None, "", []) else []


def _csv(flag: str) -> Callable[[Any], list[str]]:
    """List value -> comma-joined single flag (e.g. -severity medium,high)."""
    return lambda v: [flag, ",".join(map(str, v))] if v else []


# ─── Fixed dropdowns (never free-text -> no SSRF / DNS-rebind vectors) ─
ALLOWED_RESOLVERS = {"1.1.1.1", "8.8.8.8"}
ALLOWED_NAABU_PORTS = {"top-100", "top-1000", "full"}
NUCLEI_DANGEROUS_TAGS = {"dos", "fuzz", "intrusive"}


def _naabu_ports(v: Any) -> list[str]:
    if v == "top-100":
        return ["-top-ports", "100"]
    if v == "top-1000":
        return ["-top-ports", "1000"]
    if v == "full":
        return ["-p", "1-65535"]
    # validated custom list "80,443,8080" — digits and commas only
    if isinstance(v, str) and all(part.isdigit() for part in v.split(",") if part):
        return ["-p", v]
    return ["-top-ports", "100"]


def _resolver(v: Any) -> list[str]:
    return ["-r", str(v)] if v in ALLOWED_RESOLVERS else []


REGISTRY: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        base_flags=["-silent", "-json"],
        advanced={
            "all": _flag("-all"),
            "recursive": _flag("-recursive"),
            "sources": _csv("-sources"),
            "max_time": _valued("-max-time"),
        },
        defaults={"all": False, "recursive": False, "sources": [], "max_time": 10},
    ),
    "dnsx": ToolSpec(
        name="dnsx",
        binary="dnsx",
        base_flags=["-silent", "-json", "-a", "-aaaa", "-cname"],
        advanced={
            # record-type booleans
            "ns": _flag("-ns"),
            "mx": _flag("-mx"),
            "txt": _flag("-txt"),
            "resolver": _resolver,  # fixed dropdown only
            "rate_limit": _valued("-rate-limit"),
        },
        defaults={"ns": False, "mx": False, "txt": False, "resolver": "1.1.1.1",
                  "rate_limit": 100},
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        base_flags=[
            "-silent", "-json", "-status-code", "-title",
            "-tech-detect", "-tls-grab", "-follow-redirects",
        ],
        advanced={
            "screenshot": _flag("-screenshot"),
            "favicon": _flag("-favicon"),
            "server": _flag("-server"),
            "max_redirects": _valued("-max-redirects"),
            "threads": _valued("-threads"),
            "rate_limit": _valued("-rate-limit"),
        },
        defaults={"screenshot": False, "favicon": False, "server": True,
                  "max_redirects": 3, "threads": 50, "rate_limit": 150},
    ),
    "naabu": ToolSpec(
        name="naabu",
        binary="naabu",
        # connect scan (no raw sockets / CAP_NET_RAW needed)
        base_flags=["-silent", "-json", "-scan-type", "connect"],
        advanced={
            "ports": _naabu_ports,   # top-100 / top-1000 / full / custom list
            "rate": _valued("-rate"),
        },
        defaults={"ports": "top-100", "rate": 1000},
    ),
    "katana": ToolSpec(
        name="katana",
        binary="katana",
        # katana uses -jsonl (not -json); -known-files takes ONE of {all,robotstxt,
        # sitemapxml} (not a comma list). Default to "all" for a capable basic crawl.
        base_flags=["-silent", "-jsonl", "-depth", "2", "-known-files", "all"],
        advanced={
            "depth": _valued("-depth"),
            "js_crawl": _flag("-jc"),
            "concurrency": _valued("-concurrency"),
            "rate": _valued("-rate-limit"),
        },
        defaults={"depth": 2, "js_crawl": False, "concurrency": 10, "rate": 150},
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        binary="nuclei",
        base_flags=["-silent", "-jsonl", "-severity", "medium,high,critical",
                    "-exclude-tags", "dos,fuzz,intrusive"],
        advanced={
            "severity": _csv("-severity"),
            "tags": _csv("-tags"),
            "rate_limit": _valued("-rate-limit"),
            "concurrency": _valued("-concurrency"),
        },
        defaults={"severity": ["medium", "high", "critical"], "tags": [],
                  "rate_limit": 150, "concurrency": 25, "intrusive_confirmed": False},
    ),
}


def default_tool_config() -> dict[str, Any]:
    """Build the tool_config JSON for the seeded 'Standard' profile."""
    cfg: dict[str, Any] = {"enabled_stages": list(STAGES)}
    for name, spec in REGISTRY.items():
        cfg[name] = {"mode": "default", **spec.defaults}
    return cfg


def build_command(
    tool: str,
    tool_cfg: dict[str, Any] | None,
    *,
    input_path: str | None = None,
    output_path: str | None = None,
    extra_target_list: str | None = None,
) -> list[str]:
    """Translate a tool's config into an argv list.

    Default mode ignores advanced options entirely and runs base_flags only.
    Advanced mode appends allowlisted flags on top of base_flags.
    I/O paths are supplied by the backend, never by the user.
    """
    spec = REGISTRY[tool]
    tool_cfg = tool_cfg or {}
    argv: list[str] = [spec.binary, *spec.base_flags]

    if tool_cfg.get("mode") == "advanced":
        for key, builder in spec.advanced.items():
            if key not in tool_cfg:
                continue
            # Nuclei dangerous tags require the second-gate confirmation.
            if tool == "nuclei" and key == "tags":
                requested = set(tool_cfg.get("tags") or [])
                if requested & NUCLEI_DANGEROUS_TAGS and not tool_cfg.get(
                    "intrusive_confirmed"
                ):
                    requested -= NUCLEI_DANGEROUS_TAGS
                argv += builder(sorted(requested))
                continue
            argv += builder(tool_cfg[key])

    # Backend-controlled I/O (input host list / target list / output file).
    # katana's list-input flag is -list (it has no -l); the others use -l.
    if input_path:
        if tool == "katana":
            argv += ["-list", input_path]
        elif tool in {"dnsx", "httpx", "naabu"}:
            argv += ["-l", input_path]
    if extra_target_list and tool == "nuclei":
        argv += ["-l", extra_target_list]
    if output_path:
        argv += ["-o", output_path]
    return argv
