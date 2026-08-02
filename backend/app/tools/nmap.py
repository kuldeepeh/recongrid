"""nmap enrichment: service/version (-sV) and OS (-O) detection.

Runs after naabu. naabu tells us *which* ports are open; nmap tells us *what* is
running on them (product + version) and best-effort OS fingerprint. Results update
the existing Port rows in place. Third-party tool: nmap (https://nmap.org), used via
its stable XML output (-oX).

Fail-safe by design: any nmap error is caught and returned, never raised, so a
version-detection hiccup can't break an otherwise-successful scan pipeline.
"""
from __future__ import annotations

import shlex
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.config import settings


@dataclass
class NmapResult:
    command: str
    exit_code: int
    started_at: datetime
    completed_at: datetime
    # ip -> {"os": str|None, "ports": {port: {"name","product","version"}}}
    hosts: dict = field(default_factory=dict)
    updated: int = 0
    stderr: str = ""


def build_nmap_command(ip: str, ports: list[int], os_detect: bool) -> list[str]:
    portspec = ",".join(str(p) for p in sorted(set(ports)))
    argv = ["nmap", "-sV", "-Pn", f"-{settings.nmap_timing}", "-p", portspec]
    if os_detect:
        argv += ["-O", "--osscan-guess"]
    argv += ["-oX", "-", ip]
    return argv


def _parse_nmap_xml(xml_text: str) -> dict:
    hosts: dict = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        entry: dict = {"os": None, "ports": {}}
        # OS: highest-accuracy osmatch
        os_el = host.find("os")
        if os_el is not None:
            best = None
            best_acc = -1
            for m in os_el.findall("osmatch"):
                acc = int(m.get("accuracy", "0"))
                if acc > best_acc:
                    best_acc, best = acc, m.get("name")
            if best:
                entry["os"] = f"{best} ({best_acc}%)"
        # ports/services
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                pid = p.get("portid")
                svc = p.find("service")
                if svc is None or pid is None:
                    continue
                entry["ports"][int(pid)] = {
                    "name": svc.get("name"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                }
        hosts[ip] = entry
    return hosts


def run_nmap(ip: str, ports: list[int], os_detect: bool) -> NmapResult:
    argv = build_nmap_command(ip, ports, os_detect)
    command = " ".join(shlex.quote(a) for a in argv)
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=settings.nmap_timeout
        )
        hosts = _parse_nmap_xml(proc.stdout)
        return NmapResult(
            command=command,
            exit_code=proc.returncode,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            hosts=hosts,
            stderr=proc.stderr[-2000:] if proc.stderr else "",
        )
    except subprocess.TimeoutExpired:
        return NmapResult(
            command=command, exit_code=124, started_at=started,
            completed_at=datetime.now(timezone.utc),
            stderr=f"nmap timeout after {settings.nmap_timeout}s",
        )
    except FileNotFoundError as exc:
        return NmapResult(
            command=command, exit_code=127, started_at=started,
            completed_at=datetime.now(timezone.utc), stderr=f"nmap not found: {exc}",
        )
