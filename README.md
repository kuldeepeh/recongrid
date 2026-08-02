# ReconGrid — Attack Surface Management (Module 1)

A self-hosted Attack Surface Management (ASM) platform that discovers and tracks a
target's external attack surface **over time** — subdomains, DNS, live hosts, open
ports, HTTP fingerprints, TLS certs, crawled endpoints, and vulnerability findings —
and surfaces every change on a diff timeline.

---

## What this project is (and is not)

**The scanning is done by third-party open-source tools. This project's engineering
value is the orchestration around them**, not the scanning logic:

| Recon engine | Author / Project | License | What it does here |
|---|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | ProjectDiscovery | MIT | Passive subdomain enumeration |
| [DNSX](https://github.com/projectdiscovery/dnsx) | ProjectDiscovery | MIT | DNS resolution / record lookup |
| [HTTPX](https://github.com/projectdiscovery/httpx) | ProjectDiscovery | MIT | HTTP probing / fingerprinting |
| [Naabu](https://github.com/projectdiscovery/naabu) | ProjectDiscovery | MIT | Port scanning |
| [Katana](https://github.com/projectdiscovery/katana) | ProjectDiscovery | MIT | Web crawling / endpoint discovery |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery | MIT | Template-based vulnerability scanning |

**All credit for the recon capability belongs to [ProjectDiscovery](https://github.com/projectdiscovery).**
What *this* codebase builds is:

- **Orchestration** — chaining the six tools into a resumable, stage-by-stage pipeline.
- **Scheduling** — recurring scans via Celery Beat.
- **Historical diffing** — detecting new subdomains, newly opened ports, cert rotations,
  changed fingerprints, and new findings between runs (the Censys-style "diff over time").
- **Normalization & dedup** — turning noisy, repetitive tool output into one clean row
  per real asset.
- **A dashboard** — per-tool tabs with configurable options, a diff timeline, and full
  visibility into the exact command that ran.

---

## Authorized use only

This tool performs active reconnaissance. **Only ever point it at systems you own or
have explicit written authorization to test.**

- The default seed target is a **self-owned lab** (self-hosted VPS / DVWA / Juice Shop).
- Adding any new target requires an explicit **authorization attestation** before the
  first scan can run.
- The recon tools run inside an **isolated sandbox container** whose network egress is
  restricted to authorized target scope only — a bug in application-layer scope checking
  cannot accidentally scan the public internet.

Unauthorized scanning of third-party systems may be illegal. You are responsible for
how you use this software.

---

## Architecture

See [`docs/module1-asm-architecture.md`](docs/module1-asm-architecture.md) for the full
design. Short version:

```
Next.js dashboard  --HTTP-->  FastAPI API  -->  PostgreSQL (assets, scans, diffs)
                                   |
                                   v
                              Redis (broker + cache)
                                   |
                     Celery workers + Celery Beat
                                   |
                                   v
                    Isolated scan-sandbox container
        (Subfinder . DNSX . HTTPX . Naabu . Katana . Nuclei)
```

- **Backend:** FastAPI + Celery (Python)
- **Frontend:** Next.js (React, TypeScript, Tailwind)
- **Data:** PostgreSQL + Redis
- **Deployment:** Docker Compose, isolated scan sandbox
- **Auth:** single-user (one admin password)

---

## Quick start

```bash
cp .env.example .env
# edit .env - at minimum set ADMIN_PASSWORD and SECRET_KEY

docker compose up --build
```

Then open the dashboard at `http://localhost:3000` and log in with the
`ADMIN_PASSWORD` you set.

The stack seeds one pre-authorized lab target on first boot so you can run a scan
immediately.

### Services

| Service | Port | Purpose |
|---|---|---|
| `frontend` | 3000 | Next.js dashboard |
| `api` | 8000 | FastAPI REST API |
| `postgres` | 5432 | Database |
| `redis` | 6379 | Celery broker + cache |
| `worker` | - | Celery worker (runs scans) |
| `beat` | - | Celery Beat (schedules + cleanup) |
| `scan-sandbox` | - | Isolated recon-tool runner |

---

## Project layout

```
backend/     FastAPI app, Celery tasks, tool orchestration
frontend/    Next.js dashboard
sandbox/     Dockerfile for the recon-tool sandbox image
docs/        Architecture documentation
docker-compose.yml
```

---

## Development notes

- Recon tools are **not** vendored - the sandbox image installs official ProjectDiscovery
  binaries at build time (see `sandbox/Dockerfile`).
- Every executed tool command is stored (`stage_executions.command`) and shown in the UI,
  so what ran is never a black box.
- Two scan modes per tool: **Default** (one hardcoded, lab-safe command) and **Advanced**
  (a curated allowlist of flags - not the tool's full `--help`).
