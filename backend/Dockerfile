# ─── Recon tool build stage ──────────────────────────────────────────
# Compiles the third-party ProjectDiscovery binaries (MIT, ProjectDiscovery).
# Each tool pins its own (increasingly new) Go version, so we let Go's toolchain
# auto-fetch whatever each module needs instead of chasing the base image tag.
FROM golang:1.25-bookworm AS tools

ENV GOTOOLCHAIN=auto

# libpcap-dev provides pcap.h, required to *compile* naabu.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out
RUN mkdir -p /out
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Application image (shared by api / worker / beat) ────────────────
# The worker runs the recon tools directly (TOOL_EXECUTION_MODE=local), so the
# binaries live here on PATH — no docker-in-docker, no sibling sandbox container.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# libpcap0.8 = naabu runtime dep; nmap = service/version + OS detection;
# ca-certificates for TLS to passive sources.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates nmap \
 && rm -rf /var/lib/apt/lists/*

# Recon binaries go in a dedicated dir that is FIRST on PATH. This matters because
# pip (via FastAPI's dependencies) installs a Python "httpx" CLI into /usr/local/bin
# that would otherwise shadow ProjectDiscovery's httpx binary. Keeping our tools
# ahead on PATH guarantees the recon binaries always win.
COPY --from=tools /out/ /opt/recon/bin/
ENV PATH="/opt/recon/bin:${PATH}"

# Bake the nuclei template set into the image so scans don't download mid-run.
RUN nuclei -update-templates -silent || true

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
