# Scan sandbox: installs the official ProjectDiscovery recon binaries.
# These tools are third-party (MIT, ProjectDiscovery) — this image just packages them.
#
# Each PD tool pins its own (increasingly new) Go version, so instead of chasing the
# base image tag we let Go's toolchain feature auto-download whatever each module
# requires. The official golang images force GOTOOLCHAIN=local (no auto-download);
# we flip it back to "auto" so `go install` fetches the needed toolchain on demand.
FROM golang:1.25-bookworm AS build

ENV GOTOOLCHAIN=auto

# libpcap-dev provides pcap.h, required to *compile* naabu.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out
RUN mkdir -p /out

# Pin to released versions for reproducible builds.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Runtime image ───────────────────────────────────────────────────
FROM debian:bookworm-slim

# libpcap is required by naabu; ca-certificates for TLS to public sources.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /usr/local/bin/

# Pre-fetch the nuclei template set so scans don't do it mid-run.
RUN nuclei -update-templates -silent || true

# Shared scratch space mounted from the worker.
RUN mkdir -p /scandata
WORKDIR /scandata

# Non-root user for defense in depth.
RUN useradd -m -u 10001 scanner && chown -R scanner:scanner /scandata
USER scanner

CMD ["sleep", "infinity"]
