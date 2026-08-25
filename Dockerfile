# Ragnar — headless web UI in a container
#
# Runs the full Ragnar web dashboard and scanning engine with no e-Paper / GPIO
# hardware. The physical display, buttons, UPS and LED-matrix are Raspberry-Pi
# only and are skipped automatically in headless mode (RAGNAR_HEADLESS=1).
#
# Build:  docker compose build      (or: docker build -t ragnar .)
# Run:    docker compose up -d
# See docs/DOCKER.md for the full guide.

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    RAGNAR_HEADLESS=1 \
    RAGNAR_WEB_PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System packages Ragnar shells out to (network / security tooling) plus the
# shared libraries a few Python wheels load at runtime. Hardware-only packages
# (SPI, GPIO, e-Paper) are intentionally omitted — the container is headless.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        tcpdump \
        iproute2 \
        iputils-ping \
        iperf3 \
        iw \
        wireless-tools \
        net-tools \
        dnsutils \
        rfkill \
        lsof \
        procps \
        sqlite3 \
        openssh-client \
        curl \
        wget \
        ca-certificates \
        libpcap0.8 \
        libopenjp2-7 \
        libjpeg62-turbo \
        zlib1g \
        libssl3 \
        libffi8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ragnar

# Install Python deps first for layer caching. requirements.txt stays the single
# source of truth: we strip only the Raspberry-Pi-only packages (GPIO / SPI /
# UPS / LED-matrix / I2C), which cannot build or serve any purpose headless.
COPY requirements.txt /tmp/requirements.txt
RUN grep -viE '^(RPi\.GPIO|spidev|python-prctl|pisugar|smbus2|luma\.)' \
        /tmp/requirements.txt > /tmp/requirements-docker.txt \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && pip install --no-cache-dir -r /tmp/requirements-docker.txt \
    && apt-get purge -y gcc libc6-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Application source
COPY . /opt/ragnar

# Best-effort: nmap vulners script for CVE-tagged scans (needs network at build).
RUN wget -q -O /usr/share/nmap/scripts/vulners.nse \
        https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse \
    && nmap --script-updatedb >/dev/null 2>&1 \
    || echo "vulners.nse not fetched (offline build) — scans still work without it"

EXPOSE 8000

# Runtime state lives here; mount these for persistence (see docker-compose.yml).
VOLUME ["/opt/ragnar/data", "/opt/ragnar/config", "/opt/ragnar/certs"]

ENTRYPOINT ["/opt/ragnar/docker/entrypoint.sh"]
CMD ["python3", "headlessRagnar.py"]
