ARG UBUNTU_IMAGE=ubuntu:24.04
FROM ${UBUNTU_IMAGE} AS builder
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-venv python3-dev build-essential libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
COPY requirements-runtime.lock requirements-linux.txt /build/
RUN /opt/venv/bin/pip install --no-cache-dir -r /build/requirements-linux.txt

FROM ${UBUNTU_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    WAF_ENV_FILE=/app/runtime/admin.env \
    WAF_DATABASE=/app/runtime/waf.sqlite3 \
    WAF_DATAPLANE_AUTOSTART=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates iproute2 nftables libpcap0.8t64 libnetfilter-queue1 tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY waf ./waf
COPY LICENSE VERSION COPYRIGHT.md ./
COPY static ./static
COPY docs ./docs
COPY mgrnic.ini ./mgrnic.ini
RUN mkdir -p /app/runtime && chmod 700 /app/runtime
EXPOSE 8300 8301 8443
STOPSIGNAL SIGTERM
CMD ["python", "-m", "waf.cli", "serve"]
