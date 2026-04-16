# =============================================================================
#  manager/Dockerfile — Production image for the Jarvis manager
#
#  Multi-stage build: deps layer cached separately from app code.
#  Runs as a non-root user (uid 1000: jarvis).
#
#  Build:
#    docker build -f manager/Dockerfile -t jarvis-manager .
#
#  Run (quick test):
#    docker run -p 8443:8443 -e PUBLIC_IP=1.2.3.4 jarvis-manager
# =============================================================================

# ── Stage 1: install Python deps ──────────────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl openssl \
    && rm -rf /var/lib/apt/lists/*

COPY manager/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── Stage 2: application ──────────────────────────────────────────────────────
FROM deps AS app

# Create a non-root user
RUN useradd -m -u 1000 jarvis

WORKDIR /app

# Copy application code
COPY --chown=jarvis:jarvis shared/              /app/shared/
COPY --chown=jarvis:jarvis manager/             /app/manager/

# Runtime directories (writable by the app user)
RUN mkdir -p /app/data /app/logs /app/certs && \
    chown -R jarvis:jarvis /app/data /app/logs /app/certs && \
    chmod +x /app/manager/scripts/entrypoint.sh

USER jarvis

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Ports ──────────────────────────────────────────────────────────────────────
# 8443 = direct HTTPS (default)
# 8080 = plain HTTP (when running behind a reverse proxy like Caddy/nginx)
EXPOSE 8443 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -fsk https://localhost:${BIND_PORT:-8443}/health || exit 1

ENTRYPOINT ["/app/manager/scripts/entrypoint.sh"]
