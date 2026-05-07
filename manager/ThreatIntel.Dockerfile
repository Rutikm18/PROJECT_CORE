# =============================================================================
#  manager/ThreatIntel.Dockerfile — central AttackLens threat-intel service
#
#  This image runs only the shared threat-intel API and feed workers. It is meant
#  to be placed centrally and queried by multiple manager/dashboard deployments.
# =============================================================================

FROM python:3.12-slim AS deps

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY manager/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

FROM python:3.12-slim AS final

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 threatintel

WORKDIR /app

COPY --from=deps /install /usr/local
COPY --chown=threatintel:threatintel shared/ /app/shared/
COPY --chown=threatintel:threatintel manager/ /app/manager/

RUN chmod +x /app/manager/scripts/threat-intel-entrypoint.sh && \
    mkdir -p /app/data /app/logs && \
    chown -R threatintel:threatintel /app/data /app/logs

USER threatintel

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD curl -fs http://localhost:8090/health || exit 1

ENTRYPOINT ["/app/manager/scripts/threat-intel-entrypoint.sh"]
