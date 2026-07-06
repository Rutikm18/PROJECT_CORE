# =============================================================================
#  manager/ThreatIntel.Dockerfile — central AttackLens threat-intel service
#
#  Three-stage build (mirrors manager/Dockerfile):
#    1. deps   — install Python packages (threat-intel subset only)
#    2. build  — compile .py → .pyc, strip source files
#    3. final  — minimal runtime image (bytecode only, no .py source)
#
#  This image runs only the shared threat-intel API and feed workers.
#  It is placed centrally and queried by multiple manager deployments.
# =============================================================================

# ── Stage 1: install Python deps (threat-intel subset) ───────────────────────
FROM python:3.12-slim AS deps

WORKDIR /build

COPY manager/requirements-threat-intel.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# ── Stage 2: compile source to bytecode + strip .py files ────────────────────
FROM python:3.12-slim AS build

WORKDIR /build

COPY shared/   /build/shared/
COPY manager/  /build/manager/

# threat-intel serves no UI — drop the dashboard and Postgres init scripts
# that COPY manager/ brings along (the manager image keeps them)
RUN rm -rf /build/manager/dashboard /build/manager/postgres-init

RUN python -m compileall -b -q /build/shared /build/manager

RUN find /build -name "*.py" -not -name "__init__.py" -delete && \
    find /build -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

RUN find /build -name "__init__.pyc" | while read f; do \
        stub="${f%.pyc}"; \
        [ -f "$stub.py" ] || touch "$stub.py"; \
    done

# ── Stage 3: minimal runtime image ───────────────────────────────────────────
FROM python:3.12-slim AS final

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 threatintel

WORKDIR /app

COPY --from=deps /install /usr/local

COPY --chown=threatintel:threatintel --from=build /build/shared/   /app/shared/
COPY --chown=threatintel:threatintel --from=build /build/manager/  /app/manager/

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
