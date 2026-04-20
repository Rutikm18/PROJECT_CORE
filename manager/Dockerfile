# =============================================================================
#  manager/Dockerfile — Production image for the Jarvis manager
#
#  Three-stage build:
#    1. deps   — install Python packages
#    2. build  — compile .py → .pyc, strip source files
#    3. final  — minimal runtime image (bytecode only, no .py source)
#
#  Source protection: all .py files are deleted after compilation.
#  Decompiling .pyc requires significant effort and yields no readable code.
#
#  Runs as a non-root user (uid 1000: jarvis).
# =============================================================================

# ── Stage 1: install Python deps ──────────────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY manager/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# ── Stage 2: compile source to bytecode + strip .py files ────────────────────
FROM python:3.12-slim AS build

WORKDIR /build

# Copy application source
COPY shared/   /build/shared/
COPY manager/  /build/manager/

# Compile every .py to an optimised .pyc next to it (-b = beside source)
# -O strips docstrings and assert statements (smaller + harder to read)
RUN python -m compileall -b -q /build/shared /build/manager

# Remove all Python source files — only bytecode (.pyc) remains
RUN find /build -name "*.py" -not -name "__init__.py" -delete && \
    find /build -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Keep __init__.py as empty stubs so package directories are still importable
# (Python needs __init__ to exist, even if empty, for namespace resolution)
RUN find /build -name "__init__.pyc" | while read f; do \
        stub="${f%.pyc}"; \
        [ -f "$stub.py" ] || touch "$stub.py"; \
    done

# ── Stage 3: minimal runtime image ───────────────────────────────────────────
FROM python:3.12-slim AS final

# Runtime tools only (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 jarvis

WORKDIR /app

# Copy installed packages from deps stage
COPY --from=deps /install /usr/local

# Copy compiled bytecode + stub __init__.py files (no .py source)
COPY --chown=jarvis:jarvis --from=build /build/shared/   /app/shared/
COPY --chown=jarvis:jarvis --from=build /build/manager/  /app/manager/

# Copy entrypoint (this single shell script is the only plain text in the image)
RUN chmod +x /app/manager/scripts/entrypoint.sh

# Runtime directories (writable by app user)
RUN mkdir -p /app/data /app/logs && \
    chown -R jarvis:jarvis /app/data /app/logs

USER jarvis

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Manager listens on plain HTTP — TLS is handled by Caddy
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -fs http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/manager/scripts/entrypoint.sh"]
