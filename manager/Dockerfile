# =============================================================================
#  manager/Dockerfile — Production image for the mac_intel manager
#
#  Multi-stage: deps layer cached separately from app code.
#  Runs as a non-root user (uid 1000).
# =============================================================================

FROM python:3.12-slim AS deps

WORKDIR /app

# Install dependencies in a separate layer (cache-friendly)
COPY manager/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── App layer ─────────────────────────────────────────────────────────────────
FROM deps AS app

# Create a non-root user
RUN useradd -m -u 1000 macintel
WORKDIR /app

# Copy application code
COPY --chown=macintel:macintel shared/          /app/shared/
COPY --chown=macintel:macintel manager/         /app/manager/
COPY --chown=macintel:macintel manager/scripts/keygen.py /app/scripts/keygen.py

# Runtime directories (writable by the app user)
RUN mkdir -p /app/data /app/logs /app/certs && \
    chown -R macintel:macintel /app/data /app/logs

USER macintel

ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -fsk https://localhost:8443/health || exit 1

CMD ["python3", "-m", "uvicorn", "manager.manager.server:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-certfile", "/app/certs/server.crt", \
     "--ssl-keyfile",  "/app/certs/server.key"]
