#!/usr/bin/env bash
# =============================================================================
#  scripts/backup.sh — Backup Postgres databases + Docker volumes
#
#  Usage:
#    # Full backup (all DBs + volumes):
#    sudo ./scripts/backup.sh /backup/dir
#
#    # Restore (from a previous backup):
#    sudo ./scripts/backup.sh /backup/dir --restore
#
#    # S3 sync (upload backup to S3):
#    sudo ./scripts/backup.sh /backup/dir --s3-bucket my-bucket
# =============================================================================
set -euo pipefail

BACKUP_DIR="${1:-/tmp/attacklens-backup}"
MODE="${2:-backup}"  # backup | restore
S3_BUCKET="${3:-}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYN}[info]${NC}  $*"; }
ok()   { echo -e "${GRN}[ok]${NC}    $*"; }
err()  { echo -e "${RED}[err]${NC}   $*"; }

command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }

# ── Detect Postgres container ─────────────────────────────────────────────────
PG_CONTAINER=$(docker compose ps -q postgres 2>/dev/null || docker ps --filter name=postgres --format '{{.Names}}' | head -1)
if [ -z "$PG_CONTAINER" ]; then
  err "No postgres container found. Is docker compose running?"
  exit 1
fi

if [ "$MODE" = "backup" ]; then
  info "Backup mode — target: ${BACKUP_DIR}/${TS}"
  mkdir -p "${BACKUP_DIR}/${TS}"

  # ── Backup Postgres databases ─────────────────────────────────────────────
  for DB in manager intel threat_intel; do
    info "Dumping database: ${DB}"
    docker exec "$PG_CONTAINER" pg_dump -U attacklens -d "$DB" \
      --no-owner --no-acl \
      -F c \
      > "${BACKUP_DIR}/${TS}/${DB}.dump" 2>/dev/null || \
    docker exec "$PG_CONTAINER" pg_dump -U attacklens -d "$DB" \
      -F c \
      > "${BACKUP_DIR}/${TS}/${DB}.dump"
    ok "  ${DB}.dump ($(du -h "${BACKUP_DIR}/${TS}/${DB}.dump" | cut -f1))"
  done

  # ── Backup .secrets file ──────────────────────────────────────────────────
  if docker exec "$PG_CONTAINER" test -f /app/data/.secrets 2>/dev/null; then
    docker cp "attacklens-manager:/app/data/.secrets" "${BACKUP_DIR}/${TS}/.secrets" 2>/dev/null
  fi

  ok "Backup complete: ${BACKUP_DIR}/${TS}"

  # ── S3 upload ────────────────────────────────────────────────────────────
  if [ -n "$S3_BUCKET" ]; then
    command -v aws >/dev/null 2>&1 || { err "aws CLI not found, skipping S3"; exit 0; }
    info "Uploading to s3://${S3_BUCKET}/"
    aws s3 cp "${BACKUP_DIR}/${TS}" "s3://${S3_BUCKET}/${TS}/" --recursive
    ok "S3 upload complete"
    # Clean local backup after upload (optional)
    # rm -rf "${BACKUP_DIR}/${TS}"
  fi

elif [ "$MODE" = "restore" ]; then
  RESTORE_SRC="${BACKUP_DIR}"
  info "Restore mode — source: ${RESTORE_SRC}"

  for DB in manager intel threat_intel; do
    DUMP_FILE="${RESTORE_SRC}/${DB}.dump"
    if [ ! -f "$DUMP_FILE" ]; then
      warn "  ${DB}.dump not found, skipping"
      continue
    fi
    info "Restoring database: ${DB} from ${DUMP_FILE}"
    # Drop existing connections and restore
    docker exec "$PG_CONTAINER" psql -U attacklens -c \
      "SELECT pg_terminate_backend(pg_stat_activity.pid)
       FROM pg_stat_activity
       WHERE pg_stat_activity.datname = '${DB}' AND pid <> pg_backend_pid();" 2>/dev/null || true
    docker exec -i "$PG_CONTAINER" pg_restore -U attacklens -d "$DB" \
      --clean --if-exists --no-owner --no-acl \
      < "$DUMP_FILE"
    ok "  ${DB} restored"
  done

  # ── Restore .secrets ─────────────────────────────────────────────────────
  if [ -f "${RESTORE_SRC}/.secrets" ]; then
    docker cp "${RESTORE_SRC}/.secrets" "attacklens-manager:/app/data/.secrets" 2>/dev/null || true
    ok "  .secrets restored"
  fi

  ok "Restore complete. Restart containers: docker compose restart"
fi
