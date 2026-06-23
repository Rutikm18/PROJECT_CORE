-- Runs once, on first container init (docker-entrypoint-initdb.d convention).
-- POSTGRES_DB env var already creates "manager"; this adds the others so each
-- originally-separate SQLite file/store gets its own physical Postgres
-- database — same isolation, zero table-name collisions.
CREATE DATABASE intel;         -- manager/manager/indexer.py (per-manager-instance)
CREATE DATABASE threat_intel;  -- manager/manager/threat_intel_service.py (centrally shared)
