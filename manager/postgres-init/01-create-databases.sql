-- Runs once, on first container init (docker-entrypoint-initdb.d convention).
-- POSTGRES_DB env var already creates "manager"; this adds the others so each
-- originally-separate SQLite file/store gets its own physical Postgres
-- database — same isolation, zero table-name collisions.
--
-- Idempotent: plain `CREATE DATABASE` aborts the whole init script if the DB
-- already exists. The SELECT ... \gexec pattern only creates a database when it
-- is missing, so re-running this by hand (or against a partially-initialised
-- volume) is safe.
SELECT 'CREATE DATABASE intel'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'intel')\gexec

SELECT 'CREATE DATABASE threat_intel'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'threat_intel')\gexec
