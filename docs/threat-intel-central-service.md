# Central Threat Intel Service

AttackLens should run threat intelligence as a central service when multiple
managers or dashboards need the same NVD/CVE/IOC data.

## Ownership

- `manager.db`: owned by each manager deployment. Stores agent enrollment,
  agent sessions, API keys, and raw telemetry payload indexes.
- `intel.db`: owned by the central `threat-intel` service. Stores NVD CVEs,
  IOC cache, feed health, and shared threat-intel records.

This keeps high-volume agent ingest independent from slower external feed
collection.

## Runtime

- `manager`: receives agent telemetry, writes raw data, runs local findings and
  dashboard APIs.
- `rabbitmq`: absorbs bursts, supports worker prefetch, chunking, and dead-letter
  isolation.
- `threat-intel`: continuously syncs NVD modified CVEs and IOC feeds, then
  exposes reusable APIs on port `8090`.

## APIs

Central service:

- `GET /api/v1/intel/summary`
- `GET /api/v1/intel/feeds`
- `GET /api/v1/intel/cves`
- `POST /api/v1/intel/correlate/packages`
- `GET /api/v1/intel/architecture`

Manager proxy/fallback:

- `GET /api/v1/threat/intel/summary`
- `GET /api/v1/threat/intel/cves`
- `GET /api/v1/threat/intel/architecture`

When `THREAT_INTEL_URL` is configured, manager proxies shared intel requests to
the central service. If central intel is unavailable, local manager APIs degrade
to local cached data instead of blocking agent ingest.

## Failure Handling

- NVD calls are rate-limited and page-bounded.
- Feed failures are persisted in `feed_health`.
- Manager ingest does not wait on central threat-intel.
- Dashboards can still show local findings when central intel is degraded.
- RabbitMQ protects telemetry handling with bounded queues, prefetch, and DLQ.
