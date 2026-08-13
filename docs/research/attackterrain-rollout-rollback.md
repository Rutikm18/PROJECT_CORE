# AttackTerrain rollout and rollback runbook

Date: 2026-08-14  
Scope: canonical finding queries, Mesh detection, validation/OpenRouter, unified
cases, central refresh, and responsive navigation.

This runbook treats database history as evidence. Rollback selects an earlier
application or policy version; it does not destroy findings, validation runs,
case events, or migration backups.

## Release gates

Before production rollout:

- back up the database and verify a restore in a non-production environment;
- run the full manager, agent, and frontend suites from the release artifact;
- prove All Incidents/terrain/validated set equality beyond the old 500-row
  client boundary;
- approve the Mesh labeled-sample quality floor and validation gold-set
  thresholds;
- approve which evidence may leave the deployment and whether the selected
  OpenRouter provider/account contract is sufficient;
- verify tenant/RBAC roles and case SLA ownership with product/security owners;
- record the currently deployed app, schema, validation policy, prompt/schema,
  provider/model, and frontend asset versions;
- exercise the OpenRouter kill switch and the previous-version rollback in
  staging;
- complete keyboard, 200% zoom, touch, Safari/WebKit, and Chromium checks at
  375, 768, 1024, 1440, and 1728 px.

Do not enable automated enforcement merely because unit tests pass. Labeled
quality evidence, privacy approval, and a controlled production observation
window are separate gates.

## Forward rollout

### 1. Prepare and back up

1. Announce the observation and rollback window; identify platform, database,
   SOC, and security owners.
2. Pause destructive retention/cleanup jobs for the window.
3. Take a consistent database backup and export the active settings/task-model
   configuration. Record checksums and restoration instructions.
4. Verify additive schema objects and indexes in staging. Do not use destructive
   down migrations for this release.

### 2. Deploy the backend dark

1. Deploy the new backend with OpenRouter disabled:
   `ATTACKLENS_OPENROUTER_ENABLED=false`.
2. Keep the previous application artifact ready. New validation and case tables
   are additive and may remain unused during rollback.
3. Verify health, authentication, terrain metadata, canonical finding queries,
   case reads/writes, validation observability, and integration health.
4. Confirm unknown terrains and validation failures produce visible metrics and
   no raw evidence appears in application/model telemetry.

### 3. Validate query and case parity

1. Compare totals/facets for All Incidents, every terrain including Mesh, and
   active/closed Validated Findings over representative windows.
2. Import browser-local cases only after the preview is accepted. The client
   writes `al_cases_migration_backup` before import and removes `al_cases` only
   after an idempotent server import succeeds.
3. Sample case actor, tenant, version, links, notes, timeline, and outbox records.
4. Keep legacy case endpoints/storage available through the agreed dual-read
   observation window; removal is a later release.

### 4. Recompute validation safely

1. Start with a small cursor-bounded batch and `only_unscored=true`.
2. Observe progress, queue age, error classes, abstention/review rate, latency,
   and database load. Exercise cancellation and resume.
3. Expand batch processing only while agreed error/backlog thresholds hold.
4. Never relabel `legacy_unassessed` rows as validated without a reproducible
   run against their evidence revision.

### 5. Enable model assistance gradually

1. Pin the approved validation task configuration and provider policy. Keep
   automatic final-verdict fallback disabled.
2. Run the approved gold/adversarial set, then shadow traffic. The model result
   is advisory and cannot mutate findings or cases.
3. Enable a small canary only after shadow thresholds pass. Monitor actual
   provider/model, error type, attempts, tokens, cost, and latency—not prompt or
   completion text.
4. Expand in explicit stages. High/critical model false-positive
   recommendations remain `needs_review` unless authoritative deterministic
   suppression independently passes.

### 6. Release the frontend

1. Deploy hashed frontend assets matching the backend query/meta contracts.
2. Verify central refresh completion, URL reload/back-forward behavior, relative
   presets, offline errors/retry, sidebar modes, drawers, and case migration.
3. Retain the previous asset bundle until the observation window closes.

## Rollback triggers

Rollback or disable the affected stage when any agreed threshold is crossed,
including:

- canonical view totals/facets diverge or cursor pagination skips/duplicates;
- unknown-terrain, validation error, or validation backlog alerts breach limits;
- Mesh precision/recall or analyst override rate regresses;
- unauthorized or cross-tenant case access, lost audit events, or idempotency
  violations appear;
- evidence/secret content is exposed to logs or an unapproved provider;
- OpenRouter cost, rate, latency, policy, or error thresholds are exceeded;
- refresh/navigation prevents a primary analyst workflow.

## Rollback procedure

1. **Stop new model calls first.** Set
   `ATTACKLENS_OPENROUTER_ENABLED=false` and restart the relevant backend workers.
   The deterministic validator and audit history remain available.
2. **Stop recomputation.** Cancel the durable job at a batch boundary. Preserve
   its cursor and run records so it can be inspected or resumed.
3. **Restore application behavior.** Redeploy the previous backend and frontend
   artifacts. Leave additive tables/columns in place; older code ignores them.
4. **Restore configuration.** Re-select the last approved task-model,
   prompt/schema, and validation-policy versions from the exported settings.
   If correction is needed, start a new recomputation; never delete or rewrite
   the superseded validation runs.
5. **Cases.** Stop imports and writes if authorization/audit integrity is in
   doubt. Server cases and events remain intact. A browser whose import did not
   complete still has `al_cases`; a completed import has
   `al_cases_migration_backup` for recovery/export. Do not automatically replay
   that backup into the old local model because it can duplicate post-import
   server changes.
6. **Database.** Prefer forward fixes. Restore the database backup only for
   confirmed data corruption and only under the database owner's recovery
   procedure, because restoration discards legitimate writes made after the
   backup. Do not drop additive validation/case tables as routine rollback.
7. Verify canonical reads, authentication, ingestion, and existing case access;
   then document the trigger, scope, timestamps, affected tenants/findings,
   evidence retained, and the conditions for re-entry.

## Closeout

End the rollback window only after parity and safety metrics stay within the
approved thresholds for the agreed duration, all imported-case telemetry is
accounted for, and the product/security owners sign off. Legacy endpoints,
maps, and browser storage can then be deprecated in a separate reversible
release.
