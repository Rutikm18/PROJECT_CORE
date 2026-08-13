# ADR-002 — Canonical finding and validation lifecycle

**Status:** Accepted and implemented in the current working tree.  
**Date:** 2026-08-14.  
**Owners:** Security engineering, SOC product, and platform engineering.

## Context

AttackTerrain, All Incidents, Validated Findings, and case management previously
mixed four different meanings of validation. That made it possible for counts,
filters, and lifecycle decisions to disagree even when every view referred to
the same underlying security event.

The system needs stable language and one source of truth before model-assisted
validation can safely influence analyst workflow.

## Decision

The canonical record is a finding. Terrain pages and Validated Findings are
filtered projections of that record; a case links to one or more canonical
findings and never copies them.

The following terms have distinct owners and fields:

1. **Detection eligibility** is owned by the detector. Confidence and
   deterministic pre-emission gates decide whether signals may become a
   finding.
2. **Finding validation** is owned by a versioned validation policy. It produces
   exactly one of `validated`, `rejected`, `needs_review`, `inconclusive`, or
   `error` from immutable evidence references.
3. **Threat-intelligence corroboration** is a named validation stage. It records
   sources, freshness, and errors; missing external enrichment is not silently
   equivalent to a false positive.
4. **Analyst disposition** is the human workflow state, including new,
   investigating, accepted risk, false positive, resolved, and closed. It does
   not overwrite the machine-validation history.

These set relationships are contractual:

```text
AttackTerrain(T, Q) = AllIncidents(Q AND terrain = T)

ValidatedFindings(Q) =
  AllIncidents(Q AND validation_state = validated)
```

They apply with the same time window, active/closed view, authorization scope,
sort, and filter predicates. `validation_state=validated` remains required in
both active and closed Validated Findings views.

Every validation attempt is append-only and records its evidence revision,
policy/schema version, gate results, model/provider identity when used,
corroboration provenance, usage/cost metadata, and terminal failure class.
Recomputation creates a new run; it does not rewrite old reasoning.

An LLM is an advisory component behind the `ValidationModel` port. It cannot
directly mutate a finding, disposition, case, permission, or evidence object.
High-confidence model rejection of a high/critical finding routes to human
review unless an independently authoritative deterministic rule permits
suppression.

## Consequences

- One backend `FindingQuery` compiler owns list filters, counts, facets, sort,
  and cursor pagination.
- Unknown terrain never inherits another terrain's evidence policy.
- Model and external-source failures are visible as review, inconclusive, or
  error outcomes according to the explicit error policy.
- Cases use authenticated, tenant-scoped, transactional links and an
  append-only timeline.
- Historical findings without reproducible validation evidence remain
  `legacy_unassessed`; they are not inferred to be validated from old scores.

The tradeoff is a larger append-only audit history and explicit review backlog.
That cost is intentional: it preserves reproducibility and prevents automation
confidence from becoming unaudited enforcement.

## Verification and change control

Contract tests enforce both projection equalities, including datasets larger
than the former client fetch limit. Policy, prompt, model, schema, and evidence
changes require a new version. Reversing a change means selecting the previous
version and recomputing affected findings; deleting prior validation runs is not
an acceptable rollback.

Product/security owners still have to approve the labeled quality thresholds,
which evidence may leave a deployment, SLA policy, and rollout observation
windows before production enforcement is enabled.
