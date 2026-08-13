# OpenRouter and AttackTerrain validation-engine research

Retrieved: **2026-08-13**. Sources are official OpenRouter, NIST, OWASP, and OpenAI documentation. This note distinguishes transport/schema guarantees from factual finding validation: OpenRouter can shape, route, and observe an LLM call, but it does not establish that a security finding is true.

## Recommended decision boundary

AttackTerrain should remain the validation authority:

1. Normalize and validate immutable evidence deterministically.
2. Run deterministic correlation, provenance, freshness, tenant, asset, and policy checks.
3. Ask an LLM for a structured, cited recommendation only when useful.
4. Validate the response locally and resolve every cited evidence ID.
5. Return `inconclusive` for malformed, unsupported, timed-out, or insufficient results.
6. Require an analyst for critical/high-impact decisions and policy exceptions.
7. Let an application service—not the LLM—perform the auditable state transition.

JSON/schema compliance proves only that the response has the expected shape. It does not prove truth, corroboration, or authorization.

## Repository gap mapping

### `manager/manager/ai/providers.py`

| Current behavior | Gap or risk | Recommended change |
|---|---|---|
| `OpenRouterProvider` sends an OpenAI-compatible chat request. | The attribution header is `X-Title`; OpenRouter documents `X-OpenRouter-Title`. Attribution headers are optional, not authentication controls. | Rename it if attribution is desired; keep the Bearer key server-side. |
| Request contains a model and messages only. | No `provider.require_parameters`, ZDR, data-collection restriction, explicit fallback policy, or strict response schema. | Add purpose-specific provider preferences and `json_schema` structured output. |
| Response text is accepted from `choices[0]`. | No local schema validation and no refusal/empty-content/`finish_reason` handling. | Decode and validate locally; map incomplete/refused/invalid output to `inconclusive`. |
| Only a top-level `error` in the JSON body is checked. | OpenRouter can return mid-stream/in-band errors after HTTP processing begins; typed `error_type` and `Retry-After` are not represented. | Add a typed provider exception model and distinguish transient, permanent, policy, auth, budget, and malformed-output failures. |
| `AIResponse.model` is copied from configured model. | A routed/fallback request may use another actual model/provider. Generation ID, actual provider, cost, finish reason, cache/reasoning tokens, and routing attempts are lost. | Read the response model and store router/generation metadata plus full usage accounting. |
| No `X-OpenRouter-Metadata` opt-in. | Provider selection, retry attempts, fallback, and guardrail pipeline are not auditable. | Send `X-OpenRouter-Metadata: enabled` and decode unknown fields permissively. |
| Generic resilient HTTP transport is used. | The provider layer does not expose whether `Retry-After` was honored or whether a retry duplicated a validation job. | Bound retries by a task deadline and make the caller idempotent by validation-run key. |
| The configured OpenRouter default is a free model. | OpenRouter documents free-model limits as unsuitable for typical production use; model availability and behavior can also change. | Pin an evaluated production model/endpoint policy and reject expired or incompatible models during configuration checks. |

### `manager/manager/attacklens/ai_validator.py`

| Current behavior | Gap or risk | Recommended change |
|---|---|---|
| A weighted score combines deterministic factors and an LLM vote. | The architecture correctly avoids trusting the LLM alone, but `promoted` is still an automatic terminal decision with no explicit `needs_review` state. | Separate `recommended_verdict` from workflow status; add `needs_review` and analyst approval rules. |
| High-confidence LLM false positives can veto a finding. | A stochastic/untrusted response can suppress a real incident. Only KEV/hash truth overrides it. | Make an AI FP veto a review/triage recommendation unless an independently approved deterministic suppression policy also passes. |
| Transient failures are recognized by matching strings such as `429` and `503`. | This is brittle and omits the stable OpenRouter `error_type`, `Retry-After`, 502/provider-unavailable, timeout variants, and in-band errors. | Route typed failures through a bounded retry policy; never retry validation/auth/payment/policy errors. |
| `_chat_with_fallback` tries three free, heterogeneous models. | Final verdict semantics, calibration, context capacity, privacy eligibility, schema support, and cost can change silently. `_provider_used` is discarded. | Disable model fallback for final verdicts. If availability fallbacks are later approved, permit only separately evaluated equivalents and persist the actual attempt chain. |
| `AIProvider.parse_json` extracts the first apparent object and returns `{}` on failure. | This is lenient parsing, not strict schema validation. Missing fields acquire defaults, including confidence `0.5`. | Use a versioned JSON Schema/Pydantic model with required fields and `additionalProperties: false`; malformed results become `inconclusive`. |
| `key_evidence` is arbitrary model-generated text. | It cannot prove which immutable facts support the verdict and may hallucinate. | Require stored evidence IDs and reject unresolved, cross-tenant, stale, or unauthorized references. |
| The system prompt says endpoint data inside `<untrusted>` tags is untrusted, but `_build_ai_prompt` does not wrap the evidence block in those tags. | The intended trust boundary is not actually encoded in the request. | Serialize evidence as a clearly delimited data object and add input scanning; keep all authorization and state changes outside the model. |
| Only total tokens are retained in `AiVerdict`. | No request/generation correlation, prompt/schema version, actual model/provider, cost, retries, latency, or guardrail result is recorded. | Add a durable `validation_run` audit record and metadata-only telemetry. |
| Model output is directly converted to score after basic field coercion. | Confidence is not calibrated against analyst ground truth, and a valid JSON response can still be false. | Calibrate per model/prompt/schema version and release only after gold-set and adversarial eval gates. |

## Recommended OpenRouter request baseline

For final verdicts, favor reproducibility over transparent provider/model switching:

```json
{
  "model": "<explicit-evaluated-model>",
  "provider": {
    "allow_fallbacks": false,
    "require_parameters": true,
    "zdr": true,
    "data_collection": "deny"
  },
  "response_format": {
    "type": "json_schema",
    "json_schema": {
      "name": "attackterrain_finding_validation_v1",
      "strict": true,
      "schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "inconclusive"]
          },
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "reason_codes": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8
          },
          "evidence_ids": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 16
          },
          "summary": {"type": "string", "maxLength": 1200}
        },
        "required": ["verdict", "confidence", "reason_codes", "evidence_ids", "summary"]
      }
    }
  }
}
```

Also send `X-OpenRouter-Metadata: enabled`. Verify at configuration time that the selected user-eligible endpoint supports structured outputs. OpenRouter documents that strict enforcement varies by endpoint/provider, so validate the completed object again in AttackTerrain.

If automatic model fallback is ever enabled for non-final enrichment, define an allowlist of evaluated models, cap attempts, preserve ZDR/data restrictions, and store the actual model/provider for every attempt.

## Errors and retry policy

- Inspect both HTTP status and response/SSE error content. A generation-time error may be represented in-band after processing starts.
- Use OpenRouter's stable `error_type` where available rather than message matching.
- Retry only transient rate-limit, overload, unavailable-provider, and timeout classes, with bounded exponential backoff, jitter, task deadline, and idempotency key.
- Honor `Retry-After` on 429/503. Do not retry invalid schema/request, bad credentials, insufficient credits, permission/guardrail blocks, or content-policy failures.
- A mid-stream failure cannot safely fail over after partial output. Final-verdict calls should preferably be non-streaming.
- Normalize timeout-class responses even though the official material uses multiple timeout representations.

## Security and privacy controls

- Treat evidence, retrieved content, tool results, and every model response as attacker-controlled data.
- Enable OpenRouter prompt-injection detection initially in `flag` mode and measure false positives before `redact` or `block`; its documented regex/evasion detection is not exhaustive.
- Separate and delimit untrusted content. Never place secrets, authorization policy, or credentials in prompts.
- Enforce least-privilege database and tool identities. The LLM must have no direct incident/finding/case mutation capability.
- Validate and contextually encode model output. Use prepared statements for all DB operations.
- Use `provider.zdr: true` plus `provider.data_collection: "deny"` for incident evidence. Confirm endpoint policy at runtime/configuration time.
- OpenRouter's sensitive-information guardrail scans inputs, not model outputs; add AttackTerrain output-side PII/secret detection.
- Keep OpenRouter input/output logging off for production evidence unless explicitly approved: the documented retention is at least three months and may be longer until deletion is requested.
- If Broadcast is used, enable destination Privacy Mode and send metadata only. Do not emit raw incident evidence, credentials, or unrestricted tenant identifiers.
- ZDR documentation is not a substitute for customer-specific DPA, regional, regulatory, or audit review.

## Audit record and telemetry

Persist a durable `validation_run` record containing:

- validation run ID and idempotency key;
- tenant, finding, evidence snapshot/version, and immutable evidence IDs;
- deterministic rule-engine and policy versions;
- prompt, JSON Schema, model policy, and preset/config revisions;
- OpenRouter request/generation IDs and routing attempt metadata;
- requested and actual model/provider;
- started/completed timestamps, latency, retry count, error class, and finish reason;
- prompt/completion/reasoning/cache token counts and cost;
- raw model recommendation in a protected audit payload or a redacted canonical digest, according to retention policy;
- final engine disposition, analyst decision, actor, reason, and timestamps.

Recommended states are `queued`, `running`, `inconclusive`, `needs_review`, `validated`, `rejected`, and `error`. State changes should use an append-only decision/event history plus optimistic locking on the current projection.

## Evaluation and release gates

Create an analyst-labelled gold set covering true positives, false positives, duplicates, insufficient evidence, conflicting evidence, stale evidence, prompt injection, malformed model output, refusals, context overflow, provider timeout, and fallback attempts.

Measure at least:

- precision/recall and false-negative rate by terrain, severity, rule, and asset class;
- abstention/`inconclusive` rate and analyst override rate;
- confidence calibration rather than confidence average;
- evidence-citation validity and schema-valid response rate;
- injection success/false-positive rate;
- latency, timeout/retry rate, and cost per completed validation.

Run deterministic unit/contract tests on every commit. Run paid model evals separately on demand or on a schedule. Shadow and canary every prompt, schema, model, provider-policy, or preset change. Block promotion when safety/quality thresholds regress. OpenRouter's Ori Eval can compare models, use real test data, enforce cost/time/tool assertions, employ a separate LLM judge, retain baselines, and fail CI; it should supplement, not replace, deterministic tests and analyst labels.

## Implementation checklist

Progress note (2026-08-14): checked controls are implemented and covered in the
current working tree. Rollout, policy, and evaluation items remain deliberately
open.

- [x] Introduce versioned validation request/response schemas.
- [x] Add strict local schema validation and `inconclusive` fail-closed behavior.
- [x] Fix the optional OpenRouter title header and add router metadata opt-in.
- [x] Add `require_parameters`, ZDR, data-collection, and explicit fallback configuration.
- [x] Disable automatic fallback for final verdicts.
- [x] Replace message-string transient detection with typed exceptions.
- [x] Honor `Retry-After`; bound retries, deadlines, and total validation cost.
- [x] Persist actual model/provider, generation ID, attempts, usage, cost, and versions.
- [x] Require resolvable immutable evidence IDs in model recommendations.
- [x] Wrap and label untrusted evidence; add input injection and input/output sensitive-data controls.
- [x] Change high-confidence AI FP vetoes into review recommendations unless deterministic suppression independently passes.
- [ ] Add `needs_review` and explicit analyst approval/override records.
- [x] Prevent all LLM identities from directly mutating findings, incidents, cases, or permissions.
- [ ] Build the gold/adversarial evaluation suite and per-segment acceptance thresholds.
- [ ] Add shadow/canary rollout and rapid rollback for every configuration revision.
- [ ] Define retention, deletion, RBAC, tenant isolation, and metadata-only observability policy.

## Explicit unknowns requiring verification

- OpenRouter does not document one universal server timeout, default retry count, or exact SDK backoff policy.
- Timeout documentation uses multiple status representations; normalize these through integration tests.
- Exact provider attempt order under every failure combination is not specified.
- Structured-output support and enforcement can vary and change by endpoint; compatibility tests are required for each pinned route.
- Prompt-injection guardrails do not guarantee coverage of novel attacks, and published effectiveness metrics are not provided on the documentation reviewed.
- Broadcast delivery guarantees, retry policy, and trace-loss semantics are not documented.
- Retention duration for all generation metadata is not clearly specified.
- No India-region routing was found in the reviewed OpenRouter documentation; enterprise EU/US routing is documented.
- No OpenRouter feature reviewed provides runtime ground-truth finding validation or an analyst case-approval workflow.
- OpenRouter presets use the latest version when addressed by API; it is unclear whether every inference response exposes the exact applied preset version. AttackTerrain should version and approve its effective configuration independently.
- ZDR documentation alone does not establish contractual compliance, DPA terms, or customer-specific audit evidence.

## Primary sources

### OpenRouter

- [Quickstart and authentication](https://openrouter.ai/docs/quickstart)
- [API-key creation, expiry, and spend limits](https://openrouter.ai/docs/api/api-reference/api-keys/create-keys)
- [Provider routing](https://openrouter.ai/docs/guides/routing/provider-selection)
- [Model fallbacks](https://openrouter.ai/docs/guides/routing/model-fallbacks)
- [Structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs)
- [Models API](https://openrouter.ai/docs/api/api-reference/models/get-models)
- [User-policy-filtered models](https://openrouter.ai/docs/api/api-reference/models/list-models-user)
- [Errors and debugging](https://openrouter.ai/docs/api/reference/errors-and-debugging)
- [Router metadata](https://openrouter.ai/docs/guides/features/router-metadata)
- [Usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting)
- [Generation metadata](https://openrouter.ai/docs/api/api-reference/generations/get-generation)
- [Zero Data Retention](https://openrouter.ai/docs/guides/features/zdr)
- [Provider logging policies](https://openrouter.ai/docs/guides/privacy/provider-logging/)
- [Input/output logging and retention](https://openrouter.ai/docs/guides/features/input-output-logging)
- [Guardrails overview](https://openrouter.ai/docs/guides/features/guardrails/overview)
- [Prompt-injection guardrail](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection)
- [Sensitive-information guardrail](https://openrouter.ai/docs/guides/features/guardrails/sensitive-info)
- [Presets and version behavior](https://openrouter.ai/docs/guides/features/presets)
- [Ori Eval](https://openrouter.ai/docs/guides/ori/eval)
- [Braintrust Broadcast and Privacy Mode](https://openrouter.ai/docs/guides/features/broadcast/braintrust)
- [Opik Broadcast and Privacy Mode](https://openrouter.ai/docs/guides/features/broadcast/opik)

### Validation, human oversight, and security standards

- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST AI RMF Measure guidance](https://airc.nist.gov/airmf-resources/playbook/measure/)
- [NIST AI RMF Map guidance](https://airc.nist.gov/airmf-resources/playbook/map/)
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- [OWASP LLM05: Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP LLM09: Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/)
- [OWASP LLM10: Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
- [Official OpenAI Graders API](https://developers.openai.com/api/reference/resources/graders)
