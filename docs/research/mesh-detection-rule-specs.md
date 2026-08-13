# Mesh Detection Rule Specifications

Status: executable specification, 2026-08-14. The authoritative runtime
registry is `RULE_SPECS` in `manager/manager/attacklens/detections/developer_security.py`;
the positive, negative, and boundary examples are enforced by
`manager/tests/unit/test_developer_security_rules.py`.

| Rule | Asset and deterministic condition | Boundary / noise control | Severity |
|---|---|---|---|
| AL-DEV-001 | Editor extension auto-activates, exposes a command-execution indicator, and is side-loaded or has an unverified publisher. | Every anchor is required; an auto-activating but non-executing extension stays silent. | High |
| AL-DEV-002 | MCP command uses a mutable `@latest` reference, or an unpinned ephemeral runner receives sensitive environment keys/capability indicators. | Ephemeral execution without sensitive/capability access stays silent. `@latest` alone remains a medium supply-chain finding. | Medium–High |
| AL-DEV-003 | A directory in executable `PATH` is world-writable. | Missing permission data and non-world-writable entries stay silent. | High |
| AL-DEV-004 | Browser extension combines native messaging with a dangerous browser or host permission. | Native messaging or broad permission alone is insufficient. | High |
| AL-DEV-005 | Native-messaging executable is in a temporary directory or is group/world-writable. | Normal `0755` read/execute permissions are not treated as modifiable. | High |
| AL-DEV-006 | Git config sets `core.hooksPath` or `core.sshCommand`. | Unrelated Git settings stay silent. | Medium |
| AL-DEV-007 | Credential-related file grants group/other read or write access. | Owner-only `0600` files and directory modes stay silent. | High |
| AL-DEV-008 | Interesting developer/AI process listens on a wildcard interface. | Loopback binds and unrelated wildcard services stay silent. | Medium |
| AL-DEV-009 | Developer container is privileged, host-networked, mounts host root or Docker socket, or adds `SYS_ADMIN`. | Ordinary bridge-mode, non-privileged containers stay silent. | Critical |

## Data and lifecycle guarantees

- Secret values are never a rule input or finding evidence. Environment **key
  names** and value-presence booleans may be collected; model/API keys and
  argument values are redacted at the agent.
- Each snapshot reports collector version, overall `complete|partial|error`
  state, and the state of every capability. Truncation always changes the
  overall state to `partial`.
- `item_key` is the stable incident identity. `detection_fingerprint` hashes the
  rule, identity, and material evidence: an unchanged snapshot is deduplicated;
  an evidence change updates the same database row.
- A partial or errored capability is an observability/data-quality signal. Its
  absence is never interpreted as proof that the host is safe.

## Evaluation gate

The checked-in examples are synthetic executable contracts, not a claim of
production precision or recall. Shadow-mode promotion requires analyst-labelled
workstation samples per rule, reported sample size and class balance, zero
secret-value leaks, and an explicit threshold approved before enforcement.
