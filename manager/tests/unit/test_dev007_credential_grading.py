"""AL-DEV-007 precision contract — graded credential exposure.

The rule used to fire on `_SECRET_FILE` name match + mode bits alone. Replayed
against a real developer laptop that produced 193 findings per snapshot, of
which 3 were real: the rest were a cloned `nuclei-templates` corpus, Rust build
artefacts, `tokenizer.py`, `tsconfig.json`, and `.env.example` files.

Every SILENT case below is a class of false positive taken from that fleet data.
Every FIRING case is a credential store that must never be suppressed by the
filters those false positives motivated. Keep both lists growing together — a
new exclusion that also silences a FIRING case is a regression, not a tune.
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens.detections.developer_security import analyze

READABLE = "-rw-r--r--"
WORLD_WRITABLE = "-rw-rw-rw-"
OWNER_ONLY = "-rw-------"


def _payload(rows: list[dict]) -> dict:
    return {"capabilities": {"credential_locations": {"locations": rows}}}


def _row(path: str, mode: str = READABLE, **extra) -> dict:
    return {"path": path, "mode": mode, "kind": "name_match",
            "user": "dev", "size_bytes": 512, **extra}


async def _paths(rows: list[dict]) -> set[str]:
    hits = await analyze("agent", "developer_security", _payload(rows), object())
    return {
        path
        for hit in hits if hit["rule_id"] == "AL-DEV-007"
        for path in hit["evidence"]["sample_paths"]
    }


# ── Credential stores that must fire ────────────────────────────────────────
FIRING = [
    # POSIX developer credential stores
    "/home/dev/.aws/credentials",
    "/home/dev/.ssh/id_ed25519",
    "/home/dev/.ssh/prod.pem",
    "/home/dev/.npmrc",
    "/home/dev/.pypirc",
    "/home/dev/.netrc",
    "/home/dev/.pgpass",
    "/home/dev/app/.env",
    "/home/dev/app/.env.production",
    # Vendor CLI token stores — credible because of the directory they sit in
    "/home/dev/.config/gh/hosts.yml",
    "/home/dev/.docker/config.json",
    "/home/dev/.kube/config",
    "/home/dev/.terraform.d/terraform.tfstate",
    # Coding-agent credential stores: the surface this platform exists for
    "/home/dev/.claude/.credentials.json",
    # Windows paths reach the same verdicts
    "C:/Users/dev/.aws/credentials",
    "C:/Users/dev/AppData/Roaming/gcloud/credentials.db",
    "C:/Users/dev/_netrc",
]

# ── False-positive classes observed in real fleet data ──────────────────────
SILENT = [
    # Published placeholders
    "/home/dev/app/.env.example",
    "/home/dev/app/.env.template",
    "/home/dev/app/config.json.sample",
    # Tooling configs that collide with the collector's `config\.json$` pattern
    "/home/dev/app/tsconfig.json",
    "/home/dev/app/jsconfig.json",
    "/home/dev/app/.release-please-config.json",
    # `token` as in NLP tokenizer, not as in auth token
    "/home/dev/src/tokenizer.py",
    "/home/dev/src/test_tokenizers.py",
    "/home/dev/sdk/canvas-tokens.d.ts",
    # Build output and dependency trees restate upstream files
    "/home/dev/target/release/deps/libtokenizers-abc.rlib",
    "/home/dev/target/release/deps/tokenizers-abc.d",
    "/home/dev/src/__pycache__/tokenizer.cpython-313.pyc",
    "/home/dev/node_modules/foo/.npmrc",
    # Detection corpora and wordlists describe secrets, they do not hold them
    "/home/dev/nuclei-templates/file/keys/github/github-app-token.yaml",
    "/home/dev/SecLists/Passwords/scraped-JWT-secrets.txt",
    # Test fixtures name things after what they simulate
    "/home/dev/app/tests/fixtures/credentials.json",
    "/home/dev/bench/tasks/task-deps/server-secret1.txt",
    # Node CLIs scribble a `config.json` that holds no credential
    "/home/dev/Library/Preferences/nextjs-nodejs/config.json",
    # Documentation and archives
    "/home/dev/docs/output-token-reduction-guide.md",
    "/home/dev/archive/secrets.7z",
]


@pytest.mark.parametrize("path", FIRING)
@pytest.mark.asyncio
async def test_exposed_credential_store_fires(path):
    assert path in await _paths([_row(path)])


@pytest.mark.parametrize("path", SILENT)
@pytest.mark.asyncio
async def test_credential_shaped_name_stays_silent(path):
    assert path not in await _paths([_row(path)])


@pytest.mark.asyncio
async def test_owner_only_mode_is_silent_even_for_a_real_vault():
    """Exposure is mandatory: a correctly-permissioned store is not a finding."""
    assert not await _paths([_row("/home/dev/.aws/credentials", OWNER_ONLY)])


@pytest.mark.asyncio
async def test_directory_rows_are_silent():
    assert not await _paths([_row("/home/dev/.ssh", "drwx------")])


@pytest.mark.asyncio
async def test_empty_and_oversized_files_are_silent():
    """A 0-byte file leaks nothing; a 5 MiB match is an archive, not a secret."""
    assert not await _paths([_row("/home/dev/a/.env", size_bytes=0)])
    assert not await _paths([_row("/home/dev/b/.env", size_bytes=5 * 1024 * 1024)])


@pytest.mark.asyncio
async def test_key_material_survives_corpus_suppression():
    """A private key is a finding wherever it lands, including inside a corpus."""
    rows = [_row(f"/home/dev/repo/rules/case{index}/token.yaml") for index in range(12)]
    rows.append(_row("/home/dev/repo/rules/leaked.pem"))
    paths = await _paths(rows)
    assert "/home/dev/repo/rules/leaked.pem" in paths
    assert not any(path.endswith("token.yaml") for path in paths)


@pytest.mark.asyncio
async def test_dense_credential_named_tree_is_treated_as_a_corpus():
    """Generalizes the known-corpus list: sparse is a vault, dense is a repo."""
    rows = [
        _row(f"/home/dev/private-templates/keys/svc{index}/credentials.json")
        for index in range(12)
    ]
    assert not await _paths(rows)


@pytest.mark.asyncio
async def test_home_directory_is_never_graded_as_a_corpus():
    """Density must skip OS containers, or one busy $HOME silences the rule."""
    noise = [_row(f"/home/dev/proj{index}/src/tokenizer.py") for index in range(30)]
    assert "/home/dev/.aws/credentials" in await _paths(
        noise + [_row("/home/dev/.aws/credentials")]
    )


@pytest.mark.asyncio
async def test_findings_roll_up_per_directory_with_member_count():
    rows = [_row(f"/home/dev/.ssh/key{index}.pem") for index in range(6)]
    hits = [
        hit for hit in await analyze("agent", "developer_security", _payload(rows), object())
        if hit["rule_id"] == "AL-DEV-007"
    ]
    assert len(hits) == 1, "six exposed keys in one directory is one finding"
    assert hits[0]["evidence"]["member_count"] == 6
    assert hits[0]["evidence"]["object"] == "/home/dev/.ssh"


@pytest.mark.asyncio
async def test_writable_exposure_outranks_readable_exposure():
    """Severity must separate 'others can read it' from 'others can replace it'."""
    store = "/home/dev/.aws/credentials"
    readable = await analyze("agent", "developer_security",
                             _payload([_row(store)]), object())
    writable = await analyze("agent", "developer_security",
                             _payload([_row(store, WORLD_WRITABLE)]), object())
    assert readable[0]["severity"] == "high"
    assert writable[0]["severity"] == "critical"
    assert writable[0]["evidence"]["group_or_world_writable"] is True


@pytest.mark.asyncio
async def test_declared_locations_bypass_name_grading():
    """`common_location` rows come from the collector's own list, not a walk."""
    row = _row("/home/dev/.aws", READABLE, kind="common_location")
    hits = await analyze("agent", "developer_security", _payload([row]), object())
    assert [hit["evidence"]["grade"] for hit in hits] == ["declared"]


@pytest.mark.asyncio
async def test_finding_explains_why_it_matched():
    """A finding an analyst cannot triage without opening the file is noise."""
    hits = await analyze("agent", "developer_security",
                         _payload([_row("/home/dev/.aws/credentials")]), object())
    hit = hits[0]
    assert hit["evidence"]["reasons"], "the grading reason must survive into evidence"
    assert "credential material" in hit["description"] or "credential store" in hit["description"]
    assert "baseline" not in hit["false_positive_notes"], "must not use the generic note"


@pytest.mark.asyncio
async def test_repeated_snapshots_produce_a_stable_item_key():
    """Findings must not churn: same host state, same key, every hour."""
    rows = [_row("/home/dev/.aws/credentials")]
    first = await analyze("agent", "developer_security", _payload(rows), object())
    second = await analyze("agent", "developer_security", _payload(rows), object())
    assert first[0]["item_key"] == second[0]["item_key"]
