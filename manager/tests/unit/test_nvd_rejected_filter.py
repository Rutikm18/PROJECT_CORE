from __future__ import annotations

import time

from manager.manager.indexer import IntelDB


def _row(cve_id: str, status: str, keywords: str = "acme widget") -> dict:
    return {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": "Acme widget vulnerability",
        "cvss_score": 9.8,
        "cvss_vector": "",
        "severity": "critical",
        "cwe_ids": "[]",
        "cpe_uris": "[]",
        "pkg_keywords": keywords,
        "published_at": "2026-01-01",
        "modified_at": "2026-01-02",
        "synced_at": time.time(),
    }


async def test_local_nvd_search_excludes_rejected_records(pg_intel_dsn):
    db = IntelDB(pg_intel_dsn)
    await db.init()
    try:
        await db.upsert_nvd_bulk([
            _row("CVE-2026-1111", "Analyzed"),
            _row("CVE-2026-2222", "Rejected"),
            _row("CVE-2026-3333", "Analyzed", "apache httpd server"),
        ])
        rows = await db.search_nvd_local("acme", limit=10)
        assert [row["cve_id"] for row in rows] == ["CVE-2026-1111"]

        multi_word = await db.search_nvd_local("apache httpd", limit=10)
        assert [row["cve_id"] for row in multi_word] == ["CVE-2026-3333"]
    finally:
        await db.close()
