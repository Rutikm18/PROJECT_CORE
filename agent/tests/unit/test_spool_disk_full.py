"""
agent/tests/unit/test_spool_disk_full.py — DiskSpool must never raise.

The spool is the delivery path's last resort and DiskSpool.write() runs on the
sender thread and the orchestrator overflow sink. A full disk (ENOSPC), a
read-only filesystem, or a non-serialisable envelope must be swallowed — an
unhandled OSError there would kill the sender thread and stop ALL delivery.
"""
from __future__ import annotations

import errno
from unittest.mock import patch

import pytest

from agent.agent.sender import DiskSpool


def _spool(tmp_path):
    return DiskSpool(str(tmp_path / "unsent.ndjson"))


def test_write_survives_enospc(tmp_path):
    sp = _spool(tmp_path)
    boom = OSError(errno.ENOSPC, "No space left on device")
    with patch("builtins.open", side_effect=boom):
        sp.write({"section": "x", "data": 1})   # must NOT raise
    # The datum is counted as dropped, not silently lost.
    assert sp.stats()["dropped_trim"] >= 1


def test_write_survives_readonly_fs(tmp_path):
    sp = _spool(tmp_path)
    with patch("builtins.open", side_effect=OSError(errno.EROFS, "Read-only file system")):
        sp.write({"section": "x"})              # must NOT raise


def test_write_survives_non_serialisable_envelope(tmp_path):
    sp = _spool(tmp_path)
    sp.write({"bad": object()})                 # not JSON-serialisable → dropped, no raise
    assert sp.drain() == []                     # nothing was written


def test_normal_write_still_roundtrips(tmp_path):
    sp = _spool(tmp_path)
    sp.write({"section": "metrics", "n": 1})
    sp.write({"section": "processes", "n": 2})
    out = sp.drain()
    assert [e["section"] for e in out] == ["metrics", "processes"]


def test_drain_skips_corrupt_lines(tmp_path):
    path = tmp_path / "unsent.ndjson"
    path.write_text('{"section":"ok"}\n' + "NOT JSON\n" + '{"section":"ok2"}\n')
    sp = DiskSpool(str(path))
    out = sp.drain()
    assert [e["section"] for e in out] == ["ok", "ok2"]
    assert sp.stats()["dropped_corrupt"] == 1
