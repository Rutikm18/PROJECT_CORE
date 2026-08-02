"""
agent/tests/unit/test_spool.py — DiskSpool integrity primitive.

DiskSpool is the on-disk buffer the sender falls back to when the manager is
unreachable.  Zero-loss replay depends entirely on this class round-tripping
every envelope it is handed.  These tests pin down that contract:

  - write → drain returns every envelope, in order, byte-for-byte
  - drain clears the spool (replayed data isn't replayed twice)
  - empty / missing spool drains to []
  - a corrupt line is skipped without losing the good lines around it
  - oversize spool is trimmed oldest-first (bounded disk use, newest kept)
  - every drop (trim or corrupt) is counted in stats() — data loss is never silent
"""
from __future__ import annotations

import os

from agent.agent.sender import DiskSpool


def _spool(tmp_path) -> DiskSpool:
    return DiskSpool(os.path.join(str(tmp_path), "unsent.ndjson"))


def test_write_drain_roundtrip_preserves_order_and_content(tmp_path):
    s = _spool(tmp_path)
    envelopes = [{"section": "metrics", "seq": i, "data": {"x": i}} for i in range(50)]
    for env in envelopes:
        s.write(env)

    drained = s.drain()

    assert drained == envelopes, "drain must return every envelope, in write order"


def test_drain_clears_spool(tmp_path):
    s = _spool(tmp_path)
    s.write({"seq": 1})
    s.write({"seq": 2})

    first = s.drain()
    second = s.drain()

    assert len(first) == 2
    assert second == [], "a drained spool must be empty (no double-replay)"
    assert s.size() == 0


def test_empty_and_missing_spool_drain_to_empty_list(tmp_path):
    s = _spool(tmp_path)
    # Never written — file does not exist yet.
    assert s.drain() == []
    assert s.size() == 0


def test_corrupt_line_is_skipped_good_lines_survive(tmp_path):
    s = _spool(tmp_path)
    s.write({"seq": 1})
    # Inject a corrupt (non-JSON) line between two good ones.
    with open(s.path, "a", encoding="utf-8") as f:
        f.write("this-is-not-json\n")
    s.write({"seq": 2})

    drained = s.drain()

    assert drained == [{"seq": 1}, {"seq": 2}], "corrupt line dropped, good lines kept"
    assert s.stats()["dropped_corrupt"] == 1, "the corrupt drop must be counted, not silent"


def test_trim_drops_oldest_keeps_newest_when_oversize(tmp_path, monkeypatch):
    # Shrink the cap so a handful of writes trips the trim path deterministically.
    import agent.agent.sender as sender_mod
    monkeypatch.setattr(sender_mod, "_SPOOL_MAX_BYTES", 200)

    s = _spool(tmp_path)
    for i in range(100):
        s.write({"seq": i, "pad": "x" * 50})

    drained = s.drain()
    seqs = [e["seq"] for e in drained]

    # Trimming drops the oldest lines, so the newest write must always survive
    # and the surviving sequence stays monotonic (no reordering).
    assert seqs, "spool should still hold the most recent writes"
    assert seqs[-1] == 99, "newest envelope must be retained after trim"
    assert seqs == sorted(seqs), "trim must not reorder surviving envelopes"
    assert s.size() == 0
    assert s.stats()["dropped_trim"] > 0, "trim drops must be counted, not silent"


def test_stats_start_at_zero(tmp_path):
    s = _spool(tmp_path)
    assert s.stats() == {
        "dropped_trim": 0, "dropped_corrupt": 0, "dropped_auth": 0,
    }


def test_peek_survives_crash_until_ack(tmp_path):
    """A leased envelope stays durable until a manager acceptance is ACKed."""
    s = _spool(tmp_path)
    s.write({"seq": 1})
    s.write({"seq": 2})

    first, _token = s.peek()
    assert first == {"seq": 1}

    # Simulate a process crash: construct a fresh spool without acknowledging.
    restarted = _spool(tmp_path)
    replayed, token = restarted.peek()
    assert replayed == {"seq": 1}
    assert restarted.ack(token) is True

    second, second_token = restarted.peek()
    assert second == {"seq": 2}
    assert restarted.ack(second_token) is True
    assert restarted.peek() is None


def test_writes_during_replay_follow_existing_backlog(tmp_path):
    s = _spool(tmp_path)
    s.write({"seq": 1})
    first, first_token = s.peek()  # rotates the current spool to replay
    s.write({"seq": 2})           # lands in a new main spool

    assert first == {"seq": 1}
    assert s.ack(first_token) is True
    second, second_token = s.peek()
    assert second == {"seq": 2}
    assert s.ack(second_token) is True


def test_auth_rotation_discard_is_counted(tmp_path):
    s = _spool(tmp_path)
    s.write({"seq": 1})
    s.write({"seq": 2})
    assert s.discard_for_auth_rotation() == 2
    assert s.stats()["dropped_auth"] == 2
    assert s.peek() is None
