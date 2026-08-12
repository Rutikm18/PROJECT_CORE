import sqlite3

# The corrective backfill statement, kept identical to indexer.py.
MESH_BACKFILL_SQL = (
    "UPDATE findings SET terrain_id='mesh' "
    "WHERE category='developer_security' AND terrain_id IN ('origin', '')"
)


def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, category TEXT, terrain_id TEXT)")
    return c


def test_backfill_moves_devsec_from_origin_to_mesh():
    c = _db()
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','origin')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('package','origin')")
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','mesh')")
    c.execute(MESH_BACKFILL_SQL)
    rows = dict(
        (cat + "|" + tid, n)
        for cat, tid, n in c.execute(
            "SELECT category, terrain_id, COUNT(*) FROM findings GROUP BY category, terrain_id"
        )
    )
    # both origin/'' developer_security rows moved to mesh (2 already-mesh + 2 moved = 3? no: 1 was mesh)
    assert rows.get("developer_security|mesh") == 3          # 1 pre-existing + 2 moved
    assert "developer_security|origin" not in rows
    assert rows.get("package|origin") == 1                   # untouched


def test_backfill_is_idempotent():
    c = _db()
    c.execute("INSERT INTO findings (category, terrain_id) VALUES ('developer_security','origin')")
    c.execute(MESH_BACKFILL_SQL)
    c.execute(MESH_BACKFILL_SQL)  # second run is a no-op
    (n,) = c.execute(
        "SELECT COUNT(*) FROM findings WHERE terrain_id='mesh'"
    ).fetchone()
    assert n == 1
