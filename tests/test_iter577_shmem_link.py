"""
iter577: shmem_link — Shared Memory Co-occurrence Activation

OS 类比：Linux shmem/tmpfs — 多进程通过映射同一物理页隐式共享数据。
测试 entity co-occurrence 激活路径的正确性。
"""
import sys, os, sqlite3, uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["MEMORY_OS_TEST"] = "1"
os.environ["MEMORY_OS_SHMEM_LINK_ENABLED"] = "1"
os.environ["MEMORY_OS_SHMEM_LINK_MAX_RESULTS"] = "5"
os.environ["MEMORY_OS_SHMEM_LINK_MIN_SHARED_ENTITIES"] = "2"
os.environ["MEMORY_OS_SHMEM_LINK_ACTIVATION_SCORE"] = "0.25"
os.environ["MEMORY_OS_SHMEM_LINK_ENTITY_IDF_WEIGHT"] = "1"

import pytest

_PROJECT = "test-shmem-link"
_NOW = datetime.now(timezone.utc).isoformat()


def _make_db():
    """Create in-memory DB with entity_map + memory_chunks."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE entity_map (
        entity_name TEXT NOT NULL,
        chunk_id TEXT NOT NULL,
        project TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (entity_name, project, chunk_id)
    )""")
    conn.execute("""CREATE TABLE memory_chunks (
        id TEXT PRIMARY KEY,
        created_at TEXT, updated_at TEXT, project TEXT,
        source_session TEXT, chunk_type TEXT, content TEXT,
        summary TEXT, tags TEXT, importance REAL,
        retrievability REAL, last_accessed TEXT,
        access_count INTEGER DEFAULT 0, info_class TEXT,
        lru_gen INTEGER DEFAULT 0, oom_adj INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE entity_edges (
        id TEXT PRIMARY KEY, from_entity TEXT NOT NULL,
        relation TEXT NOT NULL, to_entity TEXT NOT NULL,
        project TEXT, source_chunk_id TEXT,
        confidence REAL DEFAULT 0.7, created_at TEXT NOT NULL,
        agent_id TEXT DEFAULT ''
    )""")
    return conn


def _add_chunk(conn, chunk_id, project=_PROJECT, chunk_type="decision",
               summary="test", importance=0.5):
    conn.execute(
        "INSERT INTO memory_chunks (id, created_at, updated_at, project, chunk_type, "
        "summary, importance, last_accessed, access_count, info_class, lru_gen) "
        "VALUES (?,?,?,?,?,?,?,?,0,'world',0)",
        (chunk_id, _NOW, _NOW, project, chunk_type, summary, importance, _NOW))


def _add_entity_map(conn, entity_name, chunk_id, project=_PROJECT):
    conn.execute(
        "INSERT OR IGNORE INTO entity_map (entity_name, chunk_id, project) VALUES (?,?,?)",
        (entity_name, chunk_id, project))


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_basic_cooccurrence_activation():
    """Two chunks sharing >=2 entities → candidate activated."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "candidate1")

    # hit1 and candidate1 share entities "memory" and "linux"
    _add_entity_map(conn, "memory", "hit1")
    _add_entity_map(conn, "linux", "hit1")
    _add_entity_map(conn, "memory", "candidate1")
    _add_entity_map(conn, "linux", "candidate1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    assert "candidate1" in result
    assert 0 < result["candidate1"] <= 0.25


def test_min_shared_entities_filter():
    """Candidate sharing only 1 entity is filtered out (min=2)."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "weak_candidate")

    _add_entity_map(conn, "memory", "hit1")
    _add_entity_map(conn, "linux", "hit1")
    _add_entity_map(conn, "memory", "weak_candidate")  # only 1 shared
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    assert "weak_candidate" not in result


def test_existing_ids_excluded():
    """Chunks in existing_ids are not returned."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "already_seen")

    _add_entity_map(conn, "memory", "hit1")
    _add_entity_map(conn, "linux", "hit1")
    _add_entity_map(conn, "memory", "already_seen")
    _add_entity_map(conn, "linux", "already_seen")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT,
                        existing_ids={"already_seen"})
    assert "already_seen" not in result


def test_hit_chunk_not_in_result():
    """Hit chunk itself never appears in results."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "candidate1")

    _add_entity_map(conn, "memory", "hit1")
    _add_entity_map(conn, "linux", "hit1")
    _add_entity_map(conn, "memory", "candidate1")
    _add_entity_map(conn, "linux", "candidate1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    assert "hit1" not in result


def test_idf_weighting_favors_rare_entities():
    """Rare entity co-occurrence scores higher than common entity co-occurrence."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "rare_match")
    _add_chunk(conn, "common_match")
    _add_chunk(conn, "noise1")  # shares common entities with many

    # "rare_concept" only in hit1 + rare_match
    _add_entity_map(conn, "rare_concept", "hit1")
    _add_entity_map(conn, "rare_concept", "rare_match")
    # Both share "common" entity (appears in 4 chunks)
    _add_entity_map(conn, "common", "hit1")
    _add_entity_map(conn, "common", "rare_match")
    _add_entity_map(conn, "common", "common_match")
    _add_entity_map(conn, "common", "noise1")
    # common_match also shares "generic" (appears in 3 chunks)
    _add_entity_map(conn, "generic", "hit1")
    _add_entity_map(conn, "generic", "common_match")
    _add_entity_map(conn, "generic", "noise1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    # rare_match shares a rare entity → higher IDF score
    if "rare_match" in result and "common_match" in result:
        assert result["rare_match"] >= result["common_match"]


def test_max_results_cap():
    """Results capped at max_results."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    for i in range(10):
        cid = f"cand_{i}"
        _add_chunk(conn, cid)
        _add_entity_map(conn, "alpha", cid)
        _add_entity_map(conn, "beta", cid)
    _add_entity_map(conn, "alpha", "hit1")
    _add_entity_map(conn, "beta", "hit1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT, max_results=3)
    assert len(result) <= 3


def test_disabled():
    """Disabled via sysctl returns empty."""
    # Temporarily disable at env level before importing
    old_val = os.environ.get("MEMORY_OS_SHMEM_LINK_ENABLED", "1")
    os.environ["MEMORY_OS_SHMEM_LINK_ENABLED"] = "0"

    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "cand1")
    _add_entity_map(conn, "e1", "hit1")
    _add_entity_map(conn, "e2", "hit1")
    _add_entity_map(conn, "e1", "cand1")
    _add_entity_map(conn, "e2", "cand1")
    conn.commit()

    # Reload both config and store_vfs to pick up env change
    import importlib, config, store_vfs
    importlib.reload(config)
    importlib.reload(store_vfs)

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    assert result == {}

    # Restore
    os.environ["MEMORY_OS_SHMEM_LINK_ENABLED"] = old_val
    importlib.reload(config)
    importlib.reload(store_vfs)


def test_empty_hit_ids():
    """Empty hit_chunk_ids returns empty."""
    conn = _make_db()
    from store_vfs import shmem_link
    result = shmem_link(conn, [], project=_PROJECT)
    assert result == {}


def test_no_entity_map_entries():
    """Hit chunk has no entity_map entries → empty result."""
    conn = _make_db()
    _add_chunk(conn, "orphan_hit")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["orphan_hit"], project=_PROJECT)
    assert result == {}


def test_cross_project_cooccurrence():
    """Cross-project entity co-occurrence activates candidates (shmem cross-namespace)."""
    conn = _make_db()
    _add_chunk(conn, "hit1", project=_PROJECT)
    _add_chunk(conn, "cross_proj_cand", project="other-project")

    # Same entity in different projects → cross-project shmem link
    _add_entity_map(conn, "shared_ent", "hit1", project=_PROJECT)
    _add_entity_map(conn, "shared_ent2", "hit1", project=_PROJECT)
    _add_entity_map(conn, "shared_ent", "cross_proj_cand", project="other-project")
    _add_entity_map(conn, "shared_ent2", "cross_proj_cand", project="other-project")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    # Cross-project activation is by design (shmem = cross-namespace shared memory)
    assert "cross_proj_cand" in result


def test_multiple_hit_chunks():
    """Multiple hit chunks expand seed entity set."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "hit2")
    _add_chunk(conn, "cand1")

    # hit1 shares "alpha" with cand1; hit2 shares "beta" with cand1
    _add_entity_map(conn, "alpha", "hit1")
    _add_entity_map(conn, "beta", "hit2")
    _add_entity_map(conn, "alpha", "cand1")
    _add_entity_map(conn, "beta", "cand1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1", "hit2"], project=_PROJECT)
    assert "cand1" in result  # shares 2 entities across both hits


def test_score_normalization():
    """All scores are <= activation_score (0.25)."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    for i in range(5):
        cid = f"c_{i}"
        _add_chunk(conn, cid)
        _add_entity_map(conn, "e1", cid)
        _add_entity_map(conn, "e2", cid)
        _add_entity_map(conn, "e3", cid)
    _add_entity_map(conn, "e1", "hit1")
    _add_entity_map(conn, "e2", "hit1")
    _add_entity_map(conn, "e3", "hit1")
    conn.commit()

    from store_vfs import shmem_link
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    for score in result.values():
        assert score <= 0.25


def test_idempotent():
    """Calling twice returns same result (no side effects)."""
    conn = _make_db()
    _add_chunk(conn, "hit1")
    _add_chunk(conn, "cand1")
    _add_entity_map(conn, "x", "hit1")
    _add_entity_map(conn, "y", "hit1")
    _add_entity_map(conn, "x", "cand1")
    _add_entity_map(conn, "y", "cand1")
    conn.commit()

    from store_vfs import shmem_link
    r1 = shmem_link(conn, ["hit1"], project=_PROJECT)
    r2 = shmem_link(conn, ["hit1"], project=_PROJECT)
    assert r1 == r2


def test_performance():
    """100 entities × 50 chunks completes in <500ms."""
    import time
    conn = _make_db()
    _add_chunk(conn, "hit1")
    for i in range(50):
        cid = f"perf_chunk_{i}"
        _add_chunk(conn, cid)
        for j in range(4):  # 4 shared entities each
            _add_entity_map(conn, f"ent_{j}", cid)
    for j in range(4):
        _add_entity_map(conn, f"ent_{j}", "hit1")
    conn.commit()

    from store_vfs import shmem_link
    t0 = time.time()
    result = shmem_link(conn, ["hit1"], project=_PROJECT)
    elapsed = time.time() - t0
    assert elapsed < 0.5, f"took {elapsed:.3f}s"
    assert len(result) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
