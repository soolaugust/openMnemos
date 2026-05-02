"""test_iter563_prune_icache_sb.py — iter563: Metadata Table Proportional Reclaim

OS 类比：Linux dentry_lru_isolate() + prune_icache_sb()
  (Dave Chinner / Al Viro, 2012, kernel 3.12, fs/dcache.c + fs/inode.c)
logrotate = 时间/数量轮转；prune_icache_sb = 引用/质量检查。

测试矩阵：
T1:  priming_short_tokens — 短 token(<4字符) 被清除
T2:  priming_orphaned — 无 entity_map 链接的被清除
T3:  priming_linked_preserved — 有 entity_map 链接的保留
T4:  priming_long_unlinked — 长但无链接也被清除
T5:  ipc_consumed_pruned — CONSUMED 消息全部清除
T6:  ipc_pending_preserved — 非 CONSUMED 消息保留
T7:  edges_orphaned_pruned — 引用已删除 chunk 的 edges 清除
T8:  edges_valid_preserved — 引用存在 chunk 的 edges 保留
T9:  edges_null_source — NULL source 不受此 phase 影响（留给 logrotate）
T10: txn_aggressive_cap — 超过 max_txn_keep 的旧记录清除
T11: txn_under_cap — 未超 cap 不清除
T12: disabled — enabled=False 时不执行
T13: empty_tables — 空表不报错
T14: idempotent — 连续两次执行第二次 total_pruned=0
T15: commit_on_prune — 有清除时 commit
T16: performance — <5ms/call
"""
import sys
import os
import time

# tmpfs 测试隔离
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: F401 — 必须在 store 之前

from store_core import open_db, ensure_schema, insert_chunk
from store_mm import prune_icache_sb
from datetime import datetime, timezone, timedelta
import pytest


@pytest.fixture(autouse=True)
def fresh_db():
    """Ensure each test starts with a clean database."""
    conn = open_db()
    ensure_schema(conn)
    # Clean metadata tables
    for table in ["priming_state", "ipc_msgq", "entity_edges", "hook_txn_log",
                  "memory_chunks", "entity_map"]:
        try:
            conn.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    try:
        conn.execute("DELETE FROM memory_chunks_fts")
    except Exception:
        pass
    conn.commit()
    conn.close()
    yield


def _conn():
    return open_db()


def _insert_priming(conn, entity_name, project="test_proj", strength=0.30):
    """Insert a priming_state entry."""
    conn.execute(
        "INSERT INTO priming_state (entity_name, project, primed_at, prime_strength) "
        "VALUES (?, ?, ?, ?)",
        (entity_name, project, datetime.now(timezone.utc).isoformat(), strength)
    )


def _insert_entity_map(conn, entity_name, chunk_id="dummy", project="test_proj"):
    """Insert an entity_map entry (link priming to chunk)."""
    conn.execute(
        "INSERT INTO entity_map (entity_name, chunk_id, project, updated_at) "
        "VALUES (?, ?, ?, ?)",
        (entity_name, chunk_id, project, datetime.now(timezone.utc).isoformat())
    )


def _insert_ipc(conn, status="CONSUMED", source="a", target="b"):
    """Insert an ipc_msgq entry."""
    conn.execute(
        "INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload, "
        "priority, status, created_at, ttl_seconds) "
        "VALUES (?, ?, 'test', '{}', 0, ?, ?, 3600)",
        (source, target, status, datetime.now(timezone.utc).isoformat())
    )


def _insert_edge(conn, source_chunk_id, from_e="A", to_e="B", project="test_proj"):
    """Insert an entity_edges entry."""
    import uuid
    conn.execute(
        "INSERT INTO entity_edges (id, from_entity, relation, to_entity, project, "
        "source_chunk_id, confidence, created_at) "
        "VALUES (?, ?, 'related', ?, ?, ?, 0.8, ?)",
        (str(uuid.uuid4()), from_e, to_e, project, source_chunk_id,
         datetime.now(timezone.utc).isoformat())
    )


def _insert_txn(conn, started_at=None):
    """Insert a hook_txn_log entry."""
    import uuid
    if started_at is None:
        started_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO hook_txn_log (txn_id, hook, status, chunk_count, session_id, "
        "project, started_at) VALUES (?, 'test', 'done', 0, 'sess', 'proj', ?)",
        (str(uuid.uuid4()), started_at)
    )


def _insert_chunk(conn, chunk_id="c1", project="test_proj"):
    """Insert a memory_chunks entry for edge validation."""
    now = datetime.now(timezone.utc).isoformat()
    insert_chunk(conn, {
        "id": chunk_id,
        "project": project,
        "chunk_type": "decision",
        "content": "test content for chunk",
        "summary": "test chunk summary for prune_icache_sb",
        "importance": 0.50,
        "source_session": "test-prune-icache",
        "retrievability": 0.35,
        "tags": "[]",
        "created_at": now,
        "updated_at": now,
        "last_accessed": now,
        "access_count": 0,
        "oom_adj": 0,
    })
    conn.commit()


# ── T1: priming_short_tokens ──
def test_priming_short_tokens():
    """Short entity names (<4 chars) are pruned as noise tokens."""
    conn = _conn()
    _insert_priming(conn, "pp")       # 2 chars → pruned
    _insert_priming(conn, "ms")       # 2 chars → pruned
    _insert_priming(conn, "abc")      # 3 chars → pruned
    _insert_priming(conn, "abcd")     # 4 chars → kept (if linked)
    conn.commit()

    result = prune_icache_sb(conn)
    # All 4 pruned: 3 short + "abcd" unlinked
    assert result["pruned_priming"] >= 3  # at least short ones
    remaining = conn.execute("SELECT COUNT(*) FROM priming_state").fetchone()[0]
    assert remaining == 0  # all gone (unlinked too)
    conn.close()


# ── T2: priming_orphaned ──
def test_priming_orphaned():
    """Priming entries with no entity_map link are pruned (negative dentry)."""
    conn = _conn()
    _insert_priming(conn, "orphan_entity_long_name")
    _insert_priming(conn, "another_orphan_entity")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_priming"] == 2
    remaining = conn.execute("SELECT COUNT(*) FROM priming_state").fetchone()[0]
    assert remaining == 0
    conn.close()


# ── T3: priming_linked_preserved ──
def test_priming_linked_preserved():
    """Priming entries WITH entity_map link are preserved."""
    conn = _conn()
    _insert_chunk(conn, "c1")
    _insert_priming(conn, "linked_entity")
    _insert_entity_map(conn, "linked_entity", "c1")
    _insert_priming(conn, "orphan_entity")
    conn.commit()

    result = prune_icache_sb(conn)
    remaining = conn.execute(
        "SELECT entity_name FROM priming_state"
    ).fetchall()
    assert len(remaining) == 1
    assert remaining[0][0] == "linked_entity"
    conn.close()


# ── T4: priming_long_unlinked ──
def test_priming_long_unlinked():
    """Long entity names without link are still pruned (reference check, not length)."""
    conn = _conn()
    _insert_priming(conn, "very_long_entity_name_that_looks_valid")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_priming"] == 1
    conn.close()


# ── T5: ipc_consumed_pruned ──
def test_ipc_consumed_pruned():
    """All CONSUMED ipc messages are pruned regardless of age."""
    conn = _conn()
    for _ in range(10):
        _insert_ipc(conn, status="CONSUMED")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_ipc"] == 10
    remaining = conn.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0]
    assert remaining == 0
    conn.close()


# ── T6: ipc_pending_preserved ──
def test_ipc_pending_preserved():
    """Non-CONSUMED ipc messages are preserved."""
    conn = _conn()
    _insert_ipc(conn, status="CONSUMED")
    _insert_ipc(conn, status="PENDING")
    _insert_ipc(conn, status="QUEUED")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_ipc"] == 1
    remaining = conn.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0]
    assert remaining == 2
    conn.close()


# ── T7: edges_orphaned_pruned ──
def test_edges_orphaned_pruned():
    """Entity edges referencing deleted chunks are pruned."""
    conn = _conn()
    _insert_chunk(conn, "existing_chunk")
    _insert_edge(conn, source_chunk_id="deleted_chunk_id")  # orphaned
    _insert_edge(conn, source_chunk_id="existing_chunk")    # valid
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_edges"] == 1
    remaining = conn.execute("SELECT COUNT(*) FROM entity_edges").fetchone()[0]
    assert remaining == 1
    conn.close()


# ── T8: edges_valid_preserved ──
def test_edges_valid_preserved():
    """Entity edges referencing existing chunks are preserved."""
    conn = _conn()
    _insert_chunk(conn, "c1")
    _insert_chunk(conn, "c2")
    _insert_edge(conn, source_chunk_id="c1")
    _insert_edge(conn, source_chunk_id="c2")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_edges"] == 0
    remaining = conn.execute("SELECT COUNT(*) FROM entity_edges").fetchone()[0]
    assert remaining == 2
    conn.close()


# ── T9: edges_null_source ──
def test_edges_null_source_not_affected():
    """NULL source_chunk_id edges are NOT pruned by this function (left to logrotate)."""
    conn = _conn()
    _insert_edge(conn, source_chunk_id=None)
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_edges"] == 0
    remaining = conn.execute("SELECT COUNT(*) FROM entity_edges").fetchone()[0]
    assert remaining == 1
    conn.close()


# ── T10: txn_aggressive_cap ──
def test_txn_aggressive_cap():
    """hook_txn_log over max_txn_keep(100) gets oldest entries pruned."""
    conn = _conn()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(120):
        _insert_txn(conn, started_at=(base + timedelta(minutes=i)).isoformat())
    conn.commit()

    count_before = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
    assert count_before == 120

    result = prune_icache_sb(conn)
    assert result["pruned_txn"] == 20  # 120 - 100 = 20
    remaining = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
    assert remaining == 100
    conn.close()


# ── T11: txn_under_cap ──
def test_txn_under_cap():
    """hook_txn_log under max_txn_keep is not pruned."""
    conn = _conn()
    for _ in range(50):
        _insert_txn(conn)
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["pruned_txn"] == 0
    remaining = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
    assert remaining == 50
    conn.close()


# ── T12: disabled ──
def test_disabled():
    """enabled=False skips all pruning."""
    conn = _conn()
    _insert_priming(conn, "orphan_entity")
    _insert_ipc(conn, status="CONSUMED")
    conn.commit()

    from unittest.mock import patch
    original_get = None
    import config
    original_get = config.get

    def mock_get(key, **kw):
        if key == "prune_icache_sb.enabled":
            return False
        return original_get(key, **kw)

    with patch("config.get", side_effect=mock_get):
        result = prune_icache_sb(conn)
        assert result["total_pruned"] == 0

    # Data still exists
    assert conn.execute("SELECT COUNT(*) FROM priming_state").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0] == 1
    conn.close()


# ── T13: empty_tables ──
def test_empty_tables():
    """Empty tables don't cause errors."""
    conn = _conn()
    result = prune_icache_sb(conn)
    assert result["total_pruned"] == 0
    assert result["pruned_priming"] == 0
    assert result["pruned_ipc"] == 0
    assert result["pruned_edges"] == 0
    assert result["pruned_txn"] == 0
    conn.close()


# ── T14: idempotent ──
def test_idempotent():
    """Second execution returns total_pruned=0."""
    conn = _conn()
    _insert_priming(conn, "orphan_entity_xyz")
    _insert_ipc(conn, status="CONSUMED")
    conn.commit()

    result1 = prune_icache_sb(conn)
    assert result1["total_pruned"] > 0

    result2 = prune_icache_sb(conn)
    assert result2["total_pruned"] == 0
    conn.close()


# ── T15: commit_on_prune ──
def test_commit_on_prune():
    """Changes are persisted (survive connection reopen)."""
    conn = _conn()
    _insert_priming(conn, "orphan_entity_persist")
    _insert_ipc(conn, status="CONSUMED")
    conn.commit()

    result = prune_icache_sb(conn)
    assert result["total_pruned"] > 0
    conn.close()

    # Reopen and verify
    conn2 = _conn()
    assert conn2.execute("SELECT COUNT(*) FROM priming_state").fetchone()[0] == 0
    assert conn2.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0] == 0
    conn2.close()


# ── T16: performance ──
def test_performance():
    """prune_icache_sb completes in <5ms for typical workload."""
    conn = _conn()
    # Seed with realistic data
    for i in range(100):
        _insert_priming(conn, f"entity_{i:04d}")
    for _ in range(50):
        _insert_ipc(conn, status="CONSUMED")
    _insert_chunk(conn, "c_perf")
    for i in range(20):
        _insert_edge(conn, source_chunk_id=f"deleted_{i}")
    conn.commit()

    t0 = time.time()
    result = prune_icache_sb(conn)
    elapsed_ms = (time.time() - t0) * 1000

    assert elapsed_ms < 5.0, f"prune_icache_sb took {elapsed_ms:.1f}ms (limit 5ms)"
    assert result["total_pruned"] > 0
    conn.close()
