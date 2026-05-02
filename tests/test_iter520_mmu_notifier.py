"""
iter520: mmu_notifier — Inline Reference Invalidation on Delete

OS 类比：Linux mmu_notifier (Andrea Arcangeli, 2008) — page unmap 时同步
通知所有 secondary MMU 订阅者清除 stale PTE 映射。

测试验证：
  T1  基本功能：删除 chunk 后 recall_traces stale refs 被清理
  T2  全 stale trace 被删除
  T3  部分 stale trace 被 UPDATE（保留有效引用）
  T4  checkpoints stale refs 被清理
  T5  空 checkpoint 被删除
  T6  无 stale 时无操作（幂等）
  T7  delete_chunks 自动触发 mmu_notifier
  T8  checkpoint_gc 全局上限
  T9  checkpoint_gc 不删除未超限
  T10 性能：100 IDs × 200 traces < 50ms
  T11 空输入安全
  T12 JSON 格式兼容（top_k_json 各种格式）
"""
import sys
import os
import time
import json

# tmpfs 隔离
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402, F401 — 必须在 store 之前

import store_mm
import store_vfs
from store_vfs import (
    open_db, ensure_schema, insert_chunk, delete_chunks,
    bump_chunk_version,
)


def _setup_db():
    conn = open_db()
    ensure_schema(conn)
    # Ensure checkpoints table exists (from store_criu)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            project TEXT NOT NULL,
            session_id TEXT NOT NULL,
            hit_chunk_ids TEXT NOT NULL,
            madvise_hints TEXT,
            query_topics TEXT,
            consumed INTEGER DEFAULT 0,
            chunk_snapshots TEXT
        )
    """)
    # Clean slate for each test
    conn.execute("DELETE FROM recall_traces")
    conn.execute("DELETE FROM memory_chunks")
    conn.execute("DELETE FROM checkpoints")
    conn.commit()
    return conn


def _insert_test_chunk(conn, chunk_id, project="test_proj"):
    conn.execute("""
        INSERT OR IGNORE INTO memory_chunks
        (id, summary, content, chunk_type, importance, project, source_session,
         created_at, last_accessed, access_count, oom_adj, lru_gen)
        VALUES (?, ?, '', 'decision', 0.8, ?, 'test', datetime('now'), datetime('now'), 0, 0, 0)
    """, (chunk_id, f"test chunk {chunk_id}", project))
    conn.commit()


def _insert_trace(conn, project, top_k):
    conn.execute("""
        INSERT INTO recall_traces (timestamp, session_id, project, prompt_hash,
         candidates_count, top_k_json, injected, reason)
        VALUES (datetime('now'), 'test-sess', ?, 'hash', 5, ?, 1, 'test')
    """, (project, json.dumps(top_k, ensure_ascii=False)))
    conn.commit()


def _insert_checkpoint(conn, ckpt_id, project, hit_ids):
    conn.execute("""
        INSERT INTO checkpoints (id, created_at, project, session_id,
         hit_chunk_ids, madvise_hints, query_topics, consumed, chunk_snapshots)
        VALUES (?, datetime('now'), ?, 'test-sess', ?, '[]', '[]', 0, '[]')
    """, (ckpt_id, project, json.dumps(hit_ids)))
    conn.commit()


def test_01_basic_trace_cleanup():
    """T1: 删除 chunk 后 recall_traces stale refs 被清理"""
    conn = _setup_db()
    _insert_test_chunk(conn, "alive-1")
    _insert_test_chunk(conn, "dead-1")
    _insert_trace(conn, "test_proj", [
        {"id": "alive-1", "summary": "a", "score": 0.9},
        {"id": "dead-1", "summary": "d", "score": 0.8},
    ])

    result = store_mm.mmu_notifier_invalidate(conn, ["dead-1"])
    conn.commit()

    assert result["traces_cleaned"] == 1
    assert result["refs_removed"] == 1

    # Verify trace now only has alive-1
    row = conn.execute("SELECT top_k_json FROM recall_traces").fetchone()
    tk = json.loads(row[0])
    assert len(tk) == 1
    assert tk[0]["id"] == "alive-1"
    conn.close()


def test_02_all_stale_trace_deleted():
    """T2: 全 stale → 整条 trace 被删除"""
    conn = _setup_db()
    _insert_trace(conn, "test_proj", [
        {"id": "dead-a", "summary": "a", "score": 0.9},
        {"id": "dead-b", "summary": "b", "score": 0.8},
    ])

    result = store_mm.mmu_notifier_invalidate(conn, ["dead-a", "dead-b"])
    conn.commit()

    assert result["traces_deleted"] == 1
    assert result["refs_removed"] == 2

    count = conn.execute("SELECT COUNT(*) FROM recall_traces").fetchone()[0]
    assert count == 0
    conn.close()


def test_03_partial_stale_update():
    """T3: 部分 stale → UPDATE 保留有效引用"""
    conn = _setup_db()
    _insert_test_chunk(conn, "keep-1")
    _insert_test_chunk(conn, "keep-2")
    _insert_trace(conn, "test_proj", [
        {"id": "keep-1", "summary": "k1", "score": 0.9},
        {"id": "dead-x", "summary": "dx", "score": 0.7},
        {"id": "keep-2", "summary": "k2", "score": 0.6},
    ])

    result = store_mm.mmu_notifier_invalidate(conn, ["dead-x"])
    conn.commit()

    assert result["traces_cleaned"] == 1
    assert result["refs_removed"] == 1

    row = conn.execute("SELECT top_k_json FROM recall_traces").fetchone()
    tk = json.loads(row[0])
    assert len(tk) == 2
    ids = [item["id"] for item in tk]
    assert "keep-1" in ids
    assert "keep-2" in ids
    assert "dead-x" not in ids
    conn.close()


def test_04_checkpoint_cleanup():
    """T4: checkpoints stale refs 被清理"""
    conn = _setup_db()
    _insert_test_chunk(conn, "ch-alive")
    _insert_checkpoint(conn, "ckpt-1", "test_proj", ["ch-alive", "ch-dead"])

    result = store_mm.mmu_notifier_invalidate(conn, ["ch-dead"])
    conn.commit()

    assert result["checkpoints_cleaned"] == 1
    assert result["refs_removed"] == 1

    row = conn.execute("SELECT hit_chunk_ids FROM checkpoints").fetchone()
    ids = json.loads(row[0])
    assert ids == ["ch-alive"]
    conn.close()


def test_05_empty_checkpoint_deleted():
    """T5: 空 hit_ids checkpoint 被删除"""
    conn = _setup_db()
    _insert_checkpoint(conn, "ckpt-empty", "test_proj", ["only-dead"])

    result = store_mm.mmu_notifier_invalidate(conn, ["only-dead"])
    conn.commit()

    assert result["checkpoints_deleted"] == 1
    count = conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
    assert count == 0
    conn.close()


def test_06_no_stale_noop():
    """T6: 无 stale 时无操作（幂等）"""
    conn = _setup_db()
    _insert_test_chunk(conn, "safe-1")
    _insert_trace(conn, "test_proj", [
        {"id": "safe-1", "summary": "s", "score": 0.9},
    ])

    result = store_mm.mmu_notifier_invalidate(conn, ["nonexistent-id"])
    conn.commit()

    assert result["traces_cleaned"] == 0
    assert result["traces_deleted"] == 0
    assert result["refs_removed"] == 0
    conn.close()


def test_07_delete_chunks_auto_triggers():
    """T7: delete_chunks 自动触发 mmu_notifier"""
    conn = _setup_db()
    _insert_test_chunk(conn, "victim-1")
    _insert_test_chunk(conn, "survivor-1")
    _insert_trace(conn, "test_proj", [
        {"id": "victim-1", "summary": "v", "score": 0.9},
        {"id": "survivor-1", "summary": "s", "score": 0.8},
    ])
    conn.commit()

    # delete_chunks should auto-trigger mmu_notifier
    deleted = delete_chunks(conn, ["victim-1"])
    conn.commit()

    assert deleted == 1

    # Verify trace was cleaned
    row = conn.execute("SELECT top_k_json FROM recall_traces").fetchone()
    tk = json.loads(row[0])
    assert len(tk) == 1
    assert tk[0]["id"] == "survivor-1"
    conn.close()


def test_08_checkpoint_gc_global_cap():
    """T8: checkpoint_gc 全局上限"""
    conn = _setup_db()
    # Insert 15 checkpoints across different sessions
    for i in range(15):
        conn.execute("""
            INSERT INTO checkpoints (id, created_at, project, session_id,
             hit_chunk_ids, madvise_hints, query_topics, consumed, chunk_snapshots)
            VALUES (?, datetime('now', ? || ' seconds'), 'proj', ?, '["a"]', '[]', '[]', 0, '[]')
        """, (f"ckpt-{i:02d}", str(i), f"sess-{i % 5}"))
    conn.commit()

    # Default max_global = 10
    result = store_mm.checkpoint_gc(conn)
    conn.commit()

    assert result["total_before"] == 15
    assert result["deleted"] == 5
    assert result["total_after"] == 10

    # Verify the newest 10 remain
    remaining = conn.execute(
        "SELECT id FROM checkpoints ORDER BY created_at DESC"
    ).fetchall()
    assert len(remaining) == 10
    # Newest should be ckpt-14 (highest offset)
    assert remaining[0][0] == "ckpt-14"
    conn.close()


def test_09_checkpoint_gc_under_limit():
    """T9: checkpoint_gc 不删除未超限"""
    conn = _setup_db()
    for i in range(5):
        _insert_checkpoint(conn, f"ckpt-{i}", "proj", ["chunk-1"])

    result = store_mm.checkpoint_gc(conn)
    assert result["deleted"] == 0
    assert result["total_after"] == 5
    conn.close()


def test_10_performance():
    """T10: 性能 100 deleted IDs × 200 traces < 50ms"""
    conn = _setup_db()

    # Create 200 traces each with 10 refs
    deleted_ids = [f"dead-{i}" for i in range(100)]
    alive_ids = [f"alive-{i}" for i in range(50)]

    for i in range(200):
        # Mix dead and alive IDs in each trace
        tk = []
        for j in range(5):
            tk.append({"id": alive_ids[j % 50], "summary": "a", "score": 0.9})
        for j in range(5):
            tk.append({"id": deleted_ids[(i * 5 + j) % 100], "summary": "d", "score": 0.5})
        conn.execute("""
            INSERT INTO recall_traces (timestamp, session_id, project, prompt_hash,
             candidates_count, top_k_json, injected, reason)
            VALUES (datetime('now'), 'perf-sess', 'proj', ?, 10, ?, 1, 'perf')
        """, (f"hash-{i}", json.dumps(tk)))
    conn.commit()

    t0 = time.time()
    result = store_mm.mmu_notifier_invalidate(conn, deleted_ids)
    conn.commit()
    elapsed_ms = (time.time() - t0) * 1000

    assert elapsed_ms < 50, f"Too slow: {elapsed_ms:.1f}ms"
    assert result["traces_cleaned"] == 200  # All had mixed refs
    assert result["refs_removed"] == 1000  # 200 traces × 5 dead refs each
    conn.close()


def test_11_empty_input_safe():
    """T11: 空输入安全"""
    conn = _setup_db()
    result = store_mm.mmu_notifier_invalidate(conn, [])
    assert result["refs_removed"] == 0
    assert result["traces_cleaned"] == 0
    conn.close()


def test_12_json_format_compat():
    """T12: top_k_json 各种格式兼容"""
    conn = _setup_db()

    # Format 1: standard with id/summary/score
    _insert_trace(conn, "proj", [{"id": "dead-f1", "summary": "s", "score": 0.9}])
    # Format 2: with extra fields (chunk_type etc from iter68)
    conn.execute("""
        INSERT INTO recall_traces (timestamp, session_id, project, prompt_hash,
         candidates_count, top_k_json, injected, reason)
        VALUES (datetime('now'), 's', 'proj', 'h2', 5, ?, 1, 'test')
    """, (json.dumps([{"id": "dead-f2", "summary": "s", "score": 0.8, "chunk_type": "decision"}]),))
    # Format 3: NULL top_k_json (should be skipped gracefully)
    conn.execute("""
        INSERT INTO recall_traces (timestamp, session_id, project, prompt_hash,
         candidates_count, top_k_json, injected, reason)
        VALUES (datetime('now'), 's', 'proj', 'h3', 0, NULL, 0, 'empty')
    """)
    conn.commit()

    result = store_mm.mmu_notifier_invalidate(conn, ["dead-f1", "dead-f2"])
    conn.commit()

    # f1 and f2 cleaned, NULL row untouched
    assert result["traces_deleted"] == 2  # Both fully stale
    assert result["refs_removed"] == 2
    # NULL trace still exists
    count = conn.execute("SELECT COUNT(*) FROM recall_traces").fetchone()[0]
    assert count == 1  # Only the NULL one remains
    conn.close()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
