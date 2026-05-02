"""
test_iter512_gc_namespace.py — gc_namespace 测试（Process Namespace Cleanup）

迭代512：OS 类比 Linux pid_ns_release_proc() — PID namespace 销毁时清理所有 artifacts
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: F401 — 测试隔离
import json
import sqlite3
import time
import uuid
import pytest
from datetime import datetime, timezone

from store import open_db, ensure_schema, insert_chunk, gc_namespace
from store_mm import _TEST_NS_RE


def _make_chunk(project, summary="test chunk"):
    """Helper: 构造完整的 chunk dict。"""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "summary": summary,
        "content": "content for " + summary,
        "chunk_type": "decision",
        "importance": 0.5,
        "project": project,
        "source_session": "sess1",
        "created_at": now,
        "updated_at": now,
        "last_accessed": now,
        "retrievability": 1.0,
    }


@pytest.fixture(autouse=True)
def _clean_tables():
    """每个测试前清空辅助表，防止跨测试污染。"""
    conn = open_db()
    ensure_schema(conn)
    for tbl in ["recall_traces", "shadow_traces", "memory_chunks"]:
        try:
            conn.execute(f"DELETE FROM {tbl}")
        except Exception:
            pass
    # FTS5 rebuild
    try:
        conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts) VALUES('rebuild')")
    except Exception:
        pass
    conn.commit()
    conn.close()
    yield


def _insert_trace(conn, project, session_id="sess1", prompt_hash="hash1"):
    """Helper: 插入 recall_trace（使用实际 schema）。"""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO recall_traces (timestamp, session_id, project, prompt_hash, "
        "candidates_count, top_k_json, injected, reason) "
        "VALUES (?, ?, ?, ?, 5, '[]', 1, 'test')",
        (now, session_id, project, prompt_hash))


def _ensure_checkpoints_table(conn):
    """Helper: 确保 checkpoints 表存在（tmpfs DB 可能不含此表）。"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            id TEXT PRIMARY KEY,
            created_at TEXT,
            project TEXT,
            session_id TEXT,
            hit_chunk_ids TEXT,
            madvise_hints TEXT,
            query_topics TEXT,
            consumed INTEGER DEFAULT 0,
            chunk_snapshots TEXT
        )
    """)


def _insert_shadow(conn, project, session_id=None):
    """Helper: 插入 shadow_trace（session_id 自动生成避免 UNIQUE 冲突）。"""
    if session_id is None:
        session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO shadow_traces (session_id, project, updated_at, top_k_ids) "
        "VALUES (?, ?, ?, '[]')",
        (session_id, project, now))


# ── T1: 空 DB 不崩溃 ──
def test_empty_db():
    conn = open_db()
    ensure_schema(conn)
    result = gc_namespace(conn)
    assert result["test_projects"] == []
    assert result["traces_deleted"] == 0
    assert result["checkpoints_deleted"] == 0
    assert result["shadows_deleted"] == 0
    assert result["chunks_deleted"] == 0
    conn.close()


# ── T2: 正确识别 test namespace 并清理 traces ──
def test_detect_test_projects():
    conn = open_db()
    ensure_schema(conn)
    test_projects = ["test_psi_normal", "test-swap-compat", "test_psi_ssh",
                     "perf_bench_1", "bench_latency"]
    real_projects = ["git:abc123", "abspath:def456", "global", "gitroot:xyz"]

    for proj in test_projects + real_projects:
        _insert_trace(conn, proj)
    conn.commit()

    result = gc_namespace(conn)
    assert set(result["test_projects"]) == set(test_projects)
    assert result["traces_deleted"] == len(test_projects)

    # 真实 project traces 不受影响
    remaining = conn.execute(
        "SELECT COUNT(*) FROM recall_traces").fetchone()[0]
    assert remaining == len(real_projects)
    conn.close()


# ── T3: 清理 checkpoints ──
def test_clean_checkpoints():
    conn = open_db()
    ensure_schema(conn)
    _ensure_checkpoints_table(conn)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        "INSERT INTO checkpoints (id, project, session_id, created_at, "
        "hit_chunk_ids, madvise_hints, query_topics) "
        "VALUES (?, ?, 'sess1', ?, '[]', '[]', '[]')",
        ("ckpt-test1", "test_psi_hd", now))
    conn.execute(
        "INSERT INTO checkpoints (id, project, session_id, created_at, "
        "hit_chunk_ids, madvise_hints, query_topics) "
        "VALUES (?, ?, 'sess1', ?, '[]', '[]', '[]')",
        ("ckpt-real1", "git:real", now))
    conn.commit()

    result = gc_namespace(conn)
    assert result["checkpoints_deleted"] == 1
    remaining = conn.execute(
        "SELECT COUNT(*) FROM checkpoints").fetchone()[0]
    assert remaining == 1
    conn.close()


# ── T4: 清理 shadow_traces ──
def test_clean_shadow_traces():
    conn = open_db()
    ensure_schema(conn)

    _insert_shadow(conn, "test-persist")
    _insert_shadow(conn, "abspath:real")
    conn.commit()

    result = gc_namespace(conn)
    assert result["shadows_deleted"] == 1
    remaining = conn.execute(
        "SELECT COUNT(*) FROM shadow_traces").fetchone()[0]
    assert remaining == 1
    conn.close()


# ── T5: 防御性清理 memory_chunks（含 FTS5 同步）──
def test_clean_test_chunks():
    conn = open_db()
    ensure_schema(conn)

    insert_chunk(conn, _make_chunk("test_psi_normal", "test chunk for psi"))
    insert_chunk(conn, _make_chunk("git:abc123", "real decision about auth"))
    conn.commit()

    result = gc_namespace(conn)
    assert result["chunks_deleted"] == 1

    remaining = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
    assert remaining == 1

    # FTS5 consistent
    fts_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts").fetchone()[0]
    assert fts_count == 1
    conn.close()


# ── T6: regex 正确匹配测试模式 ──
def test_regex_patterns():
    matches = [
        "test_psi_normal", "test-swap-compat", "test_psi_ssh",
        "test_psi_hd", "test_psi_mixed", "test-persist", "test-project",
        "Test_Upper", "TEST_LOUD",
        "perf_bench", "perf-latency",
        "bench_throughput", "bench-io",
        "forktest", "time-test", "func-test",
    ]
    for p in matches:
        assert _TEST_NS_RE.match(p), f"Should match: {p}"

    no_matches = [
        "git:abc123", "abspath:def456", "global", "gitroot:xyz",
        "contest_results", "latest_test",
        "testing", "performance",
    ]
    for p in no_matches:
        assert not _TEST_NS_RE.match(p), f"Should NOT match: {p}"


# ── T7: 幂等性 — 连续调用不出错 ──
def test_idempotent():
    conn = open_db()
    ensure_schema(conn)

    _insert_trace(conn, "test_idem")
    conn.commit()

    r1 = gc_namespace(conn)
    assert r1["traces_deleted"] == 1
    r2 = gc_namespace(conn)
    assert r2["traces_deleted"] == 0
    assert r2["test_projects"] == []
    conn.close()


# ── T8: 性能 — 100 test traces < 50ms ──
def test_performance():
    conn = open_db()
    ensure_schema(conn)

    for i in range(100):
        _insert_trace(conn, f"test_perf_{i % 5}", session_id=f"sess_{i}",
                       prompt_hash=f"hash_{i}")
    conn.commit()

    start = time.perf_counter()
    result = gc_namespace(conn)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result["traces_deleted"] == 100
    assert elapsed_ms < 50, f"Too slow: {elapsed_ms:.1f}ms"
    print(f"Performance: 100 traces cleaned in {elapsed_ms:.1f}ms")
    conn.close()


# ── T9: 混合清理 — 多表同时有 test 数据 ──
def test_mixed_cleanup():
    conn = open_db()
    ensure_schema(conn)
    _ensure_checkpoints_table(conn)
    proj = "test_mixed_all"
    now = datetime.now(timezone.utc).isoformat()

    _insert_trace(conn, proj)
    conn.execute(
        "INSERT INTO checkpoints (id, project, session_id, created_at, "
        "hit_chunk_ids, madvise_hints, query_topics) "
        "VALUES (?, ?, 'sess1', ?, '[]', '[]', '[]')",
        ("ckpt-mixed", proj, now))
    _insert_shadow(conn, proj)
    insert_chunk(conn, _make_chunk(proj, "mixed test chunk"))
    conn.commit()

    result = gc_namespace(conn)
    assert result["test_projects"] == [proj]
    assert result["traces_deleted"] == 1
    assert result["checkpoints_deleted"] == 1
    assert result["shadows_deleted"] == 1
    assert result["chunks_deleted"] == 1
    conn.close()


# ── T10: 不影响包含 "test" 但非前缀的 project ──
def test_no_false_positive():
    conn = open_db()
    ensure_schema(conn)

    safe_projects = ["contest", "latest_test", "testing", "attest", "protest"]
    for proj in safe_projects:
        _insert_trace(conn, proj)
    conn.commit()

    result = gc_namespace(conn)
    assert result["test_projects"] == []
    assert result["traces_deleted"] == 0

    remaining = conn.execute(
        "SELECT COUNT(*) FROM recall_traces").fetchone()[0]
    assert remaining == len(safe_projects)
    conn.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
