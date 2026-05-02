"""
iter505: shrink_dcache — Cross-Project Stale Object Reclaim 测试

OS 类比：Linux shrink_dcache_sb() — 超级块级 dentry cache 回收
验证跨项目零访问 chunk 的分级降权与删除逻辑。
"""
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

# tmpfs 隔离
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
import tmpfs  # noqa: F401 — 自动设置临时目录

from store_vfs import (
    open_db, ensure_schema, insert_chunk, delete_chunks,
    shrink_dcache, bump_chunk_version, get_chunk_count,
)
from schema import MemoryChunk


def _fresh_db():
    """每个测试用新的 DB 连接（ensure_schema 重建表）."""
    conn = open_db()
    ensure_schema(conn)
    # 清空残留数据
    conn.execute("DELETE FROM memory_chunks")
    try:
        conn.execute("DELETE FROM memory_chunks_fts")
    except Exception:
        pass
    conn.commit()
    return conn


def _make_chunk(conn, project="test-proj", importance=0.8, access_count=0,
                chunk_type="decision", age_days=5, summary="test chunk"):
    """创建一个指定属性的测试 chunk."""
    import uuid
    chunk_id = str(uuid.uuid4())
    created_at = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    conn.execute(
        """INSERT INTO memory_chunks (id, project, chunk_type, summary, content,
           importance, access_count, created_at, last_accessed, lru_gen, oom_adj)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)""",
        (chunk_id, project, chunk_type, summary, summary,
         importance, access_count, created_at, created_at),
    )
    conn.commit()
    return chunk_id


def test_cold_start_protection():
    """T1: 总 chunks < min_total 时不触发回收."""
    conn = _fresh_db()
    # 只创建 5 个 chunks（< 30 默认阈值）
    for i in range(5):
        _make_chunk(conn, age_days=10, importance=0.5)

    result = shrink_dcache(conn, "test-proj")
    assert result["phase1_candidates"] == 0
    assert result["phase2_demoted"] == 0
    assert result["phase3_deleted"] == 0
    conn.close()
    print("T1 PASS: cold start protection")


def test_age_filter():
    """T2: 只有超过 min_age_days 的零访问 chunks 被扫描."""
    conn = _fresh_db()
    # 35 个 chunks（> 30 阈值），其中 10 个 age=1d（太新），25 个 age=5d
    for i in range(10):
        _make_chunk(conn, age_days=1, importance=0.5)
    for i in range(25):
        _make_chunk(conn, age_days=5, importance=0.5)

    result = shrink_dcache(conn, "test-proj")
    # 只有 age=5d 的 25 个被扫描
    assert result["phase1_candidates"] == 25
    conn.close()
    print("T2 PASS: age filter works")


def test_access_count_filter():
    """T3: access_count > 0 的 chunks 不被回收."""
    conn = _fresh_db()
    # 35 个 chunks，其中 15 个有访问
    for i in range(15):
        _make_chunk(conn, age_days=5, importance=0.5, access_count=3)
    for i in range(20):
        _make_chunk(conn, age_days=5, importance=0.5, access_count=0)

    result = shrink_dcache(conn, "test-proj")
    # 只有 access_count=0 的 20 个被扫描
    assert result["phase1_candidates"] == 20
    conn.close()
    print("T3 PASS: access_count filter")


def test_high_importance_demote():
    """T4: importance >= 0.8 的 chunk 用 demote_high_factor (0.6) 降级."""
    conn = _fresh_db()
    for i in range(35):
        _make_chunk(conn, age_days=5, importance=0.9)

    shrink_dcache(conn, "test-proj")

    # 检查降级后 importance
    row = conn.execute(
        "SELECT importance FROM memory_chunks WHERE importance < 0.9 LIMIT 1"
    ).fetchone()
    assert row is not None
    # 0.9 * 0.6 = 0.54
    assert abs(row[0] - 0.54) < 0.01
    conn.close()
    print("T4 PASS: high importance demote factor")


def test_low_importance_demote_and_oom():
    """T5: importance < 0.8 的 chunk 用 demote_low_factor (0.4) + oom_adj += 500."""
    conn = _fresh_db()
    for i in range(35):
        _make_chunk(conn, age_days=5, importance=0.6)

    shrink_dcache(conn, "test-proj")

    # 检查降级后 importance: 0.6 * 0.4 = 0.24
    row = conn.execute(
        "SELECT importance, oom_adj FROM memory_chunks WHERE importance < 0.6 LIMIT 1"
    ).fetchone()
    assert row is not None
    assert abs(row[0] - 0.24) < 0.01
    assert row[1] == 500
    conn.close()
    print("T5 PASS: low importance demote + oom_adj")


def test_phase3_delete():
    """T6: 降级后 importance < delete_threshold (0.2) 直接删除."""
    conn = _fresh_db()
    # importance=0.3, 降级后 0.3*0.4=0.12 < 0.2 → 应该被删除
    for i in range(35):
        _make_chunk(conn, age_days=5, importance=0.3)

    before = get_chunk_count(conn)
    result = shrink_dcache(conn, "test-proj")
    after = get_chunk_count(conn)

    assert result["phase3_deleted"] > 0
    assert after < before
    conn.close()
    print("T6 PASS: phase3 delete low-value chunks")


def test_cross_project():
    """T7: 跨项目扫描，包括 global 层."""
    conn = _fresh_db()
    # 在不同 project 创建 chunks
    for i in range(15):
        _make_chunk(conn, project="global", age_days=5, importance=0.5)
    for i in range(15):
        _make_chunk(conn, project="proj-a", age_days=5, importance=0.5)
    for i in range(10):
        _make_chunk(conn, project="proj-b", age_days=5, importance=0.5)

    result = shrink_dcache(conn, "proj-a")
    # 应该扫描所有 project 的零访问 chunks（40 个全部）
    assert result["phase1_candidates"] == 40
    assert result["phase2_demoted"] == 40
    conn.close()
    print("T7 PASS: cross-project scan including global")


def test_pinned_protection():
    """T8: pinned chunks 不被回收."""
    conn = _fresh_db()

    ids = []
    for i in range(35):
        cid = _make_chunk(conn, age_days=5, importance=0.5)
        ids.append(cid)

    # Pin 前 5 个
    now = datetime.now(timezone.utc).isoformat()
    for cid in ids[:5]:
        conn.execute(
            "INSERT OR REPLACE INTO chunk_pins (chunk_id, project, pin_type, pinned_at) VALUES (?, ?, ?, ?)",
            (cid, "test-proj", "hard", now),
        )
    conn.commit()

    result = shrink_dcache(conn, "test-proj")
    # 35 candidates 但只有 30 被 demoted（5 pinned 跳过）
    assert result["phase1_candidates"] == 35
    assert result["phase2_demoted"] == 30
    conn.close()
    print("T8 PASS: pinned chunks protected")


def test_max_reclaim_limit():
    """T9: 批次限制 max_reclaim_per_scan."""
    conn = _fresh_db()
    # 创建 100 个 chunks（> 50 默认限制）
    for i in range(100):
        _make_chunk(conn, age_days=5, importance=0.5)

    result = shrink_dcache(conn, "test-proj")
    # 最多扫描 50 个
    assert result["phase1_candidates"] == 50
    assert result["phase2_demoted"] <= 50
    conn.close()
    print("T9 PASS: max_reclaim limit respected")


def test_task_state_protected():
    """T10: chunk_type=task_state 不被回收."""
    conn = _fresh_db()
    for i in range(20):
        _make_chunk(conn, age_days=5, importance=0.5, chunk_type="task_state")
    for i in range(15):
        _make_chunk(conn, age_days=5, importance=0.5, chunk_type="decision")

    result = shrink_dcache(conn, "test-proj")
    # 只有 decision 的 15 个被扫描，task_state 保护
    assert result["phase1_candidates"] == 15
    conn.close()
    print("T10 PASS: task_state protected")


def test_oom_adj_protected():
    """T11: oom_adj <= -1000 的 chunks 不被回收."""
    conn = _fresh_db()
    for i in range(35):
        cid = _make_chunk(conn, age_days=5, importance=0.5)
    # 把前 10 个标记为 oom_adj=-1000（绝对保护）
    rows = conn.execute("SELECT id FROM memory_chunks LIMIT 10").fetchall()
    for r in rows:
        conn.execute("UPDATE memory_chunks SET oom_adj=-1000 WHERE id=?", (r[0],))
    conn.commit()

    result = shrink_dcache(conn, "test-proj")
    # 只有 25 个被扫描（35 - 10 protected）
    assert result["phase1_candidates"] == 25
    conn.close()
    print("T11 PASS: oom_adj -1000 protected")


def test_performance():
    """T12: 性能测试 — 100 chunks 扫描应 < 50ms."""
    conn = _fresh_db()
    for i in range(100):
        _make_chunk(conn, age_days=5, importance=0.6)

    t0 = time.time()
    result = shrink_dcache(conn, "test-proj")
    elapsed = (time.time() - t0) * 1000

    assert elapsed < 50, f"Too slow: {elapsed:.1f}ms"
    assert result["duration_ms"] < 50
    conn.close()
    print(f"T12 PASS: performance {elapsed:.1f}ms")


if __name__ == "__main__":
    test_cold_start_protection()
    test_age_filter()
    test_access_count_filter()
    test_high_importance_demote()
    test_low_importance_demote_and_oom()
    test_phase3_delete()
    test_cross_project()
    test_pinned_protection()
    test_max_reclaim_limit()
    test_task_state_protected()
    test_oom_adj_protected()
    test_performance()
    print("\n✅ ALL 12 TESTS PASSED — iter505 shrink_dcache")
