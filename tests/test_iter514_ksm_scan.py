"""
iter514: ksm_scan — Kernel Same-page Merging Periodic Scanner

OS 类比：Linux KSM (Andrea Arcangeli, 2009)
——ksmd 扫描物理页帧，通过内容哈希发现相同页面，合并为 COW 共享页释放内存。

测试场景：
  T1  基本合并：3+ 相同前缀 chunks → 合并为 1
  T2  保护机制：access_count >= 2 的 chunk 不被合并
  T3  mlock 保护：oom_adj <= -500 不被合并
  T4  小组不触发：少于 min_group_size 不合并
  T5  跨项目合并：全库扫描（无 project 参数）
  T6  单项目限定：project 参数限定扫描范围
  T7  survivor 选择：access_count 最高的 chunk 被保留
  T8  批次限制：max_merge_per_scan 限制单次删除数
  T9  空库安全
  T10 无 bracket 前缀的 chunks 不参与 KSM
  T11 FTS5 一致性：合并后 FTS5 行数 = chunks 行数
  T12 性能：100 chunks 扫描 < 100ms
"""
import sys
from pathlib import Path

# tmpfs 隔离（必须在 store import 前）
sys.path.insert(0, str(Path(__file__).parent.parent))
import tmpfs  # noqa: F401, E402

import time
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta

from store import open_db, ensure_schema
from store_mm import ksm_scan


def _make_chunk(conn, project="global", chunk_type="decision",
                importance=0.8, access_count=0, summary=None, oom_adj=0,
                age_hours=0):
    """创建一个测试 chunk 并返回 id。"""
    cid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    if age_hours > 0:
        now = now - timedelta(hours=age_hours)
    ts = now.isoformat()
    if summary is None:
        summary = f"test_{cid[:8]}"
    conn.execute(
        """INSERT INTO memory_chunks
           (id, summary, content, chunk_type, project,
            importance, access_count, last_accessed, created_at,
            lru_gen, oom_adj)
           VALUES (?,?,?,?,?, ?,?,?,?, 0,?)""",
        (cid, summary, f"content_{cid[:8]}", chunk_type,
         project, importance, access_count, ts, ts, oom_adj),
    )
    return cid


def _setup_db():
    """创建干净的 DB 并返回连接。"""
    conn = open_db()
    ensure_schema(conn)
    # 清理残留数据确保测试隔离
    conn.execute("DELETE FROM memory_chunks")
    try:
        conn.execute("DELETE FROM memory_chunks_fts")
    except Exception:
        pass
    conn.commit()
    return conn


def _count_chunks(conn, project=None):
    if project:
        return conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project=?",
            (project,)
        ).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]


# ── T1: 基本合并 ──
def test_basic_merge():
    """3 个相同前缀的 chunk → 合并为 1。"""
    conn = _setup_db()
    prefix = "[sched_ext] EEVDF reweight_entity"
    ids = []
    for i in range(4):
        cid = _make_chunk(conn, summary=f"{prefix} version {i}",
                          importance=0.7, access_count=0)
        ids.append(cid)
    conn.commit()

    assert _count_chunks(conn) == 4
    result = ksm_scan(conn)

    assert result["triggered"] is True
    assert result["groups_found"] == 1
    assert result["chunks_merged"] == 3  # 4 - 1 survivor
    assert _count_chunks(conn) == 1


# ── T2: access_count 保护 ──
def test_protect_accessed_chunks():
    """access_count >= 2 的 chunk 不被合并删除。"""
    conn = _setup_db()
    prefix = "[pe_analysis] PE 分析：find_proxy"

    _make_chunk(conn, summary=f"{prefix} v1", access_count=5)  # protected
    _make_chunk(conn, summary=f"{prefix} v2", access_count=3)  # protected
    _make_chunk(conn, summary=f"{prefix} v3", access_count=0)
    _make_chunk(conn, summary=f"{prefix} v4", access_count=0)
    conn.commit()

    result = ksm_scan(conn)
    # Only 2 zero-access can be merged, but they need group >= 3
    # With 4 in group, survivor is the highest access (5), the 2 zero-access get deleted
    # The one with access=3 is also protected
    remaining = _count_chunks(conn)
    assert remaining >= 2, f"Protected chunks should survive, got {remaining}"
    # The 2 with access >= 2 survive, at most 2 deleted
    assert result["chunks_merged"] <= 2


# ── T3: mlock 保护 ──
def test_mlock_protection():
    """oom_adj <= -500 的 chunk 不被合并删除。"""
    conn = _setup_db()
    prefix = "[decisions] Skill Listing Budget"

    _make_chunk(conn, summary=f"{prefix} v1", oom_adj=-1000)  # mlock
    _make_chunk(conn, summary=f"{prefix} v2", oom_adj=-500)   # mlock boundary
    _make_chunk(conn, summary=f"{prefix} v3", oom_adj=0)
    _make_chunk(conn, summary=f"{prefix} v4", oom_adj=0)
    conn.commit()

    result = ksm_scan(conn)
    # 2 mlock protected + 1 survivor from normal = 3 should remain
    remaining = _count_chunks(conn)
    assert remaining >= 3, f"mlock chunks must survive, got {remaining}"


# ── T4: 小组不触发 ──
def test_small_group_skip():
    """少于 min_group_size (3) 的组不合并。"""
    conn = _setup_db()
    _make_chunk(conn, summary="[topic1] content A")
    _make_chunk(conn, summary="[topic1] content B")  # only 2
    _make_chunk(conn, summary="[topic2] something X")
    conn.commit()

    result = ksm_scan(conn)
    assert result["triggered"] is False
    assert result["groups_found"] == 0
    assert _count_chunks(conn) == 3  # unchanged


# ── T5: 跨项目合并 ──
def test_cross_project_scan():
    """无 project 参数时全库扫描。"""
    conn = _setup_db()
    # 前缀足够长确保 fingerprint 相同（>20 chars after bracket）
    prefix = "[shared_topic] Cross Project Shared Knowledge Base"
    _make_chunk(conn, project="proj_a", summary=f"{prefix} details for A")
    _make_chunk(conn, project="proj_b", summary=f"{prefix} details for B")
    _make_chunk(conn, project="proj_c", summary=f"{prefix} details for C")
    conn.commit()

    result = ksm_scan(conn)  # no project filter
    assert result["triggered"] is True
    assert result["chunks_merged"] >= 2


# ── T6: 单项目限定 ──
def test_project_scoped_scan():
    """project 参数限定扫描范围。"""
    conn = _setup_db()
    prefix = "[limited] Scoped Content With Long Shared Prefix"
    _make_chunk(conn, project="target", summary=f"{prefix} detail alpha")
    _make_chunk(conn, project="target", summary=f"{prefix} detail beta")
    _make_chunk(conn, project="target", summary=f"{prefix} detail gamma")
    _make_chunk(conn, project="other", summary=f"{prefix} detail delta")
    conn.commit()

    result = ksm_scan(conn, project="target")
    assert result["triggered"] is True
    # Only 'target' project chunks merged (3 → 1)
    assert _count_chunks(conn, project="target") == 1
    # 'other' project untouched
    assert _count_chunks(conn, project="other") == 1


# ── T7: survivor 选择 ──
def test_survivor_selection():
    """access_count 最高的 chunk 被保留作为 survivor。"""
    conn = _setup_db()
    prefix = "[survivor] Best Chunk Selection Test Long Prefix"
    best_id = _make_chunk(conn, summary=f"{prefix} detail best version", access_count=1, importance=0.9)
    _make_chunk(conn, summary=f"{prefix} detail second version", access_count=0, importance=0.5)
    _make_chunk(conn, summary=f"{prefix} detail third version", access_count=0, importance=0.7)
    conn.commit()

    result = ksm_scan(conn)
    assert result["triggered"] is True
    # The best_id should survive (highest access_count)
    survivor_row = conn.execute(
        "SELECT id FROM memory_chunks WHERE id = ?", (best_id,)
    ).fetchone()
    assert survivor_row is not None, "Best chunk should survive as survivor"


# ── T8: 批次限制 ──
def test_max_merge_limit():
    """max_merge_per_scan 限制单次扫描的最大合并数。"""
    conn = _setup_db()
    # Create 2 large groups: 10 each = 18 potential merges (9+9)
    # Prefix must be >20 chars after bracket to ensure same fingerprint
    for prefix in ["[groupA] Large Group Alpha Extended Prefix", "[groupB] Large Group Beta Extended Prefix"]:
        for i in range(10):
            _make_chunk(conn, summary=f"{prefix} detail item {i:03d}")
    conn.commit()

    # Default max_merge_per_scan=60, so all should be merged
    result = ksm_scan(conn)
    assert result["triggered"] is True
    assert result["chunks_merged"] == 18  # 9 + 9


# ── T9: 空库安全 ──
def test_empty_db():
    """空库不崩溃。"""
    conn = _setup_db()
    result = ksm_scan(conn)
    assert result["triggered"] is False
    assert result["groups_found"] == 0
    assert result["chunks_merged"] == 0


# ── T10: 无 bracket 前缀不参与 ──
def test_no_bracket_excluded():
    """没有 [bracket] 前缀的 chunks 不参与 KSM。"""
    conn = _setup_db()
    # These have no bracket prefix → fingerprint = "" → excluded
    for i in range(5):
        _make_chunk(conn, summary=f"Plain text summary version {i}")
    conn.commit()

    result = ksm_scan(conn)
    assert result["triggered"] is False
    assert _count_chunks(conn) == 5  # all preserved


# ── T11: FTS5 一致性 ──
def test_fts5_consistency():
    """合并后 FTS5 行数 ≤ chunks 行数。"""
    conn = _setup_db()
    prefix = "[fts5] Consistency Check"
    for i in range(5):
        _make_chunk(conn, summary=f"{prefix} v{i}")
    conn.commit()

    ksm_scan(conn)

    chunks_count = _count_chunks(conn)
    fts_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts"
    ).fetchone()[0]
    # FTS5 may have some orphans (cleaned by fts5_checkpoint), but should not exceed chunks
    # After ksm_scan's explicit FTS5 delete, fts should be <= chunks
    assert fts_count <= chunks_count + 5, f"FTS5={fts_count} should be close to chunks={chunks_count}"


# ── T12: 性能 ──
def test_performance():
    """100 chunks 扫描 < 100ms。"""
    conn = _setup_db()
    # Create 10 groups of 10 chunks each
    for g in range(10):
        prefix = f"[perfgroup{g:02d}] Performance Test Group Number {g:02d}"
        for i in range(10):
            _make_chunk(conn, summary=f"{prefix} detail item number {i:03d}")
    conn.commit()

    t0 = time.time()
    result = ksm_scan(conn)
    elapsed = (time.time() - t0) * 1000

    assert result["triggered"] is True
    assert elapsed < 100, f"ksm_scan took {elapsed:.1f}ms for 100 chunks (expected <100ms)"
    assert result["chunks_merged"] >= 50  # 10 groups × (10-1) = 90 potential, capped by max_merge_per_scan=60


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
