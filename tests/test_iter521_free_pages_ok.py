"""
iter521: free_pages_ok — Dead Page Frame Final Reclaim

OS 类比：Linux __free_pages_ok() (Linus Torvalds, 1991)
  当页面 refcount 降至 0 时归还 buddy allocator free list。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import tmpfs  # noqa: F401,E402 — 测试隔离

import pytest
import sqlite3
import json
from datetime import datetime, timezone, timedelta

from store_vfs import open_db, ensure_schema, insert_chunk, delete_chunks, get_project_chunk_count
from store_mm import free_pages_ok
from config import get as _cfg


PROJECT = "test_free_pages_ok"


def _make_chunk(conn, summary, importance=0.1, access_count=0, oom_adj=0,
                chunk_type="decision", project=PROJECT):
    """插入测试 chunk 并返回 ID。"""
    chunk_id = f"fp-{hash(summary) % 10**8:08d}"
    conn.execute(
        """INSERT OR REPLACE INTO memory_chunks
           (id, summary, content, chunk_type, importance, project,
            access_count, oom_adj, lru_gen, source_session,
            created_at, last_accessed)
           VALUES (?,?,?,?,?,?,?,?,0,'test',?,?)""",
        (chunk_id, summary, summary, chunk_type, importance, project,
         access_count, oom_adj,
         datetime.now(timezone.utc).isoformat(),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return chunk_id


@pytest.fixture
def conn():
    c = open_db()
    ensure_schema(c)
    yield c
    c.close()


class TestFreeBasic:
    """基本功能测试"""

    def test_free_dead_zero_access(self, conn):
        """importance < 0.2 + access=0 → 被释放"""
        cid = _make_chunk(conn, "dead chunk low imp", importance=0.05, access_count=0)
        result = free_pages_ok(conn, PROJECT)
        assert result["freed"] >= 1
        # 确认已删除
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is None

    def test_skip_accessed_chunk(self, conn):
        """importance < 0.2 但 access > 0 → 保留（曾被验证）"""
        cid = _make_chunk(conn, "low imp but accessed", importance=0.10, access_count=3)
        result = free_pages_ok(conn, PROJECT)
        assert result["skipped_accessed"] >= 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None

    def test_skip_mlock_protected(self, conn):
        """oom_adj <= -500 (mlock) → 保护不删"""
        cid = _make_chunk(conn, "mlock protected", importance=0.05, oom_adj=-1000)
        result = free_pages_ok(conn, PROJECT)
        assert result["skipped_protected"] >= 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None

    def test_skip_task_state(self, conn):
        """chunk_type=task_state → 不删"""
        cid = _make_chunk(conn, "active task", importance=0.05,
                          chunk_type="task_state")
        result = free_pages_ok(conn, PROJECT)
        assert result["skipped_protected"] >= 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None


class TestFreeThreshold:
    """阈值边界测试"""

    def test_at_threshold_not_freed(self, conn):
        """importance == dead_threshold → 不删（边界不含）"""
        threshold = _cfg("free_pages.dead_threshold")
        cid = _make_chunk(conn, "at boundary", importance=threshold, access_count=0)
        result = free_pages_ok(conn, PROJECT)
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None  # 在边界值处保留

    def test_above_threshold_not_freed(self, conn):
        """importance > threshold → 不删"""
        cid = _make_chunk(conn, "healthy chunk", importance=0.5, access_count=0)
        result = free_pages_ok(conn, PROJECT)
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None


class TestFreeBatch:
    """批次限制测试"""

    def test_max_per_scan_limit(self, conn):
        """单次最多释放 max_per_scan 个"""
        max_per = _cfg("free_pages.max_per_scan")
        # 插入超过限制的 dead chunks
        for i in range(max_per + 10):
            _make_chunk(conn, f"dead-batch-{i}", importance=0.01, access_count=0)
        result = free_pages_ok(conn, PROJECT)
        assert result["freed"] <= max_per


class TestFreeProjectScope:
    """项目隔离测试"""

    def test_project_isolation(self, conn):
        """指定 project 时不删其他 project 的 chunks"""
        cid_other = _make_chunk(conn, "other project dead", importance=0.01,
                                access_count=0, project="other_project")
        cid_target = _make_chunk(conn, "target project dead", importance=0.01,
                                 access_count=0, project=PROJECT)
        result = free_pages_ok(conn, PROJECT)
        # target 被删
        assert conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid_target,)).fetchone() is None
        # other 保留
        assert conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid_other,)).fetchone() is not None

    def test_no_project_scans_all(self, conn):
        """project=None 时扫描全部"""
        cid1 = _make_chunk(conn, "proj1 dead", importance=0.01, project="p1")
        cid2 = _make_chunk(conn, "proj2 dead", importance=0.01, project="p2")
        result = free_pages_ok(conn, None)
        assert result["freed"] >= 2


class TestFreeEmpty:
    """边界条件"""

    def test_empty_db(self, conn):
        """空 DB 不报错（使用独立 project 避免跨测试干扰）"""
        result = free_pages_ok(conn, "empty_project_521")
        assert result["freed"] == 0
        assert result["total_dead"] == 0

    def test_no_dead_chunks(self, conn):
        """所有 chunks 健康时返回 freed=0"""
        proj = "healthy_only_521"
        _make_chunk(conn, "healthy 1", importance=0.8, access_count=5, project=proj)
        _make_chunk(conn, "healthy 2", importance=0.6, access_count=2, project=proj)
        result = free_pages_ok(conn, proj)
        assert result["freed"] == 0


class TestFreePerformance:
    """性能测试"""

    def test_performance(self, conn):
        """100 chunks 扫描 < 100ms"""
        import time
        for i in range(100):
            _make_chunk(conn, f"perf-chunk-{i}",
                        importance=0.01 if i < 50 else 0.8,
                        access_count=0)
        t0 = time.time()
        result = free_pages_ok(conn, PROJECT)
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 100, f"Too slow: {elapsed:.1f}ms"
        assert result["freed"] > 0
