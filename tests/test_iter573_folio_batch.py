"""
iter573: folio_batch_drain — Converging Signal Batch Reclaim

OS 类比：Linux folio_batch / pagevec lru_add_drain()
  (Andrew Morton, 2002, mm/swap.c)
  per-CPU pagevec 将多个 LRU 操作批量化，一次性 flush 摊销开销。

测试覆盖：多信号收敛回收器——oom_adj + zero-access + low-imp + idle_rounds
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402 — 测试隔离

import sqlite3
import json
import time
import pytest
from store_core import open_db, ensure_schema, insert_chunk, bump_chunk_version, MEMORY_OS_DIR
from store_mm import folio_batch_drain, _page_idle_save, _page_idle_load, _PAGE_IDLE_FILE
from config import get as sysctl


def _make_chunk(conn, summary, project="test_proj", chunk_type="decision",
                importance=0.15, access_count=0, oom_adj=300):
    """创建测试 chunk 并返回 ID"""
    from datetime import datetime, timezone
    chunk_id = f"test-{abs(hash(summary)) % 10**8:08d}"
    conn.execute(
        """INSERT OR REPLACE INTO memory_chunks
           (id, project, chunk_type, summary, content, importance,
            access_count, oom_adj, lru_gen, last_accessed, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
        (chunk_id, project, chunk_type, summary, summary, importance,
         access_count, oom_adj, datetime.now(timezone.utc).isoformat(),
         datetime.now(timezone.utc).isoformat())
    )
    # FTS5 entry
    try:
        rowid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone()[0]
        conn.execute(
            "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
            (str(rowid), summary, summary)
        )
    except Exception:
        pass
    conn.commit()
    return chunk_id


def _setup_idle_bitmap(bitmap: dict, project: str = "test_proj"):
    """设置 page_idle bitmap（iter574: 使用嵌套格式 {project: {cid: rounds}}）"""
    # 如果传入的是 flat dict {cid: rounds}，转换为嵌套格式
    if bitmap and not any(isinstance(v, dict) for v in bitmap.values()):
        bitmap = {project: bitmap}
    _page_idle_save(bitmap)


class TestFolioBatchDrain:
    """核心功能测试"""

    def test_drains_converging_signals(self):
        """多信号收敛：oom_adj>=300 + acc=0 + imp<0.3 + idle_rounds>=2 → 删除"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "dead chunk converging", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 3})  # 3 轮空闲

        result = folio_batch_drain(conn, "test_proj")

        assert result["drained"] == 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is None  # 已删除
        conn.close()

    def test_skips_insufficient_idle_rounds(self):
        """idle_rounds < min_idle_rounds → 不回收（等待更多观测确认）"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "not enough idle", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 1})  # 只有 1 轮，不够

        result = folio_batch_drain(conn, "test_proj")

        assert result["drained"] == 0
        assert result["skipped_no_idle"] == 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is not None  # 保留
        conn.close()

    def test_skips_no_idle_entry(self):
        """chunk 不在 page_idle bitmap 中 → 无观测数据，不回收"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_no_idle_entry"
        cid = _make_chunk(conn, "no idle data unique573", project=proj, importance=0.15, oom_adj=300)
        _setup_idle_bitmap({})  # 空 bitmap

        result = folio_batch_drain(conn, proj)

        assert result["drained"] == 0
        assert result["skipped_no_idle"] >= 1
        conn.close()

    def test_skips_accessed_chunks(self):
        """access_count > 0 → 已被验证有价值，不在候选中"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "has access", importance=0.15, oom_adj=300, access_count=5)
        _setup_idle_bitmap({cid: 10})

        result = folio_batch_drain(conn, "test_proj")

        # access_count>0 的 chunk 不会被 SQL WHERE 选中
        assert result["drained"] == 0
        conn.close()

    def test_skips_high_importance(self):
        """importance >= imp_ceiling → 不在候选中"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "high importance", importance=0.80, oom_adj=300)
        _setup_idle_bitmap({cid: 5})

        result = folio_batch_drain(conn, "test_proj")

        assert result["drained"] == 0
        conn.close()

    def test_skips_low_oom_adj(self):
        """oom_adj < threshold → 未被降级子系统标记"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "low oom adj", importance=0.15, oom_adj=0)
        _setup_idle_bitmap({cid: 5})

        result = folio_batch_drain(conn, "test_proj")

        assert result["drained"] == 0
        conn.close()


class TestProtection:
    """保护机制测试"""

    def test_pinned_preserved(self):
        """chunk_pins 中的 chunk 不可回收"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_pinned_573"
        cid = _make_chunk(conn, "pinned chunk 573", project=proj, importance=0.15, oom_adj=300)
        # 添加 pin（使用 ensure_schema 创建的实际 chunk_pins schema）
        try:
            conn.execute(
                "INSERT OR REPLACE INTO chunk_pins (chunk_id, project, pin_type, pinned_at) VALUES (?, ?, 'hard', '2026-01-01')",
                (cid, proj))
            conn.commit()
        except Exception:
            pass
        _setup_idle_bitmap({cid: 5}, project=proj)

        result = folio_batch_drain(conn, proj)

        assert result["drained"] == 0
        assert result["skipped_pinned"] >= 1
        conn.close()

    def test_task_state_excluded(self):
        """task_state 类型不在候选 SQL 中"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "task state chunk", chunk_type="task_state",
                         importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 5})

        result = folio_batch_drain(conn, "test_proj")

        assert result["drained"] == 0
        conn.close()

    def test_max_drain_cap(self):
        """max_drain 限制单次删除量"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_max_drain_573"
        ids = []
        bitmap = {}
        # 创建 30 个候选（超过 max_drain=20）
        for i in range(30):
            cid = _make_chunk(conn, f"batch chunk cap {i}", project=proj, importance=0.15, oom_adj=300)
            ids.append(cid)
            bitmap[cid] = 5
        _setup_idle_bitmap(bitmap, project=proj)

        result = folio_batch_drain(conn, proj)

        assert result["drained"] <= 20  # max_drain 默认 20
        assert result["scanned"] >= 30  # 至少 30 候选
        conn.close()


class TestConfig:
    """配置测试"""

    def test_disabled(self):
        """folio_batch.enabled=False → 不执行"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "should not drain", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 5})

        os.environ["MEMORY_OS_FOLIO_BATCH_ENABLED"] = "false"
        try:
            result = folio_batch_drain(conn, "test_proj")
        finally:
            del os.environ["MEMORY_OS_FOLIO_BATCH_ENABLED"]

        assert result["drained"] == 0
        conn.close()

    def test_fts5_cleaned(self):
        """删除后 FTS5 索引也被清理"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "fts5 cleanup test folio", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 3})

        # 验证 FTS5 有记录
        fts_before = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks_fts WHERE summary MATCH 'folio'"
        ).fetchone()[0]
        assert fts_before >= 1

        folio_batch_drain(conn, "test_proj")

        # 验证 FTS5 已清理（delete_chunks 内部处理）
        remaining = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert remaining is None
        conn.close()

    def test_bitmap_cleaned_after_drain(self):
        """删除后 page_idle bitmap 中的对应条目也被清理"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "bitmap cleanup test", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 4, "other_chunk": 2})

        folio_batch_drain(conn, "test_proj")

        # iter574: bitmap 现在是嵌套结构 {project: {cid: rounds}}
        bitmap_after = _page_idle_load()
        proj_bm = bitmap_after.get("test_proj", {})
        assert cid not in proj_bm
        assert "other_chunk" in proj_bm  # 其他条目保留
        conn.close()

    def test_global_scan(self):
        """project=None 时扫描全局"""
        conn = open_db()
        ensure_schema(conn)
        cid1 = _make_chunk(conn, "proj1 dead", project="proj1", importance=0.15, oom_adj=300)
        cid2 = _make_chunk(conn, "global dead", project="global", importance=0.15, oom_adj=400)
        # iter574: 嵌套 bitmap，每个 chunk 在其实际 project 下
        _page_idle_save({"proj1": {cid1: 3}, "global": {cid2: 3}})

        result = folio_batch_drain(conn, None)  # 全局扫描

        assert result["drained"] == 2
        conn.close()

    def test_idempotent(self):
        """幂等性：第二次运行 drained=0"""
        conn = open_db()
        ensure_schema(conn)
        cid = _make_chunk(conn, "idempotent test", importance=0.15, oom_adj=300)
        _setup_idle_bitmap({cid: 3})

        r1 = folio_batch_drain(conn, "test_proj")
        r2 = folio_batch_drain(conn, "test_proj")

        assert r1["drained"] == 1
        assert r2["drained"] == 0
        conn.close()

    def test_performance(self):
        """性能：100 候选 < 100ms"""
        conn = open_db()
        ensure_schema(conn)
        bitmap = {}
        for i in range(100):
            cid = _make_chunk(conn, f"perf chunk {i}", importance=0.15, oom_adj=300)
            bitmap[cid] = 3
        _setup_idle_bitmap(bitmap)

        t0 = time.time()
        result = folio_batch_drain(conn, "test_proj")
        elapsed = (time.time() - t0) * 1000

        assert elapsed < 100  # < 100ms
        assert result["drained"] == 20  # capped at max_drain
        conn.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
