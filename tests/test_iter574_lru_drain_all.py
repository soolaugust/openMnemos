"""
iter574: lru_add_drain_all — Fix folio_batch_drain bitmap level mismatch + global coverage

OS 类比：Linux lru_add_drain_all() (Andrew Morton, 2005, mm/swap.c)
  per-CPU pagevec 分散在各 CPU 本地 batch 中。lru_add_drain_all()
  向所有 CPU 发送 IPI 执行 drain，使分散在各 CPU 的 LRU 操作全局可见。
  没有 drain_all，CPU0 标记的 idle page 对 CPU1 的 reclaimer 不可见。

根因：page_idle_mark 将 bitmap 存为 {project: {chunk_id: rounds}} 嵌套结构，
  但 folio_batch_drain 在顶层用 idle_bitmap.get(cid, 0) 查找 chunk_id，
  得到的是整个 project dict 或 default 0——永远不匹配。
  同时 page_idle_mark 只查 WHERE project = ?，不含 global，
  导致 64 个 global chunks 从不被标记到 bitmap。

修复：
  1. folio_batch_drain Phase 1 新增 lru_add_drain_all — 合并所有 project bitmap
  2. page_idle_mark 扩展覆盖 global chunks
  3. page_idle_clear drain_all 语义 — 在所有 project bitmap 中搜索并清除

测试覆盖：bitmap 层级修复 + global coverage + clear drain_all
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402 — 测试隔离

import sqlite3
import json
import time
import pytest
from datetime import datetime, timezone
from store_core import open_db, ensure_schema, insert_chunk, MEMORY_OS_DIR
from store_mm import (folio_batch_drain, page_idle_mark, page_idle_clear,
                      _page_idle_save, _page_idle_load, _PAGE_IDLE_FILE)
from config import get as sysctl


def _make_chunk(conn, summary, project="test_proj", chunk_type="decision",
                importance=0.15, access_count=0, oom_adj=300):
    """创建测试 chunk 并返回 ID"""
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


class TestLruAddDrainAll:
    """folio_batch_drain 的 bitmap 层级修复"""

    def test_nested_bitmap_drains_correctly(self):
        """嵌套 bitmap {project: {cid: rounds}} 被正确合并后可以触发回收"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_nested"
        cid = _make_chunk(conn, "nested bitmap drain test", project=proj,
                          importance=0.15, oom_adj=300)
        # 嵌套结构（page_idle_mark 的实际输出格式）
        _page_idle_save({proj: {cid: 3}})

        result = folio_batch_drain(conn, proj)

        assert result["drained"] == 1, f"Expected drain but got {result}"
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is None
        conn.close()

    def test_global_chunks_in_nested_bitmap(self):
        """global 项目的 chunks 在嵌套 bitmap 中被正确合并"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_global_nested"
        cid = _make_chunk(conn, "global chunk nested test", project="global",
                          importance=0.15, oom_adj=300)
        # global chunks 的 bitmap 存在 "global" key 下
        _page_idle_save({"global": {cid: 5}})

        result = folio_batch_drain(conn, proj)

        assert result["drained"] == 1, f"Global chunk not drained: {result}"
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is None
        conn.close()

    def test_mixed_projects_merge(self):
        """多项目 bitmap 被合并，cross-project chunks 全局可见"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_mixed"
        cid_local = _make_chunk(conn, "local mixed test", project=proj,
                                importance=0.15, oom_adj=300)
        cid_global = _make_chunk(conn, "global mixed test", project="global",
                                 importance=0.15, oom_adj=300)
        # 两个 project 的 bitmap 各自独立
        _page_idle_save({
            proj: {cid_local: 3},
            "global": {cid_global: 4}
        })

        result = folio_batch_drain(conn, proj)

        assert result["drained"] == 2, f"Expected 2 drains: {result}"
        for cid in [cid_local, cid_global]:
            row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
            assert row is None, f"Chunk {cid} not deleted"
        conn.close()

    def test_nested_bitmap_cleanup_after_drain(self):
        """删除后原始嵌套 bitmap 正确清理（不是 flat dict）"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_cleanup"
        cid = _make_chunk(conn, "cleanup bitmap test", project=proj,
                          importance=0.15, oom_adj=300)
        cid_survive = _make_chunk(conn, "survive bitmap test", project=proj,
                                  importance=0.15, oom_adj=100)  # low oom_adj, won't drain
        _page_idle_save({proj: {cid: 3, cid_survive: 5}})

        folio_batch_drain(conn, proj)

        # 验证 bitmap 仍是嵌套结构且已清理被删的 chunk
        bm = _page_idle_load()
        assert proj in bm, "Project key should still exist"
        assert cid not in bm[proj], "Drained chunk should be removed from bitmap"
        assert cid_survive in bm[proj], "Surviving chunk should remain in bitmap"
        assert bm[proj][cid_survive] == 5
        conn.close()

    def test_flat_bitmap_backward_compat(self):
        """旧格式 flat bitmap 不会崩溃（graceful degradation）"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_flat_compat"
        cid = _make_chunk(conn, "flat compat test", project=proj,
                          importance=0.15, oom_adj=300)
        # 旧格式：flat dict（iter573 测试写法）
        # 这种情况下顶层 key 是 chunk_id 不是 project，值是 int 不是 dict
        _page_idle_save({cid: 3})

        result = folio_batch_drain(conn, proj)

        # flat bitmap 中 cid:3 不是 dict → isinstance check 过滤 → 不会 drain
        # 但也不会崩溃
        assert result["drained"] == 0  # flat bitmap 无法被正确解析
        assert result["scanned"] >= 1
        conn.close()


class TestPageIdleMarkGlobal:
    """page_idle_mark 的 global coverage 扩展"""

    def test_marks_global_chunks(self):
        """global chunks 被标记到 page_idle bitmap"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_mark_global"
        _page_idle_save({})  # 清空
        cid_local = _make_chunk(conn, "local mark test", project=proj,
                                importance=0.5, oom_adj=0)
        cid_global = _make_chunk(conn, "global mark test", project="global",
                                 importance=0.5, oom_adj=0)

        result = page_idle_mark(conn, proj)

        assert result["marked"] >= 2, f"Expected >=2 marked: {result}"
        bm = _page_idle_load()
        assert proj in bm, "Local project key missing"
        assert "global" in bm, "Global project key missing"
        assert cid_local in bm[proj]
        assert cid_global in bm["global"]
        conn.close()

    def test_global_chunks_accumulate_idle_rounds(self):
        """global chunks 的 idle_rounds 正确累加"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_accumulate"
        cid = _make_chunk(conn, "accumulate idle test", project="global",
                          importance=0.5, oom_adj=0)
        _page_idle_save({"global": {cid: 2}})  # 上轮已有 2 轮

        result = page_idle_mark(conn, proj)

        bm = _page_idle_load()
        assert bm["global"][cid] == 3, f"Expected 3 rounds, got {bm['global'].get(cid)}"
        assert result["carried_over"] >= 1
        conn.close()

    def test_per_project_isolation(self):
        """不同项目的 bitmap 保持 per-project 隔离"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_isolation"
        _page_idle_save({})
        cid_local = _make_chunk(conn, "isolation local", project=proj, importance=0.5)
        cid_global = _make_chunk(conn, "isolation global", project="global", importance=0.5)

        page_idle_mark(conn, proj)

        bm = _page_idle_load()
        # local chunk 在自己的 project key 下
        assert cid_local in bm.get(proj, {})
        assert cid_local not in bm.get("global", {})
        # global chunk 在 "global" key 下
        assert cid_global in bm.get("global", {})
        assert cid_global not in bm.get(proj, {})
        conn.close()


class TestPageIdleClearDrainAll:
    """page_idle_clear 的 drain_all 语义"""

    def test_clears_global_chunk(self):
        """命中 global chunk 时从 bitmap['global'] 中清除"""
        proj = "test_clear_global"
        cid = "test-global-clear-001"
        _page_idle_save({proj: {}, "global": {cid: 5}})

        cleared = page_idle_clear([cid], proj)

        assert cleared == 1
        bm = _page_idle_load()
        assert cid not in bm.get("global", {})

    def test_clears_across_projects(self):
        """chunk 出现在多个 project bitmap 中时全部清除"""
        cid = "test-cross-clear-001"
        _page_idle_save({"projA": {cid: 3}, "projB": {cid: 5}})

        cleared = page_idle_clear([cid], "projA")

        assert cleared == 2  # 在两个 project 中各清除一次
        bm = _page_idle_load()
        assert cid not in bm.get("projA", {})
        assert cid not in bm.get("projB", {})

    def test_preserves_unrelated_entries(self):
        """清除只影响目标 chunk，不影响其他 chunk"""
        cid_target = "test-preserve-target"
        cid_other = "test-preserve-other"
        _page_idle_save({"proj": {cid_target: 3, cid_other: 7}})

        page_idle_clear([cid_target], "proj")

        bm = _page_idle_load()
        assert cid_target not in bm["proj"]
        assert bm["proj"][cid_other] == 7


class TestEndToEnd:
    """page_idle_mark → folio_batch_drain 端到端验证"""

    def test_mark_then_drain_global(self):
        """E2E: global chunk 标记→积累→回收完整流程"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_e2e_global"
        _page_idle_save({})
        cid = _make_chunk(conn, "e2e global dead chunk", project="global",
                          importance=0.15, oom_adj=300)

        # Session 1: 首次标记
        page_idle_mark(conn, proj)
        bm = _page_idle_load()
        assert bm["global"][cid] == 1

        # Session 2: 累加（模拟第二次 SessionStart）
        page_idle_mark(conn, proj)
        bm = _page_idle_load()
        assert bm["global"][cid] == 2

        # folio_batch_drain 现在应该能回收（idle_rounds=2 >= min=2）
        result = folio_batch_drain(conn, proj)
        assert result["drained"] == 1
        row = conn.execute("SELECT id FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row is None
        conn.close()

    def test_mark_clear_resets_rounds(self):
        """E2E: mark → clear（被访问）→ mark 重置轮次"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_e2e_clear"
        _page_idle_save({})
        cid = _make_chunk(conn, "e2e clear chunk", project=proj,
                          importance=0.15, oom_adj=300)

        # Session 1: 标记
        page_idle_mark(conn, proj)
        bm = _page_idle_load()
        assert bm[proj][cid] == 1

        # 被 retriever 命中 → 清除
        page_idle_clear([cid], proj)
        bm = _page_idle_load()
        assert cid not in bm.get(proj, {})

        # Session 2: 重新标记（从 1 开始）
        page_idle_mark(conn, proj)
        bm = _page_idle_load()
        assert bm[proj][cid] == 1  # 重置，不是 2
        conn.close()


class TestPerformance:
    """性能基线"""

    def test_performance(self):
        """folio_batch_drain + nested bitmap 合并 100 chunks < 50ms"""
        conn = open_db()
        ensure_schema(conn)
        proj = "test_perf"
        bitmap = {proj: {}, "global": {}}
        for i in range(50):
            cid = _make_chunk(conn, f"perf local {i}", project=proj,
                              importance=0.15, oom_adj=300)
            bitmap[proj][cid] = 3
        for i in range(50):
            cid = _make_chunk(conn, f"perf global {i}", project="global",
                              importance=0.15, oom_adj=300)
            bitmap["global"][cid] = 3
        _page_idle_save(bitmap)

        t0 = time.time()
        result = folio_batch_drain(conn, proj)
        duration_ms = (time.time() - t0) * 1000

        # max_drain=20 限制
        assert result["drained"] <= 20
        assert result["scanned"] == 100
        assert duration_ms < 50, f"Too slow: {duration_ms:.1f}ms"
        conn.close()
