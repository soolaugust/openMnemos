"""
iter557: bdi_writeback — Boot-Time Dirty Page Writeback Audit

OS 类比：Linux bdi_writeback (Jens Axboe, 2009, kernel 2.6.32, mm/backing-dev.c)
  per-BDI (Backing Device Info) writeback thread 在 boot 时审计并回写 dirty pages。
  替代全局 pdflush，每个 backing device 独立审计。

测试：content quality re-audit at boot time
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tmpfs  # noqa: E402 — must precede store imports for test isolation
import sqlite3
import pytest
from store_mm import bdi_writeback
from store_core import open_db, ensure_schema, insert_chunk, bump_chunk_version


@pytest.fixture
def conn():
    """Create isolated test DB connection."""
    c = open_db()
    ensure_schema(c)
    # Clean any default data inserted by ensure_schema
    c.execute("DELETE FROM memory_chunks")
    c.commit()
    yield c
    c.close()


def _insert(conn, summary, chunk_type="decision", importance=0.80,
            access_count=0, oom_adj=0, project="test_proj"):
    """Helper to insert a test chunk directly (bypassing write gates for test setup)."""
    cid = f"test-{os.urandom(4).hex()}"
    conn.execute(
        """INSERT INTO memory_chunks
           (id, summary, content, chunk_type, importance, access_count,
            oom_adj, project, source_session, created_at, last_accessed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test', datetime('now'), datetime('now'))""",
        (cid, summary, summary, chunk_type,
         importance, access_count, oom_adj, project),
    )
    conn.commit()
    return cid


# ── Phase 1: Fragment Detection ──

class TestFragmentDetection:
    def test_empty_summary_detected(self, conn):
        _insert(conn, "", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1
        assert result["fragments_deleted"] >= 1

    def test_short_summary_detected(self, conn):
        _insert(conn, "短文本测试", project="test_proj")  # < 15 chars
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1
        assert result["fragments_deleted"] >= 1

    def test_table_row_detected(self, conn):
        _insert(conn, "| 问题 | 每次 SessionStart 创建 per-session 状态 |", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1
        assert result["fragments_deleted"] >= 1

    def test_pipe_start_detected(self, conn):
        _insert(conn, "|--- header ---|", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1

    def test_colon_ending_detected(self, conn):
        _insert(conn, "核心成果的内容描述是这样的：", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1

    def test_numbered_list_item_no_anchor(self, conn):
        _insert(conn, "3. 新工作流成立后（需≥3个验证案例）", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1

    def test_dash_list_item_short(self, conn):
        _insert(conn, "- 冷启动保护：< 2 samples 不触发", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1

    def test_markdown_heading_detected(self, conn):
        _insert(conn, "## 这是标题不是内容摘要", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1


# ── Phase 2: Preservation ──

class TestPreservation:
    def test_valid_decision_preserved(self, conn):
        _insert(conn, "选择 SQLite FTS5 替代 chromadb 的原因是中文 BM25 在小规模数据集上效果更好，且无额外依赖",
                project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["fragments_deleted"] == 0
        assert result["low_quality_demoted"] == 0

    def test_valid_constraint_preserved(self, conn):
        _insert(conn, "内核/调度开发前置约束：触发词（kernel patch/sched_ext/EEVDF/PE）须主动读 wiki；commit 前验证 git config user.name/email",
                chunk_type="design_constraint", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["fragments_deleted"] == 0

    def test_numbered_list_with_tech_anchor_preserved(self, conn):
        """Numbered item with .py file reference should be preserved."""
        _insert(conn, "3. store_vfs.py 新增 fts5_checkpoint() 三阶段校验", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["fragments_deleted"] == 0

    def test_long_dash_item_preserved(self, conn):
        """Dash items >= 50 chars are not treated as fragments."""
        _insert(conn, "- 解决方案：使用 immutable=1 URI 只读模式避免与 writer 锁竞争，fallback query_only=ON",
                project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["fragments_deleted"] == 0

    def test_task_state_skipped(self, conn):
        """task_state chunks are never audited."""
        _insert(conn, "x", chunk_type="task_state", project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["fragments_deleted"] == 0
        assert result["dirty_found"] == 0


# ── Phase 3: Protection Mechanisms ──

class TestProtection:
    def test_mlock_not_deleted(self, conn):
        _insert(conn, "| table | row |", oom_adj=-500, project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["skipped_protected"] >= 1
        assert result["fragments_deleted"] == 0
        # Chunk should still exist
        cnt = conn.execute("SELECT COUNT(*) FROM memory_chunks WHERE oom_adj=-500").fetchone()[0]
        assert cnt == 1

    def test_accessed_chunk_demoted_not_deleted(self, conn):
        cid = _insert(conn, "| x | y | z |", access_count=3, project="test_proj")
        result = bdi_writeback(conn, "test_proj")
        assert result["low_quality_demoted"] >= 1
        assert result["fragments_deleted"] == 0
        # Verify importance was capped
        row = conn.execute(
            "SELECT importance FROM memory_chunks WHERE id=?", (cid,)
        ).fetchone()
        assert row[0] <= 0.30

    def test_max_per_scan_limit(self, conn):
        # Insert 40 fragments
        for i in range(40):
            _insert(conn, f"x{i}", project="test_proj")  # All < 15 chars
        result = bdi_writeback(conn, "test_proj")
        # Should process at most 30 (default max_per_scan)
        assert result["dirty_found"] <= 30


# ── Phase 4: Config & Edge Cases ──

class TestConfig:
    def test_disabled_noop(self, conn):
        os.environ["MEMORY_OS_BDI_WRITEBACK_ENABLED"] = "false"
        try:
            _insert(conn, "| bad | leak |", project="test_proj")
            result = bdi_writeback(conn, "test_proj")
            assert result["triggered"] is False
            assert result["fragments_deleted"] == 0
        finally:
            del os.environ["MEMORY_OS_BDI_WRITEBACK_ENABLED"]

    def test_empty_db_safe(self, conn):
        result = bdi_writeback(conn, "test_proj")
        assert result["scanned"] == 0
        assert result["dirty_found"] == 0

    def test_global_project_included(self, conn):
        _insert(conn, "| table | row |", project="global")
        result = bdi_writeback(conn, "test_proj")
        assert result["dirty_found"] >= 1

    def test_no_project_scans_all(self, conn):
        _insert(conn, "| table | row |", project="proj_a")
        _insert(conn, "| another | leak |", project="proj_b")
        result = bdi_writeback(conn, None)
        assert result["dirty_found"] >= 2

    def test_performance(self, conn):
        """100 clean chunks audit < 100ms."""
        import time
        for i in range(100):
            _insert(conn, f"Valid decision about topic {i} with technical detail and sufficient length to pass filters easily",
                    project="test_proj")
        t0 = time.time()
        result = bdi_writeback(conn, "test_proj")
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 100, f"Too slow: {elapsed:.1f}ms"
        assert result["scanned"] == 100
        assert result["dirty_found"] == 0

    def test_idempotent(self, conn):
        """Running twice with same data produces same results (fragments already deleted)."""
        _insert(conn, "| leak | one |", project="test_proj")
        _insert(conn, "| leak | two |", project="test_proj")
        r1 = bdi_writeback(conn, "test_proj")
        assert r1["fragments_deleted"] == 2
        # Second run — already clean
        r2 = bdi_writeback(conn, "test_proj")
        assert r2["fragments_deleted"] == 0
        assert r2["dirty_found"] == 0
