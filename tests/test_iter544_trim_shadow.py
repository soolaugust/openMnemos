"""
iter544: trim_shadow_entries — Shadow Entry Expiry & Stale Reference Scrub
OS 类比：Linux shadow_lru_isolate() (Johannes Weiner, 2013, mm/workingset.c)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402, F401 — 测试隔离
import json
import sqlite3
import pytest
from datetime import datetime, timezone
from store_vfs import open_db, ensure_schema, insert_chunk
from store_mm import trim_shadow_entries


@pytest.fixture
def conn():
    """Create a fresh test DB with schema, clear shadow_traces between tests."""
    c = open_db()
    ensure_schema(c)
    # Clean state for each test
    c.execute("DELETE FROM shadow_traces")
    c.execute("DELETE FROM memory_chunks")
    c.commit()
    return c


def _insert_shadow(conn, session_id, project, top_k_ids):
    """Helper to insert a shadow_trace entry."""
    conn.execute(
        "INSERT INTO shadow_traces (session_id, project, agent_id, updated_at, top_k_ids) "
        "VALUES (?, ?, '', datetime('now'), ?)",
        (session_id, project, json.dumps(top_k_ids)),
    )
    conn.commit()


def _insert_chunk(conn, chunk_id, project="test-proj"):
    """Helper to insert a live chunk."""
    now = datetime.now(timezone.utc).isoformat()
    insert_chunk(conn, {
        "id": chunk_id,
        "created_at": now,
        "updated_at": now,
        "project": project,
        "source_session": "test",
        "chunk_type": "decision",
        "summary": f"Test chunk {chunk_id}",
        "content": f"Content for {chunk_id}",
        "tags": "[]",
        "importance": 0.8,
        "retrievability": 0.5,
        "last_accessed": now,
    })
    conn.commit()


class TestPhase1Expire:
    """Phase 1: 超过 max_entries 时淘汰最老条目"""

    def test_no_expire_when_below_limit(self, conn):
        """总数 < max_entries 时不淘汰"""
        _insert_chunk(conn, "c1", "proj")
        _insert_shadow(conn, "s1", "proj", ["c1"])
        _insert_shadow(conn, "s2", "proj", ["c1"])

        result = trim_shadow_entries(conn, "proj")
        assert result["expired"] == 0
        assert result["remaining"] == 2

    def test_expire_oldest_when_over_limit(self, conn):
        """超过 max_entries 时从最老开始淘汰"""
        _insert_chunk(conn, "c1", "proj")
        # 插入 110 条
        for i in range(110):
            _insert_shadow(conn, f"session-{i:03d}", "proj", ["c1"])

        # max_entries=100 → 应淘汰 10 条
        result = trim_shadow_entries(conn, "proj")
        assert result["expired"] == 10
        assert result["remaining"] == 100

    def test_expire_respects_project_filter(self, conn):
        """project 过滤只影响指定项目"""
        _insert_chunk(conn, "c1", "proj-a")
        _insert_chunk(conn, "c2", "proj-b")
        for i in range(110):
            _insert_shadow(conn, f"a-{i:03d}", "proj-a", ["c1"])
        for i in range(5):
            _insert_shadow(conn, f"b-{i:03d}", "proj-b", ["c2"])

        result = trim_shadow_entries(conn, "proj-a")
        assert result["expired"] == 10
        # proj-b 不受影响
        b_count = conn.execute(
            "SELECT COUNT(*) FROM shadow_traces WHERE project='proj-b'"
        ).fetchone()[0]
        assert b_count == 5


class TestPhase2Scrub:
    """Phase 2: 清理 stale chunk ID 引用"""

    def test_scrub_stale_refs(self, conn):
        """引用已删除 chunk → 从 top_k_ids 中移除"""
        _insert_chunk(conn, "live-1", "proj")
        # shadow 引用 live-1 + dead-1（不存在）
        _insert_shadow(conn, "s1", "proj", ["live-1", "dead-1", "dead-2"])

        result = trim_shadow_entries(conn, "proj")
        assert result["scrubbed_refs"] == 2
        assert result["scrubbed_traces"] == 1

        # 验证更新后只保留 live ref
        row = conn.execute(
            "SELECT top_k_ids FROM shadow_traces WHERE session_id='s1'"
        ).fetchone()
        assert json.loads(row[0]) == ["live-1"]

    def test_all_stale_leads_to_purge(self, conn):
        """所有引用都 stale → purge 整条"""
        _insert_shadow(conn, "s1", "proj", ["dead-1", "dead-2"])

        result = trim_shadow_entries(conn, "proj")
        assert result["purged"] == 1
        assert result["remaining"] == 0

    def test_no_scrub_when_all_live(self, conn):
        """所有引用都存活 → 不修改"""
        _insert_chunk(conn, "live-1", "proj")
        _insert_chunk(conn, "live-2", "proj")
        _insert_shadow(conn, "s1", "proj", ["live-1", "live-2"])

        result = trim_shadow_entries(conn, "proj")
        assert result["scrubbed_refs"] == 0
        assert result["scrubbed_traces"] == 0
        assert result["purged"] == 0


class TestPhase3Purge:
    """Phase 3: 空/无效条目清理"""

    def test_purge_empty_top_k_ids(self, conn):
        """top_k_ids 为空列表 → purge"""
        _insert_shadow(conn, "s1", "proj", [])

        result = trim_shadow_entries(conn, "proj")
        assert result["purged"] == 1
        assert result["remaining"] == 0

    def test_purge_empty_string(self, conn):
        """top_k_ids 为空字符串 → purge"""
        conn.execute(
            "INSERT INTO shadow_traces (session_id, project, agent_id, updated_at, top_k_ids) "
            "VALUES ('s1', 'proj', '', datetime('now'), '')"
        )
        conn.commit()

        result = trim_shadow_entries(conn, "proj")
        assert result["purged"] == 1

    def test_purge_malformed_json(self, conn):
        """top_k_ids JSON 损坏 → purge"""
        conn.execute(
            "INSERT INTO shadow_traces (session_id, project, agent_id, updated_at, top_k_ids) "
            "VALUES ('s1', 'proj', '', datetime('now'), '{invalid json')"
        )
        conn.commit()

        result = trim_shadow_entries(conn, "proj")
        assert result["purged"] == 1


class TestGlobalScan:
    """project=None 时全局扫描"""

    def test_global_scan_all_projects(self, conn):
        """不传 project → 扫描所有"""
        _insert_chunk(conn, "c1", "proj-a")
        _insert_shadow(conn, "s1", "proj-a", ["c1", "dead-1"])
        _insert_shadow(conn, "s2", "proj-b", ["dead-2", "dead-3"])

        result = trim_shadow_entries(conn, project=None)
        assert result["scrubbed_refs"] == 3  # s1: dead-1, s2: dead-2 + dead-3
        assert result["purged"] == 1  # s2: all dead
        assert result["remaining"] == 1  # only s1 survives


class TestEdgeCases:
    """边界场景"""

    def test_empty_table(self, conn):
        """空表 → 安全返回"""
        result = trim_shadow_entries(conn, "proj")
        assert result["expired"] == 0
        assert result["scrubbed_refs"] == 0
        assert result["purged"] == 0
        assert result["remaining"] == 0

    def test_combined_expire_and_scrub(self, conn):
        """同时触发 expire + scrub"""
        _insert_chunk(conn, "live-1", "proj")
        # 插入 120 条，前 50 引用 dead，后 70 引用 live
        for i in range(50):
            _insert_shadow(conn, f"old-{i:03d}", "proj", ["dead-x"])
        for i in range(70):
            _insert_shadow(conn, f"new-{i:03d}", "proj", ["live-1"])

        result = trim_shadow_entries(conn, "proj")
        # expire 先删 20 条最老的（总 120 - max 100 = 20）
        assert result["expired"] == 20
        # 剩余 100 条中：30 条 dead-x → purge，70 条 live-1 → 存活
        assert result["purged"] == 30
        assert result["remaining"] == 70

    def test_performance_large_batch(self, conn):
        """性能：500 条 < 200ms"""
        import time
        _insert_chunk(conn, "live-1", "proj")
        for i in range(500):
            _insert_shadow(conn, f"s-{i:04d}", "proj", ["live-1", f"dead-{i}"])

        start = time.time()
        result = trim_shadow_entries(conn, "proj")
        elapsed = (time.time() - start) * 1000

        assert elapsed < 200, f"Too slow: {elapsed:.1f}ms"
        # iter1860: full_flush — 一次清完全部积压 (500-100=400)
        assert result["expired"] == 400
        # 剩余 100 条中各有 1 stale ref 需要 scrub
        assert result["scrubbed_refs"] >= 50  # 至少 scrub 存活的那些


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
