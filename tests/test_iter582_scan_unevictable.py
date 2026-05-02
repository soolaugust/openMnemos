"""
iter582: scan_unevictable — Round-Robin Dark Page Batch Exposure

OS 类比：Linux scan_unevictable_pages() (Lee Schermerhorn, 2008, kernel 2.6.28)
测试 round-robin cursor、batch 注入、公平轮转、排除逻辑。
"""
import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from store_mm import scan_unevictable, _SCAN_CURSOR_FILE, _save_cursor, MEMORY_OS_DIR


@pytest.fixture
def conn():
    """In-memory DB with schema."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE memory_chunks (
        id TEXT PRIMARY KEY,
        summary TEXT,
        content TEXT DEFAULT '',
        chunk_type TEXT DEFAULT 'decision',
        importance REAL DEFAULT 0.8,
        project TEXT DEFAULT 'test_proj',
        access_count INTEGER DEFAULT 0,
        last_accessed TEXT DEFAULT '2026-01-01T00:00:00',
        created_at TEXT DEFAULT '2026-01-01T00:00:00',
        oom_adj INTEGER DEFAULT 0,
        lru_gen INTEGER DEFAULT 0
    )""")
    return db


@pytest.fixture(autouse=True)
def cleanup_cursor():
    """Clean up cursor file before/after each test."""
    if _SCAN_CURSOR_FILE.exists():
        _SCAN_CURSOR_FILE.unlink()
    yield
    if _SCAN_CURSOR_FILE.exists():
        _SCAN_CURSOR_FILE.unlink()


def _insert_chunk(conn, id, chunk_type="decision", importance=0.8,
                  access_count=0, project="test_proj", oom_adj=0,
                  created_at="2026-01-01T00:00:00"):
    conn.execute(
        "INSERT INTO memory_chunks (id, summary, chunk_type, importance, "
        "project, access_count, created_at, oom_adj) VALUES (?,?,?,?,?,?,?,?)",
        (id, f"Summary of {id}", chunk_type, importance, project,
         access_count, created_at, oom_adj)
    )
    conn.commit()


class TestBasicInjection:
    """基础注入功能"""

    def test_injects_dark_pages(self, conn):
        """应从 dark pages 中选取并返回 chunk"""
        _insert_chunk(conn, "dark1", created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "dark2", created_at="2026-01-02T01:00:00")
        _insert_chunk(conn, "dark3", created_at="2026-01-03T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 2  # default max_inject=2
        assert result[0]["id"] == "dark1"  # oldest first (round-robin)
        assert result[1]["id"] == "dark2"

    def test_empty_db_returns_empty(self, conn):
        """空 DB 应返回空列表"""
        result = scan_unevictable(conn, "test_proj", set())
        assert result == []

    def test_excludes_top_k_ids(self, conn):
        """已在 top_k 中的 chunk 不应被重复注入"""
        _insert_chunk(conn, "dark1", created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "dark2", created_at="2026-01-02T01:00:00")
        _insert_chunk(conn, "dark3", created_at="2026-01-03T01:00:00")

        result = scan_unevictable(conn, "test_proj", {"dark1", "dark2"})
        assert len(result) == 1
        assert result[0]["id"] == "dark3"


class TestRoundRobin:
    """Round-Robin cursor 公平轮转"""

    def test_cursor_advances(self, conn):
        """cursor 应在每次调用后推进"""
        for i in range(5):
            _insert_chunk(conn, f"chunk{i}", created_at=f"2026-01-0{i+1}T01:00:00")

        # 第一次调用: cursor=0, 取 chunk0, chunk1
        r1 = scan_unevictable(conn, "test_proj", set())
        assert r1[0]["id"] == "chunk0"
        assert r1[1]["id"] == "chunk1"

        # 第二次调用: cursor=2, 取 chunk2, chunk3
        r2 = scan_unevictable(conn, "test_proj", set())
        assert r2[0]["id"] == "chunk2"
        assert r2[1]["id"] == "chunk3"

        # 第三次调用: cursor=4, 取 chunk4, chunk0 (wrap)
        r3 = scan_unevictable(conn, "test_proj", set())
        assert r3[0]["id"] == "chunk4"
        assert r3[1]["id"] == "chunk0"

    def test_cursor_wraps_around(self, conn):
        """cursor 超出范围时应 wrap around"""
        _insert_chunk(conn, "a", created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "b", created_at="2026-01-02T01:00:00")

        # 设置 cursor 到超出范围
        _save_cursor(10)

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 2
        assert result[0]["id"] == "a"  # wraps back to 0

    def test_cursor_persisted(self, conn):
        """cursor 应被持久化到文件"""
        _insert_chunk(conn, "x", created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "y", created_at="2026-01-02T01:00:00")
        _insert_chunk(conn, "z", created_at="2026-01-03T01:00:00")

        scan_unevictable(conn, "test_proj", set())

        assert _SCAN_CURSOR_FILE.exists()
        data = json.loads(_SCAN_CURSOR_FILE.read_text())
        assert data["offset"] == 2  # advanced by max_inject(2)
        assert "ts" in data

    def test_full_coverage_in_n_calls(self, conn):
        """N 次调用应覆盖所有 dark pages"""
        n = 7
        for i in range(n):
            _insert_chunk(conn, f"d{i}", created_at=f"2026-01-{i+1:02d}T01:00:00")

        seen = set()
        # ceil(7/2) = 4 calls to cover all
        for _ in range(4):
            results = scan_unevictable(conn, "test_proj", set())
            for r in results:
                seen.add(r["id"])

        assert seen == {f"d{i}" for i in range(n)}


class TestFiltering:
    """过滤逻辑"""

    def test_skips_accessed_chunks(self, conn):
        """access_count > 0 的 chunk 不是 dark page"""
        _insert_chunk(conn, "accessed", access_count=1)
        _insert_chunk(conn, "dark", access_count=0, created_at="2026-01-02T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 1
        assert result[0]["id"] == "dark"

    def test_imp_threshold_filters(self, conn):
        """低 importance 的 chunk 被过滤"""
        _insert_chunk(conn, "low_imp", importance=0.3)
        _insert_chunk(conn, "high_imp", importance=0.8, created_at="2026-01-02T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 1
        assert result[0]["id"] == "high_imp"

    def test_excludes_dead_chunks(self, conn):
        """oom_adj >= 300 的 dead chunk 不值得曝光"""
        _insert_chunk(conn, "dead", oom_adj=300)
        _insert_chunk(conn, "alive", oom_adj=0, created_at="2026-01-02T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 1
        assert result[0]["id"] == "alive"

    def test_exclude_types(self, conn):
        """排除指定 chunk_type"""
        _insert_chunk(conn, "pc", chunk_type="prompt_context",
                      created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "cs", chunk_type="conversation_summary",
                      created_at="2026-01-02T01:00:00")
        _insert_chunk(conn, "dec", chunk_type="decision",
                      created_at="2026-01-03T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 1
        assert result[0]["id"] == "dec"

    def test_project_filter(self, conn):
        """只返回当前项目和 global 的 chunk"""
        _insert_chunk(conn, "mine", project="test_proj",
                      created_at="2026-01-01T01:00:00")
        _insert_chunk(conn, "glob", project="global",
                      created_at="2026-01-02T01:00:00")
        _insert_chunk(conn, "other", project="other_proj",
                      created_at="2026-01-03T01:00:00")

        result = scan_unevictable(conn, "test_proj", set())
        ids = {r["id"] for r in result}
        assert "mine" in ids
        assert "glob" in ids
        assert "other" not in ids


class TestConfig:
    """配置相关"""

    def test_disabled(self, conn):
        """disabled 时返回空"""
        _insert_chunk(conn, "dark1")

        with patch("config.get", side_effect=lambda k, **kw: False if k == "scan_unevictable.enabled" else None):
            result = scan_unevictable(conn, "test_proj", set())
        assert result == []

    def test_max_inject_respected(self, conn):
        """max_inject 限制注入数量"""
        for i in range(10):
            _insert_chunk(conn, f"d{i}", created_at=f"2026-01-{i+1:02d}T01:00:00")

        # default max_inject=2
        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 2

    def test_single_dark_page(self, conn):
        """只有 1 个 dark page 时最多返回 1 个"""
        _insert_chunk(conn, "only_one")

        result = scan_unevictable(conn, "test_proj", set())
        assert len(result) == 1
        assert result[0]["id"] == "only_one"

    def test_cursor_reset_on_empty(self, conn):
        """dark pages 清空后 cursor 应重置"""
        _save_cursor(5)

        # 所有 chunk 都有 access
        _insert_chunk(conn, "accessed", access_count=1)

        result = scan_unevictable(conn, "test_proj", set())
        assert result == []

        # cursor 应已重置
        if _SCAN_CURSOR_FILE.exists():
            data = json.loads(_SCAN_CURSOR_FILE.read_text())
            assert data["offset"] == 0


class TestPerformance:
    """性能"""

    def test_performance(self, conn):
        """100 chunks 应在 10ms 内完成"""
        for i in range(100):
            _insert_chunk(conn, f"perf{i}", created_at=f"2026-01-01T{i:02d}:00:00")

        start = time.time()
        for _ in range(50):
            scan_unevictable(conn, "test_proj", set())
        elapsed = (time.time() - start) / 50

        assert elapsed < 0.01  # < 10ms per call

    def test_idempotent_with_same_cursor(self, conn):
        """相同 cursor 位置应返回相同结果（确定性）"""
        for i in range(5):
            _insert_chunk(conn, f"d{i}", created_at=f"2026-01-0{i+1}T01:00:00")

        _save_cursor(0)
        r1 = scan_unevictable(conn, "test_proj", set())

        _save_cursor(0)
        r2 = scan_unevictable(conn, "test_proj", set())

        # IDs 应该相同（但 cursor 会推进，所以只比较第一次）
        assert r1[0]["id"] == r2[0]["id"]
