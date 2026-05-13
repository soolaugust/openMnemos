#!/usr/bin/env python3
"""
test_memory_zones.py — 迭代82: Memory Zones — chunk_type Retrieval Exclusion Filter

OS 类比：Linux ZONE_DMA/ZONE_NORMAL/ZONE_HIGHMEM — 不同区域的内存用途隔离
验证 retriever.exclude_types sysctl 正确排除 prompt_context 等类型
"""
import tmpfs  # noqa: F401 — must be first to isolate test DB

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from store import open_db, ensure_schema, fts_search, get_chunks


def _insert_chunk(conn, project, chunk_type, summary, content, importance=0.8):
    import uuid as _uuid
    from store_vfs import _cjk_tokenize
    chunk_id = str(_uuid.uuid4())
    conn.execute("""
        INSERT INTO memory_chunks
        (id, project, source_session, chunk_type, content, summary, tags, importance,
         retrievability, last_accessed, access_count, oom_adj, lru_gen)
        VALUES (?, ?, 'test-sess', ?, ?, ?, '[]', ?,
                1.0, datetime('now'), 0, 0, 0)
    """, (chunk_id, project, chunk_type, content, summary, importance))
    # 迭代97：独立FTS5模式需要手动维护索引
    new_rowid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone()
    if new_rowid and summary:
        try:
            conn.execute(
                "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                (str(new_rowid[0]), _cjk_tokenize(summary), _cjk_tokenize(content or ""))
            )
        except Exception:
            pass
    conn.commit()
    return chunk_id


class TestMemoryZonesSysctl(unittest.TestCase):
    """Test that retriever.exclude_types sysctl is correctly registered."""

    def test_sysctl_registered(self):
        """exclude_types sysctl exists with expected default."""
        import config
        val = config.get("retriever.exclude_types")
        self.assertEqual(val, "prompt_context,conversation_summary",
                         f"Default should be 'prompt_context,conversation_summary', got {val!r}")


class TestFtsSearchTypeFilter(unittest.TestCase):
    """Test fts_search respects chunk_types exclusion."""

    def setUp(self):
        self.conn = open_db()
        ensure_schema(self.conn)
        self.conn.execute("DELETE FROM memory_chunks")
        self.conn.execute("DELETE FROM memory_chunks_fts")  # 迭代97：独立FTS5需手动同步
        self.conn.commit()

        _insert_chunk(self.conn, "test-proj", "decision",
                      "python 迭代器协议决策", "python decision content", 0.9)
        _insert_chunk(self.conn, "test-proj", "reasoning_chain",
                      "python 推理链记录", "python reasoning content", 0.8)
        _insert_chunk(self.conn, "test-proj", "prompt_context",
                      "python 用户指令上下文", "python prompt context content", 0.85)
        _insert_chunk(self.conn, "test-proj", "conversation_summary",
                      "python 对话摘要", "python summary content", 0.7)

    def tearDown(self):
        self.conn.close()

    def test_fts_no_filter_returns_non_excluded_types(self):
        """Without chunk_types filter, prompt_context is excluded by default."""
        results = fts_search(self.conn, "python", "test-proj", top_k=10)
        types = {r["chunk_type"] for r in results}
        self.assertNotIn("prompt_context", types)
        self.assertIn("decision", types)

    def test_fts_excludes_prompt_context(self):
        """With chunk_types excluding prompt_context, no prompt_context returned."""
        allowed = ("decision", "reasoning_chain", "conversation_summary",
                   "excluded_path", "task_state")
        results = fts_search(self.conn, "python", "test-proj", top_k=10,
                             chunk_types=allowed)
        types = {r["chunk_type"] for r in results}
        self.assertNotIn("prompt_context", types,
                         "prompt_context must be excluded when not in chunk_types")
        self.assertIn("decision", types)

    def test_fts_returns_non_excluded_when_none(self):
        """None chunk_types means sysctl exclude_types applies."""
        results = fts_search(self.conn, "python", "test-proj", top_k=10,
                             chunk_types=None)
        types = {r["chunk_type"] for r in results}
        self.assertNotIn("prompt_context", types)
        self.assertIn("decision", types)

    def test_fts_single_allowed_type(self):
        """chunk_types=('decision',) only returns decisions."""
        results = fts_search(self.conn, "python", "test-proj", top_k=10,
                             chunk_types=("decision",))
        types = {r["chunk_type"] for r in results}
        self.assertEqual(types, {"decision"},
                         f"Only 'decision' expected, got {types}")


class TestGetChunksTypeFilter(unittest.TestCase):
    """Test get_chunks BM25 fallback respects chunk_types exclusion."""

    def setUp(self):
        self.conn = open_db()
        ensure_schema(self.conn)
        self.conn.execute("DELETE FROM memory_chunks")
        self.conn.commit()

        _insert_chunk(self.conn, "zone-proj", "decision", "arch决策", "decision body", 0.9)
        _insert_chunk(self.conn, "zone-proj", "prompt_context", "prompt指令", "prompt body", 0.8)
        _insert_chunk(self.conn, "zone-proj", "reasoning_chain", "推理链", "reasoning body", 0.7)

    def tearDown(self):
        self.conn.close()

    def test_get_chunks_no_filter(self):
        """Without filter, all types returned."""
        chunks = get_chunks(self.conn, "zone-proj")
        types = {c["chunk_type"] for c in chunks}
        self.assertIn("prompt_context", types)
        self.assertEqual(len(chunks), 3)

    def test_get_chunks_excludes_prompt_context(self):
        """chunk_types filter excludes prompt_context from BM25 pool."""
        allowed = ("decision", "reasoning_chain", "conversation_summary",
                   "excluded_path", "task_state")
        chunks = get_chunks(self.conn, "zone-proj", chunk_types=allowed)
        types = {c["chunk_type"] for c in chunks}
        self.assertNotIn("prompt_context", types)
        self.assertEqual(len(chunks), 2)

    def test_get_chunks_none_means_all(self):
        """chunk_types=None returns all."""
        chunks = get_chunks(self.conn, "zone-proj", chunk_types=None)
        self.assertEqual(len(chunks), 3)


class TestMemoryZonesExcludeSet(unittest.TestCase):
    """Test the exclude_set computation logic matching retriever.py."""

    def _compute_retrieve_types(self, exclude_str):
        """Replicate retriever.py logic."""
        _ALL = ("decision", "reasoning_chain", "conversation_summary",
                "excluded_path", "task_state", "prompt_context")
        exc = set(t.strip() for t in exclude_str.split(",") if t.strip()) if exclude_str else set()
        result = tuple(t for t in _ALL if t not in exc)
        return result or None

    def test_default_excludes_prompt_context(self):
        types = self._compute_retrieve_types("prompt_context")
        self.assertNotIn("prompt_context", types)
        self.assertIn("decision", types)
        self.assertIn("reasoning_chain", types)

    def test_empty_string_returns_all(self):
        """Empty exclude string means no exclusion — return all types."""
        types = self._compute_retrieve_types("")
        self.assertEqual(len(types), 6)
        self.assertIn("prompt_context", types)
        self.assertIn("decision", types)

    def test_exclude_multiple(self):
        types = self._compute_retrieve_types("prompt_context,task_state")
        self.assertNotIn("prompt_context", types)
        self.assertNotIn("task_state", types)
        self.assertIn("decision", types)

    def test_exclude_unknown_type_no_error(self):
        """Excluding a non-existent type is harmless."""
        types = self._compute_retrieve_types("nonexistent_type")
        self.assertIn("prompt_context", types)
        self.assertIn("decision", types)

    def test_exclude_all_types_returns_none(self):
        """Excluding all known types → None (no filter fallback)."""
        all_types = "decision,reasoning_chain,conversation_summary,excluded_path,task_state,prompt_context"
        types = self._compute_retrieve_types(all_types)
        self.assertIsNone(types)

    def test_whitespace_in_exclude_str(self):
        """Whitespace around type names is stripped."""
        types = self._compute_retrieve_types(" prompt_context , task_state ")
        self.assertNotIn("prompt_context", types)
        self.assertNotIn("task_state", types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
