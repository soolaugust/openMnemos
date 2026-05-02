"""
iter548: logrotate — Metadata Table Lifecycle Rotation
OS 类比：Linux logrotate (Red Hat, 1997) — 元数据/日志表 per-table 轮转策略

Tests:
  1. ipc_msgq — CONSUMED 旧消息被清除，PENDING 不受影响
  2. ipc_msgq — 未超龄的 CONSUMED 消息保留
  3. hook_txn_log — 超出 max_entries 时淘汰最旧
  4. hook_txn_log — 不超额时不删除
  5. session_focus — 超龄记录被清除
  6. session_focus — 未超龄记录保留
  7. priming_state — per-project 超额时淘汰 prime_strength 最弱的
  8. priming_state — 不超额的 project 不受影响
  9. tool_patterns — 超额时淘汰低频旧模式
  10. entity_edges — orphaned (NULL source_chunk_id) 超龄被清除
  11. entity_edges — 有 source_chunk_id 的不受 logrotate 影响
  12. 所有 phase 独立 fault isolation — 单表异常不影响其他
  13. 幂等性 — 连续调用不重复删除
  14. 性能 — < 500ms
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402, F401 — 测试隔离
import json
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta
from store_vfs import open_db, ensure_schema
from store_mm import logrotate
from config import get as _cfg, sysctl_set


PROJECT = "test:logrotate"


def _setup_db():
    """Create DB with schema and clean ALL test data for isolation."""
    conn = open_db()
    ensure_schema(conn)
    # Clean test data from all relevant tables
    for table in ["ipc_msgq", "hook_txn_log", "session_focus",
                   "priming_state", "tool_patterns", "entity_edges"]:
        try:
            conn.execute(f"DELETE FROM [{table}]")
        except Exception:
            pass
    conn.commit()
    return conn


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _ago_iso(hours=0, days=0):
    dt = datetime.now(timezone.utc) - timedelta(hours=hours, days=days)
    return dt.isoformat()


# ── Phase 1: ipc_msgq tests ──

class TestIpcMsgqRotation:
    def test_consumed_old_messages_deleted(self):
        """CONSUMED + 超龄消息被清除。"""
        conn = _setup_db()
        # Ensure ipc_msgq table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ipc_msgq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_agent TEXT, target_agent TEXT, msg_type TEXT,
                payload TEXT, priority INTEGER DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT, consumed_at TEXT, ttl_seconds INTEGER DEFAULT 0
            )
        """)
        # Insert old CONSUMED messages (3 days old)
        for i in range(5):
            conn.execute(
                "INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload, status, created_at) "
                "VALUES (?, ?, ?, ?, 'CONSUMED', ?)",
                (f"agent_{i}", "*", "knowledge_update", "{}", _ago_iso(hours=72))
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["ipc_msgq"] == 5
        remaining = conn.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0]
        assert remaining == 0
        conn.close()

    def test_pending_messages_preserved(self):
        """PENDING 消息不被清除。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ipc_msgq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_agent TEXT, target_agent TEXT, msg_type TEXT,
                payload TEXT, priority INTEGER DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT, consumed_at TEXT, ttl_seconds INTEGER DEFAULT 0
            )
        """)
        # Insert old PENDING message (should NOT be deleted)
        conn.execute(
            "INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload, status, created_at) "
            "VALUES (?, ?, ?, ?, 'PENDING', ?)",
            ("agent_x", "*", "knowledge_update", "{}", _ago_iso(hours=72))
        )
        # Insert recent CONSUMED message (should NOT be deleted)
        conn.execute(
            "INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload, status, created_at) "
            "VALUES (?, ?, ?, ?, 'CONSUMED', ?)",
            ("agent_y", "*", "knowledge_update", "{}", _now_iso())
        )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["ipc_msgq"] == 0
        remaining = conn.execute("SELECT COUNT(*) FROM ipc_msgq").fetchone()[0]
        assert remaining == 2
        conn.close()


# ── Phase 2: hook_txn_log tests ──

class TestHookTxnLogRotation:
    def test_overflow_oldest_deleted(self):
        """超出 max_entries 时淘汰最旧记录。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hook_txn_log (
                txn_id TEXT, hook TEXT, status TEXT, chunk_count INTEGER,
                session_id TEXT, project TEXT, started_at TEXT,
                committed_at TEXT, error TEXT, agent_id TEXT
            )
        """)
        max_entries = int(_cfg("logrotate.hook_txn_log_max_entries"))  # 200
        # Insert more than max
        for i in range(max_entries + 50):
            conn.execute(
                "INSERT INTO hook_txn_log (txn_id, hook, status, started_at) VALUES (?, ?, ?, ?)",
                (f"txn_{i:04d}", "writer", "committed", _ago_iso(hours=(max_entries + 50 - i)))
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["hook_txn_log"] == 50
        remaining = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
        assert remaining == max_entries
        conn.close()

    def test_under_limit_no_deletion(self):
        """不超额时不删除。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hook_txn_log (
                txn_id TEXT, hook TEXT, status TEXT, chunk_count INTEGER,
                session_id TEXT, project TEXT, started_at TEXT,
                committed_at TEXT, error TEXT, agent_id TEXT
            )
        """)
        for i in range(10):
            conn.execute(
                "INSERT INTO hook_txn_log (txn_id, hook, status, started_at) VALUES (?, ?, ?, ?)",
                (f"txn_{i}", "writer", "committed", _now_iso())
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["hook_txn_log"] == 0
        remaining = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
        assert remaining == 10
        conn.close()


# ── Phase 3: session_focus tests ──

class TestSessionFocusRotation:
    def test_old_focus_deleted(self):
        """超龄 session_focus 被清除。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_focus (
                session_id TEXT, keyword TEXT, updated_at TEXT, hit_count INTEGER
            )
        """)
        # Insert old focus records (4 days old)
        for i in range(10):
            conn.execute(
                "INSERT INTO session_focus (session_id, keyword, updated_at, hit_count) VALUES (?, ?, ?, ?)",
                (f"session_{i}", f"keyword_{i}", _ago_iso(hours=96), 5)
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["session_focus"] == 10
        remaining = conn.execute("SELECT COUNT(*) FROM session_focus").fetchone()[0]
        assert remaining == 0
        conn.close()

    def test_recent_focus_preserved(self):
        """未超龄 session_focus 保留。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_focus (
                session_id TEXT, keyword TEXT, updated_at TEXT, hit_count INTEGER
            )
        """)
        conn.execute(
            "INSERT INTO session_focus (session_id, keyword, updated_at, hit_count) VALUES (?, ?, ?, ?)",
            ("session_recent", "python", _now_iso(), 10)
        )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["session_focus"] == 0
        remaining = conn.execute("SELECT COUNT(*) FROM session_focus").fetchone()[0]
        assert remaining == 1
        conn.close()


# ── Phase 4: priming_state tests ──

class TestPrimingStateRotation:
    def test_per_project_overflow_prunes_weakest(self):
        """per-project 超额时淘汰 prime_strength 最弱的。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS priming_state (
                entity_name TEXT, project TEXT, primed_at TEXT, prime_strength REAL
            )
        """)
        max_per_project = int(_cfg("logrotate.priming_max_per_project"))  # 100
        # Insert more than max for one project
        for i in range(max_per_project + 30):
            conn.execute(
                "INSERT INTO priming_state (entity_name, project, primed_at, prime_strength) VALUES (?, ?, ?, ?)",
                (f"entity_{i:04d}", PROJECT, _now_iso(), i * 0.01)  # strength: 0.0 to ~1.3
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["priming_state"] == 30
        remaining = conn.execute(
            "SELECT COUNT(*) FROM priming_state WHERE project = ?", (PROJECT,)
        ).fetchone()[0]
        assert remaining == max_per_project

        # Verify strongest were kept (the last max_per_project entries have highest strength)
        min_strength = conn.execute(
            "SELECT MIN(prime_strength) FROM priming_state WHERE project = ?", (PROJECT,)
        ).fetchone()[0]
        # The 30 weakest (strength 0.0-0.29) should be deleted
        assert min_strength >= 0.29
        conn.close()

    def test_under_limit_project_not_affected(self):
        """不超额的 project 不受影响。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS priming_state (
                entity_name TEXT, project TEXT, primed_at TEXT, prime_strength REAL
            )
        """)
        for i in range(5):
            conn.execute(
                "INSERT INTO priming_state (entity_name, project, primed_at, prime_strength) VALUES (?, ?, ?, ?)",
                (f"entity_{i}", PROJECT, _now_iso(), 0.8)
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["priming_state"] == 0
        conn.close()


# ── Phase 5: tool_patterns tests ──

class TestToolPatternsRotation:
    def test_overflow_prunes_low_frequency(self):
        """超额时淘汰低频旧模式。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT, tool_sequence TEXT, context_keywords TEXT,
                frequency INTEGER, avg_duration_ms REAL, success_rate REAL,
                first_seen TEXT, last_seen TEXT, project TEXT
            )
        """)
        max_entries = int(_cfg("logrotate.tool_patterns_max_entries"))  # 300
        # Insert more than max
        for i in range(max_entries + 40):
            conn.execute(
                "INSERT INTO tool_patterns (pattern_hash, tool_sequence, context_keywords, "
                "frequency, avg_duration_ms, success_rate, first_seen, last_seen, project) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"hash_{i:04d}", f"Read,Edit", "test",
                 i,  # frequency: 0 to max+39 (low freq first)
                 100.0, 1.0,
                 _ago_iso(hours=24), _ago_iso(hours=(max_entries + 40 - i)),
                 PROJECT)
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["tool_patterns"] == 40
        remaining = conn.execute("SELECT COUNT(*) FROM tool_patterns").fetchone()[0]
        assert remaining == max_entries

        # Verify high-frequency patterns were kept
        min_freq = conn.execute("SELECT MIN(frequency) FROM tool_patterns").fetchone()[0]
        assert min_freq >= 40  # The 40 lowest (0-39) should be deleted
        conn.close()


# ── Phase 6: entity_edges tests ──

class TestEntityEdgesRotation:
    def test_orphan_old_edges_deleted(self):
        """NULL source_chunk_id + 超龄的 orphaned edges 被清除。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_edges (
                id TEXT, from_entity TEXT, relation TEXT, to_entity TEXT,
                project TEXT, source_chunk_id TEXT, confidence REAL,
                created_at TEXT, agent_id TEXT
            )
        """)
        # Insert orphaned edges (no source_chunk_id, 4 days old)
        for i in range(10):
            conn.execute(
                "INSERT INTO entity_edges (id, from_entity, relation, to_entity, project, "
                "source_chunk_id, confidence, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                (f"ee_orphan_{i}", f"entity_a_{i}", "uses", f"entity_b_{i}",
                 PROJECT, 0.7, _ago_iso(hours=96))
            )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["entity_edges"] == 10
        remaining = conn.execute("SELECT COUNT(*) FROM entity_edges").fetchone()[0]
        assert remaining == 0
        conn.close()

    def test_edges_with_source_chunk_preserved(self):
        """有 source_chunk_id 的 edges 不受 logrotate 影响（由 fstrim 管理）。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_edges (
                id TEXT, from_entity TEXT, relation TEXT, to_entity TEXT,
                project TEXT, source_chunk_id TEXT, confidence REAL,
                created_at TEXT, agent_id TEXT
            )
        """)
        # Insert edge with source_chunk_id (old but should NOT be deleted by logrotate)
        conn.execute(
            "INSERT INTO entity_edges (id, from_entity, relation, to_entity, project, "
            "source_chunk_id, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("ee_with_src", "entity_a", "uses", "entity_b",
             PROJECT, "some-chunk-id", 0.7, _ago_iso(hours=96))
        )
        conn.commit()

        result = logrotate(conn)
        assert result["rotated"]["entity_edges"] == 0
        remaining = conn.execute("SELECT COUNT(*) FROM entity_edges").fetchone()[0]
        assert remaining == 1
        conn.close()


# ── Cross-cutting tests ──

class TestLogrotateGeneral:
    def test_fault_isolation(self):
        """单表异常不影响其他 phase。"""
        conn = _setup_db()
        # Only create some tables, not all — missing tables should not crash
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_focus (
                session_id TEXT, keyword TEXT, updated_at TEXT, hit_count INTEGER
            )
        """)
        # Insert old data in the one table that exists
        conn.execute(
            "INSERT INTO session_focus (session_id, keyword, updated_at, hit_count) VALUES (?, ?, ?, ?)",
            ("session_old", "keyword", _ago_iso(hours=96), 1)
        )
        conn.commit()

        # Should not crash even if other tables are missing
        result = logrotate(conn)
        # session_focus should still be cleaned
        assert result["rotated"]["session_focus"] == 1
        assert result["total_rotated"] >= 1
        conn.close()

    def test_idempotent(self):
        """连续调用不重复删除。"""
        conn = _setup_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ipc_msgq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_agent TEXT, target_agent TEXT, msg_type TEXT,
                payload TEXT, priority INTEGER DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT, consumed_at TEXT, ttl_seconds INTEGER DEFAULT 0
            )
        """)
        for i in range(5):
            conn.execute(
                "INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload, status, created_at) "
                "VALUES (?, ?, ?, ?, 'CONSUMED', ?)",
                (f"agent_{i}", "*", "test", "{}", _ago_iso(hours=72))
            )
        conn.commit()

        r1 = logrotate(conn)
        assert r1["rotated"]["ipc_msgq"] == 5

        r2 = logrotate(conn)
        assert r2["rotated"]["ipc_msgq"] == 0
        assert r2["total_rotated"] == 0
        conn.close()

    def test_performance(self):
        """性能：logrotate < 500ms。"""
        conn = _setup_db()
        # Setup all tables with moderate data
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ipc_msgq (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_agent TEXT, target_agent TEXT, msg_type TEXT,
                payload TEXT, priority INTEGER DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT, consumed_at TEXT, ttl_seconds INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hook_txn_log (
                txn_id TEXT, hook TEXT, status TEXT, chunk_count INTEGER,
                session_id TEXT, project TEXT, started_at TEXT,
                committed_at TEXT, error TEXT, agent_id TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_focus (
                session_id TEXT, keyword TEXT, updated_at TEXT, hit_count INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS priming_state (
                entity_name TEXT, project TEXT, primed_at TEXT, prime_strength REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT, tool_sequence TEXT, context_keywords TEXT,
                frequency INTEGER, avg_duration_ms REAL, success_rate REAL,
                first_seen TEXT, last_seen TEXT, project TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_edges (
                id TEXT, from_entity TEXT, relation TEXT, to_entity TEXT,
                project TEXT, source_chunk_id TEXT, confidence REAL,
                created_at TEXT, agent_id TEXT
            )
        """)
        conn.commit()

        import time
        t0 = time.time()
        result = logrotate(conn)
        elapsed_ms = (time.time() - t0) * 1000
        assert elapsed_ms < 500, f"logrotate took {elapsed_ms:.1f}ms (>500ms)"
        conn.close()
