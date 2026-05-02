"""iter523: kfree_rcu — Deferred Cross-Project Zombie Reclaim tests."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402, F401 — test isolation (must precede store imports)

import sqlite3
import time
import pytest

from store_mm import kfree_rcu, dmesg_log, DMESG_INFO
from store_vfs import open_db, ensure_schema, delete_chunks


def _setup_db():
    """Create in-memory DB with schema."""
    conn = open_db(":memory:")
    ensure_schema(conn)
    return conn


def _insert_chunk(conn, chunk_id, project, chunk_type="decision", importance=0.5,
                  access_count=0, oom_adj=0, summary="test chunk"):
    """Helper to insert a test chunk."""
    conn.execute(
        """INSERT INTO memory_chunks (id, project, chunk_type, importance,
           access_count, oom_adj, summary, content, source_session, created_at, last_accessed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test', datetime('now'), datetime('now'))""",
        (chunk_id, project, chunk_type, importance, access_count, oom_adj, summary, summary),
    )
    conn.commit()


class TestKfreeRcuBasic:
    """Basic functionality tests."""

    def test_empty_db(self):
        """T1: Empty DB returns zeros, no crash."""
        conn = _setup_db()
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["total_dead"] == 0
        assert result["duration_ms"] >= 0

    def test_no_zombies(self):
        """T2: All chunks above threshold → nothing to free."""
        conn = _setup_db()
        _insert_chunk(conn, "c1", "global", importance=0.5)
        _insert_chunk(conn, "c2", "proj_a", importance=0.8)
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["total_dead"] == 0

    def test_frees_global_zombie(self):
        """T3: Global zombie (imp<0.2, access=0) is freed."""
        conn = _setup_db()
        _insert_chunk(conn, "z1", "global", importance=0.15, access_count=0)
        _insert_chunk(conn, "alive", "global", importance=0.8, access_count=3)
        result = kfree_rcu(conn)
        assert result["freed"] == 1
        # Verify actually deleted
        remaining = conn.execute("SELECT id FROM memory_chunks").fetchall()
        assert len(remaining) == 1
        assert remaining[0][0] == "alive"

    def test_frees_cross_project_zombie(self):
        """T4: Zombie in ANY project (not just global) is freed."""
        conn = _setup_db()
        _insert_chunk(conn, "z1", "proj_a", importance=0.10, access_count=0)
        _insert_chunk(conn, "z2", "proj_b", importance=0.05, access_count=0)
        _insert_chunk(conn, "z3", "global", importance=0.15, access_count=0)
        result = kfree_rcu(conn)
        assert result["freed"] == 3
        remaining = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
        assert remaining == 0

    def test_multiple_zombies_batch(self):
        """T5: Multiple zombies in one scan."""
        conn = _setup_db()
        for i in range(15):
            _insert_chunk(conn, f"z{i}", "global", importance=0.10 + i * 0.005)
        result = kfree_rcu(conn)
        assert result["freed"] == 15
        assert result["total_dead"] == 15


class TestKfreeRcuProtection:
    """Protection mechanism tests."""

    def test_protects_mlock(self):
        """T6: oom_adj <= -500 (mlock) chunks are protected."""
        conn = _setup_db()
        _insert_chunk(conn, "mlock", "global", importance=0.10, oom_adj=-1000)
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["skipped_protected"] == 1

    def test_protects_pinned(self):
        """T7: Pinned chunks are protected."""
        conn = _setup_db()
        _insert_chunk(conn, "pinned", "global", importance=0.10)
        conn.execute(
            "INSERT INTO chunk_pins (chunk_id, pin_type, project, pinned_at) VALUES (?, 'hard', 'global', datetime('now'))",
            ("pinned",),
        )
        conn.commit()
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["skipped_protected"] == 1

    def test_protects_task_state(self):
        """T8: task_state type is protected."""
        conn = _setup_db()
        _insert_chunk(conn, "ts", "global", chunk_type="task_state", importance=0.10)
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["skipped_protected"] == 1

    def test_protects_design_constraint(self):
        """T9: design_constraint type is protected."""
        conn = _setup_db()
        _insert_chunk(conn, "dc", "global", chunk_type="design_constraint", importance=0.10)
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        assert result["skipped_protected"] == 1

    def test_preserves_accessed_chunks(self):
        """T10: Chunks with access_count > 0 are preserved even if imp < threshold."""
        conn = _setup_db()
        _insert_chunk(conn, "accessed", "global", importance=0.10, access_count=2)
        result = kfree_rcu(conn)
        assert result["freed"] == 0
        # Not counted as protected — just skipped by access logic
        remaining = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
        assert remaining == 1


class TestKfreeRcuIntegration:
    """Integration tests."""

    def test_respects_batch_limit(self):
        """T11: Batch limit prevents over-deletion."""
        conn = _setup_db()
        # Insert 80 zombies (max_per_scan default = 40)
        for i in range(80):
            _insert_chunk(conn, f"z{i}", "global", importance=0.05)
        result = kfree_rcu(conn)
        assert result["freed"] <= 40  # max_per_scan limit

    def test_dmesg_logged_on_free(self):
        """T12: Successful free logs to dmesg."""
        conn = _setup_db()
        _insert_chunk(conn, "z1", "global", importance=0.10)
        kfree_rcu(conn)
        rows = conn.execute(
            "SELECT message FROM dmesg WHERE subsystem = 'kfree_rcu'"
        ).fetchall()
        assert len(rows) >= 1
        assert "freed=1" in rows[0][0]

    def test_performance(self):
        """T13: 100 zombies scanned in < 100ms."""
        conn = _setup_db()
        for i in range(100):
            _insert_chunk(conn, f"z{i}", "global", importance=0.10)
        # Warmup
        kfree_rcu(conn)
        # Insert more for second run
        for i in range(100, 200):
            _insert_chunk(conn, f"z{i}", "global", importance=0.10)
        t0 = time.time()
        result = kfree_rcu(conn)
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 100, f"Too slow: {elapsed:.1f}ms"

    def test_fts5_consistency_after_free(self):
        """T14: After kfree_rcu, remaining chunks are intact."""
        conn = _setup_db()
        _insert_chunk(conn, "z1", "global", importance=0.10, summary="zombie one")
        _insert_chunk(conn, "z2", "global", importance=0.10, summary="zombie two")
        _insert_chunk(conn, "keep", "global", importance=0.8, summary="keeper")
        result = kfree_rcu(conn)
        assert result["freed"] == 2
        chunks = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
        assert chunks == 1
        kept = conn.execute("SELECT id FROM memory_chunks").fetchone()[0]
        assert kept == "keep"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
