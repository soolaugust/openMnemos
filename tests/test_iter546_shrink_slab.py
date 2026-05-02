"""
iter546: shrink_slab — Watermark-Independent Slab Object Reaper
OS 类比：Linux do_shrink_slab() (Dave Chinner, 2013, mm/vmscan.c kernel 3.12)
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
from store_mm import shrink_slab
from store_core import dmesg_log, DMESG_INFO


PROJECT = "test:shrink_slab"


def _setup_db():
    """Create DB with schema and clean ALL test data for isolation."""
    conn = open_db()
    ensure_schema(conn)
    conn.execute("DELETE FROM memory_chunks WHERE project LIKE 'test:%'")
    conn.execute("DELETE FROM swap_chunks WHERE project LIKE 'test:%'")
    conn.execute("DELETE FROM dmesg WHERE subsystem = 'loader'")
    conn.commit()
    return conn


def _insert_chunk(conn, chunk_id, project=PROJECT, chunk_type="decision",
                  importance=0.7, access_count=0, oom_adj=0, created_at=None):
    """Insert a test chunk."""
    now = created_at or (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO memory_chunks "
        "(id, created_at, updated_at, project, chunk_type, summary, content, "
        "importance, access_count, oom_adj, chunk_state, lru_gen, last_accessed) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (chunk_id, now, now, project, chunk_type,
         f"test chunk {chunk_id}", f"content for {chunk_id}",
         importance, access_count, oom_adj, "ACTIVE", 0, now)
    )
    conn.commit()


def _insert_session_markers(conn, count=5):
    """Insert N session_start dmesg markers with distinct timestamps (for grace period)."""
    # Insert markers with timestamps spread across hours so grace period works reliably
    now = datetime.now(timezone.utc)
    for i in range(count):
        marker_ts = (now - timedelta(hours=i)).isoformat()
        # Directly insert into dmesg with controlled timestamp for test reliability
        conn.execute(
            "INSERT INTO dmesg (timestamp, subsystem, level, message, session_id, project) "
            "VALUES (?,?,?,?,?,?)",
            (marker_ts, "loader", "INFO", f"session_start test marker {i}",
             f"s-{i}", PROJECT)
        )
    conn.commit()


def _get_chunk_state(conn, chunk_id):
    """Get chunk state, None if not in memory_chunks."""
    row = conn.execute("SELECT chunk_state FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone()
    return row[0] if row else None


def _is_swapped(conn, chunk_id):
    """Check if chunk is in swap_chunks."""
    row = conn.execute("SELECT COUNT(*) FROM swap_chunks WHERE id=?", (chunk_id,)).fetchone()
    return row[0] > 0


# ── count_objects Tests ──

class TestCountObjects:
    def test_empty_db(self):
        """No chunks → freeable=0, reclaimed=0."""
        conn = _setup_db()
        result = shrink_slab(conn, PROJECT)
        assert result["freeable"] == 0
        assert result["reclaimed"] == 0
        conn.close()

    def test_count_high_oom_adj(self):
        """Chunks with oom_adj >= 400 and access_count=0 are freeable."""
        conn = _setup_db()
        _insert_chunk(conn, "z1", oom_adj=400, access_count=0)
        _insert_chunk(conn, "z2", oom_adj=600, access_count=0)
        _insert_chunk(conn, "z3", oom_adj=900, access_count=0)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        assert result["freeable"] == 3
        conn.close()

    def test_skip_low_oom_adj(self):
        """Chunks with oom_adj < 400 are not freeable."""
        conn = _setup_db()
        _insert_chunk(conn, "ok1", oom_adj=0, access_count=0)
        _insert_chunk(conn, "ok2", oom_adj=200, access_count=0)
        _insert_chunk(conn, "ok3", oom_adj=-500, access_count=0)
        result = shrink_slab(conn, PROJECT)
        assert result["freeable"] == 0
        conn.close()

    def test_skip_accessed_chunks(self):
        """Chunks with access_count > 0 are not freeable (even if high oom_adj)."""
        conn = _setup_db()
        _insert_chunk(conn, "a1", oom_adj=600, access_count=3)
        _insert_chunk(conn, "a2", oom_adj=400, access_count=1)
        result = shrink_slab(conn, PROJECT)
        assert result["freeable"] == 0
        conn.close()


# ── scan_objects + Reclaim Tests ──

class TestReclaim:
    def test_basic_reclaim(self):
        """High oom_adj + zero access chunks get reclaimed (removed from memory_chunks)."""
        conn = _setup_db()
        _insert_chunk(conn, "zz1", oom_adj=600, access_count=0, importance=0.6)
        _insert_chunk(conn, "zz2", oom_adj=400, access_count=0, importance=0.7)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        assert result["reclaimed"] == 2
        # Chunks should be removed from memory_chunks (swapped out)
        assert _get_chunk_state(conn, "zz1") is None
        assert _get_chunk_state(conn, "zz2") is None
        conn.close()

    def test_reclaim_priority_order(self):
        """Higher oom_adj reclaimed first (ORDER BY oom_adj DESC)."""
        conn = _setup_db()
        # Insert more than max_scan_per_run (default 5)
        for i in range(8):
            _insert_chunk(conn, f"p{i}", oom_adj=400 + i * 50, access_count=0, importance=0.3)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        # Default max_scan_per_run=5, should reclaim only 5
        assert result["reclaimed"] == 5
        assert result["freeable"] == 8
        # Highest oom_adj should be reclaimed first
        # p7(750), p6(700), p5(650), p4(600), p3(550) should be gone
        assert _get_chunk_state(conn, "p7") is None
        assert _get_chunk_state(conn, "p6") is None
        # p0(400), p1(450), p2(500) should still exist
        assert _get_chunk_state(conn, "p0") == "ACTIVE"
        conn.close()

    def test_protect_high_importance(self):
        """importance >= 0.9 chunks not reclaimed even with high oom_adj."""
        conn = _setup_db()
        _insert_chunk(conn, "imp1", oom_adj=900, access_count=0, importance=0.95)
        _insert_chunk(conn, "imp2", oom_adj=600, access_count=0, importance=0.5)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        # imp1 protected by importance, imp2 reclaimed
        assert result["reclaimed"] == 1
        assert _get_chunk_state(conn, "imp1") == "ACTIVE"
        assert _get_chunk_state(conn, "imp2") is None
        conn.close()


# ── Grace Period Tests ──

class TestGracePeriod:
    def test_grace_period_skip(self):
        """Chunks created within the last N sessions are skipped."""
        conn = _setup_db()
        _insert_session_markers(conn, 5)
        # Create a chunk with a very recent timestamp (within grace period)
        recent = datetime.now(timezone.utc).isoformat()
        _insert_chunk(conn, "new1", oom_adj=600, access_count=0, created_at=recent)
        # Create an old chunk
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        _insert_chunk(conn, "old1", oom_adj=600, access_count=0, created_at=old)
        result = shrink_slab(conn, PROJECT)
        assert result["skipped_grace"] == 1
        assert result["reclaimed"] == 1
        # new1 should survive, old1 should be reclaimed
        assert _get_chunk_state(conn, "new1") == "ACTIVE"
        assert _get_chunk_state(conn, "old1") is None
        conn.close()

    def test_no_session_markers(self):
        """Without session markers, grace period is disabled (no skips)."""
        conn = _setup_db()
        recent = datetime.now(timezone.utc).isoformat()
        _insert_chunk(conn, "new2", oom_adj=600, access_count=0, created_at=recent)
        result = shrink_slab(conn, PROJECT)
        # No session markers → grace_cutoff is None → no grace skip
        assert result["skipped_grace"] == 0
        assert result["reclaimed"] == 1
        conn.close()


# ── Global Scan Tests ──

class TestGlobalScan:
    def test_global_scan(self):
        """project=None scans all projects."""
        conn = _setup_db()
        _insert_chunk(conn, "g1", project="test:proj_a", oom_adj=500, access_count=0)
        _insert_chunk(conn, "g2", project="test:proj_b", oom_adj=600, access_count=0)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, project=None)
        assert result["freeable"] >= 2
        conn.close()

    def test_project_isolation(self):
        """Project-specific scan only touches project + global chunks."""
        conn = _setup_db()
        _insert_chunk(conn, "iso1", project=PROJECT, oom_adj=600, access_count=0)
        _insert_chunk(conn, "iso2", project="test:other", oom_adj=600, access_count=0)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        # Only iso1 (same project) should be freeable — iso2 is in another project
        assert result["freeable"] == 1
        assert result["reclaimed"] == 1
        assert _get_chunk_state(conn, "iso1") is None
        assert _get_chunk_state(conn, "iso2") == "ACTIVE"
        conn.close()


# ── Edge Cases ──

class TestEdgeCases:
    def test_duration_ms(self):
        """Result includes duration_ms."""
        conn = _setup_db()
        result = shrink_slab(conn, PROJECT)
        assert "duration_ms" in result
        assert isinstance(result["duration_ms"], float)
        conn.close()

    def test_mixed_state(self):
        """Mix of freeable and non-freeable chunks."""
        conn = _setup_db()
        # Freeable: high oom, zero access (SQL level: oom>=400 + access=0)
        _insert_chunk(conn, "m1", oom_adj=600, access_count=0, importance=0.3)
        _insert_chunk(conn, "m2", oom_adj=400, access_count=0, importance=0.5)
        # Also counted as freeable by SQL (oom>=400, access=0) but protected by importance
        _insert_chunk(conn, "m6", oom_adj=600, access_count=0, importance=0.95)
        # Not freeable (SQL filter excludes): protected oom, accessed, low oom
        _insert_chunk(conn, "m3", oom_adj=-500, access_count=0, importance=0.3)
        _insert_chunk(conn, "m4", oom_adj=600, access_count=5, importance=0.3)
        _insert_chunk(conn, "m5", oom_adj=100, access_count=0, importance=0.3)
        _insert_session_markers(conn, 5)
        result = shrink_slab(conn, PROJECT)
        # freeable=3 (SQL sees m1, m2, m6), but m6 is protected by importance in scan phase
        assert result["freeable"] == 3
        assert result["reclaimed"] == 2  # Only m1 and m2 actually reclaimed
        # Verify survivors
        assert _get_chunk_state(conn, "m3") == "ACTIVE"
        assert _get_chunk_state(conn, "m4") == "ACTIVE"
        assert _get_chunk_state(conn, "m5") == "ACTIVE"
        assert _get_chunk_state(conn, "m6") == "ACTIVE"  # importance protection
        conn.close()

    def test_idempotent_double_run(self):
        """Running shrink_slab twice doesn't cause errors."""
        conn = _setup_db()
        _insert_chunk(conn, "d1", oom_adj=600, access_count=0)
        _insert_session_markers(conn, 5)
        r1 = shrink_slab(conn, PROJECT)
        assert r1["reclaimed"] == 1
        r2 = shrink_slab(conn, PROJECT)
        assert r2["freeable"] == 0
        assert r2["reclaimed"] == 0
        conn.close()
