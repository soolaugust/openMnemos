"""test_iter561_place_entity.py — iter561: place_entity CFS Fair Initial Importance

OS 类比：Linux CFS place_entity() (Ingo Molnár, 2007, kernel 2.6.23)
新 task fork() 时 vruntime 设为 cfs_rq->min_vruntime，公平起点。
memory-os：bulk import imp=0.15 chunk 提升到活跃 chunk P25 importance。

测试矩阵：
T1: 基础 place_entity——imp=0.15 提升到 min_vruntime
T2: grace_days 宽限期——新 chunk 不提升
T3: access_count>0 不提升——已被访问过的不动
T4: oom_adj>=500 不提升——明确低优先级不动
T5: min_active_chunks 冷启动——活跃 chunk 不够时不执行
T6: max_per_scan 限制——单次不超过 N 个
T7: min_vruntime clamp——不低于 0.30 不高于 0.60
T8: enabled=False——禁用时不执行
T9: task_state 不提升——task_state chunk 排除
T10: 多次执行幂等——已提升的不重复提升
T11: project 隔离——只影响当前 project + global
T12: 性能基准——<5ms/call
"""
import sys
import os
import time

# tmpfs 测试隔离
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: F401 — 必须在 store 之前

from store_core import open_db, ensure_schema, insert_chunk
from store_mm import place_entity
from datetime import datetime, timezone, timedelta
import json
import pytest


@pytest.fixture(autouse=True)
def fresh_db():
    """Ensure each test starts with a clean database."""
    conn = open_db()
    ensure_schema(conn)
    conn.execute("DELETE FROM memory_chunks")
    try:
        conn.execute("DELETE FROM memory_chunks_fts")
    except Exception:
        pass
    conn.commit()
    conn.close()
    yield

# Test helper: insert chunk with specific attributes
def _insert(conn, chunk_id, importance=0.15, access_count=0,
            chunk_type="decision", project="test_proj",
            created_at=None, oom_adj=None):
    if created_at is None:
        # Default: 3 days ago (past grace_days=1)
        created_at = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    insert_chunk(conn, {
        "id": chunk_id,
        "summary": f"test chunk {chunk_id}",
        "content": f"content for {chunk_id}",
        "chunk_type": chunk_type,
        "importance": importance,
        "project": project,
        "source_session": "test-place-entity",
        "retrievability": 0.35,
        "tags": json.dumps([chunk_type]),
        "created_at": created_at,
        "updated_at": now,
        "last_accessed": created_at,
        "access_count": access_count,
        "oom_adj": oom_adj or 0,
    })
    conn.commit()


def _setup_active_chunks(conn, n=10, project="test_proj"):
    """Create N active chunks with importance 0.50-0.90 to establish min_vruntime."""
    now = datetime.now(timezone.utc).isoformat()
    for i in range(n):
        imp = 0.50 + (i * 0.04)  # 0.50, 0.54, 0.58, ..., 0.86
        cid = f"active_{i:02d}"
        created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        insert_chunk(conn, {
            "id": cid,
            "summary": f"active chunk {cid}",
            "content": f"active content {cid}",
            "chunk_type": "decision",
            "importance": imp,
            "project": project,
            "source_session": "test-place-entity",
            "retrievability": 0.35,
            "tags": json.dumps(["decision"]),
            "created_at": created,
            "updated_at": now,
            "last_accessed": created,
            "access_count": 3 + i,
        })
    conn.commit()


class TestPlaceEntityBasic:
    """Tests T1-T4: Basic place_entity behavior."""

    def test_basic_placement(self):
        """T1: imp=0.15 chunk gets promoted to min_vruntime."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        # Insert low-importance chunk
        _insert(conn, "low_001", importance=0.15, project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 1
        assert result["min_vruntime"] >= 0.30
        assert result["min_vruntime"] <= 0.60
        # Verify chunk was actually updated
        row = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'low_001'").fetchone()
        assert row[0] == result["min_vruntime"]
        conn.close()

    def test_grace_days_protection(self):
        """T2: Chunk younger than grace_days is NOT promoted."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        # Insert chunk created just now (within grace period)
        _insert(conn, "new_001", importance=0.15, project="test_proj",
                created_at=datetime.now(timezone.utc).isoformat())

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 0
        # Verify chunk unchanged
        row = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'new_001'").fetchone()
        assert row[0] == 0.15
        conn.close()

    def test_accessed_chunks_not_promoted(self):
        """T3: Chunk with access_count>0 is NOT promoted (already participated)."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        _insert(conn, "acc_001", importance=0.20, access_count=1, project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 0
        row = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'acc_001'").fetchone()
        assert row[0] == 0.20  # unchanged
        conn.close()

    def test_high_oom_adj_not_promoted(self):
        """T4: Chunk with oom_adj>=500 is NOT promoted."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        _insert(conn, "oom_001", importance=0.15, project="test_proj", oom_adj=500)

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 0
        row = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'oom_001'").fetchone()
        assert row[0] == 0.15  # unchanged
        conn.close()


class TestPlaceEntityGuards:
    """Tests T5-T9: Guard conditions and limits."""

    def test_min_active_chunks_cold_start(self):
        """T5: Not enough active chunks → skip."""
        conn = open_db()
        ensure_schema(conn)
        # Only 2 active chunks (below min_active_chunks=5)
        _setup_active_chunks(conn, n=2, project="test_proj")
        _insert(conn, "low_002", importance=0.15, project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 0
        assert result["min_vruntime"] == 0.0
        conn.close()

    def test_max_per_scan_limit(self):
        """T6: No more than max_per_scan promoted in one call."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        # Insert 50 low-importance chunks
        for i in range(50):
            _insert(conn, f"bulk_{i:03d}", importance=0.10, project="test_proj")

        result = place_entity(conn, project="test_proj")

        # Default max_per_scan=30
        assert result["placed"] <= 30
        assert result["eligible"] <= 30  # SQL LIMIT applies
        conn.close()

    def test_min_vruntime_clamp_low(self):
        """T7a: min_vruntime clamped to >= 0.30."""
        conn = open_db()
        ensure_schema(conn)
        now = datetime.now(timezone.utc).isoformat()
        # All active chunks have low importance 0.20-0.25
        for i in range(10):
            cid = f"low_active_{i:02d}"
            created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
            insert_chunk(conn, {
                "id": cid, "summary": f"low active {cid}",
                "content": f"content {cid}", "chunk_type": "decision",
                "importance": 0.20 + (i * 0.005),
                "project": "test_proj", "source_session": "test-place-entity",
                "retrievability": 0.35, "tags": json.dumps(["decision"]),
                "created_at": created, "updated_at": now,
                "last_accessed": created, "access_count": 2,
            })
        conn.commit()
        _insert(conn, "target_001", importance=0.10, project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["min_vruntime"] == 0.30  # clamped from ~0.20
        conn.close()

    def test_min_vruntime_clamp_high(self):
        """T7b: min_vruntime clamped to <= 0.60."""
        conn = open_db()
        ensure_schema(conn)
        now = datetime.now(timezone.utc).isoformat()
        # All active chunks have high importance 0.85-0.95
        for i in range(10):
            cid = f"high_active_{i:02d}"
            created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
            insert_chunk(conn, {
                "id": cid, "summary": f"high active {cid}",
                "content": f"content {cid}", "chunk_type": "decision",
                "importance": 0.85 + (i * 0.01),
                "project": "test_proj", "source_session": "test-place-entity",
                "retrievability": 0.35, "tags": json.dumps(["decision"]),
                "created_at": created, "updated_at": now,
                "last_accessed": created, "access_count": 5,
            })
        conn.commit()
        _insert(conn, "target_002", importance=0.10, project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["min_vruntime"] == 0.60  # clamped from ~0.87
        conn.close()

    def test_disabled(self):
        """T8: enabled=False → no action."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        _insert(conn, "low_003", importance=0.15, project="test_proj")

        # Temporarily disable via env
        os.environ["MEMORY_OS_PLACE_ENTITY_ENABLED"] = "false"
        try:
            from config import _invalidate_cache
            _invalidate_cache()
            result = place_entity(conn, project="test_proj")
        finally:
            del os.environ["MEMORY_OS_PLACE_ENTITY_ENABLED"]
            _invalidate_cache()

        assert result["placed"] == 0
        conn.close()

    def test_task_state_excluded(self):
        """T9: task_state chunks are NOT promoted."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        _insert(conn, "ts_001", importance=0.15, chunk_type="task_state",
                project="test_proj")

        result = place_entity(conn, project="test_proj")

        assert result["placed"] == 0
        row = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'ts_001'").fetchone()
        assert row[0] == 0.15  # unchanged
        conn.close()


class TestPlaceEntityIdempotency:
    """Tests T10-T12: Idempotency, isolation, performance."""

    def test_idempotent_after_placement(self):
        """T10: Already-promoted chunks are not promoted again."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        _insert(conn, "low_004", importance=0.15, project="test_proj")

        # First run
        r1 = place_entity(conn, project="test_proj")
        assert r1["placed"] == 1

        # Second run — chunk now has importance >= min_vruntime
        r2 = place_entity(conn, project="test_proj")
        assert r2["placed"] == 0
        conn.close()

    def test_project_isolation(self):
        """T11: Only affects target project + global, not other projects."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=10, project="test_proj")
        # Insert low-imp chunk in another project
        _insert(conn, "other_001", importance=0.15, project="other_proj")
        # Insert low-imp chunk in target project
        _insert(conn, "target_003", importance=0.15, project="test_proj")

        result = place_entity(conn, project="test_proj")

        # Only target project chunk should be affected
        row_other = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'other_001'").fetchone()
        assert row_other[0] == 0.15  # untouched

        row_target = conn.execute("SELECT importance FROM memory_chunks WHERE id = 'target_003'").fetchone()
        assert row_target[0] >= 0.30  # promoted
        conn.close()

    def test_performance_benchmark(self):
        """T12: place_entity completes in <5ms."""
        conn = open_db()
        ensure_schema(conn)
        _setup_active_chunks(conn, n=20, project="test_proj")
        for i in range(30):
            _insert(conn, f"perf_{i:03d}", importance=0.12, project="test_proj")

        times = []
        for _ in range(10):
            t0 = time.time()
            place_entity(conn, project="test_proj")
            times.append((time.time() - t0) * 1000)
            # Reset for next iteration
            conn.execute("UPDATE memory_chunks SET importance = 0.12 WHERE id LIKE 'perf_%'")
            conn.commit()

        avg_ms = sum(times) / len(times)
        assert avg_ms < 5.0, f"Too slow: avg={avg_ms:.2f}ms"
        conn.close()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
