"""test_iter503_writeback_pressure.py — iter503: Writeback Pressure 单元测试

OS 类比：Linux vm.dirty_ratio / vm.dirty_background_ratio writeback throttle
当零访问率超过阈值时，新写入 chunk 的 importance 被降级（反压机制）。

WP1: 零访问率 < dirty_bg_ratio → no pressure, importance 不变
WP2: 零访问率 >= dirty_bg_ratio 但 < dirty_ratio → background 降级
WP3: 零访问率 >= dirty_ratio → throttle 硬性降级
WP4: total_chunks < min_chunks → 不触发（冷启动保护）
WP5: writeback_pressure_enabled=False → 不触发
WP6: 边界值测试：零访问率恰好等于阈值
WP7: importance=1.0 经 throttle 后降至 throttle_factor
"""
import sys
import sqlite3
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import tmpfs  # noqa: E402 — must be before store imports
from store_vfs import ensure_schema, insert_chunk, writeback_pressure
import config


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    return c


def _insert_chunks(conn, project, total, zero_access_count):
    """Helper: 插入 total 个 chunks，其中 zero_access_count 个 access_count=0."""
    accessed_count = total - zero_access_count
    for i in range(accessed_count):
        insert_chunk(conn, {
            "id": f"accessed-{i}",
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:00:00Z",
            "project": project,
            "source_session": "test",
            "chunk_type": "decision",
            "info_class": "world",
            "content": f"accessed chunk {i}",
            "summary": f"accessed chunk {i}",
            "tags": "[]",
            "importance": 0.8,
            "retrievability": 0.5,
            "last_accessed": "2026-04-01T00:00:00Z",
            "access_count": 5,
            "oom_adj": 0,
            "lru_gen": 0,
            "stability": 2.0,
            "raw_snippet": "",
            "encoding_context": "{}",
            "confidence_score": 0.7,
        })
    for i in range(zero_access_count):
        insert_chunk(conn, {
            "id": f"zero-{i}",
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:00:00Z",
            "project": project,
            "source_session": "test",
            "chunk_type": "decision",
            "info_class": "world",
            "content": f"zero access chunk {i}",
            "summary": f"zero access chunk {i}",
            "tags": "[]",
            "importance": 0.8,
            "retrievability": 0.5,
            "last_accessed": "2026-04-01T00:00:00Z",
            "access_count": 0,
            "oom_adj": 0,
            "lru_gen": 0,
            "stability": 2.0,
            "raw_snippet": "",
            "encoding_context": "{}",
            "confidence_score": 0.7,
        })
    conn.commit()


def test_wp1_below_bg_ratio_no_pressure(conn):
    """零访问率 30% < dirty_bg_ratio(50%) → no pressure."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=30)
    result = writeback_pressure(conn, "proj1", 0.85)
    assert result["pressure_level"] == "none"
    assert result["adjusted_importance"] == 0.85
    assert result["zero_access_ratio"] == 0.3


def test_wp2_bg_ratio_background_throttle(conn):
    """零访问率 60% >= dirty_bg_ratio(50%) 但 < dirty_ratio(70%) → background."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=60)
    result = writeback_pressure(conn, "proj1", 0.80)
    assert result["pressure_level"] == "background"
    expected = round(0.80 * 0.85, 4)  # bg_throttle_factor=0.85
    assert result["adjusted_importance"] == expected


def test_wp3_dirty_ratio_hard_throttle(conn):
    """零访问率 80% >= dirty_ratio(70%) → throttle."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=80)
    result = writeback_pressure(conn, "proj1", 0.90)
    assert result["pressure_level"] == "throttle"
    expected = round(0.90 * 0.6, 4)  # throttle_factor=0.6
    assert result["adjusted_importance"] == expected


def test_wp4_cold_start_bypass(conn):
    """total_chunks < min_chunks(20) → 不触发反压."""
    _insert_chunks(conn, "proj1", total=10, zero_access_count=9)  # 90% 但只有 10 个
    result = writeback_pressure(conn, "proj1", 0.85)
    assert result["pressure_level"] == "none"
    assert result["adjusted_importance"] == 0.85
    assert result["total_chunks"] == 10


def test_wp5_disabled(conn, monkeypatch):
    """writeback_pressure_enabled=False → 不触发."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=90)
    monkeypatch.setenv("MEMORY_OS_STORE_VFS_WRITEBACK_PRESSURE_ENABLED", "false")
    config._invalidate_cache()
    result = writeback_pressure(conn, "proj1", 0.85)
    assert result["pressure_level"] == "none"
    assert result["adjusted_importance"] == 0.85


def test_wp6_boundary_at_dirty_ratio(conn):
    """零访问率恰好 = dirty_ratio(70%) → throttle（>=）."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=70)
    result = writeback_pressure(conn, "proj1", 0.80)
    assert result["pressure_level"] == "throttle"


def test_wp7_importance_1_throttled(conn):
    """importance=1.0 经 throttle 后降至 0.6."""
    _insert_chunks(conn, "proj1", total=100, zero_access_count=80)
    result = writeback_pressure(conn, "proj1", 1.0)
    assert result["adjusted_importance"] == 0.6
    assert result["pressure_level"] == "throttle"
