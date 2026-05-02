"""test_iter559_fair_clock.py — iter559: fair_clock Cumulative Retrieval Score Calibration

OS 类比：Linux CFS vruntime (Ingo Molnár, 2007, kernel 2.6.23, sched/fair.c)
测试 fair_clock() 基于检索累积分数的 importance 校准。

测试清单：
T1: demote — high importance + zero cum_score + old → importance 衰减
T2: promote — high cum_score + low importance → importance 提升到 target
T3: grace period — 新 chunk 不降级（age < min_age_days）
T4: protected — oom_adj <= -200 (ONFAULT/mlock) 不降级
T5: exempt types — task_state/excluded_path 不降级
T6: cold start — trace 数 < min_traces → 不校准
T7: disabled — fair_clock.enabled=False → 不校准
T8: promote threshold — cum_score < promote_min_cum → 不提升
T9: already high — cum_score 高但 importance 已 >= target → 不提升
T10: demote has cum_score — chunk 有 cum_score 记录 → 不降级
T11: max_per_scan — 不超过扫描上限
T12: multi_project — 不同 project 独立校准
T13: performance — < 50ms for 100 traces
"""
import sys
import os
import json
import time
import tempfile

# ── tmpfs 测试隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="test_fair_clock_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store_mm import fair_clock
from store_core import open_db, ensure_schema, insert_chunk

import pytest
from datetime import datetime, timezone, timedelta


@pytest.fixture
def conn():
    """Create fresh DB with schema."""
    c = open_db()
    ensure_schema(c)
    # Ensure recall_traces table exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS recall_traces (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL DEFAULT '',
            project TEXT NOT NULL DEFAULT '',
            prompt_hash TEXT NOT NULL DEFAULT '',
            candidates_count INTEGER DEFAULT 0,
            top_k_json TEXT,
            injected INTEGER DEFAULT 0,
            reason TEXT,
            duration_ms REAL DEFAULT 0,
            ftrace_json TEXT,
            user_feedback TEXT,
            feedback_ts TEXT,
            agent_id TEXT DEFAULT ''
        )
    """)
    c.commit()
    return c


def _insert_chunk(conn, cid, project, chunk_type, importance, access_count=0,
                   oom_adj=0, age_days=10):
    """Helper: insert a chunk with specified properties."""
    created_at = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    insert_chunk(conn, {
        "id": cid,
        "summary": f"Test chunk {cid}",
        "chunk_type": chunk_type,
        "content": f"Content for {cid}",
        "project": project,
        "source_session": "test-fair-clock",
        "importance": importance,
        "retrievability": 0.35,
        "tags": json.dumps([chunk_type]),
        "access_count": access_count,
        "oom_adj": oom_adj,
        "created_at": created_at,
        "updated_at": now,
        "last_accessed": now,
    })
    conn.commit()


def _insert_traces(conn, project, top_k_entries, n_traces=10):
    """Helper: insert recall traces with specified top_k entries.

    top_k_entries: list of (chunk_id, score) tuples per trace,
                   or list of lists for per-trace control.
    """
    now = datetime.now(timezone.utc)
    if top_k_entries and isinstance(top_k_entries[0], tuple):
        # Same entries for all traces
        entries = top_k_entries
        for i in range(n_traces):
            ts = (now - timedelta(minutes=i)).isoformat()
            top_k_json = json.dumps([
                {"id": cid, "summary": f"summary-{cid}", "score": score, "chunk_type": "decision"}
                for cid, score in entries
            ])
            conn.execute(
                "INSERT INTO recall_traces (id, timestamp, session_id, project, "
                "prompt_hash, candidates_count, top_k_json) VALUES (?,?,?,?,?,?,?)",
                (f"trace-{project}-{i}", ts, f"sess-{i}", project,
                 f"hash-{i}", 10, top_k_json)
            )
    elif top_k_entries and isinstance(top_k_entries[0], list):
        # Per-trace entries
        for i, entries in enumerate(top_k_entries):
            ts = (now - timedelta(minutes=i)).isoformat()
            top_k_json = json.dumps([
                {"id": cid, "summary": f"summary-{cid}", "score": score, "chunk_type": "decision"}
                for cid, score in entries
            ])
            conn.execute(
                "INSERT INTO recall_traces (id, timestamp, session_id, project, "
                "prompt_hash, candidates_count, top_k_json) VALUES (?,?,?,?,?,?,?)",
                (f"trace-{project}-{i}", ts, f"sess-{i}", project,
                 f"hash-{i}", 10, top_k_json)
            )
    else:
        # Empty traces
        for i in range(n_traces):
            ts = (now - timedelta(minutes=i)).isoformat()
            conn.execute(
                "INSERT INTO recall_traces (id, timestamp, session_id, project, "
                "prompt_hash, candidates_count, top_k_json) VALUES (?,?,?,?,?,?,?)",
                (f"trace-{project}-{i}", ts, f"sess-{i}", project,
                 f"hash-{i}", 10, json.dumps([]))
            )
    conn.commit()


# ── T1: Demote — high importance + zero cum_score + old ──

def test_demote_zero_cum_score(conn):
    """高 importance chunk 从未在 top_k 中出现 → importance 应衰减。"""
    _insert_chunk(conn, "chunk-never-seen", "proj-a", "decision", 0.90, age_days=10)
    # Insert traces that don't contain this chunk
    _insert_traces(conn, "proj-a", [("other-chunk", 0.8)], n_traces=10)

    result = fair_clock(conn, "proj-a")
    assert result["demoted"] == 1

    row = conn.execute("SELECT importance FROM memory_chunks WHERE id = ?",
                       ("chunk-never-seen",)).fetchone()
    # 0.90 * 0.75 = 0.675
    assert row[0] < 0.90
    assert abs(row[0] - 0.675) < 0.01


# ── T2: Promote — high cum_score + low importance ──

def test_promote_high_cum_score(conn):
    """累积检索分数高但 importance 低 → 应提升到 target。"""
    _insert_chunk(conn, "chunk-popular", "proj-b", "decision", 0.40, access_count=5, age_days=10)
    # 10 traces, each scoring 0.5 → cum_score = 5.0 >> promote_min_cum (2.0)
    _insert_traces(conn, "proj-b", [("chunk-popular", 0.5)], n_traces=10)

    result = fair_clock(conn, "proj-b")
    assert result["promoted"] == 1

    row = conn.execute("SELECT importance FROM memory_chunks WHERE id = ?",
                       ("chunk-popular",)).fetchone()
    assert row[0] == 0.75  # promote_target default


# ── T3: Grace period — new chunk not demoted ──

def test_grace_period_no_demote(conn):
    """新 chunk（age < min_age_days=3）不降级。"""
    _insert_chunk(conn, "chunk-new", "proj-c", "decision", 0.85, age_days=1)
    _insert_traces(conn, "proj-c", [("other-chunk", 0.8)], n_traces=10)

    result = fair_clock(conn, "proj-c")
    assert result["demoted"] == 0
    assert result["skipped_grace"] == 1

    row = conn.execute("SELECT importance FROM memory_chunks WHERE id = ?",
                       ("chunk-new",)).fetchone()
    assert row[0] == 0.85  # unchanged


# ── T4: Protected — oom_adj <= -200 not demoted ──

def test_protected_no_demote(conn):
    """受保护 chunk (oom_adj <= -200) 不降级。"""
    _insert_chunk(conn, "chunk-prot", "proj-d", "decision", 0.90, oom_adj=-500, age_days=10)
    _insert_traces(conn, "proj-d", [("other-chunk", 0.8)], n_traces=10)

    result = fair_clock(conn, "proj-d")
    assert result["demoted"] == 0
    # oom_adj=-500 is filtered by SQL WHERE oom_adj > -500


# ── T5: Exempt types — task_state/excluded_path not demoted ──

def test_exempt_types_no_demote(conn):
    """控制面类型 (task_state, excluded_path) 不降级。"""
    _insert_chunk(conn, "chunk-ts", "proj-e", "task_state", 0.90, age_days=10)
    _insert_chunk(conn, "chunk-ex", "proj-e", "excluded_path", 0.85, age_days=10)
    _insert_traces(conn, "proj-e", [("other-chunk", 0.8)], n_traces=10)

    result = fair_clock(conn, "proj-e")
    assert result["demoted"] == 0


# ── T6: Cold start — too few traces ──

def test_cold_start_no_calibrate(conn):
    """trace 数 < min_traces(5) → 不校准。"""
    _insert_chunk(conn, "chunk-cold", "proj-f", "decision", 0.90, age_days=10)
    _insert_traces(conn, "proj-f", [("other-chunk", 0.8)], n_traces=3)

    result = fair_clock(conn, "proj-f")
    assert result["demoted"] == 0
    assert result["promoted"] == 0


# ── T7: Disabled ──

def test_disabled(conn):
    """fair_clock.enabled=False → 返回空结果。"""
    from config import sysctl_set
    sysctl_set("fair_clock.enabled", False)
    try:
        _insert_chunk(conn, "chunk-dis", "proj-g", "decision", 0.90, age_days=10)
        _insert_traces(conn, "proj-g", [("other-chunk", 0.8)], n_traces=10)

        result = fair_clock(conn, "proj-g")
        assert result["demoted"] == 0
        assert result["promoted"] == 0
    finally:
        sysctl_set("fair_clock.enabled", True)


# ── T8: Promote threshold — cum_score < min → no promote ──

def test_promote_below_threshold(conn):
    """cum_score < promote_min_cum(2.0) → 不提升。"""
    _insert_chunk(conn, "chunk-low-score", "proj-h", "decision", 0.40, age_days=10)
    # 1 trace, score 0.3 → cum_score = 0.3 < 2.0
    _insert_traces(conn, "proj-h", [("chunk-low-score", 0.3)], n_traces=1)
    # Need enough traces total for min_traces
    for i in range(10):
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json) VALUES (?,?,?,?,?,?,?)",
            (f"trace-extra-h-{i}", datetime.now(timezone.utc).isoformat(),
             f"sess-ex-{i}", "proj-h", f"hash-ex-{i}", 10, json.dumps([]))
        )
    conn.commit()

    result = fair_clock(conn, "proj-h")
    assert result["promoted"] == 0


# ── T9: Already high — no promote needed ──

def test_already_high_no_promote(conn):
    """cum_score 高但 importance 已 >= target → 不提升。"""
    _insert_chunk(conn, "chunk-already-high", "proj-i", "decision", 0.80, age_days=10)
    _insert_traces(conn, "proj-i", [("chunk-already-high", 0.5)], n_traces=10)

    result = fair_clock(conn, "proj-i")
    assert result["promoted"] == 0  # 0.80 >= 0.75 (promote_target)


# ── T10: Has cum_score — not demoted ──

def test_has_cum_score_no_demote(conn):
    """chunk 在 top_k 中出现过（有 cum_score）→ 即使 importance 高也不降级。"""
    _insert_chunk(conn, "chunk-scored", "proj-j", "decision", 0.90, age_days=10)
    _insert_traces(conn, "proj-j", [("chunk-scored", 0.6)], n_traces=10)

    result = fair_clock(conn, "proj-j")
    assert result["demoted"] == 0


# ── T11: max_per_scan limit ──

def test_max_per_scan(conn):
    """降级数不超过 max_per_scan。"""
    from config import sysctl_set
    sysctl_set("fair_clock.max_per_scan", 3)
    try:
        for i in range(10):
            _insert_chunk(conn, f"chunk-many-{i}", "proj-k", "decision", 0.85, age_days=10)
        _insert_traces(conn, "proj-k", [("other-chunk", 0.8)], n_traces=10)

        result = fair_clock(conn, "proj-k")
        assert result["demoted"] <= 3
    finally:
        sysctl_set("fair_clock.max_per_scan", 20)


# ── T12: Multi-project independence ──

def test_multi_project(conn):
    """不同 project 的校准互不影响。"""
    _insert_chunk(conn, "chunk-p1", "proj-l1", "decision", 0.90, age_days=10)
    _insert_chunk(conn, "chunk-p2", "proj-l2", "decision", 0.90, age_days=10)
    # Only proj-l1 has traces
    _insert_traces(conn, "proj-l1", [("other-chunk", 0.8)], n_traces=10)

    # proj-l1 should demote (has enough traces, chunk not in top_k)
    result_l1 = fair_clock(conn, "proj-l1")
    assert result_l1["demoted"] == 1

    # proj-l2 should NOT demote (insufficient traces)
    result_l2 = fair_clock(conn, "proj-l2")
    assert result_l2["demoted"] == 0

    # Verify chunk-p2 unchanged
    row = conn.execute("SELECT importance FROM memory_chunks WHERE id = ?",
                       ("chunk-p2",)).fetchone()
    assert row[0] == 0.90


# ── T13: Performance ──

def test_performance(conn):
    """< 50ms for 100 traces + 50 chunks。"""
    for i in range(50):
        _insert_chunk(conn, f"perf-chunk-{i}", "proj-perf", "decision",
                      0.80, age_days=10)
    now = datetime.now(timezone.utc)
    for i in range(100):
        ts = (now - timedelta(minutes=i)).isoformat()
        top_k = json.dumps([
            {"id": f"perf-chunk-{i % 20}", "summary": f"s-{i}", "score": 0.5, "chunk_type": "decision"}
        ])
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json) VALUES (?,?,?,?,?,?,?)",
            (f"perf-trace-{i}", ts, f"perf-sess-{i}", "proj-perf",
             f"perf-hash-{i}", 50, top_k)
        )
    conn.commit()

    t0 = time.time()
    result = fair_clock(conn, "proj-perf")
    elapsed_ms = (time.time() - t0) * 1000
    assert elapsed_ms < 50, f"fair_clock took {elapsed_ms:.1f}ms (>50ms)"
    assert result["total_scored"] > 0
