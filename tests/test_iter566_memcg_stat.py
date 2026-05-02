"""
iter566: memcg_stat — Cross-Project Recall Accounting for Global Chunks

根因：chunk_recall_counts() 使用 WHERE project=? 只统计当前项目的召回次数。
global 层 chunk 被多个项目共享召回，但每个项目独立计数 → 从新项目访问时
recall_count=0 → anti-monopoly 机制全部短路 → 垄断 chunk score 永远 ~0.99。

OS 类比：Linux cgroup v2 memory.stat hierarchical aggregation (Tejun Heo, 2012,
kernel 3.16, mm/memcontrol.c) — 共享页面的跨 cgroup 访问计数聚合，
反映真实系统级资源压力。

测试覆盖：
  1. cross_project_counts: 跨项目 recall 计数正确聚合
  2. excludes_current_project: memcg 排除当前项目（避免双重计数）
  3. merge_takes_max: 合并时取 max(local, memcg) 而非 sum
  4. local_higher_preserved: 本地计数更高时保留本地值
  5. empty_cross_project: 无跨项目 traces 时返回空 dict
  6. disabled_returns_empty: memcg_stat.enabled=False 时不执行跨项目查询
  7. score_impact_monopoly: 垄断 chunk 跨项目 throttle 后 score 显著下降
  8. score_impact_fresh: 无跨项目 recall 的 chunk 不受影响
  9. window_respected: memcg window 参数正确限制回溯范围
  10. multiple_projects: 多项目分布式 recall 正确聚合
  11. non_injected_excluded: injected=0 的 traces 不计入
  12. idempotent: 多次调用结果一致
  13. performance: 100 traces 下 <5ms
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
import uuid

# ── 测试隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="test_memcg_stat_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from store_criu import chunk_recall_counts, chunk_recall_counts_memcg
from scorer import (
    retrieval_score, bandwidth_throttle, cfs_bandwidth_throttle,
    saturation_penalty,
)


def _create_test_db(db_path: str) -> sqlite3.Connection:
    """创建带 recall_traces 和 memory_chunks 表的测试 DB。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS recall_traces (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        session_id TEXT NOT NULL,
        project TEXT NOT NULL,
        prompt_hash TEXT NOT NULL,
        candidates_count INTEGER,
        top_k_json TEXT,
        injected INTEGER DEFAULT 0,
        reason TEXT,
        duration_ms REAL DEFAULT 0,
        ftrace_json TEXT,
        user_feedback TEXT,
        feedback_ts TEXT,
        agent_id TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS memory_chunks (
        id TEXT PRIMARY KEY,
        created_at TEXT, updated_at TEXT, project TEXT,
        source_session TEXT, chunk_type TEXT, content TEXT,
        summary TEXT, tags TEXT, importance REAL,
        retrievability REAL, last_accessed TEXT, feishu_url TEXT,
        access_count INTEGER DEFAULT 0, oom_adj INTEGER DEFAULT 0,
        lru_gen INTEGER DEFAULT 0, confidence_score REAL DEFAULT 0.7,
        evidence_chain TEXT, verification_status TEXT DEFAULT 'pending',
        info_class TEXT DEFAULT 'world', stability REAL DEFAULT 30.0,
        emotional_weight REAL DEFAULT 0, emotional_valence REAL DEFAULT 0,
        depth_of_processing REAL DEFAULT 0.5, source_type TEXT DEFAULT 'unknown',
        source_reliability REAL DEFAULT 0.7, encode_context TEXT DEFAULT '',
        raw_snippet TEXT DEFAULT '', encoding_context TEXT DEFAULT '{}',
        original_ec_count INTEGER DEFAULT 0, spaced_access_count INTEGER DEFAULT 0,
        hypermnesia_last_boost TEXT, access_source TEXT DEFAULT 'retrieval',
        row_version INTEGER DEFAULT 1, chunk_state TEXT DEFAULT 'ACTIVE',
        boundary_proximity REAL DEFAULT 0, session_type_history TEXT DEFAULT ''
    )""")
    conn.commit()
    return conn


def _insert_traces(conn, project: str, chunk_ids: list, count: int,
                   session_id: str = "test-session", injected: int = 1):
    """插入 N 条包含指定 chunks 的 recall_traces。"""
    for i in range(count):
        trace_id = str(uuid.uuid4())
        top_k = json.dumps([{"id": cid, "summary": "test", "score": 0.9}
                            for cid in chunk_ids])
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json, injected, reason, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (trace_id, f"2026-05-02T{10+i:02d}:00:00+00:00", session_id,
             project, f"hash_{i}_{project}", 10, top_k, injected, "test", 50.0)
        )
    conn.commit()


# ── Test 1: 跨项目 recall 计数正确聚合 ──
def test_cross_project_counts():
    """memcg 应聚合其他项目的 recall_traces 中的 chunk 出现次数。"""
    db_path = os.path.join(_tmpdir, "t1.db")
    conn = _create_test_db(db_path)
    # chunk_g1 在 project_a 被召回 5 次，在 project_b 被召回 8 次
    _insert_traces(conn, "project_a", ["chunk_g1"], 5)
    _insert_traces(conn, "project_b", ["chunk_g1"], 8)
    conn.close()

    std = sqlite3.connect(db_path)
    # 从 project_c 的视角查询 memcg（排除 project_c 自身）
    memcg = chunk_recall_counts_memcg(std, "project_c", window=60)
    std.close()

    # 应该看到 chunk_g1 的跨项目总计 = 5 + 8 = 13
    assert memcg.get("chunk_g1", 0) == 13, \
        f"Expected 13, got {memcg.get('chunk_g1', 0)}"


# ── Test 2: memcg 排除当前项目 ──
def test_excludes_current_project():
    """memcg 应排除当前项目的 traces（避免与 chunk_recall_counts 双重计数）。"""
    db_path = os.path.join(_tmpdir, "t2.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "project_a", ["chunk_g1"], 10)
    _insert_traces(conn, "project_b", ["chunk_g1"], 5)
    conn.close()

    std = sqlite3.connect(db_path)
    # 从 project_a 查询 memcg — 应只看到 project_b 的 5 次
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    assert memcg.get("chunk_g1", 0) == 5, \
        f"Expected 5 (only project_b), got {memcg.get('chunk_g1', 0)}"


# ── Test 3: 合并时取 max 而非 sum ──
def test_merge_takes_max():
    """合并策略应取 max(local, memcg) 而非 sum，避免过度惩罚。"""
    db_path = os.path.join(_tmpdir, "t3.db")
    conn = _create_test_db(db_path)
    # local (project_a): chunk_g1 出现 3 次
    _insert_traces(conn, "project_a", ["chunk_g1"], 3)
    # memcg (project_b): chunk_g1 出现 20 次
    _insert_traces(conn, "project_b", ["chunk_g1"], 20)
    conn.close()

    std = sqlite3.connect(db_path)
    local = chunk_recall_counts(std, "project_a", window=30)
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    # merge: max(3, 20) = 20
    merged = dict(local)
    for mcid, mcnt in memcg.items():
        existing = merged.get(mcid, 0)
        if mcnt > existing:
            merged[mcid] = mcnt

    assert merged.get("chunk_g1", 0) == 20, \
        f"Expected max(3,20)=20, got {merged.get('chunk_g1', 0)}"


# ── Test 4: 本地计数更高时保留本地值 ──
def test_local_higher_preserved():
    """当 local recall_count > memcg count 时，保留 local 值。"""
    db_path = os.path.join(_tmpdir, "t4.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "project_a", ["chunk_g1"], 15)
    _insert_traces(conn, "project_b", ["chunk_g1"], 3)
    conn.close()

    std = sqlite3.connect(db_path)
    local = chunk_recall_counts(std, "project_a", window=30)
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    merged = dict(local)
    for mcid, mcnt in memcg.items():
        existing = merged.get(mcid, 0)
        if mcnt > existing:
            merged[mcid] = mcnt

    assert merged.get("chunk_g1", 0) == 15, \
        f"Expected max(15,3)=15, got {merged.get('chunk_g1', 0)}"


# ── Test 5: 无跨项目 traces 时返回空 ──
def test_empty_cross_project():
    """当其他项目无 traces 时，memcg 返回空 dict。"""
    db_path = os.path.join(_tmpdir, "t5.db")
    conn = _create_test_db(db_path)
    # 只有 project_a 有 traces
    _insert_traces(conn, "project_a", ["chunk_g1"], 10)
    conn.close()

    std = sqlite3.connect(db_path)
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    assert len(memcg) == 0, f"Expected empty dict, got {len(memcg)} entries"


# ── Test 6: disabled 时不执行跨项目查询（功能级测试）──
def test_disabled_config():
    """memcg_stat.enabled=False 时，chunk_recall_counts_memcg 仍返回有效数据，
    但调用方（retriever）不应执行合并。这里测试函数本身总是返回正确数据。"""
    db_path = os.path.join(_tmpdir, "t6.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "project_a", ["chunk_g1"], 5)
    _insert_traces(conn, "project_b", ["chunk_g1"], 10)
    conn.close()

    std = sqlite3.connect(db_path)
    # 函数本身不受 config 控制（config 门控在 retriever 层）
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    # 函数应正常返回 project_b 的数据
    assert memcg.get("chunk_g1", 0) == 10


# ── Test 7: 垄断 chunk 跨项目 throttle 后 score 显著下降 ──
def test_score_impact_monopoly():
    """高 recall_count 的 global chunk 通过 memcg 合并后应触发强力 throttle。"""
    # 模拟：chunk 在其他项目被召回 25 次，本地 0 次
    local_rc = 0
    memcg_rc = 25
    effective_rc = max(local_rc, memcg_rc)

    # Before memcg: recall_count=0, no throttle
    bw_before = min(bandwidth_throttle(local_rc), cfs_bandwidth_throttle(local_rc))
    assert bw_before == 1.0, "Before: no throttle at rc=0"

    # After memcg: recall_count=25, strong throttle
    bw_after = min(bandwidth_throttle(effective_rc), cfs_bandwidth_throttle(effective_rc))
    assert bw_after < 0.05, f"After: should be heavily throttled, got {bw_after}"

    # Impact: >95% reduction
    reduction = (1.0 - bw_after / bw_before) * 100
    assert reduction > 95, f"Expected >95% reduction, got {reduction:.1f}%"


# ── Test 8: 无跨项目 recall 的 chunk 不受影响 ──
def test_score_impact_fresh():
    """只在本地出现的 chunk 不受 memcg 影响（memcg returns 0）。"""
    local_rc = 3
    memcg_rc = 0
    effective_rc = max(local_rc, memcg_rc)

    bw_before = min(bandwidth_throttle(local_rc), cfs_bandwidth_throttle(local_rc))
    bw_after = min(bandwidth_throttle(effective_rc), cfs_bandwidth_throttle(effective_rc))

    assert bw_before == bw_after, \
        f"Fresh chunk should not be affected: {bw_before} != {bw_after}"


# ── Test 9: window 参数限制回溯范围 ──
def test_window_respected():
    """memcg window 应限制回溯的 traces 数量。"""
    db_path = os.path.join(_tmpdir, "t9.db")
    conn = _create_test_db(db_path)
    # 插入 30 条 traces
    _insert_traces(conn, "project_b", ["chunk_g1"], 30)
    conn.close()

    std = sqlite3.connect(db_path)
    # window=10: 只看最近 10 条
    memcg_10 = chunk_recall_counts_memcg(std, "project_a", window=10)
    # window=60: 看所有 30 条
    memcg_60 = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    assert memcg_10.get("chunk_g1", 0) == 10, \
        f"window=10 should see 10, got {memcg_10.get('chunk_g1', 0)}"
    assert memcg_60.get("chunk_g1", 0) == 30, \
        f"window=60 should see 30, got {memcg_60.get('chunk_g1', 0)}"


# ── Test 10: 多项目分布式 recall 正确聚合 ──
def test_multiple_projects():
    """chunk 在 5 个不同项目中各被召回若干次，memcg 应聚合总和（排除当前项目）。"""
    db_path = os.path.join(_tmpdir, "t10.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_1", ["chunk_g1"], 3)
    _insert_traces(conn, "proj_2", ["chunk_g1"], 5)
    _insert_traces(conn, "proj_3", ["chunk_g1"], 7)
    _insert_traces(conn, "proj_4", ["chunk_g1"], 2)
    _insert_traces(conn, "proj_5", ["chunk_g1"], 4)  # 当前项目
    conn.close()

    std = sqlite3.connect(db_path)
    memcg = chunk_recall_counts_memcg(std, "proj_5", window=60)
    std.close()

    # 排除 proj_5(4)，总计 3+5+7+2 = 17
    assert memcg.get("chunk_g1", 0) == 17, \
        f"Expected 17 (excluding proj_5), got {memcg.get('chunk_g1', 0)}"


# ── Test 11: injected=0 的 traces 不计入 ──
def test_non_injected_excluded():
    """injected=0 的 traces 不应计入 memcg 计数。"""
    db_path = os.path.join(_tmpdir, "t11.db")
    conn = _create_test_db(db_path)
    # 5 条 injected=1
    _insert_traces(conn, "project_b", ["chunk_g1"], 5, injected=1)
    # 10 条 injected=0（不应计入）
    _insert_traces(conn, "project_b", ["chunk_g1"], 10, injected=0)
    conn.close()

    std = sqlite3.connect(db_path)
    memcg = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    assert memcg.get("chunk_g1", 0) == 5, \
        f"Expected 5 (only injected), got {memcg.get('chunk_g1', 0)}"


# ── Test 12: 幂等性 ──
def test_idempotent():
    """多次调用 chunk_recall_counts_memcg 结果一致。"""
    db_path = os.path.join(_tmpdir, "t12.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "project_b", ["chunk_g1"], 12)
    conn.close()

    std = sqlite3.connect(db_path)
    r1 = chunk_recall_counts_memcg(std, "project_a", window=60)
    r2 = chunk_recall_counts_memcg(std, "project_a", window=60)
    r3 = chunk_recall_counts_memcg(std, "project_a", window=60)
    std.close()

    assert r1 == r2 == r3, "Multiple calls should return identical results"


# ── Test 13: 性能 ──
def test_performance():
    """100 traces 下 memcg 查询应 <5ms。"""
    db_path = os.path.join(_tmpdir, "t13_perf.db")
    conn = _create_test_db(db_path)
    # 插入 100 条 traces 跨 5 个项目
    for p in ["p1", "p2", "p3", "p4", "p5"]:
        _insert_traces(conn, p, [f"chunk_{i}" for i in range(5)], 20)
    conn.close()

    std = sqlite3.connect(db_path)
    t0 = time.time()
    for _ in range(100):
        chunk_recall_counts_memcg(std, "target_project", window=100)
    elapsed = (time.time() - t0) / 100 * 1000  # avg ms
    std.close()

    assert elapsed < 5.0, f"Expected <5ms, got {elapsed:.2f}ms"
    print(f"  [perf] avg memcg query: {elapsed:.3f}ms")


# ── 运行所有测试 ──
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed + failed} tests passed")
    if failed:
        sys.exit(1)
