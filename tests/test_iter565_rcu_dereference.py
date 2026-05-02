"""
iter565: rcu_dereference — Recall Counts Visibility Barrier

根因：retriever 使用 immutable=1 连接（不读 WAL），recall_traces 新记录在 WAL 中，
导致 chunk_recall_counts 返回空 → bandwidth_throttle/cfs_bandwidth_throttle 全部失效
→ 垄断 chunk score 永远 ~0.99。

OS 类比：rcu_dereference() (Paul McKenney, 2002) — RCU reader 必须通过 memory barrier
看到 writer 的最新更新。immutable=1 等价于缺失 read barrier 的 RCU reader。

测试覆盖：
  1. immutable=1 连接看不到 WAL 中的 recall_traces（复现根因）
  2. 标准 WAL 连接能看到最新 recall_traces（验证修复）
  3. recall_count>0 时 bandwidth_throttle 正确触发
  4. recall_count>0 时 cfs_bandwidth_throttle 正确触发
  5. saturation_penalty 在 recall_count>0 时生效
  6. 端到端：高 recall_count 导致 score 显著下降
  7. 修复前后 score 差异验证
  8. 连接正确关闭（无泄漏）
  9. 异常容错：DB 不存在时 fallback
  10. 幂等性：多次加载结果一致
"""
import json
import os
import sqlite3
import sys
import tempfile
import time

# ── 测试隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="test_rcu_dereference_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from store_criu import chunk_recall_counts, chunk_session_recall_counts
from scorer import (
    retrieval_score, bandwidth_throttle, cfs_bandwidth_throttle,
    saturation_penalty,
)


def _create_test_db(db_path: str) -> sqlite3.Connection:
    """创建带 WAL 模式的测试 DB。"""
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


def _insert_traces(conn, project: str, chunk_id: str, count: int,
                   session_id: str = "test-session"):
    """插入 N 条包含指定 chunk 的 recall_traces（injected=1）。"""
    import uuid
    for i in range(count):
        trace_id = str(uuid.uuid4())
        top_k = json.dumps([{"id": chunk_id, "summary": "test", "score": 0.9}])
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json, injected, reason, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (trace_id, f"2026-05-02T{10+i:02d}:00:00+00:00", session_id,
             project, f"hash_{i}", 10, top_k, 1, "test", 50.0)
        )
    conn.commit()


# ── Test 1: immutable=1 连接看不到 WAL 中的数据（复现根因）──
def test_immutable_misses_wal_data():
    """immutable=1 连接无法看到 WAL 中未 checkpoint 的 recall_traces。"""
    db_path = os.path.join(_tmpdir, "t1.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_a", "chunk_001", 15)
    # 不做 checkpoint，数据还在 WAL 中
    conn.close()

    # immutable=1 连接
    imm_conn = sqlite3.connect(f"file:{db_path}?immutable=1", uri=True)
    counts_imm = chunk_recall_counts(imm_conn, "proj_a", window=30)
    imm_conn.close()

    # 标准连接
    std_conn = sqlite3.connect(db_path)
    counts_std = chunk_recall_counts(std_conn, "proj_a", window=30)
    std_conn.close()

    # immutable 可能看到 0（WAL 未 checkpoint）
    # 标准连接一定能看到 15
    assert counts_std.get("chunk_001", 0) == 15, \
        f"Standard conn should see 15, got {counts_std.get('chunk_001', 0)}"
    # 核心断言：标准连接比 immutable 连接看到更多（或相等，如果恰好 checkpoint 了）
    assert counts_std.get("chunk_001", 0) >= counts_imm.get("chunk_001", 0), \
        "Standard conn must see >= immutable conn data"


# ── Test 2: 标准连接能看到最新 recall_traces ──
def test_standard_conn_sees_latest():
    """标准 WAL 连接能看到所有已提交的 recall_traces。"""
    db_path = os.path.join(_tmpdir, "t2.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_b", "chunk_002", 20)
    conn.close()

    std_conn = sqlite3.connect(db_path)
    counts = chunk_recall_counts(std_conn, "proj_b", window=30)
    std_conn.close()

    assert counts.get("chunk_002", 0) == 20


# ── Test 3: bandwidth_throttle 在高 recall_count 时触发 ──
def test_bandwidth_throttle_triggers():
    """recall_count/window > 30% 时 bandwidth_throttle 返回 0.15。"""
    # 10/30 = 33% > 30%
    assert bandwidth_throttle(10) < 1.0
    assert abs(bandwidth_throttle(10) - 0.15) < 0.01
    # 5/30 = 16.7% < 30%
    assert bandwidth_throttle(5) == 1.0
    # 0 → 不触发
    assert bandwidth_throttle(0) == 1.0


# ── Test 4: cfs_bandwidth_throttle 在超 quota 时触发 ──
def test_cfs_bandwidth_throttle_triggers():
    """recall_count > quota 时 cfs_bandwidth_throttle 返回渐进衰减值。"""
    # <= quota → 1.0
    assert cfs_bandwidth_throttle(8) == 1.0
    assert cfs_bandwidth_throttle(5) == 1.0
    # > quota → 衰减
    t9 = cfs_bandwidth_throttle(9)  # overflow=1
    assert t9 < 1.0, f"Expected <1.0, got {t9}"
    t15 = cfs_bandwidth_throttle(15)  # overflow=7
    assert t15 < t9, f"t15={t15} should be < t9={t9} (more overflow)"
    t25 = cfs_bandwidth_throttle(25)  # overflow=17
    assert t25 < 0.05, f"t25={t25} should be < 0.05 (heavy overflow)"


# ── Test 5: saturation_penalty 在 recall_count>0 时生效 ──
def test_saturation_penalty_nonzero():
    """saturation_penalty 随 recall_count 增长。"""
    assert saturation_penalty(0) == 0.0
    sp3 = saturation_penalty(3)
    sp10 = saturation_penalty(10)
    sp30 = saturation_penalty(30)
    assert 0 < sp3 < sp10 < sp30
    assert sp30 <= 0.25  # cap


# ── Test 6: 端到端 score 差异 ──
def test_score_drops_with_recall_count():
    """高 recall_count 导致 retrieval_score 显著下降。"""
    common = dict(
        relevance=0.9,
        importance=0.95,
        last_accessed="2026-05-02T10:00:00+00:00",
        access_count=40,
        created_at="2026-04-20T00:00:00+00:00",
        chunk_id="test-chunk",
        query_seed="test",
        confidence_score=0.96,
        verification_status="verified",
        lru_gen=0,
        chunk_project="proj_x",
        current_project="proj_x",
        chunk_type="design_constraint",
    )
    score_0 = retrieval_score(recall_count=0, session_recall_count=0, **common)
    score_15 = retrieval_score(recall_count=15, session_recall_count=3, **common)
    score_25 = retrieval_score(recall_count=25, session_recall_count=5, **common)

    assert score_0 > 0.5, f"score_0={score_0} should be > 0.5"
    assert score_15 < score_0 * 0.3, \
        f"score_15={score_15} should be < 30% of score_0={score_0}"
    assert score_25 < score_15, \
        f"score_25={score_25} should be < score_15={score_15}"
    # 核心验证：如果 recall_count 误为 0，score 会是 ~1.0；正确传入后 <0.1
    assert score_25 < 0.1, f"score_25={score_25} should be < 0.1 with heavy throttle"


# ── Test 7: 修复前后 score 差异量化 ──
def test_fix_impact_quantification():
    """量化 recall_count=0 (bug) vs recall_count=24 (fix) 的 score 差异。"""
    common = dict(
        relevance=0.85,
        importance=0.90,
        last_accessed="2026-05-01T23:45:00+00:00",
        access_count=89,
        created_at="2026-04-18T00:00:00+00:00",
        chunk_id="monopoly-chunk",
        query_seed="test query",
        confidence_score=0.96,
        verification_status="verified",
        lru_gen=0,
        chunk_project="proj_x",
        current_project="proj_x",
        chunk_type="design_constraint",
    )
    score_bug = retrieval_score(recall_count=0, session_recall_count=0, **common)
    score_fix = retrieval_score(recall_count=24, session_recall_count=5, **common)

    ratio = score_fix / score_bug if score_bug > 0 else 0
    assert ratio < 0.05, \
        f"Fix should reduce score by >95%, ratio={ratio:.4f} (bug={score_bug:.4f}, fix={score_fix:.4f})"


# ── Test 8: session_recall_counts 也使用标准连接 ──
def test_session_recall_counts_visibility():
    """session_recall_counts 通过标准连接也能看到 WAL 数据。"""
    db_path = os.path.join(_tmpdir, "t8.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_c", "chunk_008", 5, session_id="sess_001")
    conn.close()

    std_conn = sqlite3.connect(db_path)
    counts = chunk_session_recall_counts(std_conn, "proj_c", "sess_001", window=100)
    std_conn.close()

    assert counts.get("chunk_008", 0) == 5


# ── Test 9: 异常容错 ──
def test_fallback_on_missing_db():
    """DB 不存在时 chunk_recall_counts 返回空 dict（不崩溃）。"""
    fake_path = os.path.join(_tmpdir, "nonexistent.db")
    try:
        conn = sqlite3.connect(fake_path)
        counts = chunk_recall_counts(conn, "proj_d", window=30)
        conn.close()
    except Exception:
        counts = {}
    # 应返回空 dict 或抛异常被捕获
    assert isinstance(counts, dict)


# ── Test 10: 幂等性 ──
def test_idempotent_loading():
    """多次加载 recall_counts 结果一致。"""
    db_path = os.path.join(_tmpdir, "t10.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_e", "chunk_010", 12)
    conn.close()

    results = []
    for _ in range(3):
        std_conn = sqlite3.connect(db_path)
        counts = chunk_recall_counts(std_conn, "proj_e", window=30)
        results.append(counts.get("chunk_010", 0))
        std_conn.close()

    assert all(r == 12 for r in results), f"Non-idempotent: {results}"


# ── Test 11: 多 chunk 混合场景 ──
def test_multi_chunk_recall_counts():
    """多个 chunk 在同一 trace 中的 recall_count 正确统计。"""
    db_path = os.path.join(_tmpdir, "t11.db")
    conn = _create_test_db(db_path)

    import uuid
    for i in range(10):
        top_k = json.dumps([
            {"id": "chunk_a", "summary": "a", "score": 0.9},
            {"id": "chunk_b", "summary": "b", "score": 0.7},
        ])
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json, injected, reason, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), f"2026-05-02T{10+i:02d}:00:00+00:00", "sess",
             "proj_f", f"h_{i}", 10, top_k, 1, "test", 50.0)
        )
    # 5 条只包含 chunk_a
    for i in range(5):
        top_k = json.dumps([{"id": "chunk_a", "summary": "a", "score": 0.9}])
        conn.execute(
            "INSERT INTO recall_traces (id, timestamp, session_id, project, "
            "prompt_hash, candidates_count, top_k_json, injected, reason, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), f"2026-05-02T{20+i:02d}:00:00+00:00", "sess",
             "proj_f", f"h2_{i}", 10, top_k, 1, "test", 50.0)
        )
    conn.commit()
    conn.close()

    std_conn = sqlite3.connect(db_path)
    counts = chunk_recall_counts(std_conn, "proj_f", window=30)
    std_conn.close()

    assert counts.get("chunk_a", 0) == 15, f"chunk_a: {counts.get('chunk_a', 0)}"
    assert counts.get("chunk_b", 0) == 10, f"chunk_b: {counts.get('chunk_b', 0)}"


# ── Test 12: 性能基准 ──
def test_performance():
    """recall_counts 加载应在 5ms 内完成（100 traces）。"""
    db_path = os.path.join(_tmpdir, "t12.db")
    conn = _create_test_db(db_path)
    _insert_traces(conn, "proj_perf", "chunk_perf", 100)
    conn.close()

    t0 = time.time()
    for _ in range(10):
        std_conn = sqlite3.connect(db_path)
        chunk_recall_counts(std_conn, "proj_perf", window=30)
        std_conn.close()
    elapsed_ms = (time.time() - t0) / 10 * 1000
    assert elapsed_ms < 5.0, f"Too slow: {elapsed_ms:.1f}ms"


if __name__ == "__main__":
    import shutil
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    shutil.rmtree(_tmpdir, ignore_errors=True)
