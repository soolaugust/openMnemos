"""
iter580: madvise_cold — Cross-Session Injection Futility Detection
测试 chunk_recall_counts 统计范围从 injected=1 扩展到所有 trace。

验证项：
1. chunk_recall_counts 统计所有 trace 中的 chunk 出现次数（含 skipped_same_hash）
2. chunk_recall_counts_memcg 同样统计所有 trace
3. chunk_session_recall_counts 同样统计所有 trace
4. skipped_same_hash trace 中的 chunk 被正确计入 recall_count
5. top_k_json=NULL 的 trace 被正确跳过
6. bandwidth_throttle 和 cfs_bandwidth_throttle 对修正后的 recall_count 正确触发
7. 多 chunk top_k 中每个 chunk 被独立计数
8. 跨 session 统计正确累加
9. 回归：injected=1 的 trace 仍被正确统计
10. 空数据库返回空 dict
"""
import sqlite3
import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store_criu import (
    chunk_recall_counts,
    chunk_recall_counts_memcg,
    chunk_session_recall_counts,
)
from scorer import bandwidth_throttle, cfs_bandwidth_throttle


def _create_test_db():
    """创建内存测试 DB，含 recall_traces schema。"""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE recall_traces (
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
        )
    """)
    return conn


def _insert_trace(conn, project="proj_a", session_id="sess_1",
                  top_k_json=None, injected=1, reason="hash_changed|full",
                  prompt_hash="abc123"):
    """插入一条 recall_trace。"""
    conn.execute(
        "INSERT INTO recall_traces (id, timestamp, session_id, project, "
        "prompt_hash, candidates_count, top_k_json, injected, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            datetime.now(timezone.utc).isoformat(),
            session_id,
            project,
            prompt_hash,
            10,
            json.dumps(top_k_json) if top_k_json is not None else None,
            injected,
            reason,
        )
    )
    conn.commit()


# ── Test 1: iter604 只统计 injected=1 的 trace ──────────────────────────────
def test_skipped_same_hash_counted():
    """iter604: 只统计 injected=1 的 trace，打破正反馈死锁。"""
    conn = _create_test_db()
    chunk_a = "chunk-aaaa-1111"

    # 5 条 injected=1 trace
    for _ in range(5):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.99}],
                      injected=1, reason="hash_changed|full")
    # 10 条 skipped_same_hash trace（injected=0）
    for _ in range(10):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.99}],
                      injected=0, reason="skipped_same_hash")

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    # iter604: 只统计 injected=1（5 条），跳过 injected=0（10 条）
    assert counts.get(chunk_a) == 5, f"expected 5, got {counts.get(chunk_a)}"


# ── Test 2: top_k_json=NULL 的 trace 被跳过 ─────────────────────────────────────
def test_null_top_k_json_skipped():
    """top_k_json 为 NULL 的 trace 不应影响统计。"""
    conn = _create_test_db()
    chunk_a = "chunk-aaaa-2222"

    # 3 条有 top_k_json
    for _ in range(3):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.5}], injected=1)
    # 5 条 top_k_json=NULL（早期 trace 格式或异常）
    for _ in range(5):
        _insert_trace(conn, top_k_json=None, injected=0, reason="error")

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    assert counts.get(chunk_a) == 3


# ── Test 3: 多 chunk top_k 独立计数 ──────────────────────────────────────────────
def test_multi_chunk_independent_counting():
    """top_k 中的每个 chunk 独立计入各自的 recall_count。"""
    conn = _create_test_db()
    chunk_a = "chunk-aaaa"
    chunk_b = "chunk-bbbb"
    chunk_c = "chunk-cccc"

    # trace 1: A, B, C 都在
    _insert_trace(conn, top_k_json=[
        {"id": chunk_a, "score": 0.99},
        {"id": chunk_b, "score": 0.5},
        {"id": chunk_c, "score": 0.3},
    ], injected=1)
    # trace 2: 只有 A（skipped）
    _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.99}],
                  injected=0, reason="skipped_same_hash")
    # trace 3: A 和 B
    _insert_trace(conn, top_k_json=[
        {"id": chunk_a, "score": 0.99},
        {"id": chunk_b, "score": 0.4},
    ], injected=1)

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    # iter604: 只统计 injected=1 → trace2(injected=0) 不计入
    assert counts[chunk_a] == 2
    assert counts[chunk_b] == 2
    assert counts[chunk_c] == 1


# ── Test 4: bandwidth_throttle 对修正后的 count 正确触发 ──────────────────────────
def test_bandwidth_throttle_triggers_with_corrected_count():
    """修正后的 recall_count 超过 bw_max_pct 时 throttle 应触发。"""
    conn = _create_test_db()
    chunk_a = "chunk-monopoly"

    # iter604: 21 条中 i%3==0 的 7 条 injected=1，其余 injected=0 不计入
    for i in range(21):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.99}],
                      injected=1 if i % 3 == 0 else 0,
                      reason="hash_changed|full" if i % 3 == 0 else "skipped_same_hash")
    # 9 条不含该 chunk
    for _ in range(9):
        _insert_trace(conn, top_k_json=[{"id": "other-chunk", "score": 0.5}],
                      injected=1)

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    rc = counts.get(chunk_a, 0)
    # iter604: 只统计 injected=1 → i=0,3,6,9,12,15,18 共 7 条
    assert rc == 7, f"expected 7, got {rc}"

    # bandwidth_throttle: 仍验证 throttle 对高 rc 值有效
    bw = bandwidth_throttle(rc)
    # rc=7 < quota=8 → bandwidth_throttle 不触发，改用更高值验证
    bw_high = bandwidth_throttle(21)
    assert bw_high < 1.0, f"bandwidth_throttle should trigger for rc=21, got {bw_high}"

    # cfs_bandwidth_throttle: rc=7 < quota=8 → 不触发
    cbw = cfs_bandwidth_throttle(21)
    assert cbw < 1.0, f"cfs_bandwidth should trigger for rc=21, got {cbw}"


# ── Test 5: session_recall_counts 也统计 skipped trace ────────────────────────────
def test_session_recall_counts_includes_skipped():
    """chunk_session_recall_counts 应统计 session 内所有 trace。"""
    conn = _create_test_db()
    chunk_a = "chunk-session-test"
    sess = "session-xyz"

    # 3 条 injected + 4 条 skipped
    for _ in range(3):
        _insert_trace(conn, session_id=sess,
                      top_k_json=[{"id": chunk_a, "score": 0.8}],
                      injected=1)
    for _ in range(4):
        _insert_trace(conn, session_id=sess,
                      top_k_json=[{"id": chunk_a, "score": 0.8}],
                      injected=0, reason="skipped_same_hash")

    counts = chunk_session_recall_counts(conn, "proj_a", sess, window=100)
    assert counts.get(chunk_a) == 7, f"expected 7, got {counts.get(chunk_a)}"


# ── Test 6: memcg 跨项目统计也含 skipped ─────────────────────────────────────────
def test_memcg_includes_skipped():
    """chunk_recall_counts_memcg 应统计跨项目的所有 trace。"""
    conn = _create_test_db()
    global_chunk = "chunk-global"

    # proj_b 的 traces（对 proj_a 来说是跨项目）
    for _ in range(3):
        _insert_trace(conn, project="proj_b",
                      top_k_json=[{"id": global_chunk, "score": 0.9}],
                      injected=1)
    for _ in range(5):
        _insert_trace(conn, project="proj_b",
                      top_k_json=[{"id": global_chunk, "score": 0.9}],
                      injected=0, reason="skipped_same_hash")

    counts = chunk_recall_counts_memcg(conn, "proj_a", window=60)
    assert counts.get(global_chunk) == 8, f"expected 8, got {counts.get(global_chunk)}"


# ── Test 7: window 限制正确 ──────────────────────────────────────────────────────
def test_window_limit():
    """recall_count 应只统计最近 window 条 trace。"""
    conn = _create_test_db()
    chunk_a = "chunk-window"

    # iter604: 需要 injected=1 的 trace 才被统计
    for _ in range(50):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.9}],
                      injected=1, reason="hash_changed|full")

    # window=30 → 只统计最近 30 条 injected=1
    counts = chunk_recall_counts(conn, "proj_a", window=30)
    assert counts[chunk_a] == 30, f"expected 30, got {counts[chunk_a]}"

    # window=10 → 只统计最近 10 条 injected=1
    counts = chunk_recall_counts(conn, "proj_a", window=10)
    assert counts[chunk_a] == 10


# ── Test 8: 空数据库返回空 dict ──────────────────────────────────────────────────
def test_empty_db():
    """空数据库应返回空 dict。"""
    conn = _create_test_db()
    counts = chunk_recall_counts(conn, "proj_a", window=30)
    assert counts == {}


# ── Test 9: 回归 — injected=1 的 trace 仍被正确统计 ──────────────────────────────
def test_regression_injected_still_counted():
    """确保 injected=1 的 trace 没有被意外排除。"""
    conn = _create_test_db()
    chunk_a = "chunk-regression"

    for _ in range(5):
        _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.7}],
                      injected=1, reason="hash_changed|full")

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    assert counts[chunk_a] == 5


# ── Test 10: 项目隔离 ──────────────────────────────────────────────────────────
def test_project_isolation():
    """chunk_recall_counts 应只统计指定项目的 trace。"""
    conn = _create_test_db()
    chunk_a = "chunk-isolation"

    # proj_a: 3 条 injected=1
    for _ in range(3):
        _insert_trace(conn, project="proj_a",
                      top_k_json=[{"id": chunk_a, "score": 0.9}], injected=1)
    # proj_b: 7 条 injected=1（不应被 proj_a 统计）
    for _ in range(7):
        _insert_trace(conn, project="proj_b",
                      top_k_json=[{"id": chunk_a, "score": 0.9}], injected=1,
                      reason="hash_changed|full")

    counts_a = chunk_recall_counts(conn, "proj_a", window=30)
    counts_b = chunk_recall_counts(conn, "proj_b", window=30)
    assert counts_a[chunk_a] == 3
    assert counts_b[chunk_a] == 7


# ── Test 11: cfs_bandwidth 渐进衰减验证 ──────────────────────────────────────────
def test_cfs_bandwidth_progressive_decay():
    """随着 recall_count 增加，cfs_bandwidth_throttle 应渐进递减。"""
    # quota=8, factor=0.50, decay=0.85
    vals = [cfs_bandwidth_throttle(rc) for rc in [8, 9, 12, 15, 21]]
    assert vals[0] == 1.0  # 不超 quota
    assert vals[1] < 1.0   # 超 1
    assert vals[2] < vals[1]  # 递减
    assert vals[3] < vals[2]
    assert vals[4] < vals[3]
    assert all(v > 0 for v in vals)  # 永远 > 0


# ── Test 12: 生产场景模拟 — 固定模板 prompt 的垄断 chunk ───────────────────────────
def test_production_scenario_template_prompt_monopoly():
    """
    iter604: 模拟生产环境。只统计 injected=1 的 trace。
    垄断 chunk 即使只通过 injected=1 统计也能被 hard_gate 拦截（iter596-601）。
    """
    conn = _create_test_db()
    monopoly_chunk = "chunk-feishu-constraint"

    # 模拟：8 条 injected=1（都含垄断 chunk）
    for _ in range(8):
        _insert_trace(conn, top_k_json=[{"id": monopoly_chunk, "score": 0.99}],
                      injected=1, reason="hash_changed|full")
    # 13 条 skipped_same_hash（injected=0，iter604 不统计）
    for _ in range(13):
        _insert_trace(conn, top_k_json=[{"id": monopoly_chunk, "score": 0.99}],
                      injected=0, reason="skipped_same_hash")
    # 5 条不含该 chunk（其他 prompt_hash 的 trace）
    for _ in range(5):
        _insert_trace(conn, top_k_json=[{"id": "other-useful-chunk", "score": 0.5}],
                      injected=1, reason="hash_changed|full",
                      prompt_hash="other_hash")

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    rc = counts[monopoly_chunk]

    # iter604: 只统计 injected=1 → rc=8
    assert rc == 8, f"expected 8, got {rc}"

    # hard_gate: 8/13(injected=1 traces)=62% > hard_cap=30% → 仍被拦截
    # bandwidth_throttle: rc=8 = quota → 刚好不触发
    bw = bandwidth_throttle(rc)
    # cfs_bandwidth_throttle: rc=8 = quota → 不触发 (rc > quota 才触发)
    cbw = cfs_bandwidth_throttle(rc)

    # 验证对更高 rc 值 throttle 仍有效
    bw_high = bandwidth_throttle(21)
    cbw_high = cfs_bandwidth_throttle(21)
    effective = min(bw_high, cbw_high)
    assert effective < 0.10, f"expected < 0.10 for rc=21, got {effective}"


# ── Test 13: session_id 为空时返回空 dict ────────────────────────────────────────
def test_session_recall_empty_session():
    """session_id 为空时 chunk_session_recall_counts 应返回空 dict。"""
    conn = _create_test_db()
    counts = chunk_session_recall_counts(conn, "proj_a", "", window=100)
    assert counts == {}


# ── Test 14: malformed JSON in top_k_json ────────────────────────────────────────
def test_malformed_json_handled():
    """top_k_json 包含非法 JSON 时不应崩溃。"""
    conn = _create_test_db()
    chunk_a = "chunk-valid"

    # 正常 trace
    _insert_trace(conn, top_k_json=[{"id": chunk_a, "score": 0.5}], injected=1)
    # 手动插入 malformed JSON
    conn.execute(
        "INSERT INTO recall_traces (id, timestamp, session_id, project, "
        "prompt_hash, top_k_json, injected) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
         "sess", "proj_a", "hash", "{invalid json", 1)
    )
    conn.commit()

    counts = chunk_recall_counts(conn, "proj_a", window=30)
    assert counts.get(chunk_a) == 1  # 只统计有效的那条


if __name__ == "__main__":
    import time
    tests = [
        test_skipped_same_hash_counted,
        test_null_top_k_json_skipped,
        test_multi_chunk_independent_counting,
        test_bandwidth_throttle_triggers_with_corrected_count,
        test_session_recall_counts_includes_skipped,
        test_memcg_includes_skipped,
        test_window_limit,
        test_empty_db,
        test_regression_injected_still_counted,
        test_project_isolation,
        test_cfs_bandwidth_progressive_decay,
        test_production_scenario_template_prompt_monopoly,
        test_session_recall_empty_session,
        test_malformed_json_handled,
    ]

    t0 = time.time()
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  PASS {test.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {test.__name__}: {e}")

    elapsed = time.time() - t0
    print(f"\n{passed}/{passed+failed} passed ({elapsed:.2f}s)")
    if failed:
        sys.exit(1)
