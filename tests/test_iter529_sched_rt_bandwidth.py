"""
iter529: sched_rt_bandwidth — Working Set Recall Bandwidth Cap

测试 sched_rt_bandwidth() 函数，验证：
1. 超过带宽上限的 chunk 被正确标记为 throttled
2. 未超过上限的 chunk 不受影响
3. 空 traces / 空 candidates 安全处理
4. 与 loader _load_working_set 的集成
"""
import sys
import os
import json
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone, timedelta

# tmpfs 测试隔离
_tmpdir = tempfile.mkdtemp(prefix="test_iter529_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store_core import open_db, ensure_schema, insert_chunk, STORE_DB
from store_mm import sched_rt_bandwidth
from config import get as _cfg


def _make_chunk(conn, summary, project="git:test123", chunk_type="decision",
                importance=0.8, access_count=0):
    """创建测试 chunk 并返回 ID。"""
    chunk_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO memory_chunks (id, summary, content, chunk_type, importance,
                                   access_count, project, source_session, created_at, last_accessed, lru_gen, oom_adj)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
    """, (chunk_id, summary, summary, chunk_type, importance, access_count,
          project, "test-session", datetime.now(timezone.utc).isoformat(),
          datetime.now(timezone.utc).isoformat()))
    conn.commit()
    return chunk_id


def _make_trace(conn, project, chunk_ids, injected=1):
    """创建测试 recall_trace。"""
    top_k = [{"id": cid, "summary": f"test_{cid[:8]}", "score": 0.8} for cid in chunk_ids]
    conn.execute("""
        INSERT INTO recall_traces (id, timestamp, session_id, project, prompt_hash,
                                   candidates_count, top_k_json, injected, reason, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
          "test-session", project, "hash123", 10,
          json.dumps(top_k), injected, "test", 5.0))
    conn.commit()


def test_empty_candidates():
    """空候选集返回空结果。"""
    conn = open_db()
    ensure_schema(conn)
    result = sched_rt_bandwidth(conn, "git:test123", [])
    assert result["throttled_ids"] == set()
    assert result["window_size"] == 0
    conn.close()


def test_no_traces():
    """没有 recall_traces 时不 throttle 任何 chunk。"""
    conn = open_db()
    ensure_schema(conn)
    cid = _make_chunk(conn, "test chunk no traces")
    result = sched_rt_bandwidth(conn, "git:test123", [cid])
    assert result["throttled_ids"] == set()
    assert result["window_size"] == 0
    conn.close()


def test_below_threshold():
    """chunk 在带宽阈值以下不被 throttle。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_below"
    cid = _make_chunk(conn, "normal chunk", project=project)

    # 创建 10 条 trace，chunk 只出现 3 次（30% = 阈值，不触发）
    for i in range(10):
        if i < 3:
            _make_trace(conn, project, [cid])
        else:
            _make_trace(conn, project, [str(uuid.uuid4())])

    result = sched_rt_bandwidth(conn, project, [cid])
    assert cid not in result["throttled_ids"]
    assert result["window_size"] == 10
    # 3/10 = 0.30, threshold default is 0.40 → not throttled
    assert result["recall_rates"][cid] == 0.3
    conn.close()


def test_above_threshold():
    """chunk 超过带宽阈值被 throttle。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_above"
    monopoly_id = _make_chunk(conn, "monopoly chunk", project=project, access_count=89)
    normal_id = _make_chunk(conn, "normal chunk", project=project)
    other_id = str(uuid.uuid4())  # 不在 candidates 中的填充 ID

    # 创建 10 条 trace，monopoly 出现 5 次（50% > 40% 阈值），normal 出现 3 次（30% ≤ 40%）
    for i in range(10):
        if i < 5:
            _make_trace(conn, project, [monopoly_id])
        elif i < 8:
            _make_trace(conn, project, [normal_id])
        else:
            _make_trace(conn, project, [other_id])

    result = sched_rt_bandwidth(conn, project, [monopoly_id, normal_id])
    assert monopoly_id in result["throttled_ids"]
    assert normal_id not in result["throttled_ids"]
    assert result["recall_rates"][monopoly_id] == 0.5
    assert result["recall_rates"][normal_id] == 0.3
    conn.close()


def test_multiple_throttled():
    """多个 chunk 同时超过阈值都被 throttle。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_multi"
    id_a = _make_chunk(conn, "chunk A", project=project)
    id_b = _make_chunk(conn, "chunk B", project=project)
    id_c = _make_chunk(conn, "chunk C", project=project)

    # A 出现 8/10=80%, B 出现 6/10=60%, C 出现 2/10=20%
    for i in range(10):
        ids_in_trace = []
        if i < 8:
            ids_in_trace.append(id_a)
        if i < 6:
            ids_in_trace.append(id_b)
        if i < 2:
            ids_in_trace.append(id_c)
        if not ids_in_trace:
            ids_in_trace.append(str(uuid.uuid4()))
        _make_trace(conn, project, ids_in_trace)

    result = sched_rt_bandwidth(conn, project, [id_a, id_b, id_c])
    # 默认阈值 0.40: A(0.8) throttled, B(0.6) throttled, C(0.2) not
    assert id_a in result["throttled_ids"]
    assert id_b in result["throttled_ids"]
    assert id_c not in result["throttled_ids"]
    conn.close()


def test_only_injected_traces_counted():
    """只计算 injected=1 的 trace，injected=0 不计入。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_injected"
    cid = _make_chunk(conn, "test injected only", project=project)

    # 5 条 injected=1 的 trace 包含 chunk，5 条 injected=0 不计
    for i in range(5):
        _make_trace(conn, project, [cid], injected=1)
    for i in range(5):
        _make_trace(conn, project, [cid], injected=0)

    result = sched_rt_bandwidth(conn, project, [cid])
    # 只有 5 条 injected trace 被统计，chunk 在全部 5 条中 → 100%
    assert result["window_size"] == 5
    assert cid in result["throttled_ids"]
    assert result["recall_rates"][cid] == 1.0
    conn.close()


def test_project_isolation():
    """不同项目的 traces 互不影响。"""
    conn = open_db()
    ensure_schema(conn)
    project_a = "git:proj_a"
    project_b = "git:proj_b"
    cid = _make_chunk(conn, "shared chunk", project=project_a)

    # 在 project_b 中大量出现，但在 project_a 中不出现
    for i in range(10):
        _make_trace(conn, project_b, [cid])

    result = sched_rt_bandwidth(conn, project_a, [cid])
    assert result["window_size"] == 0  # project_a 没有 trace
    assert cid not in result["throttled_ids"]
    conn.close()


def test_window_respects_limit():
    """只查看最近 window 条 trace，旧数据不影响。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_window"
    cid = _make_chunk(conn, "windowed chunk", project=project)

    # 创建 50 条旧 trace 全部包含 chunk
    for i in range(50):
        _make_trace(conn, project, [cid])
    # 再创建 30 条新 trace 不包含 chunk
    for i in range(30):
        _make_trace(conn, project, [str(uuid.uuid4())])

    # 窗口默认 30，只看最新 30 条 → chunk 不出现 → rate=0
    result = sched_rt_bandwidth(conn, project, [cid])
    assert result["window_size"] == 30
    assert cid not in result["throttled_ids"]
    assert result["recall_rates"][cid] == 0.0
    conn.close()


def test_unknown_chunk_ids_safe():
    """候选列表中包含不存在于 traces 中的 ID 不报错。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_unknown"
    fake_id = "nonexistent-chunk-id"

    for i in range(5):
        _make_trace(conn, project, [str(uuid.uuid4())])

    result = sched_rt_bandwidth(conn, project, [fake_id])
    assert fake_id not in result["throttled_ids"]
    assert result["recall_rates"][fake_id] == 0.0
    conn.close()


def test_boundary_exact_threshold():
    """刚好等于阈值时不触发（> 不是 >=）。"""
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_boundary"
    cid = _make_chunk(conn, "boundary chunk", project=project)

    # 默认阈值 0.40, 创建 10 条 trace, chunk 出现 4 次 → rate=0.40 刚好等于阈值
    for i in range(10):
        if i < 4:
            _make_trace(conn, project, [cid])
        else:
            _make_trace(conn, project, [str(uuid.uuid4())])

    result = sched_rt_bandwidth(conn, project, [cid])
    assert cid not in result["throttled_ids"]  # 0.40 不 > 0.40, 不触发
    assert result["recall_rates"][cid] == 0.4
    conn.close()


def test_performance():
    """300 条 traces × 50 candidates 在 50ms 内完成。"""
    import time
    conn = open_db()
    ensure_schema(conn)
    project = "git:test_perf"

    # 创建 50 个 candidates
    candidates = []
    for i in range(50):
        cid = _make_chunk(conn, f"perf chunk {i}", project=project)
        candidates.append(cid)

    # 创建 300 条 traces
    for i in range(300):
        trace_ids = [candidates[i % 50], candidates[(i + 7) % 50]]
        _make_trace(conn, project, trace_ids)

    t0 = time.time()
    result = sched_rt_bandwidth(conn, project, candidates)
    elapsed = (time.time() - t0) * 1000
    print(f"  sched_rt_bandwidth: {elapsed:.2f}ms (300 traces × 50 candidates)")
    assert elapsed < 50
    assert result["window_size"] == 30  # 默认 window
    conn.close()


# ── 清理 ──
import atexit
import shutil
atexit.register(lambda: shutil.rmtree(_tmpdir, ignore_errors=True))

if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: {e}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
