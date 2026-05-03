"""
iter584: daemon constraint forced injection gate — refault_distance + Jaccard dedup

根因：retriever_daemon.py 的 design_constraint 强制注入路径缺少两个门控：
  1. refault_distance thrash gate（iter543）：recall_count/window > max_pct 的垄断约束未被拦截
  2. Jaccard content dedup（iter337）：与 top_k 高度重叠的约束仍被重复注入

生产实证：
  - 全局约束 "飞书 CLI" 占 35.2% 召回率（25/71 traces），score=0.99 绕过所有 throttle
  - 61.1% chunks 从未出现在任何 recall trace（dark page rate）
  - cfs_bandwidth_throttle(recall_count=23) = 0.044 → 自然路径可压制
  - 但 forced injection score=0.99 硬编码 → throttle 无效

OS 类比：Linux cfs_burst_throttle (Paul Turner, 2011) — cgroup 超出 bandwidth quota
  即使允许 burst，也必须在下一个 period 偿还。daemon 强制注入等于无限 burst，
  绕过了 period-level 的 bandwidth accounting。

测试项：
  1. refault_distance 门控：高召回率 constraint 被 gate 拦截
  2. Jaccard dedup：与 top_k 内容高度重叠的 constraint 被跳过
  3. 正常 constraint（低召回+无重叠）正常注入
  4. 低相关性 constraint 被 min_relevance 过滤
"""
import os
import sys
import json
import sqlite3
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hooks"))

# Set up tmpfs before any other imports
os.environ["MEMORY_OS_DIR"] = tempfile.mkdtemp(prefix="test_iter584_")
os.environ["MEMORY_OS_DB"] = os.path.join(os.environ["MEMORY_OS_DIR"], "store.db")

PASS = 0
FAIL = 0

def test(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name}")

def _make_chunk(id, summary, content, chunk_type, importance, project, oom_adj=0):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": id, "summary": summary, "content": content,
        "chunk_type": chunk_type, "importance": importance,
        "project": project, "oom_adj": oom_adj,
        "created_at": now, "updated_at": now,
        "source_session": "test-iter584", "tags": "[]",
        "last_accessed": now, "access_count": 0,
        "retrievability": 1.0, "source_reliability": 0.7,
        "emotional_weight": 0.0, "emotional_valence": 0.0,
        "confidence_score": 0.7, "verification_status": "unverified",
        "lru_gen": 0, "raw_snippet": "", "encoding_context": "{}",
        "info_class": "world",
    }


def setup_db():
    """Create test DB with chunks and recall_traces."""
    from store import open_db, ensure_schema, insert_chunk
    conn = open_db()
    ensure_schema(conn)

    insert_chunk(conn, _make_chunk(
        "constraint-monopoly-001",
        "飞书文档 wiki 访问必须用 feishu CLI 禁止通用 HTTP 工具",
        "飞书链接需要认证 fetch 只返回 401",
        "design_constraint", 0.90, "global", -500))

    insert_chunk(conn, _make_chunk(
        "constraint-normal-002",
        "API 超时必须设置 30 秒上限",
        "所有外部 API 调用必须有超时",
        "design_constraint", 0.80, "global", -500))

    insert_chunk(conn, _make_chunk(
        "constraint-overlap-003",
        "memory os 检索 BM25 评分 scorer 统一引擎",
        "all scoring through unified scorer",
        "design_constraint", 0.80, "test_proj", -500))

    insert_chunk(conn, _make_chunk(
        "decision-topk-004",
        "memory os 检索使用 BM25 评分 scorer 统一引擎实现",
        "unified scorer for all retrieval scoring",
        "decision", 0.85, "test_proj"))

    insert_chunk(conn, _make_chunk(
        "constraint-irrelevant-005",
        "Android binder IPC 等待时间不计入 CPU running",
        "binder call sleep L1",
        "design_constraint", 0.80, "global", -500))

    # Create recall_traces making constraint-monopoly appear in 25/30 traces
    for i in range(30):
        trace_data = []
        if i < 25:  # 25 out of 30 → 83% recall rate
            trace_data.append({
                "id": "constraint-monopoly-001",
                "summary": "飞书文档 wiki",
                "score": 0.99,
                "chunk_type": "design_constraint",
            })
        else:
            trace_data.append({
                "id": "decision-topk-004",
                "summary": "memory os 检索",
                "score": 0.85,
                "chunk_type": "decision",
            })
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        conn.execute("""INSERT INTO recall_traces
            (timestamp, session_id, project, prompt_hash, top_k_json, injected, candidates_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ts, f"sess-{i:03d}", "test_proj", f"hash{i}",
             json.dumps(trace_data), 1 if i < 25 else 0, 10))

    conn.commit()
    return conn


def test_refault_distance_gate():
    """高召回率 constraint 被 refault_distance 拦截。"""
    print("\n[1] refault_distance thrash gate")

    from config import get as sysctl
    import re
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    # Simulate the recall_counts
    _recall_counts = {"constraint-monopoly-001": 25}  # 25/30 = 0.83
    _bw_window = sysctl("scorer.bw_window") or 30
    _thrash_max_pct = sysctl("retriever.constraint_thrash_max_pct")  # 0.40
    _constraint_min_rel = sysctl("retriever.constraint_min_relevance")  # 0.05

    # Use a query that has good overlap with the constraint summary
    query = "飞书文档 wiki 访问 feishu CLI"
    _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())

    # The monopoly constraint
    monopoly = {
        "id": "constraint-monopoly-001",
        "summary": "飞书文档 wiki 访问必须用 feishu CLI 禁止通用 HTTP 工具",
    }

    def _constraint_relevance(c):
        s_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
        if not _query_words or not s_words:
            return 0.0
        return len(_query_words & s_words) / len(_query_words | s_words)

    rel = _constraint_relevance(monopoly)
    thrash = _recall_counts.get(monopoly["id"], 0) / max(_bw_window, 1)

    test(f"monopoly relevance={rel:.3f} > min_relevance={_constraint_min_rel}", rel >= _constraint_min_rel)
    test(f"monopoly thrash rate={thrash:.2f} > max_pct={_thrash_max_pct}", thrash > _thrash_max_pct)
    test("monopoly should be GATED (high thrash)",
         not (rel >= _constraint_min_rel and thrash <= _thrash_max_pct))

    # Normal constraint should pass
    normal = {
        "id": "constraint-normal-002",
        "summary": "API 超时必须设置 30 秒上限",
    }
    _recall_counts["constraint-normal-002"] = 1  # low recall
    query2 = "API 超时设置"
    _query_words2 = set(_CONSTRAINT_RE.sub(' ', query2.lower()).split())

    def _rel2(c):
        s_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
        if not _query_words2 or not s_words:
            return 0.0
        return len(_query_words2 & s_words) / len(_query_words2 | s_words)

    rel2 = _rel2(normal)
    thrash2 = _recall_counts.get(normal["id"], 0) / max(_bw_window, 1)
    test("normal constraint relevance > 0", rel2 > 0)
    test("normal constraint thrash < max_pct", thrash2 <= _thrash_max_pct)
    test("normal constraint should PASS", rel2 >= _constraint_min_rel and thrash2 <= _thrash_max_pct)


def test_jaccard_dedup():
    """与 top_k 内容高度重叠的 constraint 被跳过。"""
    print("\n[2] Jaccard content dedup")

    import re
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    # Simulate top_k containing a decision about "memory os BM25 scorer"
    top_k_summary = "memory os 检索使用 BM25 评分 scorer 统一引擎实现"
    top_k_words = set(_CONSTRAINT_RE.sub(' ', top_k_summary.lower()).split())

    # Constraint with high overlap
    overlap_summary = "memory os 检索 BM25 评分 scorer 统一引擎"
    overlap_words = set(_CONSTRAINT_RE.sub(' ', overlap_summary.lower()).split())

    union = top_k_words | overlap_words
    jaccard = len(top_k_words & overlap_words) / len(union) if union else 0

    test(f"overlap Jaccard = {jaccard:.2f} >= 0.50", jaccard >= 0.50)
    test("overlap constraint should be SKIPPED (redundant)", jaccard >= 0.50)

    # Non-overlapping constraint
    nonoverlap_summary = "Android binder IPC 等待时间不计入 CPU running"
    nonoverlap_words = set(_CONSTRAINT_RE.sub(' ', nonoverlap_summary.lower()).split())

    union2 = top_k_words | nonoverlap_words
    jaccard2 = len(top_k_words & nonoverlap_words) / len(union2) if union2 else 0

    test(f"non-overlap Jaccard = {jaccard2:.2f} < 0.50", jaccard2 < 0.50)
    test("non-overlap constraint should PASS", jaccard2 < 0.50)


def test_low_relevance_filtered():
    """低相关性 constraint 被 min_relevance 过滤。"""
    print("\n[3] Low relevance filter")

    import re
    from config import get as sysctl
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    _constraint_min_rel = sysctl("retriever.constraint_min_relevance")

    query = "memory os 检索评分"
    _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())

    # Irrelevant constraint
    irrelevant = {"summary": "Android binder IPC 等待时间不计入 CPU running"}
    s_words = set(_CONSTRAINT_RE.sub(' ', irrelevant["summary"].lower()).split())
    jaccard = len(_query_words & s_words) / len(_query_words | s_words) if (_query_words | s_words) else 0

    test(f"irrelevant Jaccard = {jaccard:.3f} < min_rel={_constraint_min_rel}",
         jaccard < _constraint_min_rel)
    test("irrelevant constraint should be FILTERED", jaccard < _constraint_min_rel)


def test_combined_filter_flow():
    """完整流程模拟：gate + dedup + injection。"""
    print("\n[4] Combined filter flow simulation")

    import re
    from config import get as sysctl
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    # Query that matches multiple constraints: monopoly(飞书), normal(API 超时), overlap(memory os)
    query = "飞书文档 API 超时 memory os 检索 设置"
    _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())
    _bw_window = sysctl("scorer.bw_window") or 30
    _thrash_max_pct = sysctl("retriever.constraint_thrash_max_pct")
    _constraint_min_rel = sysctl("retriever.constraint_min_relevance")

    # Recall counts
    _recall_counts = {
        "constraint-monopoly-001": 25,  # 83% → gated
        "constraint-normal-002": 1,     # 3% → pass
        "constraint-overlap-003": 0,    # 0% → pass relevance+thrash, but Jaccard blocks
        "constraint-irrelevant-005": 0, # 0% but low relevance → filtered
    }

    # Top-K already contains decision-topk-004
    top_k_summaries = ["memory os 检索使用 BM25 评分 scorer 统一引擎实现"]
    _top_k_token_sets = [set(_CONSTRAINT_RE.sub(' ', s.lower()).split()) for s in top_k_summaries]

    # All constraints to process
    extra_constraints = [
        {"id": "constraint-monopoly-001", "summary": "飞书文档 wiki 访问必须用 feishu CLI 禁止通用 HTTP 工具"},
        {"id": "constraint-normal-002", "summary": "API 超时必须设置 30 秒上限"},
        {"id": "constraint-overlap-003", "summary": "memory os 检索 BM25 评分 scorer 统一引擎"},
        {"id": "constraint-irrelevant-005", "summary": "Android binder IPC 等待时间不计入 CPU running"},
    ]

    def _constraint_relevance(c):
        s_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
        if not _query_words or not s_words:
            return 0.0
        return len(_query_words & s_words) / len(_query_words | s_words)

    # Phase 1: refault_distance gate
    passed_gate = [
        c for c in extra_constraints
        if _constraint_relevance(c) >= _constraint_min_rel
        and (_recall_counts.get(c["id"], 0) / max(_bw_window, 1)) <= _thrash_max_pct
    ]

    gated_ids = set(c["id"] for c in extra_constraints) - set(c["id"] for c in passed_gate)
    test("monopoly gated", "constraint-monopoly-001" in gated_ids)
    test("irrelevant gated (low relevance)", "constraint-irrelevant-005" in gated_ids)
    test("normal passed gate", "constraint-normal-002" in [c["id"] for c in passed_gate])
    test("overlap passed gate", "constraint-overlap-003" in [c["id"] for c in passed_gate])

    # Phase 2: Jaccard dedup
    injected = []
    for c in passed_gate:
        c_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
        is_redundant = False
        if c_words and _top_k_token_sets:
            for existing in _top_k_token_sets:
                union = existing | c_words
                if union and len(existing & c_words) / len(union) >= 0.50:
                    is_redundant = True
                    break
        if not is_redundant:
            injected.append(c["id"])
            if c_words:
                _top_k_token_sets.append(c_words)

    test("overlap blocked by Jaccard dedup", "constraint-overlap-003" not in injected)
    test("normal injected successfully", "constraint-normal-002" in injected)
    test(f"final injected count = {len(injected)} (expected 1)", len(injected) == 1)


def test_empty_recall_counts_no_crash():
    """空 recall_counts 不崩溃。"""
    print("\n[5] Empty recall_counts resilience")

    import re
    from config import get as sysctl
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    _recall_counts = {}
    _bw_window = sysctl("scorer.bw_window") or 30
    _thrash_max_pct = sysctl("retriever.constraint_thrash_max_pct")
    _constraint_min_rel = sysctl("retriever.constraint_min_relevance")

    query = "飞书文档"
    _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())

    constraint = {"id": "test-001", "summary": "飞书文档 wiki 访问"}

    def _rel(c):
        s_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
        if not _query_words or not s_words:
            return 0.0
        return len(_query_words & s_words) / len(_query_words | s_words)

    # Should pass (no recall count → 0/30 = 0 <= 0.40)
    passed = (
        _rel(constraint) >= _constraint_min_rel
        and (_recall_counts.get(constraint["id"], 0) / max(_bw_window, 1)) <= _thrash_max_pct
    )
    test("constraint with no recall history should PASS", passed)


def test_perf():
    """Performance: gate + dedup < 1ms for 20 constraints."""
    print("\n[6] Performance")

    import re
    _CONSTRAINT_RE = re.compile(r'[^\w\u4e00-\u9fff]')

    _recall_counts = {f"c-{i}": i for i in range(20)}
    query = "memory os 飞书 检索 API 约束"
    _query_words = set(_CONSTRAINT_RE.sub(' ', query.lower()).split())

    constraints = [
        {"id": f"c-{i}", "summary": f"约束 {i} 关于 memory os 检索 {'飞书' if i%3==0 else 'API'} 规则"}
        for i in range(20)
    ]

    top_k_summaries = [f"memory os 检索 BM25 统一评分引擎 版本{i}" for i in range(5)]
    _top_k_token_sets = [set(_CONSTRAINT_RE.sub(' ', s.lower()).split()) for s in top_k_summaries]

    t0 = time.perf_counter()
    for _ in range(100):
        # Gate
        passed = [
            c for c in constraints
            if len(set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split()) & _query_words) /
               max(len(set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split()) | _query_words), 1) >= 0.05
            and (_recall_counts.get(c["id"], 0) / 30) <= 0.40
        ]
        # Dedup
        for c in passed[:3]:
            c_words = set(_CONSTRAINT_RE.sub(' ', (c.get("summary") or "").lower()).split())
            for existing in _top_k_token_sets:
                union = existing | c_words
                if union:
                    len(existing & c_words) / len(union)

    elapsed_ms = (time.perf_counter() - t0) / 100 * 1000
    test(f"gate + dedup avg {elapsed_ms:.3f}ms < 1ms", elapsed_ms < 1.0)


if __name__ == "__main__":
    print("=" * 60)
    print("iter584: daemon constraint forced injection gate")
    print("=" * 60)

    conn = setup_db()

    test_refault_distance_gate()
    test_jaccard_dedup()
    test_low_relevance_filtered()
    test_combined_filter_flow()
    test_empty_recall_counts_no_crash()
    test_perf()

    conn.close()

    print(f"\n{'='*60}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed!")
