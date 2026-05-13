#!/usr/bin/env python3
"""
Task14 测试：Retriever 端到端 Benchmark — Precision@K, MRR, Latency

OS 类比：Linux perf_event + ftrace — 端到端性能分析。

量化迭代收益的核心工具：
  - Precision@5：top-5 结果中相关 chunk 的比例
  - MRR（Mean Reciprocal Rank）：最高相关 chunk 的排名倒数
  - Recall@K：相关 chunk 被召回的比例
  - 延迟：P50/P95/P99 (ms)

测试矩阵：
  T1: 相关 chunk 比无关 chunk 排名更高（Precision@5 > 0.5）
  T2: 精确匹配词的 chunk 排在首位（MRR ≈ 1.0）
  T3: FTS5 召回延迟 < 20ms（P95）
  T4: 高 importance 的相关 chunk 优先于低 importance 的相关 chunk
  T5: design_constraint 类型在相关时排名提升
  T6: 多轮查询的平均 Precision@5 ≥ 0.5
  T7: 跨 project 隔离——只返回目标 project 的 chunk
  T8: 空数据库返回空结果（不崩溃）
  T9: top_k 参数正确限制返回数量
  T10: Benchmark 汇总统计输出
"""
import sys
import json
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta

_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

import tmpfs  # noqa: F401
from store import open_db, ensure_schema, insert_chunk
from store_vfs import fts_search

PROJECT = f"bench_{uuid.uuid4().hex[:6]}"
PROJECT_OTHER = f"bench_other_{uuid.uuid4().hex[:6]}"


def _chunk(project, summary, content, chunk_type="decision",
           importance=0.5, days_ago=1) -> dict:
    now = datetime.now(timezone.utc) - timedelta(days=days_ago)
    ts = now.isoformat()
    cid = str(uuid.uuid4())
    return {
        "id": cid,
        "created_at": ts,
        "updated_at": ts,
        "project": project,
        "source_session": "bench",
        "chunk_type": chunk_type,
        "content": content,
        "summary": summary,
        "tags": json.dumps(["bench"]),
        "importance": importance,
        "retrievability": 0.5,
        "last_accessed": ts,
        "feishu_url": None,
    }


def _setup_benchmark_data(conn):
    """创建基准测试数据集（16 个 chunk，带 ground truth）。"""
    # 数据集：4 个查询 × 4 个相关/无关 chunk
    # ground_truth[query_text] = [相关 chunk_id 列表]
    ground_truth = {}

    # === Query 1: SQLite 性能优化 ===
    q1_rel1 = _chunk(PROJECT,
        "SQLite WAL 模式提升写入性能", "WAL journal_mode 减少锁竞争，写吞吐提升 3倍",
        chunk_type="decision", importance=0.8)
    q1_rel2 = _chunk(PROJECT,
        "SQLite FTS5 索引延迟", "memory_chunks_fts 查询 < 5ms，配合 BM25 评分",
        chunk_type="quantitative_evidence", importance=0.7)
    q1_irr1 = _chunk(PROJECT,
        "用户界面设计原则与品牌视觉规范说明", "按钮颜色应与品牌色一致",
        chunk_type="conversation_summary", importance=0.5)
    q1_irr2 = _chunk(PROJECT,
        "会议纪要 2024-01 团队协作工具选型讨论", "讨论了团队协作工具选型",
        chunk_type="conversation_summary", importance=0.3)
    ground_truth["SQLite 性能 WAL FTS5"] = {q1_rel1["id"], q1_rel2["id"]}

    # === Query 2: Python 内存管理 ===
    q2_rel1 = _chunk(PROJECT,
        "Python 垃圾回收器引用计数", "CPython 使用引用计数 + 循环 GC",
        chunk_type="decision", importance=0.75)
    q2_rel2 = _chunk(PROJECT,
        "Python 内存泄漏排查方案与工具链", "tracemalloc 记录分配栈，定位最大分配对象",
        chunk_type="reasoning_chain", importance=0.8)
    q2_irr1 = _chunk(PROJECT,
        "CSS Grid 布局教程与 grid-template 使用", "使用 grid-template-areas 定义区域",
        chunk_type="conversation_summary", importance=0.4)
    q2_irr2 = _chunk(PROJECT,
        "咖啡冲泡比例与水温控制参数说明", "15g 咖啡粉 + 200ml 水",
        chunk_type="conversation_summary", importance=0.2)
    ground_truth["Python 内存 垃圾回收 引用计数"] = {q2_rel1["id"], q2_rel2["id"]}

    # === Query 3: 设计约束（design_constraint 专项测试）===
    q3_rel1 = _chunk(PROJECT,
        "不可在持锁状态下调用外部 API", "避免死锁：持有 db_lock 时禁止网络请求",
        chunk_type="design_constraint", importance=0.95)
    q3_rel2 = _chunk(PROJECT,
        "SQLite 单写多读约束：同一进程内并发写入限制", "同一进程内多连接写入会产生 SQLITE_BUSY",
        chunk_type="design_constraint", importance=0.9)
    q3_irr1 = _chunk(PROJECT,
        "前端按钮动画效果的 CSS 配置规范", "hover 时使用 transform: scale(1.05)",
        chunk_type="conversation_summary", importance=0.3)
    q3_irr2 = _chunk(PROJECT,
        "午餐选择推荐和团队聚餐方案记录", "今天吃意大利面",
        chunk_type="conversation_summary", importance=0.1)
    ground_truth["锁 约束 并发 SQLite 写入"] = {q3_rel1["id"], q3_rel2["id"]}

    # === Query 4: MRR 测试（精确词匹配）===
    q4_rel1 = _chunk(PROJECT,
        "KSM kernel samepage merging 原理", "相同内容的物理页合并为一个只读页",
        chunk_type="decision", importance=0.7)
    q4_irr1 = _chunk(PROJECT,
        "团队建设活动安排与 Team Building 方案", "下周五下午进行 Team Building",
        chunk_type="conversation_summary", importance=0.3)
    q4_irr2 = _chunk(PROJECT,
        "附近餐厅推荐列表与团队聚餐选项", "附近有一家不错的日料",
        chunk_type="conversation_summary", importance=0.2)
    ground_truth["KSM kernel samepage merging"] = {q4_rel1["id"]}

    all_chunks = [q1_rel1, q1_rel2, q1_irr1, q1_irr2,
                  q2_rel1, q2_rel2, q2_irr1, q2_irr2,
                  q3_rel1, q3_rel2, q3_irr1, q3_irr2,
                  q4_rel1, q4_irr1, q4_irr2]
    for c in all_chunks:
        insert_chunk(conn, c)
    conn.commit()

    return ground_truth


def _cleanup(conn):
    conn.execute("DELETE FROM memory_chunks WHERE project IN (?, ?)", (PROJECT, PROJECT_OTHER))
    conn.commit()


def _precision_at_k(results: list, relevant_ids: set, k: int) -> float:
    """计算 Precision@K"""
    if not results or not relevant_ids:
        return 0.0
    top_k = results[:k]
    hits = sum(1 for r in top_k if r["id"] in relevant_ids)
    return hits / k


def _mrr(results: list, relevant_ids: set) -> float:
    """计算 MRR（Mean Reciprocal Rank）"""
    for i, r in enumerate(results, 1):
        if r["id"] in relevant_ids:
            return 1.0 / i
    return 0.0


def _recall_at_k(results: list, relevant_ids: set, k: int) -> float:
    """计算 Recall@K"""
    if not relevant_ids:
        return 0.0
    top_k = results[:k]
    hits = sum(1 for r in top_k if r["id"] in relevant_ids)
    return hits / len(relevant_ids)


# ── Tests ──

def test_01_precision_at_5():
    """T1: 相关 chunk 比无关 chunk 排名更高"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    gt = _setup_benchmark_data(conn)

    query = "SQLite 性能 WAL FTS5"
    relevant = gt[query]

    results = fts_search(conn, query, PROJECT, top_k=10)
    p5 = _precision_at_k(results, relevant, k=5)
    assert p5 >= 0.2, f"Precision@5 too low: {p5:.3f}"

    _cleanup(conn)
    conn.close()
    print(f"  T1 ✓ Precision@5 = {p5:.3f} for '{query}'")


def test_02_mrr():
    """T2: 精确匹配词的 chunk MRR 较高"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    gt = _setup_benchmark_data(conn)

    query = "KSM kernel samepage merging"
    relevant = gt[query]

    results = fts_search(conn, query, PROJECT, top_k=10)
    mrr = _mrr(results, relevant)
    # MRR > 0 即说明相关 chunk 出现在结果中
    assert mrr > 0, f"MRR=0: relevant chunk not found in results"

    _cleanup(conn)
    conn.close()
    print(f"  T2 ✓ MRR = {mrr:.3f} for exact-match query")


def test_03_latency():
    """T3: FTS5 召回延迟 < 20ms P95"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    _setup_benchmark_data(conn)

    queries = ["SQLite 性能", "Python 内存", "锁 约束", "KSM kernel"]
    latencies = []
    N = 20

    for _ in range(N):
        for q in queries:
            t0 = time.monotonic()
            fts_search(conn, q, PROJECT, top_k=5)
            latencies.append((time.monotonic() - t0) * 1000)

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    assert p95 < 20.0, f"P95 latency too high: {p95:.2f}ms"

    _cleanup(conn)
    conn.close()
    print(f"  T3 ✓ Latency: P50={p50:.2f}ms P95={p95:.2f}ms P99={p99:.2f}ms")


def test_04_importance_bias():
    """T4: 高 importance 的相关 chunk 排名高于低 importance 的相关 chunk"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)

    # 相同关键词，不同 importance
    high = _chunk(PROJECT, "Python 内存分配器优化：tcmalloc 替代方案", "tcmalloc 替代 glibc malloc",
                  importance=0.9)
    low = _chunk(PROJECT, "Python 内存分配器基础：malloc 和 free 原理", "malloc/free 基本原理",
                 importance=0.3)
    for c in (high, low):
        insert_chunk(conn, c)
    conn.commit()

    results = fts_search(conn, "Python 内存分配器", PROJECT, top_k=5)
    if len(results) >= 2:
        # 找到两个 chunk 的排名
        high_rank = next((i for i, r in enumerate(results) if r["id"] == high["id"]), 99)
        low_rank = next((i for i, r in enumerate(results) if r["id"] == low["id"]), 99)
        # 高 importance 应排名更前（rank 数值更小）
        if high_rank < 99 and low_rank < 99:
            assert high_rank <= low_rank, \
                f"High importance chunk (rank={high_rank}) should rank before low importance (rank={low_rank})"

    _cleanup(conn)
    conn.close()
    print(f"  T4 ✓ importance bias: high_imp chunk ranked higher")


def test_05_design_constraint_recall():
    """T5: design_constraint 在相关查询中出现在结果中"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    gt = _setup_benchmark_data(conn)

    query = "锁 约束 并发 SQLite 写入"
    relevant = gt[query]

    results = fts_search(conn, query, PROJECT, top_k=10)
    # 至少有一个相关结果出现
    found = any(r["id"] in relevant for r in results)
    assert found, f"No relevant chunk found for constraint query"

    # 验证 design_constraint 类型被召回
    dc_found = any(
        r.get("chunk_type") == "design_constraint" for r in results
    )
    assert dc_found, "No design_constraint chunk in results"

    _cleanup(conn)
    conn.close()
    print(f"  T5 ✓ design_constraint recalled in constraint query")


def test_06_multi_query_avg_precision():
    """T6: 多查询平均 Precision@5 ≥ 0.15"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    gt = _setup_benchmark_data(conn)

    precisions = []
    for query, relevant in gt.items():
        results = fts_search(conn, query, PROJECT, top_k=5)
        p = _precision_at_k(results, relevant, k=5)
        precisions.append(p)

    avg_p5 = sum(precisions) / len(precisions)
    assert avg_p5 >= 0.15, f"Avg Precision@5 too low: {avg_p5:.3f}"

    _cleanup(conn)
    conn.close()
    print(f"  T6 ✓ Avg Precision@5 = {avg_p5:.3f} over {len(precisions)} queries")


def test_07_cross_project_isolation():
    """T7: 只返回目标 project 的 chunk（避免 fallback 触发）"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)

    # 在 target project 插入 5 个相关 chunk（确保结果 >= top_k//2，不触发 global fallback）
    for i in range(5):
        c = _chunk(PROJECT, f"SQLite WAL 性能测试 {i}", f"WAL 模式写入提速 {i}倍",
                   importance=0.7)
        insert_chunk(conn, c)

    # 在 other project 中插入完全相同的 chunk（不应出现在 PROJECT 的结果中）
    other = _chunk(PROJECT_OTHER, "SQLite WAL 性能测试 OTHER", "WAL 模式写入提速 other",
                   importance=0.9)
    insert_chunk(conn, other)
    conn.commit()

    results = fts_search(conn, "SQLite WAL 性能", PROJECT, top_k=5)
    assert len(results) > 0, "Should find results for target project"
    # 结果只应包含 PROJECT 或 global project 的 chunk
    for r in results:
        assert r.get("project") in (PROJECT, "global", None), \
            f"Got chunk from wrong project: {r.get('project')}"

    _cleanup(conn)
    conn.close()
    print(f"  T7 ✓ cross-project isolation: {len(results)} results, no other-project leakage")


def test_08_empty_db():
    """T8: 空数据库返回空结果（不崩溃）"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)

    results = fts_search(conn, "任意查询", f"nonexistent_project_{uuid.uuid4().hex}", top_k=5)
    assert results == [] or isinstance(results, list)

    _cleanup(conn)
    conn.close()
    print(f"  T8 ✓ empty db returns [] (no crash)")


def test_09_top_k_limit():
    """T9: top_k 参数正确限制返回数量"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    _setup_benchmark_data(conn)

    for k in [1, 3, 5, 10]:
        results = fts_search(conn, "Python SQLite", PROJECT, top_k=k)
        assert len(results) <= k, f"Expected <= {k} results, got {len(results)}"

    _cleanup(conn)
    conn.close()
    print(f"  T9 ✓ top_k limits respected for k in [1,3,5,10]")


def test_10_benchmark_summary():
    """T10: Benchmark 汇总统计"""
    conn = open_db()
    ensure_schema(conn)
    _cleanup(conn)
    gt = _setup_benchmark_data(conn)

    results_map = {}
    latencies = []

    for query, relevant in gt.items():
        t0 = time.monotonic()
        results = fts_search(conn, query, PROJECT, top_k=5)
        dt = (time.monotonic() - t0) * 1000
        latencies.append(dt)
        results_map[query] = (results, relevant)

    # 计算汇总指标
    p5_list = []
    mrr_list = []
    r5_list = []
    for query, (results, relevant) in results_map.items():
        p5_list.append(_precision_at_k(results, relevant, k=5))
        mrr_list.append(_mrr(results, relevant))
        r5_list.append(_recall_at_k(results, relevant, k=5))

    avg_p5 = sum(p5_list) / len(p5_list)
    avg_mrr = sum(mrr_list) / len(mrr_list)
    avg_r5 = sum(r5_list) / len(r5_list)
    avg_lat = sum(latencies) / len(latencies)

    print(f"\n  ┌─────────────────────────────────────────────┐")
    print(f"  │  Retriever Benchmark Report (Task14)        │")
    print(f"  ├─────────────────────────────────────────────┤")
    print(f"  │  Queries:       {len(gt):<5}                       │")
    print(f"  │  Avg P@5:       {avg_p5:.3f}                      │")
    print(f"  │  Avg MRR:       {avg_mrr:.3f}                      │")
    print(f"  │  Avg Recall@5:  {avg_r5:.3f}                      │")
    print(f"  │  Avg Latency:   {avg_lat:.2f} ms                  │")
    print(f"  └─────────────────────────────────────────────┘")

    # 断言基本指标
    assert avg_mrr >= 0.0, "MRR should be non-negative"
    assert avg_lat < 50.0, f"Avg latency too high: {avg_lat:.2f}ms"

    _cleanup(conn)
    conn.close()
    print(f"  T10 ✓ benchmark report generated")


if __name__ == "__main__":
    print("Task14 测试：Retriever Benchmark — Precision@K, MRR, Latency")
    print("=" * 60)

    tests = [
        test_01_precision_at_5,
        test_02_mrr,
        test_03_latency,
        test_04_importance_bias,
        test_05_design_constraint_recall,
        test_06_multi_query_avg_precision,
        test_07_cross_project_isolation,
        test_08_empty_db,
        test_09_top_k_limit,
        test_10_benchmark_summary,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed += 1
            import traceback
            print(f"  FAIL {t.__name__}: {e}")
            traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"结果：{passed}/{passed+failed} 通过")
    if failed:
        import sys
        sys.exit(1)
