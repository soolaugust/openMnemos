#!/usr/bin/env python3
"""
迭代71: 完整端到端性能基线 — E2E Baseline Measurement

目标：建立虚拟内存系统的性能基线，量化：
  1. PreCompact swap_out 信息完整性（recall_traces 命中率）
  2. PostCompact swap_in 恢复速度和准确性
  3. 注入上下文的实际质量（覆盖度 vs 空间）
  4. 系统健康状态（DB 一致性、trace stale refs）

方法论：
  - 模拟真实会话：冷启动 → 多轮对话 → compaction 前状态 → swap_out → PostCompact
  - 量化指标：hit_rate, stale_ref_rate, restore_time_ms, injection_chars, knowledge_diversity
  - 基线记录：作为迭代72+ 的对标，用于评估优化收益

输出：
  - test_e2e_baseline_result.json — 量化指标汇总
  - test_e2e_baseline.log — 详细日志
"""

import sys
import json
import time
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import os

sys.path.insert(0, str(Path(__file__).parent))

import tmpfs
from store_core import ensure_schema, open_db

def populate_test_data(conn):
    """构造测试数据集：模拟 10 轮对话的知识积累"""
    ensure_schema(conn)

    project_id = "test:e2e_baseline"
    chunks = [
        # 决策类知识（高价值）
        {"chunk_type": "decision", "summary": "Swap_out 100% 恢复率需要 queries_global_top_k", "importance": 0.9, "access_count": 5},
        {"chunk_type": "decision", "summary": "PreCompact hook 需要 immutable DB 避免锁竞争", "importance": 0.85, "access_count": 3},
        {"chunk_type": "decision", "summary": "TLB 多槽缓存解决 DB mtime 频繁失效", "importance": 0.8, "access_count": 2},

        # 推理链类知识
        {"chunk_type": "reasoning_chain", "summary": "Session ID 从 env 改为 stdin 修复了 0 hit_ids 问题", "importance": 0.75, "access_count": 1},
        {"chunk_type": "reasoning_chain", "summary": "VFS mount_walk 解决了子目录 project_id 不匹配", "importance": 0.7, "access_count": 0},

        # 排除路径类
        {"chunk_type": "excluded_path", "summary": "/test/*, *.bak, __pycache__", "importance": 0.6, "access_count": 2},

        # 对话摘要
        {"chunk_type": "conversation_summary", "summary": "讨论虚拟内存 swap 和 hook 过载治理", "importance": 0.5, "access_count": 1},

        # 提示上下文
        {"chunk_type": "prompt_context", "summary": "当前任务：性能基线评测", "importance": 0.4, "access_count": 1},
    ]

    cursor = conn.cursor()
    inserted_ids = []

    for chunk_idx, chunk in enumerate(chunks):
        chunk_id = f"test_chunk_{chunk_idx}"
        now = datetime.utcnow()
        age_days = chunk_idx  # 模拟递减的创建日期
        created_at = (now - timedelta(days=age_days)).isoformat()

        cursor.execute("""
            INSERT OR REPLACE INTO memory_chunks
            (id, project, chunk_type, summary, importance, access_count, created_at, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (chunk_id, project_id, chunk["chunk_type"], chunk["summary"],
              chunk["importance"], chunk["access_count"], created_at, created_at))

        inserted_ids.append(chunk_id)

    # 构造 recall_traces：模拟查询历史
    queries = [
        "虚拟内存 swap 100%",
        "compaction 前工作集恢复",
        "session_id stdin 修复",
    ]

    for query_idx, query in enumerate(queries):
        hit_batch = inserted_ids[:min(3, len(inserted_ids))]
        top_k = [{"id": inserted_ids[i], "summary": chunks[i]["summary"],
                   "score": 0.8 - i * 0.1} for i in range(len(hit_batch))]
        try:
            cursor.execute("""
                INSERT INTO recall_traces
                (session_id, project, prompt_hash, top_k_json, injected, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "test_session",
                project_id,
                str(hash(query) % (2**31)),
                json.dumps(top_k),
                1,
                datetime.utcnow().isoformat()
            ))
        except sqlite3.OperationalError:
            pass

    conn.commit()
    return project_id, inserted_ids

def measure_swap_out(conn, project_id):
    """模拟 PreCompact swap_out 并测量信息完整性"""
    start_time = time.time()

    cursor = conn.cursor()

    # 1. 收集 recall_traces 命中（如果表存在）
    hit_ids = []
    try:
        cursor.execute("""
            SELECT top_k_json FROM recall_traces
            WHERE project = ? AND injected = 1 ORDER BY timestamp DESC LIMIT 100
        """, (project_id,))
        seen = set()
        for row in cursor.fetchall():
            if row[0]:
                for item in json.loads(row[0]):
                    cid = item["id"] if isinstance(item, dict) else item
                    if cid not in seen:
                        hit_ids.append(cid)
                        seen.add(cid)
    except sqlite3.OperationalError:
        pass

    # 2. 收集 decisions（全局 Top-K）
    cursor.execute("""
        SELECT id, summary, importance FROM memory_chunks
        WHERE project = ? AND chunk_type = 'decision'
        ORDER BY importance DESC LIMIT 10
    """, (project_id,))

    decisions = cursor.fetchall()

    # 3. 收集 excluded_paths
    cursor.execute("""
        SELECT summary FROM memory_chunks
        WHERE project = ? AND chunk_type = 'excluded_path'
    """, (project_id,))

    excluded_paths = [row[0] for row in cursor.fetchall()]

    elapsed_ms = (time.time() - start_time) * 1000

    return {
        "hit_ids_count": len(hit_ids),
        "decisions_count": len(decisions),
        "excluded_paths_count": len(excluded_paths),
        "elapsed_ms": elapsed_ms,
        "hit_ids": hit_ids,
        "decisions": [{"id": d[0], "summary": d[1], "importance": d[2]} for d in decisions],
        "excluded_paths": excluded_paths,
    }

def measure_swap_in(conn, project_id, swap_out_data):
    """模拟 PostCompact swap_in 并测量恢复质量"""
    start_time = time.time()

    cursor = conn.cursor()

    # 恢复 hit_ids 对应的 chunks
    restored_chunks = []
    for chunk_id in swap_out_data["hit_ids"][:10]:  # 限制恢复数量模拟窗口大小
        cursor.execute("""
            SELECT id, chunk_type, summary, importance FROM memory_chunks
            WHERE id = ?
        """, (chunk_id,))

        row = cursor.fetchone()
        if row:
            restored_chunks.append({
                "id": row[0],
                "type": row[1],
                "summary": row[2],
                "importance": row[3],
            })

    # 组装恢复上下文（模拟 additionalContext 格式）
    context_text = "【上次会话状态 · 自动恢复】\n"
    context_text += f"关键知识（{len(restored_chunks)} items）:\n"
    for chunk in restored_chunks:
        context_text += f"  [{chunk['type']}] {chunk['summary']} (importance={chunk['importance']:.2f})\n"

    if swap_out_data["decisions"]:
        context_text += f"\n核心决策（{len(swap_out_data['decisions'])} items）:\n"
        for dec in swap_out_data["decisions"][:3]:
            context_text += f"  • {dec['summary']}\n"

    context_text += f"\n排除路径: {', '.join(swap_out_data['excluded_paths'])}\n"

    elapsed_ms = (time.time() - start_time) * 1000

    # 质量评分：覆盖度 × 空间效率
    max_chars = 1500
    actual_chars = len(context_text.encode('utf-8'))
    coverage = len(restored_chunks) / max(1, len(swap_out_data["hit_ids"]))
    space_efficiency = actual_chars / max_chars
    quality_score = coverage * (1 - min(1, space_efficiency - 0.7))  # 超 70% 开始扣分

    return {
        "restored_chunks_count": len(restored_chunks),
        "actual_chars": actual_chars,
        "max_chars": max_chars,
        "coverage": coverage,
        "space_efficiency": space_efficiency,
        "quality_score": quality_score,
        "elapsed_ms": elapsed_ms,
        "sample_context": context_text[:300] + "...",
    }

def check_db_health(conn, project_id):
    """检查数据库健康状态"""
    cursor = conn.cursor()

    # 1. chunks 行数
    cursor.execute("SELECT COUNT(*) FROM memory_chunks WHERE project = ?", (project_id,))
    chunk_count = cursor.fetchone()[0]

    # 2. Stale refs：recall_traces 中失效的 chunk 引用
    stale_refs = 0
    try:
        cursor.execute("""
            SELECT COUNT(*) FROM recall_traces t
            WHERE project = ? AND NOT EXISTS (
                SELECT 1 FROM memory_chunks c WHERE c.id = json_extract(t.hit_ids, '$[0]')
            )
        """, (project_id,))
        stale_refs = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        pass

    # 3. Orphan chunks：未被任何 trace 引用的 chunk
    orphan_chunks = 0
    try:
        cursor.execute("""
            SELECT COUNT(*) FROM memory_chunks c
            WHERE project = ? AND NOT EXISTS (
                SELECT 1 FROM recall_traces t
                WHERE t.project = ? AND json_extract(t.hit_ids, '$[0]') = c.id
            )
        """, (project_id, project_id))
        orphan_chunks = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        pass

    health_status = "HEALTHY"
    issues = []

    if stale_refs > 0:
        issues.append(f"stale_refs={stale_refs}")
        health_status = "DEGRADED"

    if orphan_chunks > chunk_count * 0.5:  # >50% 孤立 chunks 为异常
        issues.append(f"orphan_chunks={orphan_chunks}")
        health_status = "DEGRADED"

    return {
        "status": health_status,
        "chunk_count": chunk_count,
        "stale_refs": stale_refs,
        "orphan_chunks": orphan_chunks,
        "issues": issues,
    }

def test_e2e_baseline():
    """完整端到端基线测试"""
    print("=" * 60)
    print("迭代71: 完整端到端性能基线")
    print("=" * 60)

    conn = open_db()
    project_id, inserted_ids = populate_test_data(conn)
    print(f"✅ 测试数据: {len(inserted_ids)} chunks, {project_id}")

    # 测量 swap_out
    print("\n【PreCompact Swap Out】")
    swap_out_data = measure_swap_out(conn, project_id)
    print(f"  hit_ids 命中: {swap_out_data['hit_ids_count']}")
    print(f"  decisions: {swap_out_data['decisions_count']}")
    print(f"  elapsed: {swap_out_data['elapsed_ms']:.2f}ms")

    # 测量 swap_in
    print("\n【PostCompact Swap In】")
    swap_in_data = measure_swap_in(conn, project_id, swap_out_data)
    print(f"  恢复 chunks: {swap_in_data['restored_chunks_count']}")
    print(f"  覆盖度: {swap_in_data['coverage']:.1%}")
    print(f"  空间效率: {swap_in_data['space_efficiency']:.1%}")
    print(f"  质量评分: {swap_in_data['quality_score']:.2f}")
    print(f"  elapsed: {swap_in_data['elapsed_ms']:.2f}ms")

    # 检查 DB 健康
    print("\n【数据库健康】")
    health = check_db_health(conn, project_id)
    print(f"  状态: {health['status']}")
    print(f"  chunks: {health['chunk_count']}")
    print(f"  stale_refs: {health['stale_refs']}")
    if health['issues']:
        print(f"  ⚠️  问题: {', '.join(health['issues'])}")

    # 汇总结果
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "iteration": 71,
        "project_id": project_id,
        "swap_out": swap_out_data,
        "swap_in": swap_in_data,
        "db_health": health,
        "metrics": {
            "total_time_ms": swap_out_data["elapsed_ms"] + swap_in_data["elapsed_ms"],
            "hit_rate": swap_out_data["hit_ids_count"] / max(1, len(inserted_ids)),
            "quality_score": swap_in_data["quality_score"],
        }
    }

    # 保存结果
    result_file = Path(__file__).parent / "test_e2e_baseline_result.json"
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n📊 结果已保存: {result_file}")
    print("\n【汇总指标】")
    print(f"  总耗时: {result['metrics']['total_time_ms']:.2f}ms")
    print(f"  hit_rate: {result['metrics']['hit_rate']:.1%}")
    print(f"  quality_score: {result['metrics']['quality_score']:.2f}")

    conn.close()
    return result

if __name__ == "__main__":
    result = test_e2e_baseline()
    print("\n✅ 迭代71 基线评测完成")
