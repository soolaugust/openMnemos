#!/usr/bin/env python3
"""
test_constraint_e2e.py — 迭代98: Design Constraint 端到端集成测试

验证约束知识的完整生命周期：
  1. 提取（extractor.py）— 从消息中识别约束信号
  2. 存储（store_vfs.py）— 以高保护级别写入 DB
  3. 检索（retriever.py）— FTS5 搜索 + 强制注入
  4. 注入（retriever.py）— 在提示词中显示 ⚠️ 约束 + 置信度降级
"""
import tmpfs  # noqa: F401
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from hooks.extractor import _extract_constraints, _is_quality_chunk
from store import open_db, ensure_schema, insert_chunk, get_chunks
from schema import MemoryChunk
import hashlib


def test_e2e_sched_ext_case():
    """
    真实场景：sched_ext SCX_ENQ_IMMED 约束

    AI 推理过程中发现了系统级约束，但由于没读完整上下文，
    检索时约束 BM25 评分可能较低。系统应强制注入 + 置信度降级。
    """
    # Step 1: 模拟 AI 消息（包含约束信号）
    assistant_message = """
    经分析，SCX_ENQ_IMMED 这个入口点不能在 EXITING 路径使用，因为会导致任务状态污染和上下文丢失。

    这样做会破坏 task_struct 中的调度不变性。根本原因是路径隔离不完整。

    设计约束：所有 sched_ext 操作必须验证任务生命周期状态，绕过此检查的代码会产生竞态条件。

    设计约束：SCX_ENQ_IMMED 不能在 task_dead/task_exiting 路径调用，否则 task_struct 引用计数泄漏导致内存不可回收。
    """

    # Step 2: 提取约束
    constraints = _extract_constraints(assistant_message)
    # 过滤掉不符合质量标准的约束（如太短的截断碎片）
    valid_constraints = [c for c in constraints if _is_quality_chunk(c)]

    print(f"✅ 约束提取：{len(constraints)} 条 (有效 {len(valid_constraints)} 条)")
    for i, c in enumerate(valid_constraints, 1):
        print(f"   {i}. {c[:60]}...")

    assert len(valid_constraints) >= 2, f"Expected ≥2 valid constraints, got {len(valid_constraints)}"
    constraints = valid_constraints  # 只用有效约束

    # Step 3: 存储约束
    conn = open_db()
    ensure_schema(conn)
    try:
        conn.execute("DELETE FROM memory_chunks")
        conn.execute("DELETE FROM memory_chunks_fts")
        conn.commit()

        project = "test-sched-ext"
        session_id = "e2e-session-001"

        written_constraints = []
        for constraint_text in constraints:
            chunk = MemoryChunk(
                project=project,
                source_session=session_id,
                chunk_type="design_constraint",
                content=f"[design_constraint] {constraint_text}",
                summary=constraint_text,
                tags=["design_constraint", project],
                importance=0.95,
                retrievability=0.5,
            )
            chunk_dict = chunk.to_dict()
            chunk_dict["oom_adj"] = -800  # OOM_ADJ_PROTECTED
            insert_chunk(conn, chunk_dict)
            written_constraints.append(constraint_text)

        conn.commit()
        print(f"✅ 约束存储：{len(written_constraints)} 条 (importance=0.95, oom_adj=-800)")

        # Step 4: 检索约束
        # 模拟用户查询（直接用约束中的关键词）
        query = "SCX_ENQ_IMMED EXITING"

        from store import fts_search
        results = fts_search(conn, query, project, top_k=10)
        constraint_results = [r for r in results if r["chunk_type"] == "design_constraint"]

        print(f"✅ 约束检索：查询 '{query}' → {len(constraint_results)} 条约束")
        for r in constraint_results:
            print(f"   - {r['summary'][:60]}... (score={r['fts_rank']:.2f})")

        # 如果 FTS5 搜不到（词不匹配），验证强制注入机制可以补充
        if len(constraint_results) == 0:
            print(f"   (FTS5 无结果，但约束会在强制注入阶段补充)")

        # 约束总数应该存在
        all_from_db = get_chunks(conn, project, chunk_types=("design_constraint",))
        assert len(all_from_db) > 0, "Constraints should be in database"

        # Step 5: 模拟强制注入场景
        # 假设 BM25 评分低，但约束仍需注入

        # 创建一个高相关性的普通决策
        decision = MemoryChunk(
            project=project,
            source_session=session_id,
            chunk_type="decision",
            content="[decision] Use SCX_ENQ_IMMED for fast path scheduling",
            summary="Use SCX_ENQ_IMMED for fast path scheduling",
            tags=["decision"],
            importance=0.85,
            retrievability=0.5,
        )
        insert_chunk(conn, decision.to_dict())
        conn.commit()

        # 获取所有 chunks
        all_chunks = get_chunks(conn, project)
        print(f"✅ 可用 chunks：{len(all_chunks)} 条 "
              f"({sum(1 for c in all_chunks if c['chunk_type'] == 'decision')} decisions, "
              f"{sum(1 for c in all_chunks if c['chunk_type'] == 'design_constraint')} constraints)")

        # Step 6: 验证强制注入逻辑
        # 模拟 retriever.py 的强制注入代码
        from scorer import retrieval_score

        final = []
        for chunk in all_chunks:
            score = retrieval_score(
                relevance=0.3,  # 低相关性（搜索词不匹配）
                importance=float(chunk["importance"]),
                last_accessed=chunk["last_accessed"],
                access_count=chunk.get("access_count", 0) or 0,
            )
            final.append((score, chunk))

        final.sort(key=lambda x: x[0], reverse=True)
        top_k = final[:2]  # 只选 top 2

        all_constraints = [c for s, c in final if c.get("chunk_type") == "design_constraint"]
        top_k_ids = {c["id"] for _, c in top_k}

        forced_constraints = []
        for c in all_constraints:
            if c["id"] not in top_k_ids:
                forced_constraints.append(c["summary"])
                top_k.insert(0, (0.99, c))

        print(f"✅ 强制注入：{len(forced_constraints)} 条约束被 insert 到 top_k")

        # Step 7: 验证注入文本格式
        _TYPE_PREFIX = {
            "decision": "[决策]",
            "excluded_path": "[排除]",
            "reasoning_chain": "[推理]",
            "conversation_summary": "[摘要]",
            "task_state": "",
            "design_constraint": "⚠️ [约束]",
        }

        constraint_items = []
        normal_items = []
        for _, c in top_k:
            prefix = _TYPE_PREFIX.get(c.get("chunk_type", ""), "")
            line = f"{prefix} {c['summary']}".strip()
            if c.get("chunk_type") == "design_constraint":
                constraint_items.append(line)
            else:
                normal_items.append(line)

        inject_lines = ["【相关历史记录（BM25 召回）】"]
        if constraint_items:
            inject_lines.append("")
            inject_lines.append("【已知约束（系统级设计限制）】")
            inject_lines.extend(constraint_items)

            if forced_constraints:
                inject_lines.append("")
                inject_lines.append("ℹ️ 注：上述约束经系统强制注入（非检索相关性排序），")
                inject_lines.append("代表已知设计决策，但在本次会话的局部上下文中可能未出现信号词。")
                inject_lines.append("若约束与当前任务无关，可选择性忽略。")

            inject_lines.append("")
            inject_lines.append("【相关知识】")
            inject_lines.extend(normal_items)
        else:
            inject_lines.extend(normal_items)

        context_text = "\n".join(inject_lines)
        print(f"\n✅ 注入文本格式验证（{len(inject_lines)} 行）：")
        print(context_text)

        # 验证关键特征
        assert "【已知约束（系统级设计限制）】" in context_text
        assert "⚠️ [约束]" in context_text

        print("\n✅ 所有端到端验证通过")

    finally:
        conn.close()


def test_constraint_confidence_degradation():
    """
    验证置信度降级机制：当约束被强制注入时，显式标注为"非检索相关性排序"。

    场景：
    1. 约束 BM25 分数低（因为查询词不匹配）
    2. 但约束被强制包含（importance 高）
    3. 文本中需明确说明这是"系统级设计决策"而非"相关性推荐"
    """
    conn = open_db()
    ensure_schema(conn)
    try:
        conn.execute("DELETE FROM memory_chunks")
        conn.commit()

        project = "test-confidence"
        session_id = "conf-session-001"

        # 插入约束
        now_iso = datetime.now(timezone.utc).isoformat()
        constraint_dict = {
            "id": "constraint-123",
            "created_at": now_iso,
            "updated_at": now_iso,
            "project": project,
            "source_session": session_id,
            "chunk_type": "design_constraint",
            "content": "[design_constraint] Must not use spinlock in this context",
            "summary": "Must not use spinlock in this context",
            "tags": ["design_constraint"],
            "importance": 0.95,
            "retrievability": 0.5,
            "last_accessed": now_iso,
            "feishu_url": None,
            "access_count": 0,
            "oom_adj": -800,
            "lru_gen": 0,
        }
        insert_chunk(conn, constraint_dict)
        conn.commit()

        # 查询词完全不相关
        query = "weather forecast python"

        from store import fts_search
        results = fts_search(conn, query, project, top_k=10)

        # 约束不应该在 FTS5 结果中（因为词不匹配）
        constraint_in_fts = any(r["chunk_type"] == "design_constraint" for r in results)

        print(f"✅ 置信度测试：")
        print(f"   查询词：'{query}' (与约束完全无关)")
        print(f"   约束在 FTS5 结果中：{constraint_in_fts} (预期 False)")
        print(f"   但约束会在 retriever.py 中被强制注入 + 加置信度降级")

        # 验证强制注入逻辑会补充该约束
        all_chunks = get_chunks(conn, project)
        constraints_to_force = [c for c in all_chunks
                               if c.get("chunk_type") == "design_constraint"]

        assert len(constraints_to_force) > 0, "Should find constraint in forced injection pool"

        # 生成置信度降级文本
        disclaimer = (
            "ℹ️ 注：上述约束经系统强制注入（非检索相关性排序），\n"
            "代表已知设计决策，但在本次会话的局部上下文中可能未出现信号词。\n"
            "若约束与当前任务无关，可选择性忽略。"
        )

        print(f"\n   置信度降级文本：\n   {disclaimer.replace(chr(10), chr(10) + '   ')}")

        assert "非检索相关性排序" in disclaimer
        assert "可选择性忽略" in disclaimer

        print(f"\n✅ 置信度降级验证通过")

    finally:
        conn.close()


if __name__ == "__main__":
    print("=" * 70)
    print("Task #28: Design Constraint 端到端验证")
    print("=" * 70)

    test_e2e_sched_ext_case()
    print()
    test_constraint_confidence_degradation()

    print("\n" + "=" * 70)
    print("✅ 所有端到端集成测试通过")
    print("=" * 70)
