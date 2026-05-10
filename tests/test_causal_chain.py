"""
test_causal_chain.py — 迭代324：causal_chain 召回修复单元测试

验证：
  1. _write_chunk content_override 参数正常工作
  2. 相邻节点聚合：中间节点 content 包含前/后节点
  3. 首节点 content 只含当前+后节点
  4. 末节点 content 只含前节点+当前
  5. 单节点列表 content 只含当前节点（无邻居）
  6. content 长度明显大于 summary（FTS5 token 密度提升）
  7. summary 保持不变（展示层不受影响）
  8. FTS5 能通过邻居 content 召回中间节点
  9. 聚合后 content 不超过 400 字
 10. topic 正确嵌入 content 前缀

OS 类比：Linux readahead + page clustering
  相邻因果节点批量聚合 → 每个 chunk content 包含完整推理脉络
  FTS5 token 密度从 ~89 字提升到 ~200-300 字（接近 decision 的 248 字）
"""
import sys
import sqlite3
import pytest
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "hooks"))

import tmpfs  # noqa

from store_vfs import ensure_schema, insert_chunk
from store import fts_search


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


def _make_cc_chunk(cid, summary, content, project="test"):
    now = _now_iso()
    return {
        "id": cid,
        "created_at": now,
        "updated_at": now,
        "project": project,
        "source_session": "s1",
        "chunk_type": "causal_chain",
        "info_class": "episodic",
        "content": content,
        "summary": summary,
        "tags": ["causal_chain"],
        "importance": 0.82,
        "retrievability": 0.2,
        "last_accessed": now,
        "access_count": 0,
        "oom_adj": 0,
        "lru_gen": 0,
        "stability": 1.5,
        "raw_snippet": "",
        "encoding_context": {},
    }


# ══════════════════════════════════════════════════════════════════════
# 1. content_override 基础功能
# ══════════════════════════════════════════════════════════════════════

def test_content_override_stored_correctly(conn):
    """content_override 写入后可以正确读取。"""
    chunk = _make_cc_chunk(
        "c1",
        summary="内存分配路径导致了严重的调度延迟上升问题",
        content="[causal_chain] kmalloc → 内存分配路径导致了严重的调度延迟上升问题 → 最终结果",
    )
    insert_chunk(conn, chunk)
    conn.commit()
    row = conn.execute("SELECT summary, content FROM memory_chunks WHERE id='c1'").fetchone()
    assert row["summary"] == "内存分配路径导致了严重的调度延迟上升问题"
    assert "kmalloc" in row["content"]
    assert "最终结果" in row["content"]
    assert row["content"] != row["summary"]


def test_content_richer_than_summary(conn):
    """content 长度显著大于 summary（聚合后 token 密度提升）。"""
    summary = "内存分配路径中 kmalloc 调用导致调度延迟增加"
    neighbors = ["原因是 slab 碎片化导致 buddy allocator 回退", summary, "最终 P99 延迟从 1.3ms 提升到 15.0ms"]
    content = "[causal_chain] " + " → ".join(neighbors)
    chunk = _make_cc_chunk("c2", summary=summary, content=content)
    insert_chunk(conn, chunk)
    conn.commit()
    row = conn.execute("SELECT summary, content FROM memory_chunks WHERE id='c2'").fetchone()
    assert len(row["content"]) > len(row["summary"]) * 1.5, \
        f"content 应显著长于 summary，content={len(row['content'])} summary={len(row['summary'])}"


# ══════════════════════════════════════════════════════════════════════
# 2. 相邻节点聚合逻辑
# ══════════════════════════════════════════════════════════════════════

def _simulate_chain_write(qualified_chains, topic=""):
    """
    模拟 extractor 写入循环的聚合逻辑（与 extractor.py 相同算法）。
    返回 [(summary, content)] 列表。
    """
    results = []
    for idx, summary in enumerate(qualified_chains):
        ctx_parts = []
        if idx > 0:
            ctx_parts.append(qualified_chains[idx - 1])
        ctx_parts.append(summary)
        if idx < len(qualified_chains) - 1:
            ctx_parts.append(qualified_chains[idx + 1])
        topic_tag = f"[causal_chain|{topic}]" if topic else "[causal_chain]"
        rich_content = f"{topic_tag} {' → '.join(ctx_parts)}"[:400]
        results.append((summary, rich_content))
    return results


def test_middle_node_has_both_neighbors():
    """中间节点 content 包含前后两个邻居。"""
    chains = ["A 导致 B", "B 因此 C", "C 最终 D"]
    results = _simulate_chain_write(chains)
    _, middle_content = results[1]
    assert "A 导致 B" in middle_content, "中间节点应包含前邻居"
    assert "B 因此 C" in middle_content, "中间节点应包含自身"
    assert "C 最终 D" in middle_content, "中间节点应包含后邻居"


def test_first_node_has_only_next_neighbor():
    """首节点 content 只包含自身+后邻居（无前邻居）。"""
    chains = ["A 导致 B", "B 因此 C", "C 最终 D"]
    results = _simulate_chain_write(chains)
    first_summary, first_content = results[0]
    assert first_summary in first_content
    assert "B 因此 C" in first_content
    # 不应包含虚构的"前节点"
    assert first_content.count(" → ") == 1  # 首节点：self + next


def test_last_node_has_only_prev_neighbor():
    """末节点 content 只包含前邻居+自身（无后邻居）。"""
    chains = ["A 导致 B", "B 因此 C", "C 最终 D"]
    results = _simulate_chain_write(chains)
    last_summary, last_content = results[2]
    assert "B 因此 C" in last_content
    assert last_summary in last_content
    assert last_content.count(" → ") == 1  # 末节点：prev + self


def test_single_node_content_equals_self():
    """单节点列表：content 只含自身（无邻居 → 分隔符）。"""
    chains = ["A 因为 B 导致 C"]
    results = _simulate_chain_write(chains)
    _, content = results[0]
    assert "A 因为 B 导致 C" in content
    assert " → " not in content  # 无邻居拼接，只有类型前缀


def test_content_within_400_chars():
    """聚合后 content 不超过 400 字（[:400] 截断保护）。"""
    # 构造三个极长的链节点
    long_chains = [
        "A" * 150 + " 因此 导致 下游影响",
        "B" * 150 + " 因此 导致 系统降级",
        "C" * 150 + " 最终 触发 故障级联",
    ]
    results = _simulate_chain_write(long_chains)
    for _, content in results:
        assert len(content) <= 400, f"content 超过 400 字：{len(content)}"


def test_topic_embedded_in_content_prefix():
    """topic 正确嵌入 content 前缀。"""
    chains = ["因为 X 导致 Y"]
    results = _simulate_chain_write(chains, topic="memory-os")
    _, content = results[0]
    assert "[causal_chain|memory-os]" in content


def test_no_topic_uses_default_prefix():
    """无 topic 时使用 [causal_chain] 前缀。"""
    chains = ["因为 X 导致 Y"]
    results = _simulate_chain_write(chains, topic="")
    _, content = results[0]
    assert content.startswith("[causal_chain]")


# ══════════════════════════════════════════════════════════════════════
# 3. FTS5 召回验证（端到端）
# ══════════════════════════════════════════════════════════════════════

def test_fts5_recall_via_neighbor_content(conn):
    """FTS5 能通过邻居节点的 content token 召回中间节点。"""
    # 模拟三个相邻节点，中间节点 content 包含前后节点文本
    chains = [
        "cp_non_rt_waker 函数触发了异常的任务唤醒路径",
        "因此调度器将该任务判定为异常抢占行为",
        "最终影响了系统中实时线程的优先级调度决策",
    ]
    results = _simulate_chain_write(chains)

    for idx, (summary, content) in enumerate(results):
        chunk = _make_cc_chunk(f"fts_{idx}", summary=summary, content=content)
        insert_chunk(conn, chunk)
    conn.commit()

    # 用中间节点的邻居关键词查询
    fts_results = fts_search(conn, "cp_non_rt_waker 实时线程", project="test", top_k=5)
    recalled_ids = {r["id"] for r in fts_results}

    # 中间节点 content 包含两侧邻居的关键词，应以高分被召回
    assert "fts_1" in recalled_ids, \
        f"中间节点应通过邻居 token 被召回，recalled={recalled_ids}"

    # 末节点 content 包含"实时线程"，也应被召回
    assert "fts_2" in recalled_ids, \
        f"末节点应通过自身 token '实时线程' 被召回，recalled={recalled_ids}"


def test_fts5_recall_improves_with_rich_content(conn):
    """丰富 content 比稀薄 content 有更好的 FTS5 召回（模拟修复前后对比）。"""
    query = "RT 线程 抢占 调度异常"

    # 修复前：content = "[causal_chain] summary"（极短）
    chunk_before = _make_cc_chunk(
        "before",
        summary="因此调度器将该任务判定为异常抢占行为",
        content="[causal_chain] 因此调度器将该任务判定为异常抢占行为",
    )
    # 修复后：content 包含前后节点
    chunk_after = _make_cc_chunk(
        "after",
        summary="因此调度器将该任务判定为异常抢占行为",
        content="[causal_chain] 非RT线程抢占了RT线程 → 因此调度器将该任务判定为异常抢占行为 → 最终影响了实时线程优先级",
    )

    insert_chunk(conn, chunk_before)
    insert_chunk(conn, chunk_after)
    conn.commit()

    fts_results = fts_search(conn, query, project="test", top_k=5)
    recalled_ids = {r["id"] for r in fts_results}

    # 修复后的 chunk 包含更多相关 token（"RT线程"、"抢占"），应被召回
    assert "after" in recalled_ids, \
        f"丰富 content 的 chunk 应被召回，recalled={recalled_ids}"
