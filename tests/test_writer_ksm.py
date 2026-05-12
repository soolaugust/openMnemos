#!/usr/bin/env python3
"""
迭代58 测试：writer.py KSM 去重 + store.py already_exists() prompt_context 支持

验证：
1. already_exists() 检测 prompt_context 类型
2. already_exists() 向后兼容（无 chunk_type 参数）
3. merge_similar() 对 prompt_context 正常工作
4. writer prompt_context 路径：exact dup → 跳过
5. writer prompt_context 路径：similar → KSM merge
6. writer prompt_context 路径：新 topic → 正常写入
7. prompt_context 去重不影响其他类型
"""
import tmpfs  # 测试隔离（迭代54）

import sys
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone

_MOS_ROOT = Path(__file__).parent
sys.path.insert(0, str(_MOS_ROOT))
_HOOKS_DIR = _MOS_ROOT / "hooks"
sys.path.insert(0, str(_HOOKS_DIR))

from store import open_db, ensure_schema, insert_chunk, already_exists, find_similar, merge_similar


def _make_chunk(summary: str, chunk_type: str = "prompt_context",
                importance: float = 0.5, project: str = "test_proj") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "project": project,
        "source_session": "test-session",
        "chunk_type": chunk_type,
        "content": f"用户话题：{summary}",
        "summary": summary,
        "tags": json.dumps([chunk_type, project]),
        "importance": importance,
        "retrievability": 0.15,
        "created_at": now,
        "updated_at": now,
        "last_accessed": now,
        "access_count": 0,
        "lru_gen": 0,
        "oom_adj": 0,
    }


# ── 测试用例 ──────────────────────────────────────────────────────────

def test_already_exists_prompt_context():
    """测试1：already_exists() 检测 prompt_context 类型"""
    conn = open_db()
    ensure_schema(conn)

    chunk = _make_chunk("BM25 检索功能优化方案与实施路径")
    insert_chunk(conn, chunk)
    conn.commit()

    assert already_exists(conn, "BM25 检索功能优化方案与实施路径", chunk_type="prompt_context"), \
        "Should detect existing prompt_context"
    assert not already_exists(conn, "完全不同的主题内容测试用例验证", chunk_type="prompt_context"), \
        "Should not match different summary"

    conn.close()
    print("  PASS test_already_exists_prompt_context")


def test_already_exists_backward_compat():
    """测试2：already_exists() 无 chunk_type 参数向后兼容"""
    conn = open_db()
    ensure_schema(conn)

    chunk = _make_chunk("使用 FTS5 替代全表扫描以提升检索性能", chunk_type="decision", importance=0.8)
    insert_chunk(conn, chunk)

    chunk2 = _make_chunk("FTS5 查询优化策略与索引配置方案")
    insert_chunk(conn, chunk2)
    conn.commit()

    assert already_exists(conn, "使用 FTS5 替代全表扫描以提升检索性能"), \
        "Should find decision without chunk_type param"
    assert already_exists(conn, "FTS5 查询优化策略与索引配置方案"), \
        "Should find prompt_context without chunk_type param"
    assert not already_exists(conn, "不存在的摘要"), \
        "Should not find nonexistent summary"

    conn.close()
    print("  PASS test_already_exists_backward_compat")


def test_merge_similar_prompt_context():
    """测试3：merge_similar() 对 prompt_context 正常工作"""
    conn = open_db()
    ensure_schema(conn)

    chunk = _make_chunk("memory-os retriever BM25 检索优化")
    insert_chunk(conn, chunk)
    conn.commit()

    merged = merge_similar(conn, "memory-os retriever BM25 延迟优化", "prompt_context", 0.6)
    conn.commit()

    assert merged, "Should merge similar prompt_context (Jaccard > 0.5)"

    row = conn.execute(
        "SELECT importance FROM memory_chunks WHERE id=?", (chunk["id"],)
    ).fetchone()
    assert row[0] >= 0.6, f"importance should be max(0.5, 0.6)=0.6, got {row[0]}"

    conn.close()
    print("  PASS test_merge_similar_prompt_context")


def test_writer_exact_dup_skipped():
    """测试4：writer prompt_context 路径 — exact dup 跳过写入"""
    conn = open_db()
    ensure_schema(conn)

    chunk = _make_chunk("实现 TLB 缓存快速路径优化内存访问延迟")
    insert_chunk(conn, chunk)
    conn.commit()

    topic = "实现 TLB 缓存快速路径优化内存访问延迟"
    skipped = already_exists(conn, topic, chunk_type="prompt_context")
    assert skipped, "Should skip exact duplicate"

    count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE summary=? AND chunk_type='prompt_context'",
        (topic,)
    ).fetchone()[0]
    assert count == 1, f"Should have exactly 1, got {count}"

    conn.close()
    print("  PASS test_writer_exact_dup_skipped")


def test_writer_similar_merged():
    """测试5：writer prompt_context 路径 — similar topic KSM merge"""
    conn = open_db()
    ensure_schema(conn)

    proj = f"test_merge_{uuid.uuid4().hex[:6]}"
    chunk = _make_chunk("memory-os store.py VFS 统一数据访问层重构", project=proj)
    insert_chunk(conn, chunk)
    conn.commit()

    topic = "memory-os store.py VFS 数据访问层优化"
    if already_exists(conn, topic, chunk_type="prompt_context"):
        action = "skip"
    elif merge_similar(conn, topic, "prompt_context", 0.5):
        action = "merge"
        conn.commit()
    else:
        action = "insert"

    assert action == "merge", f"Should merge similar topic, got {action}"

    count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE chunk_type='prompt_context' AND project=?",
        (proj,)
    ).fetchone()[0]
    assert count == 1, f"Should have exactly 1 after merge, got {count}"

    conn.close()
    print("  PASS test_writer_similar_merged")


def test_writer_new_topic_inserted():
    """测试6：writer prompt_context 路径 — 全新 topic 正常写入"""
    conn = open_db()
    ensure_schema(conn)

    proj = f"test_new_{uuid.uuid4().hex[:6]}"
    chunk = _make_chunk("Python 异步编程模式与协程调度实践", project=proj)
    insert_chunk(conn, chunk)
    conn.commit()

    topic = "Rust 所有权系统与借用检查器"
    is_dup = already_exists(conn, topic, chunk_type="prompt_context")
    is_similar = merge_similar(conn, topic, "prompt_context", 0.5) if not is_dup else False

    assert not is_dup, "Should not be exact dup"
    assert not is_similar, "Should not be similar (completely different topic)"

    new_chunk = _make_chunk(topic, project=proj)
    insert_chunk(conn, new_chunk)
    conn.commit()

    count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE chunk_type='prompt_context' AND project=?",
        (proj,)
    ).fetchone()[0]
    assert count == 2, f"Should have 2 distinct topics, got {count}"

    conn.close()
    print("  PASS test_writer_new_topic_inserted")


def test_no_cross_type_collision():
    """测试7：prompt_context 去重不影响其他类型"""
    conn = open_db()
    ensure_schema(conn)

    decision = _make_chunk("优化 BM25 检索延迟以降低 P99 响应时间", chunk_type="decision", importance=0.8)
    prompt_ctx = _make_chunk("优化 BM25 检索延迟以降低 P99 响应时间", chunk_type="prompt_context")
    insert_chunk(conn, decision)
    insert_chunk(conn, prompt_ctx)
    conn.commit()

    assert already_exists(conn, "优化 BM25 检索延迟以降低 P99 响应时间", chunk_type="prompt_context"), \
        "Should find prompt_context with chunk_type filter"
    assert already_exists(conn, "优化 BM25 检索延迟以降低 P99 响应时间", chunk_type="decision"), \
        "Should find decision with chunk_type filter"
    assert already_exists(conn, "优化 BM25 检索延迟以降低 P99 响应时间"), \
        "Should find via default (no chunk_type)"

    conn.close()
    print("  PASS test_no_cross_type_collision")


# ── run ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== 迭代58 Writer KSM Dedup 测试 ===")
    tests = [
        test_already_exists_prompt_context,
        test_already_exists_backward_compat,
        test_merge_similar_prompt_context,
        test_writer_exact_dup_skipped,
        test_writer_similar_merged,
        test_writer_new_topic_inserted,
        test_no_cross_type_collision,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL {t.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n结果：{passed}/{passed+failed} 通过")
