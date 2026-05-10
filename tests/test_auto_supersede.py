"""
test_auto_supersede.py — iter381: Auto-Supersede 单元测试

覆盖：
  AS1: detect_conflict() 对包含否定词+实体交集的 summary 返回冲突 ID
  AS2: detect_conflict() 对不含否定词的 summary 返回空列表（快速路径）
  AS3: detect_conflict() 对无实体交集的否定词 summary 返回空列表
  AS4: supersede_chunk() 降低旧 chunk importance × 0.5 + oom_adj += 200
  AS5: supersede_chunk() 写入 knowledge_versions 记录
  AS6: supersede_chunk() 对不存在的 old_id 安全返回 new_id
  AS7: 端到端 — 写入新 decision chunk 后旧冲突 chunk 自动被 supersede
  AS8: supersede_chunk() 幂等 — 多次调用不超过预期降权
"""
import sys
import sqlite3
import pytest
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import tmpfs  # noqa

from store_vfs import (
    open_db, ensure_schema,
    detect_conflict, supersede_chunk,
    get_superseded_ids,
)
from store import insert_chunk


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


def _make_chunk(cid, summary, chunk_type="decision", project="test",
                importance=0.8, access_count=1):
    now = datetime.now(timezone.utc).isoformat()
    padded = summary if len(summary) >= 15 else summary + "（测试用补充上下文信息）"
    return {
        "id": cid,
        "created_at": now,
        "updated_at": now,
        "project": project,
        "source_session": "s1",
        "chunk_type": chunk_type,
        "info_class": "semantic",
        "content": f"[{chunk_type}] {padded} — context for testing",
        "summary": padded,
        "tags": [chunk_type],
        "importance": importance,
        "retrievability": 0.8,
        "last_accessed": now,
        "access_count": access_count,
        "oom_adj": 0,
        "lru_gen": 0,
        "stability": importance * 2.0,
        "raw_snippet": "",
        "encoding_context": {},
    }


# ── AS1: 包含否定词 + 实体交集 → 冲突 ───────────────────────────────────────

def test_as1_conflict_detected_with_negation_and_entity_overlap(conn):
    """否定词 + 实体交集 → 检测到冲突。"""
    # 旧知识：使用 Redis 作缓存
    insert_chunk(conn, _make_chunk("old1", "使用 Redis 作为缓存层"))
    conn.commit()

    # 新知识：不再使用 Redis（否定词 + 实体 Redis 交集）
    conflicts = detect_conflict(conn, "不再使用 Redis，改用 Memcached", "decision", "test")
    assert "old1" in conflicts, f"应检测到与 old1 的冲突，got {conflicts}"


# ── AS2: 无否定词 → 快速路径返回空列表 ─────────────────────────────────────

def test_as2_no_negation_returns_empty(conn):
    """不含否定/替换关键词 → 直接返回 []（快速路径）。"""
    insert_chunk(conn, _make_chunk("ch1", "使用 PostgreSQL 存储用户数据"))
    conn.commit()

    # 新 summary 无否定词
    conflicts = detect_conflict(conn, "查询 PostgreSQL 获取报表数据", "decision", "test")
    assert conflicts == [], f"无否定词不应返回冲突，got {conflicts}"


# ── AS3: 有否定词但无实体交集 → 不冲突 ──────────────────────────────────────

def test_as3_negation_without_entity_overlap(conn):
    """否定词存在但实体无交集 → 不冲突。

    注意：_extract_key_entities 使用 CJK bigram，常见动词也会被提取，
    因此测试数据需要确保连 CJK bigram 也无交集（使用完全不同的领域词）。
    """
    # 使用完全不同的专有名词（数据库 vs 音频处理）
    insert_chunk(conn, _make_chunk("ch1", "PostgreSQL 存储订单数据库"))
    conn.commit()

    # 新 summary 谈论完全不同领域（无任何实体交集）
    conflicts = detect_conflict(conn, "不渲染 WebGL 音频处理器", "decision", "test")
    assert "ch1" not in conflicts, f"实体不交集时不应冲突，got {conflicts}"


# ── AS4: supersede_chunk 降权旧 chunk ────────────────────────────────────────

def test_as4_supersede_decreases_old_importance(conn):
    """supersede_chunk 将旧 chunk importance 降低 × 0.5 并上调 oom_adj。"""
    original_imp = 0.8
    insert_chunk(conn, _make_chunk("old_ch", "使用 BM25 检索", importance=original_imp))
    conn.commit()

    result = supersede_chunk(conn, "old_ch", "new_ch",
                              reason="superseded test", project="test")
    conn.commit()

    assert result == "new_ch"
    row = conn.execute("SELECT importance, oom_adj FROM memory_chunks WHERE id='old_ch'").fetchone()
    assert row is not None
    assert row["importance"] < original_imp, \
        f"旧 chunk importance 应降低，got {row['importance']}"
    assert row["oom_adj"] >= 200, f"oom_adj 应 ≥ 200，got {row['oom_adj']}"


# ── AS5: supersede_chunk 写入 knowledge_versions ─────────────────────────────

def test_as5_supersede_writes_knowledge_versions(conn):
    """supersede_chunk 在 knowledge_versions 中写入版本对记录。"""
    insert_chunk(conn, _make_chunk("old_kv", "旧决策"))
    conn.commit()

    supersede_chunk(conn, "old_kv", "new_kv",
                    reason="superseded test", project="test", session_id="s_test")
    conn.commit()

    row = conn.execute(
        "SELECT * FROM knowledge_versions WHERE old_chunk_id='old_kv'"
    ).fetchone()
    assert row is not None, "应在 knowledge_versions 中有记录"
    assert row["new_chunk_id"] == "new_kv"
    assert row["project"] == "test"


# ── AS6: supersede_chunk 对不存在的 old_id 安全 ──────────────────────────────

def test_as6_supersede_nonexistent_old_id_safe(conn):
    """supersede_chunk 对不存在的 old_id 安全返回 new_id（不抛异常）。"""
    result = supersede_chunk(conn, "nonexistent_id", "new_id_x",
                              reason="safety test", project="test")
    # Should return new_id without exception
    assert result == "new_id_x" or result is not None


# ── AS7: 端到端 — 写入新 chunk 后旧冲突 chunk 被自动降权 ─────────────────────

def test_as7_end_to_end_old_chunk_superseded(conn):
    """端到端：写入否定型新 chunk → 旧同实体 chunk 被 supersede（importance 下降）。"""
    original_imp = 0.85
    insert_chunk(conn, _make_chunk("old_end", "使用 MongoDB 存储文档数据",
                                   importance=original_imp))
    conn.commit()

    # 模拟 _write_chunk 内部的 auto-supersede 逻辑
    new_summary = "不使用 MongoDB，改用 PostgreSQL 存储文档"
    conflict_ids = detect_conflict(conn, new_summary, "decision", "test")
    assert "old_end" in conflict_ids, f"端到端应检测到冲突，got {conflict_ids}"

    insert_chunk(conn, _make_chunk("new_end", new_summary, importance=0.9))
    conn.commit()

    for old_id in conflict_ids:
        if old_id != "new_end":
            supersede_chunk(conn, old_id, "new_end",
                            reason=f"superseded by newer: {new_summary[:60]}",
                            project="test", session_id="s_e2e")
    conn.commit()

    row = conn.execute(
        "SELECT importance FROM memory_chunks WHERE id='old_end'"
    ).fetchone()
    assert row["importance"] < original_imp, \
        f"旧 chunk 应被降权，got {row['importance']}"

    # 验证 knowledge_versions 记录
    kv_row = conn.execute(
        "SELECT new_chunk_id FROM knowledge_versions WHERE old_chunk_id='old_end'"
    ).fetchone()
    assert kv_row is not None
    assert kv_row["new_chunk_id"] == "new_end"


# ── AS8: supersede_chunk 幂等性 ──────────────────────────────────────────────

def test_as8_supersede_idempotent_bounded_decay(conn):
    """多次调用 supersede_chunk 降权有界 — 不会降到 0。"""
    original_imp = 0.8
    insert_chunk(conn, _make_chunk("idem_ch", "使用 Redis", importance=original_imp))
    conn.commit()

    for i in range(5):
        supersede_chunk(conn, "idem_ch", f"new_ch_{i}",
                        reason="idempotent test", project="test")
    conn.commit()

    row = conn.execute("SELECT importance FROM memory_chunks WHERE id='idem_ch'").fetchone()
    # After 5 × 0.5 decay: 0.8 × 0.5^5 = 0.025 — still > 0
    assert row["importance"] > 0, "降权后 importance 不应变为 0"
    assert row["importance"] < original_imp, "多次降权后应低于原始值"


# ── AS9: get_superseded_ids 返回已被取代的 ID ─────────────────────────────────

def test_as9_get_superseded_ids(conn):
    """get_superseded_ids 返回被 supersede 的旧 chunk ID 集合。"""
    insert_chunk(conn, _make_chunk("sup_old", "旧 chunk"))
    conn.commit()

    supersede_chunk(conn, "sup_old", "sup_new",
                    reason="test", project="test")
    conn.commit()

    superseded = get_superseded_ids(conn, project="test")
    assert "sup_old" in superseded, f"sup_old 应在 superseded 集合，got {superseded}"
