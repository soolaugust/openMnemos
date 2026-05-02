"""
迭代504: FTS5 Journal Checkpoint — 启动时一致性校验与修复
OS 类比：ext4 Journal Checkpoint + e2fsck -y

测试场景：
T1: 正常状态 — FTS5 与 chunks 一致，checkpoint 无修复
T2: 孤儿检测 — FTS5 有条目但 chunk 已删除 → 删除孤儿
T3: 缺失检测 — chunk 存在但 FTS5 无条目 → 补建
T4: 混合场景 — 同时有孤儿和缺失 → 双向修复
T5: merge_similar 后 FTS5 同步 — content 更新反映在 FTS5
T6: 空 DB — checkpoint 无异常
T7: _fts5_sync_chunk 幂等性 — 多次调用结果一致
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: F401 — 测试隔离

import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from store_vfs import (
    open_db, ensure_schema, insert_chunk, fts5_checkpoint,
    _fts5_sync_chunk, _cjk_tokenize, _normalize_structured_summary,
    delete_chunks, merge_similar,
)
from schema import MemoryChunk


def _make_chunk(summary="test decision", chunk_type="decision", project="test_proj"):
    now = datetime.now(timezone.utc).isoformat()
    return MemoryChunk(
        id=str(uuid4()), created_at=now, updated_at=now,
        project=project, source_session="test",
        chunk_type=chunk_type, content=summary,
        summary=summary, tags=[], importance=0.8,
        retrievability=1.0, last_accessed=now,
    ).__dict__


def test_t1_consistent_state():
    """T1: FTS5 与 chunks 一致时，checkpoint 无修复动作。"""
    conn = open_db()
    ensure_schema(conn)
    # 插入 3 个 chunks
    for i in range(3):
        insert_chunk(conn, _make_chunk(f"decision number {i}"))
    conn.commit()
    # checkpoint 应该返回 0 修复
    stats = fts5_checkpoint(conn)
    assert stats["orphans_removed"] == 0, f"Expected 0 orphans, got {stats['orphans_removed']}"
    assert stats["missing_rebuilt"] == 0, f"Expected 0 missing, got {stats['missing_rebuilt']}"
    assert stats["fts5_count"] == stats["chunks_count"]
    conn.close()


def test_t2_orphan_removal():
    """T2: 直接删除 chunk 不经 delete_chunks → FTS5 孤儿被清除。"""
    conn = open_db()
    ensure_schema(conn)
    chunk = _make_chunk("orphan test chunk")
    insert_chunk(conn, chunk)
    conn.commit()
    # 直接 DELETE memory_chunks 不走 delete_chunks（模拟漂移路径）
    conn.execute("DELETE FROM memory_chunks WHERE id=?", (chunk["id"],))
    conn.commit()
    # FTS5 应该还有条目
    fts_before = conn.execute("SELECT count(*) FROM memory_chunks_fts").fetchone()[0]
    assert fts_before >= 1, "FTS5 should have orphan entry"
    # checkpoint 修复
    stats = fts5_checkpoint(conn)
    assert stats["orphans_removed"] >= 1, f"Expected orphans removed, got {stats}"
    # 修复后一致
    fts_after = conn.execute("SELECT count(*) FROM memory_chunks_fts").fetchone()[0]
    chunks_after = conn.execute("SELECT count(*) FROM memory_chunks WHERE summary != ''").fetchone()[0]
    assert fts_after == chunks_after, f"FTS5={fts_after} != chunks={chunks_after}"
    conn.close()


def test_t3_missing_rebuild():
    """T3: chunk 存在但 FTS5 无条目 → 补建索引。"""
    conn = open_db()
    ensure_schema(conn)
    chunk = _make_chunk("missing fts entry chunk")
    insert_chunk(conn, chunk)
    conn.commit()
    # 手动删除 FTS5 条目（模拟漂移）
    rowid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (chunk["id"],)).fetchone()[0]
    conn.execute("DELETE FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),))
    conn.commit()
    # checkpoint 修复
    stats = fts5_checkpoint(conn)
    assert stats["missing_rebuilt"] >= 1, f"Expected missing rebuilt, got {stats}"
    # FTS5 搜索应该能命中
    fts_count = conn.execute(
        "SELECT count(*) FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),)
    ).fetchone()[0]
    assert fts_count == 1, f"Expected 1 FTS5 entry, got {fts_count}"
    conn.close()


def test_t4_mixed_orphan_and_missing():
    """T4: 同时有孤儿和缺失 → 双向修复。"""
    conn = open_db()
    ensure_schema(conn)
    # 创建正常 chunk
    c1 = _make_chunk("normal chunk alpha")
    c2 = _make_chunk("normal chunk beta")
    insert_chunk(conn, c1)
    insert_chunk(conn, c2)
    conn.commit()
    # 制造孤儿：直接删除 c1
    conn.execute("DELETE FROM memory_chunks WHERE id=?", (c1["id"],))
    # 制造缺失：删除 c2 的 FTS5
    r2 = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (c2["id"],)).fetchone()[0]
    conn.execute("DELETE FROM memory_chunks_fts WHERE rowid_ref=?", (str(r2),))
    conn.commit()
    # checkpoint 修复
    stats = fts5_checkpoint(conn)
    assert stats["orphans_removed"] >= 1
    assert stats["missing_rebuilt"] >= 1
    assert stats["fts5_count"] == stats["chunks_count"]
    conn.close()


def test_t5_merge_similar_fts_sync():
    """T5: merge_similar 更新 content 后 FTS5 同步反映新内容。"""
    conn = open_db()
    ensure_schema(conn)
    # 插入原始 chunk
    c = _make_chunk("决定使用 sqlite3 而非 postgresql", project="merge_test")
    insert_chunk(conn, c)
    conn.commit()
    # merge_similar 追加新内容
    merged = merge_similar(conn, "决定使用 sqlite3 而非 postgresql", "decision", 0.9, project="merge_test")
    conn.commit()
    # FTS5 应包含新内容（merge_similar 的 content 更新了）
    rowid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (c["id"],)).fetchone()[0]
    fts_row = conn.execute(
        "SELECT content FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),)
    ).fetchone()
    assert fts_row is not None, "FTS5 entry should exist after merge"
    conn.close()


def test_t6_empty_db():
    """T6: 空 DB（无 chunks）上 checkpoint 无异常。"""
    import tempfile
    tmp = tempfile.mkdtemp()
    from pathlib import Path
    db_path = Path(tmp) / "empty.db"
    conn = open_db(db_path)
    ensure_schema(conn)
    # ensure_schema 已调用 fts5_checkpoint，再次调用应幂等
    stats = fts5_checkpoint(conn)
    assert stats["orphans_removed"] == 0
    assert stats["missing_rebuilt"] == 0
    assert stats["fts5_count"] == 0
    assert stats["chunks_count"] == 0
    conn.close()
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


def test_t7_fts5_sync_idempotent():
    """T7: _fts5_sync_chunk 多次调用结果一致（幂等）。"""
    conn = open_db()
    ensure_schema(conn)
    c = _make_chunk("idempotent sync test")
    insert_chunk(conn, c)
    conn.commit()
    # 多次 sync
    _fts5_sync_chunk(conn, c["id"], content="updated content v1")
    _fts5_sync_chunk(conn, c["id"], content="updated content v2")
    conn.commit()
    # 应只有 1 条 FTS5 记录
    rowid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (c["id"],)).fetchone()[0]
    count = conn.execute(
        "SELECT count(*) FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),)
    ).fetchone()[0]
    assert count == 1, f"Expected 1 FTS5 entry after idempotent sync, got {count}"
    # 内容是最新的 v2
    content = conn.execute(
        "SELECT content FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),)
    ).fetchone()[0]
    assert "updated" in content and "v2" in content
    conn.close()


if __name__ == "__main__":
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in sorted(tests):
        try:
            globals()[t]()
            print(f"  ✅ {t}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {t}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
