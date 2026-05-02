#!/usr/bin/env python3
"""
test_iter516_madv_free.py — MADV_FREE: Lazy Page Reclaim + FTS5 Exclusion

OS 类比：Linux madvise(MADV_FREE) (Minchan Kim, 2016)
"""
import tmpfs  # noqa: F401 — 测试隔离
import os, sys, pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from store_vfs import open_db, ensure_schema
from store_mm import madv_free_scan

_conn = None


@pytest.fixture(autouse=True)
def fresh_db():
    """每个测试前清空 DB 数据，避免测试间污染。"""
    global _conn
    _conn = open_db()
    ensure_schema(_conn)
    _conn.commit()
    # 清空测试数据
    _conn.execute("DELETE FROM memory_chunks")
    _conn.execute("DELETE FROM memory_chunks_fts")
    _conn.commit()
    yield _conn
    _conn.close()
    _conn = None


def _make_import(chunk_id, project="global", age_days=10,
                 importance=0.15, access_count=0, oom_adj=300,
                 summary="test import chunk"):
    """创建 import 来源的 chunk。"""
    created = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    _conn.execute(
        "INSERT INTO memory_chunks (id, created_at, updated_at, project, source_session, "
        "chunk_type, summary, content, importance, access_count, oom_adj, last_accessed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (chunk_id, created, now, project, "import:wiki",
         "decision", summary, f"content of {chunk_id}",
         importance, access_count, oom_adj, now),
    )
    rowid = _conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone()[0]
    _conn.execute(
        "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
        (str(rowid), summary, f"content of {chunk_id}"),
    )
    _conn.commit()
    return rowid


def _fts5_has(rowid_val):
    return _conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts WHERE rowid_ref=?",
        (str(rowid_val),),
    ).fetchone()[0] > 0


def test_t1_basic_unmap():
    """超过 min_age_days 的 lazy import → FTS5 移除，主表保留"""
    rid = _make_import("t1", age_days=10)
    r = madv_free_scan(_conn)
    _conn.commit()
    assert r["unmapped"] >= 1
    assert _conn.execute("SELECT 1 FROM memory_chunks WHERE id='t1'").fetchone()
    assert not _fts5_has(rid)


def test_t2_basic_free():
    """超过 delete_age_days 的 lazy import → 主表删除"""
    _make_import("t2", age_days=25)
    r = madv_free_scan(_conn)
    _conn.commit()
    assert r["freed"] >= 1
    assert _conn.execute("SELECT 1 FROM memory_chunks WHERE id='t2'").fetchone() is None


def test_t3_skip_non_import():
    """非 import 来源的 chunk 不受影响"""
    created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    _conn.execute(
        "INSERT INTO memory_chunks (id, created_at, updated_at, project, source_session, "
        "chunk_type, summary, content, importance, access_count, oom_adj) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("t3", created, now, "global", "session-abc",
         "decision", "non-import", "content", 0.15, 0, 300),
    )
    _conn.commit()
    r = madv_free_scan(_conn)
    assert r["unmapped"] == 0 and r["freed"] == 0


def test_t4_skip_promoted():
    """已 promote（importance>=0.4）不处理"""
    _make_import("t4", age_days=10, importance=0.75)
    r = madv_free_scan(_conn)
    assert r["unmapped"] == 0 and r["freed"] == 0


def test_t5_skip_accessed():
    """有访问记录不处理"""
    _make_import("t5", age_days=10, access_count=2)
    r = madv_free_scan(_conn)
    assert r["unmapped"] == 0 and r["freed"] == 0


def test_t6_skip_mlock():
    """mlock 保护不处理"""
    _make_import("t6", age_days=10, oom_adj=-500)
    r = madv_free_scan(_conn)
    assert r["unmapped"] == 0 and r["freed"] == 0


def test_t7_skip_young():
    """太新的 chunk 不处理"""
    _make_import("t7", age_days=2)
    r = madv_free_scan(_conn)
    assert r["unmapped"] == 0 and r["freed"] == 0


def test_t8_project_filter():
    """project 过滤只处理指定 project"""
    _make_import("t8a", project="global", age_days=10)
    rid_b = _make_import("t8b", project="other", age_days=10)
    madv_free_scan(_conn, project="global")
    _conn.commit()
    assert _conn.execute("SELECT 1 FROM memory_chunks WHERE id='t8b'").fetchone()
    assert _fts5_has(rid_b)


def test_t9_batch_limit():
    """max_per_scan=60（默认），创建 70 个超过限制"""
    for i in range(70):
        _make_import(f"t9-{i}", age_days=10, summary=f"batch {i}")
    r = madv_free_scan(_conn)
    _conn.commit()
    # 默认 max_per_scan=60，70 个中只处理 60 个
    assert r["total_lazy"] == 60  # LIMIT 60
    assert r["unmapped"] + r["freed"] == 60


def test_t10_empty_db():
    """空库安全"""
    r = madv_free_scan(_conn)
    assert r == {"unmapped": 0, "freed": 0, "total_lazy": 0, "skipped_protected": 0}


def test_t11_fts5_search_exclusion():
    """unmap 后 FTS5 搜索不再返回该 chunk"""
    _make_import("t11", age_days=10, summary="unique_kw_madv_t11")
    pre = _conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts WHERE memory_chunks_fts MATCH 'unique_kw_madv_t11'"
    ).fetchone()[0]
    assert pre >= 1
    madv_free_scan(_conn)
    _conn.commit()
    post = _conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts WHERE memory_chunks_fts MATCH 'unique_kw_madv_t11'"
    ).fetchone()[0]
    assert post == 0


def test_t12_mixed_unmap_and_free():
    """同时有 unmap（10天）和 free（25天）的 chunks"""
    _make_import("t12a", age_days=10)   # → unmap
    _make_import("t12b", age_days=25)   # → free
    r = madv_free_scan(_conn)
    _conn.commit()
    assert r["unmapped"] >= 1
    assert r["freed"] >= 1
    assert _conn.execute("SELECT 1 FROM memory_chunks WHERE id='t12a'").fetchone()
    assert _conn.execute("SELECT 1 FROM memory_chunks WHERE id='t12b'").fetchone() is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
