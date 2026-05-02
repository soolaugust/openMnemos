"""iter519: mem_scrub — ECC Memory Patrol Scrub 测试。"""
import sys, os, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tmpfs  # noqa: F401 — 测试隔离
from store import open_db, ensure_schema
from store_mm import mem_scrub
from datetime import datetime, timezone
import pytest

PROJECT = "test_scrub"


def _make_db():
    conn = open_db()
    ensure_schema(conn)
    return conn


def _insert(conn, summary, chunk_type="decision", importance=0.8,
            content="", oom_adj=0, project=PROJECT):
    cid = f"test-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO memory_chunks "
        "(id, summary, content, chunk_type, importance, source_session, "
        "project, created_at, updated_at, last_accessed, access_count, "
        "lru_gen, oom_adj) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,0,0,?)",
        (cid, summary, content or summary, chunk_type, importance, "test",
         project, now, now, now, oom_adj),
    )
    # FTS5 entry
    rowid = conn.execute(
        "SELECT rowid FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES(?,?,?)",
        (str(rowid), summary, content or summary),
    )
    conn.commit()
    return cid


# ── T1: Repeated merge tags → stripped to clean summary ──

def test_repeated_merge_tags_fixed():
    conn = _make_db()
    bad_summary = (
        "[merged→abc] [merged→def] [merged→ghi] "
        "Android 性能诊断核心规则：Running 慢=资源管控"
    )
    cid = _insert(conn, bad_summary, importance=0.5)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ce_fixed"] >= 1
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert "[merged→" not in row[0]
    assert "Android 性能诊断核心规则" in row[0]
    conn.close()


# ── T2: Single merge tag with high importance → ghost mismatch fixed ──

def test_ghost_importance_mismatch():
    conn = _make_db()
    bad_summary = "[merged→xyz123] 有意义的知识内容超过十个字"
    cid = _insert(conn, bad_summary, importance=0.7)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ce_fixed"] >= 1
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert "[merged→" not in row[0]
    assert "有意义的知识内容" in row[0]
    conn.close()


# ── T3: Single merge tag with low importance → no fix (normal ghost) ──

def test_normal_ghost_not_touched():
    conn = _make_db()
    bad_summary = "[merged→xyz123] some old content"
    cid = _insert(conn, bad_summary, importance=0.0)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    # importance=0.0 < 0.3 threshold → not a ghost mismatch, not repeated → skip
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert row[0] == bad_summary  # unchanged
    conn.close()


# ── T4: Content with duplicate appends → deduplicated ──

def test_content_dup_append():
    conn = _make_db()
    line = "重要的决策内容行一二三四五六七八九十"
    dup_content = "\n".join([line] * 5)
    cid = _insert(conn, line, content=dup_content)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ce_fixed"] >= 1
    row = conn.execute(
        "SELECT content FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert row[0].count(line) == 1  # deduplicated to single occurrence
    conn.close()


# ── T5: Leading punctuation → stripped ──

def test_leading_punctuation_fixed():
    conn = _make_db()
    bad_summary = "：Hook 合并调度方案确认使用 pretool_coalesced"
    cid = _insert(conn, bad_summary)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ce_fixed"] >= 1
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert not row[0].startswith("：")
    assert "Hook 合并调度" in row[0]
    conn.close()


# ── T6: Protected (mlock) chunks → reported but not modified ──

def test_mlock_protected_not_modified():
    conn = _make_db()
    bad_summary = "[merged→a] [merged→b] protected content"
    cid = _insert(conn, bad_summary, oom_adj=-1000)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    # Should detect but NOT modify
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert row[0] == bad_summary  # unchanged
    conn.close()


# ── T7: Clean chunks → no changes ──

def test_clean_chunks_untouched():
    conn = _make_db()
    clean_proj = "test_scrub_clean_only"
    _insert(conn, "正常的干净知识内容没有任何问题abcdef", project=clean_proj)
    _insert(conn, "另一条正常的知识内容应该不会被修改", project=clean_proj)

    result = mem_scrub(conn, clean_proj)
    assert result["ce_fixed"] == 0
    assert result["ue_marked"] == 0
    assert result["scanned"] == 2
    conn.commit()
    conn.close()


# ── T8: Summary that is ONLY merge tags → UE ──

def test_only_merge_tags_ue():
    conn = _make_db()
    bad_summary = "[merged→a] [merged→b] [merged→c]"
    cid = _insert(conn, bad_summary, importance=0.5)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ue_marked"] >= 1
    row = conn.execute(
        "SELECT importance, oom_adj FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert row[0] == 0  # zeroed
    assert row[1] >= 900  # high oom_adj for reclaim
    conn.close()


# ── T9: Global scan (project=None) ──

def test_global_scan():
    conn = _make_db()
    _insert(conn, "[merged→a] [merged→b] content one", project="proj_a")
    _insert(conn, "[merged→c] [merged→d] content two", project="proj_b")

    result = mem_scrub(conn, project=None)
    conn.commit()

    assert result["scanned"] >= 2
    assert result["ce_fixed"] >= 2
    conn.commit()
    conn.close()


# ── T10: max_per_scan limit respected ──

def test_max_per_scan_limit():
    conn = _make_db()
    # Insert 5 corrupted chunks
    for i in range(5):
        _insert(conn, f"[merged→a{i}] [merged→b{i}] content {i}")

    # Patch config to limit to 2
    import config
    orig = config._REGISTRY.get("scrub.max_per_scan")
    config._REGISTRY["scrub.max_per_scan"] = (2, int, 1, 200, None, "test")
    config._disk_config = None  # force reload

    try:
        result = mem_scrub(conn, PROJECT)
        conn.commit()
        # Should fix at most 2 (max_per_scan=2)
        total_fixes = result["ce_fixed"] + result["ue_marked"]
        assert total_fixes <= 2
    finally:
        config._REGISTRY["scrub.max_per_scan"] = orig
        config._disk_config = None
    conn.close()


# ── T11: FTS5 consistency after scrub ──

def test_fts5_consistency_after_scrub():
    conn = _make_db()
    bad_summary = "[merged→x] [merged→y] 重要知识内容关于架构设计"
    cid = _insert(conn, bad_summary)

    mem_scrub(conn, PROJECT)
    conn.commit()

    # Verify FTS5 updated
    chunks = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
    fts = conn.execute("SELECT COUNT(*) FROM memory_chunks_fts").fetchone()[0]
    assert fts == chunks

    # Clean summary should be searchable
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert "架构设计" in row[0]
    conn.close()


# ── T12: Performance — 200 chunks < 100ms ──

def test_performance():
    import time
    conn = _make_db()
    perf_project = "test_perf_scrub"
    for i in range(200):
        _insert(conn, f"正常知识条目编号 {i} 用于性能测试", project=perf_project)

    t0 = time.monotonic()
    result = mem_scrub(conn, perf_project)
    elapsed = (time.monotonic() - t0) * 1000

    assert elapsed < 100, f"scrub took {elapsed:.1f}ms for 200 clean chunks"
    assert result["scanned"] == 200
    assert result["ce_fixed"] == 0
    conn.close()


# ── T13: Leading ） corruption ──

def test_leading_fullwidth_bracket():
    conn = _make_db()
    bad_summary = "）后续内容关于系统架构的重要决策"
    cid = _insert(conn, bad_summary)

    result = mem_scrub(conn, PROJECT)
    conn.commit()

    assert result["ce_fixed"] >= 1
    row = conn.execute(
        "SELECT summary FROM memory_chunks WHERE id=?", (cid,)
    ).fetchone()
    assert row[0].startswith("后续内容")
    conn.close()


# ── T14: Idempotent — second scrub finds nothing ──

def test_idempotent():
    conn = _make_db()
    idem_proj = "test_scrub_idempotent"
    _insert(conn, "[merged→a] [merged→b] 知识内容超过十个字符", project=idem_proj)

    r1 = mem_scrub(conn, idem_proj)
    conn.commit()
    assert r1["ce_fixed"] >= 1

    r2 = mem_scrub(conn, idem_proj)
    assert r2["ce_fixed"] == 0
    assert r2["ue_marked"] == 0
    conn.commit()
    conn.close()
