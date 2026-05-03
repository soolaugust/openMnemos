"""
iter586: proactive_compaction — Fragmentation Index Driven Chunk Consolidation

OS 类比：Linux proactive memory compaction (Nitin Gupta, 2019, kernel 5.9, mm/compaction.c)
— 传统 compaction 仅在 allocation 失败时被动触发。Proactive compaction 在系统空闲时
主动扫描 zone fragmentation index，超过阈值时执行 page migration 整理碎片。

测试验证：
  - Phase 1: Fragmentation index 计算
  - Phase 2: Exact duplicate reap
  - Phase 3: Degenerate chunk demotion
  - 边界条件、保护机制、性能
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
_TEST_DIR = tempfile.mkdtemp(prefix="test_iter586_")
os.environ["MEMORY_OS_DIR"] = _TEST_DIR
os.environ["MEMORY_OS_DB"] = os.path.join(_TEST_DIR, "store.db")

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


def _fresh_conn():
    """Create a fresh in-memory DB with schema for isolated testing."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE IF NOT EXISTS memory_chunks (
        id TEXT PRIMARY KEY, summary TEXT, content TEXT,
        chunk_type TEXT, importance REAL, project TEXT,
        oom_adj INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT,
        source_session TEXT, tags TEXT, last_accessed TEXT,
        access_count INTEGER DEFAULT 0, retrievability REAL,
        source_reliability REAL, emotional_weight REAL,
        emotional_valence REAL, confidence_score REAL,
        verification_status TEXT, lru_gen INTEGER,
        raw_snippet TEXT, encoding_context TEXT, info_class TEXT
    )""")
    conn.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_fts
        USING fts5(rowid_ref, summary, content, tokenize='unicode61')""")
    return conn


def _insert(conn, id, summary, content, chunk_type="decision",
            importance=0.8, project="global", oom_adj=0, access_count=0):
    """Direct insert into test DB."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO memory_chunks (id, summary, content, chunk_type, importance, "
        "project, oom_adj, created_at, updated_at, source_session, tags, "
        "last_accessed, access_count, retrievability, source_reliability, "
        "emotional_weight, emotional_valence, confidence_score, "
        "verification_status, lru_gen, raw_snippet, encoding_context, info_class) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (id, summary, content, chunk_type, importance, project, oom_adj,
         now, now, "test-iter586", "[]", now, access_count, 1.0, 0.7,
         0.0, 0.0, 0.7, "unverified", 0, "", "{}", "world"))
    conn.execute(
        "INSERT INTO memory_chunks_fts (rowid_ref, summary, content) VALUES (?,?,?)",
        (id, summary, content))


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Exact duplicates are detected and removed
# ═══════════════════════════════════════════════════════════════════════════════
def test_exact_duplicates_removed():
    print("\n[Test 1] Exact duplicates removed")
    conn = _fresh_conn()
    # 4 identical chunks (3 extras → frag ≥ 0.3)
    for i in range(4):
        _insert(conn, f"dup-{i}",
                "核心变更：CRITICAL 不再停机，自动从第一性原理修复",
                "核心变更：CRITICAL 不再停机，自动从第一性原理修复",
                "conversation_summary", access_count=(2 if i == 0 else 0))
    # 6 normal chunks
    for i in range(6):
        _insert(conn, f"normal-{i}", f"短摘要 {i}",
                f"完全不同的独立内容，与摘要无关 chunk_{i}" * 3,
                access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    test("triggered=True", result["triggered"])
    test("exact_dups_deleted=3", result["exact_dups_deleted"] == 3)

    remaining = conn.execute("SELECT id FROM memory_chunks WHERE id LIKE 'dup-%'").fetchall()
    test("survivor kept (highest access)", len(remaining) == 1 and remaining[0][0] == "dup-0")
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Degenerate chunks are demoted
# ═══════════════════════════════════════════════════════════════════════════════
def test_degenerate_demoted():
    print("\n[Test 2] Degenerate chunks demoted")
    conn = _fresh_conn()
    # Degenerate: content is substring of summary, access=0
    _insert(conn, "degen-1",
            "冷启动保护：< 2 samples 不触发 throttle 详细描述",
            "冷启动保护：< 2 samples",
            access_count=0)
    _insert(conn, "degen-2",
            "释放 163.7KB，cold_sync 854→200 条完整版说明",
            "释放 163.7KB",
            access_count=0)
    _insert(conn, "degen-3",
            "检索不是瓶颈生成才是完整分析报告内容",
            "检索不是瓶颈",
            access_count=0)
    # 7 normal to ensure frag > 0.25 (3 degen / 10 = 0.3)
    for i in range(7):
        _insert(conn, f"normal-{i}", f"短摘要 {i}",
                f"独立内容段落与摘要完全不同的文字 {i}" * 3,
                access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    test("triggered=True", result["triggered"])
    test("degenerate_demoted=3", result["degenerate_demoted"] == 3)

    row = conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='degen-1'").fetchone()
    test("oom_adj demoted to 150", row[0] == 150)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: mlock protected chunks not touched
# ═══════════════════════════════════════════════════════════════════════════════
def test_mlock_protected():
    print("\n[Test 3] mlock protected chunks not touched")
    conn = _fresh_conn()
    _insert(conn, "mlock-1", "飞书 CLI 约束",
            "飞书文档/wiki 访问必须用 feishu CLI",
            "design_constraint", oom_adj=-500)
    _insert(conn, "mlock-2", "飞书 CLI 约束",
            "飞书文档/wiki 访问必须用 feishu CLI",
            "design_constraint", oom_adj=0)
    # Filler degenerate for threshold
    for i in range(8):
        _insert(conn, f"degen-{i}",
                f"一段很长的 summary 包含很多信息 {i} 额外文字",
                f"一段很长的",
                access_count=0)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    mlock_exists = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE id='mlock-1'").fetchone()[0]
    test("mlock-1 preserved", mlock_exists == 1)
    # Non-mlock dup should be deleted
    non_mlock = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE id='mlock-2'").fetchone()[0]
    test("mlock-2 deleted (non-protected dup)", non_mlock == 0)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Below frag_threshold → not triggered
# ═══════════════════════════════════════════════════════════════════════════════
def test_below_threshold():
    print("\n[Test 4] Below frag_threshold → not triggered")
    conn = _fresh_conn()
    # All normal chunks, no degenerate/dups — content much longer than summary
    for i in range(10):
        _insert(conn, f"normal-{i}", f"短摘要 {i}",
                f"这段内容比摘要长得多包含完全不同独立技术细节背景信息 number {i}" * 3,
                access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    test("triggered=False", not result["triggered"])
    test("frag_index=0.0", result["frag_index"] == 0.0)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Disabled via config
# ═══════════════════════════════════════════════════════════════════════════════
def test_disabled():
    print("\n[Test 5] Disabled via config")
    conn = _fresh_conn()
    for i in range(5):
        _insert(conn, f"dup-{i}", "same summary",
                "same content that repeats", access_count=0)
    conn.commit()

    from config import sysctl_set
    sysctl_set("proactive_compaction.enabled", False)

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)
    test("not triggered when disabled", not result["triggered"])

    sysctl_set("proactive_compaction.enabled", True)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: max_actions_per_scan limits work
# ═══════════════════════════════════════════════════════════════════════════════
def test_max_actions_limit():
    print("\n[Test 6] max_actions_per_scan limits work")
    conn = _fresh_conn()
    for i in range(10):
        _insert(conn, f"dup-{i}", "identical",
                "identical content that is exactly the same across all ten",
                access_count=0)
    conn.commit()

    from config import sysctl_set
    sysctl_set("proactive_compaction.max_actions_per_scan", 3)

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    total_actions = result["exact_dups_deleted"] + result["degenerate_demoted"]
    test("actions limited to 3", total_actions <= 3)

    sysctl_set("proactive_compaction.max_actions_per_scan", 20)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Accessed chunks not demoted
# ═══════════════════════════════════════════════════════════════════════════════
def test_accessed_not_demoted():
    print("\n[Test 7] Accessed degenerate chunks not demoted")
    conn = _fresh_conn()
    # Degenerate but has access_count > 0
    _insert(conn, "degen-accessed",
            "这是一个带有访问记录的退化 chunk 完整描述",
            "退化 chunk", access_count=3)
    # More degenerate for threshold
    for i in range(9):
        _insert(conn, f"degen-{i}",
                f"退化 chunk 系列很长 summary 第 {i} 个额外描述信息",
                f"退化 chunk", access_count=0)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    row = conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='degen-accessed'").fetchone()
    test("accessed chunk oom_adj unchanged", row[0] == 0)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Empty DB → no crash
# ═══════════════════════════════════════════════════════════════════════════════
def test_empty_db():
    print("\n[Test 8] Empty DB → no crash")
    conn = _fresh_conn()
    from store_mm import proactive_compaction
    result = proactive_compaction(conn)
    test("no crash, triggered=False", not result["triggered"])
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: Fragmentation index calculation
# ═══════════════════════════════════════════════════════════════════════════════
def test_frag_index_calculation():
    print("\n[Test 9] Fragmentation index calculation")
    conn = _fresh_conn()
    # 3 degenerate + 2 dup pairs (2 extras) = 5 items / 10 = 0.5
    for i in range(3):
        _insert(conn, f"degen-{i}",
                f"长 summary 确保 content 是子串 number {i} extra words",
                f"长 summary", access_count=0)
    _insert(conn, "dp-a1", "dup A", "duplicate A content body text", access_count=0)
    _insert(conn, "dp-a2", "dup A", "duplicate A content body text", access_count=0)
    _insert(conn, "dp-b1", "dup B", "duplicate B content body text", access_count=0)
    _insert(conn, "dp-b2", "dup B", "duplicate B content body text", access_count=0)
    # 3 normal
    for i in range(3):
        _insert(conn, f"norm-{i}", f"norm {i}",
                f"unique long content paragraph for norm chunk {i}" * 2,
                access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    # frag = (3 degen + 2 dup extras) / 10 = 0.5
    test("frag_index ~ 0.5", 0.3 <= result["frag_index"] <= 0.7)
    test("triggered at high frag", result["triggered"])
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Different chunk_types not considered duplicates
# ═══════════════════════════════════════════════════════════════════════════════
def test_different_types_not_dup():
    print("\n[Test 10] Different chunk_types not considered duplicates")
    conn = _fresh_conn()
    _insert(conn, "type-a", "same summary",
            "same content that could look like a duplicate",
            "decision")
    _insert(conn, "type-b", "same summary",
            "same content that could look like a duplicate",
            "design_constraint")
    # Degenerate filler for threshold
    for i in range(8):
        _insert(conn, f"degen-{i}",
                f"退化 chunk 为了达到碎片阈值 number {i} extra",
                f"退化", access_count=0)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    both_exist = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE id IN ('type-a', 'type-b')").fetchone()[0]
    test("both types preserved", both_exist == 2)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 11: Performance — 200 chunks < 50ms
# ═══════════════════════════════════════════════════════════════════════════════
def test_performance():
    print("\n[Test 11] Performance: 200 chunks < 50ms")
    conn = _fresh_conn()
    for i in range(200):
        _insert(conn, f"perf-{i}",
                f"性能测试 chunk {i} with some text extra words for length",
                f"性能测试 chunk" if i % 3 == 0 else f"unique content paragraph for perf {i}" * 2,
                access_count=(0 if i % 2 == 0 else 1))
    conn.commit()

    from store_mm import proactive_compaction
    t0 = time.time()
    result = proactive_compaction(conn)
    elapsed = (time.time() - t0) * 1000

    test(f"elapsed {elapsed:.1f}ms < 50ms", elapsed < 50)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 12: Idempotent — second run after compaction
# ═══════════════════════════════════════════════════════════════════════════════
def test_idempotent():
    print("\n[Test 12] Idempotent — second run has fewer actions")
    conn = _fresh_conn()
    for i in range(5):
        _insert(conn, f"dup-{i}", "same summary",
                "same content for idempotent test", access_count=0)
    for i in range(5):
        _insert(conn, f"norm-{i}", f"normal {i}",
                f"unique content for normal chunk {i}" * 3, access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    r1 = proactive_compaction(conn)
    test("first run triggered", r1["triggered"])
    test("first run deleted dups", r1["exact_dups_deleted"] > 0)

    r2 = proactive_compaction(conn)
    test("second run no dups to delete", r2["exact_dups_deleted"] == 0)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 13: Config tunables registered
# ═══════════════════════════════════════════════════════════════════════════════
def test_config_registered():
    print("\n[Test 13] Config tunables registered")
    from config import get as _cfg
    test("enabled registered", _cfg("proactive_compaction.enabled") is not None)
    test("frag_threshold registered", _cfg("proactive_compaction.frag_threshold") is not None)
    test("demote_oom_adj registered", _cfg("proactive_compaction.demote_oom_adj") is not None)
    test("max_actions registered", _cfg("proactive_compaction.max_actions_per_scan") is not None)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 14: Very short content (≤ 5 chars) not treated as duplicate
# ═══════════════════════════════════════════════════════════════════════════════
def test_short_content_ignored():
    print("\n[Test 14] Very short content ignored for dup detection")
    conn = _fresh_conn()
    for i in range(5):
        _insert(conn, f"tiny-{i}", f"summary {i}", "ab", access_count=0)
    for i in range(5):
        _insert(conn, f"norm-{i}", f"normal {i}",
                f"enough content to not be degenerate {i}" * 3, access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    test("no exact_dups from tiny content", result["exact_dups_deleted"] == 0)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 15: Production simulation — mixed scenario
# ═══════════════════════════════════════════════════════════════════════════════
def test_production_simulation():
    print("\n[Test 15] Production simulation — mixed scenario")
    conn = _fresh_conn()

    # 4 exact dups (conversation_summary)
    for i in range(4):
        _insert(conn, f"conv-{i}",
                "核心变更：CRITICAL 不再停机，自动从第一性原理修复",
                "核心变更：CRITICAL 不再停机，自动从第一性原理修复",
                "conversation_summary", access_count=0)

    # 4 degenerate decision chunks
    for i in range(4):
        _insert(conn, f"degen-{i}",
                f"迭代记录第 {i} 项某个优化效果很好的描述文字额外信息",
                f"迭代记录第 {i}",
                access_count=0)

    # 5 healthy chunks
    for i in range(5):
        _insert(conn, f"healthy-{i}", f"健康 chunk {i}",
                f"这是一段独立的有意义的知识内容与 summary 完全不同提供额外信息 {i}" * 2,
                "design_constraint", access_count=3)

    conn.commit()

    from store_mm import proactive_compaction
    result = proactive_compaction(conn)

    test("triggered", result["triggered"])
    test("dups deleted = 3", result["exact_dups_deleted"] == 3)
    test("degenerate demoted >= 3", result["degenerate_demoted"] >= 3)

    healthy_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE id LIKE 'healthy-%'").fetchone()[0]
    test("healthy chunks preserved", healthy_count == 5)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 16: FTS5 cleaned for deleted duplicates
# ═══════════════════════════════════════════════════════════════════════════════
def test_fts5_cleaned():
    print("\n[Test 16] FTS5 entries removed for deleted duplicates")
    conn = _fresh_conn()
    for i in range(4):
        _insert(conn, f"dup-{i}", "FTS5清理测试",
                "FTS5 cleanup test content identical across all four",
                access_count=(5 if i == 0 else 0))
    for i in range(6):
        _insert(conn, f"norm-{i}", f"normal {i}",
                f"unique content paragraph {i}" * 3, access_count=1)
    conn.commit()

    from store_mm import proactive_compaction
    proactive_compaction(conn)

    fts_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts WHERE rowid_ref IN ('dup-1', 'dup-2', 'dup-3')"
    ).fetchone()[0]
    test("FTS5 entries removed", fts_count == 0)

    survivor_fts = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks_fts WHERE rowid_ref = 'dup-0'"
    ).fetchone()[0]
    test("survivor FTS5 preserved", survivor_fts == 1)
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("iter586: proactive_compaction — unit tests")
    print("=" * 60)

    test_exact_duplicates_removed()
    test_degenerate_demoted()
    test_mlock_protected()
    test_below_threshold()
    test_disabled()
    test_max_actions_limit()
    test_accessed_not_demoted()
    test_empty_db()
    test_frag_index_calculation()
    test_different_types_not_dup()
    test_performance()
    test_idempotent()
    test_config_registered()
    test_short_content_ignored()
    test_production_simulation()
    test_fts5_cleaned()

    print(f"\n{'=' * 60}")
    print(f"Results: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    print(f"{'=' * 60}")
    sys.exit(0 if FAIL == 0 else 1)
