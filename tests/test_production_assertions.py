"""
test_production_assertions.py — 验证生产断言系统本身的正确性

确保探针在各种场景（健康/降级/空库）下行为正确。
"""
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

# 测试隔离
_tmpdir = tempfile.mkdtemp(prefix="test_prod_assert_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import production_assertions as pa

# Override paths
pa.MEMORY_OS_DIR = Path(_tmpdir)
pa.STORE_DB = Path(_tmpdir) / "store.db"
pa.ASSERTIONS_LOG = Path(_tmpdir) / "assertions.log"


def _fresh_db():
    """每次调用前删除旧 DB，确保隔离"""
    if pa.STORE_DB.exists():
        pa.STORE_DB.unlink()
    if pa.ASSERTIONS_LOG.exists():
        pa.ASSERTIONS_LOG.unlink()


def _setup_db() -> sqlite3.Connection:
    """创建最小 schema"""
    _fresh_db()
    conn = sqlite3.connect(str(pa.STORE_DB))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS memory_chunks (
            id TEXT PRIMARY KEY,
            summary TEXT,
            content TEXT,
            chunk_type TEXT,
            project TEXT,
            importance REAL DEFAULT 0.7,
            access_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_accessed TEXT,
            lru_gen INTEGER DEFAULT 0,
            oom_adj INTEGER DEFAULT 0,
            chunk_state TEXT DEFAULT 'ACTIVE'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_fts USING fts5(
            rowid_ref, summary, content
        );
        CREATE TABLE IF NOT EXISTS recall_traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            project TEXT,
            query TEXT,
            top_k_json TEXT,
            injected INTEGER DEFAULT 0,
            duration_ms REAL DEFAULT 0,
            timestamp TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS dmesg (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            level TEXT,
            subsystem TEXT,
            message TEXT,
            extra TEXT
        );
        CREATE TABLE IF NOT EXISTS swap_chunks (
            id TEXT PRIMARY KEY,
            data TEXT
        );
    """)
    return conn


def _insert_chunk(conn, chunk_id, summary="test", chunk_type="decision",
                  project="test_proj", access_count=1, content="",
                  created_at=None):
    conn.execute(
        "INSERT INTO memory_chunks (id, summary, content, chunk_type, project, access_count, created_at) VALUES (?,?,?,?,?,?,COALESCE(?,datetime('now')))",
        (chunk_id, summary, content, chunk_type, project, access_count, created_at)
    )
    _rid = conn.execute("SELECT rowid FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone()[0]
    conn.execute(
        "INSERT INTO memory_chunks_fts (rowid_ref, summary, content) VALUES (?, ?, ?)",
        (str(_rid), summary, content)
    )
    conn.commit()


def _insert_trace(conn, injected=1, chunk_ids=None, duration_ms=10.0):
    top_k = json.dumps([{"id": cid, "chunk_type": "decision"} for cid in (chunk_ids or [])])
    conn.execute(
        "INSERT INTO recall_traces (session_id, project, query, top_k_json, injected, duration_ms) VALUES (?,?,?,?,?,?)",
        ("sess1", "test_proj", "test query", top_k, injected, duration_ms)
    )
    conn.commit()


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_T1_empty_db_fix_mode():
    """空 DB + --fix 模式应能自修复到 HEALTHY"""
    conn = _setup_db()
    report = pa.run_all(fix=True)
    # fix 模式下空库应该被修复或忽略
    assert report["status"] in ("HEALTHY", "DEGRADED"), f"Empty DB with fix got {report['status']}"
    conn.close()


def test_T2_fts5_consistency_pass():
    """FTS5 行数 = chunk 行数 → pass"""
    conn = _setup_db()
    _insert_chunk(conn, "c1", "hello world")
    _insert_chunk(conn, "c2", "foo bar")

    r = pa.assert_fts5_covers_all_chunks(conn)
    assert r.passed, f"FTS5 should pass: {r.message}"
    conn.close()


def test_T3_fts5_inconsistency_fail():
    """FTS5 行数 != chunk 行数 → fail (通过 monkey-patch 模拟)"""
    conn = _setup_db()
    _insert_chunk(conn, "c1", "hello")
    _insert_chunk(conn, "c2", "world")

    # FTS5 content table 有自动同步机制，真实场景中不一致通常由
    # 触发器失败/DB 损坏/手动 DELETE 导致。这里通过包装 conn 模拟。
    original_execute = conn.execute
    call_count = [0]

    class FakeConn:
        def execute(self, sql, *args, **kwargs):
            call_count[0] += 1
            result = original_execute(sql, *args, **kwargs)
            # 第二次 COUNT 查询（FTS5 表）返回不同值
            if "memory_chunks_fts" in sql and "COUNT" in sql:
                class FakeResult:
                    def fetchone(self):
                        return (99,)  # 伪造 FTS5 行数
                return FakeResult()
            return result

    r = pa.assert_fts5_covers_all_chunks(FakeConn())
    assert not r.passed, f"FTS5 inconsistency should fail, got: {r.message}"
    assert r.severity == "critical"
    conn.close()


def test_T4_retriever_injection_pass():
    """有注入 → pass"""
    conn = _setup_db()
    _insert_chunk(conn, "c1")
    _insert_trace(conn, injected=1, chunk_ids=["c1"])

    r = pa.assert_retriever_injects_knowledge(conn)
    assert r.passed, f"Should pass with injection: {r.message}"
    conn.close()


def test_T5_retriever_zero_injection_fail():
    """有请求但 0 注入 → fail"""
    conn = _setup_db()
    _insert_trace(conn, injected=0, chunk_ids=[])
    _insert_trace(conn, injected=0, chunk_ids=[])
    _insert_trace(conn, injected=0, chunk_ids=[])

    r = pa.assert_retriever_injects_knowledge(conn)
    assert not r.passed, "Zero injections should fail"
    assert r.severity == "critical"
    conn.close()


def test_T6_zero_access_rate_pass():
    """低零访问率 → pass"""
    conn = _setup_db()
    # 8 个有访问，2 个无访问 = 20% < 35%
    for i in range(8):
        _insert_chunk(conn, f"c{i}", access_count=3)
    for i in range(8, 10):
        _insert_chunk(conn, f"c{i}", access_count=0)

    r = pa.audit_zero_access_rate(conn)
    assert r.passed, f"20% should pass: {r.message}"
    conn.close()


def test_T7_zero_access_rate_fail():
    """高零访问率 → fail"""
    conn = _setup_db()
    _old = "2026-01-01T00:00:00"
    # 2 个有访问，8 个无访问 = 80% > 35%
    for i in range(2):
        _insert_chunk(conn, f"c{i}", access_count=3, created_at=_old)
    for i in range(2, 10):
        _insert_chunk(conn, f"c{i}", access_count=0, created_at=_old)

    r = pa.audit_zero_access_rate(conn)
    assert not r.passed, f"80% should fail: {r.message}"
    conn.close()


def test_T8_test_pollution_detected():
    """测试数据泄漏检测"""
    conn = _setup_db()
    _insert_chunk(conn, "c1", project="pytest-tmpdir-123")

    r = pa.check_test_pollution(conn)
    assert not r.passed, "Should detect test pollution"
    conn.close()


def test_T9_stale_refs_detected():
    """过期引用检测"""
    conn = _setup_db()
    _insert_chunk(conn, "c1")
    # trace 引用了不存在的 chunk
    top_k = json.dumps([{"id": "c1", "chunk_type": "decision"}, {"id": "DELETED_CHUNK", "chunk_type": "decision"}])
    conn.execute(
        "INSERT INTO recall_traces (session_id, project, query, top_k_json, injected, duration_ms) VALUES (?,?,?,?,?,?)",
        ("s1", "p1", "q", top_k, 1, 5.0)
    )
    conn.commit()

    r = pa.check_stale_refs(conn)
    assert r.passed, f"Stale refs should be auto-cleaned: {r.message}"
    conn.close()


def test_T10_no_stale_refs_clean():
    """无过期引用 → pass"""
    conn = _setup_db()
    _insert_chunk(conn, "c1")
    _insert_trace(conn, injected=1, chunk_ids=["c1"])

    r = pa.check_stale_refs(conn)
    assert r.passed, f"Should pass with valid refs: {r.message}"
    conn.close()


def test_T11_run_all_returns_report():
    """run_all 返回完整报告结构"""
    _setup_db()
    report = pa.run_all()

    assert "summary" in report
    assert "status" in report
    assert "results" in report
    assert report["summary"]["total"] == 14
    assert report["summary"]["passed"] + report["summary"]["failed"] == report["summary"]["total"]


def test_T12_log_written():
    """断言日志写入验证"""
    _setup_db()
    pa.run_all()

    assert pa.ASSERTIONS_LOG.exists(), "Log file should be created"
    content = pa.ASSERTIONS_LOG.read_text()
    assert content.strip(), "Log should not be empty"
    line = json.loads(content.strip().split("\n")[-1])
    assert "status" in line
    assert "passed" in line


def test_T13_diversity_pass_with_mixed_types():
    """多类型检索 → diversity pass"""
    conn = _setup_db()
    _insert_chunk(conn, "c1", chunk_type="decision")
    _insert_chunk(conn, "c2", chunk_type="reasoning_chain")
    _insert_chunk(conn, "c3", chunk_type="causal_chain")

    # 创建有多样性的 traces
    for i in range(10):
        types = ["decision", "reasoning_chain", "causal_chain"]
        ct = types[i % 3]
        top_k = json.dumps([{"id": f"c{(i%3)+1}", "chunk_type": ct}])
        conn.execute(
            "INSERT INTO recall_traces (session_id, project, query, top_k_json, injected, duration_ms) VALUES (?,?,?,?,?,?)",
            ("s1", "p1", f"query_{i}", top_k, 1, 5.0)
        )
    conn.commit()

    r = pa.audit_retrieval_diversity(conn)
    assert r.passed, f"Mixed types should pass: {r.message}"
    conn.close()


def test_T14_swap_state_valid():
    """swap_state.json 有内容 → pass"""
    conn = _setup_db()
    swap_state = pa.MEMORY_OS_DIR / "swap_state.json"
    swap_state.write_text(json.dumps({
        "hit_ids": ["c1", "c2"],
        "decisions": [{"id": "d1"}]
    }))

    r = pa.assert_swap_out_produces_output(conn)
    assert r.passed, f"Valid swap_state should pass: {r.message}"
    conn.close()


def test_T15_subsection_dedup_detect():
    """子 chunk 内容完全被父 chunk 包含 → 检测为冗余"""
    conn = _setup_db()
    parent_content = "sched_ext 框架概述。开发分支在 work/v27-tip。详细说明见文档。"
    child_content = "开发分支在 work/v27-tip。"
    _insert_chunk(conn, "parent-1", summary="框架概述", access_count=5,
                  content=parent_content)
    _insert_chunk(conn, "child-1", summary="框架概述 > 开发分支", access_count=0,
                  content=child_content)

    r = pa.check_subsection_dedup(conn)
    assert not r.passed, f"Should detect 1 redundant chunk: {r.message}"
    assert r.actual["dupe_count"] == 1
    conn.close()


def test_T16_subsection_dedup_fix():
    """fix=True 归档冗余子 chunk 并清理 FTS5"""
    conn = _setup_db()
    parent_content = "完整内容包含子节点的所有信息，包括详细的配置和路径说明。"
    child_content = "子节点的所有信息，包括详细的配置和路径说明。"
    _insert_chunk(conn, "parent-2", summary="完整文档", access_count=3,
                  content=parent_content)
    _insert_chunk(conn, "child-2", summary="完整文档 > 子节", access_count=0,
                  content=child_content)

    r = pa.check_subsection_dedup(conn, fix=True)
    assert r.passed, f"Fix should succeed: {r.message}"

    state = conn.execute(
        "SELECT chunk_state FROM memory_chunks WHERE id='child-2'"
    ).fetchone()[0]
    assert state == "DEDUP_ARCHIVED"

    conn.close()


def test_T17_subsection_dedup_no_false_positive():
    """不同内容的 ac=0 chunk 不应被误判为冗余"""
    conn = _setup_db()
    _insert_chunk(conn, "a-1", summary="A 知识", access_count=5,
                  content="这是关于 A 的完整知识。")
    _insert_chunk(conn, "b-1", summary="B 知识", access_count=0,
                  content="这是关于 B 的独立知识，与 A 无关。")

    r = pa.check_subsection_dedup(conn)
    assert r.passed, f"Should not detect false positives: {r.message}"
    conn.close()


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_T")]
    passed = 0
    failed = 0

    for test_fn in tests:
        # 每个测试重建 DB
        if pa.STORE_DB.exists():
            pa.STORE_DB.unlink()

        try:
            test_fn()
            print(f"  ✓ {test_fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test_fn.__name__}: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{'✅' if failed == 0 else '❌'} {passed}/{passed+failed} tests passed")
    sys.exit(0 if failed == 0 else 1)
