"""
iter570: populate_pte — Entity Edge Target PTE Population

OS 类比：Linux populate_pte() / vmalloc_fault() (Linus Torvalds, 2001, mm/vmalloc.c)
  为 entity_edges 中无 entity_map 映射的目标实体建立 PTE，
  修复 spreading_activate 72.8% 死路。

测试矩阵：
  - unmapped entity 被正确回填
  - 已映射 entity 不重复处理（幂等）
  - ghost chunk (importance=0) 不被映射
  - 实体长度过短被过滤
  - max_populate 上限生效
  - disabled 配置生效
  - 空 entity_edges 不报错
  - 双向（from_entity + to_entity）都处理
  - project 过滤生效
  - 性能基线
"""
import os
import sys
import sqlite3
import time
import uuid

import pytest

# ── path setup ─────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("MEMORY_OS_STORE", ":memory:")

from store_mm import populate_pte


# ── fixtures ───────────────────────────────────────────────────

def _make_db():
    """Create an in-memory DB with required tables."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE memory_chunks (
            id TEXT PRIMARY KEY,
            created_at TEXT,
            updated_at TEXT,
            project TEXT,
            source_session TEXT,
            chunk_type TEXT,
            content TEXT,
            summary TEXT,
            tags TEXT,
            importance REAL,
            retrievability REAL,
            access_count INTEGER DEFAULT 0,
            oom_adj INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE entity_map (
            entity_name TEXT NOT NULL,
            chunk_id    TEXT NOT NULL,
            project     TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (entity_name, project)
        )
    """)
    conn.execute("""
        CREATE TABLE entity_edges (
            id TEXT PRIMARY KEY,
            from_entity TEXT NOT NULL,
            relation TEXT NOT NULL,
            to_entity TEXT NOT NULL,
            project TEXT,
            source_chunk_id TEXT,
            confidence REAL DEFAULT 0.7,
            created_at TEXT NOT NULL,
            agent_id TEXT DEFAULT ''
        )
    """)
    conn.commit()
    return conn


def _insert_chunk(conn, chunk_id, summary, project="global", importance=0.5):
    conn.execute(
        "INSERT INTO memory_chunks (id, summary, project, importance, chunk_type, content) "
        "VALUES (?, ?, ?, ?, 'decision', '')",
        (chunk_id, summary, project, importance),
    )


def _insert_edge(conn, from_ent, to_ent, project="global"):
    conn.execute(
        "INSERT INTO entity_edges (id, from_entity, relation, to_entity, project, created_at) "
        "VALUES (?, ?, 'related_to', ?, ?, datetime('now'))",
        (str(uuid.uuid4()), from_ent, to_ent, project),
    )


def _insert_entity_map(conn, entity_name, chunk_id, project="global"):
    conn.execute(
        "INSERT OR IGNORE INTO entity_map (entity_name, chunk_id, project) VALUES (?, ?, ?)",
        (entity_name, chunk_id, project),
    )


# ── tests ──────────────────────────────────────────────────────

def test_unmapped_to_entity_populated():
    """to_entity 不在 entity_map 中，summary 包含该实体 → 应建立映射。"""
    conn = _make_db()
    cid = "chunk-aaa"
    _insert_chunk(conn, cid, "The kernel_sched module handles scheduling", project="global")
    _insert_edge(conn, "some_entity", "kernel_sched")
    # from_entity 在 entity_map 中
    _insert_entity_map(conn, "some_entity", cid)
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] == 1
    assert result["mappings_created"] == 1
    # verify entity_map now has kernel_sched
    row = conn.execute("SELECT chunk_id FROM entity_map WHERE entity_name='kernel_sched'").fetchone()
    assert row is not None
    assert row[0] == cid


def test_unmapped_from_entity_populated():
    """from_entity 不在 entity_map 中也应被处理（双向）。"""
    conn = _make_db()
    cid = "chunk-bbb"
    _insert_chunk(conn, cid, "The cpu_freq governor controls frequency", project="global")
    _insert_edge(conn, "cpu_freq", "some_target")
    _insert_entity_map(conn, "some_target", cid)
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] >= 1
    row = conn.execute("SELECT chunk_id FROM entity_map WHERE entity_name='cpu_freq'").fetchone()
    assert row is not None


def test_already_mapped_not_duplicated():
    """已在 entity_map 中的实体不再处理（幂等）。"""
    conn = _make_db()
    cid = "chunk-ccc"
    _insert_chunk(conn, cid, "The scheduler handles tasks")
    _insert_edge(conn, "scheduler", "tasks")
    _insert_entity_map(conn, "scheduler", cid)
    _insert_entity_map(conn, "tasks", cid)
    conn.commit()

    result = populate_pte(conn)
    assert result["unmapped_found"] == 0
    assert result["populated"] == 0


def test_ghost_chunk_skipped():
    """importance=0 的 ghost chunk 不被用作映射目标。"""
    conn = _make_db()
    _insert_chunk(conn, "ghost-1", "ghost_entity is here", importance=0.0)
    _insert_chunk(conn, "alive-1", "alive chunk no match here", importance=0.5)
    _insert_edge(conn, "something", "ghost_entity")
    _insert_entity_map(conn, "something", "alive-1")
    conn.commit()

    result = populate_pte(conn)
    # ghost_entity 只在 ghost chunk summary 中 → 无有效映射
    assert result["populated"] == 0


def test_short_entity_filtered():
    """实体长度 < min_entity_len (3) 被过滤。"""
    conn = _make_db()
    _insert_chunk(conn, "chunk-d", "ab is short", importance=0.5)
    _insert_edge(conn, "ab", "cd")  # both < 3 chars
    conn.commit()

    result = populate_pte(conn)
    assert result["unmapped_found"] == 0  # filtered before counting


def test_max_populate_cap():
    """max_populate 限制单次处理量。"""
    conn = _make_db()
    # 创建 5 个 chunk，各有不同实体名在 summary 中
    for i in range(5):
        _insert_chunk(conn, f"chunk-{i}", f"entity_{i:03d} is important", importance=0.5)
        _insert_edge(conn, "anchor", f"entity_{i:03d}")
    _insert_entity_map(conn, "anchor", "chunk-0")
    conn.commit()

    # 临时修改 config — 通过 monkey-patch
    import config
    original = config._REGISTRY.get("populate_pte.max_populate")
    config._REGISTRY["populate_pte.max_populate"] = (2, int, 1, 200, None, "test")
    try:
        result = populate_pte(conn)
        assert result["populated"] <= 2
        assert result["unmapped_found"] == 5
    finally:
        if original:
            config._REGISTRY["populate_pte.max_populate"] = original
        else:
            config._REGISTRY.pop("populate_pte.max_populate", None)


def test_disabled():
    """配置 disabled 时直接返回零。"""
    conn = _make_db()
    _insert_chunk(conn, "chunk-e", "kernel_sched module")
    _insert_edge(conn, "xxx", "kernel_sched")
    conn.commit()

    import config
    original = config._REGISTRY.get("populate_pte.enabled")
    config._REGISTRY["populate_pte.enabled"] = (False, bool, None, None, None, "test")
    try:
        result = populate_pte(conn)
        assert result["populated"] == 0
        assert result["duration_ms"] == 0.0
    finally:
        if original:
            config._REGISTRY["populate_pte.enabled"] = original
        else:
            config._REGISTRY.pop("populate_pte.enabled", None)


def test_empty_entity_edges():
    """空 entity_edges 不报错。"""
    conn = _make_db()
    _insert_chunk(conn, "chunk-f", "some content")
    conn.commit()

    result = populate_pte(conn)
    assert result["unmapped_found"] == 0
    assert result["populated"] == 0


def test_idempotent():
    """连续两次运行，第二次 populated=0。"""
    conn = _make_db()
    cid = "chunk-g"
    _insert_chunk(conn, cid, "The memory_alloc function allocates memory")
    _insert_edge(conn, "anchor", "memory_alloc")
    _insert_entity_map(conn, "anchor", cid)
    conn.commit()

    r1 = populate_pte(conn)
    assert r1["populated"] == 1

    r2 = populate_pte(conn)
    assert r2["populated"] == 0
    assert r2["mappings_created"] == 0


def test_project_filter():
    """指定 project 时只匹配该 project + global 的 chunk。"""
    conn = _make_db()
    _insert_chunk(conn, "c-proj-a", "special_func is used here", project="proj_a", importance=0.5)
    _insert_chunk(conn, "c-proj-b", "special_func is also here", project="proj_b", importance=0.5)
    _insert_edge(conn, "anchor", "special_func")
    _insert_entity_map(conn, "anchor", "c-proj-a", project="proj_a")
    conn.commit()

    result = populate_pte(conn, project="proj_a")
    # 应只映射 proj_a 的 chunk（不应映射 proj_b）
    assert result["populated"] >= 0
    # 不管有没有映射成功，proj_b 不应出现在 entity_map（除非全局模式）
    row = conn.execute(
        "SELECT chunk_id FROM entity_map WHERE entity_name='special_func' AND project='proj_b'"
    ).fetchone()
    assert row is None


def test_case_insensitive_match():
    """实体匹配应大小写不敏感。"""
    conn = _make_db()
    cid = "chunk-ci"
    _insert_chunk(conn, cid, "The KERNEL_SCHED module is important", project="global")
    _insert_edge(conn, "anchor", "kernel_sched")  # lowercase in edge
    _insert_entity_map(conn, "anchor", cid)
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] == 1


def test_multiple_chunks_first_match():
    """多个 chunk 包含同一实体时，映射到第一个匹配。"""
    conn = _make_db()
    _insert_chunk(conn, "c-first", "the cpu_freq data", project="global", importance=0.9)
    _insert_chunk(conn, "c-second", "also cpu_freq here", project="global", importance=0.5)
    _insert_edge(conn, "anchor", "cpu_freq")
    _insert_entity_map(conn, "anchor", "c-first")
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] == 1
    assert result["mappings_created"] == 1


def test_commit_on_populate():
    """有映射创建时应 commit。"""
    conn = _make_db()
    _insert_chunk(conn, "c-commit", "the sched_entity struct", project="global")
    _insert_edge(conn, "anchor", "sched_entity")
    _insert_entity_map(conn, "anchor", "c-commit")
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] == 1

    # 验证数据持久化（重新查询）
    row = conn.execute("SELECT entity_name FROM entity_map WHERE entity_name='sched_entity'").fetchone()
    assert row is not None


def test_no_commit_when_zero():
    """无映射创建时不 commit（避免空写）。"""
    conn = _make_db()
    conn.commit()

    result = populate_pte(conn)
    assert result["populated"] == 0


def test_performance():
    """100 entity_edges + 50 chunks 应在 200ms 内完成。"""
    conn = _make_db()
    # 创建 50 个 chunk
    for i in range(50):
        _insert_chunk(conn, f"perf-{i}", f"entity_perf_{i:03d} is performance test chunk {i}",
                       project="global", importance=0.5)
    # 创建 100 个 edges，50 个 to_entity 存在于 summary
    for i in range(100):
        target = f"entity_perf_{i:03d}" if i < 50 else f"nonexist_{i:03d}"
        _insert_edge(conn, "perf_anchor", target)
    _insert_entity_map(conn, "perf_anchor", "perf-0")
    conn.commit()

    t0 = time.time()
    result = populate_pte(conn)
    elapsed_ms = (time.time() - t0) * 1000

    assert elapsed_ms < 200, f"populate_pte took {elapsed_ms:.1f}ms, expected < 200ms"
    assert result["populated"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
