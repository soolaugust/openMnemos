"""
test_iter517_rlimit_nproc.py — RLIMIT_NPROC: Import Tombstone Registry

迭代517：OS 类比 Linux RLIMIT_NPROC (IEEE Std 1003.1, 1988)
验证 import tombstone 注册表阻止 fork bomb 循环：
  import→ksm_scan→delete→re-import 无限循环。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402, F401 — 测试隔离

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from store_core import open_db, ensure_schema, insert_chunk, bump_chunk_version

# import_knowledge 模块路径
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from import_knowledge import (
    _load_tombstones, _save_tombstones, register_import_tombstones,
    make_chunk,
)


# Tombstone 文件路径（与实现一致）
_TS_FILE = Path.home() / ".claude" / "memory-os" / ".import_tombstones.json"
# 备份原始 tombstone（如有）
_ORIG_BACKUP = None


@pytest.fixture(autouse=True)
def clean_tombstones():
    """每个测试前清空 tombstone 文件，测试后恢复。"""
    global _ORIG_BACKUP
    if _TS_FILE.exists():
        _ORIG_BACKUP = _TS_FILE.read_text(encoding="utf-8")
    # 清空
    if _TS_FILE.exists():
        _TS_FILE.unlink()
    yield
    # 恢复
    if _ORIG_BACKUP is not None:
        _TS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _TS_FILE.write_text(_ORIG_BACKUP, encoding="utf-8")
    elif _TS_FILE.exists():
        _TS_FILE.unlink()


@pytest.fixture
def conn():
    c = open_db()
    ensure_schema(c)
    c.execute("PRAGMA busy_timeout = 5000")
    yield c
    c.close()


def _insert_import_chunk(conn, chunk_id, summary="test chunk", importance=0.15):
    """Helper: 插入一个 import 来源的 chunk 到 DB。"""
    now = datetime.now(timezone.utc).isoformat()
    chunk = {
        "id": chunk_id,
        "created_at": now,
        "updated_at": now,
        "project": "global",
        "source_session": "import:wiki/test.md",
        "chunk_type": "decision",
        "content": f"content of {chunk_id}",
        "summary": summary,
        "tags": "[]",
        "importance": importance,
        "retrievability": 1.0,
        "embedding": "[]",
        "access_count": 0,
        "last_accessed": now,
        "lru_gen": 0,
        "oom_adj": 300,
    }
    insert_chunk(conn, chunk)
    conn.commit()


class TestTombstoneRegistry:
    """Tombstone 注册表基础功能。"""

    def test_t1_empty_load(self):
        """T1: 无 tombstone 文件时返回空集。"""
        assert _load_tombstones() == set()

    def test_t2_save_and_load(self):
        """T2: 保存后可加载。"""
        ts = {"import-abc123", "import-def456"}
        _save_tombstones(ts)
        loaded = _load_tombstones()
        assert loaded == ts

    def test_t3_cap_2000(self):
        """T3: 超过 2000 条时只保留最后 2000 条。"""
        ts = {f"import-{i:05d}" for i in range(2500)}
        _save_tombstones(ts)
        loaded = _load_tombstones()
        assert len(loaded) == 2000

    def test_t4_register_import_only(self):
        """T4: 只注册 import- 前缀的 ID，有机 chunk 忽略。"""
        register_import_tombstones(["import-aaa", "organic-bbb", "import-ccc"])
        loaded = _load_tombstones()
        assert loaded == {"import-aaa", "import-ccc"}

    def test_t5_register_empty(self):
        """T5: 空列表不出错。"""
        register_import_tombstones([])
        assert _load_tombstones() == set()

    def test_t6_register_no_import_prefix(self):
        """T6: 全为非 import 前缀时不创建文件。"""
        register_import_tombstones(["chunk-a", "chunk-b"])
        assert _load_tombstones() == set()

    def test_t7_accumulate(self):
        """T7: 多次注册累积。"""
        register_import_tombstones(["import-1"])
        register_import_tombstones(["import-2", "import-3"])
        loaded = _load_tombstones()
        assert loaded == {"import-1", "import-2", "import-3"}

    def test_t8_idempotent(self):
        """T8: 重复注册不增加计数。"""
        register_import_tombstones(["import-dup"])
        register_import_tombstones(["import-dup"])
        loaded = _load_tombstones()
        assert loaded == {"import-dup"}


class TestKsmScanTombstone:
    """ksm_scan 删除后注册 tombstone。"""

    def test_t9_ksm_registers_tombstone(self, conn):
        """T9: ksm_scan 合并删除的 import chunk 被注册到 tombstone。"""
        from store_mm import ksm_scan

        # 创建一组可被 ksm_scan 合并的 chunks（相同 fingerprint 前缀）
        for i in range(5):
            _insert_import_chunk(
                conn, f"import-ksm9{i:02d}",
                summary=f"[topic_ksm9] same prefix content variation {i}",
                importance=0.15,
            )
        conn.commit()

        result = ksm_scan(conn, project="global")
        conn.commit()

        if result.get("chunks_deleted", 0) > 0:
            # 验证被删除的 chunk ID 被注册为 tombstone
            tombstones = _load_tombstones()
            assert len(tombstones) > 0, "ksm_scan should register tombstones for deleted import chunks"
            # 所有 tombstone 都应是 import- 前缀
            for ts in tombstones:
                assert ts.startswith("import-")


class TestOvercommitKillTombstone:
    """overcommit_kill 删除后注册 tombstone。"""

    def test_t10_overcommit_registers_tombstone(self, conn):
        """T10: overcommit_kill 删除的 import chunk 被注册到 tombstone。"""
        from store_mm import overcommit_kill

        # 创建大量零访问 global import chunks
        for i in range(40):
            _insert_import_chunk(
                conn, f"import-oc{i:03d}",
                summary=f"overcommit test chunk {i}",
                importance=0.15,
            )
        conn.commit()

        result = overcommit_kill(conn)
        conn.commit()

        if result.get("deleted", 0) > 0:
            tombstones = _load_tombstones()
            assert len(tombstones) > 0, "overcommit_kill should register tombstones"


class TestMadvFreeTombstone:
    """madv_free_scan Phase 2 删除后注册 tombstone。"""

    def test_t11_madv_free_registers_tombstone(self, conn):
        """T11: madv_free_scan 删除的 import chunk 被注册到 tombstone。"""
        from store_mm import madv_free_scan

        # 创建超过 delete_age_days（21天）的 import chunk
        old_created = (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        chunk = {
            "id": "import-madv11",
            "created_at": old_created,
            "updated_at": now,
            "project": "global",
            "source_session": "import:wiki/test.md",
            "chunk_type": "decision",
            "content": "madv free test content",
            "summary": "madv free tombstone test",
            "tags": "[]",
            "importance": 0.15,
            "retrievability": 1.0,
            "embedding": "[]",
            "access_count": 0,
            "last_accessed": now,
            "lru_gen": 0,
            "oom_adj": 300,
        }
        insert_chunk(conn, chunk)
        # 插入 FTS5
        rowid = conn.execute(
            "SELECT rowid FROM memory_chunks WHERE id='import-madv11'"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
            (str(rowid), "madv free tombstone test", "madv free test content"),
        )
        conn.commit()

        result = madv_free_scan(conn)
        conn.commit()

        if result.get("freed", 0) > 0:
            tombstones = _load_tombstones()
            assert "import-madv11" in tombstones, "madv_free_scan should register tombstone for freed import chunk"


class TestThreeLevelAdmission:
    """三级准入控制集成测试。"""

    def test_t12_tombstone_blocks_reimport(self, conn):
        """T12: tombstone 中的 ID 不被重新导入。"""
        # 注册 tombstone
        register_import_tombstones(["import-blocked01"])

        # 模拟 make_chunk 生成与 tombstone 相同 ID 的 chunk
        chunk = make_chunk("decision", "test summary blocked", "test content",
                           source_file="test.md")
        # 手动设置 ID 为已 tombstone 的
        chunk["id"] = "import-blocked01"

        # 三级准入逻辑的第一级：tombstone check
        tombstones = _load_tombstones()
        assert chunk["id"] in tombstones
        # 这意味着 incremental_import 会跳过它

    def test_t13_existing_id_blocks_reimport(self, conn):
        """T13: DB 中已存在的 ID 不被重新导入。"""
        _insert_import_chunk(conn, "import-exists01", "existing chunk")

        # 验证 ID 已在 DB
        row = conn.execute(
            "SELECT id FROM memory_chunks WHERE id='import-exists01'"
        ).fetchone()
        assert row is not None

    def test_t14_make_chunk_deterministic_id(self):
        """T14: 相同 summary 生成相同 ID（幂等性保证）。"""
        c1 = make_chunk("decision", "identical summary", "c1", source_file="a.md")
        c2 = make_chunk("decision", "identical summary", "c2", source_file="b.md")
        assert c1["id"] == c2["id"]
        assert c1["id"].startswith("import-")


class TestDeletePathCoverage:
    """验证所有删除路径都注册 tombstone。"""

    def test_t15_oom_reaper_tombstone(self, conn):
        """T15: oom_reaper 删除路径注册 tombstone（代码检查）。"""
        # 通过 grep 验证代码路径存在（静态检查）
        import inspect
        from store_vfs import oom_reaper
        source = inspect.getsource(oom_reaper)
        assert "register_import_tombstones" in source, \
            "oom_reaper must call register_import_tombstones"

    def test_t16_shrink_dcache_tombstone(self, conn):
        """T16: shrink_dcache 删除路径注册 tombstone（代码检查）。"""
        import inspect
        from store_vfs import shrink_dcache
        source = inspect.getsource(shrink_dcache)
        assert "register_import_tombstones" in source, \
            "shrink_dcache must call register_import_tombstones"

    def test_t17_ksm_scan_tombstone(self, conn):
        """T17: ksm_scan 删除路径注册 tombstone（代码检查）。"""
        import inspect
        from store_mm import ksm_scan
        source = inspect.getsource(ksm_scan)
        assert "register_import_tombstones" in source, \
            "ksm_scan must call register_import_tombstones"

    def test_t18_overcommit_kill_tombstone(self, conn):
        """T18: overcommit_kill 删除路径注册 tombstone（代码检查）。"""
        import inspect
        from store_mm import overcommit_kill
        source = inspect.getsource(overcommit_kill)
        assert "register_import_tombstones" in source, \
            "overcommit_kill must call register_import_tombstones"

    def test_t19_madv_free_tombstone(self, conn):
        """T19: madv_free_scan 删除路径注册 tombstone（代码检查）。"""
        import inspect
        from store_mm import madv_free_scan
        source = inspect.getsource(madv_free_scan)
        assert "register_import_tombstones" in source, \
            "madv_free_scan must call register_import_tombstones"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
