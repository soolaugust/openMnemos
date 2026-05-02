"""
iter528: munlock_idle — Revoke Stale mlock Protection
OS 类比：Linux munlock() + MADV_COLD (Minchan Kim, 2019)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: F401 — 测试隔离
from store_mm import munlock_idle, page_idle_mark, page_idle_scan, _page_idle_load, _page_idle_save, _PAGE_IDLE_FILE
from store_core import open_db, ensure_schema, insert_chunk, OOM_ADJ_DEFAULT
from schema import MemoryChunk
from datetime import datetime, timezone, timedelta
import json
import pytest

_TEST_SEQ = 0

def _unique_project():
    global _TEST_SEQ
    _TEST_SEQ += 1
    return f"test_munlock_{_TEST_SEQ}"


def _make_chunk(conn, chunk_type="decision", importance=0.9, oom_adj=-500,
                access_count=0, created_at=None, project="test_munlock"):
    """创建测试 chunk 并插入 DB"""
    if created_at is None:
        created_at = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
    chunk = MemoryChunk(
        project=project,
        chunk_type=chunk_type,
        summary=f"test {chunk_type} {importance}",
        content=f"test content {chunk_type}",
        importance=importance,
    )
    insert_chunk(conn, chunk.to_dict())
    # 设置 oom_adj 和 access_count（insert_chunk 不直接支持）
    conn.execute("UPDATE memory_chunks SET oom_adj=?, access_count=?, created_at=? WHERE id=?",
                 (oom_adj, access_count, created_at, chunk.id))
    conn.commit()
    return chunk.id


def _set_idle_rounds(project, chunk_id, rounds):
    """设置 page_idle bitmap 中的 idle rounds"""
    bitmap = _page_idle_load()
    if project not in bitmap:
        bitmap[project] = {}
    bitmap[project][chunk_id] = rounds
    _page_idle_save(bitmap)


@pytest.fixture(autouse=True)
def clean_bitmap():
    """每个测试前清理 page_idle bitmap"""
    _page_idle_save({})
    yield
    _page_idle_save({})


@pytest.fixture
def conn():
    c = open_db()
    ensure_schema(c)
    yield c
    c.close()


class TestMunlockIdle:
    """iter528: munlock_idle 测试"""

    def test_basic_munlock(self, conn):
        """T1: access=0 + idle_rounds>=5 + oom_adj<=-500 → 被 munlock"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid, 6)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 1
        assert result["scanned"] == 1

        row = conn.execute("SELECT oom_adj FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row[0] == OOM_ADJ_DEFAULT  # 0

    def test_not_enough_idle_rounds(self, conn):
        """T2: idle_rounds < threshold → 不处理"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid, 3)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 0

        row = conn.execute("SELECT oom_adj FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row[0] == -500

    def test_has_access_skip(self, conn):
        """T3: access_count > 0 → 已被验证，不处理"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=-500, access_count=3, project=p)
        _set_idle_rounds(p, cid, 10)

        result = munlock_idle(conn, p)
        assert result["scanned"] == 0  # SQL WHERE access_count=0 过滤
        assert result["unlocked"] == 0

    def test_not_mlock_skip(self, conn):
        """T4: oom_adj > -500 → 不是 mlock，不处理"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=0, access_count=0, project=p)
        _set_idle_rounds(p, cid, 10)

        result = munlock_idle(conn, p)
        assert result["scanned"] == 0  # SQL WHERE oom_adj<=-500 过滤

    def test_design_constraint_grace_period(self, conn):
        """T5: design_constraint 创建 < 7 天 → grace period 保护"""
        p = _unique_project()
        created_at = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        cid = _make_chunk(conn, chunk_type="design_constraint",
                         oom_adj=-500, access_count=0, created_at=created_at, project=p)
        _set_idle_rounds(p, cid, 10)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 0
        assert result["skipped_grace"] == 1

        row = conn.execute("SELECT oom_adj FROM memory_chunks WHERE id=?", (cid,)).fetchone()
        assert row[0] == -500

    def test_design_constraint_past_grace(self, conn):
        """T6: design_constraint 创建 > 7 天 → grace period 已过"""
        p = _unique_project()
        created_at = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        cid = _make_chunk(conn, chunk_type="design_constraint",
                         oom_adj=-500, access_count=0, created_at=created_at, project=p)
        _set_idle_rounds(p, cid, 10)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 1

    def test_non_design_constraint_no_grace(self, conn):
        """T7: quantitative_evidence 新创建也无 grace period"""
        p = _unique_project()
        created_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        cid = _make_chunk(conn, chunk_type="quantitative_evidence",
                         oom_adj=-500, access_count=0, created_at=created_at, project=p)
        _set_idle_rounds(p, cid, 6)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 1

    def test_max_per_scan_limit(self, conn):
        """T8: 单次最多 munlock max_per_scan 个"""
        p = _unique_project()
        for i in range(25):
            cid = _make_chunk(conn, oom_adj=-500, access_count=0,
                            importance=0.9 + i * 0.001, project=p)
            _set_idle_rounds(p, cid, 10)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 20  # default max_per_scan=20
        assert result["scanned"] == 25

    def test_empty_project(self, conn):
        """T9: 空项目不报错"""
        result = munlock_idle(conn, "empty_project_xxx")
        assert result["scanned"] == 0
        assert result["unlocked"] == 0

    def test_no_bitmap_entry(self, conn):
        """T10: chunk 不在 page_idle bitmap 中 → idle_rounds=0 → 不处理"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=-500, access_count=0, project=p)
        # 不设置 bitmap entry

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 0

    def test_multiple_chunks_mixed(self, conn):
        """T11: 混合场景 — 部分满足条件、部分不满足"""
        p = _unique_project()
        # 满足：access=0, idle>=5, oom=-500
        cid1 = _make_chunk(conn, chunk_type="decision", oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid1, 8)

        # 不满足：access>0
        cid2 = _make_chunk(conn, chunk_type="decision", oom_adj=-500, access_count=5, project=p)
        _set_idle_rounds(p, cid2, 8)

        # 不满足：idle_rounds<5
        cid3 = _make_chunk(conn, chunk_type="decision", oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid3, 2)

        # 满足：quantitative_evidence
        cid4 = _make_chunk(conn, chunk_type="quantitative_evidence", oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid4, 10)

        result = munlock_idle(conn, p)
        assert result["unlocked"] == 2  # cid1 + cid4

    def test_chunk_version_bumped(self, conn):
        """T12: munlock 后 chunk_version 被 bump（TLB 失效）"""
        p = _unique_project()
        cid = _make_chunk(conn, oom_adj=-500, access_count=0, project=p)
        _set_idle_rounds(p, cid, 6)

        ver_file = os.path.join(os.environ.get("MEMORY_OS_DIR", ""), "chunk_version")
        if os.path.exists(ver_file):
            with open(ver_file) as f:
                old_ver = int(f.read().strip())
        else:
            old_ver = 0

        munlock_idle(conn, p)

        if os.path.exists(ver_file):
            with open(ver_file) as f:
                new_ver = int(f.read().strip())
            assert new_ver > old_ver

    def test_performance(self, conn):
        """T13: 性能 — 20 chunks < 50ms"""
        import time
        p = _unique_project()
        for i in range(20):
            cid = _make_chunk(conn, oom_adj=-500, access_count=0,
                            importance=0.8 + i * 0.005, project=p)
            _set_idle_rounds(p, cid, 10)

        t0 = time.time()
        result = munlock_idle(conn, p)
        elapsed = (time.time() - t0) * 1000

        assert elapsed < 50
        assert result["unlocked"] == 20
