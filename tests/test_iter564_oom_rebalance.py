"""
iter564: oom_score_adj_rebalance — Runtime OOM Score Recalibration
OS 类比：Linux oom_badness() (Andrew Morton, 2006, kernel/mm/oom_kill.c)
"""
import sys
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

# tmpfs 隔离
import tmpfs  # noqa: F401

from store_core import open_db, ensure_schema, _ensure_checkpoint_schema
from store_mm import oom_score_adj_rebalance


def _conn():
    conn = open_db()
    ensure_schema(conn)
    _ensure_checkpoint_schema(conn)
    conn.execute("""CREATE TABLE IF NOT EXISTS chunk_pins (
        chunk_id TEXT, project TEXT, pin_type TEXT, pinned_at TEXT)""")
    conn.commit()
    return conn


def _ins(conn, project, cid, chunk_type="decision", importance=0.7,
         access_count=0, oom_adj=0, age_days=10):
    created = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    conn.execute(
        """INSERT OR REPLACE INTO memory_chunks
           (id, project, chunk_type, summary, content, importance,
            access_count, oom_adj, created_at, last_accessed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, project, chunk_type, f"test {cid}", f"content {cid}",
         importance, access_count, oom_adj, created, created))
    conn.commit()


# ── R1: demote_active_high_oom ──

def test_r1_active_demoted():
    """活跃 chunk (acc>=3) + oom>=500 → 降至 0"""
    conn = _conn()
    _ins(conn, "p", "c1", access_count=5, oom_adj=1000)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r1_demoted"] == 1
    assert conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='c1'").fetchone()[0] == 0
    conn.close()


def test_r1_inactive_not_demoted():
    """acc<3 + oom>=500 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c1", access_count=2, oom_adj=500)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r1_demoted"] == 0
    conn.close()


def test_r1_low_oom_not_demoted():
    """活跃但 oom<500 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c1", access_count=10, oom_adj=300)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r1_demoted"] == 0
    conn.close()


# ── R2: promote_dead_low_oom ──

def test_r2_dead_promoted():
    """零访问 + 老 + 低imp + oom<300 → 升至 300"""
    conn = _conn()
    _ins(conn, "p", "c2", importance=0.15, access_count=0, oom_adj=0, age_days=10)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r2_promoted"] == 1
    assert conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='c2'").fetchone()[0] == 300
    conn.close()


def test_r2_young_not_promoted():
    """年轻(<7d) → 宽限期不触发"""
    conn = _conn()
    _ins(conn, "p", "c2", importance=0.15, access_count=0, oom_adj=0, age_days=3)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r2_promoted"] == 0
    conn.close()


def test_r2_accessed_not_promoted():
    """有访问 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c2", importance=0.15, access_count=1, oom_adj=0, age_days=10)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r2_promoted"] == 0
    conn.close()


def test_r2_high_imp_not_promoted():
    """imp>=0.3 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c2", importance=0.5, access_count=0, oom_adj=0, age_days=10)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r2_promoted"] == 0
    conn.close()


def test_r2_already_high_oom():
    """oom>=300 → 已足够高不触发"""
    conn = _conn()
    _ins(conn, "p", "c2", importance=0.15, access_count=0, oom_adj=300, age_days=10)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r2_promoted"] == 0
    conn.close()


# ── R3: protect_hot ──

def test_r3_hot_protected():
    """高频(acc>=10) + 高价值(imp>=0.7) + oom>0 → 降至 -200"""
    conn = _conn()
    _ins(conn, "p", "c3", importance=0.9, access_count=15, oom_adj=200)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r3_protected"] == 1
    assert conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='c3'").fetchone()[0] == -200
    conn.close()


def test_r3_low_access():
    """acc<10 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c3", importance=0.9, access_count=5, oom_adj=200)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r3_protected"] == 0
    conn.close()


def test_r3_low_imp():
    """imp<0.7 → 不触发"""
    conn = _conn()
    _ins(conn, "p", "c3", importance=0.5, access_count=15, oom_adj=200)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r3_protected"] == 0
    conn.close()


def test_r3_already_protected():
    """oom<=0 → 已保护不触发"""
    conn = _conn()
    _ins(conn, "p", "c3", importance=0.9, access_count=15, oom_adj=0)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r3_protected"] == 0
    conn.close()


# ── Protection mechanisms ──

def test_pinned_not_touched():
    """mlock chunk 绝对不动"""
    conn = _conn()
    _ins(conn, "p", "pin1", access_count=5, oom_adj=1000)
    conn.execute("INSERT INTO chunk_pins VALUES ('pin1','p','hard',?)",
                 (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    r = oom_score_adj_rebalance(conn, "p")
    assert r["adjusted"] == 0
    assert conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='pin1'").fetchone()[0] == 1000
    conn.close()


def test_task_state_not_touched():
    """task_state 控制面不动"""
    conn = _conn()
    _ins(conn, "p", "ts1", chunk_type="task_state", access_count=5, oom_adj=1000)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["adjusted"] == 0
    conn.close()


def test_highly_protected_not_touched():
    """oom_adj<=-500 用户显式保护不动"""
    conn = _conn()
    _ins(conn, "p", "hp1", importance=0.15, access_count=0, oom_adj=-500, age_days=30)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["adjusted"] == 0
    conn.close()


def test_max_adjustments_capped():
    """超过 max_adjustments(20) 时停止"""
    conn = _conn()
    for i in range(30):
        _ins(conn, "p", f"d{i}", importance=0.15, access_count=0, oom_adj=0, age_days=10)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["adjusted"] == 20
    conn.close()


# ── Config & edge cases ──

def test_disabled():
    """disabled 时 adjusted=0"""
    conn = _conn()
    _ins(conn, "p", "c1", access_count=5, oom_adj=1000)
    import config
    orig = config.get
    def mock_get(key):
        if key == "oom_rebalance.enabled":
            return False
        return orig(key)
    config.get = mock_get
    try:
        r = oom_score_adj_rebalance(conn, "p")
        assert r["adjusted"] == 0
    finally:
        config.get = orig
    conn.close()


def test_global_included():
    """global project chunks 被扫描"""
    conn = _conn()
    _ins(conn, "global", "g1", access_count=20, importance=0.9, oom_adj=200)
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r3_protected"] == 1
    assert conn.execute("SELECT oom_adj FROM memory_chunks WHERE id='g1'").fetchone()[0] == -200
    conn.close()


def test_empty_project():
    """无此 project 的 chunks 不报错"""
    conn = _conn()
    r = oom_score_adj_rebalance(conn, "nonexistent_project_xyz")
    assert r["adjusted"] == 0
    conn.close()


def test_multi_rule():
    """多条规则独立触发"""
    conn = _conn()
    _ins(conn, "p", "r1c", access_count=5, oom_adj=1000)  # R1
    _ins(conn, "p", "r2c", importance=0.15, access_count=0, oom_adj=0, age_days=10)  # R2
    _ins(conn, "p", "r3c", importance=0.9, access_count=20, oom_adj=100)  # R3
    r = oom_score_adj_rebalance(conn, "p")
    assert r["r1_demoted"] == 1
    assert r["r2_promoted"] == 1
    assert r["r3_protected"] == 1
    assert r["adjusted"] == 3
    conn.close()


def test_idempotent():
    """第二次运行 adjusted=0"""
    conn = _conn()
    _ins(conn, "p", "c1", access_count=5, oom_adj=1000)
    r1 = oom_score_adj_rebalance(conn, "p")
    assert r1["adjusted"] == 1
    r2 = oom_score_adj_rebalance(conn, "p")
    assert r2["adjusted"] == 0
    conn.close()


def test_performance():
    """100 chunks <50ms"""
    conn = _conn()
    for i in range(100):
        _ins(conn, "perf_proj", f"perf{i}", importance=0.5, access_count=i % 15,
             oom_adj=(i % 5) * 200 - 200, age_days=i % 20)
    t0 = time.time()
    r = oom_score_adj_rebalance(conn, "perf_proj")
    elapsed = (time.time() - t0) * 1000
    assert elapsed < 50, f"Too slow: {elapsed:.1f}ms"
    assert r["scanned"] >= 100
    conn.close()


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
