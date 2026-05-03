"""
iter585: tmpfiles_d — Per-Session State File Reaper

OS 类比：systemd-tmpfiles-clean (Lennart Poettering, 2010, systemd/tmpfiles.d)
  /usr/lib/tmpfiles.d/*.conf 声明每类临时文件的清理策略。
  systemd-tmpfiles-clean.timer 每日触发，按 atime/mtime 判定过期，unlink 释放 inode+block。

测试：验证各类 per-session 文件按 mtime 过期清理，全局文件不被删除。
"""
import json
import os
import sys
import time
import tempfile
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Sysctl Stub ──────────────────────────────────────────────────────────────
_SYSCTL_DEFAULTS = {
    "tmpfiles_d.enabled": True,
    "tmpfiles_d.max_age_hours": 24,
    "tmpfiles_d.max_cold_sync_entries": 200,
}
_sysctl_overrides = {}


def _stub_get(key, default=None):
    if key in _sysctl_overrides:
        return _sysctl_overrides[key]
    return _SYSCTL_DEFAULTS.get(key, default)


@pytest.fixture(autouse=True)
def _patch_config(monkeypatch):
    _sysctl_overrides.clear()
    import config
    monkeypatch.setattr(config, "get", _stub_get)
    yield
    _sysctl_overrides.clear()


@pytest.fixture
def tmp_mem_dir():
    """Create a temporary directory simulating ~/.claude/memory-os/."""
    with tempfile.TemporaryDirectory() as d:
        yield d


def _touch(path, age_hours=0):
    """Create a file and set its mtime to age_hours ago."""
    with open(path, "w") as f:
        f.write("{}")
    if age_hours > 0:
        old_time = time.time() - age_hours * 3600
        os.utime(path, (old_time, old_time))


def _exists(path):
    return os.path.exists(path)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: shadow_trace files
# ═══════════════════════════════════════════════════════════════════════════════

class TestShadowTraceCleanup:
    def test_removes_old_shadow_trace(self, tmp_mem_dir):
        """超过 max_age 的 per-session shadow_trace 被清理。"""
        from store_mm import tmpfiles_d
        old_file = os.path.join(tmp_mem_dir, ".shadow_trace.abc12345def67890.json")
        _touch(old_file, age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 1
        assert not _exists(old_file)
        assert result["bytes_freed"] > 0

    def test_keeps_recent_shadow_trace(self, tmp_mem_dir):
        """未过期的 per-session shadow_trace 不被清理。"""
        from store_mm import tmpfiles_d
        new_file = os.path.join(tmp_mem_dir, ".shadow_trace.recent12345678.json")
        _touch(new_file, age_hours=1)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 0
        assert _exists(new_file)

    def test_preserves_global_shadow_trace(self, tmp_mem_dir):
        """全局 .shadow_trace.json 不被清理（retriever 使用）。"""
        from store_mm import tmpfiles_d
        global_file = os.path.join(tmp_mem_dir, ".shadow_trace.json")
        _touch(global_file, age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 0
        assert _exists(global_file)

    def test_multiple_shadow_traces(self, tmp_mem_dir):
        """批量清理多个过期 shadow_trace。"""
        from store_mm import tmpfiles_d
        for i in range(10):
            _touch(os.path.join(tmp_mem_dir, f".shadow_trace.session{i:08d}.json"), age_hours=48)
        # 保留 2 个新的
        for i in range(2):
            _touch(os.path.join(tmp_mem_dir, f".shadow_trace.fresh{i:010d}.json"), age_hours=1)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 10
        # 新文件仍在
        remaining = [f for f in os.listdir(tmp_mem_dir) if f.startswith(".shadow_trace.")]
        assert len(remaining) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: page_fault_log files
# ═══════════════════════════════════════════════════════════════════════════════

class TestPageFaultLogCleanup:
    def test_removes_old_page_fault_log(self, tmp_mem_dir):
        """过期的 per-session page_fault_log 被清理。"""
        from store_mm import tmpfiles_d
        old_file = os.path.join(tmp_mem_dir, "page_fault_log.abc12345.json")
        _touch(old_file, age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["page_fault_log"] == 1
        assert not _exists(old_file)

    def test_preserves_global_page_fault_log(self, tmp_mem_dir):
        """全局 page_fault_log.json 不被清理。"""
        from store_mm import tmpfiles_d
        global_file = os.path.join(tmp_mem_dir, "page_fault_log.json")
        _touch(global_file, age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["page_fault_log"] == 0
        assert _exists(global_file)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: citation_stats files
# ═══════════════════════════════════════════════════════════════════════════════

class TestCitationStatsCleanup:
    def test_removes_old_citation_stats(self, tmp_mem_dir):
        """过期的 citation_stats 缓存文件被清理。"""
        from store_mm import tmpfiles_d
        for suffix in ["cc1_abc123", "sm1_def456", "sas_h_789abc"]:
            _touch(os.path.join(tmp_mem_dir, f"citation_stats.{suffix}.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["citation_stats"] == 3

    def test_keeps_recent_citation_stats(self, tmp_mem_dir):
        """未过期的 citation_stats 不被清理。"""
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, "citation_stats.fresh_one.json"), age_hours=1)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["citation_stats"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: ctx_pressure_state files
# ═══════════════════════════════════════════════════════════════════════════════

class TestCtxPressureCleanup:
    def test_removes_old_ctx_pressure(self, tmp_mem_dir):
        """过期的 per-session ctx_pressure_state 被清理。"""
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, "ctx_pressure_state.abc12345.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["ctx_pressure"] == 1

    def test_preserves_global_ctx_pressure(self, tmp_mem_dir):
        """全局 ctx_pressure_state.json 不被清理。"""
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, "ctx_pressure_state.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["ctx_pressure"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: cold_sync_state.json truncation
# ═══════════════════════════════════════════════════════════════════════════════

class TestColdSyncTruncation:
    def test_truncates_cold_sync(self, tmp_mem_dir):
        """超过 max_entries 的 cold_sync_state 被截断到最新 N 条。"""
        _sysctl_overrides["tmpfiles_d.max_cold_sync_entries"] = 5
        from store_mm import tmpfiles_d
        data = {}
        for i in range(20):
            data[f"chunk-{i:04d}"] = {
                "synced_at": f"2026-04-{i+1:02d}T00:00:00+00:00",
                "content_hash": f"hash{i}"
            }
        cold_path = os.path.join(tmp_mem_dir, "cold_sync_state.json")
        with open(cold_path, "w") as f:
            json.dump(data, f)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["cold_sync"] == 15  # 20 - 5
        with open(cold_path) as f:
            remaining = json.load(f)
        assert len(remaining) == 5
        # 保留的是最新的 5 条（April 16-20）
        dates = [v["synced_at"] for v in remaining.values()]
        assert all("2026-04-1" in d or "2026-04-20" in d for d in dates)

    def test_cold_sync_within_limit(self, tmp_mem_dir):
        """cold_sync 条目数在限制内时不截断。"""
        _sysctl_overrides["tmpfiles_d.max_cold_sync_entries"] = 200
        from store_mm import tmpfiles_d
        data = {f"chunk-{i}": {"synced_at": "2026-04-01T00:00:00+00:00"} for i in range(10)}
        cold_path = os.path.join(tmp_mem_dir, "cold_sync_state.json")
        with open(cold_path, "w") as f:
            json.dump(data, f)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["cold_sync"] == 0

    def test_cold_sync_missing_file(self, tmp_mem_dir):
        """cold_sync_state.json 不存在时不报错。"""
        from store_mm import tmpfiles_d
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["cold_sync"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Integration & edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    def test_disabled(self, tmp_mem_dir):
        """disabled 时不清理任何文件。"""
        _sysctl_overrides["tmpfiles_d.enabled"] = False
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.old12345678.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["total_cleaned"] == 0
        # 文件仍在
        assert _exists(os.path.join(tmp_mem_dir, ".shadow_trace.old12345678.json"))

    def test_empty_dir(self, tmp_mem_dir):
        """空目录不报错。"""
        from store_mm import tmpfiles_d
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["total_cleaned"] == 0
        assert result["bytes_freed"] == 0

    def test_custom_max_age(self, tmp_mem_dir):
        """自定义 max_age_hours。"""
        _sysctl_overrides["tmpfiles_d.max_age_hours"] = 2
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.age3h_session.json"), age_hours=3)
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.age1h_session.json"), age_hours=1)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 1  # 只有 3h 的被清理

    def test_mixed_all_phases(self, tmp_mem_dir):
        """所有类型混合测试。"""
        from store_mm import tmpfiles_d
        # 创建各类过期文件
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.sess1_abcdefgh.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.sess2_12345678.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "page_fault_log.abcd1234.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "citation_stats.cc1_hash01.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "ctx_pressure_state.sess_abcd.json"), age_hours=48)
        # 全局文件（不清理）
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "page_fault_log.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "ctx_pressure_state.json"), age_hours=48)

        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 2
        assert result["cleaned"]["page_fault_log"] == 1
        assert result["cleaned"]["citation_stats"] == 1
        assert result["cleaned"]["ctx_pressure"] == 1
        assert result["total_cleaned"] == 5
        assert result["bytes_freed"] > 0
        # 全局文件仍在
        assert _exists(os.path.join(tmp_mem_dir, ".shadow_trace.json"))
        assert _exists(os.path.join(tmp_mem_dir, "page_fault_log.json"))
        assert _exists(os.path.join(tmp_mem_dir, "ctx_pressure_state.json"))

    def test_performance(self, tmp_mem_dir):
        """300 个文件清理 < 50ms。"""
        from store_mm import tmpfiles_d
        for i in range(300):
            _touch(os.path.join(tmp_mem_dir, f".shadow_trace.perf{i:012d}.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["cleaned"]["shadow_trace"] == 300
        assert result["duration_ms"] < 50

    def test_total_cleaned_sum(self, tmp_mem_dir):
        """total_cleaned == sum of all phase counts。"""
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.sum_test_s1.json"), age_hours=48)
        _touch(os.path.join(tmp_mem_dir, "page_fault_log.sum_test.json"), age_hours=48)
        result = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert result["total_cleaned"] == sum(result["cleaned"].values())

    def test_idempotent(self, tmp_mem_dir):
        """连续调用两次，第二次清理数为 0。"""
        from store_mm import tmpfiles_d
        _touch(os.path.join(tmp_mem_dir, ".shadow_trace.idemp_test_01.json"), age_hours=48)
        r1 = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert r1["total_cleaned"] == 1
        r2 = tmpfiles_d(mem_dir=tmp_mem_dir)
        assert r2["total_cleaned"] == 0
