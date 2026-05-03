"""
iter554: cgroup_budget — Subsystem Group Budget Enforcement
OS 类比：Linux cgroup v2 memory.max (Tejun Heo, 2015, kernel 4.5)

测试覆盖：
1. 分组定义完整性（所有 _ts_skip 子系统都有归属）
2. load/save 持久化 roundtrip
3. tick 递减
4. should_throttle — 历史 throttle + 实时预算耗尽
5. consume 累加
6. settle — EMA 收敛 + 超标 throttle + 回落恢复
7. 冷启动容忍（< 2 samples 不 throttle）
8. 豁免子系统（不属于任何 cgroup）不受影响
9. stats 统计
10. 多组独立性（一组超标不影响其他组）
11. load 缺失/损坏文件容错
12. 实时预算耗尽门控
"""
import sys
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

# 添加项目根目录到 path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCgroupBudget:
    """iter554: cgroup_budget 核心逻辑测试"""

    def setup_method(self):
        """每个测试用例前清理环境"""
        self._tmpdir = tempfile.mkdtemp()
        self._mock_file = Path(self._tmpdir) / "cgroup_budget_state.json"
        # Patch 文件路径
        import store_mm
        self._orig_file = store_mm._CGROUP_BUDGET_FILE
        store_mm._CGROUP_BUDGET_FILE = self._mock_file

    def teardown_method(self):
        """恢复环境"""
        import store_mm
        store_mm._CGROUP_BUDGET_FILE = self._orig_file
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_group_definitions_complete(self):
        """所有分组都有成员，且反向索引正确"""
        from store_mm import CGROUP_GROUPS, _SUBSYSTEM_TO_GROUP

        # 每组有成员
        for group, members in CGROUP_GROUPS.items():
            assert len(members) > 0, f"Group {group} has no members"

        # 反向索引覆盖所有成员
        all_members = set()
        for members in CGROUP_GROUPS.values():
            all_members.update(members)

        for m in all_members:
            assert m in _SUBSYSTEM_TO_GROUP, f"{m} not in reverse index"

    def test_exempt_subsystems_not_in_any_group(self):
        """CLOCK_REALTIME 强制执行子系统不属于任何 cgroup"""
        from store_mm import _SUBSYSTEM_TO_GROUP, _CLOCK_REALTIME_SUBSYSTEMS

        for exempt in _CLOCK_REALTIME_SUBSYSTEMS:
            assert exempt not in _SUBSYSTEM_TO_GROUP, \
                f"CLOCK_REALTIME subsystem {exempt} should not be in any cgroup"

    def test_load_missing_file(self):
        """缺失文件返回空 dict"""
        from store_mm import cgroup_budget_load
        state = cgroup_budget_load()
        assert state == {}

    def test_load_corrupt_file(self):
        """损坏文件返回空 dict"""
        from store_mm import cgroup_budget_load
        self._mock_file.write_text("not json {{{")
        state = cgroup_budget_load()
        assert state == {}

    def test_save_load_roundtrip(self):
        """保存/加载 roundtrip 正确（运行时字段被清除）"""
        from store_mm import cgroup_budget_save, cgroup_budget_load

        state = {
            "reclaim": {"ema_ms": 45.5, "throttle_sessions": 1, "samples": 3, "consumed_ms": 30.0},
            "gc": {"ema_ms": 20.0, "throttle_sessions": 0, "samples": 5, "consumed_ms": 15.0},
        }
        cgroup_budget_save(state)
        loaded = cgroup_budget_load()

        # consumed_ms 应被重置为 0（每 session 重新累计）
        assert loaded["reclaim"]["consumed_ms"] == 0.0
        assert loaded["gc"]["consumed_ms"] == 0.0
        # 其他字段保留
        assert loaded["reclaim"]["ema_ms"] == 45.5
        assert loaded["reclaim"]["throttle_sessions"] == 1
        assert loaded["reclaim"]["samples"] == 3

    def test_tick_decrements(self):
        """tick 递减 throttle_sessions"""
        from store_mm import cgroup_budget_tick

        state = {
            "reclaim": {"ema_ms": 80.0, "throttle_sessions": 2, "samples": 5, "consumed_ms": 0.0},
            "gc": {"ema_ms": 30.0, "throttle_sessions": 0, "samples": 3, "consumed_ms": 0.0},
        }
        state = cgroup_budget_tick(state)
        assert state["reclaim"]["throttle_sessions"] == 1
        assert state["gc"]["throttle_sessions"] == 0

        state = cgroup_budget_tick(state)
        assert state["reclaim"]["throttle_sessions"] == 0

    def test_should_throttle_history(self):
        """历史 throttle 阻止组内子系统"""
        from store_mm import cgroup_budget_should_throttle

        state = {
            "reclaim": {"ema_ms": 80.0, "throttle_sessions": 2, "samples": 5, "consumed_ms": 0.0},
        }
        # reclaim 组内成员应被 throttle
        assert cgroup_budget_should_throttle(state, "shrink_dcache") is True
        assert cgroup_budget_should_throttle(state, "oom_reaper") is True
        # 非 reclaim 组不受影响
        assert cgroup_budget_should_throttle(state, "numa_balancing") is False
        # 不在任何组的子系统
        assert cgroup_budget_should_throttle(state, "watchdog") is False

    @patch("config.get")
    def test_should_throttle_realtime_budget(self, mock_cfg):
        """当前 session 实时预算耗尽"""
        mock_cfg.return_value = 60.0  # group_budget_ms = 60

        from store_mm import cgroup_budget_should_throttle

        state = {
            "reclaim": {"ema_ms": 40.0, "throttle_sessions": 0, "samples": 5, "consumed_ms": 65.0},
        }
        # consumed_ms(65) >= budget(60) → throttle
        assert cgroup_budget_should_throttle(state, "shrink_dcache") is True

    def test_consume_accumulates(self):
        """consume 正确累加到组"""
        from store_mm import cgroup_budget_consume

        state = {}
        state = cgroup_budget_consume(state, "shrink_dcache", 15.0)
        state = cgroup_budget_consume(state, "oom_reaper", 10.0)
        state = cgroup_budget_consume(state, "free_pages_ok", 8.0)

        assert state["reclaim"]["consumed_ms"] == 33.0

    def test_consume_different_groups_independent(self):
        """不同组的 consume 独立"""
        from store_mm import cgroup_budget_consume

        state = {}
        state = cgroup_budget_consume(state, "shrink_dcache", 20.0)  # reclaim
        state = cgroup_budget_consume(state, "numa_balancing", 12.0)  # rebalance

        assert state["reclaim"]["consumed_ms"] == 20.0
        assert state["rebalance"]["consumed_ms"] == 12.0

    def test_consume_exempt_subsystem_noop(self):
        """豁免子系统 consume 无效果"""
        from store_mm import cgroup_budget_consume

        state = {}
        state = cgroup_budget_consume(state, "watchdog", 50.0)
        # watchdog 不属于任何 cgroup，state 应为空
        assert state == {}

    @patch("config.get")
    def test_settle_ema_convergence(self, mock_cfg):
        """settle EMA 收敛到稳定值"""
        mock_cfg.return_value = 60.0  # group_budget_ms = 60

        from store_mm import cgroup_budget_settle

        state = {}
        # 连续 5 次输入 50ms → EMA 应收敛到 ~50ms
        for _ in range(5):
            state = cgroup_budget_settle(state, {"reclaim": 50.0})

        # EMA(α=0.3): 50 → 50 → 50 → ... = 50
        assert abs(state["reclaim"]["ema_ms"] - 50.0) < 1.0
        assert state["reclaim"]["throttle_sessions"] == 0  # 50 < 60

    @patch("config.get")
    def test_settle_throttle_trigger(self, mock_cfg):
        """组合计超标 → throttle"""
        def cfg_side_effect(key):
            if key == "cgroup_budget.group_budget_ms":
                return 60.0
            if key == "cgroup_budget.throttle_sessions":
                return 2
            return 60.0
        mock_cfg.side_effect = cfg_side_effect

        from store_mm import cgroup_budget_settle

        state = {}
        # 连续输入 80ms（> budget 60ms）
        state = cgroup_budget_settle(state, {"reclaim": 80.0})
        # 只有 1 sample，不 throttle
        assert state["reclaim"]["throttle_sessions"] == 0

        state = cgroup_budget_settle(state, {"reclaim": 80.0})
        # 2 samples，EMA=80 > 60 → throttle
        assert state["reclaim"]["throttle_sessions"] == 2

    @patch("config.get")
    def test_settle_recovery_clears_throttle(self, mock_cfg):
        """EMA 回到预算内时自动解除 throttle"""
        def cfg_side_effect(key):
            if key == "cgroup_budget.group_budget_ms":
                return 60.0
            if key == "cgroup_budget.throttle_sessions":
                return 2
            return 60.0
        mock_cfg.side_effect = cfg_side_effect

        from store_mm import cgroup_budget_settle

        state = {
            "reclaim": {"ema_ms": 80.0, "throttle_sessions": 2, "samples": 5, "consumed_ms": 0.0}
        }
        # 输入 30ms（远低于 budget）→ EMA 下降，解除 throttle
        state = cgroup_budget_settle(state, {"reclaim": 30.0})
        # EMA = 0.3*30 + 0.7*80 = 9 + 56 = 65 > 60 → 仍然 throttle
        # 再来一次
        state = cgroup_budget_settle(state, {"reclaim": 30.0})
        # EMA = 0.3*30 + 0.7*65 = 9 + 45.5 = 54.5 < 60 → 解除
        assert state["reclaim"]["throttle_sessions"] == 0

    @patch("config.get")
    def test_cold_start_no_throttle(self, mock_cfg):
        """冷启动（<2 samples）不触发 throttle"""
        def cfg_side_effect(key):
            if key == "cgroup_budget.group_budget_ms":
                return 60.0
            if key == "cgroup_budget.throttle_sessions":
                return 2
            return 60.0
        mock_cfg.side_effect = cfg_side_effect

        from store_mm import cgroup_budget_settle

        state = {}
        # 第一个样本 200ms（远超 budget），但只有 1 sample
        state = cgroup_budget_settle(state, {"reclaim": 200.0})
        assert state["reclaim"]["samples"] == 1
        assert state["reclaim"]["throttle_sessions"] == 0

    def test_stats_accuracy(self):
        """stats 返回正确统计"""
        from store_mm import cgroup_budget_stats

        state = {
            "reclaim": {"ema_ms": 80.0, "throttle_sessions": 2, "samples": 5, "consumed_ms": 0.0},
            "gc": {"ema_ms": 30.0, "throttle_sessions": 0, "samples": 3, "consumed_ms": 0.0},
            "rebalance": {"ema_ms": 70.0, "throttle_sessions": 1, "samples": 4, "consumed_ms": 0.0},
        }

        with patch("config.get", return_value=60.0):
            stats = cgroup_budget_stats(state)

        assert stats["total_groups"] == 4  # 总是 4 组
        assert stats["throttled_groups"] == 2  # reclaim + rebalance
        assert stats["over_budget_groups"] == 2  # reclaim(80>60) + rebalance(70>60)
        assert stats["groups"]["reclaim"]["throttled"] is True
        assert stats["groups"]["gc"]["throttled"] is False

    def test_multi_group_independence(self):
        """一组超标不影响其他组"""
        from store_mm import cgroup_budget_should_throttle

        state = {
            "reclaim": {"ema_ms": 80.0, "throttle_sessions": 2, "samples": 5, "consumed_ms": 0.0},
            "gc": {"ema_ms": 30.0, "throttle_sessions": 0, "samples": 3, "consumed_ms": 0.0},
        }
        # reclaim 组被 throttle
        assert cgroup_budget_should_throttle(state, "shrink_dcache") is True
        # gc 组正常
        assert cgroup_budget_should_throttle(state, "gc_traces") is False
        assert cgroup_budget_should_throttle(state, "fstrim") is False

    def test_empty_state_operations(self):
        """空状态下各操作不出错"""
        from store_mm import (cgroup_budget_should_throttle, cgroup_budget_consume,
                             cgroup_budget_tick, cgroup_budget_stats)

        state = {}
        assert cgroup_budget_should_throttle(state, "shrink_dcache") is False
        state = cgroup_budget_consume(state, "shrink_dcache", 10.0)
        state = cgroup_budget_tick(state)
        with patch("config.get", return_value=60.0):
            stats = cgroup_budget_stats(state)
        assert stats["throttled_groups"] == 0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
