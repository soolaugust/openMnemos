"""
iter553: sched_deadline — Per-Subsystem Runtime Budget Enforcement

Tests for SCHED_DEADLINE-inspired per-subsystem runtime budget enforcement.
OS 类比：Linux SCHED_DEADLINE (Luca Abeni & Juri Lelli, 2014, kernel 3.14)

测试维度：
  1. EMA 更新逻辑 (冷启动/平滑/收敛)
  2. Throttle 触发条件 (预算超出 + 最小样本数)
  3. Throttle 自动恢复 (tick decrement)
  4. 豁免子系统 (DEADLINE_EXEMPT)
  5. Budget 内自动解除 throttle
  6. Save/Load 持久化
  7. Stats 统计准确性
  8. 与 timer_slack 独立性
"""
import sys
import os
import json
import tempfile

# ── tmpfs 测试隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="memtest_sched_deadline_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store_mm import (
    sched_deadline_load, sched_deadline_save,
    sched_deadline_update, sched_deadline_should_throttle,
    sched_deadline_tick, sched_deadline_stats,
    _DEADLINE_EXEMPT_SUBSYSTEMS,
)


def test_ema_cold_start():
    """首次样本直接作为 EMA（无历史时无平滑）。"""
    state = {}
    state = sched_deadline_update(state, "sleep_consolidation", 25.0)
    entry = state["sleep_consolidation"]
    assert entry["ema_ms"] == 25.0
    assert entry["samples"] == 1


def test_ema_smoothing():
    """EMA 按 α=0.3 平滑：ema = 0.3×current + 0.7×prev。"""
    state = {"test_sub": {"ema_ms": 10.0, "throttle_sessions": 0, "samples": 5}}
    state = sched_deadline_update(state, "test_sub", 30.0)
    # expected: 0.3*30 + 0.7*10 = 9 + 7 = 16.0
    assert abs(state["test_sub"]["ema_ms"] - 16.0) < 0.01


def test_ema_convergence():
    """连续相同输入 EMA 收敛到该值。"""
    state = {"test_sub": {"ema_ms": 5.0, "throttle_sessions": 0, "samples": 3}}
    for _ in range(20):
        state = sched_deadline_update(state, "test_sub", 50.0)
    # 经过 20 次 α=0.3 迭代，应非常接近 50
    assert abs(state["test_sub"]["ema_ms"] - 50.0) < 0.5


def test_throttle_trigger_requires_min_samples():
    """需要至少 3 个样本才触发 throttle（防冷启动误判）。"""
    state = {}
    # 第 1 次：超预算但 samples=1 → 不 throttle
    state = sched_deadline_update(state, "slow_sub", 50.0)
    assert state["slow_sub"]["throttle_sessions"] == 0
    # 第 2 次：samples=2 → 仍不 throttle
    state = sched_deadline_update(state, "slow_sub", 50.0)
    assert state["slow_sub"]["throttle_sessions"] == 0
    # 第 3 次：samples=3，EMA > budget(20) → throttle
    state = sched_deadline_update(state, "slow_sub", 50.0)
    assert state["slow_sub"]["throttle_sessions"] > 0


def test_throttle_check():
    """should_throttle 正确反映 throttle_sessions > 0。"""
    state = {"sub_a": {"ema_ms": 30.0, "throttle_sessions": 2, "samples": 5}}
    assert sched_deadline_should_throttle(state, "sub_a") is True
    state["sub_a"]["throttle_sessions"] = 0
    assert sched_deadline_should_throttle(state, "sub_a") is False


def test_exempt_subsystem_never_throttled():
    """豁免子系统永不被 throttle（即使超预算）。"""
    state = {}
    for exempt in ["watchdog", "autotune", "initcall_debug", "mglru_aging"]:
        # 喂入超高值
        for _ in range(5):
            state = sched_deadline_update(state, exempt, 100.0)
        # 豁免子系统不进入 state
        assert exempt not in state
        # should_throttle 永远 False
        assert sched_deadline_should_throttle(state, exempt) is False


def test_tick_decrements():
    """tick 每次递减 throttle_sessions，到 0 时自动恢复。"""
    state = {
        "sub_a": {"ema_ms": 30.0, "throttle_sessions": 3, "samples": 5},
        "sub_b": {"ema_ms": 25.0, "throttle_sessions": 1, "samples": 5},
    }
    state = sched_deadline_tick(state)
    assert state["sub_a"]["throttle_sessions"] == 2
    assert state["sub_b"]["throttle_sessions"] == 0  # 恢复执行


def test_budget_recovery_clears_throttle():
    """EMA 回到预算内时自动清除 throttle。"""
    state = {"sub_a": {"ema_ms": 25.0, "throttle_sessions": 2, "samples": 5}}
    # 喂入低值使 EMA 降到 budget 以下
    # EMA = 0.3*5 + 0.7*25 = 1.5 + 17.5 = 19.0 (< 20 budget)
    state = sched_deadline_update(state, "sub_a", 5.0)
    assert state["sub_a"]["throttle_sessions"] == 0  # 自动解除


def test_save_load_roundtrip():
    """持久化和加载保持状态一致。"""
    state = {
        "sub_a": {"ema_ms": 15.3, "throttle_sessions": 2, "samples": 7},
        "sub_b": {"ema_ms": 8.1, "throttle_sessions": 0, "samples": 12},
    }
    sched_deadline_save(state)
    loaded = sched_deadline_load()
    assert loaded == state


def test_load_missing_file():
    """状态文件不存在时返回空 dict。"""
    # 确保文件不存在
    from store_mm import _SCHED_DEADLINE_FILE
    if _SCHED_DEADLINE_FILE.exists():
        _SCHED_DEADLINE_FILE.unlink()
    loaded = sched_deadline_load()
    assert loaded == {}


def test_load_corrupt_file():
    """损坏的状态文件返回空 dict（容错）。"""
    from store_mm import _SCHED_DEADLINE_FILE
    _SCHED_DEADLINE_FILE.write_text("not valid json {{{{")
    loaded = sched_deadline_load()
    assert loaded == {}


def test_stats_accuracy():
    """统计正确反映 throttled/over_budget 数量。"""
    state = {
        "sub_a": {"ema_ms": 30.0, "throttle_sessions": 2, "samples": 5},  # throttled + over_budget
        "sub_b": {"ema_ms": 25.0, "throttle_sessions": 0, "samples": 5},  # over_budget only
        "sub_c": {"ema_ms": 10.0, "throttle_sessions": 0, "samples": 5},  # healthy
    }
    stats = sched_deadline_stats(state)
    assert stats["total_tracked"] == 3
    assert stats["currently_throttled"] == 1
    assert stats["over_budget"] == 2


def test_empty_state_operations():
    """空状态上的所有操作不崩溃。"""
    state = {}
    assert sched_deadline_should_throttle(state, "nonexistent") is False
    state = sched_deadline_tick(state)
    assert state == {}
    stats = sched_deadline_stats(state)
    assert stats["total_tracked"] == 0


def test_multi_subsystem_independent():
    """多个子系统独立跟踪，互不干扰。"""
    state = {}
    # sub_a: 快
    for _ in range(5):
        state = sched_deadline_update(state, "sub_a", 5.0)
    # sub_b: 慢
    for _ in range(5):
        state = sched_deadline_update(state, "sub_b", 50.0)

    assert state["sub_a"]["throttle_sessions"] == 0  # 在预算内
    assert state["sub_b"]["throttle_sessions"] > 0   # 超预算被 throttle
    assert sched_deadline_should_throttle(state, "sub_a") is False
    assert sched_deadline_should_throttle(state, "sub_b") is True


if __name__ == "__main__":
    import shutil
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  PASS {t.__name__}")
        except Exception as e:
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    shutil.rmtree(_tmpdir, ignore_errors=True)
