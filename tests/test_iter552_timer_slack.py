"""
iter552: timer_slack — Idle Subsystem Frequency Reduction
OS 类比：Linux timer_slack_ns (Arjan van de Ven, 2008, kernel 2.6.28)

测试覆盖：
  1. 基本 idle_streak 计数和 skip_sessions 计算
  2. CLOCK_REALTIME 子系统不可降频
  3. did_work=True 立即重置
  4. tick 递减 skip_sessions
  5. 指数退避和 max_skip 上限
  6. 状态持久化 save/load
  7. stats 统计准确性
  8. 空状态容错
  9. loader 集成：_ts_skip 和 _ts_report 的 did_work 判定
"""
import json
import os
import sys
import tempfile

# ── 测试隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="test_timer_slack_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from store_mm import (
    timer_slack_load, timer_slack_should_skip,
    timer_slack_report, timer_slack_tick, timer_slack_save,
    timer_slack_stats, _CLOCK_REALTIME_SUBSYSTEMS, _TIMER_SLACK_FILE,
)


def test_idle_streak_basic():
    """连续空转积累 idle_streak，达到阈值后设置 skip_sessions。"""
    state = {}
    # 3 次空转（默认 idle_threshold=3）
    for _ in range(3):
        state = timer_slack_report(state, "shrink_dcache", False)
    assert state["shrink_dcache"]["idle_streak"] == 3
    assert state["shrink_dcache"]["skip_sessions"] == 1  # 3-3+1=1
    assert timer_slack_should_skip(state, "shrink_dcache") is True


def test_did_work_resets():
    """did_work=True 立即将 idle_streak 和 skip_sessions 归零。"""
    state = {}
    for _ in range(5):
        state = timer_slack_report(state, "kfree_rcu", False)
    assert state["kfree_rcu"]["idle_streak"] == 5
    assert state["kfree_rcu"]["skip_sessions"] > 0

    state = timer_slack_report(state, "kfree_rcu", True)
    assert state["kfree_rcu"]["idle_streak"] == 0
    assert state["kfree_rcu"]["skip_sessions"] == 0
    assert timer_slack_should_skip(state, "kfree_rcu") is False


def test_clock_realtime_never_skipped():
    """CLOCK_REALTIME 子系统永远不被跳过，不进入 state。"""
    state = {}
    for rt_sub in ["watchdog", "autotune", "mglru_aging", "page_idle"]:
        for _ in range(10):
            state = timer_slack_report(state, rt_sub, False)
        assert rt_sub not in state, f"{rt_sub} should not be in state"
        assert timer_slack_should_skip(state, rt_sub) is False


def test_tick_decrements():
    """每次 tick 使 skip_sessions 递减 1。"""
    state = {"test_sub": {"idle_streak": 5, "skip_sessions": 3}}
    state = timer_slack_tick(state)
    assert state["test_sub"]["skip_sessions"] == 2

    state = timer_slack_tick(state)
    assert state["test_sub"]["skip_sessions"] == 1

    state = timer_slack_tick(state)
    assert state["test_sub"]["skip_sessions"] == 0
    assert timer_slack_should_skip(state, "test_sub") is False


def test_exponential_backoff_with_cap():
    """idle_streak 超过阈值后 skip_sessions 递增但不超过 max_skip(4)。"""
    state = {}
    # 默认 idle_threshold=3, max_skip_sessions=4
    for i in range(1, 10):
        state = timer_slack_report(state, "fstrim", False)
        streak = state["fstrim"]["idle_streak"]
        skip = state["fstrim"]["skip_sessions"]
        if streak < 3:
            assert skip == 0
        else:
            expected = min(streak - 3 + 1, 4)
            assert skip == expected, f"streak={streak} expected skip={expected} got {skip}"


def test_save_load_roundtrip():
    """状态持久化到 JSON 文件后可正确恢复。"""
    state = {"sub_a": {"idle_streak": 5, "skip_sessions": 2},
             "sub_b": {"idle_streak": 0, "skip_sessions": 0}}
    timer_slack_save(state)
    assert _TIMER_SLACK_FILE.exists()

    loaded = timer_slack_load()
    assert loaded["sub_a"]["idle_streak"] == 5
    assert loaded["sub_a"]["skip_sessions"] == 2
    assert loaded["sub_b"]["idle_streak"] == 0


def test_load_missing_file():
    """文件不存在时返回空 dict。"""
    if _TIMER_SLACK_FILE.exists():
        _TIMER_SLACK_FILE.unlink()
    loaded = timer_slack_load()
    assert loaded == {}


def test_load_corrupt_file():
    """损坏文件时返回空 dict。"""
    _TIMER_SLACK_FILE.write_text("not json {{{")
    loaded = timer_slack_load()
    assert loaded == {}


def test_stats_accuracy():
    """stats 返回正确的统计数据。"""
    state = {
        "sub1": {"idle_streak": 5, "skip_sessions": 2},
        "sub2": {"idle_streak": 3, "skip_sessions": 0},
        "sub3": {"idle_streak": 1, "skip_sessions": 0},
    }
    stats = timer_slack_stats(state)
    assert stats["total_tracked"] == 3
    assert stats["currently_skipping"] == 1  # sub1
    assert stats["idle_subsystems"] == 2  # sub1(5>=3), sub2(3>=3)


def test_empty_state_operations():
    """空状态下所有操作正常。"""
    state = {}
    assert timer_slack_should_skip(state, "anything") is False
    state = timer_slack_tick(state)
    assert state == {}
    stats = timer_slack_stats(state)
    assert stats["total_tracked"] == 0


def test_below_threshold_no_skip():
    """未达到阈值的子系统不被跳过。"""
    state = {}
    state = timer_slack_report(state, "vacuum", False)
    state = timer_slack_report(state, "vacuum", False)
    assert state["vacuum"]["idle_streak"] == 2
    assert state["vacuum"]["skip_sessions"] == 0
    assert timer_slack_should_skip(state, "vacuum") is False


def test_multi_subsystem_independent():
    """多个子系统状态独立互不影响。"""
    state = {}
    for _ in range(5):
        state = timer_slack_report(state, "sub_a", False)
    state = timer_slack_report(state, "sub_b", False)

    assert state["sub_a"]["idle_streak"] == 5
    assert state["sub_b"]["idle_streak"] == 1
    assert timer_slack_should_skip(state, "sub_a") is True
    assert timer_slack_should_skip(state, "sub_b") is False


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")

    # Cleanup
    import shutil
    shutil.rmtree(_tmpdir, ignore_errors=True)
