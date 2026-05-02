"""
iter579: copy_page_range — Score Gap Bridging 测试

OS 类比：Linux copy_page_range() (Andrea Arcangeli, 2004, mm/memory.c)
  fork() 复制父进程地址空间时，大 VMA 间的 gap 不阻止复制下一个有效 VMA。
  内核遍历 page table 各层级，跳过 unmapped region，复制下一个有效 PTE。

问题：top1=0.99（精确关键词命中）vs top2=0.15（语义相关但词汇不匹配）
  adaptive_floor=0.247 过滤全部 top2+ 候选 → 永远只注入 1 个结果

解法：检测 top1/top2 > gap_ratio（score gap），若 gap 后存在内聚 cluster
  （成员分数彼此在 cluster_ratio 内），将 threshold 降至 cluster_top × cluster_ratio
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tmpfs  # noqa: E402 — 测试隔离
import pytest
from config import get as _sysctl, _REGISTRY


# ─── 单元测试：gap bridging 逻辑复现 ───

def _gap_bridge(final_scores, enabled=True, min_ratio=3.0,
                cluster_ratio=0.4, min_cluster=2, base_thresh=0.3):
    """
    复现 retriever.py 中 iter579 gap bridging 逻辑。
    final_scores: 降序排列的分数列表
    返回 effective threshold
    """
    _min_thresh = base_thresh
    # mremap adaptive floor (iter578)
    if final_scores and final_scores[0] >= 0.5:
        _adaptive_floor = final_scores[0] * 0.25
        _min_thresh = min(_min_thresh, max(_adaptive_floor, 0.10))
    # gap bridging (iter579)
    if not enabled or len(final_scores) < 3:
        return _min_thresh
    top1 = final_scores[0]
    top2 = final_scores[1] if final_scores[1] > 0 else 0.001
    if top1 / top2 < min_ratio:
        return _min_thresh
    # Gap detected
    cluster_top = final_scores[1]
    cluster_floor = cluster_top * cluster_ratio
    cluster_size = sum(1 for s in final_scores[1:] if s >= cluster_floor)
    if cluster_size < min_cluster:
        return _min_thresh
    new_thresh = max(cluster_floor, 0.05)
    if new_thresh < _min_thresh:
        _min_thresh = new_thresh
    return _min_thresh


def _count_positive(scores, thresh):
    """Count scores >= thresh"""
    return sum(1 for s in scores if s >= thresh)


class TestGapBridgeLogic:
    """Score Gap Bridging 计算逻辑"""

    def test_large_gap_bridges(self):
        """top1=0.99, top2=0.15 → gap=6.6x → bridge 降低阈值"""
        scores = [0.99, 0.15, 0.14, 0.12, 0.11, 0.10, 0.08]
        thresh = _gap_bridge(scores)
        # cluster_top=0.15, cluster_floor=0.15*0.4=0.06
        assert thresh < 0.247  # lower than mremap floor
        assert thresh == max(0.15 * 0.4, 0.05)  # = 0.06
        # Now all 7 candidates pass (0.99, 0.15, 0.14, 0.12, 0.11, 0.10, 0.08 >= 0.06)
        assert _count_positive(scores, thresh) == 7

    def test_no_gap_keeps_mremap_floor(self):
        """top1=0.99, top2=0.50 → gap=1.98x < 3.0 → no bridge"""
        scores = [0.99, 0.50, 0.45, 0.40, 0.35]
        thresh = _gap_bridge(scores)
        # mremap: 0.99*0.25 = 0.2475
        assert abs(thresh - 0.2475) < 0.001

    def test_small_cluster_no_bridge(self):
        """gap exists but cluster size < min_cluster → no bridge"""
        scores = [0.99, 0.15, 0.01, 0.005]
        # cluster_top=0.15, cluster_floor=0.06, only 1 score >= 0.06 in [1:]
        # Actually: 0.15>=0.06 ✓, 0.01<0.06, 0.005<0.06 → cluster=1 < 2
        thresh = _gap_bridge(scores, min_cluster=2)
        # Should stay at mremap floor
        assert abs(thresh - 0.2475) < 0.001

    def test_cluster_with_2_members(self):
        """gap + 2 members in cluster → bridge activates"""
        scores = [0.99, 0.15, 0.10, 0.02]
        # cluster_top=0.15, cluster_floor=0.06, members: 0.15, 0.10 >= 0.06 → 2
        thresh = _gap_bridge(scores, min_cluster=2)
        assert thresh == 0.06  # 0.15*0.4=0.06 > absolute_min 0.05

    def test_disabled_no_effect(self):
        """gap_bridge_enabled=False → 不启用"""
        scores = [0.99, 0.15, 0.14, 0.12]
        thresh = _gap_bridge(scores, enabled=False)
        assert abs(thresh - 0.2475) < 0.001

    def test_absolute_min_floor(self):
        """cluster_floor < 0.05 时被钳位到 0.05"""
        scores = [0.99, 0.10, 0.08, 0.06, 0.04]
        # cluster_top=0.10, cluster_floor=0.10*0.4=0.04 < 0.05 → clamp to 0.05
        thresh = _gap_bridge(scores)
        assert thresh == 0.05

    def test_custom_min_ratio(self):
        """自定义 min_ratio=5.0 → gap=3.3 不触发"""
        scores = [0.99, 0.30, 0.25, 0.20]
        # gap=3.3 < 5.0
        thresh = _gap_bridge(scores, min_ratio=5.0)
        # mremap floor: 0.2475
        assert abs(thresh - 0.2475) < 0.001

    def test_custom_cluster_ratio(self):
        """cluster_ratio=0.6 → 更严格的 cluster 要求"""
        scores = [0.99, 0.20, 0.15, 0.10, 0.05]
        # cluster_top=0.20, cluster_floor=0.20*0.6=0.12
        # members in [1:] >= 0.12: 0.20, 0.15 → 2
        thresh = _gap_bridge(scores, cluster_ratio=0.6)
        assert thresh == 0.12

    def test_too_few_candidates_no_bridge(self):
        """< 3 candidates → 不触发"""
        scores = [0.99, 0.15]
        thresh = _gap_bridge(scores)
        assert abs(thresh - 0.2475) < 0.001

    def test_production_scenario(self):
        """生产场景复现：top1=0.99(feishu), 其余=0.05-0.20"""
        scores = [0.99, 0.20, 0.18, 0.16, 0.14, 0.12, 0.10, 0.08, 0.06, 0.05]
        thresh = _gap_bridge(scores)
        # gap=4.95x → bridge
        # cluster_top=0.20, cluster_floor=0.20*0.4=0.08, cluster_size=8(all>=0.08)
        assert abs(thresh - 0.08) < 0.001
        # Without bridge: mremap thresh=0.2475, only 1 passes
        assert _count_positive(scores, 0.2475) == 1
        # With bridge: ~0.08 threshold, many pass
        assert _count_positive(scores, thresh) >= 5

    def test_uniform_scores_no_gap(self):
        """分数均匀分布 → 无 gap → 不触发"""
        scores = [0.50, 0.45, 0.40, 0.35, 0.30]
        # gap=1.11 < 3.0
        thresh = _gap_bridge(scores)
        # mremap: 0.50*0.25=0.125
        assert abs(thresh - 0.125) < 0.001

    def test_all_low_scores_bridge_still_activates(self):
        """全部低分 < 0.5 → mremap 不触发，但 bridge 独立工作降低阈值"""
        scores = [0.31, 0.10, 0.08, 0.05]
        # top1=0.31 < 0.5 → mremap 不启用 → thresh stays 0.30
        # gap=3.1x > 3.0 → bridge check
        # cluster_top=0.10, cluster_floor=0.04 → clamp 0.05
        # cluster_size: 0.10, 0.08, 0.05 >= 0.05 → 3
        thresh = _gap_bridge(scores)
        # 0.05 < 0.30 → bridge lowers
        assert thresh == 0.05

    def test_gap_above_boundary(self):
        """gap ratio > min_ratio → triggers bridge"""
        # top1/top2 = 0.63/0.20 = 3.15 > 3.0
        scores = [0.63, 0.20, 0.18, 0.15]
        thresh = _gap_bridge(scores)
        # mremap: 0.63*0.25=0.1575
        # gap=3.15 → bridge
        # cluster_top=0.20, cluster_floor=0.08, members: 0.20, 0.18, 0.15 → 3
        assert abs(thresh - 0.08) < 0.001


class TestGapBridgeConfig:
    """Config 注册验证"""

    def test_gap_bridge_enabled_registered(self):
        assert "retriever.gap_bridge_enabled" in _REGISTRY
        assert _sysctl("retriever.gap_bridge_enabled") is True

    def test_gap_bridge_min_ratio_registered(self):
        assert "retriever.gap_bridge_min_ratio" in _REGISTRY
        val = _sysctl("retriever.gap_bridge_min_ratio")
        assert val == 3.0

    def test_gap_bridge_cluster_ratio_registered(self):
        assert "retriever.gap_bridge_cluster_ratio" in _REGISTRY
        val = _sysctl("retriever.gap_bridge_cluster_ratio")
        assert val == 0.4

    def test_gap_bridge_min_cluster_registered(self):
        assert "retriever.gap_bridge_min_cluster" in _REGISTRY
        val = _sysctl("retriever.gap_bridge_min_cluster")
        assert val == 2


class TestGapBridgeEffects:
    """效果验证：注入数量变化"""

    def test_before_after_injection_count(self):
        """验证 bridge 前后的注入数量差异"""
        scores = [0.99, 0.20, 0.18, 0.16, 0.14, 0.12, 0.10, 0.08, 0.06, 0.05]
        # Without bridge (mremap only)
        mremap_thresh = min(0.30, max(0.99 * 0.25, 0.10))  # = 0.2475
        without_bridge = _count_positive(scores, mremap_thresh)
        # With bridge
        bridge_thresh = _gap_bridge(scores)
        with_bridge = _count_positive(scores, bridge_thresh)
        assert with_bridge > without_bridge
        assert without_bridge == 1  # only top1
        assert with_bridge >= 5    # top1 + cluster

    def test_no_noise_when_no_gap(self):
        """无 gap 时不引入额外噪音"""
        scores = [0.50, 0.45, 0.40, 0.35, 0.30, 0.25]
        thresh = _gap_bridge(scores)
        # mremap floor = 0.125 → all pass naturally
        assert _count_positive(scores, thresh) == 6


class TestPerformance:
    """性能测试"""

    def test_gap_bridge_speed(self):
        """gap bridge 逻辑耗时 < 0.1ms"""
        import time
        scores = [0.99] + [0.15 - i * 0.01 for i in range(50)]
        start = time.perf_counter()
        for _ in range(1000):
            _gap_bridge(scores)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 100  # < 0.1ms per call
        print(f"\nPerformance: {elapsed_ms/1000:.4f}ms/call ({elapsed_ms:.1f}ms for 1000 calls)")
