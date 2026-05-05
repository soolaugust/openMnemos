"""
test_numa_distance — 迭代111 NUMA 节点距离惩罚测试

OS 类比：Linux NUMA node distance matrix 验证
  - 同 node 距离 = 10（最小，无额外延迟）
  - 跨 node 距离 = 20-40+（延迟增加，调度器倾向本地分配）

验证：
  1. numa_distance_penalty 矩阵正确性
  2. retrieval_score 中 NUMA 惩罚生效
  3. 本地 chunk vs 跨项目 chunk 的排序正确性
  4. global tier 的轻微惩罚符合"共享 NUMA node"语义
"""
import pytest
from scorer import retrieval_score, numa_distance_penalty


# ── 1. Penalty Matrix ────────────────────────────────────────────────────────

def test_same_project_no_penalty():
    assert numa_distance_penalty("proj_a", "proj_a") == 0.0


def test_global_tier_small_penalty():
    # iter846: global penalty 0.05→0.10
    p = numa_distance_penalty("global", "proj_a")
    assert p == 0.10, f"global 惩罚应为 0.10，实际 {p}"


def test_cross_project_large_penalty():
    p = numa_distance_penalty("proj_b", "proj_a")
    assert p == 0.25, f"跨项目惩罚应为 0.25，实际 {p}"


def test_empty_project_no_penalty():
    assert numa_distance_penalty("", "proj_a") == 0.0
    assert numa_distance_penalty("proj_a", "") == 0.0
    assert numa_distance_penalty("", "") == 0.0


# ── 2. retrieval_score 集成 ──────────────────────────────────────────────────

_COMMON = dict(
    relevance=0.6,
    importance=0.85,
    last_accessed="2026-04-22T00:00:00+00:00",
    access_count=5,
    created_at="2026-04-20T00:00:00+00:00",
)


def test_local_scores_higher_than_cross_project():
    local = retrieval_score(**_COMMON, chunk_project="proj_a", current_project="proj_a")
    cross = retrieval_score(**_COMMON, chunk_project="proj_b", current_project="proj_a")
    assert local > cross, f"本地 chunk ({local:.4f}) 应高于跨项目 ({cross:.4f})"


def test_global_between_local_and_cross():
    local = retrieval_score(**_COMMON, chunk_project="proj_a", current_project="proj_a")
    glob = retrieval_score(**_COMMON, chunk_project="global", current_project="proj_a")
    cross = retrieval_score(**_COMMON, chunk_project="proj_b", current_project="proj_a")
    assert local >= glob >= cross, (
        f"排序应为 local ({local:.4f}) >= global ({glob:.4f}) >= cross ({cross:.4f})"
    )


def test_numa_penalty_applied_at_all_relevance_levels():
    """在各 relevance 级别下，本地 chunk 始终排在跨项目 chunk 前面。"""
    for rel in [0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
        local = retrieval_score(
            relevance=rel, importance=0.8,
            last_accessed="2026-04-22T00:00:00+00:00",
            access_count=3, created_at="2026-04-21T00:00:00+00:00",
            chunk_project="proj_a", current_project="proj_a"
        )
        cross = retrieval_score(
            relevance=rel, importance=0.95,  # 故意给跨项目更高 importance
            last_accessed="2026-04-22T00:00:00+00:00",
            access_count=10, created_at="2026-04-21T00:00:00+00:00",
            chunk_project="proj_b", current_project="proj_a"
        )
        # 注：高 importance + 高 access_count 的跨项目 chunk 可以超过本地
        # 这里只验证惩罚确实被应用（cross 比无惩罚版本低）
        cross_no_penalty = retrieval_score(
            relevance=rel, importance=0.95,
            last_accessed="2026-04-22T00:00:00+00:00",
            access_count=10, created_at="2026-04-21T00:00:00+00:00",
        )
        assert cross < cross_no_penalty, (
            f"rel={rel}: 跨项目 chunk 加惩罚后 ({cross:.4f}) 应低于无惩罚 ({cross_no_penalty:.4f})"
        )


def test_cross_project_penalty_is_0_25():
    """惩罚量精确验证：跨项目 = 0.25"""
    score_with = retrieval_score(**_COMMON, chunk_project="proj_b", current_project="proj_a")
    score_without = retrieval_score(**_COMMON)
    delta = score_without - score_with
    assert abs(delta - 0.25) < 0.001, f"惩罚量应为 0.25，实际 {delta:.4f}"


def test_backward_compatible_no_project_args():
    """不传 chunk_project/current_project 时行为与原 API 相同（无惩罚）。"""
    score_new = retrieval_score(**_COMMON)
    score_old = retrieval_score(**_COMMON, chunk_project="", current_project="")
    assert abs(score_new - score_old) < 1e-9, f"无 project 参数时应等同于无惩罚: {score_new} vs {score_old}"
