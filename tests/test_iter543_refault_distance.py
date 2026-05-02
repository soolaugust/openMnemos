"""
iter543: refault_distance — Constraint Force-Injection Relevance Gate

OS 类比：Linux workingset.c refault_distance (Johannes Weiner, 2018, kernel 4.18)
  页面被淘汰后重新 fault in 时，kernel 计算 refault_distance。
  若 distance < working_set_size → promote 到 active list（真正的工作集页面）
  若 distance >= working_set_size → 保持 inactive（streaming/scanning access，防 cache pollution）

问题（数据驱动）：
  chunk 3192147e (design_constraint, ac=89) 出现在 42% 的 unique queries 中，
  force-injection 使用 hardcoded score=0.99 绕过了所有 anti-monopoly 机制
  （saturation_penalty, bandwidth_throttle, tmv_discount）。
  根因：_constraint_relevance() 的 Jaccard 结果仅用于排序，不用于门控。
  Jaccard=0.0 的无关约束仍被 score=0.99 注入 → 跨 query cache pollution。

测试覆盖：
  T1: constraint_min_relevance 门控 — Jaccard < threshold 的约束被拦截
  T2: constraint_min_relevance=0.0 退化 — 关闭门控，所有约束通过
  T3: thrash dampener — recall_count/window > thrash_max_pct 的约束被拦截
  T4: thrash dampener 放行 — recall_count/window <= thrash_max_pct 的约束正常通过
  T5: 双条件联合 — relevance 高但 thrash 超标 → 拦截
  T6: 双条件联合 — thrash 正常但 relevance 低 → 拦截
  T7: sysctl tunables 存在性 — constraint_min_relevance, constraint_thrash_max_pct 注册正确
  T8: sysctl 范围 — tunables 的 min/max 范围合理
  T9: 相关约束正常注入 — Jaccard 高 + thrash 低 → 通过门控
  T10: 边界条件 — Jaccard 恰好等于 threshold → 通过
  T11: 边界条件 — thrash 恰好等于 threshold → 通过
  T12: 空 recall_counts — 无历史数据时约束正常通过（不误拦）
"""
import tmpfs  # noqa: F401  — 测试隔离，必须在 store import 之前
import re
import pytest
from config import get as sysctl_get


# ── 模拟 refault_distance 门控逻辑（从 retriever.py 提取的核心判断） ──

def _constraint_relevance(query_words: set, summary: str) -> float:
    """计算 query 词集与 summary 词集的 Jaccard 相似度。"""
    s_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ', summary.lower()).split())
    if not query_words or not s_words:
        return 0.0
    return len(query_words & s_words) / len(query_words | s_words)


def refault_distance_gate(
    constraints: list,
    query: str,
    recall_counts: dict,
    min_relevance: float = 0.05,
    thrash_max_pct: float = 0.40,
    bw_window: int = 30,
) -> list:
    """
    iter543 refault_distance 门控：过滤掉不在当前工作集内的约束。
    返回通过门控的约束列表。
    """
    query_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ', query.lower()).split())
    return [
        c for c in constraints
        if _constraint_relevance(query_words, c.get("summary", "")) >= min_relevance
        and (recall_counts.get(c.get("id", ""), 0) / max(bw_window, 1)) <= thrash_max_pct
    ]


# ── T1: Jaccard < threshold → 拦截 ──

def test_low_relevance_gated():
    """Jaccard=0 的无关约束被 refault_distance 门控拦截。"""
    constraints = [
        {"id": "c1", "summary": "memory 引用前必须用 Glob/Read 验证路径存在"},
    ]
    # query 与 constraint 无词重叠
    result = refault_distance_gate(
        constraints, "请帮我写一个 Python 函数", {}, min_relevance=0.05)
    assert len(result) == 0, "zero-relevance constraint should be gated"


# ── T2: min_relevance=0.0 退化 — 门控关闭 ──

def test_min_relevance_zero_passthrough():
    """min_relevance=0.0 时门控完全关闭，所有约束通过。"""
    constraints = [
        {"id": "c1", "summary": "memory 引用前必须用 Glob/Read 验证路径存在"},
    ]
    result = refault_distance_gate(
        constraints, "请帮我写一个 Python 函数", {}, min_relevance=0.0)
    assert len(result) == 1, "min_relevance=0 should pass all"


# ── T3: thrash dampener — recall/window > max_pct → 拦截 ──

def test_thrash_dampener_blocks():
    """cross-query presence 超过 thrash_max_pct 的约束被拦截。"""
    constraints = [
        {"id": "c1", "summary": "memory 验证路径存在 check glob read"},
    ]
    # Jaccard 有重叠但 thrash 超标：recall=15, window=30 → 50% > 40%
    result = refault_distance_gate(
        constraints, "memory 验证",
        {"c1": 15}, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 0, "thrashing constraint should be gated"


# ── T4: thrash 正常 → 放行 ──

def test_thrash_dampener_allows():
    """cross-query presence 未超标的约束正常通过。"""
    constraints = [
        {"id": "c1", "summary": "memory 验证路径存在 check glob read"},
    ]
    # recall=3, window=30 → 10% < 40%
    result = refault_distance_gate(
        constraints, "memory 验证",
        {"c1": 3}, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 1, "non-thrashing constraint should pass"


# ── T5: relevance 高 + thrash 超标 → 拦截 ──

def test_high_relevance_but_thrashing():
    """即使 Jaccard 高，如果 thrash 超标也被拦截（AND 逻辑）。"""
    constraints = [
        {"id": "c1", "summary": "memory 引用前必须用 Glob Read 验证路径存在"},
    ]
    # 高相关 + 高 thrash
    result = refault_distance_gate(
        constraints, "memory 引用 验证 路径",
        {"c1": 20}, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 0, "high relevance + thrashing → gated"


# ── T6: thrash 正常 + relevance 低 → 拦截 ──

def test_low_thrash_but_irrelevant():
    """thrash 正常但 Jaccard 不足也被拦截（AND 逻辑）。"""
    constraints = [
        {"id": "c1", "summary": "Android 性能诊断核心规则"},
    ]
    result = refault_distance_gate(
        constraints, "请帮我写一个 Python 排序函数",
        {"c1": 1}, min_relevance=0.05, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 0, "low relevance + low thrash → still gated"


# ── T7: sysctl tunables 存在性 ──

def test_sysctl_constraint_min_relevance_exists():
    """constraint_min_relevance tunable 已注册。"""
    val = sysctl_get("retriever.constraint_min_relevance")
    assert val is not None
    assert isinstance(val, float)
    assert val == 0.05  # default


def test_sysctl_constraint_thrash_max_pct_exists():
    """constraint_thrash_max_pct tunable 已注册。"""
    val = sysctl_get("retriever.constraint_thrash_max_pct")
    assert val is not None
    assert isinstance(val, float)
    assert val == 0.40  # default


# ── T8: sysctl 范围合理 ──

def test_sysctl_ranges():
    """tunables 的范围限制合理。"""
    from config import _REGISTRY
    # constraint_min_relevance: [0.0, 0.5]
    entry = _REGISTRY["retriever.constraint_min_relevance"]
    assert entry[2] == 0.0   # lo
    assert entry[3] == 0.5   # hi
    # constraint_thrash_max_pct: [0.1, 0.8]
    entry = _REGISTRY["retriever.constraint_thrash_max_pct"]
    assert entry[2] == 0.1   # lo
    assert entry[3] == 0.8   # hi


# ── T9: 相关约束正常注入 ──

def test_relevant_constraint_passes():
    """Jaccard 高 + thrash 低 → 正常通过门控。"""
    constraints = [
        {"id": "c1", "summary": "memory 引用前必须用 Glob Read 验证路径存在"},
    ]
    result = refault_distance_gate(
        constraints, "memory 路径 验证",
        {"c1": 2}, min_relevance=0.05, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 1


# ── T10: 边界 — Jaccard 恰好等于 threshold ──

def test_boundary_relevance_equals_threshold():
    """Jaccard 恰好等于 min_relevance → 通过（>= 语义）。"""
    # Craft query/summary with known Jaccard
    # "a b c" vs "a d e" → intersection={"a"}, union={"a","b","c","d","e"} → J=0.2
    constraints = [{"id": "c1", "summary": "a d e"}]
    result = refault_distance_gate(
        constraints, "a b c", {}, min_relevance=0.2, bw_window=30)
    assert len(result) == 1, "Jaccard == threshold should pass"


# ── T11: 边界 — thrash 恰好等于 threshold ──

def test_boundary_thrash_equals_threshold():
    """thrash pct 恰好等于 thrash_max_pct → 通过（<= 语义）。"""
    constraints = [{"id": "c1", "summary": "memory 验证"}]
    # recall=12, window=30 → 40% == 40%
    result = refault_distance_gate(
        constraints, "memory 验证",
        {"c1": 12}, thrash_max_pct=0.40, bw_window=30)
    assert len(result) == 1, "thrash == threshold should pass"


# ── T12: 空 recall_counts 不误拦 ──

def test_empty_recall_counts_no_false_positive():
    """无历史 recall 数据时，相关约束不被误拦。"""
    constraints = [
        {"id": "c1", "summary": "memory 引用前必须用 Glob Read 验证路径存在"},
        {"id": "c2", "summary": "飞书文档访问必须用 feishu CLI"},
    ]
    result = refault_distance_gate(
        constraints, "memory 引用 验证 路径",
        {}, min_relevance=0.05, bw_window=30)
    # c1 相关，c2 不相关
    assert len(result) == 1
    assert result[0]["id"] == "c1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
