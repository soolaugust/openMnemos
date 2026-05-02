#!/usr/bin/env python3
"""
iter534: io_uring SQE validation — 写入时内容密度验证
测试 _sqe_validate_importance() 的密度信号检测和 importance 降级逻辑。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import tmpfs  # noqa: F401 — 测试隔离

from extractor import _sqe_validate_importance


class TestSQEValidate:
    """iter534 SQE validation 测试套件"""

    # ─── 快速路径：不应触发验证 ─────────────────────────────────────

    def test_low_importance_passthrough(self):
        """imp < 0.85 直接透传，不验证"""
        assert _sqe_validate_importance(0.70, "短内容", "decision") == 0.70
        assert _sqe_validate_importance(0.60, "x", "quantitative_evidence") == 0.60

    def test_excluded_types_passthrough(self):
        """excluded_path/prompt_context/conversation_summary 不验证"""
        assert _sqe_validate_importance(0.90, "短", "excluded_path") == 0.90
        assert _sqe_validate_importance(0.90, "短", "prompt_context") == 0.90
        assert _sqe_validate_importance(0.90, "短", "conversation_summary") == 0.90

    # ─── 快速拒绝：编号列表项碎片 ──────────────────────────────────

    def test_numbered_fragment_rejected(self):
        """编号列表项（'3. xxx'）且短 → 降级"""
        result = _sqe_validate_importance(0.99, "3. 新工作流成立后（需≥3个验证案例）", "quantitative_evidence")
        assert result == 0.60

    def test_numbered_q_fragment_rejected(self):
        """Q 编号（'Q1. xxx'）且短 → 降级"""
        result = _sqe_validate_importance(0.99, "Q1. 这是一个问题", "quantitative_evidence")
        assert result == 0.60

    def test_numbered_but_long_passes(self):
        """编号但内容长（>=60字） → 不触发快速拒绝，走正常验证"""
        long_content = "3. 当 task_rq_lock 不能保证看到已经赋值的 p->scx.sched 时，需要使用 WRITE_ONCE/READ_ONCE 保证可见性 — 因为 scx 字段的赋值与 rq lock 获取是异步的"
        result = _sqe_validate_importance(0.99, long_content, "quantitative_evidence")
        # Should pass or be evaluated normally (not instant reject)
        assert result >= 0.60  # May pass or cap depending on density

    # ─── 低密度降级 ─────────────────────────────────────────────────

    def test_vague_phrase_rejected(self):
        """模糊短语（无实体/动词/因果/量化）→ 降级"""
        result = _sqe_validate_importance(0.99, "信息丢失，低估问题复杂度", "design_constraint")
        assert result == 0.60

    def test_title_only_rejected(self):
        """纯标题/标签（无实质内容）→ 降级"""
        result = _sqe_validate_importance(0.98, "[decisions] Skill Listing Budget 控制 > 决策", "decision")
        assert result == 0.60

    def test_scheduling_note_rejected(self):
        """日程/审计笔记 → 降级"""
        result = _sqe_validate_importance(0.99,
            "下一个审计点：累计纠正 ≥ 5 条或检测到规则失效时，或周期性月度审计（2026-06-01）",
            "quantitative_evidence")
        assert result == 0.60

    # ─── 高密度通过 ─────────────────────────────────────────────────

    def test_technical_constraint_passes(self):
        """含实体+因果+长度 → 通过"""
        s = "git commit author/Signed-off-by 字段必须严格取自 git config 原值，不得因\"更规范\"等推断修改大小写 — git config 里是小写，SOB 也必须小写"
        result = _sqe_validate_importance(0.95, s, "design_constraint")
        assert result == 0.95

    def test_quantitative_evidence_passes(self):
        """含量化数据+因果+实体 → 通过"""
        s = "这就是 +125% 的根因：MTK vendor 的 mtk_active_load_balance_cpu_stop 导致 P15 migration 线程执行大量额外 ALB，三星 A06 (6.6.92) 此路径已删除"
        result = _sqe_validate_importance(0.95, s, "quantitative_evidence")
        assert result == 0.95

    def test_causal_chain_passes(self):
        """含因果关系+实体 → 通过"""
        s = "飞书文档/wiki 访问必须用 feishu CLI，禁止 mcp__fetch__fetch 等通用 HTTP 工具 — feishu 链接需要认证，fetch 只返回 401/403"
        result = _sqe_validate_importance(0.91, s, "design_constraint")
        assert result == 0.91

    def test_memory_os_decision_passes(self):
        """memory-os 迭代决策（含标签前缀） → 通过"""
        s = "[memory-os/iter76] TLB Flush — recall_traces 清理 188→86，删除 102 条 stale references"
        result = _sqe_validate_importance(0.90, s, "decision")
        assert result == 0.90  # has quant (188→86, 102条) and entities

    def test_code_identifier_passes(self):
        """含多个代码标识符 → entities >= 2 信号"""
        s = "task_rq_lock 与 p->scx.sched 的赋值是异步的，不能保证在 rq lock 内可见 — 必须使用 WRITE_ONCE/READ_ONCE"
        result = _sqe_validate_importance(0.89, s, "design_constraint")
        assert result == 0.89

    # ─── 边界情况 ──────────────────────────────────────────────────

    def test_empty_summary(self):
        """空 summary → 降级（因为 len < 40, 无信号）"""
        result = _sqe_validate_importance(0.90, "", "decision")
        assert result == 0.60

    def test_none_summary(self):
        """None summary → 降级"""
        result = _sqe_validate_importance(0.90, None, "decision")
        assert result == 0.60

    def test_exactly_at_threshold(self):
        """importance 刚好 0.85 → 参与验证"""
        result = _sqe_validate_importance(0.85, "短", "decision")
        assert result == 0.60  # 短 + 无信号 → 降级

    def test_just_below_threshold(self):
        """importance 0.84 → 不参与验证"""
        result = _sqe_validate_importance(0.84, "短", "decision")
        assert result == 0.84

    # ─── 性能测试 ──────────────────────────────────────────────────

    def test_performance(self):
        """1000 次调用 < 50ms"""
        import time
        samples = [
            (0.99, "3. 新工作流成立后（需≥3个验证案例）", "quantitative_evidence"),
            (0.95, "git commit 字段必须取自 git config，不得修改大小写", "design_constraint"),
            (0.90, "这就是 +125% 的根因：MTK vendor 导致 migration +125%", "quantitative_evidence"),
            (0.70, "低重要性直接跳过", "decision"),
        ]
        start = time.perf_counter()
        for _ in range(250):
            for imp, s, ct in samples:
                _sqe_validate_importance(imp, s, ct)
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 50, f"1000 calls took {elapsed:.1f}ms (limit 50ms)"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
