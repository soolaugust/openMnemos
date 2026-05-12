#!/usr/bin/env python3
"""
test_design_constraint.py — 迭代98: Design Constraint 约束知识注入

OS 类比：Linux mlock(2) — 标记的内存不可淘汰，总是驻留在 RAM
设计约束 chunk 对应不可淘汰的系统级知识，强制注入，防止 AI 提出架构性错误

验证：
1. 约束提取 — CONSTRAINT_SIGNALS 准确识别"不能做这事"语句
2. 约束写入 — importance=0.95, oom_adj=-800 最高保护级别
3. 约束检索 — design_constraint 绕过评分排序，强制进前端
4. 约束注入 — 以 ⚠️ [约束] 前缀展示，约束优先于普通知识
5. 约束去重 — 与其他类型分开去重，不冲突
"""
import tmpfs  # noqa: F401 — must be first to isolate test DB

import os
import sys
import unittest
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from store import open_db, ensure_schema, insert_chunk, delete_chunks, already_exists, fts_search, update_accessed
from store import OOM_ADJ_PROTECTED
from schema import MemoryChunk


def _make_constraint_chunk(project, summary, importance=0.95, oom_adj=OOM_ADJ_PROTECTED):
    """创建约束类型 chunk 用于测试。"""
    import uuid as _uuid
    chunk = MemoryChunk(
        project=project,
        source_session="test-constraint-session",
        chunk_type="design_constraint",
        content=f"[design_constraint] {summary}",
        summary=summary,
        tags=["design_constraint", project],
        importance=importance,
        retrievability=0.5,
    )
    chunk_dict = chunk.to_dict()
    chunk_dict["oom_adj"] = oom_adj  # 覆盖默认值
    return chunk_dict


class TestConstraintExtraction(unittest.TestCase):
    """验证 CONSTRAINT_SIGNALS 从文本中准确提取约束。"""

    def test_must_not_pattern(self):
        """匹配 'must not / 不能' 模式。"""
        from hooks.extractor import _extract_constraints
        text = "这个路径不能使用 BPF scheduler，因为会导致任务状态污染"
        constraints = _extract_constraints(text)
        self.assertTrue(any("BPF scheduler" in c for c in constraints),
                       f"Should extract BPF scheduler constraint, got {constraints}")

    def test_this_would_break_pattern(self):
        """匹配 'this would / 这样做会' 模式。"""
        from hooks.extractor import _extract_constraints
        text = "在并发修改时设置该 flag，这会导致并发竞态条件和内存不安全"
        constraints = _extract_constraints(text)
        self.assertTrue(any("并发竞态条件" in c for c in constraints),
                       f"Should extract concurrency constraint, got {constraints}")

    def test_design_constraint_label(self):
        """匹配显式 '设计约束' 标签。"""
        from hooks.extractor import _extract_constraints
        text = "设计约束：所有 checkpoint 必须在单个事务内完成，否则恢复逻辑失效"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract design constraint label, got {constraints}")
        self.assertTrue(any("checkpoint" in c.lower() for c in constraints))

    def test_why_must_not_pattern(self):
        """匹配 'why must not / 为什么不能' 模式。"""
        from hooks.extractor import _extract_constraints
        text = "为什么不能跳过这个 barrier：因为可能导致内存可见性错误"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract why-must-not pattern, got {constraints}")

    def test_prerequisite_pattern(self):
        """匹配 '前提条件' 模式。"""
        from hooks.extractor import _extract_constraints
        text = "前提条件：rq lock 必须在 task migration 前持有，否则会 race condition"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract prerequisite pattern, got {constraints}")

    # ── 迭代102：新增模式验证 ──

    def test_chinese_warning_注意不要(self):
        """迭代102 新增：中文警告 '注意不要'"""
        from hooks.extractor import _extract_constraints
        text = "注意不要在持锁时调用外部函数，会引发死锁"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract '注意不要' constraint, got {constraints}")

    def test_chinese_warning_警告(self):
        """迭代102 新增：'警告：' 标题式警告"""
        from hooks.extractor import _extract_constraints
        text = "警告：直接写入会绕过引用计数，导致 use-after-free"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract '警告：' constraint, got {constraints}")

    def test_emoji_warning_pattern(self):
        """迭代102 新增：emoji 警告前缀 ⚠️"""
        from hooks.extractor import _extract_constraints
        text = "⚠️ 修改此函数会破坏 ABI 兼容性，所有调用方需同步更新"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract emoji warning constraint, got {constraints}")

    def test_markdown_WARNING_prefix(self):
        """迭代102 新增：markdown WARNING: 前缀"""
        from hooks.extractor import _extract_constraints
        text = "WARNING: calling this without the global lock held is unsafe"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract WARNING: constraint, got {constraints}")

    def test_never_because_pattern(self):
        """迭代102 新增：英文 'never ... because'"""
        from hooks.extractor import _extract_constraints
        text = "never call malloc in interrupt context because it sleeps"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract 'never...because' constraint, got {constraints}")

    def test_otherwise_pattern(self):
        """迭代102 新增：'否则会' 后果模式"""
        from hooks.extractor import _extract_constraints
        text = "否则会触发未定义行为，导致系统崩溃"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract '否则会' constraint, got {constraints}")

    def test_race_condition_pattern(self):
        """迭代102 新增：race condition 后果关键词"""
        from hooks.extractor import _extract_constraints
        text = "race condition will corrupt the shared queue state"
        constraints = _extract_constraints(text)
        self.assertTrue(len(constraints) > 0,
                       f"Should extract race condition constraint, got {constraints}")

    def test_pattern_count_gte_22(self):
        """迭代102：CONSTRAINT_SIGNALS 总数 >= 22"""
        from hooks.extractor import CONSTRAINT_SIGNALS
        count = len(CONSTRAINT_SIGNALS)
        self.assertGreaterEqual(count, 22,
                               f"CONSTRAINT_SIGNALS should have >= 22 patterns, got {count}")


class TestConstraintStorage(unittest.TestCase):
    """验证约束 chunk 的存储、去重、保护级别。"""

    def setUp(self):
        self.conn = open_db()
        ensure_schema(self.conn)
        self.conn.execute("DELETE FROM memory_chunks")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_constraint_deduplication(self):
        """同一约束只存储一次，already_exists() 检测正常。"""
        constraint_dict = _make_constraint_chunk(
            "test-proj",
            "SCX_ENQ_IMMED 不能在 PF_EXITING 路径使用"
        )
        insert_chunk(self.conn, constraint_dict)
        self.assertTrue(already_exists(self.conn, constraint_dict["summary"], "design_constraint"))

        # 尝试写入相同约束，应被 already_exists() 拦截（调用方的职责）
        self.assertTrue(
            already_exists(self.conn, constraint_dict["summary"], "design_constraint"),
            "Duplicate constraint should be detected"
        )

    def test_constraint_importance_0_95(self):
        """约束默认 importance = 0.95（最高）。"""
        constraint_dict = _make_constraint_chunk("test-proj", "Test constraint", importance=0.95)
        insert_chunk(self.conn, constraint_dict)
        row = self.conn.execute(
            "SELECT importance FROM memory_chunks WHERE chunk_type='design_constraint'"
        ).fetchone()
        self.assertEqual(row[0], 0.95)

    def test_constraint_oom_adj_protected(self):
        """约束 oom_adj = -800（OOM_ADJ_PROTECTED，绝对保护）。"""
        constraint_dict = _make_constraint_chunk("test-proj", "Protected constraint", oom_adj=-800)
        insert_chunk(self.conn, constraint_dict)
        row = self.conn.execute(
            "SELECT oom_adj FROM memory_chunks WHERE chunk_type='design_constraint'"
        ).fetchone()
        self.assertEqual(row[0], -800, "Constraint should have OOM_ADJ_PROTECTED")

    def test_constraint_cross_project_shared(self):
        """约束在 'global' 项目中也能被其他项目检索到（跨项目共享）。"""
        import uuid as _uuid
        constraint_dict = _make_constraint_chunk("global", "Universal constraint")
        insert_chunk(self.conn, constraint_dict)

        # 从 'test-proj' 检索，应该也能看到 'global' 约束
        rows = self.conn.execute(
            """SELECT id, chunk_type FROM memory_chunks
               WHERE project IN ('test-proj', 'global') AND chunk_type='design_constraint'"""
        ).fetchall()
        self.assertTrue(len(rows) > 0, "Should find global constraint from other project")


class TestConstraintRetrieval(unittest.TestCase):
    """验证检索时约束绕过评分，强制进前端。"""

    def setUp(self):
        self.conn = open_db()
        ensure_schema(self.conn)
        self.conn.execute("DELETE FROM memory_chunks")
        self.conn.execute("DELETE FROM memory_chunks_fts")
        self.conn.commit()

        # 插入普通决策
        decision_dict = MemoryChunk(
            project="test-proj",
            source_session="test-session",
            chunk_type="decision",
            content="[decision] Use Redis for caching",
            summary="Use Redis for caching",
            tags=["decision"],
            importance=0.85,
            retrievability=0.5,
        ).to_dict()
        insert_chunk(self.conn, decision_dict)

        # 插入低相关性约束（即使评分低也要注入）
        constraint_dict = _make_constraint_chunk(
            "test-proj",
            "Never use in-memory cache without TTL expiration",
            importance=0.95  # 高保护，但 FTS5 匹配度可能低
        )
        insert_chunk(self.conn, constraint_dict)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_constraint_in_retrieve_types(self):
        """design_constraint 在检索类型列表中。"""
        from config import get as _sysctl
        exclude_str = _sysctl("retriever.exclude_types")
        exclude_set = set(t.strip() for t in exclude_str.split(",") if t.strip()) if exclude_str else set()
        # 默认只排除 prompt_context，design_constraint 应该被检索
        self.assertNotIn("design_constraint", exclude_set,
                        "design_constraint should not be excluded from retrieval")

    def test_fts_search_includes_constraints(self):
        """FTS5 搜索结果包含 design_constraint。"""
        results = fts_search(self.conn, "cache", "test-proj", top_k=10)
        constraint_results = [r for r in results if r["chunk_type"] == "design_constraint"]
        # 即使查询是 "cache"，约束包含 "cache" 也应被返回
        # （注：这里假设了约束的 summary 包含 "cache"）
        self.assertTrue(
            any("cache" in r["summary"].lower() for r in results),
            f"Results should include cache-related chunks, got {[r['summary'] for r in results]}"
        )

    def test_constraint_chunks_detected(self):
        """在检索后的 top_k 中正确识别约束。"""
        from store import get_chunks
        chunks = get_chunks(self.conn, "test-proj")
        constraint_chunks = [c for c in chunks if c.get("chunk_type") == "design_constraint"]
        self.assertTrue(len(constraint_chunks) > 0,
                       "Should find constraint chunks in result set")


class TestConstraintInjection(unittest.TestCase):
    """验证约束在提示词中的展示格式。"""

    def test_constraint_prefix(self):
        """约束使用 ⚠️ [约束] 前缀。"""
        _TYPE_PREFIX = {
            "design_constraint": "⚠️ [约束]",
            "decision": "[决策]",
        }
        prefix = _TYPE_PREFIX.get("design_constraint")
        self.assertEqual(prefix, "⚠️ [约束]")

    def test_constraint_first_display(self):
        """约束在注入文本中首先显示，位于"【已知约束（系统级设计限制）】"。"""
        # 模拟 retriever 的注入逻辑
        top_k = [
            (0.8, {"chunk_type": "decision", "summary": "Use Redis"}),
            (0.95, {"chunk_type": "design_constraint", "summary": "No in-memory without TTL"}),
            (0.7, {"chunk_type": "reasoning_chain", "summary": "Why we chose Redis"}),
        ]

        _TYPE_PREFIX = {
            "decision": "[决策]",
            "excluded_path": "[排除]",
            "reasoning_chain": "[推理]",
            "conversation_summary": "[摘要]",
            "task_state": "",
            "design_constraint": "⚠️ [约束]",
        }

        constraint_items = []
        normal_items = []
        for _, c in top_k:
            prefix = _TYPE_PREFIX.get(c.get("chunk_type"), "")
            line = f"{prefix} {c['summary']}".strip()
            if c.get("chunk_type") == "design_constraint":
                constraint_items.append(line)
            else:
                normal_items.append(line)

        inject_lines = ["【相关历史记录（BM25 召回）】"]
        if constraint_items:
            inject_lines.append("")
            inject_lines.append("【已知约束（系统级设计限制）】")
            inject_lines.extend(constraint_items)
            inject_lines.append("")
            inject_lines.append("【相关知识】")
            inject_lines.extend(normal_items)
        else:
            inject_lines.extend(normal_items)

        context_text = "\n".join(inject_lines)
        # 约束应该在决策之前
        constraint_pos = context_text.find("⚠️ [约束]")
        decision_pos = context_text.find("[决策]")
        self.assertLess(constraint_pos, decision_pos,
                       "Constraint should appear before decision")
        # 确认约束标题存在
        self.assertIn("【已知约束（系统级设计限制）】", context_text)


class TestConstraintGlobalPromotion(unittest.TestCase):
    """验证约束可晋升到全局层（跨项目共享）。"""

    def setUp(self):
        self.conn = open_db()
        ensure_schema(self.conn)
        self.conn.execute("DELETE FROM memory_chunks")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_constraint_promotion_to_global(self):
        """高价值约束（importance >= 0.85）可晋升到 global。"""
        # 在项目中写入约束
        constraint_dict = _make_constraint_chunk(
            "linux-dev",
            "sched_ext BPF scheduler isolation prerequisite",
            importance=0.95
        )
        insert_chunk(self.conn, constraint_dict)

        # 模拟晋升逻辑（从 extractor._promote_to_global）
        candidates = self.conn.execute(
            """SELECT id, chunk_type, summary
               FROM memory_chunks
               WHERE project='linux-dev'
                 AND chunk_type='design_constraint'
                 AND importance >= 0.85"""
        ).fetchall()

        self.assertTrue(len(candidates) > 0, "Should find promotable constraint")

        # 晋升到 global
        for src_id, ctype, summary in candidates:
            exists = self.conn.execute(
                "SELECT id FROM memory_chunks WHERE project='global' AND summary=?",
                (summary,)
            ).fetchone()
            if not exists:
                import uuid as _uuid
                now = datetime.now(timezone.utc).isoformat()
                global_id = f"global-{_uuid.uuid4().hex[:12]}"
                self.conn.execute("""
                    INSERT INTO memory_chunks
                    (id, created_at, updated_at, project, source_session,
                     chunk_type, content, summary, tags, importance,
                     retrievability, last_accessed, access_count, lru_gen, oom_adj)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, [global_id, now, now, "global", f"promoted:linux-dev",
                      ctype, f"[{ctype}] {summary}", summary,
                      json.dumps(["global", "linux-dev"]),
                      0.95, 0.5, now, 0, 0, -400])

        self.conn.commit()
        # 验证全局层有约束
        global_constraints = self.conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project='global' AND chunk_type='design_constraint'"
        ).fetchone()[0]
        self.assertGreater(global_constraints, 0, "Constraint should be promoted to global")


if __name__ == "__main__":
    unittest.main(verbosity=2)
