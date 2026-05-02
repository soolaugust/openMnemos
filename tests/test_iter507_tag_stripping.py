"""
iter507: drop_caches Tag Stripping — FTS5 索引中分类标签剥离测试

OS 类比：Linux drop_caches (2006) — flush 无用 page cache/dentry/inode。
FTS5 索引中的分类标签 token 不参与用户查询，是无用的 dentry 缓存条目。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import tmpfs  # noqa: F401

from store_vfs import _normalize_structured_summary


class TestTagStripping:
    """iter507: _normalize_structured_summary 标签剥离"""

    # ── 标签应被完全移除 ──

    def test_decisions_tag(self):
        result = _normalize_structured_summary("[decisions] 选择方案A 因为性能更好")
        assert "decisions" not in result
        assert "选择方案A" in result

    def test_memory_os_tag(self):
        result = _normalize_structured_summary("[memory-os] 迭代87: Scheduler CRUD")
        assert "memory-os" not in result
        assert "迭代87" in result

    def test_kernel_process_tag(self):
        result = _normalize_structured_summary("[kernel_process] Kernel Patch 格式规范")
        assert "kernel_process" not in result
        assert "Kernel Patch" in result

    def test_chinese_tag(self):
        result = _normalize_structured_summary("[规则/Patterns] 前端组件命名规范")
        assert "规则" not in result
        assert "Patterns" not in result
        assert "前端组件命名规范" in result

    def test_semantic_tag(self):
        result = _normalize_structured_summary("[语义化] Android 性能诊断核心规则")
        assert "语义化" not in result
        assert "Android" in result

    def test_pe_analysis_tag(self):
        result = _normalize_structured_summary("[pe_analysis] PE upstream 合并策略")
        assert "pe_analysis" not in result
        assert "PE upstream" in result

    def test_sched_ext_tag(self):
        result = _normalize_structured_summary("[sched_ext] Dispatch Queue (DSQ) 定义")
        assert "sched_ext" not in result
        assert "Dispatch Queue" in result

    # ── 不应被影响的内容 ──

    def test_no_tag_unchanged(self):
        text = "store_vfs.py 新增 writeback_pressure() 函数"
        assert _normalize_structured_summary(text) == text

    def test_merged_tag_preserved(self):
        """[merged→xxx] 不是分类标签，应保留"""
        result = _normalize_structured_summary("[merged→sem_abc] old content")
        assert "merged" in result

    def test_code_brackets_preserved(self):
        """代码中的方括号不应被误处理"""
        result = _normalize_structured_summary("array[0] 的值是 42")
        # [0] 只有1个字符，不匹配 {2,30} 长度限制
        assert "42" in result

    # ── > 分隔符处理 ──

    def test_gt_separator(self):
        result = _normalize_structured_summary("格式规范 > Subject Line")
        assert ">" not in result
        assert "格式规范" in result
        assert "Subject Line" in result

    # ── 综合效果：标签移除后文档长度缩短 ──

    def test_shorter_after_stripping(self):
        """标签移除后，FTS5 文档更短 → BM25 分数更高"""
        tagged = "[decisions] [memory-os] 采用 shrink_dcache 回收零访问 chunks"
        stripped = _normalize_structured_summary(tagged)
        assert len(stripped) < len(tagged)
        assert "采用" in stripped
        assert "decisions" not in stripped
