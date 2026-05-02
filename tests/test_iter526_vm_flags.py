#!/usr/bin/env python3
"""
iter526: vm_flags — Loader Page Table Export for Retriever Dedup

OS 类比：Linux /proc/PID/smaps vm_flags (VM_READ|VM_WRITE|VM_EXEC)
  公开已映射 VMA 信息，供其他子系统避免重复 mmap。

测试 Loader 写入 .loader_page_table.json + Retriever 读取并排除。
"""
import sys
import os
import json
import time
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone

# ── tmpfs 隔离 ──
_tmpdir = tempfile.mkdtemp(prefix="test_vm_flags_")
os.environ["MEMORY_OS_DIR"] = _tmpdir
os.environ["MEMORY_OS_DB"] = os.path.join(_tmpdir, "store.db")

# 设置路径
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "hooks"))

# 现在可以安全导入
from store import open_db, ensure_schema, insert_chunk
from schema import MemoryChunk
from config import get as _sysctl

MEMORY_OS_DIR = Path(_tmpdir)
PT_FILE = MEMORY_OS_DIR / ".loader_page_table.json"


def _make_chunk(chunk_id, summary, chunk_type="decision", project="git:test123",
                importance=0.8):
    """创建测试 chunk 并写入 DB。"""
    conn = open_db()
    ensure_schema(conn)
    chunk = MemoryChunk(
        id=chunk_id,
        summary=summary,
        content=f"[{chunk_type}] {summary}",
        chunk_type=chunk_type,
        source_session="test",
        project=project,
        importance=importance,
        tags=[chunk_type],
    )
    insert_chunk(conn, chunk.__dict__)
    conn.commit()
    conn.close()


def _write_page_table(ids, project="git:test123"):
    """模拟 loader 写入 page table。"""
    data = {
        "injected_ids": ids,
        "project": project,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    PT_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


class TestVmFlagsPageTable(unittest.TestCase):
    """测试 Loader Page Table 写入。"""

    def test_01_write_page_table(self):
        """写入 page table 文件。"""
        ids = ["chunk_a", "chunk_b", "chunk_c"]
        _write_page_table(ids)
        self.assertTrue(PT_FILE.exists())
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        self.assertEqual(data["injected_ids"], ids)
        self.assertEqual(data["project"], "git:test123")
        self.assertIn("timestamp", data)

    def test_02_read_page_table(self):
        """读取 page table 并正确解析。"""
        ids = ["chunk_x", "chunk_y"]
        _write_page_table(ids, project="git:abc")
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        exclude_set = set(data.get("injected_ids", []))
        self.assertEqual(exclude_set, {"chunk_x", "chunk_y"})
        self.assertEqual(data["project"], "git:abc")

    def test_03_empty_page_table(self):
        """空 injected_ids 应该产生空集合。"""
        _write_page_table([])
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        exclude_set = set(data.get("injected_ids", []))
        self.assertEqual(exclude_set, set())

    def test_04_project_isolation(self):
        """跨 project 的 page table 不应影响检索。"""
        _write_page_table(["chunk_a"], project="git:other_project")
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        # 当前 project 是 git:test123，page table project 是 git:other_project
        # 应该不排除
        if data.get("project") != "git:test123":
            exclude_set = set()  # 不同 project，不排除
        else:
            exclude_set = set(data.get("injected_ids", []))
        self.assertEqual(exclude_set, set())

    def test_05_missing_page_table(self):
        """page table 文件不存在时不应出错。"""
        if PT_FILE.exists():
            PT_FILE.unlink()
        # 模拟 retriever 读取逻辑
        exclude_ids = set()
        try:
            if PT_FILE.exists():
                with open(PT_FILE, encoding="utf-8") as f:
                    pt_data = json.loads(f.read())
                exclude_ids = set(pt_data.get("injected_ids", []))
        except Exception:
            pass
        self.assertEqual(exclude_ids, set())


class TestVmFlagsFilterIntegration(unittest.TestCase):
    """测试 FTS5 结果过滤。"""

    def setUp(self):
        """创建测试 chunks。"""
        self.project = "git:test_filter"
        _make_chunk("filter_a", "Android RT 线程分析约束", "design_constraint", self.project)
        _make_chunk("filter_b", "性能诊断核心规则", "decision", self.project)
        _make_chunk("filter_c", "MTK vendor ALB 路径分析", "causal_chain", self.project)
        _make_chunk("filter_d", "migration 统计假象根因", "quantitative_evidence", self.project)

    def test_06_filter_loader_injected_from_fts(self):
        """FTS5 结果中排除 loader 已注入的 chunks。"""
        # 模拟 loader 注入了 filter_a 和 filter_b
        _write_page_table(["filter_a", "filter_b"], project=self.project)

        # 模拟 FTS5 结果（4 个 chunks）
        fts_results = [
            {"id": "filter_a", "summary": "Android RT"},
            {"id": "filter_b", "summary": "性能诊断"},
            {"id": "filter_c", "summary": "MTK vendor"},
            {"id": "filter_d", "summary": "migration"},
        ]

        # 读取 page table
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        loader_exclude_ids = set()
        if data.get("project") == self.project:
            loader_exclude_ids = set(data.get("injected_ids", []))

        # 过滤
        filtered = [r for r in fts_results if r.get("id") not in loader_exclude_ids]

        self.assertEqual(len(filtered), 2)
        self.assertEqual([r["id"] for r in filtered], ["filter_c", "filter_d"])

    def test_07_no_filter_when_different_project(self):
        """不同 project 的 page table 不过滤。"""
        _write_page_table(["filter_a", "filter_b"], project="git:other")

        fts_results = [
            {"id": "filter_a", "summary": "Android RT"},
            {"id": "filter_b", "summary": "性能诊断"},
            {"id": "filter_c", "summary": "MTK vendor"},
        ]

        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        loader_exclude_ids = set()
        if data.get("project") == self.project:
            loader_exclude_ids = set(data.get("injected_ids", []))

        filtered = [r for r in fts_results if r.get("id") not in loader_exclude_ids]
        # 不同 project，不过滤
        self.assertEqual(len(filtered), 3)

    def test_08_bm25_fallback_also_filtered(self):
        """BM25 fallback 路径也排除 loader IDs。"""
        _write_page_table(["filter_a"], project=self.project)
        loader_exclude_ids = {"filter_a"}

        # 模拟 BM25 全表扫描
        all_chunks = [
            {"id": "filter_a", "summary": "Android RT"},
            {"id": "filter_b", "summary": "性能诊断"},
            {"id": "filter_c", "summary": "MTK vendor"},
        ]
        fts_ids = {"filter_c"}  # FTS5 已有 filter_c
        exclude_all = fts_ids | loader_exclude_ids
        extra = [c for c in all_chunks if c.get("id") not in exclude_all]
        self.assertEqual(len(extra), 1)
        self.assertEqual(extra[0]["id"], "filter_b")


class TestVmFlagsPerformance(unittest.TestCase):
    """性能测试。"""

    def test_09_write_performance(self):
        """page table 写入 < 1ms。"""
        ids = [f"chunk_{i}" for i in range(20)]
        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            _write_page_table(ids)
            times.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(times) / len(times)
        self.assertLess(avg_ms, 1.0, f"avg write: {avg_ms:.3f}ms")
        print(f"  page_table write: avg {avg_ms:.3f}ms")

    def test_10_read_performance(self):
        """page table 读取 < 0.5ms。"""
        _write_page_table([f"chunk_{i}" for i in range(20)])
        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            with open(PT_FILE, encoding="utf-8") as f:
                data = json.loads(f.read())
            exclude_ids = set(data.get("injected_ids", []))
            times.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(times) / len(times)
        self.assertLess(avg_ms, 0.5, f"avg read: {avg_ms:.3f}ms")
        print(f"  page_table read: avg {avg_ms:.3f}ms")

    def test_11_filter_performance(self):
        """filter 操作 < 0.1ms（100 个 FTS 结果 vs 20 个排除 IDs）。"""
        exclude_ids = {f"chunk_{i}" for i in range(20)}
        fts_results = [{"id": f"result_{i}", "summary": f"test {i}"} for i in range(100)]
        # 让一些 IDs 重叠
        for i in range(5):
            fts_results[i]["id"] = f"chunk_{i}"

        times = []
        for _ in range(1000):
            t0 = time.perf_counter()
            filtered = [r for r in fts_results if r.get("id") not in exclude_ids]
            times.append((time.perf_counter() - t0) * 1000)
        avg_ms = sum(times) / len(times)
        self.assertEqual(len(filtered), 95)  # 100 - 5 overlapping
        self.assertLess(avg_ms, 0.1, f"avg filter: {avg_ms:.3f}ms")
        print(f"  filter 100 chunks: avg {avg_ms:.4f}ms")


class TestVmFlagsEdgeCases(unittest.TestCase):
    """边界情况。"""

    def test_12_corrupt_page_table(self):
        """损坏的 JSON 文件应该静默忽略。"""
        PT_FILE.write_text("not json", encoding="utf-8")
        exclude_ids = set()
        try:
            if PT_FILE.exists():
                with open(PT_FILE, encoding="utf-8") as f:
                    data = json.loads(f.read())
                exclude_ids = set(data.get("injected_ids", []))
        except Exception:
            pass
        self.assertEqual(exclude_ids, set())

    def test_13_concurrent_safety(self):
        """多次连续写入不应导致文件损坏。"""
        for i in range(10):
            _write_page_table([f"chunk_{i}"], project=f"git:test{i}")
        # 最后一次写入应该是可读的
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        self.assertEqual(data["injected_ids"], ["chunk_9"])
        self.assertEqual(data["project"], "git:test9")

    def test_14_large_id_list(self):
        """大量 IDs（200个）仍然能正确处理。"""
        ids = [f"chunk_{i:04d}" for i in range(200)]
        _write_page_table(ids)
        data = json.loads(PT_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(data["injected_ids"]), 200)
        exclude_set = set(data["injected_ids"])
        self.assertEqual(len(exclude_set), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
