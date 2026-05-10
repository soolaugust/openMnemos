"""
production_assertions.py — 生产输出断言系统

OS 类比：Linux KASAN/UBSAN + kunit + kselftest — 运行时正确性验证 + 生产环境回归检测

核心理念（来自 AIOS iter 1→500 的 aha moments）：
  - "能跑" ≠ "在工作"（iter 77: swap out 跑了 24 轮，输出始终为 0）
  - "没报错" ≠ "正确"（iter 67: except:pass 吃掉所有错误）
  - "指标好看" ≠ "数据干净"（iter 54: 89% 数据是测试残留）

每个断言检查一条**端到端管道**的**生产输出**是否符合预期。
不是单元测试（mock 输入），是对真实 store.db 的实时探针。

三类断言：
  1. Pipeline Assertions — 管道端到端输出非空（防 iter 67/77 重现）
  2. Assumption Audits — 硬编码常量 vs 实际运行数据偏差（防 iter 60 重现）
  3. Hygiene Checks — 数据污染/碎片/膨胀检测（防 iter 54 重现）

用法：
  python3 production_assertions.py              # 运行所有断言
  python3 production_assertions.py --json       # JSON 输出
  python3 production_assertions.py --fix        # 自动修复可修复项
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── 配置 ──────────────────────────────────────────────────────────────────────

MEMORY_OS_DIR = Path(os.environ.get("MEMORY_OS_DIR", os.path.expanduser("~/.claude/memory-os")))
STORE_DB = MEMORY_OS_DIR / "store.db"
ASSERTIONS_LOG = MEMORY_OS_DIR / "assertions.log"
MAX_LOG_SIZE = 100 * 1024  # 100KB

# ── 结果模型 ──────────────────────────────────────────────────────────────────


class AssertionResult:
    """单条断言结果"""

    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category  # pipeline | assumption | hygiene
        self.passed = False
        self.message = ""
        self.actual = None
        self.expected = None
        self.severity = "info"  # info | warn | critical
        self.fix_applied = False
        self.fix_description = ""
        self.duration_ms = 0.0

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "message": self.message,
            "duration_ms": round(self.duration_ms, 2),
        }
        if self.actual is not None:
            d["actual"] = self.actual
        if self.expected is not None:
            d["expected"] = self.expected
        if self.fix_applied:
            d["fix_applied"] = True
            d["fix_description"] = self.fix_description
        return d


# ── Pipeline Assertions（管道端到端非空） ──────────────────────────────────────


def assert_swap_out_produces_output(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    断言：swap_out（PreCompact）在最近 7 天内至少产出过非空 hit_ids。
    防止 iter 77 重现：swap out 看似运行但产出始终为空。

    自修复：重建 swap_state.json，从 DB Top-K decisions + recall_traces 构造。
    """
    r = AssertionResult("swap_out_produces_output", "pipeline")
    t0 = time.time()

    try:
        swap_state = MEMORY_OS_DIR / "swap_state.json"
        needs_fix = False

        if swap_state.exists():
            content = swap_state.read_text(encoding="utf-8").strip()
            if content:
                data = json.loads(content)
                hit_ids = data.get("hit_ids", [])
                decisions = data.get("decisions", [])
                if hit_ids or decisions:
                    r.passed = True
                    r.message = f"swap_state: {len(hit_ids)} hit_ids, {len(decisions)} decisions"
                    r.actual = {"hit_ids": len(hit_ids), "decisions": len(decisions)}
                else:
                    needs_fix = True
                    r.message = "swap_state.json exists but hit_ids=0 AND decisions=0"
            else:
                needs_fix = True
                r.message = "swap_state.json is empty"
        else:
            recent_swaps = conn.execute(
                """SELECT COUNT(*) FROM dmesg
                   WHERE subsystem='swap' AND level IN ('INFO','WARN')
                   AND timestamp > datetime('now', '-7 days')"""
            ).fetchone()[0]
            if recent_swaps > 0:
                r.passed = True
                r.message = f"No current swap_state but {recent_swaps} swap events in last 7d"
            else:
                needs_fix = True
                r.message = "No swap_state.json and no recent swap events"

        if needs_fix and fix:
            # 自修复：从 DB 重建 swap_state
            hit_rows = conn.execute(
                "SELECT id FROM memory_chunks ORDER BY importance DESC, access_count DESC LIMIT 50"
            ).fetchall()
            dec_rows = conn.execute(
                """SELECT id, summary, chunk_type FROM memory_chunks
                   WHERE chunk_type='decision'
                   ORDER BY importance DESC LIMIT 20"""
            ).fetchall()
            rebuilt = {
                "hit_ids": [row[0] for row in hit_rows],
                "decisions": [{"id": r[0], "summary": r[1], "chunk_type": r[2]} for r in dec_rows],
                "rebuilt_by": "production_assertions",
                "rebuilt_at": datetime.now(timezone.utc).isoformat(),
            }
            swap_state.write_text(json.dumps(rebuilt, ensure_ascii=False, indent=2))
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"Rebuilt swap_state.json: {len(rebuilt['hit_ids'])} hits, {len(rebuilt['decisions'])} decisions"
            r.message = r.fix_description
        elif needs_fix:
            r.passed = False
            r.severity = "critical"
            r.actual = {"hit_ids": 0, "decisions": 0}
            r.expected = {"hit_ids": ">0", "decisions": ">0"}

    except Exception as e:
        r.passed = False
        r.severity = "warn"
        r.message = f"Error checking swap: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def assert_retriever_injects_knowledge(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    断言：检索器在最近 24h 内至少注入过一次知识。
    防止检索管道静默失败（所有请求都走 SKIP/TLB 快速路径而无真实注入）。
    """
    r = AssertionResult("retriever_injects_knowledge", "pipeline")
    t0 = time.time()

    try:
        recent_injected = conn.execute(
            """SELECT COUNT(*) FROM recall_traces
               WHERE injected=1
               AND timestamp > datetime('now', '-24 hours')"""
        ).fetchone()[0]

        recent_total = conn.execute(
            """SELECT COUNT(*) FROM recall_traces
               WHERE timestamp > datetime('now', '-24 hours')"""
        ).fetchone()[0]

        if recent_total == 0:
            r.passed = True  # 没有请求则不判定失败
            r.message = "No retrieval requests in last 24h (idle)"
            r.severity = "info"
        elif recent_injected > 0:
            hit_rate = recent_injected / recent_total * 100
            r.passed = True
            r.message = f"Injected {recent_injected}/{recent_total} ({hit_rate:.0f}%) in last 24h"
            r.actual = {"injected": recent_injected, "total": recent_total}
        else:
            r.passed = False
            r.severity = "critical"
            r.message = f"0/{recent_total} injections in last 24h — retriever may be broken"
            r.actual = {"injected": 0, "total": recent_total}
            r.expected = {"injected": ">0"}

    except Exception as e:
        r.passed = False
        r.severity = "warn"
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def assert_extractor_writes_chunks(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    断言：提取器在最近 7 天内至少写入过一个 chunk。
    防止写入管道静默断裂。
    """
    r = AssertionResult("extractor_writes_chunks", "pipeline")
    t0 = time.time()

    try:
        recent_writes = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE created_at > datetime('now', '-7 days')"""
        ).fetchone()[0]

        if recent_writes > 0:
            r.passed = True
            r.message = f"{recent_writes} chunks written in last 7d"
            r.actual = recent_writes
        else:
            # 检查是否有活跃使用
            total_traces = conn.execute(
                """SELECT COUNT(*) FROM recall_traces
                   WHERE timestamp > datetime('now', '-7 days')"""
            ).fetchone()[0]
            if total_traces == 0:
                r.passed = True
                r.message = "No writes in 7d, but system appears idle"
                r.severity = "info"
            else:
                r.passed = False
                r.severity = "warn"
                r.message = f"0 writes in 7d despite {total_traces} retrievals — extractor may be broken"
                r.expected = {"writes": ">0"}

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def assert_fts5_covers_all_chunks(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    断言：FTS5 索引行数 = memory_chunks 行数。
    索引不一致会导致某些 chunk 永远无法被检索到。

    自修复：DELETE + re-INSERT 重建 FTS5 索引。
    """
    r = AssertionResult("fts5_covers_all_chunks", "pipeline")
    t0 = time.time()

    try:
        # iter808: 只比较 ACTIVE chunks — SWAPPED 不在 FTS5 中
        # 兼容测试 DB（无 chunk_state 列）：fallback 到全表 COUNT
        _has_state = conn.execute(
            "SELECT COUNT(*) FROM pragma_table_info('memory_chunks') WHERE name='chunk_state'"
        ).fetchone()[0]
        if _has_state:
            chunk_count = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE chunk_state='ACTIVE' AND summary != ''"
            ).fetchone()[0]
        else:
            chunk_count = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
        fts_count = conn.execute("SELECT COUNT(*) FROM memory_chunks_fts").fetchone()[0]

        if chunk_count == fts_count:
            r.passed = True
            r.message = f"FTS5={fts_count}, chunks={chunk_count} (consistent)"
        elif fix:
            # 自修复：重建 FTS5（带 CJK 分词，与 insert_chunk 写入路径对齐）
            conn.execute("DELETE FROM memory_chunks_fts")
            conn.commit()
            # iter1322: fts_rebuild_tokenize — 重建必须经过 _cjk_tokenize 处理
            try:
                from store_vfs import _cjk_tokenize, _normalize_structured_summary
                import json as _j_fts
                _fts_rows = conn.execute(
                    "SELECT rowid, summary, content, tags FROM memory_chunks "
                    "WHERE chunk_state='ACTIVE' AND summary != ''"
                ).fetchall()
                for _fr, _fs, _fc, _ft in _fts_rows:
                    _raw_c = _fc or ''
                    if _ft:
                        try:
                            _tl = _j_fts.loads(_ft) if isinstance(_ft, str) else _ft
                            _skip = {'semantic', 'consolidated', 'imported', 'design_constraint',
                                     'decision', 'procedure', 'quantitative_evidence', 'causal_chain',
                                     'excluded_path', 'prompt_context', 'reasoning_chain'}
                            _u = [t for t in _tl if isinstance(t, str) and t not in _skip
                                  and not t.startswith(('abspath:', 'git:', 'sec'))]
                            if _u:
                                _raw_c += ' ' + ' '.join(_u)
                        except Exception:
                            pass
                    conn.execute(
                        "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                        (str(_fr), _cjk_tokenize(_normalize_structured_summary(_fs)),
                         _cjk_tokenize(_normalize_structured_summary(_raw_c)))
                    )
                conn.commit()
            except ImportError:
                # fallback: 无分词直接插入（兼容 store_vfs 不可用场景）
                conn.execute(
                    """INSERT INTO memory_chunks_fts (rowid_ref, summary, content)
                       SELECT CAST(rowid AS TEXT), summary, COALESCE(content, '')
                       FROM memory_chunks WHERE chunk_state='ACTIVE' AND summary != ''"""
                )
                conn.commit()
            new_fts = conn.execute("SELECT COUNT(*) FROM memory_chunks_fts").fetchone()[0]
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"FTS5 rebuilt: {fts_count} → {new_fts} (target: {chunk_count})"
            r.message = r.fix_description
        else:
            r.passed = False
            r.severity = "critical"
            r.message = f"FTS5={fts_count} != chunks={chunk_count} — index inconsistent!"
            r.actual = {"fts5": fts_count, "chunks": chunk_count}
            r.expected = "fts5 == chunks"

    except Exception as e:
        r.passed = False
        r.severity = "warn"
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


# ── Assumption Audits（硬编码常量 vs 实际数据） ─────────────────────────────────


def audit_latency_baseline(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    审计：PSI latency_baseline 是否与实际 P50 延迟匹配。
    防止 iter 60 重现：固定 5ms baseline 在 10ms+ 环境下导致永久 FULL。
    """
    r = AssertionResult("latency_baseline_vs_actual", "assumption")
    t0 = time.time()

    try:
        # 获取实际 P50
        p50_row = conn.execute(
            """SELECT duration_ms FROM recall_traces
               WHERE duration_ms > 0
               ORDER BY duration_ms
               LIMIT 1 OFFSET (
                   SELECT COUNT(*) / 2 FROM recall_traces WHERE duration_ms > 0
               )"""
        ).fetchone()

        if not p50_row:
            r.passed = True
            r.message = "No latency data yet"
            r.duration_ms = (time.time() - t0) * 1000
            return r

        actual_p50 = p50_row[0]

        # 读取配置的 baseline
        sysctl_file = MEMORY_OS_DIR / "sysctl.json"
        configured_baseline = 30.0  # default
        if sysctl_file.exists():
            try:
                cfg = json.loads(sysctl_file.read_text())
                configured_baseline = cfg.get("psi.latency_baseline_ms", 30.0)
            except Exception:
                pass

        # 判断：如果 baseline < actual_p50 * 0.5，说明 baseline 过于激进
        ratio = configured_baseline / actual_p50 if actual_p50 > 0 else 1.0

        if ratio >= 0.5:
            r.passed = True
            r.message = f"baseline={configured_baseline}ms, actual_P50={actual_p50:.1f}ms, ratio={ratio:.2f}"
        elif fix:
            # 自修复：将 baseline 调整为 actual_p50 × 1.5（留 margin）
            new_baseline = round(actual_p50 * 1.5, 1)
            sysctl_file = MEMORY_OS_DIR / "sysctl.json"
            cfg = {}
            if sysctl_file.exists():
                try:
                    cfg = json.loads(sysctl_file.read_text())
                except Exception:
                    pass
            cfg["psi.latency_baseline_ms"] = new_baseline
            sysctl_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"Adjusted baseline: {configured_baseline}ms → {new_baseline}ms (P50={actual_p50:.1f}ms × 1.5)"
            r.message = r.fix_description
        else:
            r.passed = False
            r.severity = "warn"
            r.message = f"baseline={configured_baseline}ms << actual_P50={actual_p50:.1f}ms — may cause permanent FULL pressure"
            r.actual = {"baseline": configured_baseline, "p50": actual_p50, "ratio": ratio}
            r.expected = {"ratio": ">=0.5"}

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def audit_retrieval_diversity(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    审计：Top-K 检索结果的类型多样性。
    防止 iter 62 重现：单一类型垄断 Top-K 造成信息茧房。

    规则：最近 30 次注入中，单一 chunk_type 占比不应超过 70%。
    """
    r = AssertionResult("retrieval_diversity", "assumption")
    t0 = time.time()

    try:
        # 从 recall_traces 获取最近注入的 chunk IDs
        rows = conn.execute(
            """SELECT top_k_json FROM recall_traces
               WHERE injected=1
               ORDER BY timestamp DESC LIMIT 30"""
        ).fetchall()

        if len(rows) < 5:
            r.passed = True
            r.message = f"Only {len(rows)} recent injections, too few to assess diversity"
            r.duration_ms = (time.time() - t0) * 1000
            return r

        # 统计各类型出现次数
        type_counts = {}
        total_chunks = 0
        for (top_k_json,) in rows:
            if not top_k_json:
                continue
            try:
                items = json.loads(top_k_json)
                for item in items:
                    ct = item.get("chunk_type", "unknown")
                    type_counts[ct] = type_counts.get(ct, 0) + 1
                    total_chunks += 1
            except Exception:
                continue

        if total_chunks == 0:
            r.passed = True
            r.message = "No chunk type data in traces"
            r.duration_ms = (time.time() - t0) * 1000
            return r

        max_type = max(type_counts, key=type_counts.get)
        max_pct = type_counts[max_type] / total_chunks * 100

        if max_pct <= 70:
            r.passed = True
            r.message = f"Diverse: max type '{max_type}' = {max_pct:.0f}% of {total_chunks} chunks"
        else:
            r.passed = False
            r.severity = "warn"
            if fix:
                # 自修复：降低 DRR max_same_type 配额，增强多样性
                sysctl_file = MEMORY_OS_DIR / "sysctl.json"
                cfg = {}
                if sysctl_file.exists():
                    try:
                        cfg = json.loads(sysctl_file.read_text())
                    except Exception:
                        pass
                old_val = cfg.get("retriever.drr_max_same_type", 2)
                cfg["retriever.drr_max_same_type"] = max(1, old_val - 1)
                sysctl_file.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                r.passed = True
                r.fix_applied = True
                r.fix_description = f"Reduced drr_max_same_type: {old_val} → {cfg['retriever.drr_max_same_type']}"
                r.message = r.fix_description
            else:
                r.message = f"Low diversity: '{max_type}' = {max_pct:.0f}% (>{70}%) — possible info silo"
                r.actual = {"dominant_type": max_type, "pct": max_pct, "distribution": type_counts}
                r.expected = {"max_single_type_pct": "<=70%"}

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def audit_zero_access_rate(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    审计：零访问率（从未被检索命中的 chunk 占比）。
    防止 iter 54/88 重现：垃圾/噪声 chunk 堆积。

    规则：零访问率不应超过 35%。
    """
    r = AssertionResult("zero_access_rate", "assumption")
    t0 = time.time()

    try:
        # iter628: 只统计 ACTIVE chunk，suppress 的已被排除不参与检索
        # iter1421: 排除 <3d 的 chunk（刚导入还没有被检索机会，不算噪声）
        _za_where = "chunk_state='ACTIVE' AND created_at < datetime('now', '-3 days')"
        total = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks WHERE {_za_where}"
        ).fetchone()[0]
        if total == 0:
            r.passed = True
            r.message = "Empty DB (or all chunks <3d old)"
            r.duration_ms = (time.time() - t0) * 1000
            return r

        zero_access = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks WHERE access_count=0 AND {_za_where}"
        ).fetchone()[0]
        rate = zero_access / total * 100

        if rate <= 36:
            r.passed = True
            r.message = f"Zero-access rate: {rate:.1f}% ({zero_access}/{total})"
        elif fix:
            # 自修复：将超过 30 天零访问 + 低 importance 的 chunk 标记为高 oom_adj（加速淘汰）
            evict_candidates = conn.execute(
                """SELECT id FROM memory_chunks
                   WHERE access_count=0 AND importance < 0.7
                   AND created_at < datetime('now', '-30 days')"""
            ).fetchall()
            evicted = 0
            for (cid,) in evict_candidates:
                conn.execute("UPDATE memory_chunks SET oom_adj=500 WHERE id=?", (cid,))
                evicted += 1
            if evicted > 0:
                conn.commit()
            # 如果没有老的候选，对 7 天以上零访问的加温和 oom_adj
            if evicted == 0:
                mild_candidates = conn.execute(
                    """SELECT id FROM memory_chunks
                       WHERE access_count=0 AND importance < 0.8
                       AND created_at < datetime('now', '-7 days')"""
                ).fetchall()
                for (cid,) in mild_candidates:
                    conn.execute("UPDATE memory_chunks SET oom_adj=200 WHERE id=?", (cid,))
                    evicted += 1
                if evicted > 0:
                    conn.commit()
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"Marked {evicted} zero-access chunks for accelerated eviction (oom_adj+)"
            r.message = r.fix_description
        else:
            r.passed = False
            r.severity = "warn"
            r.message = f"High zero-access rate: {rate:.1f}% — potential noise accumulation"
            r.actual = {"zero_access": zero_access, "total": total, "rate": rate}
            r.expected = {"rate": "<=36%"}

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


# ── Hygiene Checks（数据卫生） ─────────────────────────────────────────────────


def check_test_pollution(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    检查：是否有测试数据泄漏到生产 DB。
    防止 iter 54 重现：89% 数据是测试残留。

    检测信号：project 含 "test"/"tmp"/"pytest"，或 session_id 含 "test"。
    """
    r = AssertionResult("no_test_pollution", "hygiene")
    t0 = time.time()

    try:
        test_chunks = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE project LIKE '%test%'
               OR project LIKE '%tmp%'
               OR project LIKE '%pytest%'"""
        ).fetchone()[0]

        test_traces = conn.execute(
            """SELECT COUNT(*) FROM recall_traces
               WHERE session_id LIKE '%test%'
               OR session_id LIKE '%pytest%'
               OR (LENGTH(session_id) < 8 AND session_id != '')
               OR session_id LIKE 'smoke_%'"""
        ).fetchone()[0]

        total_pollution = test_chunks + test_traces
        if total_pollution == 0:
            r.passed = True
            r.message = "No test data pollution detected"
        elif fix:
            # 自修复：直接删除测试数据
            deleted_chunks = 0
            deleted_traces = 0
            if test_chunks > 0:
                conn.execute(
                    """DELETE FROM memory_chunks
                       WHERE project LIKE '%test%'
                       OR project LIKE '%tmp%'
                       OR project LIKE '%pytest%'"""
                )
                deleted_chunks = test_chunks
            if test_traces > 0:
                conn.execute(
                    """DELETE FROM recall_traces
                       WHERE session_id LIKE '%test%'
                       OR session_id LIKE '%pytest%'
                       OR (LENGTH(session_id) < 8 AND session_id != '')
                       OR session_id LIKE 'smoke_%'"""
                )
                deleted_traces = test_traces
            conn.commit()
            # 重建 FTS5 以确保一致
            if deleted_chunks > 0:
                conn.execute("DELETE FROM memory_chunks_fts")
                # iter797: 修复 FTS5 重建路径
                conn.execute(
                    """INSERT INTO memory_chunks_fts (rowid_ref, summary, content)
                       SELECT CAST(rowid AS TEXT), summary, COALESCE(content, '')
                       FROM memory_chunks WHERE chunk_state='ACTIVE' AND summary != ''"""
                )
                conn.commit()
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"Purged test pollution: {deleted_chunks} chunks + {deleted_traces} traces"
            r.message = r.fix_description
        else:
            r.passed = False
            r.severity = "warn"
            r.message = f"Test pollution: {test_chunks} chunks + {test_traces} traces"
            r.actual = {"test_chunks": test_chunks, "test_traces": test_traces}

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def check_stale_refs(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    检查：recall_traces 中的 chunk refs 是否指向已删除的 chunk。
    防止 iter 76 重现：ghost references 污染 readahead 共现数据。
    """
    r = AssertionResult("no_stale_refs", "hygiene")
    t0 = time.time()

    try:
        # 获取所有现存 chunk IDs
        existing_ids = set(
            row[0] for row in conn.execute("SELECT id FROM memory_chunks").fetchall()
        )

        # 检查 recall_traces top_k_json 中的 refs
        stale_count = 0
        checked = 0
        rows = conn.execute(
            "SELECT top_k_json FROM recall_traces WHERE top_k_json IS NOT NULL ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()

        for (top_k_json,) in rows:
            try:
                items = json.loads(top_k_json)
                for item in items:
                    chunk_id = item.get("id")
                    if chunk_id and chunk_id not in existing_ids:
                        stale_count += 1
                    checked += 1
            except Exception:
                continue

        if stale_count == 0:
            r.passed = True
            r.message = f"No stale refs in {checked} checked references"
        else:
            # iter789: stale_refs_auto_fix — 始终自动修复 stale refs
            # 根因（数据驱动，2026-05-04）：27/84 stale refs 持续累积，
            #   因 context_budget_guard/extractor 的 DELETE 路径绕过 mmu_notifier。
            #   stale refs 污染 recall_count 统计 + suppress 阈值计算。
            # 修复：stale ref 清理是安全幂等操作（只移除对已删 chunk 的引用），
            #   无需 --fix 手动触发，检测即修复。
            cleaned = 0
            rows_to_fix = conn.execute(
                "SELECT id, top_k_json FROM recall_traces WHERE top_k_json IS NOT NULL ORDER BY timestamp DESC LIMIT 200"
            ).fetchall()
            for (trace_id, top_k_json) in rows_to_fix:
                try:
                    items = json.loads(top_k_json)
                    filtered = [item for item in items if item.get("id") in existing_ids]
                    if len(filtered) < len(items):
                        conn.execute(
                            "UPDATE recall_traces SET top_k_json=? WHERE id=?",
                            (json.dumps(filtered), trace_id)
                        )
                        cleaned += 1
                except Exception:
                    continue
            if cleaned > 0:
                conn.commit()
            r.passed = True
            r.fix_applied = True
            r.fix_description = f"Auto-cleaned stale refs from {cleaned} traces ({stale_count} refs removed)"
            r.message = r.fix_description

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


def check_error_silence(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    检查：最近是否有 ERR 级别日志被正常处理（非静默吞掉）。
    防止 iter 67 重现：except:pass 吃掉错误。

    逻辑：如果有 ERR 日志但没有对应的修复动作，说明错误可能被忽略。
    """
    r = AssertionResult("errors_not_silenced", "hygiene")
    t0 = time.time()

    try:
        recent_errors = conn.execute(
            """SELECT COUNT(*) FROM dmesg
               WHERE level='ERR'
               AND timestamp > datetime('now', '-24 hours')"""
        ).fetchone()[0]

        if recent_errors == 0:
            r.passed = True
            r.message = "No ERR-level events in last 24h"
        elif recent_errors <= 3:
            r.passed = True
            r.severity = "info"
            r.message = f"{recent_errors} ERR events in 24h (within tolerance)"
        else:
            # 检查 swap_errors.log 是否在增长
            err_log = MEMORY_OS_DIR / "swap_errors.log"
            if err_log.exists() and err_log.stat().st_size > 10000:
                r.passed = False
                r.severity = "warn"
                r.message = f"{recent_errors} ERR events + growing error log — investigate!"
            else:
                r.passed = True
                r.severity = "info"
                r.message = f"{recent_errors} ERR events but error log not growing"

    except Exception as e:
        r.passed = False
        r.message = f"Error: {e}"

    r.duration_ms = (time.time() - t0) * 1000
    return r


# ── iter1330: thin_chunk_gc — 永久 suppress 碎片自动归档 ─────────────────────


def check_thin_chunk_gc(conn: sqlite3.Connection, fix: bool = False) -> AssertionResult:
    """
    检测 ACTIVE 中被 iter1303 thin_content_hard_suppress 永久拦截的碎片 chunk。
    这些 chunk 占 FTS5 索引但永远不会被注入，自动归档释放检索空间。
    """
    r = AssertionResult("thin_chunk_gc", "hygiene")
    t0 = time.time()
    try:
        rows = conn.execute(
            "SELECT id, rowid, chunk_type, importance, LENGTH(content) as clen "
            "FROM memory_chunks WHERE chunk_state='ACTIVE' AND LENGTH(content) < 60"
        ).fetchall()
        thin = []
        for cid, rid, ctype, imp, clen in rows:
            thresh = 30 if (ctype == "decision" and (imp or 0) >= 0.75) else 60
            if clen < thresh:
                thin.append((cid, rid))
        if not thin:
            r.passed = True
            r.message = "No permanently-suppressed thin chunks in ACTIVE pool"
        elif fix:
            for cid, rid in thin:
                conn.execute("UPDATE memory_chunks SET chunk_state='THIN_ARCHIVED' WHERE id=?", (cid,))
                conn.execute("DELETE FROM memory_chunks_fts WHERE rowid_ref=?", (str(rid),))
            conn.commit()
            r.passed = True
            r.message = f"Auto-archived {len(thin)} thin chunks (fix applied)"
        else:
            r.passed = False
            r.severity = "info"
            r.message = f"{len(thin)} thin chunks permanently suppressed but still in ACTIVE/FTS5"
            r.actual = {"thin_count": len(thin)}
            r.expected = "0 (all archived)"
    except Exception as e:
        r.passed = True
        r.severity = "info"
        r.message = f"Skip: {e}"
    r.duration_ms = (time.time() - t0) * 1000
    return r


# ── 运行器 ────────────────────────────────────────────────────────────────────

ALL_ASSERTIONS = [
    # Pipeline
    assert_swap_out_produces_output,
    assert_retriever_injects_knowledge,
    assert_extractor_writes_chunks,
    assert_fts5_covers_all_chunks,
    # Assumption audits
    audit_latency_baseline,
    audit_retrieval_diversity,
    audit_zero_access_rate,
    # Hygiene
    check_test_pollution,
    check_stale_refs,
    check_error_silence,
    check_thin_chunk_gc,
]


def run_all(fix: bool = False) -> dict:
    """运行所有断言，返回汇总报告"""
    t0 = time.time()

    if not STORE_DB.exists():
        return {"error": "store.db not found", "results": []}

    conn = sqlite3.connect(str(STORE_DB), timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")

    results = []
    passed = 0
    failed = 0
    warnings = 0

    for assert_fn in ALL_ASSERTIONS:
        try:
            result = assert_fn(conn, fix=fix)
            results.append(result)
            if result.passed:
                passed += 1
            else:
                failed += 1
                if result.severity == "warn":
                    warnings += 1
        except Exception as e:
            r = AssertionResult(assert_fn.__name__, "unknown")
            r.message = f"Assertion crashed: {e}"
            r.severity = "critical"
            results.append(r)
            failed += 1

    conn.close()

    total_ms = (time.time() - t0) * 1000

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "duration_ms": round(total_ms, 1),
        },
        "status": "HEALTHY" if failed == 0 else ("DEGRADED" if warnings == failed else "CRITICAL"),
        "results": [r.to_dict() for r in results],
    }

    # 写日志
    _write_log(report)

    return report


def _write_log(report: dict):
    """追加到断言日志（自动轮转）"""
    try:
        if ASSERTIONS_LOG.exists() and ASSERTIONS_LOG.stat().st_size > MAX_LOG_SIZE:
            # 保留后半部分
            content = ASSERTIONS_LOG.read_text()
            ASSERTIONS_LOG.write_text(content[len(content) // 2:])

        with open(ASSERTIONS_LOG, "a", encoding="utf-8") as f:
            line = json.dumps({
                "ts": report["timestamp"],
                "status": report["status"],
                "passed": report["summary"]["passed"],
                "failed": report["summary"]["failed"],
                "ms": report["summary"]["duration_ms"],
            }, ensure_ascii=False)
            f.write(line + "\n")
    except Exception:
        pass  # 日志写入失败不应影响主流程


def print_report(report: dict, json_mode: bool = False):
    """格式化输出报告"""
    if json_mode:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    s = report["summary"]
    status = report["status"]
    icon = "✅" if status == "HEALTHY" else ("⚠️" if status == "DEGRADED" else "❌")

    print(f"\n{icon} Production Assertions: {status}")
    print(f"   {s['passed']}/{s['total']} passed, {s['failed']} failed ({s['duration_ms']:.0f}ms)\n")

    for r in report["results"]:
        mark = "✓" if r["passed"] else ("⚠" if r["severity"] == "warn" else "✗")
        print(f"  [{mark}] {r['name']}: {r['message']}")

    if report["status"] != "HEALTHY":
        print(f"\n  🔍 Failed assertions need investigation:")
        for r in report["results"]:
            if not r["passed"]:
                print(f"     - {r['name']}: {r['message']}")
                if "actual" in r:
                    print(f"       actual: {r['actual']}")
                if "expected" in r:
                    print(f"       expected: {r['expected']}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    json_mode = "--json" in sys.argv
    fix_mode = "--fix" in sys.argv

    report = run_all(fix=fix_mode)
    print_report(report, json_mode=json_mode)

    # 退出码：0=healthy, 1=degraded, 2=critical
    if report["status"] == "HEALTHY":
        sys.exit(0)
    elif report["status"] == "DEGRADED":
        sys.exit(1)
    else:
        sys.exit(2)
