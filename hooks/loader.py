#!/usr/bin/env python3
"""
memory-os loader — SessionStart hook
1. 读取 latest.json 获取最新任务状态
2. 从 store.db 加载项目工作集（高权值 decision/reasoning_chain）
3. 注入 L2（additionalContext），总长控制 < 800 字

v2 升级（迭代18）：Working Set Restoration
OS 类比：Denning Working Set Model（1968）
  进程恢复时预加载其最近频繁访问的页面集，而非从空白页开始。
  新 session 不仅恢复"上次在干什么"，还恢复"这个项目的关键决策和上下文"。
"""
import sys
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
from schema import MemoryChunk
from utils import resolve_project_id
from scorer import working_set_score as _unified_ws_score
from store import open_db, ensure_schema, get_chunks as store_get_chunks, dmesg_log, DMESG_INFO, DMESG_WARN, DMESG_DEBUG, watchdog_check, damon_scan, mglru_aging, checkpoint_restore, autotune, gc_traces, rmap_sweep, vma_merge, page_idle_scan, page_idle_mark, gc_orphan_swap, gc_namespace, overcommit_kill, ksm_scan, perf_counters
from config import get as _sysctl  # 迭代27: sysctl Runtime Tunables
from store_mm import (timer_slack_load, timer_slack_should_skip,  # iter552
                      timer_slack_report, timer_slack_tick, timer_slack_save,
                      timer_slack_stats,
                      sched_deadline_load, sched_deadline_save,  # iter553
                      sched_deadline_update, sched_deadline_should_throttle,
                      sched_deadline_tick, sched_deadline_stats,
                      cgroup_budget_load, cgroup_budget_save,  # iter554
                      cgroup_budget_should_throttle, cgroup_budget_consume,
                      cgroup_budget_settle, cgroup_budget_tick, cgroup_budget_stats,
                      CGROUP_GROUPS, _SUBSYSTEM_TO_GROUP,
                      schedstat_load, schedstat_save,  # iter555
                      schedstat_record_skip, schedstat_record_exec,
                      schedstat_record_session, schedstat_blame,
                      sched_autogroup)  # iter556

MEMORY_OS_DIR = Path.home() / ".claude" / "memory-os"
LATEST_JSON = MEMORY_OS_DIR / "latest.json"
STORE_DB = MEMORY_OS_DIR / "store.db"

# 迭代27：常量迁移至 config.py sysctl 注册表（运行时可调）
# 原硬编码：MAX_AGE_SECS=86400, MAX_CONTEXT_CHARS=800, WORKING_SET_TOP_K=5
# 工作集只恢复高价值 chunk 类型（task_state 已通过 latest.json 恢复）
WORKING_SET_TYPES = ("decision", "reasoning_chain", "conversation_summary", "design_constraint", "procedure")


# ── iter535: deferred_initcall — Conditional Boot Subsystem Bypass ──
# OS 类比：Linux deferred_struct_pages (Mel Gorman, 2015, kernel 4.2)
#   CONFIG_DEFERRED_STRUCT_PAGE_INIT 在大内存系统中跳过 boot node 以外的
#   memmap 初始化，由后台线程按需完成。boot time 缩短 80%+。
#   对小内存系统（<4GB）不触发——不需要 deferred init。
#
# 根因：SessionStart 运行 25 个回收/GC/平衡子系统，每个都执行 SQL 扫描。
#   生产 DB 72 chunks, 19.4% 零访问率——系统已健康。
#   大部分子系统 find nothing to do 但仍付 import + query 成本。
#
# 策略：一次 O(1) 健康探针决定是否跳过整个 reclaim 阶段。
def _should_defer_reclaim(conn: sqlite3.Connection, project: str) -> tuple:
    """
    快速健康探针：决定是否跳过 reclaim 子系统套件。

    返回 (should_defer: bool, reason: str, metrics: dict)

    跳过条件（全部满足）：
      1. 总 chunks < defer_max_chunks (默认 150) — 小库不需要激进回收
      2. 零访问率 < defer_zero_pct (默认 30%) — 数据质量已健康
      3. 无 zombie (importance < 0.2 + access=0) — 无需最终回收
      4. 距上次 reclaim < defer_cooldown_hours (默认 2h) — 最近已扫过

    任一条件不满足 → 执行完整 reclaim（不跳过）。
    """
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project IN (?, 'global')",
            (project,)
        ).fetchone()[0]
    except Exception:
        return (False, "query_error", {})

    # 条件 1：小库快速路径
    defer_max = int(_sysctl("loader.defer_max_chunks"))
    if total >= defer_max:
        return (False, f"large_db({total}>={defer_max})", {"total": total})

    # 条件 2：零访问率
    try:
        zero_acc = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project IN (?, 'global') AND access_count = 0",
            (project,)
        ).fetchone()[0]
    except Exception:
        zero_acc = 0
    zero_pct = zero_acc / total if total > 0 else 0
    defer_zero = _sysctl("loader.defer_zero_pct")
    if zero_pct >= defer_zero:
        return (False, f"high_zero({zero_pct:.1%}>={defer_zero:.0%})", {"total": total, "zero_pct": zero_pct})

    # 条件 3：无 zombie
    try:
        zombies = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE importance < 0.2 AND access_count = 0"
        ).fetchone()[0]
    except Exception:
        zombies = 0
    if zombies > 0:
        return (False, f"zombies({zombies})", {"total": total, "zero_pct": zero_pct, "zombies": zombies})

    # 条件 4：最近 reclaim 冷却期
    defer_cooldown_h = _sysctl("loader.defer_cooldown_hours")
    try:
        last_reclaim = conn.execute(
            "SELECT MAX(timestamp) FROM dmesg WHERE subsystem IN "
            "('kfree_rcu','free_pages_ok','oom_reaper','overcommit_kill','shrink_dcache','damon','put_page')"
        ).fetchone()[0]
        if last_reclaim:
            from datetime import datetime, timezone
            last_dt = datetime.fromisoformat(last_reclaim.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            hours_since = (now - last_dt).total_seconds() / 3600
            if hours_since >= defer_cooldown_h:
                return (False, f"cooldown_expired({hours_since:.1f}h>={defer_cooldown_h}h)",
                        {"total": total, "zero_pct": zero_pct, "hours_since_reclaim": hours_since})
    except Exception:
        pass  # 无 dmesg 记录 → 视为已冷却，不强制执行

    return (True, "healthy", {"total": total, "zero_pct": zero_pct, "zombies": zombies})
# 迭代111: 加入 design_constraint — 当前项目的约束应在 SessionStart 预加载（常驻内核模块类比）
# iter117: 加入 procedure — wiki 导入的操作协议也需要 SessionStart 预加载（importance≥0.85，具有高稳定性）


def _age_secs(iso_str: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_str)
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds()
    except Exception:
        return float("inf")


    # ── 评分函数已迁移至 scorer.py（迭代20 Unified Scorer）──


def _load_working_set_from_checkpoint(project: str) -> tuple:
    """
    迭代49：CRIU restore — 尝试从 checkpoint 恢复精确工作集。
    OS 类比：CRIU restore 从镜像文件重建进程的完整内存映射，
    而非从零开始让进程自己缺页加载。

    返回 (working_set_list, checkpoint_info_or_None)。
    如果有可用 checkpoint → 用精确 chunk IDs 恢复（比泛化 Top-K 更准）。
    如果没有 → 返回 ([], None)，调用方 fallback 到泛化 Top-K。
    """
    if not STORE_DB.exists():
        return [], None
    try:
        conn = open_db()
        ensure_schema(conn)
        ckpt = checkpoint_restore(conn, project)
        if ckpt and ckpt.get("chunks"):
            restore_boost = _sysctl("criu.restore_boost")
            _TYPE_PREFIX = {
                "decision": "[决策]",
                "reasoning_chain": "[推理]",
                "conversation_summary": "[摘要]",
                "excluded_path": "[排除]",
                "design_constraint": "⚠️ [约束]",
            }
            scored = []
            for c in ckpt["chunks"]:
                # 迭代14: CRIU restore 也应用 WORKING_SET_TYPES 过滤
                # 原问题：checkpoint 包含 causal_chain（bug修复记录）被注入
                # causal_chain 是因果追踪，对新 session 价值低（已修复的 bug 更是噪音）
                # 设计原则：CRIU 路径不应绕过 working set 类型过滤
                # OS 类比：CRIU restore 只恢复 mlock 的关键内存段，不恢复匿名 dirty page
                if c.get("chunk_type") not in WORKING_SET_TYPES:
                    continue
                # 用 working_set_score + restore_boost 评分
                base_score = _unified_ws_score(c["importance"], c["last_accessed"])
                score = base_score + restore_boost  # checkpoint 命中加权
                prefix = _TYPE_PREFIX.get(c["chunk_type"], "")
                scored.append((score, c["chunk_type"], c["summary"], c.get("id", "")))
            scored.sort(key=lambda x: x[0], reverse=True)
            top_k = _sysctl("loader.working_set_top_k")

            # ── iter529: sched_rt_bandwidth — CRIU 路径同样排除垄断 chunk ──
            try:
                from store_mm import sched_rt_bandwidth
                candidate_ids = [item[3] for item in scored if len(item) > 3 and item[3]]
                if candidate_ids:
                    bw_result = sched_rt_bandwidth(conn, project, candidate_ids)
                    throttled = bw_result.get("throttled_ids", set())
                    if throttled:
                        scored = [item for item in scored if (len(item) <= 3 or item[3] not in throttled)]
            except Exception:
                pass  # bandwidth check 失败不影响主流程

            conn.commit()  # commit consumed 状态
            conn.close()
            return scored[:top_k], ckpt
        conn.close()
    except Exception:
        pass
    return [], None


def _load_working_set(project: str) -> list:
    """
    从 store.db 加载当前项目的工作集：Top-K 高权值 chunk。
    v3 迭代21：委托 store.py VFS 统一数据访问层。
    v4 迭代49：优先从 CRIU checkpoint 恢复精确工作集。
    v5 iter529：sched_rt_bandwidth — 排除超过召回带宽上限的垄断 chunk。

    OS 类比：working set = 最近频繁访问的页面集。
    进程重新调度时，OS 预加载 working set 避免大量缺页中断。
    iter529：sched_rt_runtime_us — RT 带宽限制，防止单个高优先级任务垄断 CPU。
    """
    if not STORE_DB.exists():
        return []
    try:
        conn = open_db()
        ensure_schema(conn)
        chunks = store_get_chunks(conn, project, chunk_types=WORKING_SET_TYPES)
    except Exception:
        return []

    if not chunks:
        try:
            conn.close()
        except Exception:
            pass
        return []

    # 评分：Unified Scorer working_set_score（迭代20 CFS 统一评分）
    scored = []
    for c in chunks:
        score = _unified_ws_score(c["importance"], c["last_accessed"])
        scored.append((score, c["chunk_type"], c["summary"], c.get("id", "")))

    scored.sort(key=lambda x: x[0], reverse=True)

    # ── iter529: sched_rt_bandwidth — 排除超过带宽上限的 chunk ──
    # OS 类比：sched_rt_runtime_us 限制 RT 任务带宽，防止 CPU 垄断
    try:
        from store_mm import sched_rt_bandwidth
        candidate_ids = [item[3] for item in scored if len(item) > 3 and item[3]]
        if candidate_ids:
            bw_result = sched_rt_bandwidth(conn, project, candidate_ids)
            throttled = bw_result.get("throttled_ids", set())
            if throttled:
                scored = [item for item in scored if (len(item) <= 3 or item[3] not in throttled)]
    except Exception:
        pass  # bandwidth check 失败不影响主流程

    try:
        conn.close()
    except Exception:
        pass
    return scored[:_sysctl("loader.working_set_top_k")]


def _parse_content(content: str) -> tuple:
    current_tasks, next_tasks, excluded = [], [], []
    section = None
    for line in content.splitlines():
        if line.startswith("当前任务"):
            section = "current"
        elif line.startswith("待执行"):
            section = "next"
        elif line.startswith("已排除"):
            section = "excluded"
        elif line.startswith("- "):
            item = line[2:].strip()
            if section == "current":
                current_tasks.append(item)
            elif section == "next":
                next_tasks.append(item)
            elif section == "excluded":
                excluded.append(item)
    return current_tasks, next_tasks, excluded



def _get_last_session_timestamp() -> str | None:
    """
    从 store.db dmesg 表中获取上一次 session_start 记录的 timestamp。
    返回 ISO 8601 字符串，失败时返回 None。
    """
    if not STORE_DB.exists():
        return None
    try:
        conn = sqlite3.connect(str(STORE_DB))
        # 取倒数第2条（当前 session 写入前，最新那条就是上一次的）
        rows = conn.execute(
            "SELECT timestamp FROM dmesg "
            "WHERE subsystem='loader' AND message LIKE 'session_start%' "
            "ORDER BY id DESC LIMIT 2"
        ).fetchall()
        conn.close()
        if len(rows) >= 2:
            return rows[1][0]  # 上一次
        elif len(rows) == 1:
            return rows[0][0]  # 只有一条（首次 session）
    except Exception:
        pass
    return None


def _detect_changes(last_ts: str | None, project_dir: Path) -> list[str]:
    """
    迭代90：实时变化感知 — 检测自上次 session 以来的环境变化。
    OS 类比：inotify + git fsck — 进程恢复时感知文件系统和版本控制变化，
    让 AI 无需"热身"即可知道外部世界发生了什么。

    返回变化摘要行列表（空列表 = 无变化，不注入）。
    总字符数控制在 300 以内。
    """
    if not last_ts:
        return []

    change_lines = []
    try:
        last_dt = datetime.fromisoformat(last_ts)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        last_ts_epoch = last_dt.timestamp()
    except Exception:
        return []

    # ── 1. Git 变化检测 ──
    try:
        _git_dir = project_dir
        _git_check = subprocess.run(
            ["git", "-C", str(_git_dir), "rev-parse", "--git-dir"],
            capture_output=True, timeout=3
        )
        if _git_check.returncode == 0:
            # 获取自上次 session 以来的 commit
            _log_result = subprocess.run(
                ["git", "-C", str(_git_dir), "log", "--oneline",
                 f"--since={last_ts}"],
                capture_output=True, text=True, timeout=3
            )
            if _log_result.returncode == 0:
                _commits = [l.strip() for l in _log_result.stdout.splitlines() if l.strip()]
                if _commits:
                    _latest_msg = _commits[0].split(" ", 1)[1] if " " in _commits[0] else _commits[0]
                    # 截断长 commit 消息
                    if len(_latest_msg) > 40:
                        _latest_msg = _latest_msg[:37] + "..."
                    change_lines.append(
                        f"- Git: {len(_commits)} commit{'s' if len(_commits) > 1 else ''} "
                        f"since last session (最新: \"{_latest_msg}\")"
                    )
    except Exception:
        pass

    # ── 2. self-improving/ 文件变更检测 ──
    try:
        _si_dir = Path.home() / "self-improving"
        if _si_dir.exists():
            _changed_files = []
            for _f in sorted(_si_dir.rglob("*.md")):
                try:
                    if _f.stat().st_mtime > last_ts_epoch:
                        # 取相对路径
                        try:
                            _rel = _f.relative_to(Path.home())
                        except ValueError:
                            _rel = _f
                        _changed_files.append(str(_rel))
                except Exception:
                    pass
            if _changed_files:
                # 最多展示 3 个文件
                _shown = _changed_files[:3]
                _suffix = f" (+{len(_changed_files) - 3} more)" if len(_changed_files) > 3 else ""
                change_lines.append(
                    f"- 文件变更: {', '.join(_shown)}{_suffix}"
                )
    except Exception:
        pass

    # ── 3. CLAUDE.md 变更检测 ──
    try:
        _claude_md = project_dir / "CLAUDE.md"
        if not _claude_md.exists():
            # fallback: ~/.claude/CLAUDE.md
            _claude_md = Path.home() / ".claude" / "CLAUDE.md"
        if _claude_md.exists():
            _claude_mtime = _claude_md.stat().st_mtime
            if _claude_mtime > last_ts_epoch:
                change_lines.append("- CLAUDE.md: 已修改")
            # else: 未变化则不注入（遵循"0变化不注入"原则）
    except Exception:
        pass

    if not change_lines:
        return []

    # 组装 header + 内容，总字符数限制 300
    result = ["【环境变化感知】"] + change_lines
    total = sum(len(l) for l in result)
    if total > 300:
        # 截断最后一行
        budget = 300 - sum(len(l) for l in result[:-1]) - 1  # -1 for newline
        if budget > 10:
            result[-1] = result[-1][:budget] + "…"
        else:
            result = result[:-1]  # 直接去掉最后一行

    return result


def _preheat_retriever(conn, project: str) -> None:
    """
    SessionStart 预热：import heavy modules + FTS5 warm cache。
    OS 类比：Linux readahead + module preloading — 进程启动时预取页面和模块，
    让后续 UserPromptSubmit 调用时 Python bytecode cache 和 SQLite page cache 已热。
    目标：将后续第一次检索的冷启动延迟从 ~27ms import + ~40ms WAL 降至 <5ms。
    """
    import time as _t
    t0 = _t.time()
    try:
        # 1. import heavy modules — 触发 Python bytecode cache 加载
        from scorer import retrieval_score  # noqa: F401
        from bm25 import hybrid_tokenize, bm25_scores  # noqa: F401
        from store import fts_search
        # 2. 空查询预热 FTS5 索引页 — 触发 SQLite page cache 加载
        fts_search(conn, "warmup", project, top_k=1)
    except Exception:
        pass  # 预热失败不影响主流程
    elapsed = (_t.time() - t0) * 1000
    try:
        dmesg_log(conn, DMESG_INFO, "loader", f"preheat: {elapsed:.1f}ms", project=project)
    except Exception:
        pass


def main():
    # 迭代66：从 stdin 获取 session_id（SessionStart hook 也提供 session_id）
    try:
        _raw = sys.stdin.read()
        _hook_input = json.loads(_raw) if _raw.strip() else {}
    except Exception:
        _hook_input = {}
    _session_id = (_hook_input.get("session_id", "")
                   or os.environ.get("CLAUDE_SESSION_ID", "")
                   or "unknown")

    project = resolve_project_id()
    has_latest = False

    lines = ["【上次会话状态 · 自动恢复】"]

    # ── Part 1：latest.json 任务状态恢复（原有逻辑）──
    if LATEST_JSON.exists():
        try:
            chunk = MemoryChunk.from_json(LATEST_JSON.read_text(encoding="utf-8"))
            if _age_secs(chunk.updated_at) <= _sysctl("loader.max_age_secs"):
                has_latest = True
                current_tasks, next_tasks, excluded = _parse_content(chunk.content)
                if current_tasks:
                    lines.append(f"任务：{' / '.join(current_tasks)}")
                if next_tasks:
                    lines.append(f"下一步：{' / '.join(next_tasks)}")
                if excluded:
                    lines.append(f"已排除：{' / '.join(excluded)}")
                if chunk.summary:
                    lines.append(f"背景：{chunk.summary}")
                if chunk.project:
                    lines.append(f"项目：{chunk.project}")
        except Exception:
            pass

    # ── Part 2：Working Set 关键知识恢复 ──
    # 迭代49：CRIU restore 优先 — 从 checkpoint 恢复精确工作集
    # OS 类比：CRIU restore > 泛化 working set restoration
    checkpoint_info = None
    working_set, checkpoint_info = _load_working_set_from_checkpoint(project)
    if not working_set:
        # fallback：泛化 Top-K（迭代18 原有逻辑）
        working_set = _load_working_set(project)

    # ── iter526: vm_flags — 收集 loader 注入的 chunk IDs，写入 page table ──
    # OS 类比：/proc/PID/smaps vm_flags — 公开已映射 VMA 信息，
    # 供其他子系统（retriever）避免重复映射同一虚拟地址区间。
    _loader_injected_ids = []

    if working_set:
        _TYPE_PREFIX = {
            "decision": "[决策]",
            "reasoning_chain": "[推理]",
            "conversation_summary": "[摘要]",
            "excluded_path": "[排除]",
            "design_constraint": "⚠️ [约束]",  # 迭代111
        }
        ws_label = "【项目工作集】" if not checkpoint_info else "【项目工作集·CRIU恢复】"
        lines.append(ws_label)
        for item in working_set:
            score, chunk_type, summary = item[0], item[1], item[2]
            chunk_id = item[3] if len(item) > 3 else ""
            prefix = _TYPE_PREFIX.get(chunk_type, "")
            lines.append(f"- {prefix} {summary}".strip())
            if chunk_id:
                _loader_injected_ids.append(chunk_id)

    # ── iter378: Persistent Working Set Restoration ──────────────────────────
    # OS 类比：CRIU restore — 从磁盘反序列化上次进程的工作集页面，恢复到 warm cache 状态。
    # 人的记忆类比：Denning (1968) Working Set — 切换项目时自动带上"最近用过的热页面"。
    # 直接解决"不记得端口"问题：hot chunks（端口/配置/约束）持久化→下次 SessionStart 注入。
    if _sysctl("loader.restore_working_set"):
        try:
            _ws_fname = f".ws_{project.replace(':', '_').replace('/', '_')}.json"
            _ws_path = MEMORY_OS_DIR / _ws_fname
            if _ws_path.exists():
                _ws_data = json.loads(_ws_path.read_text(encoding="utf-8"))
                _ws_age_secs = _age_secs(_ws_data.get("saved_at", ""))
                # 只恢复 24 小时内的工作集（避免注入过时数据）
                if _ws_age_secs <= 86400:
                    _ws_restored_chunks = _ws_data.get("chunks", [])
                    if _ws_restored_chunks:
                        _TYPE_PREFIX_WS = {
                            "decision": "[决策]",
                            "reasoning_chain": "[推理]",
                            "conversation_summary": "[摘要]",
                            "excluded_path": "[排除]",
                            "design_constraint": "⚠️ [约束]",
                            "quantitative_evidence": "[量化]",
                            "causal_chain": "[因果]",
                            "procedure": "[流程]",
                        }
                        # 去重：已在 working_set 中出现的 summary 不重复注入
                        _existing_summaries = set()
                        if working_set:
                            for _score, _ct, _sm in working_set:
                                _existing_summaries.add(_sm)

                        _ws_new_lines = []
                        for _wc in _ws_restored_chunks:
                            _sm = _wc.get("summary", "").strip()
                            _ct = _wc.get("chunk_type", "")
                            if not _sm or _sm in _existing_summaries:
                                continue
                            _existing_summaries.add(_sm)
                            _pfx = _TYPE_PREFIX_WS.get(_ct, "")
                            _ws_new_lines.append(f"- {_pfx} {_sm}".strip())

                        if _ws_new_lines:
                            lines.append("【热工作集·持久化恢复】")
                            lines.extend(_ws_new_lines[:10])  # 最多 10 条，保持注入简洁
        except Exception:
            pass  # 持久化工作集恢复失败不影响主流程

    # ── iter363: Workspace Activation — 工作区感知 ──
    # OS 类比：exec() → 加载新程序的地址空间，而非一页一页缺页加载
    # 切换到项目目录时，整体激活该工作区的结构化知识（端口/服务/命令）
    try:
        _cwd = _hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
        if _cwd:
            import sys as _sys_ws
            _ROOT_WS = Path(__file__).parent.parent
            if str(_ROOT_WS) not in _sys_ws.path:
                _sys_ws.path.insert(0, str(_ROOT_WS))
            from store_workspace import resolve_workspace, activate_workspace
            from workspace_scanner import scan_and_store
            _ws_conn = open_db()
            from store_workspace import ensure_workspace_schema as _ensure_ws
            _ensure_ws(_ws_conn)
            _ws_id = resolve_workspace(_ws_conn, _cwd)
            # 增量扫描（hash 比对，只处理变更文件）
            scan_and_store(_ws_conn, _ws_id, _cwd, force=False)
            _ws_data = activate_workspace(_ws_conn, _ws_id)
            _ws_conn.close()

            _ws_lines = []
            # file_facts: 端口/服务等结构化信息
            if _ws_data.get("file_facts"):
                _ws_lines.append(f"【工作区: {_ws_data['workspace_name']}】")
                for _ff in _ws_data["file_facts"][:3]:  # 最多展示 3 个文件
                    _fname = Path(_ff["file"]).name
                    _ports = [f for f in _ff["facts"] if f.get("type") == "port"]
                    _envs = [f for f in _ff["facts"] if f.get("type") == "env_var"]
                    if _ports:
                        _port_strs = [f.get("description", "") for f in _ports[:4]]
                        _ws_lines.append(f"  {_fname}: " + " | ".join(_port_strs))
                    if _envs and not _ports:
                        _env_strs = [f.get("description", "") for f in _envs[:3]]
                        _ws_lines.append(f"  {_fname}: " + " | ".join(_env_strs))
            # kb_chunks: workspace 关联的已积累知识
            if _ws_data.get("kb_chunks"):
                if not _ws_lines:
                    _ws_lines.append(f"【工作区: {_ws_data['workspace_name']}】")
                for _kc in _ws_data["kb_chunks"][:3]:
                    _ws_lines.append(f"  [{_kc['chunk_type']}] {_kc['summary'][:80]}")
            if _ws_lines:
                lines.extend(_ws_lines)
    except Exception:
        pass  # workspace 激活失败不影响主流程

    # ── iter364: Session Episode Injection — 情节时间线注入 ──────────────────
    # OS 类比：ftrace 重放 — 新 session 看到上次进程运行的行为轨迹
    # 人的记忆类比：情节记忆激活 — 进入熟悉环境时自动想起"上次在这里做了什么"
    try:
        _ep_cwd = _hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
        _ep_ws_id = None
        if _ep_cwd:
            from store_workspace import _workspace_id as _ws_id_fn2
            _ep_ws_id = _ws_id_fn2(_ep_cwd)

        from store_episodes import (get_recent_episodes, format_episodes_for_injection,
                                     ensure_episodes_schema, mark_episode_injected)
        _ep_conn2 = open_db()
        ensure_episodes_schema(_ep_conn2)
        _episodes = get_recent_episodes(
            _ep_conn2, project,
            workspace_id=_ep_ws_id,
            limit=3,
        )
        _ep_text = format_episodes_for_injection(_episodes, max_chars=300)
        if _ep_text:
            lines.append(_ep_text)
            for _ep in _episodes:
                mark_episode_injected(_ep_conn2, _ep["session_id"])
        _ep_conn2.close()
    except Exception:
        pass  # episode 注入失败不影响主流程

    # ── iter365: Workspace Todos Injection — 前瞻性记忆 ──────────────────────
    # OS 类比：cron 到达时间 → 触发 job — 进入工作区时注入 pending 待办
    # 人的记忆类比：前瞻性记忆激活 — 回到熟悉地方时想起"我记得要做 X"
    try:
        if _cwd:  # _cwd 来自上方 workspace activation block
            from store_todos import (get_pending_todos, format_todos_for_injection,
                                      ensure_todos_schema, mark_todo_injected)
            from store_workspace import _workspace_id as _ws_id_todo
            _todo_ws_id = _ws_id_todo(_cwd)
            _todo_conn2 = open_db()
            ensure_todos_schema(_todo_conn2)
            _pending_todos = get_pending_todos(_todo_conn2, _todo_ws_id, limit=5)
            _todo_text = format_todos_for_injection(_pending_todos, max_chars=200)
            if _todo_text:
                lines.append(_todo_text)
                for _td in _pending_todos:
                    mark_todo_injected(_todo_conn2, _td["id"])
            _todo_conn2.close()
    except Exception:
        pass  # todo 注入失败不影响主流程

    # ── 迭代91: 活跃目标注入 — Goal Awareness ──
    # OS 类比：/etc/rc.d/rc.local — 系统启动时自动加载持久化的任务目标配置
    if STORE_DB.exists():
        try:
            _goal_conn = open_db()
            ensure_schema(_goal_conn)
            active_goals = _goal_conn.execute(
                """SELECT title, progress FROM goals
                   WHERE project = ? AND status = 'active'
                   ORDER BY updated_at DESC LIMIT 3""",
                [project]
            ).fetchall()
            _goal_conn.close()
            if active_goals:
                lines.append("【长期目标】")
                for g_title, g_progress in active_goals:
                    pct = int(g_progress * 100)
                    lines.append(f"- {g_title[:60]} [{pct}%]")
        except Exception:
            pass

    # 如果既没有 latest.json 也没有工作集，不注入
    if not has_latest and not working_set:
        sys.exit(0)

    # ── 迭代86：Readahead Warm — SessionStart 预热 shadow_trace ──
    # OS 类比：Linux readahead() syscall — 进程启动时主动预取预期页面，
    #   避免首次访问时的缺页中断。
    # 根因：新 session 直到第一次 FULL 检索前，所有 swap_out 都是 0 hit_ids，
    #   因为 SKIP/TLB 快速路径不写 recall_traces，shadow_trace 也未初始化。
    # 修复：SessionStart 时查询当前 project 的 Top-K chunk IDs，
    #   写入 shadow_trace.json，使新 session 第一次 swap_out 就能恢复工作集。
    if working_set and STORE_DB.exists():
        try:
            _st_conn = open_db()
            ensure_schema(_st_conn)
            _top_k = _sysctl("loader.working_set_top_k")
            _ws_rows = _st_conn.execute(
                """SELECT id FROM memory_chunks
                   WHERE project = ?
                     AND chunk_type IN ({})
                   ORDER BY importance DESC, access_count DESC
                   LIMIT ?""".format(",".join("?" * len(WORKING_SET_TYPES))),
                [project, *WORKING_SET_TYPES, _top_k]
            ).fetchall()
            _st_conn.close()
            _ws_ids = [r[0] for r in _ws_rows]
            if _ws_ids:
                import time as _time
                _shadow_data = {
                    "project": project,
                    "top_k_ids": _ws_ids,
                    "session_id": _session_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "session_start_readahead",
                }
                # iter259: 写入 shadow_traces DB 表（per-session 隔离，替代全局文件）
                # OS 类比：/proc/PID/maps — 每进程独立，不同进程间不互相覆盖
                try:
                    _sh_conn = open_db()
                    ensure_schema(_sh_conn)
                    _sh_conn.execute("""
                        CREATE TABLE IF NOT EXISTS shadow_traces (
                            session_id   TEXT PRIMARY KEY,
                            project      TEXT NOT NULL DEFAULT '',
                            agent_id     TEXT NOT NULL DEFAULT '',
                            updated_at   TEXT NOT NULL,
                            top_k_ids    TEXT NOT NULL DEFAULT '[]'
                        )
                    """)
                    _sh_conn.execute(
                        "INSERT OR REPLACE INTO shadow_traces "
                        "(session_id, project, agent_id, updated_at, top_k_ids) VALUES (?,?,?,?,?)",
                        (_session_id, project, _session_id[:16],
                         datetime.now(timezone.utc).isoformat(),
                         json.dumps(_ws_ids, ensure_ascii=False))
                    )
                    _sh_conn.commit()
                    _sh_conn.close()
                except Exception:
                    pass
                # 向后兼容：写入 per-session 文件（替代全局 .shadow_trace.json）
                # 全局文件已废弃（多 agent 并发时最后写者覆盖之前写者）
                _sid_tag = _session_id[:16] if _session_id else "unknown"
                _shadow_file = MEMORY_OS_DIR / f".shadow_trace.{_sid_tag}.json"
                _shadow_file.write_text(
                    json.dumps(_shadow_data, ensure_ascii=False),
                    encoding="utf-8"
                )
        except Exception:
            pass  # shadow_trace 预热失败不影响主流程

    # ── 迭代90：Change Awareness — 自上次 session 以来的环境变化感知 ──
    # OS 类比：inotify + git log — 进程恢复时主动感知外部世界变化，
    #   避免 AI 在新 session 中"热身"才能知道环境变了什么。
    # 实现：读取 dmesg 中上一条 session_start 时间戳，对比 git/文件变更。
    # 约束：0 变化不注入；总字符 ≤300；subprocess timeout=3s；全程 try/except。
    try:
        _last_ts = _get_last_session_timestamp()
        _change_lines = _detect_changes(_last_ts, Path(os.environ.get("CLAUDE_CWD", Path.home() / "ssd/codes/claude-workspace")))
        if _change_lines:
            lines.extend(_change_lines)
    except Exception:
        pass  # 变化感知失败不影响主流程

    # ── 迭代110 P2: CRIU Session Intent Restore ──────────────────────────────
    # OS 类比：CRIU restore_task() — 从 dump 文件恢复进程的执行断点状态
    # 读取上一个 session Stop 时保存的 incomplete intent，注入到新 session
    # iter259：优先从 session_intents DB 表读取最近一条（兼容旧文件 fallback）
    try:
        import datetime as _dt
        _intent = {}
        _saved_at = ""
        _intent_loaded = False

        # 优先从 DB 读取（查最近一条 intent，同 project，按 saved_at 降序）
        try:
            from store import open_db as _open_db2, ensure_schema as _ensure2
            _ldr_conn = _open_db2()
            _ensure2(_ldr_conn)
            _intent_row = _ldr_conn.execute(
                """SELECT intent_json, saved_at FROM session_intents
                   WHERE project=? ORDER BY saved_at DESC LIMIT 1""",
                (project,)
            ).fetchone()
            _ldr_conn.close()
            if _intent_row:
                _intent = json.loads(_intent_row[0] or "{}")
                _saved_at = _intent_row[1] or ""
                _intent_loaded = True
        except Exception:
            pass

        # Fallback：旧 session_intent.json 文件
        if not _intent_loaded:
            _intent_file = MEMORY_OS_DIR / "session_intent.json"
            if _intent_file.exists():
                _intent_data = json.loads(_intent_file.read_text(encoding="utf-8"))
                _intent = _intent_data.get("intent", {})
                _saved_at = _intent_data.get("saved_at", "")

        # 只注入距今 < 24h 的 intent（过期的无意义）
        _intent_age = float("inf")
        if _saved_at:
            try:
                _saved_dt = _dt.datetime.fromisoformat(_saved_at)
                if _saved_dt.tzinfo is None:
                    _saved_dt = _saved_dt.replace(tzinfo=_dt.timezone.utc)
                _intent_age = (_dt.datetime.now(_dt.timezone.utc) - _saved_dt).total_seconds()
            except Exception:
                pass
        if _intent and _intent_age < 86400:  # 24h
            _intent_lines = ["【上次会话断点（CRIU恢复）】"]
            if _intent.get("next_actions"):
                _intent_lines.append("  待执行：" + " / ".join(_intent["next_actions"][:2]))
            if _intent.get("open_questions"):
                _intent_lines.append("  待验证：" + " / ".join(_intent["open_questions"][:2]))
            if _intent.get("partial_work"):
                _intent_lines.append("  进行中：" + " / ".join(_intent["partial_work"][:2]))
            if len(_intent_lines) > 1:
                lines.extend(_intent_lines)
    except Exception:
        pass  # intent 恢复失败不影响主流程

    context_text = "\n".join(lines)
    _max_ctx = _sysctl("loader.max_context_chars")
    if len(context_text) > _max_ctx:
        context_text = context_text[:_max_ctx] + "…"

    # ── 迭代103：跨Agent知识同步（OS 类比：inotify 事件消费）──
    # extractor 在其他 session 写入后广播通知，loader 在 SessionStart 消费
    # 告知用户当前 session 启动前其他 agent 积累了哪些新知识
    try:
        from net.agent_notify import consume_pending_notifications
        _notifs = consume_pending_notifications(_session_id, limit=3)
        if _notifs:
            # 迭代13: 信噪比过滤 — 只注入有实质内容的跨Agent知识
            # 原问题："+12个chunk" 是纯计数，Claude 无法从数字推导出任何知识
            # 新策略：只注入有 decisions/constraints 的通知，且带摘要
            # OS 类比：inotify IN_CLOSE_WRITE 过滤 — 只在文件真正写完时通知，
            #   忽略 IN_ACCESS（只读）事件，减少无意义 wake-up
            _substantive = []
            for _n in _notifs:
                _stats = _n.get("stats", {})
                _d = _stats.get("decisions", 0)
                _c = _stats.get("constraints", 0)
                _summary_chunks = _n.get("top_summaries", [])  # 实质摘要列表
                # 只有 decisions 或 constraints 时才注入（纯 chunk 数量没有召回价值）
                if _d > 0 or _c > 0:
                    _proj = _n.get("project", "?")
                    _label = []
                    if _d:
                        _label.append(f"{_d}决策")
                    if _c:
                        _label.append(f"{_c}约束")
                    _label_str = "、".join(_label)
                    _substantive.append(f"- {_proj}: 新增{_label_str}")
                    # 附加最重要的一条摘要
                    if _summary_chunks:
                        _substantive.append(f"  最新: {_summary_chunks[0][:60]}")
            if _substantive:
                lines.append("【跨Agent知识同步】")
                lines.extend(_substantive)
                # 重新组装（已有 context_text 可能不含新内容）
                context_text = "\n".join(lines)
    except Exception:
        pass  # IPC 消费失败不影响 SessionStart

    # ── 迭代89：Incremental Knowledge Import — SessionStart 增量导入 ──
    # OS 类比：Linux firmware loading — 启动时从 /lib/firmware 加载新固件到内核
    # 检查 self-improving/ 是否有新增/修改的 .md 文件，有则增量导入到 store.db
    try:
        _tools_dir = _ROOT / "tools"
        if _tools_dir.exists():
            sys.path.insert(0, str(_tools_dir))
            from import_knowledge import incremental_import
            _import_result = incremental_import()
            if _import_result.get("status") == "imported" and _import_result.get("count", 0) > 0:
                dmesg_log(open_db(), DMESG_INFO, "loader",
                          f"incremental_import: {_import_result['count']} new chunks from self-improving/",
                          session_id=_session_id, project=project)
    except Exception:
        pass  # 增量导入失败不影响 SessionStart

    # ── 迭代35：Watchdog Timer — SessionStart 时做 POST (Power-On Self-Test) ──
    # OS 类比：BIOS POST 在启动时检测硬件健康，Linux watchdog 在启动时注册
    try:
        _log_conn = open_db()
        ensure_schema(_log_conn)

        # ── iter551: initcall_debug — Boot Subsystem Latency Instrumentation ──
        # OS 类比：Linux initcall_debug (Arjan van de Ven, 2008, kernel 2.6.24)
        # 为每个 SessionStart 子系统记录执行耗时，定位启动瓶颈。
        # 使用 milestone 方式：在每个子系统入口处记录 (name, time)，
        # 最后 diff 计算每段耗时，避免修改 try/except 结构。
        import time as _ict_time
        _ict_enabled = bool(_sysctl("initcall_debug.enabled"))
        _ict_milestones = [("_boot_start", _ict_time.time())] if _ict_enabled else []

        # ── 迭代B3：Hook Analyzer 启动健康检查 ──
        # OS 类比：systemd-analyze verify — 启动时检测 unit 配置问题
        # 检测循环依赖和高风险超时，记录 WARN 级别 dmesg
        if _ict_enabled: _ict_milestones.append(("hook_analyzer", _ict_time.time()))
        try:
            from init.hook_analyzer import HookAnalyzer
            _ha = HookAnalyzer()
            _ha_report = _ha.analyze()
            _ha_issues = []
            if _ha_report.cycle_errors:
                for _ev, _err in _ha_report.cycle_errors.items():
                    _ha_issues.append(f"cycle:{_ev}")
            _ha_high_risks = [r for r in _ha_report.timeout_risks if r.risk_level == "HIGH"]
            if _ha_high_risks:
                _ha_issues.append(f"timeout_high:{len(_ha_high_risks)}")
            if _ha_issues:
                dmesg_log(_log_conn, DMESG_WARN, "hook_analyzer",
                          f"health_check: {', '.join(_ha_issues)} total_hooks={_ha_report.total_hooks}",
                          session_id=_session_id, project=project,
                          extra={"cycle_errors": list(_ha_report.cycle_errors.keys()),
                                 "high_timeout_hooks": [r.unit_name for r in _ha_high_risks]})
        except Exception:
            pass  # hook_analyzer 失败不影响 SessionStart 主流程

        if _ict_enabled: _ict_milestones.append(("watchdog", _ict_time.time()))
        wd_result = watchdog_check(_log_conn)
        wd_status = wd_result.get("status", "UNKNOWN")
        wd_repairs = wd_result.get("repairs", [])
        wd_dur = wd_result.get("duration_ms", 0)

        # 如果有修复动作或异常，记录 dmesg
        if wd_status == "REPAIRED":
            repair_summary = ", ".join(r["action"] for r in wd_repairs)
            dmesg_log(_log_conn, DMESG_WARN, "watchdog",
                      f"POST: {wd_status} repairs=[{repair_summary}] {wd_dur:.1f}ms",
                      session_id=_session_id, project=project,
                      extra={"repairs": wd_repairs})
        elif wd_status == "DEGRADED":
            dmesg_log(_log_conn, DMESG_WARN, "watchdog",
                      f"POST: {wd_status} — manual intervention may be needed {wd_dur:.1f}ms",
                      session_id=_session_id, project=project,
                      extra={"checks": wd_result.get("checks", [])})

        # ── 迭代51：Autotune — 参数自优化 ──
        # OS 类比：TCP Window Auto-Tuning — 根据运行时统计自动调整参数
        # SessionStart 时运行，分析 recall_traces 命中率和延迟，微调 per-project sysctl
        if _ict_enabled: _ict_milestones.append(("autotune", _ict_time.time()))
        autotune_result = {"tuned": False}
        try:
            autotune_result = autotune(_log_conn, project)
            if autotune_result.get("tuned"):
                _log_conn.commit()
                adj_summary = ", ".join(f"{a['key']}:{a['old']}→{a['new']}" for a in autotune_result["adjustments"])
                dmesg_log(_log_conn, DMESG_INFO, "autotune",
                          f"tuned: {adj_summary} hit_rate={autotune_result['stats'].get('hit_rate_pct',0)}%",
                          session_id=_session_id, project=project,
                          extra={"adjustments": autotune_result["adjustments"]})
        except Exception:
            pass

        # ── iter537: perf_counters — Retrieval Quality PMU Counters ──
        # OS 类比：perf stat — 读取 PMU 计数器诊断微架构效率
        if _ict_enabled: _ict_milestones.append(("perf_counters", _ict_time.time()))
        try:
            _pc_result = perf_counters(_log_conn, project)
            if _pc_result.get("total_traces", 0) > 0:
                dmesg_log(_log_conn, DMESG_INFO, "perf_counters",
                          f"avg_score={_pc_result['avg_score']:.3f} "
                          f"low_ratio={_pc_result['low_score_ratio']:.2f} "
                          f"hhi={_pc_result['type_concentration']:.3f} "
                          f"inj_rate={_pc_result['injection_rate']:.2f}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── iter558: pelt_update — Per-Entity Load Tracking ──
        # OS 类比：Linux PELT (Vincent Guittot, 2012) — 更新 per-type util_avg
        if _ict_enabled: _ict_milestones.append(("pelt_update", _ict_time.time()))
        try:
            from store_mm import pelt_update, pelt_save, pelt_load
            _pelt_state = pelt_update(_log_conn, project)
            pelt_save(_pelt_state)
            _pelt_proj = _pelt_state.get(project, {})
            if _pelt_proj:
                _pelt_low = [(t, u) for t, u in _pelt_proj.items() if u < 0.15]
                if _pelt_low:
                    dmesg_log(_log_conn, DMESG_INFO, "pelt_update",
                              f"low_util_types: {', '.join(f'{t}={u:.3f}' for t, u in _pelt_low)}",
                              session_id=_session_id, project=project)
        except Exception:
            pass

        # ── iter413: Sleep Consolidation — 离线记忆巩固 ──
        # OS 类比：Linux pdflush/writeback — session 间 idle period 内后台巩固 dirty pages
        # Stickgold (2005): 海马重放最近学习的记忆 → stability 提升（light sleep consolidation）
        if _ict_enabled: _ict_milestones.append(("sleep_consolidation", _ict_time.time()))
        consolidation_result = {"consolidated": 0}
        if not _ts_skip("sleep_consolidation"):
            try:
                from store_vfs import run_sleep_consolidation
                consolidation_result = run_sleep_consolidation(_log_conn, project)
                if consolidation_result.get("consolidated", 0) > 0:
                    _log_conn.commit()
                _ts_report("sleep_consolidation", consolidation_result.get("consolidated", 0) > 0)
            except Exception:
                pass

        # ── 迭代44：MGLRU aging — 推进 generation clock ──
        # OS 类比：MGLRU lru_gen_inc() — SessionStart 时推进所有 chunk 的 gen
        # 被访问的 chunk 在 retriever 中 promote 回 gen 0，未访问的逐渐变老
        if _ict_enabled: _ict_milestones.append(("mglru_aging", _ict_time.time()))
        mglru_result = {"aged": False}
        try:
            mglru_result = mglru_aging(_log_conn, project)
            if mglru_result.get("aged"):
                _log_conn.commit()
        except Exception:
            pass

        # ── iter535: deferred_initcall — 条件性启动旁路 ──
        # OS 类比：Linux deferred_struct_pages (Mel Gorman, 2015, kernel 4.2)
        # 小库+健康 DB 时跳过全部 reclaim/GC/rebalance 子系统（25 个），省 ~100ms+
        if _ict_enabled: _ict_milestones.append(("deferred_initcall", _ict_time.time()))
        _defer_reclaim, _defer_reason, _defer_metrics = _should_defer_reclaim(_log_conn, project)
        if _defer_reclaim:
            dmesg_log(_log_conn, DMESG_DEBUG, "deferred_initcall",
                      f"skip_reclaim: reason={_defer_reason} total={_defer_metrics.get('total',0)} "
                      f"zero={_defer_metrics.get('zero_pct',0):.1%}",
                      session_id=_session_id, project=project)
        # ── End deferred_initcall gate ──

        # ── iter552: timer_slack — 加载降频状态 + tick ──
        _ts_enabled = _sysctl("timer_slack.enabled")
        _ts_state = {}
        _ts_skipped_subsystems = []
        if _ts_enabled:
            try:
                _ts_state = timer_slack_load()
                _ts_state = timer_slack_tick(_ts_state)
            except Exception:
                _ts_state = {}

        # ── iter553: sched_deadline — 加载预算执行状态 + tick ──
        _sd_enabled = _sysctl("sched_deadline.enabled")
        _sd_state = {}
        _sd_throttled_subsystems = []
        if _sd_enabled:
            try:
                _sd_state = sched_deadline_load()
                _sd_state = sched_deadline_tick(_sd_state)
            except Exception:
                _sd_state = {}

        # ── iter554: cgroup_budget — 加载分组预算状态 + tick ──
        _cg_enabled = _sysctl("cgroup_budget.enabled")
        _cg_state = {}
        _cg_throttled_subsystems = []
        if _cg_enabled:
            try:
                _cg_state = cgroup_budget_load()
                _cg_state = cgroup_budget_tick(_cg_state)
            except Exception:
                _cg_state = {}

        # ── iter555: schedstat — 加载累积调度统计 ──
        _ss_enabled = _sysctl("schedstat.enabled")
        _ss_state = {}
        if _ss_enabled:
            try:
                _ss_state = schedstat_load()
            except Exception:
                _ss_state = {"subsystems": {}, "session_count": 0, "boot_times_ms": []}

        def _ts_skip(name):
            """检查子系统是否应跳过。
            优先级：sched_deadline(per-task) > cgroup_budget(per-group) > timer_slack(idle)
            iter552: timer_slack — 空转子系统降频
            iter553: sched_deadline — 超预算子系统节流
            iter554: cgroup_budget — 分组预算耗尽节流
            iter555: schedstat — 跳过事件累积记录
            任一触发则跳过。"""
            nonlocal _ss_state
            # iter553: sched_deadline throttle 优先检查（per-task 超预算）
            if _sd_enabled and sched_deadline_should_throttle(_sd_state, name):
                _sd_throttled_subsystems.append(name)
                if _ss_enabled:
                    _ss_state = schedstat_record_skip(_ss_state, name, "throttle")
                return True
            # iter554: cgroup_budget throttle（per-group 预算耗尽）
            if _cg_enabled and cgroup_budget_should_throttle(_cg_state, name):
                _cg_throttled_subsystems.append(name)
                if _ss_enabled:
                    _ss_state = schedstat_record_skip(_ss_state, name, "group_throttle")
                return True
            # iter552: timer_slack idle 跳过
            if _ts_enabled and timer_slack_should_skip(_ts_state, name):
                _ts_skipped_subsystems.append(name)
                if _ss_enabled:
                    _ss_state = schedstat_record_skip(_ss_state, name, "idle")
                return True
            return False

        def _ts_report(name, did_work):
            """汇报子系统执行结果。"""
            nonlocal _ts_state, _ss_state
            if _ts_enabled:
                try:
                    _ts_state = timer_slack_report(_ts_state, name, did_work)
                except Exception:
                    pass
        # ── End timer_slack + sched_deadline init ──

        # ── iter518：migrate_pages — 跨 project_id 知识迁移 ──
        if _ict_enabled: _ict_milestones.append(("migrate_pages", _ict_time.time()))
        # OS 类比：Linux migrate_pages() (Christoph Lameter, 2006) — 跨 NUMA 节点页面迁移
        # 同一物理仓库产生不同 project_id 时，将旧别名下的知识迁移到当前 project
        # 必须在回收器之前运行，否则旧别名 chunks 可能被误删
        if not _ts_skip("migrate_pages"):
            try:
                from store_mm import migrate_pages
                mig_result = migrate_pages(_log_conn, project)
                if mig_result["migrated"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "migrate_pages",
                              f"migrate: aliases={mig_result['aliases_found']} "
                              f"migrated={mig_result['migrated']} dup={mig_result['skipped_dup']} "
                              f"{mig_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("migrate_pages", mig_result.get("migrated", 0) > 0)
            except Exception:
                pass

        # ── iter519：mem_scrub — ECC patrol scrub 数据完整性巡检 ──
        if _ict_enabled: _ict_milestones.append(("mem_scrub", _ict_time.time()))
        # OS 类比：Intel EDAC patrol scrub (2005) — 后台巡检修复 ECC CE
        # 在回收器之前运行：修复腐蚀数据避免影响 DAMON/kswapd 决策
        if not _ts_skip("mem_scrub"):
            try:
                from store_mm import mem_scrub
                scrub_result = mem_scrub(_log_conn, project)
                if scrub_result["ce_fixed"] > 0 or scrub_result["ue_marked"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "mem_scrub",
                              f"scrub: ce={scrub_result['ce_fixed']} ue={scrub_result['ue_marked']} "
                              f"scanned={scrub_result['scanned']} {scrub_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("mem_scrub", (scrub_result.get("ce_fixed", 0) + scrub_result.get("ue_marked", 0)) > 0)
            except Exception:
                pass

        # ── iter557：bdi_writeback — Boot-Time Dirty Page Content Audit ──
        # OS 类比：Linux bdi_writeback (Jens Axboe, 2009) — per-BDI 审计 dirty pages
        if _ict_enabled: _ict_milestones.append(("bdi_writeback", _ict_time.time()))
        if not _ts_skip("bdi_writeback"):
            try:
                from store_mm import bdi_writeback
                wb_result = bdi_writeback(_log_conn, project)
                if wb_result.get("dirty_found", 0) > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "bdi_writeback",
                              f"audit: dirty={wb_result['dirty_found']} "
                              f"deleted={wb_result['fragments_deleted']} "
                              f"demoted={wb_result['low_quality_demoted']} "
                              f"protected={wb_result['skipped_protected']} "
                              f"{wb_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("bdi_writeback", wb_result.get("dirty_found", 0) > 0)
            except Exception:
                pass

        # ── iter520：checkpoint_gc — 全局 checkpoint 垃圾回收 ──
        # OS 类比：Linux memcg hierarchy v2 memory.max — 全局上限防止 per-session 膨胀
        try:
            from store_mm import checkpoint_gc
            gc_result = checkpoint_gc(_log_conn)
            if gc_result["deleted"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "checkpoint_gc",
                          f"gc: {gc_result['total_before']}→{gc_result['total_after']} "
                          f"deleted={gc_result['deleted']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── 迭代42：DAMON scan — 主动数据访问模式监控 ──
        if _ict_enabled: _ict_milestones.append(("damon_scan", _ict_time.time()))
        # OS 类比：Linux DAMON (2021) 在系统运行时主动采样 access pattern
        # SessionStart 时做一次全量扫描，识别 dead/cold chunk 并主动回收
        damon_result = {"heatmap": {}, "actions": {}}
        if not _defer_reclaim and not _ts_skip("damon_scan"):
            try:
                damon_result = damon_scan(_log_conn, project)
                damon_actions = damon_result.get("actions", {})
                if any(v > 0 for v in damon_actions.values()):
                    _log_conn.commit()
                _ts_report("damon_scan", any(v > 0 for v in damon_actions.values()))
            except Exception:
                pass

        # ── iter505：shrink_dcache — Cross-Project Stale Object Reclaim ──
        if _ict_enabled: _ict_milestones.append(("shrink_dcache", _ict_time.time()))
        # OS 类比：Linux shrink_dcache_sb() (Al Viro, 2001) — 超级块级 dentry cache 回收
        # 跨所有 project 扫描零访问+超龄 chunks，分级降权/删除，解决 82%+ 零访问率
        shrink_result = {"phase1_candidates": 0, "phase2_demoted": 0, "phase3_deleted": 0}
        if not _defer_reclaim and not _ts_skip("shrink_dcache"):
            try:
                from store_vfs import shrink_dcache
                shrink_result = shrink_dcache(_log_conn, project)
                if shrink_result.get("phase2_demoted", 0) > 0 or shrink_result.get("phase3_deleted", 0) > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "shrink_dcache",
                              f"reclaim: candidates={shrink_result['phase1_candidates']} demoted={shrink_result['phase2_demoted']} deleted={shrink_result['phase3_deleted']} {shrink_result.get('duration_ms', 0):.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("shrink_dcache", (shrink_result.get("phase2_demoted", 0) + shrink_result.get("phase3_deleted", 0)) > 0)
            except Exception:
                pass

        # ── iter508：oom_reaper — 零访问率超标时批量降级回收 ──
        if _ict_enabled: _ict_milestones.append(("oom_reaper", _ict_time.time()))
        # OS 类比：Linux oom_reaper (Michal Hocko, 2016) — OOM 选中后立即回收匿名页
        # 不受 min_age_days 限制，专门处理各回收器保护条件叠加形成的"回收死区"
        if not _defer_reclaim and not _ts_skip("oom_reaper"):
            try:
                from store_vfs import oom_reaper
                reaper_result = oom_reaper(_log_conn, project)
                if reaper_result.get("triggered"):
                    dmesg_log(_log_conn, DMESG_INFO, "oom_reaper",
                              f"reap: ratio={reaper_result['zero_access_ratio']:.1%} reaped={reaper_result['reaped']} deleted={reaper_result['deleted']} {reaper_result.get('duration_ms', 0):.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("oom_reaper", reaper_result.get("triggered", False))
            except Exception:
                pass

        # ── iter513：overcommit_kill — Global 层过度承诺知识回收 ──
        if _ict_enabled: _ict_milestones.append(("overcommit_kill", _ict_time.time()))
        # OS 类比：Linux vm.overcommit_memory=2 (Rik van Riel, 2001) — 严格内存计量
        # global 层批量导入的知识绕过有机准入，85%+ 零访问需要激进回收
        if not _defer_reclaim and not _ts_skip("overcommit_kill"):
            try:
                oc_result = overcommit_kill(_log_conn)
                if oc_result.get("triggered"):
                    dmesg_log(_log_conn, DMESG_INFO, "overcommit_kill",
                              f"reap: global={oc_result['global_total']} zero={oc_result['global_zero_access']}({oc_result['zero_access_ratio']:.1%}) reaped={oc_result['reaped']} deleted={oc_result['deleted']} {oc_result.get('duration_ms', 0):.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("overcommit_kill", oc_result.get("triggered", False))
            except Exception:
                pass

        # ── iter521：free_pages_ok — Dead Page Frame Final Reclaim ──
        if _ict_enabled: _ict_milestones.append(("free_pages_ok", _ict_time.time()))
        # OS 类比：Linux __free_pages_ok() (Linus Torvalds, 1991) — refcount=0 归还 buddy
        # 统一最终回收：所有降级器（shrink/reaper/page_idle/overcommit）跑完后，
        # 清理 importance < 0.2 + access_count = 0 的 zombie chunks
        if not _defer_reclaim and not _ts_skip("free_pages_ok"):
            try:
                from store_mm import free_pages_ok
                fp_result = free_pages_ok(_log_conn, project)
                if fp_result["freed"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "free_pages_ok",
                              f"freed={fp_result['freed']} dead={fp_result['total_dead']} "
                              f"skip_acc={fp_result['skipped_accessed']} "
                              f"skip_prot={fp_result['skipped_protected']} "
                              f"{fp_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("free_pages_ok", fp_result.get("freed", 0) > 0)
            except Exception:
                pass

        # ── iter523：kfree_rcu — Deferred Cross-Project Zombie Reclaim ──
        if _ict_enabled: _ict_milestones.append(("kfree_rcu", _ict_time.time()))
        # OS 类比：Linux kfree_rcu() (Paul E. McKenney, 2002) — 延迟到 grace period 后全局释放
        # free_pages_ok 只扫描当前 project，global 层 zombie 无人回收 → 全局扫描补漏
        if not _defer_reclaim and not _ts_skip("kfree_rcu"):
            try:
                from store_mm import kfree_rcu
                kr_result = kfree_rcu(_log_conn)
                if kr_result["freed"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "kfree_rcu",
                              f"freed={kr_result['freed']} dead={kr_result['total_dead']} "
                              f"skip_prot={kr_result['skipped_protected']} "
                              f"{kr_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("kfree_rcu", kr_result.get("freed", 0) > 0)
            except Exception:
                pass

        # ── iter530：put_page — Unified Final Release + Bitmap Scrub ──
        if _ict_enabled: _ict_milestones.append(("put_page", _ict_time.time()))
        # OS 类比：Linux put_page()/__page_cache_release() — refcount=0 时统一释放路径
        # 三盲区修复：UE force kill(imp=0+acc>0) + OOM_MAX reap + bitmap stale scrub
        if not _defer_reclaim and not _ts_skip("put_page"):
            try:
                from store_mm import put_page
                pp_result = put_page(_log_conn, project)
                total_pp = (pp_result["ue_killed"] + pp_result["oom_max_reaped"]
                            + pp_result["oom_max_demoted"] + pp_result["bitmap_stale_removed"])
                if total_pp > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "put_page",
                              f"ue={pp_result['ue_killed']} oom_reap={pp_result['oom_max_reaped']} "
                              f"oom_demote={pp_result['oom_max_demoted']} "
                              f"bitmap_stale={pp_result['bitmap_stale_removed']} "
                              f"{pp_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("put_page", total_pp > 0)
            except Exception:
                pass

        # ── iter522：numa_balancing — Access-Pattern Importance Rebalancing ──
        if _ict_enabled: _ict_milestones.append(("numa_balancing", _ict_time.time()))
        # OS 类比：Linux AutoNUMA (Ingo Molnár, 2012) — 观察访问模式动态迁移页面到正确 NUMA node
        # 双向平衡：高访问+低imp → promote，高imp+零访问+超龄 → demote
        if not _defer_reclaim and not _ts_skip("numa_balancing"):
            try:
                from store_mm import numa_balancing
                nb_result = numa_balancing(_log_conn, project)
                if nb_result["promoted"] > 0 or nb_result["demoted"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "numa_balancing",
                              f"rebalance: promoted={nb_result['promoted']} "
                              f"demoted={nb_result['demoted']} "
                              f"skip_prot={nb_result['skipped_protected']} "
                              f"{nb_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("numa_balancing", (nb_result.get("promoted", 0) + nb_result.get("demoted", 0)) > 0)
            except Exception:
                pass

        # ── iter559：fair_clock — Cumulative Retrieval Score Importance Calibration ──
        if _ict_enabled: _ict_milestones.append(("fair_clock", _ict_time.time()))
        # OS 类比：Linux CFS vruntime (Ingo Molnár, 2007, kernel 2.6.23)
        # 基于累积检索分数校准 importance：cum_score=0+高imp → demote, cum_score高+低imp → promote
        # 与 numa_balancing(access_count 粗粒度) 互补：fair_clock 用检索 score 连续值
        if not _defer_reclaim and not _ts_skip("fair_clock"):
            try:
                from store_mm import fair_clock
                fc_result = fair_clock(_log_conn, project)
                if fc_result["demoted"] > 0 or fc_result["promoted"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "fair_clock",
                              f"calibrate: demoted={fc_result['demoted']} "
                              f"promoted={fc_result['promoted']} "
                              f"scored={fc_result['total_scored']} "
                              f"grace_skip={fc_result['skipped_grace']} "
                              f"prot_skip={fc_result['skipped_protected']} "
                              f"{fc_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("fair_clock", (fc_result.get("demoted", 0) + fc_result.get("promoted", 0)) > 0)
            except Exception:
                pass

        # ── iter561：place_entity — CFS Fair Initial Importance ──
        if _ict_enabled: _ict_milestones.append(("place_entity", _ict_time.time()))
        # OS 类比：Linux CFS place_entity() (Ingo Molnár, 2007, kernel 2.6.23)
        # 新 chunk（bulk import imp=0.15）无法与 avg imp=0.60 竞争 → 永远零访问
        # place_entity 提升到 min_vruntime（活跃 chunk P25 importance）公平起点
        if not _defer_reclaim and not _ts_skip("place_entity"):
            try:
                from store_mm import place_entity
                pe_result = place_entity(_log_conn, project)
                if pe_result["placed"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "place_entity",
                              f"placed={pe_result['placed']} "
                              f"eligible={pe_result['eligible']} "
                              f"min_vruntime={pe_result['min_vruntime']:.2f} "
                              f"{pe_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("place_entity", pe_result.get("placed", 0) > 0)
            except Exception:
                pass

        # ── iter524：mincore — Memory Residency Validation ──
        if _ict_enabled: _ict_milestones.append(("mincore", _ict_time.time()))
        # OS 类比：Linux mincore() (Linus Torvalds, 1994) — 查询哪些页面真实驻留在物理内存
        # 诊断高 importance 段的"虚假驻留"并校准 importance
        if not _defer_reclaim and not _ts_skip("mincore"):
            try:
                from store_mm import mincore
                mc_result = mincore(_log_conn, project)
                if mc_result["calibrated"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "mincore",
                              f"calibrate: high={mc_result['total_high']} "
                              f"resident={mc_result['resident']} "
                              f"non_resident={mc_result['non_resident']} "
                              f"calibrated={mc_result['calibrated']} "
                              f"{mc_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("mincore", mc_result.get("calibrated", 0) > 0)
            except Exception:
                pass

        # ── iter514：ksm_scan — 同页合并扫描（去除版本化重复） ──
        if _ict_enabled: _ict_milestones.append(("ksm_scan", _ict_time.time()))
        # OS 类比：Linux KSM (Andrea Arcangeli, 2009) — ksmd 扫描相同页面合并为 COW 共享页
        if not _defer_reclaim and not _ts_skip("ksm_scan"):
            try:
                ksm_result = ksm_scan(_log_conn)
                if ksm_result.get("triggered"):
                    dmesg_log(_log_conn, DMESG_INFO, "ksm_scan",
                              f"ksm: groups={ksm_result['groups_found']} merged={ksm_result['chunks_merged']} deleted={ksm_result['chunks_deleted']} {ksm_result.get('duration_ms', 0):.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("ksm_scan", ksm_result.get("triggered", False))
            except Exception:
                pass

        # ── 迭代516：madv_free — 惰性页面回收与 FTS5 索引排除 ──
        if _ict_enabled: _ict_milestones.append(("madv_free", _ict_time.time()))
        # OS 类比：Linux madvise(MADV_FREE) (Minchan Kim, 2016) — 标记页面可释放，移除 PTE mapping
        if not _defer_reclaim and not _ts_skip("madv_free"):
            try:
                from store_mm import madv_free_scan
                mf_result = madv_free_scan(_log_conn)
                if mf_result["unmapped"] > 0 or mf_result["freed"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "madv_free",
                              f"madv_free: unmapped={mf_result['unmapped']} freed={mf_result['freed']} lazy={mf_result['total_lazy']}",
                              session_id=_session_id, project=project)
                _ts_report("madv_free", (mf_result.get("unmapped", 0) + mf_result.get("freed", 0)) > 0)
            except Exception:
                pass

        # ── 迭代512：gc_namespace — 测试命名空间清理 ──
        # OS 类比：Linux pid_ns_release_proc() — namespace 销毁时批量清理所有 artifacts
        if not _defer_reclaim and not _ts_skip("gc_namespace"):
            try:
                ns_result = gc_namespace(_log_conn)
                if ns_result["traces_deleted"] > 0 or ns_result["chunks_deleted"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "gc",
                              f"gc_namespace: projects={len(ns_result['test_projects'])} traces={ns_result['traces_deleted']} ckpts={ns_result['checkpoints_deleted']} chunks={ns_result['chunks_deleted']}",
                              session_id=_session_id, project=project)
                _ts_report("gc_namespace", (ns_result.get("traces_deleted", 0) + ns_result.get("chunks_deleted", 0)) > 0)
            except Exception:
                pass

        # ── 迭代63：Trace GC — recall_traces 生命周期管理 ──
        # OS 类比：logrotate — SessionStart 时清理过期日志
        gc_result = {"deleted_age": 0, "deleted_rows": 0, "remaining": 0}
        try:
            gc_result = gc_traces(_log_conn, project)
            if gc_result["deleted_age"] > 0 or gc_result["deleted_rows"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "gc",
                          f"trace_gc: age={gc_result['deleted_age']} rows={gc_result['deleted_rows']} remaining={gc_result['remaining']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── 迭代509：rmap_sweep — recall_traces stale ref 清理 ──
        # OS 类比：Linux rmap (Rik van Riel, 2002) — page frame 释放后清除反向映射
        rmap_result = {"scrubbed_traces": 0, "deleted_traces": 0, "stale_refs_removed": 0}
        try:
            rmap_result = rmap_sweep(_log_conn, project)
            if rmap_result["stale_refs_removed"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "gc",
                          f"rmap_sweep: scrubbed={rmap_result['scrubbed_traces']} deleted={rmap_result['deleted_traces']} stale_refs={rmap_result['stale_refs_removed']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── 迭代510：vma_merge — recall_traces 重复合并 ──
        # OS 类比：Linux vma_merge() — 相邻 VMA 属性相同时自动合并
        vma_result = {"exact_merged": 0, "fuzzy_merged": 0}
        try:
            vma_result = vma_merge(_log_conn, project)
            total_merged = vma_result["exact_merged"] + vma_result["fuzzy_merged"]
            if total_merged > 0:
                dmesg_log(_log_conn, DMESG_INFO, "gc",
                          f"vma_merge: exact={vma_result['exact_merged']} fuzzy={vma_result['fuzzy_merged']} remaining={vma_result['remaining']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── iter544：trim_shadow_entries — shadow_traces expiry + stale ref scrub ──
        if _ict_enabled: _ict_milestones.append(("trim_shadow", _ict_time.time()))
        # OS 类比：Linux shadow_lru_isolate() (Johannes Weiner, 2013, mm/workingset.c)
        # shadow entry 超过 active page count 时从 LRU 尾部批量回收
        try:
            from store_mm import trim_shadow_entries
            shadow_result = trim_shadow_entries(_log_conn, project)
            if shadow_result["expired"] > 0 or shadow_result["purged"] > 0 or shadow_result["scrubbed_refs"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "gc",
                          f"trim_shadow: expired={shadow_result['expired']} purged={shadow_result['purged']} "
                          f"scrubbed_refs={shadow_result['scrubbed_refs']} remaining={shadow_result['remaining']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass

        # ── 迭代511：page_idle — 空闲页面精确追踪 ──
        if _ict_enabled: _ict_milestones.append(("page_idle", _ict_time.time()))
        # OS 类比：Linux page_idle bitmap (Vladimir Davydov, 2015)
        # 先 scan（收割上轮 idle chunks）→ 再 mark（标记本轮）
        try:
            idle_scan = page_idle_scan(_log_conn, project)
            if idle_scan["demoted"] > 0 or idle_scan["deleted"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "page_idle",
                          f"scan: demoted={idle_scan['demoted']} deleted={idle_scan['deleted']} max_rounds={idle_scan['max_idle_rounds']}",
                          session_id=_session_id, project=project)
        except Exception:
            pass
        try:
            idle_mark = page_idle_mark(_log_conn, project)
            # mark 结果仅 DEBUG 级别，不消耗 dmesg 空间
        except Exception:
            pass

        # ── iter528：munlock_idle — 撤销过期 mlock 保护 ──
        # OS 类比：Linux munlock() + MADV_COLD (Minchan Kim, 2019)
        # mlock 保护的 chunk 若连续 N 轮 idle 且 access=0，说明从未被实战验证，撤销保护
        if not _defer_reclaim and not _ts_skip("munlock_idle"):
            try:
                from store_mm import munlock_idle
                munlock_result = munlock_idle(_log_conn, project)
                if munlock_result["unlocked"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "munlock_idle",
                              f"unlocked={munlock_result['unlocked']} scanned={munlock_result['scanned']} "
                              f"grace_skip={munlock_result['skipped_grace']}",
                              session_id=_session_id, project=project)
                _ts_report("munlock_idle", munlock_result.get("unlocked", 0) > 0)
            except Exception:
                pass

        # ── iter542：oom_reaper_onfault — MLOCK_ONFAULT Demotion Reaper ──
        # OS 类比：Linux oom_reaper (Michal Hocko, 2016, kernel 4.6)
        # ONFAULT(-200) 零访问 chunk 处于保护死区（munlock_idle 不管，全局 oom_reaper 不触发）
        # 定向降级为 OOM_ADJ_PREFER(300)，允许正常回收路径处理
        if not _defer_reclaim and not _ts_skip("oom_reaper_onfault"):
            try:
                from store_mm import oom_reaper_onfault
                reaper_result = oom_reaper_onfault(_log_conn, project)
                if reaper_result["reaped"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "oom_reaper_onfault",
                              f"reaped={reaper_result['reaped']} scanned={reaper_result['scanned']} "
                              f"grace_skip={reaper_result['skipped_grace']}",
                              session_id=_session_id, project=project)
                _ts_report("oom_reaper_onfault", reaper_result.get("reaped", 0) > 0)
            except Exception:
                pass

        # ── iter532：cpuset — FTS5 Index Quarantine for Bandwidth Violators ──
        # OS 类比：Linux sched_setaffinity() / cpuset (Ingo Molnár, 2004)
        # 召回率超 50% 的垄断 chunk 从 FTS5 物理移除，cooldown 后自动恢复
        if not _defer_reclaim and not _ts_skip("cpuset_quarantine"):
            try:
                from store_mm import cpuset_quarantine
                cpuset_result = cpuset_quarantine(_log_conn, project)
                if cpuset_result["quarantined"] or cpuset_result["released"]:
                    dmesg_log(_log_conn, DMESG_INFO, "cpuset",
                              f"quarantine: new={len(cpuset_result['quarantined'])} "
                              f"released={len(cpuset_result['released'])} active={cpuset_result['active']}",
                              session_id=_session_id, project=project)
                _ts_report("cpuset_quarantine", bool(cpuset_result.get("quarantined") or cpuset_result.get("released")))
            except Exception:
                pass

        # ── iter545：vmstat_scan — Scan Efficiency & Dark Page Demotion ──
        # OS 类比：Linux /proc/vmstat pgscan/pgsteal (Mel Gorman, 2004)
        # 扫描效率审计：candidates_count(pgscan) vs top_k items(pgsteal)
        # dark pages（从未出现在 top_k）降级 oom_adj 为新知识让路
        if not _defer_reclaim and not _ts_skip("vmstat_scan"):
            try:
                from store_mm import vmstat_scan
                vmstat_result = vmstat_scan(_log_conn, project)
                if vmstat_result["dark_pages_demoted"] > 0 or vmstat_result["pgscan"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "vmstat",
                              f"scan_eff={vmstat_result['scan_efficiency']:.2f} "
                              f"pgscan={vmstat_result['pgscan']} pgsteal={vmstat_result['pgsteal']} "
                              f"dark={vmstat_result['dark_pages_total']} demoted={vmstat_result['dark_pages_demoted']}",
                              session_id=_session_id, project=project)
                _ts_report("vmstat_scan", vmstat_result.get("dark_pages_demoted", 0) > 0)
            except Exception:
                pass

        # ── iter546：shrink_slab — Watermark-Independent Slab Object Reaper ──
        if _ict_enabled: _ict_milestones.append(("shrink_slab", _ict_time.time()))
        # OS 类比：do_shrink_slab() (Dave Chinner, 2013, mm/vmscan.c)
        # 回收高 oom_adj + 零访问的 zombie chunks，不依赖 kswapd 水位线
        slab_result = {"freeable": 0, "reclaimed": 0, "skipped_grace": 0}
        if not _defer_reclaim and not _ts_skip("shrink_slab"):
            try:
                from store_mm import shrink_slab
                slab_result = shrink_slab(_log_conn, project)
                if slab_result["reclaimed"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "shrink_slab",
                              f"freeable={slab_result['freeable']} reclaimed={slab_result['reclaimed']} "
                              f"skip_grace={slab_result['skipped_grace']} "
                              f"{slab_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                    _log_conn.commit()
                _ts_report("shrink_slab", slab_result.get("reclaimed", 0) > 0)
            except Exception:
                pass

        # ── iter547：fstrim — Auxiliary Table Dead Block TRIM ──
        # OS 类比：fstrim / FITRIM ioctl (Lukas Czerner, 2010, kernel 2.6.37)
        # 辅助表（entity_edges/entity_map/chunk_coactivation/chunk_pins 等）
        # 保留指向已删除 chunks 的 stale references → TRIM 清除死块
        fstrim_result = {"total_trimmed": 0, "trimmed": {}}
        if not _defer_reclaim and not _ts_skip("fstrim"):
            try:
                from config import get as _cfg547
                if _cfg547("fstrim.enabled"):
                    from store_mm import fstrim
                    fstrim_result = fstrim(_log_conn)
                    if fstrim_result["total_trimmed"] > 0:
                        parts = [f"{k}={v}" for k, v in fstrim_result["trimmed"].items() if v > 0]
                        dmesg_log(_log_conn, DMESG_INFO, "fstrim",
                                  f"trimmed={fstrim_result['total_trimmed']} "
                                  f"({' '.join(parts)}) "
                                  f"{fstrim_result['duration_ms']:.1f}ms",
                                  session_id=_session_id, project=project)
                        _log_conn.commit()
                    _ts_report("fstrim", fstrim_result.get("total_trimmed", 0) > 0)
            except Exception:
                pass

        # ── iter548：logrotate — Metadata Table Lifecycle Rotation ──
        # OS 类比：logrotate (Red Hat, 1997) — 元数据/日志表无 chunk 外键，
        # 不能被 fstrim 清理。logrotate 按 per-table policy 轮转过期记录。
        logrotate_result = {"total_rotated": 0, "rotated": {}}
        if not _defer_reclaim and not _ts_skip("logrotate"):
            try:
                from config import get as _cfg548
                if _cfg548("logrotate.enabled"):
                    from store_mm import logrotate
                    logrotate_result = logrotate(_log_conn)
                    if logrotate_result["total_rotated"] > 0:
                        parts = [f"{k}={v}" for k, v in logrotate_result["rotated"].items() if v > 0]
                        dmesg_log(_log_conn, DMESG_INFO, "logrotate",
                                  f"rotated={logrotate_result['total_rotated']} "
                                  f"({' '.join(parts)}) "
                                  f"{logrotate_result['duration_ms']:.1f}ms",
                                  session_id=_session_id, project=project)
                        _log_conn.commit()
                    _ts_report("logrotate", logrotate_result.get("total_rotated", 0) > 0)
            except Exception:
                pass

        # ── iter563：prune_icache_sb — Metadata Table Proportional Reclaim ──
        # OS 类比：Linux dentry_lru_isolate() + prune_icache_sb() (Dave Chinner, 2012)
        # 不同于 logrotate（时间/数量轮转），prune_icache_sb 做引用/质量检查：
        # 清除无链接 priming、已消费 IPC、orphaned edges、过剩 txn log
        prune_result = {"total_pruned": 0}
        if not _defer_reclaim and not _ts_skip("prune_icache_sb"):
            try:
                from config import get as _cfg563
                if _cfg563("prune_icache_sb.enabled"):
                    from store_mm import prune_icache_sb
                    prune_result = prune_icache_sb(_log_conn, project)
                    if prune_result["total_pruned"] > 0:
                        parts = []
                        if prune_result["pruned_priming"] > 0:
                            parts.append(f"priming={prune_result['pruned_priming']}")
                        if prune_result["pruned_ipc"] > 0:
                            parts.append(f"ipc={prune_result['pruned_ipc']}")
                        if prune_result["pruned_edges"] > 0:
                            parts.append(f"edges={prune_result['pruned_edges']}")
                        if prune_result["pruned_txn"] > 0:
                            parts.append(f"txn={prune_result['pruned_txn']}")
                        dmesg_log(_log_conn, DMESG_INFO, "prune_icache_sb",
                                  f"pruned={prune_result['total_pruned']} "
                                  f"({' '.join(parts)}) "
                                  f"{prune_result['duration_ms']:.1f}ms",
                                  session_id=_session_id, project=project)
                        _log_conn.commit()
                    _ts_report("prune_icache_sb", prune_result.get("total_pruned", 0) > 0)
            except Exception:
                pass

        # ── iter564：oom_score_adj_rebalance — Runtime OOM Score Recalibration ──
        if _ict_enabled: _ict_milestones.append(("oom_rebalance", _ict_time.time()))
        # OS 类比：Linux oom_badness() — 综合静态 adj + 动态指标重算 OOM 分数
        _oom_rb_result = {"adjusted": 0}
        if not _defer_reclaim and not _ts_skip("oom_rebalance"):
            try:
                from store_mm import oom_score_adj_rebalance
                _oom_rb_result = oom_score_adj_rebalance(_log_conn, project)
                if _oom_rb_result["adjusted"] > 0:
                    parts = []
                    if _oom_rb_result["r1_demoted"]:
                        parts.append(f"r1_demote={_oom_rb_result['r1_demoted']}")
                    if _oom_rb_result["r2_promoted"]:
                        parts.append(f"r2_promote={_oom_rb_result['r2_promoted']}")
                    if _oom_rb_result["r3_protected"]:
                        parts.append(f"r3_protect={_oom_rb_result['r3_protected']}")
                    if _oom_rb_result.get("r4_invalidated"):
                        parts.append(f"r4_invalid={_oom_rb_result['r4_invalidated']}")
                    dmesg_log(_log_conn, DMESG_INFO, "oom_rebalance",
                              f"adjusted={_oom_rb_result['adjusted']} "
                              f"({' '.join(parts)}) "
                              f"scanned={_oom_rb_result['scanned']} "
                              f"{_oom_rb_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("oom_rebalance", _oom_rb_result.get("adjusted", 0) > 0)
            except Exception:
                pass

        # ── iter568：shrink_dcache_sb — Immediate Fragment Reclaim ──
        if _ict_enabled: _ict_milestones.append(("shrink_dcache_sb", _ict_time.time()))
        # OS 类比：Linux shrink_dcache_sb() — 事件驱动即时清理，无 LRU aging 等待
        _shrink_result = {"deleted": 0}
        if not _defer_reclaim and not _ts_skip("shrink_dcache_sb"):
            try:
                from store_mm import shrink_dcache_sb
                _shrink_result = shrink_dcache_sb(_log_conn, project)
                if _shrink_result["deleted"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "shrink_dcache_sb",
                              f"deleted={_shrink_result['deleted']} "
                              f"scanned={_shrink_result['scanned']} "
                              f"{_shrink_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("shrink_dcache_sb", _shrink_result.get("deleted", 0) > 0)
            except Exception:
                pass

        # ── iter569：anon_vma_prepare — Entity Map Backfill ──
        if _ict_enabled: _ict_milestones.append(("anon_vma_prepare", _ict_time.time()))
        # OS 类比：Linux anon_vma_prepare() — 为迁移页面建立 rmap 基础设施
        # 无 entity_map 的 chunk 对 spreading_activate 不可见（57% dark page rate）
        if not _defer_reclaim and not _ts_skip("anon_vma_prepare"):
            try:
                from store_mm import anon_vma_prepare
                _avp_result = anon_vma_prepare(_log_conn, project)
                if _avp_result["backfilled"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "anon_vma_prepare",
                              f"backfilled={_avp_result['backfilled']} "
                              f"entities={_avp_result['entities_created']} "
                              f"orphans={_avp_result['orphans_found']} "
                              f"{_avp_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("anon_vma_prepare", _avp_result.get("backfilled", 0) > 0)
            except Exception:
                pass

        # ── iter570：populate_pte — Entity Edge Target PTE Population ──
        if _ict_enabled: _ict_milestones.append(("populate_pte", _ict_time.time()))
        # OS 类比：Linux populate_pte() / vmalloc_fault() — 为 entity_edges 中无 entity_map
        # 映射的目标实体建立 PTE，修复 spreading_activate 72.8% 死路
        if not _defer_reclaim and not _ts_skip("populate_pte"):
            try:
                from store_mm import populate_pte
                _pte_result = populate_pte(_log_conn, project)
                if _pte_result["populated"] > 0:
                    dmesg_log(_log_conn, DMESG_INFO, "populate_pte",
                              f"populated={_pte_result['populated']} "
                              f"mappings={_pte_result['mappings_created']} "
                              f"unmapped={_pte_result['unmapped_found']} "
                              f"{_pte_result['duration_ms']:.1f}ms",
                              session_id=_session_id, project=project)
                _ts_report("populate_pte", _pte_result.get("populated", 0) > 0)
            except Exception:
                pass

        # ── iter549：vacuum — Database File Compaction ──
        # OS 类比：SSD Background GC / Firmware Compaction — fstrim 通知 SSD 哪些 LBA
        # 空闲，但物理回收需要 SSD 内部 GC 搬迁有效 pages 合并 erase blocks。
        # SQLite freelist pages = invalidated pages, VACUUM = background GC compaction。
        vacuum_result = {"vacuumed": False, "freed_kb": 0}
        if not _defer_reclaim and not _ts_skip("vacuum"):
            try:
                from config import get as _cfg549
                if _cfg549("vacuum.enabled"):
                    from store_mm import vacuum
                    vacuum_result = vacuum(str(STORE_DB))
                    if vacuum_result["vacuumed"]:
                        dmesg_log(_log_conn, DMESG_INFO, "vacuum",
                                  f"compacted {vacuum_result['before_size_kb']:.0f}KB→{vacuum_result['after_size_kb']:.0f}KB "
                                  f"freed={vacuum_result['freed_kb']:.0f}KB({vacuum_result['freed_pct']:.1f}%) "
                                  f"freelist_was={vacuum_result['freelist_pct']:.1f}% "
                                  f"{vacuum_result['duration_ms']:.1f}ms",
                                  session_id=_session_id, project=project)
                        _log_conn.commit()
                    _ts_report("vacuum", vacuum_result.get("vacuumed", False))
            except Exception:
                pass

        # ── iter550：release_task — Per-Session Runtime State Cleanup ──
        # OS 类比：release_task() (kernel/exit.c) — 进程退出时清理 per-process 运行时状态
        # (/proc/PID/, fd, mm_struct)。没有 release_task → zombie 资源泄漏。
        release_task_result = {"total_cleaned": 0, "phases": {}}
        if not _defer_reclaim and not _ts_skip("release_task"):
            try:
                from config import get as _cfg550
                if _cfg550("release_task.enabled"):
                    from store_mm import release_task
                    release_task_result = release_task(_log_conn, project)
                    if release_task_result["total_cleaned"] > 0:
                        _ph = release_task_result["phases"]
                        parts = []
                        if _ph.get("shadow_file_gc", {}).get("removed", 0):
                            parts.append(f"files={_ph['shadow_file_gc']['removed']}")
                        if _ph.get("shadow_db_dedup", {}).get("removed", 0):
                            parts.append(f"db_dedup={_ph['shadow_db_dedup']['removed']}")
                        if _ph.get("session_episodes_gc", {}).get("removed", 0):
                            parts.append(f"episodes={_ph['session_episodes_gc']['removed']}")
                        if _ph.get("checkpoint_gc", {}).get("removed", 0):
                            parts.append(f"checkpoints={_ph['checkpoint_gc']['removed']}")
                        dmesg_log(_log_conn, DMESG_INFO, "release_task",
                                  f"cleaned={release_task_result['total_cleaned']} "
                                  f"{' '.join(parts)} "
                                  f"{release_task_result['duration_ms']:.1f}ms",
                                  session_id=_session_id, project=project)
                        _log_conn.commit()
                    _ts_report("release_task", release_task_result.get("total_cleaned", 0) > 0)
            except Exception:
                pass

        # ── 迭代146：Swap GC — 孤儿 project 清理 ──
        if _ict_enabled: _ict_milestones.append(("gc_swap", _ict_time.time()))
        # OS 类比：process exit → free anonymous swap pages (do_exit → exit_mmap)
        # 消亡 project（主表已无 chunk）的 swap 条目永久占位，不会被 swap_in，
        # 挤压活跃 project 的 swap 使用空间 → SessionStart 清理
        gc_swap_result = {"orphan_projects": [], "deleted_count": 0, "freed_pct": 0.0}
        try:
            gc_swap_result = gc_orphan_swap(_log_conn)
            if gc_swap_result["deleted_count"] > 0:
                dmesg_log(_log_conn, DMESG_INFO, "gc",
                          f"swap_gc: orphans={len(gc_swap_result['orphan_projects'])} deleted={gc_swap_result['deleted_count']} freed={gc_swap_result['freed_pct']}%",
                          session_id=_session_id, project=project)
                _log_conn.commit()
        except Exception:
            pass

        # ── iter430: Spontaneous Recovery — 自发恢复（Pavlov 1927）──
        # OS 类比：Linux MGLRU 跨代晋升 — swap 中高历史访问 chunk 自发恢复
        # 在 swap_gc 之后执行（先清理孤儿，再恢复有价值的 chunk）
        sr_result = {"recovered": 0, "boosted": 0}
        try:
            from store_swap import run_spontaneous_recovery
            sr_result = run_spontaneous_recovery(_log_conn, project)
            if sr_result.get("recovered", 0) > 0:
                dmesg_log(_log_conn, DMESG_INFO, "swap",
                          f"spontaneous_recovery: recovered={sr_result['recovered']} stability_boosted={sr_result['boosted']}",
                          session_id=_session_id, project=project)
                _log_conn.commit()
        except Exception:
            pass

        # ── iter551: initcall_debug — 计算 per-subsystem 延迟 ──
        if _ict_enabled: _ict_milestones.append(("_boot_end", _ict_time.time()))
        _ict_blame = ""
        try:
            from store_mm import initcall_debug as _icd_analyze
            # 从 milestones 计算 per-subsystem timings:
            # [(name, elapsed_ms, True)] — milestone[i+1].time - milestone[i].time
            _ict_timings = []
            for i in range(len(_ict_milestones) - 1):
                _m_name = _ict_milestones[i + 1][0]  # 下一个 milestone 的名字
                if _m_name.startswith("_"):  # skip internal markers
                    _m_name = _ict_milestones[i][0]
                else:
                    _m_name = _ict_milestones[i][0] if not _ict_milestones[i][0].startswith("_") else _m_name
                # 使用当前 milestone 的名字作为 subsystem 名
                name = _ict_milestones[i][0]
                if name.startswith("_"):
                    continue
                elapsed_ms = (_ict_milestones[i + 1][1] - _ict_milestones[i][1]) * 1000
                _ict_timings.append((name, round(elapsed_ms, 2), True))
            _ict_result = _icd_analyze(_ict_timings)
            _ict_blame = _ict_result.get("blame_line", "")
            if _ict_blame:
                dmesg_log(_log_conn, DMESG_INFO, "initcall_debug",
                          _ict_blame,
                          session_id=_session_id, project=project)
        except Exception:
            pass  # initcall_debug 失败不影响 SessionStart

        # ── iter553: sched_deadline — 喂入 timing 数据 + 保存 ──
        if _sd_enabled and _ict_timings:
            try:
                for _sd_name, _sd_ms, _sd_ok in _ict_timings:
                    if _sd_ok:  # 只对成功执行的子系统更新 EMA
                        _sd_state = sched_deadline_update(_sd_state, _sd_name, _sd_ms)
                sched_deadline_save(_sd_state)
                _sd_stats_result = sched_deadline_stats(_sd_state)
                if _sd_throttled_subsystems:
                    dmesg_log(_log_conn, DMESG_DEBUG, "sched_deadline",
                              f"throttled={len(_sd_throttled_subsystems)} "
                              f"({','.join(_sd_throttled_subsystems)}) "
                              f"over_budget={_sd_stats_result['over_budget']}",
                              session_id=_session_id, project=project)
            except Exception:
                pass

        # ── iter554: cgroup_budget — 从 timing 数据计算 per-group 合计 + settle ──
        if _cg_enabled and _ict_timings:
            try:
                # 按 group 聚合本 session 各子系统耗时
                _cg_group_totals = {}
                for _cg_name, _cg_ms, _cg_ok in _ict_timings:
                    if _cg_ok:
                        _cg_grp = _SUBSYSTEM_TO_GROUP.get(_cg_name)
                        if _cg_grp:
                            _cg_group_totals[_cg_grp] = _cg_group_totals.get(_cg_grp, 0.0) + _cg_ms
                # settle: 用实际合计更新 EMA + throttle 判定
                _cg_state = cgroup_budget_settle(_cg_state, _cg_group_totals)
                cgroup_budget_save(_cg_state)
                _cg_stats_result = cgroup_budget_stats(_cg_state)
                if _cg_throttled_subsystems:
                    dmesg_log(_log_conn, DMESG_DEBUG, "cgroup_budget",
                              f"throttled={len(_cg_throttled_subsystems)} "
                              f"({','.join(_cg_throttled_subsystems)}) "
                              f"over_budget_groups={_cg_stats_result['over_budget_groups']}",
                              session_id=_session_id, project=project)
            except Exception:
                pass

        # ── iter552: timer_slack — 保存状态 + dmesg 统计 ──
        if _ts_enabled:
            try:
                _ts_stats = timer_slack_stats(_ts_state)
                if _ts_skipped_subsystems:
                    dmesg_log(_log_conn, DMESG_DEBUG, "timer_slack",
                              f"skipped={len(_ts_skipped_subsystems)} "
                              f"({','.join(_ts_skipped_subsystems)}) "
                              f"idle={_ts_stats['idle_subsystems']}",
                              session_id=_session_id, project=project)
                timer_slack_save(_ts_state)
            except Exception:
                pass

        # ── iter555: schedstat — 从 initcall_debug timing 记录执行统计 + session boot time ──
        if _ss_enabled:
            try:
                # 记录每个已执行子系统的 runtime + did_work
                if _ict_enabled:
                    for _ss_name, _ss_ms, _ss_ok in _ict_timings:
                        if _ss_ok:
                            # did_work: 用 elapsed > 1ms 作为"有实质工作"的保守估算
                            _ss_state = schedstat_record_exec(_ss_state, _ss_name, _ss_ms, _ss_ms > 1.0)
                    # 记录 session boot time
                    _ss_boot_ms = _ict_result.get("total_ms", 0.0) if _ict_result else 0.0
                    if _ss_boot_ms > 0:
                        _ss_state = schedstat_record_session(_ss_state, _ss_boot_ms)
                # blame line → dmesg
                _ss_blame_line = schedstat_blame(_ss_state)
                if _ss_blame_line:
                    dmesg_log(_log_conn, DMESG_DEBUG, "schedstat",
                              _ss_blame_line,
                              session_id=_session_id, project=project)
                schedstat_save(_ss_state)
            except Exception:
                pass

        # ── iter556: sched_autogroup — 基于 schedstat 自动调参 ──
        # OS 类比：Linux sched_autogroup (Mike Galbraith, 2010, kernel 2.6.38)
        # 读取 schedstat 累积数据，自动调节 timer_slack/sched_deadline/cgroup_budget 参数
        if _ss_enabled and _sysctl("sched_autogroup.enabled"):
            try:
                _ag_result = sched_autogroup(_ss_state)
                if _ag_result.get("adjusted"):
                    _ag_adj_str = ", ".join(
                        f"{a['param']}:{a['old']}→{a['new']}" for a in _ag_result["adjustments"]
                    )
                    dmesg_log(_log_conn, DMESG_INFO, "sched_autogroup",
                              f"tuned: {_ag_adj_str}",
                              session_id=_session_id, project=project)
            except Exception:
                pass  # autogroup 失败不影响 SessionStart

        # 迭代29 dmesg：SessionStart 加载记录
        damon_summary = ""
        damon_hm = damon_result.get("heatmap", {})
        if damon_hm:
            damon_summary = f" damon=H{damon_hm.get('hot',0)}/W{damon_hm.get('warm',0)}/C{damon_hm.get('cold',0)}/D{damon_hm.get('dead',0)}"
        mglru_summary = ""
        if mglru_result.get("aged"):
            mglru_summary = f" mglru_aged={mglru_result.get('affected_count', 0)}"

        criu_summary = ""
        if checkpoint_info:
            criu_summary = f" criu_restore={checkpoint_info['checkpoint_id']} age={checkpoint_info['age_hours']}h ids={len(checkpoint_info['chunks'])}"

        autotune_summary = ""
        if autotune_result.get("tuned"):
            autotune_summary = f" autotune={len(autotune_result['adjustments'])}adj"
        elif autotune_result.get("skipped_reason"):
            autotune_summary = f" autotune=skip({autotune_result['skipped_reason'][:20]})"

        gc_summary = ""
        gc_deleted = gc_result.get("deleted_age", 0) + gc_result.get("deleted_rows", 0)
        if gc_deleted > 0:
            gc_summary = f" gc_traces={gc_deleted}del/{gc_result.get('remaining', 0)}rem"

        rmap_summary = ""
        if rmap_result.get("stale_refs_removed", 0) > 0:
            rmap_summary = f" rmap={rmap_result['stale_refs_removed']}refs/{rmap_result['deleted_traces']}del"

        gc_swap_summary = ""
        if gc_swap_result.get("deleted_count", 0) > 0:
            gc_swap_summary = f" gc_swap={gc_swap_result['deleted_count']}del({gc_swap_result['freed_pct']}%freed)"

        consolidation_summary = ""
        if consolidation_result.get("consolidated", 0) > 0:
            consolidation_summary = f" sleep_consol={consolidation_result['consolidated']}chunks"

        slab_summary = ""
        if slab_result.get("reclaimed", 0) > 0:
            slab_summary = f" shrink_slab={slab_result['reclaimed']}recl/{slab_result['freeable']}free"

        fstrim_summary = ""
        if fstrim_result.get("total_trimmed", 0) > 0:
            fstrim_summary = f" fstrim={fstrim_result['total_trimmed']}trimmed"

        logrotate_summary = ""
        if logrotate_result.get("total_rotated", 0) > 0:
            logrotate_summary = f" logrotate={logrotate_result['total_rotated']}rotated"

        prune_summary = ""
        if prune_result.get("total_pruned", 0) > 0:
            prune_summary = f" prune_icache={prune_result['total_pruned']}pruned"

        vacuum_summary = ""
        if vacuum_result.get("vacuumed"):
            vacuum_summary = f" vacuum={vacuum_result['freed_kb']:.0f}KB({vacuum_result['freed_pct']:.1f}%)"

        release_task_summary = ""
        if release_task_result.get("total_cleaned", 0) > 0:
            release_task_summary = f" release_task={release_task_result['total_cleaned']}cleaned"

        cgroup_summary = ""
        if _cg_throttled_subsystems:
            cgroup_summary = f" cgroup_throttled={len(_cg_throttled_subsystems)}"

        dmesg_log(_log_conn, DMESG_INFO, "loader",
                  f"session_start latest={'Y' if has_latest else 'N'} working_set={len(working_set)} ctx_len={len(context_text)} watchdog={wd_status}{autotune_summary}{criu_summary}{damon_summary}{mglru_summary}{gc_summary}{rmap_summary}{gc_swap_summary}{slab_summary}{fstrim_summary}{logrotate_summary}{prune_summary}{vacuum_summary}{release_task_summary}{consolidation_summary}{cgroup_summary}",
                  session_id=_session_id, project=project)
        _log_conn.commit()
        _log_conn.close()
    except Exception:
        pass

    # ── 迭代B4：预热 retriever heavy modules + FTS5 index cache ──
    # 在输出之前执行，利用 SessionStart 的空闲时间预热，
    # 降低第一次 UserPromptSubmit 的冷启动延迟（目标：消除 ~27ms import + WAL checkpoint）
    if STORE_DB.exists():
        try:
            _ph_conn = open_db()
            ensure_schema(_ph_conn)
            _preheat_retriever(_ph_conn, project)
            _ph_conn.commit()
            _ph_conn.close()
        except Exception:
            pass  # 预热失败不影响主流程

    # ── 迭代100：IPC 消息消费 + 过期清理（OS 类比：init 进程收割僵尸进程）──
    try:
        _ipc_conn = open_db()
        ensure_schema(_ipc_conn)
        from store_vfs import ipc_recv, ipc_cleanup_expired
        # 清理过期消息
        expired = ipc_cleanup_expired(_ipc_conn)
        # 消费待处理的知识更新通知
        msgs = ipc_recv(_ipc_conn, _session_id, msg_type="knowledge_update", limit=5)
        if msgs or expired:
            dmesg_log(_ipc_conn, DMESG_INFO, "loader",
                      f"ipc: consumed={len(msgs)} expired={expired}",
                      session_id=_session_id, project=project)
        _ipc_conn.commit()
        _ipc_conn.close()
    except Exception:
        pass  # IPC 失败不影响主流程

    # ── 语义记忆层预热（跨项目通用知识，__semantic__ project）──────────────────
    # OS 类比：shared library mmap — 启动时将 libc 等共享库映射入地址空间，
    # 所有 project 共享同一份语义记忆页，不重复占用 per-project token budget。
    # 只加载 importance 最高的 top-K，严格控制 token 开销。
    try:
        _sem_conn = open_db()
        ensure_schema(_sem_conn)
        _sem_rows = _sem_conn.execute("""
            SELECT summary, content, importance, tags
            FROM memory_chunks
            WHERE project='__semantic__'
              AND chunk_type='semantic_memory'
              AND COALESCE(oom_adj, 0) <= 0
            ORDER BY importance DESC
            LIMIT 5
        """).fetchall()
        _sem_conn.close()

        if _sem_rows:
            _sem_lines = ["【跨项目语义记忆（通用知识）】"]
            for _sr in _sem_rows:
                _s_summary, _s_content, _s_imp, _s_tags = _sr
                _projects = ""
                try:
                    _projects = " [来源: " + ", ".join(json.loads(_s_tags or "[]")[:3]) + "]"
                except Exception:
                    pass
                _sem_lines.append(f"- {_s_summary}{_projects}")
            _sem_text = "\n".join(_sem_lines)
            # 插入在 context_text 前面（高优先级，类比 mlock 常驻页）
            _sem_budget = 400  # 严格限制语义层 token 开销
            if len(_sem_text) > _sem_budget:
                _sem_text = _sem_text[:_sem_budget] + "…"
            context_text = _sem_text + "\n\n" + context_text
    except Exception:
        pass  # 语义层预热失败不影响 SessionStart

    # ── iter526: vm_flags — Write Loader Page Table ──────────────────────────
    # 将 loader 注入的 chunk IDs 写入 .loader_page_table.json，
    # retriever 读取后排除这些 IDs，避免同一 chunk 被 SessionStart + UserPromptSubmit 双重注入。
    # OS 类比：/proc/PID/smaps vm_flags 公开 VMA 映射信息，防止重复 mmap。
    if _loader_injected_ids:
        try:
            _pt_path = MEMORY_OS_DIR / ".loader_page_table.json"
            _pt_data = {
                "injected_ids": _loader_injected_ids,
                "project": project,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            _pt_path.write_text(json.dumps(_pt_data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass  # page table 写入失败不影响 SessionStart

    output = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context_text,
        }
    }
    print(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
