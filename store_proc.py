"""
store_proc.py — /proc Virtual Filesystem + dmesg Ring Buffer

从 store_core.py 拆分（迭代26-29 功能集）。
包含：proc_stats()（运行时可观测性）、dmesg 日志系统。

OS 类比：Linux /proc (Plan 9 -> Linux 1992) + /dev/kmsg ring buffer
"""
import json
from datetime import datetime, timezone

from store_vfs import open_db, ensure_schema, STORE_DB, MEMORY_OS_DIR

# ── /proc Virtual Filesystem — 运行时可观测性（迭代26）─────────

def proc_stats(conn=None) -> dict:
    """
    迭代26：/proc — 运行时可观测性。
    OS 类比：Linux /proc/meminfo + /proc/stat + /proc/vmstat
      cat /proc/meminfo 给出内存使用全貌，
      cat /proc/stat 给出 CPU 调度统计，
      cat /proc/vmstat 给出页面换入换出计数。
    proc_stats() 一次调用返回 memory-os 全貌：
      chunks — 总量/按项目/按类型分布（≈ /proc/meminfo）
      retrieval — 召回次数/命中率/平均延迟（≈ /proc/stat）
      staleness — 7/30/90天未访问 chunk 数（≈ /proc/vmstat pgsteal）

    返回 dict，可直接 json.dumps 输出。
    """
    own_conn = conn is None
    if own_conn:
        if not STORE_DB.exists():
            return {"error": "store.db not found"}
        conn = open_db()
        ensure_schema(conn)

    try:
        stats = {}

        # ── /proc/meminfo：chunk 分布 ──
        total = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]

        by_project = conn.execute(
            "SELECT project, COUNT(*) FROM memory_chunks GROUP BY project ORDER BY COUNT(*) DESC"
        ).fetchall()

        by_type = conn.execute(
            "SELECT chunk_type, COUNT(*) FROM memory_chunks GROUP BY chunk_type ORDER BY COUNT(*) DESC"
        ).fetchall()

        stats["chunks"] = {
            "total": total,
            "by_project": {p: c for p, c in by_project},
            "by_type": {t: c for t, c in by_type},
        }

        # ── /proc/stat：召回统计 ──
        trace_total = conn.execute("SELECT COUNT(*) FROM recall_traces").fetchone()[0]
        trace_injected = conn.execute(
            "SELECT COUNT(*) FROM recall_traces WHERE injected=1"
        ).fetchone()[0]
        trace_skipped = conn.execute(
            "SELECT COUNT(*) FROM recall_traces WHERE injected=0"
        ).fetchone()[0]

        avg_latency = conn.execute(
            "SELECT AVG(duration_ms) FROM recall_traces WHERE duration_ms > 0"
        ).fetchone()[0]
        p95_latency = conn.execute(
            """SELECT duration_ms FROM recall_traces
               WHERE duration_ms > 0
               ORDER BY duration_ms DESC
               LIMIT 1 OFFSET (
                   SELECT CAST(COUNT(*) * 0.05 AS INTEGER)
                   FROM recall_traces WHERE duration_ms > 0
               )"""
        ).fetchone()

        hit_rate = (trace_injected / trace_total * 100) if trace_total > 0 else 0.0

        stats["retrieval"] = {
            "total_queries": trace_total,
            "injected": trace_injected,
            "skipped": trace_skipped,
            "hit_rate_pct": round(hit_rate, 1),
            "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0.0,
            "p95_latency_ms": round(p95_latency[0], 2) if p95_latency else 0.0,
        }

        # ── /proc/vmstat：过期/活跃度统计 ──
        # 迭代147：datetime(last_accessed) 修复 ISO8601+timezone 字符串比较 bug
        stale_7d = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE datetime(last_accessed) < datetime('now', '-7 days')"""
        ).fetchone()[0]
        stale_30d = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE datetime(last_accessed) < datetime('now', '-30 days')"""
        ).fetchone()[0]
        stale_90d = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE datetime(last_accessed) < datetime('now', '-90 days')"""
        ).fetchone()[0]

        avg_importance = conn.execute(
            "SELECT AVG(importance) FROM memory_chunks"
        ).fetchone()[0]
        avg_access_count = conn.execute(
            "SELECT AVG(COALESCE(access_count, 0)) FROM memory_chunks"
        ).fetchone()[0]

        stats["staleness"] = {
            "not_accessed_7d": stale_7d,
            "not_accessed_30d": stale_30d,
            "not_accessed_90d": stale_90d,
            "active_pct": round((total - stale_7d) / total * 100, 1) if total > 0 else 0.0,
        }

        stats["health"] = {
            "avg_importance": round(avg_importance, 3) if avg_importance else 0.0,
            "avg_access_count": round(avg_access_count, 1) if avg_access_count else 0.0,
        }

        # ── 迭代38：/proc/[pid]/oom_score_adj 统计 ──
        try:
            protected_count = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE COALESCE(oom_adj, 0) < 0"
            ).fetchone()[0]
            disposable_count = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE COALESCE(oom_adj, 0) > 0"
            ).fetchone()[0]
            locked_count = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE COALESCE(oom_adj, 0) <= -1000"
            ).fetchone()[0]
            stats["oom_score"] = {
                "protected": protected_count,   # oom_adj < 0
                "locked": locked_count,         # oom_adj <= -1000 (mlock)
                "disposable": disposable_count, # oom_adj > 0
                "default": total - protected_count - disposable_count,
            }
        except Exception:
            stats["oom_score"] = {"protected": 0, "locked": 0, "disposable": 0, "default": total}

        # ── 迭代33：/proc/swaps — swap 分区统计 ──
        try:
            swap_total = conn.execute("SELECT COUNT(*) FROM swap_chunks").fetchone()[0]
            swap_by_project = conn.execute(
                "SELECT project, COUNT(*) FROM swap_chunks GROUP BY project ORDER BY COUNT(*) DESC"
            ).fetchall()
            stats["swap"] = {
                "total": swap_total,
                "by_project": {p: c for p, c in swap_by_project},
            }
        except Exception:
            stats["swap"] = {"total": 0, "by_project": {}}

        # ── 迭代36：/proc/pressure — PSI 压力统计 ──
        try:
            from store_mm import psi_stats as _psi_stats
            psi_by_project = {}
            for proj, _ in by_project:
                psi_by_project[proj] = _psi_stats(conn, proj)
            stats["pressure"] = psi_by_project
        except Exception:
            stats["pressure"] = {}

        # ── 迭代42：/proc/damon — 数据访问热度分布 ──
        try:
            zero_access = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE COALESCE(access_count, 0) = 0"
            ).fetchone()[0]
            stats["access_heatmap"] = {
                "zero_access_count": zero_access,
                "zero_access_pct": round(zero_access / total * 100, 1) if total > 0 else 0.0,
                "avg_access_count": round(avg_access_count, 1) if avg_access_count else 0.0,
            }
        except Exception:
            stats["access_heatmap"] = {}

        # ── 迭代41：/proc/schedstat — Deadline I/O Scheduler 统计 ──
        try:
            deadline_traces = conn.execute(
                """SELECT COUNT(*) FROM recall_traces
                   WHERE reason LIKE '%deadline%'"""
            ).fetchone()[0]
            hard_deadline_traces = conn.execute(
                """SELECT COUNT(*) FROM recall_traces
                   WHERE reason LIKE '%hard_deadline%'"""
            ).fetchone()[0]
            stats["deadline"] = {
                "soft_deadline_skips": deadline_traces,
                "hard_deadline_hits": hard_deadline_traces,
                "total_traces": trace_total,
                "skip_rate_pct": round(deadline_traces / max(1, trace_total) * 100, 1),
            }
        except Exception:
            stats["deadline"] = {"soft_deadline_skips": 0, "hard_deadline_hits": 0}

        # ── /proc/aimd：TCP AIMD 拥塞窗口统计（迭代50）──
        try:
            from store_mm import _AIMD_STATE_FILE, _cwnd_to_policy
            aimd_data = {}
            if _AIMD_STATE_FILE.exists():
                aimd_raw = json.loads(_AIMD_STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(aimd_raw, dict):
                    for proj, pdata in aimd_raw.items():
                        if isinstance(pdata, dict):
                            aimd_data[proj] = {
                                "cwnd": pdata.get("cwnd", 0),
                                "policy": _cwnd_to_policy(pdata.get("cwnd", 0.7)),
                                "hit_rate": pdata.get("hit_rate", 0),
                                "direction": pdata.get("direction", ""),
                            }
            stats["aimd"] = aimd_data if aimd_data else {"status": "no_data"}
        except Exception:
            stats["aimd"] = {"status": "error"}

        return stats

    finally:
        if own_conn:
            conn.close()

# ── dmesg Ring Buffer — 结构化事件日志（迭代29）─────────────────

# 日志级别常量（严重度从高到低）
DMESG_ERR = "ERR"       # 错误：FTS5 查询失败、配额超限触发淘汰
DMESG_WARN = "WARN"     # 警告：降级路径、接近配额
DMESG_INFO = "INFO"     # 信息：正常操作记录
DMESG_DEBUG = "DEBUG"   # 调试：详细内部状态

_LEVEL_ORDER = {DMESG_ERR: 0, DMESG_WARN: 1, DMESG_INFO: 2, DMESG_DEBUG: 3}


# ── iter538: printk_ratelimit — dmesg 去重抑制 ──────────────────────────────────
# OS 类比：Linux printk_ratelimit() / __ratelimit() (Alan Cox, 1999)
#   net_ratelimit() 防止网络攻击填满 dmesg ring buffer。
#   对同一子系统的重复消息进行去重压缩，保护有限 ring buffer 容量。
#
# 实现：进程内 LRU 缓存，记录 (subsystem, message_key) → (timestamp, count)。
#   同一 key 在 ratelimit_interval_s 内再次出现 → 跳过写入，累加 suppressed 计数。
#   窗口过期时写入一条 "suppressed N duplicates" 摘要。
_ratelimit_cache: dict = {}  # {(subsystem, msg_key): {"ts": float, "count": int}}
_RATELIMIT_CACHE_MAX = 64    # 最多追踪 64 个 key（防内存泄漏）


def _ratelimit_key(message: str) -> str:
    """提取消息的去重 key：取等号前的字段名骨架。
    例如 'freed=27 dead=27 skip_prot=0 12.4ms' → 'freed= dead= skip_prot='
    这样不同数值的同结构消息会被归为同一 key。
    """
    import re
    # 提取所有 field=value 中的 field= 部分
    fields = re.findall(r'[a-z_]+=', message)
    if fields:
        return " ".join(fields)
    # 无结构化字段 → 用前 40 字符
    return message[:40]


def _printk_ratelimit(subsystem: str, message: str) -> bool:
    """
    iter538: 判断是否应该抑制此条日志。
    返回 True = 抑制（不写入），False = 允许写入。

    抑制条件：同一 (subsystem, msg_key) 在 ratelimit_interval_s 内已写入过。
    """
    import time
    try:
        from config import get as _cfg
        interval = _cfg("dmesg.ratelimit_interval_s")
    except Exception:
        interval = 30  # 默认 30 秒内同 key 去重

    if interval <= 0:
        return False  # 禁用去重

    key = (subsystem, _ratelimit_key(message))
    now = time.time()

    if key in _ratelimit_cache:
        entry = _ratelimit_cache[key]
        elapsed = now - entry["ts"]
        if elapsed < interval:
            entry["count"] += 1
            return True  # 抑制
        # 窗口过期 — 重置
        entry["ts"] = now
        entry["count"] = 0
        return False

    # 新 key — 记录并允许
    if len(_ratelimit_cache) >= _RATELIMIT_CACHE_MAX:
        # LRU evict: 删除最旧的 entry
        oldest_key = min(_ratelimit_cache, key=lambda k: _ratelimit_cache[k]["ts"])
        del _ratelimit_cache[oldest_key]
    _ratelimit_cache[key] = {"ts": now, "count": 0}
    return False


def dmesg_log(conn, level: str, subsystem: str,
              message: str, session_id: str = "", project: str = "",
              extra: dict = None) -> None:
    """
    迭代29：写入一条 dmesg 日志。
    OS 类比：printk(KERN_ERR "subsystem: message") — 内核子系统通过 printk
    向环形缓冲区写入带级别和子系统标签的结构化日志。

    iter538: printk_ratelimit 去重 — 同一子系统的重复结构消息在短时间窗口内被抑制，
    防止 ring buffer 被重复 no-op 状态消息填满（实测 kfree_rcu 48%、page_idle 5% 浪费）。

    参数：
      level — ERR/WARN/INFO/DEBUG（对应 KERN_ERR/KERN_WARNING/KERN_INFO/KERN_DEBUG）
      subsystem — 来源子系统（retriever/extractor/writer/loader/router/eviction）
      message — 日志内容（简洁，<200字）
      extra — 可选附加数据（JSON 序列化）

    环形缓冲区机制：
      写入后检查总条目数，超过 dmesg.ring_buffer_size 时删除最旧条目。
      OS 类比：__log_buf 固定大小，满时覆盖最旧记录。
    """
    # iter538: printk_ratelimit — ERR/WARN 永不抑制，INFO/DEBUG 可被去重
    if level in (DMESG_INFO, DMESG_DEBUG):
        if _printk_ratelimit(subsystem, message):
            return  # 抑制：不写入 ring buffer

    now_iso = datetime.now(timezone.utc).isoformat()
    extra_json = json.dumps(extra, ensure_ascii=False) if extra else None

    conn.execute(
        """INSERT INTO dmesg (timestamp, level, subsystem, message, session_id, project, extra)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now_iso, level, subsystem, message[:500], session_id or "", project or "", extra_json),
    )

    # 环形缓冲区裁剪：保留最新 N 条
    try:
        from config import get as _cfg
        max_size = _cfg("dmesg.ring_buffer_size")
    except Exception:
        max_size = 500

    count = conn.execute("SELECT COUNT(*) FROM dmesg").fetchone()[0]
    if count > max_size:
        overflow = count - max_size
        conn.execute(
            "DELETE FROM dmesg WHERE id IN (SELECT id FROM dmesg ORDER BY id ASC LIMIT ?)",
            (overflow,),
        )


def dmesg_read(conn, level: str = None,
               subsystem: str = None, limit: int = 50,
               project: str = None) -> list:
    """
    迭代29：读取 dmesg 日志。
    OS 类比：dmesg | grep -i "error" — 按级别/子系统过滤内核日志。

    返回 dict 列表，按时间倒序（最新在前）。
    level 过滤：指定级别 = 该级别及更严重的级别（ERR 只返回 ERR，INFO 返回 ERR+WARN+INFO）。
    """
    sql = "SELECT id, timestamp, level, subsystem, message, session_id, project, extra FROM dmesg WHERE 1=1"
    params = []

    if level and level in _LEVEL_ORDER:
        threshold = _LEVEL_ORDER[level]
        allowed = [k for k, v in _LEVEL_ORDER.items() if v <= threshold]
        placeholders = ",".join("?" * len(allowed))
        sql += f" AND level IN ({placeholders})"
        params.extend(allowed)

    if subsystem:
        sql += " AND subsystem = ?"
        params.append(subsystem)

    if project:
        sql += " AND project = ?"
        params.append(project)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    result = []
    for rid, ts, lvl, sub, msg, sid, proj, ext in rows:
        entry = {
            "id": rid, "timestamp": ts, "level": lvl, "subsystem": sub,
            "message": msg, "session_id": sid, "project": proj,
        }
        if ext:
            try:
                entry["extra"] = json.loads(ext)
            except Exception:
                entry["extra"] = ext
        result.append(entry)
    return result


def dmesg_clear(conn) -> int:
    """
    清空 dmesg 缓冲区。
    OS 类比：dmesg -c（读取并清空内核日志缓冲区）。
    返回清除的条目数。
    """
    count = conn.execute("SELECT COUNT(*) FROM dmesg").fetchone()[0]
    conn.execute("DELETE FROM dmesg")
    return count


# ── 迭代359/Task11：memory_profile() — Per-Project Memory Profiler ──────────
# OS 类比：/proc/[pid]/smaps — per-VMA 精细内存映射统计
#   smaps 是 /proc/[pid]/maps 的增强版，给出每个 VMA 的 RSS/PSS/Private/Shared 细分。
#   memory_profile(project) 等价于对单个 project（进程）的 smaps 深度分析：
#     chunk 分布 ≈ RSS（实际占用）
#     pin_rate ≈ Locked（mlock'd 页比例）
#     swap_ratio ≈ SwapPss（已 swap out 比例）
#     ksm_boost ≈ KSMPages（被 KSM 合并/提升的页数）
#     dedup_rate ≈ KSM dedup savings（注入去重节省率）

def memory_profile(conn=None, project: str = None) -> dict:
    """
    迭代359/Task11：Per-project memory profiler。
    OS 类比：/proc/[pid]/smaps — 进程级精细内存分析。

    参数：
      conn — SQLite 连接（None 时自动打开）
      project — 目标项目（None 时返回全局汇总）

    返回 dict，包含：
      summary — 快照摘要（total/active/pinned/swapped/zero_access）
      pin_analysis — pin 类型分布（hard/soft/unpinned）
      swap_analysis — swap 统计（total_swapped/swap_ratio）
      ksm_analysis — KSM/知识提升统计（high_retrievability/ksm_candidates）
      access_distribution — access_count 分布（buckets：0/1-5/6-20/21+）
      importance_distribution — importance 分布
      session_dedup — 注入去重效率估算
      type_breakdown — 各 chunk_type 的细粒度分析
      recommendations — 基于指标的优化建议列表
    """
    own_conn = conn is None
    if own_conn:
        if not STORE_DB.exists():
            return {"error": "store.db not found"}
        conn = open_db()
        ensure_schema(conn)

    try:
        where = "WHERE project=?" if project else ""
        params = (project,) if project else ()
        where_and = ("AND project=?" if project else "")

        # ── summary ──
        total = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where}", params
        ).fetchone()[0]

        stale_7d = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where} "
            f"{'AND' if project else 'WHERE'} "
            f"datetime(last_accessed) < datetime('now', '-7 days')",
            params,
        ).fetchone()[0]

        zero_access = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where} "
            f"{'AND' if project else 'WHERE'} "
            f"COALESCE(access_count, 0) = 0",
            params,
        ).fetchone()[0]

        # ── pin analysis ──
        pin_counts = {"hard": 0, "soft": 0}
        try:
            pin_sql = (
                "SELECT pin_type, COUNT(*) FROM chunk_pins WHERE project=? GROUP BY pin_type"
                if project else
                "SELECT pin_type, COUNT(*) FROM chunk_pins GROUP BY pin_type"
            )
            pin_params = (project,) if project else ()
            for ptype, cnt in conn.execute(pin_sql, pin_params).fetchall():
                pin_counts[ptype] = cnt
        except Exception:
            pass
        total_pinned = pin_counts["hard"] + pin_counts["soft"]
        pin_rate = round(total_pinned / total * 100, 1) if total > 0 else 0.0

        # ── swap analysis ──
        swap_total = 0
        try:
            swap_sql = (
                "SELECT COUNT(*) FROM swap_chunks WHERE project=?"
                if project else
                "SELECT COUNT(*) FROM swap_chunks"
            )
            swap_total = conn.execute(swap_sql, params).fetchone()[0]
        except Exception:
            pass
        swap_ratio = round(swap_total / max(1, total + swap_total) * 100, 1)

        # ── KSM / retrievability analysis ──
        high_ret = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where} "
            f"{'AND' if project else 'WHERE'} "
            f"COALESCE(retrievability, 0.3) >= 0.7",
            params,
        ).fetchone()[0]
        avg_retrievability = conn.execute(
            f"SELECT AVG(COALESCE(retrievability, 0.3)) FROM memory_chunks {where}",
            params,
        ).fetchone()[0]

        # ── access_count distribution ──
        ac_dist = {"zero": 0, "low_1_5": 0, "mid_6_20": 0, "high_21plus": 0}
        for label, lo, hi in [
            ("zero", 0, 0), ("low_1_5", 1, 5), ("mid_6_20", 6, 20), ("high_21plus", 21, 999999)
        ]:
            op_lo = "=" if lo == hi else ">="
            if lo == hi:
                cond = f"COALESCE(access_count, 0) = {lo}"
            elif hi == 999999:
                cond = f"COALESCE(access_count, 0) >= {lo}"
            else:
                cond = f"COALESCE(access_count, 0) BETWEEN {lo} AND {hi}"
            cnt = conn.execute(
                f"SELECT COUNT(*) FROM memory_chunks {where} "
                f"{'AND' if project else 'WHERE'} {cond}",
                params,
            ).fetchone()[0]
            ac_dist[label] = cnt

        # ── importance distribution ──
        imp_dist = {"low_0_0.3": 0, "mid_0.3_0.6": 0, "high_0.6_0.8": 0, "critical_0.8plus": 0}
        for label, lo, hi in [
            ("low_0_0.3", 0.0, 0.3), ("mid_0.3_0.6", 0.3, 0.6),
            ("high_0.6_0.8", 0.6, 0.8), ("critical_0.8plus", 0.8, 1.1)
        ]:
            cnt = conn.execute(
                f"SELECT COUNT(*) FROM memory_chunks {where} "
                f"{'AND' if project else 'WHERE'} "
                f"COALESCE(importance, 0.5) >= {lo} AND COALESCE(importance, 0.5) < {hi}",
                params,
            ).fetchone()[0]
            imp_dist[label] = cnt

        # ── type breakdown ──
        type_rows = conn.execute(
            f"SELECT chunk_type, COUNT(*), AVG(importance), AVG(COALESCE(access_count,0)) "
            f"FROM memory_chunks {where} GROUP BY chunk_type ORDER BY COUNT(*) DESC",
            params,
        ).fetchall()
        type_breakdown = {}
        for ctype, cnt, avg_imp, avg_acc in type_rows:
            type_breakdown[ctype] = {
                "count": cnt,
                "avg_importance": round(avg_imp or 0, 3),
                "avg_access_count": round(avg_acc or 0, 1),
                "pct": round(cnt / total * 100, 1) if total > 0 else 0.0,
            }

        # ── session dedup estimation ──
        # 高 access_count（>= threshold × 2）的 chunk 是潜在重复注入目标
        dedup_threshold = 2
        try:
            from config import get as _cfg
            dedup_threshold = _cfg("retriever.session_dedup_threshold")
        except Exception:
            pass
        dedup_candidates = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where} "
            f"{'AND' if project else 'WHERE'} "
            f"COALESCE(access_count, 0) >= {dedup_threshold * 3}",
            params,
        ).fetchone()[0]
        # 估算 tokens saved：每个候选 chunk ~10 tokens/call
        estimated_tokens_saved_per_call = dedup_candidates * 10

        # ── recommendations ──
        recommendations = []
        if zero_access / max(1, total) > 0.3:
            recommendations.append(
                f"⚠️ {zero_access}/{total} chunks ({round(zero_access/total*100)}%) 零访问 — "
                "考虑降低 kswapd.stale_days 或 evict_lowest_retention"
            )
        if pin_rate > 20.0:
            recommendations.append(
                f"⚠️ pin 率 {pin_rate}% 偏高 — 检查是否过度 pin，考虑 unpin 低价值 chunks"
            )
        if swap_ratio > 30.0:
            recommendations.append(
                f"⚠️ swap 比 {swap_ratio}% 偏高 — 考虑增加 extractor.chunk_quota 或清理 swap"
            )
        if dedup_candidates > 3:
            recommendations.append(
                f"💡 {dedup_candidates} 个高频 chunk 可被注入去重，预计节省 "
                f"~{estimated_tokens_saved_per_call} tokens/call"
            )
        if high_ret / max(1, total) < 0.1:
            recommendations.append(
                "💡 high-retrievability chunk 占比 < 10% — KSM/close_session 提升较少，"
                "考虑手动运行 bulk_ksm_scan()"
            )
        if not recommendations:
            recommendations.append("✅ 内存健康，无明显优化建议")

        return {
            "project": project or "*all*",
            "summary": {
                "total": total,
                "active_7d": total - stale_7d,
                "stale_7d": stale_7d,
                "zero_access": zero_access,
                "pinned": total_pinned,
                "swapped": swap_total,
                "pin_rate_pct": pin_rate,
                "swap_ratio_pct": swap_ratio,
            },
            "pin_analysis": {
                "hard": pin_counts["hard"],
                "soft": pin_counts["soft"],
                "total_pinned": total_pinned,
                "unpinned": total - total_pinned,
                "pin_rate_pct": pin_rate,
            },
            "swap_analysis": {
                "total_swapped": swap_total,
                "swap_ratio_pct": swap_ratio,
                "active_in_memory": total,
            },
            "ksm_analysis": {
                "high_retrievability": high_ret,
                "avg_retrievability": round(avg_retrievability or 0.3, 3),
                "ksm_boost_pct": round(high_ret / max(1, total) * 100, 1),
            },
            "access_distribution": ac_dist,
            "importance_distribution": imp_dist,
            "session_dedup": {
                "dedup_threshold": dedup_threshold,
                "dedup_candidates": dedup_candidates,
                "estimated_tokens_saved_per_call": estimated_tokens_saved_per_call,
            },
            "type_breakdown": type_breakdown,
            "recommendations": recommendations,
        }
    finally:
        if own_conn:
            conn.close()


# ── Task12：Chunk Lifecycle FSM ────────────────────────────────────────────
# OS 类比：Linux Page State Machine (mm/page_alloc.c, mm/vmscan.c)
#   物理页在分配/使用/回收过程中穿越多个状态：
#   PageActive → PageLRU(inactive) → PageSwapCache → PageFree
#
# chunk 等价状态机：
#   ACTIVE  (热数据，≤7天有访问)
#   ↓ [7天无访问 → mark_cold()]
#   COLD    (温数据，7-30天无访问)
#   ↓ [30天无访问 OR DAMON DEAD → mark_dead()]
#   DEAD    (冷数据，可 swap_out 或 evict)
#   ↓ [swap_out]           ↓ [evict/gc]
#   SWAP                   GHOST
#   ↑ [swap_in]
#   COLD/ACTIVE（根据 importance 决定）
#
# 状态转换：
#   ACTIVE → COLD        : mark_cold(conn, project, stale_days=7)
#   COLD   → DEAD        : mark_dead(conn, project, dead_days=30)
#   DEAD   → GHOST       : mark_ghost(conn, ids)  [evict 前]
#   any    → ACTIVE      : mark_active(conn, ids)  [update_accessed]
#   *      → SWAP        : 由 swap_out() 处理（state='SWAP'）
#   SWAP   → COLD        : 由 swap_in()  处理（state='COLD'）

# 有效状态集合
CHUNK_STATES = frozenset(["ACTIVE", "COLD", "DEAD", "SWAP", "GHOST"])


def mark_active(conn, chunk_ids: list) -> int:
    """
    Task12：ACTIVE 转换 — 任意状态 → ACTIVE（update_accessed 触发）。
    OS 类比：mark_page_accessed() — 设置 PageActive/PageReferenced。
    返回更新的 chunk 数。
    """
    if not chunk_ids:
        return 0
    ph = ",".join("?" * len(chunk_ids))
    result = conn.execute(
        f"UPDATE memory_chunks SET chunk_state='ACTIVE' WHERE id IN ({ph}) AND chunk_state != 'SWAP'",
        chunk_ids,
    )
    return result.rowcount


def mark_cold(conn, project: str = None, stale_days: int = 7) -> int:
    """
    Task12：COLD 转换 — ACTIVE → COLD（7天无访问）。
    OS 类比：shrink_active_list() → inactive list（PG_lru inactive）。
    iter1634: ac>=3 保护 — 经用户多次验证的知识不因 suppress 导致的 last_accessed 过期而降级。
    返回转换的 chunk 数。
    """
    where_clause = "chunk_state='ACTIVE' AND access_count < 3"
    params = []
    if project:
        where_clause += " AND project=?"
        params.append(project)
    where_clause += f" AND datetime(last_accessed) < datetime('now', '-{stale_days} days')"
    conn.execute("UPDATE memory_chunks SET chunk_state='COLD' WHERE " + where_clause, params)
    return conn.execute(
        "SELECT changes()"
    ).fetchone()[0]


def mark_dead(conn, project: str = None, dead_days: int = 30) -> int:
    """
    Task12：DEAD 转换 — COLD → DEAD（30天无访问 或 importance<0.3 的 COLD chunk）。
    OS 类比：DAMON DEAD region detection — 长期无访问的内存区域标记为可回收。
    返回转换的 chunk 数。
    """
    where_clause = "chunk_state='COLD'"
    params = []
    if project:
        where_clause += " AND project=?"
        params.append(project)
    where_clause += f" AND datetime(last_accessed) < datetime('now', '-{dead_days} days')"
    conn.execute(
        "UPDATE memory_chunks SET chunk_state='DEAD' WHERE " + where_clause,
        params,
    )
    return conn.execute("SELECT changes()").fetchone()[0]


def mark_ghost(conn, chunk_ids: list) -> int:
    """
    Task12：GHOST 转换 — DEAD → GHOST（evict 前短暂标记）。
    OS 类比：ghost entry in inactive list — 保留 PFN 但清除内容，供下次加速 swap-in。
    返回转换的 chunk 数。
    """
    if not chunk_ids:
        return 0
    ph = ",".join("?" * len(chunk_ids))
    conn.execute(
        f"UPDATE memory_chunks SET chunk_state='GHOST' WHERE id IN ({ph})",
        chunk_ids,
    )
    return conn.execute("SELECT changes()").fetchone()[0]


def fsm_transition(conn, project: str = None,
                   cold_days: int = 7, dead_days: int = 30) -> dict:
    """
    Task12：批量执行 FSM 状态转换（ACTIVE→COLD→DEAD）。
    OS 类比：Linux kswapd + DAMON 协同驱动页面老化：
      kswapd 周期性将 inactive list 页面 swap out；
      DAMON 识别长期无访问区域标记为 DEAD。
    返回 {cold: n, dead: n} 转换统计。
    """
    # Step 1: ACTIVE → COLD（cold_days 天无访问）
    # iter1634: ac>=3 保护 — 与 mark_cold 对齐
    where_cold = "chunk_state='ACTIVE' AND access_count < 3"
    params_cold = []
    if project:
        where_cold += " AND project=?"
        params_cold.append(project)
    where_cold += f" AND datetime(last_accessed) < datetime('now', '-{cold_days} days')"
    conn.execute(
        "UPDATE memory_chunks SET chunk_state='COLD' WHERE " + where_cold, params_cold
    )
    cold_count = conn.execute("SELECT changes()").fetchone()[0]

    # Step 2: COLD → DEAD（dead_days 天无访问）
    where_dead = "chunk_state='COLD'"
    params_dead = []
    if project:
        where_dead += " AND project=?"
        params_dead.append(project)
    where_dead += f" AND datetime(last_accessed) < datetime('now', '-{dead_days} days')"
    conn.execute(
        "UPDATE memory_chunks SET chunk_state='DEAD' WHERE " + where_dead, params_dead
    )
    dead_count = conn.execute("SELECT changes()").fetchone()[0]

    return {"cold": cold_count, "dead": dead_count, "project": project or "*all*"}


def get_state_distribution(conn, project: str = None) -> dict:
    """
    Task12：查询 chunk_state 分布统计。
    OS 类比：/proc/meminfo MemActive/MemInactive/MemSwapCached
    """
    where = "WHERE project=?" if project else ""
    params = (project,) if project else ()
    rows = conn.execute(
        f"SELECT COALESCE(chunk_state, 'ACTIVE'), COUNT(*) FROM memory_chunks {where} "
        f"GROUP BY chunk_state",
        params,
    ).fetchall()
    dist = {"ACTIVE": 0, "COLD": 0, "DEAD": 0, "SWAP": 0, "GHOST": 0}
    for state, cnt in rows:
        dist[state] = cnt
    dist["total"] = sum(dist.values())
    return dist


# ── Task13：Optimistic Locking — Compare-And-Swap ──────────────────────────
# OS 类比：Linux seqlock + atomic_cmpxchg (arch/x86/include/asm/atomic.h)
#   读路径：read_seqbegin() → 记录 seq_begin
#   写路径：cmpxchg(ptr, old_val, new_val) → 仅当 *ptr == old_val 时写入
#   冲突时：返回实际值（caller 决定重试还是放弃）
#
# memory-os 多 agent 场景：
#   Agent A 和 B 同时读到 chunk.row_version=5，都准备更新。
#   Agent A 先写成功 → row_version=6。
#   Agent B 写时发现版本已变 (expected=5 but actual=6) → 返回失败。
#   Agent B 可选择重新读取后重试（optimistic retry）。

def cas_update(conn, chunk_id: str, expected_version: int,
               updates: dict) -> dict:
    """
    Task13：Compare-And-Swap 更新。
    OS 类比：atomic_cmpxchg — 仅当 row_version == expected_version 时执行更新。

    参数：
      conn — SQLite 连接
      chunk_id — 目标 chunk ID
      expected_version — 调用者上次读取时的 row_version
      updates — 要更新的字段 dict（不含 id/row_version，会自动递增）

    返回 dict：
      {"ok": True, "new_version": n}     — 写入成功
      {"ok": False, "actual_version": n, "reason": "version_conflict"} — 版本冲突
      {"ok": False, "reason": "not_found"} — chunk 不存在
    """
    if not updates:
        return {"ok": False, "reason": "empty_updates"}

    # 先读当前版本（SELECT FOR UPDATE 语义，SQLite 用事务保证）
    row = conn.execute(
        "SELECT row_version FROM memory_chunks WHERE id=?", (chunk_id,)
    ).fetchone()
    if row is None:
        return {"ok": False, "reason": "not_found"}

    actual_version = row[0] or 1
    if actual_version != expected_version:
        return {"ok": False, "actual_version": actual_version, "reason": "version_conflict"}

    # 构建 UPDATE 语句
    allowed_keys = {
        "summary", "content", "importance", "chunk_type", "tags",
        "retrievability", "confidence_score", "verification_status",
        "last_accessed", "updated_at", "raw_snippet", "chunk_state",
        "oom_adj", "info_class", "stability", "encoding_context",
    }
    safe_updates = {k: v for k, v in updates.items() if k in allowed_keys}
    if not safe_updates:
        return {"ok": False, "reason": "no_safe_fields"}

    set_parts = [f"{k}=?" for k in safe_updates]
    set_parts.append("row_version=row_version+1")
    set_parts.append("updated_at=datetime('now')")
    sql = f"UPDATE memory_chunks SET {', '.join(set_parts)} WHERE id=? AND row_version=?"
    values = list(safe_updates.values()) + [chunk_id, expected_version]

    conn.execute(sql, values)
    changed = conn.execute("SELECT changes()").fetchone()[0]
    if changed == 0:
        # 另一个 agent 在我们读取和写入之间抢先写入了
        actual = conn.execute(
            "SELECT row_version FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        actual_version = actual[0] if actual else None
        return {"ok": False, "actual_version": actual_version, "reason": "version_conflict"}

    new_version = conn.execute(
        "SELECT row_version FROM memory_chunks WHERE id=?", (chunk_id,)
    ).fetchone()[0]
    return {"ok": True, "new_version": new_version}


def get_chunk_version(conn, chunk_id: str) -> int | None:
    """
    Task13：获取 chunk 当前 row_version。
    用于 optimistic locking 的读阶段：先获取版本，再做 cas_update。
    返回版本号，不存在则返回 None。
    """
    row = conn.execute(
        "SELECT COALESCE(row_version, 1) FROM memory_chunks WHERE id=?", (chunk_id,)
    ).fetchone()
    return row[0] if row else None


def broadcast_invalidate(conn, chunk_ids: list, agent_id: str = "") -> int:
    """
    Task13：广播失效通知 — 向所有共享 chunk 的 agent 发送 IPC 消息。
    OS 类比：cache coherency protocol broadcast invalidate (MESI protocol)
      修改方发出 Invalidate 消息，所有持有该缓存行的 CPU 将状态标记为 Invalid。
    通过 ipc_msgq 表广播，目标 agent='*'（全局广播）。
    返回广播的消息数。
    """
    if not chunk_ids:
        return 0
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    count = 0
    try:
        for cid in chunk_ids:
            conn.execute(
                """INSERT INTO ipc_msgq
                   (source_agent, target_agent, msg_type, payload, created_at, ttl_seconds)
                   VALUES (?, '*', 'INVALIDATE', ?, ?, 60)""",
                (agent_id or "system", json.dumps({"chunk_id": cid}), now),
            )
            count += 1
    except Exception:
        pass
    return count
