"""
store_mm.py — Memory Management Subsystems

内存管理子系统集合：kswapd/PSI/DAMON/MGLRU/OOM/cgroup/balloon/compact/
madvise/readahead/AIMD/autotune/governor。

所有函数依赖 store_core 提供的基础 CRUD、FTS5、日志和 swap 功能。
"""
import json
import os
import re
import sqlite3
import time as _time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from store_core import (
    open_db, ensure_schema, MEMORY_OS_DIR, STORE_DB,
    get_project_chunk_count, evict_lowest_retention,
    dmesg_log, DMESG_INFO, DMESG_WARN, DMESG_DEBUG, DMESG_ERR,
    swap_out, delete_chunks, bump_chunk_version,
    insert_chunk, already_exists, merge_similar, find_similar,
    OOM_ADJ_MIN, OOM_ADJ_PROTECTED, OOM_ADJ_DEFAULT, OOM_ADJ_PREFER, OOM_ADJ_MAX,
    _ensure_checkpoint_schema,
)


# ── kswapd — Background Watermark Reclaim（迭代30）────────────────

def kswapd_scan(conn: sqlite3.Connection, project: str,
                incoming_count: int = 1) -> dict:
    """
    迭代30：kswapd — 后台水位线预淘汰。
    OS 类比：Linux kswapd (1994) 内核线程

    Linux 内存管理三级水位线：
      pages_high — kswapd 休眠（空闲页面充足）
      pages_low  — kswapd 唤醒（开始后台回收）
      pages_min  — direct reclaim（同步阻塞回收）

    本函数在写入前调用（相当于 __alloc_pages_slowpath 中的 kswapd 唤醒检查）：
      1. 计算当前水位 = (current_count + incoming_count) / quota
      2. watermark < pages_low_pct → ZONE_OK（无需淘汰）
      3. pages_low_pct <= watermark < pages_min_pct → ZONE_LOW（预淘汰至 pages_high）
      4. watermark >= pages_min_pct → ZONE_MIN（同步硬淘汰，等价于现有 OOM handler）
      5. 额外扫描 stale chunk（> stale_days 未访问）并一并淘汰

    参数：
      conn — 数据库连接（复用调用方连接，Per-Request Connection Scope）
      project — 项目 ID
      incoming_count — 即将写入的 chunk 数量

    返回 dict：
      zone — "OK" / "LOW" / "MIN"
      evicted_ids — 被淘汰的 chunk ID 列表
      evicted_count — 淘汰数量
      current_count — 当前 chunk 数
      quota — 配额上限
      watermark_pct — 当前水位百分比
      stale_evicted — stale chunk 淘汰数量
    """
    try:
        from config import get as _cfg
    except Exception:
        # fallback：无 config 时不做 kswapd
        return {"zone": "OK", "evicted_ids": [], "evicted_count": 0,
                "current_count": 0, "quota": 200, "watermark_pct": 0,
                "stale_evicted": 0, "compaction_freed": 0}

    # 迭代46：Memory Balloon — 动态配额替代固定配额
    # OS 类比：VM 分配内存前先查询 balloon 驱动获取当前可用额度
    balloon = balloon_quota(conn, project)
    quota = balloon["quota"]

    pages_low_pct = _cfg("kswapd.pages_low_pct")
    pages_high_pct = _cfg("kswapd.pages_high_pct")
    pages_min_pct = _cfg("kswapd.pages_min_pct")
    stale_days = _cfg("kswapd.stale_days")
    batch_size = _cfg("kswapd.batch_size")

    # 迭代121：修复 kswapd watermark 计算错误 — 使用 per-project count 配合 per-project balloon quota
    # 根因：旧修复（使用全局 count 防止孤儿 project 水位为 0）与 balloon 引入后冲突：
    #   balloon 给低活跃 project 分配小配额（如 58），但全局 count=74 → watermark=127% → ZONE_MIN
    #   每次 extractor 运行都触发强制淘汰，实际上内存充裕（global project quota=500 余量巨大）
    # 修复：balloon 已通过 min_quota=30 保底，孤儿 project 不再是问题；恢复 per-project count
    # 等价 OS fix：per-cgroup 内存统计（memory.current）只统计本 cgroup 的页面，
    #   不应拿全局 MemTotal 和本 cgroup memory.high 比较
    current_count = get_project_chunk_count(conn, project)
    projected = current_count + incoming_count
    watermark_pct = (projected / quota * 100) if quota > 0 else 100

    all_evicted_ids = []

    # ── Phase 0: Memory Compaction（迭代31 — 碎片整理优先于淘汰）──
    # OS 类比：kcompactd 在 kswapd 之前尝试整理碎片，可能无需淘汰就释放空间
    compaction_freed = 0
    if watermark_pct >= pages_low_pct:
        try:
            compact_result = compact_zone(conn, project)
            compaction_freed = compact_result.get("chunks_freed", 0)
            if compaction_freed > 0:
                # 重新计算水位（compaction 后可能已安全）
                current_count = get_project_chunk_count(conn, project)
                projected = current_count + incoming_count
                watermark_pct = (projected / quota * 100) if quota > 0 else 100
        except Exception:
            pass  # compaction 失败不影响主流程

    # ── Phase 0.5: Pin Decay + Cap（迭代356）──
    # OS 类比：memcg 的 RLIMIT_MEMLOCK enforcement — 在 kswapd 扫描前先释放
    # 过期的 mlock 区域，让 LRU 有更多可驱逐目标。
    # 这里：soft pin 超期自动解除 → 参与正常 LRU eviction；
    #       pin count > cap → 驱逐最旧 soft pin。
    try:
        from store_vfs import pin_decay as _pin_decay, enforce_pin_cap as _enforce_pin_cap
        _pin_decay(conn, project)
        _enforce_pin_cap(conn, project)
    except Exception:
        pass  # pin decay 失败不阻塞 kswapd

    # ── Phase 0.6: FTS5 Auto-Optimize（迭代360）──
    # OS 类比：kswapd 附带触发 ext4 online defrag — 后台维护 FTS5 索引健康度，
    #   合并碎片化 segment，使 FTS5 查询从 O(S×logN) 降回 O(logN)。
    # 有冷却保护（默认 1h），不频繁触发；kswapd 是低频后台路径，适合承载此任务。
    try:
        from store_vfs import fts_optimize as _fts_optimize
        _fts_optimize(conn)
    except Exception:
        pass  # FTS5 optimize 失败不阻塞 kswapd

    # ── Phase 1: Stale page reclaim（过期 chunk 回收）──
    # OS 类比：kswapd 优先回收 inactive_list 尾部（长时间未访问的页面）
    stale_evicted = _reclaim_stale_chunks(conn, project, stale_days, batch_size)
    all_evicted_ids.extend(stale_evicted)

    # 重新计算水位（stale 回收后可能已安全）
    if stale_evicted:
        current_count = get_project_chunk_count(conn, project)
        projected = current_count + incoming_count
        watermark_pct = (projected / quota * 100) if quota > 0 else 100

    # ── Phase 2: Watermark-based reclaim ──
    if watermark_pct < pages_low_pct:
        # ZONE_OK：pages_high 以下，无需淘汰
        return {"zone": "OK", "evicted_ids": all_evicted_ids,
                "evicted_count": len(all_evicted_ids),
                "current_count": current_count, "quota": quota,
                "watermark_pct": round(watermark_pct, 1),
                "stale_evicted": len(stale_evicted),
                "compaction_freed": compaction_freed}

    if watermark_pct >= pages_min_pct:
        # ZONE_MIN：direct reclaim — 同步硬淘汰至 pages_high
        target_count = int(quota * pages_high_pct / 100)
        evict_count = max(0, current_count + incoming_count - target_count)
        if evict_count > 0:
            evicted = evict_lowest_retention(conn, project, evict_count)
            all_evicted_ids.extend(evicted)
        return {"zone": "MIN", "evicted_ids": all_evicted_ids,
                "evicted_count": len(all_evicted_ids),
                "current_count": get_project_chunk_count(conn, project),
                "quota": quota,
                "watermark_pct": round(watermark_pct, 1),
                "stale_evicted": len(stale_evicted),
                "compaction_freed": compaction_freed}

    # ZONE_LOW：kswapd 预淘汰（pages_low ~ pages_min 之间）
    # 目标：淘汰至 pages_high 以下
    target_count = int(quota * pages_high_pct / 100)
    evict_count = max(0, projected - target_count)
    evict_count = min(evict_count, batch_size)  # 每次最多 batch_size
    if evict_count > 0:
        evicted = evict_lowest_retention(conn, project, evict_count)
        all_evicted_ids.extend(evicted)

    return {"zone": "LOW", "evicted_ids": all_evicted_ids,
            "evicted_count": len(all_evicted_ids),
            "current_count": get_project_chunk_count(conn, project),
            "quota": quota,
            "watermark_pct": round(watermark_pct, 1),
            "stale_evicted": len(stale_evicted),
            "compaction_freed": compaction_freed}

def _reclaim_stale_chunks(conn: sqlite3.Connection, project: str,
                          stale_days: int, max_reclaim: int) -> list:
    """
    迭代30：回收 stale chunk（长时间未访问的页面）。
    OS 类比：kswapd 扫描 inactive_list，将 Referenced bit 未置位的页面回收。

    条件：
      - last_accessed 超过 stale_days 天
      - 不回收 task_state 类型（当前会话状态，受保护）
      - 不回收 importance >= 0.9（核心决策，受保护，等价于 mlock）
      - 按 retention_score 升序淘汰（最低分先回收）
    迭代104：排除 chunk_pins 中 project 对应的 pinned chunk（项目级 mlock）
    """
    from scorer import retention_score as _retention_score
    from store_vfs import get_pinned_ids

    stale_threshold = f"-{stale_days} days"
    # 迭代38：排除 oom_adj <= -1000 的 chunk（绝对保护，即使 stale 也不回收）
    # 迭代147：datetime(last_accessed) 修复 ISO8601+timezone 字符串与 SQLite datetime() 比较 bug。
    # 根因：Python 写入的 last_accessed 格式为 'YYYY-MM-DDTHH:MM:SS.xxxxxx+00:00'（含 'T' 和时区），
    #   SQLite datetime('now', ?) 返回 'YYYY-MM-DD HH:MM:SS'（无时区，空格分隔）。
    #   字符串直接比较时，'T'(84) > ' '(32) → 所有带时区的时间戳都被判为"比 cutoff 更新"，
    #   导致 stale chunk 回收完全失效（所有 chunk 永远不被视为 stale）。
    # 修复：datetime(last_accessed) 让 SQLite 解析 ISO8601 格式后再比较。
    rows = conn.execute(
        """SELECT id, importance, last_accessed, COALESCE(access_count, 0),
                  COALESCE(oom_adj, 0)
           FROM memory_chunks
           WHERE project = ?
             AND chunk_type != 'task_state'
             AND importance < 0.9
             AND COALESCE(oom_adj, 0) > -1000
             AND datetime(last_accessed) < datetime('now', ?)
           ORDER BY importance ASC, last_accessed ASC
           LIMIT ?""",
        (project, stale_threshold, max_reclaim * 3),
    ).fetchall()

    if not rows:
        return []

    # 迭代104：排除当前 project 的 pinned chunks（soft pin + hard pin 均保护）
    pinned = get_pinned_ids(conn, project)

    # 用 Unified Scorer 精确排序（迭代38：含 oom_adj 修正）
    scored = []
    for rid, importance, last_accessed, access_count, oom_adj in rows:
        if rid in pinned:
            continue  # 项目级 pin 保护，跳过
        score = _retention_score(
            importance=importance if importance is not None else 0.5,
            last_accessed=last_accessed or "",
            uniqueness=0.5,
            access_count=access_count or 0,
        )
        oom_modifier = oom_adj / 2000.0
        score = max(0.0, score - oom_modifier)
        scored.append((score, rid))

    scored.sort(key=lambda x: x[0])
    evict_ids = [rid for _, rid in scored[:max_reclaim]]
    if evict_ids:
        # 迭代33：swap out 替代直接删除
        swap_out(conn, evict_ids)
    return evict_ids

def set_oom_adj(conn: sqlite3.Connection, chunk_id: str, oom_adj: int) -> bool:
    """
    迭代38：设置 chunk 的 oom_score_adj。
    OS 类比：echo -1000 > /proc/[pid]/oom_score_adj
      Linux OOM Killer (2003) 在系统内存耗尽时选择杀死进程释放内存。
      每个进程有一个 oom_score（基于内存占用自动计算），
      管理员可以通过 oom_score_adj (-1000 ~ +1000) 手动调整优先级：
        -1000 → 绝对保护，OOM Killer 永远不会杀这个进程（init, sshd）
        0     → 默认（由系统自动决定）
        +1000 → 最先被杀（已知可丢弃的进程）

    memory-os 等价：
      oom_adj = -1000 → 绝对保护（不可淘汰、不可 swap out）—— mlock 语义
      oom_adj = -500  → 高保护（量化证据、核心决策，提高 retention_score）
      oom_adj = 0     → 默认（由 retention_score 自然排序）
      oom_adj = +500  → 优先淘汰（prompt_context 等临时 chunk）
      oom_adj = +1000 → 最先淘汰（明确标记为可丢弃）

    参数：
      conn — 数据库连接
      chunk_id — chunk ID
      oom_adj — -1000 ~ +1000 之间的整数

    返回 True 表示成功设置，False 表示 chunk 不存在。
    """
    oom_adj = max(-1000, min(1000, int(oom_adj)))
    rowcount = conn.execute(
        "UPDATE memory_chunks SET oom_adj = ? WHERE id = ?",
        (oom_adj, chunk_id),
    ).rowcount
    return rowcount > 0

def get_oom_adj(conn: sqlite3.Connection, chunk_id: str) -> Optional[int]:
    """
    迭代38：读取 chunk 的 oom_score_adj。
    OS 类比：cat /proc/[pid]/oom_score_adj

    返回 oom_adj 值，chunk 不存在返回 None。
    """
    row = conn.execute(
        "SELECT COALESCE(oom_adj, 0) FROM memory_chunks WHERE id = ?",
        (chunk_id,),
    ).fetchone()
    return row[0] if row else None

def batch_set_oom_adj(conn: sqlite3.Connection, chunk_ids: list,
                      oom_adj: int) -> int:
    """
    迭代38：批量设置 oom_score_adj。
    OS 类比：systemd 的 OOMPolicy=kill/continue — 批量配置服务级 OOM 策略。

    返回成功设置的 chunk 数。
    """
    if not chunk_ids:
        return 0
    oom_adj = max(-1000, min(1000, int(oom_adj)))
    placeholders = ",".join("?" * len(chunk_ids))
    return conn.execute(
        f"UPDATE memory_chunks SET oom_adj = ? WHERE id IN ({placeholders})",
        [oom_adj] + chunk_ids,
    ).rowcount

def get_protected_chunks(conn: sqlite3.Connection, project: str = None) -> list:
    """
    迭代38：列出所有受 OOM 保护的 chunk（oom_adj < 0）。
    OS 类比：查看所有 oom_score_adj < 0 的进程（受保护进程）。

    返回 dict 列表：{id, summary, chunk_type, oom_adj, importance}
    """
    sql = """SELECT id, summary, chunk_type, COALESCE(oom_adj, 0), importance
             FROM memory_chunks
             WHERE COALESCE(oom_adj, 0) < 0"""
    params = []
    if project:
        sql += " AND project = ?"
        params.append(project)
    sql += " ORDER BY oom_adj ASC"

    rows = conn.execute(sql, params).fetchall()
    return [
        {"id": r[0], "summary": r[1], "chunk_type": r[2],
         "oom_adj": r[3], "importance": r[4]}
        for r in rows
    ]

# ── cgroup v2 memory.high — Soft Quota Throttling（迭代40）──────────

def cgroup_throttle_check(conn: sqlite3.Connection, project: str,
                          incoming_count: int = 1) -> dict:
    """
    迭代40：cgroup v2 memory.high — 软配额限流检查。
    OS 类比：Linux cgroup v2 memory controller (2015, Tejun Heo)

    Linux cgroup v2 内存控制器有两级限制：
      memory.high — 软限制（超过时 throttle，减慢分配速度）
      memory.max  — 硬限制（超过时 OOM Kill）

    memory.high 的设计哲学：
      传统 cgroup v1 只有 memory.limit_in_bytes（硬限制），
      超过就 OOM Kill——没有中间状态，要么正常要么死。
      cgroup v2 引入 memory.high 作为"减速带"：
        用量 < memory.high → 正常（不限制）
        memory.high < 用量 < memory.max → throttle（减慢分配，给回收时间）
        用量 > memory.max → OOM Kill

      throttle 机制：
        超过 memory.high 的进程在每次内存分配时被强制调用
        try_charge → mem_cgroup_throttle_swaprate()，
        插入一个与超额量成比例的 sleep（最多几百 ms），
        让 kswapd 有时间在后台回收页面。
        效果：进程不会被杀死，只是变慢了——graceful degradation。

    memory-os 当前的水位线（kswapd 迭代30）：
      < pages_low(80%)  → ZONE_OK（正常写入）
      80% - 95%         → ZONE_LOW（预淘汰一批，但新写入不受影响）
      > pages_min(95%)  → ZONE_MIN（硬淘汰，direct reclaim）

    问题：ZONE_LOW 区间（80%-95%）的新写入和 ZONE_OK 一样不受任何约束。
    一次 burst 写入（如长对话产出大量 prompt_context/conversation_summary）
    可能瞬间从 85% 跳到 96%，触发 ZONE_MIN 硬淘汰——淘汰掉的可能包含
    比新写入更有价值的旧 decision。

    解决：在 ZONE_LOW 中插入 memory.high 分界线（默认 85%）：
      < pages_low(80%)    → ZONE_OK（正常写入）
      80% - memory_high   → ZONE_LOW（预淘汰，写入不受影响）
      memory_high - 95%   → ZONE_THROTTLE（新写入被 throttle：降 importance + 加 oom_adj）
      > pages_min(95%)    → ZONE_MIN（硬淘汰）

    throttle 效果：
      - 新 chunk 的 importance 乘以 throttle_factor（0.7），降低保留评分
      - 新 chunk 自动设 oom_adj = +throttle_oom_adj（300），加速被未来 kswapd 回收
      - 不阻塞写入，不淘汰已有 chunk
      - 效果等价于 cgroup v2 的 "减速而非杀死"

    参数：
      conn — 数据库连接
      project — 项目 ID
      incoming_count — 即将写入的 chunk 数

    返回 dict：
      throttled — bool，是否应 throttle 新写入
      zone — "OK" / "THROTTLE"
      importance_factor — importance 乘法因子（throttled=True 时 < 1.0）
      oom_adj_delta — 建议的 oom_adj 增量（throttled=True 时 > 0）
      watermark_pct — 当前水位百分比
      current_count — 当前 chunk 数
      quota — 配额
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"throttled": False, "zone": "OK", "importance_factor": 1.0,
                "oom_adj_delta": 0, "watermark_pct": 0, "current_count": 0, "quota": 200}

    # 迭代46：Memory Balloon — 动态配额替代固定配额
    balloon = balloon_quota(conn, project)
    quota = balloon["quota"]

    memory_high_pct = _cfg("cgroup.memory_high_pct")
    throttle_factor = _cfg("cgroup.throttle_factor")
    throttle_oom_adj = _cfg("cgroup.throttle_oom_adj")

    current_count = get_project_chunk_count(conn, project)
    projected = current_count + incoming_count
    watermark_pct = (projected / quota * 100) if quota > 0 else 100

    base = {"watermark_pct": round(watermark_pct, 1),
            "current_count": current_count, "quota": quota}

    if watermark_pct < memory_high_pct:
        # 低于软限制：正常写入
        return {**base, "throttled": False, "zone": "OK",
                "importance_factor": 1.0, "oom_adj_delta": 0}

    # 超过 memory.high：throttle 新写入
    # 超额越多，throttle 越重（线性插值到 pages_min）
    pages_min_pct = _cfg("kswapd.pages_min_pct")
    overshoot = min(1.0, (watermark_pct - memory_high_pct) / max(1, pages_min_pct - memory_high_pct))
    # importance_factor: 从 1.0 线性降至 throttle_factor
    eff_factor = 1.0 - overshoot * (1.0 - throttle_factor)
    # oom_adj_delta: 从 0 线性升至 throttle_oom_adj
    eff_oom_adj = int(overshoot * throttle_oom_adj)

    return {**base, "throttled": True, "zone": "THROTTLE",
            "importance_factor": round(eff_factor, 3),
            "oom_adj_delta": eff_oom_adj}

# ── Memory Compaction — 碎片整理（迭代31）────────────────────────

def compact_zone(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代31：Memory Compaction — 合并碎片化的相关 chunk。
    OS 类比：Linux Memory Compaction (compact_zone, Mel Gorman, 2010)

    Linux 内存碎片化问题：
      长时间运行后，物理内存虽有足够空闲页面但不连续（external fragmentation）。
      当需要分配 huge page（连续 2MB）时失败——不是内存不够，是碎片太多。
      compact_zone() 通过迁移页面将分散的空闲页归拢为连续块：
        - Scanner 从区域两端向中间扫描
        - 一端找可迁移页面，另一端找空闲位置
        - 迁移后释放出连续空闲块

    memory-os 碎片化问题：
      多次会话后，同一主题/实体积累了多个小 chunk（决策碎片）：
        - "BM25 选择 hybrid tokenize"
        - "BM25 bigram 效果优于 unigram"
        - "BM25 延迟 3ms 满足约束"
      每个 chunk 单独 importance 较低，但集体代表了一个完整的技术决策。
      碎片化导致：
        1. 配额浪费（5 个碎片 vs 1 个合并后的完整记录）
        2. 召回噪声（返回碎片而非完整知识）
        3. 低 retention_score 被 kswapd 误淘汰

    算法：
      1. 加载项目所有非 task_state chunk
      2. 从 summary 提取关键实体（复用 retriever 的实体提取逻辑）
      3. 构建倒排索引：entity → {chunk_ids}
      4. 通过共享实体发现聚类（≥ entity_overlap_min 个共享实体）
      5. 对每个大小 ≥ min_cluster_size 的聚类：
         a. 选 importance 最高的 chunk 作为 anchor
         b. 将其余 chunk 的 summary 合并到 anchor.content
         c. anchor.importance = max(all)
         d. anchor.access_count = sum(all)
         e. 删除被合并的碎片 chunk
      6. 返回统计信息

    参数：
      conn — 数据库连接
      project — 项目 ID

    返回 dict：
      clusters_found — 发现的碎片聚类数
      chunks_merged — 被合并的 chunk 数
      chunks_freed — 释放的 chunk 数（= merged - clusters，每个聚类保留1个anchor）
      anchor_ids — 合并后保留的 anchor chunk ID 列表
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"clusters_found": 0, "chunks_merged": 0, "chunks_freed": 0, "anchor_ids": []}

    min_cluster = _cfg("compaction.min_cluster_size")
    max_merge = _cfg("compaction.max_merge_per_run")
    overlap_min = _cfg("compaction.entity_overlap_min")

    # ── Step 1: 加载所有非 task_state chunk ──
    rows = conn.execute(
        """SELECT id, summary, content, importance, last_accessed,
                  chunk_type, COALESCE(access_count, 0), created_at
           FROM memory_chunks
           WHERE project = ? AND chunk_type NOT IN ('task_state', 'prompt_context')
             AND summary != ''""",
        (project,),
    ).fetchall()

    if len(rows) < min_cluster:
        return {"clusters_found": 0, "chunks_merged": 0, "chunks_freed": 0, "anchor_ids": []}

    chunks_by_id = {}
    for rid, summary, content, importance, last_accessed, chunk_type, access_count, created_at in rows:
        chunks_by_id[rid] = {
            "id": rid, "summary": summary or "", "content": content or "",
            "importance": importance if importance is not None else 0.5,
            "last_accessed": last_accessed or "",
            "chunk_type": chunk_type or "", "access_count": access_count or 0,
            "created_at": created_at or "",
        }

    # ── Step 2: 从 summary 提取实体 ──
    def _extract_entities(text):
        entities = set()
        # 反引号内容
        for m in re.finditer(r'`([^`]{2,30})`', text):
            entities.add(m.group(1).lower())
        # 文件路径
        for m in re.finditer(r'[\w./]+\.(?:py|js|ts|md|json|db|sql)\b', text):
            entities.add(m.group(0).lower())
        # 英文技术词（≥3字符，含大写/数字）
        for m in re.finditer(r'\b([a-zA-Z][a-zA-Z0-9_]{2,20})\b', text):
            word = m.group(1)
            # 排除常见虚词
            if word.lower() not in _COMPACT_STOPWORDS:
                entities.add(word.lower())
        # 中文双字词
        cn = re.sub(r'[^\u4e00-\u9fff]', '', text)
        for i in range(len(cn) - 1):
            entities.add(cn[i:i + 2])
        return entities

    chunk_entities = {}
    for cid, chunk in chunks_by_id.items():
        chunk_entities[cid] = _extract_entities(chunk["summary"])

    # ── Step 3: 倒排索引 → 聚类 ──
    # entity → set of chunk_ids
    inverted = {}
    for cid, entities in chunk_entities.items():
        for ent in entities:
            if ent not in inverted:
                inverted[ent] = set()
            inverted[ent].add(cid)

    # 计算 chunk 对之间的共享实体数
    from collections import Counter
    pair_overlap = Counter()
    for ent, cids in inverted.items():
        cid_list = list(cids)
        for i in range(len(cid_list)):
            for j in range(i + 1, len(cid_list)):
                pair = tuple(sorted([cid_list[i], cid_list[j]]))
                pair_overlap[pair] += 1

    # 构建连通分量（共享实体 ≥ overlap_min 的 chunk 归入同一聚类）
    # Union-Find
    parent = {cid: cid for cid in chunks_by_id}

    def _find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a, b):
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[ra] = rb

    for (a, b), count in pair_overlap.items():
        if count >= overlap_min:
            _union(a, b)

    # 收集聚类
    clusters = {}
    for cid in chunks_by_id:
        root = _find(cid)
        if root not in clusters:
            clusters[root] = []
        clusters[root].append(cid)

    # 过滤：只保留大小 ≥ min_cluster 的聚类
    mergeable = [cids for cids in clusters.values() if len(cids) >= min_cluster]
    # 按聚类大小降序，限制每次最多处理 max_merge 个聚类
    mergeable.sort(key=len, reverse=True)
    mergeable = mergeable[:max_merge]

    if not mergeable:
        return {"clusters_found": 0, "chunks_merged": 0, "chunks_freed": 0, "anchor_ids": []}

    # ── Step 4: 合并 ──
    total_merged = 0
    total_freed = 0
    anchor_ids = []

    now_iso = datetime.now(timezone.utc).isoformat()

    for cluster_cids in mergeable:
        cluster_chunks = [chunks_by_id[cid] for cid in cluster_cids]
        # Anchor = importance 最高的 chunk
        cluster_chunks.sort(key=lambda c: c["importance"], reverse=True)
        anchor = cluster_chunks[0]
        fragments = cluster_chunks[1:]

        if not fragments:
            continue

        # 合并 summary
        merged_summaries = [f["summary"] for f in fragments if f["summary"] != anchor["summary"]]
        # 去重
        seen = {anchor["summary"].lower().strip()}
        unique_merged = []
        for s in merged_summaries:
            key = s.lower().strip()
            if key not in seen:
                seen.add(key)
                unique_merged.append(s)

        # 更新 anchor
        new_importance = max(c["importance"] for c in cluster_chunks)
        new_access_count = sum(c["access_count"] for c in cluster_chunks)

        # 合并内容格式
        if unique_merged:
            related_text = " | ".join(unique_merged[:5])  # 最多保留5条相关摘要
            new_content = f"{anchor['content']}\n[consolidated] {related_text}"
        else:
            new_content = anchor["content"]

        # 更新 anchor chunk
        conn.execute(
            """UPDATE memory_chunks
               SET importance = ?, access_count = ?, content = ?,
                   last_accessed = ?, updated_at = ?
               WHERE id = ?""",
            (new_importance, new_access_count, new_content[:2000], now_iso, now_iso, anchor["id"]),
        )

        # 删除碎片
        fragment_ids = [f["id"] for f in fragments]
        delete_chunks(conn, fragment_ids)

        total_merged += len(cluster_chunks)
        total_freed += len(fragments)
        anchor_ids.append(anchor["id"])

    return {
        "clusters_found": len(mergeable),
        "chunks_merged": total_merged,
        "chunks_freed": total_freed,
        "anchor_ids": anchor_ids,
    }

# ── madvise — Memory Access Hints（迭代32）────────────────────────

_MADVISE_FILE = MEMORY_OS_DIR / "madvise.json"


def madvise_write(project: str, hints: list, session_id: str = "") -> None:
    """
    迭代32：madvise(MADV_WILLNEED) — 写入检索 hint 关键词。
    OS 类比：madvise(addr, len, MADV_WILLNEED)
      应用程序通过 madvise 告知内核"即将访问这段内存"，
      内核提前将对应磁盘页加载到 page cache（readahead），
      后续访问直接命中 cache 而非产生 page fault。

    memory-os 的 madvise：
      extractor 在 Stop hook 中分析对话主题，提取关键词写入 hint 文件。
      retriever 在下一轮检索时读取 hint，对匹配的 chunk 加 boost。
      效果：热话题的 chunk 在下一轮检索中排名更高（预热优势）。

    参数：
      project — 项目 ID
      hints — 关键词列表（从对话中提取的主题实体）
      session_id — 来源 session
    """
    try:
        from config import get as _cfg
        max_hints = _cfg("madvise.max_hints")
    except Exception:
        max_hints = 10

    now_iso = datetime.now(timezone.utc).isoformat()

    # 读取已有 hints
    existing = _madvise_load()

    # 按 project 更新（替换而非追加）
    existing[project] = {
        "hints": hints[:max_hints],
        "timestamp": now_iso,
        "session_id": session_id,
    }

    # 写入
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        _MADVISE_FILE.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def madvise_read(project: str) -> list:
    """
    迭代32：读取 madvise hints（MADV_WILLNEED 查询）。
    OS 类比：内核检查 page cache 是否有预读的页面。

    返回当前有效的 hint 关键词列表（已过滤过期 hint）。
    空列表表示无 hint（等价于 cache miss）。
    """
    try:
        from config import get as _cfg
        ttl = _cfg("madvise.ttl_secs")
    except Exception:
        ttl = 1800

    data = _madvise_load()
    entry = data.get(project)
    if not entry:
        return []

    # TTL 检查
    ts = entry.get("timestamp", "")
    if ts:
        try:
            hint_time = datetime.fromisoformat(ts)
            now = datetime.now(timezone.utc)
            if hint_time.tzinfo is None:
                hint_time = hint_time.replace(tzinfo=timezone.utc)
            age_secs = (now - hint_time).total_seconds()
            if age_secs > ttl:
                return []  # 过期 hint，等价于 cache eviction
        except Exception:
            pass

    return entry.get("hints", [])


def madvise_clear(project: str = None) -> int:
    """
    迭代32：madvise(MADV_DONTNEED) — 清除 hint。
    OS 类比：madvise(addr, len, MADV_DONTNEED) 告知内核释放页面。

    project=None 时清除所有项目的 hint。
    返回清除的 hint 条目数。
    """
    data = _madvise_load()
    if project:
        if project in data:
            count = len(data[project].get("hints", []))
            del data[project]
        else:
            return 0
    else:
        count = sum(len(v.get("hints", [])) for v in data.values())
        data = {}

    try:
        _MADVISE_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return count


def _madvise_load() -> dict:
    """加载 madvise.json（容错）。"""
    if not _MADVISE_FILE.exists():
        return {}
    try:
        return json.loads(_MADVISE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

# ── Watchdog Timer — 自我修复与健康检测（迭代35）─────────────────

def _watchdog_backup(conn: sqlite3.Connection, checks: list, repairs: list) -> bool:
    """
    iter259 W0: store.db 每日滚动备份（7天保留）。
    OS 类比：LVM snapshot — 定期创建存储快照，损坏时可 rollback to known-good state。

    备份策略：
      - 每天最多备份一次（以当日日期为标记）
      - 保留最近 7 天的备份，超出自动删除
      - integrity_check 失败时自动尝试从最新备份恢复

    返回 True 表示本检查项无 error（即使未触发备份）。
    """
    import shutil as _shutil
    try:
        backup_dir = MEMORY_OS_DIR / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)

        today = datetime.now().strftime("%Y%m%d")
        backup_file = backup_dir / f"store.db.{today}"

        if not backup_file.exists() and STORE_DB.exists():
            # 使用 SQLite online backup API（避免锁定问题）
            import sqlite3 as _sq3
            src = _sq3.connect(str(STORE_DB))
            dst = _sq3.connect(str(backup_file))
            src.backup(dst)
            dst.close()
            src.close()
            repairs.append({"action": "db_backup", "reason": "daily_backup",
                            "result": f"ok → {backup_file.name}"})

        # 清理超过 7 天的备份
        backups = sorted(backup_dir.glob("store.db.*"))
        for old in backups[:-7]:
            old.unlink(missing_ok=True)

        checks.append({"name": "db_backup", "status": "ok",
                        "detail": f"backup_dir={backup_dir} today={today}"})
        return True
    except Exception as e:
        checks.append({"name": "db_backup", "status": "skip",
                        "detail": str(e)[:80]})
        return True  # 备份失败不影响 watchdog 整体状态


def _watchdog_restore_from_backup(checks: list, repairs: list) -> bool:
    """
    integrity_check 失败后，尝试从最新备份恢复。
    OS 类比：fsck 无法修复时，从 LVM snapshot 恢复分区。

    返回 True 表示恢复成功，False 表示无可用备份或恢复失败。
    """
    import shutil as _shutil
    try:
        backup_dir = MEMORY_OS_DIR / "backups"
        if not backup_dir.exists():
            return False

        # 找最新备份（按文件名日期降序）
        backups = sorted(backup_dir.glob("store.db.*"), reverse=True)
        if not backups:
            return False

        latest = backups[0]
        # 验证备份本身完整
        import sqlite3 as _sq3
        try:
            bconn = _sq3.connect(str(latest))
            result = bconn.execute("PRAGMA integrity_check(1)").fetchone()
            bconn.close()
            if not result or result[0] != "ok":
                return False
        except Exception:
            return False

        # 恢复：备份原损坏文件，替换为备份
        corrupted = STORE_DB.with_suffix(".db.corrupted")
        _shutil.copy2(str(STORE_DB), str(corrupted))
        _shutil.copy2(str(latest), str(STORE_DB))
        repairs.append({"action": "db_restore_from_backup",
                        "reason": "integrity_check_failed",
                        "result": f"restored from {latest.name}, corrupted→{corrupted.name}"})
        return True
    except Exception as e:
        checks.append({"name": "db_restore", "status": "failed",
                        "detail": str(e)[:80]})
        return False


def watchdog_check(conn: sqlite3.Connection) -> dict:
    """
    迭代35：Watchdog Timer — 系统自我修复与健康检测。
    OS 类比：Linux Watchdog (2003) + softlockup detector (2005) + hung_task detector

    Linux watchdog 背景：
      硬件 watchdog timer（如 iTCO_wdt）要求用户空间进程定期写入 /dev/watchdog
      （"喂狗"），超时未喂则触发系统重启——检测系统是否挂死。
      softlockup detector 检测 CPU 被长时间独占（没有调度其他任务）。
      hung_task detector 检测进程长时间处于 TASK_UNINTERRUPTIBLE 状态。

    memory-os 等价问题：
      hook 可能静默失败、FTS5 索引可能和主表不同步（触发器失败/损坏）、
      swap 分区可能膨胀失控、dmesg 可能积累 ERR 无人处理。
      没有自检机制时这些问题只能等到用户端到端体验劣化后才被发现。

    检测项（6 级，按严重度排序）：
      W0 每日备份：store.db 滚动备份（7天保留）+ integrity_check 失败时恢复（iter259）
      W1 数据库完整性：PRAGMA integrity_check（检测 B-tree 损坏）
      W2 FTS5 一致性：FTS5 行数 vs 主表行数，不一致则 rebuild
      W3 swap 膨胀：swap 分区 > max_chunks 时裁剪
      W4 dmesg ERR 聚合：最近 ERR 数量超阈值发出告警
      W5 sysctl 验证：所有 tunable 值在合法范围内

    在 SessionStart (loader.py) 时调用——相当于 watchdog 在系统启动时做 POST (Power-On Self-Test)。
    自动修复能力：FTS5 rebuild、swap 裁剪、dmesg ERR 清理、db 备份+恢复。
    只读检查 + 自愈修复，不会阻塞主流程。

    返回 dict：
      status — "HEALTHY" / "REPAIRED" / "DEGRADED"
      checks — 各检查项结果列表
      repairs — 自动修复动作列表
      duration_ms — 检测耗时
    """
    import time as _time
    _t_start = _time.time()

    checks = []
    repairs = []
    has_error = False

    # ── W0: 每日备份（iter259）──
    # OS 类比：LVM snapshot — 定期备份，损坏时可 rollback
    _watchdog_backup(conn, checks, repairs)

    # ── W1: 数据库完整性（PRAGMA integrity_check）──
    # OS 类比：fsck — 文件系统一致性检查
    try:
        result = conn.execute("PRAGMA integrity_check(1)").fetchone()
        ok = result and result[0] == "ok"
        checks.append({"name": "db_integrity", "status": "ok" if ok else "error",
                        "detail": result[0] if result else "no result"})
        if not ok:
            # iter259: integrity_check 失败 → 尝试从备份恢复
            restored = _watchdog_restore_from_backup(checks, repairs)
            if not restored:
                has_error = True
            # 恢复后仍标记本次 has_error=False，以 REPAIRED 状态退出（repairs 非空）
    except Exception as e:
        checks.append({"name": "db_integrity", "status": "error", "detail": str(e)[:100]})
        has_error = True

    # ── W2: FTS5 一致性检查（integrity-check 命令）──
    # OS 类比：e2fsck 检查 inode 和 directory entry 的一致性
    # FTS5 content-sync 模式下 COUNT(*) 不可靠（引用主表），改用 integrity-check
    try:
        # FTS5 integrity-check：验证索引与 content 表的一致性
        # 如果索引损坏或不同步，会抛出异常
        conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts, rank) VALUES('integrity-check', 1)")
        checks.append({"name": "fts5_consistency", "status": "ok",
                        "detail": "integrity-check passed"})
    except Exception as e:
        err_msg = str(e)[:100]
        checks.append({"name": "fts5_consistency", "status": "drift",
                        "detail": f"integrity-check failed: {err_msg}"})
        # 自愈：FTS5 rebuild
        try:
            conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts) VALUES('rebuild')")
            conn.commit()
            repairs.append({"action": "fts5_rebuild", "reason": err_msg[:60],
                            "result": "ok"})
        except Exception as re_err:
            # iter259: rebuild 失败 → 降级到 readonly 模式，记录 dmesg
            # OS 类比：ext4 以 ro 模式重挂载 — 无法写入但仍可读取
            repairs.append({"action": "fts5_rebuild", "reason": err_msg[:60],
                            "result": f"failed: {str(re_err)[:80]}"})
            try:
                dmesg_log(conn, DMESG_WARN, "watchdog",
                          "fts5_rebuild_failed: degrading to readonly FTS5 mode",
                          extra={"rebuild_error": str(re_err)[:80]})
                conn.commit()
            except Exception:
                pass
            # 不设 has_error=True：FTS5 仍可降级查询（主表完整），DEGRADED 但不 FAILED

    # ── W3: swap 膨胀检查 ──
    # OS 类比：swapon -s 检查 swap 使用率
    try:
        from config import get as _cfg
        max_swap = _cfg("swap.max_chunks")
        swap_count = conn.execute("SELECT COUNT(*) FROM swap_chunks").fetchone()[0]
        swap_ok = swap_count <= max_swap
        checks.append({"name": "swap_health", "status": "ok" if swap_ok else "bloated",
                        "detail": f"count={swap_count} max={max_swap}"})
        if not swap_ok:
            # 自愈：裁剪最旧条目
            overflow = swap_count - max_swap
            conn.execute(
                "DELETE FROM swap_chunks WHERE id IN "
                "(SELECT id FROM swap_chunks ORDER BY swapped_at ASC LIMIT ?)",
                (overflow,)
            )
            conn.commit()
            repairs.append({"action": "swap_trim", "reason": f"overflow={overflow}",
                            "result": "ok"})
    except Exception as e:
        checks.append({"name": "swap_health", "status": "skip",
                        "detail": str(e)[:60]})

    # ── W4: dmesg ERR 聚合（最近 1 小时）+ 告警去重（iter259）──
    # OS 类比：journalctl -p err --since "1 hour ago" | wc -l
    # iter259: 同类告警 1h 内只写入一次（去重），避免 dmesg 被 watchdog 自身的告警刷满。
    # OS 类比：netlink 告警合并 — 相同事件在窗口期内只产生一条日志。
    try:
        # 迭代147：datetime(timestamp) 修复 ISO8601+timezone 字符串比较 bug
        err_count = conn.execute(
            """SELECT COUNT(*) FROM dmesg
               WHERE level = 'ERR'
               AND datetime(timestamp) > datetime('now', '-1 hour')"""
        ).fetchone()[0]
        err_threshold = 10
        err_ok = err_count < err_threshold
        checks.append({"name": "dmesg_errors", "status": "ok" if err_ok else "elevated",
                        "detail": f"err_1h={err_count} threshold={err_threshold}"})
        if not err_ok:
            # 告警去重：检查最近 1h 内是否已有相同 watchdog/elevated 告警
            _already_warned = conn.execute(
                """SELECT COUNT(*) FROM dmesg
                   WHERE level = 'WARN' AND subsystem = 'watchdog'
                   AND message LIKE '%elevated errors%'
                   AND datetime(timestamp) > datetime('now', '-1 hour')"""
            ).fetchone()[0]
            if not _already_warned:
                dmesg_log(conn, DMESG_WARN, "watchdog",
                          f"elevated errors: {err_count} ERR in last 1h (threshold={err_threshold})",
                          extra={"err_count": err_count})
    except Exception as e:
        checks.append({"name": "dmesg_errors", "status": "skip",
                        "detail": str(e)[:60]})

    # ── W5: sysctl 验证 ──
    # OS 类比：sysctl --system 验证所有参数值合法
    try:
        from config import sysctl_list, _REGISTRY
        invalid_keys = []
        for key, info in _REGISTRY.items():
            default, typ, lo, hi, env_key, desc = info
            try:
                from config import get as _cfg_get
                val = _cfg_get(key)
                # 类型检查
                if not isinstance(val, typ):
                    invalid_keys.append(f"{key}: type mismatch (got {type(val).__name__}, want {typ.__name__})")
            except Exception as ve:
                invalid_keys.append(f"{key}: {str(ve)[:40]}")
        sysctl_ok = len(invalid_keys) == 0
        checks.append({"name": "sysctl_valid", "status": "ok" if sysctl_ok else "invalid",
                        "detail": f"checked={len(_REGISTRY)} invalid={len(invalid_keys)}"
                                  + (f" keys={invalid_keys[:3]}" if invalid_keys else "")})
    except Exception as e:
        checks.append({"name": "sysctl_valid", "status": "skip",
                        "detail": str(e)[:60]})

    duration_ms = (_time.time() - _t_start) * 1000

    # 综合状态判定
    if has_error:
        status = "DEGRADED"
    elif repairs:
        status = "REPAIRED"
    else:
        status = "HEALTHY"

    return {
        "status": status,
        "checks": checks,
        "repairs": repairs,
        "duration_ms": round(duration_ms, 2),
    }

# ── PSI — Pressure Stall Information（迭代36）─────────────────

def psi_stats(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代36：PSI — Pressure Stall Information（压力停顿信息）。
    OS 类比：Linux PSI (Facebook, 2018, Linux 5.2)

    Linux PSI 背景：
      传统监控（top/vmstat）只看资源使用率，无法回答核心问题：
      "系统在因资源不足而等待吗？"
      CPU 100% 不一定有问题（可能都在做有用功），
      但 CPU 100% 且有任务在 runqueue 等待 = 真正的压力。

      PSI 量化三个维度的压力：
        /proc/pressure/cpu    — 任务因 CPU 不足而等待的时间占比
        /proc/pressure/memory — 任务因内存不足而等待（reclaim/swap）的时间占比
        /proc/pressure/io     — 任务因 I/O 而阻塞的时间占比

      每个维度报告两个值：
        some: 至少有一个任务在等待的时间比例（部分降级）
        full: 所有任务都在等待的时间比例（完全停顿）

      三级压力状态：
        NONE — 无任务等待（系统健康）
        SOME — 部分任务受影响（需要关注）
        FULL — 全面受影响（需要立即干预）

    memory-os 等价问题：
      迭代 26 的 /proc 只是静态快照（"当前有多少 chunk"），
      没有回答 "系统在因资源不足而劣化吗？"。
      例如：
        - 检索延迟从 1ms 涨到 10ms，但没有触发任何告警
        - 命中率从 80% 降到 30%，scheduler 仍然按原策略分类
        - 配额 85% 使用率，kswapd 还没触发但已在压力边缘
      这些都是"有压力但还没完全 stall"的 SOME 状态，
      是 PSI 能捕获而简单阈值无法捕获的。

    memory-os PSI 三个维度：
      1. retrieval_pressure — 检索延迟压力
         基于最近 N 次检索的延迟分布 vs 基线延迟
         some: 超过基线的比例 > 30%
         full: 超过基线的比例 > 70% 或 P95 > 3× 基线
      2. capacity_pressure — 容量压力
         基于当前 chunk 数 / 配额
         some: 使用率 > some_pct（默认 70%）
         full: 使用率 > full_pct（默认 90%）
      3. quality_pressure — 召回质量压力
         基于最近 N 次检索的命中率 vs 基线命中率
         some: 命中率低于基线
         full: 命中率低于基线的 50%

    返回 dict：
      retrieval — {level, some_pct, avg_ms, p95_ms, baseline_ms}
      capacity  — {level, usage_pct, current, quota}
      quality   — {level, hit_rate_pct, baseline_pct, miss_streak}
      overall   — 综合压力级别（三个维度中最严重的）
      recommendation — 建议动作
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"overall": "NONE", "retrieval": {}, "capacity": {}, "quality": {},
                "recommendation": "config unavailable"}

    window = _cfg("psi.window_size")
    latency_baseline_fixed = _cfg("psi.latency_baseline_ms")
    hit_baseline = _cfg("psi.hit_rate_baseline_pct")
    cap_some = _cfg("psi.capacity_some_pct")
    cap_full = _cfg("psi.capacity_full_pct")
    quota = _cfg("extractor.chunk_quota")

    # ── 迭代60：PSI Adaptive Baseline ──
    # OS 类比：Linux PSI 的 psi_trigger 支持可配置 time window + threshold，
    # 且现代 scheduler（如 EEVDF）用指数加权移动平均（EWMA）而非固定阈值。
    # 问题：固定 latency_baseline=5ms 在 Python hook 冷启动 ~10ms 的环境下
    # 导致 >50% 请求被标记为 stall → PSI 永久 FULL → 所有 FULL query 被降级为 LITE
    # → 信息覆盖度持续下降（恶性循环）。
    # 解决：自适应基线 = 滑动窗口 P50 × margin，反映真实的"正常"延迟水平。
    adaptive_enabled = bool(_cfg("psi.adaptive_baseline"))
    adaptive_margin = _cfg("psi.adaptive_margin")
    adaptive_min_samples = _cfg("psi.adaptive_min_samples")

    # ── 维度1：retrieval_pressure（检索延迟）──
    # 从 recall_traces 取最近 N 次检索的延迟
    # 迭代61：PSI Noise Floor — 排除 skipped_same_hash trace
    # OS 类比：Linux perf_event_open() 的 exclude_idle 标志（2008）
    #   采样 CPU 性能计数器时，exclude_idle=1 排除 CPU 处于 idle 状态的样本，
    #   因为 idle 不代表真实工作负载，计入会稀释 CPI/cache-miss-rate 等指标。
    #   同理，skipped_same_hash trace 是"发现结果没变就退出"的开销，
    #   不代表真实检索工作量。计入 PSI 延迟采样会：
    #     1. 抬高 P50/P95 → 虚假 stall 信号
    #     2. 触发 PSI FULL → retriever 系统性降级为 LITE → 信息覆盖度下降
    #   过滤后 PSI 只反映真正执行了检索+注入的请求延迟。
    # 迭代62：额外排除 hard_deadline trace
    # hard_deadline 路径的 duration_ms 包含 import 开销（修复前），
    # 即使修复后，hard_deadline 意味着检索被中断（不完整），不代表正常延迟。
    latency_rows = conn.execute(
        """SELECT duration_ms FROM recall_traces
           WHERE project = ? AND duration_ms > 0
             AND reason NOT LIKE '%skipped_same_hash%'
             AND reason NOT LIKE '%hard_deadline%'
           ORDER BY timestamp DESC LIMIT ?""",
        (project, window),
    ).fetchall()

    if latency_rows:
        latencies = [r[0] for r in latency_rows]
        avg_ms = sum(latencies) / len(latencies)
        sorted_lat = sorted(latencies)
        p95_idx = max(0, int(len(sorted_lat) * 0.95) - 1)
        p95_ms = sorted_lat[p95_idx]

        # 迭代60：自适应基线计算
        # OS 类比：EWMA (Exponentially Weighted Moving Average) 在 TCP RTT 估算中的应用
        #   TCP 不用固定 RTO，而是 RTO = SRTT + 4×RTTVAR (RFC 6298)
        #   同理，PSI 不用固定 latency_baseline，而是 baseline = P50 × margin
        #
        # 附加 IQR outlier 过滤：
        #   统计学标准做法 (Tukey, 1977): outlier = value > Q3 + 1.5 × IQR
        #   过滤后的数据计算 P95 更准确（不被 Python 冷启动 200ms+ 异常值污染）
        if adaptive_enabled and len(latencies) >= adaptive_min_samples:
            p50_idx = len(sorted_lat) // 2
            p50_ms = sorted_lat[p50_idx]
            latency_baseline = p50_ms * adaptive_margin
            # 下限保护：不低于 5ms（避免全缓存命中时基线过低）
            latency_baseline = max(latency_baseline, 5.0)

            # IQR outlier 过滤（用于 P95 FULL 判断，不影响 stall_pct）
            q1_idx = max(0, int(len(sorted_lat) * 0.25))
            q3_idx = max(0, int(len(sorted_lat) * 0.75) - 1)
            q1 = sorted_lat[q1_idx]
            q3 = sorted_lat[q3_idx]
            iqr = q3 - q1
            outlier_fence = q3 + 1.5 * iqr
            filtered_lat = [l for l in sorted_lat if l <= outlier_fence]
            if filtered_lat:
                fp95_idx = max(0, int(len(filtered_lat) * 0.95) - 1)
                filtered_p95 = filtered_lat[fp95_idx]
            else:
                filtered_p95 = p95_ms
        else:
            latency_baseline = latency_baseline_fixed
            filtered_p95 = p95_ms

        stall_count = sum(1 for l in latencies if l > latency_baseline)
        stall_pct = stall_count / len(latencies) * 100

        # 迭代60：P95 FULL 阈值也自适应
        # 使用 IQR-filtered P95 与 baseline×3 比较（而非原始 P95）
        # 原因：Python 冷启动偶尔 200ms+ 不应触发 FULL 降级
        p95_full_threshold = latency_baseline * 3

        if stall_pct > 70 or filtered_p95 > p95_full_threshold:
            ret_level = "FULL"
        elif stall_pct > 30:
            ret_level = "SOME"
        else:
            ret_level = "NONE"

        retrieval = {
            "level": ret_level,
            "some_pct": round(stall_pct, 1),
            "avg_ms": round(avg_ms, 2),
            "p95_ms": round(p95_ms, 2),
            "filtered_p95_ms": round(filtered_p95, 2),
            "baseline_ms": round(latency_baseline, 2),
            "p95_threshold_ms": round(p95_full_threshold, 2),
            "adaptive": adaptive_enabled,
            "samples": len(latencies),
        }
    else:
        latency_baseline = latency_baseline_fixed
        retrieval = {"level": "NONE", "some_pct": 0, "avg_ms": 0,
                     "p95_ms": 0, "baseline_ms": latency_baseline,
                     "adaptive": adaptive_enabled, "samples": 0}

    # ── 维度2：capacity_pressure（容量）──
    current_count = get_project_chunk_count(conn, project)
    usage_pct = (current_count / quota * 100) if quota > 0 else 0

    if usage_pct >= cap_full:
        cap_level = "FULL"
    elif usage_pct >= cap_some:
        cap_level = "SOME"
    else:
        cap_level = "NONE"

    capacity = {
        "level": cap_level,
        "usage_pct": round(usage_pct, 1),
        "current": current_count,
        "quota": quota,
    }

    # ── 维度3：quality_pressure（召回质量）──
    quality_rows = conn.execute(
        """SELECT injected FROM recall_traces
           WHERE project = ?
           ORDER BY timestamp DESC LIMIT ?""",
        (project, window),
    ).fetchall()

    if quality_rows:
        injected_count = sum(1 for r in quality_rows if r[0] == 1)
        hit_rate = injected_count / len(quality_rows) * 100

        # miss streak: 最近连续 miss 的次数
        miss_streak = 0
        for r in quality_rows:
            if r[0] == 0:
                miss_streak += 1
            else:
                break

        if hit_rate < hit_baseline * 0.5:
            qual_level = "FULL"
        elif hit_rate < hit_baseline:
            qual_level = "SOME"
        else:
            qual_level = "NONE"

        quality = {
            "level": qual_level,
            "hit_rate_pct": round(hit_rate, 1),
            "baseline_pct": hit_baseline,
            "miss_streak": miss_streak,
            "samples": len(quality_rows),
        }
    else:
        quality = {"level": "NONE", "hit_rate_pct": 0,
                   "baseline_pct": hit_baseline, "miss_streak": 0, "samples": 0}

    # ── 综合压力级别（取三个维度中最严重的）──
    levels = [retrieval["level"], capacity["level"], quality["level"]]
    if "FULL" in levels:
        overall = "FULL"
    elif "SOME" in levels:
        overall = "SOME"
    else:
        overall = "NONE"

    # ── 建议动作 ──
    recommendations = []
    if capacity["level"] == "FULL":
        recommendations.append("capacity_critical: trigger kswapd or raise quota")
    elif capacity["level"] == "SOME":
        recommendations.append("capacity_warning: consider compaction or stale reclaim")
    if quality["level"] == "FULL":
        recommendations.append("quality_critical: check extractor, freshness, or swap_fault")
    elif quality["level"] == "SOME":
        recommendations.append("quality_degraded: review hint coverage or FTS5 health")
    if retrieval["level"] == "FULL":
        recommendations.append("latency_critical: consider LITE downgrade or FTS5 rebuild")
    elif retrieval["level"] == "SOME":
        recommendations.append("latency_elevated: monitor trend")

    return {
        "overall": overall,
        "retrieval": retrieval,
        "capacity": capacity,
        "quality": quality,
        "recommendation": "; ".join(recommendations) if recommendations else "system healthy",
    }

# compact_zone 使用的停用词（排除常见虚词，避免过度聚类）
_COMPACT_STOPWORDS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "has",
    "not", "but", "can", "will", "all", "one", "its", "had", "been", "each",
    "which", "their", "than", "other", "into", "more", "some", "such", "when",
    "use", "used", "using", "new", "old", "set", "get", "add", "run", "see",
    "now", "way", "may", "also", "per", "via", "yet", "out", "how", "why",
})

# ── DAMON — Data Access MONitor（迭代42）────────────────────────

def damon_scan(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代42：DAMON — Data Access MONitor（数据访问模式监控）。
    OS 类比：Linux DAMON (Data Access MONitor, Amazon, 2021, Linux 5.15)

    Linux DAMON 背景：
      传统内存管理（kswapd/LRU）只在分配或回收时被动观察访问模式。
      DAMON (SeongJae Park, Amazon, 2021) 引入主动、低开销的访问采样：
        1. 将地址空间划分为 regions
        2. 对每个 region 随机采样一个页面的 Accessed bit
        3. 定期扫描（默认 5ms 采样 + 100ms 聚合）
        4. 生成 access pattern snapshot（每个 region 的访问热度）
      基于 snapshot，DAMON 驱动三种后续动作：
        - DAMOS (DAMON-based Operation Schemes): 自动对 cold region 做 madvise(MADV_COLD)
        - 页面迁移：将 cold page 从 DRAM 移到 PMEM/CXL（memory tiering）
        - 告警：当 working set 超预期增长时发出 pressure 信号

      核心创新：
        O(1) 采样（随机选一个页面代表整个 region）+ 自适应 region 合并/拆分，
        开销 < 1% CPU，却能提供精确的 hot/warm/cold 分类。

    memory-os 当前的被动问题：
      1. 只在淘汰时（kswapd/evict）才评估 chunk 冷热——已经太晚了
      2. 大量 "dead chunk"（创建后从未被检索命中）占用配额
         但它们的 importance 可能不低（0.7+），不会被 kswapd 淘汰
      3. SessionStart 的 watchdog 只做健康检查，不做优化
      4. 没有 access pattern 的宏观统计——PSI 只看压力信号，不看冷热分布

    DAMON scan 做什么：
      Phase 1 — 访问热度采样（region-based sampling）
        将项目 chunk 按 access_count 分为 3 个 region：
          HOT:  access_count >= hot_threshold (top 20%)
          WARM: access_count > 0 但 < hot_threshold
          COLD: access_count = 0 且 age > cold_age_days
          DEAD: access_count = 0 且 age > dead_age_days 且 importance < dead_imp_threshold

      Phase 2 — DAMOS 动作（自动 cold/dead 管理）
        - DEAD chunk → 主动 swap out（释放配额）
        - COLD chunk → 标记 oom_adj += cold_oom_adj_delta（加速未来淘汰）
        - HOT chunk  → 确保 oom_adj <= 0（保护高频 chunk 不被误淘汰）

      Phase 3 — Access Heatmap 生成
        输出热度分布统计（hot/warm/cold/dead 各占比），写入 dmesg。

    调用时机：
      loader.py SessionStart — 每次新会话开始时做一次全量扫描。
      开销：纯 SQL 聚合 + 少量 UPDATE，预期 < 5ms。

    参数：
      conn — 数据库连接
      project — 项目 ID

    返回 dict：
      heatmap — {hot, warm, cold, dead} 各区域的 chunk 数量
      actions — {swapped_dead, marked_cold, protected_hot} 动作计数
      hot_threshold — 本次计算的 HOT 阈值
      duration_ms — 扫描耗时
    """
    import time as _time
    _t_start = _time.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"heatmap": {}, "actions": {}, "hot_threshold": 0, "duration_ms": 0}

    cold_age_days = _cfg("damon.cold_age_days")
    dead_age_days = _cfg("damon.dead_age_days")
    dead_imp_threshold = _cfg("damon.dead_importance_max")
    cold_oom_delta = _cfg("damon.cold_oom_adj_delta")
    max_actions = _cfg("damon.max_actions_per_scan")

    # ── Phase 1: 访问热度采样 ──
    # 计算 HOT 阈值：access_count 的 P80（top 20% 为 HOT）
    all_access = conn.execute(
        "SELECT COALESCE(access_count, 0) FROM memory_chunks WHERE project = ?",
        (project,),
    ).fetchall()

    total_chunks = len(all_access)
    if total_chunks == 0:
        return {"heatmap": {"hot": 0, "warm": 0, "cold": 0, "dead": 0},
                "actions": {"swapped_dead": 0, "marked_cold": 0, "protected_hot": 0},
                "hot_threshold": 0, "duration_ms": round((_time.time() - _t_start) * 1000, 2)}

    access_values = sorted([r[0] for r in all_access], reverse=True)
    # P80 阈值：如果 access_count 分布很平（大多数为 0），则 threshold 至少为 2
    p80_idx = max(0, int(total_chunks * 0.2) - 1)
    hot_threshold = max(2, access_values[p80_idx] if p80_idx < len(access_values) else 2)

    # 分类各 region
    cold_threshold_ts = f"-{cold_age_days} days"
    dead_threshold_ts = f"-{dead_age_days} days"

    # HOT: access_count >= hot_threshold
    hot_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project = ? AND COALESCE(access_count, 0) >= ?",
        (project, hot_threshold),
    ).fetchone()[0]

    # WARM: access_count > 0 但 < hot_threshold
    warm_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project = ? "
        "AND COALESCE(access_count, 0) > 0 AND COALESCE(access_count, 0) < ?",
        (project, hot_threshold),
    ).fetchone()[0]

    # 迭代104：获取当前 project 的 pinned chunk IDs（排除所有 pin 类型）
    from store_vfs import get_pinned_ids as _get_pinned_ids
    _pinned = _get_pinned_ids(conn, project)

    # DEAD: access_count = 0 且 age > dead_age_days 且 importance < threshold
    # 迭代147：datetime(created_at) 修复 ISO8601+timezone 字符串与 SQLite datetime() 比较 bug
    dead_ids = conn.execute(
        """SELECT id FROM memory_chunks
           WHERE project = ?
             AND COALESCE(access_count, 0) = 0
             AND datetime(created_at) < datetime('now', ?)
             AND importance < ?
             AND chunk_type NOT IN ('task_state')
             AND COALESCE(oom_adj, 0) > -1000""",
        (project, dead_threshold_ts, dead_imp_threshold),
    ).fetchall()
    # 迭代104：排除 pinned chunks（hard pin 阻止 DEAD swap out）
    dead_ids = [r[0] for r in dead_ids if r[0] not in _pinned]

    # COLD: access_count = 0 且 age > cold_age_days（排除已分类为 DEAD 的）
    # 迭代147：datetime(created_at) 修复同上
    cold_ids = conn.execute(
        """SELECT id FROM memory_chunks
           WHERE project = ?
             AND COALESCE(access_count, 0) = 0
             AND datetime(created_at) < datetime('now', ?)
             AND chunk_type NOT IN ('task_state')
             AND COALESCE(oom_adj, 0) > -1000
             AND importance >= ?""",
        (project, cold_threshold_ts, dead_imp_threshold),
    ).fetchall()
    # 迭代104：排除 pinned chunks（soft pin 阻止 COLD oom_adj 升级）
    cold_ids = [r[0] for r in cold_ids if r[0] not in _pinned]

    heatmap = {
        "hot": hot_count,
        "warm": warm_count,
        "cold": len(cold_ids),
        "dead": len(dead_ids),
    }

    # ── Phase 1.4: Verified Status TTL（迭代493）──
    # OS 类比：TLS 证书过期检查 — 定期验证 verified 状态是否仍在有效期内。
    # verified chunk 豁免 Ebbinghaus 衰减，但 verified 本身不应永久有效：
    #   TTL 到期后重置为 pending，再次使用会触发重新验证。
    # 在 Ebbinghaus Phase 1.5 之前运行：过期 → pending → 下一步可被 Ebbinghaus 衰减。
    try:
        from store_vfs import expire_stale_verified as _expire_verified
        _expire_verified(conn, project, max_expire=20)
    except Exception:
        pass  # TTL 过期失败不阻塞 DAMON

    # ── Phase 1.5: Ebbinghaus Time-Decay（先于 COLD，避免双重惩罚）──
    # 优先级协调：Ebbinghaus 基于时间的连续衰减（精确模型）>
    #              DAMON COLD 基于 access_count=0 的粗粒度衰减（简化模型）
    # 若 chunk 本轮已被 Ebbinghaus 衰减，当天跳过 DAMON COLD importance 惩罚。
    # OS 类比：Linux DAMON DAMOS 动作有优先级（migrate > madvise > reclaim），
    #   高优先级动作完成后低优先级动作跳过，避免 thundering herd 式惩罚叠加。
    ebbinghaus_result = {"decayed": 0, "total_scanned": 0, "decayed_ids": set()}
    try:
        ebbinghaus_result = apply_ebbinghaus_decay(conn, project, max_chunks=50)
    except Exception:
        pass
    _ebbinghaus_decayed_ids = ebbinghaus_result.get("decayed_ids", set())

    # ── Phase 2: DAMOS 动作 ──
    swapped_dead = 0
    marked_cold = 0
    protected_hot = 0
    action_count = 0

    # DEAD → swap out（释放配额，但保留在 swap 分区可恢复）
    if dead_ids and action_count < max_actions:
        batch = dead_ids[:max(1, max_actions - action_count)]
        result = swap_out(conn, batch)
        swapped_dead = result.get("swapped_count", 0)
        action_count += swapped_dead

    # COLD → 标记 oom_adj + importance 衰减（加速未来 kswapd 淘汰）
    # iter105: 增加 importance decay — 零访问页面随时间降级，最终进入 stale reclaim 范围
    # OS 类比：DAMON DAMOS madvise(MADV_COLD) 后 page 不被 accessed bit 清零但降低 LRU 优先级
    # iter470: 若已被 Ebbinghaus 衰减（更精确的时间模型），跳过 importance 惩罚部分
    #   但仍更新 oom_adj（oom_adj 是 kswapd 淘汰优先级标记，独立于 importance）
    if cold_ids and action_count < max_actions:
        batch = cold_ids[:max(1, max_actions - action_count)]
        for cid in batch:
            row = conn.execute(
                "SELECT COALESCE(oom_adj, 0), importance FROM memory_chunks WHERE id = ?",
                (cid,),
            ).fetchone()
            if row:
                current_adj, current_imp = row
                if current_adj < cold_oom_delta:
                    if cid in _ebbinghaus_decayed_ids:
                        # 本轮已被 Ebbinghaus 精确衰减 → 只更新 oom_adj，跳过 importance 惩罚
                        conn.execute(
                            "UPDATE memory_chunks SET oom_adj = MAX(COALESCE(oom_adj, 0), ?) WHERE id = ?",
                            (cold_oom_delta, cid),
                        )
                    else:
                        # importance 每次 COLD 扫描衰减 5%（最低到 0.5，保留基本可检索性）
                        new_imp = max(0.5, round(current_imp * 0.95, 3))
                        conn.execute(
                            "UPDATE memory_chunks SET oom_adj = MAX(COALESCE(oom_adj, 0), ?), importance = ? WHERE id = ?",
                            (cold_oom_delta, new_imp, cid),
                        )
                    marked_cold += 1
                    action_count += 1
                    if action_count >= max_actions:
                        break

    # HOT → 确保受保护（oom_adj > 0 的 HOT chunk 重置为 0）
    if action_count < max_actions:
        hot_unprotected = conn.execute(
            """SELECT id FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(access_count, 0) >= ?
                 AND COALESCE(oom_adj, 0) > 0
               LIMIT ?""",
            (project, hot_threshold, max_actions - action_count),
        ).fetchall()
        for row in hot_unprotected:
            conn.execute(
                "UPDATE memory_chunks SET oom_adj = 0 WHERE id = ?",
                (row[0],),
            )
            protected_hot += 1

    # iter433: Reminiscence Bump — 批量扫描项目形成期 chunk 并应用 stability 加成
    # OS 类比：Linux early_boot_params 在内核稳定后 confirm（创生期 chunk 回顾性加强）
    bump_result = {"bumped": 0, "skipped": 0}
    try:
        from store_vfs import apply_reminiscence_bump_batch
        bump_result = apply_reminiscence_bump_batch(conn, project, max_chunks=20)
    except Exception:
        pass

    # Phase 5: recall_traces TTL 清理 — 删除超过 30 天的旧 trace
    # OS 类比：Linux journal commit → old journal blocks GC（不需要的历史日志主动回收）
    # 防止 recall_traces 无限增长拖慢 Adaptive Citation Rate 的滑动窗口查询
    _cleaned_traces = 0
    try:
        _TRACE_TTL_DAYS = 30
        _trace_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=_TRACE_TTL_DAYS)
        ).isoformat()
        _clean_result = conn.execute(
            "DELETE FROM recall_traces WHERE project=? AND timestamp < ?",
            (project, _trace_cutoff)
        )
        _cleaned_traces = _clean_result.rowcount
    except Exception:
        pass

    actions = {
        "swapped_dead": swapped_dead,
        "marked_cold": marked_cold,
        "protected_hot": protected_hot,
        "reminiscence_bumped": bump_result.get("bumped", 0),
        "ebbinghaus_decayed": ebbinghaus_result.get("decayed", 0),
        "traces_cleaned": _cleaned_traces,
    }

    duration_ms = (_time.time() - _t_start) * 1000

    # ── Phase 3: Access Heatmap → dmesg ──
    hot_pct = round(hot_count / total_chunks * 100, 1) if total_chunks else 0
    warm_pct = round(warm_count / total_chunks * 100, 1) if total_chunks else 0
    cold_pct = round(len(cold_ids) / total_chunks * 100, 1) if total_chunks else 0
    dead_pct = round(len(dead_ids) / total_chunks * 100, 1) if total_chunks else 0

    dmesg_log(conn, DMESG_INFO, "damon",
              f"scan: total={total_chunks} hot={hot_count}({hot_pct}%) warm={warm_count}({warm_pct}%) "
              f"cold={len(cold_ids)}({cold_pct}%) dead={len(dead_ids)}({dead_pct}%) "
              f"actions: swapped={swapped_dead} marked_cold={marked_cold} protected={protected_hot} "
              f"{duration_ms:.1f}ms",
              project=project,
              extra={"heatmap": heatmap, "actions": actions, "hot_threshold": hot_threshold})

    return {
        "heatmap": heatmap,
        "actions": actions,
        "hot_threshold": hot_threshold,
        "duration_ms": round(duration_ms, 2),
    }

# ── Ebbinghaus Time-Decay（迭代470）────────────────────────────

def apply_ebbinghaus_decay(conn: sqlite3.Connection, project: str,
                            max_chunks: int = 100) -> dict:
    """
    迭代470：Ebbinghaus Time-Decay — 基于遗忘曲线将 importance 持久化衰减。

    OS 类比：Linux page aging clock — kswapd 定期将长时间未访问页降代；
      DAMON dead_region → madvise(MADV_COLD) — 持久化降温，不等下次回收触发。

    心理学：Ebbinghaus (1885) 遗忘曲线 R = e^(-t/S)
      - t = 自上次访问以来经过的时间（天）
      - S = stability（间隔重复稳定性，越高衰减越慢）
      - stability 高的 chunk（高频引用、SM-2加强的）衰减极慢
      - stability 低的 chunk（新写入、未被引用的）衰减快

    设计决策：
      - 虚拟衰减（scorer.py importance_with_decay）vs 持久化衰减（本函数）
        虚拟衰减：查询时实时计算有效 importance，不写 DB——对检索友好但不影响淘汰
        持久化衰减：写回 importance——影响 kswapd 淘汰评分、semantic 聚合、citation 统计
        两者互补：本函数负责持久化，避免长期 zombie chunks（高 importance 但从不被引用）
      - iter491 动态 cutoff：stability 越高保护期越长（高稳定 chunk 需要更长空闲才参与 decay）
        stability < 2.0 → cutoff=0.5天（新 chunk 快速响应）
        stability in [2.0, 5.0) → cutoff=1.0天（默认）
        stability in [5.0, 10.0) → cutoff=3.0天（已稳定，保护期）
        stability >= 10.0 → cutoff=7.0天（高度稳定，仅长期闲置才 decay）
      - 上界保护：oom_adj < 0（pinned chunk）跳过衰减
      - SKIP_CITATION_TYPES 跳过（系统记录不参与遗忘机制）
      - iter492 max_chunks 自动缩放：总 chunk 数影响每次扫描配额

    参数：
      max_chunks — 单次最多衰减的 chunk 数（避免单次扫描阻塞）；
                   iter492: 传入值为上限，实际值按项目规模自动缩放

    返回：
      {"decayed": N, "total_scanned": M}
    """
    import math

    # 非知识类 chunk 不参与时间衰减
    _SKIP_TYPES = frozenset({
        "task_state", "prompt_context", "conversation_summary",
        "session_summary", "goal",
    })

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # ── iter491: 动态 cutoff — stability-aware 扫描保护期 ─────────────────────
    # OS 类比：Linux MGLRU generation-aware reclaim horizon —
    #   每代（generation）有不同的 "min_age" 保护期，最年轻代（gen=0，刚被访问）
    #   至少需要经过 1 个 aging cycle 才会被扫描，高代（gen=N-1）立即可被回收。
    # 心理学：SuperMemo SM-2 — 高 stability（多次成功复习加强的知识）的复习间隔
    #   远大于低 stability（新知识或未被引用的知识）。同样，decay 扫描间隔也应随
    #   stability 线性增长，避免对稳定知识频繁执行无意义的 decay 计算。
    # 实现：通过多重 WHERE 子句分组，筛选出"已超过 stability 对应 cutoff"的 chunk。
    # 注意：SQLite 不支持动态行级 cutoff，采用分段 UNION ALL 查询或 Python 过滤：
    #   此处用 Python 过滤（先宽口查询，在循环中按 stability 动态跳过）以保持代码简洁。
    # 宽口 cutoff = 0.5 天（覆盖所有 stability 级别的最小保护期）
    _CUTOFF_WIDE = 0.5     # 宽口：新 chunk(stability<2.0) 的最小保护期
    _CUTOFF_MID = 1.0      # 默认 stability ∈ [2.0, 5.0)
    _CUTOFF_HIGH = 3.0     # stability ∈ [5.0, 10.0)
    _CUTOFF_VHIGH = 7.0    # stability >= 10.0

    cutoff_wide = (now - timedelta(days=_CUTOFF_WIDE)).isoformat()

    # ── iter492: max_chunks 自动缩放 ──────────────────────────────────────────
    # OS 类比：Linux kswapd scan_control.nr_to_scan — 根据内存压力等级动态调整
    #   单次 LRU 扫描的页面数量。压力越大扫描越多；内存充裕时扫描更少（降低 overhead）。
    # 心理学：工作记忆容量适应（Cowan 2001）— 大项目有更多知识需要维护，
    #   但每次扫描也需要控制计算成本，否则 kswapd 响应时间增长。
    # 公式：
    #   total <= 50  → scan_max = total（全扫，小项目不遗漏）
    #   total <= 200 → scan_max = max(50, total // 3)
    #   total > 200  → scan_max = max(100, min(max_chunks, total // 5))
    try:
        total_chunks = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project=? AND importance > 0.05",
            (project,)
        ).fetchone()[0] or 0
    except Exception:
        total_chunks = 0

    if total_chunks <= 50:
        effective_max = min(max_chunks, total_chunks) if total_chunks > 0 else max_chunks
    elif total_chunks <= 200:
        effective_max = max(50, min(max_chunks, total_chunks // 3))
    else:
        effective_max = max(100, min(max_chunks, total_chunks // 5))

    # iter486: MGLRU-style 分代扫描 — 优先 decay 冷 chunk（lru_gen 大 = 更冷）。
    # OS 类比：Linux MGLRU kswapd — 总是从最老代（gen=N-1）开始 reclaim，
    #   热页（gen=0）最后处理。同样地，lru_gen 大的 chunk 最先被 Ebbinghaus 衰减。
    # 心理学：记忆巩固层次（Squire 1992）— 长期未激活（冷）的记忆优先进入遗忘，
    #   而工作记忆中频繁激活（热）的记忆即使超过1天也应最后处理。
    # 双重排序：先按 lru_gen DESC（冷优先），再按 last_accessed ASC（同代内按时序）
    # iter491: 用宽口 cutoff（0.5天），Python 层按 stability 动态过滤
    rows = conn.execute(
        """SELECT id, importance, stability, last_accessed, chunk_type, confidence_score,
                  COALESCE(verification_status, 'pending'),
                  COALESCE(oom_adj, 0)
           FROM memory_chunks
           WHERE project=?
             AND last_accessed < ?
             AND COALESCE(oom_adj, 0) >= 0
             AND importance > 0.05
           ORDER BY COALESCE(lru_gen, 0) DESC, last_accessed ASC
           LIMIT ?""",
        (project, cutoff_wide, effective_max * 3)  # 取 3× 供 iter491 Python 过滤后仍有足够候选
    ).fetchall()

    # 高稳定性 chunk 的下界保护（iter470）
    # 心理学：知识结晶化（crystallized knowledge, Cattell 1971）——
    #   高频使用、高稳定性的陈述性知识不会轻易遗忘，即使暂时不激活
    # OS 类比：Linux huge page lock — mlock() 的高稳定性内存页不被 swap 降到物理限制以下
    # 实现：stability >= STABILITY_FLOOR_THRESHOLD → 下界提高为 STABILITY_HIGH_FLOOR
    _STABILITY_FLOOR_THRESHOLD = 5.0   # stability >= 5：历史证明重要
    _STABILITY_HIGH_FLOOR = 0.10       # 高稳定 chunk 的 importance 下界（高于全局 0.05）
    _GLOBAL_FLOOR = 0.05               # 普通 chunk 下界

    # iter478: confidence 衰减常数 — 衰减速率为 importance 的一半
    # 心理学：知识可信度（epistemological confidence）衰减比记忆强度（importance）慢；
    #   未被验证的记忆可信度随时间降低（source monitoring theory, Johnson 1993）
    # OS 类比：Linux ECC memory status — 长期未读取验证的 page 的 ECC 状态降为 unknown
    # iter488: per-type confidence decay factor
    # 心理学：不同类型知识的认知可信度衰减速率不同
    #   - reasoning_chain/procedure：演绎推理步骤，可能过时（FACTOR=1.5 — 较快）
    #   - design_constraint：规范性知识，不随时间失效（FACTOR=6.0 — 极慢）
    #   - 其余：默认 2.0（decision, decision_log, episodic 等）
    # 注意：task_state/prompt_context 在 _SKIP_TYPES 中，不参与 decay，故不设 fast factor
    # OS 类比：Linux page type hot/cold tier — 不同类型的内存（anonymous vs file-backed）
    #   有不同的 swap out 策略；规范性知识如 tmpfs（不 swap），时效性知识如 anonymous（优先 swap）
    _CONFIDENCE_DECAY_FACTOR_DEFAULT = 2.0
    _CONFIDENCE_DECAY_FACTOR_FAST = 1.5   # reasoning_chain/procedure — 时效推理衰减较快
    _CONFIDENCE_DECAY_FACTOR_SLOW = 6.0   # design_constraint — 规范知识极慢衰减
    _CONFIDENCE_FAST_TYPES = frozenset({"reasoning_chain", "procedure"})
    _CONFIDENCE_SLOW_TYPES = frozenset({"design_constraint"})
    _MIN_CONFIDENCE = 0.10           # confidence 下界

    decayed = 0
    decayed_ids: set = set()
    # iter492: 实际处理上限（Python 层截断，限制写入次数）
    processed = 0
    for cid, imp, stab, la, ctype, conf, vstatus, oom_adj in rows:
        if processed >= effective_max:
            break
        if (ctype or "") in _SKIP_TYPES:
            continue
        # iter484: verified chunk 豁免 Ebbinghaus decay
        # 心理学：外部验证的知识（verified by external source/human）不受遗忘影响；
        #   Bartlett (1932) schema theory — 与 schema 一致且被验证的知识异常稳定。
        # OS 类比：Linux page pinned via get_user_pages() — 被外部 DMA 锁定的页不参与 reclaim。
        if vstatus == "verified":
            continue
        if not la or not imp or not stab:
            continue

        try:
            la_dt = datetime.fromisoformat(la.replace("Z", "+00:00"))
            delta_days = (now - la_dt).total_seconds() / 86400.0
        except Exception:
            continue

        # ── iter491: stability-aware 动态 cutoff ──────────────────────────────
        # 根据 chunk 的 stability 确定其最小保护期，未达到保护期的 chunk 跳过
        # OS 类比：Linux MGLRU min_age — 每代页面有最小驻留时间，防止抖动（thrashing）
        # 心理学：SuperMemo SM-2 — stability 高的记忆复习间隔更长；
        #   类似地，decay 检查间隔也应随 stability 成比例扩大。
        effective_stab_val = float(stab or 1.0)
        if effective_stab_val >= 10.0:
            required_days = _CUTOFF_VHIGH     # 7天
        elif effective_stab_val >= 5.0:
            required_days = _CUTOFF_HIGH      # 3天
        elif effective_stab_val >= 2.0:
            required_days = _CUTOFF_MID       # 1天
        else:
            required_days = _CUTOFF_WIDE      # 0.5天

        if delta_days < required_days:
            continue  # 未达到 stability 对应的保护期，跳过

        processed += 1

        # 根据 stability 选择下界：高稳定 chunk 保护下界
        # iter491: effective_stab_val 已在动态 cutoff 中计算，直接复用
        effective_stab = max(0.1, effective_stab_val)
        floor = _STABILITY_HIGH_FLOOR if effective_stab >= _STABILITY_FLOOR_THRESHOLD else _GLOBAL_FLOOR

        # Ebbinghaus: R = e^(-t/S), 新 importance = old × R
        decay_factor = math.exp(-delta_days / effective_stab)
        new_imp = max(floor, float(imp) * decay_factor)

        # iter478/iter488: confidence_score 时间衰减（per-type factor）
        # 公式：new_conf = old × exp(-t / (S × TYPE_CONFIDENCE_FACTOR))
        # iter488: 时效性知识（task_state/prompt_context）衰减更快，规范知识极慢
        old_conf = float(conf or 0.7)
        _ctype_factor = (
            _CONFIDENCE_DECAY_FACTOR_FAST if (ctype or "") in _CONFIDENCE_FAST_TYPES
            else _CONFIDENCE_DECAY_FACTOR_SLOW if (ctype or "") in _CONFIDENCE_SLOW_TYPES
            else _CONFIDENCE_DECAY_FACTOR_DEFAULT
        )
        conf_decay_factor = math.exp(-delta_days / (effective_stab * _ctype_factor))
        new_conf = max(_MIN_CONFIDENCE, old_conf * conf_decay_factor)

        imp_changed = float(imp) - new_imp >= 0.005
        conf_changed = old_conf - new_conf >= 0.003

        # 任一字段有实质变化才写入
        if not imp_changed and not conf_changed:
            continue

        # ── B11: MGLRU-style OOM adj bump on low importance ───────────────
        # OS 类比：Linux MGLRU kswapd — page 落入最老代（gen=0，可回收）时
        #   oom_score 自动升高，使其在下次内存压力时优先被驱逐。
        # 人类记忆：Atkinson-Shiffrin (1968) 记忆衰退模型 — importance 持续
        #   低于阈值的记忆进入"遗忘候选"状态，不再主动干扰工作记忆。
        # 机制：new_imp < 0.1 且 oom_adj < 300 → oom_adj += 300（标记淘汰候选）
        #   oom_adj 已 >= 300 则不重复累加（幂等性）
        #   豁免：design_constraint（架构约束不参与自动淘汰）
        _oom_adj_bump = 0
        if (new_imp < 0.1
                and (ctype or "") != "design_constraint"
                and (oom_adj or 0) < 300):
            _oom_adj_bump = 300 - (oom_adj or 0)  # bump 到 300
            conn.execute(
                "UPDATE memory_chunks SET oom_adj=? WHERE id=?",
                ((oom_adj or 0) + _oom_adj_bump, cid)
            )

        conn.execute(
            "UPDATE memory_chunks SET importance=?, confidence_score=?, updated_at=? WHERE id=?",
            (round(new_imp, 4) if imp_changed else float(imp),
             round(new_conf, 4) if conf_changed else old_conf,
             now_iso, cid)
        )
        decayed += 1
        decayed_ids.add(cid)

    return {"decayed": decayed, "total_scanned": len(rows), "decayed_ids": decayed_ids}


# ── MGLRU — Multi-Gen LRU（迭代44）────────────────────────────

# 上次 aging 时间戳文件（防止频繁 /clear 导致过度 aging）
_MGLRU_AGING_TS_FILE = MEMORY_OS_DIR / ".mglru_last_aging"


def mglru_aging(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代44：MGLRU aging — 所有 chunk 的 generation number 递增一代。
    OS 类比：Linux MGLRU (Multi-Gen LRU, Yu Zhao/Google, 2022, Linux 6.1)

    Linux MGLRU 背景：
      传统 LRU 只有 2 个链表（active/inactive），分界线是全局的：
        - 新页面加入 active list
        - 长时间未被访问降到 inactive list
        - inactive 页面被 kswapd 回收
      问题：
        1. 只有 2 级粒度，高频/中频/低频页面混在一起
        2. 大内存系统扫描 inactive list 是 O(N)
        3. 新页面和旧热页面共享 active list，竞争激烈

      MGLRU (Yu Zhao, Google, 2022) 引入 generation number：
        - gen 0 = youngest（刚被访问/刚写入）
        - gen max = oldest（最久未被访问）
        - 每个 clock tick（定期扫描），所有页面 gen += 1
        - 页面被访问时 gen 重置为 0（promote 到最年轻代）
        - eviction 从 gen max 开始回收（最老代优先）
        - 多代粒度比 2-list LRU 更精确地描述页面热度

      benchmark: MGLRU 在 Chrome OS / Android / 服务器场景中
      将 kswapd CPU 使用率降低 40-60%，同时减少 false positive eviction。

    memory-os 当前问题：
      迭代34 Second Chance 给新 chunk 一个 grace period，
      但过了 grace period 后，所有"不够新也不够热"的 chunk 都在同一层——
      一个 30 天未访问的 chunk 和一个 3 天未访问的 chunk 在 kswapd 看来
      差距只由 recency_score (1/(1+age_days)) 体现，区分度不足。

      MGLRU 给每个 chunk 一个离散的"代"标记：
        gen 0: 刚被访问或写入（当前活跃）
        gen 1: 上一个 session tick 后未被访问
        gen 2: 两个 session tick 后未被访问
        gen 3+: 多个 tick 后未被访问（冷/死亡候选）

      kswapd/evict 优先从最高 gen 开始回收，
      比纯 recency_score 连续值更稳定（不受时间精度影响）。

    aging 时机：
      每次 SessionStart（loader.py）调用。
      频率控制：两次 aging 之间间隔 ≥ aging_interval_hours（默认 6h），
      防止频繁 /clear 导致 chunk 过度老化。

    算法：
      1. 检查距上次 aging 是否 ≥ interval
      2. 全表 UPDATE lru_gen = min(lru_gen + 1, max_gen)
      3. 记录本次 aging 时间戳
      4. 返回统计信息

    参数：
      conn — 数据库连接
      project — 项目 ID

    返回 dict：
      aged — bool，是否执行了 aging
      reason — 跳过或执行的原因
      affected_count — 被 aging 的 chunk 数
      gen_distribution — aging 后各代 chunk 分布
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"aged": False, "reason": "config_unavailable", "affected_count": 0}

    max_gen = _cfg("mglru.max_gen")
    interval_hours = _cfg("mglru.aging_interval_hours")

    # ── 频率控制：防止频繁 /clear 导致过度 aging ──
    now = datetime.now(timezone.utc)
    try:
        if _MGLRU_AGING_TS_FILE.exists():
            last_ts_str = _MGLRU_AGING_TS_FILE.read_text(encoding="utf-8").strip()
            last_ts = datetime.fromisoformat(last_ts_str)
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            hours_since = (now - last_ts).total_seconds() / 3600
            if hours_since < interval_hours:
                return {"aged": False, "reason": f"too_recent ({hours_since:.1f}h < {interval_hours}h)",
                        "affected_count": 0}
    except Exception:
        pass  # 文件不存在或解析失败 → 执行 aging

    # ── 执行 aging：所有 project 的 chunk gen += 1，上限 max_gen ──
    # OS 类比：MGLRU 的 lru_gen_inc() — clock tick 推进所有页面的 generation
    # 修复：原来只 age 当前 project，导致历史 project（abspath 变化后）的
    # chunks 永远停在 gen=0，无法被 kswapd 淘汰。改为全库 aging。
    affected = conn.execute(
        """UPDATE memory_chunks
           SET lru_gen = MIN(COALESCE(lru_gen, 0) + 1, ?)
             WHERE COALESCE(lru_gen, 0) < ?""",
        (max_gen, max_gen),
    ).rowcount

    # 记录时间戳
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        _MGLRU_AGING_TS_FILE.write_text(now.isoformat(), encoding="utf-8")
    except Exception:
        pass

    # ── gen 分布统计（全库）──
    gen_dist = {}
    for row in conn.execute(
        "SELECT COALESCE(lru_gen, 0), COUNT(*) FROM memory_chunks GROUP BY COALESCE(lru_gen, 0) ORDER BY 1",
    ).fetchall():
        gen_dist[f"gen{row[0]}"] = row[1]

    # dmesg 记录
    dmesg_log(conn, DMESG_INFO, "mglru",
              f"aging: affected={affected} max_gen={max_gen} dist={gen_dist}",
              project=project)

    return {
        "aged": True,
        "reason": "interval_elapsed",
        "affected_count": affected,
        "gen_distribution": gen_dist,
    }


def mglru_promote(conn: sqlite3.Connection, chunk_ids: list) -> int:
    """
    迭代44：MGLRU promote — 被访问的 chunk 晋升到 gen 0（最年轻代）。
    OS 类比：MGLRU 的 folio_inc_gen() / lru_gen_addition()
      当 MMU 的 Accessed bit 被置位（页面被读/写），
      MGLRU 将该页面的 gen 重置为 0（youngest generation）。
      这等价于"续命"——被访问的页面不会因为全局 aging 而变老。

    调用时机：
      retriever.py 检索命中后，对 Top-K chunk 调用 mglru_promote。
      与 update_accessed 配合：
        update_accessed → 更新 last_accessed + access_count（连续量）
        mglru_promote  → 重置 lru_gen 到 0（离散代标记）

    参数：
      conn — 数据库连接
      chunk_ids — 被访问的 chunk ID 列表

    返回 promote 的 chunk 数。
    """
    if not chunk_ids:
        return 0
    placeholders = ",".join("?" * len(chunk_ids))
    return conn.execute(
        f"UPDATE memory_chunks SET lru_gen = 0 WHERE id IN ({placeholders})",
        chunk_ids,
    ).rowcount


def mglru_stats(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代44：MGLRU 统计 — 各代 chunk 分布和冷热比例。
    OS 类比：cat /sys/kernel/mm/lru_gen/enabled + debugfs lru_gen 统计

    返回 dict：
      gen_distribution — {gen0: N, gen1: N, ...} 各代 chunk 数量
      hot_pct — gen 0-1 的比例（活跃 chunk）
      cold_pct — gen >= max_gen-1 的比例（冷 chunk）
      total — 总 chunk 数
    """
    try:
        from config import get as _cfg
        max_gen = _cfg("mglru.max_gen")
    except Exception:
        max_gen = 4

    rows = conn.execute(
        "SELECT COALESCE(lru_gen, 0), COUNT(*) FROM memory_chunks WHERE project = ? GROUP BY COALESCE(lru_gen, 0) ORDER BY 1",
        (project,),
    ).fetchall()

    gen_dist = {}
    total = 0
    hot = 0
    cold = 0
    for gen, cnt in rows:
        gen_dist[f"gen{gen}"] = cnt
        total += cnt
        if gen <= 1:
            hot += cnt
        if gen >= max_gen - 1:
            cold += cnt

    return {
        "gen_distribution": gen_dist,
        "hot_pct": round(hot / total * 100, 1) if total else 0,
        "cold_pct": round(cold / total * 100, 1) if total else 0,
        "total": total,
        "max_gen": max_gen,
    }

# ── Memory Balloon — 弹性配额动态分配（迭代46）─────────────────

def balloon_quota(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代46：Memory Balloon — 弹性配额动态分配。
    OS 类比：KVM/Xen Memory Balloon Driver (2003 → virtio-balloon 2008)

    虚拟化背景：
      物理主机的 RAM 有限，但多个 VM 共享这些内存。
      固定分配（static partitioning）问题：
        - VM1 分配 4GB，但只用 1GB → 3GB 浪费
        - VM2 分配 4GB，实际需要 6GB → OOM Kill
      Memory Balloon 驱动（VMware 2003 / Xen / KVM virtio-balloon 2008）：
        - 宿主机通过 balloon 驱动向 VM 发送 inflate/deflate 指令
        - inflate（充气）：balloon 驱动在 VM 内分配页面并返还给宿主机 → VM 可用内存减少
        - deflate（放气）：宿主机释放页面给 VM → VM 可用内存增加
        - 效果：空闲 VM 的内存被动态回收给繁忙 VM，无需重启
      KSM (Kernel Same-page Merging) 是另一种优化（迭代16已实现），
      balloon 是配额层面的动态调整。

    memory-os 当前问题：
      extractor.chunk_quota=200（固定值，所有项目相同）。
      但项目活跃度差异巨大：
        - 活跃项目（每天多次 session）：200 不够用，频繁触发 kswapd 淘汰
        - 不活跃项目（几周没碰）：200 中大部分是 stale chunk 占位
      固定配额无法适应多项目多租户的动态需求。

    解决：
      全局 pool（默认 1000 chunks）在所有项目间按活跃度动态分配：
      1. 扫描所有项目的活跃度（activity_window 内的写入/访问次数）
      2. 按活跃度加权分配 pool（加权公式：activity_score = writes + accesses × 0.5）
      3. 每个项目的配额 = max(min_quota, min(max_quota, weighted_share))
      4. 不活跃项目自动缩减到 min_quota（balloon inflate — 释放容量）
      5. 活跃项目自动扩展到更大配额（balloon deflate — 获得更多容量）

    参数：
      conn — 数据库连接
      project — 当前项目 ID

    返回 dict：
      quota — 当前项目的动态配额
      activity_score — 当前项目的活跃度分数
      total_projects — 参与分配的项目数
      pool_size — 全局 pool 大小
      fallback — 是否降级到固定配额（数据不足时）
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"quota": 200, "activity_score": 0, "total_projects": 1,
                "pool_size": 1000, "fallback": True}

    global_pool = _cfg("balloon.global_pool")
    min_quota = _cfg("balloon.min_quota")
    max_quota = _cfg("balloon.max_quota")
    window_days = _cfg("balloon.activity_window_days")

    # ── 扫描所有项目的活跃度 ──
    # activity_score = 近期 chunk 数 + 近期 access 的 chunk 数 × 0.5
    # OS 类比：宿主机轮询各 VM 的 memory.stat 获取活跃页面统计
    try:
        rows = conn.execute(
            """SELECT project,
                      COUNT(*) as chunk_count,
                      SUM(CASE WHEN julianday('now') - julianday(created_at) <= ? THEN 1 ELSE 0 END) as recent_writes,
                      SUM(CASE WHEN COALESCE(access_count, 0) > 0
                                AND julianday('now') - julianday(last_accessed) <= ? THEN 1 ELSE 0 END) as recent_accesses
               FROM memory_chunks
               GROUP BY project""",
            (window_days, window_days),
        ).fetchall()
    except Exception:
        # 数据库问题 → 降级到固定配额
        return {"quota": _cfg("extractor.chunk_quota"), "activity_score": 0,
                "total_projects": 1, "pool_size": global_pool, "fallback": True}

    if not rows:
        return {"quota": min(max_quota, max(min_quota, global_pool)),
                "activity_score": 0, "total_projects": 0,
                "pool_size": global_pool, "fallback": False}

    # ── 计算各项目活跃度 ──
    project_scores = {}
    for proj, chunk_count, recent_writes, recent_accesses in rows:
        recent_writes = recent_writes or 0
        recent_accesses = recent_accesses or 0
        # 活跃度 = 近期写入 + 近期被访问 × 0.5 + 存量 × 0.1（保底权重）
        score = recent_writes + recent_accesses * 0.5 + chunk_count * 0.1
        project_scores[proj] = max(score, 1.0)  # 最低 1.0 保底

    total_score = sum(project_scores.values())
    num_projects = len(project_scores)

    # ── 按活跃度加权分配 ──
    # 预留 min_quota × num_projects 作为保障，剩余按活跃度分配
    reserved = min_quota * num_projects
    distributable = max(0, global_pool - reserved)

    my_score = project_scores.get(project, 1.0)
    my_share = (my_score / total_score) * distributable if total_score > 0 else 0
    my_quota = int(min_quota + my_share)

    # 范围钳位
    my_quota = max(min_quota, min(max_quota, my_quota))

    return {
        "quota": my_quota,
        "activity_score": round(my_score, 1),
        "total_projects": num_projects,
        "pool_size": global_pool,
        "fallback": False,
    }

# ── 迭代48：Readahead — Co-Access Prefetch ──────────────────────────
# OS 类比：Linux readahead (generic_file_readahead, 2002→2004)
#
# Linux readahead 背景：
#   当进程读取文件时，内核检测到顺序访问模式，提前将后续 block 读入 page cache。
#   不等进程请求就预取，减少 I/O 等待。关键数据结构 struct file_ra_state
#   追踪每个 fd 的 readahead 窗口（start/size/async_size）。
#
#   memory-os 等价问题：
#     retriever 只返回当前 query 命中的 chunk。但某些 chunk 总是一起被需要：
#     如 "选择 React" 和 "排除 Vue" 是同一决策的两面。
#     每次只返回 "选择 React" 而缺少 "排除 Vue"，上下文不完整。
#
#   解决：
#     从 recall_traces.top_k_json 分析历史上哪些 chunk 频繁共同出现（co-access）。
#     当 chunk A 被检索命中时，如果 chunk B 与 A 共现次数 ≥ min_cooccurrence，
#     且 B 不在当前结果中，则将 B 作为 prefetch candidate 注入，
#     给予 prefetch_bonus 加分（不改变排序主权重，仅作为补充信号）。

def readahead_pairs(conn: sqlite3.Connection, project: str,
                    hit_ids: list = None) -> dict:
    """
    从 recall_traces 分析共现模式，返回 readahead pair 映射。
    OS 类比：file_ra_state — 追踪每个 fd 的 readahead 窗口。

    算法：
      1. 取最近 window_traces 条 injected=1 的 trace
      2. 解析每条 trace 的 top_k_json → 提取 chunk_id 集合
      3. 对每对 (id_a, id_b) 在同一次检索中共现，计数 +1
      4. 过滤 count >= min_cooccurrence 的 pair
      5. 如果提供了 hit_ids，只返回与 hit_ids 相关的 pair

    返回：
      {chunk_id: [(partner_id, cooccurrence_count), ...], ...}
      按 cooccurrence_count 降序排列
    """
    from config import get as _cfg
    window = _cfg("readahead.window_traces")
    min_co = _cfg("readahead.min_cooccurrence")

    rows = conn.execute(
        """SELECT top_k_json FROM recall_traces
           WHERE project=? AND injected=1
           ORDER BY timestamp DESC LIMIT ?""",
        (project, window)
    ).fetchall()

    if not rows:
        return {}

    # ── 统计共现计数 ──
    from collections import defaultdict
    pair_counts = defaultdict(int)  # (id_a, id_b) → count, id_a < id_b

    for (top_k_raw,) in rows:
        try:
            top_k = json.loads(top_k_raw) if isinstance(top_k_raw, str) else top_k_raw
        except Exception:
            continue
        if not isinstance(top_k, list):
            continue
        ids = [item["id"] for item in top_k if isinstance(item, dict) and "id" in item]
        if len(ids) < 2:
            continue
        # 两两组合
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = (ids[i], ids[j]) if ids[i] < ids[j] else (ids[j], ids[i])
                pair_counts[(a, b)] += 1

    # ── 过滤低共现 pair ──
    result = defaultdict(list)
    for (a, b), count in pair_counts.items():
        if count < min_co:
            continue
        result[a].append((b, count))
        result[b].append((a, count))

    # ── 按共现次数降序排列 ──
    for k in result:
        result[k].sort(key=lambda x: x[1], reverse=True)

    # ── 如果指定了 hit_ids，只返回相关 pair ──
    if hit_ids is not None:
        hit_set = set(hit_ids)
        filtered = {}
        for cid in hit_set:
            if cid in result:
                # 排除已在 hit_ids 中的 partner（不需要 prefetch 已命中的）
                partners = [(pid, cnt) for pid, cnt in result[cid] if pid not in hit_set]
                if partners:
                    filtered[cid] = partners
        return filtered

    return dict(result)

# ── io_uring — Batched Submission Queue（迭代49）──────────────────
# OS 类比：Linux io_uring (Jens Axboe, Linux 5.1, 2019)
#
# io_uring 背景：
#   传统 Linux I/O 模型（read/write/pread/pwrite）每次 I/O 是一次 syscall。
#   高 IOPS 场景（NVMe SSD 可达 100 万 IOPS）下 syscall 开销成为瓶颈：
#     - 每次 syscall 需要 user→kernel 模式切换（~1μs）
#     - 100 万 IOPS × 1μs = 1 秒纯 syscall 开销
#   aio (Linux 2.5, 2002) 尝试解决但 API 复杂、限制多（仅支持 O_DIRECT）。
#
#   io_uring (Jens Axboe, 2019) 引入 ring buffer 共享内存模型：
#     1. io_uring_setup() — 创建 SQ (Submission Queue) + CQ (Completion Queue)
#        两个 ring buffer 映射到 user/kernel 共享内存
#     2. io_uring_prep_*() — 应用程序向 SQ 填入 I/O 请求（无 syscall）
#     3. io_uring_submit() — 一次 syscall 批量提交 SQ 中所有请求
#     4. io_uring_wait_cqe() — 从 CQ 读取完成通知
#
#   关键创新：
#     - 批量提交（batching）：N 个 I/O 请求只需 1 次 syscall
#     - 零拷贝通知：SQ/CQ 在共享内存中，无需数据拷贝
#     - 链式请求（SQE linking）：多个 SQE 串联，前一个完成后自动提交下一个
#
#   benchmark: 随机 4K 读写从 ~400K IOPS (aio) 提升到 >1M IOPS (io_uring)
#
# memory-os 当前问题：
#   extractor.py 对每个提取的 chunk 逐一调用 _write_chunk()：
#     for summary in decisions:
#         _write_chunk("decision", summary, ...)  # 1 次 already_exists + 1 次 merge_similar + 1 次 INSERT + 1 次 commit
#     for summary in excluded:
#         _write_chunk("excluded_path", summary, ...)
#   假设提取 9 个 chunk：9 × (SELECT + Jaccard全表扫描 + INSERT + COMMIT) = 36 次 DB 操作。
#   每次 _write_chunk 的 conn.commit() 触发 SQLite WAL fsync。
#
# 解决：
#   io_uring_sq — Submission Queue 收集所有待写入 chunk
#   io_uring_submit — 一次性批量执行：
#     Phase 1: 批量去重（一次 SELECT IN 替代 N 次 already_exists）
#     Phase 2: 批量 KSM merge（一次性加载 + Jaccard）
#     Phase 3: 批量 INSERT（executemany 替代 N 次 execute）
#     Phase 4: 单次 commit
#   36 次 DB 操作 → 约 4 次（1 SELECT + 1 Jaccard scan + 1 executemany + 1 commit）


class IoUringSQ:
    """
    io_uring Submission Queue — 收集写入请求，延迟到 submit 时批量执行。
    OS 类比：struct io_uring_sqe — 每个 SQE 描述一个 I/O 请求。

    用法：
        sq = IoUringSQ()
        sq.prep_write("decision", "选择 React", project, session_id, topic, importance=0.85)
        sq.prep_write("excluded_path", "排除 Vue", project, session_id, topic, importance=0.70)
        result = sq.submit(conn)
        # result: {"submitted": 2, "inserted": 1, "merged": 1, "skipped_dup": 0}
    """

    def __init__(self):
        self._entries = []  # list of SQE dicts

    def prep_write(self, chunk_type: str, summary: str, project: str,
                   session_id: str, topic: str = "",
                   importance: float = None, retrievability: float = None) -> None:
        """
        io_uring_prep_write() — 向 SQ 添加一个写入请求。
        不执行任何 I/O，只记录请求参数。
        """
        importance_map = {
            "decision": 0.85,
            "reasoning_chain": 0.80,
            "excluded_path": 0.70,
            "conversation_summary": 0.65,
        }
        if importance is None:
            importance = importance_map.get(chunk_type, 0.70)
        if retrievability is None:
            retrievability = 0.2 if chunk_type == "reasoning_chain" else 0.35

        self._entries.append({
            "chunk_type": chunk_type,
            "summary": summary,
            "project": project,
            "session_id": session_id,
            "topic": topic,
            "importance": importance,
            "retrievability": retrievability,
        })

    def depth(self) -> int:
        """返回 SQ 中待提交的请求数。OS 类比：io_uring_sq_ready()。"""
        return len(self._entries)

    def submit(self, conn: sqlite3.Connection) -> dict:
        """
        io_uring_submit() — 一次性批量执行所有 SQ 中的写入请求。

        Phase 1: 批量去重（Batch Dedup）
          用一次 SELECT ... WHERE summary IN (...) 替代 N 次 already_exists()。

        Phase 2: 批量 KSM merge
          只加载一次全表 summary → Jaccard，找到可合并的统一处理。

        Phase 3: 批量 INSERT
          用 executemany 替代 N 次 execute。

        Phase 4: 单次 commit
          由调用方负责 commit（与 Per-Request Connection Scope 保持一致）。

        返回 CQE (Completion Queue Entry) 汇总：
          submitted — SQ 中的请求总数
          inserted — 成功插入的新 chunk 数
          merged — KSM 合并的 chunk 数
          skipped_dup — 去重跳过的 chunk 数
          skipped_quality — 质量过滤跳过的 chunk 数
        """
        if not self._entries:
            return {"submitted": 0, "inserted": 0, "merged": 0,
                    "skipped_dup": 0, "skipped_quality": 0}

        from schema import MemoryChunk

        total = len(self._entries)
        inserted = 0
        merged = 0
        skipped_dup = 0
        skipped_quality = 0

        # ── Phase 1: Batch Dedup — 一次 SELECT 替代 N 次 already_exists ──
        # OS 类比：io_uring SQE 链中的 barrier flag — 一次系统调用做批量检查
        all_summaries = [e["summary"] for e in self._entries]
        existing_summaries = set()
        if all_summaries:
            # 分批查询（SQLite 变量限制 999）
            batch_size = 900
            for i in range(0, len(all_summaries), batch_size):
                batch = all_summaries[i:i + batch_size]
                placeholders = ",".join("?" * len(batch))
                rows = conn.execute(
                    f"SELECT summary FROM memory_chunks WHERE summary IN ({placeholders}) "
                    f"AND chunk_type IN ('decision','excluded_path','reasoning_chain','conversation_summary')",
                    batch
                ).fetchall()
                existing_summaries.update(r[0] for r in rows)

        # 过滤已存在的
        new_entries = []
        for entry in self._entries:
            if entry["summary"] in existing_summaries:
                skipped_dup += 1
            else:
                new_entries.append(entry)

        if not new_entries:
            return {"submitted": total, "inserted": 0, "merged": 0,
                    "skipped_dup": skipped_dup, "skipped_quality": 0}

        # ── Phase 2: Batch KSM Merge — 一次加载 + 批量 Jaccard ──
        # OS 类比：KSM ksmd 线程一次扫描 pages_to_scan 个页面找相同页
        # 按 chunk_type 分组，每种类型只加载一次已有 summary
        types_needed = set(e["chunk_type"] for e in new_entries)
        type_summaries_cache = {}  # chunk_type → [(id, summary, tokens)]
        for ct in types_needed:
            rows = conn.execute(
                "SELECT id, summary FROM memory_chunks WHERE chunk_type=? AND summary!=''",
                (ct,)
            ).fetchall()
            cached = []
            for rid, existing_summary in rows:
                tokens = _sq_tokenize(existing_summary)
                if tokens:
                    cached.append((rid, existing_summary, tokens))
            type_summaries_cache[ct] = cached

        to_insert = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for entry in new_entries:
            summary = entry["summary"]
            chunk_type = entry["chunk_type"]
            importance = entry["importance"]

            # KSM Jaccard 检查
            q_tokens = _sq_tokenize(summary)
            if not q_tokens:
                skipped_quality += 1
                continue

            merged_this = False
            for rid, _, d_tokens in type_summaries_cache.get(chunk_type, []):
                intersection = len(q_tokens & d_tokens)
                union = len(q_tokens | d_tokens)
                jaccard = intersection / union if union > 0 else 0.0
                if jaccard >= 0.5:
                    # Merge: 更新已有 chunk 的 importance
                    conn.execute(
                        "UPDATE memory_chunks SET importance=MAX(importance, ?), last_accessed=?, updated_at=? WHERE id=?",
                        (importance, now_iso, now_iso, rid),
                    )
                    merged += 1
                    merged_this = True
                    break

            if not merged_this:
                # ── iter541: inode_permission — 统一写入门控 ──────────────────
                # OS 类比：Linux inode_permission() (Al Viro, 1999) — VFS 层强制权限检查，
                # 无论哪条 syscall 路径（open/creat/link/rename）到达文件系统，
                # 都必须经过 inode_permission()。此前 IoUringSQ 直接 INSERT 绕过了
                # _vfs_write_protect()，导致表格行碎片泄漏到生产 DB。
                try:
                    from store_vfs import _vfs_write_protect
                    if _vfs_write_protect(summary):
                        skipped_quality += 1
                        continue
                except ImportError:
                    pass
                # 准备 INSERT
                tags = [chunk_type, entry["project"]]
                if entry["topic"]:
                    tags.append(entry["topic"][:30])
                content = f"[{chunk_type}] {summary}"
                if entry["topic"]:
                    content = f"[{chunk_type}|{entry['topic']}] {summary}"

                chunk = MemoryChunk(
                    project=entry["project"],
                    source_session=entry["session_id"],
                    chunk_type=chunk_type,
                    content=content,
                    summary=summary,
                    tags=tags,
                    importance=importance,
                    retrievability=entry["retrievability"],
                )
                to_insert.append(chunk.to_dict())

                # 更新缓存（新插入的也参与后续 Jaccard 检查，防止 SQ 内部重复）
                type_summaries_cache.setdefault(chunk_type, []).append(
                    (chunk.to_dict()["id"], summary, q_tokens)
                )

        # ── Phase 3: Batch INSERT — executemany 替代 N 次 execute ──
        # OS 类比：io_uring SQ ring 一次 submit 提交全部 SQE
        if to_insert:
            insert_data = []
            for d in to_insert:
                tags_json = json.dumps(d["tags"], ensure_ascii=False) if isinstance(d.get("tags"), list) else d.get("tags", "[]")
                insert_data.append((
                    d["id"], d["created_at"], d["updated_at"], d["project"], d["source_session"],
                    d["chunk_type"], d["content"], d["summary"], tags_json,
                    d["importance"], d["retrievability"], d["last_accessed"], d.get("feishu_url"),
                ))
            conn.executemany("""
                INSERT OR REPLACE INTO memory_chunks
                (id, created_at, updated_at, project, source_session,
                 chunk_type, content, summary, tags, importance,
                 retrievability, last_accessed, feishu_url)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, insert_data)
            inserted = len(insert_data)

        # Phase 4: commit 由调用方负责（Per-Request Connection Scope 原则）
        # 清空 SQ
        self._entries.clear()

        return {
            "submitted": total,
            "inserted": inserted,
            "merged": merged,
            "skipped_dup": skipped_dup,
            "skipped_quality": skipped_quality,
        }


def _sq_tokenize(text: str) -> set:
    """
    io_uring SQ 内部用的 tokenizer — 与 find_similar 的 _tok 保持一致。
    提取英文词 + 中文 bigram。
    """
    tokens = set()
    for m in re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', text):
        tokens.add(m.group().lower())
    cn = re.sub(r'[^\u4e00-\u9fff]', '', text)
    for i in range(len(cn) - 1):
        tokens.add(cn[i:i + 2])
    return tokens

# ── 迭代50：TCP AIMD — Adaptive Extraction Window ──────────────────────
#
# OS 类比：TCP Congestion Control AIMD (Jacobson/Karels, 1988 → CUBIC 2006 → BBR 2016)
#
# TCP 背景：
#   早期 ARPANET 遭遇"拥塞崩溃"(1986, Nagle)：所有主机以最大速率发包，
#   网络拥塞 → 丢包 → 重传 → 更多拥塞 → 正反馈死循环。
#   Jacobson (1988) 引入 AIMD 拥塞控制：
#     - Additive Increase: 无丢包时，cwnd 每 RTT 增加 1 MSS（线性增长）
#     - Multiplicative Decrease: 检测到丢包时，cwnd 减半（指数缩减）
#   效果：
#     - 慢启动快速探测带宽 → 拥塞避免阶段谨慎增长
#     - 丢包时快速退让 → 避免拥塞崩溃
#     - 多流公平收敛（AIMD 是唯一能保证公平收敛的策略, Chiu/Jain 1989）
#
# memory-os 等价问题：
#   extractor 以固定标准提取所有匹配信号词的 chunk。
#   不论提取质量（chunk 是否被后续检索命中），提取速率不变。
#   等价于 TCP 没有拥塞控制——无论"网络"状况如何都以固定速率"发包"：
#     - 质量好时（chunk 被召回命中）→ 应该更积极提取（带宽充足，cwnd 增大）
#     - 质量差时（chunk 被 evict/忽略）→ 应该收紧提取（拥塞了，cwnd 减小）
#   当前问题：
#     - 大量低质量 chunk 占用配额 → kswapd/eviction 频繁 → 系统资源浪费
#     - 高质量 chunk 和低质量 chunk 一视同仁 → 信噪比下降
#
# 解决：
#   维护 extraction_cwnd（拥塞窗口），跟踪最近写入 chunk 的命中率：
#     hit_rate = (被 retriever 实际召回的 chunk 数) / (最近写入的 chunk 总数)
#   AIMD 策略：
#     if hit_rate >= target: cwnd += additive_increase  (线性增大)
#     else: cwnd *= multiplicative_decrease  (指数减小)
#   cwnd 影响 extractor 行为：
#     - cwnd >= 0.7: 全速提取（所有信号匹配都写入）
#     - 0.5 <= cwnd < 0.7: 中等速率（跳过 conversation_summary、低 importance excluded_path）
#     - cwnd < 0.5: 保守提取（只写 decision + reasoning_chain + 量化证据）
#   效果：
#     - 提取质量好的项目自动获得更宽松的提取策略
#     - 提取质量差的项目自动收紧，减少噪声
#     - 类似 TCP 的公平收敛：多项目场景下高质量项目获得更多"带宽"


def aimd_stats(conn: sqlite3.Connection, project: str) -> dict:
    """
    计算 AIMD 所需的统计数据：最近写入 chunk 的被召回命中率。
    OS 类比：TCP 的 RTT 采样 + 丢包检测 — 测量网络真实状况。

    方法：
      1. 取最近 N 条 recall_traces（代表最近的"ACK"）
      2. 提取所有被召回命中的 chunk IDs
      3. 取最近写入的 chunk（同一时间窗口内）
      4. 命中率 = 被召回的 / 总写入的

    返回 dict:
      recent_written: 最近窗口内写入的 chunk 数
      recent_hit: 其中被至少一次 recall_trace 命中的 chunk 数
      hit_rate: 命中率 [0, 1]
      sample_traces: 采样的 trace 数
    """
    from config import get as _sysctl
    window = _sysctl("aimd.window_traces")

    # 1. 最近 N 条 recall_traces 中的所有命中 chunk IDs
    rows = conn.execute(
        "SELECT top_k_json FROM recall_traces WHERE project=? AND injected=1 "
        "ORDER BY timestamp DESC LIMIT ?",
        (project, window)
    ).fetchall()

    hit_ids = set()
    for (top_k_json,) in rows:
        try:
            top_k = json.loads(top_k_json) if top_k_json else []
        except Exception:
            continue
        for entry in top_k:
            cid = entry.get("id") if isinstance(entry, dict) else None
            if cid:
                hit_ids.add(cid)

    sample_traces = len(rows)
    if sample_traces == 0:
        return {"recent_written": 0, "recent_hit": 0, "hit_rate": 0.0,
                "sample_traces": 0}

    # 2. 同一时间窗口内写入的 chunk（取最早 trace 的时间作为窗口起点）
    if rows:
        earliest_ts = conn.execute(
            "SELECT MIN(timestamp) FROM (SELECT timestamp FROM recall_traces "
            "WHERE project=? AND injected=1 ORDER BY timestamp DESC LIMIT ?)",
            (project, window)
        ).fetchone()
        earliest = earliest_ts[0] if earliest_ts and earliest_ts[0] else None
    else:
        earliest = None

    if earliest:
        recent_chunks = conn.execute(
            "SELECT id FROM memory_chunks WHERE project=? AND created_at>=?",
            (project, earliest)
        ).fetchall()
    else:
        recent_chunks = conn.execute(
            "SELECT id FROM memory_chunks WHERE project=? ORDER BY created_at DESC LIMIT ?",
            (project, window * 3)
        ).fetchall()

    recent_ids = {row[0] for row in recent_chunks}
    recent_written = len(recent_ids)

    if recent_written == 0:
        return {"recent_written": 0, "recent_hit": 0, "hit_rate": 0.0,
                "sample_traces": sample_traces}

    # 3. 命中率
    recent_hit = len(recent_ids & hit_ids)
    hit_rate = recent_hit / recent_written

    return {
        "recent_written": recent_written,
        "recent_hit": recent_hit,
        "hit_rate": round(hit_rate, 4),
        "sample_traces": sample_traces,
    }


def aimd_window(conn: sqlite3.Connection, project: str) -> dict:
    """
    计算当前 AIMD 拥塞窗口 (cwnd) 和提取策略。
    OS 类比：TCP 的 cwnd 计算 — 每次 ACK 后更新窗口大小。

    AIMD 策略：
      1. 计算 hit_rate
      2. if hit_rate >= target: cwnd = last_cwnd + additive_increase (AI)
         else: cwnd = last_cwnd * multiplicative_decrease (MD)
      3. clamp cwnd to [cwnd_min, cwnd_max]

    cwnd 到提取策略的映射：
      cwnd >= 0.7 → "full"（全速提取，所有信号匹配）
      0.5 <= cwnd < 0.7 → "moderate"（中等，跳过低价值类型）
      cwnd < 0.5 → "conservative"（保守，只提取 decision + reasoning）

    返回 dict:
      cwnd: 当前窗口值 [cwnd_min, cwnd_max]
      policy: "full" / "moderate" / "conservative"
      hit_rate: 当前命中率
      direction: "increase" / "decrease" / "init"（AIMD 方向）
      stats: aimd_stats 详细数据
    """
    from config import get as _sysctl

    cwnd_max = _sysctl("aimd.cwnd_max")
    cwnd_min = _sysctl("aimd.cwnd_min")
    cwnd_init = _sysctl("aimd.cwnd_init")

    # ── 迭代65：Small Pool Bypass — 小库直通 ──────────────────────────
    # OS 类比：TCP Nagle's Algorithm (RFC 896, 1984)
    #   Nagle 对小包不做拥塞控制——数据量太少时拥塞控制的开销大于收益。
    #   "Don't send small packets when the pipe is almost empty."
    #
    # memory-os 等价问题：
    #   生产项目 23 chunks / quota 200 = 11.5% 占用率，远低于拥塞水位。
    #   但 AIMD cwnd 仍被 MD 拖低到 0.35 → conservative → 丢弃 excluded/summary。
    #   小池塘里没有拥塞——所有鱼都应该被捞起来。
    #
    # 解决：chunk_count < quota × small_pool_pct 时直接 bypass：
    #   cwnd=max, policy="full"，不执行 AIMD 计算。
    small_pool_pct = _sysctl("aimd.small_pool_pct")
    try:
        chunk_count = get_project_chunk_count(conn, project)
        balloon = balloon_quota(conn, project)
        quota = balloon["quota"] if isinstance(balloon, dict) else balloon
        if chunk_count < quota * small_pool_pct:
            return {
                "cwnd": cwnd_max,
                "policy": "full",
                "hit_rate": 0.0,
                "direction": "bypass_small_pool",
                "stats": {"bypass": True, "chunk_count": chunk_count,
                          "quota": quota, "threshold_pct": small_pool_pct},
            }
    except Exception:
        pass  # bypass 失败不影响正常 AIMD 流程

    stats = aimd_stats(conn, project)
    hit_rate = stats["hit_rate"]

    target = _sysctl("aimd.hit_rate_target")
    ai_step = _sysctl("aimd.additive_increase")
    md_factor = _sysctl("aimd.multiplicative_decrease")

    # 无历史数据 → 使用初始窗口
    if stats["sample_traces"] < 3 or stats["recent_written"] < 5:
        return {
            "cwnd": cwnd_init,
            "policy": _cwnd_to_policy(cwnd_init),
            "hit_rate": hit_rate,
            "direction": "init",
            "stats": stats,
        }

    # 读取上次 cwnd（持久化在 madvise.json 旁边的 aimd_state.json）
    last_cwnd = _aimd_load_cwnd(project, cwnd_init)

    # AIMD 计算（迭代63：Slow Start 指数恢复）
    # OS 类比：TCP Slow Start (Van Jacobson, 1988)
    #   TCP 新连接不知道网络容量，从 cwnd=1 开始：
    #     cwnd < ssthresh → 指数增长（每个 ACK: cwnd *= 2）
    #     cwnd >= ssthresh → 线性增长（每个 RTT: cwnd += 1）= Congestion Avoidance
    #   这让 TCP 在丢包后快速恢复到安全速率，再谨慎探测上限。
    #
    #   memory-os 等价问题：
    #     cwnd 从 0.3 线性恢复（+0.05/step）到 0.7 需要 8 步 = 8 次 SessionStart，
    #     可能需要数天才能回到 full 策略。
    #   Slow Start 解决：cwnd < ssthresh 时指数增长（0.3→0.6→1.0，2步到 full）。
    ssthresh = _sysctl("aimd.ssthresh")
    slow_start_factor = _sysctl("aimd.slow_start_factor")

    if hit_rate >= target:
        if last_cwnd < ssthresh:
            # Slow Start 阶段：指数增长（快速恢复）
            new_cwnd = last_cwnd * slow_start_factor
            # 不超过 ssthresh（到达 ssthresh 后切换为线性增长）
            new_cwnd = min(new_cwnd, ssthresh)
            direction = "slow_start"
        else:
            # Congestion Avoidance 阶段：线性增长（谨慎探测）
            new_cwnd = last_cwnd + ai_step  # Additive Increase
            direction = "increase"
    else:
        new_cwnd = last_cwnd * md_factor  # Multiplicative Decrease
        direction = "decrease"

    # Clamp
    new_cwnd = max(cwnd_min, min(cwnd_max, round(new_cwnd, 4)))

    # 持久化
    _aimd_save_cwnd(project, new_cwnd, hit_rate, direction)

    return {
        "cwnd": new_cwnd,
        "policy": _cwnd_to_policy(new_cwnd),
        "hit_rate": hit_rate,
        "direction": direction,
        "stats": stats,
    }


def _cwnd_to_policy(cwnd: float) -> str:
    """将 cwnd 映射到提取策略。"""
    if cwnd >= 0.7:
        return "full"
    elif cwnd >= 0.5:
        return "moderate"
    else:
        return "conservative"


# ── AIMD State Persistence ──────────────────────────────────────────

_AIMD_STATE_FILE = MEMORY_OS_DIR / "aimd_state.json"


def _aimd_load_cwnd(project: str, default: float) -> float:
    """加载项目的上次 cwnd 值。"""
    try:
        if _AIMD_STATE_FILE.exists():
            data = json.loads(_AIMD_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                proj_data = data.get(project, {})
                if isinstance(proj_data, dict) and "cwnd" in proj_data:
                    return float(proj_data["cwnd"])
    except Exception:
        pass
    return default


def _aimd_save_cwnd(project: str, cwnd: float, hit_rate: float,
                    direction: str) -> None:
    """持久化项目的 cwnd 值。"""
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        data = {}
        if _AIMD_STATE_FILE.exists():
            try:
                data = json.loads(_AIMD_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        data[project] = {
            "cwnd": cwnd,
            "hit_rate": hit_rate,
            "direction": direction,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _AIMD_STATE_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass

# ── 迭代63：Trace GC — recall_traces 生命周期管理 ────────────────────
#
# OS 类比：Linux Log Rotation (logrotate, 1996)
#   /var/log/ 日志文件无限增长会耗尽磁盘空间。
#   logrotate 定期轮转：按大小（maxsize）或时间（daily/weekly）淘汰旧日志。
#   两个维度：过期删除（maxage）+ 容量限制（rotate count）。
#
#   memory-os 等价问题：
#     recall_traces 是检索事件日志（每次 UserPromptSubmit 写一条）。
#     随使用增长无限膨胀——影响 AIMD 计算速度、PSI 统计准确性、DB 体积。
#     旧 trace（>14天）对 AIMD 命中率统计已无价值（窗口通常只看最近 30 条）。
#
#   解决：
#     gc_traces(conn, project) — 两个维度清理：
#       1. 时间淘汰：删除 > gc.trace_max_age_days 的 trace
#       2. 容量淘汰：保留最近 gc.trace_max_rows 条，超出按时间删除
#     在 loader.py SessionStart 调用（与 watchdog/damon 并列的开机维护）。

def gc_traces(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    清理过期的 recall_traces 记录。
    OS 类比：logrotate — 按时间 + 容量两个维度淘汰旧日志。

    参数：
      conn    — 数据库连接
      project — 项目 ID（None 时清理所有项目的 trace）

    返回 dict:
      deleted_age  — 按时间淘汰的条目数
      deleted_rows — 按容量淘汰的条目数
      remaining    — 剩余条目数
    """
    from config import get as _sysctl

    max_age_days = _sysctl("gc.trace_max_age_days")
    max_rows = _sysctl("gc.trace_max_rows")

    deleted_age = 0
    deleted_rows = 0

    # Phase 1：时间淘汰 — 删除超过 max_age_days 的 trace
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    if project:
        cur = conn.execute(
            "DELETE FROM recall_traces WHERE project=? AND timestamp < ?",
            (project, cutoff))
    else:
        cur = conn.execute(
            "DELETE FROM recall_traces WHERE timestamp < ?",
            (cutoff,))
    deleted_age = cur.rowcount

    # Phase 2：容量淘汰 — 保留最近 max_rows 条（per-project）
    if project:
        projects = [project]
    else:
        rows = conn.execute(
            "SELECT DISTINCT project FROM recall_traces").fetchall()
        projects = [r[0] for r in rows]

    for proj in projects:
        count_row = conn.execute(
            "SELECT COUNT(*) FROM recall_traces WHERE project=?",
            (proj,)).fetchone()
        total = count_row[0] if count_row else 0
        if total > max_rows:
            excess = total - max_rows
            # 删除最旧的 excess 条
            conn.execute(
                "DELETE FROM recall_traces WHERE id IN ("
                "  SELECT id FROM recall_traces WHERE project=? "
                "  ORDER BY timestamp ASC LIMIT ?"
                ")", (proj, excess))
            deleted_rows += excess

    # 统计剩余
    if project:
        remaining_row = conn.execute(
            "SELECT COUNT(*) FROM recall_traces WHERE project=?",
            (project,)).fetchone()
    else:
        remaining_row = conn.execute(
            "SELECT COUNT(*) FROM recall_traces").fetchone()
    remaining = remaining_row[0] if remaining_row else 0

    conn.commit()

    return {
        "deleted_age": deleted_age,
        "deleted_rows": deleted_rows,
        "remaining": remaining,
    }

# ── 迭代509：rmap_sweep — Reverse Mapping Stale Reference Scrubber ─────────
#
# OS 类比：Linux rmap (Rik van Riel, 2002)
#   当 page frame 被释放时，内核通过 reverse mapping 找到所有指向该 frame 的
#   page table entries (PTEs)，将它们标记为 invalid。没有 rmap，stale PTEs
#   会导致 use-after-free（进程读到已分配给别人的物理页）。
#
#   memory-os 的问题：
#     chunks 被 oom_reaper/shrink_dcache/kswapd 删除后，recall_traces 的
#     top_k_json 仍引用已删除 chunk IDs。readahead_pairs() 从这些 ghost refs
#     计算虚假共现 → 预取不存在的 chunk → 浪费时间 + 污染检索结果。
#
#   解决：rmap_sweep() 在 gc_traces 之后运行，遍历所有 recall_traces，
#     将 top_k_json 中引用不存在 chunks 的条目移除。
#     空 top_k_json 的 trace 整条删除（无信息价值）。


def rmap_sweep(conn: sqlite3.Connection, project: str = None) -> dict:
    """iter509: rmap_sweep — 清除 recall_traces 中的 stale chunk references.

    OS 类比：Linux rmap (Rik van Riel, 2002) — page frame 释放时清除所有 PTE 反向映射。

    算法：
      1. 加载当前所有有效 chunk IDs（live set）
      2. 遍历 recall_traces，解析 top_k_json
      3. 过滤掉引用不存在 chunk 的条目
      4. 若全部条目都是 stale → 删除整条 trace
      5. 若部分 stale → UPDATE top_k_json 只保留有效引用

    返回：
      scrubbed_traces — 被修改的 trace 数
      deleted_traces  — 被整条删除的 trace 数（全 stale）
      stale_refs_removed — 移除的 stale reference 总数
      total_scanned — 扫描的 trace 总数
    """
    # Phase 1: 构建 live chunk ID set
    if project:
        live_rows = conn.execute(
            "SELECT id FROM memory_chunks WHERE project=?", (project,)
        ).fetchall()
    else:
        live_rows = conn.execute("SELECT id FROM memory_chunks").fetchall()
    live_ids = set(r[0] for r in live_rows)

    # Phase 2: 扫描 recall_traces（用 ROWID 作为稳定标识，因为 id 列可能为 NULL）
    if project:
        traces = conn.execute(
            "SELECT rowid, top_k_json FROM recall_traces WHERE project=? AND top_k_json IS NOT NULL",
            (project,)
        ).fetchall()
    else:
        traces = conn.execute(
            "SELECT rowid, top_k_json FROM recall_traces WHERE top_k_json IS NOT NULL"
        ).fetchall()

    scrubbed = 0
    deleted = 0
    stale_refs_removed = 0
    delete_rowids = []
    update_batch = []  # (new_json, rowid)

    for rowid, top_k_raw in traces:
        try:
            top_k = json.loads(top_k_raw) if isinstance(top_k_raw, str) else top_k_raw
        except Exception:
            continue
        if not isinstance(top_k, list):
            continue

        # 分离有效和 stale 条目
        valid = []
        stale_count = 0
        for item in top_k:
            if isinstance(item, dict) and "id" in item:
                if item["id"] in live_ids:
                    valid.append(item)
                else:
                    stale_count += 1
            else:
                valid.append(item)  # 保留非标准格式条目

        if stale_count == 0:
            continue  # 此 trace 无 stale refs

        stale_refs_removed += stale_count

        if len(valid) == 0:
            # 全部 stale → 删除整条 trace
            delete_rowids.append(rowid)
            deleted += 1
        else:
            # 部分 stale → 更新
            update_batch.append((json.dumps(valid, ensure_ascii=False), rowid))
            scrubbed += 1

    # Phase 3: 批量写入（使用 ROWID，兼容 id=NULL 的历史记录）
    if delete_rowids:
        # SQLite 限制：SQLITE_MAX_VARIABLE_NUMBER 默认 999
        for i in range(0, len(delete_rowids), 500):
            batch = delete_rowids[i:i+500]
            placeholders = ",".join("?" * len(batch))
            conn.execute(f"DELETE FROM recall_traces WHERE rowid IN ({placeholders})", batch)

    if update_batch:
        conn.executemany(
            "UPDATE recall_traces SET top_k_json=? WHERE rowid=?",
            update_batch
        )

    if delete_rowids or update_batch:
        conn.commit()

    return {
        "scrubbed_traces": scrubbed,
        "deleted_traces": deleted,
        "stale_refs_removed": stale_refs_removed,
        "total_scanned": len(traces),
    }


# ── 迭代510：vma_merge — Recall Trace Deduplication ──────────────────
#
# OS 类比：Linux vma_merge() (Linus Torvalds, 1994)
#   当进程 mmap() 新区域时，内核检查是否可以与相邻的 vm_area_struct 合并
#   （相同 vm_flags/vm_file/vm_pgoff 连续）。合并后 find_vma() 的红黑树
#   节点数减少，遍历开销降低。没有 vma_merge，频繁 mmap/munmap 会导致
#   mm_struct 碎片化（数千个微小 VMA，O(log N) 查找变慢）。
#
#   memory-os 的问题：
#     recall_traces 中 66% 的记录引用完全相同的 chunk ID 集合（重复 traces），
#     44% 的相邻 traces Jaccard>=0.8。readahead_pairs() 对每条 trace 做
#     O(K²) 两两组合计算共现，重复 traces 人为膨胀 co-occurrence 计数
#     并浪费 CPU。rmap_sweep 也扫描无意义的重复行。
#
#   解决：vma_merge() 在 gc_traces + rmap_sweep 之后运行，合并相同或
#     高度相似（Jaccard>=threshold）的 traces，保留最新时间戳和最高分数。


def vma_merge(conn: sqlite3.Connection, project: str = None) -> dict:
    """iter510: vma_merge — 合并重复/高度相似的 recall_traces.

    OS 类比：Linux vma_merge() — 相邻 VMA 属性相同时自动合并，减少碎片。

    算法：
      1. 加载所有 traces（按 timestamp DESC），解析 top_k_json → chunk ID set
      2. 按 chunk ID set 的 frozenset 分组（完全重复检测）
      3. 每组保留最新的 1 条，删除其余（exact merge）
      4. 对剩余 traces 做相邻 Jaccard 检测，>=threshold 时合并（fuzzy merge）
         合并策略：保留 ID 集合的并集 + 最新时间戳

    返回：
      exact_merged  — 完全重复合并删除的条数
      fuzzy_merged  — 模糊合并删除的条数
      remaining     — 合并后剩余条数
      total_scanned — 扫描的 trace 总数
    """
    from config import get as _cfg

    threshold = _cfg("vma_merge.jaccard_threshold")  # default 0.8
    max_merge_per_scan = _cfg("vma_merge.max_merge_per_scan")  # default 100

    # Phase 1: 加载 traces
    if project:
        traces = conn.execute(
            "SELECT rowid, top_k_json, timestamp FROM recall_traces "
            "WHERE project=? AND top_k_json IS NOT NULL "
            "ORDER BY timestamp DESC",
            (project,)
        ).fetchall()
    else:
        traces = conn.execute(
            "SELECT rowid, top_k_json, timestamp FROM recall_traces "
            "WHERE top_k_json IS NOT NULL "
            "ORDER BY timestamp DESC"
        ).fetchall()

    if len(traces) < 2:
        return {"exact_merged": 0, "fuzzy_merged": 0,
                "remaining": len(traces), "total_scanned": len(traces)}

    # 解析 → (rowid, id_set, timestamp)
    parsed = []
    for rowid, top_k_raw, ts in traces:
        try:
            top_k = json.loads(top_k_raw) if isinstance(top_k_raw, str) else top_k_raw
        except Exception:
            continue
        if not isinstance(top_k, list):
            continue
        ids = frozenset(
            item["id"] for item in top_k
            if isinstance(item, dict) and "id" in item
        )
        if ids:  # 跳过空集
            parsed.append((rowid, ids, ts, top_k))

    # Phase 2: Exact merge — 按 frozenset 分组
    groups = defaultdict(list)  # frozenset → [(rowid, ts, top_k), ...]
    for rowid, ids, ts, top_k in parsed:
        groups[ids].append((rowid, ts, top_k))

    delete_rowids = []
    exact_merged = 0

    for ids_key, members in groups.items():
        if len(members) <= 1:
            continue
        # 按时间降序（已排序），保留第一条（最新），删除其余
        for rowid, ts, top_k in members[1:]:
            delete_rowids.append(rowid)
            exact_merged += 1
            if exact_merged >= max_merge_per_scan:
                break
        if exact_merged >= max_merge_per_scan:
            break

    # Phase 3: Fuzzy merge — 相邻 Jaccard >= threshold
    # 先从 parsed 中移除已标记删除的 rowid
    deleted_set = set(delete_rowids)
    remaining_parsed = [
        (rowid, ids, ts, top_k) for rowid, ids, ts, top_k in parsed
        if rowid not in deleted_set
    ]

    fuzzy_merged = 0
    budget = max_merge_per_scan - exact_merged

    if budget > 0 and len(remaining_parsed) >= 2:
        fuzzy_delete = []
        i = 0
        while i < len(remaining_parsed) - 1 and fuzzy_merged < budget:
            _, ids_a, _, _ = remaining_parsed[i]
            rowid_b, ids_b, _, _ = remaining_parsed[i + 1]
            # Jaccard similarity
            intersection = len(ids_a & ids_b)
            union = len(ids_a | ids_b)
            if union > 0 and intersection / union >= threshold:
                # 合并：删除较旧的（i+1，因为 DESC 排序 i 更新）
                fuzzy_delete.append(rowid_b)
                fuzzy_merged += 1
                # 跳过被合并的条目，继续比较 i 和 i+2
                remaining_parsed.pop(i + 1)
            else:
                i += 1
        delete_rowids.extend(fuzzy_delete)

    # Phase 4: 批量删除
    if delete_rowids:
        for i in range(0, len(delete_rowids), 500):
            batch = delete_rowids[i:i+500]
            placeholders = ",".join("?" * len(batch))
            conn.execute(
                f"DELETE FROM recall_traces WHERE rowid IN ({placeholders})",
                batch
            )
        conn.commit()

    # 统计剩余
    if project:
        remaining = conn.execute(
            "SELECT COUNT(*) FROM recall_traces WHERE project=?",
            (project,)
        ).fetchone()[0]
    else:
        remaining = conn.execute(
            "SELECT COUNT(*) FROM recall_traces"
        ).fetchone()[0]

    return {
        "exact_merged": exact_merged,
        "fuzzy_merged": fuzzy_merged,
        "remaining": remaining,
        "total_scanned": len(traces),
    }


# ── 迭代51：Autotune — sysctl 参数自优化引擎 ─────────────────────
#
# OS 类比：
#   1. Linux TCP Window Auto-Tuning (2.6.17, 2006, John Heffner)
#      TCP 发送/接收缓冲区大小不再是固定值，内核根据 RTT 和带宽动态调整
#      net.ipv4.tcp_moderate_rcvbuf=1 启用接收窗口自动调整
#
#   2. PostgreSQL Auto-Vacuum / Auto-Analyze (8.1, 2005)
#      vacuum/analyze 不再需要 DBA 手动调度
#      根据表的 dead tuple 比例自动决定何时运行
#
# memory-os 当前问题：
#   60+ 个 sysctl tunable 全部使用编译时默认值。
#   不同项目特征差异大：高命中率项目 top_k 偏小，低命中率项目 quota 偏大。
#   手动调参不现实（每个项目独立，运行时特征变化）。
#
# 解决：
#   autotune(conn, project) — SessionStart 时运行，根据运行时统计自动调参。
#   调参策略（保守优先，每次 ±step_pct%）：
#     1. hit_rate 高 → top_k +step%, quota +step%（供给不足，扩容）
#     2. hit_rate 低 → top_k -step%, quota -step%（噪声多，收缩）
#     3. p95_latency 高 → deadline +step%（检索延迟大，放宽 deadline）
#     4. capacity 接近上限 → kswapd.pages_low -step%（提前淘汰）
#   写入 per-project namespace，不影响全局默认值。

_AUTOTUNE_STATE_FILE = MEMORY_OS_DIR / "autotune_state.json"


def autotune(conn: sqlite3.Connection, project: str) -> dict:
    """
    迭代51：Autotune — 基于运行时统计的 per-project 参数自优化。
    OS 类比：TCP Window Auto-Tuning + PG Auto-Vacuum。

    SessionStart 时运行，分析检索统计和容量状态，自动微调 per-project sysctl。

    返回 dict:
      tuned: bool — 是否进行了调参
      adjustments: list — 调整明细 [{key, old, new, reason}]
      stats: dict — 统计摘要
      skipped_reason: str — 如果 tuned=False，跳过原因
    """
    from config import get as _cfg, sysctl_set, ns_list, _REGISTRY

    enabled = _cfg("autotune.enabled", project=project)
    if not enabled:
        return {"tuned": False, "adjustments": [], "stats": {},
                "skipped_reason": "disabled"}

    # ── Cooldown 检查（防振荡）──
    cooldown_hours = _cfg("autotune.cooldown_hours")
    last_run = _autotune_load_state(project)
    if last_run:
        try:
            last_ts = datetime.fromisoformat(last_run["timestamp"])
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - last_ts).total_seconds() / 3600
            if age_hours < cooldown_hours:
                return {"tuned": False, "adjustments": [], "stats": {},
                        "skipped_reason": f"cooldown ({age_hours:.1f}h < {cooldown_hours}h)"}
        except Exception:
            pass

    # ── iter494: Circuit Breaker — 连续恶化检测 ──
    # OS 类比：TCP anti-windup + perf_event overflow circuit breaker
    #   当 autotune 控制回路连续 N 次调整后核心指标持续恶化（hit_rate 下降），
    #   断路（open）暂停调参 + 回滚到最近"好参数快照"；
    #   经 cb_open_hours 后进入 half-open，试探一次；若成功则关闭熔断。
    cb_enabled = _cfg("autotune.cb_enabled")
    if cb_enabled and last_run:
        try:
            circuit = last_run.get("circuit", {})
            cb_state = circuit.get("state", "closed")  # closed / open / half_open
            cb_consecutive = circuit.get("consecutive_bad", 0)
            cb_max = _cfg("autotune.cb_consecutive_bad")
            cb_degrade_pct = _cfg("autotune.cb_degrade_pct") / 100.0
            cb_open_hours = _cfg("autotune.cb_open_hours")

            if cb_state == "open":
                # 检查是否到了 half-open 窗口
                open_since_str = circuit.get("open_since", "")
                should_half_open = False
                if open_since_str:
                    open_since = datetime.fromisoformat(open_since_str)
                    if open_since.tzinfo is None:
                        open_since = open_since.replace(tzinfo=timezone.utc)
                    hours_open = (datetime.now(timezone.utc) - open_since).total_seconds() / 3600
                    should_half_open = hours_open >= cb_open_hours

                if not should_half_open:
                    hours_open = circuit.get("hours_open", 0)
                    return {"tuned": False, "adjustments": [], "stats": {},
                            "skipped_reason": f"circuit_open (consecutive_bad={cb_consecutive}, "
                                              f"open_since={open_since_str[:16]})"}
                # else: 进入 half-open，允许本次执行，但 circuit 状态记为 half_open
                circuit["state"] = "half_open"
        except Exception:
            pass

    # ── 采集统计数据 ──
    min_traces = _cfg("autotune.min_traces")
    step_pct = _cfg("autotune.step_pct") / 100.0

    trace_rows = conn.execute(
        "SELECT injected, duration_ms, top_k_json FROM recall_traces "
        "WHERE project=? ORDER BY timestamp DESC LIMIT 30",
        (project,)
    ).fetchall()

    sample_count = len(trace_rows)
    if sample_count < min_traces:
        return {"tuned": False, "adjustments": [],
                "stats": {"sample_count": sample_count},
                "skipped_reason": f"insufficient traces ({sample_count} < {min_traces})"}

    injected_count = sum(1 for r in trace_rows if r[0] == 1)
    hit_rate_pct = (injected_count / sample_count * 100) if sample_count > 0 else 0.0

    # ── 迭代136：deadline_skip 轨迹自引用修复 ──
    # 问题：deadline_skip 轨迹的 duration_ms ≈ 当前 deadline_ms（因为运行到软截止才返回），
    #       将这类轨迹纳入 p95 计算 → p95 > 2×baseline → autotune 推高 deadline_ms
    #       → 新轨迹 duration 更高 → p95 再升 → 正反馈循环（gitroot 项目实测 50→97ms）
    # 修复：延迟计算专用查询，排除 deadline_skip + hard_deadline 轨迹（自引用的测量误差）
    # OS 类比：Linux scheduler 用 vruntime 排除 idle time — 停机期间不计入 fair share
    latency_rows = conn.execute(
        "SELECT duration_ms FROM recall_traces "
        "WHERE project=? AND duration_ms > 0 "
        "  AND reason NOT LIKE '%deadline_skip%' "
        "  AND reason NOT LIKE '%hard_deadline%' "
        "ORDER BY timestamp DESC LIMIT 30",
        (project,)
    ).fetchall()
    latencies = [r[0] for r in latency_rows]
    latencies.sort()
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    p95_idx = int(len(latencies) * 0.95) if latencies else 0
    p95_latency = latencies[min(p95_idx, len(latencies) - 1)] if latencies else 0.0

    chunk_count = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
    ).fetchone()[0]

    stats = {
        "sample_count": sample_count,
        "hit_rate_pct": round(hit_rate_pct, 1),
        "avg_latency_ms": round(avg_latency, 2),
        "p95_latency_ms": round(p95_latency, 2),
        "chunk_count": chunk_count,
        "current_overrides": len(ns_list(project)),
    }

    # ── 调参决策 ──
    adjustments = []
    hit_low = _cfg("autotune.hit_rate_low_pct")
    hit_high = _cfg("autotune.hit_rate_high_pct")

    def _adjust(key, direction, reason):
        if key not in _REGISTRY:
            return
        default, typ, lo, hi, _, _ = _REGISTRY[key]
        current = _cfg(key, project=project)
        if direction == "up":
            new_val = current * (1 + step_pct)
        else:
            new_val = current * (1 - step_pct)
        if typ is int:
            new_val = int(round(new_val))
        else:
            new_val = round(new_val, 4)
        if lo is not None:
            new_val = max(lo, new_val)
        if hi is not None:
            new_val = min(hi, new_val)
        if new_val != current:
            sysctl_set(key, new_val, project=project)
            adjustments.append({"key": key, "old": current, "new": new_val, "reason": reason})

    # 迭代129：修复调参方向逻辑反转 bug
    # OS 类比：TCP AIMD — 丢包（命中率低）时收缩 cwnd，正常时线性增长
    #
    # 旧逻辑（错误）：命中率高 → 扩大 top_k
    #   根因：高命中率 = 系统已充分满足需求，继续扩大 top_k 只会增加噪声和延迟
    #   实测：top_k 从 5 被推到 12，与 design_constraint 膨胀叠加，造成 injected=14+
    #
    # 新逻辑（正确）：
    #   命中率低（供给不足）→ 扩大 top_k 和 quota（补充知识供给）
    #   命中率高（系统健康）→ top_k 不动，但 quota 适度扩大（为未来知识积累空间）
    #   注意：top_k 只在供给不足时增加，永远不因高命中率增加
    #
    # 额外保护：top_k per-project 上限（autotune.top_k_max），防止无限膨胀
    top_k_max = _cfg("autotune.top_k_max", project=project)
    current_top_k = _cfg("retriever.top_k", project=project)
    # 迭代137：读取 quota 上限，策略1/2 中的 quota 扩大操作受此上限约束
    chunk_quota_max_fwd = _cfg("autotune.chunk_quota_max")
    current_quota_fwd = _cfg("extractor.chunk_quota", project=project)

    if hit_rate_pct > hit_high:
        # 命中率高：系统健康，quota 适度扩大（知识积累空间），top_k 保持不变
        # 迭代137：仅在 quota < chunk_quota_max 时才扩大（防止已超标的继续推高）
        if current_quota_fwd < chunk_quota_max_fwd:
            _adjust("extractor.chunk_quota", "up",
                    f"hit_rate {hit_rate_pct:.0f}%>{hit_high}% → expand capacity for future knowledge")
        # top_k 不扩大（高命中率不是扩大 top_k 的信号）
    elif hit_rate_pct < hit_low:
        # 命中率低：供给不足，扩大 top_k + quota
        if current_top_k < top_k_max:
            _adjust("retriever.top_k", "up",
                    f"hit_rate {hit_rate_pct:.0f}%<{hit_low}% → expand retrieval (supply shortage)")
        # 迭代137：命中率低时也检查 quota 上限（低命中率不意味着可以无限扩容）
        if current_quota_fwd < chunk_quota_max_fwd:
            _adjust("extractor.chunk_quota", "up",
                    f"hit_rate {hit_rate_pct:.0f}%<{hit_low}% → expand capacity")

    # 策略 3: p95 延迟高/低 → 双向调节 deadline（迭代139：添加收缩方向）
    # OS 类比：TCP Congestion Avoidance 双向调节 — 丢包时 cwnd 缩，ACK 时 cwnd 增
    #   原策略3 单向放宽：p95 > 2×baseline → deadline +10%。问题：p95 恢复后 deadline 不回收。
    #   gitroot 实测：deadline 97ms（被 iter136 cap 到 100ms），即使延迟恢复也锁死高位。
    # 修复：添加收缩条件 — p95 < baseline 时，deadline 向默认值(50ms)收缩（每次 -step_pct%）
    #   收缩路径（step_pct=10%，从 deadline_max=100ms 回到 default=50ms）：
    #     100→90→81→72.9→65.6→59→53.1→50（7 个 autotune 周期，42 小时）
    #   与 iter136 配合：iter136 cap 防止超过 100ms，iter139 收缩防止永久停在高位
    #   收缩下限：retriever.deadline_ms 的配置下限（5ms）通过 _adjust lo/hi 自动保护
    latency_baseline = _cfg("psi.latency_baseline_ms")
    default_deadline_ms = 50.0  # retriever.deadline_ms 默认值
    if p95_latency > latency_baseline * 2:
        # 延迟高：放宽 deadline（允许检索多跑一会儿）
        _adjust("retriever.deadline_ms", "up",
                f"p95={p95_latency:.1f}ms>2×baseline({latency_baseline}ms) → relax deadline")
    elif p95_latency > 0 and p95_latency < default_deadline_ms:
        # iter143：收缩条件改为 p95 < default_deadline_ms（50ms）而非 p95 < baseline(30ms)
        # 根因：baseline=30ms 太低，真实 LITE 延迟普遍 30-50ms，p95 < baseline 永远不满足，
        #       deadline 一旦被推高（如 97ms）就永久锁死高位（iter139 收缩逻辑失效）。
        # 修复：只要 p95 低于 default_deadline_ms（50ms），即认为"延迟可接受"，开始向默认值收缩。
        #   效果：P95=46ms < 50ms → 触发收缩，97→87→78→70→63→57→51→50（7 个 autotune 周期）
        # OS 类比：TCP CUBIC cubic_cwnd_reset — cwnd 超标后不等到 loss 才收缩，
        #   而是当 RTT 低于 target（min_rtt × 1.1）时主动 probe 更小 cwnd
        current_dl = _cfg("retriever.deadline_ms", project=project)
        if current_dl > default_deadline_ms:
            new_dl = max(default_deadline_ms, round(current_dl * (1 - step_pct), 1))
            if new_dl != current_dl:
                sysctl_set("retriever.deadline_ms", new_dl, project=project)
                adjustments.append({
                    "key": "retriever.deadline_ms",
                    "old": current_dl,
                    "new": new_dl,
                    "reason": f"iter143 p95={p95_latency:.1f}ms<default({default_deadline_ms}ms) → shrink deadline toward default",
                })

    # 策略 4: 容量接近上限 → 降低 kswapd 水位提前淘汰
    # 迭代138：添加回弹机制 — 容量压力降低后，pages_low_pct 恢复向默认值
    # OS 类比：Linux vm.watermark_boost_factor — 内存压力解除后 watermark 恢复
    #   问题：策略4 单方向降水位，abspath:7e3095aef7a6 实测 80→58（7次 -10%）
    #         但当 quota 被 iter137 钳制/或 chunk 被 kswapd 淘汰后，capacity 恢复
    #         pages_low_pct 却永久停在 58，kswapd 持续过激进（58% 就启动淘汰）
    #   修复：容量 < recover_pct(70%) 时，将 pages_low_pct 向默认值回弹（每次 +10%）
    quota = _cfg("extractor.chunk_quota", project=project)
    capacity_ratio = chunk_count / quota if quota > 0 else 0.0
    if capacity_ratio > 0.90:
        _adjust("kswapd.pages_low_pct", "down",
                f"capacity {chunk_count}/{quota}({capacity_ratio:.0%}>{90}%) → earlier kswapd reclaim")
    elif capacity_ratio < 0.70:
        # 容量压力解除，尝试回弹 pages_low_pct 向默认值（每次+step_pct，不超过默认80）
        current_pages_low = _cfg("kswapd.pages_low_pct", project=project)
        default_pages_low = 80  # kswapd.pages_low_pct 默认值
        if current_pages_low < default_pages_low:
            # 向上调整（回弹），但不超过默认值
            new_val = min(int(current_pages_low * (1 + step_pct)), default_pages_low)
            if new_val != current_pages_low:
                sysctl_set("kswapd.pages_low_pct", new_val, project=project)
                adjustments.append({
                    "key": "kswapd.pages_low_pct",
                    "old": current_pages_low,
                    "new": new_val,
                    "reason": f"iter138 capacity={capacity_ratio:.0%}<70% → recover pages_low_pct toward default({default_pages_low})",
                })

    # 迭代129：策略 5 — top_k 超标主动回缩
    # OS 类比：TCP RTT-based cwnd reduction — 检测到缓冲区膨胀时主动收缩
    # 旧逻辑在高命中率下持续推高 top_k，需要一次性修正到上限以内
    if current_top_k > top_k_max:
        sysctl_set("retriever.top_k", top_k_max, project=project)
        adjustments.append({
            "key": "retriever.top_k",
            "old": current_top_k,
            "new": top_k_max,
            "reason": f"iter129 top_k={current_top_k}>{top_k_max}(top_k_max) → clamp down",
        })

    # 迭代136：策略 6 — deadline_ms 超标主动回缩
    # OS 类比：TCP RTO max (RFC 6298 Section 2.4) — 退避上限 64 秒，防止无限指数退避
    # 根因：p95 之前包含 deadline_skip 轨迹（自引用），导致 deadline_ms 持续推高。
    # iter136 已修复 p95 计算，但历史推高的值需要一次性回缩到合理范围。
    deadline_max = _cfg("autotune.deadline_max_ms")
    current_deadline = _cfg("retriever.deadline_ms", project=project)
    if current_deadline > deadline_max:
        sysctl_set("retriever.deadline_ms", deadline_max, project=project)
        adjustments.append({
            "key": "retriever.deadline_ms",
            "old": current_deadline,
            "new": deadline_max,
            "reason": f"iter136 deadline={current_deadline:.1f}>{deadline_max}(deadline_max) → clamp down (self-reinforcing loop fix)",
        })

    # 迭代137：策略 7 — chunk_quota 超标主动回缩
    # OS 类比：Linux cgroup memory.max — 超过硬上限时内存分配失败（OOM）
    #   autotune 策略1（命中率高）每次 +10% quota 且无上限检查：
    #     gitroot 实测 200→389（19 次），balloon.max_quota=500 是全局上限
    #     但 autotune 直接写 per-project namespace，绕过 balloon 的动态分配
    #     若不设上限，高命中率项目每 6 小时推高 quota，最终挤压其他项目分配空间
    #   修复：autotune.chunk_quota_max 限制 autotune 可调上限
    #     与策略5（top_k 回缩）和策略6（deadline 回缩）保持一致的防膨胀模式
    chunk_quota_max = _cfg("autotune.chunk_quota_max")
    current_quota = _cfg("extractor.chunk_quota", project=project)
    if current_quota > chunk_quota_max:
        sysctl_set("extractor.chunk_quota", chunk_quota_max, project=project)
        adjustments.append({
            "key": "extractor.chunk_quota",
            "old": current_quota,
            "new": chunk_quota_max,
            "reason": f"iter137 quota={current_quota}>{chunk_quota_max}(chunk_quota_max) → clamp down (uncapped autotune inflation fix)",
        })

    # ── iter537: 策略 8 — perf_counters 驱动的 min_score_threshold 自适应调节 ──
    # OS 类比：perf stat IPC counter → 当 IPC 持续低于阈值时触发 microcode 参数调整
    # 当 low_score_ratio 高（太多弱相关注入）时提高 min_score_threshold；
    # 当 avg_score 高且 low_score_ratio=0 时适度降低（允许更多探索性注入）
    perf_quality_enabled = _cfg("perf.autotune_enabled", project=project)
    if perf_quality_enabled and sample_count >= min_traces:
        try:
            _pc = perf_counters(conn, project, window=window if 'window' in dir() else 30)
            _pc_low_ratio = _pc.get("low_score_ratio", 0.0)
            _pc_avg_score = _pc.get("avg_score", 0.0)
            _pc_raise_pct = _cfg("perf.raise_threshold_pct") / 100.0
            _pc_lower_pct = _cfg("perf.lower_threshold_pct") / 100.0
            _pc_threshold_max = _cfg("perf.threshold_max")
            _pc_threshold_min = _cfg("perf.threshold_min")
            current_threshold = _cfg("retriever.min_score_threshold", project=project)

            if _pc_low_ratio > _pc_raise_pct:
                # 太多低分注入 → 提高阈值（过滤更严）
                new_threshold = min(round(current_threshold + 0.05, 4), _pc_threshold_max)
                if new_threshold != current_threshold:
                    sysctl_set("retriever.min_score_threshold", new_threshold, project=project)
                    adjustments.append({
                        "key": "retriever.min_score_threshold",
                        "old": current_threshold,
                        "new": new_threshold,
                        "reason": f"iter537 perf low_score_ratio={_pc_low_ratio:.2f}>{_pc_raise_pct:.2f} → raise threshold (too many weak injections)",
                    })
            elif _pc_low_ratio == 0.0 and _pc_avg_score > 0.7 and current_threshold > _pc_threshold_min:
                # 所有注入都高质量 + 当前阈值高于最低值 → 适度降低（允许探索）
                new_threshold = max(round(current_threshold - 0.02, 4), _pc_threshold_min)
                if new_threshold != current_threshold:
                    sysctl_set("retriever.min_score_threshold", new_threshold, project=project)
                    adjustments.append({
                        "key": "retriever.min_score_threshold",
                        "old": current_threshold,
                        "new": new_threshold,
                        "reason": f"iter537 perf avg_score={_pc_avg_score:.3f}>0.7 low_ratio=0 → lower threshold (allow exploration)",
                    })
            stats["perf_counters"] = {
                "avg_score": _pc_avg_score,
                "low_score_ratio": _pc_low_ratio,
                "type_concentration": _pc.get("type_concentration", 0.0),
            }
        except Exception:
            pass

    # ── iter494: Circuit Breaker — 调整后更新 circuit 状态 ──
    # 比较本次 hit_rate 和上次 hit_rate，决定连续恶化计数
    circuit_update = {}
    if cb_enabled:
        try:
            prev_circuit = (last_run or {}).get("circuit", {}) if last_run else {}
            prev_hit_rate = (last_run or {}).get("stats", {}).get("hit_rate_pct", None) if last_run else None
            curr_hit_rate = stats.get("hit_rate_pct", None)
            cb_degrade_pct = _cfg("autotune.cb_degrade_pct") / 100.0
            cb_max = _cfg("autotune.cb_consecutive_bad")
            cb_open_hours = _cfg("autotune.cb_open_hours")
            prev_cb_state = prev_circuit.get("state", "closed")
            prev_consecutive = prev_circuit.get("consecutive_bad", 0)

            # 判断本次是否"恶化"：hit_rate 相对下降 > degrade_pct
            is_bad = False
            if (prev_hit_rate is not None and curr_hit_rate is not None
                    and prev_hit_rate > 0 and len(adjustments) > 0):
                # 只在有调整的情况下才判定恶化（无调整时不计入）
                drop = (prev_hit_rate - curr_hit_rate) / prev_hit_rate
                is_bad = drop > cb_degrade_pct

            if prev_cb_state == "half_open":
                if is_bad:
                    # half_open 试探失败 → 重新 open
                    circuit_update = {
                        "state": "open",
                        "consecutive_bad": prev_consecutive + 1,
                        "open_since": datetime.now(timezone.utc).isoformat(),
                        "prev_good_snapshot": prev_circuit.get("prev_good_snapshot", {}),
                    }
                else:
                    # half_open 试探成功 → close
                    circuit_update = {"state": "closed", "consecutive_bad": 0}
            elif is_bad:
                new_consecutive = prev_consecutive + 1
                if new_consecutive >= cb_max:
                    # 触发熔断：rollback + open
                    snapshot = prev_circuit.get("param_snapshot", {})
                    rolled = _autotune_rollback_params(conn, project, snapshot)
                    circuit_update = {
                        "state": "open",
                        "consecutive_bad": new_consecutive,
                        "open_since": datetime.now(timezone.utc).isoformat(),
                        "prev_good_snapshot": snapshot,
                        "rollback": rolled,
                    }
                    # 在 adjustments 里记录回滚事件
                    for r in rolled:
                        adjustments.append({
                            "key": r["key"], "old": r["from"], "new": r["to"],
                            "reason": f"iter494 circuit_open: rollback after {new_consecutive} consecutive bad adjustments",
                        })
                else:
                    # 累积恶化计数，但尚未熔断
                    circuit_update = {
                        "state": "closed",
                        "consecutive_bad": new_consecutive,
                        "param_snapshot": {a["key"]: a["old"] for a in adjustments},
                    }
            else:
                # 指标没有恶化（好调整）— 更新快照，重置计数
                circuit_update = {
                    "state": "closed",
                    "consecutive_bad": 0,
                    "param_snapshot": {a["key"]: a["old"] for a in adjustments} if adjustments else prev_circuit.get("param_snapshot", {}),
                }
        except Exception:
            circuit_update = {}

    _autotune_save_state(project, stats, adjustments, circuit=circuit_update or None)

    cb_info = {}
    if circuit_update:
        cb_info = {"circuit_state": circuit_update.get("state", "closed"),
                   "consecutive_bad": circuit_update.get("consecutive_bad", 0)}

    return {
        "tuned": len(adjustments) > 0,
        "adjustments": adjustments,
        "stats": stats,
        "skipped_reason": "" if adjustments else "no adjustment needed",
        **cb_info,
    }


def _autotune_load_state(project: str) -> Optional[dict]:
    """加载项目的上次 autotune 状态。"""
    try:
        if _AUTOTUNE_STATE_FILE.exists():
            data = json.loads(_AUTOTUNE_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get(project)
    except Exception:
        pass
    return None


def _autotune_save_state(project: str, stats: dict, adjustments: list,
                         circuit: Optional[dict] = None) -> None:
    """持久化 autotune 状态。iter494：增加 circuit 字段。"""
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        data = {}
        if _AUTOTUNE_STATE_FILE.exists():
            try:
                data = json.loads(_AUTOTUNE_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
            "adjustments": [a["key"] for a in adjustments],
            "adjustment_count": len(adjustments),
        }
        if circuit is not None:
            entry["circuit"] = circuit
        data[project] = entry
        _AUTOTUNE_STATE_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception:
        pass


def _autotune_rollback_params(conn: sqlite3.Connection, project: str,
                               snapshot: dict) -> list:
    """
    iter494：将 per-project sysctl 回滚到 snapshot 中记录的值。
    OS 类比：git revert — 将文件系统恢复到已知好提交。

    参数：
      snapshot — {key: value} 调整前各参数的值
    返回：回滚的参数列表 [{key, from, to}]
    """
    try:
        from config import sysctl_set, get as _cfg
    except Exception:
        return []

    rolled = []
    for key, old_val in snapshot.items():
        try:
            current = _cfg(key, project=project)
            if current != old_val:
                sysctl_set(key, old_val, project=project)
                rolled.append({"key": key, "from": current, "to": old_val})
        except Exception:
            pass
    return rolled

# ── 迭代55：Context Pressure Governor ──────────────────────────────
#
# OS 类比：Linux TCP Congestion Control (Reno/CUBIC/BBR, 1988→2016)
#
# TCP 拥塞控制背景：
#   TCP 发送方不知道网络有多少剩余带宽。Reno (1988) 用 AIMD（加法增大/
#   乘法减小）试探：每 RTT cwnd += 1（加法增大），丢包时 cwnd /= 2（乘法
#   减小）。CUBIC (2008) 用三次函数替代线性增长，高带宽网络收敛更快。
#   BBR (2016, Google) 不依赖丢包信号，而是通过测量 RTprop（最小 RTT）
#   和 BtlBw（瓶颈带宽）主动建模链路容量，将发送速率设为 BtlBw × RTprop。
#
# memory-os 当前问题：
#   retriever/loader 注入量是静态配置（max_context_chars=600/800）——
#   无论上下文窗口多满多空，注入量都一样。
#   接近 compaction 时继续注入 600 字 = 加速溢出（TCP 拥塞后继续全速发送）
#   上下文很空时只注入 600 字 = 信息密度不足（TCP 在空闲链路上仍用 cwnd=1）
#
# 解决：
#   context_pressure_governor(conn, project) — 多信号压力估算 + 动态缩放因子
#
#   压力信号（多维度融合，类似 BBR 的 BtlBw + RTprop 双信号）：
#     1. conversation_turns — 当前会话轮次（从 recall_traces 计数）
#     2. compaction_count — 本会话已发生的 compaction 次数（从 dmesg swap_in 计）
#     3. time_since_compaction — 距上次 compaction 的时间
#
#   压力等级（四级水位，类比 kswapd 水位线）：
#     LOW      → scale=1.5（上下文充裕，多注入历史知识提升密度）
#     NORMAL   → scale=1.0（标准注入）
#     HIGH     → scale=0.6（接近 compaction，精简注入）
#     CRITICAL → scale=0.3（compaction 刚发生或高频发生，仅注入最关键信息）

# Governor 状态文件（跨 hook 调用持久化）
_GOVERNOR_STATE_FILE = MEMORY_OS_DIR / "governor_state.json"

# 压力等级常量
GOV_LOW = "LOW"
GOV_NORMAL = "NORMAL"
GOV_HIGH = "HIGH"
GOV_CRITICAL = "CRITICAL"


def context_pressure_governor(conn: sqlite3.Connection, project: str,
                              session_id: str = "") -> dict:
    """
    评估当前上下文压力并返回注入缩放因子。

    OS 类比：BBR 的 pacing_rate 计算 —
      pacing_rate = BtlBw × gain，其中 gain 根据 BBR 状态机切换：
        STARTUP(2.885) → DRAIN(1/2.885) → PROBE_BW(1.0/0.75/1.25) → PROBE_RTT(1.0)
      Governor 的 scale 就是 BBR 的 gain：
        LOW(1.5) → NORMAL(1.0) → HIGH(0.6) → CRITICAL(0.3)

    参数：
      conn       — SQLite 连接
      project    — 项目 ID
      session_id — 会话 ID（可选，从 dmesg 推断）

    返回 dict：
      level         — "LOW" / "NORMAL" / "HIGH" / "CRITICAL"
      scale         — float 缩放因子（0.3 ~ 1.5）
      turns         — 当前会话对话轮次
      compactions   — 本会话 compaction 次数
      secs_since_compact — 距上次 compaction 的秒数（-1 = 未发生过）
      reason        — 压力判定理由
    """
    from config import get as _cfg

    # ── 迭代63：时间窗口 + consecutive 衰减 ──
    # 根因修复：之前统计全量历史 swap_in/recall_traces（跨 session 累积），
    # 导致 compactions=20 → 永久 CRITICAL，注入窗口锁死在 0.3。
    # 修复：只统计最近 window_hours 内的信号（类比 Linux load average 1/5/15min 窗口）。

    window_hours = _cfg("governor.window_hours")  # 默认 2.0h
    decay_hours = _cfg("governor.consecutive_decay_hours")  # 默认 1.0h
    window_cutoff = (datetime.now(timezone.utc)
                     - timedelta(hours=window_hours)).isoformat()

    # ── 信号采集 ──

    # 信号1：当前时间窗口内的对话轮次（从 recall_traces 计数）
    turns = 0
    if session_id:
        try:
            row = conn.execute("""
                SELECT COUNT(*) FROM recall_traces
                WHERE project = ? AND session_id = ?
                  AND timestamp > ?
            """, (project, session_id, window_cutoff)).fetchone()
            turns = row[0] if row else 0
        except Exception:
            pass

    if turns == 0:
        try:
            row = conn.execute("""
                SELECT COUNT(DISTINCT prompt_hash) FROM recall_traces
                WHERE project = ? AND timestamp > ?
            """, (project, window_cutoff)).fetchone()
            turns = row[0] if row else 0
        except Exception:
            pass

    # 信号2：时间窗口内的 compaction 次数（从 dmesg swap_in 日志计数）
    compactions = 0
    last_compact_ts = None
    try:
        rows = conn.execute("""
            SELECT timestamp FROM dmesg
            WHERE subsystem = 'swap_in' AND timestamp > ?
            ORDER BY timestamp DESC
        """, (window_cutoff,)).fetchall()
        compactions = len(rows)
        if rows:
            last_compact_ts = rows[0][0]
    except Exception:
        pass

    # 信号3：距上次 compaction 的时间
    secs_since_compact = -1
    if last_compact_ts:
        try:
            dt = datetime.fromisoformat(last_compact_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            secs_since_compact = (datetime.now(timezone.utc) - dt).total_seconds()
        except Exception:
            pass

    # 信号4：读取持久化的 governor 状态（连续压力追踪 + 衰减）
    prev_state = _governor_load_state()
    consecutive_high = prev_state.get("consecutive_high", 0)

    # 迭代63：consecutive_high 自动衰减 — 超过 decay_hours 未更新则 reset
    prev_updated = prev_state.get("updated_at", "")
    if prev_updated and consecutive_high > 0:
        try:
            prev_dt = datetime.fromisoformat(prev_updated)
            if prev_dt.tzinfo is None:
                prev_dt = prev_dt.replace(tzinfo=timezone.utc)
            hours_since = (datetime.now(timezone.utc) - prev_dt).total_seconds() / 3600
            if hours_since > decay_hours:
                consecutive_high = 0  # 衰减：长时间无活动 → reset
        except Exception:
            pass

    # ── 压力判定（多信号融合，迭代63 重构）──
    # 核心变更：compaction 从"累积次数"改为"近期频率+冷却时间"双信号判定。
    # 根因：跨 session 累积的 compaction 次数会持续误判 CRITICAL，
    #       即使当前 session 刚开始（turns=2）也被锁死在最低注入。
    #
    # 新判定逻辑（优先级从高到低）：
    #   1. 近期密集 compaction（10分钟内 ≥2 次）→ CRITICAL（当前正在高频 compact）
    #   2. consecutive_high ≥3 → CRITICAL（持续高压未缓解）
    #   3. 近期 compaction（2分钟内刚发生）→ HIGH
    #   4. turns ≥ critical → HIGH（对话轮次驱动）
    #   5. turns ≥ high → HIGH
    #   6. turns ≤ low → LOW（上下文充裕）
    #   7. 其余 → NORMAL

    turns_low = _cfg("governor.turns_low")            # 默认 5
    turns_high = _cfg("governor.turns_high")           # 默认 15
    turns_critical = _cfg("governor.turns_critical")   # 默认 25
    compact_high = _cfg("governor.compact_high")       # 默认 2
    compact_critical = _cfg("governor.compact_critical")  # 默认 4
    recent_compact_secs = _cfg("governor.recent_compact_secs")  # 默认 120

    # 迭代63：计算近期密集 compaction（最近 10 分钟内的次数）
    recent_burst_secs = 600  # 10 分钟
    burst_cutoff = (datetime.now(timezone.utc)
                    - timedelta(seconds=recent_burst_secs)).isoformat()
    recent_burst = 0
    try:
        row = conn.execute("""
            SELECT COUNT(*) FROM dmesg
            WHERE subsystem = 'swap_in' AND timestamp > ?
        """, (burst_cutoff,)).fetchone()
        recent_burst = row[0] if row else 0
    except Exception:
        pass

    level = GOV_NORMAL
    reason = "standard"
    scale = 1.0

    # 规则1：近期密集 compaction（10分钟内 ≥ compact_critical 次）→ 当前真正高压
    if recent_burst >= compact_critical or consecutive_high >= 3:
        level = GOV_CRITICAL
        scale = _cfg("governor.scale_critical")  # 默认 0.3
        reason = f"burst={recent_burst}/10min consecutive_high={consecutive_high}"
    # 规则2：近期有 compaction（10分钟内 ≥ compact_high 次）
    elif recent_burst >= compact_high or turns >= turns_critical:
        level = GOV_HIGH
        scale = _cfg("governor.scale_high")  # 默认 0.6
        reason = f"burst={recent_burst}/10min turns={turns}"
    elif 0 < secs_since_compact < recent_compact_secs:
        # 刚 compaction 过（2 分钟内）— 高压状态
        level = GOV_HIGH
        scale = _cfg("governor.scale_high")
        reason = f"recent_compact {secs_since_compact:.0f}s ago"
    elif turns >= turns_high:
        level = GOV_HIGH
        scale = _cfg("governor.scale_high")
        reason = f"turns={turns}"
    elif turns <= turns_low:
        # 上下文很新很空 — 可以多注入
        level = GOV_LOW
        scale = _cfg("governor.scale_low")  # 默认 1.5
        reason = f"fresh_context turns={turns}"

    # 更新持久状态
    new_consecutive = (consecutive_high + 1) if level in (GOV_HIGH, GOV_CRITICAL) else 0
    _governor_save_state({
        "level": level,
        "scale": scale,
        "turns": turns,
        "compactions": compactions,
        "consecutive_high": new_consecutive,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })

    return {
        "level": level,
        "scale": scale,
        "turns": turns,
        "compactions": compactions,
        "secs_since_compact": secs_since_compact,
        "consecutive_high": new_consecutive,
        "reason": reason,
    }


def _governor_load_state() -> dict:
    """加载 governor 持久化状态"""
    if _GOVERNOR_STATE_FILE.exists():
        try:
            return json.loads(_GOVERNOR_STATE_FILE.read_text("utf-8"))
        except Exception:
            pass
    return {}


def _governor_save_state(state: dict):
    """保存 governor 状态"""
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        _GOVERNOR_STATE_FILE.write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception:
        pass


# ── 迭代362：Swap Warmup — 会话启动时预热高价值 swap chunk ───────────────────
# OS 类比：Linux MGLRU proactive reclaim (5.17+) 反向操作 — 在进程首次访问页面之前，
#   kswapd 已根据访问历史将热 swap page 提前 swap_in 到 inactive_list。
#   传统模型：page fault → swap_in（每次 query 都付 swap_fault 检测开销）
#   MGLRU 模型：后台 scan 热 swap page → 提前 swap_in → 首次访问命中 page cache
#
# memory-os 等价问题：
#   swap_chunks 中有高 importance（avg=0.885）的 chunk，0 次 swap_fault 被触发，
#   因为 swap_fault 只在 FTS5 完全 miss（use_fts=False）时才执行。
#   这些高价值 chunk 在新会话中永远不被找到（dead cold start）。
#
# 解决：会话启动时（loader/session_start hook）调用一次 warmup_swap_cache：
#   1. 查询 swap_chunks 中 importance >= threshold 的高价值 chunk
#   2. swap_in 恢复到主表（memory_chunks）
#   3. 后续 retriever 正常 FTS5 路径即可召回这些 chunk
#   4. 有每会话冷却（_WARMUP_COOLDOWN_FILE）防止重复执行

_WARMUP_COOLDOWN_FILE = MEMORY_OS_DIR / ".last_swap_warmup.json"
_WARMUP_SESSION_COOLDOWN = 300.0  # 同一 session 内最多每 5 分钟执行一次


def warmup_swap_cache(conn: sqlite3.Connection, project: str,
                      importance_threshold: float = 0.8,
                      max_warmup: int = 10,
                      session_id: str = "") -> dict:
    """
    迭代362：会话启动预热 — 将 swap_chunks 中高 importance chunk 恢复到主表。

    Args:
        conn: 写连接（swap_in 需要修改主表）
        project: 项目 ID
        importance_threshold: 最低 importance 阈值（默认 0.8）
        max_warmup: 最多恢复 chunk 数（防止冷启动加速过度）
        session_id: 当前 session ID（用于冷却判断）

    Returns:
        {restored_count, skipped_cooldown, chunk_ids}
    """
    import time as _wt

    # ── 冷却检查：同一 session 内防止重复执行 ──
    try:
        if _WARMUP_COOLDOWN_FILE.exists():
            cooldown_data = json.loads(_WARMUP_COOLDOWN_FILE.read_text("utf-8"))
            last_session = cooldown_data.get("session_id", "")
            last_ts = cooldown_data.get("timestamp", 0.0)
            now_ts = _wt.time()
            if (last_session == session_id and session_id
                    and (now_ts - last_ts) < _WARMUP_SESSION_COOLDOWN):
                return {"restored_count": 0, "skipped_cooldown": True, "chunk_ids": []}
    except Exception:
        pass  # 冷却文件读取失败，继续执行

    try:
        from store_core import swap_in as _swap_in, swap_fault as _swap_fault
    except Exception:
        return {"restored_count": 0, "skipped_cooldown": False, "chunk_ids": []}

    # ── 查询 swap_chunks 中高价值 chunk ──
    # swap_chunks 表字段：id, swapped_at, project, chunk_type, original_importance,
    #   access_count_at_swap, compressed_data（无 resolved 字段）
    try:
        rows = conn.execute(
            """SELECT id, original_importance FROM swap_chunks
               WHERE project = ?
                 AND original_importance >= ?
               ORDER BY original_importance DESC
               LIMIT ?""",
            (project, importance_threshold, max_warmup),
        ).fetchall()
    except Exception:
        return {"restored_count": 0, "skipped_cooldown": False, "chunk_ids": []}

    if not rows:
        return {"restored_count": 0, "skipped_cooldown": False, "chunk_ids": []}

    swap_ids = [r[0] for r in rows]

    # ── 执行 swap_in ──
    try:
        result = _swap_in(conn, swap_ids)
        restored_count = result.get("restored_count", 0)

        if restored_count > 0:
            conn.commit()
            try:
                dmesg_log(conn, DMESG_INFO, "warmup",
                          f"swap_warmup: restored={restored_count} "
                          f"imp>={importance_threshold:.2f} project={project}",
                          session_id=session_id, project=project)
            except Exception:
                pass

        # ── 更新冷却文件 ──
        try:
            MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
            _WARMUP_COOLDOWN_FILE.write_text(
                json.dumps({"session_id": session_id,
                            "timestamp": _wt.time(),
                            "restored_count": restored_count},
                           ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception:
            pass

        return {"restored_count": restored_count, "skipped_cooldown": False,
                "chunk_ids": swap_ids[:restored_count]}

    except Exception:
        return {"restored_count": 0, "skipped_cooldown": False, "chunk_ids": []}


# ── page_idle — Idle Page Tracking（迭代511）────────────────────────────
# OS 类比：Linux /sys/kernel/mm/page_idle/bitmap (Vladimir Davydov, 2015)
#
# Linux page_idle 机制：
#   用户态工具通过 /sys/kernel/mm/page_idle/bitmap 标记物理页帧为 "idle"，
#   然后等待一个观察周期。周期结束后仍标记为 idle 的页面说明没被任何进程访问，
#   可以安全回收。与 LRU 的"相对顺序"和 DAMON 的"采样估算"不同，
#   page_idle 提供精确的 per-page 活跃/空闲状态。
#
# memory-os 类比：
#   问题：DAMON 依赖 dead_age_days=30（在 2-3 天数据中永不触发），
#         shrink_dcache 依赖 min_age_days=3（但 import 批量导入的 chunk created_at 较新），
#         oom_reaper 只看零访问率阈值（全局粗粒度）。
#   解决：page_idle 按"会话轮次"追踪——每个 SessionStart 标记当前所有 chunks 为 idle，
#         本轮会话期间被检索命中的 chunk 从 idle set 移除。
#         下次 SessionStart 时，连续 N 轮仍为 idle 的 chunks 执行降级/淘汰。
#         这是精确的、按使用事实判定的机制，不依赖绝对时间。

_PAGE_IDLE_FILE = MEMORY_OS_DIR / "page_idle_bitmap.json"


def page_idle_mark(conn: sqlite3.Connection, project: str) -> dict:
    """
    标记阶段：将当前项目所有 chunk 标记为 idle。

    在 SessionStart 时调用。记录 {chunk_id: idle_rounds} 到 bitmap 文件。
    - 新出现的 chunk：idle_rounds = 1
    - 已存在于 bitmap 中的（上轮仍为 idle）：idle_rounds += 1
    - 上轮被检索命中的（已从 bitmap 移除）：不在文件中，本轮重新标记为 1

    返回：
      marked — 本轮标记的 chunk 数
      carried_over — 从上轮延续的（连续 idle）chunk 数
    """
    try:
        # 获取当前项目所有 active chunk IDs
        rows = conn.execute(
            """SELECT id FROM memory_chunks
               WHERE project = ? AND chunk_type != 'task_state'""",
            (project,)
        ).fetchall()
        current_ids = {r[0] for r in rows}

        if not current_ids:
            return {"marked": 0, "carried_over": 0}

        # 加载上轮 bitmap
        old_bitmap = _page_idle_load()
        project_bitmap = old_bitmap.get(project, {})

        # 构建新 bitmap：当前存在的 chunk 全标 idle
        new_project_bitmap = {}
        carried_over = 0
        for cid in current_ids:
            if cid in project_bitmap:
                # 连续 idle：轮次 +1
                new_project_bitmap[cid] = project_bitmap[cid] + 1
                carried_over += 1
            else:
                # 新标记或上轮被访问过（已移除）
                new_project_bitmap[cid] = 1

        # 保存
        old_bitmap[project] = new_project_bitmap
        _page_idle_save(old_bitmap)

        return {"marked": len(new_project_bitmap), "carried_over": carried_over}

    except Exception:
        return {"marked": 0, "carried_over": 0}


def page_idle_clear(chunk_ids: list, project: str) -> int:
    """
    清除阶段：将被访问的 chunk 从 idle bitmap 中移除。

    在 retriever 检索命中后调用（与 update_accessed/mglru_promote 同路径）。
    移除意味着"本轮会话中被使用了"，下次 mark 时不会被判为连续 idle。

    返回：实际清除的 chunk 数
    """
    if not chunk_ids:
        return 0
    try:
        bitmap = _page_idle_load()
        project_bitmap = bitmap.get(project, {})
        if not project_bitmap:
            return 0

        cleared = 0
        for cid in chunk_ids:
            if cid in project_bitmap:
                del project_bitmap[cid]
                cleared += 1

        if cleared > 0:
            bitmap[project] = project_bitmap
            _page_idle_save(bitmap)

        return cleared
    except Exception:
        return 0


def page_idle_scan(conn: sqlite3.Connection, project: str) -> dict:
    """
    收割阶段：对连续多轮 idle 的 chunks 执行降级。

    在 SessionStart 时调用（mark 之前），扫描 bitmap 中 idle_rounds >= threshold 的 chunk。
    动作：
      - idle_rounds >= idle_demote_rounds (默认 3)：importance *= decay_factor + oom_adj += 200
      - idle_rounds >= idle_delete_rounds (默认 5)：importance < 0.2 的直接删除
    保护：
      - oom_adj <= -500 (mlock) 的 chunk 不处理
      - design_constraint/quantitative_evidence 类型不删除（只降级）
      - task_state 不参与（mark 时已排除）

    返回：
      scanned — 扫描的 chunk 数
      demoted — 降级的 chunk 数
      deleted — 删除的 chunk 数
      max_idle_rounds — 最大连续 idle 轮次
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"scanned": 0, "demoted": 0, "deleted": 0, "max_idle_rounds": 0}

    demote_rounds = _cfg("page_idle.demote_rounds")
    delete_rounds = _cfg("page_idle.delete_rounds")
    decay_factor = _cfg("page_idle.decay_factor")
    demote_oom_adj = _cfg("page_idle.demote_oom_adj")
    protect_types = ("design_constraint", "quantitative_evidence")

    bitmap = _page_idle_load()
    project_bitmap = bitmap.get(project, {})

    if not project_bitmap:
        return {"scanned": 0, "demoted": 0, "deleted": 0, "max_idle_rounds": 0}

    # 找出需要处理的 chunk IDs（idle_rounds >= demote_rounds）
    candidates = {cid: rounds for cid, rounds in project_bitmap.items()
                  if rounds >= demote_rounds}

    if not candidates:
        max_rounds = max(project_bitmap.values()) if project_bitmap else 0
        return {"scanned": len(project_bitmap), "demoted": 0, "deleted": 0,
                "max_idle_rounds": max_rounds}

    # 批量查询 chunk 元数据
    cid_list = list(candidates.keys())
    placeholders = ",".join("?" * len(cid_list))
    rows = conn.execute(
        f"""SELECT id, importance, oom_adj, chunk_type FROM memory_chunks
            WHERE id IN ({placeholders})""",
        cid_list
    ).fetchall()

    demoted = 0
    deleted = 0
    delete_ids = []

    for chunk_id, importance, oom_adj, chunk_type in rows:
        # 保护：mlock 的 chunk 不处理
        if oom_adj <= -500:
            continue

        idle_rounds = candidates[chunk_id]

        # 降级：importance 衰减 + oom_adj 升高
        new_importance = importance * decay_factor
        new_oom_adj = min(oom_adj + demote_oom_adj, OOM_ADJ_MAX)

        # 删除条件：超过 delete_rounds 且 importance 已很低
        if (idle_rounds >= delete_rounds and new_importance < 0.2
                and chunk_type not in protect_types):
            delete_ids.append(chunk_id)
            deleted += 1
        else:
            # 执行降级
            conn.execute(
                """UPDATE memory_chunks SET importance = ?, oom_adj = ?
                   WHERE id = ?""",
                (round(new_importance, 4), new_oom_adj, chunk_id)
            )
            demoted += 1

    # 批量删除
    if delete_ids:
        delete_chunks(conn, delete_ids)
        # 从 bitmap 中移除已删除的
        for cid in delete_ids:
            project_bitmap.pop(cid, None)
        bitmap[project] = project_bitmap
        _page_idle_save(bitmap)

    if demoted > 0 or deleted > 0:
        conn.commit()
        try:
            bump_chunk_version()
        except Exception:
            pass
        # iter538: 移除内部 dmesg_log — loader 调用方已负责记录，避免 ring buffer 双写

    max_rounds = max(project_bitmap.values()) if project_bitmap else 0
    return {"scanned": len(project_bitmap), "demoted": demoted,
            "deleted": deleted, "max_idle_rounds": max_rounds}


# ── munlock_idle — Revoke Stale mlock Protection（iter528）─────────────
#
# OS 类比：Linux munlock() + MADV_COLD (Minchan Kim, 2019)
#   mlock 页面不会被 swap out，但当进程退出或 admin 决定后可以 munlock。
#   Android PROCESS_STATE_CACHED 触发 MADV_COLD 对 locked pages 降级。
#   关键原则：mlock 不是永久的，应有续期机制——长期无访问的 mlock 页面应被 revoke。
#
# 问题（数据驱动）：
#   16 个 mlock chunks (oom_adj<=-500) 中 7 个 access_count=0（43% 资源从未被使用）。
#   page_idle bitmap 显示这些 chunk 已连续 24 轮空闲，但因 mlock 保护跳过所有回收器。
#   mlock 一旦设置永不过期 → 无效知识永久占位 → 检索噪声（FTS5 候选池膨胀）。
#
# 解决：
#   munlock_idle(conn, project) — 撤销从未被验证的 mlock 保护：
#     条件：oom_adj <= -500 AND access_count = 0 AND idle_rounds >= threshold
#     动作：oom_adj → OOM_ADJ_DEFAULT(0)，解除保护，允许 page_idle/shrink_dcache 正常降级
#     保护：design_constraint 类型有 grace period（创建 < N 天不处理）


def munlock_idle(conn: sqlite3.Connection, project: str) -> dict:
    """
    iter528: 撤销从未被检索验证的 mlock 保护。

    mlock (oom_adj<=-500) 应保护**经过实战验证**的核心知识。
    但某些 chunk 被创建时即获得 mlock，之后从未被 retriever 召回（access=0）。
    这些 chunk 占据 FTS5 候选池且不可回收，是 mlock 资源浪费。

    触发条件：
      - oom_adj <= -500 (mlock 级别)
      - access_count = 0 (从未被 retriever 召回验证)
      - 存在于 page_idle bitmap 且 idle_rounds >= munlock_idle_rounds

    动作：oom_adj → 0 (OOM_ADJ_DEFAULT)，解除 mlock 保护。
    不修改 importance（让 page_idle/numa_balancing 正常衰减）。

    保护机制：
      - design_constraint 有 grace_days 宽限期（新创建的约束需要时间被验证）
      - pinned chunks (MCP pin_memory) 不处理
      - access_count > 0 的 chunk 已被实战验证，保留 mlock
    """
    t0 = _time.time()

    # 读取配置
    try:
        from config import get as _cfg
    except Exception:
        _cfg = lambda k: None

    munlock_rounds = _cfg("munlock.idle_rounds") or 5
    grace_days = _cfg("munlock.grace_days") or 7
    max_per_scan = _cfg("munlock.max_per_scan") or 20

    # Phase 1: 找到所有 mlock + zero-access chunks
    mlock_chunks = conn.execute(
        """SELECT id, chunk_type, importance, oom_adj, access_count, created_at
           FROM memory_chunks
           WHERE project = ? AND oom_adj <= -500 AND access_count = 0""",
        (project,)
    ).fetchall()

    if not mlock_chunks:
        return {"scanned": 0, "unlocked": 0, "skipped_grace": 0,
                "skipped_pinned": 0, "duration_ms": 0}

    # Phase 2: 加载 page_idle bitmap 验证 idle 轮次
    bitmap = _page_idle_load()
    project_bitmap = bitmap.get(project, {})

    now = datetime.now(timezone.utc)
    unlocked = 0
    skipped_grace = 0
    skipped_pinned = 0
    unlocked_ids = []

    for chunk_id, chunk_type, importance, oom_adj, access_count, created_at in mlock_chunks:
        if unlocked >= max_per_scan:
            break

        # 检查 idle_rounds
        idle_rounds = project_bitmap.get(chunk_id, 0)
        if idle_rounds < munlock_rounds:
            continue

        # Grace period：design_constraint 新创建的不处理
        if chunk_type == "design_constraint" and created_at:
            try:
                dt = datetime.fromisoformat(created_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = (now - dt).total_seconds() / 86400
                if age_days < grace_days:
                    skipped_grace += 1
                    continue
            except Exception:
                pass

        # 执行 munlock：oom_adj → 0
        conn.execute(
            "UPDATE memory_chunks SET oom_adj = ? WHERE id = ?",
            (OOM_ADJ_DEFAULT, chunk_id)
        )
        unlocked += 1
        unlocked_ids.append(chunk_id)

    if unlocked > 0:
        conn.commit()
        try:
            bump_chunk_version()
        except Exception:
            pass
        try:
            dmesg_log(conn, DMESG_INFO, "munlock_idle",
                      f"unlocked={unlocked} scanned={len(mlock_chunks)} "
                      f"skipped_grace={skipped_grace}",
                      project=project,
                      extra={"unlocked_ids": unlocked_ids[:10]})
        except Exception:
            pass

    duration_ms = (_time.time() - t0) * 1000
    return {
        "scanned": len(mlock_chunks),
        "unlocked": unlocked,
        "skipped_grace": skipped_grace,
        "skipped_pinned": skipped_pinned,
        "duration_ms": round(duration_ms, 2),
    }


# ── mlock_onfault_promote — mlock2(MLOCK_ONFAULT) Page Fault Promotion（iter531）──
#
# OS 类比：Linux mlock2(MLOCK_ONFAULT) (Eric B Munson, 2015, kernel 4.4)
#   mlock() 立即锁定所有页面；mlock2(MLOCK_ONFAULT) 仅标记地址范围为"lock-on-fault"，
#   页面在首次 page fault 时才被锁入 RAM。这避免了预分配未使用页面的资源浪费。
#
# 问题（数据驱动）：
#   extractor 在写入时立即授予 OOM_ADJ_PROTECTED(-500) 给 quantitative_evidence 和
#   design_constraint 类型 chunks。这些 chunk 在被 retriever 召回验证前就获得了完全保护，
#   导致 5/18 零访问 chunks 拥有 mlock 且 munlock_idle 需 5 轮才能撤销（太慢）。
#
# 解决：
#   写入时使用 OOM_ADJ_ONFAULT(-200) 代替 OOM_ADJ_PROTECTED(-500)：
#     - -200: 受保护于 aggressive reclaim（oom_reaper 阈值 -500），但 page_idle/numa_balancing 可降级
#     - 首次检索命中（page fault）时 promote 到 OOM_ADJ_PROTECTED(-500)
#   retriever write-back 路径调用 mlock_onfault_promote(conn, accessed_ids)


def mlock_onfault_promote(conn: sqlite3.Connection, chunk_ids: list) -> dict:
    """
    iter531: mlock2(MLOCK_ONFAULT) — 首次检索命中时将 ONFAULT 升级为 PROTECTED。

    当 retriever 命中一个 oom_adj == OOM_ADJ_ONFAULT(-200) 的 chunk 时，
    说明该知识已被实战验证有价值，将其升级为真正的 mlock (OOM_ADJ_PROTECTED=-500)。

    条件：oom_adj == -200 (ONFAULT 状态，尚未被验证)
    动作：oom_adj → -500 (PROTECTED，经过验证的核心知识)

    幂等：已经是 -500 或更低的 chunk 不受影响。
    """
    if not chunk_ids:
        return {"promoted": 0}

    from store_swap import OOM_ADJ_ONFAULT, OOM_ADJ_PROTECTED

    promoted = 0
    for cid in chunk_ids:
        row = conn.execute(
            "SELECT oom_adj FROM memory_chunks WHERE id = ?", (cid,)
        ).fetchone()
        if row and row[0] == OOM_ADJ_ONFAULT:
            conn.execute(
                "UPDATE memory_chunks SET oom_adj = ? WHERE id = ?",
                (OOM_ADJ_PROTECTED, cid)
            )
            promoted += 1

    if promoted:
        try:
            from store_vfs import bump_chunk_version
            bump_chunk_version()
        except Exception:
            pass

    return {"promoted": promoted}


# ── oom_reaper_onfault — MLOCK_ONFAULT Demotion Reaper（iter542）───────────────
#
# OS 类比：Linux oom_reaper (Michal Hocko, 2016, kernel 4.6)
#   OOM killer 标记牺牲进程 TIF_MEMDIE 后，若进程阻塞在不可中断 sleep（D state），
#   内存无法释放。oom_reaper 内核线程独立异步回收其匿名页，不等待进程退出。
#   关键设计：oom_reaper 仅处理 TIF_MEMDIE 已标记但未释放的进程——
#   介于 "已选中" 和 "已回收" 之间的死区。
#
# 问题（数据驱动）：
#   mlock2(MLOCK_ONFAULT) iter531 为 quantitative_evidence / design_constraint
#   在写入时授予 oom_adj=-200（延迟保护，等待首次检索命中后升级为 -500）。
#   但如果 chunk 从未被检索命中（永远不 page fault），它处于保护死区：
#     - munlock_idle 只扫描 oom_adj <= -500，不管 -200
#     - 全局 oom_reaper（iter508）需零访问率 >70% 才触发，当前 20.5% 远不够
#     - 结果：5/5 oom_adj=-200 chunks 零访问，100% 浪费保护槽位
#   这等价于 TIF_MEMDIE 进程卡在 D state——已被标记但内存永远不释放。

def oom_reaper_onfault(conn: sqlite3.Connection, project: str) -> dict:
    """
    iter542: oom_reaper_onfault — 定向回收从未 page fault 的 ONFAULT chunk。

    扫描 oom_adj == OOM_ADJ_ONFAULT(-200) + access_count == 0 + 超过宽限期的 chunks，
    将其降级为 OOM_ADJ_DEFAULT(0)，允许正常回收路径处理。

    与 munlock_idle 的区别：
      - munlock_idle: oom_adj <= -500 → 0（解除硬保护）
      - oom_reaper_onfault: oom_adj == -200 → 0（ONFAULT 死区 → 正常优先级）

    与 oom_reaper（iter508）的区别：
      - iter508: 全局零访问率 >70% 才触发（大规模危机 last resort）
      - iter542: 精确定向 ONFAULT chunk，无全局阈值（手术刀 vs 核弹）

    降级而非删除：给 chunk 一次被自然回收的机会（kswapd/page_idle/numa_balancing）。
    如果 chunk 后续被检索命中，retriever 的 mlock_onfault_promote 会重新升级它。

    宽限期：grace_sessions（默认 3），给新 chunk 至少 N 个 session 的曝光机会。
    """
    t0 = _time.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"scanned": 0, "reaped": 0, "skipped_grace": 0, "duration_ms": 0}

    grace_sessions = int(_cfg("oom_reaper_onfault.grace_sessions") or 3)
    max_per_scan = int(_cfg("oom_reaper_onfault.max_per_scan") or 10)

    # Phase 1: 找到所有 ONFAULT + zero-access chunks
    from store_core import OOM_ADJ_ONFAULT
    candidates = conn.execute(
        """SELECT id, chunk_type, importance, created_at, source_session
           FROM memory_chunks
           WHERE project IN (?, 'global')
             AND oom_adj = ?
             AND access_count = 0""",
        (project, OOM_ADJ_ONFAULT)
    ).fetchall()

    if not candidates:
        return {"scanned": 0, "reaped": 0, "skipped_grace": 0,
                "duration_ms": round((_time.time() - t0) * 1000, 2)}

    # Phase 2: 计算 session 年龄（用 page_idle bitmap 的 idle_rounds 作近似）
    bitmap = _page_idle_load()
    project_bitmap = bitmap.get(project, {})
    global_bitmap = bitmap.get("global", {})

    reaped = 0
    skipped_grace = 0
    reaped_ids = []

    for chunk_id, chunk_type, importance, created_at, source_session in candidates:
        if reaped >= max_per_scan:
            break

        # 宽限期检查：idle_rounds < grace_sessions → 跳过
        idle_rounds = project_bitmap.get(chunk_id, global_bitmap.get(chunk_id, 0))
        if idle_rounds < grace_sessions:
            skipped_grace += 1
            continue

        # 执行降级：oom_adj → OOM_ADJ_DEFAULT(0)
        # 不用 PREFER(500) 避免过度惩罚——给 chunk 回到正常回收优先级的机会
        conn.execute(
            "UPDATE memory_chunks SET oom_adj = ? WHERE id = ?",
            (OOM_ADJ_DEFAULT, chunk_id)
        )
        reaped += 1
        reaped_ids.append(chunk_id)

    if reaped > 0:
        conn.commit()
        try:
            bump_chunk_version()
        except Exception:
            pass
        try:
            dmesg_log(conn, DMESG_INFO, "oom_reaper_onfault",
                      f"reaped={reaped} scanned={len(candidates)} "
                      f"skipped_grace={skipped_grace}",
                      project=project,
                      extra={"reaped_ids": reaped_ids[:10]})
        except Exception:
            pass

    duration_ms = (_time.time() - t0) * 1000
    return {
        "scanned": len(candidates),
        "reaped": reaped,
        "skipped_grace": skipped_grace,
        "reaped_ids": reaped_ids,
        "duration_ms": round(duration_ms, 2),
    }


# ── gc_namespace — Process Namespace Cleanup（迭代512）───────────────

# 测试 namespace 正则：匹配 test_*、test-*、perf_*、bench_* 前缀的 project ID
_TEST_NS_RE = re.compile(
    r'^(?:test[-_]|perf[-_]|bench[-_]|forktest|time-test|func-test)',
    re.IGNORECASE
)


def gc_namespace(conn: sqlite3.Connection) -> dict:
    """
    迭代512：gc_namespace — 跨项目测试命名空间清理。
    OS 类比：Linux pid_ns_release_proc() (Eric Biederman, 2006)
      — PID namespace 销毁时清理所有命名空间内进程的 /proc 条目、
        cgroup 关联和信号队列。内核不遍历全局进程表，
        而是按 namespace 隔离域批量释放。

    根因：
      tmpfs 隔离（iter54）防止了 chunk 污染，但 recall_traces、
      checkpoints、shadow_traces 等辅助表仍可被测试 session 写入
      生产 DB（测试 project ID 如 test_psi_normal、test-swap-compat）。
      gc_traces 只做时间/容量 GC，从不识别 test namespace。
      这些 ghost traces 污染 readahead_pairs() 的共现计算。

    策略：
      1. 枚举 recall_traces/checkpoints/shadow_traces 中所有 project
      2. 匹配 _TEST_NS_RE 的 project ID 视为"已销毁的 test namespace"
      3. 批量清理这些 namespace 的所有 artifacts
      4. 同时清理 memory_chunks 中匹配 test namespace 的残留（防御性）

    保护：
      - 只匹配明确的测试前缀模式（test_/test-/perf_/bench_/forktest/...）
      - 不触碰真实 project（git:*/abspath:*/global/gitroot:*）
      - 冷启动安全：空表直接跳过

    返回 dict:
      test_projects    — 发现的测试 project 列表
      traces_deleted   — 删除的 recall_traces 条数
      checkpoints_deleted — 删除的 checkpoints 条数
      shadows_deleted  — 删除的 shadow_traces 条数
      chunks_deleted   — 删除的 memory_chunks 条数（防御性）
    """
    result = {
        "test_projects": [],
        "traces_deleted": 0,
        "checkpoints_deleted": 0,
        "shadows_deleted": 0,
        "chunks_deleted": 0,
    }

    # Phase 1: 发现所有 test namespace project IDs
    test_projects = set()

    # 扫描 recall_traces
    try:
        for (proj,) in conn.execute(
            "SELECT DISTINCT project FROM recall_traces"
        ).fetchall():
            if proj and _TEST_NS_RE.match(proj):
                test_projects.add(proj)
    except Exception:
        pass

    # 扫描 checkpoints
    try:
        for (proj,) in conn.execute(
            "SELECT DISTINCT project FROM checkpoints"
        ).fetchall():
            if proj and _TEST_NS_RE.match(proj):
                test_projects.add(proj)
    except Exception:
        pass

    # 扫描 shadow_traces
    try:
        for (proj,) in conn.execute(
            "SELECT DISTINCT project FROM shadow_traces"
        ).fetchall():
            if proj and _TEST_NS_RE.match(proj):
                test_projects.add(proj)
    except Exception:
        pass

    # 扫描 memory_chunks（防御性 — tmpfs 应已隔离，但历史残留可能存在）
    try:
        for (proj,) in conn.execute(
            "SELECT DISTINCT project FROM memory_chunks"
        ).fetchall():
            if proj and _TEST_NS_RE.match(proj):
                test_projects.add(proj)
    except Exception:
        pass

    if not test_projects:
        return result

    result["test_projects"] = sorted(test_projects)

    # Phase 2: 批量清理每个 test namespace 的 artifacts
    for proj in test_projects:
        # recall_traces
        try:
            cur = conn.execute(
                "DELETE FROM recall_traces WHERE project=?", (proj,))
            result["traces_deleted"] += cur.rowcount
        except Exception:
            pass

        # checkpoints
        try:
            cur = conn.execute(
                "DELETE FROM checkpoints WHERE project=?", (proj,))
            result["checkpoints_deleted"] += cur.rowcount
        except Exception:
            pass

        # shadow_traces
        try:
            cur = conn.execute(
                "DELETE FROM shadow_traces WHERE project=?", (proj,))
            result["shadows_deleted"] += cur.rowcount
        except Exception:
            pass

        # memory_chunks（防御性，含 FTS5 同步）
        try:
            chunk_ids = [
                row[0] for row in conn.execute(
                    "SELECT id FROM memory_chunks WHERE project=?", (proj,)
                ).fetchall()
            ]
            if chunk_ids:
                delete_chunks(conn, chunk_ids)
                result["chunks_deleted"] += len(chunk_ids)
        except Exception:
            pass

    try:
        conn.commit()
    except Exception:
        pass

    return result


# ── iter513: overcommit_kill — Global Layer Aggressive Reclaim ──────────────

def overcommit_kill(conn: "sqlite3.Connection") -> dict:
    """iter513: overcommit_kill — global 层过度承诺知识的强制回收。

    OS 类比：Linux vm.overcommit_memory=2 strict accounting (Rik van Riel, 2001)
    ——当系统过度承诺虚拟内存（RSS 远超物理内存+swap）时，OOM killer 强制回收。

    解决的问题：
      - global 层 254 chunks, 85% 零访问率（batch import 绕过有机准入）
      - oom_reaper 每次 30 个 ×0.5 衰减，高 importance chunks 需 3 轮才被删
      - 216 零访问 / 30 每轮 × 3 轮 = 21.6 sessions 才能清空
      - 但 import_knowledge 持续注入，形成"写入-回收竞赛"永远追不上

    策略（与 oom_reaper 的区别）：
      - 仅针对 project='global'（批量导入的知识堆积区）
      - 激进衰减 ×0.3（而非 ×0.5）—— 未经实战验证的知识不值得温和对待
      - 更高删除阈值 < 0.35（而非 < 0.2）—— 加速清除
      - 更大批量 50/scan（而非 30）—— 追赶写入速度
      - 仅保护 design_constraint + pinned（不保护 quantitative_evidence）

    调用时机：loader.py SessionStart，在 oom_reaper 之后。
    """
    import time as _time
    _t0 = _time.time()

    result = {
        "triggered": False,
        "global_total": 0,
        "global_zero_access": 0,
        "zero_access_ratio": 0.0,
        "reaped": 0,
        "deleted": 0,
        "duration_ms": 0.0,
    }

    try:
        from config import get as _cfg
        threshold = float(_cfg("overcommit.zero_access_threshold"))
        max_reap = int(_cfg("overcommit.max_reap_per_scan"))
        decay = float(_cfg("overcommit.importance_decay"))
        min_global = int(_cfg("overcommit.min_global_chunks"))
        delete_threshold = float(_cfg("overcommit.delete_threshold"))
    except Exception:
        threshold = 0.6
        max_reap = 50
        decay = 0.3
        min_global = 30
        delete_threshold = 0.35

    # 只处理 global 层
    total = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project = 'global'"
    ).fetchone()[0]
    result["global_total"] = total

    if total < min_global:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    zero = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project = 'global' AND COALESCE(access_count, 0) = 0"
    ).fetchone()[0]
    result["global_zero_access"] = zero
    ratio = zero / total if total > 0 else 0.0
    result["zero_access_ratio"] = round(ratio, 4)

    if ratio < threshold:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    result["triggered"] = True

    # 收集 pinned IDs
    pinned_ids = set()
    try:
        pin_rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE pin_type IN ('hard', 'soft')"
        ).fetchall()
        pinned_ids = {r[0] for r in pin_rows}
    except Exception:
        pass

    # 选择牺牲者：global 层, 零访问, 非 design_constraint, 非 task_state, 非 mlock
    # 按 importance ASC（先杀低价值）+ lru_gen DESC（先杀最老代）
    candidates = conn.execute(
        """SELECT id, importance FROM memory_chunks
           WHERE project = 'global'
             AND COALESCE(access_count, 0) = 0
             AND chunk_type NOT IN ('task_state', 'design_constraint')
             AND COALESCE(oom_adj, 0) > -500
           ORDER BY importance ASC, lru_gen DESC
           LIMIT ?""",
        (max_reap,)
    ).fetchall()

    reaped = 0
    to_delete = []

    for chunk_id, imp in candidates:
        if chunk_id in pinned_ids:
            continue

        new_imp = round(imp * decay, 4)
        if new_imp < delete_threshold:
            to_delete.append(chunk_id)
        else:
            conn.execute(
                "UPDATE memory_chunks SET importance = ?, "
                "oom_adj = MIN(COALESCE(oom_adj, 0) + 400, 1000) WHERE id = ?",
                (new_imp, chunk_id),
            )
        reaped += 1

    # 批量删除
    if to_delete:
        try:
            delete_chunks(conn, to_delete)
            bump_chunk_version(conn)
        except Exception:
            # fallback: 逐个删除
            for cid in to_delete:
                try:
                    conn.execute("DELETE FROM memory_chunks WHERE id = ?", (cid,))
                except Exception:
                    pass
        # iter517: 注册 import tombstones — 阻止 fork bomb 循环
        try:
            from tools.import_knowledge import register_import_tombstones
            register_import_tombstones(to_delete)
        except Exception:
            pass

    result["reaped"] = reaped
    result["deleted"] = len(to_delete)
    result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)

    try:
        conn.commit()
    except Exception:
        pass

    return result


# ── iter514: ksm_scan — Kernel Same-page Merging Periodic Scanner ──────────────

def ksm_scan(conn: "sqlite3.Connection", project: "Optional[str]" = None) -> dict:
    """iter514: ksm_scan — 定期扫描并合并语义重复的 chunks。

    OS 类比：Linux KSM (Kernel Same-page Merging, Andrea Arcangeli, 2009)
    ——ksmd 后台线程周期性扫描物理页帧，通过内容哈希发现相同页面，
    将多个相同页面合并为一个 copy-on-write 共享页，释放物理内存。

    memory-os 问题：
      - import_knowledge 批量导入产生同主题多版本 chunks
        例如：[pe_analysis] PE 分析：task_queued... ×7, [sched_ext] EEVDF... ×8
      - 这些是同一知识的不同迭代记录/不同细节面，而非独立知识
      - 已有的 already_exists() 只检查精确匹配，compact_zone() 基于实体重叠
      - 两者都无法处理"同主题前缀、不同内容后缀"的版本化重复

    算法（三阶段）：
      Phase 1: Topic Fingerprint — 提取每个 chunk 的结构化前缀作为 page hash
        - [bracket_topic] + 前 20 字符 作为 fingerprint
        - 相同 fingerprint = 同一 "物理页面" 的候选
      Phase 2: Merge Selection — 每组保留最佳 chunk（survivor）
        - 优先级：access_count DESC → importance DESC → created_at DESC
        - survivor 继承被合并 chunks 的 access_count（cumulative）
      Phase 3: Deduplicate & Delete — 删除被合并的 chunks
        - survivor.content 追加 "[merged N chunks]" 标记
        - bump_chunk_version 触发 TLB 失效

    调用时机：loader.py SessionStart，在 overcommit_kill 之后。
    """
    _t0 = _time.time()

    result = {
        "triggered": False,
        "groups_found": 0,
        "chunks_merged": 0,
        "chunks_deleted": 0,
        "survivors": [],
        "duration_ms": 0.0,
    }

    try:
        from config import get as _cfg
        min_group_size = int(_cfg("ksm_scan.min_group_size"))
        max_merge_per_scan = int(_cfg("ksm_scan.max_merge_per_scan"))
        prefix_chars = int(_cfg("ksm_scan.prefix_chars"))
        protect_accessed = int(_cfg("ksm_scan.protect_min_access"))
    except Exception:
        min_group_size = 3
        max_merge_per_scan = 60
        prefix_chars = 20
        protect_accessed = 2

    # 加载所有非 task_state chunks（全库扫描，跨 project）
    query = """
        SELECT id, summary, content, importance, access_count, created_at,
               project, chunk_type, oom_adj
        FROM memory_chunks
        WHERE chunk_type NOT IN ('task_state', 'prompt_context')
          AND summary != ''
    """
    params = ()
    if project:
        query += " AND project = ?"
        params = (project,)

    rows = conn.execute(query, params).fetchall()
    if len(rows) < min_group_size:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    # ── Phase 1: Topic Fingerprint ──
    # 提取 [bracket] + rest[:prefix_chars] 作为 fingerprint
    _PREFIX_RE = re.compile(r'^\[([^\]]+)\]\s*(.*)', re.DOTALL)

    def _fingerprint(summary: str) -> str:
        m = _PREFIX_RE.match(summary)
        if m:
            topic = m.group(1)
            rest = m.group(2)[:prefix_chars].strip()
            return f"[{topic}] {rest}"
        return ""  # 无 bracket 前缀的不参与 KSM

    groups = defaultdict(list)
    for row in rows:
        rid, summary = row[0], row[1] or ""
        fp = _fingerprint(summary)
        if fp:
            groups[fp].append({
                "id": rid,
                "summary": summary,
                "content": row[2] or "",
                "importance": row[3] if row[3] is not None else 0.5,
                "access_count": row[4] or 0,
                "created_at": row[5] or "",
                "project": row[6] or "",
                "chunk_type": row[7] or "",
                "oom_adj": row[8] or 0,
            })

    # ── Phase 2: Merge Selection ──
    merge_candidates = [(fp, chunks) for fp, chunks in groups.items()
                        if len(chunks) >= min_group_size]

    if not merge_candidates:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    result["triggered"] = True
    result["groups_found"] = len(merge_candidates)

    total_deleted = 0
    survivors = []
    _all_deleted_ids = []  # iter517: 收集所有被删除的 ID

    for fp, chunks in merge_candidates:
        if total_deleted >= max_merge_per_scan:
            break

        # 排序：access_count DESC → importance DESC → created_at DESC（最新优先）
        chunks_sorted = sorted(chunks, key=lambda c: (
            c["access_count"],
            c["importance"],
            c["created_at"],
        ), reverse=True)

        survivor = chunks_sorted[0]
        to_merge = chunks_sorted[1:]

        # 保护：不删除 oom_adj <= -500 (mlock) 或 access >= protect_accessed 的 chunks
        to_delete = []
        for c in to_merge:
            if total_deleted >= max_merge_per_scan:
                break
            if c["oom_adj"] <= -500:
                continue  # mlock protected
            if c["access_count"] >= protect_accessed:
                continue  # has been accessed, might have unique value
            to_delete.append(c)
            total_deleted += 1

        if not to_delete:
            continue

        # ── Phase 3: Merge & Delete ──
        # survivor 继承被合并 chunks 的 access_count 总和
        merged_access = sum(c["access_count"] for c in to_delete)
        new_access = survivor["access_count"] + merged_access

        # 更新 survivor
        merge_note = f"\n[ksm_merged {len(to_delete)} chunks, fp=\"{fp[:40]}\"]"
        conn.execute(
            "UPDATE memory_chunks SET access_count = ?, content = content || ? WHERE id = ?",
            (new_access, merge_note, survivor["id"])
        )

        # 删除被合并 chunks（先清 FTS5，再删主表）
        delete_ids = [c["id"] for c in to_delete]
        _all_deleted_ids.extend(delete_ids)  # iter517: 记录
        for i in range(0, len(delete_ids), 100):
            batch = delete_ids[i:i+100]
            placeholders = ",".join("?" * len(batch))
            # Phase 3a: 先删 FTS5（rowid_ref 是 standalone FTS5 的关联字段）
            try:
                conn.execute(
                    f"DELETE FROM memory_chunks_fts WHERE rowid_ref IN ({placeholders})",
                    batch
                )
            except Exception:
                pass  # FTS5 will be cleaned by fts5_checkpoint at next boot
            # Phase 3b: 再删主表
            conn.execute(
                f"DELETE FROM memory_chunks WHERE id IN ({placeholders})",
                batch
            )

        survivors.append({"id": survivor["id"], "fp": fp[:50], "merged": len(to_delete)})
        result["chunks_merged"] += len(to_delete)

    # Commit & bump version
    try:
        conn.commit()
        if result["chunks_merged"] > 0:
            bump_chunk_version(conn)
    except Exception:
        pass

    # iter517: 注册 import tombstones — 阻止 fork bomb 循环
    # OS 类比：exit_notify() → 被 reaper 回收的 PID 进入不可 fork 状态
    if _all_deleted_ids:
        try:
            from tools.import_knowledge import register_import_tombstones
            register_import_tombstones(_all_deleted_ids)
        except Exception:
            pass

    result["chunks_deleted"] = result["chunks_merged"]
    result["survivors"] = survivors
    result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
    return result


# ── userfaultfd — Demand-Paged Import Promotion（迭代515）────────────

def userfaultfd_promote(conn: "sqlite3.Connection",
                        chunk_ids: list) -> dict:
    """
    迭代515：userfaultfd — 按需导入 page fault 处理。
    OS 类比：Linux userfaultfd (Andrea Arcangeli, 2015) — 用户空间 page fault handler。

    当 mmap(MAP_LAZY) 映射的页面被首次访问时触发 page fault，
    userfaultfd handler 在用户空间按需分配物理页面并填充数据。

    Memory-OS 类比：
      - import_knowledge 写入 chunks 时 importance=0.15（mapped but not present）
      - FTS5 可发现但 Top-K 排序中基本不可见
      - 首次检索命中 = page fault → promote importance + reset oom_adj
      - 后续访问走正常 MGLRU/update_accessed 路径（page 已 resident）

    参数：
      conn — 写连接（在 retriever write-back 阶段调用）
      chunk_ids — 本次检索命中的 chunk ID 列表

    返回 dict：
      promoted — 被提升的 chunk 数
      ids — 被提升的 chunk ID 列表
    """
    result = {"promoted": 0, "ids": []}
    if not chunk_ids:
        return result

    try:
        from config import get as _cfg
    except Exception:
        return result

    promote_imp = _cfg("userfaultfd.promote_importance")
    promote_oom = _cfg("userfaultfd.promote_oom_adj")

    placeholders = ",".join("?" * len(chunk_ids))
    # 找到 import 来源 + importance 仍然很低（未被 promote 过） + 首次访问的 chunks
    # access_count <= 1 因为 update_accessed 可能在本次调用前已自增
    rows = conn.execute(
        f"SELECT id, importance FROM memory_chunks "
        f"WHERE id IN ({placeholders}) "
        f"  AND source_session LIKE 'import:%' "
        f"  AND importance < 0.4 "
        f"  AND access_count <= 1",
        chunk_ids,
    ).fetchall()

    if not rows:
        return result

    now_iso = datetime.now(timezone.utc).isoformat()
    for row in rows:
        chunk_id, old_imp = row
        conn.execute(
            "UPDATE memory_chunks SET importance=?, oom_adj=?, updated_at=? "
            "WHERE id=?",
            (promote_imp, promote_oom, now_iso, chunk_id),
        )
        result["ids"].append(chunk_id)

    result["promoted"] = len(result["ids"])

    if result["promoted"] > 0:
        try:
            dmesg_log(conn, DMESG_INFO, "userfaultfd",
                      f"page_fault: promoted={result['promoted']} "
                      f"ids={result['ids'][:3]} imp→{promote_imp} oom→{promote_oom}")
        except Exception:
            pass

    return result


# ── MADV_FREE — Lazy Page Reclaim + FTS5 Exclusion（迭代516）────────────

def madv_free_scan(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    迭代516：MADV_FREE — 惰性页面回收与索引排除。
    OS 类比：Linux madvise(MADV_FREE) (Minchan Kim, 2016) — 标记页面为"可释放"，
    从 page table 移除 PTE mapping（MMU 不再 page walk 到这些页面），
    物理页面保留但不计入 RSS，只在内存压力时被 page reclaim 回收。

    Memory-OS 类比：
      - import chunks 以 importance=0.15 写入（mapped but not present, iter515）
      - 被首次检索命中时 userfaultfd_promote 提升 importance（page fault）
      - 但大量 import chunks 永远不会被命中（搜索词不匹配），形成"死重"：
        - FTS5 索引包含这些 chunks → 增加搜索扫描量（TLB miss + page walk）
        - 永远排不到 Top-K → 不产出价值
        - 不满足 oom_reaper/shrink_dcache 删除条件 → 不会被回收
      - MADV_FREE 解决方案：
        Phase 1 (unmap): 从 FTS5 移除（消除搜索噪声）→ 等价于移除 PTE mapping
        Phase 2 (free): 超过 delete_age_days 仍未被直接 ID 访问 → 删除主表

    触发条件：
      - source_session LIKE 'import:%'（仅处理 import 来源）
      - importance < madv_free.lazy_threshold（仍为 lazy 状态）
      - access_count = 0（从未被检索命中 → 无 page fault 发生）
      - age > madv_free.min_age_days（给予足够曝光窗口）

    参数：
      conn — 写连接
      project — 限定 project（None=全局扫描）

    返回 dict：
      unmapped — 从 FTS5 移除的 chunk 数
      freed — 删除的 chunk 数（超长期无用）
      total_lazy — 符合条件的 lazy chunks 总数
    """
    result = {"unmapped": 0, "freed": 0, "total_lazy": 0, "skipped_protected": 0}

    try:
        from config import get as _cfg
    except Exception:
        return result

    min_age_days = _cfg("madv_free.min_age_days")
    lazy_threshold = _cfg("madv_free.lazy_threshold")
    delete_age_days = _cfg("madv_free.delete_age_days")
    max_per_scan = _cfg("madv_free.max_per_scan")

    # 查找 lazy import chunks（从未被命中，超过最短曝光期）
    age_cutoff = (datetime.now(timezone.utc) - timedelta(days=min_age_days)).isoformat()
    delete_cutoff = (datetime.now(timezone.utc) - timedelta(days=delete_age_days)).isoformat()

    where_clause = (
        "source_session LIKE 'import:%' "
        "AND importance < ? "
        "AND access_count = 0 "
        "AND created_at < ? "
    )
    params = [lazy_threshold, age_cutoff]

    if project:
        where_clause += "AND project = ? "
        params.append(project)

    # 排除受保护的 chunks
    where_clause += "AND oom_adj > -500 "  # mlock 保护不处理

    rows = conn.execute(
        f"SELECT id, rowid, created_at, importance FROM memory_chunks "
        f"WHERE {where_clause} "
        f"ORDER BY created_at ASC LIMIT ?",
        params + [max_per_scan],
    ).fetchall()

    result["total_lazy"] = len(rows)
    if not rows:
        return result

    freed_ids = []
    unmapped_ids = []

    for chunk_id, rowid_val, created_at, imp in rows:
        if created_at < delete_cutoff:
            # Phase 2: 超长期无用 → 直接删除（free physical page）
            # 先删 FTS5 再删主表
            conn.execute(
                "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                (str(rowid_val),),
            )
            conn.execute("DELETE FROM memory_chunks WHERE id=?", (chunk_id,))
            freed_ids.append(chunk_id)
        else:
            # Phase 1: 从 FTS5 移除（unmap PTE）— 保留主表数据
            # chunk 仍可通过 ID 直接访问（如 checkpoint restore），但 FTS5 搜索不再找到它
            conn.execute(
                "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                (str(rowid_val),),
            )
            unmapped_ids.append(chunk_id)

    result["unmapped"] = len(unmapped_ids)
    result["freed"] = len(freed_ids)

    if freed_ids:
        bump_chunk_version()
        # iter517: 注册 import tombstones — 阻止 fork bomb 循环
        try:
            from tools.import_knowledge import register_import_tombstones
            register_import_tombstones(freed_ids)
        except Exception:
            pass

    try:
        dmesg_log(conn, DMESG_INFO, "madv_free",
                  f"scan: unmapped={result['unmapped']} freed={result['freed']} "
                  f"total_lazy={result['total_lazy']}",
                  extra=json.dumps({
                      "unmapped_sample": unmapped_ids[:5],
                      "freed_sample": freed_ids[:5],
                      "project": project or "all",
                  }))
    except Exception:
        pass

    return result


def _page_idle_load() -> dict:
    """加载 page_idle bitmap 文件。"""
    try:
        if _PAGE_IDLE_FILE.exists():
            return json.loads(_PAGE_IDLE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _page_idle_save(data: dict) -> None:
    """保存 page_idle bitmap 文件。"""
    try:
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        _PAGE_IDLE_FILE.write_text(
            json.dumps(data, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception:
        pass


# ── migrate_pages — Cross-NUMA Page Migration（迭代518）────────────────

def migrate_pages(conn: "sqlite3.Connection", current_project: str) -> dict:
    """
    迭代518：migrate_pages — 跨 project_id 知识迁移。
    OS 类比：Linux migrate_pages() (Christoph Lameter, 2006) — 当进程迁移到
    不同 NUMA 节点时，内核自动将其热页面从远程节点迁移到本地节点，
    减少跨节点访问延迟（remote memory latency ~100ns vs local ~50ns）。

    Memory-OS 类比：
      - NUMA 节点 = project_id（不同的 namespace 隔离域）
      - 页面 = memory chunks（知识单元）
      - 跨节点访问 = 知识被碎片化到旧 project_id 下，当前 project 查询不可见
      - migrate_pages = 将旧别名下的 chunks 迁移到当前活跃 project_id

    根因：同一物理仓库/工作目录随时间产生不同的 project_id：
      1. git remote 配置变化：abspath:xxx → git:xxx（首次添加 remote）
      2. CWD 变化：从父目录 abspath:parent → 子目录 git:child
      3. git 仓库初始化：abspath:xxx → gitroot:xxx → git:xxx
      这导致同一工作域的知识被分散到多个 project_id 下，
      当前 project 的 get_chunks() 只查询当前 ID → 历史知识不可见。

    别名检测策略（两级）：
      Phase 1 — Path ancestry：当前 CWD 是某 project 的子目录（CWD 包含关系）
      Phase 2 — Hash fingerprint：不同 label 但相同物理路径（git: vs abspath: vs gitroot:）

    迁移策略：
      - 只迁移 chunks，不迁移 recall_traces（traces 仅做统计参考）
      - 去重：迁移时检查目标 project 是否已存在相同 summary → 跳过
      - 增量：已迁移的 chunk 记录到 alias cache 文件，不重复扫描
      - access_count/importance 继承：保留原值（迁移不改变知识质量）

    保护机制：
      - current_project == 'global' → 不迁移（global 是跨项目共享层）
      - 源 project chunks < 2 → 不值得迁移
      - 每次最多迁移 max_migrate_per_scan 条（避免大事务）

    参数：
      conn — 写连接
      current_project — 当前活跃 project_id

    返回 dict：
      aliases_found — 发现的别名 project_id 列表
      migrated — 迁移的 chunk 数
      skipped_dup — 去重跳过的 chunk 数
      skipped_protected — 受保护跳过的 chunk 数
    """
    result = {
        "aliases_found": [],
        "migrated": 0,
        "skipped_dup": 0,
        "skipped_protected": 0,
        "duration_ms": 0,
    }
    t0 = _time.monotonic()

    # ── 守卫：不迁移 global / 空 project ──
    if not current_project or current_project == "global":
        return result

    try:
        from config import get as _cfg
    except Exception:
        return result

    max_migrate = _cfg("migrate.max_per_scan")

    # ── Phase 1: 发现别名 project_id ──
    all_projects = [
        r[0] for r in conn.execute(
            "SELECT DISTINCT project FROM memory_chunks WHERE project != 'global'"
        ).fetchall()
    ]

    aliases = _find_aliases(current_project, all_projects)
    if not aliases:
        result["duration_ms"] = round((_time.monotonic() - t0) * 1000, 2)
        return result

    result["aliases_found"] = aliases

    # ── Phase 2: 收集当前 project 的 summaries 用于去重 ──
    existing_summaries = set()
    for r in conn.execute(
        "SELECT summary FROM memory_chunks WHERE project=?",
        (current_project,),
    ).fetchall():
        existing_summaries.add(r[0][:60])  # 前 60 字符做粗粒度去重

    # ── Phase 3: 迁移 ──
    migrated_count = 0
    for alias in aliases:
        if migrated_count >= max_migrate:
            break

        rows = conn.execute(
            "SELECT id, summary, chunk_type FROM memory_chunks "
            "WHERE project=? ORDER BY importance DESC",
            (alias,),
        ).fetchall()

        for chunk_id, summary, chunk_type in rows:
            if migrated_count >= max_migrate:
                break

            # 去重：目标 project 已有相似 summary
            if summary[:60] in existing_summaries:
                result["skipped_dup"] += 1
                continue

            # 迁移：UPDATE project
            conn.execute(
                "UPDATE memory_chunks SET project=? WHERE id=?",
                (current_project, chunk_id),
            )
            existing_summaries.add(summary[:60])
            migrated_count += 1

    result["migrated"] = migrated_count

    if migrated_count > 0:
        conn.commit()
        bump_chunk_version()

        # 同步迁移 recall_traces
        for alias in aliases:
            conn.execute(
                "UPDATE recall_traces SET project=? WHERE project=?",
                (current_project, alias),
            )
        conn.commit()

    result["duration_ms"] = round((_time.monotonic() - t0) * 1000, 2)

    try:
        dmesg_log(conn, DMESG_INFO, "migrate_pages",
                  f"migrate: aliases={aliases} migrated={result['migrated']} "
                  f"dup={result['skipped_dup']} {result['duration_ms']:.1f}ms",
                  extra=json.dumps({
                      "current": current_project,
                      "aliases": aliases,
                      "migrated": result["migrated"],
                  }))
    except Exception:
        pass

    return result


def _find_aliases(current_project: str, all_projects: list) -> list:
    """
    发现当前 project 的别名 project_id。

    检测策略：
      1. Label 互换：同一 hash 后缀出现在不同 label 前缀下
         (git:abc123 vs abspath:abc123 → 不同 hash 算法，不匹配)
      2. Path ancestry：通过 project_id cache 文件找到物理路径映射
      3. CWD containment：父目录/子目录关系

    保守策略：只检测 _project_id_cache.json 中有明确路径映射的别名。
    """
    aliases = []

    # ── 策略1: 基于 git 根目录的别名检测 ──
    # 如果当前 project 是 git:xxx，找所有同仓库的 abspath/gitroot 变体
    # 核心逻辑：从 CWD 反推 git 根目录路径，计算其 abspath hash
    current_cwd = os.environ.get("CLAUDE_CWD", os.getcwd())

    try:
        import subprocess
        # 获取当前仓库的 git root
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=current_cwd, timeout=3,
        )
        if r.returncode == 0 and r.stdout.strip():
            git_root = r.stdout.strip()
            import hashlib

            # 计算 git root 的各种可能 project_id
            possible_ids = set()

            # abspath hash of git root
            h = hashlib.sha256(git_root.encode()).hexdigest()[:12]
            possible_ids.add(f"abspath:{h}")

            # gitroot hash of git root
            possible_ids.add(f"gitroot:{h}")

            # abspath hash of parent directories (up to 3 levels)
            p = Path(git_root)
            for _ in range(3):
                parent = p.parent
                if parent == p:
                    break
                h_parent = hashlib.sha256(str(parent).encode()).hexdigest()[:12]
                possible_ids.add(f"abspath:{h_parent}")
                p = parent

            # 过滤：只保留实际存在于 DB 中的别名
            possible_ids.discard(current_project)
            for pid in possible_ids:
                if pid in all_projects:
                    aliases.append(pid)
    except Exception:
        pass

    # ── 策略3: label 互换检测 ──
    # 如果当前是 git:xxx，检查是否有 abspath:* 或 gitroot:* 指向同一仓库
    # 反之亦然
    if current_project.startswith("git:"):
        # 已在策略2中覆盖
        pass
    elif current_project.startswith("abspath:"):
        # 如果当前是 abspath，检查是否有 git:* 指向同一仓库
        # 通过 _project_id_cache 中的 CWD key 匹配
        current_hash = current_project.split(":", 1)[1] if ":" in current_project else ""
        for pid in all_projects:
            if pid == current_project:
                continue
            # gitroot:same_hash → 同一路径
            if pid == f"gitroot:{current_hash}":
                aliases.append(pid)

    return list(set(aliases))  # 去重


def _load_project_id_cache() -> dict:
    """加载 project_id 缓存文件（utils.py 写入的 vDSO 缓存）。"""
    cache_file = MEMORY_OS_DIR / ".project_id_cache.json"
    try:
        if cache_file.exists():
            return json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


# ── mem_scrub — Memory Scrubbing for Data Integrity（迭代519）────────────────

import re as _re_mod

# Precompiled patterns for corruption detection
_MERGED_TAG_RE = _re_mod.compile(r"\[merged→[^\]]*\]\s*")
_REPEATED_MERGED_RE = _re_mod.compile(r"(\[merged→[^\]]*\]\s*){2,}")
_LEADING_PUNCTUATION_RE = _re_mod.compile(r"^[\s：:）】》\-]+")


def mem_scrub(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    迭代519：mem_scrub — ECC Memory Patrol Scrubbing。
    OS 类比：Intel EDAC patrol scrub (2005) + Linux GHES (Generic Hardware Error Source)
    — 后台巡检物理 DRAM，发现 ECC 可纠正的单比特错误（CE）并修复，
    防止 CE 累积为不可纠正的多比特错误（UE）导致 machine check exception。

    Memory-OS 类比：
      - 物理页帧 = memory_chunks（知识单元）
      - 单比特错误(CE) = summary/content 轻度腐蚀（可修复）
      - 多比特错误(UE) = 知识完全损坏（需删除）
      - patrol scrub = 周期性遍历所有 chunks 检测并修复数据完整性问题

    检测并修复的腐蚀类型：
      1. Repeated merge tags：[merged→xxx] 重复出现（merge 循环导致）
      2. Ghost with positive importance：importance > 0 但 summary 含 [merged→]
         （正常 ghost 应 importance=0，如果 > 0 说明被错误提升）
      3. Orphan content pollution：content 字段被反复追加相同 summary 片段
      4. Leading punctuation corruption：summary 以非正常字符开头（截断/合并残留）

    修复策略：
      - CE（可修复）：strip 重复 tags、修正 importance、清理 content
      - UE（不可修复）：importance=0 + oom_adj=900（标记为待回收）

    保护机制：
      - pinned / mlock (oom_adj <= -500) 不做修改（只报告）
      - design_constraint / quantitative_evidence 只修复不删除
      - 单次最多修复 max_scrub_per_scan 条

    参数：
      conn — 写连接
      project — 项目 ID（None = 全局扫描）

    返回 dict：
      scanned — 扫描的 chunk 数
      ce_fixed — 修复的 CE（可修复腐蚀）数
      ue_marked — 标记的 UE（不可修复）数
      details — 修复详情列表
    """
    result = {
        "scanned": 0,
        "ce_fixed": 0,
        "ue_marked": 0,
        "details": [],
        "duration_ms": 0.0,
    }
    t0 = _time.monotonic()

    try:
        from config import get as _cfg
    except Exception:
        _cfg = lambda k: {"scrub.max_per_scan": 40, "scrub.ue_oom_adj": 900}.get(k, 40)

    max_per_scan = _cfg("scrub.max_per_scan")
    ue_oom_adj = _cfg("scrub.ue_oom_adj")

    # ── 加载候选 chunks ──
    if project:
        rows = conn.execute(
            "SELECT id, summary, content, importance, oom_adj, chunk_type "
            "FROM memory_chunks WHERE project=?",
            (project,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, summary, content, importance, oom_adj, chunk_type "
            "FROM memory_chunks"
        ).fetchall()

    result["scanned"] = len(rows)
    repairs_done = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for row in rows:
        if repairs_done >= max_per_scan:
            break

        chunk_id, summary, content, importance, oom_adj, chunk_type = row
        is_protected = (oom_adj is not None and oom_adj <= -500)
        fixes = []

        # ── Check 1: Repeated [merged→xxx] tags ──
        if _REPEATED_MERGED_RE.search(summary or ""):
            # Strip ALL merge tags, keep only the actual content
            clean_summary = _MERGED_TAG_RE.sub("", summary).strip()
            if clean_summary:
                fixes.append(("ce", "repeated_merge_tags", summary[:60], clean_summary[:60]))
                if not is_protected:
                    conn.execute(
                        "UPDATE memory_chunks SET summary=?, updated_at=? WHERE id=?",
                        (clean_summary, now_iso, chunk_id),
                    )
                    # Sync FTS5
                    try:
                        _fts5_sync_after_scrub(conn, chunk_id, clean_summary, content)
                    except Exception:
                        pass
            else:
                # Summary is ONLY merge tags — UE
                fixes.append(("ue", "summary_only_merge_tags", summary[:60], ""))
                if not is_protected:
                    conn.execute(
                        "UPDATE memory_chunks SET importance=0, oom_adj=? WHERE id=?",
                        (ue_oom_adj, chunk_id),
                    )

        # ── Check 2: Single [merged→] with positive importance (ghost mismatch) ──
        elif _MERGED_TAG_RE.match(summary or "") and importance > 0.3:
            # This chunk was supposed to be a ghost (importance=0) but got re-promoted
            clean_summary = _MERGED_TAG_RE.sub("", summary).strip()
            if clean_summary and len(clean_summary) > 10:
                # Recoverable: strip tag, keep content
                fixes.append(("ce", "ghost_importance_mismatch", f"imp={importance:.2f}", clean_summary[:60]))
                if not is_protected:
                    conn.execute(
                        "UPDATE memory_chunks SET summary=?, updated_at=? WHERE id=?",
                        (clean_summary, now_iso, chunk_id),
                    )
                    try:
                        _fts5_sync_after_scrub(conn, chunk_id, clean_summary, content)
                    except Exception:
                        pass
            else:
                # Non-recoverable: force ghost
                fixes.append(("ue", "ghost_unrecoverable", f"imp={importance:.2f}", summary[:40]))
                if not is_protected:
                    conn.execute(
                        "UPDATE memory_chunks SET importance=0, oom_adj=? WHERE id=?",
                        (ue_oom_adj, chunk_id),
                    )

        # ── Check 3: Content has excessive duplicate appends ──
        if content and summary:
            # Detect if the same summary fragment appears 3+ times in content
            short_summary = summary[:40]
            if short_summary and content.count(short_summary) >= 3:
                # Deduplicate content: keep each unique line once
                lines = content.split("\n")
                seen = set()
                deduped = []
                for line in lines:
                    stripped = line.strip()
                    if stripped and stripped not in seen:
                        seen.add(stripped)
                        deduped.append(line)
                new_content = "\n".join(deduped)[:2000]
                if len(new_content) < len(content) * 0.8:  # significant reduction
                    fixes.append(("ce", "content_dup_append",
                                  f"lines:{len(lines)}→{len(deduped)}", ""))
                    if not is_protected:
                        conn.execute(
                            "UPDATE memory_chunks SET content=?, updated_at=? WHERE id=?",
                            (new_content, now_iso, chunk_id),
                        )

        # ── Check 4: Leading punctuation corruption ──
        if summary and _LEADING_PUNCTUATION_RE.match(summary):
            clean = _LEADING_PUNCTUATION_RE.sub("", summary).strip()
            if clean and len(clean) > 10:
                fixes.append(("ce", "leading_punctuation", summary[:20], clean[:40]))
                if not is_protected:
                    conn.execute(
                        "UPDATE memory_chunks SET summary=?, updated_at=? WHERE id=?",
                        (clean, now_iso, chunk_id),
                    )
                    try:
                        _fts5_sync_after_scrub(conn, chunk_id, clean, content)
                    except Exception:
                        pass

        # ── Record results ──
        if fixes:
            repairs_done += 1
            for severity, kind, before, after in fixes:
                if severity == "ce":
                    result["ce_fixed"] += 1
                else:
                    result["ue_marked"] += 1
                result["details"].append({
                    "id": chunk_id[:12],
                    "severity": severity,
                    "kind": kind,
                    "before": before,
                    "after": after,
                })

    # Bump chunk_version if any repairs were made
    if result["ce_fixed"] > 0 or result["ue_marked"] > 0:
        try:
            from store_vfs import bump_chunk_version
            bump_chunk_version(conn)
        except Exception:
            pass

    result["duration_ms"] = round((_time.monotonic() - t0) * 1000, 2)
    return result


def _fts5_sync_after_scrub(
    conn: "sqlite3.Connection", chunk_id: str,
    new_summary: str, content: str
) -> None:
    """Sync FTS5 index after a scrub repair (summary/content change).
    Delegates to store_vfs._fts5_sync_chunk for correct FTS5 handling."""
    try:
        from store_vfs import _fts5_sync_chunk
        _fts5_sync_chunk(conn, chunk_id, summary=new_summary, content=content)
    except Exception:
        pass


# ── iter520: mmu_notifier — Inline Reference Invalidation on Delete ────────

def mmu_notifier_invalidate(conn: "sqlite3.Connection", deleted_ids: list) -> dict:
    """
    迭代520：mmu_notifier — chunk 删除时内联清理所有反向引用。

    OS 类比：Linux mmu_notifier (Andrea Arcangeli, 2008) — 当内核通过
    zap_pte_range() 释放物理页面时，调用 mmu_notifier_invalidate_range()
    通知所有注册的 secondary MMU 订阅者（KVM shadow page table、RDMA MR、
    IOMMU 映射等），让它们同步清除自己的 PTE 映射。
    没有 mmu_notifier → KVM guest 仍持有 stale host PFN 映射 → use-after-free。

    Memory-OS 类比：
      - 物理页面释放 = delete_chunks() 删除 memory_chunks 行
      - secondary MMU = recall_traces.top_k_json、checkpoints.hit_chunk_ids
      - stale PTE = trace/checkpoint 中引用已删除 chunk 的 ID
      - mmu_notifier = 本函数：删除时同步清理所有引用方

    问题：delete_chunks() 只清理 memory_chunks + FTS5，不清理 recall_traces
    和 checkpoints 中的引用 → stale refs 累积（生产实测 22.4%）。
    rmap_sweep 只在 SessionStart 批量清理 → session 内持续累积 →
    readahead_pairs() 计算虚假共现 → 预取 ghost chunks。

    策略：
      1. recall_traces：遍历 top_k_json，过滤掉 deleted_ids，
         全 stale → 删除整条 trace，部分 stale → UPDATE 保留有效引用
      2. checkpoints：遍历 hit_chunk_ids，过滤掉 deleted_ids，
         空 → 删除 checkpoint，否则 UPDATE

    性能预算：<5ms（100 deleted_ids × 100 traces）。
    不使用全表扫描：只处理包含 deleted_ids 的 traces（LIKE 粗筛 + JSON 精筛）。

    参数：
      conn — 写连接
      deleted_ids — 被删除的 chunk ID 列表

    返回 dict：
      traces_cleaned — 清理了 stale ref 的 trace 数
      traces_deleted — 全 stale 被删除的 trace 数
      checkpoints_cleaned — 清理了 stale ref 的 checkpoint 数
      checkpoints_deleted — 空 hit_ids 被删除的 checkpoint 数
      refs_removed — 总共移除的 stale ref 数
    """
    result = {
        "traces_cleaned": 0,
        "traces_deleted": 0,
        "checkpoints_cleaned": 0,
        "checkpoints_deleted": 0,
        "refs_removed": 0,
    }

    if not deleted_ids:
        return result

    deleted_set = set(deleted_ids)

    # ── Phase 1: recall_traces 清理 ──
    # 粗筛：LIKE 匹配任意一个 deleted_id 的前缀（避免全表 JSON 解析）
    # 对于小表（<500 traces）直接全扫描更高效
    try:
        rows = conn.execute(
            "SELECT ROWID, top_k_json FROM recall_traces "
            "WHERE top_k_json IS NOT NULL"
        ).fetchall()
    except Exception:
        rows = []

    for rowid, tk_json in rows:
        try:
            tk = json.loads(tk_json)
        except (json.JSONDecodeError, TypeError):
            continue

        # 过滤掉 deleted_ids
        original_len = len(tk)
        filtered = [item for item in tk if item.get("id") not in deleted_set]

        if len(filtered) == original_len:
            continue  # 无 stale ref

        removed = original_len - len(filtered)
        result["refs_removed"] += removed

        if not filtered:
            # 全 stale → 删除整条 trace
            conn.execute("DELETE FROM recall_traces WHERE ROWID=?", (rowid,))
            result["traces_deleted"] += 1
        else:
            # 部分 stale → UPDATE 保留有效引用
            conn.execute(
                "UPDATE recall_traces SET top_k_json=? WHERE ROWID=?",
                (json.dumps(filtered, ensure_ascii=False), rowid),
            )
            result["traces_cleaned"] += 1

    # ── Phase 2: checkpoints 清理 ──
    try:
        ckpt_rows = conn.execute(
            "SELECT ROWID, id, hit_chunk_ids FROM checkpoints "
            "WHERE hit_chunk_ids IS NOT NULL"
        ).fetchall()
    except Exception:
        ckpt_rows = []

    for rowid, ckpt_id, ids_json in ckpt_rows:
        try:
            ids = json.loads(ids_json)
        except (json.JSONDecodeError, TypeError):
            continue

        if not isinstance(ids, list):
            continue

        original_len = len(ids)
        filtered = [cid for cid in ids if cid not in deleted_set]

        if len(filtered) == original_len:
            continue  # 无 stale ref

        result["refs_removed"] += original_len - len(filtered)

        if not filtered:
            conn.execute("DELETE FROM checkpoints WHERE ROWID=?", (rowid,))
            result["checkpoints_deleted"] += 1
        else:
            conn.execute(
                "UPDATE checkpoints SET hit_chunk_ids=? WHERE ROWID=?",
                (json.dumps(filtered, ensure_ascii=False), rowid),
            )
            result["checkpoints_cleaned"] += 1

    return result


def checkpoint_gc(conn: "sqlite3.Connection") -> dict:
    """
    迭代520：checkpoint 全局垃圾回收 — 限制总 checkpoint 数量。

    OS 类比：Linux memcg hierarchy (v2, Tejun Heo, 2014) — per-cgroup
    memory.max 限制子进程总内存，而非只限制单进程。
    _checkpoint_cleanup() 是 per-session RLIMIT_RSS（每 session 3 个），
    本函数是全局 memory.max（所有 session 合计不超过上限）。

    问题：11 sessions × max_checkpoints=3 = 33 个 checkpoint（实测 31 个），
    每个 checkpoint ~49 hit_chunk_ids → 1500+ 引用占用 DB 空间，
    旧 session 的 checkpoint 永远不会被清理（session 结束后不再有写入触发 cleanup）。

    策略：
      - 保留最近 N 个全局 checkpoint（max_global_checkpoints, 默认 10）
      - 按 created_at DESC 排序，超出的直接删除
      - 独立于 per-session cleanup（互补，不替代）

    调用时机：loader.py SessionStart（低频，每 session 一次）。
    """
    try:
        from config import get as _cfg
        max_global = int(_cfg("criu.max_global_checkpoints"))
    except Exception:
        max_global = 10

    result = {"total_before": 0, "deleted": 0, "total_after": 0}

    try:
        result["total_before"] = conn.execute(
            "SELECT COUNT(*) FROM checkpoints"
        ).fetchone()[0]
    except Exception:
        return result

    if result["total_before"] <= max_global:
        result["total_after"] = result["total_before"]
        return result

    # 保留最新 max_global 个，删除其余
    try:
        rows = conn.execute(
            "SELECT id FROM checkpoints ORDER BY created_at DESC"
        ).fetchall()
        to_delete = [r[0] for r in rows[max_global:]]
        if to_delete:
            placeholders = ",".join("?" * len(to_delete))
            conn.execute(
                f"DELETE FROM checkpoints WHERE id IN ({placeholders})",
                to_delete,
            )
            result["deleted"] = len(to_delete)
    except Exception:
        pass

    result["total_after"] = result["total_before"] - result["deleted"]
    return result


# ── iter521: free_pages_ok — Dead Page Frame Final Reclaim ────────────────────
def free_pages_ok(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter521: free_pages_ok — 统一最终回收器，清理所有已判死但未释放的 zombie chunks。

    OS 类比：Linux __free_pages_ok() (Linus Torvalds, 1991)
      当页面引用计数通过 put_page() 降至 0 时，__free_pages_ok() 将页面归还
      buddy allocator 的 free list。不管是哪条路径（swap out、munmap、OOM kill、
      page_idle scan）把 refcount 降到 0，最终都经过同一个释放路径。

    根因：29 个 importance < 0.2 的 chunks 仍然存活。多个回收器
      （shrink_dcache/oom_reaper/page_idle/overcommit_kill）将它们降级，但：
      - 各回收器的 delete_threshold 不同（0.2/0.35/...）
      - 有些回收器只降级不删除（设计为分步收敛）
      - 没有统一的最终清理者 → zombie chunks 长期占空间

    策略（简洁、零误删）：
      - importance < dead_threshold AND access_count = 0：直接删除
      - importance < dead_threshold AND access_count > 0：保留（曾被验证有价值）
      - 保护：oom_adj <= -500 (mlock)、pinned、task_state 豁免

    参数：
      conn — DB 连接
      project — 限定项目（None = 扫描全部）

    返回：
      freed — 删除的 chunk 数
      skipped_accessed — 因有访问记录而保留的 chunk 数
      skipped_protected — 因保护而跳过的 chunk 数
      total_dead — 满足 importance < threshold 的总数
      duration_ms — 执行时间
    """
    import time as _t
    t0 = _t.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"freed": 0, "skipped_accessed": 0, "skipped_protected": 0,
                "total_dead": 0, "duration_ms": 0}

    dead_threshold = _cfg("free_pages.dead_threshold")
    max_free_per_scan = _cfg("free_pages.max_per_scan")

    # 查询所有 importance < threshold 的 chunks
    where_clause = "WHERE importance < ?"
    params = [dead_threshold]
    if project:
        where_clause += " AND project = ?"
        params.append(project)

    rows = conn.execute(
        f"""SELECT id, access_count, oom_adj, chunk_type
            FROM memory_chunks
            {where_clause}
            ORDER BY importance ASC, oom_adj DESC
            LIMIT ?""",
        params + [max_free_per_scan * 3],  # 多查一些，过滤后可能不够
    ).fetchall()

    total_dead = len(rows)
    to_delete = []
    skipped_accessed = 0
    skipped_protected = 0

    # 获取 pinned IDs（如果可用）
    pinned_ids = set()
    try:
        from store_vfs import get_pinned_ids as _get_pinned
        pinned_ids = set(_get_pinned(conn, project)) if project else set(_get_pinned(conn))
    except Exception:
        pass

    for chunk_id, access_count, oom_adj, chunk_type in rows:
        # 保护：mlock (oom_adj <= -500)
        if oom_adj is not None and oom_adj <= -500:
            skipped_protected += 1
            continue
        # 保护：pinned
        if chunk_id in pinned_ids:
            skipped_protected += 1
            continue
        # 保护：task_state 不删
        if chunk_type == "task_state":
            skipped_protected += 1
            continue
        # 核心判定：有访问记录的保留（曾被实战验证过）
        if access_count and access_count > 0:
            skipped_accessed += 1
            continue
        # 可回收
        to_delete.append(chunk_id)
        if len(to_delete) >= max_free_per_scan:
            break

    # 执行删除
    freed = 0
    if to_delete:
        freed = delete_chunks(conn, to_delete)
        try:
            dmesg_log(conn, DMESG_INFO, "free_pages_ok",
                      f"freed={freed} dead={total_dead} "
                      f"skip_acc={skipped_accessed} skip_prot={skipped_protected}",
                      project=project or "all")
        except Exception:
            pass

    duration_ms = (_t.time() - t0) * 1000
    return {
        "freed": freed,
        "skipped_accessed": skipped_accessed,
        "skipped_protected": skipped_protected,
        "total_dead": total_dead,
        "duration_ms": round(duration_ms, 2),
    }


# ── iter523: kfree_rcu — Deferred Cross-Project Zombie Reclaim ───────────────
def kfree_rcu(conn: "sqlite3.Connection") -> dict:
    """
    iter523: kfree_rcu — 跨 project 延迟 zombie 回收器。

    OS 类比：Linux kfree_rcu() (Paul E. McKenney, 2002)
      RCU read-side critical section 持有引用时 kfree() 不能立即释放。
      kfree_rcu() 将释放延迟到所有读者退出 grace period 后执行。
      解决"多个子系统各自判定可回收，但无人执行最终释放"的问题。

    根因：
      free_pages_ok(conn, project) 只扫描当前 project，不扫描 global 层。
      overcommit_kill 有自稳定阈值（60%），零访问率降到阈值以下即停止触发。
      当 global 零访问率 42.2% < 60% 后，27 个 importance=0.150 的 zombie
      chunks 被所有回收器遗漏——处于"回收死区"。

    策略：
      - 全局扫描（不限 project）所有 importance < dead_threshold + access=0
      - 跳过当前 project（已由 free_pages_ok 处理）
      - 保护：mlock / pinned / task_state / design_constraint
      - 批次限制防止单次删除过多

    调用时机：loader.py SessionStart，在 free_pages_ok 之后。
    """
    import time as _t
    t0 = _t.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"freed": 0, "skipped_protected": 0, "total_dead": 0, "duration_ms": 0}

    dead_threshold = _cfg("free_pages.dead_threshold")  # 复用同一阈值 (0.2)
    max_free = int(_cfg("free_pages.max_per_scan"))  # 复用同一批次限制

    # 全局扫描：所有 project 的 zombie chunks
    rows = conn.execute(
        """SELECT id, access_count, oom_adj, chunk_type, project
           FROM memory_chunks
           WHERE importance < ?
           ORDER BY importance ASC, oom_adj DESC
           LIMIT ?""",
        (dead_threshold, max_free * 3),
    ).fetchall()

    total_dead = len(rows)
    to_delete = []
    skipped_protected = 0

    # 获取 pinned IDs
    pinned_ids = set()
    try:
        pin_rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE pin_type IN ('hard', 'soft')"
        ).fetchall()
        pinned_ids = {r[0] for r in pin_rows}
    except Exception:
        pass

    for chunk_id, access_count, oom_adj, chunk_type, _proj in rows:
        # 保护：mlock
        if oom_adj is not None and oom_adj <= -500:
            skipped_protected += 1
            continue
        # 保护：pinned
        if chunk_id in pinned_ids:
            skipped_protected += 1
            continue
        # 保护：task_state / design_constraint
        if chunk_type in ("task_state", "design_constraint"):
            skipped_protected += 1
            continue
        # 核心判定：有访问记录 → 保留
        if access_count and access_count > 0:
            continue
        # 可回收
        to_delete.append(chunk_id)
        if len(to_delete) >= max_free:
            break

    # 执行删除
    freed = 0
    if to_delete:
        freed = delete_chunks(conn, to_delete)
        # iter538: 移除内部 dmesg_log — loader 调用方已负责记录，避免 ring buffer 双写

    duration_ms = (_t.time() - t0) * 1000
    return {
        "freed": freed,
        "skipped_protected": skipped_protected,
        "total_dead": total_dead,
        "duration_ms": round(duration_ms, 2),
    }


# ── iter530: put_page — Unified Final Release + Bitmap Scrub ──────────────────

def put_page(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter530: put_page — 统一最终释放路径 + page_idle bitmap 反向清理。

    OS 类比：Linux put_page() / __page_cache_release() (Linus Torvalds, 1991)
      当一个 page frame 的 _refcount 通过 put_page() 降至 0 时，不管是哪条
      路径（munmap、swap out、OOM kill、page_idle scan、truncate）触发了最后
      一次 put_page()，都会调用 __page_cache_release() 从所有缓存
      （page cache、swap cache、buffer_head）中移除该页面，并归还到 buddy
      allocator。关键特性：put_page 不检查 "who" 降了 refcount，只检查
      "refcount == 0" 这个最终状态。

    三个问题（free_pages_ok / kfree_rcu 的盲区）：
      1. imp=0 + acc>0 zombies：mem_scrub 标记为 UE (importance=0) 但
         free_pages_ok 因 access>0 保护 → 永久存活
      2. oom_adj=OOM_ADJ_MAX(1000) 但 imp>0.2：被所有回收器标记为"最高优先
         级回收"但无回收器以 oom_adj 为主选择条件 → 永久存活
      3. page_idle bitmap stale entries：chunk 被其他 project 删除后 bitmap
         条目未清理 → 下轮 mark 时无法匹配 DB → 不影响正确性但浪费空间

    策略：
      Phase 1 — UE Force Kill：importance == 0 的 chunk 无条件删除
        （mem_scrub 已判定为不可修复错误，access 历史不再有参考价值）
      Phase 2 — OOM_ADJ_MAX Reap：oom_adj >= OOM_ADJ_MAX 的 chunk
        降级 importance *= 0.4 + 删除 imp < 0.3 的
        （经过完整回收管线标记后仍未死亡 → 强制收割）
      Phase 3 — Bitmap Scrub：从 page_idle bitmap 删除不存在于 DB 的
        stale chunk IDs（反向映射清理）

    调用时机：loader.py SessionStart，在 kfree_rcu 之后运行。
    """
    import time as _t
    t0 = _t.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"ue_killed": 0, "oom_max_reaped": 0, "oom_max_demoted": 0,
                "bitmap_stale_removed": 0, "duration_ms": 0}

    max_per_scan = int(_cfg("free_pages.max_per_scan"))
    oom_max_decay = _cfg("put_page.oom_max_decay")
    oom_max_delete_threshold = _cfg("put_page.oom_max_delete_threshold")

    # ── Phase 1: UE Force Kill (importance == 0, 无论 access_count) ──
    # mem_scrub 将不可修复数据标记为 importance=0 + oom_adj=900，
    # 但 free_pages_ok 和 kfree_rcu 均保护 access>0 的 chunk → 遗漏
    ue_rows = conn.execute(
        """SELECT id, chunk_type, oom_adj FROM memory_chunks
           WHERE importance < 0.001
           ORDER BY oom_adj DESC
           LIMIT ?""",
        (max_per_scan,)
    ).fetchall()

    ue_to_delete = []
    for chunk_id, chunk_type, oom_adj in ue_rows:
        # 唯一保护：mlock (显式人工保护)
        if oom_adj is not None and oom_adj <= -500:
            continue
        # task_state 豁免
        if chunk_type == "task_state":
            continue
        ue_to_delete.append(chunk_id)

    ue_killed = 0
    if ue_to_delete:
        ue_killed = delete_chunks(conn, ue_to_delete)

    # ── Phase 2: OOM_ADJ_MAX Reap (oom_adj >= 1000, 任何 importance) ──
    # 多个回收器通过 oom_adj += N 累积到 MAX，但无人执行最终删除
    oom_max_rows = conn.execute(
        """SELECT id, importance, access_count, chunk_type, oom_adj
           FROM memory_chunks
           WHERE oom_adj >= ?
           ORDER BY importance ASC
           LIMIT ?""",
        (OOM_ADJ_MAX, max_per_scan)
    ).fetchall()

    oom_to_delete = []
    oom_demoted = 0
    for chunk_id, imp, acc, chunk_type, oom_adj in oom_max_rows:
        # mlock 保护
        if oom_adj is not None and oom_adj <= -500:
            continue
        # task_state 豁免
        if chunk_type == "task_state":
            continue

        # imp < threshold → 直接删除（已经足够低）
        if imp is not None and imp < oom_max_delete_threshold:
            oom_to_delete.append(chunk_id)
        else:
            # 高 imp 但 oom_adj=MAX → 强制降级 importance × decay
            new_imp = round((imp or 0.5) * oom_max_decay, 4)
            conn.execute(
                "UPDATE memory_chunks SET importance = ? WHERE id = ?",
                (new_imp, chunk_id)
            )
            oom_demoted += 1

    oom_max_reaped = 0
    if oom_to_delete:
        oom_max_reaped = delete_chunks(conn, oom_to_delete)

    if oom_demoted > 0:
        try:
            bump_chunk_version(conn)
        except Exception:
            pass

    # ── Phase 3: Bitmap Scrub (page_idle bitmap stale entry removal) ──
    # 当 chunk 被其他 project/路径删除后，bitmap 条目未被清理
    bitmap_stale_removed = 0
    try:
        bitmap = _page_idle_load()
        if bitmap:
            # 获取所有 live chunk IDs (一次查询)
            live_ids = set(r[0] for r in conn.execute(
                "SELECT id FROM memory_chunks"
            ).fetchall())

            modified = False
            for proj_key in list(bitmap.keys()):
                proj_bitmap = bitmap[proj_key]
                if not isinstance(proj_bitmap, dict):
                    continue
                stale_keys = [k for k in proj_bitmap if k not in live_ids]
                for k in stale_keys:
                    del proj_bitmap[k]
                    bitmap_stale_removed += 1
                    modified = True
                # 清空的 project entry 删除
                if not proj_bitmap:
                    del bitmap[proj_key]
                    modified = True

            if modified:
                _page_idle_save(bitmap)
    except Exception:
        pass

    # ── Commit + Log ──
    if ue_killed > 0 or oom_max_reaped > 0 or oom_demoted > 0:
        conn.commit()

    total_actions = ue_killed + oom_max_reaped + oom_demoted + bitmap_stale_removed
    # iter538: 移除内部 dmesg_log — loader 调用方已负责记录，避免 ring buffer 双写

    duration_ms = (_t.time() - t0) * 1000
    return {
        "ue_killed": ue_killed,
        "oom_max_reaped": oom_max_reaped,
        "oom_max_demoted": oom_demoted,
        "bitmap_stale_removed": bitmap_stale_removed,
        "duration_ms": round(duration_ms, 2),
    }


# ── iter522: numa_balancing — Access-Pattern Importance Rebalancing ──────────
def numa_balancing(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter522: numa_balancing — 基于实际访问模式双向重平衡 importance。

    OS 类比：Linux Automatic NUMA Balancing (Ingo Molnár / Peter Zijlstra, 2012)
      AutoNUMA 周期性将页面标记为 PROT_NONE（不可访问），当进程再次访问时
      触发 NUMA hint page fault。根据 fault 源 CPU 的 NUMA node，决定是否
      迁移页面到本地 node。核心思想：
        - 不依赖静态放置策略（write-time importance）
        - 通过观察实际访问模式（access_count）动态调整放置
        - 页面在正确 node 上 → 本地访问快；错误 node → 远程访问慢
      效果：将"猜测式"初始放置进化为"证据驱动"的最优放置。

    根因：write-time importance 与 access_count 的 Pearson 相关性仅 0.186。
      即 importance 几乎是随机的——有 imp=0.99 从未被召回的噪声，也有 imp=0.24
      被访问 7 次的核心知识。检索公式 score = relevance × (base_importance + ...)
      中，错误的 importance 直接影响 Top-K 排序质量。

    策略（双向平衡）：
      1. Promote（热迁移）：access_count ≥ promote_min_access 但 importance 低于
         同 access 层的预期值 → importance 上调至 access_floor
      2. Demote（冷迁移）：importance ≥ demote_min_importance 但 access_count = 0
         且 age > min_age_days → importance × decay_factor 下调
      3. 保护：oom_adj ≤ -500 (mlock) 不动、task_state 不动、pinned 不动

    参数：
      conn — DB 连接
      project — 限定项目（None = 全部项目）

    返回：
      promoted — 上调 importance 的 chunk 数
      demoted — 下调 importance 的 chunk 数
      skipped_protected — 因保护跳过的数量
      duration_ms — 执行时间
    """
    import time as _t
    t0 = _t.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"promoted": 0, "demoted": 0, "skipped_protected": 0, "duration_ms": 0}

    # Tunables
    promote_min_access = _cfg("numa_balancing.promote_min_access")
    promote_floor = _cfg("numa_balancing.promote_floor")
    demote_min_importance = _cfg("numa_balancing.demote_min_importance")
    demote_decay = _cfg("numa_balancing.demote_decay")
    demote_min_age_days = _cfg("numa_balancing.demote_min_age_days")
    max_rebalance_per_scan = _cfg("numa_balancing.max_per_scan")

    promoted = 0
    demoted = 0
    skipped_protected = 0

    # ── Phase 1: Promote — 热迁移 ──
    # 高访问但低 importance 的 chunks：access 证明了真实价值，上调 importance
    where_proj = "AND project = ?" if project else ""
    params_promote = [promote_min_access, promote_floor]
    if project:
        params_promote.append(project)

    promote_rows = conn.execute(f"""
        SELECT id, importance, access_count, oom_adj, chunk_type
        FROM memory_chunks
        WHERE access_count >= ?
          AND importance < ?
          AND chunk_type != 'task_state'
          {where_proj}
        ORDER BY access_count DESC
        LIMIT ?
    """, params_promote + [max_rebalance_per_scan]).fetchall()

    for chunk_id, imp, acc, oom_adj, ctype in promote_rows:
        # 保护检查
        if (oom_adj or 0) <= -500:
            skipped_protected += 1
            continue
        # 计算新 importance：access-derived floor，不超过 0.95
        # 公式：floor + 0.05 * log2(access_count) 但 cap 0.95
        import math
        new_imp = min(0.95, promote_floor + 0.05 * math.log2(max(1, acc)))
        if new_imp <= imp:
            continue  # 已经足够高
        conn.execute(
            "UPDATE memory_chunks SET importance = ? WHERE id = ?",
            (round(new_imp, 3), chunk_id)
        )
        promoted += 1

    # ── Phase 2: Demote — 冷迁移 ──
    # 高 importance 但零访问 + 超龄的 chunks：write-time 高估，下调 importance
    age_cutoff = (datetime.now(timezone.utc) - timedelta(days=demote_min_age_days)).isoformat()
    params_demote = [demote_min_importance, age_cutoff]
    if project:
        params_demote.append(project)

    demote_rows = conn.execute(f"""
        SELECT id, importance, oom_adj, chunk_type
        FROM memory_chunks
        WHERE importance >= ?
          AND access_count = 0
          AND created_at < ?
          AND chunk_type NOT IN ('task_state', 'design_constraint')
          {where_proj}
        ORDER BY importance DESC
        LIMIT ?
    """, params_demote + [max_rebalance_per_scan]).fetchall()

    for chunk_id, imp, oom_adj, ctype in demote_rows:
        # 保护检查
        if (oom_adj or 0) <= -500:
            skipped_protected += 1
            continue
        # 衰减 importance
        new_imp = round(imp * demote_decay, 3)
        conn.execute(
            "UPDATE memory_chunks SET importance = ? WHERE id = ?",
            (new_imp, chunk_id)
        )
        demoted += 1

    if promoted > 0 or demoted > 0:
        conn.commit()
        bump_chunk_version()
        # iter538: 移除内部 dmesg_log — loader 调用方已负责记录，避免 ring buffer 双写

    duration_ms = (_t.time() - t0) * 1000
    return {
        "promoted": promoted,
        "demoted": demoted,
        "skipped_protected": skipped_protected,
        "duration_ms": round(duration_ms, 2),
    }


# ── iter524: mincore — Memory Residency Validation ───────────────────────────

def mincore(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter524: mincore — 内存驻留验证。

    OS 类比：Linux mincore() (Linus Torvalds, 1994)
      mincore(addr, length, vec) 查询 [addr, addr+length) 范围内每个页面
      是否驻留在物理内存（page cache）中。返回 vec 位图：1=resident, 0=not resident。
      用途：让用户空间了解哪些页面是"真实活跃"的，哪些只是"已映射但从未触碰"。
      与 madvise(MADV_DONTNEED) 的区别：mincore 是只读诊断，不改变页面状态。

    根因：write-time importance 基于语法信号（数字/代码标识符/技术术语），
      不反映语义价值。结果：imp=0.99 的迭代报告"PostToolUse 阻塞：76ms→43ms"
      从未被检索命中（0 access），而 imp=0.24 的核心知识被访问 7 次。
      numa_balancing 的 demote 需要 age > 3d，对新写入的大量高 imp 垃圾无能为力。

    策略：
      Phase 1 (mincore scan)：查找 importance ≥ high_importance_threshold 且
        access_count = 0 的 chunks，按 importance DESC 输出诊断报告。
      Phase 2 (calibrate)：如果零访问率在高 importance 段超过 anomaly_ratio，
        对这些 chunks 应用 importance × calibration_decay 校准。
        只校准非保护类型（task_state/design_constraint 豁免）。
      Phase 3 (report)：返回 resident/non-resident 统计，供 dmesg 审计。

    与 numa_balancing 的互补关系：
      - numa_balancing：age > 3d 才触发 demote（慢路径，保守）
      - mincore：不限 age，只要高 imp + 零 access 就标记并校准（快路径，激进）
      - 不冲突：mincore 校准后的 chunk 如果后来被 access，numa_balancing promote 回来

    参数：
      conn — DB 连接
      project — 限定项目（None = 当前 + global）

    返回：
      total_high — 高 importance chunks 总数
      resident — 高 imp + access > 0（真实驻留）
      non_resident — 高 imp + access = 0（虚假驻留）
      calibrated — 被校准的 chunk 数
      skipped_protected — 因保护跳过的数量
      anomaly_detected — 是否触发校准（non_resident / total_high > anomaly_ratio）
      duration_ms — 执行时间
    """
    import time as _t
    t0 = _t.time()

    try:
        from config import get as _cfg
    except Exception:
        return {
            "total_high": 0, "resident": 0, "non_resident": 0,
            "calibrated": 0, "skipped_protected": 0,
            "anomaly_detected": False, "duration_ms": 0,
        }

    # Tunables
    high_threshold = _cfg("mincore.high_importance_threshold")
    anomaly_ratio = _cfg("mincore.anomaly_ratio")
    calibration_decay = _cfg("mincore.calibration_decay")
    max_calibrate = _cfg("mincore.max_per_scan")

    # ── Phase 1: mincore scan — 诊断高 importance 段的驻留状态 ──
    where_proj = "AND project = ?" if project else ""
    params = [high_threshold]
    if project:
        params.append(project)

    rows = conn.execute(f"""
        SELECT id, importance, access_count, oom_adj, chunk_type
        FROM memory_chunks
        WHERE importance >= ?
          {where_proj}
        ORDER BY importance DESC
    """, params).fetchall()

    total_high = len(rows)
    resident = 0       # access > 0: page is in cache
    non_resident = 0   # access = 0: page mapped but not touched
    non_resident_ids = []

    for chunk_id, imp, acc, oom_adj, ctype in rows:
        if (acc or 0) > 0:
            resident += 1
        else:
            non_resident += 1
            non_resident_ids.append((chunk_id, imp, oom_adj, ctype))

    # ── Phase 2: calibrate if anomaly detected ──
    anomaly_detected = False
    calibrated = 0
    skipped_protected = 0

    if total_high > 0 and (non_resident / total_high) > anomaly_ratio:
        anomaly_detected = True
        calibrate_count = 0
        for chunk_id, imp, oom_adj, ctype in non_resident_ids:
            if calibrate_count >= max_calibrate:
                break
            # Protection checks
            if (oom_adj or 0) <= -500:  # mlock
                skipped_protected += 1
                continue
            if ctype in ('task_state', 'design_constraint'):
                skipped_protected += 1
                continue
            # Calibrate: decay importance
            new_imp = round(imp * calibration_decay, 3)
            conn.execute(
                "UPDATE memory_chunks SET importance = ? WHERE id = ?",
                (new_imp, chunk_id)
            )
            calibrated += 1
            calibrate_count += 1

        if calibrated > 0:
            conn.commit()
            bump_chunk_version()
            try:
                dmesg_log(conn, DMESG_INFO, "mincore",
                          f"calibrate: total_high={total_high} "
                          f"resident={resident} non_resident={non_resident} "
                          f"calibrated={calibrated} decay={calibration_decay}",
                          project=project or "all")
            except Exception:
                pass

    duration_ms = (_t.time() - t0) * 1000
    return {
        "total_high": total_high,
        "resident": resident,
        "non_resident": non_resident,
        "calibrated": calibrated,
        "skipped_protected": skipped_protected,
        "anomaly_detected": anomaly_detected,
        "duration_ms": round(duration_ms, 2),
    }


# ── iter529: sched_rt_bandwidth — Working Set Recall Bandwidth Cap ───────────

def sched_rt_bandwidth(conn: "sqlite3.Connection", project: str,
                       candidate_ids: list) -> dict:
    """
    iter529: sched_rt_bandwidth — 工作集召回带宽限制器。

    OS 类比：Linux sched_rt_runtime_us (Ingo Molnár, 2008)
      /proc/sys/kernel/sched_rt_runtime_us = 950000 (95% of 1s period)
      即使是最高优先级的 RT-FIFO 任务，也不能消耗超过 95% 的 CPU 带宽。
      超过带宽上限后任务被 throttled 直到下一个周期。
      这防止了一个失控 RT 线程饿死所有其他任务（包括 kthreadd、migration、ksoftirqd 等）。

    根因：loader working_set 按 importance × recency 排序选 Top-K，
      不考虑 chunk 的 recall 频率。高频 chunk（如 acc=89 的垄断 chunk，
      出现在 45% 的 recall_traces 中）每次 SessionStart 都占据 Top-K 槽位。
      retriever 的 bandwidth_throttle (iter527) 在检索路径生效，
      但 loader 路径绕过 → 垄断 chunk 仍通过 working_set 注入上下文。
      其他有价值但低频的 chunk 被挤出，无法获得曝光。

    策略：
      1. 从 recall_traces 统计每个 candidate 的召回频率（window 内占比）
      2. 超过 rt_bandwidth_pct 的 chunk 标记为 throttled
      3. 返回 throttled set，供 loader 在 Top-K 选择时排除

    与 scorer.bandwidth_throttle (iter527) 的关系：
      - bandwidth_throttle: 检索路径（retriever），对 score 做 ×0.15 乘法削减
      - sched_rt_bandwidth: 注入路径（loader），直接从候选集排除
      - 两者互补：loader 排除 + retriever 削减 = 全路径覆盖

    参数：
      conn — DB 连接
      project — 项目 ID
      candidate_ids — 候选 chunk ID 列表

    返回：
      throttled_ids — 应被排除的 chunk ID set
      recall_rates — {chunk_id: recall_rate} 诊断信息
      window_size — 实际使用的 trace 窗口大小
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"throttled_ids": set(), "recall_rates": {}, "window_size": 0}

    rt_bandwidth_pct = _cfg("loader.rt_bandwidth_pct")
    rt_window = _cfg("loader.rt_bandwidth_window")

    if not candidate_ids:
        return {"throttled_ids": set(), "recall_rates": {}, "window_size": 0}

    # 统计最近 window 条 injected traces 中每个 candidate 出现的次数
    candidate_set = set(candidate_ids)
    try:
        rows = conn.execute(
            "SELECT top_k_json FROM recall_traces "
            "WHERE project=? AND injected=1 "
            "ORDER BY rowid DESC LIMIT ?",
            (project, rt_window)
        ).fetchall()
    except Exception:
        return {"throttled_ids": set(), "recall_rates": {}, "window_size": 0}

    window_size = len(rows)
    if window_size == 0:
        return {"throttled_ids": set(), "recall_rates": {}, "window_size": 0}

    counts: dict = {}
    for (top_k_json,) in rows:
        try:
            top_k = json.loads(top_k_json) if isinstance(top_k_json, str) else top_k_json
            if isinstance(top_k, list):
                for item in top_k:
                    if isinstance(item, dict) and "id" in item:
                        cid = item["id"]
                        if cid in candidate_set:
                            counts[cid] = counts.get(cid, 0) + 1
        except Exception:
            continue

    # 计算召回率并判断是否超过带宽上限
    throttled_ids = set()
    recall_rates = {}
    for cid in candidate_ids:
        cnt = counts.get(cid, 0)
        rate = cnt / window_size
        recall_rates[cid] = round(rate, 3)
        if rate > rt_bandwidth_pct:
            throttled_ids.add(cid)

    return {
        "throttled_ids": throttled_ids,
        "recall_rates": recall_rates,
        "window_size": window_size,
    }


# ── iter532: cpuset — FTS5 Index Quarantine for Bandwidth Violators ──────────

_QUARANTINE_FILE = os.path.join(str(MEMORY_OS_DIR), ".cpuset_quarantine.json")


def _cpuset_load() -> dict:
    """Load quarantine registry: {chunk_id: {"sessions_remaining": N, "quarantined_at": ts}}"""
    try:
        if os.path.exists(_QUARANTINE_FILE):
            with open(_QUARANTINE_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _cpuset_save(data: dict) -> None:
    """Persist quarantine registry."""
    try:
        with open(_QUARANTINE_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def cpuset_quarantine(conn: "sqlite3.Connection", project: str) -> dict:
    """
    iter532: cpuset — FTS5 Index Quarantine for Bandwidth Violators.

    OS 类比：Linux sched_setaffinity() / cpuset (Ingo Molnár, 2004)
      nice(19) 只减少时间片——进程仍可在任意 CPU 上运行。
      cpuset 是物理隔离：强制进程只能在指定 CPU 子集运行，
      不在 allowed CPUs 中 → 调度器**物理上不可能**选中它。

    Memory-OS 类比：
      bandwidth_throttle (iter527): 软惩罚，score ×0.15——chunk 仍在 FTS5 候选池
      cpuset_quarantine (iter532): 硬隔离，从 FTS5 索引移除——搜索物理上找不到它

    问题（数据驱动）：
      chunk 3192147e (design_constraint, access=89) 在 30-window 中 recall_rate=60%。
      bandwidth_throttle ×0.15 后 score 仍高于其他 chunk（因 FTS5 relevance 极高）。
      sched_rt_bandwidth (iter529) 排除 loader 路径，但 retriever FTS5 路径无法物理隔离。

    策略：
      1. cpuset_quarantine(conn, project) — SessionStart 时扫描 recall_traces
         召回率 > bw_quarantine_pct(50%) 的 chunk → 从 FTS5 索引移除 + 注册 cooldown
      2. cpuset_release(conn) — 每次 SessionStart 先检查 cooldown 到期的 chunk → 恢复 FTS5

    保护机制：
      - 只隔离 FTS5 索引，不删除主表数据（chunk 仍可通过 checkpoint/working_set ID 直接访问）
      - max_quarantine 限制同时隔离数（防止信息真空）
      - cooldown_sessions 到期自动恢复（不是永久移除）
      - min_traces 样本保护（样本不足时跳过）

    返回：
      quarantined: 本次新隔离的 chunk IDs
      released: 本次解除隔离的 chunk IDs
      active: 当前仍在隔离中的总数
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"quarantined": [], "released": [], "active": 0}

    bw_quarantine_pct = _cfg("cpuset.bw_quarantine_pct")
    cooldown_sessions = int(_cfg("cpuset.cooldown_sessions"))
    max_quarantine = int(_cfg("cpuset.max_quarantine"))
    min_traces = int(_cfg("cpuset.min_traces"))

    result = {"quarantined": [], "released": [], "active": 0}

    # ── Phase 1: Release expired quarantines ──
    registry = _cpuset_load()
    released_ids = []
    for cid, info in list(registry.items()):
        remaining = info.get("sessions_remaining", 0) - 1
        if remaining <= 0:
            released_ids.append(cid)
            del registry[cid]
        else:
            registry[cid]["sessions_remaining"] = remaining

    # Re-index released chunks
    for cid in released_ids:
        try:
            from store_vfs import _fts5_sync_chunk
            _fts5_sync_chunk(conn, cid)
        except Exception:
            pass
    result["released"] = released_ids

    # ── Phase 2: Detect new bandwidth violators ──
    # Check minimum sample size
    trace_count = conn.execute(
        "SELECT COUNT(*) FROM recall_traces WHERE project = ?", (project,)
    ).fetchone()[0]
    if trace_count < min_traces:
        result["active"] = len(registry)
        _cpuset_save(registry)
        if released_ids:
            bump_chunk_version()
        return result

    # Get recall counts from recent window
    window = int(_cfg("scorer.bw_window") if _cfg("scorer.bw_window") else 30)
    rows = conn.execute(
        "SELECT top_k_json FROM recall_traces WHERE project = ? "
        "ORDER BY rowid DESC LIMIT ?",
        (project, window)
    ).fetchall()

    if len(rows) < min_traces:
        result["active"] = len(registry)
        _cpuset_save(registry)
        if released_ids:
            bump_chunk_version()
        return result

    # Count per-chunk recall frequency
    chunk_counts = Counter()
    for (tk_json,) in rows:
        if not tk_json:
            continue
        try:
            items = json.loads(tk_json)
            for item in items:
                cid = item.get("id", "") if isinstance(item, dict) else str(item)
                if cid:
                    chunk_counts[cid] += 1
        except Exception:
            continue

    window_size = len(rows)
    # Find violators: recall_rate > bw_quarantine_pct
    violators = []
    for cid, cnt in chunk_counts.most_common():
        rate = cnt / window_size
        if rate > bw_quarantine_pct and cid not in registry:
            violators.append((cid, rate))

    # Respect max_quarantine limit
    available_slots = max_quarantine - len(registry)
    new_quarantine = violators[:max(0, available_slots)]

    # ── Phase 3: Quarantine violators — remove from FTS5 ──
    now_iso = datetime.now(timezone.utc).isoformat()
    for cid, rate in new_quarantine:
        # Remove from FTS5 index (chunk stays in main table)
        row = conn.execute(
            "SELECT rowid FROM memory_chunks WHERE id = ?", (cid,)
        ).fetchone()
        if row:
            conn.execute(
                "DELETE FROM memory_chunks_fts WHERE rowid_ref = ?",
                (str(row[0]),)
            )
            registry[cid] = {
                "sessions_remaining": cooldown_sessions,
                "quarantined_at": now_iso,
                "recall_rate": round(rate, 3),
            }
            result["quarantined"].append(cid)

    result["active"] = len(registry)
    _cpuset_save(registry)

    # Bump chunk_version if any FTS5 change occurred
    if result["quarantined"] or result["released"]:
        bump_chunk_version()

    # dmesg log
    try:
        dmesg_log(conn, DMESG_INFO, "cpuset",
                  f"quarantine: new={len(result['quarantined'])} "
                  f"released={len(result['released'])} active={result['active']}",
                  extra=json.dumps({
                      "quarantined_sample": result["quarantined"][:3],
                      "released_sample": result["released"][:3],
                      "project": project,
                  }))
    except Exception:
        pass

    return result


# ──────────────────────────────────────────────
# iter537: perf_counters — Retrieval Quality PMU Counters
# OS 类比：Linux perf_event_open() / perf stat (Ingo Molnár / Thomas Gleixner, 2009)
#   CPU 通过 PMU 暴露 IPC/cache-miss/branch-misprediction 硬件计数器。
#   `perf stat` 读取计数器诊断代码是否高效运行。
#   没有计数器 → 对微架构低效完全盲目。
# ──────────────────────────────────────────────
def perf_counters(conn: "sqlite3.Connection", project: str,
                  window: int = 30) -> dict:
    """
    从 recall_traces 聚合检索质量计数器。

    返回 dict:
      total_traces: int — 窗口内总 trace 数
      injected_traces: int — 实际注入数
      injection_rate: float — 注入率
      avg_score: float — 注入 chunks 平均 score
      min_score: float — 注入 chunks 最低 score
      p25_score: float — 注入 chunks 第 25 百分位 score
      low_score_count: int — score < low_threshold 的注入 chunk 数
      low_score_ratio: float — 低分注入占比
      score_histogram: dict — 分桶计数 {bucket_label: count}
      type_concentration: float — chunk_type 集中度 (HHI, 0~1)
      top_type: str — 最常被注入的 chunk_type
    """
    from config import get as _cfg

    low_threshold = _cfg("perf.low_score_threshold", project=project)

    rows = conn.execute(
        "SELECT top_k_json, injected FROM recall_traces "
        "WHERE project=? ORDER BY timestamp DESC LIMIT ?",
        (project, window)
    ).fetchall()

    if not rows:
        return {"total_traces": 0, "injected_traces": 0, "injection_rate": 0.0,
                "avg_score": 0.0, "min_score": 0.0, "p25_score": 0.0,
                "low_score_count": 0, "low_score_ratio": 0.0,
                "score_histogram": {}, "type_concentration": 0.0, "top_type": ""}

    total = len(rows)
    injected = sum(1 for r in rows if r[1] == 1)

    # 收集所有注入 chunk 的 score 和 type
    all_scores = []
    type_counts = {}
    for top_k_json_str, was_injected in rows:
        if not was_injected or not top_k_json_str:
            continue
        try:
            items = json.loads(top_k_json_str) if isinstance(top_k_json_str, str) else top_k_json_str
        except (json.JSONDecodeError, TypeError):
            continue
        for item in items:
            score = item.get("score", 0)
            if score:
                all_scores.append(score)
            ct = item.get("chunk_type", "unknown")
            type_counts[ct] = type_counts.get(ct, 0) + 1

    if not all_scores:
        return {"total_traces": total, "injected_traces": injected,
                "injection_rate": round(injected / total, 3) if total else 0.0,
                "avg_score": 0.0, "min_score": 0.0, "p25_score": 0.0,
                "low_score_count": 0, "low_score_ratio": 0.0,
                "score_histogram": {}, "type_concentration": 0.0, "top_type": ""}

    all_scores.sort()
    n = len(all_scores)
    avg_score = sum(all_scores) / n
    min_score = all_scores[0]
    p25_score = all_scores[max(0, int(n * 0.25))]
    low_count = sum(1 for s in all_scores if s < low_threshold)
    low_ratio = low_count / n

    # Score histogram: 5 buckets [0-0.2), [0.2-0.4), [0.4-0.6), [0.6-0.8), [0.8-1.0+]
    buckets = {"0.0-0.2": 0, "0.2-0.4": 0, "0.4-0.6": 0, "0.6-0.8": 0, "0.8+": 0}
    for s in all_scores:
        if s < 0.2:
            buckets["0.0-0.2"] += 1
        elif s < 0.4:
            buckets["0.2-0.4"] += 1
        elif s < 0.6:
            buckets["0.4-0.6"] += 1
        elif s < 0.8:
            buckets["0.6-0.8"] += 1
        else:
            buckets["0.8+"] += 1

    # Type concentration: Herfindahl-Hirschman Index (HHI)
    total_type = sum(type_counts.values())
    hhi = sum((c / total_type) ** 2 for c in type_counts.values()) if total_type else 0.0
    top_type = max(type_counts, key=type_counts.get) if type_counts else ""

    return {
        "total_traces": total,
        "injected_traces": injected,
        "injection_rate": round(injected / total, 3) if total else 0.0,
        "avg_score": round(avg_score, 4),
        "min_score": round(min_score, 4),
        "p25_score": round(p25_score, 4),
        "low_score_count": low_count,
        "low_score_ratio": round(low_ratio, 4),
        "score_histogram": buckets,
        "type_concentration": round(hhi, 4),
        "top_type": top_type,
    }


# ── iter544: trim_shadow_entries — Shadow Entry Expiry & Stale Ref Scrub ─────
#
# OS 类比：Linux shadow_lru_isolate() / workingset_eviction() (Johannes Weiner, 2013)
#   mm/workingset.c 中，shadow entry 记录被淘汰页面的 eviction 信息（zone, recent, workingset）。
#   当 shadow entry 数量超过 active page count 时，shadow_lru_isolate() 从 shadow LRU
#   批量回收最老的 shadow entries，防止 inode radix tree 节点无限膨胀。
#   shadow entry 只是用来检测 refault 的辅助数据——如果对应的物理页已被重新分配且
#   shadow entry 从未触发 refault，则该 shadow 已失去价值，应该被回收。
#
# 问题：shadow_traces 表每个 session 写入一条记录但无 GC。
#   543 条记录中 534 个 stale chunk ID 引用（指向已删除 chunks）。
#   extractor.py 读取 shadow_traces 获取 top_k_ids 做反馈降级，
#   stale refs 导致查找无效 + 表膨胀增加扫描时间。
#
def trim_shadow_entries(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    迭代544: trim_shadow_entries — Shadow Entry Expiry & Stale Reference Scrub。

    三阶段清理：
      Phase 1 (expire): 超过 max_shadow_entries 时按 ROWID ASC 删除最老条目
      Phase 2 (scrub):  清理存活条目中指向已删除 chunk 的 stale references
      Phase 3 (purge):  清理后 top_k_ids 为空的条目（所有引用都 stale → 无价值）

    Returns:
        dict: expired/scrubbed/purged/remaining 统计
    """
    from config import get as sysctl_get

    max_entries = int(sysctl_get("shadow.max_entries", 100))
    max_expire_per_scan = int(sysctl_get("shadow.max_expire_per_scan", 200))

    result = {
        "expired": 0,
        "scrubbed_refs": 0,
        "scrubbed_traces": 0,
        "purged": 0,
        "remaining": 0,
    }

    # ── Phase 1: Expire oldest entries beyond capacity ──
    # shadow_lru_isolate() 语义：超过 active page count 的 shadow 从 LRU 尾部回收
    if project:
        total = conn.execute(
            "SELECT COUNT(*) FROM shadow_traces WHERE project=?", (project,)
        ).fetchone()[0]
    else:
        total = conn.execute("SELECT COUNT(*) FROM shadow_traces").fetchone()[0]

    if total > max_entries:
        excess = min(total - max_entries, max_expire_per_scan)
        if project:
            # 按 ROWID 升序（最老优先）批量删除
            conn.execute(
                "DELETE FROM shadow_traces WHERE ROWID IN "
                "(SELECT ROWID FROM shadow_traces WHERE project=? ORDER BY ROWID ASC LIMIT ?)",
                (project, excess),
            )
        else:
            conn.execute(
                "DELETE FROM shadow_traces WHERE ROWID IN "
                "(SELECT ROWID FROM shadow_traces ORDER BY ROWID ASC LIMIT ?)",
                (excess,),
            )
        result["expired"] = excess

    # ── Phase 2: Scrub stale references in surviving entries ──
    # 类似 rmap_sweep 对 recall_traces 的 stale ref 清理，
    # 但 shadow_traces 使用 top_k_ids JSON 数组（不含 score，只有 ID 列表）
    live_ids = set(
        r[0] for r in conn.execute("SELECT id FROM memory_chunks").fetchall()
    )

    if project:
        rows = conn.execute(
            "SELECT ROWID, top_k_ids FROM shadow_traces WHERE project=?", (project,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT ROWID, top_k_ids FROM shadow_traces"
        ).fetchall()

    purge_rowids = []
    for rowid, top_k_raw in rows:
        if not top_k_raw:
            purge_rowids.append(rowid)
            continue
        try:
            ids = json.loads(top_k_raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            purge_rowids.append(rowid)
            continue

        if not isinstance(ids, list) or not ids:
            # 非列表或空列表 → purge（shadow 无引用 = 无价值）
            purge_rowids.append(rowid)
            continue

        live = [i for i in ids if i in live_ids]
        stale_count = len(ids) - len(live)
        if stale_count > 0:
            result["scrubbed_refs"] += stale_count
            result["scrubbed_traces"] += 1
            if not live:
                # 所有引用都 stale → 标记 purge
                purge_rowids.append(rowid)
            else:
                # 部分 stale → 更新保留有效引用
                conn.execute(
                    "UPDATE shadow_traces SET top_k_ids=? WHERE ROWID=?",
                    (json.dumps(live), rowid),
                )

    # ── Phase 3: Purge empty entries ──
    if purge_rowids:
        # 分批删除，每批 500
        for i in range(0, len(purge_rowids), 500):
            batch = purge_rowids[i : i + 500]
            placeholders = ",".join("?" * len(batch))
            conn.execute(
                f"DELETE FROM shadow_traces WHERE ROWID IN ({placeholders})", batch
            )
        result["purged"] = len(purge_rowids)

    conn.commit()

    # 统计最终剩余
    if project:
        result["remaining"] = conn.execute(
            "SELECT COUNT(*) FROM shadow_traces WHERE project=?", (project,)
        ).fetchone()[0]
    else:
        result["remaining"] = conn.execute(
            "SELECT COUNT(*) FROM shadow_traces"
        ).fetchone()[0]

    return result


# ── iter545: vmstat_scan — Scan Efficiency Accounting & Dark Page Demotion ──────
#
# OS 类比：Linux /proc/vmstat pgscan_kswapd/pgsteal_kswapd (Mel Gorman, 2004)
#   内核追踪每个 zone 的 pgscan（扫描页面数）和 pgsteal（成功回收页面数）。
#   scan efficiency = pgsteal / pgscan。当效率持续低下（扫描多但回收少），
#   表明 working set 过大或页面 pin 过多，内核据此切换 direct reclaim 策略、
#   触发 compaction、或调整 watermark。
#
#   memory-os 等价：recall_traces 记录 candidates_count（扫描）和 top_k_json 中
#   实际 chunk 数（steal/注入）。scan_efficiency = injected_items / candidates_scanned。
#   当效率持续低于阈值，说明大量 chunk 被反复评估但从未胜出——"futile scanning"。
#   对长期处于"被扫描但从不被偷取"状态的 dark pages 做 oom_adj 降级，
#   降低它们在未来检索中的竞争力，为新知识让路。
#
def vmstat_scan(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    iter545: vmstat_scan — Scan Efficiency Accounting & Dark Page Demotion.

    Phase 1 (accounting): 从 recall_traces 计算 scan/steal counters.
    Phase 2 (dark page detection): 识别存在时间 >= min_traces 但从未出现
      在任何 top_k_json 中的 chunks（dark pages）。
    Phase 3 (demotion): 对 dark pages 增加 oom_adj 惩罚，降低未来竞争力。

    返回:
      pgscan: int — 窗口内总 candidates 扫描量
      pgsteal: int — 窗口内总 top_k 注入量
      scan_efficiency: float — pgsteal/pgscan (0~1)
      dark_pages_total: int — dark page 数量
      dark_pages_demoted: int — 本次降级数量
      dark_pages_skipped: int — 跳过数量（已保护/已降级）
      duration_ms: float
    """
    from config import get as _cfg

    t0 = _time.time()

    window = _cfg("vmstat.window_traces")
    min_traces_for_dark = _cfg("vmstat.min_traces_dark")
    demote_adj = _cfg("vmstat.dark_demote_adj")
    max_demote_per_scan = _cfg("vmstat.max_demote_per_scan")

    result = {
        "pgscan": 0,
        "pgsteal": 0,
        "scan_efficiency": 0.0,
        "dark_pages_total": 0,
        "dark_pages_demoted": 0,
        "dark_pages_skipped": 0,
        "duration_ms": 0.0,
    }

    # ── Phase 1: Scan/Steal Accounting ──
    if project:
        rows = conn.execute(
            "SELECT candidates_count, top_k_json FROM recall_traces "
            "WHERE project=? ORDER BY timestamp DESC LIMIT ?",
            (project, window)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT candidates_count, top_k_json FROM recall_traces "
            "ORDER BY timestamp DESC LIMIT ?",
            (window,)
        ).fetchall()

    trace_count = len(rows)
    pgscan = 0
    pgsteal = 0
    stolen_ids = set()  # chunk IDs that appeared in any top_k

    for candidates_count, top_k_json_str in rows:
        pgscan += candidates_count or 0
        if top_k_json_str:
            try:
                items = json.loads(top_k_json_str) if isinstance(top_k_json_str, str) else []
                pgsteal += len(items)
                for item in items:
                    cid = item.get("id", "")
                    if cid:
                        stolen_ids.add(cid)
            except (json.JSONDecodeError, TypeError):
                pass

    result["pgscan"] = pgscan
    result["pgsteal"] = pgsteal
    result["scan_efficiency"] = round(pgsteal / pgscan, 4) if pgscan > 0 else 0.0

    # ── Phase 2: Dark Page Detection ──
    # 只在有足够 trace 历史时进行（避免新项目误判）
    if trace_count < min_traces_for_dark:
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # 获取当前项目所有 active chunks
    if project:
        all_chunks = conn.execute(
            "SELECT id, oom_adj, access_count, importance FROM memory_chunks "
            "WHERE project=? AND chunk_state='ACTIVE'",
            (project,)
        ).fetchall()
    else:
        all_chunks = conn.execute(
            "SELECT id, oom_adj, access_count, importance FROM memory_chunks "
            "WHERE chunk_state='ACTIVE'"
        ).fetchall()

    # Dark pages: 存在但从未出现在任何 top_k
    dark_pages = []
    for chunk_id, oom_adj, access_count, importance in all_chunks:
        if chunk_id not in stolen_ids:
            dark_pages.append((chunk_id, oom_adj, access_count, importance))

    result["dark_pages_total"] = len(dark_pages)

    # ── Phase 3: Demotion ──
    # 只降级：oom_adj >= 0（未保护）且 access_count == 0（从未被检索命中）
    # 且 importance < 0.9（非关键知识）
    demoted = 0
    skipped = 0

    for chunk_id, oom_adj, access_count, importance in dark_pages:
        if demoted >= max_demote_per_scan:
            break
        # 跳过已保护的 chunks（oom_adj < 0 = 有保护策略）
        if oom_adj < 0:
            skipped += 1
            continue
        # 跳过已被访问过的（可能只是最近 trace window 不够长）
        if access_count > 0:
            skipped += 1
            continue
        # 跳过高 importance（由用户/系统标记为重要）
        if importance >= 0.9:
            skipped += 1
            continue
        # 跳过已经被充分降级的（避免重复叠加）
        if oom_adj >= demote_adj:
            skipped += 1
            continue

        # 降级：设置 oom_adj = demote_adj
        conn.execute(
            "UPDATE memory_chunks SET oom_adj=? WHERE id=?",
            (demote_adj, chunk_id)
        )
        demoted += 1

    if demoted > 0:
        conn.commit()
        bump_chunk_version()

    result["dark_pages_demoted"] = demoted
    result["dark_pages_skipped"] = skipped
    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)

    return result


# ── iter546: shrink_slab — Periodic Slab Object Reaper ──────────────────

def shrink_slab(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    iter546: shrink_slab — Watermark-Independent Slab Object Reaper.

    OS 类比：Linux do_shrink_slab() (Dave Chinner, 2013, mm/vmscan.c kernel 3.12)
      内核为 inode cache/dentry cache/buffer_head 等注册 struct shrinker。
      每次内存回收扫描时，vmscan 调用 shrinker->count_objects() 获取可回收对象数，
      shrinker->scan_objects(nr_to_scan) 释放它们。
      关键：shrinkers 不依赖 kswapd 水位线——即使系统在 ZONE_OK 也会被调用，
      只要存在 "freeable" 对象（LRU 尾部、引用计数=0 的 slab 对象）。

    根因：
      vmstat_scan(iter545) 将 dark pages 降级到 oom_adj=400，
      page_idle(iter530) 将多轮 idle 后进一步降级到 oom_adj=600。
      但没有任何机制最终回收这些高 oom_adj 的 zombie chunks：
        - kswapd: 需要 watermark >= pages_low_pct (75%) 才唤醒，当前 75/200 = 37.5%
        - _reclaim_stale_chunks: 只在 kswapd 内部被调用
      结果：11 个 oom_adj >= 400 的 zombie chunks 永久存活，
      占总量 75 的 14.7%，零价值但永远不被清理。

    设计：
      shrink_slab 不关心水位线，只关心对象自身的状态：
        1. count_objects: 扫描 oom_adj >= shrink_min_adj(400) + access_count=0
        2. scan_objects: 按 oom_adj DESC + importance ASC 排序，取 Top-N swap_out
        3. 保护: importance >= 0.9 或 oom_adj < 0 不回收（已受保护）
        4. 宽限期: 最近 shrink_grace_sessions 内创建的 chunk 跳过（避免误杀新知识）

    参数：
      conn — 数据库连接
      project — 项目 ID (None = 全局扫描)

    返回 dict:
      freeable: int — 可回收对象总数 (count_objects)
      scanned: int — 本次扫描数
      reclaimed: int — 实际回收数 (swap_out)
      skipped_grace: int — 宽限期内跳过数
      duration_ms: float
    """
    from config import get as _cfg

    t0 = _time.time()

    shrink_min_adj = int(_cfg("shrink.min_adj"))
    max_scan_per_run = int(_cfg("shrink.max_scan_per_run"))
    grace_sessions = int(_cfg("shrink.grace_sessions"))

    result = {
        "freeable": 0,
        "scanned": 0,
        "reclaimed": 0,
        "skipped_grace": 0,
        "duration_ms": 0.0,
    }

    # ── Phase 1: count_objects — 统计可回收对象 ──
    if project:
        freeable_rows = conn.execute(
            """SELECT id, oom_adj, importance, access_count, created_at
               FROM memory_chunks
               WHERE project IN (?, 'global')
                 AND COALESCE(oom_adj, 0) >= ?
                 AND COALESCE(access_count, 0) = 0
                 AND chunk_state = 'ACTIVE'
               ORDER BY oom_adj DESC, importance ASC""",
            (project, shrink_min_adj)
        ).fetchall()
    else:
        freeable_rows = conn.execute(
            """SELECT id, oom_adj, importance, access_count, created_at
               FROM memory_chunks
               WHERE COALESCE(oom_adj, 0) >= ?
                 AND COALESCE(access_count, 0) = 0
                 AND chunk_state = 'ACTIVE'
               ORDER BY oom_adj DESC, importance ASC""",
            (shrink_min_adj,)
        ).fetchall()

    result["freeable"] = len(freeable_rows)

    if not freeable_rows:
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # ── Phase 2: scan_objects — 宽限期过滤 + 回收 ──
    # 宽限期：计算最近 N 个 session 的时间范围
    grace_cutoff = None
    if grace_sessions > 0:
        try:
            # 用 dmesg loader 条目作为 session 边界标记
            session_rows = conn.execute(
                "SELECT DISTINCT timestamp FROM dmesg "
                "WHERE subsystem='loader' AND message LIKE 'session_start%' "
                "ORDER BY timestamp DESC LIMIT ?",
                (grace_sessions,)
            ).fetchall()
            if len(session_rows) >= grace_sessions:
                grace_cutoff = session_rows[-1][0]
        except Exception:
            pass

    to_reclaim = []
    skipped_grace = 0

    for chunk_id, oom_adj, importance, access_count, created_at in freeable_rows:
        if len(to_reclaim) >= max_scan_per_run:
            break

        # 保护高重要性（额外防护层，SQL 已过滤 access_count=0 但 importance 可能高）
        if importance is not None and importance >= 0.9:
            continue

        # 宽限期检查：最近 N 个 session 内创建的跳过
        if grace_cutoff and created_at and created_at >= grace_cutoff:
            skipped_grace += 1
            continue

        to_reclaim.append(chunk_id)

    result["scanned"] = len(to_reclaim) + skipped_grace
    result["skipped_grace"] = skipped_grace

    # ── Phase 3: 回收（swap_out）──
    if to_reclaim:
        try:
            swap_out(conn, to_reclaim)
            conn.commit()
            bump_chunk_version()
            result["reclaimed"] = len(to_reclaim)
        except Exception:
            result["reclaimed"] = 0

    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
    return result


def fstrim(conn: sqlite3.Connection) -> dict:
    """
    iter547: fstrim — Auxiliary Table Dead Block TRIM.

    OS 类比：Linux fstrim / FITRIM ioctl (Lukas Czerner, 2010, kernel 2.6.37)
      SSD 控制器不知道文件系统层面哪些 LBA 已被释放（unlink/truncate 只更新元数据）。
      fstrim 遍历 free space bitmap，向 SSD 发送 TRIM/DISCARD 命令，
      通知设备这些物理块可以回收。不 TRIM → write amplification + GC 效率下降。
      运行频率：systemd fstrim.timer 每周一次（低频即可，不是每次写都 TRIM）。

    根因：
      memory_chunks 通过 swap_out/delete_chunks 删除后，8 张辅助表保留 stale references：
        - entity_edges: source_chunk_id → 已删除 chunk
        - entity_map: chunk_id → 已删除 chunk
        - chunk_coactivation: chunk_a/chunk_b → 已删除 chunk
        - chunk_pins: chunk_id → 已删除 chunk
        - shm_segments: chunk_id → 已删除 chunk
        - trigger_conditions: chunk_id → 已删除 chunk
        - schema_anchors: chunk_id → 已删除 chunk
        - episodic_consolidations: source_chunk_ids JSON 包含已删除 chunk IDs
      生产实证：69 active chunks，辅助表 1176 条记录，484 条 stale (41%)。
      stale records 造成：
        1. entity graph 查询返回无效结果
        2. 扫描时间增加（entity_map 262 条中 224 条 stale = 85.5%）
        3. DB 文件膨胀

    设计：
      fstrim 扫描每张辅助表，DELETE 所有指向非 ACTIVE chunk 的记录。
      每张表独立 phase，失败不影响其他表（fault isolation）。
      运行时机：SessionStart 时，shrink_slab 之后（先回收 zombie，再 TRIM 死块）。

    返回 dict:
      trimmed: dict — 每张表被 TRIM 的行数
      total_trimmed: int — 总清理行数
      duration_ms: float
    """
    t0 = _time.time()

    trimmed = {}

    # ── Phase 1: entity_edges — TRIM stale source_chunk_id ──
    try:
        r = conn.execute(
            """DELETE FROM entity_edges
               WHERE source_chunk_id IS NOT NULL
                 AND source_chunk_id != ''
                 AND NOT EXISTS (
                     SELECT 1 FROM memory_chunks
                     WHERE id = entity_edges.source_chunk_id
                       AND chunk_state = 'ACTIVE'
                 )"""
        )
        trimmed["entity_edges"] = r.rowcount
    except Exception:
        trimmed["entity_edges"] = 0

    # ── Phase 2: entity_map — TRIM stale chunk_id ──
    try:
        r = conn.execute(
            """DELETE FROM entity_map
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = entity_map.chunk_id
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["entity_map"] = r.rowcount
    except Exception:
        trimmed["entity_map"] = 0

    # ── Phase 3: chunk_coactivation — TRIM rows where either side is dead ──
    try:
        r = conn.execute(
            """DELETE FROM chunk_coactivation
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = chunk_coactivation.chunk_a
                     AND chunk_state = 'ACTIVE'
               )
               OR NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = chunk_coactivation.chunk_b
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["chunk_coactivation"] = r.rowcount
    except Exception:
        trimmed["chunk_coactivation"] = 0

    # ── Phase 4: chunk_pins — TRIM stale pins ──
    try:
        r = conn.execute(
            """DELETE FROM chunk_pins
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = chunk_pins.chunk_id
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["chunk_pins"] = r.rowcount
    except Exception:
        trimmed["chunk_pins"] = 0

    # ── Phase 5: shm_segments — TRIM stale shared memory ──
    try:
        r = conn.execute(
            """DELETE FROM shm_segments
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = shm_segments.chunk_id
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["shm_segments"] = r.rowcount
    except Exception:
        trimmed["shm_segments"] = 0

    # ── Phase 6: trigger_conditions — TRIM stale triggers ──
    try:
        r = conn.execute(
            """DELETE FROM trigger_conditions
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = trigger_conditions.chunk_id
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["trigger_conditions"] = r.rowcount
    except Exception:
        trimmed["trigger_conditions"] = 0

    # ── Phase 7: schema_anchors — TRIM stale anchors ──
    try:
        r = conn.execute(
            """DELETE FROM schema_anchors
               WHERE NOT EXISTS (
                   SELECT 1 FROM memory_chunks
                   WHERE id = schema_anchors.chunk_id
                     AND chunk_state = 'ACTIVE'
               )"""
        )
        trimmed["schema_anchors"] = r.rowcount
    except Exception:
        trimmed["schema_anchors"] = 0

    # ── Phase 8: episodic_consolidations — TRIM fully-stale consolidations ──
    # (all source_chunk_ids point to deleted chunks → no value)
    try:
        rows = conn.execute(
            "SELECT id, source_chunk_ids FROM episodic_consolidations"
        ).fetchall()
        to_delete = []
        for row_id, src_json in rows:
            try:
                src_ids = json.loads(src_json) if src_json else []
            except (json.JSONDecodeError, TypeError):
                src_ids = []
            if not src_ids:
                to_delete.append(row_id)
                continue
            # Check if ALL source chunks are dead
            placeholders = ",".join("?" * len(src_ids))
            alive = conn.execute(
                f"SELECT COUNT(*) FROM memory_chunks "
                f"WHERE id IN ({placeholders}) AND chunk_state='ACTIVE'",
                src_ids
            ).fetchone()[0]
            if alive == 0:
                to_delete.append(row_id)
        if to_delete:
            placeholders = ",".join("?" * len(to_delete))
            conn.execute(
                f"DELETE FROM episodic_consolidations WHERE id IN ({placeholders})",
                to_delete
            )
        trimmed["episodic_consolidations"] = len(to_delete)
    except Exception:
        trimmed["episodic_consolidations"] = 0

    total = sum(trimmed.values())

    if total > 0:
        conn.commit()

    return {
        "trimmed": trimmed,
        "total_trimmed": total,
        "duration_ms": round((_time.time() - t0) * 1000, 2),
    }


# ── iter548: logrotate — Metadata Table Lifecycle Rotation ──────────────────

def logrotate(conn: sqlite3.Connection) -> dict:
    """
    iter548: logrotate — 元数据表生命周期轮转。
    OS 类比：Linux logrotate (Red Hat, 1997) — /etc/logrotate.d/ 配置每个日志文件的
      轮转策略（maxsize/maxage/rotate count）。logrotate 由 cron.daily 触发，
      按策略 truncate/rotate/compress/remove 过期日志。
      没有 logrotate → /var/log 无限膨胀，inode 耗尽，journald 写满整盘。

    根因：
      fstrim(iter547) 清理辅助表中引用已删除 chunk 的 stale records，
      但 6 张元数据/日志表没有 chunk 外键，无法通过 stale ref 检测——
      它们只是随时间单调增长的日志/状态表：
        - ipc_msgq: 424 条 CONSUMED 消息（全部已消费，无保留价值）
        - hook_txn_log: 470 条事务日志（仅审计用，保留最近 N 条即可）
        - session_focus: 103 条 session 焦点（旧 session 数据无召回价值）
        - priming_state: 1656 条实体 priming（无上限，按 project 线性增长）
        - tool_patterns: 639 条工具模式（低频模式无价值，保留 Top-N 即可）
        - entity_edges: 507 条（98.4% orphaned，NULL source_chunk_id 无法被 fstrim 清理）

    策略：per-table rotation policy，每表独立 try/except（fault isolation）：
      Phase 1: ipc_msgq — 清除 CONSUMED 且超过 max_age 的消息
      Phase 2: hook_txn_log — 保留最新 max_entries，删除最旧
      Phase 3: session_focus — 清除超过 max_age 的旧 session 焦点
      Phase 4: priming_state — per-project 保留 top-N（按 prime_strength DESC）
      Phase 5: tool_patterns — 保留高频/近期使用的，清除低频旧模式
      Phase 6: entity_edges — 清除 orphaned edges（NULL source + entity 不在任何 active chunk 中）

    运行频率：SessionStart，fstrim 之后，受 deferred_initcall 门控。
    """
    try:
        from config import get as _cfg
    except Exception:
        return {"rotated": {}, "total_rotated": 0, "duration_ms": 0}

    t0 = _time.time()
    rotated = {}

    # ── Phase 1: ipc_msgq — 清除已消费的旧消息 ──
    # logrotate policy: status=CONSUMED + age > max_age_hours → delete
    try:
        max_age_h = int(_cfg("logrotate.ipc_msgq_max_age_hours"))
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_h)).isoformat()
        r = conn.execute(
            """DELETE FROM ipc_msgq
               WHERE status = 'CONSUMED'
                 AND created_at < ?""",
            (cutoff,)
        )
        rotated["ipc_msgq"] = r.rowcount
    except Exception:
        rotated["ipc_msgq"] = 0

    # ── Phase 2: hook_txn_log — 保留最新 N 条 ──
    # logrotate policy: rotate count = max_entries, 超出按 started_at ASC 删除
    try:
        max_entries = int(_cfg("logrotate.hook_txn_log_max_entries"))
        count = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
        if count > max_entries:
            overflow = count - max_entries
            conn.execute(
                "DELETE FROM hook_txn_log WHERE rowid IN "
                "(SELECT rowid FROM hook_txn_log ORDER BY started_at ASC LIMIT ?)",
                (overflow,)
            )
            rotated["hook_txn_log"] = overflow
        else:
            rotated["hook_txn_log"] = 0
    except Exception:
        rotated["hook_txn_log"] = 0

    # ── Phase 3: session_focus — 清除超龄 session 焦点 ──
    # logrotate policy: maxage = max_age_hours
    try:
        max_age_h = int(_cfg("logrotate.session_focus_max_age_hours"))
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_h)).isoformat()
        r = conn.execute(
            "DELETE FROM session_focus WHERE updated_at < ?",
            (cutoff,)
        )
        rotated["session_focus"] = r.rowcount
    except Exception:
        rotated["session_focus"] = 0

    # ── Phase 4: priming_state — per-project 保留 Top-N ──
    # logrotate policy: maxsize per-project = max_per_project
    try:
        max_per_project = int(_cfg("logrotate.priming_max_per_project"))
        # 找出超额 project
        proj_counts = conn.execute(
            "SELECT project, COUNT(*) as cnt FROM priming_state "
            "GROUP BY project HAVING cnt > ?",
            (max_per_project,)
        ).fetchall()
        total_pruned = 0
        for proj, cnt in proj_counts:
            overflow = cnt - max_per_project
            # 保留 prime_strength 最高的（降序），删除最弱的
            conn.execute(
                """DELETE FROM priming_state WHERE rowid IN (
                    SELECT rowid FROM priming_state
                    WHERE project = ?
                    ORDER BY prime_strength ASC, primed_at ASC
                    LIMIT ?
                )""",
                (proj, overflow)
            )
            total_pruned += overflow
        rotated["priming_state"] = total_pruned
    except Exception:
        rotated["priming_state"] = 0

    # ── Phase 5: tool_patterns — 清除低频旧模式 ──
    # logrotate policy: 保留 max_entries，按 frequency*recency 排序淘汰
    try:
        max_entries = int(_cfg("logrotate.tool_patterns_max_entries"))
        count = conn.execute("SELECT COUNT(*) FROM tool_patterns").fetchone()[0]
        if count > max_entries:
            overflow = count - max_entries
            # 淘汰 frequency 最低 + last_seen 最旧的
            conn.execute(
                """DELETE FROM tool_patterns WHERE rowid IN (
                    SELECT rowid FROM tool_patterns
                    ORDER BY frequency ASC, last_seen ASC
                    LIMIT ?
                )""",
                (overflow,)
            )
            rotated["tool_patterns"] = overflow
        else:
            rotated["tool_patterns"] = 0
    except Exception:
        rotated["tool_patterns"] = 0

    # ── Phase 6: entity_edges — 清除 orphaned edges ──
    # fstrim 只清理有 source_chunk_id 的 stale edges。
    # logrotate 补充清理：source_chunk_id IS NULL + 超龄（created_at 过旧）
    # 这些是 entity graph 早期版本遗留的无锚 edges，无法关联到任何 chunk。
    try:
        max_age_h = int(_cfg("logrotate.entity_edges_orphan_max_age_hours"))
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_h)).isoformat()
        r = conn.execute(
            """DELETE FROM entity_edges
               WHERE (source_chunk_id IS NULL OR source_chunk_id = '')
                 AND created_at < ?""",
            (cutoff,)
        )
        rotated["entity_edges"] = r.rowcount
    except Exception:
        rotated["entity_edges"] = 0

    total = sum(rotated.values())

    if total > 0:
        conn.commit()

    return {
        "rotated": rotated,
        "total_rotated": total,
        "duration_ms": round((_time.time() - t0) * 1000, 2),
    }


# ── vacuum — Database File Compaction（迭代549）────────────────────────

def vacuum(db_path: str) -> dict:
    """
    迭代549：vacuum — Database File Compaction。
    OS 类比：SSD Background GC / Firmware Compaction (Samsung 840 EVO, ~2013)

    Linux fstrim 通知 SSD 哪些 LBA 已释放（TRIM/DISCARD），但 SSD 内部仍需
    background GC 将有效 pages 从碎片化的 erase block 搬迁合并，腾出完整
    erase block 用于后续写入。没有 background GC → write amplification 上升、
    可用 overprovisioning 空间耗尽、性能下降。

    SQLite 的 freelist pages 等价于 SSD 的 invalidated pages——逻辑已释放
    （DELETE/DROP 后 page 加入 freelist），但 DB 文件大小不变，OS 仍需读写
    这些无用 pages 的 I/O（stat/backup/sync）。
    VACUUM 相当于 SSD 的 background GC：重写整个 DB 为紧凑格式，
    归还空闲页给 OS 文件系统。

    触发策略（模仿 SSD GC 的保守触发逻辑）：
      1. freelist_pct >= vacuum_threshold_pct (默认 40%) — 空闲率高到值得整理
      2. 距上次 vacuum >= vacuum_cooldown_hours (默认 24h) — 避免频繁重写
      3. DB 文件 >= vacuum_min_size_kb (默认 512KB) — 小文件不值得 vacuum

    参数：
      db_path — 数据库文件路径（字符串）

    返回 dict：
      vacuumed — 是否执行了 VACUUM
      reason — 跳过/执行原因
      before_size_kb — VACUUM 前文件大小
      after_size_kb — VACUUM 后文件大小
      freed_kb — 释放空间
      freed_pct — 释放百分比
      freelist_pct — VACUUM 前 freelist 占比
      duration_ms — 执行时间
    """
    t0 = _time.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"vacuumed": False, "reason": "no_config", "duration_ms": 0}

    # 配置参数
    threshold_pct = float(_cfg("vacuum.threshold_pct"))
    cooldown_hours = int(_cfg("vacuum.cooldown_hours"))
    min_size_kb = int(_cfg("vacuum.min_size_kb"))

    result = {
        "vacuumed": False,
        "reason": "",
        "before_size_kb": 0,
        "after_size_kb": 0,
        "freed_kb": 0,
        "freed_pct": 0.0,
        "freelist_pct": 0.0,
        "duration_ms": 0.0,
    }

    # 检查文件存在
    if not os.path.exists(db_path):
        result["reason"] = "db_not_found"
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # 条件 1：最小文件大小
    before_size = os.path.getsize(db_path)
    result["before_size_kb"] = round(before_size / 1024, 1)
    if before_size < min_size_kb * 1024:
        result["reason"] = f"small_db({result['before_size_kb']:.0f}KB<{min_size_kb}KB)"
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # 条件 2：冷却期（避免频繁 VACUUM）
    cooldown_flag = Path(db_path).parent / "vacuum_last.json"
    now_ts = _time.time()
    if cooldown_flag.exists():
        try:
            vdata = json.loads(cooldown_flag.read_text())
            last_ts = vdata.get("ts", 0)
            if now_ts - last_ts < cooldown_hours * 3600:
                remaining_h = (cooldown_hours * 3600 - (now_ts - last_ts)) / 3600
                result["reason"] = f"cooldown({remaining_h:.1f}h_remaining)"
                result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
                return result
        except Exception:
            pass

    # 条件 3：freelist 占比
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        page_count = conn.execute("PRAGMA page_count").fetchone()[0]
        freelist_count = conn.execute("PRAGMA freelist_count").fetchone()[0]
        conn.close()
    except Exception as e:
        result["reason"] = f"pragma_error({e})"
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    freelist_pct = (freelist_count / page_count * 100) if page_count > 0 else 0
    result["freelist_pct"] = round(freelist_pct, 1)

    if freelist_pct < threshold_pct:
        result["reason"] = f"low_fragmentation({freelist_pct:.1f}%<{threshold_pct}%)"
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # 所有条件满足，执行 VACUUM
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        conn.execute("VACUUM")
        conn.close()
    except Exception as e:
        result["reason"] = f"vacuum_error({e})"
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # 计算释放空间
    after_size = os.path.getsize(db_path)
    freed = before_size - after_size
    result["vacuumed"] = True
    result["reason"] = f"compacted(freelist={freelist_pct:.1f}%)"
    result["after_size_kb"] = round(after_size / 1024, 1)
    result["freed_kb"] = round(freed / 1024, 1)
    result["freed_pct"] = round(freed / before_size * 100, 1) if before_size > 0 else 0

    # 更新冷却标记
    try:
        cooldown_flag.write_text(json.dumps({
            "ts": now_ts,
            "freed_kb": result["freed_kb"],
            "freed_pct": result["freed_pct"],
        }))
    except Exception:
        pass

    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
    return result


# ── iter550: release_task — Per-Session Runtime State Cleanup ──────
def release_task(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    iter550: release_task — Per-Session Runtime State Cleanup。
    OS 类比：Linux release_task() (Linus Torvalds, 1994, kernel/exit.c)

    当进程退出 (do_exit()) 时，release_task() 清理所有 per-process 运行时状态：
    /proc/PID/ 条目、文件描述符、信号处理器、内存映射。没有 release_task()，
    zombie 进程永久泄漏资源。systemd-tmpfiles --clean 补充清理 /tmp/ 和 /run/
    中的累积文件。

    Memory-OS 问题：每次 SessionStart 创建 per-session 状态但从不清理：
    - .shadow_trace.<session_id>.json 文件（每个 ~380 bytes）→ 数百个文件累积
    - shadow_traces DB 表（大量行内容重复——47/106 行共享相同 top_k_ids）
    - session_episodes 中已注入旧记录累积
    - checkpoints 中已消费/超龄记录累积

    四阶段清理（模仿 release_task + systemd-tmpfiles）：
      Phase 1: shadow_file_gc — 删除超龄 .shadow_trace.*.json 文件
      Phase 2: shadow_db_dedup — shadow_traces 表按 top_k_ids 去重
      Phase 3: session_episodes_gc — 删除已注入的旧 episodes
      Phase 4: checkpoint_gc — 删除超龄/已消费的 checkpoints

    返回 dict:
      total_cleaned — 总清理数
      phases — 各 phase 清理详情
      duration_ms — 执行时间
    """
    t0 = _time.time()

    try:
        from config import get as _cfg
    except Exception:
        return {"total_cleaned": 0, "phases": {}, "duration_ms": 0}

    # 配置参数
    shadow_file_max_age_hours = int(_cfg("release_task.shadow_file_max_age_hours"))
    shadow_db_max_per_content = int(_cfg("release_task.shadow_db_max_per_content"))
    episodes_max_age_hours = int(_cfg("release_task.episodes_max_age_hours"))
    checkpoint_max_age_hours = int(_cfg("release_task.checkpoint_max_age_hours"))

    total_cleaned = 0
    phases = {}
    now = _time.time()

    # ── Phase 1: shadow_file_gc — 清理超龄 .shadow_trace.*.json 文件 ──
    # OS 类比：systemd-tmpfiles --clean /run/user/UID/
    try:
        shadow_pattern = MEMORY_OS_DIR / ".shadow_trace.*.json"
        import glob as _glob_mod
        shadow_files = _glob_mod.glob(str(shadow_pattern))
        removed_files = 0
        max_age_secs = shadow_file_max_age_hours * 3600
        for fpath in shadow_files:
            try:
                mtime = os.path.getmtime(fpath)
                if now - mtime > max_age_secs:
                    os.remove(fpath)
                    removed_files += 1
            except Exception:
                continue
        phases["shadow_file_gc"] = {
            "scanned": len(shadow_files),
            "removed": removed_files,
        }
        total_cleaned += removed_files
    except Exception:
        phases["shadow_file_gc"] = {"scanned": 0, "removed": 0, "error": True}

    # ── Phase 2: shadow_db_dedup — shadow_traces 表按 content 去重 ──
    # OS 类比：release_task() → __put_task_struct() 释放重复 mm_struct 引用
    # 相同 top_k_ids 内容的多行只保留最新一条
    try:
        tbl = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='shadow_traces'"
        ).fetchone()
        removed_rows = 0
        total_before = 0
        if tbl:
            rows = conn.execute(
                "SELECT session_id, top_k_ids, updated_at FROM shadow_traces "
                "ORDER BY updated_at DESC"
            ).fetchall()
            total_before = len(rows)
            # 按 top_k_ids 内容分组
            content_groups = defaultdict(list)
            for sid, tk_ids, upd in rows:
                content_groups[tk_ids].append(sid)
            # 每组保留最新 max_per_content 条，删除其余
            delete_ids = []
            for tk_ids, sids in content_groups.items():
                if len(sids) > shadow_db_max_per_content:
                    delete_ids.extend(sids[shadow_db_max_per_content:])
            if delete_ids:
                for batch_start in range(0, len(delete_ids), 100):
                    batch = delete_ids[batch_start:batch_start + 100]
                    placeholders = ",".join("?" * len(batch))
                    conn.execute(
                        f"DELETE FROM shadow_traces WHERE session_id IN ({placeholders})",
                        batch
                    )
                conn.commit()
                removed_rows = len(delete_ids)
        phases["shadow_db_dedup"] = {
            "before": total_before,
            "removed": removed_rows,
            "after": total_before - removed_rows,
        }
        total_cleaned += removed_rows
    except Exception:
        phases["shadow_db_dedup"] = {"before": 0, "removed": 0, "after": 0, "error": True}

    # ── Phase 3: session_episodes_gc — 清理已注入的旧 episodes ──
    # OS 类比：release_task() → exit_files() — 关闭进程打开的文件描述符
    # 兼容两种 schema：旧版用 injected+updated_at，新版用 injected_count+ended_at
    try:
        tbl = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='session_episodes'"
        ).fetchone()
        removed_episodes = 0
        if tbl:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=episodes_max_age_hours)).isoformat()
            # 检测 schema：查看有哪些列
            cols = {r[1] for r in conn.execute("PRAGMA table_info(session_episodes)").fetchall()}
            if "injected_count" in cols and "ended_at" in cols:
                # 新 schema：injected_count > 0 表示已注入
                cur = conn.execute(
                    "DELETE FROM session_episodes WHERE injected_count > 0 AND ended_at < ?",
                    [cutoff]
                )
            elif "injected" in cols and "updated_at" in cols:
                # 旧 schema
                cur = conn.execute(
                    "DELETE FROM session_episodes WHERE injected = 1 AND updated_at < ?",
                    [cutoff]
                )
            else:
                cur = None
            if cur is not None:
                removed_episodes = cur.rowcount
                conn.commit()
        phases["session_episodes_gc"] = {"removed": removed_episodes}
        total_cleaned += removed_episodes
    except Exception:
        phases["session_episodes_gc"] = {"removed": 0, "error": True}

    # ── Phase 4: checkpoint_gc — 清理超龄/已消费的 checkpoints ──
    # OS 类比：release_task() → exit_mm() — 释放进程的内存映射
    try:
        tbl = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='checkpoints'"
        ).fetchone()
        removed_checkpoints = 0
        if tbl:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=checkpoint_max_age_hours)).isoformat()
            cur = conn.execute(
                "DELETE FROM checkpoints WHERE consumed = 1 AND created_at < ?",
                [cutoff]
            )
            removed_checkpoints = cur.rowcount
            conn.commit()
        phases["checkpoint_gc"] = {"removed": removed_checkpoints}
        total_cleaned += removed_checkpoints
    except Exception:
        phases["checkpoint_gc"] = {"removed": 0, "error": True}

    duration_ms = round((_time.time() - t0) * 1000, 2)
    return {
        "total_cleaned": total_cleaned,
        "phases": phases,
        "duration_ms": duration_ms,
    }


# ── iter551: initcall_debug — Boot Subsystem Latency Instrumentation ──────────
# OS 类比：Linux initcall_debug (Arjan van de Ven, 2008, kernel 2.6.24)
#   内核启动时每个 __initcall 函数打印执行时间：
#     "initcall xyz_init+0x0/0x20 returned 0 after 4523 usecs"
#   配合 systemd-analyze blame / bootchart 定位最慢启动模块。
#   没有 initcall_debug → 启动变慢只能猜，无法数据驱动优化。
#
# Memory-OS 问题：
#   loader.py SessionStart 运行 25+ 子系统（watchdog, autotune, perf_counters,
#   damon, shrink_dcache, oom_reaper, overcommit_kill, free_pages_ok, kfree_rcu,
#   put_page, numa_balancing, mincore, ksm_scan, fstrim, logrotate, vacuum,
#   release_task...），但只有最终汇总 dmesg 行，没有 per-subsystem 延迟分解。
#   deferred_initcall (iter535) 是粗粒度全有/全无，不知道具体该跳过谁。
#
# 实现：
#   1. _InitcallTimer context manager — 零侵入计时，记录每个子系统 elapsed_ms
#   2. initcall_debug() — 分析 timings，输出 Top-N 最慢 + total + deferred 节省
#   3. loader.py 集成：wrap 每个子系统调用，SessionStart 末尾写 dmesg

# ── iter552: timer_slack — Idle Subsystem Frequency Reduction ──────────
# OS 类比：Linux timer_slack_ns (Arjan van de Ven, 2008, kernel 2.6.28)
#   为非精确定时器添加 slack，内核将相近 timer 合并到同一 wakeup 点（batch），
#   减少不必要的 CPU 唤醒。Android timer_slack_ms 在 PowerManager 中进一步放大
#   休眠态 slack。核心：如果定时回调"大多数时候 nothing to do"，增大 slack 降频。

_TIMER_SLACK_FILE = MEMORY_OS_DIR / "timer_slack_state.json"

# 关键子系统标记为 CLOCK_REALTIME — 不可降频，每次 session 必须执行
_CLOCK_REALTIME_SUBSYSTEMS = frozenset({
    "watchdog", "autotune", "initcall_debug", "mglru_aging",
    "page_idle",  # bitmap 标记必须每次执行保证追踪连续性
    "gc_traces", "rmap_sweep", "vma_merge",  # 引用完整性
})


def timer_slack_load() -> dict:
    """
    加载 timer_slack 状态文件。
    格式: {subsystem_name: {"idle_streak": N, "skip_sessions": N}, ...}
    """
    try:
        if _TIMER_SLACK_FILE.exists():
            data = json.loads(_TIMER_SLACK_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def timer_slack_should_skip(state: dict, subsystem: str) -> bool:
    """
    判断子系统是否应被跳过（处于 slack 休眠期）。

    Returns True 表示跳过，False 表示执行。
    CLOCK_REALTIME 子系统永远返回 False。
    """
    if subsystem in _CLOCK_REALTIME_SUBSYSTEMS:
        return False
    entry = state.get(subsystem)
    if not entry or not isinstance(entry, dict):
        return False
    return entry.get("skip_sessions", 0) > 0


def timer_slack_report(state: dict, subsystem: str, did_work: bool) -> dict:
    """
    汇报子系统执行结果，更新 slack 状态。

    did_work=True  → reset idle_streak=0, skip_sessions=0
    did_work=False → idle_streak++, 超过阈值时设置 skip_sessions

    Returns: 更新后的完整 state dict
    """
    from config import get as _cfg
    slack_threshold = int(_cfg("timer_slack.idle_threshold"))
    max_skip = int(_cfg("timer_slack.max_skip_sessions"))

    if subsystem in _CLOCK_REALTIME_SUBSYSTEMS:
        # CLOCK_REALTIME 不参与 slack 调度
        return state

    entry = state.get(subsystem, {"idle_streak": 0, "skip_sessions": 0})
    if not isinstance(entry, dict):
        entry = {"idle_streak": 0, "skip_sessions": 0}

    if did_work:
        entry["idle_streak"] = 0
        entry["skip_sessions"] = 0
    else:
        entry["idle_streak"] = entry.get("idle_streak", 0) + 1
        if entry["idle_streak"] >= slack_threshold:
            # 指数退避但有上限：skip = min(idle_streak - threshold + 1, max_skip)
            entry["skip_sessions"] = min(
                entry["idle_streak"] - slack_threshold + 1, max_skip
            )

    state[subsystem] = entry
    return state


def timer_slack_tick(state: dict) -> dict:
    """
    每个 session 开始时调用：所有被跳过的子系统 skip_sessions -= 1。
    skip_sessions 到 0 时下次将执行。

    Returns: tick 后的 state dict
    """
    for sub, entry in state.items():
        if isinstance(entry, dict) and entry.get("skip_sessions", 0) > 0:
            entry["skip_sessions"] -= 1
    return state


def timer_slack_save(state: dict) -> None:
    """持久化 timer_slack 状态到磁盘。"""
    try:
        _TIMER_SLACK_FILE.write_text(json.dumps(state, ensure_ascii=False))
    except Exception:
        pass


def timer_slack_stats(state: dict) -> dict:
    """返回 timer_slack 统计摘要。"""
    total = len(state)
    skipping = sum(1 for e in state.values()
                   if isinstance(e, dict) and e.get("skip_sessions", 0) > 0)
    idle = sum(1 for e in state.values()
               if isinstance(e, dict) and e.get("idle_streak", 0) >= 3)
    return {"total_tracked": total, "currently_skipping": skipping, "idle_subsystems": idle}


class _InitcallTimer:
    """
    轻量级 SessionStart 子系统计时收集器。

    用法（在 loader.py 中）：
        timer = _InitcallTimer()
        with timer.probe("watchdog"):
            watchdog_check(conn)
        with timer.probe("autotune"):
            autotune(conn, project)
        ...
        result = initcall_debug(timer.timings)
    """
    __slots__ = ("timings",)

    def __init__(self):
        self.timings: list = []  # [(name, elapsed_ms, ok)]

    class _Probe:
        __slots__ = ("_timer", "_name", "_t0")

        def __init__(self, timer: "_InitcallTimer", name: str):
            self._timer = timer
            self._name = name
            self._t0 = 0.0

        def __enter__(self):
            self._t0 = _time.time()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed_ms = (_time.time() - self._t0) * 1000
            ok = exc_type is None
            self._timer.timings.append((self._name, round(elapsed_ms, 2), ok))
            return True  # suppress exceptions — 每个子系统独立 fault isolation

    def probe(self, name: str) -> "_Probe":
        return self._Probe(self, name)


def initcall_debug(timings: list, top_n: int = 5) -> dict:
    """
    iter551: initcall_debug — 分析 SessionStart per-subsystem timing 数据。

    OS 类比：
      Linux initcall_debug (Arjan van de Ven, 2008, kernel 2.6.24)
      内核启动参数 initcall_debug 为每个 __initcall 函数打印执行耗时：
        "initcall xyz_init+0x0/0x20 returned 0 after 4523 usecs"
      systemd-analyze blame 做同样的事——按耗时降序列出所有 systemd unit。
      这是 Linux 启动优化的基础工具：先 measure，再 optimize。

    Memory-OS 等价：
      loader.py SessionStart 运行 25+ 子系统，但只有汇总行：
        "session_start latest=Y working_set=1 ctx_len=313 watchdog=HEALTHY
         damon=H2/W4/C0/D0 shrink_slab=2recl/2free ..."
      没有 per-subsystem 延迟 → 无法定位瓶颈 → 无法数据驱动优化。
      deferred_initcall (iter535) 是粗粒度 all-or-nothing，
      而 initcall_debug 提供细粒度 per-subsystem 数据，
      支持 selective defer（只跳过慢且无效的子系统）。

    参数：
      timings — [(name, elapsed_ms, ok)] 由 _InitcallTimer 收集
      top_n — 输出 Top-N 最慢子系统（默认 5）

    返回 dict：
      total_ms — 所有子系统总耗时
      subsystem_count — 子系统总数
      top_slow — Top-N 最慢 [{name, ms, ok}]
      failed — 失败的子系统列表 [{name, ms}]
      blame_line — 格式化的 blame 行（类似 systemd-analyze blame 输出）
      below_1ms — 耗时 < 1ms 的子系统数（候选 defer 对象）
    """
    if not timings:
        return {
            "total_ms": 0,
            "subsystem_count": 0,
            "top_slow": [],
            "failed": [],
            "blame_line": "",
            "below_1ms": 0,
        }

    total_ms = sum(t[1] for t in timings)
    subsystem_count = len(timings)

    # 按耗时降序排序
    sorted_timings = sorted(timings, key=lambda t: t[1], reverse=True)

    top_slow = [
        {"name": name, "ms": ms, "ok": ok}
        for name, ms, ok in sorted_timings[:top_n]
    ]

    failed = [
        {"name": name, "ms": ms}
        for name, ms, ok in timings if not ok
    ]

    below_1ms = sum(1 for _, ms, _ in timings if ms < 1.0)

    # blame_line: 类似 systemd-analyze blame 的紧凑格式
    # "352ms total (25 subsystems) top: watchdog=89ms damon=45ms autotune=38ms ..."
    blame_parts = [f"{t['name']}={t['ms']:.0f}ms" for t in top_slow if t["ms"] >= 1.0]
    blame_line = (
        f"{total_ms:.0f}ms total ({subsystem_count} subsystems) "
        f"top: {' '.join(blame_parts)}"
    )
    if failed:
        blame_line += f" FAILED: {','.join(f['name'] for f in failed)}"

    return {
        "total_ms": round(total_ms, 2),
        "subsystem_count": subsystem_count,
        "top_slow": top_slow,
        "failed": failed,
        "blame_line": blame_line,
        "below_1ms": below_1ms,
    }


# ── iter553: sched_deadline — Per-Subsystem Runtime Budget Enforcement ────────
# OS 类比：Linux SCHED_DEADLINE (Luca Abeni & Juri Lelli, 2014, kernel 3.14, sched/deadline.c)
#
# 每个 SCHED_DEADLINE 任务声明 (runtime, deadline, period) 三元组：
#   - runtime: 每个 period 内允许消耗的 CPU 时间上限
#   - 超出 runtime → dl_throttled=1，任务从 runqueue 中移除直到下个 period
#   - 与 CFS nice 值不同：nice 是相对权重（soft），deadline 是硬预算（hard enforcement）
#
# Memory-OS 等价：
#   initcall_debug(iter551) 只测量不执行（类似 perf stat）
#   timer_slack(iter552) 只跳过空转子系统（idle_streak >= threshold）
#   sched_deadline 补充第三维度：跳过超预算子系统（runtime EMA > budget）
#
#   问题：sleep_consolidation 占 39%（27ms/69ms），但 timer_slack 不管它
#   （因为它 did_work=True）。sched_deadline 说："你做了工作，但太慢了，
#   throttle 你 N 个 session，让总 boot time 回到合理范围。"
#
# 与 timer_slack 的关系（互补）：
#   timer_slack:     idle (did_work=False) for N sessions → skip
#   sched_deadline:  slow (EMA > budget_ms) → throttle for N sessions
#   两者独立判断，任一触发则跳过。

_SCHED_DEADLINE_FILE = MEMORY_OS_DIR / "sched_deadline_state.json"

# 关键子系统永不被 deadline throttle（等同 CLOCK_REALTIME）
_DEADLINE_EXEMPT_SUBSYSTEMS = frozenset({
    "watchdog", "autotune", "initcall_debug",
    "mglru_aging", "gc_traces", "rmap_sweep", "vma_merge",
})


def sched_deadline_load() -> dict:
    """
    加载 sched_deadline 持久化状态。

    格式: {subsystem_name: {
        "ema_ms": float,       # 运行时 EMA (指数移动平均)
        "throttle_sessions": int,  # 剩余 throttle 轮数
        "samples": int,        # 样本数（用于 EMA 启动阶段）
    }, ...}
    """
    try:
        if _SCHED_DEADLINE_FILE.exists():
            data = json.loads(_SCHED_DEADLINE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def sched_deadline_save(state: dict) -> None:
    """持久化 sched_deadline 状态到磁盘。"""
    try:
        _SCHED_DEADLINE_FILE.write_text(json.dumps(state, ensure_ascii=False))
    except Exception:
        pass


def sched_deadline_update(state: dict, name: str, elapsed_ms: float) -> dict:
    """
    记录子系统本次执行耗时，更新 EMA。

    EMA 公式 (α=0.3): ema = α × current + (1-α) × prev_ema
    α=0.3 意味着最近一次占 30% 权重，历史占 70%——
    既不被单次 spike 误导，又能在 3-4 个 session 内收敛到新均值。

    首次记录直接用当前值作为 EMA（冷启动无历史）。

    超过 budget_ms 时设置 throttle_sessions。
    """
    from config import get as _cfg

    if name in _DEADLINE_EXEMPT_SUBSYSTEMS:
        return state

    budget_ms = float(_cfg("sched_deadline.budget_ms"))
    throttle_n = int(_cfg("sched_deadline.throttle_sessions"))
    alpha = 0.3  # EMA smoothing factor

    entry = state.get(name, {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0})
    if not isinstance(entry, dict):
        entry = {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0}

    samples = entry.get("samples", 0)
    prev_ema = entry.get("ema_ms", 0.0)

    # 首次样本直接赋值；后续按 EMA 平滑
    if samples == 0:
        new_ema = elapsed_ms
    else:
        new_ema = alpha * elapsed_ms + (1 - alpha) * prev_ema

    entry["ema_ms"] = round(new_ema, 2)
    entry["samples"] = samples + 1

    # 判断是否超预算：需要至少 3 个样本（避免冷启动误判）
    if entry["samples"] >= 3 and new_ema > budget_ms:
        entry["throttle_sessions"] = throttle_n
    elif new_ema <= budget_ms:
        # EMA 回到预算内 → 解除 throttle
        entry["throttle_sessions"] = 0

    state[name] = entry
    return state


def sched_deadline_should_throttle(state: dict, name: str) -> bool:
    """
    判断子系统是否被 deadline throttle。

    Returns True 表示应跳过（超预算被节流），False 表示正常执行。
    豁免子系统永远返回 False。
    """
    if name in _DEADLINE_EXEMPT_SUBSYSTEMS:
        return False
    entry = state.get(name)
    if not entry or not isinstance(entry, dict):
        return False
    return entry.get("throttle_sessions", 0) > 0


def sched_deadline_tick(state: dict) -> dict:
    """
    每个 session 开始时调用：所有被 throttle 的子系统 throttle_sessions -= 1。
    throttle_sessions 到 0 时下次将执行（自动恢复）。
    """
    for sub, entry in state.items():
        if isinstance(entry, dict) and entry.get("throttle_sessions", 0) > 0:
            entry["throttle_sessions"] -= 1
    return state


def sched_deadline_stats(state: dict) -> dict:
    """返回 sched_deadline 统计摘要。"""
    total = len(state)
    throttled = sum(1 for e in state.values()
                    if isinstance(e, dict) and e.get("throttle_sessions", 0) > 0)
    over_budget = 0
    try:
        from config import get as _cfg
        budget_ms = float(_cfg("sched_deadline.budget_ms"))
        over_budget = sum(1 for e in state.values()
                         if isinstance(e, dict) and e.get("ema_ms", 0) > budget_ms)
    except Exception:
        pass
    return {
        "total_tracked": total,
        "currently_throttled": throttled,
        "over_budget": over_budget,
    }


# ── iter554: cgroup_budget — Subsystem Group Budget Enforcement ────────────────
# OS 类比：Linux cgroup v2 memory.max (Tejun Heo, 2015, kernel 4.5, kernel/cgroup/)
#
# Linux cgroup 演化:
#   进程级调度（nice/SCHED_DEADLINE）→ 分组级资源控制（cgroup v1/v2）
#   per-task 预算不足以控制"群体效应"：单个子系统 15ms 不超标，
#   但 reclaim 组 9 个子系统 × 15ms = 135ms，远超合理 boot time。
#   cgroup v2 memory.max 对组施加 hard ceiling：组内进程合计不能超过上限。
#
# Memory-OS 等价：
#   sched_deadline(iter553) = per-subsystem 预算（单任务超 20ms → throttle）
#   cgroup_budget(iter554) = per-group 预算（组合计超 group_budget → 组内后续跳过）
#
#   问题：reclaim 组 9 个子系统，每个 10-18ms 不触发 sched_deadline(20ms)，
#   但合计 90-162ms 让 boot 变慢。cgroup_budget 在组级别 enforce 上限。
#
# 与 sched_deadline 的关系（互补）：
#   sched_deadline:  per-task hard budget（单个超标 → throttle 个体）
#   cgroup_budget:   per-group hard budget（组合计超标 → throttle 整组剩余）

_CGROUP_BUDGET_FILE = Path(os.environ.get(
    "MEMORY_OS_DIR", str(Path.home() / ".claude" / "memory-os")
)) / "cgroup_budget_state.json"

# 子系统分组定义（按功能域）
# exempt 子系统（CLOCK_REALTIME / DEADLINE_EXEMPT）不属于任何 cgroup
CGROUP_GROUPS = {
    "reclaim": [
        "shrink_dcache", "oom_reaper", "overcommit_kill", "free_pages_ok",
        "kfree_rcu", "put_page", "munlock_idle", "oom_reaper_onfault", "shrink_slab",
    ],
    "gc": [
        "gc_namespace", "gc_swap",
        "trim_shadow", "fstrim", "logrotate", "vacuum", "release_task",
    ],
    "rebalance": [
        "numa_balancing", "mincore", "ksm_scan", "vmstat_scan",
        "cpuset_quarantine", "madv_free",
    ],
    "audit": [
        "damon_scan", "mem_scrub", "perf_counters", "migrate_pages",
    ],
}

# 反向索引：subsystem → group
_SUBSYSTEM_TO_GROUP = {}
for _grp, _members in CGROUP_GROUPS.items():
    for _m in _members:
        _SUBSYSTEM_TO_GROUP[_m] = _grp


def cgroup_budget_load() -> dict:
    """
    加载 cgroup_budget 持久化状态。

    格式: {group_name: {
        "ema_ms": float,           # 组合计 EMA (指数移动平均)
        "throttle_sessions": int,  # 剩余组 throttle 轮数
        "samples": int,            # 样本数
        "consumed_ms": float,      # 当前 session 已消耗（运行时累计）
    }, ...}
    """
    try:
        if _CGROUP_BUDGET_FILE.exists():
            data = json.loads(_CGROUP_BUDGET_FILE.read_text())
            if isinstance(data, dict):
                # 清除运行时字段（每 session 重新累计）
                for grp in data.values():
                    if isinstance(grp, dict):
                        grp["consumed_ms"] = 0.0
                return data
    except Exception:
        pass
    return {}


def cgroup_budget_save(state: dict) -> None:
    """持久化 cgroup_budget 状态到磁盘。"""
    try:
        # 保存前清除运行时字段
        save_state = {}
        for grp, entry in state.items():
            if isinstance(entry, dict):
                save_state[grp] = {
                    "ema_ms": entry.get("ema_ms", 0.0),
                    "throttle_sessions": entry.get("throttle_sessions", 0),
                    "samples": entry.get("samples", 0),
                }
        _CGROUP_BUDGET_FILE.write_text(json.dumps(save_state, ensure_ascii=False))
    except Exception:
        pass


def cgroup_budget_should_throttle(state: dict, subsystem: str) -> bool:
    """
    判断子系统所在 cgroup 是否被 throttle。

    两个触发条件（任一为 True → 跳过）：
      1. 组级 EMA 历史超标（throttle_sessions > 0）— 上 session 组合计超标
      2. 当前 session 组内已消耗超出 budget — 实时预算耗尽

    不属于任何 cgroup 的子系统永远返回 False。
    CLOCK_REALTIME 子系统（引用完整性保证）永远返回 False。
    """
    # CLOCK_REALTIME 子系统强制执行，不受 cgroup 控制
    if subsystem in _CLOCK_REALTIME_SUBSYSTEMS:
        return False
    group = _SUBSYSTEM_TO_GROUP.get(subsystem)
    if not group:
        return False

    entry = state.get(group)
    if not entry or not isinstance(entry, dict):
        return False

    # 条件 1：历史超标 throttle
    if entry.get("throttle_sessions", 0) > 0:
        return True

    # 条件 2：当前 session 实时预算耗尽
    try:
        from config import get as _cfg
        budget_ms = float(_cfg("cgroup_budget.group_budget_ms"))
        consumed = entry.get("consumed_ms", 0.0)
        if consumed >= budget_ms:
            return True
    except Exception:
        pass

    return False


def cgroup_budget_consume(state: dict, subsystem: str, elapsed_ms: float) -> dict:
    """
    记录子系统执行消耗，累加到所在 cgroup 的当前 session 已消耗量。

    每个子系统执行完后调用，用于实时预算检查。
    """
    group = _SUBSYSTEM_TO_GROUP.get(subsystem)
    if not group:
        return state

    if group not in state:
        state[group] = {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0, "consumed_ms": 0.0}

    entry = state[group]
    if not isinstance(entry, dict):
        state[group] = {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0, "consumed_ms": 0.0}
        entry = state[group]

    entry["consumed_ms"] = entry.get("consumed_ms", 0.0) + elapsed_ms
    return state


def cgroup_budget_settle(state: dict, group_totals: dict) -> dict:
    """
    Session 结束时，用 initcall_debug 的 per-group 合计数据更新 EMA。

    参数：
      group_totals — {group_name: total_ms} 本 session 各组实际耗时合计

    EMA 公式 (α=0.3): ema = α × current + (1-α) × prev_ema
    组 EMA 超过 group_budget_ms → 设置 throttle_sessions

    注意：throttle_sessions 对整组生效——下个 session 组内所有子系统跳过。
    """
    try:
        from config import get as _cfg
        budget_ms = float(_cfg("cgroup_budget.group_budget_ms"))
        throttle_n = int(_cfg("cgroup_budget.throttle_sessions"))
    except Exception:
        budget_ms = 60.0
        throttle_n = 2

    alpha = 0.3

    for group, total_ms in group_totals.items():
        if group not in state:
            state[group] = {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0, "consumed_ms": 0.0}

        entry = state[group]
        if not isinstance(entry, dict):
            state[group] = {"ema_ms": 0.0, "throttle_sessions": 0, "samples": 0, "consumed_ms": 0.0}
            entry = state[group]

        samples = entry.get("samples", 0)
        prev_ema = entry.get("ema_ms", 0.0)

        if samples == 0:
            new_ema = total_ms
        else:
            new_ema = alpha * total_ms + (1 - alpha) * prev_ema

        entry["ema_ms"] = round(new_ema, 2)
        entry["samples"] = samples + 1

        # 超预算判定：至少 2 个样本（组级冷启动容忍度比个体低）
        if entry["samples"] >= 2 and new_ema > budget_ms:
            entry["throttle_sessions"] = throttle_n
        elif new_ema <= budget_ms:
            entry["throttle_sessions"] = 0

    return state


def cgroup_budget_tick(state: dict) -> dict:
    """
    每个 session 开始时调用：所有被 throttle 的 group throttle_sessions -= 1。
    """
    for group, entry in state.items():
        if isinstance(entry, dict) and entry.get("throttle_sessions", 0) > 0:
            entry["throttle_sessions"] -= 1
    return state


def cgroup_budget_stats(state: dict) -> dict:
    """返回 cgroup_budget 统计摘要。"""
    total_groups = len(CGROUP_GROUPS)
    throttled_groups = 0
    over_budget_groups = 0
    group_details = {}

    try:
        from config import get as _cfg
        budget_ms = float(_cfg("cgroup_budget.group_budget_ms"))
    except Exception:
        budget_ms = 60.0

    for group in CGROUP_GROUPS:
        entry = state.get(group, {})
        if isinstance(entry, dict):
            ema = entry.get("ema_ms", 0.0)
            throttled = entry.get("throttle_sessions", 0) > 0
            over = ema > budget_ms
            if throttled:
                throttled_groups += 1
            if over:
                over_budget_groups += 1
            group_details[group] = {
                "ema_ms": ema,
                "throttled": throttled,
                "over_budget": over,
                "members": len(CGROUP_GROUPS[group]),
            }

    return {
        "total_groups": total_groups,
        "throttled_groups": throttled_groups,
        "over_budget_groups": over_budget_groups,
        "budget_ms": budget_ms,
        "groups": group_details,
    }


# ── iter555: schedstat — Unified Scheduler Statistics Accumulator ────────────
# OS 类比：Linux SCHEDSTAT (Mike Galbraith, 2004, kernel 2.6.7, kernel/sched/stats.c)
#   /proc/schedstat 暴露 per-CPU 调度统计：total runtime, wait time, timeslices。
#   /proc/PID/schedstat 暴露 per-task 级别统计。
#   管理员通过这些累积计数器识别调度病理（饥饿、过度抢占），
#   无需打开 ftrace 全量追踪（开销 <1%）。
#
# 根因：timer_slack(iter552) / sched_deadline(iter553) / cgroup_budget(iter554)
#   各自在独立 JSON 文件中维护状态，但都是「当前快照」——
#   不保留跨 session 的累积历史。无法回答：
#     - 某子系统历史上被跳过了多少次？主要原因是什么？
#     - sched_deadline 的 throttle 是否有效（throttle 后 boot time 下降）？
#     - boot time 跨 session 的趋势是上升还是下降？
#     - 哪些子系统是"空转大户"（idle 率 > 80%）？
#
# 实现：
#   schedstat_state.json 持久化累积统计，per-subsystem 记录：
#     - exec_count: 总执行次数
#     - skip_idle: timer_slack 空转跳过次数
#     - skip_throttle: sched_deadline 超预算节流次数
#     - skip_group_throttle: cgroup_budget 分组预算节流次数
#     - total_runtime_ms: 累积运行时间
#     - did_work_count: 实际做了工作的次数（非空转执行）
#   全局记录：
#     - session_count: 总 session 数
#     - boot_times_ms: 最近 N 个 session 的 boot time（环形缓冲区）

_SCHEDSTAT_FILE = os.path.join(MEMORY_OS_DIR, "schedstat_state.json")


def schedstat_load() -> dict:
    """加载 schedstat 累积统计状态。"""
    try:
        with open(_SCHEDSTAT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {"subsystems": {}, "session_count": 0, "boot_times_ms": []}


def schedstat_save(state: dict) -> None:
    """持久化 schedstat 状态。"""
    try:
        os.makedirs(os.path.dirname(_SCHEDSTAT_FILE), exist_ok=True)
        with open(_SCHEDSTAT_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    except OSError:
        pass


def schedstat_record_skip(state: dict, subsystem: str, reason: str) -> dict:
    """
    记录子系统被跳过。

    reason: "idle" (timer_slack), "throttle" (sched_deadline),
            "group_throttle" (cgroup_budget)
    """
    subs = state.setdefault("subsystems", {})
    entry = subs.setdefault(subsystem, _schedstat_empty_entry())
    if not isinstance(entry, dict):
        entry = _schedstat_empty_entry()
        subs[subsystem] = entry

    key = f"skip_{reason}"
    if key in entry:
        entry[key] = entry.get(key, 0) + 1
    # 不论原因，总跳过计数 +1 方便计算 skip_rate
    entry["skip_total"] = entry.get("skip_total", 0) + 1
    return state


def schedstat_record_exec(state: dict, subsystem: str,
                          elapsed_ms: float, did_work: bool) -> dict:
    """
    记录子系统执行结果。

    elapsed_ms: 本次执行耗时
    did_work: 是否实际做了工作（True=有效执行，False=空转执行）
    """
    subs = state.setdefault("subsystems", {})
    entry = subs.setdefault(subsystem, _schedstat_empty_entry())
    if not isinstance(entry, dict):
        entry = _schedstat_empty_entry()
        subs[subsystem] = entry

    entry["exec_count"] = entry.get("exec_count", 0) + 1
    entry["total_runtime_ms"] = round(entry.get("total_runtime_ms", 0.0) + elapsed_ms, 2)
    if did_work:
        entry["did_work_count"] = entry.get("did_work_count", 0) + 1
    return state


def schedstat_record_session(state: dict, boot_time_ms: float,
                             max_history: int = 0) -> dict:
    """
    记录一次 session boot 完成。

    boot_time_ms: 本次 SessionStart 总耗时
    max_history: boot_times_ms 环形缓冲区大小（0=从 config 读取）
    """
    if max_history <= 0:
        try:
            from config import get as _cfg
            max_history = int(_cfg("schedstat.max_history_sessions"))
        except Exception:
            max_history = 20

    state["session_count"] = state.get("session_count", 0) + 1

    boot_times = state.get("boot_times_ms", [])
    if not isinstance(boot_times, list):
        boot_times = []
    boot_times.append(round(boot_time_ms, 2))
    # 环形缓冲区：只保留最近 max_history 条
    if len(boot_times) > max_history:
        boot_times = boot_times[-max_history:]
    state["boot_times_ms"] = boot_times
    return state


def schedstat_report(state: dict) -> dict:
    """
    生成 schedstat 统计报告。

    返回 dict：
      session_count — 总 session 数
      boot_time_avg_ms — 平均 boot time
      boot_time_trend — "improving" / "stable" / "degrading"（比较前半 vs 后半均值）
      subsystem_count — 被追踪的子系统数
      top_idle — skip_rate 最高的 N 个子系统（空转大户）
      top_slow — avg_runtime 最高的 N 个子系统
      skip_breakdown — {idle: N, throttle: N, group_throttle: N} 全局跳过原因分布
      effective_work_rate — 全局有效工作率 = did_work_count / exec_count
    """
    subs = state.get("subsystems", {})
    boot_times = state.get("boot_times_ms", [])
    session_count = state.get("session_count", 0)

    # Boot time 统计
    boot_avg = round(sum(boot_times) / len(boot_times), 2) if boot_times else 0.0
    boot_trend = "stable"
    if len(boot_times) >= 4:
        mid = len(boot_times) // 2
        first_half = sum(boot_times[:mid]) / mid
        second_half = sum(boot_times[mid:]) / (len(boot_times) - mid)
        # 后半比前半低 10%+ → improving；高 10%+ → degrading
        if first_half > 0:
            change_pct = (second_half - first_half) / first_half
            if change_pct < -0.10:
                boot_trend = "improving"
            elif change_pct > 0.10:
                boot_trend = "degrading"

    # 全局跳过原因分布
    skip_breakdown = {"idle": 0, "throttle": 0, "group_throttle": 0}
    total_exec = 0
    total_did_work = 0
    sub_stats = []

    for name, entry in subs.items():
        if not isinstance(entry, dict):
            continue
        exec_count = entry.get("exec_count", 0)
        skip_total = entry.get("skip_total", 0)
        did_work = entry.get("did_work_count", 0)
        total_ms = entry.get("total_runtime_ms", 0.0)
        attempts = exec_count + skip_total

        skip_breakdown["idle"] += entry.get("skip_idle", 0)
        skip_breakdown["throttle"] += entry.get("skip_throttle", 0)
        skip_breakdown["group_throttle"] += entry.get("skip_group_throttle", 0)
        total_exec += exec_count
        total_did_work += did_work

        skip_rate = round(skip_total / attempts, 3) if attempts > 0 else 0.0
        avg_ms = round(total_ms / exec_count, 2) if exec_count > 0 else 0.0
        work_rate = round(did_work / exec_count, 3) if exec_count > 0 else 0.0

        sub_stats.append({
            "name": name,
            "exec_count": exec_count,
            "skip_total": skip_total,
            "skip_rate": skip_rate,
            "avg_runtime_ms": avg_ms,
            "work_rate": work_rate,
        })

    # Top idle（skip_rate 最高，至少有 2 次 attempt）
    eligible = [s for s in sub_stats if s["exec_count"] + s["skip_total"] >= 2]
    top_idle = sorted(eligible, key=lambda x: x["skip_rate"], reverse=True)[:5]
    top_slow = sorted(eligible, key=lambda x: x["avg_runtime_ms"], reverse=True)[:5]

    effective_work_rate = round(total_did_work / total_exec, 3) if total_exec > 0 else 0.0

    return {
        "session_count": session_count,
        "boot_time_avg_ms": boot_avg,
        "boot_time_trend": boot_trend,
        "subsystem_count": len(subs),
        "top_idle": top_idle,
        "top_slow": top_slow,
        "skip_breakdown": skip_breakdown,
        "effective_work_rate": effective_work_rate,
    }


def schedstat_blame(state: dict) -> str:
    """
    生成一行 blame 摘要（类似 initcall_debug blame_line），
    适合写入 dmesg。

    格式：sessions=N avg_boot=Xms trend=Y work_rate=Z% top_idle: a(80%) b(60%)
    """
    report = schedstat_report(state)
    parts = [
        f"sessions={report['session_count']}",
        f"avg_boot={report['boot_time_avg_ms']}ms",
        f"trend={report['boot_time_trend']}",
        f"work_rate={report['effective_work_rate'] * 100:.0f}%",
    ]

    # top idle 子系统
    idle_parts = []
    for s in report["top_idle"][:3]:
        if s["skip_rate"] > 0:
            idle_parts.append(f"{s['name']}({s['skip_rate'] * 100:.0f}%)")
    if idle_parts:
        parts.append("top_idle: " + " ".join(idle_parts))

    # skip breakdown
    sb = report["skip_breakdown"]
    total_skips = sb["idle"] + sb["throttle"] + sb["group_throttle"]
    if total_skips > 0:
        parts.append(f"skips: idle={sb['idle']} throttle={sb['throttle']} group={sb['group_throttle']}")

    return " ".join(parts)


def _schedstat_empty_entry() -> dict:
    """返回新子系统的初始 schedstat 条目。"""
    return {
        "exec_count": 0,
        "skip_total": 0,
        "skip_idle": 0,
        "skip_throttle": 0,
        "skip_group_throttle": 0,
        "total_runtime_ms": 0.0,
        "did_work_count": 0,
    }


# ── iter556: sched_autogroup — Adaptive Scheduler Parameter Tuning ──
# OS 类比：Linux sched_autogroup (Mike Galbraith, 2010, kernel 2.6.38, sched/autogroup.c)
# 同一 tty session 的进程自动分组到 task_group，CFS 按 group 公平调度。
# 管理员无需手动调 nice 值，系统根据进程归属自动分配带宽。
#
# 根因：schedstat(iter555) 揭示跨 session 趋势（improving/degrading）和空转率，
# 但数据不可执行——人需手动解读并调参。timer_slack 的 idle_threshold 是硬编码 3，
# sched_deadline 的 budget_ms 是固定 20ms，cgroup_budget 的 group_budget_ms 是固定 60ms。
# 缺乏根据历史统计自动调整这些阈值的闭环控制机制。
#
# 策略：
#   1. 读取 schedstat 累积数据
#   2. 计算 per-subsystem 空转率和平均耗时
#   3. 生成调整建议：
#      - 空转率 > 80% 且连续 5+ sessions → 降低 timer_slack.idle_threshold（更快跳过）
#      - boot_time trend=degrading → 收紧 sched_deadline.budget_ms（更早节流）
#      - boot_time trend=improving + work_rate 高 → 放松 budget（给予更多空间）
#      - group 内所有子系统空转率 > 70% → 降低 cgroup_budget.group_budget_ms
#   4. 通过 config.set() 写入运行时参数

_AUTOGROUP_FILE = os.path.join(
    os.path.expanduser("~"), ".claude", "memory-os", ".sched_autogroup.json"
)


def sched_autogroup_load() -> dict:
    """加载 sched_autogroup 历史调整记录。"""
    try:
        with open(_AUTOGROUP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {
        "adjustments": [],        # 历史调整记录 [{param, old, new, reason, session_count}]
        "last_run_session": 0,    # 上次运行时的 session_count（防止频繁调整）
        "cooldown_sessions": 3,   # 两次调整之间最少间隔 session 数
    }


def sched_autogroup_save(state: dict) -> None:
    """持久化 sched_autogroup 状态。"""
    try:
        os.makedirs(os.path.dirname(_AUTOGROUP_FILE), exist_ok=True)
        with open(_AUTOGROUP_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    except OSError:
        pass


def sched_autogroup(schedstat_state: dict) -> dict:
    """
    基于 schedstat 累积数据自动调节调度参数。

    返回 dict:
      adjusted: bool — 是否做了调整
      adjustments: list[{param, old, new, reason}] — 具体调整列表
      skipped_reason: str — 如跳过，原因
    """
    from config import get as _cfg, sysctl_set as _cfg_set

    ag_state = sched_autogroup_load()
    report = schedstat_report(schedstat_state)

    result = {"adjusted": False, "adjustments": [], "skipped_reason": ""}

    # ── 冷却期检查：两次调整间隔至少 N sessions ──
    session_count = report["session_count"]
    last_run = ag_state.get("last_run_session", 0)
    cooldown = ag_state.get("cooldown_sessions", 3)
    if session_count - last_run < cooldown:
        result["skipped_reason"] = f"cooldown({session_count - last_run}/{cooldown})"
        return result

    # ── 数据充分性检查：至少 5 sessions 才有统计意义 ──
    if session_count < 5:
        result["skipped_reason"] = f"insufficient_data({session_count}<5)"
        return result

    adjustments = []

    # ── 规则 1: 高空转子系统 → 降低 timer_slack.idle_threshold ──
    # 如果 top_idle 中有 skip_rate > 0.80 的子系统超过 3 个，
    # 说明大量子系统反复空转，应更快进入跳过模式
    top_idle = report.get("top_idle", [])
    high_idle_count = sum(1 for s in top_idle if s["skip_rate"] > 0.80)
    if high_idle_count >= 3:
        current_threshold = int(_cfg("timer_slack.idle_threshold"))
        if current_threshold > 1:
            new_val = max(1, current_threshold - 1)
            _cfg_set("timer_slack.idle_threshold", new_val)
            adjustments.append({
                "param": "timer_slack.idle_threshold",
                "old": current_threshold,
                "new": new_val,
                "reason": f"high_idle_subsystems={high_idle_count}(>3@80%+)",
            })

    # ── 规则 2: boot_time degrading → 收紧 sched_deadline.budget_ms ──
    # 性能恶化时，降低单子系统预算，迫使慢子系统更早被节流
    boot_trend = report.get("boot_time_trend", "stable")
    if boot_trend == "degrading":
        current_budget = float(_cfg("sched_deadline.budget_ms"))
        # 减少 15%，但不低于 5ms
        new_budget = round(max(5.0, current_budget * 0.85), 1)
        if new_budget < current_budget:
            _cfg_set("sched_deadline.budget_ms", new_budget)
            adjustments.append({
                "param": "sched_deadline.budget_ms",
                "old": current_budget,
                "new": new_budget,
                "reason": f"boot_trend=degrading avg={report['boot_time_avg_ms']}ms",
            })

    # ── 规则 3: boot_time improving + work_rate > 60% → 放松 budget ──
    # 性能改善且有效工作率高，说明系统高效，可给予更多执行空间
    elif boot_trend == "improving" and report.get("effective_work_rate", 0) > 0.60:
        current_budget = float(_cfg("sched_deadline.budget_ms"))
        # 增加 10%，但不超过 50ms（合理上限）
        new_budget = round(min(50.0, current_budget * 1.10), 1)
        if new_budget > current_budget:
            _cfg_set("sched_deadline.budget_ms", new_budget)
            adjustments.append({
                "param": "sched_deadline.budget_ms",
                "old": current_budget,
                "new": new_budget,
                "reason": f"boot_trend=improving work_rate={report['effective_work_rate']:.0%}",
            })

    # ── 规则 4: 全局有效工作率极低 → 收紧 cgroup_budget ──
    # work_rate < 30% 说明大部分执行是无效空转，组级预算应收紧
    if report.get("effective_work_rate", 1.0) < 0.30 and session_count >= 8:
        current_group_budget = float(_cfg("cgroup_budget.group_budget_ms"))
        new_group_budget = round(max(20.0, current_group_budget * 0.85), 1)
        if new_group_budget < current_group_budget:
            _cfg_set("cgroup_budget.group_budget_ms", new_group_budget)
            adjustments.append({
                "param": "cgroup_budget.group_budget_ms",
                "old": current_group_budget,
                "new": new_group_budget,
                "reason": f"low_work_rate={report['effective_work_rate']:.0%}(<30%)",
            })

    # ── 规则 5: 全局有效工作率高 + improving → 放松 cgroup_budget ──
    elif (report.get("effective_work_rate", 0) > 0.70
          and boot_trend == "improving"
          and session_count >= 8):
        current_group_budget = float(_cfg("cgroup_budget.group_budget_ms"))
        new_group_budget = round(min(120.0, current_group_budget * 1.10), 1)
        if new_group_budget > current_group_budget:
            _cfg_set("cgroup_budget.group_budget_ms", new_group_budget)
            adjustments.append({
                "param": "cgroup_budget.group_budget_ms",
                "old": current_group_budget,
                "new": new_group_budget,
                "reason": f"high_work_rate={report['effective_work_rate']:.0%}(>70%)+improving",
            })

    if adjustments:
        result["adjusted"] = True
        result["adjustments"] = adjustments
        # 记录到 autogroup 历史
        ag_state["last_run_session"] = session_count
        for adj in adjustments:
            ag_state.setdefault("adjustments", []).append({
                **adj,
                "session_count": session_count,
            })
        # 只保留最近 20 条调整记录
        ag_state["adjustments"] = ag_state["adjustments"][-20:]
        sched_autogroup_save(ag_state)
    else:
        # 无调整也更新 last_run 避免每次都尝试
        ag_state["last_run_session"] = session_count
        sched_autogroup_save(ag_state)
        result["skipped_reason"] = "no_action_needed"

    return result


def sched_autogroup_stats(schedstat_state: dict) -> dict:
    """返回 autogroup 当前状态摘要（用于 dmesg/诊断）。"""
    ag_state = sched_autogroup_load()
    report = schedstat_report(schedstat_state)
    recent_adj = ag_state.get("adjustments", [])[-5:]
    return {
        "total_adjustments": len(ag_state.get("adjustments", [])),
        "last_run_session": ag_state.get("last_run_session", 0),
        "current_session": report["session_count"],
        "boot_trend": report.get("boot_time_trend", "stable"),
        "work_rate": report.get("effective_work_rate", 0),
        "recent_adjustments": recent_adj,
    }


# ── iter557: bdi_writeback — Boot-Time Dirty Page Writeback Audit ──────
# OS 类比：Linux bdi_writeback (Jens Axboe, 2009, kernel 2.6.32, mm/backing-dev.c)
#   per-BDI (Backing Device Info) writeback 线程替代全局 pdflush。
#   每个 backing device 独立审计和回写 dirty pages。
#   boot 时 bdi_forker_thread 扫描所有已注册 BDI，
#   为有 dirty pages 的设备创建 writeback 线程。
#
# 根因：历史 chunks（写入于 iter533/541 写保护之前）永久绕过内容质量检查。
#   7 个 <30 字符碎片 + 3 个 table-row 泄漏存活在 DB 中，
#   reclaim 子系统用 importance/access/age 但从不 re-validate 内容质量。
#   这些 "dirty pages" 永远不会被 writeback（清洗）。
#
# 解决：boot-time content re-audit — 用当前 _vfs_write_protect + 额外规则
#   扫描所有 chunks，标记/删除不符合当前质量标准的历史数据。

def bdi_writeback(conn: "sqlite3.Connection", project: "Optional[str]" = None) -> dict:
    """iter557: bdi_writeback — boot-time dirty page content audit.

    三阶段处理器：
      Phase 1 (scan): 扫描所有 chunks，应用当前写保护规则检测 dirty pages
      Phase 2 (classify): 分类 dirty pages —— fragment(直接删除) vs low_quality(降级)
      Phase 3 (writeback): 执行清洗 —— 删除碎片 + 降级低质量 + FTS5 一致性

    保护机制：
      - mlock (oom_adj <= -500) 不删除，只标记
      - task_state 类型跳过
      - 单次最多处理 max_per_scan 个
      - access_count > 0 的不删除（曾被验证有价值），只降级

    返回 dict: {triggered, scanned, dirty_found, fragments_deleted,
                low_quality_demoted, skipped_protected, duration_ms}
    """
    _t0 = _time.time()
    result = {
        "triggered": False,
        "scanned": 0,
        "dirty_found": 0,
        "fragments_deleted": 0,
        "low_quality_demoted": 0,
        "skipped_protected": 0,
        "duration_ms": 0.0,
    }

    try:
        from config import get as _cfg
        enabled = _cfg("bdi_writeback.enabled")
        max_per_scan = int(_cfg("bdi_writeback.max_per_scan"))
        min_summary_len = int(_cfg("bdi_writeback.min_summary_len"))
        demote_importance = float(_cfg("bdi_writeback.demote_importance"))
        demote_oom_adj = int(_cfg("bdi_writeback.demote_oom_adj"))
    except Exception:
        enabled = True
        max_per_scan = 30
        min_summary_len = 15
        demote_importance = 0.30
        demote_oom_adj = 400

    if not enabled:
        result["duration_ms"] = (_time.time() - _t0) * 1000
        return result

    result["triggered"] = True

    # ── Phase 1: Scan — 加载所有 chunks 的 summary 进行质量审计 ──
    query = "SELECT id, summary, chunk_type, importance, access_count, oom_adj FROM memory_chunks"
    params = ()
    if project:
        query += " WHERE project IN (?, 'global')"
        params = (project,)

    try:
        rows = conn.execute(query, params).fetchall()
    except Exception:
        result["duration_ms"] = (_time.time() - _t0) * 1000
        return result

    result["scanned"] = len(rows)

    # ── Phase 2: Classify — 检测 dirty pages ──
    dirty_fragments = []   # 直接删除
    dirty_low_quality = []  # 降级
    processed = 0

    for row in rows:
        if processed >= max_per_scan:
            break
        chunk_id, summary, chunk_type, importance, access_count, oom_adj = row

        # 跳过 task_state
        if chunk_type == "task_state":
            continue

        if not summary:
            dirty_fragments.append(chunk_id)
            processed += 1
            result["dirty_found"] += 1
            continue

        s = summary.strip()

        # ── Rule 1: _vfs_write_protect 规则 re-apply ──
        is_fragment = False

        # 空/极短
        if len(s) < 8:
            is_fragment = True
        # 以截断符号开头
        elif s[0] in ('|', ')', ']', '}', '>', '+', '=', '：', '）', '】', '》',
                       ',', '，', '、', ';', '；'):
            is_fragment = True
        # markdown 表格行 (>= 2 管道符)
        elif s.count('|') >= 2:
            is_fragment = True
        # 以冒号结尾
        elif s.rstrip().endswith(':') or s.rstrip().endswith('：'):
            is_fragment = True
        # 纯数字/符号行
        elif re.match(r'^[\d\s.,:;/×\-+=%]+$', s):
            is_fragment = True

        # ── Rule 2: 额外短文本检测 ──
        if not is_fragment and len(s) < min_summary_len:
            is_fragment = True

        # ── Rule 3: markdown 标题行
        if not is_fragment and s.startswith('#'):
            is_fragment = True

        # ── Rule 4: 编号列表项碎片 (无技术锚点)
        if not is_fragment and re.match(r'^\d+\.\s', s) and len(s) < 60:
            # 有技术锚点则保留
            if not re.search(r'[.](py|js|ts|go|rs|sh|yaml|json|toml)|`[^`]+`|\d+%|\d+ms', s):
                is_fragment = True

        # ── Rule 5: 以 dash 开头的短列表项 (< 50 chars, 无技术锚点)
        if not is_fragment and s.startswith('- ') and len(s) < 50:
            if not re.search(r'[.](py|js|ts|go|rs|sh|yaml|json|toml)|`[^`]+`|\d+%|\d+ms', s):
                is_fragment = True

        if not is_fragment:
            continue

        # ── Classification ──
        processed += 1
        result["dirty_found"] += 1

        # mlock 保护：标记但不删除
        if oom_adj <= -500:
            result["skipped_protected"] += 1
            continue

        # 有访问记录：曾被验证有价值，只降级不删除
        if access_count > 0:
            dirty_low_quality.append(chunk_id)
        else:
            dirty_fragments.append(chunk_id)

    # ── Phase 3: Writeback — 执行清洗 ──

    # 3a: 删除碎片（零访问的 dirty pages）
    if dirty_fragments:
        try:
            delete_chunks(conn, dirty_fragments)
            conn.commit()
            result["fragments_deleted"] = len(dirty_fragments)
        except Exception:
            pass

    # 3b: 降级低质量（有访问的 dirty pages）
    for cid in dirty_low_quality:
        try:
            conn.execute(
                "UPDATE memory_chunks SET importance = MIN(importance, ?), oom_adj = MAX(oom_adj, ?) WHERE id = ?",
                (demote_importance, demote_oom_adj, cid),
            )
            result["low_quality_demoted"] += 1
        except Exception:
            pass

    if dirty_low_quality:
        try:
            conn.commit()
            bump_chunk_version(conn)
        except Exception:
            pass

    result["duration_ms"] = round((_time.time() - _t0) * 1000, 1)
    return result


# ── pelt_load — Per-Entity Load Tracking for Write-Time Admission（iter558）──

_PELT_FILE = os.path.join(MEMORY_OS_DIR, "pelt_state.json")

# Types exempt from PELT discount — always admitted at full importance
_PELT_EXEMPT_TYPES = frozenset({"task_state", "excluded_path"})


def pelt_load() -> dict:
    """Load PELT state from disk. Format: {project: {chunk_type: util_avg}}."""
    try:
        with open(_PELT_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def pelt_save(state: dict) -> None:
    """Save PELT state to disk."""
    try:
        with open(_PELT_FILE, "w") as f:
            json.dump(state, f, separators=(",", ":"))
    except OSError:
        pass


def pelt_update(conn: "sqlite3.Connection", project: str,
                state: dict = None) -> dict:
    """iter558: pelt_load — Per-Entity Load Tracking.

    OS 类比：Linux PELT (Per-Entity Load Tracking, Vincent Guittot, 2012,
    kernel 3.8, sched/pelt.c) — CFS 用几何级数衰减平均追踪每个 sched_entity
    的 util_avg (0-1024)。高 util 任务放大核，低 util 任务放小核。
    不是瞬时采样，而是历史加权移动平均（EMA），反映持续利用率。

    计算每个 (project, chunk_type) 的 recall utilization：
      util_avg = recalled_count / total_count_of_type (capped at 1.0)
    从 recall_traces 的 top_k_json 统计各类型被实际召回的次数，
    除以该类型在 DB 中的总数量，得到「利用率」。

    util_avg 高 → 该类型在此项目中被频繁检索（有价值）
    util_avg 低 → 该类型历史上很少被召回（写入可能是浪费）

    返回 dict: {project: {chunk_type: util_avg}, ...}
    """
    if state is None:
        state = pelt_load()

    try:
        from config import get as _cfg
        window = int(_cfg("pelt.window_traces"))
    except Exception:
        window = 50

    # ── Phase 1: 统计 recall 中各 type 被召回次数 ──
    # global 层的 chunks 在其他项目的 traces 中被召回（retriever 查询 IN (proj, 'global')），
    # 所以 global 的 util 统计需要看 ALL traces，不限 project
    try:
        if project == "global":
            traces = conn.execute(
                "SELECT top_k_json FROM recall_traces "
                "ORDER BY ROWID DESC LIMIT ?",
                (window,),
            ).fetchall()
        else:
            traces = conn.execute(
                "SELECT top_k_json FROM recall_traces WHERE project=? "
                "ORDER BY ROWID DESC LIMIT ?",
                (project, window),
            ).fetchall()
    except Exception:
        return state

    # For global project: only count recalls of chunks that actually belong to global
    # For regular projects: count all types (including global chunks recalled in their context)
    global_chunk_ids = set()
    if project == "global":
        try:
            global_chunk_ids = {r[0] for r in conn.execute(
                "SELECT id FROM memory_chunks WHERE project='global'"
            ).fetchall()}
        except Exception:
            pass

    type_recalled = Counter()
    for (tk_json,) in traces:
        try:
            for item in json.loads(tk_json):
                ct = item.get("chunk_type")
                if not ct:
                    continue
                # For global: only count if the chunk actually belongs to global
                if project == "global":
                    cid = item.get("id", "")
                    if cid not in global_chunk_ids:
                        continue
                type_recalled[ct] += 1
        except (json.JSONDecodeError, TypeError):
            continue

    # ── Phase 2: 统计 DB 中各 type 总数 ──
    try:
        if project == "global":
            rows = conn.execute(
                "SELECT chunk_type, COUNT(*) FROM memory_chunks "
                "WHERE project='global' GROUP BY chunk_type",
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT chunk_type, COUNT(*) FROM memory_chunks "
                "WHERE project IN (?, 'global') GROUP BY chunk_type",
                (project,),
            ).fetchall()
    except Exception:
        return state

    type_totals = {r[0]: r[1] for r in rows}

    # ── Phase 3: 计算 util_avg = recalled / total (capped 1.0) ──
    proj_state = state.get(project, {})
    alpha = 0.3  # EMA smoothing factor

    for chunk_type, total in type_totals.items():
        if chunk_type in _PELT_EXEMPT_TYPES or total == 0:
            continue
        raw_util = min(type_recalled.get(chunk_type, 0) / total, 1.0)
        # EMA: blend with previous value for stability
        prev = proj_state.get(chunk_type, raw_util)  # cold start = raw
        proj_state[chunk_type] = round(prev * (1 - alpha) + raw_util * alpha, 4)

    state[project] = proj_state
    return state


def pelt_discount(project: str, chunk_type: str,
                  importance: float, state: dict = None) -> float:
    """Write-time importance discount based on PELT utilization.

    如果该 (project, chunk_type) 的 util_avg < low_util_threshold：
      importance *= discount_factor
    util_avg 越低，discount 越强（线性插值）。

    exempt types (task_state, excluded_path) 不折扣。
    冷启动（无历史数据）不折扣。

    返回调整后的 importance。
    """
    if chunk_type in _PELT_EXEMPT_TYPES:
        return importance

    try:
        from config import get as _cfg
        enabled = _cfg("pelt.enabled")
        low_threshold = float(_cfg("pelt.low_util_threshold"))
        min_discount = float(_cfg("pelt.min_discount_factor"))
    except Exception:
        enabled = True
        low_threshold = 0.15
        min_discount = 0.50

    if not enabled:
        return importance

    if state is None:
        state = pelt_load()

    proj_state = state.get(project, {})
    util_avg = proj_state.get(chunk_type)

    # 冷启动（无数据）→ 不折扣
    if util_avg is None:
        return importance

    # util_avg >= threshold → 不折扣
    if util_avg >= low_threshold:
        return importance

    # 线性插值: util_avg=0 → discount=min_discount, util_avg=threshold → discount=1.0
    discount = min_discount + (1.0 - min_discount) * (util_avg / low_threshold)
    return round(importance * discount, 4)


# ── iter559: fair_clock — Cumulative Retrieval Score Importance Calibration ──
# OS 类比：Linux CFS vruntime (Ingo Molnár, 2007, kernel 2.6.23, sched/fair.c)
#   CFS 为每个 sched_entity 维护 vruntime——基于实际 CPU 时间而非静态优先级。
#   仅 nice 值高(静态)不保证获得 CPU；必须有实际 runtime 才积累 vruntime。
#   min_vruntime 作为 fairness 基线：新进程从 min_vruntime 开始，
#   而非 0（否则新进程饿死旧进程）或 max（否则新进程永远轮不到）。
#
# Memory-OS 应用：
#   write-time importance 是"nice 值"(静态声明)，cum_score 是"vruntime"(运行时累积)。
#   静态 importance 高但 cum_score=0 → 如同高 nice 进程从不运行 → importance 被高估。
#   cum_score 高但 importance 低 → 如同低 nice 进程承担大量 CPU → importance 被低估。
#   校准逻辑：
#     Demote: imp≥threshold + cum_score=0 + age>grace_days → imp *= decay
#     Promote: cum_score≥threshold + imp<target → imp = target


def fair_clock(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter559: fair_clock — 基于累积检索分数校准 importance。

    OS 类比：CFS update_min_vruntime() + update_curr() — 每个 tick 更新
    当前 sched_entity 的 vruntime，然后比较所有 entity 的 vruntime 做调度决策。

    Phase 1: 从 recall_traces.top_k_json 计算 per-chunk cum_score
    Phase 2: Demote — high importance + zero cum_score + old → decay
    Phase 3: Promote — high cum_score + low importance → boost

    与 numa_balancing 的区别：
      - numa_balancing 看 access_count（是否被注入到上下文的二值信号）
      - fair_clock 看 cum_score（检索相关性分数的连续值累积）
      - 一个 chunk 可能 access_count>0 但 cum_score 很低（候选池小时侥幸入选）
      - 一个 chunk 可能 access_count=0 但 cum_score>0（在 candidates 中多次高分
        但竞争激烈未进 top_k——vmstat dark page 会误判为无价值）

    返回:
      demoted: int — 降级数量
      promoted: int — 提升数量
      skipped_grace: int — 宽限期跳过
      skipped_protected: int — 保护跳过（mlock/pinned）
      total_scored: int — 有 cum_score 的 chunk 数
      duration_ms: float
    """
    from config import get as _cfg

    t0 = _time.time()
    result = {
        "demoted": 0,
        "promoted": 0,
        "skipped_grace": 0,
        "skipped_protected": 0,
        "total_scored": 0,
        "duration_ms": 0.0,
    }

    if not _cfg("fair_clock.enabled"):
        return result

    window = _cfg("fair_clock.window_traces")
    min_traces = _cfg("fair_clock.min_traces")
    demote_min_imp = float(_cfg("fair_clock.demote_min_importance"))
    demote_decay = float(_cfg("fair_clock.demote_decay"))
    demote_min_age_days = _cfg("fair_clock.demote_min_age_days")
    promote_min_cum = float(_cfg("fair_clock.promote_min_cum_score"))
    promote_target = float(_cfg("fair_clock.promote_target"))
    max_per_scan = _cfg("fair_clock.max_per_scan")

    # ── Phase 0: 检查 trace 数量是否充足 ──
    try:
        if project:
            trace_count = conn.execute(
                "SELECT COUNT(*) FROM recall_traces WHERE project = ?",
                (project,)
            ).fetchone()[0]
        else:
            trace_count = conn.execute(
                "SELECT COUNT(*) FROM recall_traces"
            ).fetchone()[0]
    except Exception:
        trace_count = 0

    if trace_count < min_traces:
        result["duration_ms"] = (_time.time() - t0) * 1000
        return result

    # ── Phase 1: 计算 per-chunk cum_score from top_k_json ──
    # OS 类比：update_curr() — 从调度实体的实际运行记录计算 vruntime
    cum_scores = {}  # chunk_id -> cumulative score
    try:
        if project:
            rows = conn.execute(
                "SELECT top_k_json FROM recall_traces "
                "WHERE project = ? AND top_k_json IS NOT NULL "
                "ORDER BY timestamp DESC LIMIT ?",
                (project, window)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT top_k_json FROM recall_traces "
                "WHERE top_k_json IS NOT NULL "
                "ORDER BY timestamp DESC LIMIT ?",
                (window,)
            ).fetchall()

        for (tk_json,) in rows:
            try:
                items = json.loads(tk_json)
                if isinstance(items, list):
                    for item in items:
                        cid = item.get("id", "")
                        score = item.get("score", 0)
                        if cid and isinstance(score, (int, float)) and score > 0:
                            cum_scores[cid] = cum_scores.get(cid, 0.0) + score
            except (json.JSONDecodeError, TypeError):
                continue
    except Exception:
        result["duration_ms"] = (_time.time() - t0) * 1000
        return result

    result["total_scored"] = len(cum_scores)
    scored_ids = set(cum_scores.keys())

    # ── Phase 2: Demote — high importance + zero cum_score + old ──
    # OS 类比：CFS put_prev_entity() — 进程被抢占时比较 vruntime 是否落后太多
    demote_count = 0
    try:
        # 候选：imp >= threshold, access 非高频, 非保护
        proj_filter = "AND project IN (?, 'global')" if project else ""
        params = [project] if project else []

        candidates = conn.execute(
            f"""SELECT id, importance, created_at, oom_adj, access_count, chunk_type
                FROM memory_chunks
                WHERE importance >= ?
                  AND COALESCE(oom_adj, 0) > -500
                  AND chunk_type NOT IN ('task_state', 'excluded_path')
                  {proj_filter}
                ORDER BY importance DESC""",
            [demote_min_imp] + params
        ).fetchall()

        now = datetime.now(timezone.utc)
        for cid, imp, created_at, oom_adj, acc, ctype in candidates:
            if demote_count >= max_per_scan:
                break

            # 只 demote cum_score = 0 的 chunk
            if cid in scored_ids:
                continue

            # 宽限期检查
            try:
                created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_days = (now - created_dt).total_seconds() / 86400
            except Exception:
                age_days = 0

            if age_days < demote_min_age_days:
                result["skipped_grace"] += 1
                continue

            # 保护检查：pinned chunks 不动
            if oom_adj is not None and oom_adj <= -200:
                result["skipped_protected"] += 1
                continue

            # 执行 demote: importance *= decay
            new_imp = round(imp * demote_decay, 4)
            conn.execute(
                "UPDATE memory_chunks SET importance = ?, updated_at = ? WHERE id = ?",
                (new_imp, now.isoformat(), cid)
            )
            demote_count += 1

        result["demoted"] = demote_count
    except Exception:
        pass

    # ── Phase 3: Promote — high cum_score + low importance ──
    # OS 类比：CFS place_entity() — 新进程/唤醒进程放置到 min_vruntime 附近
    #   cum_score 高说明该 chunk 在检索中频繁高相关性 → importance 应匹配
    promote_count = 0
    try:
        for cid, cum_score in sorted(cum_scores.items(),
                                     key=lambda x: x[1], reverse=True):
            if promote_count >= max_per_scan:
                break
            if cum_score < promote_min_cum:
                break  # sorted desc, 后面都更小

            # 查询当前 chunk 状态
            row = conn.execute(
                "SELECT importance, chunk_type, oom_adj FROM memory_chunks WHERE id = ?",
                (cid,)
            ).fetchone()
            if not row:
                continue

            current_imp, ctype, oom_adj = row
            # 只 promote importance 低于 target 的
            if current_imp >= promote_target:
                continue
            # 不 promote 控制面类型
            if ctype in ("task_state", "excluded_path"):
                continue

            # 执行 promote
            now = datetime.now(timezone.utc)
            conn.execute(
                "UPDATE memory_chunks SET importance = ?, updated_at = ? WHERE id = ?",
                (promote_target, now.isoformat(), cid)
            )
            promote_count += 1

        result["promoted"] = promote_count
    except Exception:
        pass

    if demote_count > 0 or promote_count > 0:
        conn.commit()

    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
    return result


# ── place_entity — Fair Initial Importance for New Chunks（iter561）──

def place_entity(conn: "sqlite3.Connection", project: str = None) -> dict:
    """
    iter561: place_entity — CFS 公平初始化新 chunk importance。

    OS 类比：Linux CFS place_entity() (Ingo Molnár, 2007, kernel 2.6.23,
    kernel/sched/fair.c)
      当新 task 被 fork() 或 wake_up() 时，CFS 不将其 vruntime 设为 0
      （否则新 task 会无限抢占直到追上 min_vruntime）。也不设为 max_vruntime
      （否则永远排到最后无法执行）。
      place_entity() 设置：se->vruntime = max(se->vruntime, cfs_rq->min_vruntime)
      效果：新 task 从"公平起点"开始竞争，既不饥饿也不抢占。

      kernel 3.12 添加了 START_DEBIT（sysctl_sched_child_runs_first=0 时
      新 task vruntime += sched_vslice(cfs_rq, se) 即一个调度周期的虚拟时间片），
      保证父进程有短暂执行优先权。

    memory-os 等价问题：
      - 批量导入 chunk（iter515 userfaultfd 等）初始 importance=0.15
      - 知识库平均 importance ~0.60，min importance ~0.40（活跃 chunk）
      - imp=0.15 的 chunk 在 retrieval_score 中被 importance_with_decay 乘法
        放大劣势：score ∝ 0.15×0.55 = 0.083 vs 0.60×0.55 = 0.33（4倍差距）
      - starvation_boost(0.30) 无法弥补（需要 BM25 relevance 命中才生效）
      - 结果：42.2% chunks 零访问，永远无法被召回 → 知识浪费

    解决：
      Phase 1: 计算当前知识库的 "min_vruntime" — 活跃 chunk importance 的 P25
      Phase 2: 扫描 imp < min_vruntime 且 access_count=0 的 chunk
      Phase 3: place_entity — 提升 importance 到 min_vruntime（公平起点）
      保护：
        - 宽限期（grace_days）：只对存在超过 N 天的 chunk 执行（避免刚写入立即改）
        - oom_adj >= 500 的 chunk 不提升（明确标记为低优先级的不动）
        - max_per_scan 限制单次扫描量（防止大批量导入时一次性全提升）

    返回:
      placed: int — 已提升数量
      min_vruntime: float — 计算出的公平起点 importance
      eligible: int — 符合提升条件的 chunk 数
      duration_ms: float
    """
    from config import get as _cfg

    t0 = _time.time()
    result = {
        "placed": 0,
        "min_vruntime": 0.0,
        "eligible": 0,
        "duration_ms": 0.0,
    }

    if not _cfg("place_entity.enabled"):
        return result

    grace_days = _cfg("place_entity.grace_days")
    max_per_scan = _cfg("place_entity.max_per_scan")
    floor_percentile = _cfg("place_entity.floor_percentile")  # P25 by default
    min_active_chunks = _cfg("place_entity.min_active_chunks")

    # ── Phase 1: 计算 min_vruntime ──
    # OS 类比：update_min_vruntime(cfs_rq) — 从所有活跃 entity 中取最小 vruntime
    # 我们取活跃 chunk（access_count > 0）的 importance P25 作为公平起点
    try:
        proj_filter = "AND project IN (?, 'global')" if project else ""
        params = [project] if project else []

        # 获取活跃 chunk 的 importance 分布
        active_imps = conn.execute(
            f"""SELECT importance FROM memory_chunks
                WHERE access_count > 0
                  AND COALESCE(oom_adj, 0) < 500
                  {proj_filter}
                ORDER BY importance ASC""",
            params
        ).fetchall()

        if len(active_imps) < min_active_chunks:
            # 活跃 chunk 太少，无法建立可靠的 min_vruntime
            result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
            return result

        # 计算 P25（floor_percentile）
        idx = max(0, int(len(active_imps) * floor_percentile / 100.0) - 1)
        min_vruntime = active_imps[idx][0]

        # Clamp: min_vruntime 不低于 0.30（太低无意义）也不高于 0.60（不过度提升）
        min_vruntime = max(0.30, min(0.60, min_vruntime))
        result["min_vruntime"] = min_vruntime

    except Exception:
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # ── Phase 2: 扫描需要 place_entity 的 chunk ──
    # 条件：importance < min_vruntime, access_count=0, 存在超过 grace_days
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=grace_days)).isoformat()

    try:
        eligible_chunks = conn.execute(
            f"""SELECT id, importance FROM memory_chunks
                WHERE importance < ?
                  AND access_count = 0
                  AND created_at < ?
                  AND COALESCE(oom_adj, 0) < 500
                  AND chunk_type NOT IN ('task_state')
                  {proj_filter}
                ORDER BY created_at ASC
                LIMIT ?""",
            [min_vruntime, cutoff] + params + [max_per_scan]
        ).fetchall()

        result["eligible"] = len(eligible_chunks)

    except Exception:
        result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
        return result

    # ── Phase 3: place_entity — 提升 importance 到 min_vruntime ──
    # OS 类比：se->vruntime = max(se->vruntime, cfs_rq->min_vruntime)
    placed = 0
    for (cid, cur_imp) in eligible_chunks:
        try:
            new_imp = min_vruntime  # 直接设为公平起点
            conn.execute(
                "UPDATE memory_chunks SET importance = ?, last_accessed = ? WHERE id = ?",
                (new_imp, now.isoformat(), cid)
            )
            placed += 1
        except Exception:
            continue

    if placed > 0:
        conn.commit()

    result["placed"] = placed
    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
    return result


# ── iter563: prune_icache_sb — Metadata Table Proportional Reclaim ──────────
# OS 类比：Linux dentry_lru_isolate() + prune_icache_sb()
#   (Dave Chinner / Al Viro, 2012, kernel 3.12, fs/dcache.c + fs/inode.c)
#
#   dcache/icache 是内核文件系统元数据缓存。当元数据缓存膨胀到占用过多内存时，
#   shrinker 回调 dentry_lru_isolate() 遍历 LRU list，对每个 dentry 做结构化检查：
#     - d_count == 0 (无引用)? → 回收
#     - 是 negative dentry (lookup miss 缓存)? → 超时后回收
#     - 子目录数 == 0? → 回收
#   prune_icache_sb() 做 per-superblock inode LRU 扫描，按 i_count/i_state 判断。
#
#   关键区别于 logrotate(iter548)：
#     - logrotate = 时间/数量轮转（类似 cron + maxage policy）
#     - prune_icache_sb = 引用/质量检查（类似 shrinker isolate callback）
#   logrotate 处理"过期"；prune_icache_sb 处理"无效"——即使是新创建的也会被清除。
#
# 根因：
#   生产 DB 99 chunks，但 priming_state 1053 条（10.6x 比例），其中：
#     - 1040 条无 entity_map 链接（98.8% orphaned，从未被实际关联到 chunk）
#     - 212 条 ≤2 字符（"pp", "ms"——无意义 token）
#     - 111 条 3 字符（"决策", "原因"——中文 stopword）
#   ipc_msgq 337 条全部 CONSUMED，但 <48h 所以 logrotate 未清理。
#   hook_txn_log 200 条（已达 max_entries 但 logrotate 按 FIFO 保持恰好 200）。
#
#   问题不是"过期"而是"无效"：
#     - priming 噪声 token 永远不会因为 prime_strength 下降而被轮转（全部 0.30 相等）
#     - consumed IPC 消息无论多新都没有保留价值
#     - entity_edges 引用已删除的 chunk 是结构性 orphan

def prune_icache_sb(conn: sqlite3.Connection, project: str = None) -> dict:
    """
    iter563: prune_icache_sb — Metadata Table Proportional Reclaim.

    对元数据表进行引用/质量检查式清理（不同于 logrotate 的时间/数量轮转）：
      Phase 1: priming_state — 清除无 entity_map 链接 + 短 token（dcache negative dentry）
      Phase 2: ipc_msgq — 清除 ALL consumed（i_count=0，无保留理由）
      Phase 3: entity_edges — 清除引用已删除 chunk 的 edges（orphaned inode）
      Phase 4: hook_txn_log — 更激进的 cap（只保留 max_keep，不考虑 age）

    Returns: {pruned_priming, pruned_ipc, pruned_edges, pruned_txn, total_pruned, duration_ms}
    """
    from config import get as _cfg

    t0 = _time.time()
    result = {
        "pruned_priming": 0,
        "pruned_ipc": 0,
        "pruned_edges": 0,
        "pruned_txn": 0,
        "total_pruned": 0,
        "duration_ms": 0.0,
    }

    if not _cfg("prune_icache_sb.enabled"):
        return result

    min_entity_len = _cfg("prune_icache_sb.min_entity_len")
    max_txn_keep = _cfg("prune_icache_sb.max_txn_keep")

    # ── Phase 1: priming_state — Negative Dentry Eviction ──
    # OS 类比：negative dentry = lookup 失败的缓存。priming entries 未链接到
    # 任何 entity_map 记录 = lookup miss 缓存，应被清除。
    # 同时清除过短 token（d_name 长度 < threshold = 无法构成有效文件名）
    try:
        # 1a: 清除过短 token（无意义 noise）
        r1 = conn.execute(
            "DELETE FROM priming_state WHERE LENGTH(entity_name) < ?",
            (min_entity_len,)
        )
        short_pruned = r1.rowcount

        # 1b: 清除无 entity_map 链接的条目（negative dentry — lookup never hit）
        r2 = conn.execute(
            """DELETE FROM priming_state
               WHERE entity_name NOT IN (
                   SELECT DISTINCT entity_name FROM entity_map
               )"""
        )
        orphan_pruned = r2.rowcount

        result["pruned_priming"] = short_pruned + orphan_pruned
    except Exception:
        result["pruned_priming"] = 0

    # ── Phase 2: ipc_msgq — Zero-Refcount Inode Reclaim ──
    # OS 类比：inode with i_count=0 → 可立即回收，不需要等 LRU aging。
    # CONSUMED 消息 = 引用计数归零的 inode，无论年龄都应回收。
    try:
        r = conn.execute("DELETE FROM ipc_msgq WHERE status = 'CONSUMED'")
        result["pruned_ipc"] = r.rowcount
    except Exception:
        result["pruned_ipc"] = 0

    # ── Phase 3: entity_edges — Orphaned Inode Cleanup ──
    # OS 类比：inode 指向的 block 已被释放（chunk 删除）但 inode 本身还在 icache。
    # 清除 source_chunk_id 指向不存在的 chunk 的 edges。
    try:
        r = conn.execute(
            """DELETE FROM entity_edges
               WHERE source_chunk_id IS NOT NULL
                 AND source_chunk_id != ''
                 AND source_chunk_id NOT IN (SELECT id FROM memory_chunks)"""
        )
        result["pruned_edges"] = r.rowcount
    except Exception:
        result["pruned_edges"] = 0

    # ── Phase 4: hook_txn_log — Aggressive FIFO Cap ──
    # OS 类比：printk ring buffer — 固定大小，旧消息被覆盖。
    # logrotate 保持恰好 max_entries(200)。prune_icache_sb 进一步收紧到
    # max_txn_keep（100），因为审计价值随时间指数衰减。
    try:
        count = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
        if count > max_txn_keep:
            overflow = count - max_txn_keep
            conn.execute(
                """DELETE FROM hook_txn_log WHERE rowid IN (
                    SELECT rowid FROM hook_txn_log
                    ORDER BY started_at ASC
                    LIMIT ?
                )""",
                (overflow,)
            )
            result["pruned_txn"] = overflow
    except Exception:
        result["pruned_txn"] = 0

    total = (result["pruned_priming"] + result["pruned_ipc"]
             + result["pruned_edges"] + result["pruned_txn"])
    result["total_pruned"] = total

    if total > 0:
        try:
            conn.commit()
        except Exception:
            pass

    result["duration_ms"] = round((_time.time() - t0) * 1000, 2)
    return result


# ── iter564: oom_score_adj_rebalance — Runtime OOM Score Recalibration ──────
# OS 类比：Linux oom_badness() (Andrew Morton, 2006, kernel/mm/oom_kill.c)
#   OOM killer 不依赖静态 oom_score_adj；oom_badness() 在每次 OOM 事件时
#   综合计算 badness = oom_score_adj + RSS占比 + age。即使 oom_score_adj=0，
#   高 RSS 进程仍然会被优先 kill。
#   Memory-OS 等价：oom_adj 在写入时静态设定后从不更新，导致与运行时数据
#   （access_count, recall_frequency, importance drift）不一致。
#   oom_score_adj_rebalance 定期根据运行时指标重新校准 oom_adj。

def oom_score_adj_rebalance(conn: sqlite3.Connection, project: str) -> dict:
    """
    iter564: 基于运行时指标重新校准 oom_adj。

    OS 类比：Linux oom_badness() — 综合静态 adj + 动态 RSS/age 计算最终 OOM 分数。

    三条规则：
      R1 (demote_active_high_oom): oom_adj >= 500 但 access_count >= 3 → 降至 0
         理由：活跃 chunk 被标记为"最先回收"是不一致的
      R2 (promote_dead_low_oom): access_count=0 + age>7d + imp<0.3 + oom_adj<300 → 升至 300
         理由：长期零访问的低价值 chunk 应标记为"优先回收"
      R3 (protect_hot): access_count>=10 + importance>=0.7 + oom_adj>0 → 降至 -200
         理由：高频高价值 chunk 应获 OOM 保护

    保护机制：
      - chunk_pins (mlock) 绝对不动
      - oom_adj <= -500 不降级（用户显式保护）
      - task_state 类型不动（控制面数据）
      - max_adjustments 限制单次最大调整数

    返回 dict:
      adjusted: int — 实际调整的 chunk 数
      r1_demoted: int, r2_promoted: int, r3_protected: int
      scanned: int
      duration_ms: float
    """
    from config import get as _cfg
    t0 = _time.time()

    enabled = _cfg("oom_rebalance.enabled")
    if not enabled:
        return {"adjusted": 0, "r1_demoted": 0, "r2_promoted": 0,
                "r3_protected": 0, "scanned": 0, "duration_ms": 0.0}

    max_adj = int(_cfg("oom_rebalance.max_adjustments"))
    r2_min_age_days = float(_cfg("oom_rebalance.dead_min_age_days"))
    r3_min_access = int(_cfg("oom_rebalance.hot_min_access"))

    # 获取 pinned chunk IDs (mlock — 绝对不动)
    pinned_ids = set()
    try:
        pin_rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE project IN (?, 'global')",
            (project,)
        ).fetchall()
        pinned_ids = {r[0] for r in pin_rows}
    except Exception:
        pass

    # 扫描所有相关 chunks
    rows = conn.execute(
        """SELECT id, chunk_type, importance, access_count,
                  COALESCE(oom_adj, 0) as oom_adj, created_at, last_accessed
           FROM memory_chunks
           WHERE project IN (?, 'global')""",
        (project,)
    ).fetchall()

    scanned = len(rows)
    now = datetime.now(timezone.utc)
    adjusted = 0
    r1_demoted = 0
    r2_promoted = 0
    r3_protected = 0

    for row in rows:
        if adjusted >= max_adj:
            break

        cid, ctype, imp, acc, oom, created_at, last_acc = row

        # 跳过 pinned（mlock）
        if cid in pinned_ids:
            continue
        # 跳过 task_state（控制面）
        if ctype == "task_state":
            continue
        # 跳过用户显式保护（oom_adj <= -500）
        if oom <= -500:
            continue

        # R1: demote_active_high_oom
        # 活跃 chunk 不应被标记为优先回收
        if oom >= 500 and acc >= 3:
            conn.execute(
                "UPDATE memory_chunks SET oom_adj = 0 WHERE id = ?", (cid,))
            r1_demoted += 1
            adjusted += 1
            continue

        # R3: protect_hot (优先于 R2 检查)
        # 高频高价值 chunk 应获保护
        if acc >= r3_min_access and imp >= 0.7 and oom > 0:
            conn.execute(
                "UPDATE memory_chunks SET oom_adj = -200 WHERE id = ?", (cid,))
            r3_protected += 1
            adjusted += 1
            continue

        # R2: promote_dead_low_oom
        # 长期零访问低价值 chunk 应标记为优先回收
        if acc == 0 and imp < 0.3 and oom < 300:
            # 检查年龄
            try:
                cr_dt = datetime.fromisoformat(
                    created_at.replace("Z", "+00:00") if created_at else "")
                age_days = (now - cr_dt).total_seconds() / 86400
            except Exception:
                age_days = 999
            if age_days >= r2_min_age_days:
                conn.execute(
                    "UPDATE memory_chunks SET oom_adj = 300 WHERE id = ?",
                    (cid,))
                r2_promoted += 1
                adjusted += 1
                continue

    if adjusted > 0:
        try:
            conn.commit()
        except Exception:
            pass

    return {
        "adjusted": adjusted,
        "r1_demoted": r1_demoted,
        "r2_promoted": r2_promoted,
        "r3_protected": r3_protected,
        "scanned": scanned,
        "duration_ms": round((_time.time() - t0) * 1000, 2),
    }
