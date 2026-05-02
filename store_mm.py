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
        try:
            dmesg_log(conn, DMESG_INFO, "page_idle",
                      f"scan: demoted={demoted} deleted={deleted} "
                      f"candidates={len(candidates)} project={project}",
                      project=project)
        except Exception:
            pass

    max_rounds = max(project_bitmap.values()) if project_bitmap else 0
    return {"scanned": len(project_bitmap), "demoted": demoted,
            "deleted": deleted, "max_idle_rounds": max_rounds}


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
