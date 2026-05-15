"""
store_swap.py — Swap Tier + OOM Score Constants

从 store_core.py 拆分（迭代33-38 功能集）。
包含：OOM_ADJ 常量、swap_out/in/fault、get_swap_count。

OS 类比：Linux Swap / zswap (1991 -> 2013) + OOM Killer oom_score_adj (2003->2010)
"""
import json
import re
import sqlite3
import zlib
import base64
from datetime import datetime, timezone

from store_vfs import open_db, ensure_schema, STORE_DB, bump_chunk_version

# ── OOM Score — Per-Chunk 淘汰优先级（迭代38）────────────────────────

# OOM_SCORE_ADJ 常量（与 Linux /proc/[pid]/oom_score_adj 一致）
OOM_ADJ_MIN = -1000   # 绝对保护（等价于 init/sshd 的 -1000，不可淘汰不可 swap）
OOM_ADJ_PROTECTED = -500  # 高保护（量化证据、核心架构决策）
OOM_ADJ_ONFAULT = -200    # iter531: 延迟保护（mlock2(MLOCK_ONFAULT) 语义，首次命中后升级为 PROTECTED）
OOM_ADJ_DEFAULT = 0    # 默认（正常淘汰优先级）
OOM_ADJ_PREFER = 500   # 优先淘汰（临时信息、prompt_context）
OOM_ADJ_MAX = 1000     # 最先淘汰（明确标记为可丢弃）

# ── Swap Tier — 冷数据交换分区（迭代33）─────────────────────

def swap_out(conn: sqlite3.Connection, chunk_ids: list) -> dict:
    """
    迭代33：swap_out — 将 chunk 从主表移到 swap 分区。
    OS 类比：Linux swap out (shrink_page_list -> add_to_swap)
      kswapd 将不活跃页面序列化到 swap 分区而非直接释放，
      页面数据保留在磁盘，需要时可 swap in 恢复。

    流程：
      1. 从主表读取目标 chunk 的完整数据
      2. JSON 序列化为 compressed_data（zlib 压缩）
      3. 写入 swap_chunks 表
      4. 从主表删除（释放配额）
      5. 控制 swap 分区大小（超 max_chunks 时淘汰最旧条目）

    参数：
      conn — 数据库连接
      chunk_ids — 待 swap out 的 chunk ID 列表

    返回 dict：
      swapped_count — 成功 swap out 的 chunk 数
      evicted_from_swap — swap 分区溢出淘汰数
    """
    if not chunk_ids:
        return {"swapped_count": 0, "evicted_from_swap": 0}

    try:
        from config import get as _cfg
        min_imp = _cfg("swap.min_importance_for_swap")
        max_swap = _cfg("swap.max_chunks")
    except Exception:
        min_imp = 0.5
        max_swap = 100

    now_iso = datetime.now(timezone.utc).isoformat()
    swapped = 0

    for cid in chunk_ids:
        # 读取完整 chunk 数据
        row = conn.execute(
            """SELECT id, created_at, updated_at, project, source_session,
                      chunk_type, content, summary, tags, importance,
                      retrievability, last_accessed, COALESCE(access_count, 0),
                      COALESCE(oom_adj, 0)
               FROM memory_chunks WHERE id = ?""",
            (cid,),
        ).fetchone()
        if not row:
            continue

        oom_adj_val = row[13]
        # 迭代38：oom_adj <= -1000 的 chunk 绝对保护（不可 swap out，等价于 mlock）
        if oom_adj_val <= -1000:
            continue

        importance = row[9] if row[9] is not None else 0.5
        # 低于阈值的 chunk 直接删除，不值得 swap 保留
        if importance < min_imp:
            # iter799: 修复 FTS5 清理 — 用 rowid_ref 列（旧代码用不存在的 id 列，静默失败）
            try:
                _del_rowid = conn.execute(
                    "SELECT rowid FROM memory_chunks WHERE id=?", (cid,)
                ).fetchone()
                if _del_rowid:
                    conn.execute(
                        "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                        (str(_del_rowid[0]),)
                    )
            except Exception:
                pass
            conn.execute("DELETE FROM memory_chunks WHERE id = ?", (cid,))
            continue

        # 序列化 + 压缩
        chunk_data = {
            "id": row[0], "created_at": row[1], "updated_at": row[2],
            "project": row[3], "source_session": row[4],
            "chunk_type": row[5], "content": row[6], "summary": row[7],
            "tags": row[8], "importance": row[9],
            "retrievability": row[10], "last_accessed": row[11],
            "access_count": row[12],
        }
        raw_json = json.dumps(chunk_data, ensure_ascii=False)
        compressed = base64.b64encode(zlib.compress(raw_json.encode("utf-8"))).decode("ascii")

        # 写入 swap 分区（upsert）
        conn.execute(
            """INSERT OR REPLACE INTO swap_chunks
               (id, swapped_at, project, chunk_type, original_importance,
                access_count_at_swap, compressed_data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (cid, now_iso, row[3], row[5], importance, row[12], compressed),
        )

        # 从主表删除（iter799: 修复 FTS5 清理 — 用 rowid_ref 而非不存在的 id 列）
        try:
            _sw_del_rowid = conn.execute(
                "SELECT rowid FROM memory_chunks WHERE id=?", (cid,)
            ).fetchone()
            if _sw_del_rowid:
                conn.execute(
                    "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                    (str(_sw_del_rowid[0]),)
                )
        except Exception:
            pass
        conn.execute("DELETE FROM memory_chunks WHERE id = ?", (cid,))
        swapped += 1

    # 控制 swap 分区大小
    # 迭代145：按 importance ASC 淘汰（低重要性先删），而非按 swapped_at ASC（最旧先删）
    # OS 类比：Linux swap eviction 按页面优先级（page type priority + LRU bit）选受害者，
    #           而非简单按分配时间——时间最旧不代表价值最低。
    # 根因：旧逻辑按 swapped_at 删最旧的，可能删掉 importance=0.95 的 design_constraint，
    #       同时保留了 importance=0.50 的 prompt_context——价值顺序完全倒置。
    # 修复：二级排序 (importance ASC, swapped_at ASC) — 低价值优先淘汰，同价值淘汰最旧的
    evicted_from_swap = 0
    swap_count = conn.execute("SELECT COUNT(*) FROM swap_chunks").fetchone()[0]
    if swap_count > max_swap:
        overflow = swap_count - max_swap
        conn.execute(
            "DELETE FROM swap_chunks WHERE id IN "
            "(SELECT id FROM swap_chunks "
            " ORDER BY COALESCE(original_importance, 0.5) ASC, swapped_at ASC LIMIT ?)",
            (overflow,),
        )
        evicted_from_swap = overflow

    if swapped > 0:
        bump_chunk_version()  # 迭代64: TLB v2 — chunk 被 swap out 影响 Top-K
    return {"swapped_count": swapped, "evicted_from_swap": evicted_from_swap}


def swap_in(conn: sqlite3.Connection, chunk_ids: list) -> dict:
    """
    迭代33：swap_in — 从 swap 分区恢复 chunk 到主表。
    OS 类比：Linux swap in (do_swap_page -> swap_readpage)
      进程访问被 swap out 的页面 -> page fault ->
      从 swap 分区读取 -> 解压 -> 恢复到物理内存。

    流程：
      1. 从 swap_chunks 读取压缩数据
      2. 解压 + 反序列化
      3. 写回 memory_chunks 主表（更新 last_accessed）
      4. 从 swap_chunks 删除

    返回 dict：
      restored_count — 成功恢复的 chunk 数
      not_found — swap 中找不到的 ID 数
    """
    if not chunk_ids:
        return {"restored_count": 0, "not_found": 0}

    now_iso = datetime.now(timezone.utc).isoformat()
    restored = 0
    not_found = 0

    for cid in chunk_ids:
        row = conn.execute(
            "SELECT compressed_data FROM swap_chunks WHERE id = ?", (cid,)
        ).fetchone()
        if not row:
            not_found += 1
            continue

        # 解压 + 反序列化
        try:
            raw_json = zlib.decompress(base64.b64decode(row[0])).decode("utf-8")
            chunk_data = json.loads(raw_json)
        except Exception:
            not_found += 1
            continue

        # 恢复到主表（更新时间戳）
        chunk_data["last_accessed"] = now_iso
        chunk_data["updated_at"] = now_iso
        # ── iter541: inode_permission — swap_in 路径写入门控 ──────────────
        # OS 类比：swap_in 恢复数据到物理内存前也经过 inode_permission 检查，
        # 防止损坏的 swap 数据（如截断/碎片 summary）回到主表。
        try:
            from store_vfs import _vfs_write_protect
            if _vfs_write_protect(chunk_data.get("summary", "")):
                not_found += 1
                continue
        except ImportError:
            pass
        tags = chunk_data.get("tags", "[]")
        if isinstance(tags, list):
            tags = json.dumps(tags, ensure_ascii=False)

        conn.execute("""
            INSERT OR REPLACE INTO memory_chunks
            (id, created_at, updated_at, project, source_session,
             chunk_type, content, summary, tags, importance,
             retrievability, last_accessed, access_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            chunk_data["id"], chunk_data.get("created_at", now_iso),
            now_iso, chunk_data.get("project", ""),
            chunk_data.get("source_session", ""),
            chunk_data.get("chunk_type", ""), chunk_data.get("content", ""),
            chunk_data.get("summary", ""), tags,
            chunk_data.get("importance", 0.5),
            chunk_data.get("retrievability", 0.5), now_iso,
            chunk_data.get("access_count", 0),
        ))

        # iter142: 恢复后重建 FTS5 索引（swap_in 向主表写入但不写 FTS，导致恢复后 FTS miss）
        # OS 类比：swap in 时重建 TLB 映射 — 页面回到物理内存后重新建立虚地址→物理地址映射
        try:
            from store_vfs import _cjk_tokenize, _normalize_structured_summary
            _sw_rowid = conn.execute(
                "SELECT rowid FROM memory_chunks WHERE id=?", (cid,)
            ).fetchone()
            if _sw_rowid:
                _summary = chunk_data.get("summary") or ""
                _content = chunk_data.get("content") or ""
                if _summary:
                    conn.execute(
                        "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                        (str(_sw_rowid[0]),)
                    )
                    conn.execute(
                        "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                        (str(_sw_rowid[0]),
                         _cjk_tokenize(_normalize_structured_summary(_summary)),
                         _cjk_tokenize(_normalize_structured_summary(_content)))
                    )
        except Exception:
            pass  # FTS 重建失败不影响 swap_in 主流程

        # 从 swap 分区删除
        conn.execute("DELETE FROM swap_chunks WHERE id = ?", (cid,))
        restored += 1

    # iter1893: swap_in_timeline_backfill — 恢复 chunk 时回补 injection_timeline
    # 根因（数据驱动，2026-05-15）：swap_out 时 timeline 条目被 21d GC 自然清除，
    #   swap_in 恢复后 timeline 为空 → suppress 6h/24h/7d 计数=0 → 垄断 chunk 逃脱。
    #   feishu CLI(ac=5,imp=0.95) swap_in 后将以"新 chunk"身份绕过所有 suppress。
    # 修复：从 recall_traces 回补已恢复 chunk 的 21d 内注入时间戳到 timeline 文件。
    if restored > 0:
        try:
            import os
            from pathlib import Path as _Path1893
            _mos_dir = _Path1893(os.environ.get("MEMORY_OS_DIR", "")) if os.environ.get("MEMORY_OS_DIR") else _Path1893.home() / ".claude" / "memory-os"
            _tl_path = _mos_dir / ".injection_timeline.json"
            _tl = {}
            if _tl_path.exists():
                _tl = json.loads(_tl_path.read_text(encoding="utf-8"))
            _cutoff = (datetime.now(timezone.utc) - __import__('datetime').timedelta(days=21)).isoformat()
            _patched = 0
            for cid in chunk_ids:
                if cid in _tl:
                    continue
                _rows = conn.execute(
                    "SELECT timestamp FROM recall_traces "
                    "WHERE injected=1 AND timestamp>? AND top_k_json LIKE ?",
                    (_cutoff, f'%{cid[:12]}%')
                ).fetchall()
                if _rows:
                    _tl[cid] = sorted(set(r[0] for r in _rows))
                    _patched += 1
            if _patched > 0:
                _tl_path.write_text(json.dumps(_tl, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
        bump_chunk_version()  # 迭代64: TLB v2 — swap in 恢复的 chunk 影响 Top-K
    return {"restored_count": restored, "not_found": not_found}


def swap_fault(conn: sqlite3.Connection, query: str, project: str) -> list:
    """
    迭代33：swap fault — 检索 swap 分区中的匹配 chunk。
    OS 类比：page fault -> swap in path (do_swap_page)
      当 FTS5 检索主表 miss 时，检查 swap 分区是否有匹配的被换出 chunk。
      如果有匹配，自动 swap in 恢复到主表。

    与 Linux swap fault 的对应：
      - major page fault: 需要从磁盘 swap 分区读取（较慢）
      - memory-os: 需要遍历 swap_chunks 表 + 解压检查（较慢于 FTS5）

    策略：
      从 swap_chunks 表中按 project 过滤，解压 summary 字段做关键词匹配，
      返回匹配的 chunk ID 列表（调用方可选择性 swap_in）。

    参数：
      conn — 数据库连接
      query — 搜索查询
      project — 项目 ID

    返回匹配的 swap chunk 信息列表（按 importance 降序）。
    """
    try:
        from config import get as _cfg
        fault_top_k = _cfg("swap.fault_top_k")
    except Exception:
        fault_top_k = 2

    rows = conn.execute(
        """SELECT id, original_importance, chunk_type, compressed_data
           FROM swap_chunks WHERE project = ?
           ORDER BY original_importance DESC""",
        (project,),
    ).fetchall()

    if not rows:
        return []

    # 从 query 提取关键词
    query_tokens = set()
    for m in re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', query.lower()):
        if len(m.group()) >= 2:
            query_tokens.add(m.group())
    cn = re.sub(r'[^\u4e00-\u9fff]', '', query)
    for i in range(len(cn) - 1):
        query_tokens.add(cn[i:i + 2])

    if not query_tokens:
        return []

    matches = []
    for cid, importance, chunk_type, compressed in rows:
        try:
            raw_json = zlib.decompress(base64.b64decode(compressed)).decode("utf-8")
            data = json.loads(raw_json)
            summary = data.get("summary", "").lower()
            content = data.get("content", "").lower()
            text = f"{summary} {content}"

            # 关键词匹配计数
            hit_count = sum(1 for t in query_tokens if t in text)
            if hit_count > 0:
                matches.append({
                    "id": cid,
                    "summary": data.get("summary", ""),
                    "importance": importance or 0.5,
                    "chunk_type": chunk_type or "",
                    "hit_count": hit_count,
                    "hit_ratio": hit_count / len(query_tokens),
                })
        except Exception:
            continue

    # 按 hit_ratio * importance 排序
    matches.sort(key=lambda m: m["hit_ratio"] * m["importance"], reverse=True)
    return matches[:fault_top_k]


def get_swap_count(conn: sqlite3.Connection, project: str = None) -> int:
    """返回 swap 分区中的 chunk 数量。"""
    if project:
        return conn.execute(
            "SELECT COUNT(*) FROM swap_chunks WHERE project = ?", (project,)
        ).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM swap_chunks").fetchone()[0]


def gc_orphan_swap(conn: sqlite3.Connection) -> dict:
    """
    迭代146：Swap GC — 清理孤儿 project 的 swap 条目。
    OS 类比：Linux /proc/[pid]/maps 的 anonymous page cleanup —
      进程退出后，内核回收其所有匿名页（包括 swap 中的被换出页面），
      不需要等到 swap 空间不足才回收。
      具体路径：do_exit() → exit_mm() → mmput() → __mmput() →
        exit_mmap() → unmap_vmas() → free_swap_and_cache() 对每个 swap PTE 释放。

    memory-os 等价问题：
      project "消亡"（主表 memory_chunks 中无任何该 project 的 chunk）后，
      其在 swap_chunks 中的换出记录不会自动清理。
      这些"孤儿"swap 条目：
        1. 永远不会被 swap_in（project 已死，不会再有检索触发 fault）
        2. 占用全局 swap 配额（swap.max_chunks=100 是共享的）
        3. 挤压活跃 project 的 swap 使用空间，导致活跃 project 的有价值
           chunk 被提前驱逐出 swap（即使 iter145 修复了优先级，也只能在
           swap_out 时按 importance 排序，无法阻止孤儿占位）

    算法：
      1. 查询 swap_chunks 中的所有 project 集合
      2. 查询 memory_chunks 中的所有 project 集合（活跃 project）
      3. 差集 = 孤儿 project（swap 有、主表无）
      4. 删除孤儿 project 的所有 swap 条目

    例外：
      - global project（全局知识库）即使主表为空也不清理
      - 最近 1 小时内 swapped_at 的条目不清理（可能是刚 swap out，
        还有可能被 swap in — 等价于 page grace period）

    调用时机：
      loader.py SessionStart — 与 gc_traces、watchdog 一起执行。
      开销：两次 SELECT + 一次 DELETE（孤儿少时极快）。

    返回 dict：
      orphan_projects — 检测到的孤儿 project 列表
      deleted_count   — 删除的 swap 条目数
      freed_pct       — 释放的 swap 容量百分比（相对 max_chunks）
    """
    try:
        from config import get as _cfg
        max_swap = _cfg("swap.max_chunks")
    except Exception:
        max_swap = 100

    # 获取 swap 中的 project 集合
    swap_projs = {r[0] for r in conn.execute(
        "SELECT DISTINCT project FROM swap_chunks"
    ).fetchall()}

    if not swap_projs:
        return {"orphan_projects": [], "deleted_count": 0, "freed_pct": 0.0}

    # 获取主表中的 project 集合（活跃 project）
    active_projs = {r[0] for r in conn.execute(
        "SELECT DISTINCT project FROM memory_chunks"
    ).fetchall()}

    # 孤儿 = swap 有 but 主表无
    # 例外：global project 永远保留
    orphans = swap_projs - active_projs - {"global"}

    if not orphans:
        return {"orphan_projects": [], "deleted_count": 0, "freed_pct": 0.0}

    # 保护 grace period：最近 1 小时内 swapped_at 的条目不删除
    # （刚 swap out 的可能很快被 swap_fault 触发恢复）
    # 注意：使用 datetime(swapped_at) 转换 ISO8601+timezone 格式与 SQLite datetime() 兼容，
    # 直接字符串比较会因 'T' vs ' ' 分隔符差异导致所有带时区的时间戳判断错误。
    placeholders = ",".join("?" * len(orphans))
    deleted = conn.execute(
        f"""DELETE FROM swap_chunks
            WHERE project IN ({placeholders})
              AND datetime(swapped_at) < datetime('now', '-1 hour')""",
        list(orphans),
    ).rowcount

    freed_pct = round(deleted / max_swap * 100, 1) if max_swap > 0 else 0.0

    return {
        "orphan_projects": sorted(orphans),
        "deleted_count": deleted,
        "freed_pct": freed_pct,
    }


# ── iter430: Spontaneous Recovery — 自发恢复（Pavlov 1927）─────────────────────────
#
# 认知科学依据：Pavlov (1927) 经典条件反射消退后，
#   经过一段时间的"休息"（不需强化），被抑制的反应会自发恢复（spontaneous recovery）。
#   Rescorla (1997): 恢复程度与休息时间正相关，初始重要性越高恢复越完整。
#   在记忆领域：被遗忘（inhibited）的记忆经过休息后可部分恢复，
#     尤其是历史上曾被频繁访问的"强记忆"（high access_count）。
#
# OS 类比：Linux MGLRU active 列表晋升 + zswap 热页解压缩 —
#   在 swap 分区中"休眠"一段时间后，具有高访问历史的页面被优先从 swap 提升，
#   类比 MGLRU 跨代晋升（被充分访问的 young page 晋升到 active generation）。
#   与 kswapd 的关系：kswapd 驱逐是抑制（extinction），SR 是抑制后的自发恢复。

def run_spontaneous_recovery(
    conn: sqlite3.Connection,
    project: str,
    now_iso: str = None,
) -> dict:
    """
    iter430: 自发恢复 — 扫描 swap 分区中符合条件的 chunk，
    将其 swap in 并提升 stability（Pavlov 1927 SR）。

    触发条件（AND）：
      1. 在 swap 中 >= sr_min_swap_days 天（足够休息时间）
      2. 历史 access_count_at_swap >= sr_min_access_count（曾经重要）
      3. original_importance >= sr_min_importance（本身有价值）

    恢复操作：
      - swap_in → 恢复到主表
      - stability × sr_recovery_boost（≈ +15%）

    返回 dict：
      recovered — 恢复的 chunk 数
      boosted — stability 被提升的 chunk 数
    """
    from datetime import datetime, timezone, timedelta

    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()

    try:
        from config import get as _cfg
        if not _cfg("swap.sr_enabled"):
            return {"recovered": 0, "boosted": 0}
        min_swap_days = float(_cfg("swap.sr_min_swap_days") or 3.0)
        min_access = int(_cfg("swap.sr_min_access_count") or 3)
        min_imp = float(_cfg("swap.sr_min_importance") or 0.65)
        recovery_boost = float(_cfg("swap.sr_recovery_boost") or 1.15)
        max_recover = int(_cfg("swap.sr_max_recover_per_run") or 5)
    except Exception:
        min_swap_days, min_access, min_imp = 3.0, 3, 0.65
        recovery_boost, max_recover = 1.15, 5

    # 找满足条件的 swap 条目（按 original_importance DESC 优先恢复最重要的）
    cutoff = (datetime.now(timezone.utc) - timedelta(days=min_swap_days)).isoformat()
    candidates = conn.execute(
        """SELECT id, original_importance, access_count_at_swap, compressed_data
           FROM swap_chunks
           WHERE project = ?
             AND COALESCE(original_importance, 0.0) >= ?
             AND COALESCE(access_count_at_swap, 0) >= ?
             AND datetime(swapped_at) <= datetime(?)
           ORDER BY COALESCE(original_importance, 0.0) DESC
           LIMIT ?""",
        (project, min_imp, min_access, cutoff, max_recover),
    ).fetchall()

    if not candidates:
        return {"recovered": 0, "boosted": 0}

    candidate_ids = [row[0] for row in candidates]
    # 用 swap_in 恢复
    result = swap_in(conn, candidate_ids)
    recovered = result.get("restored_count", 0)
    boosted = 0

    if recovered > 0 and recovery_boost > 1.0:
        # 对恢复成功的 chunk 提升 stability
        # 原始 stability 从 candidates 的 compressed_data 中读取（swap_in 不恢复 stability）
        orig_stab_by_id = {}
        for row in candidates:
            cid_c, imp_c, acc_c, cdata_c = row[0], row[1], row[2], row[3]
            try:
                orig_json = json.loads(
                    zlib.decompress(base64.b64decode(cdata_c)).decode("utf-8")
                )
                orig_stab_by_id[cid_c] = float(orig_json.get("stability", 1.0) or 1.0)
            except Exception:
                orig_stab_by_id[cid_c] = 1.0

        for cid in candidate_ids:
            try:
                # 先检查 chunk 是否已恢复到主表
                exists = conn.execute(
                    "SELECT id FROM memory_chunks WHERE id=?", (cid,)
                ).fetchone()
                if not exists:
                    continue
                orig_stab = orig_stab_by_id.get(cid, 1.0)
                new_stab = min(365.0, orig_stab * recovery_boost)
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (new_stab, cid)
                )
                boosted += 1
            except Exception:
                pass

    return {"recovered": recovered, "boosted": boosted}
