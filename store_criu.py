"""
store_criu.py — CRIU Checkpoint/Restore + Recall Counts

从 store_core.py 拆分（迭代49-62 功能集）。
包含：checkpoint_dump/restore/cleanup/collect_hits、chunk_recall_counts。

OS 类比：CRIU (Checkpoint/Restore In Userspace, Google/OpenVZ, 2012)
"""
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from store_vfs import open_db, ensure_schema, STORE_DB, MEMORY_OS_DIR, _safe_add_column

_CRIU_CHECKPOINT_DIR = MEMORY_OS_DIR / "checkpoints"


def _ensure_checkpoint_schema(conn: sqlite3.Connection) -> None:
    """幂等创建 checkpoints 表。"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            project TEXT NOT NULL,
            session_id TEXT NOT NULL,
            hit_chunk_ids TEXT NOT NULL,
            madvise_hints TEXT,
            query_topics TEXT,
            consumed INTEGER DEFAULT 0
        )
    """)
    # 迭代92: 内联快照 — chunk 被淘汰后仍可从 checkpoint 恢复摘要
    _safe_add_column(conn, "checkpoints", "chunk_snapshots", "TEXT")


def checkpoint_dump(conn: sqlite3.Connection, project: str, session_id: str,
                    hit_chunk_ids: list, madvise_hints: list = None,
                    query_topics: list = None) -> dict:
    """
    迭代49：CRIU checkpoint — 冻结当前会话的精确工作集。
    OS 类比：CRIU dump — 遍历 /proc/<pid>/ 序列化进程完整状态。

    参数：
      hit_chunk_ids: 本次会话中被 retriever 命中的 chunk IDs（从 recall_traces 获取）
      madvise_hints: 当前的 madvise hint 关键词
      query_topics: 本次会话的主要查询主题

    返回：{"checkpoint_id": ..., "saved_ids": N, "cleaned": M}
    """
    from config import get as _sysctl

    _ensure_checkpoint_schema(conn)

    now = datetime.now(timezone.utc).isoformat()
    max_hit_ids = _sysctl("criu.max_hit_ids")

    # 去重 + 截断
    seen = set()
    unique_ids = []
    for cid in hit_chunk_ids:
        if cid not in seen:
            seen.add(cid)
            unique_ids.append(cid)
    unique_ids = unique_ids[:max_hit_ids]

    if not unique_ids:
        return {"checkpoint_id": None, "saved_ids": 0, "cleaned": 0}

    # iter89: 内联快照 — dump 时保存完整 content + summary，防止 kswapd 淘汰后丢失
    # 修复：之前只存 summary 导致 content retention=13.9%，现在同时保存 content
    # iter259: 保存 content_hash，用于 restore 时版本校验（防止 stale snapshot 注入）
    import hashlib as _hashlib
    placeholders = ",".join("?" * len(unique_ids))
    snapshot_rows = conn.execute(f"""
        SELECT id, chunk_type, content, summary, importance
        FROM memory_chunks
        WHERE id IN ({placeholders}) AND project = ?
    """, unique_ids + [project]).fetchall()
    chunk_snapshots = [
        {
            "id": r[0],
            "chunk_type": r[1],
            "content": r[2] or "",
            "summary": r[3] or "",
            "importance": r[4] or 0.5,
            # iter259: content hash 用于 restore 时版本校验
            "content_hash": _hashlib.md5((r[2] or "").encode()).hexdigest()[:8],
        }
        for r in snapshot_rows
    ]

    import uuid as _uuid
    checkpoint_id = f"ckpt-{_uuid.uuid4().hex[:12]}"

    conn.execute("""
        INSERT INTO checkpoints (id, created_at, project, session_id,
                                 hit_chunk_ids, madvise_hints, query_topics,
                                 chunk_snapshots)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        checkpoint_id, now, project, session_id,
        json.dumps(unique_ids, ensure_ascii=False),
        json.dumps(madvise_hints or [], ensure_ascii=False),
        json.dumps(query_topics or [], ensure_ascii=False),
        json.dumps(chunk_snapshots, ensure_ascii=False),
    ))

    # FIFO 淘汰：保留最新 N 个 checkpoint（per-project per-session）
    # iter259：传入 session_id 激活 per-agent 隔离
    cleaned = _checkpoint_cleanup(conn, project, session_id=session_id)

    return {"checkpoint_id": checkpoint_id, "saved_ids": len(unique_ids), "cleaned": cleaned}


def checkpoint_restore(conn: sqlite3.Connection, project: str) -> Optional[dict]:
    """
    迭代49：CRIU restore — 从最近的 checkpoint 恢复精确工作集。
    OS 类比：CRIU restore — 读取镜像文件，重建进程状态。

    返回 None 如果无可用 checkpoint，否则返回：
    {
        "checkpoint_id": ...,
        "chunks": [{"id":..., "chunk_type":..., "summary":..., "importance":...}],
        "madvise_hints": [...],
        "query_topics": [...],
        "age_hours": float,
    }
    """
    from config import get as _sysctl

    _ensure_checkpoint_schema(conn)

    max_age_hours = _sysctl("criu.max_age_hours")

    # 取最新的未消费 checkpoint
    row = conn.execute("""
        SELECT id, created_at, session_id, hit_chunk_ids, madvise_hints, query_topics,
               chunk_snapshots
        FROM checkpoints
        WHERE project = ? AND consumed = 0
        ORDER BY created_at DESC LIMIT 1
    """, (project,)).fetchone()

    if not row:
        return None

    ckpt_id, created_at, ckpt_session_id, hit_ids_json, hints_json, topics_json, snapshots_json = row

    # 检查过期
    try:
        dt = datetime.fromisoformat(created_at)
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_hours = (now - dt).total_seconds() / 3600
    except Exception:
        age_hours = float("inf")

    if age_hours > max_age_hours:
        # 过期：标记为 consumed（不删除，保留审计痕迹）
        conn.execute("UPDATE checkpoints SET consumed = 1 WHERE id = ?", (ckpt_id,))
        return None

    # 解析 chunk IDs
    try:
        hit_chunk_ids = json.loads(hit_ids_json)
    except Exception:
        hit_chunk_ids = []

    if not hit_chunk_ids:
        conn.execute("UPDATE checkpoints SET consumed = 1 WHERE id = ?", (ckpt_id,))
        return None

    # 查找实际存在的 chunk（可能已被 kswapd/swap 淘汰）
    # iter89: 增加 content 字段，修复 live path 不返回 content 的 bug
    placeholders = ",".join("?" * len(hit_chunk_ids))
    rows = conn.execute(f"""
        SELECT id, chunk_type, content, summary, importance, last_accessed
        FROM memory_chunks
        WHERE id IN ({placeholders}) AND project = ?
    """, hit_chunk_ids + [project]).fetchall()

    # 迭代87：不再标记 consumed=1 on restore — 允许多轮 compaction 复用同一 checkpoint
    # consumed 只在过期(_checkpoint_cleanup)或空 hit_ids 时标记

    chunks = []
    live_ids = set()
    for rid, chunk_type, content, summary, importance, last_accessed in rows:
        live_ids.add(rid)
        chunks.append({
            "id": rid,
            "chunk_type": chunk_type,
            "content": content or "",
            "summary": summary or "",
            "importance": importance or 0.5,
            "last_accessed": last_accessed or "",
        })

    # iter89: Snapshot Fallback — 被淘汰的 chunk 从内联快照恢复（含 content）
    # iter259: 版本校验 — live chunk 与 snapshot content_hash 不一致时标记 _stale=True
    # OS 类比：CRIU restore 时检查 ELF 文件 checksum — 若二进制已更新则放弃旧快照
    if snapshots_json:
        import hashlib as _hashlib
        try:
            snapshots = json.loads(snapshots_json)
            # 构建 live chunk content hash 映射（用于版本校验）
            live_hash = {}
            for c in chunks:
                live_hash[c["id"]] = _hashlib.md5(c.get("content", "").encode()).hexdigest()[:8]

            for snap in snapshots:
                snap_id = snap.get("id")
                if snap_id not in live_ids:
                    # chunk 已被淘汰，从快照恢复
                    chunks.append({
                        "id": snap_id,
                        "chunk_type": snap.get("chunk_type", "decision"),
                        "content": snap.get("content", ""),
                        "summary": snap.get("summary", ""),
                        "importance": snap.get("importance", 0.5),
                        "last_accessed": "",
                        "_from_snapshot": True,
                    })
                else:
                    # iter259: live chunk 版本校验 — 比较 content_hash
                    snap_hash = snap.get("content_hash")
                    if snap_hash and live_hash.get(snap_id) != snap_hash:
                        # content 已更新（chunk 被修改），标记为 stale
                        # loader 可据此决定是否优先使用 live 版本
                        for c in chunks:
                            if c["id"] == snap_id:
                                c["_snapshot_stale"] = True
                                break
        except (json.JSONDecodeError, TypeError):
            pass

    if not chunks:
        return None

    # 解析 hints 和 topics
    try:
        madvise_hints = json.loads(hints_json) if hints_json else []
    except Exception:
        madvise_hints = []
    try:
        query_topics = json.loads(topics_json) if topics_json else []
    except Exception:
        query_topics = []

    return {
        "checkpoint_id": ckpt_id,
        "chunks": chunks,
        "madvise_hints": madvise_hints,
        "query_topics": query_topics,
        "age_hours": round(age_hours, 1),
    }


def _checkpoint_cleanup(conn: sqlite3.Connection, project: str,
                        session_id: str = "") -> int:
    """
    CRIU checkpoint FIFO 淘汰 — 保留最新 N 个 per-project per-session。
    iter259：按 session_id 隔离，防止 Agent-A 的旧 checkpoint 被 Agent-B 淘汰。
    OS 类比：CRIU 的 --leave-running + pre-dump 链清理。
    """
    from config import get as _sysctl

    max_checkpoints = _sysctl("criu.max_checkpoints")

    # iter259：优先按 session_id 清理（per-agent 隔离）
    if session_id:
        rows = conn.execute("""
            SELECT id FROM checkpoints
            WHERE project = ? AND session_id = ?
            ORDER BY created_at DESC
        """, (project, session_id)).fetchall()
    else:
        # fallback：按 project 全量清理（旧行为）
        rows = conn.execute("""
            SELECT id FROM checkpoints
            WHERE project = ?
            ORDER BY created_at DESC
        """, (project,)).fetchall()

    if len(rows) <= max_checkpoints:
        return 0

    # 删除超出数量的旧 checkpoint
    to_delete = [r[0] for r in rows[max_checkpoints:]]
    if to_delete:
        placeholders = ",".join("?" * len(to_delete))
        conn.execute(f"DELETE FROM checkpoints WHERE id IN ({placeholders})", to_delete)

    return len(to_delete)


def checkpoint_collect_hits(conn: sqlite3.Connection, project: str,
                            session_id: str, limit: int = None) -> list:
    """
    从 recall_traces 收集本次会话命中的 chunk IDs。
    OS 类比：CRIU 的 /proc/<pid>/pagemap 遍历 — 收集所有活跃页面。

    返回 chunk_id 列表（按最近访问排序，去重）。
    """
    from config import get as _sysctl

    if limit is None:
        limit = _sysctl("criu.max_hit_ids")

    rows = conn.execute("""
        SELECT top_k_json FROM recall_traces
        WHERE session_id = ? AND project = ? AND injected = 1
        ORDER BY timestamp DESC
        LIMIT 20
    """, (session_id, project)).fetchall()

    seen = set()
    hit_ids = []
    for (top_k_json,) in rows:
        try:
            top_k = json.loads(top_k_json) if top_k_json else []
        except Exception:
            continue
        for entry in top_k:
            cid = entry.get("id") if isinstance(entry, dict) else None
            if cid and cid not in seen:
                seen.add(cid)
                hit_ids.append(cid)

    return hit_ids[:limit]

# ── 迭代62：Anti-Starvation — chunk 召回计数统计 ──────────────────────────────
# OS 类比：/proc/PID/sched — 每个进程的调度统计（nr_switches, wait_sum 等）

def chunk_recall_counts(conn: 'sqlite3.Connection', project: str,
                        window: int = 30,
                        session_id: str = "",
                        max_days: int = 14) -> dict:
    """
    统计每个 chunk 在最近 window 条 injected=1 traces 中被选入 top_k 的次数。
    迭代312：新增 session_id 参数（保留兼容旧接口）。
    迭代580：madvise_cold — 统计范围从 injected=1 扩展到所有 trace。
    迭代604：feedback_loop_break — 回退为只统计 injected=1 的 trace。
      iter580 统计所有 trace 造成正反馈死锁：被 hard_gate 拦截的 chunk 仍出现在
      skipped_same_hash trace 的 top_k_json → rc 永不衰减 → 永远被拦截。
      iter596-601 已在 scoring+constraint 两路径加 hard_gate，不再需要靠膨胀 rc
      来触发拦截。回退为只统计真正注入的 trace，让被拦截的 chunk 自然衰减。
        统计"冷热"不能只看成功的 page access，还要算被 TLB cached 拦截的访问。
    iter1786：rc_time_bound — 条数窗口 + 时间窗口(14d)取交集。
      低频项目 window=30 跨越数周，过期注入持续压制 chunk → RFD 永久衰减。
      加 max_days 确保统计窗口不超过 14 天，低频项目 rc 自然归零。

    Args:
        conn: 数据库连接
        project: 项目 ID
        window: 回溯的 trace 条数（默认 30）
        session_id: 当前 session ID（保留参数，不影响全局计数）
        max_days: 时间窗口上限天数（默认 14）

    Returns:
        dict: {chunk_id: recall_count}  ← 全局计数（兼容旧接口）
    """
    try:
        # iter604: feedback_loop_break — 只统计 injected=1 的 trace。
        # iter669: bw_window_nonempty — 额外过滤 top_k_json='[]' 的空 trace。
        # 根因：60% injected trace 的 top_k_json 为空数组（无 chunk 达到注入阈值），
        #   空 trace 占据 LIMIT 窗口但不贡献任何 chunk 计数，导致有效窗口缩水。
        #   例：LIMIT 30 中只有 12 条非空 → 分子最大只能到 12，分母却是 30。
        # iter1786: rc_time_bound — 加 14d 时间约束，防止低频项目窗口跨越数周。
        cur = conn.execute(
            "SELECT top_k_json FROM recall_traces "
            "WHERE project=? AND top_k_json IS NOT NULL AND top_k_json != '[]' AND injected=1 "
            "AND timestamp > datetime('now', '-' || ? || ' days') "
            "ORDER BY rowid DESC LIMIT ?",
            (project, max_days, window)
        )
        counts = {}
        for (top_k_json,) in cur.fetchall():
            try:
                top_k = json.loads(top_k_json) if isinstance(top_k_json, str) else top_k_json
                if isinstance(top_k, list):
                    for item in top_k:
                        if isinstance(item, dict) and "id" in item:
                            cid = item["id"]
                            counts[cid] = counts.get(cid, 0) + 1
            except Exception:
                continue
        return counts
    except Exception:
        return {}


def chunk_recall_counts_memcg(conn: 'sqlite3.Connection', project: str,
                              window: int = 60) -> dict:
    """
    iter566: memcg_stat — Cross-Project Recall Accounting for Global Chunks.

    OS 类比：Linux memory.stat in cgroup v2 (Tejun Heo, 2012, kernel 3.16,
    mm/memcontrol.c) — 单个 cgroup 内的 memory.current 只反映本 cgroup 开销，
    但 memory.stat 提供 hierarchical 视图，包含子 cgroup 的累计值。
    对于共享页面（shared memory / tmpfs），每个 cgroup 各自计数无法反映真实
    系统级资源压力 — 需要 cross-cgroup 聚合统计。

    问题（数据驱动）：
      chunk_recall_counts() 使用 WHERE project=? 只统计当前项目的召回次数。
      global 层 chunk（如 design_constraint）被多个项目共享召回，
      但每个项目独立计数：
        - project A: recall_count=6, project B: recall_count=8, project C: recall_count=0
        - 从 project C 访问时 recall_count=0 → anti-monopoly 全部短路
        - 实际该 chunk 系统级已被召回 14 次（应触发强力 throttle）
      等价于：shared page 在多个 cgroup 中被访问，每个 cgroup 独立的
      memory.current 无法反映全局内存压力。

    解决：
      对 global 项目的 chunk，额外查询 ALL projects 的 recall_traces 聚合计数，
      取 max(per_project_count, cross_project_count) 作为有效 recall_count。
      仅对 project='global' 的 chunk 执行跨项目聚合（非 global chunk 无此问题）。

    Args:
        conn: 数据库连接
        project: 当前项目 ID（用于识别"非本项目"的跨项目 traces）
        window: 回溯的 trace 条数（跨项目，默认 60 — 覆盖更大时间窗口）

    Returns:
        dict: {chunk_id: cross_project_recall_count} — 仅包含 global chunk 的跨项目计数
    """
    try:
        # 查询所有项目的最近 traces（排除当前项目，当前项目已由 chunk_recall_counts 覆盖）
        # iter606: 与 chunk_recall_counts 对齐，只统计 injected=1 的 trace。
        # iter669: bw_window_nonempty — 过滤空 top_k_json，与 per-project 对齐。
        cur = conn.execute(
            "SELECT top_k_json FROM recall_traces "
            "WHERE project != ? AND top_k_json IS NOT NULL AND top_k_json != '[]' AND injected=1 "
            "ORDER BY rowid DESC LIMIT ?",
            (project, window)
        )
        counts = {}
        for (top_k_json,) in cur.fetchall():
            try:
                top_k = json.loads(top_k_json) if isinstance(top_k_json, str) else top_k_json
                if isinstance(top_k, list):
                    for item in top_k:
                        if isinstance(item, dict) and "id" in item:
                            cid = item["id"]
                            counts[cid] = counts.get(cid, 0) + 1
            except Exception:
                continue
        return counts
    except Exception:
        return {}


def chunk_session_recall_counts(conn: 'sqlite3.Connection', project: str,
                                 session_id: str, window: int = 100) -> dict:
    """
    迭代312：统计 session 内每个 chunk 被召回的次数（per-session 计数）。
    OS 类比：/proc/PID/sched per-session — 会话内调度次数统计。

    Args:
        conn: 数据库连接
        project: 项目 ID
        session_id: 当前 session ID
        window: 回溯的 trace 条数（默认 100）

    Returns:
        dict: {chunk_id: session_recall_count}
    """
    if not session_id:
        return {}
    try:
        # 迭代580：与 chunk_recall_counts 一致，统计所有 trace（含 skipped_same_hash）
        cur = conn.execute(
            "SELECT top_k_json FROM recall_traces "
            "WHERE project=? AND session_id=? AND top_k_json IS NOT NULL "
            "ORDER BY rowid DESC LIMIT ?",
            (project, session_id, window)
        )
        counts = {}
        for (top_k_json,) in cur.fetchall():
            try:
                top_k = json.loads(top_k_json) if isinstance(top_k_json, str) else top_k_json
                if isinstance(top_k, list):
                    for item in top_k:
                        if isinstance(item, dict) and "id" in item:
                            cid = item["id"]
                            counts[cid] = counts.get(cid, 0) + 1
            except Exception:
                continue
        return counts
    except Exception:
        return {}
