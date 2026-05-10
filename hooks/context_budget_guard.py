#!/usr/bin/env python3
"""
context_budget_guard.py — SessionStart 时自动检查 context budget

迭代 B5：OS 类比 — Linux Early OOM (earlyoom, 2017)

背景：
  Linux OOM killer 在内存完全耗尽时才触发——此时系统已严重卡顿。
  earlyoom (2017) 在内存压力到达阈值时就提前 kill 低优先级进程，
  避免系统进入 thrashing 状态。

  AIOS 类比：
    "Prompt is too long" = OOM（系统提示已超限，session 无法启动）。
    context_budget_guard = earlyoom（在 SessionStart 时检测并提前回收）。

集成方式：
  在 settings.json → hooks.SessionStart 中添加：
    {"type": "command", "command": "python3 .../context_budget_guard.py", "timeout": 10}

  如果 pressure >= "some"：
    1. 自动 reclaim 低优先级组件
    2. 通过 additionalContext 注入警告信息
    3. 记录 dmesg 日志
"""

import sys
import json
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

from context_cgroup import scan, reclaim

MEMORY_OS_DIR = Path.home() / ".claude" / "memory-os"
THRASHING_STATE_FILE = MEMORY_OS_DIR / "thrashing_state.json"


def _reset_thrashing_state():
    """SessionStart 时重置 thrashing_state.json 的 session 级字段。

    跨 session 状态污染会导致新 session 从第一个工具调用起就被 block——
    这是 filesize_guard 的会话级 context 增量追踪机制的 bug。
    保留 compact_count 供统计用，只清零 session_bytes 和 window_bytes_history。
    """
    try:
        state = {}
        if THRASHING_STATE_FILE.exists():
            state = json.loads(THRASHING_STATE_FILE.read_text())
        state["session_bytes"] = 0
        state["window_bytes_history"] = []
        state["last_warn_ts"] = 0
        MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
        THRASHING_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False))
    except Exception:
        pass


def _cleanup_stale_session_files():
    """SessionStart 时清理过期的 per-session 碎片文件。

    OS 类比：systemd-tmpfiles --clean — 定期清理 /run/user/PID 等 per-process 临时文件。
    清理目标：
      - ctx_pressure_state.{sid}.json：每个 session 写一个，session 结束后无用
      - page_fault_log.{sid}.json：同上
    保留策略：24h 内的文件保留（可能还有活跃 session），更旧的删除。
    """
    import time as _time
    cutoff = _time.time() - 86400  # 24h
    MAX_CTX_FILES = 5  # 最多保留 5 个（对应最近 5 个并发 session）
    try:
        # ctx_pressure_state per-session 文件
        ctx_files = sorted(
            MEMORY_OS_DIR.glob("ctx_pressure_state.*.json"),
            key=lambda p: p.stat().st_mtime
        )
        for p in ctx_files:
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
        # 若仍超上限，删除最旧的
        ctx_files = [p for p in ctx_files if p.exists()]
        for p in ctx_files[:max(0, len(ctx_files) - MAX_CTX_FILES)]:
            p.unlink(missing_ok=True)

        # page_fault_log per-session 文件
        for p in MEMORY_OS_DIR.glob("page_fault_log.*.json"):
            if p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)
    except Exception:
        pass


def _db_vacuum(db_path: Path):
    """SessionStart 时对 store.db 做 ring-buffer 截断，防止各表无限增长。

    OS 类比：systemd journal --vacuum-size + Linux dmesg ring buffer（固定容量，
    超出后最旧的记录被覆盖）。各表保留上限对应 "journal max size"：

      priming_state  → 500 条（priming 状态历史，远超 working set 无意义）
      dmesg          → 300 条（调试日志，旧的无诊断价值）
      recall_traces  → 200 条（召回历史，超出窗口期即垃圾）
      ipc_msgq       → 100 条（IPC 消息队列）
      hook_txn_log   → 200 条（事务日志）
      tool_patterns  → 500 条（工具模式，按 access_count 保留 Top-N）

    同时：重建 FTS 索引（若 rowid 脱节时，FTS JOIN 会返回空）。
    为避免 SessionStart 阻塞，跳过已在 24h 内 vacuum 过的 DB。
    """
    try:
        import sqlite3
        import time

        # 节流：自适应间隔（OS 类比：Linux writeback dirty_expire_centisecs 自适应）
        # - 上次 freed_total > 100 → DB 活跃增长，缩短到 6h（尽快清理）
        # - 上次 freed_total 10-100 → 正常，保持 24h
        # - 上次 freed_total < 10   → DB 稳定，延长到 72h（减少无谓扫描）
        # 与 _gc_merged_victims 共用 db_maintenance_last.json（减少文件 I/O）
        vacuum_flag = MEMORY_OS_DIR / "db_maintenance_last.json"
        now_ts = time.time()
        if vacuum_flag.exists():
            try:
                _vdata = json.loads(vacuum_flag.read_text())
                last = _vdata.get("ts", 0)
                last_freed = _vdata.get("freed_total", 50)  # 默认 50 → 初次按 24h
                if last_freed > 100:
                    _interval = 6 * 3600    # 活跃 DB：6h
                elif last_freed < 10:
                    _interval = 72 * 3600   # 稳定 DB：72h
                else:
                    _interval = 86400       # 正常：24h
                if now_ts - last < _interval:
                    return
            except Exception:
                pass

        if not db_path.exists():
            return
        # 校验文件头
        with open(db_path, "rb") as _f:
            if _f.read(16)[:6] != b"SQLite":
                return

        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        # 各表截断（保留最新 N 条）
        # B15 fix: hook_txn_log 无 id 列，改用 txn_id；各表单独处理避免错误扩散
        truncations = [
            ("dmesg",          300,  "id"),
            ("recall_traces",  200,  "id"),
            ("ipc_msgq",       100,  "id"),
        ]
        freed_total = 0
        for table, keep, order_col in truncations:
            try:
                cnt = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if cnt > keep:
                    conn.execute(f"""
                        DELETE FROM {table} WHERE {order_col} IN (
                            SELECT {order_col} FROM {table}
                            ORDER BY {order_col} ASC
                            LIMIT {cnt - keep}
                        )
                    """)
                    freed_total += cnt - keep
            except Exception:
                pass  # 表不存在或列名不同，跳过

        # hook_txn_log: 用 txn_id（TEXT，按字典序）截断
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM hook_txn_log").fetchone()[0]
            if cnt > 200:
                conn.execute("""
                    DELETE FROM hook_txn_log WHERE txn_id IN (
                        SELECT txn_id FROM hook_txn_log
                        ORDER BY started_at ASC
                        LIMIT ?
                    )
                """, (cnt - 200,))
                freed_total += cnt - 200
        except Exception:
            pass

        # session_episodes: 保留最近 100 条（按时间倒序保留最新）
        # 注入时只用最近 3 条（limit=3），但无限积累占磁盘且 freshness gate 依赖时间查询
        # OS 类比：Linux syslog rotate — keep last N, discard old
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM session_episodes").fetchone()[0]
            if cnt > 100:
                conn.execute("""
                    DELETE FROM session_episodes WHERE id IN (
                        SELECT id FROM session_episodes
                        ORDER BY ended_at ASC
                        LIMIT ?
                    )
                """, (cnt - 100,))
                freed_total += cnt - 100
        except Exception:
            pass

        # tool_patterns 按 frequency 保留 Top-500（LFU 淘汰最少使用的）
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM tool_patterns").fetchone()[0]
            if cnt > 500:
                conn.execute("""
                    DELETE FROM tool_patterns WHERE id IN (
                        SELECT id FROM tool_patterns
                        ORDER BY frequency ASC, last_seen ASC
                        LIMIT ?
                    )
                """, (cnt - 500,))
                freed_total += cnt - 500
        except Exception:
            pass

        # priming_state: LFU 淘汰 — 按 prime_strength ASC 删除衰减最彻底的条目
        # OS 类比：Linux active/inactive LRU — page_referenced() 保护热页（recent access），
        #   prime_strength ≈ page refcount：高强度=近期被激活=热页，应保留；
        #   低强度=长时间未激活=冷页，优先淘汰（类比 shrink_inactive_list）。
        # 优于 primed_at FIFO：FIFO 会淘汰"旧但仍活跃"的实体（如核心设计约束）。
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM priming_state").fetchone()[0]
            if cnt > 500:
                conn.execute("""
                    DELETE FROM priming_state WHERE (entity_name, project) IN (
                        SELECT entity_name, project FROM priming_state
                        ORDER BY prime_strength ASC, primed_at ASC
                        LIMIT ?
                    )
                """, (cnt - 500,))
                freed_total += cnt - 500
        except Exception:
            pass

        # iter635→1170: stale_noise_gc — 清理存量迭代器噪声 chunk
        # iter1170: 升级为函数驱动 GC（替代硬编码 LIKE 列表）
        # 根因：每次新变体噪声逃逸都需要手动添加 LIKE 模式（已累积 20+ 条）。
        #   复用 extractor 的 _is_metric_report_noise / _is_selfref_noise / _is_quality_chunk
        #   实现自适应 GC：未来新模式只需更新 extractor gate，GC 自动覆盖。
        # 清理条件：access_count=0 AND (extractor gate 判定为噪声 OR chunk_type='prompt_context')
        # 安全性：只删零访问 chunk，不影响任何已被用户使用的知识。
        try:
            _hooks_dir = str(Path(__file__).parent)
            if _hooks_dir not in sys.path:
                sys.path.insert(0, _hooks_dir)
            from extractor import _is_metric_report_noise, _is_selfref_noise, _is_quality_chunk
            _zero_ac_rows = conn.execute(
                "SELECT id, summary, chunk_type FROM memory_chunks WHERE access_count = 0"
            ).fetchall()
            _noise_ids = []
            for _nid, _nsummary, _ntype in _zero_ac_rows:
                if (_ntype == 'prompt_context'
                    or _is_metric_report_noise(_nsummary, _ntype)
                    or _is_selfref_noise(_nsummary, _ntype)
                    or not _is_quality_chunk(_nsummary)):
                    _noise_ids.append(_nid)
            if _noise_ids:
                from store_vfs import delete_chunks as _delete_chunks
                _noise_deleted = _delete_chunks(conn, _noise_ids)
                freed_total += _noise_deleted
        except Exception:
            pass

        # iter654: iter_chunk_swap_gc — 清理存量 memory-os 迭代记录 chunk
        # 根因：extractor 的 import_meta_gate（iter651）阻止新写入，但门禁前已导入的
        #   15 个 [memory-os/iterN] chunk 仍占用主表。这些是迭代器自身实现细节
        #   （DAMON、KSM Dedup、TLB Flush 等 OS 类比特性），对用户无记忆价值。
        #   实测：ac<=2（仅导入时自动访问），从未被用户主动检索使用。
        # 安全性：swap out（非删除），可通过 swap_in 恢复；只清理 ac<=2。
        try:
            _iter_ids = [r[0] for r in conn.execute("""
                SELECT id FROM memory_chunks
                WHERE summary LIKE '%memory-os/iter%' AND access_count <= 2
            """).fetchall()]
            if _iter_ids:
                from store_swap import swap_out as _swap_out
                _swap_result = _swap_out(conn, _iter_ids)
                freed_total += _swap_result.get("swapped_count", 0)
                # 清理 recall_traces 中指向已 swap out chunk 的 stale refs
                _swapped_set = set(_iter_ids)
                _existing_ids = set(r[0] for r in conn.execute(
                    "SELECT id FROM memory_chunks").fetchall())
                for (_tid, _tkj) in conn.execute(
                        "SELECT id, top_k_json FROM recall_traces WHERE top_k_json IS NOT NULL"
                ).fetchall():
                    try:
                        _items = json.loads(_tkj)
                        _filtered = [i for i in _items if i.get("id") in _existing_ids]
                        if len(_filtered) < len(_items):
                            conn.execute("UPDATE recall_traces SET top_k_json=? WHERE id=?",
                                         (json.dumps(_filtered), _tid))
                    except Exception:
                        continue
        except Exception:
            pass

        # B15: FTS orphan cleanup + rowid 对齐检查
        # 问题：FTS5 里存在 rowid_ref 指向已删除 memory_chunks 行的孤立记录（实测 7 条），
        #   导致 FTS JOIN 返回 NULL 行、search 结果异常。
        # OS 类比：Linux dentry cache pruning — 文件删除后 dentry 仍在 dcache 中缓存；
        #   dentry_kill() 清理孤立 dentry 条目，防止内存泄漏和路径查找错误。
        # 修复：
        #   1. 先删孤立 FTS 行（rowid_ref 无对应 mc.rowid）
        #   2. 再检查 JOIN 是否正常；若全部孤立则重建整张 FTS 表
        try:
            # 统计孤立行数量（避免不必要的 DELETE）
            orphan_cnt = conn.execute("""
                SELECT COUNT(*) FROM memory_chunks_fts fts
                WHERE NOT EXISTS (
                    SELECT 1 FROM memory_chunks mc
                    WHERE CAST(fts.rowid_ref AS INTEGER) = mc.rowid
                )
            """).fetchone()[0]

            if orphan_cnt > 0:
                # iter635: 直接 DELETE + re-INSERT 重建 FTS（逐行 delete 对
                # external content table 无效，实测 orphan 仍残留）
                conn.execute("DELETE FROM memory_chunks_fts")
                # iter797: 修复 FTS5 重建路径 — 必须用 rowid_ref 列，过滤 chunk_state
                conn.execute("""INSERT INTO memory_chunks_fts (rowid_ref, summary, content)
                    SELECT CAST(rowid AS TEXT), summary, COALESCE(content, '')
                    FROM memory_chunks WHERE chunk_state='ACTIVE' AND summary != ''""")
                freed_total += orphan_cnt
        except Exception:
            pass

        conn.commit()
        conn.close()

        # 更新共享节流文件（保留其他字段如 gc_ts）
        try:
            _existing = json.loads(vacuum_flag.read_text()) if vacuum_flag.exists() else {}
        except Exception:
            _existing = {}
        _existing["ts"] = now_ts
        _existing["freed_total"] = freed_total
        vacuum_flag.write_text(json.dumps(_existing))

        if freed_total > 0:
            import sys as _sys
            _sys.stderr.write(f"[db_vacuum] freed {freed_total} rows from ring-buffer truncation\n")
    except Exception:
        pass


def _gc_merged_victims(db_path: Path):
    """SessionStart 时清理 merged victim chunks（importance=0, oom_adj=500）。

    OS 类比：Linux rmap / reverse mapping GC — 当页面被合并（KSM merge）后，
    原始页面的 pte 被标记为 KSM，后续 GC 遍历时将其释放。
    这里的 merged victim = KSM 合并后的原始页，survivor = 合并后的共享页。

    产生路径：store_vfs.py mglru_aging() 中 dedup 操作把 victim 的 summary 改写为
    '[merged→{survivor_id}] ...'，importance 设为 0，oom_adj 设为 500。
    这些 victim 应被定期回收，但之前没有执行路径来清理它们，导致积累污染。

    清理条件（AND）：
      1. importance = 0
      2. oom_adj >= 500  （合并标记）
      3. access_count = 0  （从未被召回，无价值）
    节流：24h 内只执行一次（与 _db_vacuum 共用节流文件）。
    """
    try:
        import sqlite3
        import time

        # 节流：与 _db_vacuum 共用 db_maintenance_last.json（减少文件 I/O）
        # OS 类比：Linux kswapd + shrink_slab 共用同一个 vm_total_pages 计数器
        gc_flag = MEMORY_OS_DIR / "db_maintenance_last.json"
        now_ts = time.time()
        if gc_flag.exists():
            try:
                last = json.loads(gc_flag.read_text()).get("gc_ts", 0)
                if now_ts - last < 86400:
                    return
            except Exception:
                pass

        if not db_path.exists():
            return

        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        # 删除 merged victim chunks
        cur = conn.execute("""
            DELETE FROM memory_chunks
            WHERE importance = 0 AND oom_adj >= 500 AND access_count = 0
        """)
        deleted = cur.rowcount
        if deleted > 0:
            # 重建 FTS5（孤立行清理）
            try:
                conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts) VALUES('rebuild')")
            except Exception:
                pass

        conn.commit()
        conn.close()

        # 更新共享节流文件（gc_ts 字段，与 _db_vacuum 的 ts 字段区分）
        try:
            _existing = json.loads(gc_flag.read_text()) if gc_flag.exists() else {}
        except Exception:
            _existing = {}
        _existing["gc_ts"] = now_ts
        _existing["gc_last_deleted"] = deleted
        gc_flag.write_text(json.dumps(_existing))
        if deleted > 0:
            import sys as _sys
            _sys.stderr.write(f"[gc_merged_victims] deleted {deleted} merged victim chunks\n")
    except Exception:
        pass


def main():
    try:
        _raw = sys.stdin.read()
    except Exception:
        _raw = ""

    # 新 session 开始时重置 thrashing 状态，防止跨 session 状态污染
    _reset_thrashing_state()
    # 清理过期的 per-session 碎片文件
    _cleanup_stale_session_files()
    # DB ring-buffer 截断 + FTS 健康检查（24h 节流）
    _db_vacuum(MEMORY_OS_DIR / "store.db")
    # 清理 merged victim chunks（importance=0, oom_adj=500，从未被访问）
    _gc_merged_victims(MEMORY_OS_DIR / "store.db")
    # 清理孤儿 project 的 swap 条目（项目已消亡但 swap 中还有残留）
    # OS 类比：do_exit() → exit_mmap() → free_swap_and_cache() — 进程退出时自动释放 swap 占用
    try:
        import sqlite3 as _sql3
        _db_path = MEMORY_OS_DIR / "store.db"
        if _db_path.exists():
            _sc = _sql3.connect(str(_db_path), timeout=5)
            _sc.execute("PRAGMA journal_mode=WAL")
            from store_swap import gc_orphan_swap as _gc_orphan_swap
            _orphan_result = _gc_orphan_swap(_sc)
            _sc.commit()
            _sc.close()
            if _orphan_result.get("deleted_count", 0) > 0:
                import sys as _sys
                _sys.stderr.write(
                    f"[gc_orphan_swap] deleted {_orphan_result['deleted_count']} orphan swap entries "
                    f"from {_orphan_result['orphan_projects']}\n"
                )
    except Exception:
        pass  # swap GC 失败不影响主流程

    report = scan()

    if report.pressure == "none":
        # 在预算内，不输出任何 additionalContext（节省 tokens）
        sys.exit(0)

    # pressure = "some" or "full" → 自动回收
    report = reclaim(report, dry_run=False)

    # 构造注入信息
    lines = [f"⚠ Context Budget: {report.total_chars:,}/{report.max_chars:,} chars ({report.usage_pct:.0f}%) pressure={report.pressure}"]

    actions = [a for a in report.actions_taken if isinstance(a, dict)]
    if actions:
        freed = sum(a.get("chars_freed", 0) for a in actions if a.get("executed", False))
        lines.append(f"Auto-reclaimed {len(actions)} components ({freed:,} chars freed)")

    # 如果仍超限，建议手动清理
    if report.pressure == "full":
        lines.append("仍超限！建议：python3 aios/memory-os/context_cgroup.py scan")

    context_text = " | ".join(lines)

    # dmesg 日志
    try:
        from store import open_db, ensure_schema, dmesg_log, DMESG_WARN
        conn = open_db()
        ensure_schema(conn)
        dmesg_log(conn, DMESG_WARN, "context_cgroup",
                  f"budget_guard: pressure={report.pressure} total={report.total_chars} reclaimed={len(actions)}",
                  extra={"actions": [a.get("name") for a in actions if isinstance(a, dict)]})
        conn.commit()
        conn.close()
    except Exception:
        pass

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
