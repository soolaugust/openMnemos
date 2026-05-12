#!/usr/bin/env python3
"""
import_knowledge.py — 从 self-improving/ 等外部知识源批量导入到 Memory OS store.db

OS 类比：Linux initramfs → 根文件系统挂载后，将初始 ramdisk 中的知识迁移到持久存储。

用法：
  python3 import_knowledge.py [--dry-run] [--source wiki|corrections|projects|rules|all]

目标：验证"知识量增加后子系统行为是否发生有意义变化"的假设。
"""

import os, sys, json, re, sqlite3, hashlib
from pathlib import Path
from datetime import datetime, timezone

# Add parent to path for store imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.chdir(str(Path(__file__).resolve().parent.parent))

from store_core import open_db, ensure_schema, insert_chunk, already_exists, bump_chunk_version

# iter115: 从 self-improving/ 导入的知识是跨项目方法论，应写入 global tier
# 而非当前工作目录的 project ID（否则在其他 project 中被 NUMA penalty -0.25）
# OS 类比：共享内核代码段 — kernel.text 不属于某个特定进程，而是全局共享
PROJECT_ID = "global"  # was "abspath:7e3095aef7a6" — changed iter115
SELF_IMPROVING = Path.home() / "self-improving"
DRY_RUN = "--dry-run" in sys.argv
SOURCE = "all"
for arg in sys.argv[1:]:
    if arg.startswith("--source="):
        SOURCE = arg.split("=")[1]

stats = {"scanned": 0, "imported": 0, "skipped_dup": 0, "skipped_low": 0}


def _get_import_defaults():
    """迭代515: userfaultfd — 从 sysctl 读取 import 默认 importance/oom_adj。"""
    try:
        from config import get as _cfg
        return _cfg("userfaultfd.import_base_importance"), _cfg("userfaultfd.import_oom_adj")
    except Exception:
        return 0.50, 300


def make_chunk(chunk_type, summary, content, importance=None, tags=None, source_file=""):
    # 迭代515: userfaultfd — demand-paged import
    # import chunks 以低 importance 写入（mapped but not present），
    # 首次检索命中时由 userfaultfd_promote 提升（page fault handler）
    base_imp, base_oom = _get_import_defaults()
    if importance is None:
        importance = base_imp

    chunk_id = f"import-{hashlib.md5(summary.encode()).hexdigest()[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": chunk_id,
        "created_at": now,
        "updated_at": now,
        "project": PROJECT_ID,
        "source_session": f"import:{source_file}",
        "chunk_type": chunk_type,
        "content": content[:2000],
        "summary": summary[:120],
        "tags": json.dumps(tags or [], ensure_ascii=False),
        "importance": importance,
        "retrievability": 1.0,
        "embedding": "[]",
        "access_count": 0,
        "last_accessed": now,
        "lru_gen": 0,
        "oom_adj": base_oom,
    }


# iter650: import_quality_gate — 碎片子章节过滤
# 根因：wiki 按 ## 切分后，索引性子章节无独立检索价值
# 三类碎片：(1) 标题含索引关键词 (2) 内容以 URL/文件列表为主 (3) 纯 TODO/待深入
# iter651: meta_noise_gate — 知识管理系统自身的流程/协议描述对 LLM 无检索价值
# 根因：10 个零访问 chunk 中 9 个是"知识固化协议"/"推理原则"等 meta 内容，
#   这些已在 CLAUDE.md 中体现，import 为 chunk 只增加噪声不增加可检索知识。
_META_NOISE_KEYWORDS = re.compile(
    r'知识固化|固化协议|固化机制|推理与问题解决原则|'
    r'锁/并发分析协议|迁移到新项目时需确认|执行顺序（组合使用）|'
    r'wiki\s*固化|knowledge.consolidation|'
    # iter665: aios_self_mgmt — AIOS/claude-code 自身资源管理决策
    # 根因：decisions/ 下 adaptive-complexity/skill-listing-budget 等文件是
    #   工具自身的配置策略，非用户领域知识，100% 零访问。
    r'Adaptive.Complexity|Skill.Listing.Budget|token.budget|'
    r'char.budget|context.window.管理|compaction.策略',
    re.IGNORECASE
)
_INDEX_TITLE_KEYWORDS = re.compile(
    r'参考链接|相关文件|影响范围|附录|changelog|目录|索引|待深入|'
    r'references?$|related\s+files?|appendix',
    re.IGNORECASE
)

def _is_index_fragment(title: str, body: str) -> bool:
    """判断子章节是否为索引碎片或 meta 噪声（无独立检索价值）。"""
    if _INDEX_TITLE_KEYWORDS.search(title):
        return True
    # iter651: meta_noise_gate — 知识管理系统自身的流程描述
    if _META_NOISE_KEYWORDS.search(title) or _META_NOISE_KEYWORDS.search(body[:200]):
        return True
    # 纯链接/文件路径列表：URL 或路径行占比 > 60%
    lines = [l for l in body.split('\n') if l.strip()]
    if lines:
        link_lines = sum(1 for l in lines
                         if re.search(r'https?://|\.md[`\s|)]|\.py[`\s|)]|\.json[`\s|)]', l))
        if link_lines / len(lines) > 0.6:
            return True
    # 去掉链接和路径后实质内容 < 30 字符
    text_only = re.sub(r'https?://\S+', '', body)
    text_only = re.sub(r'[`|/][\w.-]+\.\w+[`|]?', '', text_only).strip()
    if len(text_only) < 30:
        return True
    return False


def extract_wiki_knowledge():
    chunks = []
    wiki_dir = SELF_IMPROVING / "wiki"

    for md_file in sorted(wiki_dir.rglob("*.md")):
        if md_file.name in ("index.md", "SCHEMA.md", "log.md"):
            continue

        rel = md_file.relative_to(SELF_IMPROVING)
        text = md_file.read_text(encoding="utf-8")

        # 迭代515: userfaultfd — chunk_type 分类保留，importance 统一用 sysctl 默认值
        # 所有 import chunks 以低 importance 写入，首次检索命中时由 userfaultfd_promote 提升
        if "decisions/" in str(rel):
            chunk_type = "decision"
        elif "capabilities/" in str(rel):
            chunk_type = "procedure"
        elif "pe_analysis/" in str(rel):
            chunk_type = "procedure"
        elif "sched_ext/" in str(rel):
            chunk_type = "decision"
        elif "schedqos/" in str(rel):
            chunk_type = "decision"
        elif "kernel_process/" in str(rel):
            chunk_type = "decision"
        elif "persona/" in str(rel):
            chunk_type = "decision"
        elif "todos/" in str(rel):
            continue
        elif "execution-log" in str(rel):
            continue
        else:
            chunk_type = "decision"

        title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else md_file.stem

        # iter651: file-level meta_noise_gate — 整个文件标题匹配 meta 噪声时跳过
        if _META_NOISE_KEYWORDS.search(title):
            continue

        # 迭代99：深度分节导入 — 按 ## 切分，每节独立 chunk（3-5x 收益）
        # OS 类比：inode 粒度从整文件降到 block 级别
        clean_text = re.sub(r'^---\n.*?---\n', '', text, flags=re.DOTALL)
        sections = re.split(r'\n##\s+', clean_text)

        if len(sections) > 1:
            # 多节文件：每 ## section 独立 chunk
            # iter1420: per_doc_chunk_cap — 单文档最多 3 chunk
            # 根因：8-section 文档拆出 8 chunk，仅 1 个被检索命中，其余 7 个零访问（70% 死库存）
            # 修复：先过滤碎片，再按 body 长度 top-3（长内容信息密度高、FTS5 可区分度强）
            _MAX_CHUNKS_PER_DOC = 3
            _candidates = []
            for i, sec in enumerate(sections[1:], 1):
                sec_lines = sec.strip().split("\n")
                sec_title = sec_lines[0].strip().rstrip("#").strip()
                sec_body = "\n".join(sec_lines[1:]).strip()[:400]
                if len(sec_body) < 20:
                    continue
                # iter650: import_quality_gate — 碎片子章节过滤
                if _is_index_fragment(sec_title, sec_body):
                    continue
                _candidates.append((i, sec_title, sec_body))
            _candidates.sort(key=lambda x: len(x[2]), reverse=True)
            # iter1480: subset_dedup — 短 section content 完全被长 section 包含时去重
            _deduped = []
            for _ci, _ct, _cb in _candidates:
                if any(_cb.strip() in _ob for _, _, _ob in _deduped):
                    continue
                _deduped.append((_ci, _ct, _cb))
            _candidates = _deduped
            for i, sec_title, sec_body in _candidates[:_MAX_CHUNKS_PER_DOC]:
                sec_summary = f"[{rel.parent.name}] {title} > {sec_title}"[:120]
                tags = [str(rel.parent.name), md_file.stem, f"sec{i}"]
                chunks.append(make_chunk(chunk_type, sec_summary, sec_body,
                                          None, tags, str(rel)))
        else:
            # 单节文件：整文件 1 chunk（原逻辑）
            content = re.sub(r'^#.*\n', '', clean_text).strip()[:500]
            if len(content) < 20:
                continue
            tags = [str(rel.parent.name), md_file.stem]
            chunks.append(make_chunk(chunk_type, f"[{rel.parent.name}] {title}",
                                      content, None, tags, str(rel)))

    return chunks


def extract_corrections():
    # iter657: 纠正记录已在 corrections.md 文件中，session 启动时按需加载
    # 重复导入与 rules 同理 — 零信息增益，占用注入 slot
    return []
    chunks = []
    corr_file = SELF_IMPROVING / "corrections.md"
    if not corr_file.exists():
        return chunks

    text = corr_file.read_text(encoding="utf-8")
    for line in text.split("\n"):
        if not line.startswith("|") or "Date" in line or "---" in line:
            continue
        parts = [p.strip() for p in line.split("|")[1:-1]]
        if len(parts) >= 3:
            date, wrong, correct = parts[0], parts[1], parts[2]
            summary = f"[纠正] {wrong[:60]}"
            content = f"错误：{wrong}\n正确：{correct}"
            chunks.append(make_chunk("excluded_path", summary, content, None,
                                      ["correction", date], "corrections.md"))

    return chunks


def extract_project_decisions():
    chunks = []
    proj_dir = SELF_IMPROVING / "projects"
    if not proj_dir.exists():
        return chunks

    # iter656: import_iter_self_gate — memory-os 项目自身的迭代记录不导入
    # 根因（数据驱动，2026-05-04）：13 个 [memory-os/iterXX] chunk 全部 ac=0，
    #   这些是系统自身实现日志（非用户知识），仅增加 FTS 噪声。
    _SELF_ITER_PROJECTS = {"memory-os"}

    for md_file in sorted(proj_dir.glob("*.md")):
        text = md_file.read_text(encoding="utf-8")
        proj_name = md_file.stem

        # iter656: 跳过 memory-os 自身的迭代记录
        if proj_name in _SELF_ITER_PROJECTS:
            continue

        # Pattern 1: ### 迭代 N: Title（标题级）
        iter_pattern = re.compile(r'###\s+迭代\s*(\d+)[^:：]*[:：]\s*(.+?)(?:\n|$)')
        for match in iter_pattern.finditer(text):
            iter_num = match.group(1)
            title = match.group(2).strip()

            start = match.end()
            next_header = re.search(r'\n###\s', text[start:])
            end = start + next_header.start() if next_header else min(start + 500, len(text))
            body = text[start:end].strip()

            os_match = re.search(r'OS 类比[：:](.+?)(?:\n|$)', body)
            os_analogy = os_match.group(1).strip()[:80] if os_match else ""

            summary = f"[{proj_name}/iter{iter_num}] {title[:60]}"
            content = f"{title}\n{os_analogy}\n{body[:300]}" if os_analogy else f"{title}\n{body[:300]}"

            chunks.append(make_chunk("decision", summary, content, None,
                                      [proj_name, f"iter{iter_num}"], f"projects/{md_file.name}"))

        # Pattern 2: - 迭代 N：Title（列表项级，迭代99 新增）
        inline_pattern = re.compile(
            r'^- 迭代\s*(\d+)[^:：]*[:：]\s*(.+?)(?:\n(?=- 迭代|\n|$)|$)', re.MULTILINE)
        for match in inline_pattern.finditer(text):
            iter_num = match.group(1)
            inline_text = match.group(2).strip()
            if len(inline_text) < 20:
                continue
            os_match = re.search(r'OS 类比[：:](.+?)(?:$|\n)', inline_text)
            os_tag = os_match.group(1).strip()[:60] if os_match else ""
            summary = f"[{proj_name}/iter{iter_num}] {inline_text[:80]}"
            content = f"{inline_text[:400]}" + (f"\nOS: {os_tag}" if os_tag else "")
            chunks.append(make_chunk("decision", summary, content, None,
                                      [proj_name, f"iter{iter_num}"], f"projects/{md_file.name}"))

    return chunks


def extract_memory_rules():
    # iter657: 规则已在 CLAUDE.md / system prompt 中，重复导入浪费 token 预算
    # 数据：10 个 rule chunk 占 33% 注入但 0% 信息增益（内容与 system prompt 100% 重叠）
    return []
    chunks = []
    mem_file = SELF_IMPROVING / "memory.md"
    if not mem_file.exists():
        return chunks

    text = mem_file.read_text(encoding="utf-8")
    sections = re.split(r'\n##\s+', text)
    for section in sections[1:]:
        lines = section.strip().split("\n")
        header = lines[0].strip()
        body = "\n".join(lines[1:]).strip()

        if not body or len(body) < 30:
            continue

        bullets = re.findall(r'^[-*]\s+(.+)', body, re.MULTILINE)
        for bullet in bullets:
            if len(bullet) < 20:
                continue
            summary = f"[规则/{header}] {bullet[:80]}"
            chunks.append(make_chunk("decision", summary, bullet, None,
                                      ["rule", header.lower()], "memory.md"))

    return chunks


def main():
    all_chunks = []

    if SOURCE in ("all", "wiki"):
        wiki_chunks = extract_wiki_knowledge()
        print(f"Wiki 知识: {len(wiki_chunks)} chunks")
        all_chunks.extend(wiki_chunks)

    if SOURCE in ("all", "corrections"):
        corr_chunks = extract_corrections()
        print(f"错误纠正: {len(corr_chunks)} chunks")
        all_chunks.extend(corr_chunks)

    if SOURCE in ("all", "projects"):
        proj_chunks = extract_project_decisions()
        print(f"项目决策: {len(proj_chunks)} chunks")
        all_chunks.extend(proj_chunks)

    if SOURCE in ("all", "rules"):
        rule_chunks = extract_memory_rules()
        print(f"行为规则: {len(rule_chunks)} chunks")
        all_chunks.extend(rule_chunks)

    stats["scanned"] = len(all_chunks)

    if DRY_RUN:
        print(f"\n[DRY RUN] 将导入 {len(all_chunks)} chunks:")
        for c in all_chunks[:15]:
            print(f"  [{c['chunk_type']}] imp={c['importance']} {c['summary']}")
        if len(all_chunks) > 15:
            print(f"  ... 还有 {len(all_chunks) - 15} 条")
        return

    conn = open_db()
    ensure_schema(conn)

    for chunk in all_chunks:
        if already_exists(conn, chunk["summary"], chunk["chunk_type"]):
            stats["skipped_dup"] += 1
            continue
        insert_chunk(conn, chunk)
        stats["imported"] += 1

    if stats["imported"] > 0:
        bump_chunk_version()

    conn.commit()

    total = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
    by_type = conn.execute(
        "SELECT chunk_type, COUNT(*) FROM memory_chunks GROUP BY chunk_type ORDER BY COUNT(*) DESC"
    ).fetchall()

    conn.close()

    print(f"\n=== 导入完成 ===")
    print(f"扫描: {stats['scanned']}, 导入: {stats['imported']}, "
          f"跳过(重复): {stats['skipped_dup']}, 跳过(低质): {stats['skipped_low']}")
    print(f"\nDB 总量: {total} chunks")
    for ct, cnt in by_type:
        print(f"  {ct}: {cnt}")


if __name__ == "__main__":
    main()


def _load_tombstones() -> set:
    """iter517: 加载 import tombstone 注册表。
    OS 类比：Linux RLIMIT_NPROC check — fork() 前查进程计数表，
    已被 reaper 回收的 PID 不允许再 fork 出来。"""
    ts_file = Path.home() / ".claude" / "memory-os" / ".import_tombstones.json"
    if ts_file.exists():
        try:
            return set(json.loads(ts_file.read_text(encoding="utf-8")))
        except Exception:
            pass
    return set()


def _save_tombstones(tombstones: set):
    """iter517: 持久化 tombstone 注册表（最多保留 2000 条，LRU 淘汰）。"""
    ts_file = Path.home() / ".claude" / "memory-os" / ".import_tombstones.json"
    ts_file.parent.mkdir(parents=True, exist_ok=True)
    # 超过 2000 条时只保留最近的（ID 排序取最后 2000）
    entries = sorted(tombstones)[-2000:]
    ts_file.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")


def register_import_tombstones(deleted_ids: list):
    """iter517: 外部调用 — 当 ksm_scan/overcommit_kill/oom_reaper 删除 import chunk 时注册 tombstone。
    阻止 incremental_import 在下次 SessionStart 重新创建已被回收的 chunks。
    OS 类比：exit_notify() → 父进程 wait() 后 PID 进入不可复用状态。"""
    if not deleted_ids:
        return
    # 只注册 import- 前缀的 ID（有机 chunk 的删除不影响 import）
    import_ids = [cid for cid in deleted_ids if cid.startswith("import-")]
    if not import_ids:
        return
    tombstones = _load_tombstones()
    tombstones.update(import_ids)
    _save_tombstones(tombstones)


def incremental_import():
    """增量导入：只在 wiki 文件有变化时执行。
    通过 .last_import_ts 文件记录上次导入时间戳。

    iter517: RLIMIT_NPROC — 三级准入控制:
      1. 文件 mtime 检查（无变更 → 跳过全部）
      2. Tombstone 注册表（已被回收 → 永不重建）
      3. ID 存在性检查（DB 中已有 → 跳过）
    消除 import→ksm_scan→delete→re-import 无限循环。"""
    ts_file = Path.home() / ".claude" / "memory-os" / ".last_import_ts"

    last_ts = 0
    if ts_file.exists():
        try:
            last_ts = float(ts_file.read_text().strip())
        except:
            pass

    # 检查是否有新文件
    import time
    has_new = False
    for md_file in SELF_IMPROVING.rglob("*.md"):
        if md_file.stat().st_mtime > last_ts:
            has_new = True
            break

    # iter1418: stale_import_gc — 每次 SessionStart 无条件执行
    # ac=0 且存活 >3 天的 import chunk 自动回收，不等 wiki 文件变更
    gc_deleted = 0
    _gc_conn = open_db()
    ensure_schema(_gc_conn)
    _gc_rows = _gc_conn.execute(
        "SELECT id FROM memory_chunks "
        "WHERE id LIKE 'import-%' AND access_count = 0 "
        "AND created_at < datetime('now', '-3 days')"
    ).fetchall()
    if _gc_rows:
        _gc_ids = [r[0] for r in _gc_rows]
        _gc_ph = ",".join("?" * len(_gc_ids))
        _gc_conn.execute(f"DELETE FROM memory_chunks WHERE id IN ({_gc_ph})", _gc_ids)
        _gc_conn.execute(
            "DELETE FROM memory_chunks_fts WHERE rowid_ref NOT IN "
            "(SELECT CAST(rowid AS TEXT) FROM memory_chunks)")
        _gc_tombstones = _load_tombstones()
        _gc_tombstones.update(_gc_ids)
        _save_tombstones(_gc_tombstones)
        gc_deleted = len(_gc_ids)
        bump_chunk_version()
        _gc_conn.commit()
    _gc_conn.close()

    # iter1660: orphan_subsection_gc — 子章节 chunk 的 parent 不存在时标记 DEAD
    # 数据驱动（2026-05-13）：import-0fe8ebc34(schedqos > 配置文件格式) ac=0 ACTIVE，
    #   parent chunk 未被 import（不在当前 DB）。孤立子章节无上下文、无独立检索价值。
    # 修复：summary 含 " > " 的 import chunk，检查去掉子标题后的 parent 是否存在。
    _orp_conn = open_db()
    ensure_schema(_orp_conn)
    _orp_rows = _orp_conn.execute(
        "SELECT id, summary FROM memory_chunks "
        "WHERE id LIKE 'import-%' AND chunk_state='ACTIVE' AND summary LIKE '% > %'"
    ).fetchall()
    _orp_dead = 0
    for _orp_id, _orp_summary in _orp_rows:
        _parent_summary = _orp_summary.rsplit(" > ", 1)[0]
        _parent_exists = _orp_conn.execute(
            "SELECT 1 FROM memory_chunks WHERE summary LIKE ? AND chunk_state='ACTIVE' LIMIT 1",
            (f"{_parent_summary}%",)
        ).fetchone()
        if not _parent_exists:
            _orp_conn.execute(
                "UPDATE memory_chunks SET chunk_state='DEAD' WHERE id=?", (_orp_id,))
            _orp_dead += 1
    if _orp_dead:
        bump_chunk_version()
        _orp_conn.commit()
        gc_deleted += _orp_dead

    # iter1662: redundant_subsection_gc — parent 存在且活跃时，ac=0 子章节归档
    # 数据驱动（2026-05-13）：3 个 import 子章节 ac=0，parent ac=5-6。
    #   子章节信息已被 parent 覆盖，占 FTS5 索引位但零检索价值。
    # 条件：summary 含 " > " + parent ACTIVE 且 ac>=1 + 子 ac=0 + 创建 >=1 天。
    _red_rows = _orp_conn.execute(
        "SELECT id, summary FROM memory_chunks "
        "WHERE id LIKE 'import-%' AND chunk_state='ACTIVE' AND access_count=0 "
        "AND summary LIKE '% > %' AND created_at < datetime('now', '-1 hour')"
    ).fetchall()
    _red_dead = 0
    for _red_id, _red_summary in _red_rows:
        _par_summary = _red_summary.rsplit(" > ", 1)[0]
        _par_alive = _orp_conn.execute(
            "SELECT 1 FROM memory_chunks WHERE summary LIKE ? AND chunk_state='ACTIVE' "
            "AND access_count >= 1 AND id != ? LIMIT 1",
            (f"{_par_summary}%", _red_id)
        ).fetchone()
        if _par_alive:
            _orp_conn.execute(
                "UPDATE memory_chunks SET chunk_state='DEAD' WHERE id=?", (_red_id,))
            _red_dead += 1
    if _red_dead:
        bump_chunk_version()
        _orp_conn.commit()
        gc_deleted += _red_dead
    _orp_conn.close()

    # iter1421: retroactive_doc_cap — 按 doc 分组，超 cap 的低价值 chunk 立即回收
    # 根因：per_doc_chunk_cap(iter1420) 只对新 import 生效，历史数据仍有 doc 5-8 chunk
    #   83/100 chunk 是 import，13/19 doc 超 cap → 检索信噪比极低
    # 修复：按 tags[:2] 分 doc，每 doc 保留 importance+ac 最高的 3 个，其余回收+tombstone
    _DOC_CAP = 3
    _cap_conn = open_db()
    ensure_schema(_cap_conn)
    _cap_rows = _cap_conn.execute(
        "SELECT id, tags, importance, access_count FROM memory_chunks WHERE id LIKE 'import-%'"
    ).fetchall()
    _cap_docs = {}
    for _cid, _tags_str, _imp, _ac in _cap_rows:
        try:
            _tgs = json.loads(_tags_str) if _tags_str else []
        except Exception:
            _tgs = []
        _dk = "/".join(_tgs[:2]) if len(_tgs) >= 2 else _cid
        _cap_docs.setdefault(_dk, []).append((_cid, _imp or 0.0, _ac or 0))
    _cap_del_ids = []
    for _dk, _chunks in _cap_docs.items():
        if len(_chunks) <= _DOC_CAP:
            continue
        _chunks.sort(key=lambda x: (x[2], x[1]), reverse=True)
        for _cid, _, _ in _chunks[_DOC_CAP:]:
            _cap_del_ids.append(_cid)
    if _cap_del_ids:
        _cap_ph = ",".join("?" * len(_cap_del_ids))
        _cap_conn.execute(f"DELETE FROM memory_chunks WHERE id IN ({_cap_ph})", _cap_del_ids)
        # FTS5 orphan cleanup: keep only ACTIVE chunks indexed
        _cap_conn.execute(
            "DELETE FROM memory_chunks_fts WHERE rowid_ref NOT IN "
            "(SELECT CAST(rowid AS TEXT) FROM memory_chunks WHERE chunk_state='ACTIVE')")
        _cap_ts = _load_tombstones()
        _cap_ts.update(_cap_del_ids)
        _save_tombstones(_cap_ts)
        gc_deleted += len(_cap_del_ids)
        bump_chunk_version()
        _cap_conn.commit()
    _cap_conn.close()

    if not has_new:
        return {"status": "skip" if gc_deleted == 0 else "gc_only",
                "reason": "no_changes", "gc_deleted": gc_deleted}

    # 有变化，执行完整导入
    conn = open_db()
    ensure_schema(conn)

    all_chunks = (extract_wiki_knowledge() + extract_corrections() +
                  extract_project_decisions() + extract_memory_rules())

    # iter517: 三级准入控制
    tombstones = _load_tombstones()
    # 预查所有 import- ID 是否已存在于 DB（批量查询，避免 N+1）
    candidate_ids = [c["id"] for c in all_chunks]
    existing_ids = set()
    for i in range(0, len(candidate_ids), 200):
        batch = candidate_ids[i:i+200]
        placeholders = ",".join("?" * len(batch))
        rows = conn.execute(
            f"SELECT id FROM memory_chunks WHERE id IN ({placeholders})", batch
        ).fetchall()
        existing_ids.update(r[0] for r in rows)

    imported = 0
    skipped_tombstone = 0
    skipped_exists = 0
    for chunk in all_chunks:
        cid = chunk["id"]
        # Level 1: tombstone check (已被回收的不重建)
        if cid in tombstones:
            skipped_tombstone += 1
            continue
        # Level 2: ID existence check (DB 中已有)
        if cid in existing_ids:
            skipped_exists += 1
            continue
        # Level 3: summary exact match (兼容旧逻辑)
        if already_exists(conn, chunk["summary"], chunk["chunk_type"]):
            skipped_exists += 1
            continue
        insert_chunk(conn, chunk)
        imported += 1

    if imported > 0:
        bump_chunk_version()
    conn.commit()

    # iter1486: fts5_import_sync_fix — JOIN-based FTS5 补漏
    # 根因（2026-05-11）：原 count 比较 total > fts 在 FTS 含 DEAD 残留时被膨胀跳过补漏。
    try:
        _has_state = conn.execute(
            "SELECT COUNT(*) FROM pragma_table_info('memory_chunks') WHERE name='chunk_state'"
        ).fetchone()[0]
        _fi_where = "chunk_state='ACTIVE' AND summary != ''" if _has_state else "id NOT LIKE 'swap_%'"
        from store_vfs import _cjk_tokenize, _normalize_structured_summary
        _fi_missing = conn.execute(
            f"SELECT mc.rowid, mc.id, mc.summary, mc.content FROM memory_chunks mc "
            f"WHERE mc.{_fi_where} AND mc.rowid NOT IN "
            f"(SELECT CAST(rowid_ref AS INTEGER) FROM memory_chunks_fts)"
        ).fetchall()
        if _fi_missing:
            for _fr, _fid, _fs, _fc in _fi_missing:
                _fs_tok = _cjk_tokenize(_normalize_structured_summary(_fs or ""))
                _fc_tok = _cjk_tokenize(_normalize_structured_summary(_fc or ""))
                conn.execute(
                    "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                    (str(_fr), _fs_tok, _fc_tok))
            conn.commit()
    except Exception:
        pass

    conn.close()

    # 更新时间戳
    ts_file.parent.mkdir(parents=True, exist_ok=True)
    ts_file.write_text(str(time.time()))

    return {"status": "imported", "count": imported,
            "skipped_tombstone": skipped_tombstone,
            "skipped_exists": skipped_exists,
            "gc_deleted": gc_deleted}
