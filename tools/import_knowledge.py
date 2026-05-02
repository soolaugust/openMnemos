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
        return 0.15, 300


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

        # 迭代99：深度分节导入 — 按 ## 切分，每节独立 chunk（3-5x 收益）
        # OS 类比：inode 粒度从整文件降到 block 级别
        clean_text = re.sub(r'^---\n.*?---\n', '', text, flags=re.DOTALL)
        sections = re.split(r'\n##\s+', clean_text)

        if len(sections) > 1:
            # 多节文件：每 ## section 独立 chunk
            for i, sec in enumerate(sections[1:], 1):
                sec_lines = sec.strip().split("\n")
                sec_title = sec_lines[0].strip().rstrip("#").strip()
                sec_body = "\n".join(sec_lines[1:]).strip()[:400]
                if len(sec_body) < 20:
                    continue
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

    for md_file in sorted(proj_dir.glob("*.md")):
        text = md_file.read_text(encoding="utf-8")
        proj_name = md_file.stem

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

    if not has_new:
        return {"status": "skip", "reason": "no_changes"}

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
    conn.close()

    # 更新时间戳
    ts_file.parent.mkdir(parents=True, exist_ok=True)
    ts_file.write_text(str(time.time()))

    return {"status": "imported", "count": imported,
            "skipped_tombstone": skipped_tombstone,
            "skipped_exists": skipped_exists}
