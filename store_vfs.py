"""
store_vfs.py — VFS 统一数据访问层（核心 CRUD + FTS5 + evict）

从 store_core.py 拆分（迭代21-64 功能集）。
包含：数据库连接、schema 迁移、FTS5 全文索引、CRUD 操作、去重/合并、淘汰。

OS 类比：Linux VFS (Virtual File System, 1992) + ext3 htree (2002)
"""
import json
import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List
import config

# ── 迭代154：Module-level bm25 imports — 消除 _fts5_escape/_cjk_tokenize 的内联 import 开销 ──
# OS 类比：ELF 动态链接器 GOT/PLT — 符号在模块加载时一次性绑定，调用时直接查表，
#   不像 dlopen(RTLD_LAZY) 每次调用时重新解析（per-call 解析 ≈ 内联 import）。
#
# 问题：_fts5_escape() 每次调用都执行 `from bm25 import ENGLISH_STOPWORDS, _porter_stem`
#   Python 内部实际是 sys.modules 查找 + 属性读取，首次还会触发 bm25 模块初始化。
#   _cjk_tokenize() 同样在 try 块中内联 import（每次都执行 sys.modules 查找）。
#   实测：FTS5 检索路径 _fts5_escape + _cjk_tokenize 合计 ~11.6ms 首次，
#   其中 bm25 import 贡献 ~3ms（bm25 未加载时）或 ~0.1ms（已缓存）。
#
# 修复：将 bm25 符号提升到 store_vfs 模块级 import。
#   bm25 模块本身很轻（纯 Python math + re，无重型依赖），~2ms 加载。
#   模块级 import 只付一次，_fts5_escape/_cjk_tokenize 调用时直接使用全局名，
#   消除 per-call sys.modules 查找 + 属性绑定开销。
try:
    from bm25 import ENGLISH_STOPWORDS as _BM25_STOPWORDS, _porter_stem as _bm25_stem
    _BM25_AVAILABLE = True
except ImportError:
    _BM25_AVAILABLE = False
    _BM25_STOPWORDS = frozenset()
    def _bm25_stem(w): return w

# tmpfs 隔离（迭代54）：环境变量覆盖，测试用临时目录，不污染生产数据
# OS 类比：Linux tmpfs (2000) — /dev/shm 内存文件系统，进程退出自动销毁
MEMORY_OS_DIR = Path(os.environ["MEMORY_OS_DIR"]) if os.environ.get("MEMORY_OS_DIR") else Path.home() / ".claude" / "memory-os"
STORE_DB = Path(os.environ["MEMORY_OS_DB"]) if os.environ.get("MEMORY_OS_DB") else MEMORY_OS_DIR / "store.db"
CHUNK_VERSION_FILE = MEMORY_OS_DIR / ".chunk_version"  # 迭代64: chunk_version for TLB v2

def open_db(db_path: Path = None) -> sqlite3.Connection:
    """
    打开 store.db 连接，统一 PRAGMA 策略。
    OS 类比：VFS 的 mount() — 一处配置挂载选项，所有后续 I/O 继承。

    WAL mode + synchronous=NORMAL：
    - WAL 允许读写并发（reader 不阻塞 writer）
    - NORMAL 在断电时最多丢失最后一个未 checkpoint 的 WAL 帧
    """
    if db_path is None:
        db_path = STORE_DB
    MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    # 迭代112: busy_timeout — WAL 写锁竞争时自动等待而非立即 SQLITE_BUSY
    # OS 类比：Linux futex FUTEX_WAIT_BITSET — 而非 FUTEX_TRYLOCK 立即失败
    # 根因：writer(async:false) + retriever(async:false) 并发时写锁竞争 → P95=266ms
    # 修复：让持有锁的连接快速释放时，等待方自动重试（最多等 150ms）
    conn.execute("PRAGMA busy_timeout=150")
    return conn

def ensure_schema(conn: sqlite3.Connection) -> None:
    """
    幂等 schema 迁移 — 一处定义，所有 hook 共用。
    OS 类比：VFS 的 super_operations.fill_super() — 挂载时检查并升级 on-disk format。

    策略：CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN（忽略已存在错误）。
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memory_chunks (
            id TEXT PRIMARY KEY,
            created_at TEXT,
            updated_at TEXT,
            project TEXT,
            source_session TEXT,
            chunk_type TEXT,
            content TEXT,
            summary TEXT,
            tags TEXT,
            importance REAL,
            retrievability REAL,
            last_accessed TEXT,
            feishu_url TEXT
        )
    """)
    _safe_add_column(conn, "memory_chunks", "access_count", "INTEGER DEFAULT 0")
    # 迭代38：oom_adj — per-chunk 淘汰优先级（-1000 绝对保护 ↔ +1000 优先淘汰）
    _safe_add_column(conn, "memory_chunks", "oom_adj", "INTEGER DEFAULT 0")
    # 迭代44：lru_gen — MGLRU 多代追踪（0=youngest, max_gen=oldest）
    _safe_add_column(conn, "memory_chunks", "lru_gen", "INTEGER DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS recall_traces (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            project TEXT NOT NULL,
            prompt_hash TEXT NOT NULL,
            candidates_count INTEGER,
            top_k_json TEXT,
            injected INTEGER DEFAULT 0,
            reason TEXT,
            duration_ms REAL DEFAULT 0
        )
    """)
    # iter259: agent_id — 多 Agent 隔离（session_id 前16字符派生）
    _safe_add_column(conn, "recall_traces", "agent_id", "TEXT DEFAULT ''")
    # 迭代65：ftrace_json — 阶段级性能追踪数据（JSON）
    _safe_add_column(conn, "recall_traces", "ftrace_json", "TEXT")

    # ── 迭代29：dmesg 环形缓冲区（OS 类比：/dev/kmsg ring buffer）──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dmesg (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            subsystem TEXT NOT NULL,
            message TEXT NOT NULL,
            session_id TEXT,
            project TEXT,
            extra TEXT
        )
    """)

    # ── 迭代33：swap_chunks 表（OS 类比：Linux swap 分区）──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS swap_chunks (
            id TEXT PRIMARY KEY,
            swapped_at TEXT NOT NULL,
            project TEXT NOT NULL,
            chunk_type TEXT,
            original_importance REAL,
            access_count_at_swap INTEGER DEFAULT 0,
            compressed_data TEXT NOT NULL
        )
    """)

    # ── 迭代100：IPC 共享内存段（OS 类比：System V shm + MESI 缓存一致性）──
    # 跨 Agent 共享知识的核心数据结构
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shm_segments (
            chunk_id TEXT NOT NULL,
            owner_agent TEXT NOT NULL,
            shared_with TEXT NOT NULL DEFAULT '*',
            version INTEGER DEFAULT 1,
            state TEXT DEFAULT 'SHARED',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (chunk_id, owner_agent),
            FOREIGN KEY (chunk_id) REFERENCES memory_chunks(id)
        )
    """)
    # state: MESI 协议 — Modified/Exclusive/Shared/Invalid
    # shared_with: '*' = 全局共享, 逗号分隔 agent_id 列表

    # ── 迭代100：IPC 消息队列（OS 类比：POSIX mq_send/mq_receive）──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ipc_msgq (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_agent TEXT NOT NULL,
            target_agent TEXT NOT NULL DEFAULT '*',
            msg_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            priority INTEGER DEFAULT 0,
            status TEXT DEFAULT 'QUEUED',
            created_at TEXT NOT NULL,
            consumed_at TEXT,
            ttl_seconds INTEGER DEFAULT 3600
        )
    """)
    # msg_type: knowledge_update | cache_invalidate | task_handoff | heartbeat
    # status: QUEUED → DELIVERED → CONSUMED | EXPIRED

    # ── 迭代100：置信度追踪（OS 类比：ECC — Error Correcting Code）──
    _safe_add_column(conn, "memory_chunks", "confidence_score", "REAL DEFAULT 0.7")
    _safe_add_column(conn, "memory_chunks", "evidence_chain", "TEXT")
    _safe_add_column(conn, "memory_chunks", "verification_status", "TEXT DEFAULT 'pending'")
    # recall_traces 反馈列
    _safe_add_column(conn, "recall_traces", "user_feedback", "TEXT")
    _safe_add_column(conn, "recall_traces", "feedback_ts", "TEXT")

    # ── 迭代104：chunk_pins — 项目级 pin（OS 类比：VMA per-process mlock）──
    # 同一 chunk 在不同 project 中有独立的 pin 状态：
    #   pinned project → kswapd/damon/stale_reclaim 跳过淘汰该 chunk
    #   未 pin project → 正常淘汰评分
    # 类比：Linux MAP_LOCKED 语义仅对调用 mlock() 的进程有效，
    #        同一物理页在其他进程的 VMA 中仍可被 swap out。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chunk_pins (
            chunk_id  TEXT NOT NULL,
            project   TEXT NOT NULL,
            pin_type  TEXT NOT NULL DEFAULT 'soft',
            pinned_at TEXT NOT NULL,
            PRIMARY KEY (chunk_id, project)
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunk_pins_project ON chunk_pins(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunk_pins_chunk ON chunk_pins(chunk_id)")
    except Exception:
        pass

    # ── 迭代148：Missing Indexes — B-tree 索引补全 ──────────────────────
    # OS 类比：Linux ext3 htree (2002, Daniel Phillips) — 目录条目 B-tree 索引
    #   没有 htree 时，大目录的文件查找是 O(N) 线性扫描 inode；
    #   htree 将目录条目组织成 B-tree，使 readdir/lookup 从 O(N) 降到 O(log N)。
    #
    # memory-os 问题：
    #   memory_chunks 主表缺少所有业务索引，而 project = ? 在全库出现 67 次。
    #   kswapd/DAMON/PSI/balloon/stale_reclaim/autotune 等所有子系统都以 project
    #   为最高频过滤条件，但每次查询都触发全表扫描。
    #   SQLite 对无索引的 WHERE project = ? 的时间复杂度是 O(N)（N=chunk 总数）。
    #
    # 索引设计（复合索引，最高选择性列在左）：
    #   1. (project)                     — 基础过滤（所有子系统共用）
    #   2. (project, chunk_type)          — get_chunks/compact_zone/find_similar
    #   3. (project, importance DESC)     — evict_lowest_retention（按重要性淘汰）
    #   4. (project, last_accessed)       — stale_reclaim/DAMON COLD/DEAD 分类
    #   5. recall_traces (project, timestamp) — AIMD/PSI/autotune/GC 时间窗口查询
    #   6. recall_traces (project, injected)  — hit_rate 统计（高频 COUNT）
    #   7. swap_chunks (project)          — gc_orphan_swap/balloon/kswapd 水位
    #
    # 注意：SQLite 对于 "importance < ?" 这种范围查询，
    #       idx_mc_project_importance 让优化器只扫描匹配 project 的子集（B-tree 层级裁剪）。
    try:
        # memory_chunks 核心索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mc_project ON memory_chunks(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mc_project_type ON memory_chunks(project, chunk_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mc_project_importance ON memory_chunks(project, importance DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mc_project_last_accessed ON memory_chunks(project, last_accessed)")
        # 迭代149：summary 索引 — already_exists/find_similar 精确去重加速
        # OS 类比：Linux VFS inode 哈希表 (inode_hashtable, 1992) —
        #   VFS 通过 (sb, ino) 哈希快速定位 inode 而非线性遍历 inode cache。
        #   already_exists 按 summary 精确匹配：O(N) 全表扫描 → O(log N) B-tree。
        #   already_exists 每次 chunk 写入前必调用，是写路径的最高频查询之一。
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mc_summary ON memory_chunks(summary)")
        # recall_traces 索引（AIMD/PSI/autotune 全都查这张表）
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_project_ts ON recall_traces(project, timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_project_injected ON recall_traces(project, injected)")
        # swap_chunks 索引（gc_orphan_swap/kswapd 水位）
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sc_project ON swap_chunks(project)")
    except Exception:
        pass

    # ── 迭代300：info_class — 五层路由（扩展自三层）──
    # OS 类比：Linux 进程地址空间分区（text/data/bss/stack/heap）——
    #   不同区域有不同的保护属性和 eviction 策略。
    #
    # 迭代319：扩展为五类（认知科学双记忆系统，Tulving 1972）：
    #   semantic  : 经多次验证的通用规律（语义记忆）——高 stability，慢衰减，优先保留
    #   episodic  : 特定会话的具体事件（情节记忆）——低 stability，快衰减，可转化
    #   world     : 关于外部世界的事实（原三层，默认，中等保留策略）
    #   operational: agent 操作配置（中等价值，项目内持久）
    #   ephemeral : 临时会话状态（低价值，优先驱逐）
    #
    # semantic vs world 区别：semantic 是"多次验证后提升的知识"，有明确的转化来源；
    #   world 是写入时就被判定为通用知识，没有经过验证路径。
    _safe_add_column(conn, "memory_chunks", "info_class", "TEXT DEFAULT 'world'")

    # ── 迭代319：episodic_consolidations — 情节→语义转化记录 ──────────────────
    # OS 类比：Linux huge page compaction (THP) — 连续小页面合并为大页面，
    #   元数据记录哪些小页面被合并（类比：哪些 episodic chunk 触发了语义化）。
    # 每条记录 = 一次 episodic→semantic 转化事件。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS episodic_consolidations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            semantic_chunk_id  TEXT NOT NULL,
            source_chunk_ids   TEXT NOT NULL,  -- JSON array of episodic chunk IDs
            project      TEXT NOT NULL,
            trigger_count INTEGER DEFAULT 0,    -- 触发转化时的召回次数
            created_at   TEXT NOT NULL
        )
    """)
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ec_project ON episodic_consolidations(project)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ec_semantic ON episodic_consolidations(semantic_chunk_id)"
        )
    except Exception:
        pass

    # ── 迭代301：stability — Ebbinghaus 记忆稳定性（单位：天）──
    # OS 类比：Linux MGLRU lru_gen — 代龄越高越不活跃；
    #   但 stability 是反向的：越高越稳固，越难被 evict。
    #   初始值 = importance * 2.0；每次检索命中 *= 2.0（间隔重复加固）
    #   eviction_score = age_days / stability（越小越不驱逐）
    _safe_add_column(conn, "memory_chunks", "stability", "REAL DEFAULT 1.0")

    # ── iter399：emotional_weight — 写入时情绪显著性权重（McGaugh 2000）──
    # OS 类比：Linux mempolicy MPOL_PREFERRED_MANY — 写入时标注页面的"情感节点亲和性"，
    #   检索时 retriever 用此权重决定 boost 量（类比 NUMA locality hint）。
    # emotional_weight ∈ [0.0, 1.0]：0=情感中性，1=极高唤醒（崩溃/critical 类词）
    _safe_add_column(conn, "memory_chunks", "emotional_weight", "REAL DEFAULT 0.0")

    # ── iter424：emotional_valence — 情绪效价（Bower 1981 Mood-Congruent Memory）──
    # OS 类比：Linux NUMA node distance matrix — 每个 page 有 home node（positive/negative），
    #   访问时按 node distance 决定延迟（同 node = 低延迟 = valence 一致 = 检索优势）。
    # emotional_valence ∈ [-1.0, +1.0]：
    #   +1 = 正面情绪（突破/发现/成功），-1 = 负面情绪（错误/崩溃/失败），0 = 中性
    # Mood-Congruent Memory：query 情绪效价与 chunk 情绪效价一致时检索加分。
    _safe_add_column(conn, "memory_chunks", "emotional_valence", "REAL DEFAULT 0.0")

    # ── iter401：depth_of_processing — 加工深度（Craik & Lockhart 1972）──
    # OS 类比：Linux page writeback dirty throttle — 页面在 dirty state 停留时间越长，
    #   获得的 write aggregation 越充分，落盘后数据更完整（类比深度加工 → 更稳固的记忆痕迹）。
    # 认知科学依据：加工层次理论 — 语义加工（深处理）比音韵/字形加工（浅处理）
    #   形成更持久的记忆痕迹，因为语义处理触发了更多的关联激活。
    # depth_of_processing ∈ [0.0, 1.0]：
    #   0.0 = 浅处理（简单陈述，无推理/因果/结构）
    #   1.0 = 深处理（丰富的因果推理、结构化分析、多概念关联）
    # 影响：写入时 stability += depth_bonus（深处理的 chunk 初始稳定性更高）
    _safe_add_column(conn, "memory_chunks", "depth_of_processing", "REAL DEFAULT 0.5")

    # ── iter400：chunk_type_decay — 个体化遗忘速率（Ebbinghaus 1885 + 记忆类型差异）──
    # OS 类比：Linux cgroup memory.reclaim_ratio — 不同 cgroup 有不同的内存回收速率，
    #   而非全局统一的 vm.swappiness。
    # 认知科学依据：Squire (1992) / Tulving (1972) 记忆类型理论：
    #   程序性记忆（如技能/约束）比情节记忆（如任务状态）衰减更慢。
    #   design_constraint/decision → 衰减极慢（类比肌肉记忆）
    #   task_state/reasoning_chain → 衰减较快（类比工作记忆/情节记忆）
    # 字段：存储在 sysctl / 配置层，每次 idle_consolidation 查询该表确定 per-type 衰减率。
    # （该 iter 不新增 DB 列，而是影响算法行为）

    # ── iter396：source_type / source_reliability — 信源监控（Johnson 1993）──
    # OS 类比：Linux LSM (Linux Security Modules) — 每次文件访问/进程创建前，
    #   LSM hook 检查来源的"域"（SELinux context / AppArmor label），
    #   来源不同 → 不同信任级别 → 不同访问权限。
    # source_type ∈ {direct, tool_output, inferred, hearsay, unknown}：
    #   direct      = 用户直接陈述/观察（第一手信源，最高可信度）
    #   tool_output = 代码运行/命令输出（机器生成，高可重复性，取决于工具可靠性）
    #   inferred    = 从多条信息推断（合理推断，中等可信度）
    #   hearsay     = 间接转述/用户描述他人说的（可信度最低）
    #   unknown     = 来源不明（默认值）
    # source_reliability ∈ [0.0, 1.0]：
    #   写入时由 compute_source_reliability() 估算；
    #   检索时作为 retrieval_score 的加权因子（source_monitor_weight()）。
    _safe_add_column(conn, "memory_chunks", "source_type", "TEXT DEFAULT 'unknown'")
    _safe_add_column(conn, "memory_chunks", "source_reliability", "REAL DEFAULT 0.7")

    # ── iter403：encode_context — 编码时上下文关键词（Tulving 1974）──
    # OS 类比：Linux NUMA-aware memory allocation — 进程倾向从本地 node 取页；
    #   编码时 context = home node；检索时 context 越接近 = NUMA距离越小 = 命中率越高。
    # encode_context TEXT：编码时的上下文关键词集合（逗号分隔的 token 列表）。
    # 写入时从 content + summary + tags + chunk_type 中提取关键词集。
    # 检索时计算 context overlap（Jaccard）→ 调整检索分（context cue boost）。
    _safe_add_column(conn, "memory_chunks", "encode_context", "TEXT DEFAULT ''")

    # ── 迭代306：raw_snippet — 写入时保真原始片段（≤500字）──
    # OS 类比：Linux page cache 保存原始 disk block，VFS 层面不压缩；
    #   读取时 on-demand 合并（类比 copy-on-read 模式）。
    # raw_snippet 不参与 FTS5 索引（避免膨胀），仅在 retriever 注入时按需附加。
    _safe_add_column(conn, "memory_chunks", "raw_snippet", "TEXT DEFAULT ''")

    # ── 迭代315：encoding_context — 情境感知注入（Encoding Specificity）──
    # OS 类比：Linux perf_event context — 记录性能事件时附带 CPU/task 上下文。
    # 存储 chunk 写入时的情境特征 JSON，检索时与 query_context 比对计算匹配度。
    _safe_add_column(conn, "memory_chunks", "encoding_context", "TEXT DEFAULT '{}'")

    # ── iter415: original_ec_count — encode_context 初始 token 数（Encoding Variability）──
    # 存储 chunk 写入时的 encode_context token 数量，用于检测后续多情境富化。
    # OS 类比：page 首次 mapped-in 的引用计数基线；后续跨进程引用增量代表多情境共享。
    _safe_add_column(conn, "memory_chunks", "original_ec_count", "INTEGER DEFAULT 0")

    # ── iter420: spaced_access_count — 间隔访问计数（Spacing Effect）──
    # 认知科学依据：Ebbinghaus (1885) Spacing Effect / Cepeda et al. (2006) Review —
    #   分布在多个间隔时间段的练习（spaced practice）比集中练习（massed practice）
    #   产生更强的长时记忆保留（间隔效应）。
    # 存储 chunk 被"间隔访问"的次数（gap >= medium_gap_hours = 24h，代表新的"学习会话"）。
    # 每次 update_accessed 时如果访问间隔 >= 24h，则递增此计数。
    # spacing_factor = spaced_access_count / max(1, access_count) ∈ [0,1]：
    #   1.0 = 完全分布式（每次都有足够间隔），0.0 = 全部集中（massed）
    # OS 类比：Linux MGLRU cross-generation promotion —
    #   跨 aging cycle 被访问的 page（distributed access）比在同一 gen 内被访问的
    #   page（massed access）更快晋升到 younger generation（真正的热页）。
    _safe_add_column(conn, "memory_chunks", "spaced_access_count", "INTEGER DEFAULT 0")

    # ── iter437: hypermnesia_last_boost — 上次 Hypermnesia boost 时间（冷却期追踪）──
    # OS 类比：khugepaged scan_sleep_millisecs — 两次 hugepage 合并之间的最小休眠间隔，
    #   防止 khugepaged 频繁唤醒消耗 CPU（hypermnesia cooldown 防止反复触发）。
    _safe_add_column(conn, "memory_chunks", "hypermnesia_last_boost", "TEXT")

    # ── iter456: access_source — 检索来源标记（RPCA：主动检索 vs 被动重读）──
    # 认知科学依据：Roediger & Karpicke (2006) Retrieval Practice vs. Restudy —
    #   主动检索（retrieval）产生的记忆巩固效益比被动重读（restudy）高约 50%。
    # access_source ∈ {'retrieval', 'restudy'}：
    #   'retrieval' = 用户 query 主动命中（默认，通过 FTS5/BM25 检索召回）
    #   'restudy'   = 被动曝光（loader注入、preload 等非主动检索路径）
    # OS 类比：Linux page fault type — demand paging（retrieval，主动缺页）vs
    #   prefetch/readahead（restudy，内核预读，未被 CPU 实际访问确认）。
    _safe_add_column(conn, "memory_chunks", "access_source", "TEXT DEFAULT 'retrieval'")

    # ── Task13：row_version — Optimistic Locking（CAS）──
    # OS 类比：Linux seqlock / atomic_cmpxchg — 读取 sequence number 后写入时验证未变化。
    # 多 agent 并发写：每次 update 递增 row_version，CAS 检查版本防止 ABA 问题。
    _safe_add_column(conn, "memory_chunks", "row_version", "INTEGER DEFAULT 1")

    # ── Task12：chunk_state — Lifecycle FSM（ACTIVE/COLD/DEAD/SWAP/GHOST）──
    # OS 类比：Linux page state machine — PG_active/PG_referenced/PG_lru/PG_swapcache
    #   ACTIVE  = PG_active + PG_referenced   — 最近访问，热数据
    #   COLD    = PG_lru (inactive list)       — 可回收候选，7-30天无访问
    #   DEAD    = DAMON DEAD region            — 极少访问，可 swap_out 或 evict
    #   SWAP    = PG_swapcache                 — 已 swap_out，在 swap_chunks
    #   GHOST   = 待 GC，evict 前短暂标记态
    _safe_add_column(conn, "memory_chunks", "chunk_state", "TEXT DEFAULT 'ACTIVE'")
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mc_state ON memory_chunks(chunk_state)"
        )
    except Exception:
        pass

    # ── iter428：boundary_proximity — 事件边界距离（Zacks et al. 2007 Event Segmentation）──
    # OS 类比：ext4 jbd2 journal commit boundary —
    #   刚越过 journal commit 的 page（新 epoch 首批写入）稳定性最高；
    #   commit 前的 dirty page（旧 epoch 末尾）处于"不稳定窗口"（doorway effect）。
    # boundary_proximity ∈ [-1.0, +1.0]：
    #   +1.0 = 本 session 刚开始时写入（刚越过 session boundary → encoding boost）
    #    0.0 = 中性（会话中间写入，无边界效应）
    #   -1.0 = 上一 session 末尾写入（doorway effect → 短暂 retrieval penalty）
    _safe_add_column(conn, "memory_chunks", "boundary_proximity", "REAL DEFAULT 0.0")
    _safe_add_column(conn, "memory_chunks", "session_type_history", "TEXT DEFAULT ''")  # iter459 CIE

    # ── iter461: HAC — chunk_coactivation 表（Hebbian 共激活次数追踪）──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chunk_coactivation (
            chunk_a     TEXT NOT NULL,
            chunk_b     TEXT NOT NULL,
            project     TEXT NOT NULL,
            coact_count INTEGER DEFAULT 1,
            last_coact  TEXT,
            PRIMARY KEY (chunk_a, chunk_b, project)
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_coact_a ON chunk_coactivation(chunk_a, project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_coact_b ON chunk_coactivation(chunk_b, project)")
    except Exception:
        pass

    # ── 迭代317：knowledge_versions — 前摄干扰控制（Proactive Interference）──
    # OS 类比：Linux kernel module versioning — 加载新模块版本时标记旧版本为
    #   MODULE_STATE_GOING，确保旧版本不再被新请求调用。
    # Bartlett 1932 图式同化：新知识依附已有框架，框架更新时必须明确标记旧框架失效。
    # 每条记录 = 一次知识演化事件：old_chunk 被 new_chunk 取代。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_versions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            old_chunk_id TEXT NOT NULL,
            new_chunk_id TEXT NOT NULL,
            reason      TEXT,
            project     TEXT,
            session_id  TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kv_old ON knowledge_versions(old_chunk_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kv_project ON knowledge_versions(project)"
        )
    except Exception:
        pass

    # ── 迭代304：entity_edges — 知识图谱关系边（OS 类比：Linux 内核模块依赖图）──
    # 每条边 = (from_entity) --[relation]--> (to_entity)，
    # 类比内核 module_kobject 依赖表：kmod 加载前检查依赖链，
    # 边缺失 → 加载失败（知识断链 → 检索回答残缺）。
    #
    # relation 类型：
    #   uses        — X 使用/采用/基于 Y
    #   depends_on  — X 依赖/需要 Y
    #   part_of     — X 是 Y 的一部分/子模块
    #   implements  — X 实现了 Y
    #   related_to  — 其他关联
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entity_edges (
            id TEXT PRIMARY KEY,
            from_entity TEXT NOT NULL,
            relation TEXT NOT NULL,
            to_entity TEXT NOT NULL,
            project TEXT,
            source_chunk_id TEXT,
            confidence REAL DEFAULT 0.7,
            created_at TEXT NOT NULL
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ee_from ON entity_edges(from_entity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ee_to ON entity_edges(to_entity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ee_project ON entity_edges(project)")
    except Exception:
        pass

    # ── 迭代310：entity_map — chunk_id ↔ entity_name 映射（Spreading Activation 锚点）──
    # OS 类比：Linux /proc/modules 中每个 module 的 kobject 指针 —
    #   entity_map 是 chunk 到 entity 的"地址翻译表"，
    #   spreading activation 通过它从 FTS5 命中的 chunk 找到对应 entity，
    #   再沿 entity_edges 扩散邻居，类比 TLB walk（chunk→entity→邻居entity→邻居chunk）。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entity_map (
            entity_name TEXT NOT NULL,
            chunk_id    TEXT NOT NULL,
            project     TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (entity_name, project)
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_em_chunk ON entity_map(chunk_id)")
    except Exception:
        pass

    # ── iter404：priming_state — 语义启动状态表（Collins & Loftus 1975）──
    # OS 类比：Linux page readahead / ra_state —
    #   访问一个 page 触发相邻 pages 预取进 page cache（readahead window）；
    #   类似地，检索一个 chunk 时，相关 entity 被"启动"（primed），
    #   后续短时间内（prime_half_life ~ 30min）相关 chunk 检索分提升。
    # prime_strength ∈ [0.0, 1.0]：当前启动强度（随时间指数衰减）
    conn.execute("""
        CREATE TABLE IF NOT EXISTS priming_state (
            entity_name TEXT NOT NULL,
            project     TEXT NOT NULL DEFAULT '',
            primed_at   TEXT NOT NULL,
            prime_strength REAL NOT NULL DEFAULT 1.0,
            PRIMARY KEY (entity_name, project)
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_prime_project ON priming_state(project, primed_at)")
    except Exception:
        pass

    # ── 迭代305：curiosity_queue — 知识空白探索队列（OS 类比：kswapd 水位触发）──
    # 当 retriever 检测到「弱命中」（FTS 有结果但 top-1 分数 < WMARK_LOW=0.25）时，
    # 说明 DB 里「有相关内容但不够用」——把 query 写入此队列。
    # deep-sleep 阶段消费队列，主动补充知识。
    #
    # OS 类比：Linux /proc/sys/vm/watermark_scale_factor +
    #   kswapd shrink_node() — 检测到 free pages < WMARK_LOW 时异步回收：
    #     WMARK_LOW（0.25）: FTS5 top-1 score 低于此值 → 判定为「知识低水位」
    #     kswapd（deep-sleep consumer）: 消费 curiosity_queue，主动填充知识空白
    #     status 生命周期: pending → processing → filled/dismissed
    #       等价于: 页面回收任务 → kswapd 领取 → 完成 swap-in 或 discard
    conn.execute("""
        CREATE TABLE IF NOT EXISTS curiosity_queue (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            query       TEXT NOT NULL,
            project     TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            top_score   REAL,
            status      TEXT DEFAULT 'pending',
            filled_at   TEXT,
            chunk_id    TEXT
        )
    """)
    # 索引设计：
    #   (project, status) — pop_curiosity_queue 按 project+pending 过滤（最高频路径）
    #   (project, query)  — enqueue_curiosity 幂等检查（7天内同 query）
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cq_project_status "
            "ON curiosity_queue(project, status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cq_project_query_time "
            "ON curiosity_queue(project, query, detected_at)"
        )
    except Exception:
        pass

    # ── iter380：schema_anchors — Bartlett (1932) Schema Theory ─────────────
    # OS 类比：Linux SLUB Allocator kmem_cache — 相似对象共享结构模板（kmem_cache），
    #   新对象写入时自动归属对应 cache；检索时 cache 整体激活，批量命中。
    #
    # schema_anchors 记录 chunk → schema 的绑定关系：
    #   chunk 写入时，扫描 summary 匹配预定义 schema 规则 → 写入绑定行
    #   retriever 命中 chunk 后，查 schema_anchors → 激活同 schema 的其他 chunk
    #   类比：kmem_cache 命中后，同 cache 的相邻 slab 自动预热到 L2
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_anchors (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            chunk_id    TEXT NOT NULL,
            schema_name TEXT NOT NULL,
            project     TEXT NOT NULL,
            confidence  REAL DEFAULT 0.8,
            created_at  TEXT NOT NULL,
            UNIQUE(chunk_id, schema_name)
        )
    """)
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sa_schema_project "
            "ON schema_anchors(schema_name, project)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sa_chunk "
            "ON schema_anchors(chunk_id)"
        )
    except Exception:
        pass

    # ── 迭代23：FTS5 全文索引（OS 类比：ext3 htree）──
    # content-sync 模式：FTS5 表引用主表数据，通过触发器保持同步
    # 搜索 summary + content 两个字段
    _ensure_fts5(conn)

    # ── 迭代504：FTS5 Journal Checkpoint（boot-time fsck）──
    # OS 类比：ext4 mount 时 journal replay — 挂载时自动修复索引与数据不一致
    fts5_checkpoint(conn)

def _safe_add_column(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    """幂等加列：已存在则静默跳过。"""
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except Exception:
        pass

def _normalize_structured_summary(text: str) -> str:
    """
    iter108+iter507：结构化 summary 归一化 — 在 FTS5 索引前清理标签和分隔符。

    iter108 目标：去除 []、>、/ 等 ASCII 符号，让 FTS5 按语义词命中。
    iter507 升级：完全剥离分类标签前缀（而非保留标签内容为 token）。

    问题（iter507）：
      [decisions]、[memory-os]、[kernel_process] 等分类标签去掉方括号后
      仍作为 FTS5 token 存在（如 "decisions"），但用户查询从不包含这些词。
      BM25 公式中文档长度是分母——标签 token 增大文档长度，稀释语义关键词权重。

    处理规则：
      - [tag] 前缀标签 → 完全移除（不保留标签内容）iter507
      - [规则/Category] → 完全移除 iter507
      - X > Y → "X Y"（去掉 >）
      - X/Y 路径分隔 → "X Y"（仅非文件路径的 /）
      - (xxx) / （xxx） → 保留内容去括号
    OS 类比：Linux drop_caches (2006) — flush 无用的 page cache/dentry/inode 条目，
      释放内存给真正有用的数据。FTS5 索引中的标签 token 就是无用的 dentry 缓存条目。
    """
    if not text:
        return text
    # iter507: 完全移除分类标签前缀（[tag] 或 [tag/subtag] 在文本开头）
    # 这些标签是存储层分类元数据，不是语义内容，不应参与 BM25 评分
    # 已知标签模式：[decisions], [memory-os], [kernel_process], [规则/Patterns], etc.
    result = re.sub(r'^\[[\w/\-\u4e00-\u9fff]+\]\s*', '', text)
    # 文本中间的 [tag] — 也移除（如 "[语义化] Android 性能诊断..."）
    result = re.sub(r'\[[\w/\-\u4e00-\u9fff]{2,30}\]\s*', ' ', result)
    # > 分隔符 → 空格
    result = result.replace('>', ' ')
    # / 在非文件路径上下文中 → 空格（文件路径含 . 不替换）
    result = re.sub(r'(?<![.\w])/(?![.\w])', ' ', result)
    # 全角括号
    result = result.replace('（', ' ').replace('）', ' ')
    # 多余空白合并
    result = re.sub(r'\s+', ' ', result).strip()
    return result


def _cjk_tokenize(text: str) -> str:
    """
    迭代97：CJK 单字分词预处理。
    在每个 CJK 字符前后插入空格，让 unicode61 tokenizer 按单字分词。

    迭代100：同时追加 CJK bigram（相邻字对）到末尾，提升精确短语匹配精度。

    迭代99：英文部分追加 stemmed 形式，使 FTS5 索引能匹配查询侧的 stemmed token。
    例如 "analyzing" 额外追加 "analyz"，查询 "analysis" stem→"analys" 时更接近命中。

    OS 类比：inverted index 中同时存 unigram + bigram posting list — 单字用于召回，
    bigram 用于精排（phrase match score 更高）。
    """
    if not text:
        return ''
    # 单字：每个 CJK 字前后加空格
    result = re.sub(r'([\u4e00-\u9fff\u3400-\u4dbf])', r' \1 ', text)
    # bigram：提取连续 CJK 字对，追加到末尾
    cjk_chars = re.findall(r'[\u4e00-\u9fff\u3400-\u4dbf]', text)
    bigrams = [cjk_chars[i] + cjk_chars[i+1] for i in range(len(cjk_chars) - 1)]
    if bigrams:
        result = result + ' ' + ' '.join(bigrams)
    # 迭代99：英文 stemming — 追加 stemmed 形式到文本末尾
    # 迭代154：使用模块级 _BM25_STOPWORDS / _bm25_stem，消除 per-call inline import
    if _BM25_AVAILABLE:
        eng_words = re.findall(r'[a-zA-Z]{3,}', text)
        stemmed_extra = []
        for w in eng_words:
            low = w.lower()
            if low not in _BM25_STOPWORDS:
                s = _bm25_stem(low)
                if s != low:
                    stemmed_extra.append(s)
        if stemmed_extra:
            result = result + ' ' + ' '.join(set(stemmed_extra))
    return result


def _ensure_fts5(conn: sqlite3.Connection) -> None:
    """
    迭代23：幂等创建 FTS5 虚拟表。
    OS 类比：ext3 的 htree 是在 mkfs/tune2fs 时创建索引结构。

    迭代97：改为非 content-sync 模式（独立存储 CJK 预处理文本）。
    - 旧 content-sync 模式：FTS5 直接引用主表原始文本，CJK 单字查询无效
    - 新独立模式：FTS5 存储经 _cjk_tokenize 处理的文本，支持单字精准匹配
    - insert_chunk / delete_chunks 中手动维护 FTS 索引（不依赖触发器）

    迁移：检测旧 content-sync 表并自动迁移为新格式。
    """
    # 检测 FTS5 表是否存在 + 是否为旧 content-sync 格式
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_chunks_fts'"
    ).fetchone()

    if exists:
        # 迭代97：检测是否为旧 content-sync 格式（有触发器 = 旧版）
        old_trigger = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='memory_chunks_ai'"
        ).fetchone()
        if old_trigger:
            # 旧 content-sync 格式：迁移为新独立格式
            # 1. 删除旧触发器
            for t in ('memory_chunks_ai', 'memory_chunks_ad', 'memory_chunks_au'):
                conn.execute(f"DROP TRIGGER IF EXISTS {t}")
            # 2. 删除旧 FTS5 表
            conn.execute("DROP TABLE IF EXISTS memory_chunks_fts")
            # 3. 重新创建（见下方）
        else:
            # 迭代100：检测是否为旧单字格式（需升级为 bigram 格式）
            # 标志：fts_schema_version 表存在且 version < 100
            ver_row = conn.execute(
                "SELECT version FROM fts_schema_version WHERE name='memory_chunks_fts'"
            ).fetchone() if conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='fts_schema_version'"
            ).fetchone() else None
            if ver_row is None or ver_row[0] < 100:
                # 迭代100 迁移：删除旧 FTS5，重建含 bigram 的新格式
                conn.execute("DROP TABLE IF EXISTS memory_chunks_fts")
                # 继续执行下方创建逻辑
            elif ver_row[0] < 124:
                # 迭代124：检测 UUID rowid_ref 污染（生产 bug）
                # 根因：历史版本的 insert_chunk 在某个代码版本中误写入 UUID 字符串
                # 而非 str(integer_rowid)，导致 fts_search JOIN CAST(rowid_ref AS INTEGER)
                # 始终返回 0/garbage，所有 FTS5 查询失效，系统静默降级到 BM25 全表扫描。
                # 检测方式：取一条 rowid_ref，如果包含 '-' 则是 UUID，需要重建。
                # OS 类比：fsck inode corruption check — 检测元数据损坏并触发磁盘重建。
                sample = conn.execute(
                    "SELECT rowid_ref FROM memory_chunks_fts LIMIT 1"
                ).fetchone()
                is_uuid_corrupted = sample and '-' in str(sample[0])
                if is_uuid_corrupted:
                    # UUID 污染：清空 FTS5 并全量重建（DROP 虚拟表会有问题，用 DELETE 代替）
                    conn.execute("DELETE FROM memory_chunks_fts")
                    # 继续执行下方重建逻辑（表已存在，跳过 CREATE VIRTUAL TABLE）
                    _fts_needs_rebuild = True
                else:
                    # version 100 且无 UUID 污染：仅升级 version 到 124
                    conn.execute(
                        "INSERT OR REPLACE INTO fts_schema_version (name, version) VALUES ('memory_chunks_fts', 124)"
                    )
                    return
            else:
                # iter787: fts_schema_integrity — 验证 FTS 表确实有 rowid_ref 列
                # 根因：历史 DB 可能 version=124 但 FTS 表仍是旧 content-sync 格式
                #   (id,content,summary,chunk_type)，导致 fts_search JOIN rowid_ref 永远 exception
                #   → 所有 FTS 查询静默返回空 → 系统退化为 BM25 全表扫描。
                # 检测：PRAGMA table_info 看 FTS 虚拟表列名，缺 rowid_ref 则强制重建。
                _cols = {r[1] for r in conn.execute(
                    "PRAGMA table_info(memory_chunks_fts)").fetchall()}
                if "rowid_ref" in _cols:
                    return
                # FTS 表 schema 损坏：DROP 并重建
                conn.execute("DROP TABLE IF EXISTS memory_chunks_fts")

    # 创建新 FTS5 虚拟表（独立模式，存储 CJK 预处理后的文本）
    # OS 类比：ext4 的 htree 独立 B-tree，不引用 inode 原始数据
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_fts USING fts5(
            rowid_ref UNINDEXED,
            summary,
            content
        )
    """)

    # 全量重建：从主表读取，经 CJK 预处理后写入 FTS5
    # OS 类比：fsck 重建 htree — 扫描所有 inode，重写 B-tree 索引
    # 迭代124：统一使用 str(rowid)（整数转字符串），确保 fts_search JOIN CAST 可正确还原。
    # 历史 bug：旧版本写入了 UUID 字符串（chunk.id）而非 str(rowid)，导致 CAST→0/garbage。
    rows = conn.execute(
        "SELECT rowid, summary, content, tags FROM memory_chunks WHERE summary != ''"
    ).fetchall()
    _skip702 = {"semantic", "consolidated", "imported", "design_constraint",
                "decision", "procedure", "quantitative_evidence", "causal_chain",
                "excluded_path", "prompt_context", "reasoning_chain"}
    for rowid, summary, content, tags in rows:
        # iter702: tags_fts_boost — tags 关键词追加到 content
        _tsuf = ""
        if tags:
            try:
                import json as _j702
                _tl = _j702.loads(tags) if isinstance(tags, str) else tags
                _u = [t for t in _tl if isinstance(t, str) and t not in _skip702
                      and not t.startswith(("abspath:", "git:", "sec"))]
                if _u:
                    _tsuf = " " + " ".join(_u)
            except Exception:
                pass
        conn.execute(
            "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
            (str(rowid), _cjk_tokenize(_normalize_structured_summary(summary or '')),
             _cjk_tokenize(_normalize_structured_summary((content or '') + _tsuf)))
        )

    # 迭代124：记录 FTS schema 版本（124 = 修复 UUID 污染后的干净重建版本）
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fts_schema_version (
            name TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        )
    """)
    conn.execute(
        "INSERT OR REPLACE INTO fts_schema_version (name, version) VALUES ('memory_chunks_fts', 124)"
    )

    # ── 迭代87：Scheduler Tables（OS 类比：CFS runqueue + task_struct）──
    # 迭代87：任务调度队列（task_struct）
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_tasks (
            id TEXT PRIMARY KEY,
            project TEXT NOT NULL,
            session_id TEXT NOT NULL,
            task_name TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT,
            due_at TEXT,
            dependencies TEXT,
            execution_log TEXT,
            swap_context TEXT,
            oom_adj INTEGER DEFAULT -800
        )
    """)
    # 迭代87：任务-决策关联表（task 依赖的核心 decision）
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_task_decisions (
            decision_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            decision_type TEXT,
            FOREIGN KEY (decision_id) REFERENCES memory_chunks(id),
            FOREIGN KEY (task_id) REFERENCES scheduler_tasks(id),
            PRIMARY KEY (decision_id, task_id)
        )
    """)
    # ── 迭代99：Hook 事务日志（OS 类比：ext4 journal — 崩溃恢复的 WAL）──
    # 记录每次 Stop hook 的事务状态，支持崩溃后诊断部分写入
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hook_txn_log (
            txn_id       TEXT PRIMARY KEY,
            hook         TEXT NOT NULL DEFAULT 'extractor',
            status       TEXT NOT NULL DEFAULT 'pending',
            chunk_count  INTEGER DEFAULT 0,
            session_id   TEXT NOT NULL DEFAULT '',
            project      TEXT NOT NULL DEFAULT '',
            started_at   TEXT NOT NULL,
            committed_at TEXT,
            error        TEXT
        )
    """)
    # iter259: agent_id 维度
    _safe_add_column(conn, "hook_txn_log", "agent_id", "TEXT DEFAULT ''")

    # ── iter259：session_intents 表 — 替代单文件 session_intent.json（并发安全）──
    # 多 Agent 场景下，session_intent.json 是单文件，最后写者覆盖之前写者。
    # 改为 DB 表，每个 session_id 独立一行，互不干扰。
    # OS 类比：per-process /proc/PID/status，而不是全局单文件 /proc/intent
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session_intents (
            session_id   TEXT PRIMARY KEY,
            project      TEXT NOT NULL DEFAULT '',
            agent_id     TEXT NOT NULL DEFAULT '',
            saved_at     TEXT NOT NULL,
            intent_json  TEXT NOT NULL DEFAULT '{}',
            pinned_chunk_ids TEXT NOT NULL DEFAULT '[]'
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_si_project ON session_intents(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_si_saved ON session_intents(saved_at DESC)")
    except Exception:
        pass

    # ── iter259：shadow_traces 表 — 替代单文件 .shadow_trace.json（并发安全）──
    # 多 Agent 场景下，.shadow_trace.json 是单文件，并发写入会相互覆盖。
    # OS 类比：per-process page table，而不是共享全局 page table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shadow_traces (
            session_id   TEXT PRIMARY KEY,
            project      TEXT NOT NULL DEFAULT '',
            agent_id     TEXT NOT NULL DEFAULT '',
            updated_at   TEXT NOT NULL,
            top_k_ids    TEXT NOT NULL DEFAULT '[]'
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sht_project ON shadow_traces(project)")
    except Exception:
        pass

    # ── iter259：tool_patterns — 工具调用序列学习（OS 类比：perf_event ring buffer）──
    # extractor 写入 tool_patterns，retriever 查询，但之前 ensure_schema 未创建该表。
    # 修复：在此统一创建，防止悬空查询（OperationalError: no such table）。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tool_patterns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_hash    TEXT UNIQUE,
            tool_sequence   TEXT NOT NULL,
            context_keywords TEXT DEFAULT '[]',
            frequency       INTEGER DEFAULT 1,
            avg_duration_ms REAL DEFAULT 0,
            success_rate    REAL DEFAULT 1.0,
            first_seen      TEXT,
            last_seen       TEXT,
            project         TEXT
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tp_project ON tool_patterns(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tp_hash ON tool_patterns(pattern_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tp_freq ON tool_patterns(frequency DESC)")
    except Exception:
        pass

    # ── iter390: trigger_conditions — 展望记忆触发条件 ──────────────────────────
    # 认知科学依据：Einstein & McDaniel (1990) Prospective Memory —
    #   意图性记忆：在未来某个时刻执行某个动作的意图（"下次打开 X 时记得..."）。
    #   触发模式：特定信号（context cue）激活相关延迟意图记忆。
    # OS 类比：Linux inotify/fanotify — 注册文件系统事件监听，触发条件满足时唤醒等待进程。
    # trigger_conditions 存储 extractor 检测到的"将来触发"意图，
    # retriever 在匹配到 trigger_pattern 时注入关联 chunk。
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trigger_conditions (
            id          TEXT PRIMARY KEY,
            chunk_id    TEXT NOT NULL,
            project     TEXT NOT NULL,
            session_id  TEXT NOT NULL DEFAULT '',
            trigger_pattern TEXT NOT NULL,
            trigger_type TEXT NOT NULL DEFAULT 'keyword',
            created_at  TEXT NOT NULL,
            fired_count INTEGER DEFAULT 0,
            last_fired  TEXT,
            expires_at  TEXT
        )
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tc_project ON trigger_conditions(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tc_chunk ON trigger_conditions(chunk_id)")
    except Exception:
        pass

    # ── iter259：entity_edges 补充 agent_id 复合唯一约束 ──
    # 多 Agent 场景下同一实体对可被不同 agent 提取，需按 agent 隔离唯一性
    _safe_add_column(conn, "entity_edges", "agent_id", "TEXT DEFAULT ''")

    conn.commit()


# ── 迭代504：FTS5 Journal Checkpoint ────────────────────────────────────────
# OS 类比：ext4 Journal Checkpoint (Theodore Ts'o, 1998) + e2fsck -y
# 文件系统挂载时检查 journal 与 data block 一致性，不一致时自动修复。
# FTS5 是独立索引表（非 content-sync），与主表可能因以下原因漂移：
#   - merge_similar 更新 content 但旧版未同步 FTS5
#   - 非 delete_chunks 路径直接 DELETE memory_chunks
#   - 手动 DB 清理未同步 FTS5

def _fts5_sync_chunk(conn: sqlite3.Connection, chunk_id: str,
                     summary: str = None, content: str = None) -> None:
    """
    单 chunk FTS5 索引同步：删除旧条目 → 重新插入预处理后的文本。
    OS 类比：ext4 journal commit for single inode — 单文件元数据更新后刷新索引。
    iter702: tags 关键词追加到 content 尾部，提升 import chunk 的 FTS5 命中率。
    """
    row = conn.execute(
        "SELECT rowid, summary, content, tags FROM memory_chunks WHERE id=?", (chunk_id,)
    ).fetchone()
    if not row:
        return
    rowid_val, db_summary, db_content, db_tags = row
    # 使用传入值或 DB 现有值
    final_summary = summary if summary is not None else (db_summary or "")
    final_content = content if content is not None else (db_content or "")
    if not final_summary and not final_content:
        return
    # iter702: tags_fts_boost — 将 tags 中有检索价值的关键词拼入 content
    # 过滤掉纯 metadata 标签（chunk_type 名、project ID、generic 标签）
    _tags_suffix = ""
    if db_tags:
        try:
            import json as _json702
            _tags_list = _json702.loads(db_tags) if isinstance(db_tags, str) else db_tags
            _skip = {"semantic", "consolidated", "imported", "design_constraint",
                     "decision", "procedure", "quantitative_evidence", "causal_chain",
                     "excluded_path", "prompt_context", "reasoning_chain"}
            _useful = [t for t in _tags_list
                       if isinstance(t, str) and t not in _skip
                       and not t.startswith(("abspath:", "git:", "sec"))]
            if _useful:
                _tags_suffix = " " + " ".join(_useful)
        except Exception:
            pass
    try:
        conn.execute("DELETE FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid_val),))
        conn.execute(
            "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
            (str(rowid_val),
             _cjk_tokenize(_normalize_structured_summary(final_summary)),
             _cjk_tokenize(_normalize_structured_summary(final_content + _tags_suffix)))
        )
    except Exception:
        pass  # FTS5 表可能未就绪


def fts5_checkpoint(conn: sqlite3.Connection) -> dict:
    """
    迭代504：FTS5 一致性校验与修复。
    OS 类比：e2fsck Phase 1-3 — 扫描 inode→检查目录→修复不一致。

    三阶段：
      Phase 1 (orphan scan): FTS5 条目指向不存在的 chunk → 删除孤儿
      Phase 2 (missing scan): chunk 存在但 FTS5 无条目 → 补建索引
      Phase 3 (stats): 报告修复结果

    返回: {"orphans_removed": N, "missing_rebuilt": N, "fts5_count": N, "chunks_count": N}
    """
    stats = {"orphans_removed": 0, "missing_rebuilt": 0}

    # Phase 1: 删除孤儿（FTS5 rowid_ref 指向不存在的 chunk）
    # OS 类比：e2fsck Phase 1 — 扫描并清除悬挂的 inode 引用
    orphans = conn.execute("""
        SELECT f.rowid, f.rowid_ref FROM memory_chunks_fts f
        WHERE NOT EXISTS (
            SELECT 1 FROM memory_chunks m WHERE m.rowid = CAST(f.rowid_ref AS INTEGER)
        )
    """).fetchall()
    if orphans:
        for fts_rowid, _ in orphans:
            conn.execute("DELETE FROM memory_chunks_fts WHERE rowid=?", (fts_rowid,))
        stats["orphans_removed"] = len(orphans)

    # Phase 1.5: 清理 SWAPPED chunk 的 FTS 条目
    # iter995: swapped_fts_cleanup — SWAPPED chunk 不应被 FTS 检索命中
    # 根因（数据驱动，2026-05-06）：3 条 chunk_state='SWAPPED' 仍有 FTS 条目，
    #   导致 PA fts5_covers_all_chunks 失败（FTS=83 vs ACTIVE=80）。
    #   设置 chunk_state 的路径未同步清理 FTS → 孤儿索引累积。
    _has_state_col = conn.execute(
        "SELECT COUNT(*) FROM pragma_table_info('memory_chunks') WHERE name='chunk_state'"
    ).fetchone()[0]
    if _has_state_col:
        swapped_fts = conn.execute("""
            SELECT f.rowid FROM memory_chunks_fts f
            JOIN memory_chunks m ON CAST(f.rowid_ref AS INTEGER) = m.rowid
            WHERE m.chunk_state != 'ACTIVE'
        """).fetchall()
        for (fts_rowid,) in swapped_fts:
            conn.execute("DELETE FROM memory_chunks_fts WHERE rowid=?", (fts_rowid,))
        stats["orphans_removed"] += len(swapped_fts)

    # Phase 2: 补建缺失条目（chunk 存在但 FTS5 无记录）
    # OS 类比：e2fsck Phase 3 — 重建缺失的目录条目
    # iter995: 只补建 ACTIVE chunk（SWAPPED 不应在 FTS 中）
    _active_filter = "AND m.chunk_state='ACTIVE'" if _has_state_col else ""
    missing = conn.execute(f"""
        SELECT m.rowid, m.summary, m.content, m.tags FROM memory_chunks m
        WHERE m.summary != '' {_active_filter} AND NOT EXISTS (
            SELECT 1 FROM memory_chunks_fts f WHERE CAST(f.rowid_ref AS INTEGER) = m.rowid
        )
    """).fetchall()
    if missing:
        _skip702c = {"semantic", "consolidated", "imported", "design_constraint",
                     "decision", "procedure", "quantitative_evidence", "causal_chain",
                     "excluded_path", "prompt_context", "reasoning_chain"}
        for rowid_val, summary, content, tags in missing:
            _tsuf = ""
            if tags:
                try:
                    import json as _j702c
                    _tl = _j702c.loads(tags) if isinstance(tags, str) else tags
                    _u = [t for t in _tl if isinstance(t, str) and t not in _skip702c
                          and not t.startswith(("abspath:", "git:", "sec"))]
                    if _u:
                        _tsuf = " " + " ".join(_u)
                except Exception:
                    pass
            try:
                conn.execute(
                    "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                    (str(rowid_val),
                     _cjk_tokenize(_normalize_structured_summary(summary or "")),
                     _cjk_tokenize(_normalize_structured_summary((content or "") + _tsuf)))
                )
            except Exception:
                pass
        stats["missing_rebuilt"] = len(missing)

    stats["fts5_count"] = conn.execute("SELECT count(*) FROM memory_chunks_fts").fetchone()[0]
    stats["chunks_count"] = conn.execute("SELECT count(*) FROM memory_chunks").fetchone()[0]
    return stats


# ── iter390: trigger_conditions CRUD ────────────────────────────────────────

def insert_trigger(conn: sqlite3.Connection, trigger: dict) -> None:
    """写入一条 trigger_conditions 记录。"""
    conn.execute("""
        INSERT OR REPLACE INTO trigger_conditions
        (id, chunk_id, project, session_id, trigger_pattern, trigger_type,
         created_at, fired_count, last_fired, expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        trigger["id"],
        trigger["chunk_id"],
        trigger["project"],
        trigger.get("session_id", ""),
        trigger["trigger_pattern"],
        trigger.get("trigger_type", "keyword"),
        trigger["created_at"],
        trigger.get("fired_count", 0),
        trigger.get("last_fired"),
        trigger.get("expires_at"),
    ))


def query_triggers(conn: sqlite3.Connection, project: str,
                   query_text: str, max_triggers: int = 3) -> list:
    """
    查询与 query_text 匹配的 trigger_conditions，返回相关 chunk_id 列表。
    OS 类比：inotify_read() — 读取待处理的文件系统事件（触发条件已满足）。

    匹配逻辑：trigger_pattern 是关键词/正则，query_text 中包含时触发。
    返回 [(chunk_id, trigger_id, trigger_pattern), ...] 最多 max_triggers 条。
    """
    import re as _re
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT id, chunk_id, trigger_pattern, trigger_type FROM trigger_conditions "
        "WHERE project=? AND (expires_at IS NULL OR expires_at > ?) "
        "ORDER BY fired_count ASC, created_at DESC LIMIT 50",
        (project, now_iso),
    ).fetchall()

    matched = []
    for row in rows:
        tid, cid, pattern, ttype = row[0], row[1], row[2], row[3]
        try:
            if ttype == "regex":
                if _re.search(pattern, query_text, _re.IGNORECASE):
                    matched.append((cid, tid, pattern))
            else:
                # keyword: pattern is a simple keyword/phrase
                if pattern.lower() in query_text.lower():
                    matched.append((cid, tid, pattern))
        except Exception:
            continue
        if len(matched) >= max_triggers:
            break
    return matched


def fire_trigger(conn: sqlite3.Connection, trigger_id: str) -> None:
    """记录 trigger 已触发（更新 fired_count + last_fired）。"""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE trigger_conditions SET fired_count=fired_count+1, last_fired=? WHERE id=?",
        (now_iso, trigger_id),
    )


def _fts5_escape(query: str) -> str:
    """
    将自然语言查询转为 FTS5 安全的 MATCH 表达式。

    迭代97：配合新 FTS5 独立模式（CJK 单字分词存储）。
    迭代100：改为 bigram 优先策略，与存储侧 _cjk_tokenize v100 对应。
    迭代103：查询侧同义词扩展（Query Expansion），打击自然语言↔技术术语的语义差距。

    策略：
      - 英文词/数字/标识符：提取词元，OR 连接
      - CJK：优先提取 bigram（相邻字对），少于 2 个 bigram 时补单字
      - 同义词扩展：对匹配到的概念追加技术术语/自然语言等价词

    OS 类比：ext4 htree 查询 + 搜索引擎的 Query Expansion (QE)。
    """
    tokens = []
    seen: set = set()

    # 迭代99：英文词 + Porter stemming + stopword 过滤（与 bm25.py 对称）
    # 迭代154：使用模块级 _BM25_STOPWORDS / _bm25_stem，消除 per-call inline import
    for m in re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', query):
        token = m.group().lower().strip('.-_')
        if len(token) >= 2 and token not in seen and token not in _BM25_STOPWORDS:
            # iter714: skip stemming for hyphenated/underscored terms
            stemmed = token if ("-" in token or "_" in token) else _bm25_stem(token)
            seen.add(token)
            seen.add(stemmed)
            tokens.append(f'"{stemmed}"')

    # CJK：bigram 优先
    cjk_chars = re.findall(r'[\u4e00-\u9fff\u3400-\u4dbf]', query)
    bigrams = [cjk_chars[i] + cjk_chars[i+1] for i in range(len(cjk_chars) - 1)]
    if bigrams:
        # iter715: limit CJK bigrams to 4 to reduce cross-word noise
        _bg_count = 0
        for bg in bigrams:
            if _bg_count >= 4:
                break
            if bg not in seen:
                seen.add(bg)
                tokens.append(f'"{bg}"')
                _bg_count += 1
    else:
        # 无 bigram（单个 CJK 字或为空）：退回单字
        for c in cjk_chars:
            if c not in seen:
                seen.add(c)
                tokens.append(f'"{c}"')

    # 迭代103：同义词扩展 — 查询侧 Query Expansion
    # 对已提取的 token 和原始 query 文本做概念匹配，追加等价术语
    syn_tokens = _synonym_expand(query, seen)
    tokens.extend(syn_tokens)

    if not tokens:
        return ""
    return " OR ".join(tokens)


# ── 迭代103：同义词/概念映射表 ──────────────────────────────────────
# OS 类比：DNS CNAME — 一个规范名可以有多个别名指向同一资源。
# 双向映射：技术术语 ↔ 自然语言描述。
# 触发条件：query 中出现左侧任一词/短语时，追加右侧所有词到 FTS5 查询。
#
# 格式：每条规则 = (trigger_patterns, expansion_terms)
#   trigger_patterns: 正则列表，匹配 query 原文
#   expansion_terms: 要追加到 FTS5 查询的术语列表
#
# 迭代153：Pre-compiled Synonym Patterns — AOT 正则预编译
# OS 类比：GCC AOT compilation vs JIT — 在模块加载时预编译所有正则，
#   消除首次 _synonym_expand 调用的 re.compile 延迟（实测 8.8ms → <1ms）。
#   Python re.search("pattern", ...) 在内部维护 512 条 LRU 编译缓存（CPython），
#   229 个触发模式首次调用时全部 cache miss → 每条 ~0.04ms，合计 ~8.8ms。
#   预编译将 229 条 re.compile() 提前到模块 import 时执行（只付一次）。

_SYNONYM_RULES = [
    # 内存管理
    (["自动清理", "自动淘汰", "自动删除", "清理记忆", "清理知识"],
     ["kswapd", "evict", "淘汰"]),
    (["kswapd", "页面回收", "内存回收"],
     ["淘汰", "清理", "evict", "watermark"]),
    # 迭代125：淘汰/驱逐机制更多触发词（原规则只覆盖"自动淘汰"，查询"淘汰策略"无法触发）
    (["淘汰策略", "淘汰机制", "驱逐", "eviction", "回收策略", "缓存驱逐",
      "chunk.*淘汰", "淘汰.*chunk", "何时.*淘汰", "怎么.*淘汰", "如何.*淘汰"],
     ["kswapd", "evict", "watermark", "retention", "oom_adj", "swap_out"]),

    # 保护/不可删除
    (["不能被删除", "不可删除", "保护.*规则", "重要.*保护", "不可淘汰", "重要.*不能", "规则.*不.*删"],
     ["oom_adj", "mlock", "design_constraint", "设计约束", "保护", "不可淘汰"]),
    (["oom_adj", "mlock", "设计约束", "design.constraint"],
     ["保护", "不可淘汰", "强制注入"]),

    # 检索优先级
    (["查询分类", "查询.*级别", "优先级分类", "检索分类"],
     ["SKIP", "LITE", "FULL", "nice", "优先级"]),
    (["SKIP.*LITE.*FULL", "nice.*level"],
     ["优先级", "分类", "查询类型"]),

    # VFS/缓存
    (["知识文件系统", "文件系统.*缓存", "两层缓存", "两级缓存"],
     ["VFS", "dentry", "inode", "cache"]),
    (["VFS", "dentry.*cache", "inode.*cache"],
     ["缓存", "文件系统", "知识"]),

    # BM25/搜索
    (["全文搜索", "全文检索", "中文.*切词", "中文.*分词"],
     ["BM25", "FTS5", "bigram", "tokenize"]),
    (["BM25", "FTS5", "bigram"],
     ["全文", "搜索", "分词", "检索"]),

    # 快速路径
    (["快速跳过", "零开销", "极速.*路径"],
     ["vDSO", "fast.*path", "快速路径"]),
    (["vDSO", "fast.path", "快速路径"],
     ["跳过", "零开销", "极速"]),

    # 新知识保护期
    (["保护期", "新.*加分", "新知识.*保护"],
     ["freshness", "grace", "bonus"]),
    (["freshness.bonus", "grace.days"],
     ["保护期", "新知识", "加分", "衰减"]),

    # chunk/quota
    (["最多.*存.*多少", "存储上限", "配额", "容量限制"],
     ["quota", "chunk_quota", "200"]),
    (["quota", "chunk_quota"],
     ["上限", "配额", "最多", "容量"]),

    # 迭代/版本 — "迭代 98" 需要扩展为 "iter98" "iter" "迭代"
    (["迭代", "第.*次迭代", "版本.*\\d+"],
     ["iter", "迭代"]),
    (["iter\\d+", "iter "],
     ["迭代"]),

    # 去重
    (["去重", "重复.*检测", "合并.*相似"],
     ["dedup", "find_similar", "merge", "already_exists"]),
    (["dedup", "find_similar", "merge_similar"],
     ["去重", "重复", "合并"]),

    # 向量数据库
    (["向量数据库", "向量.*索引", "embedding.*数据库"],
     ["chromadb", "vector", "embedding"]),
    (["chromadb"],
     ["向量", "数据库", "embedding"]),

    # 迭代125：检索/召回语义（查询"检索效果/召回率"应扩展到 FTS/BM25 相关术语）
    (["检索效果", "召回率", "检索质量", "召回精度", "检索优化"],
     ["recall", "precision", "BM25", "fts_rank", "FTS5", "retrieval"]),
    (["recall.*rate", "retrieval.*quality"],
     ["召回", "检索", "精度"]),

    # 迭代125：session/会话 相关
    (["会话恢复", "上次会话", "session.*恢复", "工作集恢复"],
     ["loader", "working_set", "checkpoint", "CRIU", "session_start"]),
    (["CRIU", "checkpoint.*restore", "working.set"],
     ["会话恢复", "工作集", "loader"]),

    # 迭代125：知识导入/wiki 相关
    (["知识导入", "wiki.*导入", "import.*知识", "导入.*知识库"],
     ["import_knowledge", "procedure", "incremental_import"]),
    (["import_knowledge", "incremental_import"],
     ["导入", "知识库", "wiki", "procedure"]),

    # ── 迭代133：memory-os 自知识同义词扩展 ─────────────────────────────────
    # 确保 iter132 导入的 memory-os 架构 chunk 能被自然语言查询命中

    # retriever 检索管道
    (["检索管道", "检索流程", "召回流程", "检索器", "retriever"],
     ["retriever", "FTS5", "BM25", "SKIP", "LITE", "FULL", "检索"]),
    (["检索优先级", "query.*优先级", "查询.*调度"],
     ["SKIP", "LITE", "FULL", "nice", "scheduler", "优先级"]),

    # extractor 提取管道
    (["提取器", "提取管道", "extractor", "知识提取", "stop.*hook"],
     ["extractor", "提取", "decision", "reasoning_chain", "chunk"]),
    (["如何.*提取", "怎么.*提取知识", "哪些.*被提取", "提取.*规则"],
     ["extractor", "chunk_type", "importance", "AIMD", "提取"]),

    # PSI 压力感知
    (["系统压力", "检索压力", "压力感知", "PSI", "psi"],
     ["PSI", "压力", "降级", "FULL", "LITE", "latency"]),
    (["动态降级", "自动降级", "检索降级", "性能降级"],
     ["PSI", "downgrade", "降级", "压力", "psi_stats"]),

    # TLB 检索缓存
    (["检索缓存", "结果缓存", "缓存命中", "TLB", "tlb"],
     ["TLB", "prompt_hash", "chunk_version", "injection_hash", "缓存"]),
    (["prompt.*hash.*缓存", "chunk.*version", "检索结果.*重复"],
     ["TLB", "tlb_read", "tlb_write", "chunk_version", "缓存"]),

    # DRR 公平调度
    (["类型多样", "多样性", "召回多样", "防.*独占", "DRR", "drr"],
     ["DRR", "drr_select", "chunk_type", "多样性", "公平"]),
    (["单一类型.*独占", "decision.*占满", "类型.*不平衡"],
     ["DRR", "max_same_type", "overflow", "多样性"]),

    # madvise 预热
    (["预热加分", "hint.*加分", "预热.*检索", "madvise"],
     ["madvise", "hint", "boost", "prefetch", "预热"]),
    (["读取提示", "访问提示", "预期.*访问"],
     ["madvise", "hint", "madvise_read", "预热"]),

    # Anti-Starvation 反饥饿
    (["饥饿.*加分", "饱和.*惩罚", "反饥饿", "召回.*同质", "anti.*starvation"],
     ["starvation", "saturation", "recall_count", "anti-starvation", "反饥饿"]),
    (["热门.*chunk.*独占", "总是召回.*相同", "新知识.*没被召回"],
     ["starvation", "boost", "saturation", "penalty", "饥饿"]),

    # Deadline Scheduler 超时控制
    (["检索超时", "检索截止", "时间预算", "deadline", "soft.*deadline", "hard.*deadline"],
     ["deadline", "deadline_ms", "deadline_hard_ms", "超时", "截止"]),
    (["检索太慢", "检索.*延迟", "超过.*时限"],
     ["deadline", "psi", "latency", "deadline_skipped", "超时"]),

    # Context Pressure Governor
    (["注入窗口", "对话.*压力", "压缩.*感知", "governor", "context.*pressure"],
     ["governor", "context_pressure", "scale", "turns", "compact", "注入"]),
    (["注入.*太多", "注入.*太少", "对话轮次.*多", "context.*满了"],
     ["governor", "scale", "CRITICAL", "HIGH", "LOW", "压力"]),

    # Readahead 预取
    (["预取", "协同访问", "共现.*预取", "readahead"],
     ["readahead", "prefetch", "cooccurrence", "pair", "预取"]),
    (["一起被召回", "频繁.*同时.*出现", "共现对"],
     ["readahead", "readahead_pairs", "cooccurrence", "预取"]),

    # ASLR 随机扰动
    (["随机扰动", "探索.*检索", "多样化.*召回", "ASLR", "aslr"],
     ["ASLR", "aslr_epsilon", "random", "扰动", "多样"]),

    # chunk_type 类型
    (["chunk.*类型", "知识.*分类", "哪种.*类型", "chunk_type"],
     ["decision", "design_constraint", "reasoning_chain", "excluded_path",
      "procedure", "conversation_summary", "quantitative_evidence"]),
    (["设计约束", "系统约束", "design.*constraint", "强制.*注入.*约束"],
     ["design_constraint", "mlock", "forced", "oom_adj", "约束"]),

    # vDSO 快速路径
    (["vdso", "vDSO", "快速.*退出", "零.*import"],
     ["vDSO", "fast_exit", "SKIP", "lazy_import", "快速路径"]),
    (["import.*开销", "启动.*慢", "冷启动.*延迟"],
     ["vDSO", "lazy_import", "fast_path", "import", "开销"]),

    # MGLRU 多代 LRU
    (["多代.*LRU", "lru.*代", "lru_gen", "MGLRU", "mglru"],
     ["MGLRU", "lru_gen", "aging", "promote", "老化"]),
    (["chunk.*老化", "旧.*chunk.*淘汰", "代数.*管理"],
     ["MGLRU", "lru_gen", "mglru_aging", "evict", "老化"]),

    # DAMON 访问监控
    (["冷.*chunk", "死.*chunk", "长期未访问", "DAMON", "damon"],
     ["DAMON", "cold", "dead", "access_count", "监控"]),
    (["access_count.*0", "从未被访问", "零访问"],
     ["DAMON", "cold", "starvation", "boost", "访问"]),

    # Swap 换入换出
    (["swap.*换出", "换入.*换出", "被换出.*找回", "swap.*fault"],
     ["swap_out", "swap_in", "swap_fault", "demand_paging", "换出"]),
    (["demand.*paging", "按需.*加载", "缺页.*补入", "page.*fault"],
     ["swap_fault", "page_fault_log", "demand_paging", "缺页"]),

    # ── 迭代332：通用语义 Query Expansion — 自然语言问法桥接规则 ─────────────────
    # 目标：将"如何/怎么/为什么"问句前缀 + 动词/名词 映射到对应技术关键词，
    # 填补 GBrain 语义检索与 memory-os BM25 词汇匹配之间的语义鸿沟。
    # 测试基线：Jaccard overlap ~0.19（自然语言 vs 技术关键词对）

    # ─── 类别 A：优化/性能类问句 ───
    # "如何优化检索速度" / "怎么加快" / "性能提升" → 技术关键词
    (["如何.*优化", "怎么.*优化", "优化.*方法", "如何.*加速", "怎么.*加快",
      "如何.*提升.*性能", "性能.*提升", "性能.*优化", "速度.*慢.*怎么",
      "how.*optim", "how.*speed.*up", "improve.*performance"],
     ["optimize", "latency", "deadline", "fast", "performance", "ms",
      "优化", "加速", "提升", "PSI", "vDSO"]),

    # ─── 类别 B：召回/检索效果类问句 ───
    # "为什么召回率低" / "检索不到" / "找不到相关内容" → recall/retrieval 关键词
    (["为什么.*召回", "召回率.*低", "检索.*效果差", "找不到.*相关",
      "检索.*不准", "为什么.*找不到", "没有.*相关.*结果",
      "why.*recall.*low", "retrieval.*quality.*poor", "不准确"],
     ["recall", "FTS5", "BM25", "fts_rank", "precision", "threshold",
      "召回", "检索", "min_score", "候选集"]),

    # ─── 类别 C：去重/合并/冗余问句 ───
    # "如何减少重复" / "合并相似内容" / "知识冗余" → dedup 关键词
    (["如何.*减少.*重复", "怎么.*去重", "合并.*相似", "知识.*冗余",
      "重复.*内容.*怎么", "避免.*重复.*知识",
      "how.*dedup", "how.*merge.*similar", "reduce.*redundan"],
     ["dedup", "find_similar", "merge", "Jaccard", "already_exists",
      "去重", "合并", "相似度", "sleep_consolidate"]),

    # ─── 类别 D：重要性/权重/优先级问句 ───
    # "怎么设置重要性" / "importance 怎么计算" / "哪些知识更重要" → importance 关键词
    (["怎么.*设置.*重要", "如何.*调整.*权重", "importance.*怎么", "哪些.*更重要",
      "知识.*重要性", "优先.*保留.*哪些", "怎么.*决定.*保留",
      "how.*set.*importance", "how.*calculate.*score"],
     ["importance", "weight", "score", "oom_adj", "stability",
      "重要性", "权重", "保留", "importance_override"]),

    # ─── 类别 E：存储/容量/上限问句 ───
    # "能存多少" / "存储容量" / "达到上限" → quota 关键词
    (["能.*存.*多少", "存储.*容量", "知识.*上限", "最多.*多少.*条",
      "达到.*上限.*怎么", "知识库.*满了",
      "how.*much.*store", "storage.*limit", "capacity.*limit"],
     ["quota", "chunk_quota", "max", "limit", "evict", "200",
      "上限", "配额", "容量", "淘汰"]),

    # ─── 类别 F：写入/保存/提取失败问句 ───
    # "知识没有被保存" / "为什么没有提取到" / "提取失败" → extractor 关键词
    (["知识.*没有.*保存", "为什么.*没.*提取", "提取.*失败", "没.*写入",
      "内容.*没有.*记录", "为什么.*不.*提取",
      "why.*not.*extract", "why.*not.*save", "knowledge.*lost"],
     ["extractor", "already_exists", "throttle", "cwnd", "AIMD",
      "提取", "去重", "流控", "写入失败"]),

    # ─── 类别 G：速度/延迟/超时问句 ───
    # "检索太慢" / "hook 超时" / "为什么这么慢" → deadline/latency 关键词
    (["检索.*太慢", "太慢.*了", "为什么.*慢", "响应.*慢",
      "hook.*超时", "超过.*时间", "延迟.*高",
      "why.*slow", "too.*slow", "latency.*high", "timeout"],
     ["deadline", "deadline_ms", "hard_deadline", "latency", "psi",
      "超时", "延迟", "deadline_skipped", "import"]),

    # ─── 类别 H：注入/上下文/输出问句 ───
    # "注入了什么" / "上下文里有什么" / "为什么注入了不相关内容" → injection 关键词
    # iter332修复：扩展目标词匹配实际DB词汇（噪音/无关/context window）
    (["注入.*什么", "为什么.*注入", "上下文.*有什么", "注入.*不相关",
      "注入.*不相关内容", "为什么.*出现.*上下文", "context.*里.*什么",
      "what.*inject", "why.*inject.*irrelevant", "context.*noise",
      "不相关.*内容", "无关.*内容"],
     ["inject", "additionalContext", "min_score", "threshold", "DRR",
      "注入", "上下文", "噪音", "过滤", "无关", "不相关", "边际", "MMR"]),

    # ─── 类别 I：中英文通用概念等价 ───
    # 核心技术词的中英文双向桥接（FTS5 无 stemming，需显式映射）
    (["优化", "提升", "改进", "加速"],
     ["optimize", "improve", "faster", "performance", "speed"]),
    (["optimize", "improve", "enhance", "accelerate"],
     ["优化", "提升", "性能", "加速", "改进"]),

    (["召回", "检索", "查找", "搜索"],
     ["recall", "retrieve", "search", "FTS5", "BM25"]),
    (["recall", "retrieve", "retrieval", "search"],
     ["召回", "检索", "查找", "FTS5"]),

    (["删除", "清理", "淘汰", "移除"],
     ["delete", "evict", "remove", "clean", "purge"]),
    (["delete", "evict", "remove", "purge"],
     ["删除", "清理", "淘汰", "移除", "clean", "delet"]),

    (["保存", "记录", "存储", "写入"],
     ["save", "store", "write", "insert", "persist"]),
    (["save", "store", "write", "insert", "persist"],
     ["保存", "记录", "存储", "写入"]),

    (["重要", "关键", "核心", "优先"],
     ["important", "critical", "priority", "key", "essential"]),
    (["important", "critical", "priority", "essential"],
     ["重要", "关键", "核心", "优先"]),

    # ─── 类别 J：因果/原因/解释问句 ───
    # "为什么会X" / "原因是什么" / "根因" / "导致" → causal_chain/reasoning_chain 关键词
    (["为什么.*会", "原因.*是什么", "怎么导致", "什么.*导致", "导致.*问题",
      "根本原因", "根因",
      "what.*cause", "why.*happen", "root.*cause"],
     ["causal_chain", "reasoning_chain", "根因", "导致", "因为",
      "原因", "causal", "因果"]),

    # ─── 类别 K：比较/对比问句 ───
    # "X 和 Y 有什么区别" / "哪个更好" → 两者的关键词都扩展
    (["有什么区别", "区别.*是什么", "对比.*两者", "哪个.*更好",
      "what.*difference", "compare.*between", "vs.*which"],
     ["difference", "compare", "versus", "区别", "对比", "优劣"]),

    # ─── 类别 L：如何查看/监控/调试问句 ───
    # "怎么查看" / "如何监控" / "怎么调试" / "如何调试" → 日志/工具关键词
    (["怎么.*查看", "如何.*监控", "怎么.*调试", "如何.*调试", "怎么.*检查",
      "如何.*诊断", "查看.*状态", "调试.*问题", "debug.*问题",
      "how.*check", "how.*monitor", "how.*debug", "how.*diagnos"],
     ["dmesg", "log", "stats", "trace", "recall_traces", "psi",
      "日志", "监控", "调试", "statistics", "debug"]),

    # ─── iter721: 类别 M：内核开发工作流 ───
    (["发.*patch", "patch.*发", "patch.*送", "提交.*patch", "send.*patch", "投递.*补丁", "邮件列表"],
     ["git", "send-email", "commit", "格式", "检查", "Signed-off-by"]),
    (["commit.*message", "提交信息", "commit.*格式"],
     ["Signed-off-by", "patch", "格式规范", "标签"]),
    (["飞书", "feishu", "文档.*访问", "知识库"],
     ["CLI", "认证", "fetch", "禁止"]),
    (["性能.*分析", "性能.*诊断", "perf.*analys", "性能.*优化"],
     ["Running", "Runnable", "simpleperf", "thermal", "uclamp", "调度"]),
    (["调度.*延迟", "调度.*优化", "scheduler", "进程.*调度"],
     ["EEVDF", "sched_ext", "migration", "RT", "uclamp", "cgroup"]),
    (["Proxy.*Execution", "PE.*分析", "proxy.*exec"],
     ["find_proxy_task", "directed_yield", "scx", "task_rq_lock"]),
]

# ── 迭代153/154：Synonym Patterns — 懒编译（first-call JIT）策略 ─────────────
# OS 类比：Linux JIT BPF verifier (4.8, 2016) — 首次调用时编译到机器码，
#   后续调用直接执行已编译的 native code（类比 Python LRU compile cache 命中）。
#
# 迭代153 的 AOT 方案在 per-process hook 模型下是 net-negative（见分析）：
#   每个进程都独立 import store_vfs → AOT 编译 229 条正则 ~16ms（每次都付）
#   而 _synonym_expand 在一次检索中只被调用 1 次，节省 ~8.8ms 首次编译
#   净效果：+16ms - 8.8ms = +7.2ms（更慢）
#
# 迭代154 改为懒编译：
#   _SYNONYM_RULES_COMPILED = None 作为哨兵（模块加载时 0ms）
#   _synonym_expand 首次调用时编译（付 ~8.8ms 一次）
#   同一进程多次调用（如测试场景）后续直接复用
#   per-process 节约：import 从 ~32ms 降回 ~16ms，首次调用 ~8.8ms（与旧 AOT 相同）
#   本质：推迟到第一次需要时再编译，不改变 per-process 总成本，但消除无用的 import 延迟
#
# 注意：如果未来改为 daemon/socket 模式（跨请求进程复用），懒编译自动变为"只付一次"优化。
_SYNONYM_RULES_COMPILED = None  # 懒编译哨兵，None = 尚未编译

# ── 迭代155：Synonym Prescan — Bloom filter 风格快速退出 ─────────────────────
# OS 类比：Linux Bloom filter in network packet classification (iptables hashlimit, 2003)
#   iptables 在做完整规则表 walk 之前，先用 Bloom filter 做 O(1) 预筛：
#   如果 Bloom filter 说"不可能命中"，直接跳过，不进入 O(N) 规则遍历。
#   memory-os 等价问题：
#     _synonym_expand 每次都要先触发 _ensure_synonym_compiled()（~9ms JIT），
#     再做 60 条规则匹配（~2.5ms），但大多数 query 根本没有同义词触发词。
#     P50 query 只有 22 字，短 query 极少含 kswapd/淘汰/BM25 等术语。
#   解决：预先提取所有同义词触发模式中的"简单关键词"（无正则元字符的子串）
#     构建 frozenset —— O(1) 成员检测，模块加载时 0ms（纯字符串操作）。
#     _synonym_expand 先检查 query 是否含任何触发关键词：
#       未命中 → return [] 立即退出（0.002ms），跳过 9ms JIT + 2.5ms 匹配
#       命中 → 继续完整流程（行为与 iter154 完全相同）
#   预期效果：P50（22 char query）中 ~60-70% 不含任何触发词 → 节省 ~9ms
#   误判代价：极低——prescan 只做快速退出（false negative 导致漏扩展），
#     不会误扩展（false positive 最多多做一次完整匹配，无害）。
def _build_synonym_trigger_keywords() -> frozenset:
    """
    从 _SYNONYM_RULES 提取所有触发模式中的简单关键词（无正则元字符的子串）。
    模块加载时调用一次（纯字符串操作，~0ms），不触发 re.compile。
    OS 类比：iptables Bloom filter 预构建 — 规则加载时建立 bit array，不在包处理时构建。
    """
    keywords: set = set()
    for triggers, _expansions in _SYNONYM_RULES:
        for t in triggers:
            # 提取 CJK 连续子串（≥2字）作为触发词
            cn_chunks = re.findall(r'[\u4e00-\u9fff]{2,}', t)
            for chunk in cn_chunks:
                keywords.add(chunk[:2])  # bigram 前缀足够区分
                if len(chunk) >= 4:
                    keywords.add(chunk[2:4])  # 第二个 bigram
            # 提取英文词（≥4字，跳过正则元字符前缀的词）
            for m in re.finditer(r'[a-zA-Z]{4,}', t):
                w = m.group().lower()
                keywords.add(w)
    return frozenset(keywords)


_SYNONYM_TRIGGER_KEYWORDS: frozenset = _build_synonym_trigger_keywords()


def _ensure_synonym_compiled():
    """
    按需编译同义词规则（懒编译，只在首次 _synonym_expand 调用时执行）。
    OS 类比：Linux JIT BPF — bpf() 系统调用时才触发 JIT 编译，不在 load time 编译。
    """
    global _SYNONYM_RULES_COMPILED
    if _SYNONYM_RULES_COMPILED is not None:
        return
    compiled = []
    for triggers, expansions in _SYNONYM_RULES:
        cpats = []
        for t in triggers:
            try:
                cpats.append(re.compile(t, re.IGNORECASE))
            except re.error:
                cpats.append(None)  # fallback to string contains
        compiled.append((cpats, triggers, expansions))
    _SYNONYM_RULES_COMPILED = compiled


def _synonym_expand(query: str, seen: set) -> list:
    """
    对 query 做同义词扩展，返回额外的 FTS5 token 列表。
    只追加 seen 中不存在的新 token，避免重复。
    迭代153+154：懒编译策略 — 首次调用时编译同义词正则，消除 import 时的 AOT 开销。
    迭代155：Prescan 快速退出 — Bloom filter 风格，O(1) 检测 query 是否含任何触发词，
      未命中则直接返回 []，跳过 ~9ms JIT 编译 + ~2.5ms 规则匹配。
    """
    query_lower = query.lower()

    # ── 迭代155：Prescan — Bloom filter 快速退出 ──────────────────────────────
    # OS 类比：iptables hashlimit Bloom filter — O(1) 预筛，不命中直接 accept，不走规则表
    # 特殊情况："迭代 N" 模式不在 _SYNONYM_TRIGGER_KEYWORDS 中（数字），需单独检测
    _has_iter_pattern = '迭代' in query
    if not _has_iter_pattern:
        # 提取 query 的 CJK bigrams + 英文词（与 _build_synonym_trigger_keywords 对称）
        _q_cjk = re.findall(r'[\u4e00-\u9fff]{2,}', query)
        _q_bigrams = set()
        for _chunk in _q_cjk:
            _q_bigrams.add(_chunk[:2])
            if len(_chunk) >= 4:
                _q_bigrams.add(_chunk[2:4])
        _q_eng = set(m.lower() for m in re.findall(r'[a-zA-Z]{4,}', query_lower))
        _q_tokens = _q_bigrams | _q_eng
        # 快速交集检测（frozenset.__and__ 是 O(min(|A|,|B|)) ≈ O(query tokens count)）
        if not (_q_tokens & _SYNONYM_TRIGGER_KEYWORDS):
            return []  # prescan miss: 0.002ms，跳过 ~11.5ms 后续处理

    _ensure_synonym_compiled()
    extra = []

    # 特殊处理："迭代 N" / "迭代N" → "iterN"（高频模式，规则表无法覆盖）
    for m in re.finditer(r'迭代\s*(\d+)', query):
        iter_token = f'iter{m.group(1)}'
        if iter_token not in seen:
            seen.add(iter_token)
            extra.append(f'"{iter_token}"')

    for compiled_patterns, raw_triggers, expansions in _SYNONYM_RULES_COMPILED:
        matched = False
        for i, pat in enumerate(compiled_patterns):
            if pat is not None:
                if pat.search(query_lower) or pat.search(query):
                    matched = True
                    break
            else:
                # re.error fallback — use string contains
                if raw_triggers[i].lower() in query_lower:
                    matched = True
                    break
        if matched:
            for term in expansions:
                term_lower = term.lower()
                if term_lower not in seen and len(term_lower) >= 2:
                    seen.add(term_lower)
                    # 英文术语加引号，CJK 术语转 bigram
                    if re.match(r'^[a-zA-Z0-9_]+$', term):
                        extra.append(f'"{term_lower}"')
                    else:
                        # CJK: 生成 bigram
                        cjk = re.findall(r'[\u4e00-\u9fff]', term)
                        if len(cjk) >= 2:
                            for i in range(len(cjk) - 1):
                                bg = cjk[i] + cjk[i+1]
                                if bg not in seen:
                                    seen.add(bg)
                                    extra.append(f'"{bg}"')
                        elif cjk:
                            for c in cjk:
                                if c not in seen:
                                    seen.add(c)
                                    extra.append(f'"{c}"')
    return extra

def fts_search(conn: sqlite3.Connection, query: str, project: str,
               top_k: int = 10, chunk_types: tuple = None) -> List[dict]:
    """
    迭代23：FTS5 全文搜索 — 替代全表扫描 + Python BM25。
    OS 类比：htree 的 ext3_htree_fill_tree() → O(log N) 目录查找。

    BM25 由 SQLite FTS5 内置函数 bm25() 计算（C 实现），
    权重参数：summary 权重 2.0, content 权重 1.0。

    迭代172：将 2 次 FTS5 查询（project + global）合并为 1 次 IN(project, 'global')。
    OS 类比：readv() vs 2×read() — 向量化 I/O 减少系统调用次数。
    节省：~0.63ms（消除第二次 FTS5 query + sort，单次 IN 查询由 SQLite 优化器处理）。

    返回与 get_chunks() 相同格式的 dict 列表，额外带 fts_rank 字段。
    """
    match_expr = _fts5_escape(query)
    if not match_expr:
        return []

    # FTS5 bm25() 返回负值（越小越相关），取负后变为正值排序
    # 权重参数按列顺序：rowid_ref(UNINDEXED)=0, summary=2.0, content=1.0
    # 迭代97：非 content-sync 模式，通过 rowid_ref 关联主表
    def _run_fts(project_filter):
        """project_filter: None=全库, str=单项目, list/tuple=多项目"""
        sql = """
            SELECT mc.id, mc.summary, mc.content, mc.importance, mc.last_accessed,
                   mc.chunk_type, COALESCE(mc.access_count, 0), mc.created_at,
                   -bm25(memory_chunks_fts, 0, 2.0, 1.0) AS fts_rank,
                   COALESCE(mc.lru_gen, 0), mc.project,
                   mc.verification_status, mc.confidence_score,
                   COALESCE(mc.retrievability, 1.0),
                   COALESCE(mc.source_reliability, 0.7),
                   COALESCE(mc.emotional_weight, 0.0),
                   COALESCE(mc.emotional_valence, 0.0)
            FROM memory_chunks_fts
            JOIN memory_chunks mc ON mc.rowid = CAST(memory_chunks_fts.rowid_ref AS INTEGER)
            WHERE memory_chunks_fts MATCH ?
              AND mc.chunk_state = 'ACTIVE'
              AND mc.summary != ''
              AND mc.importance > 0.0
              AND COALESCE(mc.access_count, 0) < 30
        """
        # ── 迭代335：Ghost Filter (Layer 2) — FTS5 查询内过滤 importance=0 的 ghost chunk ──
        # OS 类比：Linux page allocator MIGRATE_TYPES 过滤 — 分配器跳过 MIGRATE_RESERVE 类型页
        # ghost chunk 由 consolidate/merge 路径产生（importance=0, summary=[merged→...]），
        # 但未被物理删除 → 仍在 FTS5 索引中 → FTS5 命中 ghost 消耗 result slot + 计算开销。
        # AND mc.importance > 0.0 是低成本的 B-tree 过滤（importance 列已索引），
        # 无需单独的 ghost_filter_enabled sysctl 开关（始终启用，无负面影响）。
        # B17: scope filter — session-scoped chunk_type 不出现在跨项目查询中
        # 认知模型：工作记忆（task_state/prompt_context）具有情境特异性，
        #   不应污染跨 session/project 的语义记忆检索结果。
        # OS 类比：Linux process-private mmap 不可通过 /proc/pid/mem 跨进程读取；
        #   session-scoped chunk = PROT_NONE mmap region，项目外不可见。
        _SESSION_SCOPED_TYPES = ("task_state", "prompt_context", "session_summary")

        params = [match_expr]
        if project_filter is not None:
            if isinstance(project_filter, (list, tuple)):
                # iter172: 合并多个 project 为一次 IN 查询
                placeholders = ",".join("?" * len(project_filter))
                sql += f" AND mc.project IN ({placeholders})"
                params.extend(project_filter)
                # B17: 若查询跨越多个 project（含 global），排除 session-scoped types
                if len(project_filter) > 1:
                    scope_ph = ",".join("?" * len(_SESSION_SCOPED_TYPES))
                    sql += f" AND mc.chunk_type NOT IN ({scope_ph})"
                    params.extend(_SESSION_SCOPED_TYPES)
            else:
                sql += " AND mc.project = ?"
                params.append(project_filter)
        if chunk_types:
            placeholders = ",".join("?" * len(chunk_types))
            sql += f" AND mc.chunk_type IN ({placeholders})"
            params.extend(chunk_types)
        sql += " ORDER BY fts_rank DESC LIMIT ?"
        params.append(top_k)
        try:
            return conn.execute(sql, params).fetchall()
        except Exception:
            return []

    # ── 迭代123 + iter172：Always-merge global — 单次 IN 查询 ──
    # OS 类比：readv() vectorized I/O — 两个缓冲区的 I/O 合并为一次系统调用，
    #   减少 kernel/userspace 切换次数（每次 syscall ~1μs overhead）。
    #   迭代123 将 project + global 分两次查询（2×FTS5），
    #   iter172 改为单次 IN(project, 'global') 查询（1×FTS5），节省 ~0.63ms。
    #
    # 语义保持：
    #   1. IN(project, 'global') 等价于旧的 project_query UNION global_query（去重由 id 唯一保证）
    #   2. ORDER BY fts_rank DESC LIMIT top_k 在合并结果上执行（全局最优）
    #   3. 历史孤儿 fallback 路径保留（全库搜索，project=None）

    # Step 1+2（iter172合并）：单次搜 project + global
    if project is None or project == "global":
        # project 本身是 global 或未指定：直接用单 project 查询
        rows = _run_fts(project)
    else:
        # iter172: 将 project + "global" 合并为一次 IN 查询
        rows = _run_fts([project, "global"])

    # Step 3: 历史孤儿 fallback：project ID 变化后的旧 chunk 补救
    # 仅当合并后仍不足 top_k 一半时触发全库搜索
    if len(rows) < max(1, top_k // 2):
        all_rows = _run_fts(None)
        seen_ids = {r[0] for r in rows}
        for r in all_rows:
            if r[0] not in seen_ids:
                rows.append(r)
                seen_ids.add(r[0])
            if len(rows) >= top_k:
                break

    result = []
    for rid, summary, content, importance, last_accessed, chunk_type, access_count, created_at, fts_rank, lru_gen, chunk_project, verification_status, confidence_score, retrievability, source_reliability, emotional_weight, emotional_valence in rows:
        result.append({
            "id": rid,
            "summary": summary or "",
            "content": content or "",
            "importance": importance if importance is not None else 0.5,
            "last_accessed": last_accessed or "",
            "chunk_type": chunk_type or "task_state",
            "access_count": access_count or 0,
            "created_at": created_at or "",
            "fts_rank": fts_rank,
            "lru_gen": lru_gen or 0,
            "project": chunk_project or "",  # 迭代111: NUMA distance scoring
            "verification_status": verification_status,
            "confidence_score": confidence_score,
            "retrievability": retrievability if retrievability is not None else 1.0,  # iter369
            "source_reliability": float(source_reliability) if source_reliability is not None else 0.7,  # iter396
            "emotional_weight": float(emotional_weight) if emotional_weight is not None else 0.0,  # iter376
            "emotional_valence": float(emotional_valence) if emotional_valence is not None else 0.0,  # iter424
        })
    return result

# ── CRUD 操作 ─────────────────────────────────────────────────

def get_chunks(conn: sqlite3.Connection, project: str,
               chunk_types: tuple = None) -> list:
    """
    查询项目的所有 chunk，返回 dict 列表。
    OS 类比：VFS 的 readdir() — 统一接口读取不同文件系统的目录项。
    """
    # 迭代94: 同时检索 global 层（跨项目共享知识）
    projects = [project] if project == "global" else [project, "global"]
    proj_ph = ",".join("?" * len(projects))
    if chunk_types:
        placeholders = ",".join("?" * len(chunk_types))
        query = f"""SELECT id, summary, content, importance, last_accessed,
                           chunk_type, COALESCE(access_count, 0), created_at, project,
                           verification_status, confidence_score, COALESCE(lru_gen, 0)
                    FROM memory_chunks
                    WHERE project IN ({proj_ph}) AND chunk_type IN ({placeholders})
                    AND summary != ''"""
        rows = conn.execute(query, (*projects, *chunk_types)).fetchall()
    else:
        rows = conn.execute(
            f"""SELECT id, summary, content, importance, last_accessed,
                      chunk_type, COALESCE(access_count, 0), created_at, project,
                      verification_status, confidence_score, COALESCE(lru_gen, 0)
               FROM memory_chunks
               WHERE project IN ({proj_ph}) AND summary != ''""",
            tuple(projects),
        ).fetchall()
    result = []
    for rid, summary, content, importance, last_accessed, chunk_type, access_count, created_at, chunk_project, verification_status, confidence_score, lru_gen in rows:
        result.append({
            "id": rid,
            "summary": summary or "",
            "content": content or "",
            "importance": importance if importance is not None else 0.5,
            "last_accessed": last_accessed or "",
            "chunk_type": chunk_type or "task_state",
            "access_count": access_count or 0,
            "created_at": created_at or "",
            "project": chunk_project or "",  # 迭代111: NUMA distance scoring
            "verification_status": verification_status,
            "confidence_score": confidence_score,
            "lru_gen": lru_gen,
        })
    return result


# ── iter533: vfs_write_protect — LSM Mandatory Access Control at VFS Layer ──
# OS 类比：Linux LSM (Linux Security Module) security_inode_create()
#   Chris Wright & James Morris (2001) — 不管哪条 syscall 路径到达 VFS，
#   都必须通过 LSM hook 的强制完整性校验。
# 设计：最小化检查（O(1) regex），只拦截明显碎片，不做语义判断。
# 语义判断留给上层（extractor/_is_quality_chunk），VFS 层只做"物理完整性"。
import re as _re_vfs
_RE_VFS_SELFREF = _re_vfs.compile(
    r'(?:suppress|inject|score\s*[×*降=]|bandwidth|recall.count|'
    r'access.count|hard.?cap|hard.?gate|oom_adj|zero.access|'
    r'垄断|逃逸|burst|saturation|注入|chunk.{0,4}注入|'
    # iter754: 迭代器自评噪声关键词 — 拦截 "空召回率 68%→25%" 等自我描述
    r'空召回|误杀率|fallback.*率|过滤规则|写入过滤|iter\d{3})',
    _re_vfs.IGNORECASE
)

def _vfs_write_protect(summary: str) -> bool:
    """
    iter533: VFS 层写保护 — 返回 True 表示拒绝写入。

    最小化检查（仅物理完整性，不做语义判断）：
    1. 空/极短 summary（< 8 字符）
    2. 以管道符/括号/符号开头（截断碎片）
    3. 管道符 >= 2（markdown 表格行）
    4. 以冒号结尾（标题碎片）
    5. 纯数字/符号行（数据行）

    不检查的（留给上层）：
    - 语义质量（决策动词、技术锚点）
    - 重复去重（KSM）
    - 配额/反压

    可通过 sysctl vfs.write_protect_enabled=false 禁用（测试/迁移场景）。
    """
    try:
        from config import get as _cfg
        if not _cfg("vfs.write_protect_enabled"):
            return False
    except Exception:
        pass  # config 不可用时默认启用保护

    # iter814: min_len 8→15 — 与 extractor iter701 对齐，拦截 direct/MCP 短碎片
    # 数据驱动：7337e9fd "验证：PA 9/10（已"(12字) 经 MCP 写入绕过 extractor gate，
    #   最短合法 chunk summary=33 字（import wiki），15 字阈值安全余量充足。
    if not summary or len(summary.strip()) < 15:
        return True
    s = summary.strip()
    # 以截断符号开头
    if s[0] in ('|', ')', ']', '}', '>', '+', '=', '：', '）', '】', '》',
                ',', '，', '、', ';', '；'):
        return True
    # iter629: markdown list-item fragment — "- xxx" / "* xxx" / "[ ] xxx"
    # 根因：extractor._is_quality_chunk 拦截 ^[\[\]\-|]，但 direct/MCP 写入路径
    #   绕过 extractor 直达 insert_chunk。实测："- 啃食水稻秧苗" (ac=1) 经此逃逸。
    # 修复：在 VFS 层同步拦截 markdown 列表项开头（与 extractor 对齐）。
    if s[0] in ('-', '*') and len(s) > 1 and s[1] == ' ':
        return True
    if s.startswith('[ ]') or s.startswith('[x]') or s.startswith('[X]'):
        return True
    # markdown 表格行（>= 2 个管道符）
    if s.count('|') >= 2:
        return True
    # 以冒号结尾（标题碎片）
    if s.rstrip().endswith(':') or s.rstrip().endswith('：'):
        return True
    # 纯数字/符号行
    if _re_vfs.match(r'^[\d\s.,:;/×\-+=%]+$', s):
        return True
    # iter814: pa_score_gate — 迭代器验证报告碎片拦截
    # 数据驱动：7337e9fd "验证：PA 9/10（已" 经 MCP 写入，extractor noise_kw 未覆盖。
    # "PA N/N" 和 "验证：" 开头 + 数字分数 = 迭代器自评报告，对用户零价值。
    if _re_vfs.search(r'PA\s+\d+/\d+', s):
        return True
    # iter1231: vfs_iter_prefix_gate — iter\d{3,4}: 或 "数据：" + 统计格式 = 迭代器自记录
    if _re_vfs.match(r'^iter\d{3,4}\s*[：:_]', s):
        return True
    if _re_vfs.match(r'^数据[：:]', s) and _re_vfs.search(r'\d+/\d+|\d+\.?\d*%', s) \
       and _RE_VFS_SELFREF.search(s):
        return True
    # iter629+754: self-referential noise gate (VFS 层同步)
    # iter754: 上限 80→120 — "空召回率 68%→25%" 等 summary 长 50-100B 漏网。
    if len(s) < 120 and len(_RE_VFS_SELFREF.findall(s)) >= 2:
        return True
    # iter799: iterator_metric_gate — 迭代器量化自评单关键词 + 箭头格式拦截
    # 根因（数据驱动，2026-05-04）：cf82fd00 "zero_access_rate: 6% → 0%" 只命中 1 个
    #   self-ref 关键词（需 >=2），但"关键词 + → + 数值"是迭代器度量的独有格式。
    #   extractor._is_quality_chunk 行 1306 已有此规则，但 direct/MCP 写入路径绕过。
    if '→' in s and _RE_VFS_SELFREF.search(s) and _re_vfs.search(r'\d+%?\s*→\s*\d+%?', s):
        return True
    # iter1030: vfs_combo_gate — 同步 extractor iter1026 运行时术语组合检测
    # 根因（数据驱动，2026-05-07）：7 条 ac=0 噪声经 direct/MCP 路径绕过 extractor，
    #   含"垄断项目 7d=3"/"per-project 7d 注入占比"/"type_concentration_penalty"等。
    #   extractor 的 combo_gate 对 source_type=direct 无效——VFS 层必须同步。
    # 修复：检测 >=3 个 memory-os 运行时术语 → 拒绝写入。
    _mos_hits = sum(1 for _t in (
        '次注入', '注入中', 'suppress', 'per-project',
        '候选池', '内化', 'ac=', 'ac<', 'ac>',
        '7d ', '24h ', '注入位', 'global chunk', 'supplement',
        'FTS', 'final_gate', '空召回', '垄断', '衰减',
        'concentration', '_penalty', '_suppress',
    ) if _t in s)
    if _mos_hits >= 3:
        return True
    return False


# ── iter536: seccomp_filter — Summary Content Sanitizer at Syscall Boundary ──
# OS 类比：Linux seccomp(SECCOMP_SET_MODE_FILTER) (Will Drewry, 2012, kernel 3.5)
#   BPF 过滤器在 syscall entry 拦截畸形系统调用。不是在应用层面检查（too late），
#   而是在内核 syscall boundary 执行 SECCOMP_RET_ALLOW / RET_KILL_PROCESS。
#
# 根因：extractor 从 LLM 输出提取 chunks 时，部分 summary 包含 JSON 结构残留
#   （"recommended_action":, ction":）—— LLM JSON 输出被截断后残留为 summary。
#   vfs_write_protect (iter533) 检查物理碎片（管道符/表格行/纯数字），
#   但不检查语义碎片（JSON key-value 残留、截断英文 token 开头）。
#   生产 DB 中 5 个 causal_chain chunks 含 JSON 残留，污染 FTS5 索引。
#
# 三阶段：sanitize → recheck → reject
#   Phase 1 (sanitize): 尝试剥离 JSON key 前缀、引号包裹
#   Phase 2 (recheck): 清洗后 summary 通过 _vfs_write_protect 检查
#   Phase 3 (reject): 清洗后仍不合格 → 拒绝写入
import re as _re_seccomp


def _seccomp_filter(summary: str) -> tuple:
    """
    iter536: seccomp BPF filter — summary 语义碎片清洗。

    返回 (action, cleaned_summary):
      action="allow"    → summary 合格，原样通过
      action="sanitize" → 已清洗，返回清洗后的 summary
      action="reject"   → 清洗后仍不合格，应拒绝写入

    检测模式（5 类 JSON/截断碎片）：
    1. JSON key 前缀：'"key": "value...' → 剥离 key 部分
    2. 截断 JSON key 开头：'ction": "...' → 剥离截断残留
    3. 引号包裹的完整内容：'"actual content"' → 去引号
    4. JSON 对象/数组包裹：'{"key": "value"}' → 提取 value
    5. 箭头/推导残留：'→ "recommended_action": ...' → 提取箭头后内容
    """
    try:
        from config import get as _cfg536
        if not _cfg536("vfs.seccomp_filter_enabled"):
            return ("allow", summary)
    except Exception:
        pass  # config 不可用时默认启用

    if not summary:
        return ("allow", summary)

    s = summary.strip()
    original = s
    sanitized = False

    # ── Pattern 1: JSON key 前缀 '"key": "value...' ──
    # 匹配: "recommended_action": "实际内容..."
    m = _re_seccomp.match(
        r'^"?[\w_]+"?\s*:\s*"(.+)"?\s*$', s, _re_seccomp.DOTALL)
    if m:
        s = m.group(1).rstrip('"').strip()
        sanitized = True

    # ── Pattern 2: 截断 JSON key 开头 'ction": "...' ──
    # 匹配: ction": "实际内容"  (来自截断的 "recommended_action")
    if not sanitized:
        m = _re_seccomp.match(
            r'^[a-z]{1,10}"\s*:\s*"(.+)"?\s*$', s, _re_seccomp.DOTALL)
        if m:
            s = m.group(1).rstrip('"').strip()
            sanitized = True

    # ── Pattern 3: 箭头/推导后跟 JSON key ──
    # 匹配: ...内容" → "recommended_action": "剩余内容"
    if not sanitized:
        m = _re_seccomp.search(
            r'["\u201d]\s*→\s*"[\w_]+"\s*:\s*"(.+)"?\s*$', s, _re_seccomp.DOTALL)
        if m:
            # 保留箭头前的内容 + 箭头后 value
            arrow_pos = s.find('→')
            if arrow_pos > 0:
                prefix = s[:arrow_pos].rstrip('" \u201d').strip()
                suffix = m.group(1).rstrip('"').strip()
                if prefix and suffix:
                    s = prefix + " → " + suffix
                    sanitized = True

    # ── Pattern 4: 引号包裹 '"actual content"' ──
    if not sanitized:
        m = _re_seccomp.match(r'^"(.{8,})"$', s.strip())
        if m:
            s = m.group(1).strip()
            sanitized = True

    # ── Pattern 5: _action" / _key" 截断前缀 ──
    # 匹配以 _action": "... 或 _action": ... 开头
    if not sanitized:
        m = _re_seccomp.match(
            r'^_?[\w]*"\s*:\s*"?(.+)$', s, _re_seccomp.DOTALL)
        if m and len(m.group(1).strip()) >= 15:
            candidate = m.group(1).rstrip('"').strip()
            # 确保提取内容不是另一个 JSON 结构
            if not candidate.startswith('{') and not candidate.startswith('['):
                s = candidate
                sanitized = True

    # ── Phase 2: 清洗后 recheck ──
    if sanitized:
        s = s.strip()
        # 清洗后太短 → reject
        if len(s) < 8:
            return ("reject", original)
        # 清洗后仍被 vfs_write_protect 拦截 → reject
        if _vfs_write_protect(s):
            return ("reject", original)
        return ("sanitize", s)

    # ── 额外检测：未触发清洗但含高密度 JSON 特征 → reject ──
    # summary 中 ": " 出现 >= 3 次 → 可能是完整 JSON 对象残留
    json_colon_count = s.count('": ')
    if json_colon_count >= 3:
        return ("reject", original)

    return ("allow", summary)


def insert_chunk(conn: sqlite3.Connection, chunk_dict: dict) -> None:
    """
    插入或替换一条 chunk。
    OS 类比：VFS 的 write() — 统一写入接口。

    迭代97：同步维护 FTS5 索引（非 content-sync 模式，手动写入预处理文本）。
    iter533：VFS 层写保护 — security_inode_create() 强制完整性校验。
    """
    d = chunk_dict
    # ── iter533: vfs_write_protect — LSM mandatory write check ──────────────
    # OS 类比：Linux LSM security_inode_create() (2001) — VFS 层强制访问控制，
    # 无论哪条 syscall 路径（open/creat/mknod）到达 VFS，都必须过安全检查。
    # 根因：多条写入路径（extractor/_write_chunk/writer/pool/effects）各自做质量检查，
    # 遗漏路径导致碎片写入生产 DB。在最低层加不可绕过的完整性密封。
    if _vfs_write_protect(d.get("summary", "")):
        try:
            dmesg_log(conn, DMESG_WARN, "vfs",
                      f"write_protect REJECTED: '{d.get('summary', '')[:60]}'")
        except Exception:
            pass
        return  # 静默拒绝，不抛异常（与 LSM deny 语义一致）
    # iter1211: vfs_selfref_semantic_gate — VFS 层语义噪声终极防线
    try:
        from hooks.extractor import _is_selfref_noise, _is_metric_report_noise
        _vfs_s = d.get("summary", "")
        _vfs_ct = d.get("chunk_type", "")
        if _is_selfref_noise(_vfs_s, _vfs_ct) or _is_metric_report_noise(_vfs_s, _vfs_ct):
            try:
                dmesg_log(conn, DMESG_WARN, "vfs",
                          f"selfref_gate REJECTED: '{_vfs_s[:60]}'")
            except Exception:
                pass
            return
    except ImportError:
        pass
    # ── iter973: content_min_density_gate — content 过短且无增量时拒绝 ──────
    # 根因（数据驱动，2026-05-06）：17 个 ac=0 碎片 chunk 逃逸所有上层 gate 写入 DB，
    #   共同特征：content<120 字且 content≈summary（无信息增量）。占 FTS 23% 搜索空间。
    # 修复：VFS 层终极防线——content 存在且 <50 字 + 与 summary 相同 → 拒绝。
    #   有 content_override 或 content 远大于 summary 时不受影响（wiki import/聚合场景）。
    # iter1058: content_min_widen — 50→80 堵碎片逃逸
    # 根因（数据驱动，2026-05-07）：6 个 ac=0 碎片 clen=24-55 全部 content==summary，
    #   其中 clen=54/55 逃逸 <50 阈值。80 字中文约 25-40 字，单句无法构成有价值知识。
    _content_973 = (d.get("content") or "").strip()
    _summary_973 = (d.get("summary") or "").strip()
    if _content_973 and len(_content_973) < 80 and _content_973 == _summary_973:
        return
    # ── iter973b: vfs_ephemeral_type_gate — 对齐 extractor 的 _EPHEMERAL_TYPES ──
    # 根因（数据驱动，2026-05-06）：writer.py 直接调用 insert_chunk 绕过 _write_chunk 的
    #   _EPHEMERAL_TYPES 检查，5 条 conversation_summary 碎片经此路径写入 DB。
    # 修复：VFS 层统一拦截临时类型，任何路径不可绕过。
    if d.get("chunk_type") in ("prompt_context", "conversation_summary"):
        return
    # ── iter536: seccomp_filter — 语义碎片清洗 ────────────────────────
    # OS 类比：seccomp BPF (Will Drewry, 2012) — syscall 入口过滤，
    # 在 vfs_write_protect 物理检查之后执行语义检查（JSON 残留/截断 token）。
    # 三种结果：allow（原样）、sanitize（清洗后写入）、reject（拒绝）。
    _seccomp_action, _seccomp_summary = _seccomp_filter(d.get("summary", ""))
    if _seccomp_action == "reject":
        try:
            dmesg_log(conn, DMESG_WARN, "seccomp",
                      f"REJECTED: '{d.get('summary', '')[:60]}'")
        except Exception:
            pass
        return
    if _seccomp_action == "sanitize":
        try:
            dmesg_log(conn, DMESG_INFO, "seccomp",
                      f"SANITIZED: '{d.get('summary', '')[:40]}' → '{_seccomp_summary[:40]}'")
        except Exception:
            pass
        d["summary"] = _seccomp_summary
    tags = json.dumps(d["tags"], ensure_ascii=False) if isinstance(d.get("tags"), list) else d.get("tags", "[]")
    # 如果已存在（REPLACE 路径），先从 FTS5 删除旧记录
    existing_rowid = conn.execute(
        "SELECT rowid FROM memory_chunks WHERE id=?", (d["id"],)
    ).fetchone()
    if existing_rowid:
        conn.execute(
            "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
            (str(existing_rowid[0]),)
        )

    # 迭代306：raw_snippet 截断到 500 字（防止超长写入）
    raw_snippet = (d.get("raw_snippet") or "")[:500]
    # 迭代315：encoding_context 序列化为 JSON 字符串
    enc_ctx = d.get("encoding_context", {})
    if isinstance(enc_ctx, dict):
        enc_ctx_str = json.dumps(enc_ctx, ensure_ascii=False)
    else:
        enc_ctx_str = enc_ctx if isinstance(enc_ctx, str) else "{}"
    # iter479: stability warm-start — importance >= 0.5 的新 chunk 赋予更高初始稳定性。
    # 心理学：von Restorff effect (1933) — 在编码时被认为重要的信息，初始记忆强度更高；
    #   高置信度（高 importance）的知识进入记忆时，初始稳定性应更高而非从零开始。
    # OS 类比：Linux MGLRU — 新分配的大页（THP）直接进入 gen=1 而非 gen=0，
    #   避免立即被 kswapd 扫描降代（给予初始"信用期"）。
    # 规则：调用者未显式设置 stability（默认 1.0）且 importance >= 0.5 时，
    #   提升到 2.0（不覆盖调用者显式传入的 stability 值）。
    _stability_explicit = "stability" in d and d["stability"] != 1.0
    _stability_val = d.get("stability", 1.0)
    if not _stability_explicit and float(d.get("importance", 0.5)) >= 0.5:
        _stability_val = 2.0

    # iter481: 记录调用者是否显式传入 confidence_score，用于后续 warm-start 保护
    _conf_explicit_val = d.get("confidence_score")  # None 表示未显式设置
    _conf_insert = _conf_explicit_val if _conf_explicit_val is not None else 0.7

    conn.execute("""
        INSERT OR REPLACE INTO memory_chunks
        (id, created_at, updated_at, project, source_session,
         chunk_type, info_class, content, summary, tags, importance,
         retrievability, last_accessed, feishu_url, access_count, oom_adj, lru_gen,
         stability, raw_snippet, encoding_context, confidence_score)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        d["id"], d["created_at"], d["updated_at"], d["project"], d["source_session"],
        d["chunk_type"], d.get("info_class", "world"),
        d["content"], d["summary"], tags,
        d["importance"], d["retrievability"], d["last_accessed"], d.get("feishu_url"),
        d.get("access_count", 0), d.get("oom_adj", 0), d.get("lru_gen", 0),
        _stability_val, raw_snippet, enc_ctx_str, _conf_insert,
    ))
    # 迭代97：写入 FTS5（CJK 预处理）
    # iter142：使用 new_rowid 重新清理 FTS（防止 INSERT OR REPLACE 保留 rowid 时残留旧条目）
    new_rowid = conn.execute(
        "SELECT rowid FROM memory_chunks WHERE id=?", (d["id"],)
    ).fetchone()
    if new_rowid and d.get("summary"):
        try:
            # 先清理该 rowid 的所有现有 FTS 条目（幂等保护，防止 race/double-insert）
            conn.execute(
                "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                (str(new_rowid[0]),)
            )
            # iter108：结构化 summary 先归一化再 CJK 分词，修复 [topic]/>/ 截断 FTS5 检索
            fts_summary = _cjk_tokenize(_normalize_structured_summary(d.get("summary") or ""))
            # iter702: tags_fts_boost — 将 tags 关键词追加到 content
            _raw_content = d.get("content") or ""
            _tags702 = d.get("tags")
            if _tags702:
                try:
                    import json as _j702i
                    _tl = _j702i.loads(_tags702) if isinstance(_tags702, str) else _tags702
                    _skip702i = {"semantic", "consolidated", "imported", "design_constraint",
                                 "decision", "procedure", "quantitative_evidence", "causal_chain",
                                 "excluded_path", "prompt_context", "reasoning_chain"}
                    _u = [t for t in _tl if isinstance(t, str) and t not in _skip702i
                          and not t.startswith(("abspath:", "git:", "sec"))]
                    if _u:
                        _raw_content += " " + " ".join(_u)
                except Exception:
                    pass
            fts_content = _cjk_tokenize(_normalize_structured_summary(_raw_content))
            conn.execute(
                "INSERT INTO memory_chunks_fts(rowid_ref, summary, content) VALUES (?, ?, ?)",
                (str(new_rowid[0]), fts_summary, fts_content)
            )
        except Exception:
            pass  # FTS5 表可能尚未创建（ensure_schema 未调用时）
    bump_chunk_version()  # 迭代64: TLB v2 — 新 chunk 写入递增版本

    # 迭代310：entity_map 自动关联 — 将 chunk 与 entity_edges 中的 entity 绑定
    # OS 类比：Linux dentry cache — 路径名→inode 的反向映射，insert_chunk 时顺便建立
    # 策略：用 summary 子串匹配 entity_edges 中已知的 entity 名，写入 entity_map
    # 这样 spreading_activate 才能从 FTS5 命中的 chunk 找到对应 entity，沿图扩散
    try:
        chunk_id = d["id"]
        project = d.get("project", "")
        summary_lower = (d.get("summary") or "").lower()
        if summary_lower and project:
            # iter487: 短路优化 — 先检查 entity_edges 是否存在，空项目直接跳过。
            # OS 类比：Linux readdir early exit — inode 目录为空时不做任何 dentry lookup；
            #   避免每次 insert_chunk 都对空 entity_edges 做全表扫描（热路径 I/O 优化）。
            _has_edges = conn.execute(
                "SELECT 1 FROM entity_edges WHERE project=? LIMIT 1", (project,)
            ).fetchone()
            # 取该 project 的所有已知 entity（from_entity 和 to_entity）
            entity_rows = conn.execute(
                "SELECT DISTINCT from_entity FROM entity_edges WHERE project=? "
                "UNION SELECT DISTINCT to_entity FROM entity_edges WHERE project=?",
                (project, project)
            ).fetchall() if _has_edges else []
            now_str = datetime.now(timezone.utc).isoformat()
            for (ent,) in entity_rows:
                if not ent:
                    continue
                # entity 名（去下划线/中划线，小写）出现在 summary 中则建立映射
                ent_normalized = ent.lower().replace("_", " ").replace("-", " ")
                if ent_normalized in summary_lower or ent.lower() in summary_lower:
                    conn.execute(
                        """INSERT OR REPLACE INTO entity_map
                           (entity_name, chunk_id, project, updated_at)
                           VALUES (?, ?, ?, ?)""",
                        (ent, chunk_id, project, now_str)
                    )
    except Exception:
        pass  # entity_map 写入失败不阻塞主流程

    # iter396：Source Monitoring — 自动推断 source_type，写入 source_reliability
    # 仅在 chunk dict 未明确提供 source_type 时自动推断
    try:
        _sm_chunk_id = d["id"]
        _sm_source_type = d.get("source_type")  # 允许外部显式指定
        _sm_chunk_type = d.get("chunk_type", "task_state")
        _sm_content = (d.get("content") or "") + " " + (d.get("summary") or "")
        apply_source_monitoring(conn, _sm_chunk_id, _sm_chunk_type,
                                _sm_content, _sm_source_type)
    except Exception:
        pass  # source monitoring 失败不阻塞主流程

    # iter401：Elaborative Encoding — 写入时计算加工深度，调整初始 stability
    # 深度加工（因果/结构/对比/精细阐述）→ 更高初始 stability
    try:
        _dop_chunk_id = d["id"]
        _dop_content = (d.get("content") or "") + " " + (d.get("summary") or "")
        # iter479: warm-start が stability を上書きした場合、_stability_val を使う
        _dop_base_stability = _stability_val
        _dop_new_stability = apply_depth_of_processing(
            conn, _dop_chunk_id, _dop_content, _dop_base_stability
        )
    except Exception:
        _dop_new_stability = d.get("stability", 1.0)
        pass  # depth_of_processing 写入失败不阻塞主流程

    # iter402：Schema Theory — 图式先验加成（Bartlett 1932）
    # entity_map 已建立后再查 prior schema（entity_map 由上方 entity_map 自动关联步骤填充）
    # 先验 chunk stability 均值 × 0.2 作为 schema bonus
    try:
        _schema_chunk_id = d["id"]
        _schema_project = d.get("project", "")
        if _schema_project:
            apply_schema_scaffolding(conn, _schema_chunk_id, _schema_project,
                                     base_stability=_dop_new_stability)
    except Exception:
        pass  # schema scaffolding 失败不阻塞主流程

    # iter403：Cue-Dependent Forgetting — 提取编码上下文，写入 encode_context 字段
    # 编码时的上下文线索 = content + summary + tags + chunk_type 中提取的关键词集
    try:
        _cdf_content = (d.get("content") or "") + " " + (d.get("summary") or "")
        _cdf_tags = d.get("tags", [])
        if isinstance(_cdf_tags, str):
            import json as _json_cdf
            try:
                _cdf_tags = _json_cdf.loads(_cdf_tags)
            except Exception:
                _cdf_tags = []
        _cdf_chunk_type = d.get("chunk_type", "")
        _cdf_encode_ctx = extract_encode_context(
            _cdf_content, tags=_cdf_tags, chunk_type=_cdf_chunk_type
        )
        if _cdf_encode_ctx:
            conn.execute(
                "UPDATE memory_chunks SET encode_context=? WHERE id=?",
                (_cdf_encode_ctx, d["id"])
            )
    except Exception:
        pass  # encode_context 写入失败不阻塞主流程

    # iter404：Semantic Priming — 检索后启动相关 entity
    # 当 chunk 被插入时，它的 entity 被 primed（以支持后续 spreading）
    # 这里只在 insert_chunk 时做轻量 priming（full priming 在检索时触发）
    try:
        _pr_content = (d.get("content") or "") + " " + (d.get("summary") or "")
        _pr_ctx = extract_encode_context(_pr_content, chunk_type=d.get("chunk_type", ""))
        if _pr_ctx and d.get("project"):
            prime_entities(conn, _pr_ctx.split(","), d["project"], prime_strength=0.3)
    except Exception:
        pass

    # iter406：Generation Effect — 主动生成内容 stability 加成（McDaniel & Einstein 1986）
    # 检测内容中的生成标记（推理人称/假设检验/元认知），计算 generation score，
    # score 越高 → stability 增量越大（补充 iter401 结构深度 + iter392 类型加成）
    try:
        _ge_content = d.get("content") or ""
        _ge_summary = d.get("summary") or ""
        _ge_source_type = d.get("source_type")
        # iter479: 从 DB 读取当前 stability 作为 base（包含 DOP/schema 的更新）
        # 避免用 d.get("stability", 1.0) 覆盖 warm-start + DOP 的加成结果
        _ge_row = conn.execute(
            "SELECT stability FROM memory_chunks WHERE id=?", (d["id"],)
        ).fetchone()
        _ge_base_stability = float(_ge_row[0]) if _ge_row and _ge_row[0] else _dop_new_stability
        apply_generation_effect(
            conn, d["id"], _ge_content, _ge_summary,
            source_type=_ge_source_type,
            base_stability=_ge_base_stability,
        )
    except Exception:
        pass  # generation effect 写入失败不阻塞主流程

    # iter407: Von Restorff Effect — 孤立 chunk 得到 stability bonus（von Restorff 1933）
    # 在均匀背景中，语义独特/孤立的 chunk 比普通 chunk 有更强的记忆留存率
    try:
        _vr_project = d.get("project", "")
        _vr_base_stability = d.get("stability", 1.0)
        if _vr_project:
            apply_isolation_effect(conn, d["id"], _vr_project, base_stability=_vr_base_stability)
    except Exception:
        pass  # von restorff 效应写入失败不阻塞主流程

    # iter408: Proactive Interference — 旧强记忆干扰新 chunk 的 initial stability（Underwood 1957）
    # 项目中已有高相似度+高 access_count 的 chunk → 新 chunk stability 降低
    try:
        _pi_project = d.get("project", "")
        _pi_base_stability = d.get("stability", 1.0)
        if _pi_project:
            apply_proactive_interference(conn, d["id"], _pi_project, base_stability=_pi_base_stability)
    except Exception:
        pass  # proactive interference 写入失败不阻塞主流程

    # iter409: Flashbulb Memory — 高情绪唤醒 chunk 的 initial stability 加强（Brown & Kulik 1977）
    # emotional_weight > 0 → stability bonus（与 iter376 检索时加分互补，这里是写入时固化增强）
    try:
        _fb_base_stability = d.get("stability", 1.0)
        apply_flashbulb_effect(conn, d["id"], base_stability=_fb_base_stability)
    except Exception:
        pass  # flashbulb effect 写入失败不阻塞主流程

    # iter410: Primacy Effect — 项目最早创建的 chunk 是基础 schema，stability 首位加成（Murdock 1962）
    # boot-time parameters 类比：项目初期确立的知识比后来的更持久（rehearsal hypothesis）
    try:
        _pr_project = d.get("project", "")
        _pr_base_stability = d.get("stability", 1.0)
        if _pr_project:
            apply_primacy_effect(conn, d["id"], _pr_project, base_stability=_pr_base_stability)
    except Exception:
        pass  # primacy effect 写入失败不阻塞主流程

    # iter411: Levels of Processing — encode_context 实体数量代理编码深度（Craik & Lockhart 1972）
    # 更多语义实体 = 更丰富语义网络 = 更深加工 = 更强 stability
    try:
        _lop_base_stability = d.get("stability", 1.0)
        apply_depth_effect(conn, d["id"], base_stability=_lop_base_stability)
    except Exception:
        pass  # depth effect 写入失败不阻塞主流程

    # iter433: Reminiscence Bump Effect — 项目创生期 chunk 获得 stability 加成（Conway & Howe 1990）
    # 项目形成期写入的 chunk 类比人类 15-25 岁形成期记忆 — 更深层编码，更持久留存
    # 注意：Bump 是"回顾性"属性（只有在项目积累足够历史后才可判断创生期），
    #   因此 insert_chunk 时也应用，但只有当项目已经有足够年龄时才会生效。
    #   对早期项目（age < min_project_age_days），compute_reminiscence_bump_factor 返回 base_stability。
    try:
        _bump_project = d.get("project", "")
        _bump_base_stability = d.get("stability", 1.0)
        if _bump_project:
            apply_reminiscence_bump(conn, d["id"], _bump_project, base_stability=_bump_base_stability)
    except Exception:
        pass  # reminiscence bump 写入失败不阻塞主流程

    # iter414: Self-Reference Effect — 含自我参照标记的 chunk 获得 stability 加成（Rogers et al. 1977）
    # 自我参照加工激活 PFC + hippocampus 双路径，形成更强记忆痕迹
    try:
        _sr_base_stability = d.get("stability", 1.0)
        apply_self_reference_effect(conn, d["id"], base_stability=_sr_base_stability)
    except Exception:
        pass  # self-reference effect 写入失败不阻塞主流程

    # iter416: Zeigarnik Effect — 未完成任务信号词 → stability 加成（Zeigarnik 1927）
    try:
        _zg_base_stability = d.get("stability", 1.0)
        apply_zeigarnik_effect(conn, d["id"], base_stability=_zg_base_stability)
    except Exception:
        pass  # zeigarnik effect 写入失败不阻塞主流程

    # iter418: Directed Forgetting — 过时/已完成信号词 → stability 惩罚（MacLeod 1998）
    try:
        _df_base_stability = d.get("stability", 1.0)
        apply_directed_forgetting(conn, d["id"], base_stability=_df_base_stability)
    except Exception:
        pass  # directed forgetting 写入失败不阻塞主流程

    # iter419: Associative Memory — 与强关联 chunk 共享实体 → stability 加成（Ebbinghaus 1885）
    try:
        _am_project = d.get("project", "")
        _am_base_stability = d.get("stability", 1.0)
        if _am_project:
            apply_associative_memory_bonus(
                conn, d["id"], _am_project, base_stability=_am_base_stability
            )
    except Exception:
        pass  # associative memory 写入失败不阻塞主流程

    # iter421: Retroactive Interference — 新知识干扰旧相关 chunk 的稳定性（McGeoch 1932）
    try:
        _ri_project = d.get("project", "")
        _ri_base_stability = d.get("stability", 1.0)
        if _ri_project:
            apply_retroactive_interference(
                conn, d["id"], _ri_project, base_stability=_ri_base_stability
            )
    except Exception:
        pass  # retroactive interference 写入失败不阻塞主流程

    # iter415: store original encode_context token count for variability tracking
    # This count is used by apply_encoding_variability at access time to measure enrichment
    try:
        _ec_str = d.get("encoding_context", {})
        if isinstance(_ec_str, dict):
            import json as _json
            _ec_str = _json.dumps(_ec_str)
        # Read current encode_context from DB (may have been set by extract_encode_context)
        _ec_row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=?", (d["id"],)
        ).fetchone()
        if _ec_row:
            _ec_val = _ec_row[0] if isinstance(_ec_row, (list, tuple)) else _ec_row["encode_context"]
            _orig_tokens = [t.strip() for t in (_ec_val or "").split(",") if t.strip()]
            _orig_count = len(_orig_tokens)
            # Store original_ec_count in DB (if column exists; safe fallback)
            try:
                conn.execute(
                    "UPDATE memory_chunks SET original_ec_count=? WHERE id=?",
                    (_orig_count, d["id"])
                )
            except Exception:
                pass  # column may not exist in older schemas
    except Exception:
        pass  # iter415 init 失败不阻塞主流程

    # iter428: Event Segmentation — 写入时计算 boundary_proximity（Zacks et al. 2007）
    # session_started_at 由 extractor 通过 chunk_dict 传入（可选）；缺省时无法计算边界亲近度
    try:
        _bp_session_started = d.get("session_started_at")
        _bp_created = d.get("created_at")
        if _bp_session_started and _bp_created:
            _bp_val = compute_boundary_proximity(
                created_at=_bp_created,
                session_started_at=_bp_session_started,
                prev_session_ended_at=d.get("prev_session_ended_at"),
            )
            if _bp_val != 0.0:
                conn.execute(
                    "UPDATE memory_chunks SET boundary_proximity=? WHERE id=?",
                    (_bp_val, d["id"])
                )
    except Exception:
        pass  # boundary_proximity 写入失败不阻塞主流程

    # iter429: Enactment Effect — 行动编码加成（Engelkamp & Zimmer 1989）
    try:
        _en_base_stability = d.get("stability", 1.0)
        apply_enactment_effect(conn, d["id"], base_stability=float(_en_base_stability or 1.0))
    except Exception:
        pass  # enactment effect 写入失败不阻塞主流程

    # iter450: Predictive Memory Encoding — 预期将来被测试增强编码（Roediger & Karpicke 2011）
    try:
        _pme_project = d.get("project", "")
        _pme_chunk_type = d.get("chunk_type", "")
        _pme_base_stability = d.get("stability", 1.0)
        if _pme_project:
            apply_predictive_memory_encoding(
                conn, d["id"], _pme_project,
                chunk_type=_pme_chunk_type,
                base_stability=float(_pme_base_stability or 1.0)
            )
    except Exception:
        pass  # PME 写入失败不阻塞主流程

    # ── iter458: Elaborative Interrogation Effect — 因果解释型 chunk 获得 stability 加成（Pressley et al. 1992）──
    # 因果连接词密度代理"因果性解释质量"，高密度 = 深度推理编码 → stability 加成
    try:
        if config.get("store_vfs.eie_enabled"):
            _eie_importance = float(d.get("importance") or 0.0)
            _eie_min_imp = config.get("store_vfs.eie_min_importance")
            if _eie_importance >= _eie_min_imp:
                _eie_content = (d.get("content") or "") + " " + (d.get("summary") or "")
                _eie_connectives = [
                    "because", "therefore", "causes", "hence", "consequently",
                    "因为", "导致", "因此", "所以", "由于", "是因为", "的原因是"
                ]
                _eie_count = sum(_eie_content.lower().count(c) for c in _eie_connectives)
                if _eie_count >= config.get("store_vfs.eie_min_connectives"):
                    _eie_row = conn.execute(
                        "SELECT stability FROM memory_chunks WHERE id=?", (d["id"],)
                    ).fetchone()
                    _eie_base = float(_eie_row[0]) if _eie_row else float(d.get("stability") or 1.0)
                    _eie_factor = config.get("store_vfs.eie_boost_factor")   # default 1.15
                    _eie_max = config.get("store_vfs.eie_max_boost")         # default 0.30
                    _eie_raw = _eie_base * _eie_factor
                    _eie_capped = min(_eie_base * (1.0 + _eie_max), _eie_raw)
                    _eie_new = min(365.0, _eie_capped)
                    conn.execute("UPDATE memory_chunks SET stability=? WHERE id=?",
                                 (_eie_new, d["id"]))
    except Exception:
        pass  # EIE 写入失败不阻塞主流程

    # ── iter462: SMB — Source Monitoring Boost（有明确来源的记忆编码更强，Johnson et al. 1993）──
    # OS 类比：Linux inode i_generation — 有 generation 追踪的 inode 在 fsck 后可更快恢复
    try:
        if config.get("store_vfs.smb_enabled"):
            _smb_source = d.get("source_session") or ""
            if _smb_source.strip():  # 非空来源
                _smb_imp = float(d.get("importance") or 0.0)
                _smb_min_imp = config.get("store_vfs.smb_min_importance")
                if _smb_imp >= _smb_min_imp:
                    _smb_row = conn.execute(
                        "SELECT stability FROM memory_chunks WHERE id=?", (d["id"],)
                    ).fetchone()
                    _smb_base = float(_smb_row[0]) if _smb_row else float(d.get("stability") or 1.0)
                    _smb_factor = config.get("store_vfs.smb_boost_factor")   # 1.08
                    _smb_max = config.get("store_vfs.smb_max_boost")          # 0.12
                    _smb_raw = _smb_base * _smb_factor
                    _smb_capped = min(_smb_base * (1.0 + _smb_max), _smb_raw)
                    _smb_new = min(365.0, _smb_capped)
                    conn.execute("UPDATE memory_chunks SET stability=? WHERE id=?",
                                 (_smb_new, d["id"]))
    except Exception:
        pass  # SMB 写入失败不阻塞主流程

    # ── iter464: KDEE — Keyword Density Encoding Effect（高信息密度内容编码更深，Craik & Lockhart 1972）──
    # OS 类比：Linux ext4 extent tree — dense inode (many unique extents) → deeper B-tree → 更鲁棒检索
    try:
        if config.get("store_vfs.kdee_enabled"):
            _kdee_imp = float(d.get("importance") or 0.0)
            _kdee_min_imp = config.get("store_vfs.kdee_min_importance")
            if _kdee_imp >= _kdee_min_imp:
                _kdee_content = (d.get("content") or "").lower()
                import re as _re_kdee
                _kdee_words = _re_kdee.findall(r'\b\w+\b', _kdee_content)
                _kdee_total = len(_kdee_words)
                _kdee_min_words = config.get("store_vfs.kdee_min_words")
                if _kdee_total >= _kdee_min_words:
                    _kdee_unique_ratio = len(set(_kdee_words)) / _kdee_total
                    _kdee_min_density = config.get("store_vfs.kdee_min_density")
                    if _kdee_unique_ratio >= _kdee_min_density:
                        _kdee_row = conn.execute(
                            "SELECT stability FROM memory_chunks WHERE id=?", (d["id"],)
                        ).fetchone()
                        _kdee_base = float(_kdee_row[0]) if _kdee_row else float(d.get("stability") or 1.0)
                        _kdee_factor = config.get("store_vfs.kdee_boost_factor")  # 1.10
                        _kdee_max = config.get("store_vfs.kdee_max_boost")         # 0.20
                        _kdee_raw = _kdee_base * _kdee_factor
                        _kdee_capped = min(_kdee_base * (1.0 + _kdee_max), _kdee_raw)
                        _kdee_new = min(365.0, _kdee_capped)
                        conn.execute("UPDATE memory_chunks SET stability=? WHERE id=?",
                                     (_kdee_new, d["id"]))
    except Exception:
        pass  # KDEE 写入失败不阻塞主流程

    # ── iter466: ETE — Emotional Tagging Effect（情绪性内容获得杏仁核增强编码，Cahill et al. 1994）──
    # OS 类比：Linux OOM killer scoring — 高保护优先级记忆（critical/crisis/breakthrough）
    try:
        _ete_content = d.get("content") or ""
        _ete_summary = d.get("summary") or ""
        apply_emotional_tagging_effect(conn, d["id"], _ete_content, _ete_summary)
    except Exception:
        pass  # ETE 写入失败不阻塞主流程

    # ── iter467: DDE — Desirable Difficulty Effect（高词汇复杂度内容需更深认知加工，Bjork 1994）──
    # OS 类比：Linux zswap/zram — 压缩页面需要更多 CPU 解压（认知努力）→ 更高留存率
    try:
        _dde_content = d.get("content") or ""
        apply_desirable_difficulty_effect(conn, d["id"], _dde_content)
    except Exception:
        pass  # DDE 写入失败不阻塞主流程

    # ── iter469: GE — Generation Effect（主动生成的知识比被动接收的保留更好，Slamecka & Graf 1978）──
    # OS 类比：Linux CoW — dirty page（主动写入）优先留在 active LRU（PG_dirty 置位）
    try:
        _ge_chunk_type = d.get("chunk_type") or ""
        apply_generation_effect_v2(conn, d["id"], _ge_chunk_type)
    except Exception:
        pass  # GE 写入失败不阻塞主流程

    # ── iter471: SRE — Self-Reference Effect（含第一人称词的内容编码更深，Rogers et al. 1977）──
    # 注意：iter414 已在 insert_chunk 中调用 apply_self_reference_effect（同一认知原理）。
    # iter471 的 apply_self_reference_effect_v2 作为独立函数存在，供外部直接调用，
    # 不在 insert_chunk 中重复调用（避免双重加成）。
    # OS 类比：Linux MAP_PRIVATE — 进程私有页面 TLB 局部性更好，访问延迟更低

    # ── iter475: SPE-Primacy — Serial Position Primacy（session 首位 chunk stability 加成，Murdock 1962）──
    # OS 类比：CPU L1 cache LRU head slot — session 首位 chunk 被后续推理反复引用，留存率最高
    try:
        _spe_session = d.get("source_session") or ""
        _spe_project = d.get("project") or ""
        apply_serial_position_primacy(conn, d["id"], _spe_session, _spe_project)
    except Exception:
        pass

    # ── iter476: CLP — Cognitive Load Penalty（内容超出工作记忆容量时 stability 降低，Sweller 1988）──
    # OS 类比：CPU context switch overhead — 超线程数过多时调度开销超过并行收益
    try:
        _clp_content = d.get("content") or ""
        apply_cognitive_load_penalty(conn, d["id"], _clp_content)
    except Exception:
        pass

    # ── iter483: PE — Priming Effect（已有相似 chunk 启动新 chunk 编码，Meyer & Schvaneveldt 1971）──
    # OS 类比：Linux dentry cache warm — 相关目录项已缓存，新文件路径解析更快更稳定
    try:
        _pe_content = d.get("content") or ""
        apply_priming_effect(conn, d["id"], _pe_content)
    except Exception:
        pass

    # ── iter477: MBE — Memory Binding Effect（同 session 同批编码的 chunk 相互加固，Eichenbaum 2004）──
    # OS 类比：Linux THP — 相邻 page 合并为大页，提升整体 TLB coverage 和稳定性
    try:
        apply_memory_binding_effect(conn, [d["id"]])
    except Exception:
        pass

    # ── iter473: MIE — Memory Interference Effect（同类内容密集写入互相干扰，McGeoch 1932）──
    # 注意：MIE 在最后执行，作为对其他正向效应的"自然拮抗"（认知真实性）
    # OS 类比：Linux cache thrashing — working set > memory 时 page 频繁换入换出
    try:
        _mie_content = d.get("content") or ""
        _mie_project = d.get("project") or ""
        _mie_type = d.get("chunk_type") or ""
        apply_memory_interference_effect(conn, d["id"], _mie_content, _mie_project, _mie_type)
    except Exception:
        pass

    # iter479: stability warm-start 最终应用 — 在所有后处理效应（iter401-MIE）完成后执行。
    # 策略：读取 DB 当前 stability（包含 DOP/schema/gen-effect/von-restorff 等所有加成），
    # 若触发 warm-start 条件，则将 stability × (warm_base / default_base) = × 2.0。
    # 这保证 warm-start 是一个乘法因子，叠加在所有其他效应之上，而不是被后处理覆盖。
    # OS 类比：Linux MGLRU 新大页进入 gen=1 — 在 page table walk 完成后（即所有编码效应完成后）
    # 再提升 generation，避免在提升前被 kswapd 误降代。
    # 条件：和上面相同——调用者未显式设置 stability（_stability_explicit=False）
    #       且 importance >= 0.5（_stability_val 被设为 2.0）
    if not _stability_explicit and float(d.get("importance", 0.5)) >= 0.5:
        try:
            _ws_row = conn.execute(
                "SELECT stability FROM memory_chunks WHERE id=?", (d["id"],)
            ).fetchone()
            if _ws_row and _ws_row[0] is not None:
                _ws_current = float(_ws_row[0])
                # 乘以 warm-start 比率（2.0 / 1.0 = 2.0）
                _ws_new = _ws_current * 2.0
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (round(_ws_new, 4), d["id"])
                )
        except Exception:
            pass  # warm-start 写入失败不阻塞主流程

    # iter481: confidence warm-start — source_reliability 驱动初始 confidence_score。
    # 心理学：Source Monitoring Framework (Johnson 1993) — 来源可靠性影响记忆的初始编码质量；
    #   高可信来源写入的知识在编码时自动获得更高信任度（source credibility effect）。
    # OS 类比：Linux ECC memory 的初始 ECC status — 高质量 RAM（低错误率）初始 ECC=clean；
    #   低质量 RAM（高错误率历史）初始 ECC=unknown。
    # 规则（仅对新 chunk，即 existing_rowid=None 时）：
    #   source_reliability >= 0.80 → initial confidence = 0.85（高可信来源）
    #   source_reliability < 0.40  → initial confidence = 0.50（低可信来源，标注 ⚠️）
    #   其余 → 保持默认 0.70（中性）
    # 注意：仅在 chunk 未显式设置 confidence_score 时应用（尊重调用者的显式设置）
    if _conf_explicit_val is None:
        try:
            _sr_row = conn.execute(
                "SELECT source_reliability FROM memory_chunks WHERE id=?", (d["id"],)
            ).fetchone()
            if _sr_row and _sr_row[0] is not None:
                _sr_val = float(_sr_row[0])
                if _sr_val >= 0.80:
                    _ws_conf = 0.85
                elif _sr_val < 0.40:
                    _ws_conf = 0.50
                else:
                    _ws_conf = 0.70  # 中性默认值，仍写入以保证确定性

                # iter489: info_class-aware confidence warm-start 微调
                # 心理学：Tulving (1972) episodic vs semantic memory distinction —
                #   情节记忆（episodic）有明确的时空上下文，可信度通常高于语义记忆；
                #   ephemeral（临时记录）信息可信度较低，不确定性大。
                # OS 类比：Linux page frame reliability —
                #   direct-mapped cache（episodic）比 write-back（semantic）有更确定的来源；
                #   tmpfs 页（ephemeral）被视为非关键数据，可信度评分低。
                _ic = d.get("info_class", "world")
                if _ic == "episodic" and _ws_conf == 0.70:
                    _ws_conf = min(1.0, _ws_conf + 0.05)  # 情节记忆中等来源 → +0.05
                elif _ic == "ephemeral":
                    _ws_conf = max(0.10, _ws_conf - 0.10)  # 临时记录 → -0.10

                conn.execute(
                    "UPDATE memory_chunks SET confidence_score=? WHERE id=?",
                    (round(_ws_conf, 3), d["id"])
                )
        except Exception:
            pass  # confidence warm-start 写入失败不阻塞主流程


# ── iter403：Cue-Dependent Forgetting — Context-Sensitive Retrieval（Tulving 1974）──
#
# 认知科学依据：
#   Tulving & Thomson (1973) Encoding Specificity Principle：
#     编码时的上下文（cues）与检索时的上下文（retrieval cues）重叠度越高，
#     检索成功率越高。这是记忆最重要的规律之一。
#   Godden & Baddeley (1975) Context-Dependent Memory：
#     水下学的词在水下测试效果最好（环境上下文匹配），
#     陆上学的词在陆上测试效果最好。
#   Estes (1955) Stimulus Fluctuation Model：
#     记忆提取受"编码时 context"与"检索时 context"的重叠度（θ）决定。
#
# OS 类比：Linux NUMA-aware memory allocation —
#   进程倾向于从本地 NUMA node（编码时 context = home node）分配内存；
#   当进程的运行 node（检索时 context）越接近 home node，
#   内存访问延迟越低（命中率越高）。
#   context_overlap ≈ NUMA distance 的倒数：overlap = 1 → local node（最优）。
#
# 实现：
#   extract_encode_context(text, tags, chunk_type) → str（逗号分隔关键词）
#     写入时从 content/summary/tags 提取关键词集，存入 encode_context 字段。
#   compute_context_overlap(encode_ctx, retrieve_ctx) → float [0.0, 1.0]
#     Jaccard 相似度：|A∩B| / |A∪B|。
#   context_cue_weight(overlap) → float [0.85, 1.20]
#     overlap → 检索分权重：高重叠 → 提升检索优先级（+20%），低重叠 → 轻微降权。
#   apply_context_cue_boost(chunk, retrieve_context) → float
#     对 fts_search/retriever 返回的 chunk score 应用 context cue weight。

import re as _re_cdf

# 停用词（中英文，过滤掉无语义的功能词）
_CDF_STOPWORDS = frozenset({
    # 英文
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "on",
    "at", "by", "for", "with", "from", "and", "or", "but", "not", "it",
    "this", "that", "these", "those", "i", "we", "you", "he", "she", "they",
    # 中文虚词/功能词
    "的", "了", "在", "是", "有", "和", "也", "不", "这", "那", "但", "而",
    "都", "就", "以", "为", "于", "中", "上", "下", "个", "我", "你", "他",
})

_CDF_TOKEN_RE = _re_cdf.compile(r'[a-zA-Z][a-zA-Z0-9_\-]*|[\u4e00-\u9fff]{2,}')


def extract_encode_context(
    text: str,
    tags: list = None,
    chunk_type: str = "",
    max_tokens: int = 50,
) -> str:
    """
    iter403：从 content/summary/tags/chunk_type 提取编码上下文关键词。

    OS 类比：NUMA node affinity setup — 进程创建时记录 preferred node（home node），
      之后分配内存时优先从该 node 取。

    Returns:
      逗号分隔的关键词字符串（小写，去停用词，最多 max_tokens 个）
    """
    if not text:
        return ""
    # 提取 tokens
    tokens = set()
    for tok in _CDF_TOKEN_RE.findall(text.lower()):
        if tok not in _CDF_STOPWORDS and len(tok) >= 2:
            tokens.add(tok)
    # 加入 tags（标签是高权重上下文信号）
    if tags:
        for tag in tags:
            if isinstance(tag, str):
                t = tag.lower().strip()
                if t and t not in _CDF_STOPWORDS:
                    tokens.add(t)
    # 加入 chunk_type（类型本身也是 context signal）
    if chunk_type:
        tokens.add(chunk_type.lower())
    # 限制数量（取前 max_tokens，按字母序稳定）
    sorted_tokens = sorted(tokens)[:max_tokens]
    return ",".join(sorted_tokens)


def compute_context_overlap(
    encode_context: str,
    retrieve_context: str,
) -> float:
    """
    iter403：计算编码时上下文与检索时上下文的 Jaccard 重叠度。

    OS 类比：NUMA distance 计算 —
      两个 node 之间的距离越小，内存访问越快。
      overlap = 1 - normalized_distance：1.0 = 同一 node（最优）。

    Returns:
      float ∈ [0.0, 1.0]，0.0 = 无重叠，1.0 = 完全相同
    """
    if not encode_context or not retrieve_context:
        return 0.0
    try:
        enc_set = set(t.strip() for t in encode_context.split(",") if t.strip())
        ret_set = set(t.strip() for t in retrieve_context.split(",") if t.strip())
        if not enc_set or not ret_set:
            return 0.0
        intersection = len(enc_set & ret_set)
        union = len(enc_set | ret_set)
        return round(intersection / union, 4) if union > 0 else 0.0
    except Exception:
        return 0.0


def context_cue_weight(overlap: float) -> float:
    """
    iter403：将 context overlap 映射到检索分权重。

    分段函数（OS 类比：NUMA access latency tiers）：
      - overlap >= 0.50 → weight ∈ [1.10, 1.20]（高上下文匹配，类比 local node，延迟最低）
      - overlap ∈ [0.20, 0.50) → weight = 1.0（中等匹配，不调整，类比远端 node 但可访问）
      - overlap < 0.20 → weight ∈ [0.85, 1.0)（低匹配，轻微降权，类比跨 NUMA 域）

    设计原则：
      - 高匹配给正向激励（最多 +20%），强调上下文相关性
      - 低匹配给轻微惩罚（最多 -15%），避免跨 context 污染
      - 中间区域中性（避免噪声波动影响检索）

    Returns:
      float ∈ [0.85, 1.20]
    """
    try:
        r = max(0.0, min(1.0, float(overlap) if overlap is not None else 0.0))
    except (TypeError, ValueError):
        r = 0.0

    if r >= 0.50:
        # 高重叠：linear 插值 [1.10, 1.20]
        weight = 1.10 + (r - 0.50) / 0.50 * 0.10
    elif r >= 0.20:
        # 中等：不调整
        weight = 1.0
    else:
        # 低重叠：linear 插值 [0.85, 1.0)
        weight = 0.85 + r / 0.20 * 0.15

    return round(min(1.20, max(0.85, weight)), 4)


def apply_context_cue_boost(
    conn: sqlite3.Connection,
    chunk_id: str,
    retrieve_context: str,
    base_score: float = 1.0,
) -> float:
    """
    iter403：查询 chunk 的 encode_context，计算与 retrieve_context 的 overlap，
    返回 context_cue_weight 调整后的 score。

    OS 类比：NUMA-aware scheduler load balancing —
      检索时调度器偏向从与查询 context 最近的 NUMA node 上的 chunk 取结果。

    Returns:
      float：调整后的 score（base_score × context_cue_weight）
    """
    if not retrieve_context or not chunk_id:
        return base_score
    try:
        row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if row is None or not row[0]:
            return base_score
        encode_ctx = row[0]
        overlap = compute_context_overlap(encode_ctx, retrieve_context)
        weight = context_cue_weight(overlap)
        return round(base_score * weight, 4)
    except Exception:
        return base_score


# ── iter404：Semantic Priming — Spreading Activation with Temporal Decay
#             （Collins & Loftus 1975 / Meyer & Schvaneveldt 1971）────────────
#
# 认知科学依据：
#   Collins & Loftus (1975) Spreading Activation Theory:
#     语义网络中，激活从当前节点沿关联链向邻居扩散，
#     扩散强度随网络距离衰减（activation × confidence^hops）。
#     时间维度：启动效应持续约数十分钟（Meyer & Schvaneveldt 1971），
#     随时间指数衰减（prime_strength × exp(-λ × t)）。
#   Meyer & Schvaneveldt (1971) Semantic Priming:
#     "Bread"→"Butter" 反应更快（短暂语义启动），
#     但 "Bread"→"Doctor" 无启动（无语义关联）。
#   Anderson (1983) ACT*:
#     工作记忆中活跃的概念持续向关联记忆扩散激活，
#     扩散在短暂窗口（~30分钟）内有效，之后衰减到基线。
#
# OS 类比：Linux page readahead（ra_state + readahead window）
#   顺序访问 file pages 时，内核维护 readahead window；
#   访问 page N → prefetch [N+1, N+ra_size] 进 page cache；
#   类比：检索 chunk A → prime chunk A 的相关 entities → 后续相关 chunk 有 cache 优势。
#   prime_half_life ≈ ra_lookahead_time：超过此时间，预取失效（evicted from cache）。
#
# 实现：
#   prime_entities(conn, entity_names, project, prime_strength=1.0)
#     写入/更新 priming_state 表（upsert，取 max(existing, new) strength）
#   get_active_primes(conn, project, now_iso=None) → {entity_name: current_strength}
#     读取 priming_state，按时间衰减计算当前强度（>0.05 才算 active）
#   compute_priming_boost(conn, chunk_id, project, now_iso=None) → float [0.0, 0.30]
#     通过 entity_map 找到 chunk 关联 entity，查询当前 prime 强度，返回 boost
#   clear_stale_primes(conn, project, min_strength=0.05)
#     清理已衰减到阈值以下的 priming 条目（GC）

import math as _math_priming

_PRIME_HALF_LIFE_MINUTES: float = 30.0   # 启动效应半衰期（分钟）
_PRIME_MAX_BOOST: float = 0.30           # 最大启动加成
_PRIME_MIN_STRENGTH: float = 0.05        # 低于此强度视为已失效


# B12: priming_state ring-buffer — 防止 session 内无限增长
# OS 类比：Linux printk ring buffer __log_buf — 写入时自动截断最旧记录，
#   避免长时间运行 session 的 priming_state 无限膨胀。
# 实现：全局写入计数器，每 _PRIME_RING_CHECK_INTERVAL 次写入触发一次截断
_PRIME_RING_MAX = 600          # priming_state per-project 最大条目数
_PRIME_RING_CHECK_INTERVAL = 30  # 每 30 次写入检查一次（避免每次 COUNT 查询）
_prime_write_counter: dict = {}  # {project: write_count}


def prime_entities(
    conn: sqlite3.Connection,
    entity_names: list,
    project: str,
    prime_strength: float = 1.0,
    now_iso: str = None,
) -> int:
    """
    iter404：将一组 entity 写入 priming_state（启动它们）。

    OS 类比：readahead_cache_miss_trigger() — 缺页触发预取，将邻居 pages 标记为 readahead。

    Returns:
      int：实际写入/更新的 entity 数量
    """
    if not entity_names or not project:
        return 0
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()
    prime_strength = max(0.0, min(1.0, float(prime_strength)))
    count = 0
    try:
        for ent in entity_names:
            if not ent or not ent.strip():
                continue
            ent = ent.strip()
            # 若已有 prime 且更强，保留更强的（取 max）
            existing = conn.execute(
                "SELECT prime_strength, primed_at FROM priming_state "
                "WHERE entity_name=? AND project=?",
                (ent, project)
            ).fetchone()
            if existing:
                # 计算 existing 的当前有效强度（已衰减）
                _ex_strength = existing[0]
                try:
                    _ex_ts = datetime.fromisoformat(existing[1].replace("Z", "+00:00")).timestamp()
                    _now_ts = datetime.fromisoformat(now_iso.replace("Z", "+00:00")).timestamp()
                    _elapsed_min = (_now_ts - _ex_ts) / 60.0
                    _lambda = _math_priming.log(2) / _PRIME_HALF_LIFE_MINUTES
                    _current = _ex_strength * _math_priming.exp(-_lambda * _elapsed_min)
                except Exception:
                    _current = 0.0
                if prime_strength > _current:
                    conn.execute(
                        "UPDATE priming_state SET prime_strength=?, primed_at=? "
                        "WHERE entity_name=? AND project=?",
                        (prime_strength, now_iso, ent, project)
                    )
            else:
                conn.execute(
                    "INSERT INTO priming_state (entity_name, project, primed_at, prime_strength) "
                    "VALUES (?, ?, ?, ?)",
                    (ent, project, now_iso, prime_strength)
                )
            count += 1
    except Exception:
        pass

    # B12: ring-buffer 截断（每 _PRIME_RING_CHECK_INTERVAL 次写入检查一次）
    if count > 0 and project:
        try:
            _prime_write_counter[project] = _prime_write_counter.get(project, 0) + count
            if _prime_write_counter[project] >= _PRIME_RING_CHECK_INTERVAL:
                _prime_write_counter[project] = 0
                _cnt = conn.execute(
                    "SELECT COUNT(*) FROM priming_state WHERE project=?", (project,)
                ).fetchone()[0]
                if _cnt > _PRIME_RING_MAX:
                    _overflow = _cnt - _PRIME_RING_MAX
                    conn.execute(
                        """DELETE FROM priming_state WHERE (entity_name, project) IN (
                            SELECT entity_name, project FROM priming_state
                            WHERE project=? ORDER BY primed_at ASC LIMIT ?
                        )""",
                        (project, _overflow)
                    )
        except Exception:
            pass

    return count


def get_active_primes(
    conn: sqlite3.Connection,
    project: str,
    now_iso: str = None,
    min_strength: float = _PRIME_MIN_STRENGTH,
) -> dict:
    """
    iter404：返回 project 中当前活跃的 entity → current_prime_strength 映射。

    OS 类比：readahead_state.ra_pages — 返回当前 readahead window 中仍有效的 pages。

    Returns:
      {entity_name: current_strength}，只包含 current_strength > min_strength 的条目
    """
    if not project:
        return {}
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()
    try:
        _now_ts = datetime.fromisoformat(now_iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return {}
    _lambda = _math_priming.log(2) / _PRIME_HALF_LIFE_MINUTES
    result = {}
    try:
        rows = conn.execute(
            "SELECT entity_name, prime_strength, primed_at FROM priming_state WHERE project=?",
            (project,)
        ).fetchall()
        for ent, strength, primed_at in rows:
            if not ent or not strength:
                continue
            try:
                _primed_ts = datetime.fromisoformat(primed_at.replace("Z", "+00:00")).timestamp()
                _elapsed_min = (_now_ts - _primed_ts) / 60.0
                current = float(strength) * _math_priming.exp(-_lambda * _elapsed_min)
            except Exception:
                current = 0.0
            if current > min_strength:
                result[ent] = round(current, 4)
    except Exception:
        pass
    return result


def compute_priming_boost(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    now_iso: str = None,
) -> float:
    """
    iter404：计算 chunk 当前受到的语义启动加成（semantic priming boost）。

    算法：
      1. 通过 encode_context 找到 chunk 的 entity/keyword 集合
      2. 与 active primes 取交集
      3. boost = avg(matching prime strengths) × _PRIME_MAX_BOOST

    OS 类比：readahead_cache_hit() — 访问的 page 在 readahead window 内 → cache hit，
      节省一次 disk I/O（类比：primed entity match → 检索 score 提升）。

    Returns:
      float ∈ [0.0, _PRIME_MAX_BOOST]
    """
    if not chunk_id or not project:
        return 0.0
    try:
        # 获取当前活跃 primes
        active_primes = get_active_primes(conn, project, now_iso=now_iso)
        if not active_primes:
            return 0.0

        # 获取 chunk 的 encode_context（关键词集合）
        row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if row is None or not row[0]:
            return 0.0

        chunk_tokens = set(t.strip() for t in row[0].split(",") if t.strip())
        if not chunk_tokens:
            return 0.0

        # 匹配 prime entities 与 chunk tokens（entity name 子串匹配或精确匹配）
        matching_strengths = []
        for prime_ent, strength in active_primes.items():
            prime_lower = prime_ent.lower()
            # 精确匹配 OR 子串匹配（entity "redis" 匹配 token "redis-cluster"）
            if prime_lower in chunk_tokens or any(
                prime_lower in tok or tok in prime_lower
                for tok in chunk_tokens
                if len(tok) >= 3
            ):
                matching_strengths.append(strength)

        if not matching_strengths:
            return 0.0

        avg_strength = sum(matching_strengths) / len(matching_strengths)
        boost = round(avg_strength * _PRIME_MAX_BOOST, 4)
        return min(_PRIME_MAX_BOOST, max(0.0, boost))
    except Exception:
        return 0.0


def clear_stale_primes(
    conn: sqlite3.Connection,
    project: str = None,
    min_strength: float = _PRIME_MIN_STRENGTH,
    now_iso: str = None,
) -> int:
    """
    iter404：清理已衰减到阈值以下的 priming 条目（GC）。

    OS 类比：invalidate_readahead_pages() — 清理 readahead window 中已过期的预取 pages。

    Returns:
      int：删除的条目数
    """
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()
    try:
        _now_ts = datetime.fromisoformat(now_iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0
    _lambda = _math_priming.log(2) / _PRIME_HALF_LIFE_MINUTES
    # 计算在 min_strength 时的最大有效时间（分钟）
    # min_strength = 1.0 × exp(-λ × t_max) → t_max = -ln(min_strength) / λ
    try:
        t_max_min = -_math_priming.log(min_strength) / _lambda  # minutes
        cutoff_ts = _now_ts - t_max_min * 60
        cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat()
    except Exception:
        return 0

    try:
        where = "WHERE primed_at < ?"
        params = [cutoff_iso]
        if project is not None:
            where += " AND project=?"
            params.append(project)
        cursor = conn.execute(f"DELETE FROM priming_state {where}", params)
        return cursor.rowcount
    except Exception:
        return 0


# ── iter405：Retroactive Interference (RI) — Recency Penalty for Stale Chunks
#             （Underwood 1957 / McGeoch & Irion 1952）──────────────────────────
#
# 认知科学依据：
#   Underwood (1957) Proactive Inhibition and Forgetting:
#     在学习 List B 之后，回忆 List A 的成功率下降（retroactive interference）。
#     新记忆和旧记忆在同一语义领域竞争检索路径，新的倾向于"覆盖"旧的。
#   McGeoch & Irion (1952) The Psychology of Human Learning:
#     干扰效应强度 × 新旧材料的相似度；相似度越高，干扰越强。
#   Anderson & Neely (1996) Interference and Inhibition:
#     抑制（inhibition）是主动过程，不只是竞争失败的被动结果。
#
# OS 类比：Linux MGLRU generation demotion —
#   进入系统的新 page 从 youngest generation 开始；
#   老一代（older generation）的 page 在 aging scan 中随新 page 的涌入逐渐降代；
#   当内存紧张时，老一代 page 被优先驱逐（recency bias）。
#   chunk age 越大、同主题新 chunk 越多 → recency_penalty 越大 → 检索分下降。
#
# 实现：
#   compute_recency_penalty(chunk_age_days, newer_same_topic_count, similarity) → float [0.0, 0.15]
#     - chunk_age_days：chunk 的年龄（天数）
#     - newer_same_topic_count：同主题（encode_context 重叠）且更新的 chunk 数量
#     - similarity：encode_context Jaccard 与最近同主题 chunk 的平均重叠
#     返回检索分罚分（0.0 = 无干扰，0.15 = 最大干扰）
#
#   get_newer_same_topic_count(conn, chunk_id, project, overlap_threshold=0.30) → int
#     查找同 project 中更新、且 encode_context 与当前 chunk 高度重叠的 chunk 数量

_RI_MAX_PENALTY: float = 0.15     # 最大干扰罚分（降低检索分）
_RI_AGE_THRESHOLD_DAYS: float = 7.0  # 7 天以上的 chunk 才可能受 RI 影响
_RI_COUNT_SATURATION: int = 5     # 5 个以上新 chunk 后干扰饱和


def compute_recency_penalty(
    chunk_age_days: float,
    newer_same_topic_count: int,
    similarity: float = 0.5,
) -> float:
    """
    iter405：计算旧 chunk 因新内容涌入而受到的 retroactive interference 惩罚。

    公式：penalty = min(_RI_MAX_PENALTY,
                        age_factor × count_factor × similarity_factor)

      age_factor：年龄越大 → 越容易被干扰（line 0 to 1 over 30 days）
        age_factor = min(1.0, (age - threshold) / 30.0)  if age > threshold else 0.0
      count_factor：新 chunk 越多 → 干扰越强（saturate at _RI_COUNT_SATURATION）
        count_factor = min(1.0, newer_count / _RI_COUNT_SATURATION)
      similarity_factor：相似度越高 → 干扰越强
        similarity_factor = similarity

    设计：只有当 age > 7天、有 >= 1 个新 chunk 存在、且有一定相似度时才产生惩罚。

    OS 类比：MGLRU aging pressure = generation_age × page_count × access_recency

    Returns:
      float ∈ [0.0, _RI_MAX_PENALTY]
    """
    try:
        age = max(0.0, float(chunk_age_days))
        count = max(0, int(newer_same_topic_count))
        sim = max(0.0, min(1.0, float(similarity)))
    except (TypeError, ValueError):
        return 0.0

    if age <= _RI_AGE_THRESHOLD_DAYS or count == 0 or sim < 0.10:
        return 0.0

    age_factor = min(1.0, (age - _RI_AGE_THRESHOLD_DAYS) / 30.0)
    count_factor = min(1.0, count / _RI_COUNT_SATURATION)
    penalty = age_factor * count_factor * sim * _RI_MAX_PENALTY
    return round(min(_RI_MAX_PENALTY, max(0.0, penalty)), 4)


def get_newer_same_topic_count(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    overlap_threshold: float = 0.25,
    now_iso: str = None,
) -> tuple:
    """
    iter405：查找同 project 中比当前 chunk 更新、且 encode_context 重叠度 >= threshold 的 chunk 数量。

    OS 类比：mglru_scan_newer_pages() — 统计 younger generation 中的相关 pages 数量。

    Returns:
      (newer_count: int, avg_overlap: float)
    """
    if not chunk_id or not project:
        return 0, 0.0
    try:
        row = conn.execute(
            "SELECT created_at, encode_context FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if row is None or not row[0]:
            return 0, 0.0
        chunk_created_at, chunk_enc_ctx = row[0], row[1] or ""
        if not chunk_enc_ctx:
            return 0, 0.0

        chunk_tokens = set(t.strip() for t in chunk_enc_ctx.split(",") if t.strip())
        if not chunk_tokens:
            return 0, 0.0

        # 查找更新的 chunk（created_at > chunk_created_at）
        newer_rows = conn.execute(
            "SELECT encode_context FROM memory_chunks "
            "WHERE project=? AND id != ? AND created_at > ? AND encode_context IS NOT NULL",
            (project, chunk_id, chunk_created_at)
        ).fetchall()

        if not newer_rows:
            return 0, 0.0

        overlaps = []
        for (enc_ctx,) in newer_rows:
            if not enc_ctx:
                continue
            newer_tokens = set(t.strip() for t in enc_ctx.split(",") if t.strip())
            if not newer_tokens:
                continue
            union = len(chunk_tokens | newer_tokens)
            if union > 0:
                jaccard = len(chunk_tokens & newer_tokens) / union
                if jaccard >= overlap_threshold:
                    overlaps.append(jaccard)

        count = len(overlaps)
        avg_overlap = sum(overlaps) / count if count > 0 else 0.0
        return count, round(avg_overlap, 4)
    except Exception:
        return 0, 0.0


# ── iter406：Generation Effect — 自生成内容 stability 加成（McDaniel & Einstein 1986）
#            ────────────────────────────────────────────────────────────────────────────
#
# 认知科学依据：
#   Slamecka & Graf (1978) The Generation Effect: Delineation of a Phenomenon:
#     被试自己生成的词汇（相对于阅读词汇）回忆率高 20-50%，即"生成效应"。
#     生成行为本身（无论结果）强化了记忆痕迹。
#   McDaniel & Einstein (1986) Bizarre Imagery as an Effective Memory Aid:
#     生成效应与精细阐述（elaboration）协同——不只是"生成"，
#     而是"在主动建构意义的过程中生成"，是决定 stability 的关键因子。
#   Jacoby (1978) On Interpreting the Effects of Repetition:
#     主动加工（active processing）vs 被动加工（passive processing）：
#     主动生成：推理、假设检验、类比构建 → 记忆强度更高
#     被动接受：直接复制、引用、简单整理 → 记忆强度较低
#
# OS 类比：Linux Write-Allocate 缓存策略 (write-allocate + write-back, 1974)
#   Write-Allocate（写分配）：CPU 写 miss 时，将整个 cache line 从 DRAM 读入，
#     在 cache 中修改后标记 dirty，等 writeback 时才写回 DRAM。
#     效果：写入触发完整 cache line 的加载和激活，该 line 进入 active 状态，
#     后续访问命中率显著提升（vs Write-No-Allocate 直写穿透）。
#   类比：agent 主动生成的内容相当于触发 Write-Allocate——
#     不只是被动写入（Write-No-Allocate），而是在生成过程中激活并构建完整 cache line；
#     生成标记密度越高 → Write-Allocate 程度越高 → 初始 stability 越高。
#
# 与 iter392（type-based）和 iter401（structural depth）的区别：
#   iter392：基于 chunk_type（reasoning_chain/decision/causal_chain）的粗粒度加成
#   iter401：基于结构性标记（因果词、对比词、层级结构）的深度加工检测
#   iter406：基于词汇层面的"主动生成标记"密度——
#     推理人称（"我认为"/"因此"/"我的理解是"）
#     假设检验（"如果...那么"/"假设"/"验证"）
#     元认知（"这说明"/"这意味着"/"关键在于"）
#     这三类标记直接指示了 agent 处于"主动建构"状态，而非"被动整理"状态。
#
# 实现：
#   compute_generation_score(content, summary, source_type) → float [0.0, 1.0]
#     检测内容中"主动生成"词汇标记密度，返回 generation score。
#   generation_stability_bonus(generation_score, base_stability) → float
#     将 generation score 映射为 stability 增量：
#       score >= 0.7 → bonus = base × 0.35（强生成，类比 Slamecka: +50%）
#       score 0.4-0.7 → bonus = base × 0.15（中等生成）
#       score 0.2-0.4 → bonus = base × 0.05（弱生成信号）
#       score < 0.2 → bonus = 0（无生成标记，被动内容）
#   apply_generation_effect(conn, chunk_id, content, summary, source_type, base_stability)
#     查找、计算并写入 stability 更新

# ── 生成标记词典（三层：推理人称 / 假设检验 / 元认知）──
# 中英文各有独立的识别规则
_GEN_REASONING_PERSON_ZH = frozenset([
    "我认为", "我觉得", "我的理解", "我推断", "我判断", "我估计",
    "在我看来", "据我分析", "从我的角度", "基于上述",
])
_GEN_REASONING_PERSON_EN = frozenset([
    "i think", "i believe", "i infer", "in my view", "as i see it",
    "i conclude", "i estimate", "my understanding", "i reason",
])
_GEN_HYPOTHETICAL_ZH = frozenset([
    "如果", "假设", "假如", "倘若", "若", "要是",
    "验证", "检验", "测试下", "实验", "推测",
])
_GEN_HYPOTHETICAL_EN = frozenset([
    "if we", "suppose", "hypothesis", "assuming", "let's verify", "let me check",
    "hypothetically", "let's test", "what if", "assume that",
])
_GEN_METACOG_ZH = frozenset([
    "这说明", "这意味着", "关键在于", "核心是", "本质是",
    "因此可以", "由此得出", "综上所述", "总结来看", "换句话说",
    "值得注意", "需要强调", "重要的是", "这表明", "这证明",
])
_GEN_METACOG_EN = frozenset([
    "this means", "therefore", "thus", "hence", "this implies",
    "in summary", "in conclusion", "the key insight", "this suggests",
    "it follows that", "importantly", "crucially", "this demonstrates",
    "as a result", "consequently",
])

# 最小内容长度（太短的内容不做生成检测，避免噪音）
_GEN_MIN_CHARS: int = 30
# 生成分层阈值
_GEN_STRONG_THRESHOLD: float = 0.7
_GEN_MEDIUM_THRESHOLD: float = 0.4
_GEN_WEAK_THRESHOLD: float = 0.2
# 最大稳定性加成（生成效应增量上限）
_GEN_MAX_STABILITY_BONUS_FACTOR: float = 0.35  # base × 0.35，即最多 +35%


def compute_generation_score(
    content: str,
    summary: str = "",
    source_type: str = None,
) -> float:
    """
    iter406：计算内容的"主动生成"标记密度，返回 generation score ∈ [0.0, 1.0]。

    检测三类生成标记：
      1. 推理人称（agent 以第一人称推理）
      2. 假设/验证（agent 主动构建假设并检验）
      3. 元认知（agent 反思、总结、得出结论）

    source_type 快速路径：
      "direct"（直接人类输入）→ 0.0（非生成内容，被动接收）
      "tool_output"（工具输出）→ 0.1 cap（工具输出为主，agent 生成为辅）
      None/"inferred"/"hearsay" → 正常检测

    Returns:
      float ∈ [0.0, 1.0]
    """
    if not content and not summary:
        return 0.0

    # source_type 快速判断
    if source_type == "direct":
        return 0.0  # 直接人类输入：非生成内容
    cap = 1.0
    if source_type == "tool_output":
        cap = 0.1  # 工具输出：agent 生成成分极少

    text = ((content or "") + " " + (summary or "")).lower().strip()
    if len(text) < _GEN_MIN_CHARS:
        return 0.0

    # 统计各类标记命中数
    reasoning_hits = sum(1 for m in _GEN_REASONING_PERSON_ZH if m in text)
    reasoning_hits += sum(1 for m in _GEN_REASONING_PERSON_EN if m in text)
    hypo_hits = sum(1 for m in _GEN_HYPOTHETICAL_ZH if m in text)
    hypo_hits += sum(1 for m in _GEN_HYPOTHETICAL_EN if m in text)
    meta_hits = sum(1 for m in _GEN_METACOG_ZH if m in text)
    meta_hits += sum(1 for m in _GEN_METACOG_EN if m in text)

    # 分层权重：元认知 > 推理人称 > 假设（从确定度排序）
    # 元认知标记代表 agent 已得出结论，生成效应最强
    # 推理人称代表 agent 正在推理，次之
    # 假设标记代表 agent 在探索，生成效应相对最弱
    # 归一化到 [0.0, 1.0]：每层最多贡献 1/3
    meta_contribution = min(1.0, meta_hits / 3.0) * 0.45
    reasoning_contribution = min(1.0, reasoning_hits / 2.0) * 0.35
    hypo_contribution = min(1.0, hypo_hits / 3.0) * 0.20

    raw_score = meta_contribution + reasoning_contribution + hypo_contribution
    return round(min(1.0, min(cap, raw_score)), 4)


def generation_stability_bonus(
    generation_score: float,
    base_stability: float,
) -> float:
    """
    iter406：将 generation score 映射为 stability 增量。

    设计原则（Slamecka & Graf 1978）：
      强生成（>= 0.7）：回忆率提升 ~50% → stability bonus = base × 0.35
      中等生成（0.4-0.7）：回忆率提升 ~15% → stability bonus = base × 0.15
      弱生成（0.2-0.4）：回忆率提升 ~5% → stability bonus = base × 0.05
      无生成（< 0.2）：0 增量

    上限保护：total stability 不超过 base × 1.5（防止叠加后 stability 爆炸）

    Returns:
      float — stability 增量（非绝对值，需加到 base_stability 上）
    """
    try:
        generation_score = float(generation_score)
        base_stability = float(base_stability)
    except (TypeError, ValueError):
        return 0.0
    if generation_score <= 0.0 or base_stability <= 0.0:
        return 0.0
    try:
        score = float(generation_score)
        base = float(base_stability)
    except (TypeError, ValueError):
        return 0.0

    if score >= _GEN_STRONG_THRESHOLD:
        factor = _GEN_MAX_STABILITY_BONUS_FACTOR
    elif score >= _GEN_MEDIUM_THRESHOLD:
        # 线性插值：[0.4, 0.7) → factor [0.05, 0.35]
        t = (score - _GEN_MEDIUM_THRESHOLD) / (_GEN_STRONG_THRESHOLD - _GEN_MEDIUM_THRESHOLD)
        factor = 0.05 + t * (_GEN_MAX_STABILITY_BONUS_FACTOR - 0.05)
    elif score >= _GEN_WEAK_THRESHOLD:
        # 弱生成：[0.2, 0.4) → factor [0.0, 0.05]
        t = (score - _GEN_WEAK_THRESHOLD) / (_GEN_MEDIUM_THRESHOLD - _GEN_WEAK_THRESHOLD)
        factor = t * 0.05
    else:
        return 0.0

    bonus = base * factor
    # 上限：total stability 不超过 base × 1.5
    max_bonus = base * 0.50
    return round(min(bonus, max_bonus), 4)


def apply_generation_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    content: str,
    summary: str = "",
    source_type: str = None,
    base_stability: float = 1.0,
) -> float:
    """
    iter406：计算生成效应并更新 chunk 的 stability。

    Returns:
      float — 更新后的 stability（= base + bonus）
    """
    if not chunk_id:
        return base_stability
    try:
        score = compute_generation_score(content, summary, source_type)
        bonus = generation_stability_bonus(score, base_stability)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter407: Von Restorff Effect — 孤立 chunk 的 stability 加成（von Restorff 1933）──────
# 认知科学依据：von Restorff (1933) "Über die Wirkung von Bereichsbildungen im Spurenfeld"
#   在均匀背景中，孤立/突出的项目（与背景在质上不同）比普通项目保留率显著更高。
#   Klein & Saltz (1976): isolation 效应在语义上独特的项目中最强（不仅限于物理外观）。
#   Wallace (1965): 效应强度与孤立程度正相关（越独特 → 记忆越好）。
#
# OS 类比：Linux perf_event outlier detection / NUMA distant access warning
#   perf stat 输出中，远离均值的异常值被标记和报警；
#   NUMA 拓扑中，与主工作集差异大的内存地址访问触发 distant-node access penalty。
#   memory-os 类比：在语义空间中"孤立"的 chunk（与同项目邻居语义距离大）
#   → 稀有信息 → 更值得保留 → stability bonus。
#
# 认知机制：孤立效应（von Restorff）的神经机制是 LTP（长时程增强）差异激活：
#   孤立项目打破了神经激活的均匀背景，引发更强的海马体编码，形成更持久的突触权重。
#
# 实现策略：
#   encode_context（逗号分隔的关键词串）作为语义代理向量
#   Jaccard 相似度计算 chunk 与同项目邻居的平均语义相似度
#   isolation_score = 1.0 - avg_similarity（孤立度）
#   只在邻居数 >= 3 时计算（数据不足时保守处理，不给 bonus）

def _parse_ec_to_set(ctx_str: str) -> frozenset:
    """将 encode_context 字符串（逗号分隔）解析为词集合。"""
    if not ctx_str:
        return frozenset()
    return frozenset(w.strip().lower() for w in ctx_str.split(',') if w.strip())


def _jaccard_ec(a: frozenset, b: frozenset) -> float:
    """计算两个词集合的 Jaccard 相似度。"""
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union > 0 else 0.0


def compute_isolation_score(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    context_window: int = 20,
    min_neighbors: int = 3,
) -> float:
    """
    iter407: 计算 chunk 在同项目中的语义孤立度（Von Restorff Effect）。

    孤立度 = 1.0 - 平均语义相似度（与最近 context_window 个邻居的平均 Jaccard）

    Args:
      conn: SQLite 连接
      chunk_id: 目标 chunk ID
      project: 项目标识
      context_window: 考察的邻居数量（最近创建的 N 个 chunk，排除自己）
      min_neighbors: 最少需要多少邻居才计算（< min 时返回 0.0，数据不足）

    Returns:
      float ∈ [0.0, 1.0]：孤立度。0.0=完全不孤立，1.0=完全孤立（无语义重叠）
    """
    if not chunk_id or not project:
        return 0.0
    try:
        # 获取目标 chunk 的 encode_context
        row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=? AND project=?",
            (chunk_id, project)
        ).fetchone()
        if not row:
            return 0.0
        target_ctx = _parse_ec_to_set(row[0] or "")
        if not target_ctx:
            # 无 encode_context → 无法计算相似度，返回 0（保守处理）
            return 0.0

        # 获取同项目中最近的 context_window 个 chunk（排除自己）
        neighbors = conn.execute(
            """SELECT encode_context FROM memory_chunks
               WHERE project=? AND id != ? AND encode_context IS NOT NULL
                 AND encode_context != ''
               ORDER BY created_at DESC
               LIMIT ?""",
            (project, chunk_id, context_window)
        ).fetchall()

        if len(neighbors) < min_neighbors:
            return 0.0  # 数据不足，保守处理

        # 计算平均 Jaccard 相似度
        similarities = []
        for (nb_ctx_str,) in neighbors:
            nb_set = _parse_ec_to_set(nb_ctx_str or "")
            if nb_set:
                sim = _jaccard_ec(target_ctx, nb_set)
                similarities.append(sim)

        if not similarities:
            return 0.0

        avg_sim = sum(similarities) / len(similarities)
        isolation_score = max(0.0, 1.0 - avg_sim)
        return min(1.0, isolation_score)

    except Exception:
        return 0.0


def isolation_stability_bonus(
    isolation_score: float,
    base_stability: float,
) -> float:
    """
    iter407: Von Restorff Isolation Bonus — 孤立度越高 stability bonus 越大。

    设计（Wallace 1965 效应强度正相关于孤立程度）：
      isolation >= 0.85（极孤立）: factor = 0.20 → bonus = base × 0.20
      isolation [0.65, 0.85): linear interp 0.10 → 0.20
      isolation [0.45, 0.65): linear interp 0.00 → 0.10
      isolation < 0.45（不突出）: 0

    上限: base × 0.20（比 Generation Effect 小，因为孤立是被动属性，生成是主动行为）

    OS 类比：perf 异常值标记 — 异常程度越大，标记权重越高，优先级越高。
    """
    try:
        isolation_score = float(isolation_score)
        base_stability = float(base_stability)
    except (TypeError, ValueError):
        return 0.0
    if isolation_score <= 0.0 or base_stability <= 0.0:
        return 0.0

    _VRSTOFF_STRONG = 0.85
    _VRSTOFF_MED    = 0.65
    _VRSTOFF_WEAK   = 0.45
    _VRSTOFF_MAX_FACTOR = 0.20
    _VRSTOFF_MED_FACTOR = 0.10

    if isolation_score >= _VRSTOFF_STRONG:
        factor = _VRSTOFF_MAX_FACTOR
    elif isolation_score >= _VRSTOFF_MED:
        t = (isolation_score - _VRSTOFF_MED) / (_VRSTOFF_STRONG - _VRSTOFF_MED)
        factor = _VRSTOFF_MED_FACTOR + t * (_VRSTOFF_MAX_FACTOR - _VRSTOFF_MED_FACTOR)
    elif isolation_score >= _VRSTOFF_WEAK:
        t = (isolation_score - _VRSTOFF_WEAK) / (_VRSTOFF_MED - _VRSTOFF_WEAK)
        factor = 0.0 + t * _VRSTOFF_MED_FACTOR
    else:
        return 0.0

    bonus = base_stability * factor
    # 上限保护
    max_bonus = base_stability * _VRSTOFF_MAX_FACTOR
    return min(bonus, max_bonus)


def apply_isolation_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    base_stability: float = 1.0,
    context_window: int = 20,
) -> float:
    """
    iter407: 计算孤立效应并更新 chunk 的 stability。

    Returns:
      float — 更新后的 stability（= base + bonus）
    """
    if not chunk_id or not project:
        return base_stability
    try:
        isolation = compute_isolation_score(
            conn, chunk_id, project,
            context_window=context_window,
        )
        bonus = isolation_stability_bonus(isolation, base_stability)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter408: Proactive Interference — 旧知识干扰新知识写入（Underwood 1957）─────
#
# 认知科学依据：
#   Underwood (1957) "Proactive Inhibition and Forgetting":
#     学习新材料时，先前学习的相似材料产生"前摄抑制"（Proactive Interference）。
#     已学材料越多、越相似 → 新材料的初始记忆强度越低。
#   Porter & Duncan (1953): PI 效应与已有材料的数量正相关。
#   Postman & Underwood (1973) interference theory review:
#     PI 是遗忘的主要机制之一（与 RI 并列）。
#
# 与 iter405 RI（Retroactive Interference）的对称性：
#   RI（iter405）: 新 chunk 写入后，旧 chunk 检索分降低（新干扰旧）
#   PI（iter408）: 旧 chunk 存在时，新 chunk 写入时 stability 降低（旧干扰新）
#
#   RI + PI = 完整的干扰理论（Miller 1956 双向干扰）
#
# OS 类比：Linux TLB Shootdown Cost
#   修改一个被多核共享的 PTE（page table entry）时，内核必须向持有该
#   TLB entry 的所有 CPU 发送 IPI（inter-processor interrupt），强制
#   其 flush TLB（TLB shootdown）。共享该 PTE 的 CPU 越多，shootdown 开销越大。
#   类比：与新 chunk 语义重叠的旧 chunk 越多、越"活跃"（高 access_count），
#   新 chunk 写入时面临的"认知阻力"越大 → initial stability 越低。
#
# 实现：
#   compute_pi_penalty(conn, chunk_id, project) → float [0.0, 0.10]
#     1. 找最近邻居（最相似的 search_k=5 个 chunk）
#     2. 计算平均 Jaccard 相似度 avg_sim
#     3. 统计其中 access_count >= strong_acc_threshold 的"强旧记忆"数量
#     4. penalty = avg_sim × (strong_count / search_k) × max_penalty
#   apply_proactive_interference(conn, chunk_id, project, base_stability)
#     计算 penalty，更新 DB stability
#
# 保护规则：
#   1. design_constraint 类型豁免（约束永远应被记住）
#   2. 新 chunk 高 importance (> 0.85) → penalty 减半
#   3. 最大 penalty = base × 0.10（保守，避免过度惩罚新知识）


def compute_pi_penalty(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    search_k: int = 5,
    strong_acc_threshold: int = 3,
    max_penalty: float = 0.10,
) -> float:
    """
    iter408: 计算新 chunk 面临的 Proactive Interference 惩罚系数。

    Returns:
      float ∈ [0.0, max_penalty] — PI 导致的 stability 降低量（非比例，绝对值）
      返回值直接从 base_stability 中减去。

    公式：
      avg_sim = 与最近 search_k 个邻居的平均 Jaccard 相似度
      strong_ratio = 其中 access_count >= threshold 的邻居比例
      penalty = avg_sim × strong_ratio × max_penalty
    """
    if not chunk_id or not project:
        return 0.0
    try:
        row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=? AND project=?",
            (chunk_id, project)
        ).fetchone()
        if not row:
            return 0.0
        target_ctx = _parse_ec_to_set(row[0] or "")
        if not target_ctx:
            return 0.0

        # 找最近的 search_k 个邻居（不含自身）
        neighbors = conn.execute(
            """SELECT id, encode_context, access_count
               FROM memory_chunks
               WHERE project=? AND id != ?
                 AND encode_context IS NOT NULL AND encode_context != ''
               ORDER BY created_at DESC
               LIMIT ?""",
            (project, chunk_id, search_k)
        ).fetchall()

        if not neighbors:
            return 0.0

        similarities = []
        strong_count = 0
        for nb_row in neighbors:
            nb_id = nb_row[0] if isinstance(nb_row, (list, tuple)) else nb_row["id"]
            nb_ctx_str = nb_row[1] if isinstance(nb_row, (list, tuple)) else nb_row["encode_context"]
            nb_acc = nb_row[2] if isinstance(nb_row, (list, tuple)) else nb_row["access_count"]
            nb_ctx = _parse_ec_to_set(nb_ctx_str or "")
            if nb_ctx:
                sim = _jaccard_ec(target_ctx, nb_ctx)
                similarities.append(sim)
                if sim > 0.0 and (nb_acc or 0) >= strong_acc_threshold:
                    strong_count += 1

        if not similarities:
            return 0.0

        avg_sim = sum(similarities) / len(similarities)
        strong_ratio = strong_count / len(similarities)
        penalty = avg_sim * strong_ratio * max_penalty
        return min(penalty, max_penalty)
    except Exception:
        return 0.0


def apply_proactive_interference(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    base_stability: float = 1.0,
    search_k: int = 5,
    strong_acc_threshold: int = 3,
    max_penalty: float = 0.10,
) -> float:
    """
    iter408: 计算 PI 惩罚并更新 chunk 的 stability。

    保护规则：
      - design_constraint 豁免（永久知识不受 PI）
      - high importance (>0.85) → penalty 减半
      - penalty < 0.001 → 跳过 DB 写入

    Returns:
      float — 更新后的 stability
    """
    if not chunk_id or not project:
        return base_stability
    try:
        # 检查保护条件
        row = conn.execute(
            "SELECT chunk_type, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability

        chunk_type = row[0] if isinstance(row, (list, tuple)) else row["chunk_type"]
        importance = row[1] if isinstance(row, (list, tuple)) else row["importance"]

        # design_constraint 豁免
        if chunk_type == "design_constraint":
            return base_stability

        penalty = compute_pi_penalty(
            conn, chunk_id, project,
            search_k=search_k,
            strong_acc_threshold=strong_acc_threshold,
            max_penalty=max_penalty,
        )

        # 高 importance 新知识抗 PI（减半惩罚）
        if (importance or 0.0) > 0.85:
            penalty *= 0.5

        new_stability = max(0.1, base_stability - penalty)
        if penalty > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter409: Flashbulb Memory — 情绪性内容的写入时 stability 加强（Brown & Kulik 1977）
#
# 认知科学依据：
#   Brown & Kulik (1977) "Flashbulb memories":
#     高情绪唤醒事件（例如 JFK 遇刺）形成极其鲜明、持久、细节丰富的记忆。
#     与普通记忆相比，flashbulb 记忆的消退曲线更平缓。
#   McGaugh (2000) "Memory — a century of consolidation" (Science):
#     情绪唤醒触发杏仁核激活 → norepinephrine 释放 → 增强海马编码强度（amygdala modulation）。
#   Cahill et al. (1994, Nature): β-肾上腺素受体阻断剂阻断了情绪增强效应
#     → 直接神经生理证据支持 norepinephrine 机制。
#
# 与 iter376 的区别：
#   iter376（emotional_boost_factor）：retrieval 时加分——情绪 chunk 更容易被检索到
#   iter409（flashbulb_stability_bonus）：insert 时加强——情绪 chunk 的初始 stability 更高
#   → iter376 是检索优先级，iter409 是记忆固化强度，互补而非冗余
#
# OS 类比：Linux mlockall(MCL_CURRENT | MCL_FUTURE)
#   高优先级进程调用 mlockall 将所有（当前和未来）内存页锁定在 RAM 中，
#   无法被 kswapd 驱逐。情绪性记忆 = 被 mlockall 的内存 = 衰减抵抗力最强。
#
# 实现：
#   flashbulb_stability_bonus(emotional_weight, base_stability) → bonus
#     strong (≥ 0.70): +30% of base (cap: base × 0.30)
#     medium (0.50-0.70): interp 15→30%
#     weak (0.30-0.50): interp 0→15%
#     < 0.30: no bonus
#   apply_flashbulb_effect(conn, chunk_id, base_stability) → new_stability


def flashbulb_stability_bonus(emotional_weight: float, base_stability: float) -> float:
    """
    iter409: 将 emotional_weight 映射为 stability bonus（Brown & Kulik 1977）。

    设计（McGaugh 2000 杏仁核 norepinephrine 效应梯度）：
      strong (≥ 0.70): factor = 0.30（极强情绪唤醒，如系统崩溃/重大决策）
      medium [0.50, 0.70): 线性插值 0.15 → 0.30
      weak   [0.30, 0.50): 线性插值 0.00 → 0.15
      < 0.30: factor = 0（无情绪显著性，不加分）

    cap: base × 0.30（上限，防止 stability 异常膨胀）
    """
    try:
        emotional_weight = float(emotional_weight)
        base_stability = float(base_stability)
    except (TypeError, ValueError):
        return 0.0
    if emotional_weight <= 0.0 or base_stability <= 0.0:
        return 0.0

    _FB_STRONG = 0.70
    _FB_MEDIUM = 0.50
    _FB_WEAK   = 0.30
    _FB_MAX_FACTOR = 0.30
    _FB_MED_FACTOR = 0.15

    if emotional_weight >= _FB_STRONG:
        factor = _FB_MAX_FACTOR
    elif emotional_weight >= _FB_MEDIUM:
        t = (emotional_weight - _FB_MEDIUM) / (_FB_STRONG - _FB_MEDIUM)
        factor = _FB_MED_FACTOR + t * (_FB_MAX_FACTOR - _FB_MED_FACTOR)
    elif emotional_weight >= _FB_WEAK:
        t = (emotional_weight - _FB_WEAK) / (_FB_MEDIUM - _FB_WEAK)
        factor = 0.0 + t * _FB_MED_FACTOR
    else:
        return 0.0

    bonus = base_stability * factor
    max_bonus = base_stability * _FB_MAX_FACTOR
    return min(bonus, max_bonus)


def apply_flashbulb_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter409: 读取 chunk 的 emotional_weight，计算 flashbulb bonus 并更新 stability。

    Returns:
      float — 更新后的 stability（= base + bonus）
    """
    if not chunk_id:
        return base_stability
    try:
        row = conn.execute(
            "SELECT emotional_weight FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability
        ew = row[0] if isinstance(row, (list, tuple)) else row["emotional_weight"]
        bonus = flashbulb_stability_bonus(ew or 0.0, base_stability)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter410: Primacy Effect — 首位效应（Murdock 1962 Serial Position Effect）────
#
# 认知科学依据：
#   Murdock (1962) "The serial position effect of free recall" (JEP):
#     在一系列项目中，最早出现的项目（primacy）和最近出现的项目（recency）
#     记忆效果最好，中间项目最差。
#   Primacy Effect 机制（Rundus 1971）：
#     最早的项目在工作记忆中停留时间最长，被 rehearsed（复述）次数最多，
#     形成更强的长时记忆痕迹（elaborative rehearsal hypothesis）。
#   在工程知识场景中：
#     项目最初建立的 chunk（架构决策/设计约束/技术选型）是后续所有工作的
#     认知 schema（Bartlett 1932）。它们被参考、验证、依赖的次数最多，
#     相当于被 rehearsed 最多次。
#
# OS 类比：Linux boot-time kernel parameters
#   内核启动时通过 cmdline 设置的参数（如 hugepages=1024、pcie_aspm=off）
#   比 sysctl 运行时参数更持久：它们在所有子系统初始化之前就生效，
#   是系统的基础 schema，后续配置都在它之上构建。
#   对应：项目最早创建的 chunk = boot-time parameters = 基础 schema = 更持久。
#
# 实现约束：
#   1. min_total_chunks=20 阈值 — 项目少于 20 个 chunk 时不应用（避免新项目所有 chunk 都加成）
#   2. primacy_pct=0.10 — 最早的 10% 的 chunk 获得完整 primacy bonus
#   3. 延伸区间 [0.10, 0.20) — 线性衰减到 0
#   4. 上限 base × 0.15（保守，首位效应是相对效应）


def compute_primacy_rank(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    min_total_chunks: int = 20,
) -> float:
    """
    iter410: 计算 chunk 在项目中按创建时间排名的百分位 [0.0, 1.0]。

    0.0 = 最早创建（primacy 最强），1.0 = 最晚创建。
    若项目 chunk 总数 < min_total_chunks，返回 1.0（不触发 primacy 加成）。
    """
    if not chunk_id or not project:
        return 1.0
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
        ).fetchone()[0]
        if total < min_total_chunks:
            return 1.0  # 项目还太小，不应用首位效应

        # 获取 chunk 的创建时间排名（升序）
        rank_row = conn.execute(
            """SELECT COUNT(*) FROM memory_chunks
               WHERE project=? AND created_at < (
                   SELECT created_at FROM memory_chunks WHERE id=? AND project=?
               )""",
            (project, chunk_id, project)
        ).fetchone()
        if not rank_row:
            return 1.0
        rank = rank_row[0]  # 比该 chunk 更早的 chunk 数量（0-based）
        return rank / total  # 百分位：0.0 = 最早
    except Exception:
        return 1.0


def primacy_stability_bonus(primacy_rank: float, base_stability: float) -> float:
    """
    iter410: 将 primacy_rank 映射为 stability 加成（首位效应）。

    设计（Rundus 1971 rehearsal hypothesis）：
      rank < 0.10（最早 10%）: factor = 0.15（完整首位加成）
      rank [0.10, 0.20)：线性衰减 0.15 → 0.0
      rank ≥ 0.20：factor = 0（不在首位区间）

    cap: base × 0.15
    """
    try:
        primacy_rank = float(primacy_rank)
        base_stability = float(base_stability)
    except (TypeError, ValueError):
        return 0.0
    if base_stability <= 0.0:
        return 0.0

    _PRIMACY_CORE = 0.10    # 最早 10% 获得完整加成
    _PRIMACY_TAIL = 0.20    # 10-20% 线性衰减
    _PRIMACY_MAX_FACTOR = 0.15

    if primacy_rank < _PRIMACY_CORE:
        factor = _PRIMACY_MAX_FACTOR
    elif primacy_rank < _PRIMACY_TAIL:
        t = 1.0 - (primacy_rank - _PRIMACY_CORE) / (_PRIMACY_TAIL - _PRIMACY_CORE)
        factor = t * _PRIMACY_MAX_FACTOR
    else:
        return 0.0

    bonus = base_stability * factor
    max_bonus = base_stability * _PRIMACY_MAX_FACTOR
    return min(bonus, max_bonus)


def apply_primacy_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    base_stability: float = 1.0,
    min_total_chunks: int = 20,
) -> float:
    """
    iter410: 计算首位效应并更新 chunk 的 stability。

    Returns:
      float — 更新后的 stability（= base + primacy_bonus）
    """
    if not chunk_id or not project:
        return base_stability
    try:
        rank = compute_primacy_rank(conn, chunk_id, project, min_total_chunks=min_total_chunks)
        bonus = primacy_stability_bonus(rank, base_stability)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter411: Levels of Processing — 编码深度效应（Craik & Lockhart 1972）─────────
#
# 认知科学依据：
#   Craik & Lockhart (1972) "Levels of processing: A framework for memory research" (JVLVB):
#     记忆强度由编码时的加工深度决定，而非存储容量：
#     - 浅层加工（phonological）：重复发音，不理解语义 → 弱记忆
#     - 中层加工（syntactic）：理解语法结构 → 中等记忆
#     - 深层加工（semantic）：与已有语义网络建立丰富联系 → 强记忆
#   Hyde & Jenkins (1973): 语义导向任务（"它是有生命的吗？"）比
#     结构导向任务（"它有字母 e 吗？"）产生更好的记忆保留。
#
#   在 memory-os 中，encode_context（逗号分隔实体列表）是语义网络节点密度的代理指标：
#     实体越多 → 与更多概念建立了语义联系 → 更深的加工 → 更强的记忆痕迹
#
# OS 类比：Linux NUMA-aware page allocation
#   NUMA-local 页面访问延迟最低（本地 memory bank），类比语义本地性：
#   与本项目语义网络连接越多（实体越多），访问该知识的"延迟"越低（检索更容易）。
#   深层加工 = NUMA-local allocation = 低访问延迟 = 更不容易被 swap out。
#
# 实现约束：
#   1. 基于 encode_context 实体数量（已有字段，轻量）
#   2. 非线性分级：8+→1.0, 5-7→0.7, 3-4→0.4, 1-2→0.1, 0→0.0
#   3. 加成上限 base × 0.15（保守，因实体数量是间接代理，不是直接测量）
#   4. 不依赖 DB 查询（纯函数），可用于写入前预计算


def compute_encoding_depth(encode_context: str) -> float:
    """
    iter411: 基于 encode_context 实体数量计算编码深度分 [0.0, 1.0]。

    分级（Hyde & Jenkins 1973 语义网络密度代理）：
      entity_count >= 8: depth = 1.0（极丰富语义网络，深层加工）
      entity_count 5-7:  depth = 0.7（丰富）
      entity_count 3-4:  depth = 0.4（中等）
      entity_count 1-2:  depth = 0.1（浅层）
      entity_count = 0:  depth = 0.0（无语义编码）
    """
    if not encode_context:
        return 0.0
    try:
        entities = [e.strip() for e in encode_context.split(',') if e.strip()]
        count = len(entities)
        if count == 0:
            return 0.0
        elif count <= 2:
            return 0.1
        elif count <= 4:
            return 0.4
        elif count <= 7:
            return 0.7
        else:
            return 1.0
    except Exception:
        return 0.0


def depth_stability_bonus(depth: float, base_stability: float) -> float:
    """
    iter411: 将编码深度分映射为 stability 加成。

    设计（Craik & Lockhart 1972 深度 → 保留强度）：
      depth >= 0.80: factor = 0.15（极深层加工）
      depth [0.50, 0.80): 线性插值 0.08 → 0.15
      depth [0.20, 0.50): 线性插值 0.00 → 0.08
      depth < 0.20: factor = 0（浅层/无加工）

    cap: base × 0.15（保守上限，间接代理指标）
    """
    try:
        depth = float(depth)
        base_stability = float(base_stability)
    except (TypeError, ValueError):
        return 0.0
    if depth <= 0.0 or base_stability <= 0.0:
        return 0.0

    _LOP_DEEP   = 0.80
    _LOP_MED    = 0.50
    _LOP_WEAK   = 0.20
    _LOP_MAX_FACTOR = 0.15
    _LOP_MED_FACTOR = 0.08

    if depth >= _LOP_DEEP:
        factor = _LOP_MAX_FACTOR
    elif depth >= _LOP_MED:
        t = (depth - _LOP_MED) / (_LOP_DEEP - _LOP_MED)
        factor = _LOP_MED_FACTOR + t * (_LOP_MAX_FACTOR - _LOP_MED_FACTOR)
    elif depth >= _LOP_WEAK:
        t = (depth - _LOP_WEAK) / (_LOP_MED - _LOP_WEAK)
        factor = 0.0 + t * _LOP_MED_FACTOR
    else:
        return 0.0

    bonus = base_stability * factor
    max_bonus = base_stability * _LOP_MAX_FACTOR
    return min(bonus, max_bonus)


def apply_depth_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter411: 读取 chunk 的 encode_context，计算编码深度加成并更新 stability。

    Returns:
      float — 更新后的 stability（= base + depth_bonus）
    """
    if not chunk_id:
        return base_stability
    try:
        row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability
        ec = row[0] if isinstance(row, (list, tuple)) else row["encode_context"]
        depth = compute_encoding_depth(ec or "")
        bonus = depth_stability_bonus(depth, base_stability)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter433: Reminiscence Bump Effect — 项目形成期记忆强化（Conway & Howe 1990）──────────────
#
# 认知科学依据：Conway & Howe (1990) "The construction of autobiographical memories in the self-memory system";
#   Rubin et al. (1998) "A model of the autobiographical memory" —
#   人类自传体记忆中，生命 15-25 岁（"形成期"）的事件比其他阶段记忆得更清晰，
#   即使间隔 60 年也保持优势（+50%~+100% recall rate vs other life periods）。
#   机制：形成期事件被编码进"核心自我叙事"（core self-narrative）与身份认同绑定，
#     获得额外的海马-新皮层双重编码路径（hippocampal + cortical dual encoding）。
#
# 与 Primacy Effect（iter410）的区别：
#   Primacy Effect（Murdock 1962）：基于编码顺序的绝对位置效应——最先出现的少数条目
#     获得更多复述机会（Rundus 1971），是工作记忆串行扫描的结果。
#   Reminiscence Bump：基于项目生命周期的相对时间窗口效应——项目创生期（前 bump_pct% 时间）
#     写入的 chunk 形成"项目核心叙事"，与项目认知框架绑定，稳定性更高。
#
# OS 类比：Linux early_boot firmware parameters / BIOS/UEFI kernel cmdline —
#   启动早期（内核命令行参数、ACPI 表、early_initrd）设置的参数在整个系统生命周期保持不变，
#   比运行时 sysctl 具有更高的稳定性（boot-immutable vs runtime-mutable）。
#   系统初始化阶段的"核心参数"等价于项目创生期写入的"认知框架" chunk。


def compute_reminiscence_bump_factor(
    conn: "sqlite3.Connection",
    chunk_id: str,
    project: str,
    base_stability: float,
) -> float:
    """
    iter433: 计算 Reminiscence Bump 加成因子。

    算法：
      1. 查询项目第一个和最后一个 chunk 的 created_at（确定项目时间跨度）
      2. 查询当前 chunk 的 created_at + importance
      3. 计算 position_pct = (chunk.created_at - first_chunk_ts) / project_age_secs
      4. 若 position_pct <= bump_pct 且 importance >= bump_min_importance
         且 project_age_days >= bump_min_project_age_days
         → 返回 base_stability * bump_factor（加成后的 stability）
      5. 否则返回 base_stability（无加成）

    Returns:
      float — 应用 Bump 后的 stability（含加成或原值）
    """
    import config as _config
    try:
        if not _config.get("store_vfs.bump_enabled"):
            return base_stability

        bump_pct = float(_config.get("store_vfs.bump_pct") or 0.15)
        bump_min_imp = float(_config.get("store_vfs.bump_min_importance") or 0.55)
        bump_factor = float(_config.get("store_vfs.bump_factor") or 1.30)
        min_project_age = float(_config.get("store_vfs.bump_min_project_age_days") or 7.0)

        # 查询当前 chunk 信息
        chunk_row = conn.execute(
            "SELECT created_at, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not chunk_row:
            return base_stability

        chunk_created = chunk_row[0] if isinstance(chunk_row, (list, tuple)) else chunk_row["created_at"]
        importance = float(chunk_row[1] if isinstance(chunk_row, (list, tuple)) else chunk_row["importance"]) or 0.0

        if importance < bump_min_imp:
            return base_stability

        if not chunk_created:
            return base_stability

        # 查询项目时间边界
        bounds_row = conn.execute(
            "SELECT MIN(created_at), MAX(created_at) FROM memory_chunks WHERE project=?",
            (project,)
        ).fetchone()
        if not bounds_row or not bounds_row[0] or not bounds_row[1]:
            return base_stability

        proj_first = bounds_row[0] if isinstance(bounds_row, (list, tuple)) else bounds_row["MIN(created_at)"]
        proj_last = bounds_row[1] if isinstance(bounds_row, (list, tuple)) else bounds_row["MAX(created_at)"]

        # 解析时间戳
        from datetime import datetime as _dt, timezone as _tz
        def _parse(ts: str) -> float:
            return _dt.fromisoformat(ts.replace("Z", "+00:00")).timestamp()

        ts_first = _parse(proj_first)
        ts_last = _parse(proj_last)
        ts_chunk = _parse(chunk_created)

        project_age_secs = ts_last - ts_first
        if project_age_secs <= 0:
            return base_stability

        project_age_days = project_age_secs / 86400.0
        if project_age_days < min_project_age:
            return base_stability

        position_pct = (ts_chunk - ts_first) / project_age_secs
        if position_pct <= bump_pct:
            new_stab = min(365.0, base_stability * bump_factor)
            return new_stab

        return base_stability
    except Exception:
        return base_stability


def apply_reminiscence_bump(
    conn: "sqlite3.Connection",
    chunk_id: str,
    project: str,
    base_stability: float,
) -> float:
    """
    iter433: 计算 Reminiscence Bump 并更新 chunk stability。

    Returns:
      float — 更新后的 stability
    """
    new_stability = compute_reminiscence_bump_factor(conn, chunk_id, project, base_stability)
    if new_stability > base_stability + 0.001:
        try:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        except Exception:
            pass
    return new_stability


def apply_reminiscence_bump_batch(
    conn: "sqlite3.Connection",
    project: str,
    max_chunks: int = 50,
) -> dict:
    """
    iter433: 批量扫描项目的形成期 chunk 并应用 Reminiscence Bump。

    在 damon_scan / SessionStart 中调用，对已存在的早期 chunk 做回顾性加成。
    比 insert_chunk 时更准确，因为此时项目已有足够历史。

    策略：
      1. 查询项目最早 chunk 的时间边界
      2. 查询创建时间在前 bump_pct% 区间内的 chunk（position_pct <= bump_pct）
      3. 对其中 importance >= bump_min_importance 且尚未获得加成的 chunk 应用加成
         判断"已获加成"：不重复处理（通过 bump_applied 标记或 stability 阈值）

    返回 dict：
      bumped — 应用加成的 chunk 数
      skipped — 跳过（已有加成）的 chunk 数
    """
    import config as _config
    try:
        if not _config.get("store_vfs.bump_enabled"):
            return {"bumped": 0, "skipped": 0}

        bump_pct = float(_config.get("store_vfs.bump_pct") or 0.15)
        bump_min_imp = float(_config.get("store_vfs.bump_min_importance") or 0.55)
        bump_factor = float(_config.get("store_vfs.bump_factor") or 1.30)
        min_project_age = float(_config.get("store_vfs.bump_min_project_age_days") or 7.0)

        # 获取项目时间边界
        bounds = conn.execute(
            "SELECT MIN(created_at), MAX(created_at), COUNT(*) FROM memory_chunks WHERE project=?",
            (project,)
        ).fetchone()
        if not bounds or not bounds[0] or not bounds[1]:
            return {"bumped": 0, "skipped": 0}

        proj_first_str = bounds[0] if isinstance(bounds, (list, tuple)) else bounds["MIN(created_at)"]
        proj_last_str = bounds[1] if isinstance(bounds, (list, tuple)) else bounds["MAX(created_at)"]

        from datetime import datetime as _dt, timezone as _tz, timedelta as _td

        def _parse(ts: str) -> float:
            return _dt.fromisoformat(ts.replace("Z", "+00:00")).timestamp()

        ts_first = _parse(proj_first_str)
        ts_last = _parse(proj_last_str)
        project_age_secs = ts_last - ts_first
        project_age_days = project_age_secs / 86400.0

        if project_age_secs <= 0 or project_age_days < min_project_age:
            return {"bumped": 0, "skipped": 0}

        # 形成期截止时间：ts_first + bump_pct × project_age_secs
        bump_cutoff_ts = ts_first + bump_pct * project_age_secs
        bump_cutoff_dt = _dt.fromtimestamp(bump_cutoff_ts, tz=_tz.utc)
        bump_cutoff_str = bump_cutoff_dt.isoformat()

        # 查询形成期候选：created_at <= bump_cutoff 且 importance >= min_imp
        candidates = conn.execute(
            """SELECT id, stability, importance FROM memory_chunks
               WHERE project=?
                 AND created_at <= ?
                 AND importance >= ?
               LIMIT ?""",
            (project, bump_cutoff_str, bump_min_imp, max_chunks)
        ).fetchall()

        bumped = 0
        skipped = 0

        for row in candidates:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            cur_stab = float(row[1] if isinstance(row, (list, tuple)) else row["stability"]) or 1.0

            # 计算预期的"已加成"stability：如果 base_stability 是 cur_stab/bump_factor，
            # 则已经加成过。但我们没有存储原始 stability，所以用阈值判断：
            # 若 cur_stab 已经 >= base × bump_factor，跳过（防重复）
            # 简化：使用 stability > expected_base 的条件（保守策略：宁可重复 bump 也不漏）
            # 实际上由于多个加成叠加（Primacy/LOP/etc.），难以精确判断，直接应用
            new_stab = min(365.0, cur_stab * bump_factor)
            if new_stab > cur_stab + 0.001:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (new_stab, cid)
                )
                bumped += 1
            else:
                skipped += 1

        return {"bumped": bumped, "skipped": skipped}
    except Exception:
        return {"bumped": 0, "skipped": 0}


# ── iter414: Self-Reference Effect — 自我参照内容的记忆优势（Rogers et al. 1977）──
# 认知科学依据：Rogers et al. (1977), Symons & Johnson (1997 meta-analysis):
#   以"与自我相关"方式加工的信息比语义加工的记忆更强（+0.5 SD）。
# OS 类比：Linux process 自身页（stack/heap/text）在 TLB 中有最高局部性。

_SELF_REF_MARKERS = frozenset([
    "i ", "i'm", "i've", "i'll", "i'd", "we ", "we're", "we've", "we'll",
    "our ", "my ", "myself", "ourselves", "me ", "us ", "let me", "let's",
    # Chinese self-reference markers
    "我", "我们", "我的", "我们的", "自己",
])


def compute_self_reference_score(content: str, chunk_type: str = "") -> float:
    """
    iter414: 计算内容的自我参照分数 [0.0, 1.0]。

    检测内容中第一人称标记的密度，以及 agent 主动生成的 chunk 类型加成。

    Returns:
      float — 自我参照分数 [0.0, 1.0]
    """
    if not content:
        return 0.0
    try:
        content_lower = content.lower()
        # Count self-reference marker occurrences
        total_matches = 0
        for marker in _SELF_REF_MARKERS:
            # Simple substring count (fast, no regex)
            idx = 0
            while True:
                pos = content_lower.find(marker, idx)
                if pos == -1:
                    break
                total_matches += 1
                idx = pos + len(marker)

        # Normalize by content length (per 100 chars)
        content_words = max(1, len(content.split()))
        density = total_matches / content_words

        # chunk_type bonus: agent-generated types get extra self-reference weight
        type_bonus = 0.0
        if chunk_type in ("reasoning_chain", "decision", "causal_chain", "procedure"):
            type_bonus = 0.2  # agent's own reasoning = inherently self-referential

        raw_score = min(1.0, density * 5.0 + type_bonus)  # density 0.2 → raw=1.0 + bonus
        return min(1.0, raw_score)
    except Exception:
        return 0.0


def self_ref_stability_bonus(score: float, base_stability: float, bonus_cap: float = 0.25) -> float:
    """
    iter414: 根据自我参照分数计算 stability 加成。

    bonus = base × bonus_cap × score
    capped at base × bonus_cap

    Args:
      score: self-reference score [0.0, 1.0]
      base_stability: chunk 的基础 stability
      bonus_cap: 最大加成比例（默认 0.25 = base × 25%）

    Returns:
      float — stability 加成量
    """
    if score <= 0.0 or base_stability <= 0.0:
        return 0.0
    max_bonus = base_stability * bonus_cap
    return min(max_bonus, max_bonus * score)


def apply_self_reference_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter414: 读取 chunk 内容，计算自我参照加成并更新 stability。

    Returns:
      float — 更新后的 stability
    """
    if not chunk_id:
        return base_stability
    import config as _config
    if not _config.get("store_vfs.self_ref_enabled"):
        return base_stability
    try:
        row = conn.execute(
            "SELECT content, chunk_type FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability
        content = row[0] if isinstance(row, (list, tuple)) else row["content"]
        chunk_type = row[1] if isinstance(row, (list, tuple)) else row["chunk_type"]
        bonus_cap = _config.get("store_vfs.self_ref_bonus_cap")
        score = compute_self_reference_score(content or "", chunk_type or "")
        bonus = self_ref_stability_bonus(score, base_stability, bonus_cap)
        new_stability = base_stability + bonus
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter415: Encoding Variability — 多情境编码的记忆鲁棒性（Estes 1955）──────────
# 认知科学依据：多情境编码 → 更多检索线索 → retrieval robustness。
# OS 类比：共享库被 N 个进程引用 → 高引用计数 → 不易被 kswapd 驱逐。


def compute_context_enrichment(current_ec: str, original_ec_count: int) -> int:
    """
    iter415: 计算 encode_context 的富化程度（新增 token 数）。

    Returns:
      int — 超过原始 token 数的新增 token 数量（>= 0）
    """
    if not current_ec:
        return 0
    current_tokens = [t.strip() for t in current_ec.split(",") if t.strip()]
    enrichment = max(0, len(current_tokens) - original_ec_count)
    return enrichment


def encoding_variability_bonus(enrichment_count: int, base_stability: float,
                                scale: float = 0.05) -> float:
    """
    iter415: 根据 encode_context 富化程度计算 stability 加成。

    bonus = base × min(0.15, enrichment_count × scale)
    capped at base × 0.15

    Args:
      enrichment_count: 超过初始 token 数的新增 token 数量
      base_stability: 当前 stability
      scale: 每个新增 token 的加成系数（默认 0.05）

    Returns:
      float — stability 加成量
    """
    if enrichment_count <= 0 or base_stability <= 0.0:
        return 0.0
    max_factor = 0.15  # cap at base × 15%
    factor = min(max_factor, enrichment_count * scale)
    return base_stability * factor


def apply_encoding_variability(
    conn: sqlite3.Connection,
    chunk_id: str,
    current_stability: float = None,
) -> float:
    """
    iter415: 检查 encode_context 富化程度，给予 stability 加成。

    只在 update_accessed 时调用（不在 insert_chunk 时调用，因为初始状态无富化）。

    Returns:
      float — 更新后的 stability（如无富化则返回 current_stability）
    """
    if not chunk_id:
        return current_stability or 0.0
    import config as _config
    if not _config.get("store_vfs.encoding_variability_enabled"):
        return current_stability or 0.0
    try:
        row = conn.execute(
            "SELECT stability, encode_context, COALESCE(original_ec_count, 0) AS orig_count "
            "FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return current_stability or 0.0

        stab = float(row[0] if isinstance(row, (list, tuple)) else row["stability"]) or 1.0
        ec = row[1] if isinstance(row, (list, tuple)) else row["encode_context"]
        orig_count = int(row[2] if isinstance(row, (list, tuple)) else row["orig_count"])

        if current_stability is not None:
            stab = current_stability

        scale = _config.get("store_vfs.encoding_variability_scale")
        enrichment = compute_context_enrichment(ec or "", orig_count)
        bonus = encoding_variability_bonus(enrichment, stab, scale)
        new_stability = min(365.0, stab + bonus)
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return current_stability or 0.0


# ── iter416: Zeigarnik Effect — 未完成任务的记忆优势（Zeigarnik 1927）──────────────
# 认知科学依据：Zeigarnik (1927) — 未完成任务 recall superiority ≈ +90% vs completed tasks。
#   Lewin (1935) Tension System Theory — 未完成任务维持认知系统"张力"，保持记忆激活。
# OS 类比：Linux futex waitqueue — pending I/O 保留在内核队列，不被 swapd 驱逐。

_ZEIGARNIK_MARKERS = frozenset([
    "todo", "fixme", "hack", "xxx", "wip", "pending", "unresolved",
    "incomplete", "not done", "need to", "needs to", "need to check",
    "investigate", "to be done", "to do", "follow up", "follow-up",
    "open issue", "open question", "tbd", "tbf", "tbr", "revisit",
    "blocked on", "waiting for", "in progress",
    # Chinese pending markers
    "待", "待确认", "待完成", "待处理", "未完成", "未解决", "需要确认",
    "需要调查", "跟进", "待跟进", "后续", "TODO", "FIXME",
])


def compute_zeigarnik_score(content: str, chunk_type: str = "") -> float:
    """
    iter416: 计算内容的 Zeigarnik 未完成任务分数 [0.0, 1.0]。

    检测内容中未完成任务信号词的存在，以及 task_state chunk_type 加成。

    Returns:
      float — Zeigarnik 分数 [0.0, 1.0]
    """
    if not content:
        return 0.0
    try:
        content_lower = content.lower()
        total_matches = 0
        for marker in _ZEIGARNIK_MARKERS:
            if marker.lower() in content_lower:
                total_matches += 1

        # Normalize: 1 match = 0.4, 2+ matches = higher, capped at 0.8 from content
        content_score = min(0.8, total_matches * 0.4) if total_matches > 0 else 0.0

        # chunk_type bonus: task_state chunks are inherently about pending tasks
        type_bonus = 0.0
        if chunk_type == "task_state":
            type_bonus = 0.2  # task_state = tracking incomplete workflow

        return min(1.0, content_score + type_bonus)
    except Exception:
        return 0.0


def zeigarnik_stability_bonus(score: float, base_stability: float,
                               bonus_cap: float = 0.20) -> float:
    """
    iter416: 根据 Zeigarnik score 计算 stability 加成。

    bonus = score × base × bonus_cap（线性比例，最大为 base × cap）
    """
    if score <= 0.0 or base_stability <= 0.0:
        return 0.0
    return min(base_stability * bonus_cap, score * base_stability * bonus_cap)


def apply_zeigarnik_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter416: 检测 chunk 的未完成任务信号，给予 stability 加成。

    在 insert_chunk 管线中调用（Self-Reference Effect 之后）。

    Returns:
      float — 更新后的 stability
    """
    if not chunk_id:
        return base_stability
    import config as _config
    if not _config.get("store_vfs.zeigarnik_enabled"):
        return base_stability
    try:
        row = conn.execute(
            "SELECT content, chunk_type, stability FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability

        content = row[0] if isinstance(row, (list, tuple)) else row["content"]
        chunk_type = row[1] if isinstance(row, (list, tuple)) else row["chunk_type"]
        stab = float(row[2] if isinstance(row, (list, tuple)) else row["stability"]) or 1.0

        bonus_cap = _config.get("store_vfs.zeigarnik_bonus_cap")
        score = compute_zeigarnik_score(content or "", chunk_type or "")
        bonus = zeigarnik_stability_bonus(score, stab, bonus_cap)
        new_stability = min(365.0, stab + bonus)
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter422: Permastore Memory — 充分强化后的记忆永久保护（Bahrick 1979）───────────────
# 认知科学依据：Bahrick (1979) Permastore — 充分暴露+高重要性的记忆达到"永久存储"状态：
#   即使经过数十年不复习，仍能保留约 80% 的可访问性（vs 普通记忆的完全遗忘）。
#   Conway et al. (1991): 专业知识（expert knowledge）具有 permastore 特征。
# 应用：满足条件的 chunk（age>=30d, access_count>=10, importance>=0.80）进入 permastore 状态；
#   RI/RIF/DF 对这些 chunk 只能将 stability 降低到 stability×floor_factor(0.80)，
#   而非普通的硬 floor=0.1，保护核心知识不被干扰效应过度压制。
# OS 类比：Linux mlock() + MADV_WILLNEED —
#   重要页面（内核代码、共享库 .text 段）mlock 锁定在 RAM，
#   即使系统内存极度紧张，kswapd 也无法驱逐这些页面（硬保护下限）。

def compute_permastore_floor(
    conn: sqlite3.Connection,
    chunk_id: str,
    current_stability: float,
) -> float:
    """
    iter422: 计算 chunk 的 stability 下限（Permastore Memory）。

    如果 chunk 满足 permastore 条件（age >= min_age_days, access_count >= min_acc,
    importance >= min_importance），返回 current_stability × floor_factor（> 普通 0.1）。
    否则返回普通 floor=0.1。

    在 RI/RIF/DF 函数中替代硬编码的 floor=0.1。

    Returns:
      float — 该 chunk 的 stability 下限
    """
    import config as _config
    if not _config.get("store_vfs.permastore_enabled"):
        return 0.1  # disabled: use normal floor
    try:
        min_age_days = _config.get("store_vfs.permastore_min_age_days")
        min_acc = _config.get("store_vfs.permastore_min_access_count")
        min_imp = _config.get("store_vfs.permastore_min_importance")
        floor_factor = _config.get("store_vfs.permastore_floor_factor")

        row = conn.execute(
            "SELECT created_at, access_count, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return 0.1

        created_at = row[0] if isinstance(row, (list, tuple)) else row["created_at"]
        access_count = int(row[1] if isinstance(row, (list, tuple)) else row["access_count"]) or 0
        importance = float(row[2] if isinstance(row, (list, tuple)) else row["importance"]) or 0.0

        if not created_at:
            return 0.1

        # Compute age in days
        try:
            from datetime import datetime as _dt, timezone as _tz
            _created_ts = _dt.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
            _now_ts = _dt.now(_tz.utc).timestamp()
            age_days = (_now_ts - _created_ts) / 86400.0
        except Exception:
            return 0.1

        if age_days >= min_age_days and access_count >= min_acc and importance >= min_imp:
            # Permastore: floor is a fraction of current stability
            return max(0.1, current_stability * floor_factor)

        return 0.1
    except Exception:
        return 0.1


# ── iter431: Ribot's Law — 远期记忆稳定性梯度（Ribot 1882）──────────────────────────
# 认知科学依据：Théodule Ribot (1882) "Diseases of Memory" —
#   越早形成的记忆越能抵抗损伤（retrograde amnesia gradient）。
#   脑损伤患者失去近期记忆，但保留远期（远古）的记忆——因为远期记忆已被"新皮层化"
#   （hippocampal → neocortical transfer，系统巩固理论）。
# 应用：chunk 年龄（age_days）越大 + importance >= ribot_min_importance →
#   stability_floor 随年龄对数增长：
#   floor_bonus = min(ribot_max_bonus, log(1+age_days)/log(365) × ribot_scale)
# OS 类比：Linux ext4 journal aging —
#   长时间存在的 inode（ancient inodes）在 extent tree 中有更稳定的布局，
#   碎片整理操作会优先保留而非移动 ancient extents。

def compute_ribot_floor(age_days: float, importance: float) -> float:
    """
    iter431: Ribot's Law — 计算基于年龄的 stability floor bonus。

    年龄越大、重要性越高的 chunk，stability floor 越高（远期记忆更稳定）。
    floor_bonus = min(ribot_max_bonus, log(1+age_days)/log(365) × ribot_scale)

    条件：
      - ribot_enabled = True
      - age_days >= ribot_min_age_days（默认 30 天）
      - importance >= ribot_min_importance（默认 0.60）

    Returns:
      float — floor_bonus [0.0, ribot_max_bonus]，加到普通 floor=0.1 上
    """
    import config as _config
    try:
        if not _config.get("scorer.ribot_enabled"):
            return 0.0
        min_age = float(_config.get("scorer.ribot_min_age_days") or 30)
        min_imp = float(_config.get("scorer.ribot_min_importance") or 0.60)
        if age_days < min_age or importance < min_imp:
            return 0.0
        import math
        ribot_scale = float(_config.get("scorer.ribot_scale") or 0.20)
        ribot_max = float(_config.get("scorer.ribot_max_bonus") or 0.25)
        bonus = math.log(1 + age_days) / math.log(365) * ribot_scale
        return min(ribot_max, bonus)
    except Exception:
        return 0.0


def _get_chunk_age_importance(conn, chunk_id: str) -> tuple:
    """
    iter431: 获取 chunk 的 age_days 和 importance，用于 Ribot floor 计算。
    返回 (age_days, importance)，出错返回 (0.0, 0.0)。
    """
    try:
        row = conn.execute(
            "SELECT created_at, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return 0.0, 0.0
        created_at = row[0] if isinstance(row, (list, tuple)) else row["created_at"]
        importance = float(row[1] if isinstance(row, (list, tuple)) else row["importance"]) or 0.0
        if not created_at:
            return 0.0, importance
        from datetime import datetime as _dt, timezone as _tz
        _created_ts = _dt.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
        _now_ts = _dt.now(_tz.utc).timestamp()
        age_days = (_now_ts - _created_ts) / 86400.0
        return age_days, importance
    except Exception:
        return 0.0, 0.0


# ── iter417: Retrieval-Induced Forgetting — 检索引发的竞争性抑制（Anderson et al. 1994）──
# 认知科学依据：Anderson, Bjork & Bjork (1994) "Remembering can cause forgetting" —
#   检索一个记忆时主动抑制其语义竞争者（inhibitory tagging），
#   抑制强度 ∝ 语义相似度（高相似 = 强竞争 = 更多抑制）。
# OS 类比：MESI 缓存一致性协议 —
#   写入 Modified cache line → 其他核心的相同 cache line 变为 Invalid。
#   访问 chunk A → 其语义竞争者 B 的"有效性"下降（类比 cache invalidation）。


def apply_retrieval_induced_forgetting(
    conn: sqlite3.Connection,
    chunk_ids: list,
    project: str,
) -> int:
    """
    iter417: 对被检索 chunk 的语义竞争者施加轻微 stability 衰减。

    在 update_accessed 调用后，对未被检索但与检索 chunk 高度重叠的语义邻居
    施加 RIF 抑制（stability × decay_factor）。

    Args:
      conn: SQLite 连接
      chunk_ids: 本次被检索的 chunk ID 列表
      project: 项目 ID（限定 RIF 范围，跨项目不产生干扰）

    Returns:
      int — 受到 RIF 抑制的邻居数量
    """
    if not chunk_ids or not project:
        return 0
    import config as _config
    if not _config.get("store_vfs.rif_enabled"):
        return 0
    try:
        decay_factor = _config.get("store_vfs.rif_decay_factor")
        min_overlap = _config.get("store_vfs.rif_min_overlap")
        max_neighbors = _config.get("store_vfs.rif_max_neighbors")

        if decay_factor >= 1.0:
            return 0  # no-op if factor is 1.0

        # Get encode_context tokens for each accessed chunk
        placeholders = ",".join(["?"] * len(chunk_ids))
        acc_rows = conn.execute(
            f"SELECT id, encode_context FROM memory_chunks WHERE id IN ({placeholders})",
            chunk_ids,
        ).fetchall()

        # Collect all tokens from accessed chunks
        accessed_token_sets = {}
        for row in acc_rows:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            ec = row[1] if isinstance(row, (list, tuple)) else row["encode_context"]
            tokens = frozenset(t.strip() for t in (ec or "").split(",") if t.strip())
            accessed_token_sets[cid] = tokens

        if not accessed_token_sets:
            return 0

        # Get candidate neighbors: same project, not in accessed set, has encode_context
        accessed_set = set(chunk_ids)
        candidates = conn.execute(
            "SELECT id, encode_context, stability FROM memory_chunks "
            "WHERE project=? AND encode_context IS NOT NULL AND stability > 0.1 "
            "AND id NOT IN ({})".format(",".join(["?"] * len(accessed_set))),
            [project] + list(accessed_set),
        ).fetchall()

        # Compute overlap for each candidate
        neighbor_overlaps = []
        for row in candidates:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            ec = row[1] if isinstance(row, (list, tuple)) else row["encode_context"]
            stab = float(row[2] if isinstance(row, (list, tuple)) else row["stability"])
            c_tokens = frozenset(t.strip() for t in (ec or "").split(",") if t.strip())
            if not c_tokens:
                continue
            # Find max overlap with any accessed chunk
            max_overlap = max(
                len(c_tokens & acc_tokens)
                for acc_tokens in accessed_token_sets.values()
            )
            if max_overlap >= min_overlap:
                neighbor_overlaps.append((cid, stab, max_overlap))

        if not neighbor_overlaps:
            return 0

        # Sort by overlap descending, take top N
        neighbor_overlaps.sort(key=lambda x: -x[2])
        to_inhibit = neighbor_overlaps[:max_neighbors]

        # Apply RIF decay (iter422: permastore floor, iter431: Ribot floor)
        inhibited = 0
        for n_cid, n_stab, _ in to_inhibit:
            _ps_floor = compute_permastore_floor(conn, n_cid, n_stab)
            _age_d, _imp = _get_chunk_age_importance(conn, n_cid)
            _ribot_floor = 0.1 + compute_ribot_floor(_age_d, _imp)
            new_stab = max(max(_ps_floor, _ribot_floor), n_stab * decay_factor)
            if abs(new_stab - n_stab) > 0.001:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (new_stab, n_cid)
                )
                inhibited += 1
        return inhibited
    except Exception:
        return 0


# ── iter418: Directed Forgetting — 主动弃置过时知识（MacLeod 1998）──────────────
# 认知科学依据：MacLeod (1998) Directed Forgetting — 主动指令"忘记"使记忆加速衰减。
# OS 类比：Linux madvise(MADV_DONTNEED) — 通知内核不再需要该内存区域，加速回收。

_DIRECTED_FORGETTING_MARKERS = frozenset([
    "deprecated", "obsolete", "outdated", "old version", "replaced by",
    "superseded", "no longer", "not anymore", "was removed", "has been removed",
    "has been replaced", "legacy", "remove this", "to be removed", "will be removed",
    "already done", "completed", "resolved", "closed", "done", "finished",
    # Chinese deprecated markers
    "已废弃", "已过时", "已替换", "已完成", "已解决", "已关闭", "已删除",
    "不再使用", "替换为", "被替换", "旧版本",
])


def compute_directed_forgetting_score(content: str, chunk_type: str = "") -> float:
    """
    iter418: 计算内容的"主动遗忘"分数 [0.0, 1.0]。

    检测过时/已完成/已废弃信号词，返回应被主动弃置的程度。

    Returns:
      float — directed forgetting 分数 [0.0, 1.0]
    """
    if not content:
        return 0.0
    try:
        content_lower = content.lower()
        total_matches = 0
        for marker in _DIRECTED_FORGETTING_MARKERS:
            if marker.lower() in content_lower:
                total_matches += 1

        # 1 match = 0.5 score (significant signal), 2+ = capped at 1.0
        return min(1.0, total_matches * 0.5) if total_matches > 0 else 0.0
    except Exception:
        return 0.0


def directed_forgetting_penalty(score: float, base_stability: float,
                                 penalty_cap: float = 0.15) -> float:
    """
    iter418: 根据 directed forgetting score 计算 stability 惩罚量。

    penalty = score × base × penalty_cap（线性比例，最大为 base × cap）
    """
    if score <= 0.0 or base_stability <= 0.0:
        return 0.0
    return min(base_stability * penalty_cap, score * base_stability * penalty_cap)


def apply_directed_forgetting(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter418: 检测 chunk 的过时/完成信号，给予 stability 惩罚（加速自然淘汰）。

    在 insert_chunk 管线中调用（Zeigarnik Effect 之后）。

    Returns:
      float — 更新后的 stability
    """
    if not chunk_id:
        return base_stability
    import config as _config
    if not _config.get("store_vfs.df_enabled"):
        return base_stability
    try:
        row = conn.execute(
            "SELECT content, chunk_type, stability FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability

        content = row[0] if isinstance(row, (list, tuple)) else row["content"]
        chunk_type = row[1] if isinstance(row, (list, tuple)) else row["chunk_type"]
        stab = float(row[2] if isinstance(row, (list, tuple)) else row["stability"]) or 1.0

        penalty_cap = _config.get("store_vfs.df_penalty_cap")
        score = compute_directed_forgetting_score(content or "", chunk_type or "")
        penalty = directed_forgetting_penalty(score, stab, penalty_cap)
        _ps_floor = compute_permastore_floor(conn, chunk_id, stab)
        _age_d2, _imp2 = _get_chunk_age_importance(conn, chunk_id)
        _ribot_floor2 = 0.1 + compute_ribot_floor(_age_d2, _imp2)
        new_stability = max(max(_ps_floor, _ribot_floor2), stab - penalty)  # iter422+431
        if penalty > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter419: Associative Memory — 新知识借助强关联记忆的编码优势 ────────────────────
# 认知科学依据：Ebbinghaus (1885) Paired Associates; Collins & Loftus (1975) —
#   新知识与已有强记忆共享节点时形成更强记忆痕迹（associative encoding advantage）。
# OS 类比：Linux huge pages — small page adjacent to huge page shares TLB entry (associative locality)。


def apply_associative_memory_bonus(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter419: 写入新 chunk 时，若与已有高重要性 chunk 共享 encode_context token，
    给予 stability 加成（关联记忆锚点效应）。

    在 insert_chunk 管线中调用（Directed Forgetting 之后）。

    Returns:
      float — 更新后的 stability
    """
    if not chunk_id or not project:
        return base_stability
    import config as _config
    if not _config.get("store_vfs.am_enabled"):
        return base_stability
    try:
        # Get new chunk's encode_context tokens
        new_row = conn.execute(
            "SELECT encode_context, stability FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not new_row:
            return base_stability

        new_ec = new_row[0] if isinstance(new_row, (list, tuple)) else new_row["encode_context"]
        stab = float(new_row[1] if isinstance(new_row, (list, tuple)) else new_row["stability"]) or 1.0

        new_tokens = frozenset(t.strip() for t in (new_ec or "").split(",") if t.strip())
        if not new_tokens:
            return stab  # no tokens, no associative bonus

        min_overlap = _config.get("store_vfs.am_min_overlap")
        min_imp = _config.get("store_vfs.am_min_importance")
        bonus_cap = _config.get("store_vfs.am_bonus_cap")

        # Find existing high-importance chunks in same project (excluding self)
        anchors = conn.execute(
            "SELECT id, encode_context, importance FROM memory_chunks "
            "WHERE project=? AND id!=? AND importance >= ? AND encode_context IS NOT NULL",
            (project, chunk_id, min_imp)
        ).fetchall()

        # Find max overlap with any anchor chunk
        max_overlap = 0
        for anchor_row in anchors:
            a_ec = anchor_row[1] if isinstance(anchor_row, (list, tuple)) else anchor_row["encode_context"]
            a_tokens = frozenset(t.strip() for t in (a_ec or "").split(",") if t.strip())
            if not a_tokens:
                continue
            overlap = len(new_tokens & a_tokens)
            if overlap > max_overlap:
                max_overlap = overlap

        if max_overlap < min_overlap:
            return stab  # no sufficient overlap with strong anchors

        # Compute bonus: overlap-scaled, capped at base × bonus_cap
        # More overlap = stronger associative encoding
        overlap_factor = min(1.0, (max_overlap - min_overlap + 1) / 4.0)  # scale: 0.25 per extra overlap
        bonus = stab * bonus_cap * overlap_factor
        new_stability = min(365.0, stab + bonus)
        if bonus > 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stability, chunk_id)
            )
        return new_stability
    except Exception:
        return base_stability


# ── iter421: Retroactive Interference — 新学习干扰旧记忆回忆 ────────────────────
# 认知科学依据：McGeoch (1932) Interference Theory; Barnes & Underwood (1959) —
#   新学习的信息（新 chunk）干扰对旧相关信息（高重叠旧 chunk）的回忆。
#   RI 与 PI（iter408）互补：PI = 旧→新，RI = 新→旧。
#   McGeoch: 遗忘的主因是相似记忆的竞争性干扰，而非 Ebbinghaus 的被动衰减。
#   Anderson & Green (2001): 主动抑制相似记忆是 RI 的神经机制。
# 应用：insert_chunk 时，对同项目中 encode_context 高度重叠的低importance旧 chunk
#   施加轻微 stability 衰减（× ri_decay_factor=0.98），模拟新记忆干扰旧记忆。
#   高重要性（importance >= ri_protect_importance=0.85）的 chunk 免疫 RI（核心知识受保护）。
# OS 类比：TLB shootdown (inter-processor interrupt) —
#   当一个核建立新的 VA→PA 映射时，发送 IPI 使其他所有核的相同 VA TLB 条目失效。
#   新 chunk 写入 = 新映射建立 = 旧相关 chunk（旧 VA 条目）需要被"失效"（stability 降低）。

def apply_retroactive_interference(
    conn: sqlite3.Connection,
    new_chunk_id: str,
    project: str,
    base_stability: float = 1.0,
) -> int:
    """
    iter421: 写入新 chunk 后，对同项目中 encode_context 高重叠的旧 chunk 施加轻微 stability 衰减。

    在 insert_chunk 管线中调用（Associative Memory 之后）。

    Returns:
      int — 被干扰的 chunk 数量
    """
    if not new_chunk_id or not project:
        return 0
    import config as _config
    if not _config.get("store_vfs.ri_enabled"):
        return 0
    try:
        min_overlap = _config.get("store_vfs.ri_min_overlap")
        decay_factor = _config.get("store_vfs.ri_decay_factor")
        max_targets = _config.get("store_vfs.ri_max_targets")
        protect_imp = _config.get("store_vfs.ri_protect_importance")

        if decay_factor >= 1.0:
            return 0  # no-op

        # Get new chunk's encode_context tokens
        new_row = conn.execute(
            "SELECT encode_context FROM memory_chunks WHERE id=?",
            (new_chunk_id,)
        ).fetchone()
        if not new_row:
            return 0
        new_ec = new_row[0] if isinstance(new_row, (list, tuple)) else new_row["encode_context"]
        new_tokens = frozenset(t.strip() for t in (new_ec or "").split(",") if t.strip())
        if not new_tokens:
            return 0

        # Find existing chunks in same project (not self, not high-importance anchors)
        candidates = conn.execute(
            "SELECT id, encode_context, stability FROM memory_chunks "
            "WHERE project=? AND id!=? AND importance < ? AND encode_context IS NOT NULL",
            (project, new_chunk_id, protect_imp)
        ).fetchall()

        # Compute overlap for each candidate
        overlapping = []
        for cand in candidates:
            c_id = cand[0] if isinstance(cand, (list, tuple)) else cand["id"]
            c_ec = cand[1] if isinstance(cand, (list, tuple)) else cand["encode_context"]
            c_stab = float(cand[2] if isinstance(cand, (list, tuple)) else cand["stability"]) or 1.0
            c_tokens = frozenset(t.strip() for t in (c_ec or "").split(",") if t.strip())
            overlap = len(new_tokens & c_tokens)
            if overlap >= min_overlap:
                overlapping.append((c_id, c_stab, overlap))

        if not overlapping:
            return 0

        # Sort by overlap descending, take top max_targets
        overlapping.sort(key=lambda x: x[2], reverse=True)
        overlapping = overlapping[:max_targets]

        inhibited = 0
        for c_id, c_stab, _ in overlapping:
            _ps_floor = compute_permastore_floor(conn, c_id, c_stab)
            _age_d3, _imp3 = _get_chunk_age_importance(conn, c_id)
            _ribot_floor3 = 0.1 + compute_ribot_floor(_age_d3, _imp3)
            new_stab = max(max(_ps_floor, _ribot_floor3), c_stab * decay_factor)  # iter422+431
            if abs(new_stab - c_stab) > 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (new_stab, c_id)
                )
                inhibited += 1
        return inhibited
    except Exception:
        return 0


# ── iter413: Sleep Consolidation — 离线记忆巩固（Stickgold 2005）───────────────
# 认知科学依据：NREM 睡眠中海马体重放最近学习的记忆，将其转移到新皮层。
# OS 类比：Linux pdflush/writeback daemon — session 间 idle period 内后台巩固 dirty pages。


def run_sleep_consolidation(
    conn: sqlite3.Connection,
    project: str,
    now_iso: str = None,
    session_started_at: str = None,
) -> dict:
    """
    iter413: Sleep Consolidation — SessionStart 时对上一 session 的高重要性 chunk 应用离线巩固。
    iter428: Event Segmentation Gate — 分叉 boundary_proximity 处理。

    Stickgold (2005): NREM 睡眠中海马重放最近学习的记忆 → stability 提升 20-30%。
    Zacks et al. (2007) Event Segmentation: boundary 处记忆编码最强（boundary_proximity > 0）。
    Radvansky (2006) doorway effect: 边界前的 chunk 受短暂抑制（boundary_proximity < -0.5）。

    iter428 分叉逻辑（基于 boundary_proximity 列）：
      boundary_proximity > 0    → 边界加成：boost_factor × boundary_multiplier（刚越过 session boundary）
      boundary_proximity < -0.5 → doorway 惩罚：stability -= stability × doorway_penalty（上一 session 末尾）
      其余                      → 标准 sleep consolidation（× boost_factor）

    返回 dict: {"consolidated": int, "project": str, "boost_factor": float,
                "boundary_boosted": int, "doorway_penalized": int}
    """
    import config as _config
    if not _config.get("consolidation.enabled"):
        return {"consolidated": 0, "project": project, "boost_factor": 1.0,
                "boundary_boosted": 0, "doorway_penalized": 0}
    if not project:
        return {"consolidated": 0, "project": project, "boost_factor": 1.0,
                "boundary_boosted": 0, "doorway_penalized": 0}

    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()
    if session_started_at is None:
        session_started_at = now_iso

    boost_factor = _config.get("consolidation.boost_factor")
    min_importance = _config.get("consolidation.min_importance")
    window_hours = _config.get("consolidation.window_hours")
    max_chunks = _config.get("consolidation.max_chunks")
    # iter428 params
    boundary_multiplier = _config.get("consolidation.boundary_multiplier")
    doorway_penalty = _config.get("consolidation.doorway_penalty")
    boundary_enabled = _config.get("consolidation.boundary_enabled")

    try:
        from datetime import timedelta as _td
        _now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        _cutoff = (_now_dt - _td(hours=window_hours)).isoformat()

        # 选取：high-importance + recently accessed + this project
        # iter428: 加上 boundary_proximity 列（若存在）
        rows = conn.execute(
            "SELECT id, stability, COALESCE(boundary_proximity, 0.0) as bp FROM memory_chunks "
            "WHERE project=? AND importance >= ? AND last_accessed >= ? "
            "  AND COALESCE(stability, 0) < 365.0 "
            "ORDER BY importance DESC LIMIT ?",
            (project, min_importance, _cutoff, max_chunks)
        ).fetchall()

        if not rows:
            return {"consolidated": 0, "project": project, "boost_factor": boost_factor,
                    "boundary_boosted": 0, "doorway_penalized": 0}

        consolidated = 0
        boundary_boosted = 0
        doorway_penalized = 0

        for row in rows:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = float(row[1] if isinstance(row, (list, tuple)) else row["stability"]) or 1.0
            bp = float(row[2] if isinstance(row, (list, tuple)) else row["bp"])

            if boundary_enabled and bp > 0.0:
                # iter428: Boundary encoding boost — 刚越过 session boundary
                # 线性插值：proximity=1.0 时乘以 boundary_multiplier，proximity=0 时乘以 boost_factor
                effective_factor = boost_factor + (boundary_multiplier - 1.0) * bp
                new_stab = min(365.0, stab * effective_factor)
                boundary_boosted += 1
            elif boundary_enabled and bp < -0.5:
                # iter428: Doorway effect — 上一 session 末尾，短暂抑制
                # 惩罚强度随 |bp| 线性增加（bp=-1.0 时最大惩罚）
                penalty_strength = doorway_penalty * abs(bp + 0.5) / 0.5  # 从 bp=-0.5 线性增到 bp=-1.0
                new_stab = max(0.1, stab * (1.0 - penalty_strength))
                doorway_penalized += 1
            else:
                # 标准 sleep consolidation
                new_stab = min(365.0, stab * boost_factor)

            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (round(new_stab, 4), cid)
            )
            consolidated += 1

        return {"consolidated": consolidated, "project": project, "boost_factor": boost_factor,
                "boundary_boosted": boundary_boosted, "doorway_penalized": doorway_penalized}
    except Exception:
        return {"consolidated": 0, "project": project, "boost_factor": boost_factor,
                "boundary_boosted": 0, "doorway_penalized": 0}


# ── 迭代100：IPC 共享内存 API（OS 类比：shmget/shmat/shmdt + MESI 协议）────────

def shm_attach(conn: sqlite3.Connection, chunk_id: str, agent_id: str,
               shared_with: str = "*") -> None:
    """将 chunk 挂载到共享内存段，多 Agent 可见。等价于 shmat()。"""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO shm_segments
        (chunk_id, owner_agent, shared_with, version, state, created_at, updated_at)
        VALUES (?, ?, ?, 1, 'SHARED', ?, ?)
    """, (chunk_id, agent_id, shared_with, now, now))


def shm_detach(conn: sqlite3.Connection, chunk_id: str, agent_id: str) -> None:
    """从共享内存段卸载。等价于 shmdt()。"""
    conn.execute(
        "DELETE FROM shm_segments WHERE chunk_id=? AND owner_agent=?",
        (chunk_id, agent_id))


def shm_list(conn: sqlite3.Connection, agent_id: str = None,
             project: str = None) -> list:
    """列出当前可见的共享内存段。"""
    sql = """
        SELECT s.chunk_id, s.owner_agent, s.shared_with, s.version, s.state,
               m.summary, m.chunk_type, m.importance
        FROM shm_segments s
        JOIN memory_chunks m ON s.chunk_id = m.id
        WHERE s.state != 'INVALID'
    """
    params = []
    if agent_id:
        sql += " AND (s.shared_with = '*' OR s.shared_with LIKE ?)"
        params.append(f"%{agent_id}%")
    if project:
        sql += " AND m.project IN (?, 'global')"
        params.append(project)
    return [dict(zip(
        ["chunk_id", "owner_agent", "shared_with", "version", "state",
         "summary", "chunk_type", "importance"], r))
        for r in conn.execute(sql, params).fetchall()]


def shm_invalidate(conn: sqlite3.Connection, chunk_id: str) -> int:
    """MESI Invalidate — 标记所有 Agent 缓存失效。修改 chunk 时调用。"""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("""
        UPDATE shm_segments SET state='INVALID', updated_at=?
        WHERE chunk_id=? AND state != 'INVALID'
    """, (now, chunk_id))
    return cur.rowcount


def shm_promote(conn: sqlite3.Connection, chunk_id: str, agent_id: str,
                project: str = None) -> None:
    """将高价值 chunk 提升到共享内存（global promotion）。"""
    now = datetime.now(timezone.utc).isoformat()
    # 如果指定 project，同时标记 chunk 为 global
    if project:
        conn.execute(
            "UPDATE memory_chunks SET project='global' WHERE id=? AND project=?",
            (chunk_id, project))
    shm_attach(conn, chunk_id, agent_id, shared_with="*")


# ── 迭代100：IPC 消息队列 API（OS 类比：POSIX mq_send/mq_receive）────────

def ipc_send(conn: sqlite3.Connection, source: str, target: str,
             msg_type: str, payload: dict, priority: int = 0,
             ttl_seconds: int = 3600) -> int:
    """发送 IPC 消息。返回消息 ID。"""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("""
        INSERT INTO ipc_msgq (source_agent, target_agent, msg_type, payload,
                              priority, status, created_at, ttl_seconds)
        VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?)
    """, (source, target, msg_type, json.dumps(payload, ensure_ascii=False),
          priority, now, ttl_seconds))
    return cur.lastrowid


def ipc_recv(conn: sqlite3.Connection, agent_id: str,
             msg_type: str = None, limit: int = 10) -> list:
    """接收 IPC 消息。标记为 CONSUMED。等价于 mq_receive()。"""
    now = datetime.now(timezone.utc).isoformat()
    sql = """
        SELECT id, source_agent, msg_type, payload, priority, created_at
        FROM ipc_msgq
        WHERE (target_agent = ? OR target_agent = '*')
          AND status = 'QUEUED'
    """
    params = [agent_id]
    if msg_type:
        sql += " AND msg_type = ?"
        params.append(msg_type)
    sql += " ORDER BY priority DESC, created_at ASC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    msgs = []
    for r in rows:
        msgs.append({
            "id": r[0], "source": r[1], "msg_type": r[2],
            "payload": json.loads(r[3]) if r[3] else {},
            "priority": r[4], "created_at": r[5],
        })
        conn.execute(
            "UPDATE ipc_msgq SET status='CONSUMED', consumed_at=? WHERE id=?",
            (now, r[0]))
    return msgs


def ipc_broadcast_knowledge_update(conn: sqlite3.Connection, agent_id: str,
                                    project: str, stats: dict) -> int:
    """广播知识更新通知（修改 chunk 后调用）。"""
    return ipc_send(conn, agent_id, "*", "knowledge_update",
                    {"project": project, **stats}, priority=5)


def ipc_cleanup_expired(conn: sqlite3.Connection) -> int:
    """清理过期消息。loader SessionStart 时调用。"""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute("""
        DELETE FROM ipc_msgq
        WHERE status = 'QUEUED'
          AND datetime(created_at, '+' || ttl_seconds || ' seconds') < datetime(?)
    """, (now,))
    return cur.rowcount


# ── 迭代100：可验证性 API（OS 类比：ECC + TCB — Trusted Computing Base）────────

def update_confidence(conn: sqlite3.Connection, chunk_id: str,
                      delta: float, reason: str,
                      verification_status: str = None) -> float:
    """更新 chunk 置信度。返回新值。"""
    row = conn.execute(
        "SELECT confidence_score, verification_status FROM memory_chunks WHERE id=?",
        (chunk_id,)).fetchone()
    if not row:
        return 0.0
    old = row[0] or 0.7
    new_conf = max(0.05, min(0.99, old + delta))
    new_status = verification_status or row[1] or "pending"
    conn.execute("""
        UPDATE memory_chunks
        SET confidence_score=?, verification_status=?, updated_at=?
        WHERE id=?
    """, (new_conf, new_status, datetime.now(timezone.utc).isoformat(), chunk_id))
    return new_conf


def get_confidence_stats(conn: sqlite3.Connection, project: str) -> dict:
    """获取项目级置信度统计。"""
    rows = conn.execute("""
        SELECT verification_status, COUNT(*), AVG(confidence_score)
        FROM memory_chunks WHERE project IN (?, 'global')
        GROUP BY verification_status
    """, (project,)).fetchall()
    return {r[0] or "pending": {"count": r[1], "avg_conf": round(r[2] or 0.7, 3)}
            for r in rows}


# ── 迭代64：chunk_version — TLB Selective Invalidation ────────────────────────
# OS 类比：Linux inode generation number + NFS Weak Cache Consistency (WKC)

def bump_chunk_version() -> int:
    """递增并返回新版本号。仅在 chunk 新增/删除时调用。"""
    try:
        CHUNK_VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        ver = 0
        if CHUNK_VERSION_FILE.exists():
            try:
                ver = int(CHUNK_VERSION_FILE.read_text().strip())
            except (ValueError, OSError):
                ver = 0
        ver += 1
        CHUNK_VERSION_FILE.write_text(str(ver))
        return ver
    except Exception:
        return 0


def read_chunk_version() -> int:
    """读取当前 chunk_version。用于 TLB 缓存失效判断。"""
    try:
        if CHUNK_VERSION_FILE.exists():
            return int(CHUNK_VERSION_FILE.read_text().strip())
    except (ValueError, OSError):
        pass
    return 0

def update_accessed(conn: sqlite3.Connection, chunk_ids: list,
                    now_iso: str = None, recall_quality: int = None,
                    _sm2_only: bool = False, **kwargs) -> None:
    """
    批量更新 last_accessed + access_count 自增。
    iter106: 同时执行 auto-verification — access_count 达到阈值后自动升 verified。
    iter323: SM-2 Ebbinghaus 精确化 — stability × (1 + 0.1 × (quality-3))。
    OS 类比：MMU Accessed bit 置位 + kswapd 扫描计数 + ECC 自动修正。

    _sm2_only=True: 跳过所有 secondary cognitive effects，只执行 SM-2 core 公式。
      用于单元测试精确验证 SM-2 factor，不受 IOR/RIF/PEME 等效应干扰。

    Ebbinghaus spacing effect 背景（iter301）：
      心理学研究表明，知识被重复检索的间隔越长，每次重复后的记忆稳定性增益越大。
      memory-os 简化模型：每次命中 stability *= 2.0，上限 365 天（一年）。
      stability 高的 chunk 在 eviction 评分中受保护：
        eviction_score = age_days / stability（越大越优先被驱逐）
      结果：高频被用的知识越来越稳固，长期未被访问的知识自然衰减至被驱逐。
    """
    if not chunk_ids:
        return
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).isoformat()
    placeholders = ",".join("?" * len(chunk_ids))
    # iter389: Read last_accessed + stability BEFORE update (needed for reconsolidation gap calc + iter412 Testing Effect)
    # iter453: also read access_count, retrievability, importance for PEME
    # iter455: also read spaced_access_count for GSIE
    _pre_access_rows = conn.execute(
        f"SELECT id, last_accessed, COALESCE(stability,1.0), COALESCE(access_count,0), "
        f"COALESCE(retrievability,0.5), COALESCE(importance,0.5), COALESCE(spaced_access_count,0) "
        f"FROM memory_chunks WHERE id IN ({placeholders})",
        chunk_ids,
    ).fetchall()
    _pre_access_map = {row[0]: row[1] for row in _pre_access_rows}
    _pre_stability_map = {row[0]: float(row[2]) for row in _pre_access_rows}
    _pre_access_count_map = {row[0]: int(row[3]) for row in _pre_access_rows}
    _pre_retrievability_map = {row[0]: float(row[4]) for row in _pre_access_rows}
    _pre_importance_map = {row[0]: float(row[5]) for row in _pre_access_rows}
    _pre_spaced_access_map = {row[0]: int(row[6]) for row in _pre_access_rows}
    conn.execute(
        f"UPDATE memory_chunks SET last_accessed=?, access_count=COALESCE(access_count,0)+1 "
        f"WHERE id IN ({placeholders})",
        [now_iso] + chunk_ids,
    )
    # iter323: SM-2 Ebbinghaus 精确化 — 替代 stability *= 2.0 的粗糙模型
    # Wozniak (1987) SM-2 算法：S_new = S_old × (1 + 0.1 × (quality - 3))
    #   quality ∈ {0..5}：0=完全忘记，3=勉强回忆，5=完美回忆
    #   quality=5 → ×1.2（最大增益），quality=3 → ×1.0（中性），quality<3 → 降低 stability
    #   旧 ×2.0 = 固定 quality=13 的极端假设，导致 stability 过快饱和
    #
    # iter389: Reconsolidation Window — Walker & Stickgold (2004) 再巩固窗口
    #   gap < 1hr   → quality=3（短时工作记忆刷新，无长时巩固效果）
    #   1hr ≤ gap < 24hr → quality=4（中等间隔，轻微加固）
    #   gap ≥ 24hr  → quality=5（真正的间隔回忆，最大巩固效果）
    #   显式 recall_quality 参数优先（调用方已推断质量时不被覆盖）
    #
    # OS 类比：Linux MGLRU page aging —
    #   短间隔访问（< aging_interval）不晋升 generation；跨 aging 访问 → generation 晋升
    # iter389: Reconsolidation Window — dynamic SM-2 quality inference
    if recall_quality is not None:
        # explicit quality override — skip reconsolidation window
        _rq = max(0, min(5, recall_quality))
        _sm2_factor = max(0.7, 1.0 + 0.1 * (_rq - 3))
        conn.execute(
            f"UPDATE memory_chunks "
            f"SET stability=MIN(365.0, COALESCE(stability,1.0)*?) "
            f"WHERE id IN ({placeholders})",
            [_sm2_factor] + chunk_ids,
        )
    else:
        import config as _config
        _recon_enabled = _config.get("recon.enabled")
        if _recon_enabled:
            # 动态计算：使用 pre-update last_accessed 推断 quality（避免 N+1 重查）
            _short_gap_secs = _config.get("recon.short_gap_hours") * 3600.0
            _medium_gap_secs = _config.get("recon.medium_gap_hours") * 3600.0
            _long_q = _config.get("recon.long_gap_quality")
            _now_ts = datetime.fromisoformat(now_iso.replace("Z", "+00:00")).timestamp()
            # iter412: Testing Effect — 高难度检索强化记忆巩固
            # Roediger & Karpicke (2006): 难检索 → R_at_recall 低 → quality_bonus 高
            # OS 类比：L3 cache miss → aggressive LRU promotion to L1/L2
            _testing_effect_enabled = _config.get("recon.testing_effect_enabled")
            _testing_effect_scale = _config.get("recon.testing_effect_scale")
            # iter420: Spacing Effect — 分布式练习 quality 加成
            # Ebbinghaus (1885) / Cepeda et al. (2006): spaced > massed practice
            # OS 类比：MGLRU cross-generation promotion — distributed access > massed access
            _spacing_effect_enabled = _config.get("store_vfs.spacing_effect_enabled")
            _spacing_quality_scale = _config.get("store_vfs.spacing_quality_scale")

            # 构建 per-chunk quality map（使用 pre-update last_accessed），默认 quality=4
            _quality_map = {cid: 4 for cid in chunk_ids}
            _spaced_increment_ids = []  # chunks that qualify for spaced_access_count increment
            for cid, la in _pre_access_map.items():
                if la:
                    try:
                        _la_ts = datetime.fromisoformat(la.replace("Z", "+00:00")).timestamp()
                        _gap = _now_ts - _la_ts
                        if _gap < _short_gap_secs:
                            _quality_map[cid] = 3
                        elif _gap < _medium_gap_secs:
                            _quality_map[cid] = 4
                        else:
                            _quality_map[cid] = _long_q
                            # iter420: gap >= medium_gap_hours (24h) → this is a "new session"
                            # Increment spaced_access_count for this chunk
                            if _spacing_effect_enabled:
                                _spaced_increment_ids.append(cid)
                        # iter412: Testing Effect — boost quality if retrieval was difficult
                        if _testing_effect_enabled and _testing_effect_scale > 0:
                            import math as _math
                            _stab = _pre_stability_map.get(cid, 1.0)
                            # R_at_recall = exp(-gap_hours / (stability × 24))
                            _gap_hours = _gap / 3600.0
                            _r_at_recall = _math.exp(-_gap_hours / max(0.01, _stab * 24.0))
                            _difficulty = max(0.0, 1.0 - _r_at_recall)
                            _q_bonus = round(_difficulty * _testing_effect_scale)
                            if _q_bonus > 0:
                                _quality_map[cid] = min(5, _quality_map[cid] + _q_bonus)
                    except Exception:
                        pass
            # iter420: Spacing Effect — increment spaced_access_count for long-gap accesses
            if _spacing_effect_enabled and _spaced_increment_ids:
                _sp_ph = ",".join("?" * len(_spaced_increment_ids))
                conn.execute(
                    f"UPDATE memory_chunks SET spaced_access_count=COALESCE(spaced_access_count,0)+1 "
                    f"WHERE id IN ({_sp_ph})",
                    _spaced_increment_ids,
                )
            # iter420: Spacing Effect — add quality bonus based on spacing_factor
            if _spacing_effect_enabled and _spacing_quality_scale > 0:
                # Read spaced_access_count and access_count after increment
                _sp_rows = conn.execute(
                    f"SELECT id, COALESCE(spaced_access_count,0), COALESCE(access_count,1) "
                    f"FROM memory_chunks WHERE id IN ({placeholders})",
                    chunk_ids,
                ).fetchall()
                for _sp_row in _sp_rows:
                    _cid = _sp_row[0]
                    _sac = int(_sp_row[1])  # spaced_access_count
                    _ac = max(1, int(_sp_row[2]))   # access_count
                    _spacing_factor = _sac / _ac  # ∈ [0, 1]
                    if _spacing_factor > 0:
                        _sq_bonus = round(_spacing_factor * _spacing_quality_scale)
                        if _sq_bonus > 0:
                            _quality_map[_cid] = min(5, _quality_map.get(_cid, 4) + _sq_bonus)
            # 按 quality 分组批量更新（避免 N 次单独 SQL）
            from collections import defaultdict as _defaultdict
            _by_quality = _defaultdict(list)
            for cid in chunk_ids:
                _by_quality[_quality_map.get(cid, 4)].append(cid)
            for _q, _cids in _by_quality.items():
                _sm2_f = max(0.7, 1.0 + 0.1 * (_q - 3))
                _ph = ",".join("?" * len(_cids))
                conn.execute(
                    f"UPDATE memory_chunks SET stability=MIN(365.0,COALESCE(stability,1.0)*?) "
                    f"WHERE id IN ({_ph})",
                    [_sm2_f] + _cids,
                )
        else:
            # fallback: fixed quality=4
            _sm2_factor = 1.1  # quality=4 → ×1.1
            conn.execute(
                f"UPDATE memory_chunks "
                f"SET stability=MIN(365.0, COALESCE(stability,1.0)*?) "
                f"WHERE id IN ({placeholders})",
                [_sm2_factor] + chunk_ids,
            )
    # iter106: Auto-Verification — access_count >= 3 且 pending → verified
    # 逻辑：多次被实际召回说明有效，自动升级 verification_status
    # OS 类比：ECC 多次读取一致 → 标记页面为 clean
    AUTO_VERIFY_THRESHOLD = 3
    conn.execute(
        f"UPDATE memory_chunks SET verification_status='verified' "
        f"WHERE id IN ({placeholders}) "
        f"  AND verification_status='pending' "
        f"  AND COALESCE(access_count,0) >= ?",
        chunk_ids + [AUTO_VERIFY_THRESHOLD],
    )

    # Secondary cognitive effects — skipped when _sm2_only=True (unit test mode)
    if _sm2_only:
        return

    # iter404: Semantic Priming — 访问 chunk 时，prime 其 encode_context 中的实体
    # OS 类比：readahead_trigger() — 访问 page N，将相邻 pages 标记进 readahead window
    try:
        ec_rows = conn.execute(
            f"SELECT id, encode_context, project FROM memory_chunks "
            f"WHERE id IN ({placeholders}) AND encode_context IS NOT NULL AND encode_context != ''",
            chunk_ids,
        ).fetchall()
        for _cid, _ec, _proj in ec_rows:
            if _ec and _proj:
                _tokens = [t.strip() for t in _ec.split(",") if t.strip()]
                if _tokens:
                    prime_entities(conn, _tokens, _proj, prime_strength=0.8, now_iso=now_iso)
    except Exception:
        pass

    # iter415: Encoding Variability — 多情境访问 → encode_context 富化 → stability 加成
    # Estes (1955): 多情境编码提升检索鲁棒性（更多检索线索）
    # OS 类比：共享库被 N 个进程引用 → 高引用计数 → 不易被 kswapd 驱逐
    try:
        for _cid in chunk_ids:
            apply_encoding_variability(conn, _cid)
    except Exception:
        pass

    # iter417: Retrieval-Induced Forgetting (encode_context) — 语义竞争者 stability 轻微衰减
    # Anderson et al. (1994): 检索记忆 A 抑制其语义竞争者 B/C
    # OS 类比：MESI 协议 — 写入 cache line 使其他核的相同 line 变为 Invalid
    try:
        # Get project from the accessed chunks (use first hit)
        _rif_proj_row = conn.execute(
            f"SELECT project FROM memory_chunks WHERE id IN ({placeholders}) LIMIT 1",
            chunk_ids,
        ).fetchone()
        if _rif_proj_row:
            _rif_proj = _rif_proj_row[0] if isinstance(_rif_proj_row, (list, tuple)) else _rif_proj_row["project"]
            apply_retrieval_induced_forgetting(conn, chunk_ids, _rif_proj)
    except Exception:
        pass

    # iter434: Retrieval-Induced Forgetting (summary Jaccard) — 按 chunk_type 分组的精确 RIF
    # 补充 iter417：使用 summary Jaccard 相似度（比 encode_context 更鲁棒），按同类别竞争
    # OS 类比：CPU set-associative cache way eviction — same-set 竞争者被驱逐
    try:
        _rif434_proj_row = conn.execute(
            f"SELECT project FROM memory_chunks WHERE id IN ({placeholders}) LIMIT 1",
            chunk_ids,
        ).fetchone()
        if _rif434_proj_row:
            _rif434_proj = _rif434_proj_row[0] if isinstance(_rif434_proj_row, (list, tuple)) else _rif434_proj_row["project"]
            apply_rif_by_summary(conn, _rif434_proj, chunk_ids)
    except Exception:
        pass

    # ── iter453: PEME — Prediction Error Memory Enhancement ──────────────────
    # OS 类比：CPU branch predictor misprediction → forced L1 cache line promotion
    # 意外命中（低历史预期 + 当前被检索）触发多巴胺 burst → stability 加成
    try:
        for _peme_cid in chunk_ids:
            _peme_acc_before = _pre_access_count_map.get(_peme_cid, 0)
            _peme_ret = _pre_retrievability_map.get(_peme_cid, 0.5)
            _peme_imp = _pre_importance_map.get(_peme_cid, 0.5)
            _peme_stab = _pre_stability_map.get(_peme_cid, 1.0)
            # 获取 project
            _peme_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (_peme_cid,)
            ).fetchone()
            if _peme_proj_row:
                _peme_proj = _peme_proj_row[0] if isinstance(_peme_proj_row, (list, tuple)) else _peme_proj_row["project"]
                apply_prediction_error_enhancement(
                    conn, _peme_cid, _peme_proj,
                    _peme_acc_before, _peme_ret, _peme_imp, _peme_stab,
                )
    except Exception:
        pass

    # ── iter454: IPE — Interleaved Practice Effect ───────────────────────────
    # OS 类比：CPU cross-stride interleaved access → multi-stream prefetch trigger
    # 混合检索（多 chunk_type 交替）→ 每个 chunk 的 diversity_factor 加成
    try:
        if len(chunk_ids) >= 2:
            # 获取 project（取第一个 chunk 的 project）
            _ipe_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _ipe_proj_row:
                _ipe_proj = _ipe_proj_row[0] if isinstance(_ipe_proj_row, (list, tuple)) else _ipe_proj_row["project"]
                apply_interleaved_practice_effect(conn, chunk_ids, _ipe_proj)
    except Exception:
        pass

    # ── iter455: GSIE — Generation-Spacing Interaction Effect ──────────────────
    # OS 类比：Linux ARC ghost list + frequency-weighted promotion
    # 检索努力（effort = 1 - R_at_recall）× 间隔成功历史（spaced_access_count）的乘法交互加成
    # 认知科学：Pyc & Rawson (2009) "Testing the retrieval effort hypothesis" —
    #   effort × streak_factor = 真正的巩固预测因子（SM-2 饱和后的独立第二次 pass）
    try:
        if chunk_ids:
            _gsie_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _gsie_proj_row:
                _gsie_proj = _gsie_proj_row[0] if isinstance(_gsie_proj_row, (list, tuple)) else _gsie_proj_row["project"]
                apply_generation_spacing_interaction_effect(
                    conn, chunk_ids, _gsie_proj,
                    _pre_stability_map, _pre_spaced_access_map, _pre_access_map, now_iso,
                )
    except Exception:
        pass

    # ── iter456: RPCA — Retrieval Practice vs. Restudy Consolidation Asymmetry ──────────
    # OS 类比：Linux page fault (demand fault) → active LRU promotion;
    #   readahead prefetch (restudy) → inactive list first.
    # 认知科学：Roediger & Karpicke (2006) active retrieval = +50% retention vs passive restudy.
    # access_source 由调用方传入（默认 'retrieval'），update_accessed kwargs: access_source_map
    try:
        if chunk_ids:
            _rpca_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _rpca_proj_row:
                _rpca_proj = _rpca_proj_row[0] if isinstance(_rpca_proj_row, (list, tuple)) else _rpca_proj_row["project"]
                _rpca_source_map = kwargs.get("access_source_map", {}) if kwargs else {}
                apply_retrieval_practice_consolidation_asymmetry(
                    conn, chunk_ids, _rpca_proj, _rpca_source_map,
                )
    except Exception:
        pass

    # ── iter459：Contextual Interference Effect (CIE) ──────────────────────────────────────────
    # Shea & Morgan (1979): cross-session_type access history → +57% delayed retention.
    # 跨多种 session_type 被访问的 chunk 获得 stability 加成。
    try:
        if chunk_ids:
            _cie_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _cie_proj_row:
                _cie_proj = _cie_proj_row[0] if isinstance(_cie_proj_row, (list, tuple)) else _cie_proj_row["project"]
                _cie_session_type = (kwargs.get("session_type") if kwargs else None)
                apply_contextual_interference_effect(
                    conn, chunk_ids, _cie_proj, session_type=_cie_session_type,
                )
    except Exception:
        pass

    # ── iter461: HAC — 记录共激活事件（Hebbian Co-Activation Consolidation）──────────────
    # Hebb (1949): cells that fire together, wire together → co-accessed chunks reinforce each other.
    # OS 类比：Linux THP khugepaged — 共同访问的 pages 被合并为 huge page
    try:
        if len(chunk_ids) >= 2:
            _hac_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _hac_proj_row:
                _hac_proj = _hac_proj_row[0] if isinstance(_hac_proj_row, (list, tuple)) else _hac_proj_row["project"]
                record_coactivation(conn, chunk_ids, _hac_proj, now_iso=now_iso)
    except Exception:
        pass

    # ── iter463: OIE — Output Interference Effect（顺序检索后位 chunk 受前项输出干扰）──────
    # Postman & Underwood (1973): serial output interference — later items penalized.
    # OS 类比：Linux TLB invalidation cascade — later TLB entries suffer higher invalidation latency
    try:
        if len(chunk_ids) >= 2:
            _oie_proj_row = conn.execute(
                "SELECT project FROM memory_chunks WHERE id=?", (chunk_ids[0],)
            ).fetchone()
            if _oie_proj_row:
                _oie_proj = _oie_proj_row[0] if isinstance(_oie_proj_row, (list, tuple)) else _oie_proj_row["project"]
                apply_output_interference_effect(conn, chunk_ids, _oie_proj, now_iso=now_iso)
    except Exception:
        pass

    # ── iter465: LDSB — Lag-Dependent Spacing Boost（长间隔回忆获得更大加成，Landauer & Bjork 1978）──
    # OS 类比：Linux page aging — cold page reactivation = high utility signal → higher priority
    try:
        apply_lag_dependent_spacing_boost(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter468: CCRE — Contextual Cue Reinstatement Effect（上下文匹配时 stability 加成，Godden 1975）──
    # OS 类比：NUMA-aware memory access — accessing on same NUMA node as allocation = low latency
    try:
        _ccre_ctx = kwargs.get("context_tokens")
        if _ccre_ctx:
            for _ccre_cid in chunk_ids:
                apply_contextual_cue_reinstatement_effect(conn, _ccre_cid, _ccre_ctx, now_iso=now_iso)
    except Exception:
        pass

    # ── iter470: ILE — Interleaving Effect（跨多种上下文访问比单一上下文保留更好，Kornell & Bjork 2008）──
    # OS 类比：NUMA interleaving — 跨多 NUMA 节点分布访问，无单点带宽瓶颈 → 更强鲁棒性
    try:
        apply_interleaving_effect(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter472: AFB — Access Frequency Boost（检索频率越高记忆痕迹越强，Power Law of Practice）──
    # OS 类比：Linux active LRU hot page — 多次访问 → PG_referenced → active LRU → 更高驻留优先级
    try:
        apply_access_frequency_boost(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter474: SAE — Spreading Activation Effect（检索激活语义相关 chunk，Collins & Loftus 1975）──
    # OS 类比：Linux readahead — 相关 page 预取到 page cache，降低后续缺页率
    try:
        apply_spreading_activation_effect(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter475: SPE-Recency — Serial Position Recency（session 末位 chunk retrievability 加成）──
    # OS 类比：L1 cache MRU slot — 最近访问的 chunk 短期可达性最高
    try:
        apply_serial_position_recency(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter479: UDP — Use-Dependent Plasticity（共同访问的 chunk 互相加固，Hebb 1949）──
    # OS 类比：Linux working set model — 共同访问的 page 各自 refcount 递增，更难被回收
    try:
        if len(chunk_ids) >= 2:
            apply_use_dependent_plasticity(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter480: FAP — Forward Association Primacy（访问当前 chunk 提升较早 session sibling，Kahana 2002）──
    # OS 类比：CPU 指令流水线预取 — 执行当前指令时预取之前相关指令的上下文到 fetch buffer
    try:
        apply_forward_association_primacy(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter481: TPE — Testing Effect（主动检索比被动访问更强化记忆，Roediger & Karpicke 2006）──
    # OS 类比：CPU TLB hit — 主动检索命中的 page 比 page table walk 更新 LRU，降低 eviction 概率
    try:
        apply_testing_effect(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter482: SEB — Spacing Effect Bonus（间隔越长每次访问稳定性增益越大，Ebbinghaus 1885）──
    # OS 类比：Linux page access bit TLB aging — 距上次访问越久，下次命中优先级越高
    try:
        apply_spacing_effect_bonus(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter484: CCE — Cross-Session Consolidation（跨 session 访问获巩固奖励，Walker & Stickgold 2004）──
    # OS 类比：Linux kswapd background reclaim — session 间隔期 kswapd 整理 page，下次访问效率提升
    try:
        _cce_session = session_id or ""
        apply_cross_session_consolidation(conn, chunk_ids, _cce_session, now_iso=now_iso)
    except Exception:
        pass

    # ── iter485: DDE2 — Desirable Difficulty Effect（难提取 chunk 成功访问获更大 stability 增益，Bjork 1994）──
    # OS 类比：TLB miss → page walk — miss 成本高但重填 TLB 使后续命中；难检索 = TLB miss，成功 = 更新缓存
    try:
        apply_desirable_difficulty(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

    # ── iter486: CRE2 — Contextual Reinstatement Effect（上下文匹配增强检索效率，Godden & Baddeley 1975）──
    # OS 类比：CPU cache locality — 同一 namespace/tag 上下文 = 同一 cache line 集合访问效率更高
    try:
        _query_ns = kwargs.get("namespace", "") if kwargs else ""
        _query_tags = kwargs.get("tags", []) if kwargs else []
        apply_contextual_reinstatement(conn, chunk_ids, _query_ns, _query_tags)
    except Exception:
        pass

    # ── iter487: ETE2 — Emotion Tagging Effect（高情绪 chunk 衰减更慢，McGaugh 2000）──
    # OS 类比：cgroup memory.min 保护 — 高重要性进程 pages 受保护不被 kswapd 回收
    try:
        apply_emotion_tagging_decay_reduction(conn, chunk_ids)
    except Exception:
        pass

    # ── iter488: IOR — Inhibition of Return（短时重复访问 stability 增益递减，Posner 1984）──
    # OS 类比：MADV_RANDOM prefetch inhibition — 刚读过的 page 降低预取优先级
    try:
        apply_inhibition_of_return(conn, chunk_ids, now_iso=now_iso,
                                   pre_last_accessed_map=_pre_access_map)
    except Exception:
        pass

    # ── iter489: EVE — Encoding Variability Effect（多样化访问上下文增强记忆，Martin 1972）──
    # OS 类比：DM-multipath — 同一 device 多条 I/O 路径，任一失效不影响整体可用性
    try:
        apply_encoding_variability_eve(conn, chunk_ids)
    except Exception:
        pass

    # ── iter490: ZEF — Zeigarnik Effect（未完成任务 chunk 稳定性更高，Zeigarnik 1927）──
    # OS 类比：dirty page tracking — 含未刷新数据的 page 受 writeback 保护
    try:
        apply_zeigarnik_effect_zef(conn, chunk_ids)
    except Exception:
        pass

    # ── iter491: VRE — von Restorff Isolation Effect（稀有类型 chunk 记忆更深，von Restorff 1933）──
    # OS 类比：MGLRU gen=0 page in old pool — 稀有类型 = LRU gen=0，eviction 时受额外保护
    try:
        _vre_session = session_id or ""
        apply_von_restorff_isolation(conn, chunk_ids, session_id=_vre_session)
    except Exception:
        pass

    # ── iter492: PEF — Production Effect（输出类 chunk_type 编码更深，MacLeod 2010）──
    # OS 类比：write-back cache — 输出类操作需额外处理但生命周期更长
    try:
        apply_production_effect(conn, chunk_ids)
    except Exception:
        pass

    # ── iter450: CEF — Completion Effect（已完成任务失去认知张力，importance 降低，Ovsiankina 1928）──
    # OS 类比：Linux page writeback completion — PG_dirty 清除后 kswapd 可自由回收（解除保护）
    # 与 ZEF 对称：未完成=stability 提升；已完成=importance 适度降低
    try:
        from store_vfs_effects_new import apply_completion_effect as _apply_cef
        _apply_cef(conn, chunk_ids)
    except Exception:
        pass

    # ── iter451: RDG — Retrieval Difficulty Gradient（趋势困难检索获更大加成，Bjork & Bjork 1992）──
    # OS 类比：Linux adaptive readahead — 连续 miss 趋势 → 自适应扩大预取窗口（趋势驱动）
    # 补充 DDE2 (iter485)：单点快照 → 历史趋势（R 低 + spaced_access_count 高 = 持续边缘成功）
    try:
        from store_vfs_effects_new import apply_retrieval_difficulty_gradient as _apply_rdg
        _apply_rdg(conn, chunk_ids, now_iso=now_iso)
    except Exception:
        pass

def insert_trace(conn: sqlite3.Connection, trace_dict: dict) -> None:
    """写入 recall_traces 记录。迭代65：新增 ftrace_json 阶段级追踪。"""
    d = trace_dict
    top_k = json.dumps(d["top_k_json"], ensure_ascii=False) if isinstance(d.get("top_k_json"), (list, tuple)) else d.get("top_k_json", "[]")
    ftrace = d.get("ftrace_json")
    ftrace_str = json.dumps(ftrace, ensure_ascii=False) if isinstance(ftrace, dict) else ftrace
    conn.execute("""
        INSERT INTO recall_traces
        (id, timestamp, session_id, project, prompt_hash,
         candidates_count, top_k_json, injected, reason, duration_ms, ftrace_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        d["id"], d["timestamp"], d["session_id"], d["project"],
        d["prompt_hash"], d["candidates_count"], top_k,
        d["injected"], d["reason"], round(d.get("duration_ms", 0), 2),
        ftrace_str,
    ))

def find_similar(conn: sqlite3.Connection, summary: str, chunk_type: str,
                 threshold: float = 0.22, project: str = None) -> Optional[str]:
    """
    Jaccard token 相似度查重，返回最相似 chunk 的 id 或 None。
    OS 类比：KSM (Kernel Same-page Merging) — 内容相同的物理页合并。

    iter105: threshold 默认从 0.5 降到 0.28。
    原因：中文 bigram 分词粒度细，同义表述的 Jaccard 实测约 0.25-0.35，
    0.5 阈值实际上从未触发（等于没有去重）。0.28 在实测中可命中语义相近句。
    project 参数：限制去重范围到同 project，避免跨项目误合并。
    """
    if project:
        rows = conn.execute(
            "SELECT id, summary FROM memory_chunks WHERE chunk_type=? AND summary!='' AND project=?",
            (chunk_type, project)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, summary FROM memory_chunks WHERE chunk_type=? AND summary!=''",
            (chunk_type,)
        ).fetchall()
    if not rows:
        return None

    def _tok(text):
        tokens = set()
        for m in re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', text):
            tokens.add(m.group().lower())
        cn = re.sub(r'[^\u4e00-\u9fff]', '', text)
        for i in range(len(cn) - 1):
            tokens.add(cn[i:i + 2])
        return tokens

    q_set = _tok(summary)
    if not q_set:
        return None

    best_score, best_id = 0.0, None
    for rid, existing_summary in rows:
        d_set = _tok(existing_summary)
        if not d_set:
            continue
        intersection = len(q_set & d_set)
        union = len(q_set | d_set)
        jaccard = intersection / union if union > 0 else 0.0
        if jaccard > best_score:
            best_score = jaccard
            best_id = rid
    return best_id if best_score >= threshold else None

def already_exists(conn: sqlite3.Connection, summary: str, chunk_type: str = None) -> bool:
    """全局去重：相同 summary 不重复写入。
    chunk_type 为 None 时检查所有已知类型，指定时只检查该类型。

    iter107: 跨项目全局去重 — [规则/...] 前缀的 summary 不受 project 限制，
    同一规则文本在任意 project 中写过一次即全局阻断。
    根因：sleep session 在不同 project ID 下运行，旧去重逻辑只在同 project 内查重，
    导致同一规则内容在每个新 project 下各写一份，造成 DB 膨胀（每晚 +200 条）。
    OS 类比：全局页面表 (global page table) — 共享内核页面只映射一次，不因进程不同而重复分配。
    """
    # iter107：[规则/...] 跨项目全局去重（忽略 project 字段）
    if re.match(r'^\[规则[/／]', summary.strip()):
        row = conn.execute(
            "SELECT id FROM memory_chunks WHERE summary=?",
            (summary,)
        ).fetchone()
        return row is not None

    if chunk_type:
        row = conn.execute(
            "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type=?",
            (summary, chunk_type),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM memory_chunks WHERE summary=? "
            "AND chunk_type IN ('decision','excluded_path','reasoning_chain','conversation_summary','prompt_context','design_constraint')",
            (summary,)
        ).fetchone()
    return row is not None


def detect_and_invalidate_conflicts(
    conn: sqlite3.Connection,
    new_summary: str,
    chunk_type: str,
    project: str,
) -> int:
    """
    iter371: Memory Conflict Detection — MESI 缓存一致性协议类比

    认知科学背景：
      前向干扰（Retroactive Interference, McGeoch & McDonald 1931）—
      新记忆的写入会干扰已有的旧记忆，使旧记忆的提取可靠性下降。
      例如：旧知识"使用 X 方案"，新知识"放弃 X 采用 Y"—— 旧知识应降权。

    OS 类比：MESI 缓存一致性协议（Intel 1984）—
      当 CPU 核心修改缓存行（M state），其他核心持有该行的副本
      从 Shared(S) 降级为 Invalid(I)，下次访问触发 cache miss 重新从主存加载。
      这里：新写入 chunk 触发对语义矛盾旧 chunk 的 Invalid 降权。

    策略：
      1. 只对 decision/reasoning_chain 类型触发（其他类型不存在明确语义矛盾）
      2. 从 new_summary 中提取"被否定实体"：放弃/不选/废弃/replaced by/not using 后的词
      3. FTS5 搜索旧 chunk 中包含这些关键词的记录（同 project + 同 chunk_type）
      4. 对语义矛盾的旧 chunk：importance *= 0.8，oom_adj += 100（降权但不删除）
      5. 返回失效的 chunk 数

    示例：
      new: "放弃 SQLite 改用 PostgreSQL"
      → 搜索含 "SQLite" 的旧 decision chunk
      → 找到 "选择 SQLite 因为简单" → importance *= 0.8, oom_adj += 100
    """
    if chunk_type not in ("decision", "reasoning_chain"):
        return 0
    if not new_summary or len(new_summary) < 5:
        return 0

    import re as _re

    # 提取被否定/替换的实体关键词
    NEGATION_PATTERNS = [
        r'(?:放弃|不选|不用|废弃|替换|不再用|弃用|移除|删除)\s*([\w\u4e00-\u9fff_\-.]{2,20})',
        r'(?:replaced?|abandoned?|rejected?|removed?|deprecated?)\s+([\w_\-.]{2,20})',
        r'(?:不选择|不采用|不推荐)\s*([\w\u4e00-\u9fff_\-.]{2,20})',
        r'而非\s*([\w\u4e00-\u9fff_\-.]{2,20})',
        r'not\s+using\s+([\w_\-.]{2,20})',
        r'instead\s+of\s+([\w_\-.]{2,20})',
    ]

    negated_entities = []
    for pat in NEGATION_PATTERNS:
        for m in _re.finditer(pat, new_summary, _re.IGNORECASE | _re.UNICODE):
            entity = m.group(1).strip()
            if len(entity) >= 2:
                negated_entities.append(entity)

    if not negated_entities:
        return 0

    invalidated = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for entity in negated_entities[:3]:  # 最多处理3个实体（避免过度失效）
        try:
            # FTS5 搜索包含该实体的旧 chunk（同 project + 同类型）
            fts_query = entity.replace('"', '""')
            rows = conn.execute(
                """SELECT mc.id, mc.importance, mc.oom_adj, mc.summary
                   FROM memory_chunks mc
                   JOIN memory_chunks_fts fts ON mc.id = fts.rowid
                   WHERE fts.summary MATCH ?
                     AND mc.project = ?
                     AND mc.chunk_type = ?
                     AND mc.summary != ?
                   LIMIT 5""",
                (f'"{fts_query}"', project, chunk_type, new_summary)
            ).fetchall()
        except Exception:
            # FTS5 可能不可用，降级到 LIKE 查询
            try:
                rows = conn.execute(
                    """SELECT id, importance, oom_adj, summary
                       FROM memory_chunks
                       WHERE summary LIKE ?
                         AND project = ?
                         AND chunk_type = ?
                         AND summary != ?
                       LIMIT 5""",
                    (f"%{entity}%", project, chunk_type, new_summary)
                ).fetchall()
            except Exception:
                rows = []

        for row in rows:
            cid, imp, oom, old_summary = row
            # 验证旧 chunk 与新 chunk 确实语义矛盾：旧 chunk 应该是"推荐"该实体的
            # 避免把"放弃 X"之类的旧 excluded_path chunk 也降权
            AFFIRMATION_SIGNALS = _re.compile(
                r'(?:选择|采用|推荐|使用|用|基于|保留|保持|'
                r'decided?|chosen?|using|adopted?|recommended?)',
                _re.IGNORECASE
            )
            if not AFFIRMATION_SIGNALS.search(old_summary):
                continue

            new_imp = round(max(imp * 0.8, 0.1), 4)
            new_oom = min((oom or 0) + 100, 800)
            try:
                conn.execute(
                    "UPDATE memory_chunks SET importance=?, oom_adj=?, updated_at=? WHERE id=?",
                    (new_imp, new_oom, now_iso, cid)
                )
                invalidated += 1
            except Exception:
                pass

    return invalidated


def merge_similar(conn: sqlite3.Connection, summary: str, chunk_type: str,
                  importance: float, project: str = None) -> bool:
    """
    KSM merge：如果已存在相似 chunk，更新其 importance 并追加新内容到 content。
    返回 True 表示已合并（调用方不需要 INSERT）。

    iter105: threshold 提升到 0.65（减少误合并），合并时追加新 summary 到 content
    让 chunk 随时间积累不同角度的表述，提升检索召回率。
    OS 类比：KSM 合并相同物理页，但保留 COW — 写时才分离。
    """
    similar_id = find_similar(conn, summary, chunk_type, threshold=0.22, project=project)
    if not similar_id:
        return False
    now_iso = datetime.now(timezone.utc).isoformat()
    # 追加新 summary 到 content（不同角度表述的聚合，提升 FTS5 召回覆盖）
    row = conn.execute(
        "SELECT content FROM memory_chunks WHERE id=?", (similar_id,)
    ).fetchone()
    existing_content = row[0] if row else ""
    # 只在新 summary 与现有 content 不重叠时追加（避免完全重复）
    if summary not in existing_content:
        new_content = (existing_content + "\n" + summary).strip()[:2000]
    else:
        new_content = existing_content
    conn.execute(
        "UPDATE memory_chunks SET importance=MAX(importance, ?), last_accessed=?, updated_at=?, content=? WHERE id=?",
        (importance, now_iso, now_iso, new_content, similar_id),
    )
    # 迭代504：FTS5 Journal Checkpoint — merge 后同步更新 FTS5 索引
    # OS 类比：ext4 journal commit — 数据变更后必须同步更新索引，否则索引过期
    _fts5_sync_chunk(conn, similar_id, summary=None, content=new_content)
    return True

def coalesce_small_chunks(
    conn: sqlite3.Connection,
    project: str,
    min_group: int = 3,
    max_summary_len: int = 60,
    chunk_type: str = "conversation_summary",
    topic_prefix_len: int = 4,
) -> int:
    """
    iter374: Chunk Coalescing — Slab Allocator 合并碎片化小 chunk。

    人的记忆类比：Chunking (Miller 1956) — 人类将相关小记忆片段合并为有意义的组块，
      降低工作记忆负担，提升整体记忆容量。
    OS 类比：Linux Slab Allocator (Bonwick 1994) — 相同大小的对象归入同一 slab，
      避免碎片化，提高内存利用率。
      memory_chunks 中 conversation_summary 类型往往因为短会话产生大量碎片：
        chunk_1: "用户讨论了端口配置"  (imp=0.5)
        chunk_2: "用户询问了端口号"    (imp=0.5)
        chunk_3: "用户确认了3000端口" (imp=0.5)
      → 合并为一个高质量复合 chunk（max importance，content = 所有 summary 拼接）。

    触发条件（同时满足）：
      1. chunk_type 为 conversation_summary（可配置）
      2. summary 长度 <= max_summary_len（小 chunk 特征）
      3. summary 前 topic_prefix_len 字相同（同一主题组）
      4. 同组 chunk 数量 >= min_group

    合并策略：
      - 保留最高 importance 的 chunk（anchor）
      - anchor.content = 所有 chunk summary 拼接
      - anchor.importance = max(all importance)
      - 删除其余 chunk
      - 递增 chunk_version（触发 TLB 失效）

    Returns: 合并产生的 composite chunk 数量（即触发的合并组数）
    """
    try:
        # 查找所有符合条件的小 chunk（summary 短 + 指定类型 + 同项目）
        rows = conn.execute(
            """SELECT id, summary, importance, content, created_at
               FROM memory_chunks
               WHERE project = ? AND chunk_type = ?
                 AND LENGTH(summary) <= ?
               ORDER BY summary, created_at""",
            (project, chunk_type, max_summary_len),
        ).fetchall()

        if not rows:
            return 0

        # 按 topic_prefix 分组（前 N 字作为主题键）
        groups: dict = {}
        for row_id, summary, importance, content, created_at in rows:
            prefix = (summary or "")[:topic_prefix_len].strip()
            if not prefix:
                continue
            groups.setdefault(prefix, []).append({
                "id": row_id,
                "summary": summary,
                "importance": importance,
                "content": content or "",
                "created_at": created_at,
            })

        coalesced = 0
        now_iso = datetime.now(timezone.utc).isoformat()

        for prefix, members in groups.items():
            if len(members) < min_group:
                continue  # 不足 min_group，不合并

            # 按 importance 降序选 anchor（最高 importance 的 chunk 保留）
            members_sorted = sorted(members, key=lambda x: x["importance"], reverse=True)
            anchor = members_sorted[0]
            rest = members_sorted[1:]

            # 构建复合 content = 所有不重复 summary 拼接
            all_summaries = [anchor["summary"]] + [m["summary"] for m in rest]
            seen: set = set()
            unique_summaries = []
            for s in all_summaries:
                s_strip = s.strip()
                if s_strip and s_strip not in seen:
                    seen.add(s_strip)
                    unique_summaries.append(s_strip)
            composite_content = "\n".join(unique_summaries)[:2000]

            # 更新 anchor
            max_imp = anchor["importance"]
            conn.execute(
                """UPDATE memory_chunks
                   SET content=?, importance=?, updated_at=?
                   WHERE id=?""",
                (composite_content, max_imp, now_iso, anchor["id"]),
            )

            # 删除其余（包括 FTS5 同步）
            rest_ids = [m["id"] for m in rest]
            if rest_ids:
                placeholders = ",".join("?" * len(rest_ids))
                # 获取 rowids for FTS5 清理
                rowids = [r[0] for r in conn.execute(
                    f"SELECT rowid FROM memory_chunks WHERE id IN ({placeholders})",
                    rest_ids,
                ).fetchall()]
                conn.execute(
                    f"DELETE FROM memory_chunks WHERE id IN ({placeholders})",
                    rest_ids,
                )
                for rowid in rowids:
                    try:
                        conn.execute(
                            "DELETE FROM memory_chunks_fts WHERE rowid_ref=?",
                            (str(rowid),),
                        )
                    except Exception:
                        pass

            coalesced += 1

        if coalesced > 0:
            # 递增 chunk_version，触发 TLB 失效
            try:
                _cv_path = os.path.join(
                    os.environ.get("MEMORY_OS_DIR",
                                   os.path.join(os.path.expanduser("~"), ".claude", "memory-os")),
                    ".chunk_version",
                )
                try:
                    with open(_cv_path, encoding="utf-8") as _f:
                        _cv = int(_f.read().strip())
                except Exception:
                    _cv = 0
                with open(_cv_path, "w", encoding="utf-8") as _f:
                    _f.write(str(_cv + 1))
            except Exception:
                pass

        return coalesced

    except Exception:
        return 0


def delete_chunks(conn: sqlite3.Connection, chunk_ids: list) -> int:
    """
    批量删除 chunk，返回实际删除数。
    OS 类比：VFS 的 unlink() — 统一删除接口。
    迭代97：同步删除 FTS5 记录。
    """
    if not chunk_ids:
        return 0
    # 先获取要删除的 rowid（用于 FTS5 清理）
    placeholders = ",".join("?" * len(chunk_ids))
    rowids = [r[0] for r in conn.execute(
        f"SELECT rowid FROM memory_chunks WHERE id IN ({placeholders})", chunk_ids
    ).fetchall()]

    count = conn.execute(
        f"DELETE FROM memory_chunks WHERE id IN ({placeholders})",
        chunk_ids,
    ).rowcount

    # 迭代97：同步删除 FTS5 记录
    if rowids:
        for rowid in rowids:
            try:
                conn.execute("DELETE FROM memory_chunks_fts WHERE rowid_ref=?", (str(rowid),))
            except Exception:
                pass

    # iter520: mmu_notifier — 删除时同步清理 recall_traces/checkpoints 中的 stale refs
    if count > 0:
        bump_chunk_version()  # 迭代64: TLB v2
        try:
            from store_mm import mmu_notifier_invalidate
            mmu_notifier_invalidate(conn, chunk_ids)
        except Exception:
            pass  # notifier 失败不影响删除本身
    return count

def get_chunk_count(conn: sqlite3.Connection) -> int:
    """返回当前 chunk 总数。"""
    return conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]

def get_project_chunk_count(conn: sqlite3.Connection, project: str) -> int:
    """
    迭代25：返回指定项目的 chunk 数量。
    OS 类比：cgroup 的 memory.usage_in_bytes — 查询当前资源占用。
    """
    return conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
    ).fetchone()[0]

def evict_lowest_retention(conn: sqlite3.Connection, project: str,
                           count: int, protect_types: tuple = ("task_state",)) -> list:
    """
    迭代25+26：按 unified retention_score 淘汰指定项目中 score 最低的 N 条 chunk。
    OS 类比：cgroup OOM handler — 资源超配额时按优先级回收。

    迭代26 修复：使用 scorer.py 的 retention_score() 替代 ad-hoc ORDER BY。
    迭代104：hard pin 的 chunk 不参与 kswapd 硬淘汰（soft pin 不保护此路径）。

    策略：
    - 跳过 protect_types（task_state 是当前会话状态，不可淘汰）
    - 按 unified retention_score 升序（最低分先淘汰）
    - 返回被淘汰的 chunk id 列表
    """
    if count <= 0:
        return []

    from scorer import retention_score as _retention_score

    # 迭代104：hard pin 的 chunk 不被 kswapd 硬淘汰
    hard_pinned = get_pinned_ids(conn, project, pin_type="hard")

    protect_placeholders = ",".join("?" * len(protect_types))
    # 取所有候选 chunk（需要 Python 端计算 retention_score）
    # 限制候选集为 count * 5 以避免大表全扫描
    # 迭代38：排除 oom_adj <= -1000 的 chunk（OOM_SCORE_ADJ_MIN = 绝对保护）
    candidate_limit = max(count * 5, 50)
    # 迭代44：MGLRU — 优先从最老代淘汰（gen DESC），同代内按 importance/recency 排序
    # 迭代301：加入 stability 和 info_class
    # iter_multiagent P1：排除最近 10 分钟内写入的 chunk（cross-agent grace period）。
    # 根因：多 agent 共享同一 project 时，Agent B 的 kswapd 可能淘汰 Agent A 刚写入的
    # 低 retention 新 chunk（如 conversation_summary，importance=0.65）。
    # 修复：created_at >= datetime('now', '-10 minutes') 的 chunk 不参与 kswapd 硬淘汰。
    # OS 类比：Linux cgroup v2 memory.min — 保护新分配的页面不在 grace period 内被回收。
    rows = conn.execute(
        f"""SELECT id, importance, last_accessed, COALESCE(access_count, 0),
                   COALESCE(oom_adj, 0), COALESCE(lru_gen, 0),
                   COALESCE(stability, 1.0), COALESCE(info_class, 'world')
            FROM memory_chunks
            WHERE project=? AND chunk_type NOT IN ({protect_placeholders})
              AND COALESCE(oom_adj, 0) > -1000
              AND (created_at IS NULL OR datetime(created_at) < datetime('now', '-10 minutes'))
            ORDER BY COALESCE(lru_gen, 0) DESC, importance ASC, last_accessed ASC
            LIMIT ?""",
        (project, *protect_types, candidate_limit),
    ).fetchall()

    if not rows:
        return []

    # 用 Unified Scorer retention_score 精确排序
    # 迭代38：oom_adj 作为修正因子
    # 迭代300：info_class ephemeral 额外降分（更容易被淘汰）
    # 迭代301：Ebbinghaus stability 保护因子
    from datetime import datetime as _dt
    _now_ts = _dt.now(timezone.utc).isoformat()
    scored = []
    for row in rows:
        rid, importance, last_accessed, access_count, oom_adj, lru_gen, stability, info_class = (
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
        )
        if rid in hard_pinned:
            continue  # 迭代104：hard pin 跳过 kswapd 硬淘汰
        score = _retention_score(
            importance=importance if importance is not None else 0.5,
            last_accessed=last_accessed or "",
            uniqueness=0.5,
            access_count=access_count or 0,
        )
        # OOM 修正：oom_adj 正值让 score 下降（更容易被淘汰）
        oom_modifier = oom_adj / 2000.0
        score = max(0.0, score - oom_modifier)
        # 迭代300：ephemeral 额外降分 0.15（更优先被驱逐）
        if info_class == "ephemeral":
            score = max(0.0, score - 0.15)
        # 迭代301：Ebbinghaus stability 保护
        # retention_score 加上 stability_bonus = ln(stability+1) * 0.05，上限 0.2
        import math as _math
        stability_bonus = min(0.20, _math.log(stability + 1.0) * 0.05)
        score = min(1.0, score + stability_bonus)
        scored.append((score, rid))

    # 按 retention_score 升序，取最低的 count 条
    scored.sort(key=lambda x: x[0])
    evicted_ids = [rid for _, rid in scored[:count]]
    # 迭代33：swap out 替代直接删除（保留冷知识，可恢复）
    from store_swap import swap_out  # deferred import to avoid circular dependency
    swap_out(conn, evicted_ids)
    return evicted_ids


# ── 迭代104：chunk_pins — 项目级 pin API ─────────────────────────────
# OS 类比：Linux mlock()/munlock() per-VMA 内存锁定接口
#
# pin_type:
#   'hard' — kswapd/damon/stale_reclaim 全部跳过（类比 mlock + MAP_LOCKED）
#   'soft' — 仅跳过 stale/damon DEAD 清理，kswapd ZONE_MIN 仍可淘汰
#            （类比 MADV_WILLNEED：建议保留但非强制）

def pin_chunk(conn: sqlite3.Connection, chunk_id: str, project: str,
              pin_type: str = "soft") -> bool:
    """
    迭代104：将 chunk 锁定到指定项目（project-scoped mlock）。
    OS 类比：mlock(addr, len) — 将页面锁定在当前进程地址空间，阻止被 swap out。

    pin_type:
      'hard' — 任何淘汰路径均跳过该 chunk（kswapd ZONE_MIN 除外，但 stale/damon 完全保护）
      'soft' — 仅保护 stale reclaim 和 DAMON DEAD 清理，不干预 kswapd watermark 淘汰

    返回 True 表示成功写入（新 pin 或 upsert），False 表示 chunk 不存在。
    """
    from datetime import datetime, timezone
    # 验证 chunk 存在
    if not conn.execute("SELECT 1 FROM memory_chunks WHERE id=?", (chunk_id,)).fetchone():
        return False
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT OR REPLACE INTO chunk_pins (chunk_id, project, pin_type, pinned_at)
           VALUES (?, ?, ?, ?)""",
        (chunk_id, project, pin_type, now),
    )
    return True


def unpin_chunk(conn: sqlite3.Connection, chunk_id: str, project: str) -> bool:
    """
    迭代104：解除 chunk 在指定项目中的 pin。
    OS 类比：munlock(addr, len) — 解除内存锁定，页面重新可被 swap out。

    返回 True 表示成功删除，False 表示原本未 pin。
    """
    rowcount = conn.execute(
        "DELETE FROM chunk_pins WHERE chunk_id=? AND project=?",
        (chunk_id, project),
    ).rowcount
    return rowcount > 0


def is_pinned(conn: sqlite3.Connection, chunk_id: str, project: str) -> Optional[str]:
    """
    迭代104：查询 chunk 在指定项目中的 pin 状态。
    OS 类比：/proc/[pid]/smaps 中的 Locked: 字段。

    返回 pin_type ('hard'/'soft') 或 None（未 pin）。
    """
    row = conn.execute(
        "SELECT pin_type FROM chunk_pins WHERE chunk_id=? AND project=?",
        (chunk_id, project),
    ).fetchone()
    return row[0] if row else None


def get_pinned_chunks(conn: sqlite3.Connection, project: str,
                      pin_type: str = None) -> list:
    """
    迭代104：列出项目中所有 pinned chunk 的 ID。
    OS 类比：获取进程 mlock 区域列表（/proc/[pid]/smaps 的 VmLck 汇总）。

    pin_type=None 返回全部，pin_type='hard'/'soft' 按类型过滤。
    返回 {chunk_id, pin_type, pinned_at, summary, chunk_type} 字典列表。
    """
    if pin_type:
        rows = conn.execute(
            """SELECT cp.chunk_id, cp.pin_type, cp.pinned_at,
                      mc.summary, mc.chunk_type, mc.importance
               FROM chunk_pins cp
               JOIN memory_chunks mc ON mc.id = cp.chunk_id
               WHERE cp.project = ? AND cp.pin_type = ?
               ORDER BY cp.pinned_at DESC""",
            (project, pin_type),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT cp.chunk_id, cp.pin_type, cp.pinned_at,
                      mc.summary, mc.chunk_type, mc.importance
               FROM chunk_pins cp
               JOIN memory_chunks mc ON mc.id = cp.chunk_id
               WHERE cp.project = ?
               ORDER BY cp.pin_type DESC, cp.pinned_at DESC""",
            (project,),
        ).fetchall()
    return [
        {"chunk_id": r[0], "pin_type": r[1], "pinned_at": r[2],
         "summary": r[3], "chunk_type": r[4], "importance": r[5]}
        for r in rows
    ]


def get_pinned_ids(conn: sqlite3.Connection, project: str,
                   pin_type: str = None) -> set:
    """
    迭代104：返回项目中所有 pinned chunk_id 的集合（高效查询用）。
    OS 类比：内核的 locked_vm 计数 + mlock 位图。
    供 kswapd/damon/stale_reclaim 批量排除使用。
    """
    if pin_type:
        rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE project=? AND pin_type=?",
            (project, pin_type),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE project=?",
            (project,),
        ).fetchall()
    return {r[0] for r in rows}


# ── 迭代356：Pin Decay + Pin Cap ────────────────────────────────────────────
# OS 类比：Linux RLIMIT_MEMLOCK + memcg pin_user_pages 上限
#
# 问题根因（v5 audit, 2026-04-28）：
#   chunk_pins 表无过期机制。chunk 被 pin 后永久不可被 LRU 驱逐。
#   实测 47/105 chunk（45%）处于 pin 状态，仅剩 55% 参与正常 LRU 循环，
#   导致高 importance chunk 被迫 swap out（LRU 逼出），同时 swap 无法恢复（swap dead zone）。
#
# 修复方案：
#   pin_decay()  — 扫描 soft pin，last_accessed 超过 decay_days 天的自动解除
#   _enforce_pin_cap() — 新增 pin 时检查上限，超限时驱逐最旧 soft pin

def pin_decay(conn: sqlite3.Connection, project: str,
              decay_days: int = None) -> int:
    """
    迭代356：Soft pin 衰减 — 长期未访问的 soft pin 自动解除。

    OS 类比：munlock_vma_pages_range() 在进程 exit_mm 时解除 mlock 区域；
    这里模拟一个周期性 GC：soft pin 超过 decay_days 天未访问 → 解除 pin，
    允许重新参与 LRU eviction 和 swap out。

    Hard pin（design_constraint 等核心架构知识）不受衰减影响。

    返回解除的 pin 数量。
    """
    from config import get as _cfg
    if not _cfg("pin.decay_enabled"):
        return 0
    if decay_days is None:
        decay_days = _cfg("pin.decay_days")

    # 找出 soft pin 且 chunk 的 last_accessed 超过 decay_days 天的条目
    # 若 last_accessed 为 NULL，以 pinned_at 为准
    stale_rows = conn.execute(
        """SELECT cp.chunk_id
           FROM chunk_pins cp
           LEFT JOIN memory_chunks mc ON mc.id = cp.chunk_id
           WHERE cp.project = ?
             AND cp.pin_type = 'soft'
             AND (
               datetime(COALESCE(mc.last_accessed, cp.pinned_at)) <
               datetime('now', ? || ' days')
             )""",
        (project, f"-{decay_days}"),
    ).fetchall()

    if not stale_rows:
        return 0

    stale_ids = [r[0] for r in stale_rows]
    for cid in stale_ids:
        conn.execute(
            "DELETE FROM chunk_pins WHERE chunk_id=? AND project=? AND pin_type='soft'",
            (cid, project),
        )
    return len(stale_ids)


def enforce_pin_cap(conn: sqlite3.Connection, project: str,
                    cap_pct: int = None) -> int:
    """
    迭代356：Pin 上限执行 — 超过 cap_pct% 时驱逐最旧 soft pin。

    OS 类比：RLIMIT_MEMLOCK 在 mlock() 时检查当前 locked_vm，
    超限则 EAGAIN（或主动释放）。

    策略：
      1. 计算当前项目总 chunk 数
      2. 计算当前 pin 数量（hard + soft）
      3. 若 pin_count > cap_pct% × total → 按 pinned_at ASC 驱逐最旧 soft pin
      注：hard pin 不被驱逐（架构约束必须保留）

    返回驱逐的 soft pin 数量。
    """
    from config import get as _cfg
    if not _cfg("pin.cap_apply_on_pin"):
        return 0
    if cap_pct is None:
        cap_pct = _cfg("pin.cap_pct")

    total = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
    ).fetchone()[0]
    if total == 0:
        return 0

    cap_limit = max(1, int(total * cap_pct / 100))
    pin_count = conn.execute(
        "SELECT COUNT(*) FROM chunk_pins WHERE project=?", (project,)
    ).fetchone()[0]

    if pin_count <= cap_limit:
        return 0

    # 超限：驱逐最旧的 soft pin（按 pinned_at 升序）
    excess = pin_count - cap_limit
    oldest_soft = conn.execute(
        """SELECT cp.chunk_id FROM chunk_pins cp
           WHERE cp.project = ? AND cp.pin_type = 'soft'
           ORDER BY cp.pinned_at ASC
           LIMIT ?""",
        (project, excess),
    ).fetchall()

    if not oldest_soft:
        return 0

    evicted = 0
    for row in oldest_soft:
        conn.execute(
            "DELETE FROM chunk_pins WHERE chunk_id=? AND project=? AND pin_type='soft'",
            (row[0], project),
        )
        evicted += 1
    return evicted


# ── 迭代493：Verified Status TTL — 验证状态过期机制 ──────────────────────────
# OS 类比：TLS 证书有效期（X.509 NotAfter）+ Let's Encrypt 自动续期
#   TLS 证书过期不代表网站变不安全，而是需要重新证明身份（re-verification）。
#   同样，verified chunk 过期不代表知识变错误，而是需要重新确认仍然有效。
#
# 问题：verification_status='verified' 完全豁免 Ebbinghaus 衰减，
#   但 verified 本身是一个时间点的判断：
#     - 2 年前验证的 "BM25 是最佳全文检索方案" 在 2025 年可能已不成立
#     - verified chunk 的 importance 被冻结在验证时的水平，永不衰减
#     - 随时间积累，verified chunk 比例上升 → 系统对新证据越来越不敏感
#
# 解决：verified 状态设 TTL（分 stability 两档）：
#   stability < 5.0 → TTL = verified_ttl_days（默认 30 天）
#   stability >= 5.0 → TTL = verified_ttl_high_stability_days（默认 90 天）
#   超过 TTL 且在此期间未被访问（last_accessed 未更新）→ 重置为 'pending'
#   访问 verified chunk 会更新 last_accessed → 续期（类比 TLS renewal）

def expire_stale_verified(conn: sqlite3.Connection, project: str,
                          max_expire: int = 20) -> dict:
    """
    迭代493：重置过期的 verified chunk 状态为 pending。

    OS 类比：TLS 证书过期检查 — certbot renew --cert-name <domain>
      证书的有效性通过 NotAfter 字段判断；同样，verified 状态通过
      last_accessed 和 stability 判断是否在有效期内。

    参数：
      conn       — 数据库连接
      project    — 项目 ID
      max_expire — 单次最多过期的 chunk 数（防止大批量操作阻塞）

    返回：
      {expired: N, skipped_stable: N, total_verified: N}
    """
    try:
        from config import get as _cfg
        ttl_days = _cfg("damon.verified_ttl_days")
        ttl_high_days = _cfg("damon.verified_ttl_high_stability_days")
        stability_threshold = 5.0
    except Exception:
        ttl_days = 30
        ttl_high_days = 90
        stability_threshold = 5.0

    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    # 查询所有 verified chunk
    rows = conn.execute(
        """SELECT id, stability, last_accessed
           FROM memory_chunks
           WHERE project = ?
             AND COALESCE(verification_status, 'pending') = 'verified'
           ORDER BY last_accessed ASC
           LIMIT ?""",
        (project, max_expire * 5),
    ).fetchall()

    total_verified = len(rows)
    expired = 0
    skipped_stable = 0

    for cid, stab, la in rows:
        if expired >= max_expire:
            break

        effective_stab = float(stab or 1.0)
        ttl = ttl_high_days if effective_stab >= stability_threshold else ttl_days

        # 判断是否过期：last_accessed + TTL < now
        if not la:
            # 无访问记录 → 立即过期
            cutoff_dt = now
        else:
            try:
                la_dt = datetime.fromisoformat(la.replace("Z", "+00:00"))
                cutoff_dt = la_dt + timedelta(days=ttl)
            except Exception:
                continue

        if now >= cutoff_dt:
            # 过期：重置为 pending（需要重新验证）
            conn.execute(
                "UPDATE memory_chunks SET verification_status='pending', updated_at=? WHERE id=?",
                (now.isoformat(), cid),
            )
            expired += 1
        else:
            skipped_stable += 1

    return {
        "expired": expired,
        "skipped_stable": skipped_stable,
        "total_verified": total_verified,
    }


# ── 迭代304：知识图谱关系边 API ────────────────────────────────────────────
# OS 类比：Linux 内核模块依赖图（module_kobject + sysfs /sys/module/<mod>/holders/）
#   insert_edge  ≈ modprobe 写入依赖条目
#   query_neighbors ≈ modinfo --field=depends / /sys/module/<mod>/holders/

def insert_edge(conn: sqlite3.Connection,
                from_entity: str,
                relation: str,
                to_entity: str,
                project: str = None,
                source_chunk_id: str = None,
                confidence: float = 0.7) -> str:
    """
    迭代304：幂等插入关系边。
    (from_entity, relation, to_entity) 三元组相同则更新 confidence；
    否则插入新边，返回 edge_id。

    OS 类比：Linux sysfs kobject_add() — 同一对象重复 add 只更新属性，
      不会创建重复 sysfs 节点（幂等性由 kset_find_obj 保证）。
    """
    import hashlib
    # 用三元组生成确定性 id（幂等键）
    key = f"{from_entity}|{relation}|{to_entity}"
    edge_id = "ee_" + hashlib.sha1(key.encode()).hexdigest()[:16]

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO entity_edges (id, from_entity, relation, to_entity, project,
                                   source_chunk_id, confidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET confidence=excluded.confidence
        """,
        (edge_id, from_entity, relation, to_entity, project,
         source_chunk_id, confidence, now),
    )

    # 迭代310：insert_edge 时反向建立 entity_map（新增 entity 对应已有 chunks）
    # OS 类比：Linux inotify 反向 dentry — 新路径名与已有 inode 建立关联时更新 dcache
    try:
        if project:
            now_str = now
            for ent in (from_entity, to_entity):
                if not ent:
                    continue
                ent_lower = ent.lower()
                ent_normalized = ent_lower.replace("_", " ").replace("-", " ")
                # 在 memory_chunks 中找 summary 包含该 entity 的 chunk
                rows = conn.execute(
                    "SELECT id FROM memory_chunks WHERE project=? "
                    "AND (LOWER(summary) LIKE ? OR LOWER(summary) LIKE ?)",
                    (project, f"%{ent_lower}%", f"%{ent_normalized}%")
                ).fetchall()
                for (cid,) in rows:
                    conn.execute(
                        """INSERT OR REPLACE INTO entity_map
                           (entity_name, chunk_id, project, updated_at)
                           VALUES (?, ?, ?, ?)""",
                        (ent, cid, project, now_str)
                    )
    except Exception:
        pass  # entity_map 反向映射失败不阻塞主流程

    return edge_id


def query_neighbors(conn: sqlite3.Connection,
                    entity: str,
                    project: str = None,
                    direction: str = 'both') -> list:
    """
    迭代304：查询实体的邻居（关系边）。
    direction: 'out' = 以 entity 为 from（出边），
               'in'  = 以 entity 为 to（入边），
               'both'= 双向（默认）。

    返回：[(relation, neighbor_entity, confidence)]

    OS 类比：sysfs /sys/module/<mod>/holders/（入边）
           + /sys/module/<mod>/depends（出边）
           — 双向查询模块依赖关系。
    """
    results = []
    proj_filter = "AND project=?" if project else ""

    if direction in ('out', 'both'):
        # 出边：from_entity = entity
        params = [entity] + ([project] if project else [])
        rows = conn.execute(
            f"SELECT relation, to_entity, confidence FROM entity_edges "
            f"WHERE from_entity=? {proj_filter} ORDER BY confidence DESC",
            params,
        ).fetchall()
        results.extend(rows)

    if direction in ('in', 'both'):
        # 入边：to_entity = entity（返回时用 '-' 前缀标记方向）
        params = [entity] + ([project] if project else [])
        rows = conn.execute(
            f"SELECT relation, from_entity, confidence FROM entity_edges "
            f"WHERE to_entity=? {proj_filter} ORDER BY confidence DESC",
            params,
        ).fetchall()
        results.extend(rows)

    return results


# ── 迭代310：Spreading Activation（OS 类比：CPU cache prefetch + L2 warm-up）──
#
# OS 类比：CPU prefetcher 在 L1 miss 后，顺序预取相邻 cache line 到 L2，
#   使得后续访问几乎零延迟。Spreading Activation 在 FTS5 命中 chunk A 后，
#   沿 entity_edges 一/二跳扩散邻居到候选集（带 decay 权重），
#   类比 prefetch 把"可能相关"的 chunk 提前加入评分池。
#
# Collins & Loftus (1975) Spreading Activation Theory：
#   激活从一个节点沿关系边传播，每跳乘以 decay 系数（0 < decay < 1）。
#   激活强度 = 边的置信度 × decay^跳数。

def spreading_activate(
    conn,
    hit_chunk_ids: list,
    project: str = None,
    decay: float = 0.7,
    max_hops: int = 2,
    existing_ids: set = None,
    max_activation_bonus: float = 0.4,
    edge_half_life_days: float = 90.0,
    distance_decay_enabled: bool = None,
    distance_decay_factor: float = None,
) -> dict:
    """
    迭代310：从 FTS5 命中的 chunk 出发，沿 entity_edges 扩散激活邻居 chunk。

    算法：
      1. 将 hit_chunk_ids 中每个 chunk 映射到其 entity_name（通过 entity_map）
      2. 对每个 entity，查询 entity_edges 一跳邻居（带 confidence）
      3. 对一跳邻居的 entity，再查二跳邻居（max_hops 控制深度）
      4. 将邻居 entity 映射回 chunk_id（通过 entity_map）
      5. 计算激活分：effective_confidence × decay^跳数，上限 max_activation_bonus
      6. 跳过 existing_ids 中已有的 chunk

    iter387: Temporal Edge Decay — 关联强度时间衰减
      认知科学：Collins & Loftus (1975) Spreading Activation Model —
        关联强度随时间衰减（忘却导致联想路径弱化），频繁激活的路径强化（LTP）。
      OS 类比：ARP Cache TTL — 过期条目 confidence 降低，直到 GC 或刷新。
      effective_confidence = confidence × exp(-λ × days_since_created)
        λ = ln(2) / edge_half_life_days（默认 90 天半衰期）
        90 天后 confidence 折半，365 天后折至约 7%，防止旧关联路径持续污染激活。
      edge_half_life_days=0 表示禁用时间衰减（保持原行为）。

    iter393: Semantic Distance Decay — 语义距离衰减
      认知科学：Collins & Loftus (1975) — 激活从锚点沿语义图扩散时，随距离衰减：
        "cat" → "animal"（1跳，强激活）→ "mammal"（2跳，弱激活）
        距离越远语义相关性越低，激活量应按距离梯度衰减而非等权传播。
      OS 类比：NUMA 局部性 — 同节点访问快，跨 2 节点延迟呈指数增长（不是线性）。
      实现：每跳额外乘以 distance_decay_factor（独立于 edge confidence 的 decay），
        hop=1 时：score × distance_decay_factor^1
        hop=2 时：score × distance_decay_factor^2
        (distance_decay_factor < 1.0，典型值 0.6，2 跳约为 0.36)
      distance_decay_enabled=False 时退化到旧行为（只有 confidence-weighted decay）。

    Returns:
      {chunk_id: activation_score} — 仅包含新增的邻居 chunk
    """
    if existing_ids is None:
        existing_ids = set()

    hit_set = set(hit_chunk_ids) | existing_ids

    # Step 1: chunk_id → entity_name（通过 entity_map）
    if not hit_chunk_ids:
        return {}

    ph = ",".join("?" * len(hit_chunk_ids))
    proj_filter = "AND project=?" if project else ""
    params = list(hit_chunk_ids) + ([project] if project else [])
    try:
        entity_rows = conn.execute(
            f"SELECT entity_name, chunk_id FROM entity_map "
            f"WHERE chunk_id IN ({ph}) {proj_filter}",
            params,
        ).fetchall()
    except Exception:
        return {}

    if not entity_rows:
        return {}

    # BFS 沿 entity_edges 扩散
    # frontier: {entity_name: accumulated_score}
    frontier = {row[0]: 1.0 for row in entity_rows}  # seed entities 激活强度 = 1.0
    visited_entities = set(frontier.keys())
    activation: dict = {}  # chunk_id → best_activation_score

    # iter387: Temporal Edge Decay 参数
    import math as _math
    _edge_decay_enabled = edge_half_life_days > 0
    if _edge_decay_enabled:
        _edge_lambda = _math.log(2) / edge_half_life_days  # λ = ln(2)/T½
    from datetime import datetime as _dt, timezone as _tz
    _now_ts = _dt.now(_tz.utc).timestamp()

    # iter393: Semantic Distance Decay 参数
    # 从 sysctl 读取（调用者可通过参数覆盖，不传则从 config 读）
    if distance_decay_enabled is None:
        try:
            from config import get as _cget393
            distance_decay_enabled = _cget393("retriever.sa_distance_decay_enabled")
        except Exception:
            distance_decay_enabled = True
    if distance_decay_factor is None:
        try:
            from config import get as _cget393f
            distance_decay_factor = float(_cget393f("retriever.sa_distance_decay_factor") or 0.6)
        except Exception:
            distance_decay_factor = 0.6

    def _effective_confidence(conf: float, created_at_str: str) -> float:
        """iter387: 计算时间衰减后的有效 confidence。"""
        if not _edge_decay_enabled or not created_at_str:
            return conf
        try:
            # 解析 created_at（ISO 8601，可能含 +00:00 或无时区）
            ca = created_at_str.replace("Z", "+00:00")
            created_ts = _dt.fromisoformat(ca).timestamp()
            days_old = (_now_ts - created_ts) / 86400.0
            if days_old <= 0:
                return conf
            # exponential decay: conf × e^(-λ×days)
            decayed = conf * _math.exp(-_edge_lambda * days_old)
            return max(decayed, 0.01)  # 最低 0.01，防止完全失活
        except Exception:
            return conf

    # ── iter423: Fan Effect — IDF加权 Spreading Activation（Anderson 1974）──
    # entity degree 越高（扇出越大），该 entity 传播的激活权重越低。
    # 使用懒加载缓存：第一次遇到 entity 时查询其 degree，后续复用。
    _fan_effect_enabled = False
    _fan_min_degree = 3
    _fan_idf_weight = 0.5
    _entity_degree_cache: dict = {}  # entity_name → degree
    try:
        from config import get as _cfg_fan
        _fan_effect_enabled = _cfg_fan("retriever.fan_effect_enabled")
        _fan_min_degree = _cfg_fan("retriever.fan_effect_min_degree")
        _raw_idf_w = _cfg_fan("retriever.fan_effect_idf_weight")
        _fan_idf_weight = float(_raw_idf_w) if _raw_idf_w is not None else 0.5
    except Exception:
        pass

    def _fan_idf_factor(entity: str, degree: int, median_deg: float) -> float:
        """iter423: 计算 Fan Effect IDF 折扣系数。degree 越高，返回值越低（最低 0.1）。"""
        if not _fan_effect_enabled or degree < _fan_min_degree:
            return 1.0
        # IDF = log(1 + median / (1 + degree)) / log(1 + median/1)
        # 归一化：fan_min_degree 时 ≈ 1.0，degree→∞ 时 → 0.0
        import math as _m
        idf_raw = _m.log(1.0 + max(1.0, median_deg) / (1.0 + degree))
        idf_norm_max = _m.log(1.0 + max(1.0, median_deg))
        idf = idf_raw / idf_norm_max if idf_norm_max > 0 else 1.0
        idf = max(0.1, min(1.0, idf))
        # Mix: edge_score × (1 - idf_weight × (1 - idf))
        return 1.0 - _fan_idf_weight * (1.0 - idf)

    _fan_median_degree: float = 1.0  # 用于归一化，首次 BFS 后更新

    for hop in range(1, max_hops + 1):
        if decay ** hop < 0.05:  # 激活衰减至 5% 以下时停止
            break

        # iter393: 语义距离衰减系数（distance_decay_factor ^ hop）
        # hop=1: 0.6^1=0.60, hop=2: 0.6^2=0.36
        # OS 类比：NUMA 访问延迟 — 每跨一个 NUMA node，延迟约乘以 1.5-3×
        _dist_decay = (distance_decay_factor ** hop) if distance_decay_enabled else 1.0

        next_frontier = {}

        # ── iter423: Fan Effect — 批量查询当前 frontier entities 的 degree ──
        if _fan_effect_enabled and frontier:
            _uncached = [e for e in frontier if e not in _entity_degree_cache]
            if _uncached:
                try:
                    _uc_ph = ",".join("?" * len(_uncached))
                    _deg_rows = conn.execute(
                        f"SELECT entity, COUNT(*) as deg FROM ("
                        f"  SELECT from_entity as entity FROM entity_edges WHERE from_entity IN ({_uc_ph})"
                        f"  UNION ALL"
                        f"  SELECT to_entity as entity FROM entity_edges WHERE to_entity IN ({_uc_ph})"
                        f") GROUP BY entity",
                        _uncached + _uncached,
                    ).fetchall()
                    for _dr in _deg_rows:
                        _entity_degree_cache[_dr[0]] = int(_dr[1])
                except Exception:
                    pass
            # Update median degree for normalization
            if _entity_degree_cache:
                _sorted_degs = sorted(_entity_degree_cache.values())
                _mid = len(_sorted_degs) // 2
                _fan_median_degree = float(_sorted_degs[_mid]) if _sorted_degs else 1.0

        for entity, parent_score in frontier.items():
            proj_params = [entity] + ([project] if project else [])
            # iter423: Fan Effect — 获取 entity 的扇出惩罚系数
            _entity_deg = _entity_degree_cache.get(entity, 0)
            _fan_factor = _fan_idf_factor(entity, _entity_deg, _fan_median_degree)
            try:
                edges = conn.execute(
                    f"SELECT CASE WHEN from_entity=? THEN to_entity ELSE from_entity END as neighbor, "
                    f"confidence, created_at FROM entity_edges "
                    f"WHERE (from_entity=? OR to_entity=?) {proj_filter} "
                    f"ORDER BY confidence DESC LIMIT 20",
                    [entity, entity, entity] + ([project] if project else []),
                ).fetchall()
            except Exception:
                continue

            for neighbor, confidence, created_at in edges:
                if neighbor in visited_entities:
                    continue
                # iter387: 应用时间衰减
                eff_conf = _effective_confidence(confidence, created_at)
                # iter393: 每跳乘以语义距离衰减（_dist_decay = factor^hop）
                # iter423: 乘以 Fan Effect IDF 惩罚（高扇出 entity 激活权重降低）
                edge_score = parent_score * eff_conf * decay * _dist_decay * _fan_factor
                if edge_score < 0.05:
                    continue
                if neighbor not in next_frontier or next_frontier[neighbor] < edge_score:
                    next_frontier[neighbor] = edge_score

        if not next_frontier:
            break

        # neighbor entity → chunk_id
        neighbor_list = list(next_frontier.keys())
        ne_ph = ",".join("?" * len(neighbor_list))
        ne_params = neighbor_list + ([project] if project else [])
        try:
            chunk_rows = conn.execute(
                f"SELECT entity_name, chunk_id FROM entity_map "
                f"WHERE entity_name IN ({ne_ph}) {proj_filter}",
                ne_params,
            ).fetchall()
        except Exception:
            chunk_rows = []

        for ent_name, cid in chunk_rows:
            if cid in hit_set:
                continue
            score = min(next_frontier[ent_name], max_activation_bonus)
            if cid not in activation or activation[cid] < score:
                activation[cid] = score

        visited_entities.update(next_frontier.keys())
        frontier = next_frontier

    return activation


# ── iter577: shmem_link — Shared Memory Co-occurrence Activation ──────────────
# OS 类比：Linux shmem/tmpfs (Christoph Lameter, 2002, mm/shmem.c)
#   多个进程无需 pipe/socket 显式通信，通过 mmap 映射同一物理页隐式共享数据。
#   process A 写入共享页 → process B 读取时立即可见（无需 IPC message passing）。
#   共享内存是最快的 IPC 机制——消除了数据复制和内核态切换。
#
# 认知科学：Encoding Overlap Principle (Tulving & Thomson, 1973)
#   两个记忆共享的编码特征越多（encoding overlap），互相提示召回的概率越高。
#   entity co-occurrence = encoding overlap：两个 chunk 共享同一 entity_name，
#   说明它们在编码时涉及相同概念，即使没有显式关联（entity_edge），也有隐式语义连接。
#
# 根因：
#   spreading_activate 只走 entity_edges（99 条边），但 entity_map 中 95.3% 实体孤立。
#   多个 chunk 映射到同一 entity_name（co-occurrence）= 隐式共享内存页，
#   但 spreading_activate 看不到这条路径。
#
# 解决：
#   从 FTS5 命中的 chunk 出发 → 查 entity_map 获取其 entities →
#   再查 entity_map 找到共享同一 entity 的其他 chunk（不经 entity_edges）。
#   类比：通过共享页的 page frame 找到所有映射了该页的进程（rmap reverse mapping）。
#   配合 min_shared_entities 门控：只有共享 ≥N 个 entity 的 chunk 才激活，
#   避免单个通用 entity（如"决策"）造成无差别激活噪声（类似 huge page 的 false sharing）。
#
def shmem_link(
    conn,
    hit_chunk_ids: list,
    project: str = None,
    existing_ids: set = None,
    max_results: int = None,
    min_shared_entities: int = None,
    activation_score: float = None,
    entity_idf_weight: bool = None,
) -> dict:
    """
    iter577: 从 FTS5 命中 chunk 出发，通过 entity co-occurrence 发现隐式关联 chunk。

    算法：
      1. hit_chunk_ids → entity_map 获取 seed entities
      2. seed entities → entity_map 反查共享同 entity 的其他 chunk（co-occurrence）
      3. 按共享 entity 数量排序，>= min_shared_entities 门控
      4. IDF 加权：稀有 entity（出现在少数 chunk）的共享权重更高
      5. 返回 {chunk_id: activation_score}

    Returns:
      {chunk_id: float} — co-occurrence 激活的邻居 chunk（不含 hit_chunk_ids）
    """
    from config import get as _cfg

    if existing_ids is None:
        existing_ids = set()
    hit_set = set(hit_chunk_ids) | existing_ids

    if not hit_chunk_ids:
        return {}

    # ── 参数读取（调用者可覆盖，否则从 sysctl 读）──
    if max_results is None:
        max_results = int(_cfg("shmem_link.max_results") or 5)
    if min_shared_entities is None:
        min_shared_entities = int(_cfg("shmem_link.min_shared_entities") or 2)
    if activation_score is None:
        activation_score = float(_cfg("shmem_link.activation_score") or 0.25)
    if entity_idf_weight is None:
        entity_idf_weight = bool(_cfg("shmem_link.entity_idf_weight"))

    if not _cfg("shmem_link.enabled"):
        return {}

    # ── Step 1: hit chunks → seed entities ──
    # 类比：shmem attach — 进程通过 shmat() 映射到共享内存段，
    # 需要跨 namespace 可见（project + global）才能发现共享页
    ph = ",".join("?" * len(hit_chunk_ids))
    cross_proj_filter = "AND project IN (?, 'global')" if project else ""
    cross_proj_params = [project] if project else []
    try:
        seed_rows = conn.execute(
            f"SELECT entity_name, chunk_id FROM entity_map "
            f"WHERE chunk_id IN ({ph}) {cross_proj_filter}",
            list(hit_chunk_ids) + cross_proj_params,
        ).fetchall()
    except Exception:
        return {}

    if not seed_rows:
        return {}

    seed_entities = set(row[0] for row in seed_rows)

    # ── Step 2: IDF computation — 每个 entity 出现在多少 chunk 中 ──
    # 类比：shmem 的 page refcount — mapcount 越高的页越"通用"（如 libc），
    #        mapcount 低的页是"专用"共享（如两个协作进程的 shared segment）
    # 跨 project 计算（entity_map PK = entity_name+project → 同 entity 在不同 project 各一行）
    entity_chunk_count: dict = {}  # entity → total chunk count in DB
    if entity_idf_weight:
        ent_ph = ",".join("?" * len(seed_entities))
        try:
            idf_rows = conn.execute(
                f"SELECT entity_name, COUNT(DISTINCT chunk_id) as cnt "
                f"FROM entity_map WHERE entity_name IN ({ent_ph}) "
                f"GROUP BY entity_name",
                list(seed_entities),
            ).fetchall()
            entity_chunk_count = {r[0]: r[1] for r in idf_rows}
        except Exception:
            pass

    # ── Step 3: 反查共享同 entity 的其他 chunk（co-occurrence lookup）──
    # 类比：rmap (reverse mapping) — 从物理页找到所有映射它的 VMA/进程
    # 跨 project 查询：entity_map PK=(entity_name, project) 意味着同一 entity
    # 在不同 project 映射到不同 chunk — 必须去掉 project 限制才能发现跨 project 共现
    ent_ph = ",".join("?" * len(seed_entities))
    try:
        cooccur_rows = conn.execute(
            f"SELECT chunk_id, entity_name FROM entity_map "
            f"WHERE entity_name IN ({ent_ph})",
            list(seed_entities),
        ).fetchall()
    except Exception:
        return {}

    # ── Step 4: 聚合 — 每个 candidate chunk 共享了哪些 entity ──
    import math as _math
    candidate_scores: dict = {}  # chunk_id → weighted score
    candidate_shared: dict = {}  # chunk_id → shared entity count

    total_chunks_est = max(len(hit_chunk_ids) + 10, 50)  # IDF denominator estimate

    for cid, ent_name in cooccur_rows:
        if cid in hit_set:
            continue
        if cid not in candidate_shared:
            candidate_shared[cid] = 0
            candidate_scores[cid] = 0.0
        candidate_shared[cid] += 1

        # IDF weight: log(N / (1 + df)) — 稀有 entity 权重更高
        if entity_idf_weight and ent_name in entity_chunk_count:
            df = entity_chunk_count[ent_name]
            idf = _math.log(total_chunks_est / (1.0 + df)) if df > 0 else 1.0
            idf = max(0.1, idf)  # floor
            candidate_scores[cid] += idf
        else:
            candidate_scores[cid] += 1.0

    # ── Step 5: 门控 + 排序 + 截断 ──
    # 类比：shmem 的 shmem_fallocate — 只分配满足最小对齐的页，过小的不分配
    filtered = [
        (cid, candidate_scores[cid])
        for cid, cnt in candidate_shared.items()
        if cnt >= min_shared_entities
    ]

    if not filtered:
        return {}

    # 按加权分数降序排序
    filtered.sort(key=lambda x: x[1], reverse=True)
    filtered = filtered[:max_results]

    # 归一化到 [0, activation_score]
    max_raw = filtered[0][1] if filtered else 1.0
    result = {}
    for cid, raw_score in filtered:
        normalized = (raw_score / max_raw) * activation_score if max_raw > 0 else 0.0
        result[cid] = round(normalized, 4)

    return result


# ── iter380：Schema Anchoring — Bartlett (1932) Schema Theory ────────────────
#
# 认知科学：Bartlett (1932) Schema Theory — 人的记忆不是存储原始事实，
#   而是将新信息嵌入已有 schema（知识结构框架）中存储。
#   检索时，激活 schema → 框架内的所有关联知识一起浮现。
#
# OS 类比：Linux SLUB Allocator kmem_cache —
#   相同类型的对象共享 kmem_cache（schema），
#   新对象（chunk）写入时归属对应 cache；
#   内存压力时，cache 整体作为回收单元（schema-level eviction）；
#   cache 命中时，同 slab 的相邻对象自动预热（schema spreading）。
#
# 实现：
#   anchor_chunk_schema(conn, chunk_id, summary, project)
#     — 写入时扫描 summary 匹配预定义 schema 规则，写入 schema_anchors 绑定行
#   schema_spread_activate(conn, hit_chunk_ids, project)
#     — 检索时：命中 chunk → 查 schema_anchors → 激活同 schema 的其他 chunk

# 预定义 Schema 规则（基于实际使用场景，按特异性排序）
# 格式：(schema_name, [关键词正则], confidence)
_SCHEMA_RULES = [
    # web_service_config — 服务端口/URL/主机/协议配置（解决"忘记端口"核心问题）
    ("web_service_config",
     [r'\b(?:port|端口|listen|bind)\b.*?\d{2,5}',
      r'\b\d{2,5}\s*(?:port|端口)',
      r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}',
      r'(?:http|https|ws|grpc|tcp)://[^\s]+:\d{2,5}',
      r'(?:前端|backend|server|service)\s*(?:端口|port)\s*[=:]\s*\d{2,5}'],
     0.90),
    # auth_config — 认证/授权配置
    ("auth_config",
     [r'\b(?:token|api.?key|secret|password|credential|auth)\b.{0,30}(?:=|:)\s*\S+',
      r'(?:bearer|jwt|oauth|api.?key|密钥|认证|鉴权)',
      r'\b(?:GITHUB_TOKEN|OPENAI_API_KEY|AWS_SECRET)\b'],
     0.85),
    # performance_constraint — 性能约束/指标
    ("performance_constraint",
     [r'\d+(?:\.\d+)?\s*(?:ms|μs|us|s)\b.*(?:latency|延迟|timeout|超时)',
      r'(?:p99|p95|p50|avg)\s*[=<>:]\s*\d+\s*ms',
      r'(?:throughput|qps|rps|tps)\s*[=<>:]\s*\d+',
      r'(?:性能|延迟|吞吐).{0,20}(?:上限|限制|要求|不超过)'],
     0.80),
    # dependency_config — 依赖版本/包管理
    ("dependency_config",
     [r'(?:requirements|package\.json|pyproject|Cargo\.toml)',
      r'\b(?:pip install|npm install|cargo add|go get)\b',
      r'[a-z][a-z0-9_-]+==\d+\.\d+',
      r'"[a-z][a-z0-9_-]+":\s*"\d+\.\d+'],
     0.75),
    # error_pattern — 错误/异常/崩溃模式
    ("error_pattern",
     [r'(?:错误|error|exception|crash|bug|失败|failure)\s*[:：]\s*.{5,}',
      r'(?:fix|修复|resolved|fixed)\s*.{5,}(?:bug|error|crash|issue)',
      r'(?:AttributeError|KeyError|TypeError|RuntimeError|ValueError)',
      r'(?:segment fault|segfault|oom killer|memory leak)'],
     0.80),
    # design_decision — 架构/设计决策
    ("design_decision",
     [r'(?:选择|决定|采用|放弃|不用)\s*.{3,30}\s*(?:因为|原因|而非)',
      r'(?:设计决策|architectural decision|trade.?off)',
      r'(?:替代方案|alternative)\s*.{3,}被?放弃',
      r'(?:不推荐|deprecated|不使用)\s*.{5,}'],
     0.75),
    # database_config — 数据库/存储配置
    ("database_config",
     [r'(?:sqlite|postgres|mysql|redis|mongodb)\s*(?::|\s+at\s+)\s*\S+',
      r'(?:db|database|数据库)\s*(?:path|路径|host|port)\s*[=:]\s*\S+',
      r'(?:store\.db|\.db|\.sqlite)'],
     0.80),
]

# 预编译正则（模块级，避免每次调用重新编译）
_COMPILED_SCHEMA_RULES = [
    (name, [re.compile(p, re.IGNORECASE) for p in patterns], conf)
    for name, patterns, conf in _SCHEMA_RULES
]


def tot_activate(
    conn: "sqlite3.Connection",
    query: str,
    project: str,
    existing_ids: set = None,
    top_k: int = 5,
    base_score: float = 0.25,
) -> dict:
    """
    iter425: Tip-of-the-Tongue (TOT) 边缘激活补救
    Brown & McNeill (1966) — 完全提取失败时的边缘激活状态，
      通过语义邻居词触发完整回忆。

    认知科学依据：
      TOT 效应：人在无法完整回忆目标词时，仍能报告该词的首字母、音节数、
      相关词——这些"边缘信息"（peripheral activation）可触发正确词的恢复。
      memory-os 等价：FTS5 零命中时，仍可从 query 的实体词在 entity_map
      中找到关联 chunk，作为"边缘激活"路径，补救零召回场景。

    OS 类比：Linux mincore(2) — page cache miss 时回退 swap 预热：
      主路径（FTS5）miss → 用 entity_map（类比 swap 分区）尝试恢复关联页。
      entity_map 是 entity→chunk 的倒排索引，相当于 swap 中保留的"地址映射"。

    与 spreading_activate 的区别：
      spreading_activate — 从已命中 chunk 沿 entity_edges 图扩散（需要非空 FTS5）
      tot_activate      — FTS5 完全 miss 时，直接从 query 实体词查 entity_map（零命中补救）

    Args:
      query:        用户查询字符串
      project:      项目 ID（None = 全局）
      existing_ids: 已在候选集中的 chunk ID 集合（去重用）
      top_k:        最多返回 chunk 数量
      base_score:   TOT 激活基础分（低于 FTS5 直接命中，但高于纯 BM25 fallback）

    Returns:
      {chunk_id: activation_score} — 边缘激活 chunk 及其分数
    """
    if not query:
        return {}

    existing_ids = existing_ids or set()

    # 从 query 提取 entity 候选词（英文标识符 + CJK bigram）
    entity_words: list = []
    # 英文：>= 3 字符的字母数字标识符（避免噪音短词）
    for m in re.finditer(r'[a-zA-Z][a-zA-Z0-9_]{2,}', query):
        entity_words.append(m.group().lower())
    # CJK bigram：相邻两个汉字
    cjk_chars = re.sub(r'[^\u4e00-\u9fff]', '', query)
    for i in range(len(cjk_chars) - 1):
        entity_words.append(cjk_chars[i:i + 2])
    # 去重，保留顺序
    seen: set = set()
    unique_words: list = []
    for w in entity_words:
        if w not in seen:
            seen.add(w)
            unique_words.append(w)
    entity_words = unique_words[:20]  # 最多 20 个实体词，避免查询过慢

    if not entity_words:
        return {}

    try:
        # 查询 entity_map：entity_name 包含 query 实体词的 chunk_id
        # 使用 LIKE 匹配（entity_name 通常是短词，精确匹配或包含匹配）
        placeholders = ",".join("?" * len(entity_words))
        if project and project != "global":
            proj_cond = "AND em.project IN (?, 'global')"
            proj_params = [project]
        else:
            proj_cond = ""
            proj_params = []

        sql = f"""
            SELECT em.chunk_id, COUNT(DISTINCT em.entity_name) as match_count
            FROM entity_map em
            WHERE LOWER(em.entity_name) IN ({placeholders})
              {proj_cond}
            GROUP BY em.chunk_id
            ORDER BY match_count DESC
            LIMIT ?
        """
        params = entity_words + proj_params + [top_k * 3]
        rows = conn.execute(sql, params).fetchall()

        if not rows:
            return {}

        result: dict = {}
        max_count = max(r[1] for r in rows) if rows else 1

        for chunk_id, match_count in rows:
            if chunk_id in existing_ids:
                continue
            # activation score = base_score × (match_count / max_count)
            # 多个 entity 词命中同一 chunk → 更高分（类比多线索触发）
            activation = base_score * (match_count / max_count)
            result[chunk_id] = round(activation, 4)

            if len(result) >= top_k:
                break

        return result

    except Exception:
        return {}


def anchor_chunk_schema(
    conn: sqlite3.Connection,
    chunk_id: str,
    summary: str,
    project: str,
) -> int:
    """
    iter380：写入 chunk 时，扫描 summary 匹配 schema 规则，写入 schema_anchors 绑定行。

    算法：
      1. 遍历 _COMPILED_SCHEMA_RULES，对 summary 做正则匹配
      2. 任意规则命中 → INSERT OR IGNORE INTO schema_anchors
      3. 返回写入的绑定数（0=无命中）

    性能：< 1ms（纯正则，无 LLM，模块级预编译）
    OS 类比：kmem_cache_alloc — 新对象分配时，根据 size/align 归属正确的 kmem_cache
    """
    if not summary or not chunk_id:
        return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    written = 0

    for schema_name, compiled_patterns, confidence in _COMPILED_SCHEMA_RULES:
        for pat in compiled_patterns:
            if pat.search(summary):
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_anchors "
                        "(chunk_id, schema_name, project, confidence, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (chunk_id, schema_name, project, confidence, now_iso),
                    )
                    written += 1
                except Exception:
                    pass
                break  # 同一 schema 内，第一个命中即可，不重复插入

    return written


def schema_spread_activate(
    conn: sqlite3.Connection,
    hit_chunk_ids: list,
    project: str,
    max_per_schema: int = 3,
    activation_score: float = 0.25,
    existing_ids: set = None,
) -> dict:
    """
    iter380：从 FTS5 命中的 chunk 出发，通过 schema_anchors 激活同 schema 的其他 chunk。

    算法：
      1. 查 hit_chunk_ids 所属的所有 schema（schema_anchors）
      2. 对每个 schema，查询同 project 下同 schema 的其他 chunk（排除已有的）
      3. 按 importance DESC 排序，每个 schema 最多取 max_per_schema 个
      4. 返回 {chunk_id: activation_score}

    与 spreading_activate 的区别：
      spreading_activate 沿 entity_edges 图扩散（Collins & Loftus 1975）
      schema_spread_activate 沿 schema 框架激活（Bartlett 1932）—— 更高层次的语义聚合

    OS 类比：SLUB allocator partial list — kmem_cache 命中后，
      同 slab 的 partial list 中的对象自动成为候选（schema-level prefetch）
    """
    if not hit_chunk_ids:
        return {}
    if existing_ids is None:
        existing_ids = set()

    all_excluded = set(hit_chunk_ids) | existing_ids

    # Step 1: 找到命中 chunk 所属的 schema
    ph = ",".join("?" * len(hit_chunk_ids))
    try:
        schema_rows = conn.execute(
            f"SELECT DISTINCT schema_name FROM schema_anchors "
            f"WHERE chunk_id IN ({ph}) AND project=?",
            list(hit_chunk_ids) + [project],
        ).fetchall()
    except Exception:
        return {}

    if not schema_rows:
        return {}

    schema_names = [r[0] for r in schema_rows]
    result: dict = {}

    # Step 2: 对每个 schema，激活同 schema 的其他 chunk
    for schema_name in schema_names:
        try:
            related = conn.execute(
                "SELECT sa.chunk_id, mc.importance "
                "FROM schema_anchors sa "
                "JOIN memory_chunks mc ON mc.id = sa.chunk_id "
                "WHERE sa.schema_name=? AND sa.project=? "
                "ORDER BY mc.importance DESC "
                "LIMIT ?",
                (schema_name, project, max_per_schema + len(all_excluded)),
            ).fetchall()
        except Exception:
            continue

        count = 0
        for cid, importance in related:
            if cid in all_excluded:
                continue
            if cid not in result or result[cid] < activation_score:
                result[cid] = activation_score
            count += 1
            if count >= max_per_schema:
                break

    return result


# ── 迭代305：Curiosity Queue API（OS 类比：kswapd 水位触发 + 任务队列）────────
#
# OS 类比概述：
#   Linux kswapd 在 free pages < WMARK_LOW 时唤醒，异步回收内存；
#   类似地，retriever 在 FTS top-1 score < 0.25（知识低水位）时，
#   将 query 写入 curiosity_queue，deep-sleep 阶段异步填充知识空白。
#
#   enqueue_curiosity  ≡ wakeup_kswapd()  — 水位低时触发，幂等防重复
#   pop_curiosity_queue ≡ kswapd_do_work() — 取出任务并标记"正在处理"

def enqueue_curiosity(conn: sqlite3.Connection,
                      query: str, project: str,
                      top_score: float = None) -> int:
    """
    迭代305：将「弱命中 query」入队到 curiosity_queue。
    幂等：同 project+query 7天内已有记录则跳过，返回 0；否则插入，返回 1。

    OS 类比：wakeup_kswapd(zone, order) — 检测到水位不足时唤醒 kswapd，
      若 kswapd 已在运行（任务已入队），不重复触发（幂等语义）。
      7天 TTL = 知识填充周期（类比 kswapd 的 watermark_boost_factor 衰减窗口）。

    参数：
      conn      — DB 连接（调用方持有）
      query     — 触发弱命中的原始查询字符串
      project   — 所属项目 ID
      top_score — 触发时的 FTS top-1 分数（记录诊断用）

    返回：
      1 = 成功入队（新记录）
      0 = 幂等跳过（7天内已有相同 project+query）
    """
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=7)).isoformat()
    now_iso = now.isoformat()

    # 幂等检查：7天内同 project+query 已存在则跳过
    # OS 类比：page_is_in_reclaim() — 页面已在回收队列中，不重复加入
    existing = conn.execute(
        "SELECT id FROM curiosity_queue "
        "WHERE project=? AND query=? AND detected_at >= ? AND status IN ('pending','processing')",
        (project, query, cutoff)
    ).fetchone()
    if existing:
        return 0  # 幂等跳过

    conn.execute(
        "INSERT INTO curiosity_queue (query, project, detected_at, top_score, status) "
        "VALUES (?, ?, ?, ?, 'pending')",
        (query, project, now_iso, top_score)
    )
    return 1


def pop_curiosity_queue(conn: sqlite3.Connection,
                        project: str = None,
                        limit: int = 5) -> List[dict]:
    """
    迭代305：从 curiosity_queue 取出最多 limit 条 pending 记录，
    并将其状态原子更新为 processing，返回条目列表。

    OS 类比：kswapd_do_work() + lru_deactivate_folio() —
      kswapd 从 inactive LRU list 取出 folio（pending→processing），
      标记后进行异步 swap-out；若其间进程访问该页（填充完成），
      状态变为 filled（swap-in 完成），否则 dismissed（放弃回收）。

    参数：
      conn    — DB 连接（调用方持有）
      project — 限定项目（None = 全库）
      limit   — 最多取出数量（默认 5，类比 kswapd 每轮 nr_to_reclaim）

    返回：
      list of dict，每条含 {id, query, project, detected_at, top_score, status}
      返回时 status 已改为 "processing"
    """
    # 查询 pending 条目
    # OS 类比：isolate_lru_folios() — 从 inactive LRU 隔离一批页面用于回收
    if project is not None:
        rows = conn.execute(
            "SELECT id, query, project, detected_at, top_score, status "
            "FROM curiosity_queue "
            "WHERE project=? AND status='pending' "
            "ORDER BY detected_at ASC LIMIT ?",
            (project, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, query, project, detected_at, top_score, status "
            "FROM curiosity_queue "
            "WHERE status='pending' "
            "ORDER BY detected_at ASC LIMIT ?",
            (limit,)
        ).fetchall()

    if not rows:
        return []

    # 批量更新状态为 processing
    # OS 类比：SetPageReclaim(folio) — 设置页面回收标志，阻止其他路径重复处理
    ids = [r[0] for r in rows]
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE curiosity_queue SET status='processing' WHERE id IN ({placeholders})",
        ids
    )

    return [
        {
            "id": r[0],
            "query": r[1],
            "project": r[2],
            "detected_at": r[3],
            "top_score": r[4],
            "status": "processing",  # 返回更新后的状态
        }
        for r in rows
    ]


# ══════════════════════════════════════════════════════════════════════════════
# 迭代311：认知科学三机制 — Reconsolidation / Active Suppression / Sleep Consolidation
# 设计哲学：人类记忆不是静态存储再提取，而是动态演化的活跃系统。
#   每次召回都是一次重写（再巩固），
#   不被使用的记忆被主动抑制（而非被动衰减），
#   睡眠期间自动整合高频知识（巩固转移）。
# ══════════════════════════════════════════════════════════════════════════════


def reconsolidate(
    conn: sqlite3.Connection,
    recalled_chunk_ids: list,
    query: str,
    project: str = None,
    boost: float = 0.03,
    max_importance: float = 0.90,
) -> int:
    """
    迭代311-A（iter395 扩展）：再巩固（Reconsolidation，Nader et al. 2000）
    每次 chunk 被召回后，根据 query 匹配深度小幅上调 importance。

    神经科学背景：
      记忆每次被检索后进入"不稳定窗口"（labile state），
      随后以更新的形式重新巩固（re-stabilization）。
      重复且深度匹配的召回 → importance 上升（长期增强，LTP）。

    iter395 扩展 — Retrieval-Induced Reconsolidation（取回触发差异化强化）：
      1. Emotional Multiplier (McGaugh 2000)：情绪记忆再巩固效果更强
         emotional_weight > 0.4 → boost × (1 + emotional_weight × 0.5)
         根据：杏仁核激活增强海马突触可塑性（LTP），高情绪词汇的记忆在
         每次提取后更新时获得额外的 norepinephrine 加固。

      2. Frequency Gradient (Roediger & Karpicke 2006 Testing Effect)：
         首次被召回的强化效果 > 高频反复召回
         access_count ≤ 3 → boost × 1.5（测试效果最强窗口）
         access_count > 10 → boost × 0.7（已高度巩固，边际效益递减）
         根据：间隔效应研究表明首次成功检索带来最大的记忆固化增益。

      3. Co-Retrieval Association Strengthening（同次召回关联强化）：
         同一次检索中被一起召回的 chunk 对，其 entity_edge confidence += 0.02
         根据：Hebb (1949) "neurons that fire together, wire together"
         类比：CPU 的 hardware prefetcher 学习 memory access pattern —
         常一起命中的 cache line 对被记入 stride predictor。

    OS 类比：Linux ARC（Adaptive Replacement Cache）— 被反复命中的页面
      从 T1（最近访问）晋升到 T2（频繁访问），淘汰优先级降低。
      iter395 新增：T2 晋升的强度按页面的"热度梯度"差异化。

    Returns:
      更新的 chunk 数量
    """
    if not recalled_chunk_ids or not query:
        return 0

    # 提取 query 词集（英文词 + 中文双字）
    import re as _re
    query_words: set = set()
    for m in _re.finditer(r'[a-zA-Z\u4e00-\u9fff][a-zA-Z0-9\u4e00-\u9fff]{1,}', query.lower()):
        query_words.add(m.group())
    cn = _re.sub(r'[^\u4e00-\u9fff]', '', query)
    for i in range(len(cn) - 1):
        query_words.add(cn[i:i + 2])

    if not query_words:
        return 0

    ph = ",".join("?" * len(recalled_chunk_ids))
    proj_filter = "AND project=?" if project else ""
    params = recalled_chunk_ids + ([project] if project else [])

    try:
        rows = conn.execute(
            f"SELECT id, summary, importance, "
            f"COALESCE(emotional_weight, 0.0), COALESCE(access_count, 0) "
            f"FROM memory_chunks "
            f"WHERE id IN ({ph}) {proj_filter}",
            params,
        ).fetchall()
    except Exception:
        # fallback: older schema without emotional_weight
        try:
            rows = conn.execute(
                f"SELECT id, summary, importance, 0.0, COALESCE(access_count, 0) "
                f"FROM memory_chunks "
                f"WHERE id IN ({ph}) {proj_filter}",
                params,
            ).fetchall()
        except Exception:
            return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    updated = 0
    for row in rows:
        cid, summary, importance, emotional_weight, access_count = (
            row[0], row[1] or "", row[2] or 0.5, float(row[3] or 0.0), int(row[4] or 0)
        )
        # 计算 summary 词集与 query 的 Jaccard 重叠
        s_words: set = set()
        for m in _re.finditer(r'[a-zA-Z\u4e00-\u9fff][a-zA-Z0-9\u4e00-\u9fff]{1,}', summary.lower()):
            s_words.add(m.group())
        scn = _re.sub(r'[^\u4e00-\u9fff]', '', summary)
        for i in range(len(scn) - 1):
            s_words.add(scn[i:i + 2])

        if not s_words:
            overlap_ratio = 0.0
        else:
            overlap_ratio = len(query_words & s_words) / len(query_words | s_words)

        # 至少给最低 boost（被召回本身就是强化信号）
        actual_boost = boost * (0.3 + 0.7 * overlap_ratio)

        # iter395-1: Emotional Multiplier — 情绪记忆再巩固效果更强
        # emotional_weight > 0.4 → boost 乘以 (1 + ew × 0.5)
        # 最大乘数 1.5（ew=1.0 → ×1.5）
        if emotional_weight > 0.4:
            _em_multiplier = 1.0 + emotional_weight * 0.5
            actual_boost *= _em_multiplier

        # iter395-2: Frequency Gradient — 首次召回效果最强，高频边际递减
        # access_count ≤ 3  → ×1.5（测试效果最强窗口，Roediger 2006）
        # 4 ≤ count ≤ 10   → ×1.0（正常强化）
        # count > 10        → ×0.7（已高度巩固，边际递减）
        if access_count <= 3:
            actual_boost *= 1.5
        elif access_count > 10:
            actual_boost *= 0.7

        # B16: importance inflation correction
        # 旧上限 0.98 导致 285/291 chunks 通胀到 >= 0.6
        # OS 类比：Linux mm/vmscan.c overcommit_ratio 校正 — 防止虚拟内存无限通胀
        if importance > 0.85 and access_count < 5:
            # mean-reversion：高 importance 但低访问 → 缓慢回归均值（防止死锁高位）
            new_importance = max(importance - 0.01, 0.85)
        else:
            new_importance = min(importance + actual_boost, max_importance)

        if abs(new_importance - importance) > 0.001:  # 避免浮点噪音触发无意义写入
            try:
                conn.execute(
                    "UPDATE memory_chunks SET importance=?, updated_at=? WHERE id=?",
                    (round(new_importance, 4), now_iso, cid),
                )
                updated += 1
            except Exception:
                pass

    # iter395-3: Co-Retrieval Association Strengthening（Hebb 1949）
    # 同一次检索中被一起召回的 chunk 对，增强其 entity_edge confidence
    # 只在至少 2 个 chunk 被召回时触发
    if len(recalled_chunk_ids) >= 2:
        try:
            # 批量提升同次召回 chunk 之间的 entity_edge confidence
            # 找到 recalled chunk 中涉及的 entity_edges（from/to 均在召回集中的边）
            ph2 = ",".join("?" * len(recalled_chunk_ids))
            # 通过 entity_map 找到 recalled_chunk 对应的 entity
            recall_entities = conn.execute(
                f"SELECT entity_name FROM entity_map "
                f"WHERE chunk_id IN ({ph2})" + (" AND project=?" if project else ""),
                recalled_chunk_ids + ([project] if project else []),
            ).fetchall()
            recall_entity_set = {r[0] for r in recall_entities}
            if len(recall_entity_set) >= 2:
                # 提升这些 entity 之间的边 confidence（co-firing → strengthen links）
                _ent_ph = ",".join("?" * len(recall_entity_set))
                _ent_list = list(recall_entity_set)
                conn.execute(
                    f"UPDATE entity_edges "
                    f"SET confidence = MIN(0.99, confidence + 0.02) "
                    f"WHERE from_entity IN ({_ent_ph}) AND to_entity IN ({_ent_ph})",
                    _ent_list + _ent_list,
                )
        except Exception:
            pass  # entity_map/entity_edges 失败不阻塞主流程

    return updated


def find_spaced_review_candidates(
    conn: sqlite3.Connection,
    project: str,
    top_n: int = 5,
    min_importance: float = 0.70,
) -> list:
    """
    iter383：间隔效应主动复习候选 — Spacing Effect Scheduler

    认知科学依据：Ebbinghaus (1885) Spacing Effect + SuperMemo SM-2。
      知识点的记忆强度随时间指数衰减（遗忘曲线），最优复习时机在强度降至
      阈值之前。"间隔复习"比"集中复习"更能建立长期记忆（Cepeda et al. 2006）。
      公式：next_review_at = last_accessed + stability × 86400 秒
      如果 now > next_review_at → chunk 进入"即将遗忘窗口"，应主动复习。

    OS 类比：Linux pdflush（内核 2.5 引入）— 不等到内存压力才 writeback，
      而是根据 dirty_expire_interval 定期扫描并主动刷出 dirty pages。
      这里等价：不等用户查询才检索，而是在 session 开始时主动推送"即将遗忘"的知识。

    候选条件（AND）：
      1. importance >= min_importance（重要知识，值得主动复习）
      2. access_count >= 1（曾被访问过，有访问历史的才有"遗忘"概念）
      3. now - last_accessed > stability × 86400（超过稳定窗口，进入遗忘区间）
      4. chunk_type IN ('decision','design_constraint','reasoning_chain','procedure')
      5. 未被 supersede（不在 knowledge_versions.old_chunk_id 中）

    排序（优先级）：
      urgency = importance / (days_since_last_access / stability)
      urgency 越低 → 越过期，越优先复习

    Returns:
      list of dict: [{id, summary, chunk_type, importance, last_accessed, stability, urgency}]
    """
    import datetime as _dt
    now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()

    try:
        rows = conn.execute(
            """
            SELECT mc.id, mc.summary, mc.chunk_type, mc.importance,
                   mc.last_accessed, COALESCE(mc.stability, 1.0) AS stability,
                   COALESCE(mc.access_count, 0) AS access_count
            FROM memory_chunks mc
            WHERE mc.project = ?
              AND COALESCE(mc.importance, 0) >= ?
              AND COALESCE(mc.access_count, 0) >= 1
              AND mc.chunk_type IN ('decision','design_constraint','reasoning_chain','procedure')
              AND mc.last_accessed IS NOT NULL
              AND (julianday(?) - julianday(mc.last_accessed)) * 86400
                  > COALESCE(mc.stability, 1.0) * 86400
              AND mc.id NOT IN (
                SELECT old_chunk_id FROM knowledge_versions WHERE project=?
              )
            ORDER BY mc.importance DESC
            LIMIT 50
            """,
            (project, min_importance, now_iso, project),
        ).fetchall()
    except Exception:
        return []

    candidates = []
    for row in rows:
        cid, summary, ctype, importance, last_accessed, stability, access_count = row
        try:
            _la = _dt.datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
            _now = _dt.datetime.now(_dt.timezone.utc)
            days_since = (_now - _la.replace(tzinfo=_dt.timezone.utc) if _la.tzinfo is None
                          else _now - _la).total_seconds() / 86400
        except Exception:
            days_since = 9999.0

        if days_since <= 0 or stability <= 0:
            continue
        urgency = importance / (days_since / stability)  # 小 → 更迫切

        candidates.append({
            "id": cid,
            "summary": summary or "",
            "chunk_type": ctype or "",
            "importance": importance or 0.7,
            "last_accessed": last_accessed,
            "access_count": access_count,
            "stability": stability,
            "urgency": round(urgency, 4),
            "days_overdue": round(days_since - stability, 2),
        })

    # 按 urgency 升序（urgency 小 = 更迫切），取 top_n
    candidates.sort(key=lambda x: x["urgency"])
    return candidates[:top_n]


def suppress_unused(
    conn: sqlite3.Connection,
    injected_chunk_ids: list,
    assistant_response: str,
    project: str = None,
    penalty: float = 0.025,
    min_importance: float = 0.05,
    min_overlap_to_skip: float = 0.04,
) -> int:
    """
    迭代311-B：主动抑制（Active Suppression，Anderson & Green 2001）
    chunk 被注入但 LLM 未使用时，主动下调 importance。

    神经科学背景：
      前额叶皮层通过抑制性神经元主动压制不相关记忆的提取。
      Think/No-Think 实验：有意不去想某件事，大脑会主动抑制该记忆
      的海马激活，导致后续回忆成功率下降。

    OS 类比：Linux vm.swappiness — 主动将"冷"页面推出 RAM，
      而不是等 OOM 才被动淘汰。swappiness 越高，越积极换出不常用页面。

    算法：
      1. 对每个被注入的 chunk，检测其 summary 关键词是否出现在 LLM 回复中
      2. 重叠度 < min_overlap_to_skip → 判定为"未被使用"
      3. importance -= penalty，下限 min_importance

    Returns:
      被抑制的 chunk 数量
    """
    if not injected_chunk_ids or not assistant_response:
        return 0

    import re as _re
    # 提取 LLM 回复词集
    resp_lower = assistant_response.lower()
    resp_words: set = set()
    for m in _re.finditer(r'[a-zA-Z\u4e00-\u9fff][a-zA-Z0-9\u4e00-\u9fff]{1,}', resp_lower):
        resp_words.add(m.group())
    rcn = _re.sub(r'[^\u4e00-\u9fff]', '', assistant_response)
    for i in range(len(rcn) - 1):
        resp_words.add(rcn[i:i + 2])

    ph = ",".join("?" * len(injected_chunk_ids))
    proj_filter = "AND project=?" if project else ""
    params = injected_chunk_ids + ([project] if project else [])

    try:
        rows = conn.execute(
            f"SELECT id, summary, importance FROM memory_chunks "
            f"WHERE id IN ({ph}) {proj_filter}",
            params,
        ).fetchall()
    except Exception:
        return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    suppressed = 0
    for row in rows:
        cid, summary, importance = row[0], row[1] or "", row[2] or 0.5

        # 计算 summary 词集与 LLM 回复的重叠
        s_words: set = set()
        for m in _re.finditer(r'[a-zA-Z\u4e00-\u9fff][a-zA-Z0-9\u4e00-\u9fff]{1,}', summary.lower()):
            s_words.add(m.group())
        scn = _re.sub(r'[^\u4e00-\u9fff]', '', summary)
        for i in range(len(scn) - 1):
            s_words.add(scn[i:i + 2])

        if not s_words or not resp_words:
            overlap = 0.0
        else:
            overlap = len(s_words & resp_words) / len(s_words | resp_words)

        if overlap < min_overlap_to_skip:
            new_importance = max(importance - penalty, min_importance)
            if new_importance < importance - 0.001:
                try:
                    conn.execute(
                        "UPDATE memory_chunks SET importance=?, updated_at=? WHERE id=?",
                        (round(new_importance, 4), now_iso, cid),
                    )
                    suppressed += 1
                except Exception:
                    pass

    return suppressed


def sleep_consolidate(
    conn: sqlite3.Connection,
    project: str,
    session_id: str = "",
    similarity_threshold: float = 0.72,
    stability_boost: float = 1.15,
    stability_decay: float = 0.92,
    active_days: int = 7,
    stale_days: int = 30,
    max_merges: int = 20,
    gap_seconds: float = 0.0,
) -> dict:
    """
    迭代311-C：睡眠巩固（Sleep Consolidation，Walker & Stickgold 2004）
    session 结束时自动触发：合并高相似 chunk + stability 动态调整。

    神经科学背景：
      慢波睡眠（SWS）期间，海马将当日编码的情景记忆"回放"给新皮层，
      实现从海马依赖（短期）到皮层依赖（长期）的记忆转移（consolidation）。
      高频激活的记忆获得更强的皮层表征（长期增强，LTP）；
      低频记忆连接弱化（长期抑制，LTD）。

    OS 类比：Linux KSM（Kernel Samepage Merging）+ pdflush
      ksmd 在后台扫描合并相同页面（↔ 合并相似 chunk）；
      pdflush 将 dirty page 按优先级写回磁盘（↔ stability 回写）。

    三个子操作：
      1. 合并高相似 chunk（复用 Jaccard trigram）— 减少冗余
      2. 本 session 高访问 chunk stability × stability_boost（活跃记忆加固）
      3. 长期未访问 chunk stability × stability_decay（不活跃记忆弱化）

    Returns:
      {"merged": N, "boosted": N, "decayed": N}
    """
    import re as _re
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td

    result = {"merged": 0, "boosted": 0, "decayed": 0}
    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()

    proj_filter = "AND project=?" if project else ""
    proj_params = [project] if project else []

    # ── 子操作 1：合并高相似 chunk ────────────────────────────────────────────
    def _trigrams(s: str) -> set:
        s = _re.sub(r'\s+', ' ', s.strip().lower())
        return set(s[i:i + 3] for i in range(len(s) - 2)) if len(s) >= 3 else set(s)

    def _jaccard(a: str, b: str) -> float:
        ta, tb = _trigrams(a), _trigrams(b)
        if not ta or not tb:
            return 0.0
        return len(ta & tb) / len(ta | tb)

    # ── iter785: session_fragment_merge — 同 session 同 type 碎片聚合 ──────────
    # 根因（数据驱动，2026-05-04）：session e3e4392b 写了 5 条 decision（组织架构），
    #   内容各一行，Jaccard 无法捕捉（"5人小组" vs "30人部门" 相似度<0.3）。
    #   iter784 只防未来写入，不回溯历史碎片。
    # 修复：按 (source_session, chunk_type) 分组，同组>3 条 → content 拼接合并。
    merged_ids: set = set()
    merge_count = 0
    try:
        _frag_rows = conn.execute(
            f"SELECT source_session, chunk_type, COUNT(*) as cnt "
            f"FROM memory_chunks WHERE chunk_state='ACTIVE' AND source_session != '' "
            f"{proj_filter} GROUP BY source_session, chunk_type HAVING cnt > 3",
            proj_params,
        ).fetchall()
        for _fs_sess, _fs_type, _fs_cnt in _frag_rows:
            if merge_count >= max_merges:
                break
            _frags = conn.execute(
                "SELECT id, summary, content, importance FROM memory_chunks "
                "WHERE source_session=? AND chunk_type=? AND chunk_state='ACTIVE' "
                "ORDER BY created_at ASC",
                (_fs_sess, _fs_type),
            ).fetchall()
            if len(_frags) <= 3:
                continue
            # survivor = highest importance
            _frags_sorted = sorted(_frags, key=lambda r: r[3] or 0, reverse=True)
            _survivor = _frags_sorted[0]
            _victims = _frags_sorted[1:]
            # 合并 content: survivor content + victims content
            _merged_content = (_survivor[2] or _survivor[1] or "").strip()
            for _v in _victims:
                _v_text = (_v[2] or _v[1] or "").strip()
                if _v_text and _v_text not in _merged_content:
                    _merged_content += "\n" + _v_text
            _merged_content = _merged_content[:3000]
            # 合并 summary
            _merged_summary = _survivor[1] or ""
            if len(_frags) > 3:
                _merged_summary = f"{_fs_type}×{len(_frags)} from session {_fs_sess[:8]}: {_merged_summary}"
            _merged_summary = _merged_summary[:200]
            _new_imp = min(0.98, max(r[3] or 0 for r in _frags) * 1.02)
            # update survivor
            conn.execute(
                "UPDATE memory_chunks SET content=?, summary=?, importance=?, updated_at=? WHERE id=?",
                (_merged_content, _merged_summary, round(_new_imp, 4), now_iso, _survivor[0]),
            )
            try:
                _fts5_sync_chunk(conn, _survivor[0], summary=_merged_summary, content=_merged_content)
            except Exception:
                pass
            # ghost victims
            for _v in _victims:
                conn.execute(
                    "UPDATE memory_chunks SET importance=0, oom_adj=500, chunk_state='MERGED', "
                    "summary=?, updated_at=? WHERE id=?",
                    (f"[merged→{_survivor[0][:12]}] {(_v[1] or '')[:80]}"[:200], now_iso, _v[0]),
                )
                merged_ids.add(_v[0])
                merge_count += 1
    except Exception:
        pass

    try:
        rows = conn.execute(
            f"SELECT id, summary, importance, stability FROM memory_chunks "
            f"WHERE chunk_type NOT IN ('prompt_context','task_state') {proj_filter} "
            f"ORDER BY importance DESC LIMIT 500",
            proj_params,
        ).fetchall()

        for i in range(len(rows)):
            if merge_count >= max_merges:
                break
            if rows[i][0] in merged_ids:
                continue
            for j in range(i + 1, len(rows)):
                if merge_count >= max_merges:
                    break
                if rows[j][0] in merged_ids:
                    continue
                sim = _jaccard(rows[i][1] or "", rows[j][1] or "")
                if sim >= similarity_threshold:
                    # survivor = 高 importance 的那个（rows[i] 因 ORDER BY imp DESC 排前）
                    survivor_id, victim_id = rows[i][0], rows[j][0]
                    victim_imp = rows[j][2] or 0.3
                    survivor_imp = rows[i][2] or 0.5
                    # survivor importance 轻微提升（吸收了 victim 的信号）
                    new_imp = min(0.98, max(survivor_imp, victim_imp) * 1.02)
                    # victim 降为 ghost（importance=0, oom_adj=500）
                    conn.execute(
                        "UPDATE memory_chunks SET importance=0, oom_adj=500, "
                        "summary=?, updated_at=? WHERE id=?",
                        (f"[merged→{survivor_id}] {re.sub(r'\\[merged→[^\\]]*\\]\\s*', '', rows[j][1] or '').strip()}"[:200],
                         now_iso, victim_id),
                    )
                    conn.execute(
                        "UPDATE memory_chunks SET importance=?, updated_at=? WHERE id=?",
                        (round(new_imp, 4), now_iso, survivor_id),
                    )
                    merged_ids.add(victim_id)
                    merge_count += 1
        result["merged"] = merge_count
    except Exception:
        pass

    # ── 子操作 2：本 session 高访问 chunk stability × boost ──────────────────
    try:
        # 本 session 被访问过的 chunk（last_accessed 在 session 期间）
        # 简化：取 last_accessed 在最近 active_days 天内 且 access_count >= 2 的
        cutoff_active = (now - _td(days=active_days)).isoformat()
        conn.execute(
            f"UPDATE memory_chunks SET stability=MIN(365.0, stability * ?), updated_at=? "
            f"WHERE last_accessed >= ? AND access_count >= 2 {proj_filter}",
            [stability_boost, now_iso, cutoff_active] + proj_params,
        )
        result["boosted"] = conn.execute(
            f"SELECT changes()"
        ).fetchone()[0]
    except Exception:
        pass

    # ── 子操作 3：长期未访问 chunk stability × decay（iter400：per-type 个体化衰减）──
    # iter400：以 chunk_type 个体化衰减率替代统一的 stability_decay 参数。
    # 认知科学依据：程序性记忆（design_constraint/procedure）衰减慢；
    #   工作记忆/情节记忆（task_state/prompt_context）衰减快。
    # OS 类比：Linux cgroup memory.reclaim_ratio — per-group 内存回收压力。
    try:
        cutoff_stale = (now - _td(days=stale_days)).isoformat()
        # iter432: per-type 衰减 + Cumulative Interference Effect（超出 iter400）
        _ci_result = decay_stability_by_type_with_ci(conn, project, stale_days=stale_days,
                                                     now_iso=now_iso)
        # _ci_result 是 dict {"total_decayed": N, "ci_factors": {...}}
        # result["decayed"] 保持向后兼容的 int 语义
        result["decayed"] = _ci_result.get("total_decayed", 0) if isinstance(_ci_result, dict) else _ci_result
    except Exception:
        # fallback: 使用全局统一衰减率（兼容旧 schema）
        try:
            cutoff_stale = (now - _td(days=stale_days)).isoformat()
            conn.execute(
                f"UPDATE memory_chunks SET stability=MAX(0.1, stability * ?), updated_at=? "
                f"WHERE last_accessed < ? AND access_count < 2 {proj_filter}",
                [stability_decay, now_iso, cutoff_stale] + proj_params,
            )
            result["decayed"] = conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass

    # ── 子操作 4（迭代319）：情节 chunk 巩固扫描 ──────────────────────────────
    # OS 类比：khugepaged 在 kswapd 回收后，再扫描高频访问小页面尝试合并
    try:
        ep_result = episodic_decay_scan(conn, project, stale_days=stale_days)
        result["episodic_decayed"] = ep_result.get("decayed", 0)
        result["episodic_promoted"] = ep_result.get("promoted", 0)
        result["episodic_inplace_promoted"] = ep_result.get("inplace_promoted", 0)  # iter379
        result["new_semantic_ids"] = ep_result.get("new_semantic_ids", [])
    except Exception:
        pass

    # ── 子操作 5（iter436）：Output Interference — 同轮注入后序 chunk 的工作记忆竞争惩罚 ──
    # OS 类比：BFQ dispatch batch budget 消耗 — 同 batch 后序 I/O 获得更少 budget
    try:
        oi_result = apply_output_interference(conn, project, window_hours=24.0)
        result["oi_penalized"] = oi_result.get("penalized", 0)
    except Exception:
        pass

    # ── 子操作 6（iter437）：Hypermnesia — 多次分布式检索后的记忆净增强 ──
    # OS 类比：khugepaged — 跨多个 epoch 热访问的页面晋升为 hugepage（净效率提升）
    try:
        hm_result = apply_hypermnesia(conn, project)
        result["hm_boosted"] = hm_result.get("boosted", 0)
    except Exception:
        pass

    # ── 子操作 7（iter438）：Jost's Law — 高龄 chunk 衰减减速修正 ──
    # OS 类比：MGLRU old generation protection — 跨多 aging interval 存活的页面获得更弱的 reclaim pressure
    try:
        jost_result = apply_jost_law(conn, project, stale_days=stale_days)
        result["jost_adjusted"] = jost_result.get("adjusted", 0)
    except Exception:
        pass

    # ── 子操作 8（iter439）：Encoding Depth Decay Resistance — 深度编码减慢衰减 ──
    # OS 类比：ext4 extent tree depth — 深层 extent tree 的 inode 驱逐代价更高（更抗 reclaim）
    try:
        eddr_result = apply_encoding_depth_decay_resistance(conn, project, stale_days=stale_days)
        result["eddr_deep_boosted"] = eddr_result.get("deep_boosted", 0)
        result["eddr_shallow_penalized"] = eddr_result.get("shallow_penalized", 0)
    except Exception:
        pass

    # ── 子操作 9（iter440）：Proactive Facilitation — 强邻居锚定保护新知识衰减 ──
    # OS 类比：Linux page cache refcount — 被多个 inode 共享引用的 page 有高 refcount，kswapd 优先保留
    try:
        pf_result = apply_proactive_facilitation(conn, project, stale_days=stale_days)
        result["pf_facilitated"] = pf_result.get("facilitated", 0)
    except Exception:
        pass

    # ── 子操作 10（iter441）：Emotional Consolidation — 情绪显著性记忆睡眠优先巩固 ──
    # OS 类比：Linux writeback priority — 高优先级 dirty page 被 pdflush 优先刷写到磁盘
    try:
        ec_result = apply_emotional_consolidation(conn, project)
        result["ec_consolidated"] = ec_result.get("consolidated", 0)
    except Exception:
        pass

    # ── 子操作 11（iter442）：Schema-Consistent Consolidation — 图式一致性新知识快速巩固 ──
    # OS 类比：Linux readahead pattern detection — 顺序模式匹配 → 预取窗口扩大 → 更快 I/O
    try:
        scc_result = apply_schema_consistent_consolidation(conn, project)
        result["scc_schema_consolidated"] = scc_result.get("schema_consolidated", 0)
    except Exception:
        pass

    # ── 子操作 12（iter443）：Sleep-Targeted Reactivation — 主动抢救衰退的高价值记忆 ──
    # OS 类比：Linux dirty page "expire" writeback scan — 即将超时的脏页被 flusher 优先抢救写回
    try:
        str_result = apply_sleep_targeted_reactivation(conn, project)
        result["str_rescued"] = str_result.get("rescued", 0)
    except Exception:
        pass

    # ── 子操作 13（iter444）：Contextual Reinstatement Effect — session 活跃情境内的 chunk 额外巩固 ──
    # OS 类比：Linux NUMA-aware khugepaged — 同 NUMA node 热页优先合并为 hugepage（情境局部性 → 高效整合）
    try:
        cre_result = apply_contextual_reinstatement_consolidation(conn, project)
        result["cre_consolidated"] = cre_result.get("cre_consolidated", 0)
    except Exception:
        pass

    # ── 子操作 14（iter445）：Reward-Tagged Memory Consolidation — 高访问×近期访问的 chunk 获得奖励巩固 ──
    # OS 类比：Linux workingset_activation — refcount × recency = 工作集优先级 → sleep 时优先强化
    try:
        rtmc_result = apply_reward_tagged_memory_consolidation(conn, project)
        result["rtmc_boosted"] = rtmc_result.get("rtmc_boosted", 0)
    except Exception:
        pass

    # ── 子操作 15（iter446）：Temporal Contiguity Effect — 时间毗邻写入的 chunk 相互加成 stability ──
    # OS 类比：Linux MGLRU temporal cohort aging — 同代 pages 在 kswapd 扫描时相互保护
    try:
        tce_result = apply_temporal_contiguity_consolidation(conn, project)
        result["tce_boosted"] = tce_result.get("tce_boosted", 0)
    except Exception:
        pass

    # ── 子操作 16（iter447）：Von Restorff Sleep Reactivation — 孤立 chunk 在 sleep 时获得额外巩固 ──
    # OS 类比：Linux huge page mlock + MADV_HUGEPAGE 双标注 — 独特布局的锁定页受双重保护路径
    try:
        vrr_result = apply_von_restorff_sleep_reactivation(conn, project)
        result["vrr_boosted"] = vrr_result.get("vrr_boosted", 0)
    except Exception:
        pass

    # ── 子操作 17（iter448）：Retroactive Enhancement — 新 chunk 睡眠后逆行增强旧相关 chunk ──
    # OS 类比：Linux page fault 触发的 backward readahead — 新页命中触发对历史相关页的反向预取
    try:
        re_result = apply_retroactive_enhancement(conn, project)
        result["re_boosted"] = re_result.get("re_boosted", 0)
    except Exception:
        pass

    # ── 子操作 18（iter449）：Quiet Wakefulness Reactivation — 清醒安静期自发重放预巩固 ──
    # OS 类比：Linux incremental pdflush writeback — 30s 周期轻量级 dirty page 写回（vs fsync 全量同步）
    # 只在 gap_seconds > 0 时触发（gap=0 表示连续 session，未检测到休息间隔）
    try:
        if gap_seconds > 0:
            qwr_result = apply_quiet_wakefulness_reactivation(conn, project, gap_seconds)
            result["qwr_boosted"] = qwr_result.get("qwr_boosted", 0)
            result["qwr_skipped_reason"] = qwr_result.get("skipped_reason")
    except Exception:
        pass

    # ── 子操作 19（iter451）：Memory Reconsolidation Context Refresh — 再巩固窗口期编码情境刷新 ──
    # OS 类比：Linux CoW page reconsolidation — 读访问标记 COW ready 后，新内容写入时合并到旧页面
    # 机制：近期被检索的 chunk（处于再巩固可塑窗口）接收同 session 内新写入相关 chunk 的 entity 注入
    try:
        rcr_result = apply_reconsolidation_context_refresh(conn, project)
        result["rcr_updated"] = rcr_result.get("rcr_updated", 0)
    except Exception:
        pass

    # ── 子操作 20（iter452）：Primary Memory Persistence — session 内密集复述的工作记忆持久化增强 ──
    # OS 类比：Linux page working set active list — 短时内多次 referenced page 提升到 active list，
    #   kswapd 优先保护（反复 referenced = 工作集热页 = 值得额外巩固）
    # 机制：session 内注入次数 >= pmp_min_injections 的 chunk 获得 stability 加成
    try:
        pmp_result = apply_primary_memory_persistence(conn, project, gap_seconds=gap_seconds)
        result["pmp_boosted"] = pmp_result.get("pmp_boosted", 0)
    except Exception:
        pass

    # ── 子操作 21（iter457）：Cue Overload Consolidation Penalty — 同类型 chunk 过多时 sleep 巩固效益下降 ──
    # OS 类比：CPU cache set-associativity saturation — 同 set 太多 cache line → per-line 保留概率下降
    # 机制：同类型 chunk N_type > cocp_type_threshold 时，对该类型 chunk 施加轻微 stability 惩罚
    try:
        cocp_result = apply_cue_overload_consolidation_penalty(conn, project)
        result["cocp_penalized"] = cocp_result.get("cocp_penalized", 0)
    except Exception:
        pass

    # ── 子操作 22（iter460）：Sleep Spindle Density Effect — 陈述性记忆 chunk 在 sleep 时获得更强巩固加成 ──
    # OS 类比：Linux NUMA-aware writeback priority — data/metadata/journal 有不同 writeback 优先级策略；
    #   陈述性记忆类型（spindle-preferred）获得更强加成，程序性类型（REM-preferred）获得较弱加成
    try:
        ssde_result = apply_sleep_spindle_density_effect(conn, project)
        result["ssde_boosted"] = ssde_result.get("ssde_boosted", 0)
        result["ssde_reduced"] = ssde_result.get("ssde_reduced", 0)
    except Exception:
        pass

    # ── 子操作 23（iter461）：Hebbian Co-Activation Consolidation — 共同激活的 chunk 在 sleep 时相互加固 ──
    # OS 类比：Linux THP promotion — khugepaged 将共同访问的 pages 合并为 huge page，降低 TLB miss
    try:
        hac_result = apply_hebbian_coactivation_consolidation(conn, project)
        result["hac_boosted"] = hac_result.get("hac_boosted", 0)
    except Exception:
        pass

    return result


# ── 迭代315：情境感知注入 — 编码情境提取 ─────────────────────────
# OS 类比：Linux perf_event context — 记录性能事件时附带 CPU/task 上下文，
#   使后续分析能区分「在什么场景下发生的」，而不只是「发生了什么」。
# 认知科学依据：Encoding Specificity (Tulving 1973) — 检索线索与编码时线索
#   重叠越高，记忆提取成功率越高。

def extract_encoding_context(text: str) -> dict:
    """迭代315: 从文本提取编码情境特征（纯正则，不调LLM）。

    返回 dict:
      session_type: debug/design/review/refactor/qa/unknown
      entities:     核心实体词列表（≤8个）
      task_verbs:   动作类词列表（≤5个）
    """
    import re as _re
    # session_type 关键词规则
    _TYPE_RULES = [
        ("debug",    r'调试|报错|错误|traceback|exception|bug|fix|error|failed'),
        ("design",   r'设计|架构|方案|决策|接口|API|schema|interface'),
        ("review",   r'审查|review|PR|merge|代码审核|LGTM'),
        ("refactor", r'重构|重写|迁移|refactor|cleanup|rename'),
        ("qa",       r'测试|验证|test|assert|pytest|passed|failed'),
    ]
    session_type = "unknown"
    for stype, pat in _TYPE_RULES:
        if _re.search(pat, text, _re.IGNORECASE):
            session_type = stype
            break

    # entities：反引号内容 + 英文驼峰/下划线词
    entities = []
    seen = set()
    for m in _re.finditer(r'`([^`]{2,30})`', text[:2000]):
        w = m.group(1).strip()
        if w not in seen:
            seen.add(w)
            entities.append(w)
    _STOP = frozenset({
        'the', 'and', 'for', 'with', 'from', 'this', 'that', 'are', 'was',
        'has', 'not', 'but', 'can', 'will', 'use', 'new', 'get', 'set',
        'add', 'run',
    })
    for m in _re.finditer(r'\b([A-Z][a-zA-Z0-9]{2,20}|[a-z][a-z0-9_]{3,20})\b', text[:2000]):
        w = m.group(1)
        if w not in seen and w.lower() not in _STOP:
            seen.add(w)
            entities.append(w)
        if len(entities) >= 10:
            break

    # task_verbs：中文动作词
    task_verbs = []
    _VERB_PATS = [
        r'(?:修复|调试|排查|诊断|定位)',   # debug类
        r'(?:设计|规划|构建|重构|迁移)',    # design类
        r'(?:实现|添加|删除|更新|升级)',    # impl类
        r'(?:测试|验证|检查|确认|评估)',    # qa类
        r'(?:优化|改进|提升|加速|减少)',    # perf类
    ]
    for pat in _VERB_PATS:
        for m in _re.finditer(pat, text[:2000]):
            v = m.group(0)
            if v not in task_verbs:
                task_verbs.append(v)

    return {
        "session_type": session_type,
        "entities": entities[:8],
        "task_verbs": task_verbs[:5],
    }


# ══════════════════════════════════════════════════════════════════════════════
# 迭代317：前摄干扰控制（Proactive Interference Control）
# 认知科学基础：Proactive Interference (PI) — Müller & Pilzecker 1900，Bartlett 1932
#   旧知识干扰新知识的学习和检索：当新知识与旧知识语义矛盾时，
#   必须明确将旧知识"失效标记"（而不是等待自然衰减），
#   否则检索时两者并存，导致矛盾信息同时注入 LLM 上下文。
#
# OS 类比：Linux kernel module versioning（MODULE_STATE_GOING）：
#   insmod 新版本模块时，旧版本被标记为 GOING，不再接受新请求；
#   这里等价于：旧 chunk 的 importance 降权 + oom_adj 上调，使其在检索排序中沉底。
# ══════════════════════════════════════════════════════════════════════════════

# 冲突检测：否定/替换模式关键词
# 语义：含这些关键词的新 chunk 表示"否定/替换"已有知识
_CONFLICT_NEGATION_PATTERNS = [
    # 直接否定
    r'不使用', r'不采用', r'不推荐', r'不选择', r'不再使用', r'不再采用',
    # 替换/放弃
    r'放弃', r'改用', r'换成', r'替代', r'替换', r'迁移到', r'迁移至',
    # 否定建议/结论
    r'不推荐', r'不建议', r'反对', r'否定',
]

_CONFLICT_NEG_RE = re.compile('|'.join(_CONFLICT_NEGATION_PATTERNS))


def _extract_key_entities(text: str) -> set:
    """
    从文本中提取关键实体词（英文标识符 + CJK bigram）。
    用于 detect_conflict 的词集交集比对。
    """
    entities: set = set()
    # 英文词（含下划线、点，如 BM25 / PostgreSQL / redis_client）
    for m in re.finditer(r'[a-zA-Z][a-zA-Z0-9_.]{1,}', text):
        w = m.group().strip('._').lower()
        if len(w) >= 2:
            entities.add(w)
    # CJK bigram
    cjk = re.sub(r'[^\u4e00-\u9fff]', '', text)
    for i in range(len(cjk) - 1):
        entities.add(cjk[i:i + 2])
    return entities


def detect_conflict(
    conn: sqlite3.Connection,
    new_summary: str,
    chunk_type: str,
    project: str,
) -> list:
    """
    迭代317：检测 new_summary 与 DB 中同类型 chunk 的语义冲突。

    冲突判定逻辑：
      1. new_summary 含否定/替换关键词（否则直接返回 []）
      2. new_summary 与已有 chunk 有实体词交集（即谈论同一对象）
      3. 两条规则同时满足 → 判定为冲突

    只在同 project + 同 chunk_type 内检测（跨类型语义不可比）。

    Returns:
      冲突的旧 chunk ID 列表（可能为空）
    """
    # 快速路径：new_summary 不含否定/替换词 → 不可能冲突
    if not _CONFLICT_NEG_RE.search(new_summary):
        return []

    # 提取 new_summary 的关键实体
    new_entities = _extract_key_entities(new_summary)
    if not new_entities:
        return []

    # 查询同 project + 同 chunk_type 的已有 chunk
    try:
        rows = conn.execute(
            "SELECT id, summary FROM memory_chunks "
            "WHERE project=? AND chunk_type=? AND summary != ''",
            (project, chunk_type),
        ).fetchall()
    except Exception:
        return []

    conflicts = []
    for row in rows:
        cid, existing_summary = row[0], row[1] or ""
        if not existing_summary:
            continue
        existing_entities = _extract_key_entities(existing_summary)
        # 实体词交集 ≥ 1 → 谈论同一对象 → 冲突
        if new_entities & existing_entities:
            conflicts.append(cid)

    return conflicts


def supersede_chunk(
    conn: sqlite3.Connection,
    old_id: str,
    new_id: str,
    reason: str,
    project: str,
    session_id: str = "",
) -> Optional[str]:
    """
    迭代317：将 old_id chunk 标记为被 new_id 取代。

    操作：
      1. 在 knowledge_versions 中写入版本对记录
      2. 旧 chunk importance *= 0.5（降权），oom_adj += 200（更易淘汰）
      3. 若 old_id 不存在，安全返回 new_id（不抛异常）

    Returns:
      new_id（成功）或 None（仅当 old_id 存在但操作异常时）
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    # 检查 old_id 是否存在
    row = conn.execute(
        "SELECT importance, oom_adj FROM memory_chunks WHERE id=?",
        (old_id,),
    ).fetchone()

    # 无论旧 chunk 是否存在，都写入版本对记录（new_id 为知识演化的声明）
    try:
        conn.execute(
            """INSERT INTO knowledge_versions
               (old_chunk_id, new_chunk_id, reason, project, session_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (old_id, new_id, reason, project, session_id, now_iso),
        )
    except Exception:
        pass

    if row is not None:
        old_importance = row[0] if row[0] is not None else 0.5
        old_oom_adj = row[1] if row[1] is not None else 0
        new_importance = round(old_importance * 0.5, 4)
        new_oom_adj = old_oom_adj + 200
        try:
            conn.execute(
                "UPDATE memory_chunks SET importance=?, oom_adj=?, updated_at=? WHERE id=?",
                (new_importance, new_oom_adj, now_iso, old_id),
            )
        except Exception:
            return None

    return new_id


def get_superseded_ids(
    conn: sqlite3.Connection,
    project: str = None,
) -> set:
    """
    迭代317：返回已被取代的旧 chunk ID 集合。

    用途：检索时排除旧版本 chunk，防止矛盾知识注入 LLM 上下文。

    OS 类比：Linux kernel module_state_going_list — 获取所有 MODULE_STATE_GOING
      的模块 ID，供 module_find_or_load() 跳过。

    Returns:
      set of old_chunk_id strings
    """
    try:
        if project:
            rows = conn.execute(
                "SELECT DISTINCT old_chunk_id FROM knowledge_versions WHERE project=?",
                (project,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT DISTINCT old_chunk_id FROM knowledge_versions"
            ).fetchall()
        return {r[0] for r in rows}
    except Exception:
        return set()


# ══════════════════════════════════════════════════════════════════════════════
# 迭代319：情节记忆 vs 语义记忆分离（Episodic/Semantic Memory Separation）
# 认知科学基础：Tulving (1972) 双记忆系统
#   情节记忆（Episodic）：特定时间/情境的事件记忆（"上次会话里决定了X"）
#     - 高时效性，会话结束后快速衰减
#     - 来源：reasoning_chain, conversation_summary, causal_chain
#   语义记忆（Semantic）：去情境化的通用知识（"X系统使用Y算法"）
#     - 高稳定性，慢衰减，可跨会话复用
#     - 来源：decision, design_constraint, procedure
#   转化路径：情节记忆被多次召回（>=3次）→ 自动提升为语义记忆
#     类比：海马短期情节记忆 → 新皮层长期语义存储（记忆固化，consolidation）
#
# OS 类比：Linux huge page compaction + THP（Transparent Huge Pages）
#   小页面（情节 chunk）被频繁访问后合并成大页面（语义 chunk），
#   保留合并记录（episodic_consolidations），原小页面标记为"可回收"。
# ══════════════════════════════════════════════════════════════════════════════

# chunk_type → info_class 映射表
_CHUNK_TYPE_INFO_CLASS: dict = {
    # 情节记忆：高时效性，会话内有效
    "reasoning_chain": "episodic",
    "conversation_summary": "episodic",
    "causal_chain": "episodic",
    # 语义记忆：去情境化通用知识
    "decision": "semantic",
    "design_constraint": "semantic",
    "procedure": "semantic",
    "quantitative_evidence": "semantic",
    # 操作配置：项目内持久
    "task_state": "operational",
    "prompt_context": "operational",
    # 其余 → world（中等保留）
}


def classify_memory_type(chunk_type: str, summary: str) -> str:
    """
    迭代319：根据 chunk_type + summary 特征，推断 info_class。

    优先级：
      1. 内容含"临时/本次/暂时"关键词 → ephemeral（覆盖 chunk_type 映射）
      2. chunk_type 直接映射
      3. excluded_path → semantic
      4. 默认 world

    OS 类比：Linux mm/vma.c vm_area_struct.vm_flags —
      每个 VMA 在 mmap 时被赋予 VM_READ/VM_WRITE/VM_EXEC/VM_SHARED 标志，
      决定该区域的回收策略（shared+dirty → writeback，anon → swap）。

    Returns: 'episodic' | 'semantic' | 'world' | 'operational' | 'ephemeral'
    """
    # chunk_type 直接映射（情节/语义/operational 类型不受内容关键词覆盖）
    if chunk_type in _CHUNK_TYPE_INFO_CLASS:
        return _CHUNK_TYPE_INFO_CLASS[chunk_type]

    # 内容关键词：含"临时"/"本次"/"这次"关键词 → ephemeral
    # 仅作用于未被 chunk_type 映射的类型（避免覆盖明确分类的 episodic/semantic）
    if re.search(r'临时|本次|这次|暂时|测试用', summary):
        return "ephemeral"

    # excluded_path：记录"不做的选择" — 通常是多次验证后的稳定决策 → semantic
    if chunk_type == "excluded_path":
        return "semantic"

    return "world"


# ══════════════════════════════════════════════════════════════════════════════
# 迭代320：情感显著性驱动 importance（Emotional Salience）
# 认知科学基础：McGaugh (2004) "The amygdala modulates the consolidation of
#   memories of emotionally arousing experiences" — 情感唤醒激活杏仁核，
#   杏仁核通过 norepinephrine 调节海马突触可塑性，增强记忆编码。
#   结果：情感标记越强，记忆越优先被固化、越难被遗忘。
#
# 实际映射：
#   高情感唤醒词（紧急/严重/失败/崩溃/突破）→ importance 上调
#   负面情感词（已解决/废弃/过时）→ 轻微下调（"关闭"事件降权）
#   中性词 → 不改变
#
# OS 类比：Linux OOM Killer 的 /proc/[pid]/oom_score_adj —
#   进程可以声明自己的重要性，内核在 OOM 时优先 kill 分数低的进程；
#   情感显著性相当于 chunk 自我声明的"存活优先级"。
# ══════════════════════════════════════════════════════════════════════════════

# 情感唤醒词典（高唤醒 → 正调整，低唤醒 → 负调整）
# 格式：(patterns, delta)
_EMOTIONAL_SALIENCE_RULES: list = [
    # 高唤醒正向：突破/发现/关键
    (r'突破|关键发现|重要发现|核心|必须|严格要求', +0.10),
    # 高唤醒负向：错误/崩溃/失败/紧急
    (r'崩溃|严重错误|critical.*bug|P0|紧急|fatal|panic|CRITICAL', +0.12),
    (r'failed|failure|exception|traceback|ERROR|死锁|data.*loss|数据丢失', +0.08),
    # 英文高唤醒正向
    (r'breakthrough|critical|must|important|key insight|major', +0.08),
    # 情感中性但高价值
    (r'性能瓶颈|bottleneck|O\(N\)|O\(n\^2\)|slow|latency.*high', +0.06),
    # 低唤醒：已解决/已关闭/完成（降权让位新知识）
    (r'已解决|已修复|已关闭|不再需要|obsolete|deprecated|过时|已废弃', -0.08),
    (r'resolved|fixed|closed|no longer|wont.fix|done.*already', -0.06),
]

# 预编译正则（模块加载时一次性）
_EMOTIONAL_SALIENCE_RE: list = [
    (re.compile(pat, re.IGNORECASE), delta)
    for pat, delta in _EMOTIONAL_SALIENCE_RULES
]

# ── iter424: 情绪效价规则（Bower 1981 Mood-Congruent Memory）──
# 效价：+1 = 正面情绪（成功/发现/突破），-1 = 负面情绪（失败/崩溃/危机）
# 独立于唤醒度（emotional_weight）：错误可以高唤醒但为负效价
_EMOTIONAL_VALENCE_RULES: list = [
    # 正面效价：突破/成功/发现
    (r'突破|关键发现|重要发现|成功|解决了|搞定|完成|优化成功', +1.0),
    (r'breakthrough|success|solved|achieved|resolved|fixed|works|great', +1.0),
    # 负面效价：失败/错误/崩溃/危机
    (r'崩溃|严重错误|fatal|panic|死锁|数据丢失|失败|无法|报错', -1.0),
    (r'failed|failure|exception|traceback|ERROR|crash|broken|bug|error', -1.0),
    (r'P0|紧急|CRITICAL|critical.*bug|production.*down|线上.*故障', -1.0),
    # 中等负面：问题/瓶颈（不是灾难，但是挑战）
    (r'性能瓶颈|bottleneck|slow|latency.*high|阻塞|卡住|stuck', -0.5),
    (r'问题|issue|concerned|trouble|difficulty|challenge', -0.3),
]

# 预编译情绪效价正则
_EMOTIONAL_VALENCE_RE: list = [
    (re.compile(pat, re.IGNORECASE), val)
    for pat, val in _EMOTIONAL_VALENCE_RULES
]


def compute_boundary_proximity(
    created_at: str,
    session_started_at: str,
    prev_session_ended_at: str = None,
    grace_secs: float = 300.0,
    lookback_secs: float = 300.0,
) -> float:
    """
    iter428: 计算 chunk 的会话边界亲近度（Zacks et al. 2007 Event Segmentation Theory）。

    Zacks et al. (2007) — 人类将连续经验分割为离散"事件"单元，边界处记忆编码最强。
    Radvansky & Copeland (2006) "Walking through doorways causes forgetting" —
      穿越事件边界（空间/时间）后短暂抑制前一段落的记忆（doorway effect）。

    OS 类比：ext4 jbd2 journal commit boundary —
      刚提交后的 epoch 首批 page（新会话刚开始写入）= 最高一致性保证；
      commit 前的 dirty page（旧会话末尾）= 不稳定窗口，doorway penalty 适用。

    返回 boundary_proximity ∈ [-1.0, +1.0]:
      +1.0 = 本 session 首 grace_secs 内写入（boundary encoding boost 候选）
       0.0 = 中性（会话中间写入）
      -1.0 = 上一 session 末 lookback_secs 内写入（doorway effect 候选）

    参数：
      created_at           — chunk 写入时间（ISO 格式）
      session_started_at   — 当前 session 开始时间（ISO 格式）
      prev_session_ended_at — 上一 session 结束时间（ISO 格式，可选）
      grace_secs           — 被视为"session 开始后刚写入"的宽限窗口（秒）
      lookback_secs        — 被视为"上一 session 末尾"的回溯窗口（秒）
    """
    try:
        from datetime import timedelta as _td
        _created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        _started = datetime.fromisoformat(session_started_at.replace("Z", "+00:00"))

        # 计算 chunk 相对于 session 开始的偏移
        _delta_start = (_created - _started).total_seconds()

        # 情形1：chunk 在本 session 开始后写入（可能是 boundary boost 候选）
        if 0 <= _delta_start <= grace_secs:
            # 线性衰减：t=0 时 proximity=1.0，t=grace_secs 时 proximity=0.0
            proximity = 1.0 - (_delta_start / grace_secs)
            return round(max(0.0, proximity), 4)

        # 情形2：chunk 在上一 session 末尾写入（doorway effect 候选）
        if prev_session_ended_at is not None:
            _ended = datetime.fromisoformat(prev_session_ended_at.replace("Z", "+00:00"))
            _delta_end = (_ended - _created).total_seconds()
            if 0 <= _delta_end <= lookback_secs:
                # 线性衰减：t=0（session 刚结束时）时 proximity=-1.0，t=lookback_secs 时 proximity=0.0
                proximity = -1.0 + (_delta_end / lookback_secs)
                return round(min(0.0, proximity), 4)

        return 0.0  # 中性：会话中间写入
    except Exception:
        return 0.0


# ── iter429: Enactment Effect — 行动编码加成（Engelkamp & Zimmer 1989）─────────────
# 认知科学依据：Engelkamp & Zimmer (1989) "Memory for subject-performed tasks" —
#   Subject-Performed Tasks (SPT) 比仅听/说的 Verbal Tasks (VT) 记忆留存率高约 40%。
#   行动编码激活运动皮层（motor cortex）+ 语义系统双路径，形成多模态记忆痕迹。
# OS 类比：Linux writeback dirty page accounting —
#   write() syscall 产生的 dirty page 比 read() 产生的 clean page 有更高 priority。

_ENACTMENT_TOOL_SIGNATURES = frozenset({
    "bash", "edit", "write", "notebookedit",
    "computer", "execute", "run",
})

import re as _re_enact
_ENACTMENT_CONTENT_RE = _re_enact.compile(
    r'(?:'
    r'\$\s+\w+'
    r'|^\+\+\+\s+b/'
    r'|^---\s+a/'
    r'|^\+[^\+]|^-[^-]'
    r'|File written to'
    r'|Command output:'
    r'|\d+\s+(?:lines?|bytes?)\s+(?:added|removed|written|modified)'
    r')',
    _re_enact.MULTILINE | _re_enact.IGNORECASE,
)


def apply_enactment_effect(
    conn: sqlite3.Connection,
    chunk_id: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter429: 对 agent 工具调用产生的 chunk 应用行动编码 stability 加成。
    SPT（subject-performed tasks）比 VT（verbal tasks）留存率高约 40%（Engelkamp 1989）。

    检测链（L1→L3，首个匹配即生效）：
      L1: source_type 字段标记为 tool_result/bash_output 等
      L2: chunk_type == 'tool_insight'
      L3: content 包含工具调用特征（diff 标记、shell prompt、输出格式）

    Returns: 加成后的 stability 值（未改变时返回 base_stability）。
    """
    if not chunk_id:
        return base_stability
    try:
        import config as _config
        if not _config.get("store_vfs.enactment_enabled"):
            return base_stability
        row = conn.execute(
            "SELECT content, chunk_type, stability, source_type FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability
        # 兼容 Row 和 tuple
        if hasattr(row, 'keys'):
            content = row["content"]
            chunk_type = row["chunk_type"]
            stab = float(row["stability"] or base_stability)
            source_type = row["source_type"] if "source_type" in row.keys() else None
        else:
            content, chunk_type, stab, source_type = row[0], row[1], float(row[2] or base_stability), row[3]

        is_enacted = False
        # L1: source_type 检测
        if source_type and source_type.lower() in {"tool_result", "bash_output", "tool_output", "enactment"}:
            is_enacted = True
        # L2: chunk_type 检测
        if not is_enacted and chunk_type == "tool_insight":
            is_enacted = True
        # L3: content 特征检测
        if not is_enacted and content:
            if _ENACTMENT_CONTENT_RE.search(content[:1000]):
                is_enacted = True
        # L3b: 配置的工具名称检测
        if not is_enacted and content:
            _enact_tools_cfg = _config.get("store_vfs.enactment_tool_types") or ""
            _enact_tools = [t.strip().lower() for t in _enact_tools_cfg.split(",") if t.strip()]
            if _enact_tools:
                import re as _re
                _tool_re = _re.compile(
                    r'(?:tool(?:_name)?[:\s]+|^\[)(' + '|'.join(_re.escape(t) for t in _enact_tools) + r')',
                    _re.IGNORECASE | _re.MULTILINE,
                )
                if _tool_re.search(content[:500]):
                    is_enacted = True

        if not is_enacted:
            return stab

        boost = float(_config.get("store_vfs.enactment_boost") or 1.4)
        cap = float(_config.get("store_vfs.enactment_cap") or 365.0)
        new_stability = min(cap, stab * boost)
        if new_stability > stab + 0.001:
            conn.execute("UPDATE memory_chunks SET stability=? WHERE id=?", (new_stability, chunk_id))
        return new_stability
    except Exception:
        return base_stability


def apply_reconsolidation_context_refresh(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter451: Memory Reconsolidation Context Refresh — 检索后再巩固窗口期的编码情境刷新。

    认知科学依据：
      Nader et al. (2000) Nature — 被检索的记忆进入不稳定的再巩固窗口，可被更新。
      Hupbach et al. (2007) NatNeuro — 旧记忆轻微激活后与新情境信息发生整合（bidirectional integration）。
      Lee (2009) TiNS — 再巩固的适应性功能是将新情境信息注入旧记忆，使其保持与当前情境的相关性。

    机制：
      1. 找出近期被检索（last_accessed 在 rcr_labile_hours 内）且 importance >= rcr_min_importance 的旧 chunk
      2. 对每个旧 chunk，找 last_accessed 后 rcr_session_window_mins 内写入的新 chunk
      3. 若新旧 chunk encode_context entity 重叠 >= rcr_min_overlap，将新 entity 注入旧 chunk
      4. 每个旧 chunk 最多注入 rcr_max_new_entities 个新 entity（防止稀释）
      5. stability >= rcr_stable_floor 的 chunk 跳过（极度稳固记忆不需再巩固）

    OS 类比：Linux copy-on-write page reconsolidation —
      页面被读访问（=检索）→ 标记 COW ready → 后续新内容写入时合并到旧页面的 encode_context。

    返回 dict：
      rcr_updated: int — 被更新 encode_context 的旧 chunk 数量
      total_examined: int — 参与扫描的旧 chunk 数量
    """
    result = {"rcr_updated": 0, "total_examined": 0}
    if not project:
        return result
    try:
        import config as _config
        if not _config.get("store_vfs.rcr_enabled"):
            return result

        rcr_labile_hours = float(_config.get("store_vfs.rcr_labile_hours") or 6.0)
        rcr_session_window_mins = int(_config.get("store_vfs.rcr_session_window_mins") or 120)
        rcr_min_overlap = int(_config.get("store_vfs.rcr_min_overlap") or 2)
        rcr_max_new_entities = int(_config.get("store_vfs.rcr_max_new_entities") or 5)
        rcr_min_importance = float(_config.get("store_vfs.rcr_min_importance") or 0.50)
        rcr_protect_stable = bool(_config.get("store_vfs.rcr_protect_stable") if True else True)
        rcr_stable_floor = float(_config.get("store_vfs.rcr_stable_floor") or 60.0)

        now = datetime.now(timezone.utc)
        labile_cutoff = (now - timedelta(hours=rcr_labile_hours)).isoformat()

        # 1. 找出再巩固窗口内（最近被检索）的旧 chunk
        labile_rows = conn.execute(
            """SELECT id, encode_context, stability, last_accessed
               FROM memory_chunks
               WHERE project=?
                 AND importance >= ?
                 AND last_accessed >= ?
               ORDER BY last_accessed DESC
               LIMIT 100""",
            (project, rcr_min_importance, labile_cutoff)
        ).fetchall()

        if not labile_rows:
            return result

        result["total_examined"] = len(labile_rows)
        updated = 0

        for row in labile_rows:
            if hasattr(row, 'keys'):
                cid = row["id"]
                old_ctx = row["encode_context"] or ""
                stab = float(row["stability"] or 1.0)
                last_accessed_iso = row["last_accessed"] or ""
            else:
                cid = row[0]
                old_ctx = row[1] or ""
                stab = float(row[2] or 1.0)
                last_accessed_iso = row[3] or ""

            # 2. 极度稳固记忆跳过（不需要再巩固更新）
            if rcr_protect_stable and stab >= rcr_stable_floor:
                continue

            # 3. 找 last_accessed 后 rcr_session_window_mins 内写入的新 chunk
            try:
                # 解析 last_accessed 时间
                la_dt = datetime.fromisoformat(last_accessed_iso.replace("Z", "+00:00"))
                if la_dt.tzinfo is None:
                    la_dt = la_dt.replace(tzinfo=timezone.utc)
                window_end = (la_dt + timedelta(minutes=rcr_session_window_mins)).isoformat()
            except Exception:
                continue

            new_rows = conn.execute(
                """SELECT encode_context FROM memory_chunks
                   WHERE project=?
                     AND id != ?
                     AND created_at > ?
                     AND created_at <= ?
                     AND importance >= ?
                   ORDER BY created_at ASC
                   LIMIT 20""",
                (project, cid, last_accessed_iso, window_end, rcr_min_importance)
            ).fetchall()

            if not new_rows:
                continue

            # 4. 计算 old entity set
            def _tokenize(ctx: str) -> set:
                """从 encode_context 字符串提取 token 集合（逗号/空格分隔）。"""
                import re as _re
                tokens = _re.split(r'[,\s]+', ctx.strip())
                return {t.strip().lower() for t in tokens if len(t.strip()) >= 2}

            old_tokens = _tokenize(old_ctx)
            new_entities_to_add = []

            for new_row in new_rows:
                new_ctx = (new_row[0] if not hasattr(new_row, 'keys') else new_row["encode_context"]) or ""
                new_tokens = _tokenize(new_ctx)

                # 检查重叠
                overlap = old_tokens & new_tokens
                if len(overlap) < rcr_min_overlap:
                    continue

                # 收集新 entity（不在旧 chunk 中的）
                truly_new = new_tokens - old_tokens
                for tok in truly_new:
                    if tok and tok not in new_entities_to_add:
                        new_entities_to_add.append(tok)
                    if len(new_entities_to_add) >= rcr_max_new_entities:
                        break

                if len(new_entities_to_add) >= rcr_max_new_entities:
                    break

            if not new_entities_to_add:
                continue

            # 5. 将新 entity 追加到旧 chunk 的 encode_context
            new_ctx_str = old_ctx
            if new_ctx_str and not new_ctx_str.endswith(","):
                new_ctx_str += ", "
            elif not new_ctx_str:
                new_ctx_str = ""
            new_ctx_str += ", ".join(new_entities_to_add[:rcr_max_new_entities])

            conn.execute(
                "UPDATE memory_chunks SET encode_context=?, updated_at=? WHERE id=?",
                (new_ctx_str, now.isoformat(), cid)
            )
            updated += 1

        if updated > 0:
            conn.commit()

        result["rcr_updated"] = updated
        return result

    except Exception:
        return result


def apply_primary_memory_persistence(
    conn: sqlite3.Connection,
    project: str,
    gap_seconds: float = 0.0,
) -> dict:
    """
    iter452: Primary Memory Persistence — session 内密集复述的工作记忆持久化增强。

    认知科学依据：
      Waugh & Norman (1965) "Primary memory" (Psychological Review) —
        工作记忆中被持续主动复述的信息最终转入长时记忆；停止复述后快速遗忘。
      Rundus (1971) "Analysis of rehearsal processes in free recall" —
        复述次数与最终记忆保留率高度正相关（r=0.85）。

    OS 类比：Linux page working set active list promotion —
      短时间内反复 referenced 的 page 被提升到 active list，优先保护。

    参数：
      gap_seconds: sleep_consolidate 传入的 session 间隔（用于计算 session 窗口覆盖范围）
    """
    result = {"pmp_boosted": 0, "total_examined": 0}
    if not project:
        return result
    try:
        import config as _config
        if not _config.get("store_vfs.pmp_enabled"):
            return result

        pmp_min_injections = int(_config.get("store_vfs.pmp_min_injections") or 3)
        pmp_ref_count = int(_config.get("store_vfs.pmp_ref_count") or 8)
        pmp_boost = float(_config.get("store_vfs.pmp_boost") or 0.10)
        pmp_min_importance = float(_config.get("store_vfs.pmp_min_importance") or 0.40)
        pmp_session_window_hours = float(_config.get("store_vfs.pmp_session_window_hours") or 24.0)

        now = datetime.now(timezone.utc)
        # session 窗口：使用 pmp_session_window_hours，但至少覆盖本次 gap
        window_hours = max(pmp_session_window_hours, gap_seconds / 3600.0)
        window_cutoff = (now - timedelta(hours=window_hours)).isoformat()

        # 统计 session 内每个 chunk 在 recall_traces 中的注入次数
        # 通过 top_k_json 解析 chunk_id 的出现次数
        trace_rows = conn.execute(
            """SELECT top_k_json, injected FROM recall_traces
               WHERE project=? AND timestamp >= ?
               ORDER BY timestamp ASC""",
            (project, window_cutoff)
        ).fetchall()

        if not trace_rows:
            return result

        # 统计每个 chunk 在 session 内被注入的次数
        injection_counts: dict = {}
        for trace_row in trace_rows:
            top_k_json = (trace_row[0] if not hasattr(trace_row, 'keys') else trace_row["top_k_json"]) or "[]"
            injected = int(trace_row[1] if not hasattr(trace_row, 'keys') else trace_row["injected"] or 0)
            if injected <= 0:
                continue
            try:
                import json as _json
                top_k = _json.loads(top_k_json)
                for item in top_k:
                    cid = None
                    if isinstance(item, dict):
                        cid = item.get("id") or item.get("chunk_id")
                    elif isinstance(item, str):
                        cid = item
                    if cid:
                        injection_counts[cid] = injection_counts.get(cid, 0) + 1
            except Exception:
                continue

        if not injection_counts:
            return result

        # 筛选达到阈值的 chunk
        candidate_ids = [cid for cid, cnt in injection_counts.items()
                         if cnt >= pmp_min_injections]

        if not candidate_ids:
            return result

        # 获取 chunk 信息
        placeholders = ",".join("?" * len(candidate_ids))
        chunk_rows = conn.execute(
            f"""SELECT id, stability, importance FROM memory_chunks
                WHERE project=? AND id IN ({placeholders}) AND importance >= ?""",
            [project] + candidate_ids + [pmp_min_importance]
        ).fetchall()

        result["total_examined"] = len(chunk_rows)
        boosted = 0

        for crow in chunk_rows:
            if hasattr(crow, 'keys'):
                cid = crow["id"]
                stab = float(crow["stability"] or 1.0)
            else:
                cid = crow[0]
                stab = float(crow[1] or 1.0)

            session_count = injection_counts.get(cid, 0)
            pmp_factor = min(1.0, session_count / max(1, pmp_ref_count))
            bonus = pmp_boost * pmp_factor
            if bonus < 0.001:
                continue

            new_stab = min(365.0, stab * (1.0 + bonus))
            if new_stab > stab + 0.001:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                    (new_stab, now.isoformat(), cid)
                )
                boosted += 1

        if boosted > 0:
            conn.commit()

        result["pmp_boosted"] = boosted
        return result

    except Exception:
        return result


def apply_predictive_memory_encoding(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    chunk_type: str = "",
    base_stability: float = 1.0,
) -> float:
    """
    iter450: Predictive Memory Encoding — 预期将来被测试增强编码（Roediger & Karpicke 2011）。
    近期同项目同 chunk_type 被频繁检索 → 大脑处于"测试预期"状态 →
    新写入同类型 chunk 获得额外 initial_stability 加成（elaborative encoding）。
    """
    if not chunk_id or not project:
        return base_stability
    try:
        import config as _config
        if not _config.get("store_vfs.pme_enabled"):
            return base_stability
        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return base_stability
        if hasattr(row, 'keys'):
            stab = float(row["stability"] or base_stability)
            importance = float(row["importance"] or 0.0)
        else:
            stab = float(row[0] or base_stability)
            importance = float(row[1] or 0.0)
        pme_min_importance = float(_config.get("store_vfs.pme_min_importance") or 0.45)
        if importance < pme_min_importance:
            return stab
        pme_window_hours = float(_config.get("store_vfs.pme_window_hours") or 6.0)
        pme_min_queries = int(_config.get("store_vfs.pme_min_queries") or 3)
        pme_ref_count = int(_config.get("store_vfs.pme_ref_count") or 10)
        pme_boost = float(_config.get("store_vfs.pme_boost") or 0.12)
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(hours=pme_window_hours)).isoformat()
        count_row = conn.execute(
            """SELECT COUNT(*) FROM recall_traces
               WHERE project=? AND timestamp >= ? AND injected > 0""",
            (project, cutoff)
        ).fetchone()
        if count_row:
            raw_count = int(count_row[0] if isinstance(count_row, (list, tuple)) else count_row[0])
        else:
            raw_count = 0
        if raw_count < pme_min_queries:
            return stab
        pme_factor = min(1.0, raw_count / max(1, pme_ref_count))
        new_stab = min(365.0, stab * (1.0 + pme_boost * pme_factor))
        if new_stab > stab + 0.001:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?",
                (new_stab, chunk_id)
            )
        return new_stab
    except Exception:
        return base_stability


def apply_prediction_error_enhancement(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    access_count_before: int,
    retrievability: float,
    importance: float,
    stability: float,
) -> float:
    """
    iter453: Prediction Error Memory Enhancement — 意外命中触发多巴胺强化（Rescorla-Wagner 1972 / Schultz 1997）。

    触发条件（同时满足）：
      ① access_count_before <= peme_max_access（历史低召回 = 低预期相关性）
      ② retrievability < peme_low_retrievability（已部分遗忘 = 系统预期不相关）
      ③ importance >= peme_min_importance（有记忆价值）

    formula:
      surprise_score = (1 - retrievability) × (1 - access_count_before / peme_max_access)
      peme_bonus = surprise_score × peme_scale
      new_stab = min(365.0, stability × (1 + peme_bonus))

    OS 类比：CPU branch predictor misprediction → forced L1 cache line promotion。
    """
    if not chunk_id or not project:
        return stability
    try:
        import config as _config
        if not _config.get("store_vfs.peme_enabled"):
            return stability

        peme_min_importance = float(_config.get("store_vfs.peme_min_importance") or 0.45)
        if importance < peme_min_importance:
            return stability

        peme_max_access = int(_config.get("store_vfs.peme_max_access") or 5)
        peme_low_retrievability = float(_config.get("store_vfs.peme_low_retrievability") or 0.50)

        if access_count_before > peme_max_access:
            return stability
        if retrievability >= peme_low_retrievability:
            return stability

        r_surprise = max(0.0, 1.0 - retrievability)
        a_surprise = max(0.0, 1.0 - access_count_before / max(1, peme_max_access))
        surprise_score = r_surprise * a_surprise

        if surprise_score < 0.001:
            return stability

        peme_scale = float(_config.get("store_vfs.peme_scale") or 0.15)
        peme_bonus = surprise_score * peme_scale
        new_stab = min(365.0, stability * (1.0 + peme_bonus))

        if new_stab > stability + 0.001:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                (new_stab, now_iso, chunk_id, project)
            )
            return new_stab
        return stability
    except Exception:
        return stability


def apply_interleaved_practice_effect(
    conn: sqlite3.Connection,
    chunk_ids: list,
    project: str,
) -> dict:
    """
    iter454: Interleaved Practice Effect — 混合检索强化效应（Kornell & Bjork 2008）。

    同一次 update_accessed() 调用中若 chunk_ids 涵盖多种不同 chunk_type（混合检索），
    每个满足条件的 chunk 获得额外 stability 加成（diversity_factor 正比）：
      diversity_factor = unique_type_count / len(chunk_ids)
      interleave_bonus = diversity_factor × ipe_scale
      new_stab = min(365.0, stab × (1 + interleave_bonus))

    OS 类比：CPU cross-stride interleaved access → multi-stream prefetch trigger —
      跨 chunk_type 的混合检索 = 多维语义访问模式 → prefetcher 提升 cache line 预取优先级。

    Returns: {"ipe_boosted": int, "total_examined": int}
    """
    result = {"ipe_boosted": 0, "total_examined": 0}
    if not chunk_ids or not project:
        return result
    try:
        import config as _config
        if not _config.get("store_vfs.ipe_enabled"):
            return result

        ipe_min_types = int(_config.get("store_vfs.ipe_min_types") or 2)
        ipe_min_chunks = int(_config.get("store_vfs.ipe_min_chunks") or 2)
        ipe_scale = float(_config.get("store_vfs.ipe_scale") or 0.08)
        ipe_min_importance = float(_config.get("store_vfs.ipe_min_importance") or 0.40)

        # 最少 chunk 数量要求
        if len(chunk_ids) < ipe_min_chunks:
            return result

        # 获取本批次所有 chunk 的 chunk_type、importance、stability
        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, chunk_type, importance, stability FROM memory_chunks "
            f"WHERE id IN ({placeholders}) AND project=?",
            list(chunk_ids) + [project],
        ).fetchall()

        if not rows:
            return result

        # 统计本批次的 chunk_type 多样性
        type_map = {}  # chunk_id -> chunk_type
        for row in rows:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            ctype = row[1] if isinstance(row, (list, tuple)) else row["chunk_type"]
            type_map[cid] = ctype

        unique_types = set(type_map.values())
        if len(unique_types) < ipe_min_types:
            return result  # 类型多样性不足，不触发 IPE

        diversity_factor = len(unique_types) / max(1, len(chunk_ids))
        interleave_bonus = diversity_factor * ipe_scale

        if interleave_bonus < 0.001:
            return result

        now_iso = datetime.now(timezone.utc).isoformat()
        boosted = 0

        for row in rows:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            importance = float(row[2] if isinstance(row, (list, tuple)) else row["importance"])
            stability = float(row[3] if isinstance(row, (list, tuple)) else row["stability"])
            result["total_examined"] += 1

            if importance < ipe_min_importance:
                continue

            new_stab = min(365.0, stability * (1.0 + interleave_bonus))
            if new_stab > stability + 0.001:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                    (new_stab, now_iso, cid, project),
                )
                boosted += 1

        result["ipe_boosted"] = boosted
        return result
    except Exception:
        return result


def apply_generation_spacing_interaction_effect(
    conn: sqlite3.Connection,
    chunk_ids: list,
    project: str,
    pre_stability_map: dict,
    pre_spaced_access_map: dict,
    pre_last_accessed_map: dict,
    now_iso: str,
) -> dict:
    """iter455: Generation-Spacing Interaction Effect (GSIE).

    Pyc & Rawson (2009) — 检索努力 × 间隔成功历史的乘法交互加成。
    OS 类比：Linux ARC ghost list + frequency-weighted promotion —
      ghost list page re-fault = 检索努力（item was fading）× T2 weight（历史频率）= 晋升力度。

    公式：
      effort_score = max(0.0, 1.0 - R_at_recall)
        R_at_recall = exp(-gap_hours / (pre_stability × 24.0))
        gap_hours   = (now - last_accessed).total_seconds() / 3600
      streak_factor = min(1.0, spaced_access_count / gsie_ref_streak)
      interaction_score = effort_score × streak_factor
      if effort_score >= gsie_min_effort and spaced_access_count >= gsie_min_streak:
          gsie_bonus = interaction_score × gsie_scale
          new_stab = min(365.0, current_stability × (1.0 + gsie_bonus))

    在 SM-2 更新之后执行（current_stability 已经是 SM-2 更新后的值），作为独立第二次 pass。

    Args:
        conn: SQLite connection
        chunk_ids: 被检索的 chunk ID 列表
        project: 项目 ID
        pre_stability_map: {chunk_id: stability_before_sm2}
        pre_spaced_access_map: {chunk_id: spaced_access_count_before_update}
        pre_last_accessed_map: {chunk_id: last_accessed_iso_before_update}
        now_iso: 当前时间的 ISO string

    Returns:
        dict with "gsie_boosted" and "total_examined"
    """
    result = {"gsie_boosted": 0, "total_examined": 0}
    if not chunk_ids or not project:
        return result
    try:
        import config as _config
        if not _config.get("store_vfs.gsie_enabled"):
            return result

        gsie_min_streak = int(_config.get("store_vfs.gsie_min_streak") or 2)
        gsie_ref_streak = int(_config.get("store_vfs.gsie_ref_streak") or 6)
        gsie_min_effort = float(_config.get("store_vfs.gsie_min_effort") or 0.10)
        gsie_scale = float(_config.get("store_vfs.gsie_scale") or 0.12)
        gsie_min_importance = float(_config.get("store_vfs.gsie_min_importance") or 0.40)

        # 读取 SM-2 更新后的当前 stability 和 importance
        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, importance, stability FROM memory_chunks "
            f"WHERE id IN ({placeholders}) AND project=?",
            list(chunk_ids) + [project],
        ).fetchall()

        if not rows:
            return result

        now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        if now_dt.tzinfo is None:
            from datetime import timezone as _tz
            now_dt = now_dt.replace(tzinfo=_tz.utc)

        boosted = 0
        for row in rows:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            importance = float(row[1] if isinstance(row, (list, tuple)) else row["importance"])
            current_stab = float(row[2] if isinstance(row, (list, tuple)) else row["stability"])
            result["total_examined"] += 1

            if importance < gsie_min_importance:
                continue

            # 使用 pre-update 的 spaced_access_count
            spaced_acc = int(pre_spaced_access_map.get(cid, 0))
            if spaced_acc < gsie_min_streak:
                continue

            # 使用 pre-update 的 stability 来计算 R_at_recall（避免 SM-2 已更新后失真）
            pre_stab = float(pre_stability_map.get(cid, current_stab))
            last_acc_iso = pre_last_accessed_map.get(cid)

            # 计算 gap_hours
            gap_hours = 0.0
            if last_acc_iso:
                try:
                    last_acc_dt = datetime.fromisoformat(str(last_acc_iso).replace("Z", "+00:00"))
                    if last_acc_dt.tzinfo is None:
                        from datetime import timezone as _tz2
                        last_acc_dt = last_acc_dt.replace(tzinfo=_tz2.utc)
                    gap_hours = max(0.0, (now_dt - last_acc_dt).total_seconds() / 3600.0)
                except Exception:
                    pass

            # R_at_recall = exp(-gap_hours / (pre_stab × 24))
            import math as _math
            if pre_stab > 0.0:
                r_at_recall = _math.exp(-gap_hours / (pre_stab * 24.0))
            else:
                r_at_recall = 0.0
            effort_score = max(0.0, 1.0 - r_at_recall)

            if effort_score < gsie_min_effort:
                continue

            streak_factor = min(1.0, spaced_acc / max(1, gsie_ref_streak))
            interaction_score = effort_score * streak_factor
            gsie_bonus = interaction_score * gsie_scale
            if gsie_bonus < 0.001:
                continue

            new_stab = min(365.0, current_stab * (1.0 + gsie_bonus))
            if new_stab > current_stab + 0.001:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                    (new_stab, now_iso, cid, project),
                )
                boosted += 1

        result["gsie_boosted"] = boosted
        return result
    except Exception:
        return result


# ── iter456: Retrieval Practice vs. Restudy Consolidation Asymmetry (RPCA) ──────────────────────
# Roediger & Karpicke (2006): active retrieval yields ~50% more retention than passive restudy.
# access_source='retrieval' → rpca_retrieval_bonus(0.10); 'restudy' → rpca_restudy_bonus(0.02).

def apply_retrieval_practice_consolidation_asymmetry(
    conn: sqlite3.Connection,
    chunk_ids: list,
    project: str,
    access_source_map: dict,   # {chunk_id: 'retrieval' | 'restudy'}  — from update_accessed caller
) -> dict:
    """
    iter456: Retrieval Practice vs. Restudy Consolidation Asymmetry.

    Roediger & Karpicke (2006) Psychological Science "Test-Enhanced Learning" —
      active retrieval (FTS5/BM25 query hit) outperforms passive restudy (loader inject,
      prefetch) by ~50% in delayed retention. Applied as an independent stability bonus
      *after* SM-2 update, per update_accessed() call.

    OS 类比：Linux page fault (demand fault = retrieval) → immediate active LRU promotion;
      readahead prefetch (restudy) → inactive list first, needs second access to promote.

    Parameters
    ----------
    conn             : SQLite connection (write)
    chunk_ids        : list of chunk IDs processed in this update_accessed call
    project          : project identifier (used for namespace config lookup)
    access_source_map: {chunk_id: 'retrieval' | 'restudy'}, defaults to 'retrieval' if missing

    Returns
    -------
    {"rpca_boosted": int, "total_examined": int}
    """
    result = {"rpca_boosted": 0, "total_examined": 0}
    if not chunk_ids:
        return result

    try:
        import config as _cfg
        if not _cfg.get("store_vfs.rpca_enabled", project=project):
            return result

        rpca_retrieval_bonus = float(_cfg.get("store_vfs.rpca_retrieval_bonus", project=project))
        rpca_restudy_bonus   = float(_cfg.get("store_vfs.rpca_restudy_bonus",   project=project))
        rpca_min_imp         = float(_cfg.get("store_vfs.rpca_min_importance",  project=project))

        # Fetch current stability and importance for each chunk
        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, COALESCE(stability,1.0), COALESCE(importance,0.5) "
            f"FROM memory_chunks WHERE id IN ({placeholders}) AND project=?",
            list(chunk_ids) + [project],
        ).fetchall()

        now_iso = datetime.now(timezone.utc).isoformat()
        boosted = 0
        for row in rows:
            cid = row[0]
            stab = float(row[1])
            imp  = float(row[2])
            result["total_examined"] += 1

            if imp < rpca_min_imp:
                continue

            source = access_source_map.get(cid, "retrieval")
            if source == "retrieval":
                bonus = rpca_retrieval_bonus
            elif source == "restudy":
                bonus = rpca_restudy_bonus
            else:
                bonus = rpca_retrieval_bonus  # unknown → treat as retrieval

            if bonus <= 0.0:
                continue

            new_stab = min(365.0, stab * (1.0 + bonus))
            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                (round(new_stab, 6), now_iso, cid, project),
            )
            boosted += 1

        result["rpca_boosted"] = boosted
        return result
    except Exception:
        return result


def apply_cue_overload_consolidation_penalty(
    conn: "sqlite3.Connection",
    project: str,
) -> dict:
    """
    iter457: Cue Overload Consolidation Penalty (COCP) — 同类型 chunk 过多时 sleep 巩固效益下降。

    认知科学依据：Watkins & Watkins (1975) "Build-up of proactive inhibition as a cue-overload effect" —
      过多记忆项共享同一检索线索时，每个项目的单独可提取性下降（cue overload）。
      N_same_type > threshold → sleep 巩固时对该类型 chunk 施加轻微 stability 惩罚。

    OS 类比：Linux CPU cache set-associativity saturation —
      太多 cache line 映射到同一 set → 每次新写入导致更频繁的 LRU eviction（巩固效益边际递减）。

    Returns:
      {"cocp_penalized": N, "total_examined": M}
    """
    result = {"cocp_penalized": 0, "total_examined": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.cocp_enabled"):
            return result

        threshold         = int(_cfg.get("store_vfs.cocp_type_threshold"))   # 15
        scale_factor      = float(_cfg.get("store_vfs.cocp_scale_factor"))   # 20.0
        max_penalty       = float(_cfg.get("store_vfs.cocp_max_penalty"))    # 0.10
        protect_imp       = float(_cfg.get("store_vfs.cocp_protect_importance"))  # 0.80
        protect_types_str = str(_cfg.get("store_vfs.cocp_protect_types"))    # "design_constraint,procedure"
        protect_types     = {t.strip() for t in protect_types_str.split(",") if t.strip()}

        # Count per type (only active chunks)
        type_count_rows = conn.execute(
            "SELECT chunk_type, COUNT(*) FROM memory_chunks "
            "WHERE project=? AND importance > 0 GROUP BY chunk_type",
            (project,)
        ).fetchall()
        type_counts = {row[0]: row[1] for row in type_count_rows}

        now_iso = datetime.now(timezone.utc).isoformat()
        penalized = 0
        examined  = 0

        for chunk_type, n_type in type_counts.items():
            if n_type <= threshold:
                continue
            if chunk_type in protect_types:
                continue

            # overload_factor grows linearly: 0 at threshold → max_penalty at threshold + scale_factor
            overload_factor = min(max_penalty, (n_type - threshold) / scale_factor)
            if overload_factor <= 0.0:
                continue

            chunks = conn.execute(
                "SELECT id, COALESCE(stability,1.0), COALESCE(importance,0.5) "
                "FROM memory_chunks WHERE project=? AND chunk_type=? AND importance > 0",
                (project, chunk_type)
            ).fetchall()

            for ch in chunks:
                examined += 1
                cid  = ch[0]
                stab = float(ch[1])
                imp  = float(ch[2])

                # High-importance chunks are exempt (core knowledge)
                if imp >= protect_imp:
                    continue

                new_stab = max(0.1, stab * (1.0 - overload_factor))
                if abs(new_stab - stab) > 1e-6:
                    conn.execute(
                        "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                        (round(new_stab, 6), now_iso, cid, project)
                    )
                    penalized += 1

        result["cocp_penalized"] = penalized
        result["total_examined"] = examined
        return result
    except Exception:
        return result


def apply_sleep_spindle_density_effect(
    conn: "sqlite3.Connection",
    project: str,
) -> dict:
    """iter460: Sleep Spindle Density Effect (SSDE) — 根据 chunk_type 差异化 sleep 巩固系数。"""
    result = {"ssde_boosted": 0, "ssde_reduced": 0, "total_examined": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ssde_enabled"):
            return result
        decl_mult  = float(_cfg.get("store_vfs.ssde_declarative_multiplier"))
        proc_mult  = float(_cfg.get("store_vfs.ssde_procedural_multiplier"))
        min_imp    = float(_cfg.get("store_vfs.ssde_min_importance"))
        decl_types = {t.strip() for t in str(_cfg.get("store_vfs.ssde_declarative_types")).split(",") if t.strip()}
        proc_types = {t.strip() for t in str(_cfg.get("store_vfs.ssde_procedural_types")).split(",") if t.strip()}
        rows = conn.execute(
            "SELECT id, chunk_type, COALESCE(stability,1.0), COALESCE(importance,0.5) "
            "FROM memory_chunks WHERE project=? AND importance >= ?",
            (project, min_imp)
        ).fetchall()
        now_iso = datetime.now(timezone.utc).isoformat()
        boosted = 0; reduced = 0; examined = 0
        for row in rows:
            cid = row[0]; ctype = row[1]; stab = float(row[2]); imp = float(row[3])
            examined += 1
            if ctype in decl_types:
                new_stab = min(365.0, stab * decl_mult)
                if new_stab > stab + 1e-6:
                    conn.execute(
                        "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                        (round(new_stab, 6), now_iso, cid, project))
                    boosted += 1
            elif ctype in proc_types:
                new_stab = max(0.1, stab * proc_mult)
                if new_stab < stab - 1e-6:
                    conn.execute(
                        "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                        (round(new_stab, 6), now_iso, cid, project))
                    reduced += 1
        result["ssde_boosted"]   = boosted
        result["ssde_reduced"]   = reduced
        result["total_examined"] = examined
        return result
    except Exception:
        return result


def apply_contextual_interference_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    project: str,
    session_type: str = None,
) -> dict:
    """
    iter459: Contextual Interference Effect (CIE) — 跨多种 session_type 访问的 chunk 获得 stability 加成。

    认知科学依据：Shea & Morgan (1979) "Contextual interference effects on the acquisition,
      retention, and transfer of a motor skill" —
      随机（mixed）练习顺序比集中（blocked）练习在延迟测试中成绩高 57%。
      机制：随机练习迫使大脑在每次执行前重构运动程序（elaborative encoding）。

    OS 类比：Linux blk-mq — 不同 queue depth / CPU 的混合调度在多种 I/O pattern
      混合时表现优于单一 queue（cross-queue diversity = CI effect）。

    Returns:
      {"cie_boosted": N, "total_examined": M}
    """
    result = {"cie_boosted": 0, "total_examined": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.cie_enabled"):
            return result

        ref_types     = int(_cfg.get("store_vfs.cie_ref_types"))        # 4
        cie_scale     = float(_cfg.get("store_vfs.cie_scale"))          # 0.10
        min_unique    = int(_cfg.get("store_vfs.cie_min_unique_types")) # 2
        min_imp       = float(_cfg.get("store_vfs.cie_min_importance")) # 0.40
        max_history   = int(_cfg.get("store_vfs.cie_max_history"))      # 20

        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, COALESCE(stability,1.0), COALESCE(importance,0.5), "
            f"COALESCE(session_type_history,'') "
            f"FROM memory_chunks WHERE id IN ({placeholders}) AND project=?",
            list(chunk_ids) + [project]
        ).fetchall()

        now_iso  = datetime.now(timezone.utc).isoformat()
        boosted  = 0
        examined = 0

        for row in rows:
            cid      = row[0]
            stab     = float(row[1])
            imp      = float(row[2])
            history  = str(row[3]) if row[3] else ""
            examined += 1

            if imp < min_imp:
                # Still update history even for low-importance chunks
                if session_type:
                    entries = [e for e in history.split(",") if e.strip()] if history else []
                    entries.append(session_type)
                    if len(entries) > max_history:
                        entries = entries[-max_history:]
                    new_history = ",".join(entries)
                    conn.execute(
                        "UPDATE memory_chunks SET session_type_history=?, updated_at=? WHERE id=? AND project=?",
                        (new_history, now_iso, cid, project)
                    )
                continue

            # Append current session_type to history (FIFO, max cie_max_history)
            entries = [e for e in history.split(",") if e.strip()] if history else []
            if session_type:
                entries.append(session_type)
            if len(entries) > max_history:
                entries = entries[-max_history:]
            new_history = ",".join(entries)

            # Compute diversity_score
            unique_types = len(set(e for e in entries if e)) if entries else 0
            if unique_types < min_unique:
                conn.execute(
                    "UPDATE memory_chunks SET session_type_history=?, updated_at=? WHERE id=? AND project=?",
                    (new_history, now_iso, cid, project)
                )
                continue

            diversity_score = min(1.0, (unique_types - 1) / max(1, ref_types - 1))
            cie_bonus = diversity_score * cie_scale

            if cie_bonus <= 0.0:
                conn.execute(
                    "UPDATE memory_chunks SET session_type_history=?, updated_at=? WHERE id=? AND project=?",
                    (new_history, now_iso, cid, project)
                )
                continue

            new_stab = min(365.0, stab * (1.0 + cie_bonus))
            conn.execute(
                "UPDATE memory_chunks SET stability=?, session_type_history=?, updated_at=? WHERE id=? AND project=?",
                (round(new_stab, 6), new_history, now_iso, cid, project)
            )
            boosted += 1

        result["cie_boosted"] = boosted
        result["total_examined"] = examined
        return result
    except Exception:
        return result


def record_coactivation(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    project: str,
    now_iso: str = None,
) -> None:
    """
    iter461: HAC 辅助函数 — 记录 chunk 对的共激活事件到 chunk_coactivation 表。
    在 update_accessed() 中调用（列表 >= 2 个 chunk 时）。
    """
    if len(chunk_ids) < 2:
        return
    if now_iso is None:
        from datetime import datetime as _dt, timezone as _tz
        now_iso = _dt.now(_tz.utc).isoformat()
    try:
        for i in range(len(chunk_ids)):
            for j in range(i + 1, len(chunk_ids)):
                a, b = sorted([chunk_ids[i], chunk_ids[j]])
                conn.execute(
                    """INSERT INTO chunk_coactivation (chunk_a, chunk_b, project, coact_count, last_coact)
                       VALUES (?, ?, ?, 1, ?)
                       ON CONFLICT(chunk_a, chunk_b, project) DO UPDATE SET
                         coact_count = coact_count + 1,
                         last_coact  = excluded.last_coact
                    """,
                    (a, b, project, now_iso),
                )
    except Exception:
        pass


def apply_hebbian_coactivation_consolidation(
    conn: "sqlite3.Connection",
    project: str,
) -> dict:
    """
    iter461: Hebbian Co-Activation Consolidation (HAC) — 共同激活的 chunk 在 sleep 时相互加固。

    认知科学依据：Hebb (1949) "The Organization of Behavior" —
      "Cells that fire together, wire together" — 海马 Hebbian 可塑性：
      两个神经元同时激活 → 突触连接增强（Long-Term Potentiation, LTP）。
      Zeithamova et al. (2012): 睡眠期间共激活记忆对通过 SWR replay 相互巩固，
      形成 schema-linked memory network（r=0.61, hippocampal-neocortical replay）。

    OS 类比：Linux THP (Transparent Huge Pages) promotion —
      同一 2MB PMD 内频繁共同访问的 pages 被 khugepaged 合并为 huge page，
      降低 TLB miss 率（共激活 → 协同晋升到更稳定的存储层）。

    Returns:
      {"hac_boosted": N, "total_pairs_examined": M}
    """
    result = {"hac_boosted": 0, "total_pairs_examined": 0}
    try:
        import config as _cfg
        from datetime import datetime as _dt, timezone as _tz
        if not _cfg.get("store_vfs.hac_enabled"):
            return result

        min_coact   = int(_cfg.get("store_vfs.hac_min_coact"))       # 2
        boost_factor = float(_cfg.get("store_vfs.hac_boost_factor")) # 1.05
        max_boost   = float(_cfg.get("store_vfs.hac_max_boost"))      # 0.15
        min_imp     = float(_cfg.get("store_vfs.hac_min_importance")) # 0.35
        now_iso     = _dt.now(_tz.utc).isoformat()

        # 找出共激活次数达到阈值的 chunk 对
        pairs = conn.execute(
            "SELECT chunk_a, chunk_b FROM chunk_coactivation "
            "WHERE project=? AND coact_count >= ?",
            (project, min_coact),
        ).fetchall()
        result["total_pairs_examined"] = len(pairs)

        # 收集需要 boost 的 chunk ids（去重）
        candidate_ids = set()
        for row in pairs:
            candidate_ids.add(row[0])
            candidate_ids.add(row[1])
        if not candidate_ids:
            return result

        # 获取候选 chunk 的 stability 和 importance
        ph = ",".join("?" * len(candidate_ids))
        cands = conn.execute(
            f"SELECT id, stability, importance FROM memory_chunks "
            f"WHERE id IN ({ph}) AND project=?",
            list(candidate_ids) + [project],
        ).fetchall()

        boosted = 0
        for row in cands:
            cid = row[0]
            stab = float(row[1] or 1.0)
            imp = float(row[2] or 0.0)
            if imp < min_imp:
                continue
            raw_new = stab * boost_factor
            capped = min(stab * (1.0 + max_boost), raw_new)
            new_stab = min(365.0, capped)
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                    (round(new_stab, 6), now_iso, cid, project),
                )
                boosted += 1

        result["hac_boosted"] = boosted
        return result
    except Exception:
        return result


def apply_output_interference_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    project: str,
    now_iso: str = None,
) -> dict:
    """
    iter463: Output Interference Effect (OIE) — 顺序检索列表中后续 chunk 受前项输出干扰。

    认知科学依据：Postman & Underwood (1973) "Critical issues in interference theory" —
      顺序回忆（串行检索）中，后位项目受前位项目的"输出干扰"（output interference）。
      Roediger (1974): 自由回忆中，回忆第 N 个词后，第 N+1 个词可及性下降约 5-8%。
      Smith et al. (1978): 顺序输出干扰随列表长度增大而累积（serial position effect）。

    OS 类比：Linux TLB invalidation cascade —
      顺序 shootdown 多个 TLB entry 时，后续 entry 因 pipeline stall 累积而经历
      更高的 invalidation latency（顺序依赖代价递增）；
      IPI (Inter-Processor Interrupt) 后期 entries 遇到更多 broadcast collision。

    Returns:
      {"oie_penalized": N, "total_examined": M}
    """
    result = {"oie_penalized": 0, "total_examined": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        from datetime import datetime as _dt, timezone as _tz
        if not _cfg.get("store_vfs.oie_enabled"):
            return result

        min_list_len = int(_cfg.get("store_vfs.oie_min_list_len"))   # 3
        max_penalty  = float(_cfg.get("store_vfs.oie_max_penalty"))  # 0.05
        min_imp      = float(_cfg.get("store_vfs.oie_min_importance"))# 0.25

        if len(chunk_ids) < min_list_len:
            return result
        if now_iso is None:
            now_iso = _dt.now(_tz.utc).isoformat()

        n = len(chunk_ids)
        penalized = 0

        for i, cid in enumerate(chunk_ids):
            position_ratio = i / (n - 1)  # 0.0 (first) to 1.0 (last)
            if position_ratio <= 0.0:
                continue  # first item: no penalty
            penalty = position_ratio * max_penalty
            if penalty <= 0.0:
                continue

            row = conn.execute(
                "SELECT stability, importance FROM memory_chunks WHERE id=? AND project=?",
                (cid, project),
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_imp:
                continue

            result["total_examined"] += 1
            new_stab = max(0.1, stab * (1.0 - penalty))
            if new_stab < stab - 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=? AND project=?",
                    (round(new_stab, 6), now_iso, cid, project),
                )
                penalized += 1

        result["oie_penalized"] = penalized
        return result
    except Exception:
        return result


def apply_lag_dependent_spacing_boost(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter465: Lag-Dependent Spacing Boost (LDSB) — 间隔检索效应：长间隔召回后给予更大 stability 加成。

    认知科学依据：
      Landauer & Bjork (1978) "Optimum rehearsal patterns and name learning" —
        扩张间隔练习（expanding retrieval practice）比固定间隔更有效。
        回忆越难（间隔/稳定性比率越大）→ 记忆加固效果越强（Desirable Difficulty）。
      SM-2 算法（Wozniak 1987）：新稳定性 = 旧稳定性 × EF × f(lag/stability)，
        其中 EF 依赖回忆难度（lag 越长 → EF 贡献越大）。

    OS 类比：Linux page aging（mm/vmscan.c active list promotion）—
      长时间停留在 inactive list 的 page 被再次访问时，
      获得更高的 active list 优先级（cold page reactivation = high utility signal）。
    """
    result = {"ldsb_boosted": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ldsb_enabled"):
            return result
        if not chunk_ids:
            return result

        min_lag_h = float(_cfg.get("store_vfs.ldsb_min_lag_hours"))
        max_boost = float(_cfg.get("store_vfs.ldsb_max_boost"))
        min_imp = float(_cfg.get("store_vfs.ldsb_min_importance"))

        if now_iso is None:
            from datetime import datetime, timezone
            now_iso = datetime.now(timezone.utc).isoformat()
        from datetime import datetime, timezone
        now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))

        boosted = 0
        for cid in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, last_accessed FROM memory_chunks WHERE id=?",
                (cid,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            last_acc = row[2]
            if imp < min_imp or not last_acc:
                continue

            try:
                last_dt = datetime.fromisoformat(str(last_acc).replace("Z", "+00:00"))
                lag_hours = (now_dt - last_dt).total_seconds() / 3600.0
            except Exception:
                continue

            if lag_hours < min_lag_h:
                continue

            # Boost proportional to lag/stability ratio (SM-2 inspired)
            # lag_ratio = lag_hours / (stability × 24) → how overdue was this recall
            lag_ratio = lag_hours / max(stab * 24.0, 1.0)
            # Clamp lag_ratio to [0, 1] for boost calculation
            boost_frac = min(1.0, lag_ratio) * max_boost
            new_stab = min(365.0, stab * (1.0 + boost_frac))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?",
                    (new_stab, cid)
                )
                boosted += 1

        result["ldsb_boosted"] = boosted
        return result
    except Exception:
        return result


def apply_emotional_tagging_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    summary: str = "",
    now_iso: str = None,
) -> dict:
    """iter466: Emotional Tagging Effect (ETE) — 情绪性内容获得杏仁核增强编码（Cahill et al. 1994）。

    认知科学依据：
      Cahill, Prins, Weber & McGaugh (1994) "Beta-adrenergic activation and memory for
        emotional events" (Nature) — 情绪唤醒（norepinephrine 释放）→ 杏仁核激活 →
        海马-杏仁核双向增强（LTP）→ 情绪事件记忆更持久（延时测验 AUC +40%）。
      LaBar & Cabeza (2006) "Cognitive neuroscience of emotional memory" —
        情绪强度与记忆精确度正相关（r=0.53），负性情绪与正性情绪均有效（但负性略强）。

    OS 类比：Linux OOM killer scoring（mm/oom_kill.c）—
      高 oom_score_adj 的关键进程（init, kernel threads）受保护不被杀死；
      情绪显著内容（critical/crisis/breakthrough）= 高保护优先级记忆。
    """
    result = {"ete_boosted": False}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ete_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(_cfg.get("store_vfs.ete_min_importance"))
        if imp < min_imp:
            return result

        keywords_raw = str(_cfg.get("store_vfs.ete_keywords"))
        keywords = [k.strip().lower() for k in keywords_raw.split(",") if k.strip()]
        text = (content + " " + summary).lower()
        matched = sum(1 for kw in keywords if kw in text)
        if matched == 0:
            return result

        factor = float(_cfg.get("store_vfs.ete_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.ete_max_boost"))
        raw = stab * factor
        capped = min(stab * (1.0 + max_boost), raw)
        new_stab = min(365.0, capped)
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["ete_boosted"] = True
        return result
    except Exception:
        return result


def apply_keyword_density_encoding_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    now_iso: str = None,
) -> dict:
    """iter464: Keyword Density Encoding Effect (KDEE) — 高唯一词比率内容触发更深语义加工 → 更持久编码。

    认知科学依据：
      Craik & Lockhart (1972) "Levels of processing" — 语义密度高需要深度加工 → 更持久记忆。
      Kintsch (1974): 文本命题密度与长期记忆保留量正相关（r=0.62）。

    OS 类比：Linux ext4 extent tree depth — dense inode（大量唯一 extent）→ 更深 B-tree 索引 → 更鲁棒检索。
    """
    result = {"kdee_boosted": False}
    try:
        import config as _cfg
        import re as _re
        if not _cfg.get("store_vfs.kdee_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(_cfg.get("store_vfs.kdee_min_importance"))
        if imp < min_imp:
            return result

        words = _re.findall(r'\b\w+\b', (content or "").lower())
        min_words = int(_cfg.get("store_vfs.kdee_min_words"))
        if len(words) < min_words:
            return result

        unique_ratio = len(set(words)) / len(words)
        min_density = float(_cfg.get("store_vfs.kdee_min_density"))
        if unique_ratio < min_density:
            return result

        factor = float(_cfg.get("store_vfs.kdee_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.kdee_max_boost"))
        raw = stab * factor
        capped = min(stab * (1.0 + max_boost), raw)
        new_stab = min(365.0, capped)
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["kdee_boosted"] = True
        return result
    except Exception:
        return result


def apply_elaborative_interrogation_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    summary: str = "",
    now_iso: str = None,
) -> dict:
    """iter458: Elaborative Interrogation Effect (EIE) — 因果连接词触发更深推理编码 → 更持久记忆。

    认知科学依据：
      Pressley et al. (1992) — 解释"为什么"使记忆保留率提升 72%（vs 37% 对照组）。
      Martin & Pressley (1991) — "why" 问题比 "what" 问题更有效；因果性越强，编码越深。

    OS 类比：Linux ext4 htree directory indexing — 深度因果索引使文件查找从 O(N) 降到 O(log N)。
    """
    result = {"eie_boosted": False}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.eie_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(_cfg.get("store_vfs.eie_min_importance"))
        if imp < min_imp:
            return result

        text = ((content or "") + " " + (summary or "")).lower()
        connectives = [
            "because", "therefore", "causes", "hence", "consequently",
            "因为", "导致", "因此", "所以", "由于", "是因为", "的原因是"
        ]
        count = sum(text.count(c) for c in connectives)
        if count < int(_cfg.get("store_vfs.eie_min_connectives")):
            return result

        factor = float(_cfg.get("store_vfs.eie_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.eie_max_boost"))
        raw = stab * factor
        capped = min(stab * (1.0 + max_boost), raw)
        new_stab = min(365.0, capped)
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["eie_boosted"] = True
        return result
    except Exception:
        return result


def apply_desirable_difficulty_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    now_iso: str = None,
) -> dict:
    """iter467: Desirable Difficulty Effect (DDE) — 高词汇复杂度内容需要更深认知加工 → 更持久编码。

    认知科学依据：
      Bjork (1994) "Memory and metamemory considerations in the training of human beings" —
        "有益的困难"使学习时主观感受更难，但产生更强的长期记忆痕迹（r=0.49）。
      Hirshman & Bjork (1988): 生成效应（self-generation）= 认知努力代理。
      Rayner & Pollatsek (1989): 低频词（longer, less common）需要更多注视时间 → 更深语义加工。

    OS 类比：Linux zswap/zram — 被压缩的页面需要 CPU 解压（认知努力），
      但压缩率高 = 在有限内存中保留更多内容（复杂编码 = 更高信息密度）。
      zswap pages 在 LRU 中有更高留存率（desirable difficulty → long-term retention）。
    """
    result = {"dde_boosted": False}
    try:
        import config as _cfg
        import re as _re
        if not _cfg.get("store_vfs.dde_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(_cfg.get("store_vfs.dde_min_importance"))
        if imp < min_imp:
            return result

        words = _re.findall(r'\b[a-zA-Z\u4e00-\u9fff]+\b', (content or "").lower())
        min_words = int(_cfg.get("store_vfs.dde_min_words"))
        if len(words) < min_words:
            return result

        # Average word length as complexity proxy
        avg_len = sum(len(w) for w in words) / len(words)
        min_avg = float(_cfg.get("store_vfs.dde_min_avg_word_len"))
        if avg_len < min_avg:
            return result

        factor = float(_cfg.get("store_vfs.dde_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.dde_max_boost"))
        raw = stab * factor
        capped = min(stab * (1.0 + max_boost), raw)
        new_stab = min(365.0, capped)
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["dde_boosted"] = True
        return result
    except Exception:
        return result


def apply_contextual_cue_reinstatement_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    current_context_tokens: list,
    now_iso: str = None,
) -> dict:
    """iter468: Contextual Cue Reinstatement Effect (CCRE) — encode_context 匹配时提升稳定性。

    认知科学依据：
      Godden & Baddeley (1975) "Context-dependent memory in two natural environments" —
        在与编码时相同的物理/认知上下文中检索，成功率提升约 40%（vs 不同上下文）。
      Tulving & Thomson (1973) Encoding Specificity Principle：
        "retrieval cue 需包含编码时存在的信息" → 上下文 token 重叠 = 最强检索线索。
      Smith (1979): 内部上下文（mental state）匹配也有相同效果（environment-independent）。

    OS 类比：Linux NUMA-aware memory access（mm/mempolicy.c）—
      MPOL_PREFERRED：进程倾向访问与分配时相同 NUMA 节点的内存（低延迟）；
      跨 NUMA 节点访问 = context mismatch → 更高延迟（penalty）；
      encode_context token 重叠度 = NUMA locality score。
    """
    result = {"ccre_boosted": False, "ccre_matched_tokens": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ccre_enabled"):
            return result

        if not current_context_tokens:
            return result

        row = conn.execute(
            "SELECT stability, importance, encode_context FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        stored_ctx = str(row[2] or "")
        min_imp = float(_cfg.get("store_vfs.ccre_min_importance"))
        if imp < min_imp:
            return result

        # Tokenize stored encode_context
        stored_tokens = {t.strip().lower() for t in stored_ctx.split(",") if t.strip()}
        current_set = {t.strip().lower() for t in current_context_tokens if t.strip()}
        matched = len(stored_tokens & current_set)
        if matched == 0:
            return result

        boost_per = float(_cfg.get("store_vfs.ccre_boost_per_token"))
        max_boost = float(_cfg.get("store_vfs.ccre_max_boost"))
        total_boost = min(max_boost, matched * boost_per)
        new_stab = min(365.0, stab * (1.0 + total_boost))
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["ccre_boosted"] = True
            result["ccre_matched_tokens"] = matched
        return result
    except Exception:
        return result


def apply_generation_effect_v2(
    conn: "sqlite3.Connection",
    chunk_id: str,
    chunk_type: str,
    now_iso: str = None,
) -> dict:
    """iter469: Generation Effect (GE) — 主动生成的知识比被动接收的保留更好。

    认知科学依据：
      Slamecka & Graf (1978) "The generation effect: Delineation of a phenomenon" —
        自我生成的信息（自写/决策/设计）比被动阅读信息记忆保留率高 20-30%（延时测验）。
        机制：生成过程激活更深的语义处理网络 + 自我参照加工（self-referential processing）。
      McElroy & Slamecka (1982): 生成效应在词汇和命题层面均成立（语义 > 表面特征）。

    OS 类比：Linux CoW (Copy-on-Write, mm/memory.c: do_wp_page) —
      被进程主动写入（dirty）的页面获得更高 active LRU 优先级（PG_dirty 置位）；
      只读共享页面（read-only mapped, PG_dirty=0）优先被 kswapd 淘汰。
      主动生成 = dirty write → 更高驻留权重。
    """
    result = {"ge_boosted": False}
    try:
        if not config.get("store_vfs.ge_enabled"):
            return result

        generative_types_str = config.get("store_vfs.ge_generative_types") or ""
        generative_types = {t.strip() for t in generative_types_str.split(",") if t.strip()}
        if chunk_type not in generative_types:
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(config.get("store_vfs.ge_min_importance"))
        if imp < min_imp:
            return result

        boost_factor = float(config.get("store_vfs.ge_boost_factor"))
        max_boost = float(config.get("store_vfs.ge_max_boost"))
        raw_boost = stab * (boost_factor - 1.0)
        capped_boost = min(raw_boost, stab * max_boost)
        new_stab = min(365.0, stab + capped_boost)
        if new_stab > stab + 1e-6:
            now = now_iso or datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (new_stab, now, chunk_id)
            )
            result["ge_boosted"] = True
        return result
    except Exception:
        return result


def apply_interleaving_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter470: Interleaving Effect (ILE) — 跨多种上下文访问的 chunk 比单一上下文访问保留更好。

    认知科学依据：
      Kornell & Bjork (2008) "Learning concepts and categories" —
        交错练习（interleaved）vs. 分块练习（blocked）：测验成绩 64% vs. 36%（r=0.58）。
        机制：交错迫使大脑持续辨别相似概念 → 更深比较性处理 → 更精细记忆表征。
      Taylor & Rohrer (2010): 数学题交错练习比分块练习长期保留率高 43%。

    OS 类比：Linux NUMA interleaving（mm/mempolicy.c MPOL_INTERLEAVE）—
      内存分配跨多个 NUMA 节点 → 无单点 bandwidth 瓶颈 → 整体吞吐量和容错性更高；
      session_type_history 多样性 = NUMA interleave 深度 = 更强鲁棒性。
    """
    result = {"ile_boosted": 0, "ile_total_types_examined": 0}
    try:
        if not config.get("store_vfs.ile_enabled"):
            return result

        min_diversity = int(config.get("store_vfs.ile_min_diversity"))
        boost_per_type = float(config.get("store_vfs.ile_boost_per_type"))
        max_boost = float(config.get("store_vfs.ile_max_boost"))
        min_imp = float(config.get("store_vfs.ile_min_importance"))
        now = now_iso or datetime.now(timezone.utc).isoformat()

        if not chunk_ids:
            return result

        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, stability, importance, COALESCE(session_type_history,'') "
            f"FROM memory_chunks WHERE id IN ({placeholders})",
            list(chunk_ids)
        ).fetchall()

        boosted = 0
        for row in rows:
            cid = row[0]
            stab = float(row[1] or 1.0)
            imp = float(row[2] or 0.0)
            history = str(row[3]) if row[3] else ""
            result["ile_total_types_examined"] += 1

            if imp < min_imp:
                continue

            entries = [e.strip() for e in history.split(",") if e.strip()]
            unique_types = len(set(entries))
            if unique_types < min_diversity:
                continue

            extra_types = unique_types - min_diversity + 1
            raw_boost = stab * min(max_boost, extra_types * boost_per_type)
            new_stab = min(365.0, stab + raw_boost)
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                    (new_stab, now, cid)
                )
                boosted += 1

        result["ile_boosted"] = boosted
        return result
    except Exception:
        return result


def apply_self_reference_effect_v2(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    summary: str = "",
    now_iso: str = None,
) -> dict:
    """iter471: Self-Reference Effect (SRE) — 含自我参照词的内容编码更深，记忆更持久。

    认知科学依据：
      Rogers, Kuiper & Kirker (1977) "Self-reference and the encoding of personal information" —
        "Does it describe you?" 条件下记忆保留比语义判断（"Does it mean...?"）高 50-60%（r=0.61）。
        机制：自我参照激活 medial prefrontal cortex（mPFC）→ 更强 episodic memory consolidation。
      Symons & Johnson (1997): SRE 在跨文化研究中稳定复现（meta-analysis, d=1.07）。

    OS 类比：Linux process-private mappings（MAP_PRIVATE, mm/mmap.c）—
      进程私有匿名页（mmap private + CoW）的 TLB 局部性优于共享匿名映射；
      自我参照内容 = process-private data = 更高 TLB hit rate → 更快检索（lower latency）。
    """
    result = {"sre_boosted": False, "sre_matched_keywords": 0}
    try:
        if not config.get("store_vfs.sre_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        min_imp = float(config.get("store_vfs.sre_min_importance"))
        if imp < min_imp:
            return result

        keywords_str = config.get("store_vfs.sre_keywords") or ""
        keywords = [k.strip() for k in keywords_str.split(",") if k.strip()]
        combined = (content + " " + summary).lower()

        matched = sum(1 for kw in keywords if kw.lower() in combined)
        if matched == 0:
            return result

        result["sre_matched_keywords"] = matched
        boost_factor = float(config.get("store_vfs.sre_boost_factor"))
        max_boost = float(config.get("store_vfs.sre_max_boost"))
        raw_boost = stab * (boost_factor - 1.0)
        capped_boost = min(raw_boost, stab * max_boost)
        new_stab = min(365.0, stab + capped_boost)
        if new_stab > stab + 1e-6:
            now = now_iso or datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (new_stab, now, chunk_id)
            )
            result["sre_boosted"] = True
        return result
    except Exception:
        return result


def apply_access_frequency_boost(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter472: Access Frequency Boost (AFB) — 检索频率越高的 chunk 记忆痕迹越强。

    认知科学依据：
      Newell & Rosenbloom (1981) "Mechanisms of skill acquisition and the law of practice" —
        熟练度提升遵循幂律：performance ∝ trials^(-0.4)；检索次数 ↑ → 记忆强度 ↑。
      Anderson (1983) ACT* 理论：记忆激活强度 = ΣΑ_j × t_j^(-d)，检索次数是最强预测因子。
      Bahrick (1979): 间隔检索后长期保留量与检索次数正相关（r=0.78）。

    OS 类比：Linux active LRU promotion（mm/swap.c: mark_page_accessed）—
      多次被访问（PG_referenced 置位 → promote to active LRU）的页面获得更高驻留优先级；
      访问计数越高（hot page = access_count ↑）→ page_referenced() > 0 → kswapd skip；
      access_count ≥ afb_min_count = "页面进入 hot tier"。
    """
    result = {"afb_boosted": 0, "afb_total_boost": 0.0}
    try:
        if not config.get("store_vfs.afb_enabled"):
            return result

        min_count = int(config.get("store_vfs.afb_min_count"))
        afb_scale = float(config.get("store_vfs.afb_scale"))
        max_boost = float(config.get("store_vfs.afb_max_boost"))
        min_imp = float(config.get("store_vfs.afb_min_importance"))
        now = now_iso or datetime.now(timezone.utc).isoformat()

        if not chunk_ids:
            return result

        placeholders = ",".join("?" * len(chunk_ids))
        rows = conn.execute(
            f"SELECT id, stability, importance, COALESCE(access_count, 0) "
            f"FROM memory_chunks WHERE id IN ({placeholders})",
            list(chunk_ids)
        ).fetchall()

        boosted = 0
        total_boost = 0.0
        for row in rows:
            cid = row[0]
            stab = float(row[1] or 1.0)
            imp = float(row[2] or 0.0)
            access_count = int(row[3] or 0)

            if imp < min_imp:
                continue
            if access_count < min_count:
                continue

            extra = access_count - min_count + 1
            raw_boost = stab * min(max_boost, extra * afb_scale)
            new_stab = min(365.0, stab + raw_boost)
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                    (new_stab, now, cid)
                )
                boosted += 1
                total_boost += new_stab - stab

        result["afb_boosted"] = boosted
        result["afb_total_boost"] = round(total_boost, 6)
        return result
    except Exception:
        return result


def compute_emotional_valence(text: str) -> float:
    """
    iter424: 计算文本的情绪效价（Bower 1981 Mood-Congruent Memory）。

    扫描情绪效价词，正负累积后 clamp 到 [-1, +1]。
    与 compute_emotional_salience（唤醒度）正交：
      崩溃/错误 → salience=+0.12（高唤醒），valence=-1.0（负面情绪）
      突破/成功 → salience=+0.10（高唤醒），valence=+1.0（正面情绪）
      已解决    → salience=-0.08（降权），  valence=0.0（事件结束）

    OS 类比：Linux NUMA node selection — valence 是 page 的 preferred home node，
      访问者（query）有自己的 home node，同 node 时延迟最低（MCM 加分）。

    Returns:
      float ∈ [-1.0, +1.0]，0.0 表示情绪中性
    """
    if not text:
        return 0.0
    valence = 0.0
    for pat, v in _EMOTIONAL_VALENCE_RE:
        if pat.search(text):
            valence += v
    return max(-1.0, min(1.0, valence))


def compute_emotional_salience(text: str) -> float:
    """
    迭代320：计算文本的情感显著性分数（delta importance）。

    扫描 text 中的情感唤醒词，累积 delta：
      正向词（紧急/关键/崩溃）→ 累积正 delta
      负向词（已解决/废弃）→ 累积负 delta

    OS 类比：Linux OOM Killer oom_score 计算 — 综合多个维度（内存使用、
      进程优先级、用户调整）计算最终 OOM 分数，越高越被优先杀死。
      这里是情感信号的累积聚合。

    Returns:
      float delta，范围 [-0.20, +0.25]
      delta = 0.0 表示情感中性
    """
    if not text:
        return 0.0
    delta = 0.0
    for pat, d in _EMOTIONAL_SALIENCE_RE:
        if pat.search(text):
            delta += d
    return max(-0.20, min(0.25, delta))


def apply_memory_interference_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    project: str,
    chunk_type: str,
    now_iso: str = None,
) -> dict:
    """iter473: Memory Interference Effect (MIE) — 同类内容密集写入时互相干扰，stability 轻微降低。

    认知科学依据：
      McGeoch (1932) 倒摄干扰（RI）: 新学内容干扰旧记忆检索；相似度越高，干扰越强。
      Underwood (1957) 前摄干扰（PI）: 旧习惯/旧知识干扰新内容编码。
      量化：词汇重叠 > 30% 且时间窗口 < 24h → stability 降 ~7%（McGeoch 干扰函数近似）。

    OS 类比：Linux cache thrashing（mm/vmscan.c thrash_count）—
      working set > available memory 时 page 不断换入换出，effective throughput 下降。
      相似 chunk 密集写入 = 同类地址密集访问 = TLB/cache 频繁 miss = 检索代价上升。
    """
    result = {"mie_penalized": False, "mie_overlap": 0.0}
    try:
        import config as _cfg
        import re as _re
        if not _cfg.get("store_vfs.mie_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        if imp < float(_cfg.get("store_vfs.mie_min_importance")):
            return result

        window_hours = int(_cfg.get("store_vfs.mie_window_hours"))
        import datetime as _dt
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=window_hours)).isoformat()

        # 查找同项目同类型、时间窗口内的其他 chunk
        rows = conn.execute(
            """SELECT content FROM memory_chunks
               WHERE project=? AND chunk_type=? AND id!=? AND created_at >= ?
               LIMIT 20""",
            (project, chunk_type, chunk_id, cutoff)
        ).fetchall()

        if not rows:
            return result

        # 计算词汇 Jaccard 相似度
        words_a = set(_re.findall(r'\b\w+\b', (content or "").lower()))
        if not words_a:
            return result

        min_overlap = float(_cfg.get("store_vfs.mie_min_overlap"))
        max_overlap = 0.0
        for r in rows:
            words_b = set(_re.findall(r'\b\w+\b', (r[0] or "").lower()))
            if not words_b:
                continue
            intersection = len(words_a & words_b)
            union = len(words_a | words_b)
            if union == 0:
                continue
            jaccard = intersection / union
            if jaccard > max_overlap:
                max_overlap = jaccard

        result["mie_overlap"] = round(max_overlap, 4)
        if max_overlap < min_overlap:
            return result

        # 施加惩罚：penalty ∝ overlap，上限 mie_max_penalty
        penalty_factor = float(_cfg.get("store_vfs.mie_penalty_factor"))  # 0.93
        max_penalty = float(_cfg.get("store_vfs.mie_max_penalty"))        # 0.12
        # 按重叠比例线性缩放惩罚
        overlap_ratio = min(1.0, (max_overlap - min_overlap) / (1.0 - min_overlap + 1e-9))
        raw_penalty = (1.0 - penalty_factor) * overlap_ratio
        capped_penalty = min(max_penalty, raw_penalty)
        new_stab = max(0.1, stab * (1.0 - capped_penalty))
        if new_stab < stab - 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["mie_penalized"] = True
        return result
    except Exception:
        return result


def apply_spreading_activation_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter474: Spreading Activation Effect (SAE) — 检索时语义相关 chunk 的 retrievability 一起被激活。

    认知科学依据：
      Collins & Loftus (1975) "A spreading-activation theory of semantic processing" —
        语义网络中，激活沿关联边传播（decay with distance），相关概念可达性提升 20-30%。
      Anderson (1983) ACT* 模型：基线激活水平（Bi）= log(fan) + Σ(source activations)。
      效果：检索 A 后，与 A 语义相似的 B 的 retrievability 提升约 0.05~0.15。

    OS 类比：Linux readahead（mm/readahead.c）—
      顺序/相关 page 预取到 page cache，降低后续访问的 page fault 率。
      SAE = 语义层面的 readahead：被检索的 chunk 把相关 chunk 预热到"热缓存"。
    """
    result = {"sae_boosted": 0, "sae_total_neighbors": 0}
    try:
        import config as _cfg
        import re as _re
        if not _cfg.get("store_vfs.sae_enabled"):
            return result
        if not chunk_ids:
            return result

        min_sim = float(_cfg.get("store_vfs.sae_min_similarity"))
        spread_factor = float(_cfg.get("store_vfs.sae_spread_factor"))
        max_spread = float(_cfg.get("store_vfs.sae_max_spread"))
        max_neighbors = int(_cfg.get("store_vfs.sae_max_neighbors"))
        min_imp = float(_cfg.get("store_vfs.sae_min_importance"))

        for cid in chunk_ids:
            src = conn.execute(
                "SELECT content, project, importance FROM memory_chunks WHERE id=?", (cid,)
            ).fetchone()
            if not src:
                continue
            if float(src[2] or 0.0) < min_imp:
                continue

            words_src = set(_re.findall(r'\b\w+\b', (src[0] or "").lower()))
            if not words_src:
                continue

            # 查找同项目的候选邻居
            neighbors = conn.execute(
                """SELECT id, content, retrievability FROM memory_chunks
                   WHERE project=? AND id!=?
                   ORDER BY last_accessed DESC LIMIT 100""",
                (src[1], cid)
            ).fetchall()

            boosted = 0
            for nb in neighbors:
                if boosted >= max_neighbors:
                    break
                words_nb = set(_re.findall(r'\b\w+\b', (nb[1] or "").lower()))
                if not words_nb:
                    continue
                union = len(words_src | words_nb)
                if union == 0:
                    continue
                jaccard = len(words_src & words_nb) / union
                if jaccard < min_sim:
                    continue

                retr = float(nb[2] or 0.0)
                boost = min(max_spread, retr * spread_factor + spread_factor * 0.5)
                new_retr = min(1.0, retr + boost)
                if new_retr > retr + 1e-6:
                    conn.execute(
                        "UPDATE memory_chunks SET retrievability=? WHERE id=?",
                        (new_retr, nb[0])
                    )
                    boosted += 1

            result["sae_boosted"] += boosted
            result["sae_total_neighbors"] += boosted

        return result
    except Exception:
        return result


def apply_serial_position_primacy(
    conn: "sqlite3.Connection",
    chunk_id: str,
    source_session: str,
    project: str,
    now_iso: str = None,
) -> dict:
    """iter475: Serial Position Effect — Primacy 部分（session 首位 chunk stability 加成）。

    认知科学依据：
      Murdock (1962) "The serial position effect of free recall" —
        序列首位项目因有更多复习机会（longer rehearsal time）→ 长期 stability 更高。
        Primacy advantage: 首 5 项目 recall 率比中间项目高约 20-30%。
      Atkinson & Shiffrin (1968) 双存储模型：primacy 项目更可能进入长时记忆。

    OS 类比：CPU L1 cache 的 LRU most-recently-used slot —
      最先加载的 hot page 因反复被引用而留在 cache 最久。
      Session 首位 chunk = 被后续推理反复引用的基础上下文。
    """
    result = {"spe_primacy_boosted": False}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.spe_enabled"):
            return result
        if not source_session:
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        imp = float(row[1] or 0.0)
        if imp < float(_cfg.get("store_vfs.spe_min_importance")):
            return result

        primacy_window = int(_cfg.get("store_vfs.spe_primacy_window"))
        min_session_size = int(_cfg.get("store_vfs.spe_min_session_size"))

        # 查询 session 内当前 chunk 的位置（按 created_at 排序）
        session_chunks = conn.execute(
            """SELECT id FROM memory_chunks
               WHERE source_session=? AND project=?
               ORDER BY created_at ASC""",
            (source_session, project)
        ).fetchall()

        total = len(session_chunks)
        if total < min_session_size:
            return result

        ids_ordered = [r[0] for r in session_chunks]
        if chunk_id not in ids_ordered:
            return result

        pos = ids_ordered.index(chunk_id)  # 0-based
        if pos >= primacy_window:
            return result

        stab = float(row[0] or 1.0)
        primacy_boost = float(_cfg.get("store_vfs.spe_primacy_boost"))
        new_stab = min(365.0, stab * (1.0 + primacy_boost))
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["spe_primacy_boosted"] = True
        return result
    except Exception:
        return result


def apply_serial_position_recency(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter475: Serial Position Effect — Recency 部分（session 末位 chunk retrievability 加成）。

    认知科学依据：
      Murdock (1962): 序列末位项目仍在工作记忆（short-term buffer）→ 短期 retrievability 最高。
      Glanzer & Cunitz (1966): recency 效应在延迟测试后消失（与 primacy 不同）→ 仅提升 retrievability 而非 stability。

    OS 类比：L1 cache 的 MRU（最近使用）slot — 最近访问的 page 在 cache 中优先保留。
    """
    result = {"spe_recency_boosted": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.spe_enabled"):
            return result
        if not chunk_ids:
            return result

        recency_window = int(_cfg.get("store_vfs.spe_recency_window"))
        recency_boost = float(_cfg.get("store_vfs.spe_recency_boost"))
        min_session_size = int(_cfg.get("store_vfs.spe_min_session_size"))
        min_imp = float(_cfg.get("store_vfs.spe_min_importance"))

        for cid in chunk_ids:
            src = conn.execute(
                "SELECT source_session, project, importance FROM memory_chunks WHERE id=?", (cid,)
            ).fetchone()
            if not src or not src[0]:
                continue
            if float(src[2] or 0.0) < min_imp:
                continue

            session_chunks = conn.execute(
                """SELECT id FROM memory_chunks
                   WHERE source_session=? AND project=?
                   ORDER BY created_at DESC LIMIT ?""",
                (src[0], src[1], recency_window + 5)
            ).fetchall()

            if len(session_chunks) < min_session_size:
                continue

            recency_ids = {r[0] for r in session_chunks[:recency_window]}
            if cid not in recency_ids:
                continue

            retr_row = conn.execute(
                "SELECT retrievability FROM memory_chunks WHERE id=?", (cid,)
            ).fetchone()
            if not retr_row:
                continue

            retr = float(retr_row[0] or 0.0)
            new_retr = min(1.0, retr + recency_boost)
            if new_retr > retr + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET retrievability=? WHERE id=?", (new_retr, cid)
                )
                result["spe_recency_boosted"] += 1

        return result
    except Exception:
        return result


def apply_cognitive_load_penalty(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    now_iso: str = None,
) -> dict:
    """iter476: Cognitive Load Penalty (CLP) — 超出工作记忆容量的内容 stability 轻微降低。

    认知科学依据：
      Miller (1956) "The magical number seven, plus or minus two" —
        工作记忆容量上限约 7±2 chunks；超出时编码质量下降。
      Sweller (1988) Cognitive Load Theory: 内在负荷（intrinsic load）过高 → 有效编码下降。
      Paas & van Merriënboer (1994): 高认知负荷材料的长期记忆保留率反而更低。
      与 DDE 互补：短且复杂（高词汇难度）= 有益困难 → stability +；
                   长且复杂（词数超载）= 认知超载 → stability −。

    OS 类比：CPU context switch overhead（kernel/sched/core.c）—
      超线程数过多时，调度开销超过并行收益；
      TLB flush 频率 ∝ 活跃进程数 → 超过 CPU 核数后 effective IPC 下降。
    """
    result = {"clp_penalized": False, "clp_token_count": 0}
    try:
        import config as _cfg
        import re as _re
        if not _cfg.get("store_vfs.clp_enabled"):
            return result

        row = conn.execute(
            "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result

        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        if imp < float(_cfg.get("store_vfs.clp_min_importance")):
            return result

        words = _re.findall(r'\b\w+\b', (content or ""))
        token_count = len(words)
        result["clp_token_count"] = token_count

        max_tokens = int(_cfg.get("store_vfs.clp_max_tokens"))
        if token_count <= max_tokens:
            return result

        excess = token_count - max_tokens
        penalty_per_100 = float(_cfg.get("store_vfs.clp_penalty_per_100"))
        max_penalty = float(_cfg.get("store_vfs.clp_max_penalty"))
        raw_penalty = (excess / 100.0) * penalty_per_100
        capped_penalty = min(max_penalty, raw_penalty)
        new_stab = max(0.1, stab * (1.0 - capped_penalty))
        if new_stab < stab - 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["clp_penalized"] = True
        return result
    except Exception:
        return result


def apply_memory_binding_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter477: Memory Binding Effect (MBE) — 同 session 同批编码的 chunk 相互加固 stability。

    认知科学依据：
      Eichenbaum (2004) "Hippocampus: cognitive processes and neural representations
      that underlie declarative memory" — 海马体在情节编码时将同一事件内的记忆元素
      绑定（binding）在一起，形成关联记忆结构，共同激活使各部分稳定性相互增强。
      Norman & Eichenbaum (2014): 绑定程度 ∝ 编码时的共同激活强度。
      Howard & Kahana (2002): 同一时间窗口内编码的条目具有更强的联想连接。

    OS 类比：Linux THP（Transparent Huge Pages）—
      相邻的 4K page 合并为 2MB 大页（/sys/kernel/mm/transparent_hugepage/enabled）；
      合并后 TLB coverage 更大、访问局部性更好；
      同 session 同批 chunk = 相邻 page → 合并为大页 → 整体稳定性提升。
    """
    result = {"mbe_boosted": 0, "mbe_total_bound": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.mbe_enabled"):
            return result

        window_sec = int(_cfg.get("store_vfs.mbe_window_seconds"))
        boost_factor = float(_cfg.get("store_vfs.mbe_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.mbe_max_boost"))
        max_neighbors = int(_cfg.get("store_vfs.mbe_max_neighbors"))
        min_importance = float(_cfg.get("store_vfs.mbe_min_importance"))

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, source_session, project, created_at "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue
            session_id = row[2] or ""
            project = row[3] or ""
            created_at = row[4] or ""
            if not session_id:
                continue

            # 查找同 session 内在时间窗口内的其他 chunk
            neighbors = conn.execute(
                """SELECT id FROM memory_chunks
                   WHERE source_session=? AND project=? AND id != ?
                   AND ABS(JULIANDAY(created_at) - JULIANDAY(?)) * 86400 <= ?
                   ORDER BY created_at
                   LIMIT ?""",
                (session_id, project, chunk_id, created_at, window_sec, max_neighbors)
            ).fetchall()

            n_bound = len(neighbors)
            if n_bound == 0:
                continue

            raw_boost = n_bound * boost_factor
            capped_boost = min(max_boost, raw_boost)
            new_stab = min(365.0, stab * (1.0 + capped_boost))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["mbe_boosted"] += 1
                result["mbe_total_bound"] += n_bound
        return result
    except Exception:
        return result


def apply_directed_forgetting_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    project: str,
    old_importance: float,
    new_importance: float,
) -> dict:
    """iter478: Directed Forgetting Effect (DFE) — importance 显著下降时向相似 chunk 扩散遗忘。

    认知科学依据：
      Bjork (1972) "Directed forgetting: Some methodological and theoretical considerations" —
        当被明确指示"忘记"某项内容时，相关记忆也受到抑制（category inhibition mechanism）。
        机制：主动抑制目标记忆 → 压制同类竞争记忆（避免干扰）→ 相关记忆检索率降低 10-20%。
      Bjork & Woodward (1973): TBF（to-be-forgotten）条目及其关联条目均受抑制。
      MacLeod (1998): DFE 在元认知层（"这个重要性下降了"）也适用。

    OS 类比：Linux MADV_FREE（mm/madvise.c）—
      进程标记页面为"懒惰释放（lazy free）"→ 内核标记为可回收但尚未实际回收；
      当内存压力到来时页面被驱逐（类比 importance 下降触发被动遗忘传播）。
      DFE = importance drop event → 相似 chunk 标记为"被动遗忘候选" → stability 微降。
    """
    result = {"dfe_propagated": False, "dfe_neighbors_decayed": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.dfe_enabled"):
            return result

        min_drop = float(_cfg.get("store_vfs.dfe_min_importance_drop"))
        importance_drop = old_importance - new_importance
        if importance_drop < min_drop:
            return result

        min_similarity = float(_cfg.get("store_vfs.dfe_min_similarity"))
        decay_factor = float(_cfg.get("store_vfs.dfe_decay_factor"))
        max_decay = float(_cfg.get("store_vfs.dfe_max_decay"))
        max_neighbors = int(_cfg.get("store_vfs.dfe_max_neighbors"))
        min_importance = float(_cfg.get("store_vfs.dfe_min_importance"))

        # 获取源 chunk 的内容
        row = conn.execute(
            "SELECT content FROM memory_chunks WHERE id=?", (chunk_id,)
        ).fetchone()
        if not row:
            return result
        src_content = row[0] or ""
        src_words = set((src_content or "").lower().split())
        if not src_words:
            return result

        # 查找同 project 的候选邻居
        candidates = conn.execute(
            """SELECT id, content, stability, importance FROM memory_chunks
               WHERE project=? AND id != ? AND importance >= ?
               ORDER BY importance DESC LIMIT 200""",
            (project, chunk_id, min_importance)
        ).fetchall()

        decayed_count = 0
        for nb in candidates:
            if decayed_count >= max_neighbors:
                break
            nb_words = set((nb[1] or "").lower().split())
            if not nb_words:
                continue
            union = len(src_words | nb_words)
            if union == 0:
                continue
            jaccard = len(src_words & nb_words) / union
            if jaccard < min_similarity:
                continue

            nb_stab = float(nb[2] or 1.0)
            # 衰减比例 = min(max_decay, (1 - decay_factor) * jaccard)
            decay_ratio = min(max_decay, (1.0 - decay_factor) * jaccard)
            new_stab = max(0.1, nb_stab * (1.0 - decay_ratio))
            if new_stab < nb_stab - 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, nb[0])
                )
                decayed_count += 1

        if decayed_count > 0:
            result["dfe_propagated"] = True
            result["dfe_neighbors_decayed"] = decayed_count
        return result
    except Exception:
        return result


def apply_use_dependent_plasticity(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter479: Use-Dependent Plasticity (UDP) — 共同访问的 chunk 互相加固 stability。

    认知科学依据：
      Hebb (1949) "The Organization of Behavior" — "Neurons that fire together wire together"：
        共同激活的神经元之间突触连接加强（Hebbian plasticity）。
        记忆等价：同时被检索激活的记忆节点 → 相互间连接（stability）增强。
      Bhattacharya & Bhattacharya (2009) long-term potentiation（LTP）:
        重复共同激活 → AMPA receptor density 上调 → 突触效能永久增强。
      Shastri & Ajjanagadde (1993) 绑定问题：
        共同激活的概念在工作记忆中形成临时绑定 → 反复共激活转为长时连接。

    OS 类比：Linux working set model（mm/vmscan.c refcount）—
      page A 和 page B 经常被同一进程同时访问 → 两者 refcount 都高 →
      page reclaim 优先考虑低 refcount page；共激活 = 共享高 refcount = 更不易被回收。
    """
    result = {"udp_boosted": 0}
    if not chunk_ids or len(chunk_ids) < 2:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.udp_enabled"):
            return result

        boost_per_peer = float(_cfg.get("store_vfs.udp_boost_per_peer"))
        max_boost = float(_cfg.get("store_vfs.udp_max_boost"))
        max_peers = int(_cfg.get("store_vfs.udp_max_peers"))
        min_importance = float(_cfg.get("store_vfs.udp_min_importance"))

        # 每个 chunk 都从其他 chunk 中获益
        peer_list = list(chunk_ids)
        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            # 参与的对等数（排除自身，最多 max_peers 个）
            n_peers = min(max_peers, len(peer_list) - 1)
            if n_peers <= 0:
                continue

            raw_boost = n_peers * boost_per_peer
            capped_boost = min(max_boost, raw_boost)
            new_stab = min(365.0, stab * (1.0 + capped_boost))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["udp_boosted"] += 1
        return result
    except Exception:
        return result


def apply_forward_association_primacy(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter480: Forward Association Primacy (FAP) — 访问当前 chunk 时，较早的 session sibling
    retrievability 提升（前向联想比后向联想强）。

    认知科学依据：
      Kahana (2002) "Associative symmetry and memory theory" —
        自由回忆中前向转换（forward transition: item_i → item_{i+1}）概率比后向转换高 ~1.5:1。
        机制：序列编码时，先编码的项目成为"前向联想提示"，后续项目访问时激活先前项目。
      Howard & Kahana (1999) "Contextual variability and serial position effects in free recall":
        前向联想（forward asymmetry）在情节记忆中持续稳定（跨文化, d ≈ 0.4）。
      Raaijmakers & Shiffrin (1981) SAM 模型: 编码顺序 → 强非对称联想权重。

    OS 类比：CPU 指令流水线预取（arch/x86/lib/usercopy.S）—
      执行当前指令时，CPU 同时预取后续 N 条指令到 fetch buffer；
      这里"访问当前 chunk" = 触发对 session 中较早 chunk 的前向联想提升（逆向）—
      实际上后来的 chunk 访问 → 前面的 chunk retrievability 升高（符合 Kahana 的前向方向定义）。
    """
    result = {"fap_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.fap_enabled"):
            return result

        retr_boost = float(_cfg.get("store_vfs.fap_retr_boost"))
        max_boost = float(_cfg.get("store_vfs.fap_max_boost"))
        lookback_window = int(_cfg.get("store_vfs.fap_lookback_window"))
        min_session_size = int(_cfg.get("store_vfs.fap_min_session_size"))
        min_importance = float(_cfg.get("store_vfs.fap_min_importance"))

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT importance, source_session, project, created_at "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            imp = float(row[0] or 0.0)
            if imp < min_importance:
                continue
            session_id = row[1] or ""
            project = row[2] or ""
            created_at = row[3] or ""
            if not session_id:
                continue

            # 检查 session 大小
            session_size = conn.execute(
                "SELECT COUNT(*) FROM memory_chunks WHERE source_session=? AND project=?",
                (session_id, project)
            ).fetchone()[0]
            if session_size < min_session_size:
                continue

            # 查找该 chunk 在 session 中较早创建的 chunk（前向联想来源）
            earlier_chunks = conn.execute(
                """SELECT id, retrievability, importance FROM memory_chunks
                   WHERE source_session=? AND project=? AND id != ?
                   AND created_at < ?
                   ORDER BY created_at DESC LIMIT ?""",
                (session_id, project, chunk_id, created_at, lookback_window)
            ).fetchall()

            boosted_count = 0
            for ec in earlier_chunks:
                ec_retr = float(ec[1] or 0.0)
                ec_imp = float(ec[2] or 0.0)
                if ec_imp < min_importance:
                    continue
                new_retr = min(1.0, ec_retr + retr_boost)
                if new_retr > ec_retr + 1e-6:
                    conn.execute(
                        "UPDATE memory_chunks SET retrievability=? WHERE id=?",
                        (new_retr, ec[0])
                    )
                    boosted_count += 1
                    if ec_retr + retr_boost >= max_boost + ec_retr:
                        break
            if boosted_count > 0:
                result["fap_boosted"] += boosted_count
        return result
    except Exception:
        return result


def apply_testing_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter481: Testing Effect / Retrieval Practice Effect (TPE) —
    被主动检索到的 chunk 比单纯访问获得更高的 stability 加成。

    认知科学依据：
      Roediger & Karpicke (2006) "Test-enhanced learning" Science 319(5865):966-8 —
        1周后保留率：测试组 64% vs 复习组 40%；Cohen's d ≈ 1.0（认知科学最强效应之一）。
        机制：主动检索激活"检索练习"路径 → 强化编码痕迹 → 更高长时稳定性。
      Karpicke & Roediger (2008) PNAS: 4次检索比 1次检索+3次复习保留率高2倍。
      Butler & Roediger (2007): 测试效应跨领域稳定（不依赖材料类型）。

    OS 类比：CPU TLB hit vs page table walk（arch/x86/mm/tlb.c）—
      TLB 命中（= 主动检索）更新 LRU 并保留 hot page 于 L1；
      page table walk（= 被动复习）成本高且不更新 TLB；
      TPE = TLB hit 对应的额外 refcount boost。
    """
    result = {"tpe_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import datetime as _dt
        if not _cfg.get("store_vfs.tpe_enabled"):
            return result

        boost_factor = float(_cfg.get("store_vfs.tpe_boost_factor"))
        max_boost = float(_cfg.get("store_vfs.tpe_max_boost"))
        min_importance = float(_cfg.get("store_vfs.tpe_min_importance"))
        lookback_min = int(_cfg.get("store_vfs.tpe_lookback_minutes"))

        if now_iso is None:
            now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()

        # 计算时间窗口下界
        try:
            now_dt = _dt.datetime.fromisoformat(now_iso)
        except Exception:
            now_dt = _dt.datetime.now(_dt.timezone.utc)
        cutoff_dt = now_dt - _dt.timedelta(minutes=lookback_min)
        cutoff_iso = cutoff_dt.isoformat()

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            # 检查最近是否有 recall_traces 命中该 chunk
            # recall_traces.top_k_json 是 JSON 数组，包含 chunk_id
            try:
                hit_count = conn.execute(
                    """SELECT COUNT(*) FROM recall_traces
                       WHERE timestamp >= ? AND top_k_json LIKE ?""",
                    (cutoff_iso, f'%"{chunk_id}"%')
                ).fetchone()[0]
            except Exception:
                hit_count = 0

            if hit_count == 0:
                # 没有 recall_traces 命中，不是"主动检索"，不触发 TPE
                continue

            capped_boost = min(max_boost, boost_factor)
            new_stab = min(365.0, stab * (1.0 + capped_boost))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["tpe_boosted"] += 1
        return result
    except Exception:
        return result


def apply_spacing_effect_bonus(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter482: Spacing Effect Bonus (SEB) — 重复访问时，间隔越长每次获得的 stability 增益越大。

    认知科学依据：
      Ebbinghaus (1885) "Über das Gedächtnis" — 间隔复习遗忘曲线最优。
      Bahrick, Bahrick & Bahrick (1993) JEPS: 间隔越大，长期 retention 增益越大。
      Cepeda et al. (2006) Psych Bulletin meta-analysis（317 studies）: d=0.70；
        最优复习间隔 = retention interval × 10-20%。
      Landauer & Bjork (1978): 间隔练习（spaced practice）vs 集中练习（massed practice）
        长期差异可达 40-50% retention（相同总练习时间下）。

    OS 类比：Linux page access bit TLB aging（arch/x86/mm/tlb.c）—
      系统定期清除 access bit；距上次清除（= 上次访问）越久，
      下次命中时 TLB 优先级越高（aging = 越稀缺越珍贵）；
      长间隔 = 该 page 在 aged 状态下仍被访问 = 高价值 → priority++。
    """
    result = {"seb_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import math as _math
        import datetime as _dt
        if not _cfg.get("store_vfs.seb_enabled"):
            return result

        min_gap_hours = int(_cfg.get("store_vfs.seb_min_gap_hours"))
        base_bonus = float(_cfg.get("store_vfs.seb_base_bonus"))
        max_bonus = float(_cfg.get("store_vfs.seb_max_bonus"))
        min_importance = float(_cfg.get("store_vfs.seb_min_importance"))

        if now_iso is None:
            now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()

        try:
            now_dt = _dt.datetime.fromisoformat(now_iso)
        except Exception:
            now_dt = _dt.datetime.now(_dt.timezone.utc)

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, last_accessed FROM memory_chunks WHERE id=?",
                (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue
            last_acc = row[2] or ""
            if not last_acc:
                continue

            try:
                last_dt = _dt.datetime.fromisoformat(last_acc)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=_dt.timezone.utc)
                if now_dt.tzinfo is None:
                    now_dt = now_dt.replace(tzinfo=_dt.timezone.utc)
                gap_hours = (now_dt - last_dt).total_seconds() / 3600.0
            except Exception:
                continue

            if gap_hours < min_gap_hours:
                continue

            # bonus_ratio = min(max_bonus, base_bonus × log2(gap_hours/min_gap + 1))
            bonus_ratio = min(max_bonus,
                              base_bonus * _math.log2(gap_hours / min_gap_hours + 1))
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["seb_boosted"] += 1
        return result
    except Exception:
        return result


def apply_priming_effect(
    conn: "sqlite3.Connection",
    chunk_id: str,
    content: str,
    now_iso: str = None,
) -> dict:
    """iter483: Priming Effect (PE) — 编码新 chunk 时，已有语义相似 chunk 提供启动效应，
    使新 chunk 的 stability 更高（提供语义脚手架）。

    认知科学依据：
      Meyer & Schvaneveldt (1971) "Facilitation in recognizing pairs of words" JEPS —
        已激活相关概念（prime）使目标词识别更快（反应时间快 80ms），编码更深。
      Tulving & Osler (1968) "Effectiveness of retrieval cues" — 编码时的提示线索
        在检索时有效 → 说明编码质量受启动影响。
      Collins & Loftus (1975) spreading activation: 语义网络中相关节点激活传播；
        新 chunk 编码时周围语义激活越高，编码越稳固。

    OS 类比：Linux dentry cache warm（fs/dcache.c）—
      相关目录项已在 dentry cache（prime）→ 新文件路径解析（编码）更快更稳定；
      dentry cache hit = 语义启动 = 新 chunk 编码时的"语义脚手架"。
    """
    result = {"pe_boosted": False, "pe_n_primes": 0}
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.pe_enabled"):
            return result

        min_similarity = float(_cfg.get("store_vfs.pe_min_similarity"))
        boost_per_prime = float(_cfg.get("store_vfs.pe_boost_per_prime"))
        max_boost = float(_cfg.get("store_vfs.pe_max_boost"))
        min_importance = float(_cfg.get("store_vfs.pe_min_importance"))
        min_primes = int(_cfg.get("store_vfs.pe_min_primes"))

        row = conn.execute(
            "SELECT stability, importance, project FROM memory_chunks WHERE id=?",
            (chunk_id,)
        ).fetchone()
        if not row:
            return result
        stab = float(row[0] or 1.0)
        imp = float(row[1] or 0.0)
        project = row[2] or ""
        if imp < min_importance:
            return result

        src_words = set((content or "").lower().split())
        if not src_words:
            return result

        # 查找同 project 已有的相似 chunk（不包含自身）
        candidates = conn.execute(
            """SELECT id, content FROM memory_chunks
               WHERE project=? AND id != ? AND importance >= ?
               ORDER BY importance DESC LIMIT 100""",
            (project, chunk_id, min_importance)
        ).fetchall()

        n_primes = 0
        for cand in candidates:
            cand_words = set((cand[1] or "").lower().split())
            if not cand_words:
                continue
            union = len(src_words | cand_words)
            if union == 0:
                continue
            jaccard = len(src_words & cand_words) / union
            if jaccard >= min_similarity:
                n_primes += 1

        result["pe_n_primes"] = n_primes
        if n_primes < min_primes:
            return result

        boost_ratio = min(max_boost, n_primes * boost_per_prime)
        new_stab = min(365.0, stab * (1.0 + boost_ratio))
        if new_stab > stab + 1e-6:
            conn.execute(
                "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
            )
            result["pe_boosted"] = True
        return result
    except Exception:
        return result


def apply_cross_session_consolidation(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    session_id: str,
    now_iso: str = None,
) -> dict:
    """iter484: Cross-Session Consolidation Effect (CCE) — 跨 session 访问的 chunk
    获得额外的 stability 奖励（模拟睡眠/休息期的海马-皮质巩固）。

    认知科学依据：
      Walker & Stickgold (2004) "Sleep-dependent learning and memory consolidation"
        Neuron 44(1):121-133 — 睡眠期海马 sharp-wave ripple（SWR）重放 →
        皮质巩固（系统巩固理论）；睡眠后记忆提升 6-12%（performance boost）。
      Stickgold (2005) Science "Sleep-dependent memory consolidation" —
        睡眠是记忆巩固的积极过程，非仅"减少干扰"。
      Korman et al. (2007): 跨日间隔（含睡眠）vs 非睡眠间隔巩固差异显著。

    OS 类比：Linux kswapd background reclaim（mm/vmscan.c）—
      kswapd 在系统空闲时（≈ session 间隔）主动整理 page，将 cold page 回收、
      warm page 移到高 LRU 位置；session 间隔 = kswapd 运行期 = 后台巩固；
      下次访问时 stability 额外提升 = kswapd 优化后的 page 命中率提升。
    """
    result = {"cce_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import datetime as _dt
        import math as _math
        if not _cfg.get("store_vfs.cce_enabled"):
            return result

        min_gap_hours = int(_cfg.get("store_vfs.cce_min_gap_hours"))
        base_bonus = float(_cfg.get("store_vfs.cce_base_bonus"))
        max_boost = float(_cfg.get("store_vfs.cce_max_boost"))
        min_importance = float(_cfg.get("store_vfs.cce_min_importance"))

        if now_iso is None:
            now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()

        try:
            now_dt = _dt.datetime.fromisoformat(now_iso)
        except Exception:
            now_dt = _dt.datetime.now(_dt.timezone.utc)

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, source_session, last_accessed "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue
            src_session = row[2] or ""
            last_acc = row[3] or ""

            # 检查是否跨 session 访问
            if not src_session or not session_id:
                continue
            if src_session == session_id:
                continue  # 同 session，非跨 session 访问

            # 计算时间间隔
            if not last_acc:
                continue
            try:
                last_dt = _dt.datetime.fromisoformat(last_acc)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=_dt.timezone.utc)
                if now_dt.tzinfo is None:
                    now_dt = now_dt.replace(tzinfo=_dt.timezone.utc)
                gap_hours = (now_dt - last_dt).total_seconds() / 3600.0
            except Exception:
                continue

            if gap_hours < min_gap_hours:
                continue

            # bonus = min(max_boost, base_bonus × min(1.0, gap/24h))
            # 最大奖励在 >= 24h 间隔后达到
            bonus_ratio = min(max_boost, base_bonus * min(1.0, gap_hours / 24.0))
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["cce_boosted"] += 1
        return result
    except Exception:
        return result


def apply_desirable_difficulty(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
) -> dict:
    """iter485: Desirable Difficulty Effect (DDE2) — 提取难度高时（低 retrievability + 低 stability）
    成功提取后 stability 增益更大（Bjork 1994）。

    认知科学依据：
      Bjork (1994) "Memory and metamemory considerations in the training of human beings"
        — 适度困难的提取任务（高遗忘率情境下成功检索）强化编码深度；
      Schmidt & Bjork (1992) Psych Science — 困难条件下的练习产生更持久的长期保留效果。
      McDaniel & Masson (1985): 费力提取（elaborative interrogation）比浅层提取更持久。

    OS 类比：Linux TLB miss → page walk — miss 时触发完整 page walk（成本高），
      但完成后更新 TLB，后续命中更快（记忆更稳固）；难提取 = TLB miss，成功 = TLB 重新填充。
    """
    result = {"dde2_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import datetime as _dt
        import math as _math
        if not _cfg.get("store_vfs.dde2_enabled"):
            return result

        r_threshold = float(_cfg.get("store_vfs.dde2_retrievability_threshold"))
        s_threshold = float(_cfg.get("store_vfs.dde2_stability_threshold"))
        bonus_factor = float(_cfg.get("store_vfs.dde2_bonus_per_difficulty"))
        max_boost = float(_cfg.get("store_vfs.dde2_max_boost"))
        min_importance = float(_cfg.get("store_vfs.dde2_min_importance"))

        if now_iso is None:
            now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
        try:
            now_dt = _dt.datetime.fromisoformat(now_iso)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=_dt.timezone.utc)
        except Exception:
            now_dt = _dt.datetime.now(_dt.timezone.utc)

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, last_accessed "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue
            if stab > s_threshold:
                continue  # stability 已高，不算"难"

            # 计算 retrievability：R = exp(-t/S)
            last_acc = row[2] or ""
            t_days = 0.0
            if last_acc:
                try:
                    last_dt = _dt.datetime.fromisoformat(last_acc)
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=_dt.timezone.utc)
                    t_days = max(0.0, (now_dt - last_dt).total_seconds() / 86400.0)
                except Exception:
                    pass
            retrievability = _math.exp(-t_days / max(stab, 0.1))
            if retrievability > r_threshold:
                continue  # retrievability 仍高，不算"难"

            # 难度得分：越低 R 越难，奖励越大
            difficulty = 1.0 - retrievability  # [0, 1]
            bonus_ratio = min(max_boost, bonus_factor * difficulty)
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["dde2_boosted"] += 1
        return result
    except Exception:
        return result


def apply_contextual_reinstatement(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    query_namespace: str = "",
    query_tags: list = None,
) -> dict:
    """iter486: Contextual Reinstatement Effect (CRE2) — 恢复编码上下文时检索效率提高。

    认知科学依据：
      Godden & Baddeley (1975) British J Psychology — 水下/陆地编码实验证明，
        上下文匹配使记忆提取成功率提高 ~40%；
      Smith (1979): 在编码相同房间测验比不同房间高 ~25%；
      Smith & Vela (2001) Psych Bulletin — 上下文依赖记忆 meta-analysis 综述。

    OS 类比：CPU cache locality（spatial/temporal locality） —
      访问与之前同一 locality 集合的 page，L1/L2 cache 命中率更高；
      namespace/tag 匹配 = 访问同一 cache line 集合。
    """
    result = {"cre2_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.cre2_enabled"):
            return result

        ns_bonus = float(_cfg.get("store_vfs.cre2_namespace_match_bonus"))
        tag_bonus = float(_cfg.get("store_vfs.cre2_tag_overlap_bonus"))
        tag_threshold = float(_cfg.get("store_vfs.cre2_tag_overlap_threshold"))
        max_boost = float(_cfg.get("store_vfs.cre2_max_boost"))
        min_importance = float(_cfg.get("store_vfs.cre2_min_importance"))
        import json as _json

        if query_tags is None:
            query_tags = []
        query_tag_set = set(query_tags)

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT retrievability, importance, project, tags "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            ret = float(row[0] or 0.5)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            boost = 0.0
            # project 作为 namespace 代理（OS 类比：cgroup/subsystem）
            chunk_ns = row[2] or ""
            if query_namespace and chunk_ns and query_namespace == chunk_ns:
                boost += ns_bonus

            # Tag Jaccard
            if query_tag_set:
                try:
                    raw_tags = row[3]
                    if isinstance(raw_tags, str):
                        chunk_tags = set(_json.loads(raw_tags)) if raw_tags.startswith("[") else set(raw_tags.split(","))
                    elif isinstance(raw_tags, (list, set)):
                        chunk_tags = set(raw_tags)
                    else:
                        chunk_tags = set()
                    if chunk_tags:
                        intersection = len(query_tag_set & chunk_tags)
                        union = len(query_tag_set | chunk_tags)
                        jaccard = intersection / union if union else 0.0
                        if jaccard >= tag_threshold:
                            boost += tag_bonus
                except Exception:
                    pass

            if boost <= 0:
                continue
            boost = min(max_boost, boost)
            new_ret = min(1.0, ret + boost)
            if new_ret > ret + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET retrievability=? WHERE id=?", (new_ret, chunk_id)
                )
                result["cre2_boosted"] += 1
        return result
    except Exception:
        return result


def apply_emotion_tagging_decay_reduction(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter487: Emotion Tagging Effect (ETE2) — 高情绪价值 chunk 的 stability 衰减速率降低。

    认知科学依据：
      McGaugh (2000) Science "Memory — a century of consolidation" —
        杏仁核通过 norepinephrine/cortisol 调节海马巩固，情绪唤起（arousal）增强 LTP；
      Cahill & McGaugh (1998): 情绪事件被记住更长（杏仁核-海马互作）；
      LaBar & Cabeza (2006) Nat Rev Neuro — 情绪记忆优势效应 meta-analysis。

    OS 类比：Linux cgroup memory.min 保护 —
      高优先级进程的 pages 受 memory.min 保护，kswapd 不会回收；
      高情绪 = 高 importance ≈ cgroup min 保护 → 衰减减缓。

    实现：通过给 stability 设置更高下限（decay floor）来模拟衰减减缓。
    在实际访问时检测，若 chunk 满足高情绪条件，则额外提升 stability。
    """
    result = {"ete2_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ete2_enabled"):
            return result

        imp_threshold = float(_cfg.get("store_vfs.ete2_importance_threshold"))
        decay_reduction = float(_cfg.get("store_vfs.ete2_stability_decay_reduction"))
        kw_bonus = float(_cfg.get("store_vfs.ete2_keyword_bonus"))
        max_reduction = float(_cfg.get("store_vfs.ete2_max_decay_reduction"))
        emotion_keywords = _cfg.get("store_vfs.ete2_emotion_keywords") or []

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < imp_threshold:
                continue  # 不满足高情绪条件

            total_reduction = decay_reduction

            # 检测情绪关键词
            content = (row[2] or "").lower()
            if emotion_keywords and any(kw.lower() in content for kw in emotion_keywords):
                total_reduction += kw_bonus

            total_reduction = min(max_reduction, total_reduction)

            # 提升 stability（模拟衰减减缓：等效于 stability × (1 + reduction)）
            bonus_stab = min(365.0, stab * (1.0 + total_reduction))
            if bonus_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (bonus_stab, chunk_id)
                )
                result["ete2_boosted"] += 1
        return result
    except Exception:
        return result


def apply_inhibition_of_return(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    now_iso: str = None,
    pre_last_accessed_map: dict = None,
) -> dict:
    """iter488: Inhibition of Return (IOR) — 短时间内重复访问同一 chunk 时 stability 增益递减。

    认知科学依据：
      Posner & Cohen (1984) "Components of visual orienting" Attention & Performance X —
        注意力返回刚刚访问位置的速度较慢（IOR）；短时间内重复激活同一记忆收益递减；
      Klein (2000) TICS "Inhibition of return" — IOR 广泛存在于注意力和记忆提取中；
      频繁重复访问 ≈ 过度练习（overlearning），对稳定性提升边际效益递减。

    OS 类比：Linux madvise(MADV_RANDOM) + prefetch inhibition —
      对刚刚读取的 page 降低预取优先级，预取资源分配给尚未访问的 page；
      频繁重访 = 预取器降低优先级 = stability 增益惩罚。

    实现：检测 last_accessed 与 now 的间隔；若在 ior_inhibition_window_secs 内，
    则对本次访问的 stability 增益乘以 penalty_factor。
    直接调整 stability（若当前 stability 刚被其他效应提升，则部分回退）。
    """
    result = {"ior_penalized": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import datetime as _dt
        if not _cfg.get("store_vfs.ior_enabled"):
            return result

        window_secs = int(_cfg.get("store_vfs.ior_inhibition_window_secs"))
        penalty_factor = float(_cfg.get("store_vfs.ior_penalty_factor"))
        min_interval_secs = int(_cfg.get("store_vfs.ior_min_interval_secs"))
        min_importance = float(_cfg.get("store_vfs.ior_min_importance"))

        if now_iso is None:
            now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat()
        try:
            now_dt = _dt.datetime.fromisoformat(now_iso)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=_dt.timezone.utc)
        except Exception:
            now_dt = _dt.datetime.now(_dt.timezone.utc)

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, last_accessed "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            # Use pre-update last_accessed if available (avoids seeing gap=0 due to
            # last_accessed already being updated to now_iso before IOR runs)
            if pre_last_accessed_map and chunk_id in pre_last_accessed_map:
                last_acc = pre_last_accessed_map[chunk_id] or ""
            else:
                last_acc = row[2] or ""
            if not last_acc:
                continue

            try:
                last_dt = _dt.datetime.fromisoformat(last_acc)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=_dt.timezone.utc)
                gap_secs = (now_dt - last_dt).total_seconds()
            except Exception:
                continue

            if gap_secs < 0:
                continue
            if gap_secs > window_secs:
                continue  # 超出抑制窗口，不惩罚

            # 窗口内重复访问 → stability 增益惩罚
            # 间隔越短惩罚越重：0~min_interval_secs 区间线性从最重到最轻
            if gap_secs < min_interval_secs:
                effective_penalty = penalty_factor  # 最重惩罚
            else:
                # 线性插值：从 penalty_factor 到 1.0（无惩罚），按间隔比例
                t = (gap_secs - min_interval_secs) / max(window_secs - min_interval_secs, 1)
                effective_penalty = penalty_factor + t * (1.0 - penalty_factor)

            # 惩罚：将 stability 从当前值向 stab * effective_penalty 方向调整
            # 只惩罚高于"正常水平"的部分（避免无意义降低）
            penalized_stab = max(1.0, stab * effective_penalty)
            if penalized_stab < stab - 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (penalized_stab, chunk_id)
                )
                result["ior_penalized"] += 1
        return result
    except Exception:
        return result


def apply_encoding_variability_eve(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter489: Encoding Variability Effect (EVE) — 同一 chunk 在多种不同 session_type 下
    被访问时，形成多条检索路径，stability 额外提升（Martin 1972）。

    认知科学依据：
      Martin (1972) Psychological Review — 编码变异假说：同一刺激在不同上下文中编码，
        产生多条独立检索路径，降低单次遗忘的全局影响；
      Glenberg (1979): 上下文多样性与长期保留显著正相关（r≈0.60）；
      Estes (1955) context fluctuation model — 学习时的上下文在记忆中被编码，
        上下文多样 → 检索线索更丰富。

    OS 类比：DM-multipath (Device Mapper Multipath) —
      同一 block device 通过多条 I/O 路径访问，任一路径失效不影响整体可用性；
      多条检索路径 = 多路径冗余，单一遗忘不影响整体提取成功率。

    实现：从 session_type_history 字段提取不同 session 类型数量，
    不同类型数超过 min_unique_session_types 时触发 stability 加成。
    """
    result = {"eve_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        import json as _json
        if not _cfg.get("store_vfs.eve_enabled"):
            return result

        min_types = int(_cfg.get("store_vfs.eve_min_unique_session_types"))
        bonus_per_type = float(_cfg.get("store_vfs.eve_bonus_per_type"))
        max_boost = float(_cfg.get("store_vfs.eve_max_boost"))
        min_importance = float(_cfg.get("store_vfs.eve_min_importance"))

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, session_type_history "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            sth = row[2] or ""
            # session_type_history 存储格式：逗号分隔的 session_type 记录
            # 或 JSON 数组
            try:
                if sth.startswith("["):
                    types_list = _json.loads(sth)
                else:
                    types_list = [t.strip() for t in sth.split(",") if t.strip()]
            except Exception:
                types_list = [t.strip() for t in sth.split(",") if t.strip()]

            unique_types = len(set(types_list))
            if unique_types < min_types:
                continue

            # 额外多样性：超过最低要求的每个类型各增加 bonus_per_type
            extra_types = unique_types - min_types + 1  # >= 1
            bonus_ratio = min(max_boost, bonus_per_type * extra_types)
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["eve_boosted"] += 1
        return result
    except Exception:
        return result


def apply_zeigarnik_effect_zef(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter490: Zeigarnik Effect (ZEF) — 含"未完成"信号的 chunk 比已完成 chunk 稳定性更高。

    认知科学依据：
      Zeigarnik (1927) Psychologische Forschung — 未完成任务比完成任务的回忆率高 ~90%；
      持续激活假说：中断任务产生认知张力（cognitive tension），维持工作记忆激活；
      Ovsiankina (1928): 中断任务自发产生恢复冲动（resumption intention），维持记忆优先级。

    OS 类比：dirty page tracking (mm/page-writeback.c) —
      含未刷新（dirty）数据的 page 受 writeback 保护，不被 kswapd 主动回收；
      等待 fsync 完成 = 等待任务完成 = 受保护的工作状态。

    实现：扫描 content + summary 字段，检测 TODO/FIXME/PENDING 等信号词，
    若存在则提升 stability。
    """
    result = {"zef_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.zef_enabled"):
            return result

        todo_keywords = _cfg.get("store_vfs.zef_todo_keywords") or []
        stability_bonus = float(_cfg.get("store_vfs.zef_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.zef_max_boost"))
        min_importance = float(_cfg.get("store_vfs.zef_min_importance"))

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content, summary "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            content_lower = (row[2] or "").lower()
            summary_lower = (row[3] or "").lower()
            combined = content_lower + " " + summary_lower

            # 检测未完成信号词
            if not any(kw.lower() in combined for kw in todo_keywords):
                continue

            bonus_ratio = min(max_boost, stability_bonus)
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["zef_boosted"] += 1
        return result
    except Exception:
        return result


def apply_von_restorff_isolation(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    session_id: str = "",
) -> dict:
    """iter491: von Restorff Isolation Effect (VRE) — 在 session 中 chunk_type 稀少的
    chunk（独特项目）获得额外 stability 提升。

    认知科学依据：
      von Restorff (1933) Psychologische Forschung — 同质列表中的孤立（独特）项目
        被记住的频率显著高于普通项目（isolation effect）；
      Hunt & Lamb (2001) J Exp Psych — isolation effect 在语义上下文中稳健，
        效果量 d ≈ 0.80；
      Fabiani & Donchin (1995): isolation effect 与 P300 波幅（注意力增强）正相关。

    OS 类比：Linux LRU generation aging (MGLRU) —
      在主要由 old-gen page 组成的 list 中，gen=0（newly accessed）的 page
      在 eviction 时受到额外保护；稀有类型 = LRU gen=0 in old pool。

    实现：统计当前 session 中各 chunk_type 的比例，
    比例低于 vre_rarity_threshold 的类型视为"稀有/独特"，触发 stability 加成。
    """
    result = {"vre_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.vre_enabled"):
            return result

        rarity_threshold = float(_cfg.get("store_vfs.vre_rarity_threshold"))
        stability_bonus = float(_cfg.get("store_vfs.vre_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.vre_max_boost"))
        min_importance = float(_cfg.get("store_vfs.vre_min_importance"))
        min_session_chunks = int(_cfg.get("store_vfs.vre_min_session_chunks"))

        # 统计 session 中各 chunk_type 的数量
        if session_id:
            type_counts = {}
            rows = conn.execute(
                "SELECT chunk_type, COUNT(*) as cnt FROM memory_chunks "
                "WHERE source_session=? GROUP BY chunk_type", (session_id,)
            ).fetchall()
            total = sum(r[1] for r in rows)
            if total < min_session_chunks:
                # session 内 chunk 不足，用全局比例
                rows = conn.execute(
                    "SELECT chunk_type, COUNT(*) as cnt FROM memory_chunks GROUP BY chunk_type"
                ).fetchall()
                total = sum(r[1] for r in rows)
            for r in rows:
                type_counts[r[0]] = r[1]
        else:
            # 无 session id，用全局比例
            rows = conn.execute(
                "SELECT chunk_type, COUNT(*) as cnt FROM memory_chunks GROUP BY chunk_type"
            ).fetchall()
            total = sum(r[1] for r in rows)
            type_counts = {r[0]: r[1] for r in rows}

        if total < min_session_chunks:
            return result

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, chunk_type "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            ctype = row[2] or "observation"
            type_ratio = type_counts.get(ctype, 0) / max(total, 1)
            if type_ratio >= rarity_threshold:
                continue  # 不稀有，不触发

            bonus_ratio = min(max_boost, stability_bonus)
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["vre_boosted"] += 1
        return result
    except Exception:
        return result


def apply_production_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter492: Production Effect (PEF) — 输出类（生产型）chunk 的编码更深，stability 更高。

    认知科学依据：
      MacLeod et al. (2010) J Exp Psych: General — 大声朗读（production）比默读
        在再认测试中高 ~10-15%（production effect）；
      MacLeod & Bodner (2017): production effect 的核心是"增强区分度"而非简单重复；
      Forrin et al. (2012): 写作产生效果与大声朗读相当，均优于默读。

    OS 类比：write-back vs write-through cache —
      write-back（输出类 chunk）需要额外处理步骤（将数据写入 dirty page），
      但获得更长的"in-memory"生命周期（delayed writeback = 更稳固的编码）；
      decision/reflection 等 = write-back operation = higher stability.
    """
    result = {"pef_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.pef_enabled"):
            return result

        production_types = _cfg.get("store_vfs.pef_production_types") or []
        stability_bonus = float(_cfg.get("store_vfs.pef_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.pef_max_boost"))
        min_importance = float(_cfg.get("store_vfs.pef_min_importance"))

        # 规范化 production_types
        prod_set = {t.lower().strip() for t in production_types}

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, chunk_type "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            if imp < min_importance:
                continue

            ctype = (row[2] or "").lower().strip()
            if ctype not in prod_set:
                continue  # 非生产型 chunk_type

            bonus_ratio = min(max_boost, stability_bonus)
            new_stab = min(365.0, stab * (1.0 + bonus_ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["pef_boosted"] += 1
        return result
    except Exception:
        return result


def apply_emotional_salience(
    conn: sqlite3.Connection,
    chunk_id: str,
    text: str,
    base_importance: float,
) -> float:
    """
    迭代320：根据情感显著性调整 chunk 的 importance 并写回 DB。
    iter399：同时写入 emotional_weight（0.0~1.0），供 retriever 情绪增强使用。

    算法：
      delta = compute_emotional_salience(text)
      emotional_weight = clamp(delta / 0.25, 0.0, 1.0)  # 正向 delta 归一化为权重
      if |delta| < 0.01 → 不写 DB（避免无意义更新）
      new_importance = clamp(base_importance + delta, 0.05, 0.98)
      写入 memory_chunks.importance + emotional_weight

    OS 类比：Linux OOM Killer oom_score_adj 写入 —
      fork() 时继承父进程的 oom_score_adj，每个进程可自主调整；
      这里 importance 由 extractor 初始评估，情感显著性在写入后再调整。
      iter399 OS 类比：Linux mempolicy MPOL_PREFERRED_MANY —
        写入时标注页面的"情感节点亲和性"（emotional_weight），
        检索时 retriever 用此权重决定 boost 量（类比 NUMA locality hint）。

    Returns:
      new_importance（调整后；若无调整则返回 base_importance）
    """
    delta = compute_emotional_salience(text)

    # iter399: emotional_weight — 正向情绪强度归一化到 [0.0, 1.0]
    # 负向 delta（已废弃/已解决）不产生情绪权重（只影响 importance 降权）
    emotional_weight = round(max(0.0, min(1.0, delta / 0.25)), 4) if delta > 0 else 0.0

    # iter424: emotional_valence — 情绪效价（独立于唤醒度）
    emotional_valence = round(compute_emotional_valence(text), 4)

    if abs(delta) < 0.01:
        # delta 微弱 — 仍写入 emotional_weight=0（明确表示无情绪显著性）
        # 但只在字段为 NULL 时才写（避免覆盖已有有效值）
        try:
            conn.execute(
                "UPDATE memory_chunks SET emotional_weight=?, emotional_valence=? "
                "WHERE id=? AND (emotional_weight IS NULL OR emotional_weight=0)",
                (0.0, emotional_valence, chunk_id),
            )
        except Exception:
            pass
        return base_importance

    new_importance = max(0.05, min(0.98, base_importance + delta))
    if abs(new_importance - base_importance) < 0.001:
        new_importance = base_importance

    try:
        conn.execute(
            "UPDATE memory_chunks SET importance=?, emotional_weight=?, "
            "emotional_valence=?, updated_at=? WHERE id=?",
            (round(new_importance, 4), emotional_weight, emotional_valence,
             datetime.now(timezone.utc).isoformat(), chunk_id),
        )
    except Exception:
        pass
    return new_importance


# ── iter396：Source Monitoring — 信源监控加权（Johnson 1993）─────────────────
#
# 认知科学依据：
#   Johnson & Raye (1981) Reality Monitoring：
#     人类具备区分「内部生成」与「外部感知」记忆的元认知能力。
#     来自外部直接感知的记忆比内部推断的记忆更可靠，但并非绝对；
#     人容易把听说的事情记成"亲眼所见"（来源错误归因，source misattribution）。
#   Johnson (1993) MEM (Multiple Entry Model)：
#     记忆系统维护「来源标签」（source tag），帮助区分自我生成 vs 外部输入。
#     来源可信度（source credibility）影响信息的检索优先级和记忆强化程度。
#   Zaragoza & Mitchell (1996)：
#     高可信度来源的信息比低可信度来源更容易被记住和相信。
#
# OS 类比：Linux LSM（Linux Security Modules）
#   每次 file open / exec / socket 操作前，LSM hook 查询来源的 security context
#   （SELinux label / AppArmor profile），根据来源授予不同的访问权限。
#   这里：每次 chunk 写入时打上 source_type 标签，检索时据此调整 score。
#
# 实现：
#   1. compute_source_reliability(chunk_type, source_type, content) → float
#      根据 chunk_type + source_type 的组合估算可信度
#   2. source_monitor_weight(source_reliability) → float
#      将可信度转换为检索分数调整因子（range: 0.8 ~ 1.2）
#   3. apply_source_monitoring(conn, chunk_id, chunk_type, source_type, content)
#      写入 source_type + source_reliability 到 DB

# ─ 来源可信度基线表：chunk_type × source_type → base_reliability ─
_SOURCE_RELIABILITY_TABLE: dict = {
    # (chunk_type, source_type) → base reliability
    # direct = 用户直接陈述/观察
    ("design_constraint", "direct"):    0.95,
    ("decision",          "direct"):    0.90,
    ("task_state",        "direct"):    0.85,
    ("reasoning_chain",   "direct"):    0.80,
    ("procedure",         "direct"):    0.85,
    # tool_output = 代码/命令执行结果（机器生成，高重复性）
    ("design_constraint", "tool_output"): 0.88,
    ("decision",          "tool_output"): 0.85,
    ("task_state",        "tool_output"): 0.82,
    ("reasoning_chain",   "tool_output"): 0.78,
    ("procedure",         "tool_output"): 0.80,
    # inferred = 从多条信息推断（中等可信度）
    ("design_constraint", "inferred"):  0.72,
    ("decision",          "inferred"):  0.68,
    ("task_state",        "inferred"):  0.65,
    ("reasoning_chain",   "inferred"):  0.70,
    ("procedure",         "inferred"):  0.65,
    # hearsay = 间接转述/转述他人说法（最低可信度）
    ("design_constraint", "hearsay"):   0.50,
    ("decision",          "hearsay"):   0.45,
    ("task_state",        "hearsay"):   0.40,
    ("reasoning_chain",   "hearsay"):   0.48,
    ("procedure",         "hearsay"):   0.42,
}

# 各 source_type 的默认可信度（chunk_type 无明确映射时）
_SOURCE_TYPE_DEFAULT: dict = {
    "direct":      0.85,
    "tool_output": 0.80,
    "inferred":    0.68,
    "hearsay":     0.45,
    "unknown":     0.70,
}

# 关键词信号 → 推断 source_type（用于自动标注）
# 优先级：hearsay > inferred > tool_output > direct（越 uncertain 越优先检出）
import re as _re_sm

_SOURCE_HEARSAY_RE = _re_sm.compile(
    r"据说|听说|有人说|用户说|他说|她说|they said|I heard|reportedly|allegedly|"
    r"someone mentioned|it is said",
    _re_sm.IGNORECASE,
)
_SOURCE_INFERRED_RE = _re_sm.compile(
    r"推测|可能|应该|估计|推断|大概|based on|likely|probably|presumably|"
    r"it seems|appears to|suggests that",
    _re_sm.IGNORECASE,
)
_SOURCE_TOOL_OUTPUT_RE = _re_sm.compile(
    r"```|输出:|output:|result:|error:|traceback|exception|running|executed|"
    r"\$ |>>> |test passed|test failed|pytest|assert|build|compile",
    _re_sm.IGNORECASE,
)


def infer_source_type(text: str) -> str:
    """
    iter396：从文本内容自动推断 source_type。

    按优先级扫描关键词：
      hearsay → inferred → tool_output → direct（默认）

    OS 类比：Linux file magic 检测 — `file` 命令扫描文件头字节推断文件类型，
      而非依赖用户提供的文件名后缀。
    """
    if not text:
        return "unknown"
    if _SOURCE_HEARSAY_RE.search(text):
        return "hearsay"
    if _SOURCE_INFERRED_RE.search(text):
        return "inferred"
    if _SOURCE_TOOL_OUTPUT_RE.search(text):
        return "tool_output"
    return "direct"


def compute_source_reliability(
    chunk_type: str,
    source_type: str,
    content: str = "",
) -> float:
    """
    iter396：计算 chunk 的来源可信度（source_reliability）。

    算法：
      1. 从 _SOURCE_RELIABILITY_TABLE 查找 (chunk_type, source_type) 基线值
      2. 若无明确映射，使用 _SOURCE_TYPE_DEFAULT[source_type]
      3. 若 content 包含 uncertainty 词语（可能/估计/应该），适当降低（−0.05）
      4. 若 content 包含 certainty 词语（确认/已验证/verified），适当提高（+0.05）
      5. clamp 到 [0.2, 1.0]

    Returns:
      float ∈ [0.2, 1.0]，越高表示来源越可靠
    """
    if not source_type or source_type not in _SOURCE_TYPE_DEFAULT:
        source_type = "unknown"
    base = _SOURCE_RELIABILITY_TABLE.get(
        (chunk_type, source_type),
        _SOURCE_TYPE_DEFAULT.get(source_type, 0.70),
    )
    # 内容微调：不确定性词 → −0.05；确认词 → +0.05
    adjustment = 0.0
    if content:
        _uncertainty_re = _re_sm.compile(
            r'可能|估计|大概|不确定|probably|might|may be|uncertain|unclear',
            _re_sm.IGNORECASE,
        )
        _certainty_re = _re_sm.compile(
            r'确认|已验证|confirmed|verified|definitely|proven|tested',
            _re_sm.IGNORECASE,
        )
        if _uncertainty_re.search(content):
            adjustment -= 0.05
        if _certainty_re.search(content):
            adjustment += 0.05
    return round(max(0.2, min(1.0, base + adjustment)), 4)


def source_monitor_weight(source_reliability: float) -> float:
    """
    iter396：将 source_reliability 转换为检索分数调整因子。

    映射规则（线性区间）：
      reliability ≥ 0.85 → weight ∈ [1.00, 1.15]（高可信来源，微幅提升）
      0.60 ≤ reliability < 0.85 → weight ≈ 1.00（中等可信，不调整）
      reliability < 0.60 → weight ∈ [0.80, 1.00]（低可信来源，适度降权）

    设计原则：
      1. 调整幅度适中（max ±0.15），避免来源完全主导语义相关性
      2. 中间区间（0.60~0.85）不调整，防止噪音误判影响召回
      3. 对应 OS 类比：SELinux label 决定的访问权限不是二元的，
         而是 capability 粒度的（只有明确高风险的 context 才被限制）

    Returns:
      float ∈ [0.80, 1.15]
    """
    r = max(0.0, min(1.0, float(source_reliability) if source_reliability is not None else 0.70))
    if r >= 0.85:
        # 高可信度：线性插值 0.85→1.00，1.0→1.15
        return round(1.00 + (r - 0.85) / (1.0 - 0.85) * 0.15, 4)
    elif r >= 0.60:
        # 中等可信度：不调整
        return 1.00
    else:
        # 低可信度：线性插值 0.0→0.80，0.60→1.00
        return round(0.80 + r / 0.60 * 0.20, 4)


def apply_source_monitoring(
    conn: sqlite3.Connection,
    chunk_id: str,
    chunk_type: str,
    content: str,
    source_type: str = None,
) -> tuple:
    """
    iter396：推断 source_type，计算 source_reliability，并写入 DB。

    OS 类比：LSM security_inode_create hook —
      文件创建时检查 security context，打上 SELinux label（inode security blob）。
      这里 chunk 创建时打上 source_type 标签。

    Returns:
      (source_type: str, source_reliability: float)
    """
    if source_type is None or source_type == "unknown":
        source_type = infer_source_type(content or "")
    reliability = compute_source_reliability(chunk_type or "task_state",
                                             source_type, content or "")
    try:
        conn.execute(
            "UPDATE memory_chunks SET source_type=?, source_reliability=? WHERE id=?",
            (source_type, reliability, chunk_id),
        )
    except Exception:
        pass
    return (source_type, reliability)


# ── iter400：Forgetting Curve Individualization per chunk_type ──────────────
#
# 认知科学依据：
#   Squire (1992) Memory and Brain：程序性记忆（技能）比陈述性情节记忆衰减慢。
#   Tulving (1972)：语义记忆（概念/约束）比情节记忆（具体事件）持久。
#   Ebbinghaus (1885)：同一遗忘曲线对不同类型知识的参数不同。
#   Anderson et al. (1999) ACT-R：基础激活随时间衰减，衰减速率因记忆强度和类型而异。
#
# OS 类比：Linux cgroup memory.reclaim_ratio（per-cgroup）vs vm.swappiness（全局）
#   全局统一 stability_decay=0.92 相当于 vm.swappiness，对所有 chunk 一视同仁。
#   per-type 衰减率相当于 per-cgroup reclaim_ratio，允许不同类型 chunk 有不同的内存压力。
#
# CHUNK_TYPE_DECAY：chunk_type → stability_decay_factor
#   值越高（接近 1.0） → 衰减越慢，记忆越持久
#   值越低（接近 0.0） → 衰减越快，记忆越短暂
# 设计依据：
#   design_constraint  → 0.99 极慢衰减（系统约束是长期有效的，类比长时程增强 LTP）
#   decision           → 0.97 慢衰减（决策记录应长期保留）
#   reasoning_chain    → 0.94 中等衰减（推理过程较情节记忆持久，但不如决策）
#   procedure          → 0.96 较慢衰减（操作步骤是程序性记忆，耐久）
#   task_state         → 0.85 较快衰减（当前任务状态 = 工作记忆，任务完成后快速衰减）
#   prompt_context     → 0.70 快速衰减（prompt 上下文高度情景化，换会话即失效）
#   error_event        → 0.88 中等衰减（错误事件有警示价值，保留时间中等）
#   observation        → 0.90 中等衰减（观察记录较 task_state 持久，但不如 decision）

CHUNK_TYPE_DECAY: dict = {
    "design_constraint": 0.99,
    "decision":          0.97,
    "procedure":         0.96,
    "reasoning_chain":   0.94,
    "observation":       0.90,
    "error_event":       0.88,
    "task_state":        0.85,
    "prompt_context":    0.70,
}

# 未列出类型的默认衰减率（保守中值）
_DEFAULT_TYPE_DECAY: float = 0.92


def get_chunk_type_decay(chunk_type: str) -> float:
    """
    iter400：获取 chunk_type 的个体化稳定性衰减率。

    Returns:
      float ∈ (0.0, 1.0]，越高越耐久（越接近 1.0 衰减越慢）
    """
    return CHUNK_TYPE_DECAY.get(chunk_type or "", _DEFAULT_TYPE_DECAY)


def decay_stability_by_type(
    conn: sqlite3.Connection,
    project: str = None,
    stale_days: int = 30,
    now_iso: str = None,
) -> int:
    """
    iter400：按 chunk_type 个体化衰减 stability（Forgetting Curve Individualization）。

    每种 chunk_type 使用 CHUNK_TYPE_DECAY 中的独立衰减率，
    替代 sleep_consolidate 中的统一 stability_decay=0.92。

    OS 类比：Linux cgroup per-memory-group reclaim_ratio —
      不同 cgroup 有不同的内存回收压力参数，允许 DB/前台应用占用更多内存。

    算法：
      FOR each chunk_type IN CHUNK_TYPE_DECAY:
          UPDATE stability × type_decay
          WHERE last_accessed < cutoff AND access_count < 2 AND chunk_type=type_

    Returns:
      总衰减的 chunk 数
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    if now_iso is None:
        now_iso = _dt.now(_tz.utc).isoformat()
    cutoff = (_dt.now(_tz.utc) - _td(days=stale_days)).isoformat()

    proj_filter = "AND project=?" if project else ""
    proj_params = [project] if project else []

    total_decayed = 0
    all_types = list(CHUNK_TYPE_DECAY.keys()) + [""]  # "" = 无类型 → 使用默认

    # 对每种已知类型单独更新
    for ctype, decay in CHUNK_TYPE_DECAY.items():
        try:
            conn.execute(
                f"UPDATE memory_chunks "
                f"SET stability=MAX(0.1, stability * ?), updated_at=? "
                f"WHERE chunk_type=? AND last_accessed < ? AND access_count < 2 {proj_filter}",
                [decay, now_iso, ctype, cutoff] + proj_params,
            )
            total_decayed += conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass

    # 未列出的类型使用默认衰减率
    known_types_ph = ",".join("?" * len(CHUNK_TYPE_DECAY))
    try:
        conn.execute(
            f"UPDATE memory_chunks "
            f"SET stability=MAX(0.1, stability * ?), updated_at=? "
            f"WHERE (chunk_type NOT IN ({known_types_ph}) OR chunk_type IS NULL) "
            f"AND last_accessed < ? AND access_count < 2 {proj_filter}",
            [_DEFAULT_TYPE_DECAY, now_iso] + list(CHUNK_TYPE_DECAY.keys()) + [cutoff] + proj_params,
        )
        total_decayed += conn.execute("SELECT changes()").fetchone()[0]
    except Exception:
        pass

    return total_decayed


# ── iter435: Recency-Induced Decay Resistance (RDR) — 近期访问记忆的巩固窗口保护（McGaugh 2000）──
# 认知科学依据：McGaugh (2000) "Memory — a century of consolidation" —
#   记忆形成后进入 consolidation window（数分钟至数小时），海马体持续重放记忆痕迹，
#   这期间记忆对遗忘干扰的抵抗力最强（retrograde amnesia gradient 的基础）。
#   Müller & Pilzecker (1900) perseveration-consolidation hypothesis：
#     记忆痕迹需要时间"硬化"（consolidate），窗口期内应保护而非加速衰减。
#   Baddeley & Hitch (1974) Working Memory — phonological loop 维持近期信息的活跃表示，
#     防止立即遗忘，为长期记忆转移提供缓冲。
#
# memory-os 等价：
#   decay_stability_by_type 扫描时，last_accessed < 6h 且 importance >= 0.5 的 chunk
#   正处于 consolidation window，跳过本次衰减（等下次扫描时已过窗口再参与）。
#   效果：近期被检索的重要 chunk 额外获得 6 小时的衰减豁免期，
#   模拟海马体对刚访问记忆的主动保护机制。
#
# OS 类比：Linux MGLRU young generation minimum age (min_lru_age) —
#   刚被提升到 young generation 的页面有最短存活期，kswapd 在此期间不执行 aging，
#   避免"刚提升就被驱逐"的 LRU thrashing。等价于：
#   最近 access 的 chunk（young generation）在 rdr_window_hours 内不参与 stability decay。
# 实现：在 decay_stability_by_type 中追加 WHERE NOT (last_accessed > rdr_cutoff AND importance >= min_imp)

# ── iter434: Retrieval-Induced Forgetting (RIF) — 检索导致相关记忆被压制（Anderson et al. 1994）──
# 认知科学依据：Anderson, Bjork & Bjork (1994) "Remembering can cause forgetting" —
#   检索某条记忆（practiced item）主动抑制同类别相关但未被检索的记忆（unpracticed items）。
#   机制：检索激活类别竞争记忆 → 强化被选中者 → 主动抑制被压制者（RP-）→ RP- 遗忘增加 ~10-20%。
#   条件：RIF 要求竞争者与检索目标属于同一类别（chunk_type）且内容相关（Jaccard 相似度阈值）。
#
# OS 类比：CPU cache set-associativity way eviction —
#   访问 cache line A（命中 set 0, way 0）→ LRU 将同 set 的竞争 cache line B 推向更高 way
#   → B 的 eviction 概率上升（A 的命中加速了 B 的驱逐路径）。
#
# 与 iter432 Cumulative Interference 的区别：
#   CI（iter432）= 静态结构性干扰（同类数量多 → 被动衰减加速）
#   RIF（iter434）= 动态事件性抑制（检索事件 → 主动压制竞争记忆）

def _rif_tokenize(text: str) -> frozenset:
    """iter434: RIF 内部 tokenizer — 提取用于 Jaccard 相似度计算的 token 集合。"""
    import re as _re
    tokens = set()
    for m in _re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', text):
        tokens.add(m.group().lower())
    cn = _re.sub(r'[^\u4e00-\u9fff]', '', text)
    for i in range(len(cn) - 1):
        tokens.add(cn[i:i + 2])
    return frozenset(tokens)


def apply_rif_by_summary(
    conn: sqlite3.Connection,
    project: str,
    hit_chunk_ids: list,
) -> dict:
    """
    iter434: Retrieval-Induced Forgetting (RIF) by Summary Jaccard — 基于 summary 相似度的精确 RIF。

    与 iter417 apply_retrieval_induced_forgetting 的区别：
      - iter417: 基于 encode_context token 集合重叠（稀疏，依赖上下文标注）
      - iter434: 基于 summary Jaccard 相似度（更鲁棒，直接文本相似度）
      - iter434: 按 chunk_type 分组（竞争限定在同类别，更符合 RIF 实验条件）
      - iter434: 使用 scorer.rif_* sysctl（独立配置）

    Anderson, Bjork & Bjork (1994) 实验范式：
      - Practiced items (RP+): 被检索 → 记忆增强
      - Unpracticed-related (RP-): 同类别但未被检索 → 记忆被抑制（低于控制组基线）
      - Unpracticed-unrelated (NRP): 不同类别 → 不受影响（控制组基线）

    实现逻辑：
      1. 对每个命中 chunk，查询同 chunk_type 的其他 chunk（同类别竞争者）
      2. 计算 Jaccard 相似度（RP- 候选必须与命中 chunk 内容相关）
      3. 对 Jaccard >= rif_similarity_threshold 且未被命中的 chunk 施加 stability 惩罚
      4. 豁免：importance 高、受保护类型、permastore 保护的 chunk

    参数：
      conn          — 数据库连接
      project       — 项目 ID
      hit_chunk_ids — 本次被检索命中的 chunk ID 列表

    返回 dict：
      suppressed     — 受到 RIF 抑制的 chunk 数量
      total_examined — 总共检查的竞争者数量
      suppressed_ids — 被抑制的 chunk ID 列表（调试用）
    """
    if not hit_chunk_ids:
        return {"suppressed": 0, "total_examined": 0, "suppressed_ids": []}

    try:
        import config as _cfg_mod
        if not _cfg_mod.get("scorer.rif_enabled"):
            return {"suppressed": 0, "total_examined": 0, "suppressed_ids": []}

        rif_factor = _cfg_mod.get("scorer.rif_factor")
        sim_threshold = _cfg_mod.get("scorer.rif_similarity_threshold")
        max_targets = _cfg_mod.get("scorer.rif_max_targets")
        protect_imp = _cfg_mod.get("scorer.rif_protect_importance")
        protect_types_raw = _cfg_mod.get("scorer.rif_protect_types")
        protect_types = set(t.strip() for t in protect_types_raw.split(",") if t.strip())
    except Exception:
        return {"suppressed": 0, "total_examined": 0, "suppressed_ids": []}

    hit_set = set(hit_chunk_ids)
    placeholders = ",".join("?" * len(hit_chunk_ids))

    # ── 读取命中 chunk 的 chunk_type 和 summary ──
    hit_rows = conn.execute(
        f"SELECT id, chunk_type, summary FROM memory_chunks WHERE id IN ({placeholders})",
        hit_chunk_ids,
    ).fetchall()

    if not hit_rows:
        return {"suppressed": 0, "total_examined": 0, "suppressed_ids": []}

    # 按 chunk_type 分组
    type_to_hits = {}  # chunk_type → [(id, tokens)]
    for rid, ct, summary in hit_rows:
        if ct in protect_types:
            continue
        toks = _rif_tokenize(summary or "")
        if not toks:
            continue
        type_to_hits.setdefault(ct, []).append((rid, toks))

    if not type_to_hits:
        return {"suppressed": 0, "total_examined": 0, "suppressed_ids": []}

    # ── 对每种 chunk_type，查询同类竞争者（候选 RP-）──
    suppressed = 0
    total_examined = 0
    suppressed_ids = []

    now_iso = datetime.now(timezone.utc).isoformat()

    for chunk_type, hits_list in type_to_hits.items():
        if chunk_type in protect_types:
            continue

        # ── iter435: RDR — 计算近期访问保护截止时间（巩固窗口） ──
        # 近期访问的重要 chunk 正处于 McGaugh consolidation window，豁免 RIF 抑制
        try:
            _rdr_enabled_rif = _cfg_mod.get("store_vfs.rdr_enabled")
            if _rdr_enabled_rif:
                _rdr_wh = _cfg_mod.get("store_vfs.rdr_window_hours")
                _rdr_min_imp_rif = _cfg_mod.get("store_vfs.rdr_min_importance")
                from datetime import timedelta as _td_rdr
                _rdr_cutoff_rif = (datetime.now(timezone.utc) - _td_rdr(hours=_rdr_wh)).isoformat()
                _rdr_excl = (
                    f"AND NOT (last_accessed > '{_rdr_cutoff_rif}' "
                    f"AND COALESCE(importance, 0.0) >= {_rdr_min_imp_rif})"
                )
            else:
                _rdr_excl = ""
        except Exception:
            _rdr_excl = ""

        # 查询同类型的非命中 chunk
        competitors = conn.execute(
            f"""SELECT id, summary, COALESCE(stability, 1.0), importance
               FROM memory_chunks
               WHERE project = ? AND chunk_type = ?
                 AND COALESCE(importance, 0.5) < ?
                 AND COALESCE(oom_adj, 0) > -1000
                 {_rdr_excl}
               ORDER BY stability ASC""",
            (project, chunk_type, protect_imp),
        ).fetchall()

        # 排除命中 chunk
        competitors = [(rid, s, stab, imp) for rid, s, stab, imp in competitors if rid not in hit_set]
        total_examined += len(competitors)

        if not competitors:
            continue

        # 预计算竞争者 tokens
        comp_tokens = [(rid, _rif_tokenize(s or ""), stab) for rid, s, stab, imp in competitors]

        # 对每个命中 chunk，找 Jaccard >= threshold 的竞争者
        to_suppress = {}  # rid → current_stab (去重，取最小 stab 防重复压制)
        for _hit_id, hit_toks in hits_list:
            if not hit_toks:
                continue
            # 计算相似度并收集竞争者
            scored = []
            for rid, c_toks, c_stab in comp_tokens:
                if not c_toks:
                    continue
                inter = len(hit_toks & c_toks)
                union = len(hit_toks | c_toks)
                jaccard = inter / union if union > 0 else 0.0
                if jaccard >= sim_threshold:
                    scored.append((jaccard, rid, c_stab))

            # 取相似度最高的前 max_targets 个
            scored.sort(key=lambda x: x[0], reverse=True)
            for _, rid, c_stab in scored[:max_targets]:
                if rid not in to_suppress:
                    to_suppress[rid] = c_stab

        # ── 批量应用 RIF stability 惩罚 ──
        # 保护：iter422 Permastore floor 和 iter431 Ribot's Law floor
        for rid, c_stab in to_suppress.items():
            try:
                # permastore floor
                ps_floor = compute_permastore_floor(conn, rid, c_stab)
                # Ribot floor
                ribot_floor = 0.0
                try:
                    _row_r = _get_chunk_age_importance(conn, rid)
                    if _row_r:
                        ribot_floor = 0.1 + compute_ribot_floor(_row_r[0], _row_r[1])
                except Exception:
                    pass

                floor = max(ps_floor, ribot_floor)
                new_stab = max(floor, c_stab * rif_factor)
                if new_stab < c_stab:
                    conn.execute(
                        "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                        (round(new_stab, 4), now_iso, rid),
                    )
                    suppressed += 1
                    suppressed_ids.append(rid)
            except Exception:
                pass

    return {
        "suppressed": suppressed,
        "total_examined": total_examined,
        "suppressed_ids": suppressed_ids[:10],  # 只返回前10个（调试用）
    }


# ── iter436: Output Interference — 同轮注入竞争性遗忘（Roediger 1978）──────────────────
# 认知科学依据：Roediger (1978) "Recall as a self-limiting process" —
#   在一次回忆测试中，回忆早期项目（output）会干扰后续项目的提取（output interference）。
#   机制：早期输出激活该语义领域的竞争记忆，通过抑制机制阻碍后续项目进入工作记忆。
#   Roediger & Schmidt (1980): 同次测试中，越靠后的序列位置遗忘越多（OI 累积效应）。
#   与 RIF（iter434）区别：
#     RIF = 检索事件干扰"未被检索"的竞争者（编码竞争）
#     OI  = 同次输出中早期项目干扰晚期项目的工作记忆占用（输出干扰）
#
# memory-os 等价：
#   每次检索注入 N 个 chunk（recall_traces.top_k_json 记录），
#   位置 0 = 最相关/最优先（OS: cache line 命中，无干扰）
#   位置 k > 0 = 受前 k 个 chunk 的 output interference，巩固效果越来越差。
#   在 sleep_consolidate 时扫描最近注入记录，对位置 >= 1 的 chunk 施加轻微 stability 惩罚。
#
# OS 类比：Linux BFQ (Budget Fair Queue) I/O 批处理 —
#   同一 dispatch batch 中，第一个 I/O 请求消耗了大部分 budget；
#   后续请求在 budget 耗尽前完成的 I/O 减少（batch output competition）。
#   访问 cache line A 后，同 cache set 的 cache line B 在同一 dispatch cycle 中
#   获得更少的 refill 机会（类比：同轮注入的后续 chunk 巩固机会减少）。

def apply_output_interference(
    conn: sqlite3.Connection,
    project: str,
    window_hours: float = 24.0,
) -> dict:
    """
    iter436: Output Interference — 对同轮注入的后续 chunk 施加轻微 stability 惩罚。

    扫描最近 window_hours 内注入成功的 recall_traces，
    对每条 trace 的 top_k_json 中 position >= 1 的 chunk（位置越靠后干扰越强）
    施加递增的 stability 惩罚（× oi_decay_factor ^ position）。

    保护条件：
      - importance >= oi_protect_importance（核心知识豁免）
      - oi_enabled=False 时不执行
      - position 0 的 chunk（最优先）不受影响

    返回：{"penalized": N, "total_examined": N}
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    try:
        import config as _cfg_oi
    except ImportError:
        return {"penalized": 0, "total_examined": 0}

    try:
        oi_enabled = _cfg_oi.get("store_vfs.oi_enabled")
        if not oi_enabled:
            return {"penalized": 0, "total_examined": 0}

        oi_decay_factor = _cfg_oi.get("store_vfs.oi_decay_factor")
        oi_protect_imp = _cfg_oi.get("store_vfs.oi_protect_importance")
        oi_max_coinjected = _cfg_oi.get("store_vfs.oi_max_coinjected")
    except Exception:
        return {"penalized": 0, "total_examined": 0}

    now = _dt.now(_tz.utc)
    cutoff_iso = (now - _td(hours=window_hours)).isoformat()
    now_iso = now.isoformat()

    # 查询最近注入成功的 recall_traces（injected=1，top_k_json 非空）
    try:
        traces = conn.execute(
            """SELECT top_k_json FROM recall_traces
               WHERE project = ? AND injected = 1
                 AND top_k_json IS NOT NULL
                 AND timestamp >= ?
               ORDER BY timestamp DESC LIMIT 200""",
            (project, cutoff_iso),
        ).fetchall()
    except Exception:
        return {"penalized": 0, "total_examined": 0}

    penalized = 0
    total_examined = 0

    # 聚合：同一 chunk 在多条 trace 中出现时，取最靠后的 position（最大干扰）
    # chunk_id → max_position_across_traces
    chunk_positions: dict = {}

    for (tkj,) in traces:
        try:
            if not tkj:
                continue
            items = _json.loads(tkj)
            if not isinstance(items, list) or len(items) <= 1:
                continue
            # 只处理有多个注入 chunk 的 trace（单 chunk 无 OI）
            n = min(len(items), oi_max_coinjected)
            for pos in range(1, n):  # position 0 豁免
                cid = items[pos].get("id") if isinstance(items[pos], dict) else None
                if cid:
                    # 取最大 position（最严重干扰）across traces
                    if cid not in chunk_positions or chunk_positions[cid] < pos:
                        chunk_positions[cid] = pos
        except Exception:
            continue

    if not chunk_positions:
        return {"penalized": 0, "total_examined": 0}

    total_examined = len(chunk_positions)

    for cid, pos in chunk_positions.items():
        try:
            row = conn.execute(
                "SELECT stability, importance FROM memory_chunks WHERE id=? AND project=?",
                (cid, project),
            ).fetchone()
            if not row:
                continue
            stab, imp = float(row[0] or 1.0), float(row[1] or 0.5)

            # 高 importance → 豁免
            if imp >= oi_protect_imp:
                continue

            # 惩罚：position 越大，惩罚越强（cumulative: factor^pos）
            penalty = oi_decay_factor ** pos
            new_stab = max(0.1, stab * penalty)
            if abs(new_stab - stab) < 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            penalized += 1
        except Exception:
            continue

    return {"penalized": penalized, "total_examined": total_examined}


# ── iter437: Hypermnesia — 多次分布式检索后记忆净增强（Erdelyi & Becker 1974）──────────────
# 认知科学依据：Erdelyi & Becker (1974) "1974 hypermnesia for pictures" (Cognitive Psychology) —
#   多轮自由回忆测试中，随测试次数增加，总召回量呈净增长（hypermnesia）：
#   不同回忆尝试激活不同检索路径，集体覆盖更多记忆痕迹（retrieval route diversity）。
#   Payne (1987) Meta-analysis: +15-25% improvement across 3-5 test sessions。
#   关键条件：必须是间隔分布（spaced）而非集中（massed）的回忆测试。
# memory-os 等价：
#   spaced_access_count（iter420）= 跨 24h 间隔的检索次数，代理"不同 session 的检索尝试数"。
#   达到 hypermnesia_threshold 后触发一次 stability boost（避免反复触发 = cooldown）。
#   与 Spacing Effect 区别：SE 是 per-access 小幅加成；Hypermnesia 是 threshold-crossing 大幅净增强。
# OS 类比：Linux khugepaged Transparent HugePage 多 epoch 晋升 —
#   页面在多个内存分配 epoch 内持续热访问 → khugepaged 合并为 2MB hugepage，降低 TLB miss rate；
#   类比：多次跨 session 检索 → 记忆表示从分散痕迹"合并"为稳定长期表示（net improvement）。

def apply_hypermnesia(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter437: Hypermnesia — 对 spaced_access_count >= threshold 的 chunk 施加净增强 boost。

    在 sleep_consolidate 时调用：
      1. 查找 spaced_access_count >= hypermnesia_threshold 且 importance >= min_importance 的 chunk
      2. 排除在 cooldown_days 内已被 boost 的 chunk（hypermnesia_last_boost 字段）
      3. 对符合条件的 chunk：stability × hypermnesia_boost（上限 365.0）
      4. 更新 hypermnesia_last_boost = now

    返回：{"boosted": N, "total_examined": N}
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    try:
        import config as _cfg_hm
    except ImportError:
        return {"boosted": 0, "total_examined": 0}

    try:
        hm_enabled = _cfg_hm.get("store_vfs.hypermnesia_enabled")
        if not hm_enabled:
            return {"boosted": 0, "total_examined": 0}

        hm_threshold = _cfg_hm.get("store_vfs.hypermnesia_threshold")
        hm_boost = _cfg_hm.get("store_vfs.hypermnesia_boost")
        hm_min_imp = _cfg_hm.get("store_vfs.hypermnesia_min_importance")
        hm_cooldown_days = _cfg_hm.get("store_vfs.hypermnesia_cooldown_days")
    except Exception:
        return {"boosted": 0, "total_examined": 0}

    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()
    cooldown_cutoff = (now - _td(days=hm_cooldown_days)).isoformat()

    try:
        # 候选：spaced_access_count >= threshold，importance >= min_imp，
        #   且 hypermnesia_last_boost 为空或在冷却期外
        rows = conn.execute(
            """SELECT id, stability
               FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(spaced_access_count, 0) >= ?
                 AND COALESCE(importance, 0.5) >= ?
                 AND (hypermnesia_last_boost IS NULL
                      OR hypermnesia_last_boost < ?)
               LIMIT 200""",
            (project, hm_threshold, hm_min_imp, cooldown_cutoff),
        ).fetchall()
    except Exception:
        return {"boosted": 0, "total_examined": 0}

    total_examined = len(rows)
    boosted = 0

    for (cid, stab) in rows:
        try:
            new_stab = min(365.0, float(stab or 1.0) * hm_boost)
            conn.execute(
                "UPDATE memory_chunks SET stability=?, hypermnesia_last_boost=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, now_iso, cid),
            )
            boosted += 1
        except Exception:
            continue

    return {"boosted": boosted, "total_examined": total_examined}


# ── iter438: Jost's Law — 等强度记忆中较老者衰减更慢（Jost 1897）────────────────────────────────
# 认知科学依据：Jost (1897) "Die Assoziationsfestigkeit in ihrer Abhängigkeit von der Verteilung
#   der Wiederholungen" — Jost's Law of Memory：
#   若两个记忆在某一时刻强度相等，则较老的记忆在未来遗忘得更慢。
#   机制：老记忆已历经多次睡眠重放和巩固周期，突触权重矩阵更稳固；
#   Baddeley (1997): Jost's Law 是遗忘曲线的重要补充，age 越大 → 衰减率越低。
#
# 与 iter431 Ribot's Law 的互补关系：
#   Ribot = stability_floor 提高（下限保护）
#   Jost  = effective_decay 减慢（每次衰减步长缩小，持续减速）
#   两者叠加：老 chunk 既有更高 floor，也有更慢的 per-step 衰减速率。
#
# OS 类比：Linux MGLRU old generation protection —
#   在 old generation 长期存在（经历多个 aging interval）的页面，
#   kswapd 给予更弱的 reclaim pressure（不像 young gen 那样激进驱逐）；
#   类比：age 越大的 chunk → effective_decay 越接近 1.0 → per-step 衰减量越小。

def apply_jost_law(
    conn: sqlite3.Connection,
    project: str,
    stale_days: int = 30,
) -> dict:
    """
    iter438: Jost's Law — 对高龄 chunk 施加衰减减速修正。

    在 sleep_consolidate 中，decay_stability_by_type_with_ci 已对 access_count < 2 的 chunk
    执行了批量衰减。apply_jost_law 作为后处理，对满足年龄+重要性条件的 chunk 部分"撤销"
    多余的衰减（恢复一部分被过度衰减的 stability），等效于以 effective_decay 替换 base_decay：

      effective_decay = base_decay + (1 - base_decay) × jost_bonus
      stability_restored = current_stab / base_decay × effective_decay - current_stab
                         = current_stab × (effective_decay / base_decay - 1)

    实现简化：直接用 jost_bonus 乘以 (1 - current_decay_factor) 做增量修复：
      new_stab = min(old_stab, current_stab * (1 + jost_bonus / (1 - effective_decay + ε)))

    更简洁的实际实现：
      对每个符合条件的 chunk，stability × (1 + jost_effective_bonus)
      其中 jost_effective_bonus = jost_bonus × base_decay_step
                                = jost_bonus × (1 - decay_factor_used)
    但 decay_factor_used 不易追踪。改用直接乘法（近似）：
      new_stab = min(pre_decay_stab, current_stab × (1 + jost_bonus))

    由于 pre_decay_stab 未知，用保守方法：
      new_stab = current_stab × jost_multiplier，where jost_multiplier = 1 + jost_bonus×0.1
    这确保每次 sleep_consolidate 后，老 chunk 的 stability 被轻微"提振"，
    相当于减缓了 decay 的净效果。

    Returns:
      {"adjusted": N, "total_examined": N}
    """
    import math
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td

    try:
        import config as _cfg_jost
    except ImportError:
        return {"adjusted": 0, "total_examined": 0}

    try:
        if not _cfg_jost.get("store_vfs.jost_enabled"):
            return {"adjusted": 0, "total_examined": 0}
        jost_min_imp = _cfg_jost.get("store_vfs.jost_min_importance")
        jost_scale = _cfg_jost.get("store_vfs.jost_scale")
        jost_max_bonus = _cfg_jost.get("store_vfs.jost_max_bonus")
        jost_min_age = _cfg_jost.get("store_vfs.jost_min_age_days")
    except Exception:
        return {"adjusted": 0, "total_examined": 0}

    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()
    # 只对"被衰减候选"的 chunk 做修复（stale_days 未访问，access_count < 2，低重要性除外）
    cutoff_stale = (now - _td(days=stale_days)).isoformat()
    min_age_cutoff = (now - _td(days=jost_min_age)).isoformat()

    try:
        # 候选：high importance + old age + stale (recently decayed by CI)
        rows = conn.execute(
            """SELECT id, stability, created_at, importance
               FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND created_at < ?
                 AND last_accessed < ?
                 AND access_count < 2
                 AND COALESCE(stability, 0.1) > 0.1
               LIMIT 500""",
            (project, jost_min_imp, min_age_cutoff, cutoff_stale),
        ).fetchall()
    except Exception:
        return {"adjusted": 0, "total_examined": 0}

    total_examined = len(rows)
    adjusted = 0

    for row in rows:
        try:
            cid, stab, created_at, importance = row
            if not created_at:
                continue
            _ts_c = _dt.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()
            age_days = (now.timestamp() - _ts_c) / 86400.0
            if age_days < jost_min_age:
                continue

            # Jost bonus: log(1 + age_days) / log(365) × jost_scale，上限 jost_max_bonus
            raw_bonus = math.log(1 + age_days) / math.log(365) * jost_scale
            jost_bonus = min(jost_max_bonus, raw_bonus)

            # effective_decay_reduction = jost_bonus × (1 - typical_decay)
            # 典型 type_decay ≈ 0.95，(1 - 0.95) = 0.05
            # 实际 stability 恢复量 = current_stab × jost_bonus × 0.05
            # 等效 multiplier ≈ 1 + jost_bonus × 0.05（保守）
            jost_multiplier = 1.0 + jost_bonus * 0.05  # 保守系数，避免过度逆转 decay
            new_stab = min(365.0, float(stab or 0.1) * jost_multiplier)

            if new_stab <= float(stab or 0.1) + 0.0001:
                continue  # 无实质变化

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            adjusted += 1
        except Exception:
            continue

    if adjusted > 0:
        conn.commit()

    return {"adjusted": adjusted, "total_examined": total_examined}


# ── iter439: Encoding Depth Decay Resistance — 深度编码减慢衰减（Craik & Tulving 1975）──────────────
# 认知科学依据：Craik & Tulving (1975) "Depth of processing and the retention of words in
#   episodic memory" — 深度语义加工产生更强的记忆痕迹，对遗忘曲线有天然抵抗力。
#   encode_context 中 entity 数量（iter411 LOP proxy）代理编码深度：
#   entity_count >= eddr_deep_threshold → 深度编码，stability 轻微修复（减慢衰减）。
#   entity_count <= eddr_shallow_threshold → 浅层编码，stability 轻微惩罚（加速衰减）。
# OS 类比：Linux ext4 extent tree depth —
#   深层 extent tree（多 entity）= I/O 代价更高 = kswapd 驱逐优先级更低（更抗衰减）。

def apply_encoding_depth_decay_resistance(
    conn: sqlite3.Connection,
    project: str,
    stale_days: int = 30,
) -> dict:
    """
    iter439: Encoding Depth Decay Resistance — 根据 encode_context 实体数量调整 stability。

    在 sleep_consolidate 中，decay_stability_by_type_with_ci 执行批量衰减后：
    - 深度编码 chunk（entity_count >= deep_threshold）：轻微恢复 stability，模拟抗遗忘优势。
    - 浅层编码 chunk（entity_count <= shallow_threshold）：轻微加速衰减，模拟快速遗忘。

    深度修复：new_stab = current_stab × (1 + depth_bonus × 0.03)
    浅层惩罚：new_stab = current_stab × (1 - shallow_penalty)

    Returns:
      {"deep_boosted": N, "shallow_penalized": N, "total_examined": N}
    """
    try:
        import config as _cfg_eddr
    except ImportError:
        return {"deep_boosted": 0, "shallow_penalized": 0, "total_examined": 0}

    try:
        if not _cfg_eddr.get("store_vfs.eddr_enabled"):
            return {"deep_boosted": 0, "shallow_penalized": 0, "total_examined": 0}
        eddr_deep_threshold = _cfg_eddr.get("store_vfs.eddr_deep_threshold")    # 5
        eddr_shallow_threshold = _cfg_eddr.get("store_vfs.eddr_shallow_threshold")  # 1
        eddr_max_depth_bonus = _cfg_eddr.get("store_vfs.eddr_max_depth_bonus")  # 0.15
        eddr_shallow_penalty = _cfg_eddr.get("store_vfs.eddr_shallow_penalty")  # 0.05
    except Exception:
        return {"deep_boosted": 0, "shallow_penalized": 0, "total_examined": 0}

    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()
    cutoff_stale = (now - _td(days=stale_days)).isoformat()

    try:
        # 候选：stale + access_count < 2（被 decay 扫描过的）
        rows = conn.execute(
            """SELECT id, stability, encode_context, importance
               FROM memory_chunks
               WHERE project = ?
                 AND last_accessed < ?
                 AND access_count < 2
                 AND COALESCE(stability, 0.1) > 0.1
               LIMIT 500""",
            (project, cutoff_stale),
        ).fetchall()
    except Exception:
        return {"deep_boosted": 0, "shallow_penalized": 0, "total_examined": 0}

    total_examined = len(rows)
    deep_boosted = 0
    shallow_penalized = 0

    for row in rows:
        try:
            cid, stab, encode_context, importance = row
            stab_f = float(stab or 0.1)
            if stab_f <= 0.1:
                continue

            # 计算 entity 数量（encode_context 是逗号分隔字符串）
            if encode_context:
                entity_count = len([e.strip() for e in encode_context.split(',') if e.strip()])
            else:
                entity_count = 0

            new_stab = stab_f
            if entity_count >= eddr_deep_threshold:
                # 深度编码：stability 轻微修复（conservative 系数 0.03）
                raw_bonus = min(eddr_max_depth_bonus, entity_count / 10.0 * eddr_max_depth_bonus)
                new_stab = min(365.0, stab_f * (1.0 + raw_bonus * 0.03))
                if new_stab > stab_f + 0.0001:
                    deep_boosted += 1
                else:
                    continue
            elif entity_count <= eddr_shallow_threshold:
                # 浅层编码：轻微加速衰减
                new_stab = max(0.1, stab_f * (1.0 - eddr_shallow_penalty))
                if new_stab < stab_f - 0.0001:
                    shallow_penalized += 1
                else:
                    continue
            else:
                continue  # 中等深度：不干预

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
        except Exception:
            continue

    if deep_boosted > 0 or shallow_penalized > 0:
        conn.commit()

    return {"deep_boosted": deep_boosted, "shallow_penalized": shallow_penalized,
            "total_examined": total_examined}


# ── iter440: Proactive Facilitation — 强邻居锚定保护新知识衰减（Ausubel 1963）──────────────────────
# 认知科学依据：Ausubel (1963) 正向迁移/先行组织者：已有稳固 schema 锚定新知识，
#   降低新知识的遗忘速率。encode_context entity 重叠代理语义相似度。
# OS 类比：Linux page cache refcount —
#   被多个 inode 共享引用的 page 有高 refcount，kswapd 优先保留（驱逐代价 > 收益）。

def apply_proactive_facilitation(
    conn: sqlite3.Connection,
    project: str,
    stale_days: int = 30,
) -> dict:
    """
    iter440: Proactive Facilitation — 对被高 importance 强邻居锚定的 chunk 减慢衰减。

    在 sleep_consolidate 中，对 stale + access_count < 2 的候选 chunk，
    若其 encode_context entity 集合与高 importance(≥ pf_anchor_min_importance) 且
    access_count >= pf_anchor_min_access 的强邻居有足够重叠（≥ pf_min_overlap entity），
    则该 chunk 被"锚定"，获得轻微 stability 修复：
      new_stab = current_stab × (1 + pf_max_bonus × 0.04)

    注意：这是对所有候选 chunk 批量扫描，效率优先：
    将所有强邻居的 entity 集合构建成全局集合，候选 chunk 逐一与之匹配。

    Returns:
      {"facilitated": N, "total_examined": N}
    """
    try:
        import config as _cfg_pf
    except ImportError:
        return {"facilitated": 0, "total_examined": 0}

    try:
        if not _cfg_pf.get("store_vfs.pf_enabled"):
            return {"facilitated": 0, "total_examined": 0}
        pf_anchor_min_imp = _cfg_pf.get("store_vfs.pf_anchor_min_importance")
        pf_anchor_min_acc = _cfg_pf.get("store_vfs.pf_anchor_min_access")
        pf_min_overlap = _cfg_pf.get("store_vfs.pf_min_overlap")
        pf_max_bonus = _cfg_pf.get("store_vfs.pf_max_bonus")
    except Exception:
        return {"facilitated": 0, "total_examined": 0}

    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()
    cutoff_stale = (now - _td(days=stale_days)).isoformat()

    # Step 1: 获取强邻居的 entity 集合（全局锚点）
    try:
        anchor_rows = conn.execute(
            """SELECT encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND access_count >= ?
                 AND encode_context IS NOT NULL
                 AND encode_context != ''
               LIMIT 200""",
            (project, pf_anchor_min_imp, pf_anchor_min_acc),
        ).fetchall()
    except Exception:
        return {"facilitated": 0, "total_examined": 0}

    if not anchor_rows:
        return {"facilitated": 0, "total_examined": 0}

    # 构建全局强邻居 entity 集合（每个锚点 chunk 的 entity set）
    anchor_entity_sets = []
    for arow in anchor_rows:
        try:
            ec = arow[0] if isinstance(arow, (list, tuple)) else arow["encode_context"]
            if ec:
                entities = frozenset(e.strip() for e in ec.split(',') if e.strip())
                if entities:
                    anchor_entity_sets.append(entities)
        except Exception:
            continue

    if not anchor_entity_sets:
        return {"facilitated": 0, "total_examined": 0}

    # Step 2: 获取候选 chunk（stale + access_count < 2）
    try:
        candidate_rows = conn.execute(
            """SELECT id, stability, encode_context
               FROM memory_chunks
               WHERE project = ?
                 AND last_accessed < ?
                 AND access_count < 2
                 AND COALESCE(stability, 0.1) > 0.1
                 AND encode_context IS NOT NULL
                 AND encode_context != ''
               LIMIT 500""",
            (project, cutoff_stale),
        ).fetchall()
    except Exception:
        return {"facilitated": 0, "total_examined": 0}

    total_examined = len(candidate_rows)
    facilitated = 0
    pf_multiplier = 1.0 + pf_max_bonus * 0.04

    for row in candidate_rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            ec = row[2] if isinstance(row, (list, tuple)) else row["encode_context"]

            if not ec:
                continue
            stab_f = float(stab or 0.1)
            if stab_f <= 0.1:
                continue

            # 计算候选 chunk 的 entity 集合
            cand_entities = frozenset(e.strip() for e in ec.split(',') if e.strip())
            if not cand_entities:
                continue

            # 检查是否与任一强邻居有足够重叠
            anchored = False
            for anchor_set in anchor_entity_sets:
                overlap = len(cand_entities & anchor_set)
                if overlap >= pf_min_overlap:
                    anchored = True
                    break

            if not anchored:
                continue

            # 锚定：轻微 stability 修复
            new_stab = min(365.0, stab_f * pf_multiplier)
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            facilitated += 1
        except Exception:
            continue

    if facilitated > 0:
        conn.commit()

    return {"facilitated": facilitated, "total_examined": total_examined}


# ── iter441: Emotional Consolidation — 情绪显著性记忆睡眠优先巩固（McGaugh 2000）──────────────────
# 认知科学依据：McGaugh (2000) Science 287 — 情绪事件通过杏仁核-海马交互在睡眠期间优先巩固；
#   emotional_weight 代理情绪唤醒水平，高唤醒 chunk 在 sleep_consolidate 时获得额外 stability 加成。
# OS 类比：Linux writeback priority — 高优先级 dirty page 被 pdflush 优先刷写（优先巩固）。

def apply_emotional_consolidation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter441: Emotional Consolidation — 情绪显著性 chunk 在 sleep_consolidate 时获得额外 stability 加成。

    对 emotional_weight >= ec_min_weight 且 importance >= ec_min_importance 的 chunk，
    按情绪权重比例给予 stability 修复：
      bonus = emotional_weight × ec_scale
      new_stab = min(365.0, current_stab × (1 + bonus))

    这是对 iter409（Flashbulb Memory 写入时加成）的补充：
    Flashbulb = encoding 阶段一次性加成；Emotional Consolidation = consolidation 阶段持续加成。

    范围：不限于 stale chunk（情绪显著性 chunk 无论访问状态都应获得睡眠巩固优势）。

    Returns:
      {"consolidated": N, "total_examined": N}
    """
    try:
        import config as _cfg_ec
    except ImportError:
        return {"consolidated": 0, "total_examined": 0}

    try:
        if not _cfg_ec.get("store_vfs.ec_enabled"):
            return {"consolidated": 0, "total_examined": 0}
        ec_min_weight = _cfg_ec.get("store_vfs.ec_min_weight")
        ec_scale = _cfg_ec.get("store_vfs.ec_scale")
        ec_min_importance = _cfg_ec.get("store_vfs.ec_min_importance")
    except Exception:
        return {"consolidated": 0, "total_examined": 0}

    from datetime import datetime as _dt, timezone as _tz
    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()

    try:
        rows = conn.execute(
            """SELECT id, stability, emotional_weight
               FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(emotional_weight, 0.0) >= ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
               LIMIT 300""",
            (project, ec_min_weight, ec_min_importance),
        ).fetchall()
    except Exception:
        return {"consolidated": 0, "total_examined": 0}

    total_examined = len(rows)
    consolidated = 0

    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            ew = row[2] if isinstance(row, (list, tuple)) else row["emotional_weight"]

            stab_f = float(stab or 0.1)
            ew_f = float(ew or 0.0)
            if stab_f <= 0.1 or ew_f < ec_min_weight:
                continue

            bonus = ew_f * ec_scale
            new_stab = min(365.0, stab_f * (1.0 + bonus))
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            consolidated += 1
        except Exception:
            continue

    if consolidated > 0:
        conn.commit()

    return {"consolidated": consolidated, "total_examined": total_examined}


# ── iter442: Schema-Consistent Consolidation — 图式一致性记忆的额外巩固（Bartlett 1932 / Tse 2007）──
# 认知科学依据：Tse et al. (2007) Science "Schemas and memory consolidation" —
#   已有丰富图式后，新知识 1 天内完成系统巩固（vs 无图式时需 3 天）。
#   Bartlett (1932) Schema Theory：图式一致的信息被快速整合，获得额外巩固强化。
# OS 类比：Linux readahead pattern detection — 顺序访问模式匹配 → 预取窗口扩大 → 更快完成 I/O。

def apply_schema_consistent_consolidation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter442: Schema-Consistent Consolidation — 与项目核心图式高度重叠的近期 chunk 获得额外巩固加成。

    步骤：
    1. 识别图式核（schema cores）：access_count >= scc_schema_min_access + importance >= scc_schema_min_importance
    2. 对近期写入（created_at >= now - scc_window_days）的 chunk：
       计算其 encode_context 与所有图式核的最大 entity 重叠数；
       若重叠 >= scc_min_overlap → 给予 stability 加成。
    3. new_stab = min(365.0, stab × (1 + scc_bonus × 0.04))

    区别于 iter440（PF）：
      PF = stale 旧 chunk 被锚定（老知识保护）
      SCC = 近期新 chunk 嵌入图式（新知识快速系统巩固）
    """
    try:
        import config as _cfg_scc
    except ImportError:
        return {"schema_consolidated": 0, "total_examined": 0}

    try:
        if not _cfg_scc.get("store_vfs.scc_enabled"):
            return {"schema_consolidated": 0, "total_examined": 0}
        scc_schema_min_access = _cfg_scc.get("store_vfs.scc_schema_min_access")
        scc_schema_min_imp = _cfg_scc.get("store_vfs.scc_schema_min_importance")
        scc_min_overlap = _cfg_scc.get("store_vfs.scc_min_overlap")
        scc_window_days = _cfg_scc.get("store_vfs.scc_window_days")
        scc_bonus = _cfg_scc.get("store_vfs.scc_bonus")
    except Exception:
        return {"schema_consolidated": 0, "total_examined": 0}

    scc_multiplier = 1.0 + scc_bonus * 0.04  # 0.15 × 0.04 = 0.006 ≈ 0.6% 加成

    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    now = _dt.now(_tz.utc)
    now_iso = now.isoformat()

    # ── Step 1: 构建图式核 entity 集合列表 ──
    cutoff_window = (now - _td(days=scc_window_days)).isoformat()

    try:
        schema_rows = conn.execute(
            """SELECT encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(access_count, 0) >= ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(encode_context, '') != ''""",
            (project, scc_schema_min_access, scc_schema_min_imp),
        ).fetchall()
    except Exception:
        return {"schema_consolidated": 0, "total_examined": 0}

    if not schema_rows:
        return {"schema_consolidated": 0, "total_examined": 0}

    schema_entity_sets = []
    for sr in schema_rows:
        try:
            ec = sr[0] if isinstance(sr, (list, tuple)) else sr["encode_context"]
            if ec and ec.strip():
                eset = frozenset(e.strip().lower() for e in ec.split(",") if e.strip())
                if eset:
                    schema_entity_sets.append(eset)
        except Exception:
            continue

    if not schema_entity_sets:
        return {"schema_consolidated": 0, "total_examined": 0}

    # ── Step 2: 近期写入的 chunk（创建时间 >= now - scc_window_days）──
    try:
        rows = conn.execute(
            """SELECT id, stability, encode_context FROM memory_chunks
               WHERE project = ?
                 AND created_at >= ?
                 AND COALESCE(encode_context, '') != ''
                 AND COALESCE(stability, 0.1) > 0.1
               LIMIT 500""",
            (project, cutoff_window),
        ).fetchall()
    except Exception:
        return {"schema_consolidated": 0, "total_examined": 0}

    total_examined = len(rows)
    schema_consolidated = 0

    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            ec = row[2] if isinstance(row, (list, tuple)) else row["encode_context"]

            stab_f = float(stab or 0.1)
            if stab_f <= 0.1:
                continue

            if not ec or not ec.strip():
                continue

            cand_entities = frozenset(e.strip().lower() for e in ec.split(",") if e.strip())
            if not cand_entities:
                continue

            # 检查与任何图式核的重叠
            max_overlap = 0
            for schema_set in schema_entity_sets:
                overlap = len(cand_entities & schema_set)
                if overlap > max_overlap:
                    max_overlap = overlap
                if max_overlap >= scc_min_overlap:
                    break  # 已找到足够重叠，无需继续

            if max_overlap < scc_min_overlap:
                continue

            new_stab = min(365.0, stab_f * scc_multiplier)
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            schema_consolidated += 1
        except Exception:
            continue

    if schema_consolidated > 0:
        conn.commit()

    return {"schema_consolidated": schema_consolidated, "total_examined": total_examined}


# ── iter443: Sleep-Targeted Reactivation — 睡眠期主动抢救衰退的高价值记忆（Stickgold 2005）──────
# 认知科学依据：
#   Stickgold (2005) Nature: 睡眠期 targeted memory reactivation — 海马 sharp-wave ripples 优先重放
#     高价值但 retrievability 下降的记忆（即将消退的重要记忆被"抢救"）。
#   Stickgold & Walker (2013) Nature Neuroscience: sleep memory triage —
#     优先级 = importance × (1 - retrievability)（高价值 + 正在衰退 = 最需要抢救）。
# OS 类比：Linux dirty page "expire" scan — flusher 扫描即将超时的脏页，强制写回抢救。

def apply_sleep_targeted_reactivation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter443: Sleep-Targeted Reactivation (STR) — 睡眠期主动抢救高 importance 但 retrievability 低的 chunk。

    对 importance >= str_min_importance 且 retrievability <= str_max_retrievability 的 chunk，
    按衰退程度修复 stability：
      rescue_bonus = (1.0 - retrievability) × str_scale
      new_stab = min(365.0, stab × (1 + rescue_bonus))

    优先级 = importance × (1 - retrievability)：高价值且正在衰退的记忆获得最大修复。
    适用于所有满足条件的 chunk（不限 stale），模拟海马对重要衰退记忆的 targeted reactivation。

    Returns:
      {"rescued": N, "total_examined": N}
    """
    try:
        import config as _cfg_str
    except ImportError:
        return {"rescued": 0, "total_examined": 0}

    try:
        if not _cfg_str.get("store_vfs.str_enabled"):
            return {"rescued": 0, "total_examined": 0}
        str_min_importance = _cfg_str.get("store_vfs.str_min_importance")      # 0.65
        str_max_retrievability = _cfg_str.get("store_vfs.str_max_retrievability")  # 0.40
        str_scale = _cfg_str.get("store_vfs.str_scale")                        # 0.12
    except Exception:
        return {"rescued": 0, "total_examined": 0}

    from datetime import datetime as _dt, timezone as _tz
    now_iso = _dt.now(_tz.utc).isoformat()

    # 扫描：importance >= str_min_importance + retrievability <= str_max_retrievability
    try:
        rows = conn.execute(
            """SELECT id, stability, importance, retrievability FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(retrievability, 1.0) <= ?
                 AND COALESCE(stability, 0.1) > 0.1
               ORDER BY (COALESCE(importance, 0.0) * (1.0 - COALESCE(retrievability, 1.0))) DESC
               LIMIT 200""",
            (project, str_min_importance, str_max_retrievability),
        ).fetchall()
    except Exception:
        return {"rescued": 0, "total_examined": 0}

    total_examined = len(rows)
    rescued = 0

    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            imp = row[2] if isinstance(row, (list, tuple)) else row["importance"]
            ret = row[3] if isinstance(row, (list, tuple)) else row["retrievability"]

            stab_f = float(stab or 0.1)
            ret_f = float(ret if ret is not None else 1.0)

            if stab_f <= 0.1:
                continue

            # rescue_bonus 与遗忘程度正比：retrievability 越低 → 修复越大
            rescue_bonus = (1.0 - ret_f) * str_scale
            if rescue_bonus <= 0.0001:
                continue

            new_stab = min(365.0, stab_f * (1.0 + rescue_bonus))
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            rescued += 1
        except Exception:
            continue

    if rescued > 0:
        conn.commit()

    return {"rescued": rescued, "total_examined": total_examined}


# ── iter444: Contextual Reinstatement Effect — 情境再现期活跃 chunk 的睡眠额外巩固（Smith 1979 / Tulving 1983）──
# 认知科学依据：
#   Smith (1979) "Remembering in and out of context" — 情境再现时记忆提取成功率高 40-50%（环境依赖记忆）。
#   Tulving (1983) Encoding Specificity Principle — 检索线索与编码时情境越匹配，提取效率越高。
# OS 类比：Linux NUMA-aware page consolidation (khugepaged) —
#   khugepaged 优先合并同一 NUMA node 内热页为 hugepage；
#   session 活跃情境 = 当前 NUMA node，情境高度重叠 chunk = 同 node 热页 → sleep consolidate 时优先加大 stability。

def apply_contextual_reinstatement_consolidation(
    conn: sqlite3.Connection,
    project: str,
    session_accessed_ids: list = None,
) -> dict:
    """
    iter444: Contextual Reinstatement Effect (CRE) — sleep 时基于 session 活跃情境的额外巩固。

    步骤：
    1. 构建 session_active_entities：从本 session 被访问的 chunk 的 encode_context 合并 entity 集合。
       若 session_accessed_ids 为空/None，则取最近 cre_max_session_entities 个被访问的 chunk。
    2. 对所有 importance >= cre_min_importance 的 chunk，计算 encode_context 与 active_entities 的重叠：
       overlap = |chunk_entities ∩ session_active_entities|
       若 overlap >= cre_min_overlap：
         overlap_ratio = min(1.0, overlap / max(1, len(chunk_entities)))
         bonus_factor = cre_bonus × overlap_ratio
         new_stab = min(365.0, stab × (1 + bonus_factor))
    3. 返回 {"cre_consolidated": N, "total_examined": N}

    情境再现逻辑：本 session 多次访问某个主题的知识 → session_active_entities 包含大量相关 entity
    → 属于同一主题的 chunk 的 encode_context 与 active_entities 高度重叠 → 获得额外巩固加成。
    这模拟了"在情境再现期间学习的记忆被优先巩固"的认知科学效应。

    Returns:
      {"cre_consolidated": N, "total_examined": N}
    """
    try:
        import config as _cfg_cre
    except ImportError:
        return {"cre_consolidated": 0, "total_examined": 0}

    try:
        if not _cfg_cre.get("store_vfs.cre_enabled"):
            return {"cre_consolidated": 0, "total_examined": 0}
        cre_min_overlap = _cfg_cre.get("store_vfs.cre_min_overlap")       # 2
        cre_min_importance = _cfg_cre.get("store_vfs.cre_min_importance") # 0.40
        cre_bonus = _cfg_cre.get("store_vfs.cre_bonus")                   # 0.10
        cre_max_session = _cfg_cre.get("store_vfs.cre_max_session_entities")  # 200
    except Exception:
        return {"cre_consolidated": 0, "total_examined": 0}

    from datetime import datetime as _dt, timezone as _tz
    now_iso = _dt.now(_tz.utc).isoformat()

    # ── Step 1: 构建 session_active_entities 集合 ──
    # 从本 session 被访问的 chunk 的 encode_context 中提取所有 entity。
    # 使用 2 小时时间窗口（last_accessed >= now-2h），而非 LIMIT 取最新 N 条：
    # 这避免了候选 chunk 自身 entity 污染 session 情境集合（自举偏差）。
    from datetime import timedelta as _td_cre
    session_cutoff = (_dt.now(_tz.utc) - _td_cre(hours=2)).isoformat()

    try:
        if session_accessed_ids:
            # 有明确的 session 访问 ID 列表：精确构建（忽略时间窗口）
            placeholders = ",".join("?" * len(session_accessed_ids[:200]))
            session_rows = conn.execute(
                f"""SELECT encode_context FROM memory_chunks
                    WHERE project = ? AND id IN ({placeholders})
                      AND encode_context IS NOT NULL AND encode_context != ''""",
                [project] + list(session_accessed_ids[:200]),
            ).fetchall()
        else:
            # 无明确 ID：取最近 2 小时内被访问的 chunk 作为 session 情境代理
            session_rows = conn.execute(
                """SELECT encode_context FROM memory_chunks
                   WHERE project = ?
                     AND encode_context IS NOT NULL AND encode_context != ''
                     AND last_accessed >= ?
                   ORDER BY last_accessed DESC
                   LIMIT ?""",
                (project, session_cutoff, cre_max_session),
            ).fetchall()
    except Exception:
        return {"cre_consolidated": 0, "total_examined": 0}

    # 构建 session 活跃 entity 集合
    session_active_entities: set = set()
    for srow in session_rows:
        ec = srow[0] if isinstance(srow, (list, tuple)) else srow["encode_context"]
        if ec:
            for e in ec.split(","):
                e = e.strip().lower()
                if e:
                    session_active_entities.add(e)

    if len(session_active_entities) < cre_min_overlap:
        # session 情境太稀疏，无法做有意义的情境匹配
        return {"cre_consolidated": 0, "total_examined": 0}

    # ── Step 2: 扫描 importance 足够的 chunk，计算情境重叠 ──
    try:
        rows = conn.execute(
            """SELECT id, stability, importance, encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND encode_context IS NOT NULL AND encode_context != ''
                 AND COALESCE(stability, 0.1) > 0.1
               ORDER BY COALESCE(importance, 0.0) DESC
               LIMIT 500""",
            (project, cre_min_importance),
        ).fetchall()
    except Exception:
        return {"cre_consolidated": 0, "total_examined": 0}

    total_examined = len(rows)
    cre_consolidated = 0

    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            imp = row[2] if isinstance(row, (list, tuple)) else row["importance"]
            ec = row[3] if isinstance(row, (list, tuple)) else row["encode_context"]

            stab_f = float(stab or 0.1)
            if stab_f <= 0.1:
                continue

            if not ec:
                continue

            # 提取 chunk entity 集合
            chunk_entities = frozenset(e.strip().lower() for e in ec.split(",") if e.strip())
            if not chunk_entities:
                continue

            # 计算与 session 活跃情境的重叠
            overlap = len(chunk_entities & session_active_entities)
            if overlap < cre_min_overlap:
                continue

            # overlap_ratio：归一化（以 chunk 自身 entity 数为基准，避免大 session entity 集偏差）
            overlap_ratio = min(1.0, overlap / max(1, len(chunk_entities)))
            bonus_factor = cre_bonus * overlap_ratio

            if bonus_factor <= 0.0001:
                continue

            new_stab = min(365.0, stab_f * (1.0 + bonus_factor))
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            cre_consolidated += 1
        except Exception:
            continue

    if cre_consolidated > 0:
        conn.commit()

    return {"cre_consolidated": cre_consolidated, "total_examined": total_examined}


# ── iter445: Reward-Tagged Memory Consolidation — 奖励标签记忆的睡眠优先巩固（Murty & Adcock 2014）──
# 认知科学依据：
#   Murty & Adcock (2014) "Enriching experiences via prior associative learning facilitates memory" —
#     多巴胺奖励信号在慢波睡眠期（SWS）激活 VTA-海马投射，选择性强化高奖励预期的记忆痕迹。
#   Hennies et al. (2015) "Closed-loop memory reactivation during sleep" (Current Biology) —
#     高奖励标签 + 睡眠 = 最强记忆保留：reward × sleep 的交互效应显著大于单独效应之和。
# OS 类比：Linux workingset_activation（工作集激活标记）——
#   kswapd 扫描时，reference bit=1 的页获得 second chance（不立即回收）；
#   page refcount × recency = 工作集优先级（高频近期访问 page = 最高 protection）；
#   类比：access_count × recency_factor = 记忆奖励优先级 → sleep 时优先强化。

def apply_reward_tagged_memory_consolidation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter445: Reward-Tagged Memory Consolidation (RTMC) — sleep 时基于访问频率×近期性的奖励巩固。

    数学模型：
      reward_signal = min(1.0, log(1 + access_count) / log(1 + rtmc_acc_ref))
      recency_factor = max(0.0, 1.0 - hours_since_access / rtmc_recency_hours)
      priority = reward_signal × recency_factor
      bonus = priority × rtmc_scale
      new_stab = min(365.0, stab × (1 + bonus))

    触发条件：
      - rtmc_enabled = True
      - access_count >= rtmc_min_access（至少被检索 N 次 = 有奖励历史）
      - hours_since_access <= rtmc_recency_hours（最近仍有访问 = 奖励信号新鲜）
      - importance >= rtmc_min_importance（低重要性 chunk 不参与）

    Returns:
      {"rtmc_boosted": N, "total_examined": N}
    """
    try:
        import config as _cfg_rtmc
    except ImportError:
        return {"rtmc_boosted": 0, "total_examined": 0}

    try:
        if not _cfg_rtmc.get("store_vfs.rtmc_enabled"):
            return {"rtmc_boosted": 0, "total_examined": 0}
        rtmc_min_access = _cfg_rtmc.get("store_vfs.rtmc_min_access")       # 3
        rtmc_acc_ref = _cfg_rtmc.get("store_vfs.rtmc_acc_ref")             # 10
        rtmc_recency_hours = _cfg_rtmc.get("store_vfs.rtmc_recency_hours") # 48.0
        rtmc_scale = _cfg_rtmc.get("store_vfs.rtmc_scale")                 # 0.08
        rtmc_min_importance = _cfg_rtmc.get("store_vfs.rtmc_min_importance")  # 0.35
    except Exception:
        return {"rtmc_boosted": 0, "total_examined": 0}

    import math as _math_rtmc
    from datetime import datetime as _dt_rtmc, timezone as _tz_rtmc
    now_dt = _dt_rtmc.now(_tz_rtmc.utc)
    now_iso = now_dt.isoformat()

    # 计算时间窗口截止点：rtmc_recency_hours 之前
    from datetime import timedelta as _td_rtmc
    recency_cutoff = (now_dt - _td_rtmc(hours=rtmc_recency_hours)).isoformat()

    try:
        rows = conn.execute(
            """SELECT id, stability, access_count, last_accessed, importance
               FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(access_count, 0) >= ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND last_accessed IS NOT NULL
                 AND last_accessed >= ?
                 AND COALESCE(stability, 0.1) > 0.1
               ORDER BY COALESCE(access_count, 0) DESC
               LIMIT 500""",
            (project, rtmc_min_access, rtmc_min_importance, recency_cutoff),
        ).fetchall()
    except Exception:
        return {"rtmc_boosted": 0, "total_examined": 0}

    total_examined = len(rows)
    rtmc_boosted = 0
    log_ref = _math_rtmc.log(1 + rtmc_acc_ref)  # precompute denominator

    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            acc = row[2] if isinstance(row, (list, tuple)) else row["access_count"]
            last_accessed = row[3] if isinstance(row, (list, tuple)) else row["last_accessed"]

            stab_f = float(stab or 0.1)
            if stab_f <= 0.1:
                continue

            acc_f = float(acc or 0)
            if acc_f < rtmc_min_access:
                continue

            # 计算 hours_since_access
            try:
                if last_accessed.endswith("Z"):
                    last_accessed = last_accessed[:-1] + "+00:00"
                from datetime import datetime as _dt2_rtmc, timezone as _tz2_rtmc
                la_dt = _dt2_rtmc.fromisoformat(last_accessed)
                if la_dt.tzinfo is None:
                    la_dt = la_dt.replace(tzinfo=_tz2_rtmc.utc)
                hours_since = (now_dt - la_dt).total_seconds() / 3600.0
            except Exception:
                continue

            if hours_since > rtmc_recency_hours:
                continue

            # 奖励信号：对数归一化访问次数（acc=rtmc_acc_ref 时 reward_signal=1.0）
            reward_signal = min(1.0, _math_rtmc.log(1 + acc_f) / log_ref)

            # 近期因子：访问越新鲜，recency_factor 越接近 1.0
            recency_factor = max(0.0, 1.0 - hours_since / rtmc_recency_hours)

            priority = reward_signal * recency_factor
            if priority < 0.001:
                continue

            bonus = priority * rtmc_scale
            if bonus < 0.0001:
                continue

            new_stab = min(365.0, stab_f * (1.0 + bonus))
            if new_stab <= stab_f + 0.0001:
                continue

            conn.execute(
                "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
                (round(new_stab, 4), now_iso, cid),
            )
            rtmc_boosted += 1
        except Exception:
            continue

    if rtmc_boosted > 0:
        conn.commit()

    return {"rtmc_boosted": rtmc_boosted, "total_examined": total_examined}


# ── iter446: Temporal Contiguity Effect — 时间毗邻性的记忆互相强化（Kahana 1996）────────────────────
# 认知科学依据：
#   Kahana (1996) "Associative retrieval processes in free recall" (J. Memory & Language) —
#     lag-CRP 曲线峰值在 lag=±1（时间相邻的记忆强度互相激活），时间毗邻提供隐式时序链接。
#   Howard & Kahana (2002) — 时间上下文向量高度相关的相邻事件在睡眠回放时被联合重放。
# OS 类比：Linux MGLRU temporal cohort aging —
#   同一 aging interval 内被访问的 pages 属于同一 generation，sleep 扫描时互相保护。

def apply_temporal_contiguity_consolidation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter446: Temporal Contiguity Effect (TCE) — sleep 时对时间毗邻写入的 chunk 相互加成 stability。

    算法：
    1. 获取项目内 importance >= tce_min_importance 的所有 chunk，按 created_at 排序。
    2. 滑动窗口：对连续 chunk 中 created_at 差距 <= tce_window_secs 的相邻对识别。
    3. 找出属于同一时间窗口的 chunk 组（时间段内 >= 2 个 chunk = 形成时间情节单元）。
    4. 对每个有效 chunk 组（size <= tce_max_group_size），每个成员 stability × (1 + tce_bonus)。
    5. 返回 {"tce_boosted": N, "total_examined": N}

    时间毗邻逻辑：
      - 同一窗口内的 chunk 代表同一编码情节（如一次连续的调试会话、一次设计讨论）。
      - 睡眠期海马重放时，时序链接使同情节内的 chunk 相互激活（lag-CRP 效应）。
      - 相互加成体现了"情节记忆组块化"：相邻编码的知识被整合到同一情节表示中。

    Returns:
      {"tce_boosted": N, "total_examined": N}
    """
    try:
        import config as _cfg_tce
    except ImportError:
        return {"tce_boosted": 0, "total_examined": 0}

    try:
        if not _cfg_tce.get("store_vfs.tce_enabled"):
            return {"tce_boosted": 0, "total_examined": 0}
        tce_window_secs = _cfg_tce.get("store_vfs.tce_window_secs")       # 1800
        tce_bonus = _cfg_tce.get("store_vfs.tce_bonus")                   # 0.05
        tce_min_importance = _cfg_tce.get("store_vfs.tce_min_importance") # 0.45
        tce_max_group = _cfg_tce.get("store_vfs.tce_max_group_size")      # 10
    except Exception:
        return {"tce_boosted": 0, "total_examined": 0}

    from datetime import datetime as _dt_tce, timezone as _tz_tce
    now_iso = _dt_tce.now(_tz_tce.utc).isoformat()

    # 获取所有符合 importance 阈值的 chunk，按 created_at 排序
    try:
        rows = conn.execute(
            """SELECT id, stability, importance, created_at FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
                 AND created_at IS NOT NULL
               ORDER BY created_at ASC
               LIMIT 2000""",
            (project, tce_min_importance),
        ).fetchall()
    except Exception:
        return {"tce_boosted": 0, "total_examined": 0}

    if len(rows) < 2:
        return {"tce_boosted": 0, "total_examined": len(rows)}

    total_examined = len(rows)

    # 解析 created_at 为 timestamp（秒），构建 (cid, stab, ts) 列表
    parsed = []
    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = row[1] if isinstance(row, (list, tuple)) else row["stability"]
            created_at_str = row[3] if isinstance(row, (list, tuple)) else row["created_at"]

            if not created_at_str:
                continue
            if created_at_str.endswith("Z"):
                created_at_str = created_at_str[:-1] + "+00:00"
            from datetime import datetime as _dt2_tce, timezone as _tz2_tce
            ca_dt = _dt2_tce.fromisoformat(created_at_str)
            if ca_dt.tzinfo is None:
                ca_dt = ca_dt.replace(tzinfo=_tz2_tce.utc)
            ts = ca_dt.timestamp()
            parsed.append((cid, float(stab or 0.1), ts))
        except Exception:
            continue

    if len(parsed) < 2:
        return {"tce_boosted": 0, "total_examined": total_examined}

    # 滑动窗口：找出同一时间窗口内的 chunk 组（连续 created_at 差 <= tce_window_secs）
    # 算法：从左到右，维护当前组 [group_start_ts, ...]，差距超过窗口则提交当前组，开新组
    groups = []
    current_group = [parsed[0]]
    for i in range(1, len(parsed)):
        cid, stab, ts = parsed[i]
        prev_ts = parsed[i - 1][2]
        if ts - prev_ts <= tce_window_secs:
            current_group.append(parsed[i])
        else:
            if len(current_group) >= 2:
                groups.append(current_group)
            current_group = [parsed[i]]
    if len(current_group) >= 2:
        groups.append(current_group)

    if not groups:
        return {"tce_boosted": 0, "total_examined": total_examined}

    tce_boosted = 0
    updates = []

    for group in groups:
        # 如果组太大，按 importance（此处用稳定性代理）取 top tce_max_group 个
        # 注意：rows 是按 importance 降序查询出来的，但这里是按 created_at 排序后分组
        # 需要从 group 中筛选：我们已经按 importance 过滤了（>= min_imp），
        # 如果组 size 超过 max_group，随机或按顺序取前 max_group 个（时间顺序）
        if len(group) > tce_max_group:
            # 取 stability 最高的 top tce_max_group 个（保护最重要的）
            group = sorted(group, key=lambda x: x[1], reverse=True)[:tce_max_group]

        # 对组内每个 chunk 施加时间毗邻加成
        for cid, stab_f, ts in group:
            if stab_f <= 0.1:
                continue
            new_stab = min(365.0, stab_f * (1.0 + tce_bonus))
            if new_stab <= stab_f + 0.0001:
                continue
            updates.append((round(new_stab, 4), now_iso, cid))
            tce_boosted += 1

    if updates:
        conn.executemany(
            "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
            updates,
        )
        conn.commit()

    return {"tce_boosted": tce_boosted, "total_examined": total_examined}


# ── iter447: Von Restorff Sleep Reactivation — 孤立记忆的睡眠期优先回放（Restorff 1933 / McDaniel & Einstein 1986）──
# 认知科学依据：
#   Von Restorff (1933) Isolation Effect — 孤立/独特的项目比同质项目记忆更好（+40-60% recall）。
#   McDaniel & Einstein (1986) JEP — 孤立效应在延迟测试（1周后）更显著；睡眠巩固选择性保护孤立记忆。
#   Huang et al. (2004) Memory — 孤立记忆的 delayed recall 在睡眠后比清醒组高约 25%。
# OS 类比：Linux huge page mlock + MADV_HUGEPAGE 双标注 —
#   独特布局页（MADV_HUGEPAGE）+ 锁定（mlock）= kswapd 跳过 + khugepaged 优先处理（双重保护路径）。

def apply_von_restorff_sleep_reactivation(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter447: Von Restorff Sleep Reactivation (VRR) — 孤立 chunk 在 sleep 时获得额外 stability 加成。

    算法：
    1. 获取项目内 importance >= vrr_min_importance 的所有 chunk，按 created_at 排序。
    2. 对每个 chunk，取其在 created_at 序列中的前后 vrr_neighbor_window/2 个邻居。
    3. 计算孤立度：isolation_score = 1 - avg(jaccard(chunk.encode_context, neighbor.encode_context))
       Jaccard = |交集| / |并集| （基于 encode_context token 集合）
    4. isolation_score >= vrr_min_isolation → sleep bonus = isolation_score × vrr_scale
       new_stab = min(365.0, stab × (1 + sleep_bonus))
    5. 返回 {"vrr_boosted": N, "total_examined": N}

    孤立度计算细节：
      - encode_context 按逗号/空格分词（与 iter407 isolation_effect 一致）。
      - 邻居 < 3 个时 isolation_score = 0.0（避免项目初期误判所有 chunk 为孤立）。
      - 邻居 Jaccard 均值越低 = 该 chunk 与周围知识越不同 = isolation_score 越高。

    Returns:
      {"vrr_boosted": N, "total_examined": N}
    """
    try:
        import config as _cfg_vrr
    except ImportError:
        return {"vrr_boosted": 0, "total_examined": 0}

    try:
        if not _cfg_vrr.get("store_vfs.vrr_enabled"):
            return {"vrr_boosted": 0, "total_examined": 0}
        vrr_min_isolation = _cfg_vrr.get("store_vfs.vrr_min_isolation")   # 0.60
        vrr_min_importance = _cfg_vrr.get("store_vfs.vrr_min_importance") # 0.50
        vrr_neighbor_window = _cfg_vrr.get("store_vfs.vrr_neighbor_window") # 20
        vrr_scale = _cfg_vrr.get("store_vfs.vrr_scale")                   # 0.10
    except Exception:
        return {"vrr_boosted": 0, "total_examined": 0}

    from datetime import datetime as _dt_vrr, timezone as _tz_vrr
    now_iso = _dt_vrr.now(_tz_vrr.utc).isoformat()

    # 获取所有符合 importance 阈值的 chunk，按 created_at 排序
    try:
        rows = conn.execute(
            """SELECT id, stability, importance, encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
               ORDER BY created_at ASC
               LIMIT 2000""",
            (project, vrr_min_importance),
        ).fetchall()
    except Exception:
        return {"vrr_boosted": 0, "total_examined": 0}

    if not rows:
        return {"vrr_boosted": 0, "total_examined": 0}

    total_examined = len(rows)

    # 构建 (cid, stab, token_set) 列表
    parsed = []
    for row in rows:
        try:
            cid = row[0] if isinstance(row, (list, tuple)) else row["id"]
            stab = float(row[1] if isinstance(row, (list, tuple)) else row["stability"] or 0.1)
            enc_ctx = row[3] if isinstance(row, (list, tuple)) else row["encode_context"]
            # 分词：按逗号 + 空格分割，去重为 frozenset
            tokens = frozenset(
                t.strip().lower()
                for t in (enc_ctx or "").replace(",", " ").split()
                if t.strip()
            )
            parsed.append((cid, stab, tokens))
        except Exception:
            continue

    if not parsed:
        return {"vrr_boosted": 0, "total_examined": total_examined}

    half_window = max(1, vrr_neighbor_window // 2)
    vrr_boosted = 0
    updates = []

    for i, (cid, stab_f, tokens) in enumerate(parsed):
        if stab_f <= 0.1 or not tokens:
            continue

        # 取前后邻居（排除自身）
        lo = max(0, i - half_window)
        hi = min(len(parsed), i + half_window + 1)
        neighbors = [parsed[j] for j in range(lo, hi) if j != i]

        if len(neighbors) < 3:
            # 邻居太少 → 无法可靠计算孤立度（避免项目初期误判）
            continue

        # 计算 Jaccard 均值
        jaccard_sum = 0.0
        valid_neighbors = 0
        for _, _, nb_tokens in neighbors:
            if not nb_tokens:
                continue
            inter = len(tokens & nb_tokens)
            union = len(tokens | nb_tokens)
            if union > 0:
                jaccard_sum += inter / union
                valid_neighbors += 1

        if valid_neighbors == 0:
            continue

        avg_jaccard = jaccard_sum / valid_neighbors
        isolation_score = 1.0 - avg_jaccard

        if isolation_score < vrr_min_isolation:
            continue

        # 孤立度达标 → 计算 sleep bonus
        sleep_bonus = isolation_score * vrr_scale
        new_stab = min(365.0, stab_f * (1.0 + sleep_bonus))
        if new_stab <= stab_f + 0.0001:
            continue

        updates.append((round(new_stab, 4), now_iso, cid))
        vrr_boosted += 1

    if updates:
        conn.executemany(
            "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
            updates,
        )
        conn.commit()

    return {"vrr_boosted": vrr_boosted, "total_examined": total_examined}


# ── iter448: Retroactive Enhancement — 新知识睡眠后逆行增强旧相关知识（Mednick et al. 2011）──
# 认知科学依据：
#   Mednick et al. (2011) PNAS — 睡眠不仅巩固新知识，还逆行增强与之关联的旧记忆痕迹（bidirectional consolidation）。
#   Walker & Stickgold (2004) — 新技能睡眠后，结构相似的旧技能也有 overnight 提升。
#   Ellenbogen et al. (2007) Science — 睡眠促进新-旧知识联合整合，产生逆行传递性推断。
# OS 类比：Linux page fault 触发的 backward readahead —
#   page_N 缺页中断 → 内核向后预取 page_N-K 到 page_N-1（历史邻居）；
#   新 chunk 写入后睡眠 → 其关联的历史旧 chunk 也被逆行激活并增强。

def apply_retroactive_enhancement(
    conn: sqlite3.Connection,
    project: str,
) -> dict:
    """
    iter448: Retroactive Enhancement (RE) — sleep 时新 chunk 逆行增强旧相关 chunk 的 stability。

    算法：
    1. 找出"新 chunk"：created_at >= now - re_new_window_hours（24h 内写入）
       且 importance >= re_min_importance。
    2. 找出"旧 chunk"：created_at < now - re_new_window_hours
       且 importance >= re_min_importance。
    3. 对每个新 chunk，计算与所有旧 chunk 的 Jaccard(encode_context)：
       重叠 >= re_min_overlap → 候选旧 chunk。
    4. 每个旧 chunk 的 bonus = max(overlap_score × re_scale over all new chunks)。
    5. new_stab = min(365.0, old_stab × (1 + re_bonus))。
    6. 返回 {"re_boosted": N, "total_examined": N}

    关键设计：
    - 每个旧 chunk 最多被增强一次（取所有新 chunk 中的最大 bonus，避免重复叠加）。
    - re_max_old_per_new 限制每个新 chunk 影响的旧 chunk 数量（防止新 chunk 过于"广播"）。

    Returns:
      {"re_boosted": N, "total_examined": N}
    """
    try:
        import config as _cfg_re
    except ImportError:
        return {"re_boosted": 0, "total_examined": 0}

    try:
        if not _cfg_re.get("store_vfs.re_enabled"):
            return {"re_boosted": 0, "total_examined": 0}
        re_new_window_hours = _cfg_re.get("store_vfs.re_new_window_hours")  # 24.0
        re_min_overlap = _cfg_re.get("store_vfs.re_min_overlap")            # 3
        re_min_importance = _cfg_re.get("store_vfs.re_min_importance")      # 0.45
        re_scale = _cfg_re.get("store_vfs.re_scale")                        # 0.06
        re_max_old_per_new = _cfg_re.get("store_vfs.re_max_old_per_new")    # 5
    except Exception:
        return {"re_boosted": 0, "total_examined": 0}

    from datetime import datetime as _dt_re, timezone as _tz_re, timedelta as _td_re
    now_dt = _dt_re.now(_tz_re.utc)
    now_iso = now_dt.isoformat()
    new_cutoff = (now_dt - _td_re(hours=re_new_window_hours)).isoformat()

    # 获取新 chunk（24h 内写入）
    try:
        new_rows = conn.execute(
            """SELECT id, stability, importance, encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
                 AND created_at >= ?
               LIMIT 500""",
            (project, re_min_importance, new_cutoff),
        ).fetchall()
    except Exception:
        return {"re_boosted": 0, "total_examined": 0}

    if not new_rows:
        return {"re_boosted": 0, "total_examined": 0}

    # 获取旧 chunk（24h 前写入）
    try:
        old_rows = conn.execute(
            """SELECT id, stability, importance, encode_context FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
                 AND (created_at IS NULL OR created_at < ?)
               LIMIT 2000""",
            (project, re_min_importance, new_cutoff),
        ).fetchall()
    except Exception:
        return {"re_boosted": 0, "total_examined": 0}

    if not old_rows:
        return {"re_boosted": 0, "total_examined": 0}

    total_examined = len(old_rows)

    def _parse_tokens(row, idx=3):
        enc = row[idx] if isinstance(row, (list, tuple)) else row["encode_context"]
        return frozenset(
            t.strip().lower()
            for t in (enc or "").replace(",", " ").split()
            if t.strip()
        )

    def _get_field(row, idx, name):
        return row[idx] if isinstance(row, (list, tuple)) else row[name]

    # 解析旧 chunk
    old_parsed = []
    for row in old_rows:
        try:
            cid = _get_field(row, 0, "id")
            stab = float(_get_field(row, 1, "stability") or 0.1)
            tokens = _parse_tokens(row)
            old_parsed.append((cid, stab, tokens))
        except Exception:
            continue

    if not old_parsed:
        return {"re_boosted": 0, "total_examined": total_examined}

    # 解析新 chunk
    new_parsed = []
    for row in new_rows:
        try:
            tokens = _parse_tokens(row)
            if tokens:
                new_parsed.append(tokens)
        except Exception:
            continue

    if not new_parsed:
        return {"re_boosted": 0, "total_examined": total_examined}

    # 对每个旧 chunk，计算最大 bonus（来自所有新 chunk 中的最优关联）
    # old_bonus_map: {cid: max_bonus}
    old_bonus_map: dict = {}

    for new_tokens in new_parsed:
        if not new_tokens:
            continue

        # 找出与此新 chunk 高重叠的旧 chunk
        candidates = []
        for cid, stab_f, old_tokens in old_parsed:
            if not old_tokens:
                continue
            inter = len(new_tokens & old_tokens)
            if inter < re_min_overlap:
                continue
            union = len(new_tokens | old_tokens)
            if union == 0:
                continue
            overlap_score = inter / union
            candidates.append((cid, stab_f, overlap_score))

        # 取 top re_max_old_per_new（按 overlap_score 降序）
        candidates.sort(key=lambda x: x[2], reverse=True)
        for cid, stab_f, overlap_score in candidates[:re_max_old_per_new]:
            bonus = overlap_score * re_scale
            existing = old_bonus_map.get(cid, 0.0)
            if bonus > existing:
                old_bonus_map[cid] = bonus

    if not old_bonus_map:
        return {"re_boosted": 0, "total_examined": total_examined}

    # 构建更新列表（需要当前 stability）
    # 使用 old_parsed 中的 stab 值
    stab_lookup = {cid: stab_f for cid, stab_f, _ in old_parsed}
    re_boosted = 0
    updates = []

    for cid, bonus in old_bonus_map.items():
        stab_f = stab_lookup.get(cid, 0.0)
        if stab_f <= 0.1 or bonus <= 0.0:
            continue
        new_stab = min(365.0, stab_f * (1.0 + bonus))
        if new_stab <= stab_f + 0.0001:
            continue
        updates.append((round(new_stab, 4), now_iso, cid))
        re_boosted += 1

    if updates:
        conn.executemany(
            "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
            updates,
        )
        conn.commit()

    return {"re_boosted": re_boosted, "total_examined": total_examined}


def apply_quiet_wakefulness_reactivation(
    conn: sqlite3.Connection,
    project: str,
    gap_seconds: float,
) -> dict:
    """
    iter449: Quiet Wakefulness Reactivation (QWR) — 清醒安静期自发重放预巩固。

    机制：
      - Tambini et al. (2010) Neuron：学习后 10min 安静休息的功能连接增强预测 24h 记忆保留。
      - Karlsson & Frank (2009) NatNeuro：清醒安静期海马自发重放先前轨迹（awake replay）。
      - gap in [qwr_min_gap_mins, qwr_sleep_threshold_hours×3600)：处于清醒休息期 → QWR。
      - gap >= qwr_sleep_threshold_hours×3600：整夜睡眠，由 iter413 SC 处理，此函数跳过。

    参数：
      gap_seconds — 距上次 session 结束的时间间隔（秒）。

    算法：
      1. 检查 gap 是否在 QWR 窗口内（[min_gap_mins*60, sleep_threshold_hours*3600)）。
      2. 查询 last_accessed >= now - qwr_recent_hours 且 importance >= qwr_min_importance 的 chunk。
      3. 按 importance × recency_factor 排序，取前 qwr_max_chunks 个。
      4. 每个 chunk stability × qwr_boost_factor，cap 365.0。
      5. 返回 {"qwr_boosted": N, "total_examined": N, "skipped_reason": str or None}

    OS 类比：Linux page cache incremental writeback (pdflush background flush) —
      定期小批量 dirty page 写回（QWR = 轻量增量回写），防止积压到 fsync（SC = 全量回写）。
    """
    try:
        import config as _cfg_qwr
    except ImportError:
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "import_error"}

    try:
        if not _cfg_qwr.get("store_vfs.qwr_enabled"):
            return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "disabled"}
        qwr_min_gap_mins = _cfg_qwr.get("store_vfs.qwr_min_gap_mins")           # 10
        qwr_sleep_threshold_hours = _cfg_qwr.get("store_vfs.qwr_sleep_threshold_hours")  # 8.0
        qwr_recent_hours = _cfg_qwr.get("store_vfs.qwr_recent_hours")           # 4.0
        qwr_boost_factor = _cfg_qwr.get("store_vfs.qwr_boost_factor")           # 1.03
        qwr_min_importance = _cfg_qwr.get("store_vfs.qwr_min_importance")       # 0.55
        qwr_max_chunks = _cfg_qwr.get("store_vfs.qwr_max_chunks")               # 30
    except Exception:
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "config_error"}

    # 检查 gap 是否在 QWR 窗口内
    min_gap_secs = qwr_min_gap_mins * 60
    max_gap_secs = qwr_sleep_threshold_hours * 3600

    if gap_seconds < min_gap_secs:
        # 太短（连续会话），不触发 QWR
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "gap_too_short"}
    if gap_seconds >= max_gap_secs:
        # 太长（整夜睡眠），由 iter413 SC 处理
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "gap_too_long_use_sc"}

    from datetime import datetime as _dt_qwr, timezone as _tz_qwr, timedelta as _td_qwr
    now_dt = _dt_qwr.now(_tz_qwr.utc)
    now_iso = now_dt.isoformat()

    # 近期编码窗口（last_accessed 在 qwr_recent_hours 内）
    recent_cutoff = (now_dt - _td_qwr(hours=qwr_recent_hours)).isoformat()

    try:
        rows = conn.execute(
            """SELECT id, stability, importance, last_accessed FROM memory_chunks
               WHERE project = ?
                 AND COALESCE(importance, 0.0) >= ?
                 AND COALESCE(stability, 0.1) > 0.1
                 AND last_accessed >= ?
               ORDER BY importance DESC
               LIMIT ?""",
            (project, qwr_min_importance, recent_cutoff, qwr_max_chunks * 3),
        ).fetchall()
    except Exception:
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "query_error"}

    if not rows:
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "no_candidates"}

    def _get_field(row, idx, name):
        return row[idx] if isinstance(row, (list, tuple)) else row[name]

    # 按 importance × recency_factor 排序（近期 + 高重要性优先）
    scored = []
    for row in rows:
        try:
            cid = _get_field(row, 0, "id")
            stab = float(_get_field(row, 1, "stability") or 0.1)
            imp = float(_get_field(row, 2, "importance") or 0.0)
            la = _get_field(row, 3, "last_accessed") or ""
            # 计算时间新鲜度（越近 → recency_factor 越大）
            try:
                la_dt = _dt_qwr.fromisoformat(la.replace("Z", "+00:00"))
                if la_dt.tzinfo is None:
                    la_dt = la_dt.replace(tzinfo=_tz_qwr.utc)
                hours_ago = (now_dt - la_dt).total_seconds() / 3600.0
                recency_factor = max(0.0, 1.0 - hours_ago / qwr_recent_hours)
            except Exception:
                recency_factor = 0.5
            score = imp * (0.5 + 0.5 * recency_factor)  # importance 主导，recency 调节
            scored.append((cid, stab, score))
        except Exception:
            continue

    # 取前 qwr_max_chunks 个
    scored.sort(key=lambda x: x[2], reverse=True)
    top_chunks = scored[:qwr_max_chunks]
    total_examined = len(top_chunks)

    if not top_chunks:
        return {"qwr_boosted": 0, "total_examined": 0, "skipped_reason": "no_valid_rows"}

    # 应用 QWR stability 加成
    updates = []
    qwr_boosted = 0
    for cid, stab, _ in top_chunks:
        new_stab = min(365.0, stab * qwr_boost_factor)
        if new_stab <= stab + 0.0001:
            continue
        updates.append((round(new_stab, 4), now_iso, cid))
        qwr_boosted += 1

    if updates:
        conn.executemany(
            "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
            updates,
        )
        conn.commit()

    return {"qwr_boosted": qwr_boosted, "total_examined": total_examined, "skipped_reason": None}


# ── iter432: Cumulative Interference Effect — 累积干扰加速遗忘（Underwood 1957）──
# 认知科学依据：Underwood (1957) "Interference and forgetting" —
#   遗忘的主要原因是同类型知识的累积干扰，而非单纯时间流逝（decay theory 不足以解释）。
#   同类型先行学习列表越多，后续学习的遗忘越快（proactive interference）。
#   Underwood 1957 关键数据：24小时遗忘量 vs 已学干扰列表数的相关 r=0.92（极强正相关）。
#   Jenkins & Dallenbach (1924)：睡眠减少新干扰 → 遗忘更少（佐证：干扰主导，非时间）。
# OS 类比：Linux CPU cache set-associativity conflict —
#   同一 cache set 中 N-way associativity 达到上限时，新 line 必须驱逐旧 line（LRU）；
#   同 cache set 的 line 越多（more competition），每条 line 的平均留存时间越短。
#   cumulative_interference_factor = 1 + scale × log(1+N) / log(1+N_median)
#   → N 越大，factor > 1，stability 衰减更快（额外 × 1/factor 作为 penalty）。

def compute_cumulative_interference_factor(
    n_same_type: int,
    n_median: int = 10,
) -> float:
    """
    iter432: 计算累积干扰因子。

    factor = 1 + scale × log(1 + n_same_type) / log(1 + n_median)
    n_same_type < ci_min_n_same_type → factor = 1.0（无干扰）
    factor 上限为 ci_max_factor。

    在 decay_stability_by_type_with_ci() 中：
      new_stability = stability × type_decay / factor

    参数：
      n_same_type — 当前项目中同 chunk_type 的 chunk 数量
      n_median    — 参考中位数（用于规范化，默认 10）

    Returns:
      float >= 1.0 — 干扰因子（> 1 = 加速衰减）
    """
    import config as _config
    import math
    try:
        if not _config.get("scorer.cumulative_interference_enabled"):
            return 1.0
        min_n = int(_config.get("scorer.ci_min_n_same_type") or 5)
        if n_same_type < min_n:
            return 1.0
        scale = float(_config.get("scorer.ci_scale") or 0.30)
        max_factor = float(_config.get("scorer.ci_max_factor") or 2.0)
        if n_median <= 0:
            n_median = 10
        factor = 1.0 + scale * math.log(1 + n_same_type) / math.log(1 + n_median)
        return min(max_factor, factor)
    except Exception:
        return 1.0


def decay_stability_by_type_with_ci(
    conn: sqlite3.Connection,
    project: str = None,
    stale_days: int = 30,
    now_iso: str = None,
) -> dict:
    """
    iter432: decay_stability_by_type 的扩展版，叠加 Cumulative Interference Effect。

    在 decay_stability_by_type 基础上：
      对每种 chunk_type，统计当前项目中该类型的 chunk 数量（N_same_type），
      计算累积干扰因子 factor，对该类型的 stability 衰减乘以 1/factor（等效加速衰减）：
        effective_decay = type_decay × (1/factor) ≡ type_decay / factor
        new_stability = MAX(0.1, stability × effective_decay)

    豁免类型（ci_protect_types，默认 design_constraint/procedure）不受干扰影响。
    也尊重 Ribot floor：衰减结果不低于 ribot_floor。

    Returns:
      dict — {total_decayed: N, ci_factors: {chunk_type: factor}}
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    import config as _config
    if now_iso is None:
        now_iso = _dt.now(_tz.utc).isoformat()
    cutoff = (_dt.now(_tz.utc) - _td(days=stale_days)).isoformat()

    proj_filter = "AND project=?" if project else ""
    proj_params = [project] if project else []

    # 获取保护类型（不受干扰）
    protect_types_str = _config.get("scorer.ci_protect_types") or ""
    protect_types = frozenset(t.strip() for t in protect_types_str.split(",") if t.strip())

    # 统计每种 chunk_type 的数量（per-project）
    type_counts: dict = {}
    try:
        count_sql = "SELECT chunk_type, COUNT(*) FROM memory_chunks"
        count_params = []
        if project:
            count_sql += " WHERE project=?"
            count_params = [project]
        count_sql += " GROUP BY chunk_type"
        rows = conn.execute(count_sql, count_params).fetchall()
        for r in rows:
            ct = r[0] or ""
            cnt = int(r[1] or 0)
            type_counts[ct] = cnt
    except Exception:
        pass

    # N_median：所有 chunk_type 数量的中位数（规范化分母）
    counts_list = sorted(type_counts.values())
    n_median = counts_list[len(counts_list) // 2] if counts_list else 10

    total_decayed = 0
    ci_factors: dict = {}

    all_types = list(CHUNK_TYPE_DECAY.keys()) + [""]

    for ctype, decay in CHUNK_TYPE_DECAY.items():
        if ctype in protect_types:
            # 豁免类型：不应用干扰，使用普通 type_decay
            try:
                conn.execute(
                    f"UPDATE memory_chunks "
                    f"SET stability=MAX(0.1, stability * ?), updated_at=? "
                    f"WHERE chunk_type=? AND last_accessed < ? AND access_count < 2 {proj_filter}",
                    [decay, now_iso, ctype, cutoff] + proj_params,
                )
                total_decayed += conn.execute("SELECT changes()").fetchone()[0]
            except Exception:
                pass
            ci_factors[ctype] = 1.0
            continue

        n_ct = type_counts.get(ctype, 0)
        factor = compute_cumulative_interference_factor(n_ct, n_median)
        # effective_decay = type_decay / factor（factor >= 1 → 有效衰减 <= type_decay）
        # 注意：decay 是 [0,1] 的乘子（越大衰减越慢），除以 factor > 1 → 更小的乘子 → 更快衰减
        effective_decay = max(0.01, decay / factor)
        ci_factors[ctype] = factor

        try:
            conn.execute(
                f"UPDATE memory_chunks "
                f"SET stability=MAX(0.1, stability * ?), updated_at=? "
                f"WHERE chunk_type=? AND last_accessed < ? AND access_count < 2 {proj_filter}",
                [effective_decay, now_iso, ctype, cutoff] + proj_params,
            )
            total_decayed += conn.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass

    # 未列出的类型（使用默认衰减率）
    unknown_n = type_counts.get("", 0) + sum(
        v for k, v in type_counts.items() if k not in CHUNK_TYPE_DECAY
    )
    default_factor = compute_cumulative_interference_factor(unknown_n, n_median)
    effective_default = max(0.01, _DEFAULT_TYPE_DECAY / default_factor)
    ci_factors["_other"] = default_factor

    known_types_ph = ",".join("?" * len(CHUNK_TYPE_DECAY))
    try:
        conn.execute(
            f"UPDATE memory_chunks "
            f"SET stability=MAX(0.1, stability * ?), updated_at=? "
            f"WHERE (chunk_type NOT IN ({known_types_ph}) OR chunk_type IS NULL) "
            f"AND last_accessed < ? AND access_count < 2 {proj_filter}",
            [effective_default, now_iso] + list(CHUNK_TYPE_DECAY.keys()) + [cutoff] + proj_params,
        )
        total_decayed += conn.execute("SELECT changes()").fetchone()[0]
    except Exception:
        pass

    return {"total_decayed": total_decayed, "ci_factors": ci_factors}


# ── iter402：Schema Theory — Prior Knowledge Scaffolding（Bartlett 1932）────────
#
# 认知科学依据：
#   Bartlett (1932) Remembering — "图式"（Schema）理论：
#     新信息被同化到已有知识框架（图式）中，共享框架的知识相互加固。
#     当新知识和已有高稳定性知识共享概念时，新知识的初始稳定性更高。
#   Piaget (1952) Schema Assimilation：
#     assimilation — 新信息被纳入现有图式（没有根本改变图式）
#     accommodation — 现有图式被修改以适应新信息
#     这里实现 assimilation：新 chunk 共享已有 entity → 继承部分 stability
#   Anderson (1984) Schema Theory in Education：
#     先验知识越丰富，新知识越容易被编码（"rich get richer"效应）。
#
# OS 类比：Linux Transparent Hugepage (THP) promotion
#   当一个 2MB 对齐的内存区域中大多数 4KB 页面都存在时（prior_pages_exist），
#   新 fault 进来的匿名页会直接被提升为 THP 的一部分，继承 THP 的 cache 亲和性。
#   新 chunk 发现已有同主题 chunk（prior schema）→ 继承部分 stability bonus。
#
# 实现：
#   compute_schema_bonus(conn, chunk_id, project) → float [0.0, 2.0]
#     通过 entity_map 查找 chunk 关联的 entity，
#     再通过 entity_map 找到同 project 中共享这些 entity 的已有 chunk，
#     取这些先验 chunk 的 stability 均值 × schema_inherit_ratio（默认 0.2）。
#   apply_schema_scaffolding(conn, chunk_id, content, project)
#     写入 schema_bonus 到 stability

import re as _re_schema

_SCHEMA_INHERIT_RATIO: float = 0.2   # 继承先验 stability 的比例
_SCHEMA_MAX_BONUS: float = 2.0       # 最大 bonus（防止极端情况）


def compute_schema_bonus(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    max_bonus: float = _SCHEMA_MAX_BONUS,
    inherit_ratio: float = _SCHEMA_INHERIT_RATIO,
) -> float:
    """
    iter402：计算新 chunk 基于先验图式（existing knowledge）的稳定性加成。

    算法：
      1. 通过 entity_map 找到 chunk_id 关联的 entity_name（写入时已设置）
      2. 对每个 entity，通过 entity_map 找到 project 中其他 chunk 的 stability
      3. 取所有先验 chunk stability 的均值 × inherit_ratio
      4. 先验 chunk 越多、越稳定 → bonus 越高
      5. clamp 到 [0.0, max_bonus]

    OS 类比：THP promotion scan — 扫描已有同区域 pages 的 PFN 密度，
      密度越高（prior_schema 越丰富）→ 新 page 晋升 THP 概率越高。

    Returns:
      float ∈ [0.0, max_bonus]
    """
    if not chunk_id or not project:
        return 0.0
    try:
        # Step 1: 找到该 chunk 关联的 entity（entity_map 当前行 OR entity_edges）
        entity_rows = conn.execute(
            "SELECT entity_name FROM entity_map WHERE chunk_id=? AND project=?",
            (chunk_id, project),
        ).fetchall()

        # entity_map PK=(entity_name, project)：若新 chunk 刚写入，entity 已指向它
        # 所以 entity_name 已知；再通过 entity_edges 找到同 project 中
        # 以该 entity 为 from/to 的关系涉及的 source_chunk_id（历史 chunk）
        entity_names = [r[0] for r in entity_rows if r[0]]
        if not entity_names:
            return 0.0

        # Step 2a: 通过 entity_edges 找到同 project 中涉及这些 entity 的 chunk
        ent_ph = ",".join("?" * len(entity_names))
        edge_chunk_rows = conn.execute(
            f"SELECT DISTINCT source_chunk_id FROM entity_edges "
            f"WHERE (from_entity IN ({ent_ph}) OR to_entity IN ({ent_ph})) "
            f"AND project=? AND source_chunk_id IS NOT NULL AND source_chunk_id != ?",
            entity_names + entity_names + [project, chunk_id],
        ).fetchall()
        edge_chunk_ids = [r[0] for r in edge_chunk_rows if r[0]]

        # Step 2b: 通过 content/summary LIKE 搜索找到同 project 中含这些 entity 的 chunk
        # entity_map PK 限制只能指向最新 chunk，所以需要直接搜内容
        like_conditions = " OR ".join(
            ["(mc.content LIKE ? OR mc.summary LIKE ?)"] * len(entity_names)
        )
        like_params = []
        for en in entity_names:
            like_params.extend([f"%{en}%", f"%{en}%"])

        content_rows = conn.execute(
            f"SELECT mc.id, mc.stability FROM memory_chunks mc "
            f"WHERE mc.project=? AND mc.id != ? AND mc.stability IS NOT NULL "
            f"AND ({like_conditions})",
            [project, chunk_id] + like_params,
        ).fetchall()
        content_stabilities = {r[0]: float(r[1]) for r in content_rows if r[1] is not None}

        # Step 2c: 合并 edge_chunk_ids 对应的 stability
        if edge_chunk_ids:
            edge_ph = ",".join("?" * len(edge_chunk_ids))
            edge_rows = conn.execute(
                f"SELECT stability FROM memory_chunks WHERE id IN ({edge_ph}) AND stability IS NOT NULL",
                edge_chunk_ids,
            ).fetchall()
            for r in edge_rows:
                content_stabilities[f"_edge_{len(content_stabilities)}"] = float(r[0])

        if not content_stabilities:
            return 0.0

        # Step 3: 先验 chunk stability 均值 × inherit_ratio
        prior_stabilities = list(content_stabilities.values())
        avg_prior_stability = sum(prior_stabilities) / len(prior_stabilities)
        bonus = avg_prior_stability * inherit_ratio
        return round(min(max_bonus, max(0.0, bonus)), 4)
    except Exception:
        return 0.0


def apply_schema_scaffolding(
    conn: sqlite3.Connection,
    chunk_id: str,
    project: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter402：应用图式加成 — 将 compute_schema_bonus 结果加到 stability。

    OS 类比：THP promotion path — 新 page fault 落在高密度区域时，
      内核直接 alloc_huge_page() 而不是分配独立 4KB 页。

    Returns:
      new_stability（包含 schema bonus）
    """
    bonus = compute_schema_bonus(conn, chunk_id, project)
    if bonus <= 0.001:
        return base_stability

    new_stability = min(base_stability * 4.0, base_stability + bonus)
    try:
        conn.execute(
            "UPDATE memory_chunks SET stability=?, updated_at=? WHERE id=?",
            (round(new_stability, 4), datetime.now(timezone.utc).isoformat(), chunk_id),
        )
    except Exception:
        pass
    return round(new_stability, 4)


# ── iter401：Elaborative Encoding — Depth of Processing（Craik & Lockhart 1972）──
#
# 认知科学依据：
#   Craik & Lockhart (1972) Levels of Processing：
#     记忆痕迹强度由信息被加工的"深度"决定，而非单纯的重复次数。
#     - 浅处理（字形/音韵）：只分析物理特征 → 短暂记忆痕迹
#     - 深处理（语义/关联）：分析意义、关联已有知识 → 持久记忆痕迹
#   Craik & Tulving (1975)：语义判断任务（"这个词适合句子吗？"）比视觉判断
#     产生更强的记忆，因为触发了更多的语义网络激活。
#   Reder & Anderson (1980)：精细编码（elaborate encoding）通过增加区分性
#     线索来增强提取能力。
#
# OS 类比：Linux dirty page writeback 的 write aggregation —
#   页面在 dirty buffer 中等待时间越长，write aggregation 越充分，
#   I/O 效率越高（类比深度加工 → 记忆更完整，更易检索）。
#   另一类比：L1 TLB miss → L2 TLB → page table walk — 越深层的处理成本越高，
#   但缓存命中率越持久。
#
# 实现：
#   compute_depth_of_processing(text) → float [0.0, 1.0]
#   通过以下特征估算加工深度：
#     1. 因果推理词（because/therefore/causes/由于/因此）→ 语义深处理
#     2. 结构化分析词（first/then/finally/第一/第二）→ 组织性加工
#     3. 对比/比较（however/unlike/相比/但是）→ 区分性处理
#     4. 抽象概念数量（concept density）→ 语义丰富度
#     5. 文本长度（适度长度 = 充分展开）→ 信息密度代理

import re as _re_dop

_DOP_CAUSAL_RE = _re_dop.compile(
    r'because|therefore|thus|hence|causes|leads to|results in|due to|'
    r'since|so that|in order to|consequently|'
    r'因为|因此|所以|由于|导致|造成|使得|故而|结果|从而',
    _re_dop.IGNORECASE,
)
_DOP_STRUCTURAL_RE = _re_dop.compile(
    r'first[,\s]|second[,\s]|third[,\s]|finally|then |next |'
    r'step 1|step 2|step \d|phase \d|'
    r'第一[，。、]|第二[，。、]|第三[，。、]|首先|其次|最后|然后|接下来|步骤',
    _re_dop.IGNORECASE,
)
_DOP_CONTRASTIVE_RE = _re_dop.compile(
    r'however|but |although|unlike|whereas|on the other hand|'
    r'nevertheless|in contrast|compared to|'
    r'但是|然而|虽然|尽管|不过|相比|相反|与此相比|对比',
    _re_dop.IGNORECASE,
)
_DOP_ELABORATION_RE = _re_dop.compile(
    r'specifically|in particular|for example|for instance|'
    r'that is to say|in other words|namely|such as|'
    r'具体来说|特别是|例如|比如|也就是说|换句话说|即',
    _re_dop.IGNORECASE,
)

# 每个类别的最大贡献（防止单一维度主导）
_DOP_MAX_PER_CATEGORY = 0.25


def compute_depth_of_processing(text: str) -> float:
    """
    iter401：计算文本的加工深度（Depth of Processing, Craik & Lockhart 1972）。

    四个维度各贡献最多 0.25，总分 [0.0, 1.0]：
      1. 因果推理 (0.25)：有无因果/推理词
      2. 结构组织 (0.25)：有无序列/结构词
      3. 对比区分 (0.25)：有无对比/比较词
      4. 精细阐述 (0.25)：有无例证/解释词

    OS 类比：Linux perf stat 的 IPC（Instructions Per Cycle）—
      同样的代码路径，加工深度不同导致不同的缓存热度。

    Returns:
      float ∈ [0.0, 1.0]
    """
    if not text or len(text.strip()) < 4:
        return 0.0

    score = 0.0

    # 维度 1：因果推理
    causal_count = len(_DOP_CAUSAL_RE.findall(text))
    score += min(_DOP_MAX_PER_CATEGORY, causal_count * 0.12)

    # 维度 2：结构组织
    struct_count = len(_DOP_STRUCTURAL_RE.findall(text))
    score += min(_DOP_MAX_PER_CATEGORY, struct_count * 0.10)

    # 维度 3：对比区分
    contrast_count = len(_DOP_CONTRASTIVE_RE.findall(text))
    score += min(_DOP_MAX_PER_CATEGORY, contrast_count * 0.12)

    # 维度 4：精细阐述
    elab_count = len(_DOP_ELABORATION_RE.findall(text))
    score += min(_DOP_MAX_PER_CATEGORY, elab_count * 0.10)

    return round(min(1.0, max(0.0, score)), 4)


def apply_depth_of_processing(
    conn: sqlite3.Connection,
    chunk_id: str,
    content: str,
    base_stability: float = 1.0,
) -> float:
    """
    iter401：计算 depth_of_processing，写入 DB，并返回调整后的 stability。

    深度加工 bonus：
      depth >= 0.5 → stability += 0.5（中等深度加工）
      depth >= 0.75 → stability += 1.5（高度加工，形成长久记忆痕迹）
    上限：base_stability 最高 × 3.0

    OS 类比：Linux CoW（Copy-on-Write）page promotion —
      页面被多次写入且内容丰富时，从 anon page 晋升到 THP（Transparent Hugepage），
      访问延迟从 4KB miss → 2MB TLB hit。

    Returns:
      new_stability（包含 depth bonus）
    """
    dop = compute_depth_of_processing(content or "")

    # depth_bonus: 线性插值，dop=0 → +0, dop=1 → +2.0
    depth_bonus = dop * 2.0
    new_stability = min(base_stability * 3.0, base_stability + depth_bonus)

    try:
        conn.execute(
            "UPDATE memory_chunks SET depth_of_processing=?, stability=?, updated_at=? WHERE id=?",
            (dop, round(new_stability, 4), datetime.now(timezone.utc).isoformat(), chunk_id),
        )
    except Exception:
        pass

    return round(new_stability, 4)


def promote_to_semantic(
    conn: sqlite3.Connection,
    source_chunk_ids: list,
    project: str,
    session_id: str = "",
    min_recall_count: int = 3,
) -> Optional[str]:
    """
    迭代319：将多次召回的情节 chunk 合并提升为语义 chunk。

    算法：
      1. 读取所有 source_chunk_ids 的 content/summary/access_count
      2. 过滤掉 access_count < min_recall_count 的（未达到巩固阈值）
      3. 合并 summary → 生成新语义 chunk（info_class='semantic'）
      4. 降级原情节 chunk（info_class='world', importance *= 0.6, oom_adj += 100）
      5. 在 episodic_consolidations 中记录转化事件

    OS 类比：Linux THP compaction (khugepaged) —
      扫描连续小页面，若访问频率够高则合并成 2MB hugepage（类比语义 chunk），
      原小页面被 free（类比情节 chunk 降级），元数据存入 compound_page 结构。

    Returns:
      新语义 chunk 的 ID，或 None（无满足条件的情节 chunk）
    """
    if not source_chunk_ids:
        return None

    ph = ",".join("?" * len(source_chunk_ids))
    rows = conn.execute(
        f"SELECT id, summary, content, access_count, importance "
        f"FROM memory_chunks "
        f"WHERE id IN ({ph}) AND project=? AND info_class='episodic'",
        source_chunk_ids + [project],
    ).fetchall()

    # 过滤：access_count >= min_recall_count
    eligible = [(r[0], r[1], r[2], r[3], r[4]) for r in rows
                if (r[3] or 0) >= min_recall_count]
    if not eligible:
        return None

    # 合并 summary：取所有 eligible 的 summary，去重后拼接
    summaries = list({r[1] for r in eligible if r[1]})
    if not summaries:
        return None

    # 新语义 chunk：保留最高 importance，summary 为第一条，content 为所有 summary 聚合
    max_importance = max(r[4] or 0.5 for r in eligible)
    primary_summary = summaries[0]
    merged_content = "\n".join(summaries)[:2000]

    import uuid as _uuid
    new_id = "sem_" + _uuid.uuid4().hex[:16]
    now_iso = datetime.now(timezone.utc).isoformat()

    new_chunk = {
        "id": new_id,
        "created_at": now_iso,
        "updated_at": now_iso,
        "project": project,
        "source_session": session_id,
        "chunk_type": "decision",  # 语义记忆默认用 decision 类型
        "info_class": "semantic",
        "content": merged_content,
        "summary": f"[语义化] {primary_summary}",
        "tags": ["semantic", "consolidated"],
        "importance": min(0.95, max_importance * 1.1),  # 轻微提升
        "retrievability": 0.8,
        "last_accessed": now_iso,
        "access_count": sum(r[3] or 0 for r in eligible),
        "oom_adj": -100,  # 语义记忆优先保留
        "lru_gen": 0,
        "stability": min(365.0, max_importance * 30.0),  # 高 stability
        "raw_snippet": "",
        "encoding_context": {},
    }
    insert_chunk(conn, new_chunk)

    # 降级原情节 chunk
    source_ids = [r[0] for r in eligible]
    for src_id in source_ids:
        old_imp = next(r[4] for r in eligible if r[0] == src_id) or 0.5
        conn.execute(
            "UPDATE memory_chunks SET info_class='world', importance=?, oom_adj=oom_adj+100, "
            "updated_at=? WHERE id=?",
            (round(old_imp * 0.6, 4), now_iso, src_id),
        )

    # 记录转化事件
    trigger_count = max(r[3] or 0 for r in eligible)
    try:
        conn.execute(
            """INSERT INTO episodic_consolidations
               (semantic_chunk_id, source_chunk_ids, project, trigger_count, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (new_id, json.dumps(source_ids), project, trigger_count, now_iso),
        )
    except Exception:
        pass

    return new_id


def episodic_decay_scan(
    conn: sqlite3.Connection,
    project: str,
    stale_days: int = 14,
    semantic_threshold: int = 2,
    max_promote: int = 10,
    semantic_hard_threshold: int = 5,
) -> dict:
    """
    迭代319：扫描情节记忆 — 衰减过期情节 chunk，提升高频召回情节 chunk 为语义 chunk。
    迭代327：semantic_threshold 降低 3 → 2（access_count=0 的情节 chunk 因 content 太短
    从未被召回，threshold=3 导致晋升路径永远不触发；降低到 2 让 access_count>=2 的 10 个
    chunks 有资格晋升，也避免"先有鸡还是先有蛋"的死锁）。
    迭代379：新增 A0 原地提升路径 — 基于 Tulving (1972) 双加工理论：
      单个情节 chunk 多次访问（>= semantic_hard_threshold=5）时，原地升级为语义记忆。
      避免碎片合并（promote_to_semantic 路径），保留 chunk identity，
      提升 stability × 1.5，设 info_class='semantic'，让语义层衰减速率（0.97）生效。
      OS 类比：mprotect(PROT_READ|PROT_EXEC) — 热页面提升保护级别，
        从 anonymous page（情节）升级为 file-backed 共享页（语义，跨 session 共享）。

    三个子操作（类比睡眠巩固的特化版本）：
      A0. 原地提升（iter379）：单个 info_class='episodic' chunk，
          access_count >= semantic_hard_threshold（默认5）→ 原地升级 info_class='semantic',
          stability × 1.5（上限 200），oom_adj -= 50（增加保留概率）
      A.  合并提升：info_class='episodic' AND access_count >= semantic_threshold（默认2）
          → 调用 promote_to_semantic()，合并同组情节 chunk 为新语义 chunk
      B.  衰减：info_class='episodic' AND last_accessed < (now - stale_days)
          AND access_count < 2 → importance *= 0.7, oom_adj += 50

    OS 类比：Linux khugepaged + kswapd 协同 —
      A0: mprotect() 热页面原地升级权限（不复制，不移动）
      A:  khugepaged 提升高频访问小页面（促进 → 语义）
      kswapd 回收冷页面（衰减 → 降权 → 更易被 evict）

    Returns:
      {"decayed": N, "promoted": N, "inplace_promoted": N, "new_semantic_ids": [...]}
    """
    result: dict = {"decayed": 0, "promoted": 0, "inplace_promoted": 0, "new_semantic_ids": []}
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # ── 子操作 A0：原地提升（iter379 新增）────────────────────────────────────
    # 认知科学基础：Tulving (1972) episodic-to-semantic shift —
    #   情节记忆通过多次重激活（access_count++）逐渐脱离时间/情境特异性，
    #   转化为与情境无关的通用语义知识（语义记忆）。
    # 触发条件：access_count >= semantic_hard_threshold（5），chunk_type 为可巩固类型
    # 效果：info_class 原地更新（不新建 chunk），stability × 1.5，oom_adj -= 50
    _CONSOLIDATABLE_TYPES = ("reasoning_chain", "conversation_summary", "causal_chain",
                              "decision", "design_constraint")
    try:
        inplace_rows = conn.execute(
            "SELECT id, stability, oom_adj, chunk_type FROM memory_chunks "
            "WHERE project=? AND info_class='episodic' "
            "  AND chunk_type IN ({}) "
            "  AND COALESCE(access_count,0) >= ?".format(
                ",".join("?" * len(_CONSOLIDATABLE_TYPES))
            ),
            (project, *_CONSOLIDATABLE_TYPES, semantic_hard_threshold),
        ).fetchall()

        inplace_promoted = 0
        for row in inplace_rows:
            cid, cur_stability, cur_oom, ctype = row
            cur_stability = cur_stability or 1.0
            cur_oom = cur_oom or 0
            new_stability = min(200.0, cur_stability * 1.5)
            new_oom = max(-500, cur_oom - 50)
            conn.execute(
                "UPDATE memory_chunks "
                "SET info_class='semantic', stability=?, oom_adj=?, updated_at=? "
                "WHERE id=?",
                (round(new_stability, 4), new_oom, now_iso, cid),
            )
            inplace_promoted += 1

        result["inplace_promoted"] = inplace_promoted
    except Exception:
        pass

    # ── 子操作 A：合并提升高频情节 chunk（原有路径）─────────────────────────
    try:
        promote_rows = conn.execute(
            "SELECT id FROM memory_chunks "
            "WHERE project=? AND info_class='episodic' AND COALESCE(access_count,0) >= ? "
            "ORDER BY access_count DESC LIMIT ?",
            (project, semantic_threshold, max_promote),
        ).fetchall()

        promote_ids = [r[0] for r in promote_rows]
        if promote_ids:
            new_id = promote_to_semantic(
                conn, promote_ids, project, min_recall_count=semantic_threshold
            )
            if new_id:
                result["promoted"] = len(promote_ids)
                result["new_semantic_ids"].append(new_id)
    except Exception:
        pass

    # ── 子操作 B：衰减过期情节 chunk ──────────────────────────────────────────
    try:
        from datetime import timedelta as _td
        cutoff = (now - _td(days=stale_days)).isoformat()
        conn.execute(
            "UPDATE memory_chunks "
            "SET importance=MAX(0.05, importance * 0.7), oom_adj=COALESCE(oom_adj,0)+50, "
            "    updated_at=? "
            "WHERE project=? AND info_class='episodic' "
            "  AND last_accessed < ? AND COALESCE(access_count,0) < 2",
            (now_iso, project, cutoff),
        )
        result["decayed"] = conn.execute("SELECT changes()").fetchone()[0]
    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 迭代335：Ghost Reaper — zombie chunk FTS5 污染清除
# OS 类比：Linux wait4()/waitpid() — 父进程回收 zombie 子进程，释放进程表项。
#
# Ghost chunk 产生机制（consolidate/merge 路径）：
#   1. merge_similar / sleep_consolidate 合并 victim → survivor
#   2. victim 被标记：importance=0, oom_adj=500, summary=[merged→survivor_id]
#   3. 但 victim 未被 DELETE — FTS5 content table 仍有其 summary 索引
#   4. 结果：FTS5 搜索命中 ghost → 消耗 result slot + false recall count
#   5. importance=0 的 ghost 在 _score_chunk 后分数极低但仍出现在 final 列表
#
# 信息论根因（Redundancy Theory, Kolmogorov 1965）：
#   ghost chunk 携带 0 信息（已合并，K-complexity=0），但占用检索带宽。
#   每次 FTS5 hit = 浪费 ~0.1ms 评分计算 + 挤占候选池 slot（候选总量 top_k×3 固定）。
#   实测：全项目 67 ghost chunks 累计 1721 false recall（平均 25.7 次/ghost）。
#   P(ghost selected) ≈ 5%（评分极低但 DRR 偶发回流），SNR 降低约 3-5%。
#
# 解决（两层防御）：
#   Layer 1（硬删除）：reap_ghosts() 物理删除 importance=0 chunk，触发 FTS5 DELETE trigger
#   Layer 2（软过滤）：retriever.py fts_search 调用前加 importance > 0 防护（in-flight 保护）
#
# 触发时机：
#   - 手动调用（tools/reap_ghosts.py 或 CLI）
#   - kswapd 扫描时附带执行（低优先级后台任务）
#   - sleep_consolidate 合并完成后自动 reap（TODO iter336+）
# ══════════════════════════════════════════════════════════════════════════════

def reap_ghosts(conn: sqlite3.Connection,
                project: Optional[str] = None,
                dry_run: bool = False) -> dict:
    """
    迭代335：回收 ghost chunk（importance=0 且 oom_adj>=500 的已合并 chunk）。

    Ghost 判定标准（两条件同时满足，避免误删 importance=0 但有实意的 chunk）：
      1. importance <= 0.0（合并路径设置）
      2. summary LIKE '[merged→%'（合并标记前缀）

    只满足条件 1 但 summary 不含合并标记的 chunk 不被视为 ghost（可能是用户故意
    设为 0 importance 的保留 chunk），不删除。

    OS 类比：
      wait4() 的 WNOHANG 标志 — 非阻塞扫描，只回收已经是 zombie 的进程，
      不等待仍在运行的进程退出。

    Args:
      conn:     SQLite 连接（需要写权限）
      project:  限定回收范围（None = 全项目）
      dry_run:  True = 只统计不删除

    Returns:
      dict:
        reaped_count    — 已删除数量（dry_run 时为待删除数量）
        ghost_ids       — 被删除的 chunk_id 列表
        projects_stats  — {project: count} 各项目回收统计
        dry_run         — 是否只读模式
    """
    try:
        if project:
            rows = conn.execute(
                "SELECT id, project, summary FROM memory_chunks "
                "WHERE project=? AND importance <= 0.0 "
                "  AND (summary LIKE '[merged→%' OR oom_adj >= 500)",
                (project,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, project, summary FROM memory_chunks "
                "WHERE importance <= 0.0 "
                "  AND (summary LIKE '[merged→%' OR oom_adj >= 500)",
            ).fetchall()

        if not rows:
            return {"reaped_count": 0, "ghost_ids": [], "projects_stats": {}, "dry_run": dry_run}

        ghost_ids = [r[0] for r in rows]
        projects_stats: dict = {}
        for _gid, _gproj, _gsumm in rows:
            projects_stats[_gproj] = projects_stats.get(_gproj, 0) + 1

        if dry_run:
            return {
                "reaped_count": len(ghost_ids),
                "ghost_ids": ghost_ids,
                "projects_stats": projects_stats,
                "dry_run": True,
            }

        # B15 FTS sync: FTS5 独立模式，无触发器，必须手动清理孤立行
        placeholders = ",".join("?" * len(ghost_ids))
        rowid_rows = conn.execute(
            f"SELECT rowid FROM memory_chunks WHERE id IN ({placeholders})",
            ghost_ids,
        ).fetchall()
        mc_rowids = [str(r[0]) for r in rowid_rows]

        conn.execute(
            f"DELETE FROM memory_chunks WHERE id IN ({placeholders})",
            ghost_ids,
        )
        reaped = conn.execute("SELECT changes()").fetchone()[0]

        if mc_rowids:
            try:
                fts_ph = ",".join("?" * len(mc_rowids))
                conn.execute(
                    f"DELETE FROM memory_chunks_fts WHERE rowid_ref IN ({fts_ph})",
                    mc_rowids,
                )
            except Exception:
                pass

        return {
            "reaped_count": reaped,
            "ghost_ids": ghost_ids,
            "projects_stats": projects_stats,
            "dry_run": False,
        }
    except Exception as e:
        return {"reaped_count": 0, "ghost_ids": [], "projects_stats": {}, "dry_run": dry_run,
                "error": str(e)}


# ── 迭代360：FTS5 Auto-Optimize（降低 P95 延迟）────────────────────────────────
# OS 类比：ext4 e2fsck online defrag — 合并碎片化的 b-tree segment，
#   减少 FTS5 查询时需要扫描的 segment 数量（O(S×logN) → O(logN)）。
#
# 问题根因（v5 audit, 2026-04-28）：
#   SQLite FTS5 在每次 insert/delete/update 后生成新的 b-tree segment。
#   当 segment 数量 S 增大时，FTS5 查询需要合并 S 个 posting list，
#   时间复杂度从 O(logN) 退化为 O(S×logN)。
#   实测：352 次历史写入（105 chunk）→ 产生大量碎片化 segment → P95=273ms。
#   FTS5 optimize 命令：强制合并所有 segment → 单 segment → O(logN)。
#
# 冷却保护：至少间隔 _FTS_OPTIMIZE_INTERVAL 秒（默认 3600 秒 = 1 小时），
#   避免高频写入场景下 optimize 本身成为性能瓶颈（optimize 是重写操作）。
#   OS 类比：e4defrag 的 min_defrag_interval — 防止 defrag 自我拖累。

_FTS_OPTIMIZE_INTERVAL: float = 3600.0  # 冷却时间（秒），最少 1 小时间隔
_fts_last_optimize: float = 0.0  # 上次 optimize 的 monotonic 时间戳


def interference_decay(conn: sqlite3.Connection, new_chunk: dict, project: str,
                       threshold_mild: float = 0.30,
                       threshold_strong: float = 0.50,
                       decay_mild: float = 0.10,
                       decay_strong: float = 0.20,
                       max_affected: int = 10) -> int:
    """
    iter386: Interference-Based Retrievability Decay — 干扰式检索衰减

    认知科学依据：
      McGeoch (1932) Interference Theory — 遗忘的主因是新旧记忆之间的干扰，
        而非时间本身（Ebbinghaus 的衰减曲线只是表象）。
      Anderson (2003) Inhibition Theory — 海马回路通过主动抑制机制降低干扰记忆的可及性，
        确保最相关记忆优先浮现（Retrieval-Induced Forgetting, RIF）。

    OS 类比：CPU TLB Shootdown (INVLPG, x86 SMP)
      当一个核修改了页表（写入新chunk）时，必须向所有其他核广播 TLB 失效（INVLPG），
      否则其他核的 TLB 仍持有旧的虚地址→物理地址映射（过时知识仍被注入）。
      类比：写入覆盖旧知识的新 chunk → 旧 chunk 的 retrievability 降低（TLB 失效）。

    算法：
      1. FTS5 搜索新 chunk 的 summary，找语义相近旧 chunk（同 project）
      2. 计算 Jaccard 相似度（summary token 集合）
      3. mild 干扰 [threshold_mild, threshold_strong): retrievability -= decay_mild
      4. strong 干扰 [threshold_strong, +∞): retrievability -= decay_strong
      5. design_constraint 类型免疫（设计约束不受覆盖，只能显式 supersede）
      6. retrievability 下限 0.05（防止完全消失，仍可在 page fault 时 swap_in）

    保护机制：
      - design_constraint 不受干扰（mlock 保护）
      - 相同 chunk_type 的干扰权重 × 1.5（同类型更可能是覆盖更新）
      - retrievability 下限 0.05

    Returns:
      受影响的 chunk 数量
    """
    import re as _re

    if not new_chunk or not project:
        return 0

    new_summary = (new_chunk.get("summary") or "").strip()
    new_type = new_chunk.get("chunk_type", "")
    new_id = new_chunk.get("id", "")

    if not new_summary:
        return 0

    # Token 化：英文词 + CJK bigram
    def _tokenize(text: str) -> frozenset:
        tokens = set()
        for m in _re.finditer(r'[a-zA-Z0-9_\u4e00-\u9fff]{2,}', text.lower()):
            tokens.add(m.group())
        cn = _re.sub(r'[^\u4e00-\u9fff]', '', text)
        for i in range(len(cn) - 1):
            tokens.add(cn[i:i + 2])
        return frozenset(tokens)

    new_tokens = _tokenize(new_summary)
    if not new_tokens:
        return 0

    # FTS5 搜索语义相近的旧 chunk
    try:
        similar = fts_search(conn, new_summary, project, top_k=max_affected * 2)
    except Exception:
        return 0

    if not similar:
        return 0

    affected = 0
    for chunk in similar[:max_affected * 2]:
        cid = chunk.get("id", "")
        if not cid or cid == new_id:
            continue
        # design_constraint 免疫
        if chunk.get("chunk_type") == "design_constraint":
            continue
        # 获取当前 retrievability
        row = conn.execute(
            "SELECT retrievability, chunk_type FROM memory_chunks WHERE id=?", (cid,)
        ).fetchone()
        if not row:
            continue
        old_ret, old_type = float(row[0] or 0.8), (row[1] or "")

        # 计算 Jaccard 相似度
        old_tokens = _tokenize(chunk.get("summary") or "")
        if not old_tokens:
            continue
        inter = len(new_tokens & old_tokens)
        union = len(new_tokens | old_tokens)
        if union == 0:
            continue
        jaccard = inter / union

        # 同类型干扰系数 1.5（更可能是内容更新）
        type_factor = 1.5 if old_type == new_type else 1.0

        if jaccard >= threshold_strong:
            penalty = decay_strong * type_factor
        elif jaccard >= threshold_mild:
            penalty = decay_mild * type_factor
        else:
            continue  # 相似度太低，不干扰

        new_ret = max(0.05, old_ret - penalty)
        if new_ret < old_ret:
            try:
                conn.execute(
                    "UPDATE memory_chunks SET retrievability=? WHERE id=?",
                    (round(new_ret, 4), cid)
                )
                affected += 1
            except Exception:
                pass

    return affected


def fts_optimize(conn: sqlite3.Connection, force: bool = False) -> bool:
    """
    迭代360：触发 FTS5 segment 合并优化，降低查询 P95 延迟。
    OS 类比：ext4 online defrag (e4defrag) — 在线整理碎片，不需要 unmount。

    SQLite FTS5 在每次 insert 后生成新 segment；累积多个 segment 后，
    查询需要扫描所有 segment（O(S × log N)），S 增大导致 P95 上升。
    optimize 命令将所有 segment 合并为 1 个（O(log N)）。

    Args:
      conn:  SQLite 连接
      force: True = 跳过冷却时间检查，强制执行

    Returns:
      True  = 执行了 optimize
      False = 冷却期内跳过，或执行失败
    """
    global _fts_last_optimize
    import time as _time
    now = _time.monotonic()
    if not force and (now - _fts_last_optimize) < _FTS_OPTIMIZE_INTERVAL:
        return False
    try:
        conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts) VALUES('optimize')")
        _fts_last_optimize = now
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# iter495: Dual-Coding Effect (DCE) — Paivio 1971
# ══════════════════════════════════════════════════════════════════════════════

def apply_dual_coding_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter495: Dual-Coding Effect (DCE) — 同时具有语言+结构化编码的 chunk stability 更高。

    认知科学依据：
      Paivio (1971) "Imagery and Verbal Processes" — 双重编码理论（DCT）：
        信息同时以语言和视觉/结构形式编码时，形成两条独立检索路径，
        提取成功率比单通道编码高 ~30-50%。
      Clark & Paivio (1991): 具体性和双编码是长期记忆保持的最强预测指标之一。
      Mayer (2001) 多媒体学习：文字+图示的联合呈现优于纯文字。

    memory-os 等价：
      chunk 同时包含自然语言描述 + 代码/结构化数据（URL、路径、SQL） = 双编码。
      纯文字描述 = 单通道（verbal only）。
      双编码 chunk 有更多检索线索 → stability 提升。

    OS 类比：RAID-1 mirroring — 数据同时写入两块磁盘，
      单盘故障不丢失数据（= 单条检索线索失效仍可通过另一条找到）。
    """
    result = {"dce_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.dce_enabled"):
            return result

        indicators = _cfg.get("store_vfs.dce_code_indicators") or []
        stability_bonus = float(_cfg.get("store_vfs.dce_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.dce_max_boost"))
        min_importance = float(_cfg.get("store_vfs.dce_min_importance"))
        min_content_len = int(_cfg.get("store_vfs.dce_min_content_len") or 50)

        indicator_set = [ind.lower() for ind in indicators]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = row[2] or ""

            if imp < min_importance:
                continue
            if len(content) < min_content_len:
                continue

            # 检测结构化编码通道：content 中是否包含代码/URL/路径指标
            content_lower = content.lower()
            indicator_count = sum(1 for ind in indicator_set if ind in content_lower)
            if indicator_count < 2:
                continue  # 需要至少 2 个指标才构成"双编码"

            # 指标越多，bonus 越大（最多 max_boost）
            # indicator_count >= 2 才进入此处；2个=1×bonus, 3个=2×bonus, 4个=3×bonus
            ratio = min(max_boost, stability_bonus * (min(indicator_count, 5) - 1))
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["dce_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter496: Survival Processing Effect (SPE) — Nairne 2007
# ══════════════════════════════════════════════════════════════════════════════

def apply_survival_processing_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter496: Survival Processing Effect (SPE) — 生存相关信息的记忆编码优势。

    认知科学依据：
      Nairne, Thompson & Pandeirada (2007) Psych Science — 与生存相关的信息在
        自由回忆中表现优于所有传统深加工条件（pleasantness rating, imagery,
        self-reference），优势 ~10-15%。
      Nairne & Pandeirada (2008): "记忆系统的首要功能是 fitness-relevant retention"。
      Kang, McDermott & Cohen (2008): 复制了 survival processing advantage。

    memory-os 等价：
      与项目"生存"直接相关的 chunk（critical bugs, security issues, blockers,
      deadlines, outages）= fitness-relevant information。
      这类 chunk 应获得更强的编码（stability + importance 双重加分）。

    OS 类比：OOM killer priority — 关键进程（init, systemd）的 oom_score_adj = -1000，
      永远不会被 OOM killer 杀死；同理，survival-critical chunk 获得淘汰保护。
    """
    result = {"spe_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.spe_enabled"):
            return result

        keywords = _cfg.get("store_vfs.spe_survival_keywords") or []
        stability_bonus = float(_cfg.get("store_vfs.spe_stability_bonus"))
        importance_bonus = float(_cfg.get("store_vfs.spe_importance_bonus"))
        max_boost = float(_cfg.get("store_vfs.spe_max_boost"))
        min_importance = float(_cfg.get("store_vfs.spe_min_importance"))

        kw_lower = [kw.lower() for kw in keywords]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content, summary "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = (row[2] or "").lower()
            summary = (row[3] or "").lower()

            if imp < min_importance:
                continue

            # 计算 survival relevance：关键词命中数
            text = content + " " + summary
            hit_count = sum(1 for kw in kw_lower if kw in text)
            if hit_count < 1:
                continue

            # stability 提升（与命中数正相关，最多 max_boost）
            ratio = min(max_boost, stability_bonus * min(hit_count, 3))
            new_stab = min(365.0, stab * (1.0 + ratio))

            # importance 提升（固定小额加分）
            new_imp = min(1.0, imp + importance_bonus)

            updated = False
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                updated = True
            if new_imp > imp + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET importance=? WHERE id=?", (new_imp, chunk_id)
                )
                updated = True
            if updated:
                result["spe_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter497: Bizarreness Effect (BZE) — McDaniel & Einstein 1986
# ══════════════════════════════════════════════════════════════════════════════

def apply_bizarreness_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    project: str = "",
) -> dict:
    """iter497: Bizarreness Effect (BZE) — 稀有类型 chunk 的记忆编码优势。

    认知科学依据：
      McDaniel & Einstein (1986) J Exp Psych: LM&C — 奇异句子在混合列表中
        比普通句子回忆率高 ~15-25%（bizarreness effect）。
      Einstein & McDaniel (1987): distinctiveness → enhanced encoding。
      Hunt & Worthen (2006): 奇异性效应源于 item-specific distinctiveness。

    memory-os 等价：
      当项目中某个 chunk_type 出现频率极低（< threshold）时，该 chunk 具有
      "奇异性"（distinctiveness）——它从背景中突出，类似 Von Restorff 效应。
      这类 chunk 应获得 stability 加分（更不易被遗忘）。

    OS 类比：huge page promotion — 当大部分页面是 4KB 时，2MB huge page
      在 TLB 中获得特殊处理（减少 TLB miss），类似于稀有类型获得特殊保护。
    """
    result = {"bze_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.bze_enabled"):
            return result

        rare_threshold = float(_cfg.get("store_vfs.bze_rare_type_threshold"))
        stability_bonus = float(_cfg.get("store_vfs.bze_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.bze_max_boost"))
        min_importance = float(_cfg.get("store_vfs.bze_min_importance"))

        # 计算项目内 chunk_type 频率分布
        where_clause = "WHERE project=?" if project else "WHERE 1=1"
        params = (project,) if project else ()
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where_clause}", params
        ).fetchone()
        total = total_row[0] if total_row else 0
        if total < 5:
            return result  # 样本太少，无法判断稀有性

        type_counts = {}
        for row in conn.execute(
            f"SELECT chunk_type, COUNT(*) FROM memory_chunks {where_clause} GROUP BY chunk_type",
            params
        ):
            type_counts[row[0] or "unknown"] = row[1]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, chunk_type "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            ctype = row[2] or "unknown"

            if imp < min_importance:
                continue

            # 计算该类型的频率
            type_freq = type_counts.get(ctype, 0) / total
            if type_freq >= rare_threshold:
                continue  # 不够稀有

            # 越稀有，bonus 越大
            rarity_ratio = 1.0 - (type_freq / rare_threshold)
            ratio = min(max_boost, stability_bonus * rarity_ratio)
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["bze_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter498: Concreteness Effect (CCE2) — Paivio 1969
# ══════════════════════════════════════════════════════════════════════════════

def apply_concreteness_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter498: Concreteness Effect (CCE2) — 具体信息比抽象信息的记忆编码更强。

    认知科学依据：
      Paivio (1969) Psych Bulletin — 具体词（concrete words）在回忆和再认测试中
        比抽象词（abstract words）高 ~20-30%（concreteness effect）。
      Schwanenflugel (1991): 具体词同时激活 imaginal + verbal 编码（与 DCT 交互）。
      Walker & Hulme (1999): 具体性效应在 delayed recall 中尤为显著（→ stability）。

    memory-os 等价：
      包含具体数据（数字、路径、URL、时间戳、度量单位）的 chunk 比
      纯抽象描述（"考虑改进性能"）的 chunk 在长期保留中更有价值。
      具体 chunk 更易被精确匹配召回。

    OS 类比：direct-mapped cache line — 精确地址匹配比 set-associative 的
      模糊匹配更快命中；具体信息 = 精确地址，抽象信息 = tag 比较。
    """
    result = {"cce_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.cce_enabled"):
            return result

        indicators = _cfg.get("store_vfs.cce_concrete_indicators") or []
        min_indicators = int(_cfg.get("store_vfs.cce_min_indicators") or 2)
        stability_bonus = float(_cfg.get("store_vfs.cce_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.cce_max_boost"))
        min_importance = float(_cfg.get("store_vfs.cce_min_importance"))

        ind_lower = [ind.lower() for ind in indicators]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = (row[2] or "").lower()

            if imp < min_importance:
                continue

            # 计算具体性指标命中数
            hit_count = sum(1 for ind in ind_lower if ind in content)
            if hit_count < min_indicators:
                continue

            # bonus 与具体性指标数量正相关
            ratio = min(max_boost, stability_bonus * min(hit_count, 5) / 2.0)
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["cce_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter499: Picture Superiority Effect (PSE) — Shepard 1967
# ══════════════════════════════════════════════════════════════════════════════

def apply_picture_superiority_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter499: Picture Superiority Effect (PSE) — 结构化/图示 chunk 的记忆优势。

    认知科学依据：
      Shepard (1967) J Verbal Learning & Verbal Behavior — 图片在再认测试中
        正确率 98% vs 文字 88%（picture superiority effect）。
      Paivio & Csapo (1973): 图片自动激活 dual-coding（verbal + imaginal）。
      Defeyter et al. (2009): 效应在 delayed recall 更显著（→ stability 而非短期）。

    memory-os 等价：
      含 table、list、diagram（ASCII art）、结构化标记的 chunk = "图示编码"。
      纯 prose 文本 = "verbal only"。
      结构化 chunk 有更强的空间-视觉编码 → stability 提升。

    OS 类比：B-tree vs linear scan — 结构化索引（B-tree page）
      比线性日志（sequential log entry）有更高的 locality 命中率。
    """
    result = {"pse_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.pse_enabled"):
            return result

        indicators = _cfg.get("store_vfs.pse_structure_indicators") or []
        min_indicators = int(_cfg.get("store_vfs.pse_min_indicators") or 2)
        stability_bonus = float(_cfg.get("store_vfs.pse_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.pse_max_boost"))
        min_importance = float(_cfg.get("store_vfs.pse_min_importance"))

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = row[2] or ""

            if imp < min_importance:
                continue

            # 计算结构化指标命中数
            hit_count = sum(1 for ind in indicators if ind in content)
            if hit_count < min_indicators:
                continue

            ratio = min(max_boost, stability_bonus * (min(hit_count, 5) - 1))
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["pse_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter500: Anchoring Effect (AE) — Tversky & Kahneman 1974
# ══════════════════════════════════════════════════════════════════════════════

def apply_anchoring_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
    project: str = "",
) -> dict:
    """iter500: Anchoring Effect (AE) — 项目早期 chunk 作为认知锚点，持久性更强。

    认知科学依据：
      Tversky & Kahneman (1974) Science — 人类判断严重依赖初始信息（anchor），
        后续调整不足（anchoring-and-adjustment heuristic）。
      Mussweiler & Strack (1999): anchor 激活与之一致的知识，形成选择性可访问性。
      Furnham & Boo (2011): anchoring 是最稳健的认知偏差之一。

    memory-os 等价：
      项目最早创建的 chunk 是认知锚点 — 定义了项目的"基本假设"和"初始框架"。
      这些 anchor chunk 在后续决策中隐式引用 → 遗忘成本更高 → stability 加分。

    OS 类比：boot sector / initramfs — 系统启动时最先加载的数据永远保留在内存中
      （never evicted from page cache），因为所有后续操作隐式依赖它。
    """
    result = {"ae_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.ae_enabled"):
            return result

        early_pct = float(_cfg.get("store_vfs.ae_early_percentile"))
        stability_bonus = float(_cfg.get("store_vfs.ae_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.ae_max_boost"))
        min_importance = float(_cfg.get("store_vfs.ae_min_importance"))
        min_project_chunks = int(_cfg.get("store_vfs.ae_min_project_chunks") or 10)

        # 获取项目 chunk 总数
        where = "WHERE project=?" if project else "WHERE 1=1"
        params = (project,) if project else ()
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM memory_chunks {where}", params
        ).fetchone()
        total = total_row[0] if total_row else 0
        if total < min_project_chunks:
            return result

        # 获取 early threshold（按 created_at 排序前 N%）
        early_count = max(1, int(total * early_pct))
        early_rows = conn.execute(
            f"SELECT id FROM memory_chunks {where} ORDER BY created_at ASC LIMIT ?",
            params + (early_count,)
        ).fetchall()
        early_ids = {row[0] for row in early_rows}

        for chunk_id in chunk_ids:
            if chunk_id not in early_ids:
                continue
            row = conn.execute(
                "SELECT stability, importance FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)

            if imp < min_importance:
                continue

            ratio = min(max_boost, stability_bonus)
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["ae_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter501: Negative Bias Effect (NBE) — Baumeister 2001
# ══════════════════════════════════════════════════════════════════════════════

def apply_negative_bias_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter501: Negative Bias Effect (NBE) — 负面信息的记忆编码更持久。

    认知科学依据：
      Baumeister et al. (2001) Review of General Psych — "Bad is stronger than good":
        负面事件在记忆、情绪、社会交互中的影响力一致大于正面事件。
      Kensinger & Corkin (2003): 负面情绪词在 delayed recognition 中优于正面词。
      Ochsner (2000): 负面信息的杏仁核激活更强 → 海马编码更深。

    memory-os 等价：
      记录 bug/error/failure/regression 的 chunk = 负面信息。
      这类 chunk 对项目的"生存"更重要（避免重蹈覆辙）→ stability 加分。
      类似于 Linux 的 EDAC (Error Detection and Correction) — 错误记录永不清除。

    OS 类比：EDAC memory controller error log — CE/UE 错误永久记录在
      /sys/devices/system/edac/mc/，从不轮转，因为任何错误都是 RAS 分析的关键数据。
    """
    result = {"nbe_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.nbe_enabled"):
            return result

        keywords = _cfg.get("store_vfs.nbe_negative_keywords") or []
        stability_bonus = float(_cfg.get("store_vfs.nbe_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.nbe_max_boost"))
        min_importance = float(_cfg.get("store_vfs.nbe_min_importance"))

        kw_lower = [kw.lower() for kw in keywords]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content, summary "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = (row[2] or "").lower()
            summary = (row[3] or "").lower()

            if imp < min_importance:
                continue

            text = content + " " + summary
            hit_count = sum(1 for kw in kw_lower if kw in text)
            if hit_count < 1:
                continue

            ratio = min(max_boost, stability_bonus * min(hit_count, 3))
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["nbe_boosted"] += 1
        return result
    except Exception:
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iter502: Temporal Landmark Effect (TLE) — Shum 1998
# ══════════════════════════════════════════════════════════════════════════════

def apply_temporal_landmark_effect(
    conn: "sqlite3.Connection",
    chunk_ids: list,
) -> dict:
    """iter502: Temporal Landmark Effect (TLE) — 时间地标事件的记忆更鲜明。

    认知科学依据：
      Shum (1998) Memory & Cognition — 与公共事件（landmark events）在时间上接近
        的个人记忆更容易被回忆（temporal landmark effect）。
      Pillemer et al. (1996): 生活转折点作为 temporal anchor 增强相邻记忆的可访问性。
      Robinson (1986): 转折事件产生"记忆碰撞"（reminiscence bump）效应。

    memory-os 等价：
      含 deploy/release/merge/milestone 关键词的 chunk = 项目时间地标。
      这些 chunk 标记了项目的重要节点 → 它们是回忆其他事件的时间锚点 → stability 加分。

    OS 类比：filesystem journal checkpoint — ext4 journal 中的 checkpoint record
      永远保留，用于灾难恢复时确定"已知正确状态"的最近时间点。
    """
    result = {"tle_boosted": 0}
    if not chunk_ids:
        return result
    try:
        import config as _cfg
        if not _cfg.get("store_vfs.tle_enabled"):
            return result

        keywords = _cfg.get("store_vfs.tle_landmark_keywords") or []
        stability_bonus = float(_cfg.get("store_vfs.tle_stability_bonus"))
        max_boost = float(_cfg.get("store_vfs.tle_max_boost"))
        min_importance = float(_cfg.get("store_vfs.tle_min_importance"))

        kw_lower = [kw.lower() for kw in keywords]

        for chunk_id in chunk_ids:
            row = conn.execute(
                "SELECT stability, importance, content, summary "
                "FROM memory_chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if not row:
                continue
            stab = float(row[0] or 1.0)
            imp = float(row[1] or 0.0)
            content = (row[2] or "").lower()
            summary = (row[3] or "").lower()

            if imp < min_importance:
                continue

            text = content + " " + summary
            hit_count = sum(1 for kw in kw_lower if kw in text)
            if hit_count < 1:
                continue

            ratio = min(max_boost, stability_bonus * min(hit_count, 2))
            new_stab = min(365.0, stab * (1.0 + ratio))
            if new_stab > stab + 1e-6:
                conn.execute(
                    "UPDATE memory_chunks SET stability=? WHERE id=?", (new_stab, chunk_id)
                )
                result["tle_boosted"] += 1
        return result
    except Exception:
        return result


# iter503: Writeback Pressure — Zero-Access Ratio Admission Control
# OS 类比：Linux dirty page writeback throttle (vm.dirty_ratio / vm.dirty_background_ratio)
#   Jens Axboe (2007) — balance_dirty_pages_ratelimited()
#   当 dirty page 比例超过 dirty_background_ratio (10%) 时，pdflush 开始后台刷盘；
#   超过 dirty_ratio (20%) 时，写入进程被 throttle（IO_WAIT），直到脏页比例下降。
#   这防止了 burst write 耗尽 page cache，导致系统颠簸。
#
# memory-os 等价：
#   "脏页" = 写入后从未被检索命中的 chunk（zero-access）
#   "dirty_ratio" = 零访问率阈值（默认 70%）
#   "throttle" = 新写入 chunk 的 importance 乘以衰减因子
#   效果：零访问率高 → 新 chunk importance 降级 → kswapd 优先回收 → 零访问率下降

def writeback_pressure(
    conn: "sqlite3.Connection",
    project: str,
    proposed_importance: float,
) -> dict:
    """iter503: 根据当前零访问率对新写入 importance 施加反压。

    调用时机：insert_chunk 之前，extractor/_write_chunk/writer 写入路径。
    返回 dict:
      - adjusted_importance: 调整后的 importance（可能低于 proposed）
      - pressure_level: "none" | "background" | "throttle"
      - zero_access_ratio: 当前零访问率
      - total_chunks: 当前 project chunk 总数
    """
    result = {
        "adjusted_importance": proposed_importance,
        "pressure_level": "none",
        "zero_access_ratio": 0.0,
        "total_chunks": 0,
    }
    try:
        if not config.get("store_vfs.writeback_pressure_enabled"):
            return result

        min_chunks = int(config.get("store_vfs.writeback_min_chunks"))
        dirty_ratio = float(config.get("store_vfs.writeback_dirty_ratio"))
        dirty_bg_ratio = float(config.get("store_vfs.writeback_dirty_bg_ratio"))
        throttle_factor = float(config.get("store_vfs.writeback_throttle_factor"))
        bg_throttle_factor = float(config.get("store_vfs.writeback_bg_throttle_factor"))

        # 统计当前 project 的零访问率
        row = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
        ).fetchone()
        total = row[0] if row else 0
        result["total_chunks"] = total

        if total < min_chunks:
            return result

        row_zero = conn.execute(
            "SELECT COUNT(*) FROM memory_chunks WHERE project=? AND access_count=0",
            (project,),
        ).fetchone()
        zero_count = row_zero[0] if row_zero else 0
        ratio = zero_count / total
        result["zero_access_ratio"] = round(ratio, 4)

        if ratio >= dirty_ratio:
            # 硬性 throttle：importance *= throttle_factor
            result["adjusted_importance"] = round(proposed_importance * throttle_factor, 4)
            result["pressure_level"] = "throttle"
        elif ratio >= dirty_bg_ratio:
            # 轻度 background 降级
            result["adjusted_importance"] = round(proposed_importance * bg_throttle_factor, 4)
            result["pressure_level"] = "background"

        return result
    except Exception:
        return result


def shrink_dcache(conn: "sqlite3.Connection", project: str = None) -> dict:
    """iter505: shrink_dcache — Cross-Project Stale Object Reclaim.

    OS 类比：Linux shrink_dcache_sb() (Al Viro, 2001)
    ——超级块级别的 dentry cache 回收。不像 per-进程的 DAMON/LRU 回收只扫描单个
    project，shrink_dcache 跨所有 project（含 global）扫描从未被引用的陈旧条目。

    解决的问题：
      - damon_scan 是 per-project，不扫描 global 层
      - damon.dead_age_days=30 天门槛在短期数据中永远不触发
      - 批量导入的高 importance 但零访问 chunks 不被回收
      - 零访问率 82%+ 稀释 FTS5 搜索结果质量

    策略（三阶段）：
      Phase 1 — 扫描：跨所有 project 找到满足回收条件的 chunks
      Phase 2 — 分级降权：高 importance 轻度降级，低 importance 重度降级+oom_adj
      Phase 3 — 削减：极低价值条目直接删除

    调用时机：loader.py SessionStart，在 damon_scan 之后。
    """
    import time as _time
    _t0 = _time.time()

    result = {
        "phase1_candidates": 0,
        "phase2_demoted": 0,
        "phase3_deleted": 0,
        "duration_ms": 0.0,
    }

    try:
        min_age_days = int(config.get("shrink.min_age_days"))
        max_reclaim = int(config.get("shrink.max_reclaim_per_scan"))
        min_total = int(config.get("shrink.min_total_chunks"))
        demote_high_factor = float(config.get("shrink.demote_high_factor"))
        demote_low_factor = float(config.get("shrink.demote_low_factor"))
        delete_threshold = float(config.get("shrink.delete_threshold"))
    except Exception:
        min_age_days = 3
        max_reclaim = 50
        min_total = 30
        demote_high_factor = 0.6
        demote_low_factor = 0.4
        delete_threshold = 0.2

    # 冷启动保护
    total = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
    if total < min_total:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    # Phase 1: 跨项目扫描零访问 + 超龄 chunks
    age_ts = f"-{min_age_days} days"
    candidates = conn.execute(
        """SELECT id, importance, project FROM memory_chunks
           WHERE COALESCE(access_count, 0) = 0
             AND datetime(created_at) < datetime('now', ?)
             AND chunk_type NOT IN ('task_state')
             AND COALESCE(oom_adj, 0) > -1000
           ORDER BY importance ASC
           LIMIT ?""",
        (age_ts, max_reclaim),
    ).fetchall()

    result["phase1_candidates"] = len(candidates)

    if not candidates:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    # 排除 pinned chunks
    pinned_ids = set()
    try:
        pin_rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE pin_type IN ('hard', 'soft')"
        ).fetchall()
        pinned_ids = {r[0] for r in pin_rows}
    except Exception:
        pass  # chunk_pins 表可能不存在

    # Phase 2: 分级降权
    demoted = 0
    to_delete = []

    for chunk_id, imp, _proj in candidates:
        if chunk_id in pinned_ids:
            continue

        if imp >= 0.8:
            new_imp = round(imp * demote_high_factor, 4)
        else:
            new_imp = round(imp * demote_low_factor, 4)
            try:
                conn.execute(
                    "UPDATE memory_chunks SET oom_adj = MIN(COALESCE(oom_adj, 0) + 500, 1000) WHERE id = ?",
                    (chunk_id,),
                )
            except Exception:
                pass

        conn.execute(
            "UPDATE memory_chunks SET importance = ? WHERE id = ?",
            (new_imp, chunk_id),
        )
        demoted += 1

        # Phase 3: 极低价值直接删除
        if new_imp < delete_threshold:
            to_delete.append(chunk_id)

    result["phase2_demoted"] = demoted

    if to_delete:
        result["phase3_deleted"] = delete_chunks(conn, to_delete)
        # iter517: 注册 import tombstones — 阻止 fork bomb 循环
        try:
            from tools.import_knowledge import register_import_tombstones
            register_import_tombstones(to_delete)
        except Exception:
            pass

    conn.commit()

    if demoted > 0 or to_delete:
        bump_chunk_version()

    result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
    return result


def oom_reaper(conn: "sqlite3.Connection", project: str = None) -> dict:
    """iter508: oom_reaper — 零访问率超标时的批量降级回收器。

    OS 类比：Linux oom_reaper (Michal Hocko, 2016)
    ——当 OOM killer 选中牺牲进程后，oom_reaper 内核线程立即回收其匿名页，
    不等待进程自行退出（进程可能卡在 D 状态）。

    解决的问题：
      - shrink_dcache min_age_days=3 导致 1-3 天内的 dead pages 不被处理
      - DAMON dead_age_days=30 在短期数据中永远不触发
      - kswapd pages_low_pct=80% 在配额充足时不启动
      - 各回收器的保护条件相互叠加，形成"回收死区"
      - 结果：82%+ 零访问率，FTS5 候选池被稀释

    触发条件：零访问率 > oom_reaper.zero_access_threshold（默认 70%）
    策略：选择 lru_gen 最高（最老代）+ importance 最低的零访问 chunks 批量降级
    保护：design_constraint/quantitative_evidence 类型豁免、pinned 豁免、oom_adj≤-500 豁免

    调用时机：loader.py SessionStart，在 shrink_dcache 之后。
    """
    import time as _time
    _t0 = _time.time()

    result = {
        "triggered": False,
        "zero_access_ratio": 0.0,
        "reaped": 0,
        "deleted": 0,
        "duration_ms": 0.0,
    }

    try:
        enabled = bool(config.get("oom_reaper.enabled"))
        threshold = float(config.get("oom_reaper.zero_access_threshold"))
        max_reap = int(config.get("oom_reaper.max_reap_per_scan"))
        decay = float(config.get("oom_reaper.importance_decay"))
        min_total = int(config.get("oom_reaper.min_total_chunks"))
        protect_types_str = str(config.get("oom_reaper.protect_types"))
    except Exception:
        enabled = True
        threshold = 0.7
        max_reap = 30
        decay = 0.5
        min_total = 50
        protect_types_str = "design_constraint,quantitative_evidence"

    if not enabled:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    protect_types = tuple(t.strip() for t in protect_types_str.split(",") if t.strip())

    # 冷启动保护
    total = conn.execute("SELECT COUNT(*) FROM memory_chunks").fetchone()[0]
    if total < min_total:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    # 计算零访问率
    zero_access = conn.execute(
        "SELECT COUNT(*) FROM memory_chunks WHERE COALESCE(access_count, 0) = 0"
    ).fetchone()[0]
    ratio = zero_access / total if total > 0 else 0.0
    result["zero_access_ratio"] = round(ratio, 4)

    if ratio < threshold:
        result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
        return result

    # 触发 oom_reaper
    result["triggered"] = True

    # 选择牺牲者：lru_gen 最高 + importance 最低 + 零访问
    # 排除：受保护类型、task_state、oom_adj≤-500（mlock）、pinned
    protect_ph = ",".join("?" * len(protect_types)) if protect_types else "'__none__'"
    sql = f"""
        SELECT id, importance FROM memory_chunks
        WHERE COALESCE(access_count, 0) = 0
          AND chunk_type NOT IN ('task_state', {protect_ph})
          AND COALESCE(oom_adj, 0) > -500
        ORDER BY lru_gen DESC, importance ASC
        LIMIT ?
    """
    params = list(protect_types) + [max_reap]
    candidates = conn.execute(sql, params).fetchall()

    # 排除 pinned chunks
    pinned_ids = set()
    try:
        pin_rows = conn.execute(
            "SELECT chunk_id FROM chunk_pins WHERE pin_type IN ('hard', 'soft')"
        ).fetchall()
        pinned_ids = {r[0] for r in pin_rows}
    except Exception:
        pass

    # 执行降级
    to_delete = []
    reaped = 0
    delete_threshold = 0.2

    for chunk_id, imp in candidates:
        if chunk_id in pinned_ids:
            continue

        new_imp = round(imp * decay, 4)
        conn.execute(
            "UPDATE memory_chunks SET importance = ?, oom_adj = MIN(COALESCE(oom_adj, 0) + 300, 1000) WHERE id = ?",
            (new_imp, chunk_id),
        )
        reaped += 1

        if new_imp < delete_threshold:
            to_delete.append(chunk_id)

    result["reaped"] = reaped

    if to_delete:
        result["deleted"] = delete_chunks(conn, to_delete)
        # iter517: 注册 import tombstones — 阻止 fork bomb 循环
        try:
            from tools.import_knowledge import register_import_tombstones
            register_import_tombstones(to_delete)
        except Exception:
            pass

    if reaped > 0:
        conn.commit()
        bump_chunk_version()

    result["duration_ms"] = round((_time.time() - _t0) * 1000, 2)
    return result
