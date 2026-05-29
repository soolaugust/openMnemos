"""
memory-os Config — sysctl Runtime Tunables Registry

迭代 27：OS 类比 — Linux sysctl (1993)
迭代 37：OS 类比 — Linux Namespaces (2002-2013)

sysctl 背景（迭代27）：
  早期 Linux 内核参数用 #define 分散在各子系统源码中，
  修改需要重编译内核。sysctl (1993) 引入 /proc/sys/ 虚拟文件系统，
  将内核参数统一注册为可读写的虚拟文件，管理员运行时即可调参：
    sysctl vm.swappiness=60
    sysctl net.core.somaxconn=1024

Namespaces 背景（迭代37）：
  Linux Namespaces (2002 mount ns → 2013 user ns) 让每个容器看到
  独立的资源视图（PID/NET/MNT/UTS/IPC/USER），同一物理主机上的
  不同容器可以有不同的进程号空间、网络栈、文件系统挂载等。
  Docker/K8s 的核心隔离机制就是 namespace。

  memory-os 当前问题：
    sysctl 是全局的——所有项目共享同一套 tunable 值。
    但不同项目特征差异大：
      - 大项目（1000+ chunk）需要 quota=500、激进 kswapd
      - 小项目（<50 chunk）默认 quota=200 足够
      - 某些项目需要更宽松的 scheduler（不 SKIP 短查询）
    全局配置无法满足多租户差异化需求。

  解决：
    per-project namespace 覆盖层——sysctl.json 支持 namespaces 字段：
      {"namespaces": {"git:abc123": {"extractor.chunk_quota": 500}}}
    get(key, project=None) 新增 project 参数：
      优先级：环境变量 > namespace(project) > global sysctl.json > 默认值
    sysctl_set(key, value, project=None)：无 project 时写全局，有则写 namespace。
    ns_list(project) / ns_clear(project)：管理 namespace。

解决（迭代27）：
  1. _REGISTRY: dict — 所有 tunable 的单点注册表（名称/默认值/类型/范围/描述）
  2. get(key) — 优先级：环境变量 > sysctl.json 配置文件 > 默认值
  3. sysctl_list() — 返回所有当前值（≈ sysctl -a）
  4. sysctl_set(key, value) — 运行时修改 + 持久化到 sysctl.json
"""
# ── 迭代157：__future__ annotations — 消除 typing 模块 import 开销 ────────────
# OS 类比：Linux lazy symbol resolution (ELF RTLD_LAZY) — 符号引用推迟到首次调用时解析，
#   而非 dlopen 时立即解析所有符号（RTLD_NOW）。
#   Python __future__ annotations (PEP 563, 3.7+) 让所有注解变为字符串（惰性求值），
#   不需要在模块加载时实际执行 Any/Optional 的名称查找。
#   config 是 retriever.py 在 heavy import 之前就加载的轻量级模块，
#   每次 hook 调用都付一次 typing import 成本（~3.9ms）。
#   __future__ annotations 完全消除这个成本：注解变字符串，typing 名称无需在运行时存在。
from __future__ import annotations
import json
import os
from datetime import datetime, timezone

# ── 迭代158：Replace pathlib.Path with os.path — 消除 pathlib import 开销 (~7ms) ──
# OS 类比：Linux kernel 的 vfs_stat() 直接调用 sys_stat() syscall，不经 glibc 路径抽象层，
#   消除中间层开销。pathlib.Path 是 os.path 的面向对象封装层，
#   而 os 模块在 Python 启动时已预加载（在 sys.modules 中），import os.path 近乎零成本。
#   pathlib 需要额外 ~6.88ms 加载。config.py 是 retriever.py 在 vDSO Stage 0+1 快速路径
#   之前就加载的轻量模块，每次 hook 调用都付这个成本。
#   替换策略：MEMORY_OS_DIR/SYSCTL_FILE 改为 str，所有文件操作改用 os.path/open()。

# 迭代90：Check os.environ first (set by conftest or tmpfs), fallback to default
_mem_dir_env = os.environ.get("MEMORY_OS_DIR")
MEMORY_OS_DIR: str = _mem_dir_env if _mem_dir_env else os.path.join(os.path.expanduser("~"), ".claude", "memory-os")
SYSCTL_FILE: str = os.path.join(MEMORY_OS_DIR, "sysctl.json")

# ── Tunable Registry ─────────────────────────────────────────────
# 每项：(default, type, min, max, env_key, description)
# env_key: 对应的环境变量名（向后兼容已有的 env 覆盖）
# min/max: None 表示不限

_REGISTRY: dict = {
    # ── retriever ──
    "retriever.adaptive_k_enabled": (True, bool, None, None, None,
        "是否启用 Citation Rate 反馈驱动的 Adaptive K（低命中率→缩小top_k，高命中率→扩大）"),
    "retriever.second_chance_enabled": (True, bool, None, None, None,
        "是否启用 Second-Chance 多样性采样（以10%概率随机注入高stability低importance的chunk，防止死锁衰减）"),
    "retriever.inject_sort_enabled": (True, bool, None, None, None,
        "是否启用 inject_score 加权排序（trigram_score × sqrt(importance)），高importance chunk优先注入，提升SNR"),
    "retriever.inject_score_min_ratio": (0.10, float, 0.0, 1.0, None,
        "inject_score 相对门槛比例：inject_score < max_score × ratio 的 chunk 被过滤（默认10%，0禁用过滤）"),
    "retriever.top_k": (5, int, 1, 20, None,
        "默认召回 Top-K 条数（迭代72：3→5 提升知识覆盖率）"),
    "retriever.top_k_fault": (7, int, 1, 30, None,
        "有缺页信号时的扩大召回 Top-K（迭代72：5→7）"),
    "retriever.max_context_chars": (800, int, 100, 5000, None,
        "召回注入的最大字符数（迭代72：600→800 支撑 Top-5）"),
    "retriever.max_context_chars_fault": (1000, int, 100, 5000, None,
        "缺页场景的最大注入字符数（迭代72：800→1000 支撑 Top-7）"),
    "retriever.oversample_factor": (3, int, 2, 4, None,
        "FTS5 超采样倍数（候选池 = top_k × factor），延迟压力下 governor 可降为 2"),
    "retriever.min_score_threshold": (0.30, float, 0.0, 1.0, None,
        "最低注入分数阈值（迭代86→87：0.15→0.30，A/B评测T4残留干扰BM25 0.29仍通过旧阈值）"),
    "retriever.generic_query_min_threshold": (0.85, float, 0.0, 1.0, None,
        "通用知识 query 的注入阈值（迭代90：0.70→0.85，GIL题评分0.79仍通过0.70）"),
    "retriever.adaptive_floor_enabled": (True, bool, None, None, None,
        "启用自适应分数地板（iter578: mremap）"),
    "retriever.adaptive_floor_ratio": (0.25, float, 0.05, 0.8, None,
        "自适应地板 = top1_score × ratio（iter578: 当 top1=0.99 时地板=0.25）"),
    "retriever.adaptive_floor_min_top1": (0.30, float, 0.1, 1.0, None,
        "Top-1 score 低于此值时不启用自适应地板（iter822: 0.5→0.30，64% 检索 top1<0.5 导致 floor 不生效）"),
    "retriever.gap_bridge_enabled": (True, bool, None, None, None,
        "启用 score gap bridging（iter579: copy_page_range）"),
    "retriever.gap_bridge_min_ratio": (3.0, float, 1.5, 20.0, None,
        "top1/top2 比值超过此值视为 score gap（触发 bridging）"),
    "retriever.gap_bridge_cluster_ratio": (0.4, float, 0.1, 0.9, None,
        "cluster 内 score 相对 cluster_top 的最低比率（>= ratio 视为同一 cluster）"),
    "retriever.gap_bridge_min_cluster": (2, int, 1, 10, None,
        "cluster 最小成员数才启用 bridging（防止单个噪音穿透）"),

    # ── writer ──
    "writer.debounce_secs": (300, int, 0, 3600, None,
        "写入防抖窗口（秒）"),

    # ── extractor ──
    "extractor.chunk_quota": (200, int, 10, 10000, "MEMORY_OS_CHUNK_QUOTA",
        "每项目 chunk 配额上限"),
    "extractor.min_length": (10, int, 3, 50, None,
        "提取 chunk 的最小字符长度"),
    "extractor.max_summary": (120, int, 50, 500, None,
        "提取 chunk 摘要的最大字符长度"),
    "extractor.max_input_chars": (12000, int, 1000, 50000, None,
        "extractor 处理的最大输入字符数"),

    # ── loader ──
    "loader.max_age_secs": (86400, int, 3600, 604800, None,
        "latest.json 有效期（秒），超过则不注入"),
    "loader.max_context_chars": (800, int, 200, 5000, None,
        "SessionStart 注入的最大字符数"),
    "loader.working_set_top_k": (5, int, 1, 20, None,
        "工作集恢复的 Top-K 条数"),
    "loader.restore_working_set": (True, bool, None, None, None,
        "iter378: 是否在 SessionStart 时恢复持久化工作集（.ws_{project}.json）"),
    "loader.ws_max_restore": (20, int, 5, 100, None,
        "iter378: 从 .ws_{project}.json 最多恢复多少个 chunk（按 access_count 排序）"),
    "loader.rt_bandwidth_pct": (0.40, float, 0.1, 1.0, None,
        "iter529: RT 带宽上限 — chunk 在 recall_traces 中出现频率超过此比例时从 working_set 排除"),
    "loader.rt_bandwidth_window": (30, int, 10, 200, None,
        "iter529: 带宽计算窗口大小 — 回溯最近 N 条 injected traces"),
    "loader.defer_max_chunks": (150, int, 20, 1000, None,
        "iter535: deferred_initcall — 总 chunks 超过此值时不跳过 reclaim 子系统"),
    "loader.defer_zero_pct": (0.30, float, 0.05, 0.80, None,
        "iter535: deferred_initcall — 零访问率超过此值时不跳过 reclaim 子系统"),
    "loader.defer_cooldown_hours": (2.0, float, 0.5, 24.0, None,
        "iter535: deferred_initcall — 上次 reclaim 距今超过此小时数时不跳过"),

    # ── knowledge_router ──
    "router.top_k_per_source": (3, int, 1, 20, None,
        "每个知识源的 Top-K 条数"),
    "router.min_score": (0.01, float, 0.0, 1.0, None,
        "最低 BM25 分数阈值"),
    "router.cache_ttl_secs": (300, int, 0, 3600, None,
        "进程内缓存 TTL（秒）"),
    "router.scatter_shortcircuit_score": (0.75, float, 0.0, 1.0, None,
        "Scatter-Gather 短路触发分数阈值（高质量结果 score >= 此值时短路）"),
    "router.scatter_shortcircuit_count": (3, int, 1, 10, None,
        "Scatter-Gather 短路触发最少结果数（>= N 条高质量结果时短路）"),
    "working_set.max_chunks": (200, int, 50, 2000, None,
        "Per-Agent Working Set 最大 chunk 数（超出时 LRU 驱逐）"),
    "working_set.flush_dirty_on_exit": (True, bool, None, None, None,
        "Session 结束时是否 flush dirty chunks 回 store.db"),
    "prefetch.enabled": (True, bool, None, None, None,
        "是否启用 PreTool 预取引擎"),
    "prefetch.max_chunks": (10, int, 1, 50, None,
        "每次 PreTool 预取的最大 chunk 数"),
    "prefetch.timeout_ms": (80, int, 10, 500, None,
        "预取操作超时毫秒数（不阻塞主路径）"),

    # ── scheduler（迭代28）──
    "scheduler.skip_max_chars": (8, int, 3, 30, None,
        "query 短于此长度且无技术信号时 SKIP（nice 19）"),
    "scheduler.lite_max_chars": (200, int, 50, 1000, None,
        "query 短于此长度且无缺页信号时 LITE（nice 0，跳过 router）"),
    "scheduler.min_entity_count_for_full": (2, int, 1, 10, None,
        "query 含 >= N 个技术实体时强制 FULL（nice -20）"),

    # ── Query Truncation（迭代62）──
    "retriever.max_query_chars": (300, int, 50, 2000, None,
        "检索 query 最大字符数。超长 prompt 截断以防 FTS5 性能退化（1600字→300ms+）"),

    # ── scorer ──
    "scorer.importance_decay_rate": (0.95, float, 0.5, 1.0, None,
        "importance 遗忘曲线衰减率（每7天，全局默认）"),
    "scorer.importance_floor": (0.3, float, 0.0, 0.9, None,
        "importance 衰减下限"),
    # ── iter375: Type-Differential Decay Rates ──
    # 人类记忆情节/语义双系统（Tulving 1972）:情节记忆衰减快，语义记忆衰减慢
    # OS 类比：Linux MGLRU — younger generation pages age faster
    # decay_rate 越大 = 衰减越慢（0.99 ≈ 很慢，0.85 ≈ 较快）
    "scorer.decay_rate_task_state":           (0.88, float, 0.5, 1.0, None,
        "task_state 专属衰减率（情节记忆，衰减快）"),
    "scorer.decay_rate_conversation_summary": (0.90, float, 0.5, 1.0, None,
        "conversation_summary 专属衰减率（情节记忆）"),
    "scorer.decay_rate_decision":             (0.97, float, 0.5, 1.0, None,
        "decision 专属衰减率（语义记忆，衰减慢）"),
    "scorer.decay_rate_design_constraint":    (0.99, float, 0.5, 1.0, None,
        "design_constraint 专属衰减率（几乎不衰减）"),
    "scorer.decay_rate_reasoning_chain":      (0.95, float, 0.5, 1.0, None,
        "reasoning_chain 专属衰减率（语义记忆）"),
    "scorer.decay_rate_quantitative_evidence":(0.96, float, 0.5, 1.0, None,
        "quantitative_evidence 专属衰减率"),
    "scorer.decay_rate_causal_chain":         (0.95, float, 0.5, 1.0, None,
        "causal_chain 专属衰减率"),
    "scorer.decay_rate_excluded_path":        (0.93, float, 0.5, 1.0, None,
        "excluded_path 专属衰减率（中速衰减）"),
    "scorer.decay_rate_procedure":            (0.96, float, 0.5, 1.0, None,
        "procedure 专属衰减率（程序记忆，慢速衰减）"),
    "scorer.access_bonus_cap": (0.2, float, 0.0, 1.0, None,
        "access_bonus 上限"),
    "scorer.freshness_bonus_max": (0.15, float, 0.0, 0.5, None,
        "新 chunk 的初始曝光加分上限（Second Chance）"),
    "scorer.freshness_grace_days": (7, int, 1, 30, None,
        "freshness_bonus 的 grace period 天数，超过后 bonus=0"),

    # ── iter433: Reminiscence Bump Effect — 项目形成期记忆强化（Conway & Howe 1990）──────────────
    # 认知科学依据：Conway & Howe (1990); Rubin et al. (1998) "A model of the autobiographical memory" —
    #   人类自传体记忆中，15-25 岁（"形成期"）的事件比其他阶段记忆得更清晰（+50%~+100% recall rate），
    #   即使间隔 60 年也保持优势（不受普通遗忘曲线约束）。
    #   机制：形成期事件被编码进"核心自我叙事"（core self-narrative），
    #     与身份认同绑定，获得额外的记忆巩固路径（hippocampal + cortical dual encoding）。
    # 应用：chunk 在项目生命周期中的相对创建位置 position_pct <= bump_pct（默认 15%）
    #   且 importance >= bump_min_importance → initial_stability × bump_factor（+30%）。
    #   与 Primacy Effect（iter410）的区别：
    #     Primacy：编码顺序的绝对位置效应（最早的 N 条）
    #     Reminiscence Bump：项目生命周期的相对时间窗口效应（前 bump_pct% 的时间段内写入的 chunk）
    # OS 类比：Linux early_boot firmware parameters / BIOS/UEFI cmdline —
    #   早期引导阶段设置的核心参数（kernel cmdline、ACPI 表）在整个运行期保持不变，
    #   比运行时 sysctl 更稳定（boot-immutable vs runtime-mutable）。
    #   memory-os 中：项目创生期写入的 chunk = 启动参数，形成项目的"认知框架"。
    "store_vfs.bump_enabled": (True, bool, None, None, None,
        "iter433: 是否启用 Reminiscence Bump Effect：项目形成期 chunk 获得 stability 加成"),
    "store_vfs.bump_pct": (0.15, float, 0.02, 0.50, None,
        "iter433: 项目形成期时间窗口（占项目总年龄的比例，默认前 15%）"),
    "store_vfs.bump_min_importance": (0.55, float, 0.0, 1.0, None,
        "iter433: 应用 Reminiscence Bump 的最低 importance 阈值（低重要性早期 chunk 不受保护）"),
    "store_vfs.bump_factor": (1.30, float, 1.0, 2.0, None,
        "iter433: 形成期 chunk stability 加成系数（initial_stability × factor，默认 1.30）"),
    "store_vfs.bump_min_project_age_days": (7.0, float, 1.0, 90.0, None,
        "iter433: 应用 Reminiscence Bump 的最短项目年龄（天），项目太新时禁用（避免误判）"),

    # ── iter435: Recency-Induced Decay Resistance — 近期访问记忆的衰减保护窗口（McGaugh 2000）──
    # 认知科学依据：McGaugh (2000) "Memory — a century of consolidation" (Science 287) —
    #   记忆巩固需要时间：学习后数分钟到数小时内，海马体持续重放，将工作记忆转移到新皮层。
    #   在巩固窗口内（post-learning consolidation window），记忆对干扰的抵抗力更强。
    #   Müller & Pilzecker (1900) — perseveration 理论：记忆痕迹形成后有一段"硬化"期，
    #   该期内的干扰（如 electroconvulsive shock）可打断巩固；但正常干扰无法破坏已过窗口的记忆。
    #   Baddeley & Hitch (1974) Working Memory Model — 工作记忆的 phonological loop 和
    #   visuospatial sketchpad 维持近期信息的活跃表示，防止短期遗忘。
    #
    # memory-os 等价：
    #   decay_stability_by_type 运行时，last_accessed 在近期窗口内的 chunk 正处于海马巩固阶段，
    #   应跳过本次衰减（或应用更弱的衰减），等待巩固完成后再参与正常遗忘曲线。
    #   窗口期结束后恢复正常衰减率。
    #
    # OS 类比：Linux MGLRU young generation minimum age (min_lru_age) —
    #   刚被访问/提升到 young generation 的页面有一个最短存活期（grace period），
    #   在此期间 kswapd 不会 age 该页面（避免频繁 access 导致 LRU 抖动）。
    #   memory-os: recently-accessed chunks get a decay grace period —
    #   在 min_lru_age（recency_window_hours）内不参与 stability 衰减。
    "store_vfs.rdr_enabled": (True, bool, None, None, None,
        "iter435: 是否启用 Recency-Induced Decay Resistance — 近期访问的 chunk 在巩固窗口内跳过衰减"),
    "store_vfs.rdr_window_hours": (6.0, float, 0.5, 48.0, None,
        "iter435: 巩固保护窗口时长（小时）：last_accessed 在此窗口内的 chunk 跳过 decay_stability_by_type"),
    "store_vfs.rdr_min_importance": (0.5, float, 0.0, 1.0, None,
        "iter435: 触发 RDR 保护的最低 importance 阈值（低重要性 chunk 不受保护，避免噪音积累）"),

    # ── iter436: Output Interference — 同轮注入竞争性遗忘（Roediger 1978）──────────────────────────
    # 认知科学依据：Roediger (1978) "Recall as a self-limiting process" —
    #   在同一回忆测试中，回忆早期项目（output）干扰后续项目的工作记忆占用，
    #   导致越靠后的序列位置的项目巩固效果越差（output interference 累积）。
    #   Roediger & Schmidt (1980): 同次测试中序列位置 × 遗忘量呈线性关系。
    #   与 RIF（iter434）区别：RIF=检索事件干扰竞争者（编码竞争）；OI=同次输出中的工作记忆干扰。
    # OS 类比：Linux BFQ (Budget Fair Queue) dispatch batch budget 消耗 —
    #   同一 dispatch batch 中，第一个 I/O 请求消耗大部分 budget，后续请求完成的 I/O 减少；
    #   类比：同轮注入的第一个 chunk 占用工作记忆，后续 chunk 得到更少巩固 budget。
    "store_vfs.oi_enabled": (True, bool, None, None, None,
        "iter436: 是否启用 Output Interference — 同轮注入的后序 chunk 受早期 chunk 的工作记忆干扰"),
    "store_vfs.oi_decay_factor": (0.99, float, 0.90, 1.00, None,
        "iter436: Output Interference 基础衰减因子（position k 的 chunk: stability × factor^k，默认 0.99）"),
    "store_vfs.oi_protect_importance": (0.85, float, 0.0, 1.0, None,
        "iter436: importance >= 此值的 chunk 豁免 Output Interference（核心知识不受输出位置干扰）"),
    "store_vfs.oi_max_coinjected": (5, int, 2, 20, None,
        "iter436: 每条 trace 最多处理的同轮注入 chunk 数（超出部分不施加额外 OI 惩罚）"),

    # ── iter437: Hypermnesia — 多次分布式检索后记忆净增强（Erdelyi & Becker 1974）──────────────
    # 认知科学依据：Erdelyi & Becker (1974) "1974 hypermnesia for pictures" (Cognitive Psychology) —
    #   在多轮自由回忆测试中，随测试轮次增加，总召回量呈净增长（不仅是遗忘补偿）：
    #   一些在第1轮被遗忘的项目，在第2/3轮被成功回忆（"reminiscence"），且总量超过第1轮。
    #   机制：每次回忆尝试激活不同检索路径，集体覆盖更多记忆痕迹（retrieval route diversity）。
    #   Payne (1987) Meta-analysis: hypermnesia effect ≈ +15-25% across 3-5 test sessions。
    #   Roediger & Challis (1989): hypermnesia 最强出现在 imagery-rich、情节性内容（而非语义列表）。
    # memory-os 等价：
    #   spaced_access_count（iter420）= 跨 24h 间隔的检索次数，代表不同 session 的独立检索。
    #   spaced_access_count >= hypermnesia_threshold → 证明 chunk 经历了多次成功的分布式检索路径，
    #   已达到"超记忆强化"水平；sleep_consolidate 时给予额外 stability boost（hypermnesia_boost）。
    #   与 Spacing Effect（iter420）区别：SE 是 per-access 机制（每次间隔检索小幅加成）；
    #   Hypermnesia 是 threshold-triggered 宏观机制（跨越阈值后一次性较大加成，模拟 net improvement）。
    # OS 类比：Linux khugepaged (Transparent HugePage) 多 epoch 晋升 —
    #   页面在多个内存分配 epoch 内持续热访问（access_count 跨越 epoch 阈值）→
    #   khugepaged 将多个 4KB pages 合并为 2MB hugepage，大幅降低 TLB miss rate；
    #   类比：多次跨 session 检索成功 → 记忆表示从分散的情节痕迹"合并"为稳定的长期表示。
    "store_vfs.hypermnesia_enabled": (True, bool, None, None, None,
        "iter437: 是否启用 Hypermnesia — spaced_access_count 超过阈值后触发一次性 stability 净增强"),
    "store_vfs.hypermnesia_threshold": (4, int, 2, 20, None,
        "iter437: 触发 Hypermnesia boost 的 spaced_access_count 阈值（默认 4 次跨会话检索）"),
    "store_vfs.hypermnesia_boost": (1.10, float, 1.0, 1.50, None,
        "iter437: Hypermnesia stability 加成系数（stability × boost，默认 1.10 ≈ 10% 净增强）"),
    "store_vfs.hypermnesia_min_importance": (0.55, float, 0.0, 1.0, None,
        "iter437: 触发 Hypermnesia 的最低 importance 阈值（低重要性 chunk 不触发，避免噪音固化）"),
    "store_vfs.hypermnesia_cooldown_days": (7.0, float, 1.0, 90.0, None,
        "iter437: Hypermnesia boost 冷却期（天）：两次 boost 之间的最小间隔，防止反复触发"),

    # ── iter438: Jost's Law — 等强度记忆中较老者衰减更慢（Jost 1897）──────────────────────────────
    # 认知科学依据：Jost (1897) "Die Assoziationsfestigkeit in ihrer Abhängigkeit von der Verteilung
    #   der Wiederholungen" — Jost's Law of Memory（1897）：
    #   若两个记忆在某一时刻强度相等，则较老的记忆在未来遗忘得更慢。
    #   机制：老记忆已经历多次巩固周期（海马重放、间隔强化），
    #   其突触权重矩阵（synaptic weight matrix）更稳固，
    #   单次干扰难以使之退化（neurological consolidation gradient）。
    #   Baddeley (1997) "Human Memory: Theory and Practice" — Jost's Law 是 Ebbinghaus 遗忘曲线
    #   的重要补充：相同 retrievability（可提取性）时，age 越大的记忆实际衰减越慢。
    #   等价表达：若 memory_A(age=30d) = memory_B(age=10d) = strength_X，
    #     则 memory_A 在下次测试中会比 memory_B 更容易回忆。
    #
    # memory-os 等价：
    #   decay_stability_by_type 执行时，age_days 越大的 chunk 应接受更弱的 stability 衰减。
    #   effective_decay = base_decay + (1 - base_decay) × jost_bonus(age_days)
    #   jost_bonus = min(jost_max_bonus, log(1+age_days)/log(365) × jost_scale)
    #   age=14d→bonus≈0.04，age=30d→bonus≈0.06，age=365d→bonus=jost_max_bonus(0.20)
    #
    # 与 Ribot's Law（iter431）的区别：
    #   Ribot = stability_floor 提高（下限保护，防止降到太低）
    #   Jost  = effective_decay 减慢（每次衰减步长缩小，而非设置下限）
    #   两者可以叠加：老 chunk 既有更高 floor，也有更慢的 per-step 衰减
    #
    # 与 iter433 Reminiscence Bump 的区别：
    #   Bump = 项目形成期 chunk 在写入时一次性 initial_stability 加成
    #   Jost  = 每次 sleep_consolidate 时对所有高龄 chunk 的持续性衰减减速
    #
    # OS 类比：Linux MGLRU old generation promotion resistance —
    #   在 old generation 长期存在的 page 已"证明"了跨多个 aging interval 的热度，
    #   kswapd 对其施加更弱的 reclaim pressure（MGLRU aging_interval × old_gen_protection_factor）；
    #   类比：age 越大的 chunk → effective_decay 越接近 1.0 → per-step 衰减越小。
    "store_vfs.jost_enabled": (True, bool, None, None, None,
        "iter438: 是否启用 Jost's Law — 较老的 chunk 在等强度下衰减更慢（effective_decay 提升）"),
    "store_vfs.jost_min_importance": (0.50, float, 0.0, 1.0, None,
        "iter438: 触发 Jost's Law 保护的最低 importance 阈值（低重要性 chunk 不受保护）"),
    "store_vfs.jost_scale": (0.10, float, 0.0, 0.50, None,
        "iter438: Jost's Law 年龄-衰减减速系数：bonus=log(1+age_days)/log(365)×scale，"
        "age=365d 时 bonus=jost_scale（默认 0.10）"),
    "store_vfs.jost_max_bonus": (0.20, float, 0.0, 0.50, None,
        "iter438: Jost bonus 上限：effective_decay += min(max_bonus, bonus)×(1-decay)，"
        "最多让衰减步长缩小 max_bonus×(1-decay) 比例（默认 0.20）"),
    "store_vfs.jost_min_age_days": (14, int, 3, 365, None,
        "iter438: 应用 Jost's Law 的最小 chunk 年龄（天），默认 14 天"),

    # ── iter439: Encoding Depth Decay Resistance — 深度编码减慢衰减（Craik & Tulving 1975）──────────────
    # 认知科学依据：Craik & Tulving (1975) "Depth of processing and the retention of words in
    #   episodic memory" (JEPG) — 深度加工（语义联想、自我参照、问题解答）比浅层加工（形状、语音）
    #   产生更强的记忆痕迹，且深度编码记忆对时间性遗忘更有抵抗力（retention advantage）。
    #   Craik & Lockhart (1972) Levels of Processing framework：编码深度 = 语义分析深度，
    #   深度越深 → 记忆痕迹越强 → 保持时间越长。
    #   实验数据：深度编码条件下 24h 后保留率比浅层编码高 50-80%（Craik & Tulving 1975, Exp. 2）。
    #
    # memory-os 等价：
    #   encode_context 中的 entity 数量代理编码深度（iter411 LOP）：
    #   entity_count >= eddr_deep_threshold（5）→ 深度编码，decay 减速（stability × 小幅提振）。
    #   entity_count <= eddr_shallow_threshold（1）→ 浅层编码，decay 轻微加速（stability × 轻微惩罚）。
    #   与 iter411（LOP 写入时加成）区别：iter411 = 写入时一次性 stability 加成；
    #   iter439 = 运行时每次 sleep_consolidate 持续减速/加速（类比慢波睡眠记忆巩固的深浅差异）。
    #
    # OS 类比：Linux ext4 extent tree depth —
    #   extent tree depth = 1（单层 extent）的文件，随机 I/O 需要 1次 block 读取；
    #   depth = 3（三层 htree）的大文件需要 3次 block 读取（更深 = 更贵 = 更不愿意驱逐）。
    #   深度编码 chunk（多 entity）= 深 extent tree = kswapd 驱逐代价高 = 更慢衰减。
    "store_vfs.eddr_enabled": (True, bool, None, None, None,
        "iter439: 是否启用 Encoding Depth Decay Resistance — 深度编码 chunk 衰减更慢，浅层编码加速"),
    "store_vfs.eddr_deep_threshold": (5, int, 2, 20, None,
        "iter439: 触发深度编码保护的最低 entity 数量（encode_context 中的 token 数，默认 5）"),
    "store_vfs.eddr_shallow_threshold": (1, int, 0, 5, None,
        "iter439: 浅层编码的最高 entity 数量（entity_count <= 此值触发轻微加速衰减，默认 1）"),
    "store_vfs.eddr_max_depth_bonus": (0.15, float, 0.0, 0.50, None,
        "iter439: 深度编码 stability 最大修复系数（deep_bonus = min(max_depth_bonus, entity_count/10 × scale)）"),
    "store_vfs.eddr_shallow_penalty": (0.05, float, 0.0, 0.20, None,
        "iter439: 浅层编码 stability 轻微衰减系数（shallow chunk stability × (1 - penalty)，默认 0.05）"),

    # ── iter440: Proactive Facilitation — 强邻居锚定保护新知识衰减（Ausubel 1963）────────────────────
    # 认知科学依据：Ausubel (1963) "The psychology of meaningful verbal learning" —
    #   正向迁移（positive transfer）/先行组织者（advance organizer）效应：
    #   新知识与已有强记忆语义高度相关时，新知识的长期记忆保留显著改善。
    #   机制：已有稳固 schema 为新知识提供"认知锚点"（assimilative anchoring），
    #   降低新知识的遗忘速率（schema-assimilation strengthens encoding）。
    #   Ausubel & Fitzgerald (1962)：存在强先行知识 → 新知识 24h 保留率提升 30-40%。
    #   与 Proactive Interference（iter408）区别：
    #     PI（iter408）= 旧知识干扰新知识编码（负迁移，降低 initial_stability）
    #     PF（iter440）= 旧强记忆锚定新知识（正迁移，减慢后续衰减）
    #     条件：PI 触发在 importance 低的旧记忆；PF 触发在 importance 高的强邻居
    #
    # memory-os 等价：
    #   sleep_consolidate 时，若 chunk_A 的 encode_context 与高 importance(≥0.75) 强邻居 chunk_B
    #   有足够 entity 重叠（≥ pf_min_overlap），则 chunk_A 被"锚定"：
    #   new_stab = current_stab × (1 + pf_bonus × 0.04)（轻微修复，减慢净衰减）。
    #
    # OS 类比：Linux page cache 引用计数（refcount）—
    #   被多个 inode 共享引用（shared pages）的 page 有高 refcount，
    #   kswapd 优先保留（因驱逐代价 = 通知所有引用方 → 代价过高）；
    #   类比：被强邻居 chunk "引用"（共享 entity）的 chunk → refcount 提升 → 衰减更慢。
    "store_vfs.pf_enabled": (True, bool, None, None, None,
        "iter440: 是否启用 Proactive Facilitation — 与高 importance 强邻居共享 entity 的 chunk 衰减更慢"),
    "store_vfs.pf_anchor_min_importance": (0.75, float, 0.3, 1.0, None,
        "iter440: 触发 PF 锚定的强邻居最低 importance 阈值（默认 0.75）"),
    "store_vfs.pf_anchor_min_access": (2, int, 1, 50, None,
        "iter440: 强邻居最低 access_count（≥ 此值才视为'已稳固'的锚点记忆，默认 2）"),
    "store_vfs.pf_min_overlap": (3, int, 1, 10, None,
        "iter440: 触发 PF 保护所需的最小 encode_context entity 重叠数（默认 3）"),
    "store_vfs.pf_max_bonus": (0.10, float, 0.0, 0.30, None,
        "iter440: PF stability 最大修复系数（new_stab = current_stab × (1 + pf_max_bonus × 0.04)，默认 0.10）"),

    # ── iter441: Emotional Consolidation — 情绪显著性记忆睡眠优先巩固（McGaugh 2000）────────────────
    # 认知科学依据：McGaugh (2000) "Memory — a century of consolidation" Science 287 —
    #   情绪事件（高唤醒）通过杏仁核（amygdala）-海马（hippocampus）交互在睡眠期间
    #   获得优先记忆巩固：norepinephrine 在 NREM SWS 期间增强 hippocampal replay 频率，
    #   情绪显著性记忆的 synaptic weight 更新量更大。
    #   Cahill et al. (1994) "Beta-adrenergic activation and memory" (Nature) —
    #     情绪显著性内容（β-肾上腺素激活条件）的 2-week 长期保留比中性内容高 30-50%。
    #   La Bar & Cabeza (2006) Meta-analysis: emotional memories show a "consolidation
    #     advantage" — 情绪唤醒 → 长时记忆保留率更高（效应量 d≈0.5-0.8）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，emotional_weight >= ec_min_weight 的 chunk 获得额外
    #   stability 加成（优先巩固）：new_stab = current_stab × (1 + bonus)
    #   bonus 与 emotional_weight 线性正比：bonus = emotional_weight × ec_scale
    #   这与 iter409（Flashbulb Memory 写入时一次性加成）形成互补：
    #     Flashbulb(409) = 写入时 initial_stability 加成（encoding 阶段）
    #     Emotional Consolidation(441) = 每次 sleep_consolidate 持续加成（consolidation 阶段）
    #     两者叠加 = 情绪显著性记忆全生命周期的双重保护
    #
    # OS 类比：Linux writeback dirty page priority —
    #   high-priority dirty pages（PG_writeback + high importance）被 pdflush 优先刷写；
    #   类比：情绪显著性 chunk（emotional_weight 高）在 sleep consolidation 中被优先处理，
    #   获得更大的 stability 更新量（优先 writeback = 优先巩固）。
    "store_vfs.ec_enabled": (True, bool, None, None, None,
        "iter441: 是否启用 Emotional Consolidation — 情绪显著性 chunk 在 sleep 时获得额外 stability 加成"),
    "store_vfs.ec_min_weight": (0.40, float, 0.0, 1.0, None,
        "iter441: 触发 Emotional Consolidation 的最低 emotional_weight 阈值（默认 0.40）"),
    "store_vfs.ec_scale": (0.08, float, 0.0, 0.30, None,
        "iter441: 情绪巩固加成系数：bonus = emotional_weight × scale，new_stab = current_stab × (1 + bonus)，"
        "emotional_weight=1.0 时最大 bonus=ec_scale（默认 0.08 ≈ 8%）"),
    "store_vfs.ec_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter441: 触发 Emotional Consolidation 的最低 importance 阈值（低重要性情绪 chunk 不受保护）"),

    # ── iter442: Schema-Consistent Consolidation — 图式一致性记忆的额外巩固（Bartlett 1932 / Tse 2007）──
    # 认知科学依据：
    #   Bartlett (1932) "Remembering: A Study in Experimental and Social Psychology" —
    #     记忆不是精确录像，而是根据已有"图式"（schema）重构的。与已有图式高度一致的新信息
    #     被更快、更完整地整合（assimilation），在睡眠巩固期能"嵌入"已有图式结构而获得额外强化。
    #   Tse et al. (2007) Science "Schemas and memory consolidation" —
    #     已有丰富图式（schema）后，新的关联记忆可以在 1 天内（而非 3 天）完成系统巩固（rapid schema assimilation）。
    #     实验：大鼠在已有丰富 flavor-place 图式后，新 pair 1天即完成海马→新皮层转移（而非 3天）。
    #     意义：图式的存在大幅缩短了系统巩固时间，类似于预置的"知识框架"加速新信息整合。
    #   McClelland et al. (1995) Complementary Learning Systems —
    #     海马快速编码（episodic）+ 新皮层慢速图式整合（semantic）；图式越强，新皮层整合越快。
    #     图式一致性 → 跳过海马中间步骤 → 直接写入新皮层（快速系统巩固）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，若 chunk 的 encode_context 与项目的"图式核"
    #   （schema_cores：access_count >= scc_schema_min_access + importance >= scc_schema_min_importance）
    #   有足够 entity 重叠（>= scc_min_overlap），说明该 chunk 已嵌入项目核心知识图式，
    #   给予额外 stability 加成：new_stab = stab × (1 + scc_bonus × 0.04)
    #   适用于近期写入的 chunk（created_at >= now - scc_window_days，代表"新信息"），
    #   而非 stale chunk（PF 已覆盖老 chunk 的锚定）。
    #
    # 与 iter440（PF）的区别：
    #   PF：stale 候选被强邻居（access_count>=2，importance>=0.75）锚定 → 减慢衰减
    #   SCC：近期新 chunk 嵌入核心图式（access_count>=5，importance>=0.80）→ 加速系统巩固
    #   触发条件不同：PF=旧知识保护；SCC=新知识快速整合（Tse 2007 的快速图式同化）
    #
    # OS 类比：Linux page cache readahead pattern — sequential prefetch window 扩展
    #   顺序访问模式（与已有 I/O 模式 = 图式 一致）的 page，内核 readahead 算法将预取窗口扩大
    #   （ra->size 增加），因为"符合模式"降低了预取代价（等价于快速系统巩固降低了整合代价）。
    #   SCC：encode_context 与 schema core 高度重叠 = 符合访问模式 = readahead 窗口扩大 = 更快巩固。
    "store_vfs.scc_enabled": (True, bool, None, None, None,
        "iter442: 是否启用 Schema-Consistent Consolidation — 与图式核高度重叠的近期 chunk 获得额外巩固加成"),
    "store_vfs.scc_schema_min_access": (5, int, 2, 50, None,
        "iter442: 图式核的最低 access_count（>= 此值才视为'已稳固'的核心图式，默认 5）"),
    "store_vfs.scc_schema_min_importance": (0.80, float, 0.5, 1.0, None,
        "iter442: 图式核的最低 importance 阈值（默认 0.80，比 PF 锚点 0.75 更严格）"),
    "store_vfs.scc_min_overlap": (3, int, 1, 10, None,
        "iter442: 触发 SCC 保护所需的最小 encode_context entity 重叠数（默认 3）"),
    "store_vfs.scc_window_days": (7.0, float, 1.0, 30.0, None,
        "iter442: 近期 chunk 时间窗口（天）：只对 created_at >= now - window_days 的 chunk 应用 SCC，"
        "代表'刚写入的新知识'（默认 7 天）"),
    "store_vfs.scc_bonus": (0.15, float, 0.0, 0.50, None,
        "iter442: SCC stability 加成系数（new_stab = stab × (1 + scc_bonus × 0.04)，默认 0.15 → 0.6% 加成）"),

    # ── iter443: Sleep-Targeted Memory Reactivation — 睡眠期主动抢救衰退的重要记忆（Stickgold 2005）──
    # 认知科学依据：
    #   Stickgold (2005) "Sleep-dependent memory consolidation" (Nature) —
    #     睡眠期间，海马对"正在衰退"的重要记忆进行主动重放（targeted memory reactivation, TMR）：
    #     N2/SWS 期间的 sleep spindles + sharp-wave ripples 优先重放高价值但 retrievability 下降的记忆。
    #     "记忆抢救"（memory rescue）现象：睡眠后测试的记忆保留率 显著高于 清醒后，
    #     尤其对 consolidation 临界期内（学习后 12-24h 首次睡眠）的记忆保留贡献最大。
    #   Stickgold & Walker (2013) "Sleep-dependent memory triage: evolving generalization
    #     through selective processing" (Nature Neuroscience) —
    #     睡眠并非随机巩固所有记忆，而是"优先分诊"（triage）：
    #     高重要性（reward-tagged、emotionally-flagged）+ 当前 retrievability 下降的记忆
    #     获得优先的 hippocampal replay，防止进入不可逆遗忘区间。
    #     等价：importance 高 + retrievability 低 = 最需要被"抢救"的记忆。
    #   Walker & Stickgold (2004) "Sleep-dependent learning and motor-skill complexity" —
    #     睡眠巩固的资源分配遵循"价值 × 衰退度"的优先级：
    #     value × (1 - current_retrievability) = rescue_priority
    #
    # memory-os 等价：
    #   sleep_consolidate 时，扫描 importance >= str_min_importance 且
    #   retrievability <= str_max_retrievability 的 chunk（高价值但正在衰退）；
    #   对这些 chunk 施加 stability 修复：
    #     rescue_bonus = (1.0 - retrievability) × str_scale
    #     new_stab = min(365.0, stab × (1 + rescue_bonus))
    #   rescue_bonus 与遗忘程度正比：retrievability 越低 → 离遗忘临界越近 → 修复幅度越大。
    #
    # 与其他机制的区别：
    #   Testing Effect (iter412) = 被用户实际检索时修复（activation-triggered，事后）
    #   EC (iter441) = 情绪显著性 chunk 的持续加成（每次 sleep）
    #   STR (iter443) = 主动扫描正在衰退的高价值 chunk 并修复（proactive triage，事前抢救）
    #   三者互补：EC/STR 是主动保护；Testing Effect 是被动触发保护
    #
    # OS 类比：Linux dirty page writeback priority + data integrity policy —
    #   系统在写回脏页时优先处理"快要超时"的脏页（page age 接近 dirty_expire_centisecs 上限），
    #   防止数据丢失（analogous to: data 正在消退 = dirty page 即将超时 → 优先 writeback 抢救）。
    #   pdflush/flusher 的 "expire" scan：定期扫描即将超时的脏页 → 强制写回（rescue before expiry）。
    "store_vfs.str_enabled": (True, bool, None, None, None,
        "iter443: 是否启用 Sleep-Targeted Reactivation — 睡眠期主动抢救高 importance 但 retrievability 低的 chunk"),
    "store_vfs.str_min_importance": (0.65, float, 0.3, 1.0, None,
        "iter443: 触发 STR 的最低 importance 阈值（默认 0.65，只抢救重要记忆）"),
    "store_vfs.str_max_retrievability": (0.40, float, 0.0, 1.0, None,
        "iter443: 触发 STR 的最高 retrievability 阈值（<= 此值说明正在衰退，默认 0.40）"),
    "store_vfs.str_scale": (0.12, float, 0.0, 0.50, None,
        "iter443: STR 修复系数：rescue_bonus = (1.0 - retrievability) × scale，"
        "retrievability=0.0 时最大 bonus=str_scale（默认 0.12 ≈ 12%），"
        "retrievability=0.40 时 bonus=0.072 ≈ 7.2%"),

    # ── iter444: Contextual Reinstatement Effect — 情境再现期活跃 chunk 的睡眠额外巩固（Smith 1979 / Tulving 1983）──
    # 认知科学依据：
    #   Smith (1979) "Remembering in and out of context" (JEPLMC) —
    #     在原始编码情境中测试的记忆，提取成功率比新情境高 40-50%（环境依赖记忆）。
    #     机制：编码时的情境（背景线索）成为记忆的检索线索组成部分，情境再现 → 线索重激活 → 提取成功率↑。
    #   Godden & Baddeley (1975) "Context-dependent memory in two natural environments" (BJEP) —
    #     水下学习+水下回忆 vs 水上回忆：相同情境提取率比跨情境高约 40%（经典情境依赖记忆实验）。
    #   Tulving (1983) "Elements of Episodic Memory" — 编码特异性原则（Encoding Specificity Principle）：
    #     记忆的检索效率取决于检索时线索与编码时线索的匹配程度（"what is encoded ≈ what is retrieved"）。
    #   Smith & Vela (2001) "Environmental context-dependent memory: A review and meta-analysis" —
    #     情境依赖记忆效应的元分析：d=0.33，跨越多种情境类型（空间/语义/情绪/时间）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，若 chunk 的 encode_context 与本 session 其他被访问 chunk 的
    #   entity 合集（session_active_entities）有足够重叠（>= cre_min_overlap），
    #   说明该 chunk 正处于"情境活跃期"——它的编码情境在本 session 中被反复激活，
    #   给予额外 stability 加成（情境再现增强巩固）：
    #     new_stab = min(365.0, stab × (1 + cre_bonus × cre_scale))
    #   与 iter394 CSB（检索时情境匹配加分）区别：CSB = 检索阶段加分；CRE = sleep 巩固阶段加成。
    #   与 iter440 PF（邻居锚定）区别：PF = 单个强邻居锚定；CRE = session 整体活跃情境的涌现效应。
    #
    # OS 类比：Linux NUMA-aware page consolidation (khugepaged) —
    #   khugepaged 优先合并同一 NUMA node 内相邻的 4KB pages 为 2MB hugepage（情境局部性 = NUMA 局部性）；
    #   本 session 活跃 entity 集合 = 当前 NUMA node，与该集合高度重叠的 chunk = 同 node 热页，
    #   sleep consolidate 时优先合并（加大 stability），减少跨情境检索延迟。
    "store_vfs.cre_enabled": (True, bool, None, None, None,
        "iter444: 是否启用 Contextual Reinstatement Effect — session 活跃情境内的 chunk 在 sleep 时获得额外巩固"),
    "store_vfs.cre_min_overlap": (2, int, 1, 10, None,
        "iter444: 触发 CRE 巩固所需的最小 entity 重叠数（chunk.encode_context 与 session_active_entities 的交集，默认 2）"),
    "store_vfs.cre_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter444: 触发 CRE 的最低 importance 阈值（低重要性 chunk 不受情境增强保护，默认 0.40）"),
    "store_vfs.cre_bonus": (0.10, float, 0.0, 0.50, None,
        "iter444: CRE stability 加成系数：bonus_factor = cre_bonus × overlap_ratio，"
        "new_stab = min(365.0, stab × (1 + bonus_factor))，最大 bonus = cre_bonus（默认 0.10 = 10%）"),
    "store_vfs.cre_max_session_entities": (200, int, 20, 2000, None,
        "iter444: 构建 session_active_entities 时最多采样的 chunk 数量（按 last_accessed 排序，限制计算开销）"),

    # ── iter445: Reward-Tagged Memory Consolidation — 奖励标签记忆的睡眠优先巩固（Murty & Adcock 2014）──
    # 认知科学依据：
    #   Murty & Adcock (2014) "Enriching experiences via prior associative learning facilitates memory" —
    #     多巴胺奖励信号在慢波睡眠期（SWS）激活 VTA-海马投射，选择性强化高奖励预期的记忆痕迹。
    #     高奖励记忆（被频繁强化的记忆）在睡眠巩固期间比低奖励记忆获得更强的海马重放（replay）。
    #   Hennies et al. (2015) "Closed-loop memory reactivation during sleep" (Current Biology) —
    #     高奖励标签 + 睡眠 = 最强记忆保留：reward × sleep 的交互效应显著大于单独效应之和。
    #   Patil et al. (2017) "Imagining the future: the importance of cued memory" —
    #     反复被提取的记忆被视为"高价值"（access_count 代理 dopaminergic reward signal），
    #     睡眠期海马优先回放此类记忆（frequency-weighted replay）。
    #
    # memory-os 等价：
    #   access_count 高（被频繁检索 = 高奖励证明）+ 近期仍有访问（last_accessed 在 window 内）
    #   = 高奖励标签 + 奖励信号新鲜 → sleep 期额外巩固：
    #     reward_signal = min(1.0, log(1 + access_count) / log(1 + rtmc_acc_ref))
    #     recency_factor = max(0.0, 1.0 - hours_since_access / rtmc_recency_hours)
    #     priority = reward_signal × recency_factor
    #     bonus = priority × rtmc_scale
    #     new_stab = min(365.0, stab × (1 + bonus))
    #   与 iter413 Sleep Consolidation 的区别：
    #     SC(413) = importance >= 0.70 的 chunk 一律加成（importance-based gate）
    #     RTMC(445) = access_count × recency 的乘积奖励信号（behavior-based reward）
    #     两者不相互排斥：高重要性高访问的 chunk 会同时受两个机制保护
    #   与 iter437 Hypermnesia 的区别：
    #     Hypermnesia = spaced_access_count 跨阈值触发一次性较大 boost（threshold-triggered）
    #     RTMC = 每次 sleep 基于当前 access_count × recency 的持续性小奖励（continuous）
    #
    # OS 类比：Linux workingset_activation（工作集激活标记）——
    #   kswapd 扫描时，reference bit=1 的页获得 second chance（不立即回收）；
    #   page refcount × recency = 工作集优先级（高频近期访问 page = 最高 protection）；
    #   类比：access_count × recency_factor = 记忆奖励优先级 → sleep 时优先强化。
    "store_vfs.rtmc_enabled": (True, bool, None, None, None,
        "iter445: 是否启用 Reward-Tagged Memory Consolidation — 高访问×近期访问的 chunk 在 sleep 时获得额外巩固"),
    "store_vfs.rtmc_min_access": (3, int, 1, 50, None,
        "iter445: 触发 RTMC 的最低 access_count 阈值（默认 3，至少被检索 3 次才视为高奖励）"),
    "store_vfs.rtmc_acc_ref": (10, int, 3, 100, None,
        "iter445: 奖励信号参考访问次数：reward_signal = log(1+acc)/log(1+rtmc_acc_ref)，"
        "acc=rtmc_acc_ref 时 reward_signal=1.0（默认 10）"),
    "store_vfs.rtmc_recency_hours": (48.0, float, 6.0, 168.0, None,
        "iter445: 奖励信号新鲜度窗口（小时）：last_accessed 在此窗口内才应用 recency_factor，"
        "超过此时间 recency_factor=0.0 → 不触发（默认 48h = 2 天内仍有访问才算'新鲜'）"),
    "store_vfs.rtmc_scale": (0.08, float, 0.0, 0.30, None,
        "iter445: RTMC 奖励加成系数：bonus = priority × scale，new_stab = stab × (1 + bonus)，"
        "priority=1.0（最高奖励 + 最新访问）时 bonus=rtmc_scale（默认 0.08 ≈ 8%）"),
    "store_vfs.rtmc_min_importance": (0.35, float, 0.0, 1.0, None,
        "iter445: 触发 RTMC 的最低 importance 阈值（默认 0.35，低重要性 chunk 不参与奖励巩固）"),

    # ── iter446: Temporal Contiguity Effect — 时间毗邻性的记忆互相强化（Kahana 1996）─────────────────────
    # 认知科学依据：
    #   Kahana (1996) "Associative retrieval processes in free recall" (Journal of Memory and Language) —
    #     自由回忆实验中，时间上相邻编码（proximity in time）的词汇倾向于相互触发回忆（lag-CRP 曲线峰值在 lag=±1）。
    #     时间毗邻性提供了"情节内的时序链接"：你想起 item_N 时，item_{N+1} 和 item_{N-1} 被同时激活。
    #   Howard & Kahana (2002) "A distributed representation of temporal context" (Journal of Math Psychology) —
    #     时间上下文向量（temporal context vector）在相邻学习事件间高度相关，
    #     形成隐式的"时间序列索引"，使相邻编码记忆在检索时相互提示。
    #   Polyn & Kahana (2008) Meta-analysis: lag-CRP effect is robust across free recall tasks —
    #     时间毗邻性效应不依赖语义相似度（即使语义无关的词也会因时间相邻而互相触发）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，对 created_at 时间上相邻的 chunk 对（同一项目内，时间差 <= tce_window_secs）
    #   进行双向 stability 相互加成：
    #     共同属于同一时间窗口 → 时间情节单元 → 双方 stability × (1 + tce_bonus)
    #   tce_window_secs：时间毗邻窗口（秒），默认 1800s = 30分钟（一个典型编码 session 的时间粒度）
    #   只处理 importance >= tce_min_importance 的 chunk（低重要性相邻不值得强化）
    #   最多处理 tce_max_group_size 个相邻 chunk（防止一个长 session 把所有 chunk 都相互加成）
    #
    # OS 类比：Linux MGLRU temporal cohort aging —
    #   同一 aging interval 内被访问的 pages 属于同一 "generation"，
    #   同代 pages 在 kswapd 扫描时被一起保护（temporal cohort effect = 同代互保）；
    #   类比：同一时间窗口写入的 chunk = 同一 generation，sleep 时互相加成 stability
    #   （temporal contiguity → generation membership → mutual protection）。
    "store_vfs.tce_enabled": (True, bool, None, None, None,
        "iter446: 是否启用 Temporal Contiguity Effect — 时间毗邻写入的 chunk 在 sleep 时相互加成 stability"),
    "store_vfs.tce_window_secs": (1800, int, 60, 7200, None,
        "iter446: 时间毗邻窗口（秒）：created_at 差距 <= 此值的 chunk 视为时间毗邻对（默认 30 分钟）"),
    "store_vfs.tce_bonus": (0.05, float, 0.0, 0.30, None,
        "iter446: 时间毗邻加成系数：相邻对中每个 chunk stability × (1 + tce_bonus)（默认 0.05 = 5%）"),
    "store_vfs.tce_min_importance": (0.45, float, 0.0, 1.0, None,
        "iter446: 触发 TCE 的最低 importance 阈值（默认 0.45，低重要性 chunk 的时间毗邻不强化）"),
    "store_vfs.tce_max_group_size": (10, int, 2, 50, None,
        "iter446: 每个时间窗口内最多参与 TCE 的 chunk 数量（按 importance 降序取 top N，避免长 session 失控）"),

    # ── iter447: Von Restorff Sleep Reactivation — 孤立记忆的睡眠期优先回放（Restorff 1933 / McDaniel 1986）────────
    # 认知科学依据：
    #   Von Restorff (1933) "Über die Wirkung von Bereichsbildungen im Spurenfeld" (Isolation Effect) —
    #     在一串相似项目中，孤立/独特的项目（与其他项目不同）被记忆得更好（+40-60% recall advantage）。
    #     机制：孤立项目在编码时占据更多认知资源（selective attention），形成更强记忆痕迹。
    #   McDaniel & Einstein (1986) "Bizarre imagery as an effective memory aid" (JEP) —
    #     孤立效应在延迟测试（1周后）中比即时测试更显著：睡眠巩固对孤立记忆的保护尤为强烈。
    #     机制：孤立记忆在 NREM SWS 期间有更强的 hippocampal sharp-wave ripple 重放频率。
    #   Huang et al. (2004) "The isolation effect in free recall" (Memory) —
    #     孤立效应的睡眠增强：学习后睡眠使孤立项目的 delayed recall 比清醒组高约 25%；
    #     对非孤立项目无此差异（睡眠选择性保护孤立记忆）。
    #   Hunt & Lamb (2001) Meta-analysis: isolation effect ≈ d=0.80（相对普通项目的优势），
    #     在图片/词汇/行为等多个记忆类型均显著。
    #
    # memory-os 等价：
    #   encode_context 在项目内 Jaccard 相似度低（语义孤立）的 chunk = Von Restorff 孤立项。
    #   iter407 写入时已计算孤立度，但仅一次性加成（encoding 阶段）。
    #   iter447 = 睡眠巩固阶段的持续保护：
    #     sleep_consolidate 时，对 encode_context 低 Jaccard 重叠的 chunk 计算孤立度：
    #       isolation_score = 1 - avg(jaccard(chunk, neighbor_i) for neighbor_i in recent_neighbors)
    #       isolation_score >= vrr_min_isolation → sleep bonus = isolation_score × vrr_scale
    #       new_stab = min(365.0, stab × (1 + sleep_bonus))
    #     与 iter407 的区别：iter407 = 写入时一次性；iter447 = 每次 sleep 持续（离线重放）。
    #   最近邻窗口：比较同项目内创建时间相近的 N 个 chunk（vrr_neighbor_window=20）。
    #
    # OS 类比：Linux kernel huge page 特殊标记页（mlock + MADV_HUGEPAGE 双标注）—
    #   被 mlock 锁定（高价值）+ MADV_HUGEPAGE 标注（独特页布局）的页面，
    #   在内存压力下受到双重保护：kswapd 跳过 mlock 页，khugepaged 优先处理 MADV_HUGEPAGE；
    #   类比：孤立 chunk（独特语义布局）在 sleep 时受到额外巩固（双重保护路径）。
    "store_vfs.vrr_enabled": (True, bool, None, None, None,
        "iter447: 是否启用 Von Restorff Sleep Reactivation — 孤立 chunk 在 sleep 时获得额外巩固加成"),
    "store_vfs.vrr_min_isolation": (0.60, float, 0.0, 1.0, None,
        "iter447: 触发 VRR 的最低孤立度阈值（isolation_score >= 此值才获得 sleep bonus，默认 0.60）"),
    "store_vfs.vrr_min_importance": (0.50, float, 0.0, 1.0, None,
        "iter447: 触发 VRR 的最低 importance 阈值（低重要性孤立 chunk 不受特殊保护，默认 0.50）"),
    "store_vfs.vrr_neighbor_window": (20, int, 5, 100, None,
        "iter447: 计算孤立度时使用的相邻 chunk 数量（按 created_at 取最近 N 个邻居，默认 20）"),
    "store_vfs.vrr_scale": (0.10, float, 0.0, 0.30, None,
        "iter447: VRR sleep bonus 系数：bonus = isolation_score × scale，"
        "isolation_score=1.0（完全孤立）时最大 bonus=vrr_scale（默认 0.10 ≈ 10%）"),

    # ── iter448: Retroactive Enhancement — 新知识睡眠后逆行增强先前相关旧知识（Mednick et al. 2011）──
    # 认知科学依据：
    #   Mednick et al. (2011) "REM, not incubation, improves creativity by priming associative networks" (PNAS) —
    #     学习新知识 → 立即睡眠 → 睡眠不仅巩固新知识，还逆行增强与之关联的旧记忆（retroactive enhancement）。
    #     机制：新知识编码激活的 hippocampal-cortical 回路，在 NREM SWS 重放时也重放与之关联的旧记忆痕迹，
    #     使旧记忆的突触权重也得到更新（bidirectional consolidation）。
    #   Walker & Stickgold (2004) "Sleep-dependent learning and motor-skill complexity" —
    #     睡眠巩固新旧知识的"联合整合"：新技能习得后睡眠，与之结构相似的旧技能也有 overnight 提升。
    #   Stickgold & Walker (2007) "Sleep-dependent memory consolidation and reconsolidation" —
    #     系统巩固理论（Squire & Alvarez 1995）的睡眠扩展：新知识与旧知识在 SWS 期间共同重放，
    #     形成整合性表示（integrated representation），旧知识的 stability 同步提升。
    #   Ellenbogen et al. (2007) Science — 睡眠促进新-旧知识的关联发现（transitive inference），
    #     即使学习时未直接配对也能在睡眠后建立间接关联（A>B, C>B → A>C）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，找出"近期写入的新 chunk"（created_at >= now - re_new_window_hours）：
    #     对每个新 chunk，查找项目内 encode_context entity 重叠度高（>= re_min_overlap）的"旧 chunk"
    #     （created_at < now - re_new_window_hours），逆行给旧 chunk 施加 stability 加成：
    #       overlap_score = |new_tokens ∩ old_tokens| / |new_tokens ∪ old_tokens|
    #       re_bonus = overlap_score × re_scale
    #       new_stab = min(365.0, old_stab × (1 + re_bonus))
    #   只处理 importance >= re_min_importance 的新旧 chunk（低重要性不触发）。
    #   每个旧 chunk 最多被加成一次（取所有关联新 chunk 中的最大 bonus）。
    #
    # 与 iter440 PF（Proactive Facilitation）的区别：
    #   PF：旧强邻居锚定新知识（高 access_count 旧 chunk → 减慢新 chunk 衰减）
    #   RE：新知识逆行增强旧知识（新 chunk 写入后睡眠 → 逆行 boost 旧 chunk stability）
    #   PF = 前向传播（旧→新）；RE = 逆向传播（新→旧）。
    #
    # OS 类比：Linux page fault 触发的 backward readahead —
    #   当访问 page_N 时（新知识），内核的向后预取算法同时预取 page_N-4 到 page_N-1（旧页）；
    #   类比：新 chunk 编码激活的记忆回路逆行激活历史相关 chunk（backward cache warmup）。
    "store_vfs.re_enabled": (True, bool, None, None, None,
        "iter448: 是否启用 Retroactive Enhancement — 新 chunk 写入后 sleep 时逆行增强旧相关 chunk"),
    "store_vfs.re_new_window_hours": (24.0, float, 1.0, 168.0, None,
        "iter448: 新 chunk 时间窗口（小时）：created_at >= now - window 的 chunk 视为'新知识'（默认 24h）"),
    "store_vfs.re_min_overlap": (3, int, 1, 10, None,
        "iter448: 触发 RE 的最小 entity 重叠数（新旧 chunk encode_context 交集 >= 此值，默认 3）"),
    "store_vfs.re_min_importance": (0.45, float, 0.0, 1.0, None,
        "iter448: 触发 RE 的最低 importance 阈值（新旧 chunk 均需 >= 此值，默认 0.45）"),
    "store_vfs.re_scale": (0.06, float, 0.0, 0.20, None,
        "iter448: RE 逆行加成系数：re_bonus = overlap_score × scale，"
        "overlap_score=1.0 时最大 bonus=re_scale（默认 0.06 ≈ 6%，保守以防过度干扰 PF 机制）"),
    "store_vfs.re_max_old_per_new": (5, int, 1, 20, None,
        "iter448: 每个新 chunk 最多逆行增强的旧 chunk 数量（按 overlap_score 降序取 top N，默认 5）"),

    # ── iter449: Quiet Wakefulness Reactivation — 清醒安静期自发重放（Karlsson & Frank 2009）────────────
    # 认知科学依据：
    #   Karlsson & Frank (2009) Nature Neuroscience "Awake replay of remote experiences in the hippocampus" —
    #     大鼠在清醒安静期（rest between maze runs），海马体会自发重放先前的空间轨迹（awake sharp-wave ripples）。
    #     这种清醒重放（awake replay）独立于睡眠，有助于"提前巩固"（pre-consolidation）——
    #     为后续睡眠期的深度巩固做准备（类比：incremental commit → final fsync）。
    #   Tambini et al. (2010) Neuron "Enhanced brain correlations during rest are related to memory for recent experiences" —
    #     人类学习后短暂休息期（~10min quiet wakefulness）的海马-新皮层功能连接显著增强，
    #     且这种连接增强的程度预测了后续 24h 记忆保留率（r=0.62, p<0.01）。
    #     关键：只需 10 分钟不受干扰的安静休息，无需睡眠，即可触发记忆重放和早期巩固。
    #   Dewar et al. (2012) Psychological Science "Ferreting out the nature of the rest period" —
    #     任何无干扰的"空闲期"（unfilled rest）都有助于新学习，
    #     主动任务干扰（filled rest）显著削弱记忆保留（interruption effect）。
    #     等价：session 间隙的"安静期"（无新 AI 交互）= unfilled rest = 触发 QWR 的条件。
    #   Stickgold (2005) Nature + Diekelmann & Born (2010) — 系统巩固理论：
    #     海马重放分两阶段：① 清醒/轻睡期小规模重放（pre-consolidation；QWR）
    #                       ② 慢波睡眠期大规模重放（deep consolidation；iter413 SC）。
    #     QWR 处理 session 间 minutes 到 hours 的"浅巩固"，SC 处理 hours 以上的"深巩固"。
    #
    # memory-os 等价：
    #   SessionStart 时检测与上次 session 结束的时间间隔（gap = now - last_session_end）。
    #   gap in [qwr_min_gap_mins/60, qwr_max_gap_hours)：处于"清醒休息期"→ 触发 QWR。
    #   gap >= sleep_threshold_hours（8h）：由 iter413 SC 处理（深度睡眠巩固），QWR 跳过。
    #   QWR 只对近期编码（created_at 或 last_accessed >= now - qwr_recent_hours）的
    #   高 importance chunk 给予轻微 stability 加成（比 SC 保守：+3%，SC 默认 +6%）。
    #   机制：Tambini 2010 的功能连接增强 = memory-os 中近期 chunk 被"预巩固"加成，
    #   使其在下次 SC（深度睡眠）前不会过快衰减到遗忘临界。
    #
    # 与 iter413 Sleep Consolidation（SC）的区别：
    #   SC：gap >= 8h（overnight sleep），全量巩固，boost_factor=1.06（+6%），扫描 24h 内活跃 chunk
    #   QWR：gap in [10min, 8h)（short rest），轻度预巩固，boost_factor=1.03（+3%），扫描 4h 内活跃 chunk
    #   两者互补：同一 session lifecycle 的 chunk 可能先被 QWR 保护，再被 SC 深度巩固
    #   不重叠：SC 触发时 QWR 跳过（gap >= sleep_threshold_hours → 由 SC 处理）
    #
    # OS 类比：Linux page cache incremental writeback（background flusher）vs fsync（sync writeback）—
    #   pdflush 30s 定期将少量 dirty pages 写回磁盘（QWR = 轻量级增量回写）；
    #   sync()/fsync() 触发全量回写（SC = 整夜睡眠的完整巩固）。
    #   两者互补：incremental flush 防止 dirty page 积累；最终 fsync 保证持久化。
    "store_vfs.qwr_enabled": (True, bool, None, None, None,
        "iter449: 是否启用 Quiet Wakefulness Reactivation — 短休息期（< 8h gap）的近期 chunk 获得轻度预巩固"),
    "store_vfs.qwr_min_gap_mins": (10, int, 1, 120, None,
        "iter449: 触发 QWR 的最短 gap（分钟）：gap < 此值说明连续会话，不触发 QWR（默认 10 分钟）"),
    "store_vfs.qwr_sleep_threshold_hours": (8.0, float, 4.0, 24.0, None,
        "iter449: gap >= 此值（小时）视为'整夜睡眠'，由 iter413 SC 处理，QWR 跳过（默认 8h）"),
    "store_vfs.qwr_recent_hours": (4.0, float, 0.5, 24.0, None,
        "iter449: 近期编码时间窗口（小时）：last_accessed >= now - qwr_recent_hours 的 chunk 才参与 QWR（默认 4h）"),
    "store_vfs.qwr_boost_factor": (1.03, float, 1.0, 1.20, None,
        "iter449: QWR stability 加成系数（stability × boost_factor，默认 1.03 ≈ +3%，"
        "比 SC 的 1.06 更保守，对应 Tambini 2010 的较小预巩固效应）"),
    "store_vfs.qwr_min_importance": (0.55, float, 0.3, 1.0, None,
        "iter449: 触发 QWR 的最低 importance 阈值（默认 0.55，略高于 SC 的 0.70 阈值下限，但专注近期重要 chunk）"),
    "store_vfs.qwr_max_chunks": (30, int, 5, 200, None,
        "iter449: 每次 QWR 最多处理的 chunk 数量（按 importance × recency 排序取前 N，默认 30）"),

    # ── iter450: Predictive Memory Encoding — 预期将来被测试增强编码（Roediger & Karpicke 2011）────────────
    # 认知科学依据：
    #   Roediger & Karpicke (2011) "The Critical Importance of Retrieval for Learning" (Current Directions) —
    #     预期将来会被测试的知识，在学习阶段被更深度加工（elaborative encoding），
    #     形成更强记忆痕迹（Test-Expectancy Effect: encoding effort increases when test is anticipated）。
    #     实验：提示"将来有测试"→ 当场编码的记忆保留率比无测试预期组高 25-35%。
    #   Szpunar et al. (2014) Nature Communications "Interpolated Memory Tests Reduce Mind Wandering" —
    #     中间插入测试题（间隔测试）不仅强化当时记忆，还提升后续学习段的编码质量
    #     （因为大脑进入"考试预期"状态，注意力集中度更高）。
    #   Wissman & Rawson (2012) "How Quickly Do Students Forget What They Have Learned?" —
    #     测试预期使初始编码强度提升，使后续遗忘曲线斜率更平缓（steeper consolidation）。
    #
    # memory-os 等价：
    #   新 chunk 写入时，查询同项目近期（past pme_window_hours）内 recall_traces 中同 chunk_type
    #   的检索次数（pme_query_count）。如果 pme_query_count >= pme_min_queries，说明该类型知识
    #   在用户工作流中正处于"活跃测试期"（= 高被测试预期），给予额外 initial_stability 加成：
    #     pme_factor = min(1.0, pme_query_count / pme_ref_count)
    #     new_stab = min(365.0, stab × (1 + pme_boost × pme_factor))
    #   只对 importance >= pme_min_importance 的 chunk 应用（低重要性 chunk 不值得额外保护）。
    #
    # 与 iter412 Testing Effect 的区别：
    #   Testing Effect(412) = 被实际检索后（事后）stability 提升（retrieval-triggered consolidation）
    #   PME(450) = 写入时预测将来会被测试（事前）initial_stability 提升（anticipatory encoding boost）
    #   两者互补：PME 提升初始编码强度 → Testing Effect 在每次检索时再次强化 → 双重保护循环
    #
    # OS 类比：Linux writeback dirty page pre-marking（MADV_SEQUENTIAL hint）—
    #   应用程序提前告诉内核"这段内存将被顺序读取"（= 测试预期），
    #   内核提前扩大 readahead 窗口并将相关 page 提升到 active 列表（= 提升初始编码强度）；
    #   类比：同话题近期高检索频率 = MADV_SEQUENTIAL hint → 新写入的同话题 chunk 获得预测性加成。
    "store_vfs.pme_enabled": (True, bool, None, None, None,
        "iter450: 是否启用 Predictive Memory Encoding — 高检索频率话题的新 chunk 获得预测性编码加成"),
    "store_vfs.pme_window_hours": (6.0, float, 0.5, 48.0, None,
        "iter450: 检索频率统计时间窗口（小时）：查找过去 N 小时内同 chunk_type 的检索次数（默认 6h）"),
    "store_vfs.pme_min_queries": (3, int, 1, 50, None,
        "iter450: 触发 PME 的最低同类型检索次数（默认 3：该话题被检索 >= 3 次才认为处于'测试预期'）"),
    "store_vfs.pme_ref_count": (10, int, 2, 100, None,
        "iter450: 检索次数参考值：pme_factor = min(1.0, count / ref_count)，"
        "count=ref_count 时达到最大加成（默认 10）"),
    "store_vfs.pme_boost": (0.12, float, 0.0, 0.50, None,
        "iter450: PME 最大 stability 加成系数：new_stab = stab × (1 + pme_boost × pme_factor)，"
        "count=ref_count 时最大加成 = pme_boost（默认 0.12 ≈ 12%，对应 Roediger 2011 的 25-35% 记忆优势的折半估计）"),
    "store_vfs.pme_min_importance": (0.45, float, 0.0, 1.0, None,
        "iter450: 触发 PME 的最低 importance 阈值（默认 0.45，低重要性 chunk 不参与预测编码增强）"),

    # ── iter451: Memory Reconsolidation — 检索后再巩固窗口期的编码情境刷新（Nader et al. 2000）────────────
    # 认知科学依据：
    #   Nader, Schafe & LeDoux (2000) Nature "Fear memories require protein synthesis in the amygdala
    #     for reconsolidation after retrieval" — 被检索（reactivated）的记忆进入不稳定的"可塑窗口"
    #     （labile reconsolidation window），在此窗口内记忆痕迹可被更新（而非只能固化或遗忘）。
    #     蛋白质合成抑制剂在检索后注入 → 记忆被修改而非消退（reconsolidation update, not extinction）。
    #   Hupbach et al. (2007) Nature Neuroscience "Reconsolidation of episodic memories:
    #     A subtle reminder triggers integration of new information" —
    #     旧记忆被轻微激活（subtle reminder）后，与新环境中获得的信息发生整合：
    #     实验者在复习旧物体后进入新环境学习新物体列表，后测发现旧列表中混入了新物体（整合效应）；
    #     这证明再巩固窗口允许"新旧信息双向融合"（bidirectional integration）。
    #   Lee (2009) "Reconsolidation: Maintaining Memory Relevance" (Trends in Neurosciences) —
    #     再巩固的适应性功能：将新情境信息（encoding context）注入旧记忆表示，
    #     使旧记忆能反映"最新的关联情境"（keeping memories relevant to current context）；
    #     而不是让旧记忆永远锁定在原始编码情境（防止 context-dependent retrieval failure）。
    #   Fernández et al. (2016) Science "Reactivation predicts the consolidation of new episodic memories" —
    #     先前检索激活的脑区（hippocampal pattern completion）在新情境中学习时被更强地激活，
    #     促进新旧知识的"模式整合"（pattern integration）而非"模式分离"（pattern separation）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，对"近期被检索"（last_accessed 在 rcr_labile_hours 内）的
    #   高 importance chunk 扫描：
    #     若本 session 内（created_at >= last_accessed - rcr_session_window_mins）存在
    #     encode_context entity 重叠 >= rcr_min_overlap 的"新写入 chunk"（created_at > last_accessed），
    #     则将新 chunk 的 encode_context entity 中不在旧 chunk 的 token，
    #     追加到旧 chunk 的 encode_context（最多 rcr_max_new_entities 个）。
    #   这不改变 stability（不是加成），而是丰富旧 chunk 的"语义检索面"：
    #     更多 entity → 更多检索路径 → encoding variability 增加（iter415）→ 更高的跨情境可提取性。
    #   副作用：更新后的 encode_context 可触发后续 sleep 的 PF/SCC/VRR 等机制（snowball consolidation）。
    #
    # 与 iter448 RE（Retroactive Enhancement）的区别：
    #   RE：新 chunk 增强旧 chunk 的 stability（数值加成）
    #   RCR：新 chunk 更新旧 chunk 的 encode_context（质性更新，丰富语义表示）
    #   两者互补：RE 增加旧记忆强度，RCR 扩展旧记忆的检索路径 → 共同实现双向整合
    #
    # OS 类比：Linux copy-on-write (CoW) page reconsolidation —
    #   页面被读访问后标记为"读保护"（COW ready），后续写操作先 copy-on-write 产生新副本，
    #   再将更新内容写回（新内容 → 旧页面的更新版本）；
    #   类比：旧 chunk 被检索（=读访问）→ 进入再巩固窗口（=COW ready）→
    #   新 chunk 写入后将新 entity 合并入旧 chunk encode_context（=写时合并新内容）。
    "store_vfs.rcr_enabled": (True, bool, None, None, None,
        "iter451: 是否启用 Memory Reconsolidation Context Refresh — 被检索后的 chunk 在再巩固窗口期内"
        "获得新写入的相关 chunk 的 entity 注入，扩展语义检索面"),
    "store_vfs.rcr_labile_hours": (6.0, float, 0.5, 48.0, None,
        "iter451: 再巩固可塑窗口时长（小时）：last_accessed 在此窗口内的 chunk 可接受 encode_context 更新"
        "（对应 Nader 2000 蛋白质合成窗口期，默认 6h）"),
    "store_vfs.rcr_session_window_mins": (120, int, 10, 720, None,
        "iter451: 同 session 内新 chunk 的时间窗口（分钟）：只考虑 last_accessed 后 N 分钟内写入的新 chunk"
        "（模拟 Hupbach 2007 subtle reminder → new context 的时间关系，默认 120min = 2h）"),
    "store_vfs.rcr_min_overlap": (2, int, 1, 10, None,
        "iter451: 触发 RCR 更新的最小 entity 重叠数（旧 chunk 与新 chunk encode_context 交集 >= 此值，默认 2）"),
    "store_vfs.rcr_max_new_entities": (5, int, 1, 20, None,
        "iter451: 每次 RCR 最多向旧 chunk 注入的新 entity 数量（防止过度稀释 encode_context，默认 5）"),
    "store_vfs.rcr_min_importance": (0.50, float, 0.0, 1.0, None,
        "iter451: 触发 RCR 的最低 importance 阈值（低重要性 chunk 不参与再巩固更新，默认 0.50）"),
    "store_vfs.rcr_protect_stable": (True, bool, None, None, None,
        "iter451: stability >= rcr_stable_floor 的 chunk 跳过 RCR（极度稳固的记忆不需要再巩固窗口更新，默认 True）"),
    "store_vfs.rcr_stable_floor": (60.0, float, 10.0, 365.0, None,
        "iter451: 视为'极度稳固'的 stability 下限（stability >= 此值时跳过 RCR，默认 60 天以上的稳固记忆不更新）"),

    # ── iter452: Primary Memory Persistence — 主动复述的工作记忆持久化（Waugh & Norman 1965）──────────
    # 认知科学依据：
    #   Waugh & Norman (1965) "Primary memory" (Psychological Review) —
    #     工作记忆（primary memory）中的信息只要被持续"rehearsal"（主动复述），就不会快速遗忘；
    #     停止主动复述后，信息在数秒内从工作记忆中消失（Peterson & Peterson 1959 distractor effect）。
    #     两种命运：① 被复述（rehearsed）→ 保留在 primary memory → 最终转入 secondary memory（长时记忆）
    #               ② 未被复述 → 在干扰下快速遗忘（interference-driven displacement）
    #   Miller (1956) "The magical number seven, plus or minus two" —
    #     工作记忆容量有限（7±2 chunk），超过容量后只有被主动维持的信息存活。
    #     主动复述 = 对有限认知资源的主动分配 → 信号：这条信息值得保留。
    #   Rundus (1971) "Analysis of rehearsal processes in free recall" (JEP) —
    #     自由回忆实验中，复述次数与最终记忆保留率高度正相关（r=0.85）；
    #     每多复述一次，最终保留率约提升 8-12%。
    #   Craik & Watkins (1973) "The role of rehearsal in short-term memory" (JVLVB) —
    #     "type I" rehearsal（单纯重复）vs "type II" rehearsal（精细加工）：
    #     精细加工型复述的长时记忆效果更好（≈深度编码），单纯重复型仅维持短期。
    #     memory-os 中：chunk 被频繁注入到 AI 上下文 = type II rehearsal（被集成进回答推理中，不只是展示）。
    #
    # memory-os 等价：
    #   sleep_consolidate 时，统计本 session 内（过去 gap_seconds 时间窗口内）
    #   每个 chunk 在 recall_traces 中的 injected 累计次数（session_injection_count）：
    #     session_injection_count >= pmp_min_injections → chunk 在本 session 被密集复述
    #     → 给予临时 stability 加成：new_stab = min(365, stab × pmp_boost × pmp_factor)
    #     pmp_factor = min(1.0, session_injection_count / pmp_ref_count)（注入越多加成越大）
    #   只对 importance >= pmp_min_importance 的 chunk 应用（低重要性复述无效 → 符合 Craik & Watkins 1973）
    #
    # 与 iter445 RTMC（Reward-Tagged Memory Consolidation）的区别：
    #   RTMC：跨 session 长期累积 access_count × recency（多巴胺奖励信号，宏观历史模式）
    #   PMP：本 session 内密集注入次数（主动复述，微观即时信号）
    #   两者互补：RTMC 保护历史高价值记忆，PMP 保护当前 session 的密集使用记忆
    #   时间粒度：RTMC=跨 session（天级）；PMP=单 session 内（小时级）
    #
    # 与 iter413 Sleep Consolidation（SC）的区别：
    #   SC：importance >= 0.70 的 chunk 一律加成（importance-based gate，与使用频率无关）
    #   PMP：session 内 injected >= pmp_min_injections 的 chunk（behavior-based，与实际复述相关）
    #   两者互补：SC 保护重要性高的知识，PMP 保护当前 session 中被密集使用的知识
    #
    # OS 类比：Linux page working set estimation (PG_referenced + PG_active) —
    #   页面在短时间内被多次访问（reference bit 被反复置位），kswapd 将其提升到 active list，
    #   增加"最近工作集热度"权重，下次 eviction 时优先保护；
    #   类比：session 内高频注入的 chunk = 短时间内反复 referenced → 工作集热页 → sleep 时优先保护。
    "store_vfs.pmp_enabled": (True, bool, None, None, None,
        "iter452: 是否启用 Primary Memory Persistence — session 内密集复述的 chunk 在 sleep 时获得额外巩固"),
    "store_vfs.pmp_min_injections": (3, int, 1, 50, None,
        "iter452: 触发 PMP 的最低 session 内注入次数（injected 累计 >= 此值，默认 3）"),
    "store_vfs.pmp_ref_count": (8, int, 2, 50, None,
        "iter452: 注入次数参考值：pmp_factor = min(1.0, count / ref_count)，"
        "count=ref_count 时达到最大加成（默认 8）"),
    "store_vfs.pmp_boost": (0.10, float, 0.0, 0.30, None,
        "iter452: PMP 最大 stability 加成系数：new_stab = stab × (1 + pmp_boost × pmp_factor)，"
        "count=ref_count 时最大加成 = pmp_boost（默认 0.10 ≈ 10%，对应 Rundus 1971 每次复述 +8-12% 保留率）"),
    "store_vfs.pmp_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter452: 触发 PMP 的最低 importance 阈值（低重要性 chunk 的复述无效，默认 0.40）"),
    "store_vfs.pmp_session_window_hours": (24.0, float, 0.5, 48.0, None,
        "iter452: session 内注入统计时间窗口（小时）：只统计过去 N 小时内的 recall_traces，"
        "覆盖本 session 的工作区间（默认 24h，与 sleep_consolidate.window_hours 对应）"),

    # ── iter453: Prediction Error Memory Enhancement — 意外命中触发多巴胺强化（Rescorla-Wagner 1972 / Schultz 1997）──
    # 认知科学依据：
    #   Rescorla & Wagner (1972) "A theory of Pavlovian conditioning" (Classical Conditioning II) —
    #     条件反射的强化量取决于预测误差（ΔV = α × β × (λ - V)）：
    #     当结果优于预期（λ > V，正向预测误差）→ 强化量最大；
    #     当结果完全符合预期（λ = V）→ 无强化（预测误差=0）。
    #     记忆形成效率与预测误差正比：surprise 越大，记忆越强。
    #   Schultz, Dayan & Montague (1997) Science "A Neural Substrate of Prediction and Reward" —
    #     VTA 多巴胺神经元精确编码时间差分预测误差（TD error）：
    #     意外奖励 → 多巴胺爆发（burst）→ 强化 CS-US 关联（学习）；
    #     预期内奖励 → 无多巴胺变化（学习率=0）；
    #     预期奖励未出现 → 多巴胺抑制（dip）→ 弱化期望。
    #     实验：猴子 VTA 记录：意外果汁奖励 → dopamine burst；预期果汁奖励（有 CS 提示）→ 无 burst。
    #   Lisman & Grace (2005) Neuron "The hippocampal-VTA loop" —
    #     海马→VTA 投射检测"新奇性"（novelty/surprise）：海马发现预测误差信号 →
    #     激活 VTA 多巴胺 → 强化当前检索路径的海马-新皮层突触（LTP 诱导）。
    #     等价：memory-os 中"意外命中"（低历史预期但当前高相关）= 新奇信号 → LTP 加成。
    #   Wagner (1981) "SOP: A model of automatic memory processing in animal behavior" —
    #     意外/新奇刺激（A1 state）比预期刺激（A2 state）触发更强的记忆巩固（A1 > A2 in processing）。
    #     A1 = primary activation（意外）；A2 = primed/expected activation（预期内，复述）。
    #
    # memory-os 等价：
    #   update_accessed() 时，若 chunk 同时满足：
    #     ① access_count（检索前）<= peme_max_access（历史上很少被检索 = 低预期相关性）
    #     ② retrievability_at_access < peme_low_retrievability（已部分遗忘 = 系统预期不相关）
    #     ③ importance >= peme_min_importance（有记忆价值）
    #   = "系统预测该 chunk 不相关（低预期），但当前 query 检索到它（正向预测误差）"
    #   = Rescorla-Wagner 的 surprise 事件 → Schultz 多巴胺 burst → stability 加成：
    #     surprise_score = (1 - retrievability_at_access) × (1 - access_count/peme_max_access)
    #     peme_bonus = surprise_score × peme_scale
    #     new_stab = min(365.0, stab × (1 + peme_bonus))
    #
    # 与 iter412 Testing Effect（TE）的区别：
    #   TE：retrievability 低 → 检索难度高 → SM-2 quality bonus（"desirable difficulty"驱动）
    #   PEME：retrievability 低 AND access_count 低 → 意外性（surprise）驱动稳定性加成
    #   触发条件：TE 只需低 retrievability；PEME 额外要求 access_count 也低（= 历史上不预期被召回）
    #   机制：TE = "这次检索很难" → 难度奖励；PEME = "没想到系统认为这个相关" → 惊喜奖励
    #
    # 与 iter388 Temporal Priming（TP）的区别：
    #   TP：最近被检索 → 再次相关时加分（近期激活 → 降低检索阈值）= 减少 surprise
    #   PEME：长期未被检索（低 access_count）→ 意外命中 = 最大化 surprise
    #   两者效果互补但方向相反：TP 保护近期热点；PEME 救活长期冷知识
    #
    # OS 类比：CPU branch predictor misprediction → forced L1 cache line promotion —
    #   分支预测失败（BPU 预测 not-taken，但实际 taken）→ pipeline flush + 强制将目标路径
    #   cache line 提升到 L1（misprediction penalty = cache warmup benefit for future hits）；
    #   类比：低历史召回率 chunk 被意外命中（= 分支预测失败）→ stability 强制提升（= L1 强制提升），
    #   确保后续检索能更稳定地命中该路径（减少未来的"预测误差"开销）。
    "store_vfs.peme_enabled": (True, bool, None, None, None,
        "iter453: 是否启用 Prediction Error Memory Enhancement — 意外命中（低预期+当前高相关）触发 stability 加成"),
    "store_vfs.peme_max_access": (5, int, 1, 50, None,
        "iter453: 意外命中触发条件之一：检索前 access_count <= 此值（历史低召回 = 低预期，默认 5）"),
    "store_vfs.peme_low_retrievability": (0.50, float, 0.0, 1.0, None,
        "iter453: 意外命中触发条件之二：retrievability < 此值（记忆已部分遗忘 = 系统低预期，默认 0.50）"),
    "store_vfs.peme_scale": (0.15, float, 0.0, 0.50, None,
        "iter453: 预测误差加成系数：peme_bonus = surprise_score × scale，"
        "surprise_score=1.0（完全意外）时 bonus=peme_scale（默认 0.15 ≈ 15%，"
        "对应 Schultz 1997 多巴胺 burst 的 ~15-20% LTP 诱导增强）"),
    "store_vfs.peme_min_importance": (0.45, float, 0.0, 1.0, None,
        "iter453: 触发 PEME 的最低 importance 阈值（低重要性 chunk 不参与，避免噪音固化，默认 0.45）"),

    # ── iter454: Interleaved Practice Effect — 混合检索强化效应（Kornell & Bjork 2008）────────────────────────
    # 认知科学依据：
    #   Kornell & Bjork (2008) "Learning concepts and categories: Is spacing the 'enemy of
    #     induction'?" (Psychological Science) —
    #     混合练习（不同类别交替学习）比集中练习（同类别连续学习）在延迟测试中表现好 43-57%：
    #     当场学习表现差（混合 vs 集中），但长期保留率更高（延迟测试反转效果）。
    #     机制：混合练习迫使大脑在每次检索时重建"区分性特征"（discriminative hypothesis），
    #     形成更丰富的多维检索线索集（elaborated retrieval schema），降低检索混淆率。
    #   Rohrer & Taylor (2007) "The shuffling of mathematics problems improves learning" —
    #     混合练习使数学问题的分类识别能力提升（+43%），因为混合创造了更多"相互比较"机会，
    #     强化了每个概念的边界特征（boundary feature encoding）。
    #   Pan & Rickard (2018) "Transfer of test-enhanced learning" (Psychological Bulletin) —
    #     混合检索（多主题交替）产生的迁移学习效果（transfer）比集中检索强 2-3 倍：
    #     跨主题检索激活更多关联路径，减少记忆孤岛（isolated memory silos）。
    #   Rohrer et al. (2015) "Interleaved practice improves mathematics learning" (J. Educational Psych) —
    #     混合练习效应的元分析：效应量 d=0.54，跨学科、年龄段均稳定。
    #
    # memory-os 等价：
    #   update_accessed() 时，若 chunk_ids 中包含多种不同 chunk_type（混合检索）：
    #     diversity_factor = unique_type_count / len(chunk_ids)（类型多样性比例）
    #     interleave_bonus = diversity_factor × ipe_scale
    #     new_stab = min(365.0, stab × (1 + interleave_bonus))
    #   只对 importance >= ipe_min_importance 的 chunk 应用（低重要性 chunk 不值得额外保护）。
    #   只在 unique_type_count >= ipe_min_types 时触发（至少 2 种类型才算"混合"）。
    #   单次 update_accessed 调用中 len(chunk_ids) >= ipe_min_chunks 才触发（单个 chunk 不算 interleaved）。
    #
    # 与 iter412 Testing Effect（TE）的区别：
    #   TE：单个 chunk 的检索难度奖励（低 retrievability → quality bonus）
    #   IPE：本次检索集合的类型多样性奖励（多 chunk_type → diversity bonus）
    #   触发层级：TE=单 chunk 级；IPE=检索批次级（batch-level diversity）
    #
    # 与 iter415 Encoding Variability（EV）的区别：
    #   EV：单 chunk 历史编码情境的多样性（encode_context 增长 → 跨情境稳健性）
    #   IPE：当前检索批次的类型多样性（同次检索不同类型 → 混合练习效应）
    #   时间维度：EV=跨 session 历史积累；IPE=单次 update_accessed 即时效应
    #
    # OS 类比：CPU cache prefetcher stride pattern detection with cross-stride interleaving ——
    #   访问不同 cache set 的交替模式（cross-stride interleaved access）比单一 stride 连续访问
    #   更能暴露内存访问的多维语义（multi-stream prefetch trigger）；
    #   现代 Intel/AMD prefetcher 对跨 stride 的交替访问给予更高预取优先级（D-stride + IP-stride 联合激活）；
    #   类比：跨 chunk_type 的混合检索 = 多维语义访问模式 → prefetcher 提升对应 cache line 的预取优先级
    #   = memory-os 给予混合检索的每个 chunk 额外 stability 加成。
    "store_vfs.ipe_enabled": (True, bool, None, None, None,
        "iter454: 是否启用 Interleaved Practice Effect — 混合检索（多 chunk_type）时每个 chunk 获得额外 stability 加成"),
    "store_vfs.ipe_min_types": (2, int, 2, 10, None,
        "iter454: 触发 IPE 的最少不同 chunk_type 数量（默认 2：至少 2 种类型才算'混合检索'）"),
    "store_vfs.ipe_min_chunks": (2, int, 2, 20, None,
        "iter454: 触发 IPE 的最少 chunk_ids 数量（默认 2：单个 chunk 不构成混合检索）"),
    "store_vfs.ipe_scale": (0.08, float, 0.0, 0.30, None,
        "iter454: IPE 加成系数：interleave_bonus = diversity_factor × scale，"
        "diversity_factor=1.0（每个 chunk 类型不同）时最大 bonus=ipe_scale（默认 0.08 ≈ 8%，"
        "对应 Kornell 2008 混合练习的 ~43-57% 保留率优势的折半折半估计）"),
    "store_vfs.ipe_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter454: 触发 IPE 的最低 importance 阈值（低重要性 chunk 不参与混合强化，默认 0.40）"),

    # ── iter455: Generation-Spacing Interaction Effect — 检索努力×间隔历史的乘法交互加成（Pyc & Rawson 2009）──
    # 认知科学依据：
    #   Pyc & Rawson (2009) "Testing the retrieval effort hypothesis: Does greater difficulty
    #     correctly recalling information lead to higher levels of memory?" (JML 60:437-447) —
    #     检索练习的巩固效益不均等，取决于两个因素的乘积：
    #     ① 检索难度（retrieval effort）：当前检索有多难（R_at_recall 越低，effort 越高）
    #     ② 间隔成功历史（spaced_access_count）：历史上有多少次跨 session 成功检索
    #     交互效应：effort × streak_factor 才是真正的巩固预测因子，
    #     高努力+无历史 = 初次学习；高历史+无努力 = 轻松重复；两者俱高 = 最强巩固。
    #   Roediger & Karpicke (2006) Perspectives on Psychological Science "The Power of Testing Memory" —
    #     检索练习优势的核心机制是"desirable difficulty"：难但成功的检索比容易的检索产生
    #     更强、更持久的记忆痕迹（elaborative encoding 更深，Bjork 1994）。
    #   Carrier & Pashler (1992) — 检索努力在神经水平上驱动更强的 LTP：
    #     突触标记（synaptic tagging）需要同时满足：
    #     ① 先前 LTP 历史（success streak = synaptic tag already set）
    #     ② 当前去极化充分（effort = strong depolarization attempt）
    #     两者缺一不可（Frey & Morris 1997 synaptic tagging hypothesis）。
    #   与 iter412 Testing Effect（TE）的区别：
    #     TE = 单维度：难度 → SM-2 quality bonus（单次检索的直接奖励）
    #     GSIE = 双维度乘法：effort × streak_factor（累积历史 × 当次难度 = 交互奖励）
    #     TE 在 quality 满分（5）后无法继续加成；GSIE 在 SM-2 之外提供独立乘法 pass
    #   与 iter420 Spacing Effect（SE）的区别：
    #     SE = spaced_access_count 贡献 SM-2 quality 加成（单维度频率奖励）
    #     GSIE = spaced_access_count × effort 的乘法交互（当 SE 使 quality 饱和到 5 时，GSIE 仍可激活）
    #
    # memory-os 等价：
    #   update_accessed() 时，对每个命中 chunk：
    #     effort_score = max(0.0, 1.0 - R_at_recall)
    #     streak_factor = min(1.0, spaced_access_count / gsie_ref_streak)
    #     interaction_score = effort_score × streak_factor
    #     if effort_score >= gsie_min_effort and spaced_access_count >= gsie_min_streak:
    #         gsie_bonus = interaction_score × gsie_scale
    #         new_stab = min(365.0, stability × (1.0 + gsie_bonus))
    #   在 SM-2 更新之后执行（读取 SM-2 后的新 stability），作为独立第二次 pass。
    #
    # OS 类比：Linux ARC (Adaptive Replacement Cache) ghost list + frequency-weighted promotion —
    #   ARC 维护 ghost list（已驱逐但有访问历史的 page）。
    #   当 ghost list 中的 page 再次缺页（= 检索努力高，因为该 page 已过期）：
    #     → ARC 将 T2（高频历史）权重增加（= streak_factor）
    #     → 晋升力度 = T2权重 × 缺页难度（ghost list 中驻留时间，= effort_score）
    #   最终晋升到 T2（稳定工作集）的力度 = frequency_weight × recency_gap = GSIE 的乘法交互。
    "store_vfs.gsie_enabled": (True, bool, None, None, None,
        "iter455: 是否启用 Generation-Spacing Interaction Effect — 检索努力 × 间隔成功历史的乘法交互加成"),
    "store_vfs.gsie_min_streak": (2, int, 1, 20, None,
        "iter455: 触发 GSIE 的最低 spaced_access_count 阈值（>= 此值代表有间隔成功历史，默认 2）"),
    "store_vfs.gsie_ref_streak": (6, int, 2, 50, None,
        "iter455: streak_factor 达到 1.0 所需的 spaced_access_count 参考值（默认 6，"
        "对应 Pyc & Rawson 2009 完全检索努力效益约在 4-6 次成功检索后出现）"),
    "store_vfs.gsie_min_effort": (0.10, float, 0.0, 1.0, None,
        "iter455: 触发 GSIE 的最低 effort_score 阈值（effort_score = 1 - R_at_recall，"
        "< 0.10 代表几乎完美回忆，不构成'检索努力'事件，默认 0.10）"),
    "store_vfs.gsie_scale": (0.12, float, 0.0, 0.50, None,
        "iter455: GSIE 交互加成系数：bonus = interaction_score × scale，"
        "interaction_score=1.0（最大努力 + 最长历史）时最大 bonus=gsie_scale（默认 0.12 ≈ 12%，"
        "略高于 TE 的 SM-2 quality 最大加成，对应 Pyc & Rawson 2009 两因子乘法的额外增益）"),
    "store_vfs.gsie_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter455: 触发 GSIE 的最低 importance 阈值（低重要性 chunk 不参与交互加成，默认 0.40）"),

    # ── iter456: Retrieval Practice vs. Restudy Consolidation Asymmetry (RPCA) — 主动检索比被动重读巩固效益更高（Roediger & Karpicke 2006）──
    # 认知科学依据：
    #   Roediger & Karpicke (2006) "Test-Enhanced Learning: Taking Memory Tests Improves Long-Term Retention"
    #     (Psychological Science) — 学习相同材料，主动检索（retrieval practice）比被动重读（restudy）
    #     在延迟测试（一周后）中保留率高约 50%：
    #     retrieval practice: 61% retention; restudy: 40% retention (1 week test)。
    #     机制：主动检索激活更多语义网络节点（elaborative retrieval），形成更多检索路径；
    #     被动重读只是激活已有的浅层表示（shallow re-exposure），不触发额外巩固机制。
    #   Karpicke & Roediger (2008) Science "The Critical Importance of Retrieval for Learning" —
    #     即使研究材料时间相同，retrieval practice 的长时记忆优势是 restudy 的 1.5-2 倍。
    #   Karpicke & Blunt (2011) Science "Retrieval Practice Produces More Learning than Elaborative Studying" —
    #     主动测试优于包括概念图、精化笔记等多种"深度学习"策略，证明检索行为本身是关键。
    #
    # memory-os 等价：
    #   update_accessed() 时，根据 access_source 字段区分访问路径：
    #     'retrieval' = 用户 query 主动命中（FTS5/BM25 检索，真正的测试事件）→ rpca_retrieval_bonus
    #     'restudy'   = 被动曝光（SessionStart loader inject, prefetch 等预载）→ rpca_restudy_bonus
    #   bonus 作为独立 stability 乘子（额外 pass，在 SM-2 之后）：
    #     new_stab = min(365.0, stab × (1 + bonus))
    #   retrieval bonus > restudy bonus，体现主动检索的记忆优势。
    #
    # 与 iter412 Testing Effect（TE）的区别：
    #   TE：低 retrievability → 检索难度 → SM-2 quality 加成（难度驱动，单维度）
    #   RPCA：access_source='retrieval' vs 'restudy' → 路径差异 → 稳定性加成（路径驱动，二分类）
    #   两者互补：TE 奖励难度，RPCA 奖励检索行为本身（即使 retrievability 很高的"容易"检索也获得加成）
    #
    # OS 类比：Linux page fault vs readahead prefetch 的 LRU promotion 差异 —
    #   demand page fault（主动缺页 = retrieval）触发 page 立即提升到 active LRU list；
    #   readahead prefetch（被动预读 = restudy）page 先进 inactive list，需要二次访问才晋升；
    #   类比：retrieval path → 直接 active list promotion（更强 stability 加成）；
    #         restudy path → inactive list（较弱加成，需要后续真正被用到才晋升）。
    "store_vfs.rpca_enabled": (True, bool, None, None, None,
        "iter456: 是否启用 Retrieval Practice vs Restudy Consolidation Asymmetry — 主动检索比被动重读获得更高 stability 加成"),
    "store_vfs.rpca_retrieval_bonus": (0.10, float, 0.0, 0.30, None,
        "iter456: 主动检索路径（access_source='retrieval'）的 stability 加成系数，"
        "new_stab = stab × (1 + rpca_retrieval_bonus)（默认 0.10 ≈ 10%，"
        "对应 Roediger & Karpicke 2006 retrieval practice 比 restudy 高约 50% 的折半估计）"),
    "store_vfs.rpca_restudy_bonus": (0.02, float, 0.0, 0.10, None,
        "iter456: 被动重读路径（access_source='restudy'）的 stability 加成系数，"
        "new_stab = stab × (1 + rpca_restudy_bonus)（默认 0.02 ≈ 2%，被动曝光仍有轻微加成）"),
    "store_vfs.rpca_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter456: 触发 RPCA 的最低 importance 阈值（低重要性 chunk 不参与，默认 0.40）"),

    # ── iter457: Cue Overload Consolidation Penalty (COCP) — 检索线索过载降低巩固效益（Watkins & Watkins 1975）──
    # 认知科学依据：
    #   Watkins & Watkins (1975) "Build-up of proactive inhibition as a cue-overload effect"
    #     (Journal of Experimental Psychology: Human Learning and Memory) —
    #     当过多的记忆项共享同一检索线索（cue）时，每个项目的单独可提取性下降（cue overload）。
    #     机制：检索线索的"扇入扇出"信息量有限（fan effect），线索对应项目越多，
    #     每次巩固时分配到该线索下每个记忆的"巩固资源"越少。
    #     Rundus (1973) "Negative effects of using list items as recall cues" —
    #       同一列表内互相作为提示词时，反而降低彼此的回忆率（列表内干扰）。
    #     Roediger (1978) "Recall as a self-limiting process" — 同类记忆越多，单个记忆的
    #       recall probability 越低（呈次线性关系：P(recall) ∝ 1/√N_same_cue）。
    #   适用场景：同一项目内同 chunk_type 数量过多（N_same_type > threshold）时，
    #     sleep_consolidate 对该类型的 chunk 施加轻微 stability 惩罚，
    #     模拟"线索过载"：同类 chunk 互相竞争有限的巩固路径。
    # memory-os 等价：
    #   sleep_consolidate 时，统计 project 内每种 chunk_type 的数量 N_type；
    #   N_type > cocp_threshold 时，对该类型的 chunk 施加：
    #     overload_factor = min(cocp_max_penalty, (N_type - cocp_threshold) / cocp_scale_factor)
    #     new_stab = max(0.1, stab × (1 - overload_factor))
    #   importance >= cocp_protect_importance 的 chunk 豁免（核心知识不受线索过载影响）。
    # 与 iter432 累积干扰（CI）的区别：
    #   CI：同类型 chunk 数量增加导致每个 chunk 的 sleep decay 加速（CI 乘以更大 decay rate）
    #   COCP：sleep_consolidate boost 时对过多同类 chunk 施加巩固惩罚（减少 boost 量）
    #   两者互补：CI 模拟编码竞争（Underwood 1957）；COCP 模拟检索线索饱和（Watkins 1975）
    # OS 类比：Linux CPU cache set-associativity saturation —
    #   太多 cache line 映射到同一 set（= 同一检索线索下太多记忆）→
    #   每次新写入导致更频繁的 LRU eviction（= 巩固效益边际递减）；
    #   COCP = cache set-associativity 饱和后的 per-line 保留概率下降。
    "store_vfs.cocp_enabled": (True, bool, None, None, None,
        "iter457: 是否启用 Cue Overload Consolidation Penalty — 同类型 chunk 过多时 sleep 巩固效益下降"),
    "store_vfs.cocp_type_threshold": (15, int, 3, 100, None,
        "iter457: 触发 COCP 的同类型 chunk 数量阈值（超过此值时该类型 chunk 受巩固惩罚，默认 15）"),
    "store_vfs.cocp_scale_factor": (20.0, float, 5.0, 100.0, None,
        "iter457: COCP 惩罚缩放因子：overload_factor = (N - threshold) / scale_factor，"
        "N=threshold+scale_factor 时惩罚达到 cocp_max_penalty（默认 20）"),
    "store_vfs.cocp_max_penalty": (0.10, float, 0.0, 0.30, None,
        "iter457: COCP 最大惩罚系数（new_stab = stab × (1 - penalty)，最大 10% 惩罚，默认 0.10）"),
    "store_vfs.cocp_protect_importance": (0.80, float, 0.5, 1.0, None,
        "iter457: importance >= 此值的 chunk 豁免 COCP（核心知识不受线索过载影响，默认 0.80）"),
    "store_vfs.cocp_protect_types": ("design_constraint,procedure", str, None, None, None,
        "iter457: 豁免 COCP 的 chunk_type 列表（逗号分隔；这些类型即使数量多也不受惩罚）"),

    # ── iter458: Elaborative Interrogation Effect (EIE) — 因果性解释显著增强记忆编码（Pressley et al. 1992）──
    # 认知科学依据：
    #   Pressley et al. (1992) "Elaborative interrogation and memory for prose" —
    #     要求学生解释"为什么这个事实是真的"（elaborative interrogation）比被动阅读
    #     使记忆保留率提升 72%（passage retention: EI=72%, control=37%）。
    #     机制：因果性解释触发更深层的语义加工（elaborative encoding），
    #     将新信息整合进已有知识网络中（assimilation），
    #     形成更多检索路径（retrieval routes）。
    #   Woloshyn et al. (1992) "Use of elaborative interrogation to help students acquire information" —
    #     自我生成的因果解释比被动接受的解释记忆更强（generation advantage + elaboration advantage）。
    #   Martin & Pressley (1991) "Elaborative interrogation effects depend on the nature of the question" —
    #     "why" 问题比"what" 问题更有效；因果性越强（causal connective 越明确），编码越深。
    # memory-os 等价：
    #   insert_chunk() 时，检测 content 中的因果连接词（because/therefore/causes/hence/
    #   consequently/以为/导致/因此/所以/由于/是因为/的原因是）密度；
    #   causal_connective_count >= eie_min_connectives → 该 chunk 被判定为"因果解释型"，
    #   initial_stability × eie_boost_factor（写入时一次性加成，类比深度编码）。
    #   只对 importance >= eie_min_importance 的 chunk 应用。
    # 与 iter411 LOP（Levels of Processing）的区别：
    #   LOP：encode_context entity 密度代理编码深度（量化代理）
    #   EIE：content 中的因果连接词密度直接检测因果推理（文本内容分析）
    #   两者互补：LOP 检测知识图谱深度；EIE 检测语义推理质量
    # 与 iter406 Generation Effect 的区别：
    #   GE：推理标记（I think/therefore/let's/because...）= 主动生成信号
    #   EIE：因果连接词密度 ≥ 阈值 = 专门检测因果解释（subset of GE，更专注因果推理）
    #   EIE 的 boost 发生在 insert_chunk 时（与 GE 不同触发点），强调"why"的力量
    # OS 类比：Linux ext4 htree directory indexing — 深度索引（因果关联 = htree depth 深）
    #   使得同一目录下的文件查找从 O(N) 降到 O(log N)（更多检索路径 = 更快提取）；
    #   因果解释型 chunk = 有深度 htree 的目录 = 更低的"检索代价"（更高 stability）。
    "store_vfs.eie_enabled": (True, bool, None, None, None,
        "iter458: 是否启用 Elaborative Interrogation Effect — 因果解释型 chunk 写入时获得 stability 加成"),
    "store_vfs.eie_min_connectives": (2, int, 1, 10, None,
        "iter458: 触发 EIE 的最低因果连接词数量（content 中 >= 此值才视为'因果解释型'，默认 2）"),
    "store_vfs.eie_boost_factor": (1.15, float, 1.0, 2.0, None,
        "iter458: EIE stability 加成系数（initial_stability × factor，默认 1.15 ≈ +15%，"
        "对应 Pressley 1992 EI 比对照组高约 +35% 的折半估计）"),
    "store_vfs.eie_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter458: 触发 EIE 的最低 importance 阈值（低重要性 chunk 不参与，默认 0.40）"),
    "store_vfs.eie_max_boost": (0.30, float, 0.0, 0.60, None,
        "iter458: EIE 最大 stability 加成系数上限（base × (1 + max_boost)，防止过激，默认 0.30 = +30%）"),

    # ── iter459: Contextual Interference Effect (CIE) — 变化练习历史提升延迟测试成绩（Shea & Morgan 1979）──
    # 认知科学依据：
    #   Shea & Morgan (1979) "Contextual interference effects on the acquisition,
    #     retention, and transfer of a motor skill" (Journal of Experimental Psychology: HPP) —
    #     随机（mixed）练习顺序（每次不同任务）比集中（blocked）练习在延迟测试中成绩高 57%，
    #     虽然集中练习在当场表现更好（acquisition paradox）。
    #     机制：随机练习迫使大脑在每次执行前重构运动程序（elaborative encoding + action plan）；
    #     集中练习只需维持同一程序在工作记忆中（无需重构 → 浅层编码）。
    #   Brady (2008) Meta-analysis — CI effect: d=0.56，跨多种技能（运动/认知/记忆）均显著。
    #   Simon & Bjork (2001) "Contextual interference effects in skill acquisition" —
    #     CI 效应与间隔效应（SE）的交互：CI+SE 的组合是最强的学习条件（CI × SE 乘法效应）。
    # memory-os 等价：
    #   chunk 的 session_type_history（TEXT，逗号分隔的历史 session_type 序列）记录历次访问的情境类型。
    #   update_accessed() 时更新 session_type_history，增加当次 session 的 session_type。
    #   apply_contextual_interference_effect() 计算 session_type 多样性：
    #     unique_types = len(set(session_type_history.split(',')))
    #     diversity_score = min(1.0, (unique_types - 1) / cie_ref_types)
    #     cie_bonus = diversity_score × cie_scale
    #     new_stab = min(365.0, stab × (1 + cie_bonus))
    #   与 iter415 Encoding Variability（EV）的区别：
    #     EV：encode_context token 增长（知识图谱情境多样性）
    #     CIE：session_type 切换历史（任务类型情境多样性）
    #     维度不同：EV=语义空间多样性；CIE=任务类型多样性（debug vs design vs refactor）
    # OS 类比：Linux Multi-Queue Block I/O (blk-mq) — 不同 queue depth / CPU 的混合调度
    #   在多种 I/O pattern 混合时表现优于单一 queue（cross-queue diversity = CI effect）；
    #   类比：跨多种 session_type 被访问的 chunk（= multi-queue mixed pattern）获得额外 stability 加成。
    "store_vfs.cie_enabled": (True, bool, None, None, None,
        "iter459: 是否启用 Contextual Interference Effect — 跨多种 session_type 访问的 chunk 获得 stability 加成"),
    "store_vfs.cie_ref_types": (4, int, 2, 20, None,
        "iter459: diversity_score=1.0 所需的 unique session_type 数量（默认 4：4 种不同任务类型时达到满分）"),
    "store_vfs.cie_scale": (0.10, float, 0.0, 0.30, None,
        "iter459: CIE stability 加成系数：cie_bonus = diversity_score × scale，"
        "diversity=1.0 时最大 bonus=cie_scale（默认 0.10 ≈ 10%，"
        "对应 Shea & Morgan 1979 随机练习比集中练习高 57% 的折半折三估计）"),
    "store_vfs.cie_min_unique_types": (2, int, 2, 10, None,
        "iter459: 触发 CIE 的最少 unique session_type 数量（默认 2：至少 2 种不同任务类型才算'混合'）"),
    "store_vfs.cie_min_importance": (0.40, float, 0.0, 1.0, None,
        "iter459: 触发 CIE 的最低 importance 阈值（低重要性 chunk 不参与混合加成，默认 0.40）"),
    "store_vfs.cie_max_history": (20, int, 5, 100, None,
        "iter459: session_type_history 最大记录数量（FIFO 滚动，超出时删除最旧记录，默认 20）"),

    # ── iter460: Sleep Spindle Density Effect (SSDE) — 慢波睡眠纺锤波密度对陈述性记忆的差异性增强（Stickgold 2005）──
    # 认知科学依据：
    #   Stickgold (2005) "Sleep-dependent memory consolidation" (Nature 437) —
    #     睡眠期间，NREM Stage 2 的 sleep spindles（12-15 Hz）密度与陈述性记忆巩固量正相关；
    #     REM 睡眠则与程序性（procedural）记忆的巩固更相关。
    #     Spindle density 预测 declarative memory consolidation：r=0.71（p<0.001）。
    #   Gais et al. (2002) "Learning-dependent increases in sleep spindle density" (Journal of Neuroscience) —
    #     实验后与对照组相比，学习组睡眠 spindle 密度显著增加（+17%），
    #     且增加量与次日记忆保留率高度相关（选择性增强：declarative > procedural）。
    #   Walker & Stickgold (2004) "Sleep-dependent learning and motor-skill complexity" —
    #     不同记忆类型有不同睡眠阶段偏好：
    #     陈述性（episodic/semantic）→ NREM SWS + spindles（慢波巩固）
    #     程序性（motor/procedural）→ REM（快动眼期巩固）
    #     情绪性（flashbulb/emotional）→ NREM + amygdala reactivation
    # memory-os 等价：
    #   sleep_consolidate 时，根据 chunk_type 应用差异化的巩固系数（type-specific spindle preference）：
    #     陈述性类型（decision/design_constraint/reasoning_chain/quantitative_evidence/causal_chain）
    #       → 获得更强的 sleep 巩固加成（spindle-boosted declarative）
    #     程序性类型（procedure/task_state）
    #       → 获得较弱的 sleep 巩固加成（REM-boosted procedural，不需 spindles）
    #     中性类型（其他）→ 默认加成（无 SSDE 调整）
    #   SSDE 作为 sleep_consolidate boost_factor 的乘子：
    #     effective_boost = base_boost × ssde_type_multiplier[chunk_type]
    # 与 iter413 Sleep Consolidation（SC）的区别：
    #   SC：importance >= 0.70 的 chunk 一律 × boost_factor（importance-based gate）
    #   SSDE：根据 chunk_type 应用差异化 boost multiplier（type-specific gate）
    #   两者叠加：SSDE 调整 SC 的 boost_factor，使不同类型记忆获得与神经科学一致的差异化巩固
    # OS 类比：Linux NUMA-aware writeback priority —
    #   不同类型的 dirty page（data/metadata/journal）有不同的 writeback 优先级策略：
    #   data page（陈述性）→ pdflush 优先处理；
    #   journal page（程序性）→ jbd2 单独管理；
    #   类比：spindle-preferred 类型（陈述性）在 sleep_consolidate 中获得更强优先级。
    "store_vfs.ssde_enabled": (True, bool, None, None, None,
        "iter460: 是否启用 Sleep Spindle Density Effect — 陈述性记忆 chunk 在 sleep 时获得更强巩固加成"),
    "store_vfs.ssde_declarative_multiplier": (1.20, float, 1.0, 2.0, None,
        "iter460: 陈述性记忆类型的 sleep boost 乘子（默认 1.20：spindle-boosted，"
        "对应 Gais 2002 spindle density +17% ≈ consolidation +20% 的估计）"),
    "store_vfs.ssde_procedural_multiplier": (0.85, float, 0.5, 1.0, None,
        "iter460: 程序性记忆类型的 sleep boost 乘子（默认 0.85：REM-preferred，"
        "NREM spindles 对 procedural 记忆贡献较少，轻微降权）"),
    "store_vfs.ssde_declarative_types": (
        "decision,design_constraint,reasoning_chain,quantitative_evidence,causal_chain",
        str, None, None, None,
        "iter460: 陈述性记忆 chunk_type 列表（逗号分隔，这些类型获得 ssde_declarative_multiplier 加成）"),
    "store_vfs.ssde_procedural_types": ("procedure,task_state", str, None, None, None,
        "iter460: 程序性记忆 chunk_type 列表（逗号分隔，这些类型获得 ssde_procedural_multiplier 减权）"),
    "store_vfs.ssde_min_importance": (0.45, float, 0.0, 1.0, None,
        "iter460: 触发 SSDE 的最低 importance 阈值（低重要性 chunk 不参与类型差异化巩固，默认 0.45）"),

    # ── iter461: Hebbian Co-Activation Consolidation (HAC) — 共同激活的 chunk 在 sleep 时相互加固 ──
    # 认知科学依据：Hebb (1949) "The Organization of Behavior" — "Cells that fire together, wire together"
    #   海马 Hebbian 可塑性：两个神经元同时激活 → 突触连接增强（LTP）。
    #   记忆网络中，共同被检索的知识片段形成更强的关联（Schema Theory, Bartlett 1932）。
    #   Zeithamova et al. (2012): 睡眠期间共激活的记忆对通过 SWR replay 相互巩固。
    # memory-os 等价：
    #   同一 update_accessed() 调用中出现的 chunk_ids → 在 chunk_coactivation 表记录共激活次数；
    #   sleep_consolidate 时，共激活次数 >= hac_min_coact 的 chunk 对，各自 stability × hac_boost_factor。
    # OS 类比：Linux THP (Transparent Huge Pages) promotion —
    #   同一 2MB 区域频繁被共同访问的页面 → 被透明提升为 huge page（降低 TLB miss，增强保留优先级）。
    "store_vfs.hac_enabled": (True, bool, None, None, None,
        "iter461: 是否启用 Hebbian Co-Activation Consolidation — 共同激活的 chunk 在 sleep 时相互加固"),
    "store_vfs.hac_min_coact": (2, int, 1, 20, None,
        "iter461: 触发 HAC 的最低共激活次数阈值（共激活 >= 此值时在 sleep 获得加成，默认 2）"),
    "store_vfs.hac_boost_factor": (1.05, float, 1.0, 1.30, None,
        "iter461: HAC stability 加成系数（stability × hac_boost_factor，默认 1.05 = 5% 加成）"),
    "store_vfs.hac_max_boost": (0.15, float, 0.0, 0.40, None,
        "iter461: HAC 最大加成上限（stability 最多增加 hac_max_boost 比例，默认 0.15 = 15%）"),
    "store_vfs.hac_min_importance": (0.35, float, 0.0, 1.0, None,
        "iter461: 触发 HAC 的最低 importance 阈值（低重要性 chunk 不参与共激活巩固，默认 0.35）"),

    # ── iter462: Source Monitoring Boost (SMB) — 有来源溯源的记忆编码更强（Johnson et al. 1993）──
    # 认知科学依据：Johnson, Hashtroudi & Lindsay (1993) "Source monitoring" (Psychological Bulletin) —
    #   source monitoring = 区分"在哪里/什么情境下学到的"能力。
    #   有清晰来源的记忆（episodic + semantic 双重标签）比来源模糊的记忆遗忘更慢。
    #   Lindsay (2008): 来源清晰度与记忆精确度正相关（r=0.48），因为额外编码维度 = 更多检索线索。
    # memory-os 等价：
    #   insert_chunk 时，source_session 非空 → chunk 有明确来源 → stability × smb_boost_factor。
    #   source_session 空 = 无法溯源 = 较弱编码。
    # OS 类比：Linux inode i_generation — 有 generation 追踪的 inode 在 fsck 后可更快恢复（
    #   溯源信息完整 = 更鲁棒的文件系统状态 = 更低恢复成本）。
    "store_vfs.smb_enabled": (True, bool, None, None, None,
        "iter462: 是否启用 Source Monitoring Boost — 有明确来源的 chunk 获得 stability 加成"),
    "store_vfs.smb_boost_factor": (1.08, float, 1.0, 1.30, None,
        "iter462: SMB stability 加成系数（source_session 非空时 stability × smb_boost_factor，默认 1.08）"),
    "store_vfs.smb_max_boost": (0.12, float, 0.0, 0.30, None,
        "iter462: SMB 最大加成上限（stability 最多增加 smb_max_boost 比例，默认 0.12）"),
    "store_vfs.smb_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter462: 触发 SMB 的最低 importance 阈值（低重要性 chunk 不参与来源监控加成，默认 0.30）"),

    # ── iter463: Output Interference Effect (OIE) — 顺序检索中后续 chunk 受前项干扰（Postman 1971）──
    # 认知科学依据：Postman & Underwood (1973) "Critical issues in interference theory" —
    #   顺序回忆（串行检索）中，后位项目受前位项目输出干扰（output interference）。
    #   Roediger (1974): 自由回忆中，回忆第 N 个词后，第 N+1 个词的可及性下降约 5-8%。
    # memory-os 等价：
    #   update_accessed(chunk_ids=[c1,c2,...,cN]) 时，第 i 位置（0-based）的 chunk
    #   受 (i/N) × oie_max_penalty 比例的 stability 惩罚；第一个 chunk 无惩罚。
    # OS 类比：Linux TLB invalidation cascade — 顺序 shootdown 多个 TLB entry 时，
    #   后续 entry 因 pipeline stall 累积而经历更高的 invalidation latency（顺序依赖代价递增）。
    "store_vfs.oie_enabled": (True, bool, None, None, None,
        "iter463: 是否启用 Output Interference Effect — 顺序检索中后续 chunk 受前项干扰"),
    "store_vfs.oie_max_penalty": (0.05, float, 0.0, 0.20, None,
        "iter463: OIE 最大惩罚系数（列表末尾 chunk stability 最多降低 oie_max_penalty 比例，默认 0.05 = 5%）"),
    "store_vfs.oie_min_list_len": (3, int, 2, 20, None,
        "iter463: 触发 OIE 的最小 chunk_ids 列表长度（列表长度 < 此值时不应用 OIE，默认 3）"),
    "store_vfs.oie_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter463: 触发 OIE 的最低 importance 阈值（低重要性 chunk 不受 OIE 惩罚，默认 0.25）"),

    # ── iter464: Keyword Density Encoding Effect (KDEE) — 信息密度高的内容编码更深（Craik & Lockhart 1972）──
    # 认知科学依据：Craik & Lockhart (1972) "Levels of processing" (Journal of Verbal Learning) —
    #   深度加工（semantic processing）比浅层加工（phonological/orthographic）产生更持久的记忆痕迹。
    #   信息密度高（unique words / total words 比率高）= 需要更深的语义处理 = 更强编码。
    #   Kintsch (1974): 文本命题密度与长期记忆保留量正相关（r=0.62）。
    # memory-os 等价：
    #   insert_chunk 时，计算 content 的 unique_word_ratio = len(unique_words) / max(1, len(words))；
    #   unique_word_ratio >= kdee_min_density → stability × kdee_boost_factor（一次性深度编码加成）。
    # OS 类比：Linux ext4 extent tree depth — 有大量唯一文件块（extent）的 inode 具有更深的 B-tree
    #   索引结构，提供更鲁棒的随机访问性能（信息密度高 = 更深索引 = 更快检索）。
    "store_vfs.kdee_enabled": (True, bool, None, None, None,
        "iter464: 是否启用 Keyword Density Encoding Effect — 高信息密度内容获得 stability 加成"),
    "store_vfs.kdee_min_density": (0.60, float, 0.0, 1.0, None,
        "iter464: 触发 KDEE 的最低 unique_word_ratio 阈值（unique_words/total_words >= 此值，默认 0.60）"),
    "store_vfs.kdee_min_words": (6, int, 1, 50, None,
        "iter464: 触发 KDEE 的最少词数（content 总词数 < 此值时不计算密度，默认 6）"),
    "store_vfs.kdee_boost_factor": (1.10, float, 1.0, 1.50, None,
        "iter464: KDEE stability 加成系数（high-density content stability × kdee_boost_factor，默认 1.10）"),
    "store_vfs.kdee_max_boost": (0.20, float, 0.0, 0.40, None,
        "iter464: KDEE 最大加成上限（stability 最多增加 kdee_max_boost 比例，默认 0.20）"),
    "store_vfs.kdee_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter464: 触发 KDEE 的最低 importance 阈值（低重要性 chunk 不参与密度编码加成，默认 0.30）"),

    # ── iter465: Lag-Dependent Spacing Boost (LDSB) — 间隔检索效应：长间隔召回获得更大 stability 加成 ──
    # 认知科学依据：Landauer & Bjork (1978) "Optimum rehearsal patterns" —
    #   扩张间隔练习（expanding spacing）比固定间隔更有效：回忆越难（间隔越长）→ 加固效果越强。
    #   SM-2 算法（Wozniak 1987）的核心：interval/stability 比率越大，spacing bonus 越高。
    # OS 类比：Linux page aging（mm/vmscan.c）— 在 inactive list 停留时间越长的 page
    #   在被 kswapd 访问时获得更高的 active list 优先级（长期低温 page 被标记为 high-value）。
    "store_vfs.ldsb_enabled": (True, bool, None, None, None,
        "iter465: 是否启用 Lag-Dependent Spacing Boost — 长间隔回忆获得更大 stability 加成"),
    "store_vfs.ldsb_min_lag_hours": (2.0, float, 0.0, 24.0, None,
        "iter465: 触发 LDSB 的最短间隔（小时），低于此值不给加成（默认 2h = 避免短期重复）"),
    "store_vfs.ldsb_max_boost": (0.15, float, 0.0, 0.40, None,
        "iter465: LDSB 最大加成上限（最多增加 ldsb_max_boost 比例，默认 0.15）"),
    "store_vfs.ldsb_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter465: 触发 LDSB 的最低 importance 阈值（默认 0.25）"),

    # ── iter466: Emotional Intensity Effect (ETE) — 情绪性内容获得杏仁核增强编码（Cahill et al. 1994）──
    # 认知科学依据：Cahill, Prins, Weber & McGaugh (1994) "Beta-adrenergic activation and memory" —
    #   情绪唤醒（norepinephrine释放）增强杏仁核→海马双向连接 → 情绪内容记忆更持久（AUC提升40%）。
    #   LaBar & Cabeza (2006) "Cognitive neuroscience of emotional memory": 情绪强度与记忆精确度正相关(r=0.53)。
    # OS 类比：Linux OOM killer priority scoring — oom_adj/oom_score_adj 高的进程（关键系统进程）
    #   获得保护，不被 OOM killer 优先终止（情绪显著内容 = 高 oom_adj → 受保护）。
    "store_vfs.ete_enabled": (True, bool, None, None, None,
        "iter466: 是否启用 Emotional Tagging Effect — 情绪性关键词内容获得 stability 加成"),
    "store_vfs.ete_boost_factor": (1.12, float, 1.0, 1.50, None,
        "iter466: ETE stability 加成系数（情绪内容 stability × ete_boost_factor，默认 1.12）"),
    "store_vfs.ete_max_boost": (0.18, float, 0.0, 0.40, None,
        "iter466: ETE 最大加成上限（stability 最多增加 ete_max_boost 比例，默认 0.18）"),
    "store_vfs.ete_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter466: 触发 ETE 的最低 importance 阈值（默认 0.30）"),
    "store_vfs.ete_keywords": (
        "critical,error,bug,fail,urgent,crisis,breakthrough,alarm,panic,catastrophe,"
        "关键,错误,故障,紧急,危机,突破,崩溃,警报,重大",
        str, None, None, None,
        "iter466: 触发 ETE 的情绪性关键词列表（逗号分隔，英中文混合，默认包含故障/紧急/突破等词）"),

    # ── iter467: Desirable Difficulty Effect (DDE) — 认知努力越大的内容编码越深（Bjork 1994）──
    # 认知科学依据：Bjork (1994) "Memory and metamemory considerations" —
    #   "有益的困难"（desirable difficulty）：困难的学习任务（间隔练习、交错、测试）产生更强长期记忆，
    #   尽管在学习时感觉更难。内容越复杂（词汇越丰富，句子越长）→ 需要更深加工 → 更持久记忆。
    #   Hirshman & Bjork (1988): 生成效应（generation effect）= 认知努力代理（effort proxy）。
    # OS 类比：zswap/zram 压缩页面 — 需要 CPU 解压的页面比普通页面需要更多计算（cognitive effort），
    #   但压缩率高 = 能在有限内存中保留更多 pages（复杂编码 → 更高信息密度存储）。
    "store_vfs.dde_enabled": (True, bool, None, None, None,
        "iter467: 是否启用 Desirable Difficulty Effect — 内容词汇复杂度高时获得 stability 加成"),
    "store_vfs.dde_min_avg_word_len": (5.5, float, 3.0, 10.0, None,
        "iter467: 触发 DDE 的最小平均词长阈值（content 词汇平均字符数 >= 此值，默认 5.5）"),
    "store_vfs.dde_boost_factor": (1.08, float, 1.0, 1.30, None,
        "iter467: DDE stability 加成系数（默认 1.08 = 8% 加成）"),
    "store_vfs.dde_max_boost": (0.16, float, 0.0, 0.35, None,
        "iter467: DDE 最大加成上限（stability 最多增加 dde_max_boost 比例，默认 0.16）"),
    "store_vfs.dde_min_words": (5, int, 1, 50, None,
        "iter467: 触发 DDE 的最少词数（词数 < 此值时不计算平均词长，默认 5）"),
    "store_vfs.dde_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter467: 触发 DDE 的最低 importance 阈值（默认 0.30）"),

    # ── iter468: Contextual Cue Reinstatement Effect (CCRE) — 上下文匹配提升检索成功率（Godden & Baddeley 1975）──
    # 认知科学依据：Godden & Baddeley (1975) "Context-dependent memory in two natural environments" —
    #   编码时的环境上下文（encode_context）与检索时的上下文匹配度越高，检索成功率越高。
    #   Tulving & Thomson (1973) Encoding Specificity Principle：检索线索需匹配编码时的上下文。
    #   Smith (1979): 在相同上下文中测验时记忆成绩提升约 40%（vs 不同上下文）。
    # OS 类比：Linux NUMA topology-aware allocation（mm/mempolicy.c）—
    #   NUMA_PREFERRED/MPOL_BIND：在分配内存的同一 NUMA 节点访问 page → 低延迟；
    #   跨节点访问 → 高延迟（context mismatch penalty）。
    "store_vfs.ccre_enabled": (True, bool, None, None, None,
        "iter468: 是否启用 Contextual Cue Reinstatement Effect — encode_context 匹配时 stability 加成"),
    "store_vfs.ccre_boost_per_token": (0.02, float, 0.0, 0.10, None,
        "iter468: 每个匹配 encode_context token 的 stability 加成（默认 0.02 = 2%/token）"),
    "store_vfs.ccre_max_boost": (0.20, float, 0.0, 0.40, None,
        "iter468: CCRE 最大加成上限（stability 最多增加 ccre_max_boost 比例，默认 0.20）"),
    "store_vfs.ccre_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter468: 触发 CCRE 的最低 importance 阈值（默认 0.30）"),

    # ── iter469: Generation Effect (GE) — 主动生成的信息比被动接收的保留更好（Slamecka & Graf 1978）──
    # 认知科学依据：Slamecka & Graf (1978) "The generation effect: Delineation of a phenomenon" —
    #   自我生成的信息（自写/决策/约束）比被动阅读的信息记忆保留率高 20-30%（延时测验）。
    #   机制：生成过程激活更深的语义处理网络（semantic encoding）+ 自我参照加工（self-referential processing）。
    # OS 类比：Linux CoW (Copy-on-Write) — 被进程主动写入（dirty）的页面优先保留在 active LRU；
    #   只读共享页面（read-only）优先被 kswapd 淘汰（mm/vmscan.c: page_check_references）。
    "store_vfs.ge_enabled": (True, bool, None, None, None,
        "iter469: 是否启用 Generation Effect — 主动生成类型的 chunk 获得 stability 加成"),
    "store_vfs.ge_generative_types": ("decision,design_constraint,feedback", str, None, None, None,
        "iter469: 触发 GE 的 chunk_type 列表（逗号分隔，这些类型代表主动生成的知识，默认 decision/design_constraint/feedback）"),
    "store_vfs.ge_boost_factor": (1.10, float, 1.0, 1.50, None,
        "iter469: GE stability 加成系数（generative chunk stability × ge_boost_factor，默认 1.10）"),
    "store_vfs.ge_max_boost": (0.18, float, 0.0, 0.40, None,
        "iter469: GE 最大加成上限（stability 最多增加 ge_max_boost 比例，默认 0.18）"),
    "store_vfs.ge_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter469: 触发 GE 的最低 importance 阈值（默认 0.25）"),

    # ── iter470: Interleaving Effect (ILE) — 混合上下文学习比分块学习产生更强记忆（Kornell & Bjork 2008）──
    # 认知科学依据：Kornell & Bjork (2008) "Learning concepts and categories" —
    #   交错练习（interleaved practice）vs. 分块练习（blocked practice）：测验成绩 64% vs. 36%（r=0.58）。
    #   机制：交错迫使大脑持续辨别相似概念 → 更深的比较性处理 → 更精细的记忆表征。
    # OS 类比：Linux NUMA interleaving (mm/mempolicy.c MPOL_INTERLEAVE) — 内存分配跨多个 NUMA 节点
    #   → 无单点 bandwidth 瓶颈 → 整体吞吐量和容错性更高（访问多样性 = 更强鲁棒性）。
    "store_vfs.ile_enabled": (True, bool, None, None, None,
        "iter470: 是否启用 Interleaving Effect — session_type_history 多样性越高获得更大 stability 加成"),
    "store_vfs.ile_min_diversity": (2, int, 1, 20, None,
        "iter470: 触发 ILE 的最少不同 session_type 数量（默认 2，即至少在 2 种上下文中被访问过）"),
    "store_vfs.ile_boost_per_type": (0.03, float, 0.0, 0.10, None,
        "iter470: 每增加一种 session_type 的额外 stability 加成比例（默认 0.03 = 3%/type）"),
    "store_vfs.ile_max_boost": (0.18, float, 0.0, 0.40, None,
        "iter470: ILE 最大加成上限（stability 最多增加 ile_max_boost 比例，默认 0.18）"),
    "store_vfs.ile_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter470: 触发 ILE 的最低 importance 阈值（默认 0.30）"),

    # ── iter471: Self-Reference Effect (SRE) — 与自身相关的信息编码更深（Rogers, Kuiper & Kirker 1977）──
    # 认知科学依据：Rogers, Kuiper & Kirker (1977) "Self-reference and the encoding of personal information" —
    #   "Does it describe you?" 条件下记忆保留比语义判断（"Does it mean...?"）高 50-60%（r=0.61）。
    #   机制：自我参照激活 medial prefrontal cortex（mPFC）→ 更强的 episodic memory consolidation。
    # OS 类比：Linux process-private mappings (MAP_PRIVATE) — 进程私有页面（自己的 mm_struct 地址空间）
    #   访问速度比共享匿名映射快（TLB 局部性更好），页故障处理优先（mm/fault.c: handle_mm_fault）。
    "store_vfs.sre_enabled": (True, bool, None, None, None,
        "iter471: 是否启用 Self-Reference Effect — 含第一人称代词的 chunk 获得 stability 加成"),
    "store_vfs.sre_keywords": ("我,我们,我的,我们的,myself,ourselves,I ,we ,our ,my ", str, None, None, None,
        "iter471: 触发 SRE 的第一人称关键词列表（逗号分隔，英中文混合，默认包含 I/we/our/my/我/我们）"),
    "store_vfs.sre_boost_factor": (1.09, float, 1.0, 1.30, None,
        "iter471: SRE stability 加成系数（含自我参照内容 stability × sre_boost_factor，默认 1.09）"),
    "store_vfs.sre_max_boost": (0.15, float, 0.0, 0.35, None,
        "iter471: SRE 最大加成上限（stability 最多增加 sre_max_boost 比例，默认 0.15）"),
    "store_vfs.sre_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter471: 触发 SRE 的最低 importance 阈值（默认 0.30）"),

    # ── iter472: Access Frequency Boost (AFB) — 高检索频率强化记忆痕迹（Power Law of Practice）──
    # 认知科学依据：Newell & Rosenbloom (1981) "Mechanisms of skill acquisition and the law of practice" —
    #   熟练度提升遵循幂律：performance ∝ trials^(-0.4)。对记忆：检索次数越多 → 记忆痕迹越强。
    #   Anderson (1983) ACT* 理论：strength = ΣΑ_j × t_j^(-d)，检索次数 ↑ → strength ↑。
    # OS 类比：Linux active LRU promotion (mm/swap.c: mark_page_accessed) —
    #   多次访问（PG_referenced 置位 → 移入 active LRU）的页面获得更高驻留优先级；
    #   访问计数越高（hot page）→ 越难被 kswapd 淘汰（page_referenced() > 0 → skip）。
    "store_vfs.afb_enabled": (True, bool, None, None, None,
        "iter472: 是否启用 Access Frequency Boost — 高访问频率的 chunk 获得 stability 加成"),
    "store_vfs.afb_min_count": (3, int, 1, 100, None,
        "iter472: 触发 AFB 的最少访问次数（access_count >= afb_min_count 时触发，默认 3）"),
    "store_vfs.afb_scale": (0.015, float, 0.0, 0.10, None,
        "iter472: 每次超出 min_count 的访问带来的额外 stability 加成比例（默认 0.015 = 1.5%/次）"),
    "store_vfs.afb_max_boost": (0.20, float, 0.0, 0.40, None,
        "iter472: AFB 最大加成上限（stability 最多增加 afb_max_boost 比例，默认 0.20）"),
    "store_vfs.afb_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter472: 触发 AFB 的最低 importance 阈值（默认 0.25）"),

    # ── iter473: MIE — Memory Interference Effect（前摄/倒摄干扰，McGeoch 1932 / Underwood 1957）──
    # 认知科学依据：同类内容在短时窗口内密集写入，互相干扰编码，类似旧记忆压制新记忆（PI）
    #   或新记忆压制旧记忆（RI）。McGeoch (1932): 相似度越高，干扰越强。
    # OS 类比：Linux cache thrashing（mm/vmscan.c）— working set > available memory 时 page
    #   不断换入换出，effective throughput 下降。
    "store_vfs.mie_enabled": (True, bool, None, None, None,
        "iter473: 是否启用 Memory Interference Effect（前摄/倒摄干扰惩罚，默认 True）"),
    "store_vfs.mie_window_hours": (24, int, 1, 168, None,
        "iter473: 干扰检测时间窗口（小时，默认 24）"),
    "store_vfs.mie_min_overlap": (0.30, float, 0.0, 1.0, None,
        "iter473: 触发干扰的词汇 Jaccard 重叠阈值（默认 0.30）"),
    "store_vfs.mie_penalty_factor": (0.93, float, 0.5, 1.0, None,
        "iter473: 干扰惩罚系数（stability × factor，默认 0.93 即降 7%）"),
    "store_vfs.mie_max_penalty": (0.12, float, 0.0, 0.40, None,
        "iter473: 最大惩罚比例（默认 0.12 即最多降 12%）"),
    "store_vfs.mie_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter473: 触发 MIE 的最低 importance 阈值（默认 0.30）"),

    # ── iter474: SAE — Spreading Activation Effect（激活扩散，Collins & Loftus 1975）──
    # 认知科学依据：语义网络中节点激活沿关联边传播，相关概念可达性提升。
    #   Anderson (1983) ACT*: 基线激活水平互相加成，效果约 20-30% retrievability 提升。
    # OS 类比：Linux readahead（mm/readahead.c）— 顺序/相关 page 预取到 page cache，降低缺页率。
    "store_vfs.sae_enabled": (True, bool, None, None, None,
        "iter474: 是否启用 Spreading Activation Effect（激活扩散，默认 True）"),
    "store_vfs.sae_min_similarity": (0.20, float, 0.0, 1.0, None,
        "iter474: 触发激活扩散的词汇 Jaccard 相似度阈值（默认 0.20）"),
    "store_vfs.sae_spread_factor": (0.05, float, 0.0, 0.30, None,
        "iter474: 每个相邻 chunk 获得的 retrievability 加成比例（默认 0.05）"),
    "store_vfs.sae_max_spread": (0.15, float, 0.0, 0.40, None,
        "iter474: 每次激活扩散的最大 retrievability 加成（默认 0.15）"),
    "store_vfs.sae_max_neighbors": (10, int, 1, 50, None,
        "iter474: 每次扩散最多影响的邻居数（默认 10）"),
    "store_vfs.sae_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter474: 触发 SAE 的源 chunk 最低 importance 阈值（默认 0.25）"),

    # ── iter475: SPE — Serial Position Effect（序列位置效应，Murdock 1962）──
    # 认知科学依据：自由回忆中首位项目（primacy）和末位项目（recency）记忆最好。
    #   Primacy: 首位项目复习次数更多 → stability 更高。
    #   Recency: 末位项目仍在工作记忆 → 短期 retrievability 更高（r=0.61）。
    # OS 类比：CPU L1/L2 cache LRU — head（最先加载）和 tail（最近访问）都有更好命中率。
    "store_vfs.spe_enabled": (True, bool, None, None, None,
        "iter475: 是否启用 Serial Position Effect（序列位置效应，默认 True）"),
    "store_vfs.spe_primacy_window": (5, int, 1, 20, None,
        "iter475: session 内前 N 个 chunk 获得 primacy 加成（默认 5）"),
    "store_vfs.spe_primacy_boost": (0.05, float, 0.0, 0.20, None,
        "iter475: primacy stability 加成比例（默认 0.05 即 +5%）"),
    "store_vfs.spe_recency_window": (5, int, 1, 20, None,
        "iter475: session 内最近 N 个 chunk 获得 recency 加成（默认 5）"),
    "store_vfs.spe_recency_boost": (0.08, float, 0.0, 0.20, None,
        "iter475: recency retrievability 加成（绝对值，默认 0.08）"),
    "store_vfs.spe_min_session_size": (3, int, 1, 20, None,
        "iter475: session 至少有 N 个 chunk 时才触发 SPE（默认 3）"),
    "store_vfs.spe_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter475: 触发 SPE 的最低 importance 阈值（默认 0.25）"),

    # ── iter476: CLP — Cognitive Load Penalty（认知负荷惩罚，Sweller 1988）──
    # 认知科学依据：工作记忆容量有限（7±2 chunks，Miller 1956）。内容超出容量上限时，
    #   有效编码下降（Paas & van Merriënboer 1994）。与 DDE 互补：短且复杂=有益困难，
    #   长且复杂=认知超载。
    # OS 类比：CPU context switch overhead — 超线程数过多时，调度开销超过收益。
    "store_vfs.clp_enabled": (True, bool, None, None, None,
        "iter476: 是否启用 Cognitive Load Penalty（认知负荷惩罚，默认 True）"),
    "store_vfs.clp_max_tokens": (200, int, 50, 1000, None,
        "iter476: 工作记忆容量代理阈值（词数上限，默认 200）"),
    "store_vfs.clp_penalty_per_100": (0.04, float, 0.0, 0.15, None,
        "iter476: 每超出 100 词施加的 stability 惩罚比例（默认 0.04）"),
    "store_vfs.clp_max_penalty": (0.15, float, 0.0, 0.40, None,
        "iter476: 最大惩罚比例（默认 0.15 即最多降 15%）"),
    "store_vfs.clp_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter476: 触发 CLP 的最低 importance 阈值（默认 0.30）"),

    # ── iter477: Memory Binding Effect (MBE) — 同 session 共同编码的 chunk 相互加固（Eichenbaum 2004）──
    # 认知科学依据：Eichenbaum (2004) 海马体情节绑定 — 同一编码事件中的记忆被绑定在一起，
    #   共同激活使各部分稳定性相互加成（episodic binding）。OS 类比：Linux THP — 相邻页合并为大页。
    "store_vfs.mbe_enabled": (True, bool, None, None, None,
        "iter477: 是否启用 Memory Binding Effect（默认 True）"),
    "store_vfs.mbe_window_seconds": (300, int, 10, 3600, None,
        "iter477: 同 session 内被视为同批编码的时间窗口（秒，默认 300=5min）"),
    "store_vfs.mbe_boost_factor": (0.03, float, 0.0, 0.15, None,
        "iter477: 每个绑定邻居带来的 stability 加成比例（默认 0.03）"),
    "store_vfs.mbe_max_boost": (0.10, float, 0.0, 0.30, None,
        "iter477: MBE 最大 stability 加成比例（默认 0.10 = 10%）"),
    "store_vfs.mbe_max_neighbors": (5, int, 1, 20, None,
        "iter477: 最多参与绑定的邻居数（默认 5）"),
    "store_vfs.mbe_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter477: 触发 MBE 的最低 importance 阈值（默认 0.25）"),

    # ── iter478: Directed Forgetting Effect (DFE) — importance 下降时向关联 chunk 扩散遗忘（Bjork 1972）──
    # 认知科学依据：Bjork (1972) 定向遗忘 — 当被明确告知"忘记某项"时，
    #   相关记忆的检索也受到抑制（category inhibition）。OS 类比：MADV_FREE — 页标记为可回收。
    "store_vfs.dfe_enabled": (True, bool, None, None, None,
        "iter478: 是否启用 Directed Forgetting Effect（默认 True）"),
    "store_vfs.dfe_min_importance_drop": (0.20, float, 0.0, 1.0, None,
        "iter478: 触发 DFE 所需的 importance 降幅阈值（默认 0.20）"),
    "store_vfs.dfe_min_similarity": (0.30, float, 0.0, 1.0, None,
        "iter478: 邻居需达到的 Jaccard 相似度阈值（默认 0.30）"),
    "store_vfs.dfe_decay_factor": (0.95, float, 0.5, 1.0, None,
        "iter478: 遗忘扩散时邻居 stability 的衰减系数（默认 0.95，即降 5%）"),
    "store_vfs.dfe_max_decay": (0.10, float, 0.0, 0.40, None,
        "iter478: 最大衰减比例（默认 0.10 = 10%）"),
    "store_vfs.dfe_max_neighbors": (8, int, 1, 30, None,
        "iter478: 最多受影响的邻居数（默认 8）"),
    "store_vfs.dfe_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter478: 邻居被影响所需的最低 importance（默认 0.20）"),

    # ── iter479: Use-Dependent Plasticity (UDP) — 共同访问的 chunk 互相加固稳定性（Hebb 1949）──
    # 认知科学依据：Hebb (1949) "Neurons that fire together wire together" —
    #   共同激活的记忆节点间连接加强。OS 类比：Linux Working Set 共享页面 refcount++。
    "store_vfs.udp_enabled": (True, bool, None, None, None,
        "iter479: 是否启用 Use-Dependent Plasticity（默认 True）"),
    "store_vfs.udp_boost_per_peer": (0.02, float, 0.0, 0.10, None,
        "iter479: 每个共同访问邻居带来的 stability 加成（默认 0.02）"),
    "store_vfs.udp_max_boost": (0.08, float, 0.0, 0.25, None,
        "iter479: UDP 最大 stability 加成比例（默认 0.08 = 8%）"),
    "store_vfs.udp_max_peers": (5, int, 1, 20, None,
        "iter479: 最多参与共塑的对等 chunk 数（默认 5）"),
    "store_vfs.udp_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter479: 触发 UDP 的最低 importance 阈值（默认 0.25）"),

    # ── iter480: Forward Association Primacy (FAP) — 前向关联优先（Kahana 2002）──
    # 认知科学依据：Kahana (2002) 序列学习中前向联想比后向联想强 ~1.5:1 —
    #   访问后来的 chunk 时，较早的 session-sibling 的可达性提升（正向联想方向）。
    #   OS 类比：CPU 指令流水线预取 — 按顺序预取后续指令到 fetch buffer。
    "store_vfs.fap_enabled": (True, bool, None, None, None,
        "iter480: 是否启用 Forward Association Primacy（默认 True）"),
    "store_vfs.fap_retr_boost": (0.04, float, 0.0, 0.15, None,
        "iter480: 前向关联 retrievability 加成（默认 0.04）"),
    "store_vfs.fap_max_boost": (0.12, float, 0.0, 0.30, None,
        "iter480: FAP 最大 retrievability 加成（默认 0.12）"),
    "store_vfs.fap_lookback_window": (10, int, 1, 50, None,
        "iter480: 查找当前 chunk 之前的 session sibling 数量（默认 10）"),
    "store_vfs.fap_min_session_size": (3, int, 1, 20, None,
        "iter480: 触发 FAP 所需的最小 session 大小（默认 3）"),
    "store_vfs.fap_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter480: 触发 FAP 的最低 importance 阈值（默认 0.25）"),

    # ── iter481: Testing Effect / Retrieval Practice Effect (TPE) — 检索比复习更强化记忆（Roediger & Karpicke 2006）──
    # 认知科学依据：Roediger & Karpicke (2006) Science —
    #   纯检索（test）vs 纯复习（restudy）：1周后保留率 64% vs 40%；Cohen's d ≈ 1.0。
    #   机制：主动检索激活"检索练习"路径，比被动复习更强化长时记忆（检索练习效应）。
    # OS 类比：CPU TLB hit — 从 TLB 命中（主动检索）的 page 比从页表查找（被动复习）更新 LRU，降低 eviction 概率。
    "store_vfs.tpe_enabled": (True, bool, None, None, None,
        "iter481: 是否启用 Testing Effect（默认 True）"),
    "store_vfs.tpe_boost_factor": (0.05, float, 0.0, 0.20, None,
        "iter481: 检索命中带来的额外 stability 加成比例（默认 0.05 = 5%）"),
    "store_vfs.tpe_max_boost": (0.15, float, 0.0, 0.40, None,
        "iter481: TPE 最大加成比例（默认 0.15 = 15%）"),
    "store_vfs.tpe_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter481: 触发 TPE 的最低 importance 阈值（默认 0.25）"),
    "store_vfs.tpe_lookback_minutes": (5, int, 1, 60, None,
        "iter481: 查找最近 recall_traces 的时间窗口（分钟，默认 5）"),

    # ── iter482: Spacing Effect Bonus (SEB) — 间隔越长每次访问稳定性增益越大（Ebbinghaus 1885）──
    # 认知科学依据：Ebbinghaus (1885) + Cepeda et al. (2006) meta-analysis (n=317) d=0.70 —
    #   最优间隔 = retention interval × 10-20%；间隔越长，每次访问带来的 stability 增益越大。
    # OS 类比：Linux page access bit TLB aging — 距上次访问越久，下次命中优先级越高。
    "store_vfs.seb_enabled": (True, bool, None, None, None,
        "iter482: 是否启用 Spacing Effect Bonus（默认 True）"),
    "store_vfs.seb_min_gap_hours": (4, int, 1, 48, None,
        "iter482: 触发 SEB 所需的最小间隔时间（小时，默认 4）"),
    "store_vfs.seb_base_bonus": (0.03, float, 0.0, 0.10, None,
        "iter482: 基础间隔奖励比例（每倍增间隔增加，默认 0.03）"),
    "store_vfs.seb_max_bonus": (0.12, float, 0.0, 0.30, None,
        "iter482: SEB 最大奖励比例（默认 0.12 = 12%）"),
    "store_vfs.seb_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter482: 触发 SEB 的最低 importance 阈值（默认 0.25）"),

    # ── iter483: Priming Effect (PE) — 已有相似 chunk 启动新 chunk 的编码稳定性（Meyer & Schvaneveldt 1971）──
    # 认知科学依据：Meyer & Schvaneveldt (1971) JEPS — 已激活相关概念使目标识别更快更稳固；
    #   编码时的语义启动（prime）提升新内容的编码质量（提供语义脚手架）。
    # OS 类比：Linux dentry cache warm — 相关目录项已缓存，新文件路径解析更快更稳定。
    "store_vfs.pe_enabled": (True, bool, None, None, None,
        "iter483: 是否启用 Priming Effect（默认 True）"),
    "store_vfs.pe_min_similarity": (0.25, float, 0.0, 1.0, None,
        "iter483: 启动源与新 chunk 的最低 Jaccard 相似度（默认 0.25）"),
    "store_vfs.pe_boost_per_prime": (0.04, float, 0.0, 0.10, None,
        "iter483: 每个启动源带来的 stability 加成（默认 0.04）"),
    "store_vfs.pe_max_boost": (0.10, float, 0.0, 0.25, None,
        "iter483: PE 最大 stability 加成比例（默认 0.10 = 10%）"),
    "store_vfs.pe_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter483: 触发 PE 的最低 importance 阈值（默认 0.25）"),
    "store_vfs.pe_min_primes": (1, int, 1, 10, None,
        "iter483: 触发 PE 所需的最少启动源数（默认 1）"),

    # ── iter484: Cross-Session Consolidation Effect (CCE) — 跨 session 访问获巩固奖励（Walker & Stickgold 2004）──
    # 认知科学依据：Walker & Stickgold (2004) Neuron — 睡眠/休息期海马-皮质巩固使记忆更稳固；
    #   跨 session 间隔 ≈ 睡眠/休息 → 下次访问时 stability 额外提升 6-12%。
    # OS 类比：Linux kswapd background reclaim — 空闲期（session 间隔）整理 page → 降低下次分配压力。
    "store_vfs.cce_enabled": (True, bool, None, None, None,
        "iter484: 是否启用 Cross-Session Consolidation Effect（默认 True）"),
    "store_vfs.cce_min_gap_hours": (6, int, 1, 48, None,
        "iter484: 触发 CCE 的跨 session 最小时间间隔（小时，默认 6）"),
    "store_vfs.cce_base_bonus": (0.04, float, 0.0, 0.15, None,
        "iter484: 基础跨 session 巩固奖励（默认 0.04 = 4%）"),
    "store_vfs.cce_max_boost": (0.10, float, 0.0, 0.30, None,
        "iter484: CCE 最大奖励比例（默认 0.10 = 10%）"),
    "store_vfs.cce_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter484: 触发 CCE 的最低 importance 阈值（默认 0.25）"),

    # ── iter485: Desirable Difficulty Effect (DDE2) — 提取难度高时记忆更持久（Bjork 1994）──
    # 认知科学依据：Bjork (1994) "Memory and metamemory considerations" — 适度困难的检索任务
    #   强化编码深度；检索难度通过 retrievability 低、stability 低的组合衡量；难提取→成功提取收益更大。
    # OS 类比：Linux TLB miss penalty → miss 时触发完整 page walk，但同时更新 TLB，后续命中更快。
    "store_vfs.dde2_enabled": (True, bool, None, None, None,
        "iter485: 是否启用 Desirable Difficulty Effect（默认 True）"),
    "store_vfs.dde2_retrievability_threshold": (0.40, float, 0.0, 1.0, None,
        "iter485: 触发 DDE2 的最大 retrievability 阈值（低于此值才算'难'，默认 0.40）"),
    "store_vfs.dde2_stability_threshold": (10.0, float, 0.1, 100.0, None,
        "iter485: 触发 DDE2 的最大 stability 阈值（低于此值才算'难'，默认 10.0 天）"),
    "store_vfs.dde2_bonus_per_difficulty": (0.08, float, 0.0, 0.30, None,
        "iter485: 难度调用成功后 stability 增益系数（默认 0.08 = 8%）"),
    "store_vfs.dde2_max_boost": (0.20, float, 0.0, 0.50, None,
        "iter485: DDE2 最大 stability 加成比例（默认 0.20 = 20%）"),
    "store_vfs.dde2_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter485: 触发 DDE2 的最低 importance 阈值（默认 0.20）"),

    # ── iter486: Contextual Reinstatement Effect (CRE2) — 恢复编码上下文增强提取（Godden & Baddeley 1975）──
    # 认知科学依据：Godden & Baddeley (1975) British J Psych — 在与编码相同的上下文（session tags/namespace）
    #   中检索，提取成功率提高 ~40%；相同 namespace 或相似 tag 集合视为"上下文匹配"。
    # OS 类比：CPU cache locality — 访问与之前同一 working set 的 page，TLB/cache 命中率更高。
    "store_vfs.cre2_enabled": (True, bool, None, None, None,
        "iter486: 是否启用 Contextual Reinstatement Effect（默认 True）"),
    "store_vfs.cre2_namespace_match_bonus": (0.06, float, 0.0, 0.20, None,
        "iter486: namespace 相同时 retrievability 加成（默认 0.06）"),
    "store_vfs.cre2_tag_overlap_bonus": (0.04, float, 0.0, 0.15, None,
        "iter486: tag 集合重叠率超过阈值时额外加成（默认 0.04）"),
    "store_vfs.cre2_tag_overlap_threshold": (0.50, float, 0.0, 1.0, None,
        "iter486: 触发 tag 重叠加成所需的最低 Jaccard 相似度（默认 0.50）"),
    "store_vfs.cre2_max_boost": (0.12, float, 0.0, 0.30, None,
        "iter486: CRE2 最大 retrievability 加成（默认 0.12）"),
    "store_vfs.cre2_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter486: 触发 CRE2 的最低 importance 阈值（默认 0.20）"),

    # ── iter487: Emotion Tagging Effect (ETE2) — 高情绪价值 chunk 遗忘更慢（McGaugh 2000）──
    # 认知科学依据：McGaugh (2000) Science "Memory — a century of consolidation" — 杏仁核通过 NE/
    #   cortisol 调节海马巩固；情绪唤起（高 importance 或含情绪关键词）使记忆更持久，稳定性衰减更慢。
    # OS 类比：cgroup memory.min 保护层 — 高优先级进程的 pages 受保护，不被 kswapd 回收。
    "store_vfs.ete2_enabled": (True, bool, None, None, None,
        "iter487: 是否启用 Emotion Tagging Effect（默认 True）"),
    "store_vfs.ete2_importance_threshold": (0.70, float, 0.0, 1.0, None,
        "iter487: 触发 ETE2 的最低 importance 阈值（高情绪唤起，默认 0.70）"),
    "store_vfs.ete2_stability_decay_reduction": (0.15, float, 0.0, 0.50, None,
        "iter487: 高情绪 chunk 的 stability 衰减减免比例（默认 0.15 = 减少 15% 衰减）"),
    "store_vfs.ete2_keyword_bonus": (0.05, float, 0.0, 0.20, None,
        "iter487: 含情绪关键词时额外的衰减减免（默认 0.05）"),
    "store_vfs.ete2_emotion_keywords": (
        ["urgent", "critical", "important", "error", "fail", "success", "breakthrough", "problem", "solve"],
        list, None, None, None,
        "iter487: 触发关键词奖励的情绪关键词列表"),
    "store_vfs.ete2_max_decay_reduction": (0.30, float, 0.0, 0.60, None,
        "iter487: ETE2 最大衰减减免比例（默认 0.30）"),

    # ── iter488: Inhibition of Return (IOR) — 短时间内重复访问同一 chunk 收益递减（Posner 1984）──
    # 认知科学依据：Posner & Cohen (1984) Attention & Performance — 注意力短时间内不会重返刚刚访问的
    #   位置；记忆领域对应：刚访问的 chunk 重复访问时 stability 增益递减（注意力已转移）。
    # OS 类比：Linux madvise(MADV_RANDOM) — 预取器对刚读取的 page 降低预取优先级，资源分配给新页。
    "store_vfs.ior_enabled": (True, bool, None, None, None,
        "iter488: 是否启用 Inhibition of Return（默认 True）"),
    "store_vfs.ior_inhibition_window_secs": (300, int, 30, 3600, None,
        "iter488: 触发 IOR 的重复访问时间窗口（秒，默认 300=5分钟）"),
    "store_vfs.ior_penalty_factor": (0.50, float, 0.0, 1.0, None,
        "iter488: 窗口内重复访问时 stability 增益的衰减系数（默认 0.50 = 减半）"),
    "store_vfs.ior_min_interval_secs": (60, int, 10, 600, None,
        "iter488: 完全抑制所需的最小间隔（秒，默认 60）"),
    "store_vfs.ior_min_importance": (0.15, float, 0.0, 1.0, None,
        "iter488: 触发 IOR 的最低 importance 阈值（默认 0.15）"),

    # ── iter489: Encoding Variability Effect (EVE) — 多样化访问上下文增强长期保留（Martin 1972）──
    # 认知科学依据：Martin (1972) Psych Review — 同一信息在不同上下文中编码，形成多条检索路径，
    #   提升长期保留效果（encoding variability hypothesis）；
    #   同一 chunk 在不同 session_type（对话/检索/写入）中被访问，stability 额外提升。
    # OS 类比：multi-path I/O（DM-multipath） — 同一 block device 通过多条路径访问，
    #   降低单路径失效风险；多条检索路径 = 多路径冗余，降低记忆遗忘概率。
    "store_vfs.eve_enabled": (True, bool, None, None, None,
        "iter489: 是否启用 Encoding Variability Effect（默认 True）"),
    "store_vfs.eve_min_unique_session_types": (2, int, 1, 10, None,
        "iter489: 触发 EVE 所需的最少不同 session_type 数（默认 2）"),
    "store_vfs.eve_bonus_per_type": (0.04, float, 0.0, 0.15, None,
        "iter489: 每个额外不同 session_type 带来的 stability 加成（默认 0.04）"),
    "store_vfs.eve_max_boost": (0.15, float, 0.0, 0.40, None,
        "iter489: EVE 最大 stability 加成比例（默认 0.15 = 15%）"),
    "store_vfs.eve_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter489: 触发 EVE 的最低 importance 阈值（默认 0.20）"),

    # ── iter490: Zeigarnik Effect (ZEF) — 未完成任务 chunk 记忆更持久（Zeigarnik 1927）──
    # 认知科学依据：Zeigarnik (1927) — 未完成任务比已完成任务记忆更持久（持续认知激活）；
    #   chunk 内容含 TODO/FIXME/PENDING/UNRESOLVED 等未完成信号词 → 稳定性更高；
    #   Ovsiankina (1928): 中断任务产生恢复冲动，维持工作记忆激活。
    # OS 类比：dirty page tracking — 含未刷新（dirty）数据的 page 受保护不被回收，
    #   等待 fsync 完成；未完成任务 = dirty page = 受保护的工作状态。
    "store_vfs.zef_enabled": (True, bool, None, None, None,
        "iter490: 是否启用 Zeigarnik Effect（默认 True）"),
    "store_vfs.zef_todo_keywords": (
        ["TODO", "FIXME", "PENDING", "UNRESOLVED", "WIP", "BLOCKED", "IN PROGRESS", "待完成", "未完成"],
        list, None, None, None,
        "iter490: 触发 Zeigarnik Effect 的未完成信号关键词列表"),
    "store_vfs.zef_stability_bonus": (0.12, float, 0.0, 0.40, None,
        "iter490: 含未完成信号时 stability 加成比例（默认 0.12 = 12%）"),
    "store_vfs.zef_max_boost": (0.20, float, 0.0, 0.50, None,
        "iter490: ZEF 最大 stability 加成（默认 0.20 = 20%）"),
    "store_vfs.zef_min_importance": (0.15, float, 0.0, 1.0, None,
        "iter490: 触发 ZEF 的最低 importance 阈值（默认 0.15）"),

    # ── iter491: von Restorff Isolation Effect (VRE) — 与周围不同的 chunk 记忆更深（von Restorff 1933）──
    # 认知科学依据：von Restorff (1933) — 同质列表中的独特项目记忆保留率更高（isolation effect）；
    #   chunk 类型/内容与同 session 其他 chunk 显著不同 → retrieval practice 更有效；
    #   Hunt & Lamb (2001) J Exp Psych — isolation effect 在语义上下文中依然稳健。
    # OS 类比：hot/cold page separation（Linux LRU gen=0 vs gen>0）—
    #   在 cold page 中"热"的孤立 page（LRU gen=0）更难被回收；
    #   独特 chunk = gen=0 hot page in cold pool，保留优先级更高。
    "store_vfs.vre_enabled": (True, bool, None, None, None,
        "iter491: 是否启用 von Restorff Isolation Effect（默认 True）"),
    "store_vfs.vre_rarity_threshold": (0.20, float, 0.0, 1.0, None,
        "iter491: 触发 VRE 的 chunk_type 稀有度阈值（该类型占比低于此值，默认 0.20）"),
    "store_vfs.vre_stability_bonus": (0.10, float, 0.0, 0.30, None,
        "iter491: 稀有类型 chunk 的 stability 加成（默认 0.10 = 10%）"),
    "store_vfs.vre_max_boost": (0.18, float, 0.0, 0.40, None,
        "iter491: VRE 最大 stability 加成（默认 0.18 = 18%）"),
    "store_vfs.vre_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter491: 触发 VRE 的最低 importance 阈值（默认 0.20）"),
    "store_vfs.vre_min_session_chunks": (3, int, 1, 50, None,
        "iter491: 计算稀有度所需的最少 session chunk 数（默认 3）"),

    # ── iter492: Production Effect (PEF) — 大声朗读比默读产生更强记忆（MacLeod 2010）──
    # 认知科学依据：MacLeod et al. (2010) J Exp Psych — 大声朗读（production effect）比
    #   默读在再认测试中高 ~10-15%；更高质量的处理操作（production/write）= 更深编码。
    #   chunk_type=decision/observation/reflection 等"输出类"操作 → stability 额外奖励。
    # OS 类比：write-back vs write-through cache — 写回操作（生产型 chunk）
    #   需要额外处理，但数据一致性更高，equivalent 生命周期更长。
    "store_vfs.pef_enabled": (True, bool, None, None, None,
        "iter492: 是否启用 Production Effect（默认 True）"),
    "store_vfs.pef_production_types": (
        ["decision", "reflection", "hypothesis", "insight", "action"],
        list, None, None, None,
        "iter492: 视为'输出类操作'的 chunk_type 列表（这些类型获得 production bonus）"),
    "store_vfs.pef_stability_bonus": (0.08, float, 0.0, 0.25, None,
        "iter492: 输出类 chunk_type 的 stability 加成（默认 0.08 = 8%）"),
    "store_vfs.pef_max_boost": (0.15, float, 0.0, 0.35, None,
        "iter492: PEF 最大 stability 加成（默认 0.15 = 15%）"),
    "store_vfs.pef_min_importance": (0.15, float, 0.0, 1.0, None,
        "iter492: 触发 PEF 的最低 importance 阈值（默认 0.15）"),
    # ── iter450: Completion Effect (CEF) — 已完成任务 importance 降低（Ovsiankina 1928）──
    # 认知科学依据：Ovsiankina (1928) — 已完成任务失去"认知张力"，不再主动维持记忆优先级
    # OS 类比：dirty page writeback 完成后清除 PG_dirty，kswapd 可自由回收。
    "store_vfs.cef_enabled": (True, bool, None, None, None,
        "iter450: 是否启用 Completion Effect（默认 True）"),
    "store_vfs.cef_completion_keywords": (
        ["DONE", "RESOLVED", "FIXED", "CLOSED", "COMPLETED", "MERGED", "SHIPPED",
         "已完成", "已解决", "已修复", "已关闭", "完成", "解决"],
        list, None, None, None,
        "iter450: 触发 Completion Effect 的完成信号关键词列表"),
    "store_vfs.cef_importance_reduction": (0.05, float, 0.0, 0.20, None,
        "iter450: 每次触发时降低的 importance 值（默认 0.05）"),
    "store_vfs.cef_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter450: importance 降低的下限（默认 0.20）"),
    "store_vfs.cef_trigger_min_importance": (0.35, float, 0.0, 1.0, None,
        "iter450: 触发 CEF 的 importance 最低阈值（默认 0.35）"),

    # ── iter451: Retrieval Difficulty Gradient (RDG) — 趋势困难检索获得更大加成（Bjork & Bjork 1992）──
    # 认知科学依据：单点 retrievability 低可能是噪声；持续低 R + 高 spaced_access_count = 真正的边缘成功
    # OS 类比：Linux adaptive readahead — 连续 miss 趋势 → 扩大预取窗口（趋势驱动，非快照驱动）
    "store_vfs.rdg_enabled": (True, bool, None, None, None,
        "iter451: 是否启用 Retrieval Difficulty Gradient（默认 True）"),
    "store_vfs.rdg_max_retrievability": (0.40, float, 0.0, 1.0, None,
        "iter451: 触发 RDG 的可达性上限（低于此值才算困难，默认 0.40）"),
    "store_vfs.rdg_min_spaced": (3, int, 1, 20, None,
        "iter451: 触发 RDG 的最低间隔成功检索次数（spaced_access_count >= 此值，默认 3）"),
    "store_vfs.rdg_spaced_ref": (10, int, 1, 50, None,
        "iter451: 间隔检索次数的归一化参考值（次数=此值时 gradient=1.0，默认 10）"),
    "store_vfs.rdg_scale": (0.12, float, 0.0, 0.50, None,
        "iter451: RDG 加成缩放系数（bonus = gradient × (1-R) × scale，默认 0.12）"),
    "store_vfs.rdg_max_stability": (30.0, float, 1.0, 365.0, None,
        "iter451: stability 高于此值不触发 RDG（已很稳固，默认 30.0 天）"),
    "store_vfs.rdg_min_importance": (0.30, float, 0.0, 1.0, None,
        "iter451: 触发 RDG 的最低 importance 阈值（默认 0.30）"),

    # ── iter434: Retrieval-Induced Forgetting (RIF) — 检索导致相关记忆被压制（Anderson et al. 1994）──
    # 认知科学依据：Anderson, Bjork & Bjork (1994) "Remembering can cause forgetting" —
    #   检索某条记忆（practiced item）会主动抑制同类别中相关但未被检索的记忆（unpracticed items）。
    #   机制：检索激活该类别所有竞争记忆 → 强化被选中者（RP+）→ 主动抑制被压制者（RP-）→ RP- 遗忘增加。
    #   效果：测验后被练习项目增强记忆，相关未练习项目遗忘更多（比基线低 ~10-20%）。
    #   条件：RIF 要求被抑制者与被检索者属于同一类别（category-based competition）。
    #
    # memory-os 等价：
    #   检索命中 chunk_A → 对同类型（chunk_type）且内容相似（Jaccard >= threshold）的未命中 chunk_B
    #   施加轻微 stability 惩罚（× rif_factor < 1.0）。
    #   体现竞争抑制：被频繁检索的 chunk 越来越强，其竞争者越来越弱 → 系统自然专注核心知识。
    #
    # OS 类比：CPU cache set-associativity conflict eviction —
    #   访问 cache line A（命中 set 0, way 0）→ 通过 LRU 策略将同 set 的竞争 cache line B 推向更高 way
    #   → 再次访问 B 的概率降低（等价于 RIF：A 的命中加速了 B 的驱逐路径）。
    "scorer.rif_enabled": (True, bool, None, None, None,
        "iter434: 是否启用 Retrieval-Induced Forgetting — 检索 chunk 时轻微抑制同类相关但未命中的 chunk"),
    "scorer.rif_factor": (0.95, float, 0.80, 1.0, None,
        "iter434: RIF 抑制系数（被抑制 chunk stability × rif_factor，默认 0.95 = 5% 下降）"),
    "scorer.rif_similarity_threshold": (0.25, float, 0.0, 1.0, None,
        "iter434: RIF 触发的最低 Jaccard 相似度（0.25 = 至少 25% 词汇重叠才视为竞争者）"),
    "scorer.rif_max_targets": (3, int, 1, 20, None,
        "iter434: 每个命中 chunk 最多抑制的竞争者数量（按 Jaccard 降序，取前 N 个）"),
    "scorer.rif_protect_importance": (0.85, float, 0.0, 1.0, None,
        "iter434: importance >= 此值的 chunk 豁免 RIF 抑制（核心知识不被竞争压制）"),
    "scorer.rif_protect_types": ("design_constraint,procedure", str, None, None, None,
        "iter434: 豁免 RIF 的 chunk_type 列表（逗号分隔；保护类型即使相似也不被抑制）"),

    # ── iter432: Cumulative Interference Effect — 累积干扰加速遗忘（Underwood 1957）──
    # 认知科学依据：Underwood (1957) "Interference and forgetting" —
    #   遗忘的主要原因是同类型知识的累积干扰（proactive interference from prior lists），
    #   而非单纯时间流逝（decay theory）。同类型知识越多，每个 chunk 的遗忘越快。
    #   Jenkins & Dallenbach (1924): 睡眠期间比清醒期间遗忘更少，因为睡眠减少了新干扰。
    #   Underwood 1957 回归分析：24小时遗忘量与已学干扰列表数的相关 r=0.92（极强）。
    # 应用：同项目同 chunk_type 数量越多（N_same_type）→ 单个 chunk 的 stability 衰减更快。
    #   cumulative_interference_factor = 1 + scale × log(1+N) / log(1+N_median)
    #   在 episodic_decay_scan 中额外乘以 1/factor（>1 = 加速衰减）。
    # OS 类比：Linux CPU cache set-associativity conflict —
    #   同一 cache set 中的 cache line 越多，每条 line 的平均留存时间越短
    #   （more ways used = higher conflict miss rate = faster eviction）。
    "scorer.cumulative_interference_enabled": (True, bool, None, None, None,
        "iter432: 是否启用累积干扰效应——同类型 chunk 越多，每个 chunk 的 stability 衰减越快"),
    "scorer.ci_scale": (0.30, float, 0.0, 1.0, None,
        "iter432: 累积干扰强度系数：factor = 1 + scale × log(1+N)/log(1+N_med)，越大干扰越强"),
    "scorer.ci_max_factor": (2.0, float, 1.0, 5.0, None,
        "iter432: 累积干扰因子上限（最多让 stability 衰减 1/max_factor 倍，防止过激）"),
    "scorer.ci_protect_types": ("design_constraint,procedure", str, None, None, None,
        "iter432: 豁免累积干扰的 chunk_type 列表（逗号分隔；核心知识不受数量压制）"),
    "scorer.ci_min_n_same_type": (5, int, 1, 50, None,
        "iter432: 触发干扰效应的最低同类型 chunk 数量（N_same_type < 此值时不应用干扰）"),

    # ── iter431: Ribot's Law — 远期记忆稳定性梯度（Ribot 1882）──────────────────
    # 认知科学依据：Théodule Ribot (1882) "Diseases of Memory" —
    #   越早形成的记忆越能抵抗损伤（retrograde amnesia gradient）。
    #   脑损伤患者失去近期记忆，但保留远期（远古）的记忆——因为远期记忆已被"新皮层化"
    #   （hippocampal → neocortical transfer，系统巩固理论）。
    # 应用：chunk 年龄（age_days）越大 + importance >= ribot_min_importance →
    #   Ebbinghaus 遗忘曲线的 stability_floor 随年龄对数增长。
    #   floor_bonus = min(ribot_max_bonus, log(1+age_days)/log(365) × ribot_scale)
    #   年龄 1 年（365天）→ floor_bonus 达到 ribot_max_bonus。
    # OS 类比：Linux ext4 journal aging —
    #   长时间存在的 inode（ancient inodes）在 extent tree 中有更稳定的布局，
    #   碎片整理操作会优先保留而非移动 ancient extents（structural stability gradient）。
    "scorer.ribot_enabled": (True, bool, None, None, None,
        "iter431: 是否启用 Ribot's Law — 年龄越大的 chunk stability_floor 越高"),
    "scorer.ribot_min_importance": (0.60, float, 0.0, 1.0, None,
        "iter431: 应用 Ribot's Law 的最低 importance 阈值（低重要性老 chunk 不受保护）"),
    "scorer.ribot_scale": (0.20, float, 0.0, 1.0, None,
        "iter431: Ribot 稳定性梯度系数：floor_bonus = log(1+age_days)/log(365) × scale，"
        "age=365d 时 bonus=0.20，age=30d 时 bonus≈0.09"),
    "scorer.ribot_max_bonus": (0.25, float, 0.0, 0.5, None,
        "iter431: Ribot floor_bonus 上限（防止超长历史 chunk 的 floor 过高）"),
    "scorer.ribot_min_age_days": (30, int, 7, 365, None,
        "iter431: 开始应用 Ribot's Law 的最小年龄（天），默认 30 天"),

    # ── dmesg（迭代29）──
    "dmesg.ring_buffer_size": (500, int, 10, 5000, None,
        "dmesg 环形缓冲区最大条目数"),
    "dmesg.ratelimit_interval_s": (30, int, 0, 300, None,
        "iter538: printk_ratelimit 去重窗口（秒），0=禁用"),

    # ── kswapd watermarks（迭代30）──
    "kswapd.pages_low_pct": (80, int, 50, 95, None,
        "low watermark 百分比：低于此水位触发后台预淘汰"),
    "kswapd.pages_high_pct": (90, int, 60, 99, None,
        "high watermark 百分比：高于此水位停止淘汰（安全区）"),
    "kswapd.pages_min_pct": (95, int, 80, 100, None,
        "min watermark 百分比：高于此水位触发同步硬淘汰（OOM）"),
    "kswapd.stale_days": (90, int, 14, 365, None,
        "超过此天数未访问的 chunk 标记为可回收（stale page）"),
    "kswapd.batch_size": (5, int, 1, 50, None,
        "每次 kswapd 扫描最多淘汰的 chunk 数"),

    # ── compaction（迭代31）──
    "compaction.min_cluster_size": (3, int, 2, 20, None,
        "触发 compaction 的最小聚类大小（同主题 chunk 数）"),
    "compaction.max_merge_per_run": (10, int, 1, 50, None,
        "每次 compaction 最多合并的聚类数"),
    "compaction.entity_overlap_min": (2, int, 1, 10, None,
        "聚类所需的最小共享实体数"),

    # ── madvise（迭代32）──
    "madvise.boost_factor": (0.15, float, 0.0, 0.5, None,
        "hint 匹配的 chunk 召回加分（叠加在 retrieval_score 上）"),
    "madvise.max_hints": (10, int, 3, 30, None,
        "每个项目最多保留的 hint 关键词数"),
    "madvise.ttl_secs": (1800, int, 300, 7200, None,
        "hint 有效期（秒），超过则忽略"),

    # ── swap（迭代33）──
    "swap.max_chunks": (100, int, 10, 1000, None,
        "swap 分区最大 chunk 数（超出时删除最旧 swap 条目）"),
    "swap.min_importance_for_swap": (0.5, float, 0.0, 1.0, None,
        "低于此 importance 的 chunk 直接删除而非 swap out"),
    "swap.fault_top_k": (2, int, 1, 10, None,
        "swap fault 时最多 swap in 的 chunk 数"),

    # ── iter430: Spontaneous Recovery — 自发恢复（Pavlov 1927）──────────────────
    # 认知科学依据：Pavlov (1927) — 条件反射被抑制后经过休息可自发恢复（不需额外强化）。
    #   Rescorla (1997): 恢复程度与休息时间正相关。
    #   应用：被 kswapd 驱逐到 swap 的高历史访问 chunk 经过一段时间后可自发恢复。
    # OS 类比：Linux zswap 解压缩 + MGLRU active 列表晋升 —
    #   swap 分区中的页面在满足热度条件时被自动提升回 active 列表。
    "swap.sr_enabled": (True, bool, None, None, None,
        "iter430: 是否启用 Spontaneous Recovery — swap 中高历史价值 chunk 的自发恢复"),
    "swap.sr_min_swap_days": (3.0, float, 0.5, 90.0, None,
        "iter430: 在 swap 中至少 N 天才触发自发恢复（防止抖动）"),
    "swap.sr_min_access_count": (3, int, 1, 50, None,
        "iter430: 历史访问次数阈值：>= N 次才视为'曾经重要'的 chunk"),
    "swap.sr_min_importance": (0.65, float, 0.3, 1.0, None,
        "iter430: importance 阈值：>= 此值的 chunk 才参与自发恢复"),
    "swap.sr_recovery_boost": (1.15, float, 1.0, 2.0, None,
        "iter430: stability 恢复系数 — swap in 时 stability × boost（默认 1.15 ≈ 15% 提升）"),
    "swap.sr_max_recover_per_run": (5, int, 1, 50, None,
        "iter430: 每次 SessionStart 最多恢复的 chunk 数量（限制 swap in I/O）"),

    # ── OOM Score（迭代38）──
    "oom.auto_protect_quant": (-500, int, -1000, 0, None,
        "量化证据 chunk 的自动 oom_adj（负值=保护）"),
    "oom.auto_disposable_ctx": (500, int, 0, 1000, None,
        "prompt_context chunk 的自动 oom_adj（正值=优先淘汰）"),

    # ── cgroup v2 memory.high（迭代40）──
    "cgroup.memory_high_pct": (85, int, 50, 95, None,
        "软配额水位百分比：超过时 throttle 新写入（降 importance + 加 oom_adj）"),
    "cgroup.throttle_factor": (0.7, float, 0.3, 1.0, None,
        "throttle 区间内新写入 importance 的衰减因子（乘法）"),
    "cgroup.throttle_oom_adj": (300, int, 0, 1000, None,
        "throttle 区间内新写入 chunk 的自动 oom_adj（正值=加速回收）"),

    # ── COW 预扫描（迭代39）──
    "extractor.cow_prescan_chars": (3000, int, 500, 10000, None,
        "COW 预扫描采样字符数（只扫描消息前 N 个字符）"),

    # ── iter392：Generation Effect — 主动生成增强 ──
    # 认知科学：Slamecka & Graf (1978) Generation Effect —
    #   自己生成的内容（vs 被动阅读）记忆留存率显著更高（+50%~+80%）。
    #   主动生成触发更深度认知加工（elaborative encoding），形成更强记忆痕迹。
    # 应用：reasoning_chain / decision 是 agent 主动生成的推理产物，
    #   写入时给予 stability 额外乘子，使其在 Ebbinghaus 曲线下衰减更慢。
    "extractor.generation_boost_enabled": (True, bool, None, None, None,
        "是否对 agent 主动生成类 chunk（reasoning_chain/decision）应用 generation effect stability 加成（iter392）"),
    "extractor.generation_boost_factor": (1.2, float, 1.0, 2.0, None,
        "生成效应稳定性加成系数：reasoning_chain/decision 的 stability 初始值乘以此系数（iter392，默认 1.2）"),
    "extractor.generation_boost_types": ("reasoning_chain,decision,causal_chain", str, None, None, None,
        "应用 generation_boost 的 chunk_type 集合（逗号分隔，iter392）"),

    # ── iter406: Generation Effect — Lexical Marker Detection ──────────────────
    "store_vfs.generation_effect_enabled": (True, bool, None, None, None,
        "是否启用 iter406 Generation Effect：检测内容中的推理/假设/元认知标记，对主动生成内容提升 stability"),
    "store_vfs.generation_effect_source_direct_bypass": (True, bool, None, None, None,
        "source_type='direct' 时跳过生成效应检测（人直接输入=被动录入，非 agent 生成），默认 True"),

    # ── iter407: Von Restorff Effect — Isolation Stability Bonus ─────────────────
    "store_vfs.isolation_effect_enabled": (True, bool, None, None, None,
        "是否启用 iter407 Von Restorff Effect：孤立 chunk（encode_context 语义独特）得到 stability 加成"),
    "store_vfs.isolation_context_window": (20, int, 5, 100, None,
        "iter407: 计算语义孤立度时对比的最近邻居数量（基于 created_at 排序）"),
    "store_vfs.isolation_min_neighbors": (3, int, 1, 20, None,
        "iter407: 邻居少于此数时返回 0.0 孤立度（避免项目初期误判所有 chunk 为孤立）"),

    # ── iter408: Proactive Interference — 旧知识干扰新知识写入 ─────────────────────
    "store_vfs.pi_enabled": (True, bool, None, None, None,
        "是否启用 iter408 Proactive Interference：旧强记忆干扰新 chunk 写入时的 initial stability"),
    "store_vfs.pi_search_k": (5, int, 1, 20, None,
        "iter408: 计算 PI 时检索的语义邻居数量"),
    "store_vfs.pi_strong_acc_threshold": (3, int, 1, 50, None,
        "iter408: 视为'强旧记忆'的 access_count 阈值（≥ 此值才产生 PI 压力）"),
    "store_vfs.pi_max_penalty": (0.10, float, 0.0, 0.30, None,
        "iter408: PI 最大惩罚（从 base_stability 中减去的上限，默认 0.10）"),

    # ── iter409: Flashbulb Memory — 情绪性内容写入时 stability 加强 ────────────────
    "store_vfs.flashbulb_enabled": (True, bool, None, None, None,
        "是否启用 iter409 Flashbulb Memory：emotional_weight 高的 chunk 写入时 stability 加强"),
    "store_vfs.flashbulb_strong_threshold": (0.70, float, 0.3, 1.0, None,
        "iter409: 强情绪唤醒阈值（≥ 此值获得最大加成 base×0.30）"),
    "store_vfs.flashbulb_medium_threshold": (0.50, float, 0.1, 0.9, None,
        "iter409: 中等情绪唤醒阈值（[medium, strong) 区间线性插值加成）"),

    # ── iter410: Primacy Effect — 首位效应（Murdock 1962 Serial Position Effect）──
    "store_vfs.primacy_enabled": (True, bool, None, None, None,
        "是否启用 iter410 Primacy Effect：项目最早创建的 chunk 获得 stability 首位加成"),
    "store_vfs.primacy_min_total": (20, int, 5, 200, None,
        "iter410: 项目 chunk 总数低于此值时不应用首位效应（避免新项目误判）"),
    "store_vfs.primacy_core_pct": (0.10, float, 0.02, 0.30, None,
        "iter410: 最早 N% 的 chunk 获得完整首位加成（默认最早 10%）"),

    # ── iter411: Levels of Processing — 编码深度（Craik & Lockhart 1972）─────────
    "store_vfs.lop_enabled": (True, bool, None, None, None,
        "是否启用 iter411 Levels of Processing：encode_context 实体密度代理编码深度 → stability 加成"),

    # ── iter414: Self-Reference Effect — 自我参照内容的记忆优势 ─────────────────────
    # 认知科学依据：Rogers et al. (1977) Self-Reference Effect —
    #   以"与自我相关"方式加工的信息比语义加工的记忆更强（self-referential processing 激活 PFC + hippocampus）。
    #   Symons & Johnson (1997) Meta-analysis: self-reference advantage ≈ +0.5 SD vs semantic encoding。
    #   在 memory-os 中：chunk 内容含第一人称标记（I/we/our/my）或 agent 自身推理产物，
    #   代理"自我参照"加工，initial stability 获得加成。
    # OS 类比：Linux process 自身页（stack/heap/text）在 TLB 中有最高局部性 —
    #   process 直接引用的 page（自我参照）命中率最高，类比 self-referential chunk 的检索优势。
    "store_vfs.self_ref_enabled": (True, bool, None, None, None,
        "是否启用 iter414 Self-Reference Effect：含第一人称标记的 chunk 获得 stability 加成"),
    "store_vfs.self_ref_bonus_cap": (0.25, float, 0.0, 0.50, None,
        "iter414: Self-Reference Effect stability 加成上限（作为 base × 此系数，默认 0.25）"),

    # ── iter415: Encoding Variability — 多情境编码的记忆鲁棒性 ────────────────────
    # 认知科学依据：Estes (1955) Encoding Variability Theory; Bjork & Bjork (1992) New Theory of Disuse —
    #   同一记忆在多个不同情境下编码 → 更多检索线索 → 在多样化情境下均可提取（retrieval robustness）。
    #   Glenberg (1979): 分布式练习效果部分来自情境多样性（context diversification across repetitions）。
    # 实现：encode_context token 数量随 iter404 语义启动而增长；token 数超过初始值越多，
    #   代表访问情境越多样，在 update_accessed 时给予轻微 stability 加成。
    # OS 类比：Linux 共享库被 N 个进程引用 → page cache 引用计数高 → 驱逐优先级低（多情境引用 = 更稳定）。
    "store_vfs.encoding_variability_enabled": (True, bool, None, None, None,
        "是否启用 iter415 Encoding Variability：encode_context 增长（多情境访问）→ stability 加成"),
    "store_vfs.encoding_variability_scale": (0.05, float, 0.0, 0.20, None,
        "iter415: 每个新增 encode_context token 的 stability 加成系数（默认 0.05，上限 base × 0.15）"),

    # ── iter416: Zeigarnik Effect — 未完成任务的记忆优势 ──────────────────────────────
    # 认知科学依据：Zeigarnik (1927) — 未完成任务比已完成任务被记忆得更好（+90% recall superiority）。
    #   Lewin (1935) Tension System Theory — 未完成任务在认知系统中维持"心理张力"，
    #   保持记忆激活直到任务完成（类比未释放的 futex 锁）。
    #   Ovsiankina (1928) — 被中断的任务在有机会时自发恢复（resumption tendency）。
    # 应用：chunk 内容含 TODO/FIXME/pending/unresolved 信号词 → 代表"未完成"认知任务，
    #   给予 stability 加成，防止被 kswapd 过早驱逐（这些信息最需要在下次会话中恢复）。
    # OS 类比：Linux futex waitqueue / O_SYNC dirty page —
    #   待处理的 I/O 请求保留在内核等待队列，不被 swapd 驱逐；
    #   未完成写入的 dirty page 被 writeback 守护进程跟踪，优先处理。
    "store_vfs.zeigarnik_enabled": (True, bool, None, None, None,
        "是否启用 iter416 Zeigarnik Effect：含未完成任务信号词的 chunk 获得 stability 加成"),
    "store_vfs.zeigarnik_bonus_cap": (0.20, float, 0.0, 0.50, None,
        "iter416: Zeigarnik Effect stability 加成上限（作为 base × 此系数，默认 0.20）"),

    # ── iter417: Retrieval-Induced Forgetting — 检索引发的竞争性抑制 ─────────────────
    # 认知科学依据：Anderson, Bjork & Bjork (1994) "Remembering can cause forgetting" —
    #   检索一个记忆时，与之竞争的语义邻居记忆受到主动抑制（inhibitory tagging）。
    #   抑制强度与语义相似度正相关（高相似 = 强竞争 = 更多抑制）。
    #   MacLeod et al. (2003): RIF 是真实的记忆抑制（non-retrieval 控制组无此效应）。
    # 应用：update_accessed 时，对语义邻居（高 encode_context token 重叠但未被检索）
    #   应用轻微 stability 衰减，模拟竞争性抑制，促进检索多样性。
    # OS 类比：MESI 缓存一致性协议 —
    #   一个核写入 cache line（Modified状态）→ 其他核的相同 cache line 被 Invalidated；
    #   一个 chunk 被"激活"→ 其语义竞争者的局部性降低（类比 cache invalidation）。
    "store_vfs.rif_enabled": (True, bool, None, None, None,
        "是否启用 iter417 Retrieval-Induced Forgetting：检索时对语义竞争者施加轻微 stability 衰减"),
    "store_vfs.rif_decay_factor": (0.99, float, 0.90, 1.00, None,
        "iter417: RIF stability 衰减因子（neighbor stability × 此值），默认 0.99（轻微 1% 衰减）"),
    "store_vfs.rif_min_overlap": (2, int, 1, 10, None,
        "iter417: 触发 RIF 所需的最小 encode_context token 重叠数（2 token 重叠 = 语义竞争者）"),
    "store_vfs.rif_max_neighbors": (5, int, 1, 20, None,
        "iter417: 每次检索最多影响的语义邻居数量（按 overlap 降序取前 N）"),

    # ── iter418: Directed Forgetting — 主动弃置过时知识 ──────────────────────────────
    # 认知科学依据：MacLeod (1998) Directed Forgetting —
    #   主动指令"忘记"某信息时，记忆对该信息的保留显著下降（inhibition account）。
    #   Johnson (1994): 认知系统主动抑制不再有用的记忆，释放认知资源。
    # 应用：chunk 内容含 deprecated/obsolete/replaced by 等信号词 → 主动减少 stability，
    #   加速 kswapd 自然淘汰（不强制删除，而是降低其竞争力）。
    # OS 类比：Linux madvise(MADV_DONTNEED) —
    #   显式通知内核该内存区域不再需要，内核加速回收（但不立即释放，等 kswapd 处理）。
    "store_vfs.df_enabled": (True, bool, None, None, None,
        "是否启用 iter418 Directed Forgetting：含过时信号词的 chunk 获得 stability 惩罚"),
    "store_vfs.df_penalty_cap": (0.15, float, 0.0, 0.50, None,
        "iter418: Directed Forgetting stability 惩罚上限（从 base 减去 base × 此系数，默认 0.15）"),

    # ── iter422: Permastore Memory — 充分强化后的记忆永久保护（Bahrick 1979）──────────────
    # 认知科学依据：Bahrick (1979) — 充分访问+高重要性的记忆达到"permastore"状态，
    #   即使经过数十年不复习，仍能保留约 80% 的可访问性。
    #   Conway et al. (1991): 专业知识具有 permastore 特征。
    # 应用：chunk 满足 age>=30d + access_count>=10 + importance>=0.80 →
    #   RI/RIF/DF 只能降低到 stability×floor_factor(0.80)（而非普通 floor=0.1）。
    # OS 类比：Linux mlock() — 重要页面锁定在 RAM，kswapd 无法驱逐。
    "store_vfs.permastore_enabled": (True, bool, None, None, None,
        "是否启用 iter422 Permastore Memory：充分访问+高重要性 chunk 的 stability 受更高 floor 保护"),
    "store_vfs.permastore_min_age_days": (30, int, 7, 365, None,
        "iter422: 进入 permastore 所需的最小 chunk 年龄（天），默认 30 天"),
    "store_vfs.permastore_min_access_count": (10, int, 3, 100, None,
        "iter422: 进入 permastore 所需的最小访问次数，默认 10 次"),
    "store_vfs.permastore_min_importance": (0.80, float, 0.3, 1.0, None,
        "iter422: 进入 permastore 所需的最低 importance，默认 0.80"),
    "store_vfs.permastore_floor_factor": (0.80, float, 0.3, 1.0, None,
        "iter422: permastore chunk 的 stability 下限系数（stability × factor），默认 0.80"),

    # ── iter421: Retroactive Interference — 新学习干扰旧记忆回忆 ─────────────────────────
    # 认知科学依据：McGeoch (1932) Interference Theory; Barnes & Underwood (1959) —
    #   新学习的信息（新 chunk）干扰对旧相关信息的回忆（retroactive interference）。
    #   RI 与 PI（iter408）互补：PI=旧→新，RI=新→旧。
    #   Anderson & Green (2001): 主动抑制相似记忆是 RI 的神经机制。
    # 应用：insert_chunk 时，对同项目中 encode_context 高度重叠的低 importance 旧 chunk
    #   施加轻微 stability 衰减（× ri_decay_factor=0.98），模拟新记忆干扰旧记忆。
    #   高重要性（>= ri_protect_importance=0.85）的 chunk 免疫 RI。
    # OS 类比：TLB shootdown — 新 VA→PA 映射建立时，发送 IPI 使其他核的旧 TLB 条目失效。
    "store_vfs.ri_enabled": (True, bool, None, None, None,
        "是否启用 iter421 Retroactive Interference：新 chunk 写入时对语义邻居旧 chunk 施加轻微 stability 衰减"),
    "store_vfs.ri_min_overlap": (2, int, 1, 10, None,
        "iter421: 触发 RI 的最小 encode_context token 重叠数（默认 2）"),
    "store_vfs.ri_decay_factor": (0.98, float, 0.90, 1.00, None,
        "iter421: RI stability 衰减因子（旧 chunk stability × 此值，默认 0.98，轻微 2% 衰减）"),
    "store_vfs.ri_max_targets": (3, int, 1, 10, None,
        "iter421: 每次 insert_chunk 最多影响的旧 chunk 数量（按重叠度降序取前 N）"),
    "store_vfs.ri_protect_importance": (0.85, float, 0.5, 1.0, None,
        "iter421: importance >= 此值的 chunk 免疫 RI（高重要性核心知识受保护）"),

    # ── iter420: Spacing Effect — 分布式练习的记忆优势（间隔效应）────────────────────────
    # 认知科学依据：Ebbinghaus (1885) Spacing Effect; Cepeda et al. (2006) Review (300+ studies) —
    #   分布式练习（相同次数的学习，分散在多个时间间隔）比集中练习产生更强的长时记忆保留。
    #   Glenberg (1979): 情境多样性（context diversity across repetitions）是间隔效应的核心机制。
    #   间隔效应与 iter412 Testing Effect 相互增强（间隔越长 → 难度越高 → 双重加成）。
    # 应用：update_accessed 时，若访问间隔 >= medium_gap_hours(24h)，spaced_access_count+1。
    #   spacing_factor = spaced_access_count / max(1, access_count)；
    #   SM-2 quality += round(spacing_factor × spacing_quality_scale)（最大 +2）。
    # OS 类比：Linux MGLRU cross-generation promotion —
    #   跨 aging cycle 的 page 访问比同 gen 内多次访问更快晋升（distributed > massed）。
    "store_vfs.spacing_effect_enabled": (True, bool, None, None, None,
        "是否启用 iter420 Spacing Effect：访问间隔 >= 24h 时递增 spaced_access_count，影响 SM-2 质量"),
    "store_vfs.spacing_quality_scale": (2.0, float, 0.0, 4.0, None,
        "iter420: Spacing Effect SM-2 quality 加成系数：quality_bonus = round(spacing_factor × scale)，最大 +2"),

    # ── iter419: Associative Memory — 新知识借助强关联记忆的编码优势 ────────────────────
    # 认知科学依据：Ebbinghaus (1885) Paired Associates Learning;
    #   Collins & Loftus (1975) Spreading Activation — 新知识与已有强记忆共享节点时
    #   形成更强的记忆痕迹（associative encoding advantage, 类比"锚点记忆"）。
    #   Anderson & Reder (1999): 高连接度节点的新关联比孤立节点更易编码（fan effect 逆向）。
    # 应用：写入新 chunk 时，如果其 encode_context 与已有高 importance 的 chunk 重叠 ≥ 阈值，
    #   给予 stability 加成（借助已有强记忆结构"搭架"）。
    # OS 类比：Linux huge pages (THP) — small page adjacent to huge page shares same TLB entry
    #   and benefits from the huge page's TLB locality (associative memory locality)。
    "store_vfs.am_enabled": (True, bool, None, None, None,
        "是否启用 iter419 Associative Memory：新 chunk 与高 importance 旧 chunk 共享实体 → stability 加成"),
    "store_vfs.am_min_overlap": (2, int, 1, 10, None,
        "iter419: 触发关联记忆加成的最小 encode_context token 重叠数"),
    "store_vfs.am_min_importance": (0.75, float, 0.3, 1.0, None,
        "iter419: 触发关联记忆加成的锚点 chunk 的最低 importance 阈值"),
    "store_vfs.am_bonus_cap": (0.15, float, 0.0, 0.40, None,
        "iter419: 关联记忆加成上限（base × 此系数，默认 0.15）"),

    # ── Deadline I/O Scheduler（迭代41）──
    "retriever.deadline_ms": (50.0, float, 5.0, 200.0, None,
        "检索截止时间（ms），超过时跳过低优先级阶段（从30ms调整为50ms，适应VFS+PSI开销）"),
    "retriever.deadline_hard_ms": (200.0, float, 20.0, 500.0, None,
        "硬截止时间（ms），超过时立即返回已有结果（从80ms调整为200ms，避免WAL争用下的空结果）"),

    # ── ASLR 检索多样性（迭代43）──
    "scorer.aslr_epsilon": (0.08, float, 0.0, 0.3, None,
        "ASLR 随机扰动幅度上限（乘以 1-access_ratio 后叠加到 retrieval_score）"),
    "scorer.aslr_access_threshold": (5, int, 1, 50, None,
        "ASLR 生效阈值：access_count 低于此值的 chunk 才获得随机扰动"),

    # ── Anti-Starvation（迭代62）──
    "scorer.saturation_factor": (0.04, float, 0.0, 0.15, None,
        "饱和惩罚系数：penalty = factor × log2(1 + recall_count)，越大惩罚越重"),
    "scorer.saturation_cap": (0.25, float, 0.05, 0.50, None,
        "饱和惩罚上限：防止热门知识被完全压制"),

    # ── 迭代333：TMV Multiplicative Saturation Discount ──
    # OS 类比：Linux NUMA distance penalty — access_count 极高的 chunk 类似 remote NUMA node，
    #   边际信息价值趋近于零（agent 已经"内化"），需要乘法折扣而非加法惩罚。
    "scorer.tmv_acc_threshold": (50, int, 10, 500, None,
        "TMV 饱和折扣起始阈值：access_count 超过此值开始应用乘法折扣"),
    "scorer.tmv_discount_weight": (0.30, float, 0.0, 0.60, None,
        "TMV 折扣强度：score × (1 - discount_weight × log(acc/threshold) / log(1000/threshold))，"
        "acc=2044/threshold=50 时 discount=0.30×(log(41)/log(20))≈0.39，最大降权 39%"),
    "scorer.tmv_discount_floor": (0.55, float, 0.30, 0.95, None,
        "TMV 折扣下限乘子：无论 acc 多高，score 不低于原始的此比例（防止 design_constraint 被过度压制）"),
    "scorer.tmv_session_density_gate": (4, int, 2, 10, None,
        "Session 密度门控：同一 chunk 在本 session 被注入 >= 此次数时，额外乘以 0.7（防止信息茧房）"),
    "scorer.starvation_boost_factor": (0.30, float, 0.05, 0.60, None,
        "饥饿加分系数：access_count=0 的老 chunk 最大加分值"),
    "scorer.starvation_min_age_days": (0.5, float, 0.0, 7.0, None,
        "饥饿加分最小年龄：低于此天数不加分（freshness_bonus 仍在生效）"),
    "scorer.starvation_ramp_days": (3.0, float, 0.5, 14.0, None,
        "饥饿加分线性增长区间：从 min_age 到 min_age+ramp_days 线性增长到满额"),

    # ── cgroup_cpu_max（iter527）——
    "scorer.bw_max_pct": (0.30, float, 0.10, 0.80, None,
        "带宽上限：chunk 在 window 内 recall_count/window 超过此比例时触发硬限"),
    "scorer.bw_throttle": (0.15, float, 0.01, 0.50, None,
        "超额后乘法因子（0.15=削减85%分数），类似 cpu.max quota exhausted 后 throttle"),
    "scorer.bw_window": (30, int, 10, 100, None,
        "带宽计算的 recall_traces 窗口大小（与 chunk_recall_counts window 一致）"),

    # ── Memory Balloon（迭代46）──
    "balloon.global_pool": (1000, int, 100, 10000, None,
        "全局 chunk 总量池（所有项目共享），各项目配额从此池中动态分配"),
    "balloon.min_quota": (30, int, 10, 500, None,
        "每个项目的最低保障配额（即使不活跃也不低于此值）"),
    "balloon.max_quota": (500, int, 50, 5000, None,
        "单项目配额上限（即使活跃度最高也不超过此值）"),
    "balloon.activity_window_days": (14, int, 3, 90, None,
        "活跃度计算时间窗口（天），只统计此窗口内的写入/访问活动"),

    # ── MGLRU（迭代44）──
    "mglru.max_gen": (4, int, 2, 10, None,
        "MGLRU 最大代数（gen 0=youngest, max_gen=oldest，超过则不再递增）"),
    "mglru.aging_interval_hours": (6, int, 1, 168, None,
        "两次 aging 之间的最小间隔（小时），防止频繁 /clear 导致过度老化"),

    # ── DAMON（迭代42）──
    "damon.cold_age_days": (14, int, 3, 90, None,
        "chunk 创建超过此天数且 access_count=0 标记为 COLD"),
    "damon.dead_age_days": (30, int, 7, 180, None,
        "chunk 创建超过此天数且 access_count=0 且低 importance 标记为 DEAD"),
    "damon.dead_importance_max": (0.65, float, 0.3, 0.9, None,
        "DEAD 分类的 importance 上限（低于此值的零访问 chunk 被视为 DEAD）"),
    "damon.cold_oom_adj_delta": (200, int, 50, 500, None,
        "COLD chunk 的 oom_adj 增量（加速未来 kswapd 淘汰）"),
    "damon.max_actions_per_scan": (10, int, 1, 50, None,
        "每次 DAMON scan 最多执行的动作数（swap + mark + protect）"),
    "damon.verified_ttl_days": (30, int, 7, 365, None,
        "verified chunk 的 TTL（天）：超过此时间未被重新访问，verification_status 重置为 pending"),
    "damon.verified_ttl_high_stability_days": (90, int, 14, 730, None,
        "高稳定性 chunk（stability>=5.0）的 verified TTL（天），默认 90 天"),

    # ── sched_ext（迭代47）──
    "scheduler.ext_enabled": (True, bool, None, None, None,
        "是否启用 sched_ext 自定义规则（False 时只使用内置分类器）"),
    "scheduler.ext_max_rules": (20, int, 1, 100, None,
        "sched_ext 自定义规则的最大数量"),

    # ── readahead（迭代48）──
    "readahead.min_cooccurrence": (2, int, 1, 10, None,
        "共现计数阈值：两个 chunk 在 recall_traces 中至少共同出现 N 次才建立 readahead pair"),
    "readahead.prefetch_bonus": (0.10, float, 0.01, 0.50, None,
        "readahead prefetch 加分：命中 pair 的 chunk 获得此固定加分"),
    "readahead.max_prefetch": (2, int, 1, 5, None,
        "每次检索最多 prefetch 的额外 chunk 数量"),
    "readahead.window_traces": (50, int, 10, 200, None,
        "分析共现模式时回看最近 N 条 recall_traces"),

    # ── TCP AIMD — Adaptive Extraction Window（迭代50）──
    "aimd.window_traces": (30, int, 10, 200, None,
        "AIMD 计算窗口：回看最近 N 条 recall_traces 统计命中率"),
    "aimd.cwnd_max": (1.0, float, 0.3, 1.0, None,
        "AIMD cwnd 上限（1.0 = 全速提取，所有信号匹配都写入）"),
    "aimd.cwnd_min": (0.3, float, 0.1, 0.8, None,
        "AIMD cwnd 下限（保底提取能力，不会完全停止提取）"),
    "aimd.cwnd_init": (0.7, float, 0.2, 1.0, None,
        "AIMD cwnd 初始值（新项目/无历史数据时的默认窗口）"),
    "aimd.hit_rate_target": (0.3, float, 0.1, 0.8, None,
        "AIMD 目标命中率：高于此值 cwnd 线性增加，低于此值 cwnd 指数减少"),
    "aimd.additive_increase": (0.05, float, 0.01, 0.2, None,
        "AIMD 加法增大步长：命中率达标时 cwnd += AI 步长"),
    "aimd.multiplicative_decrease": (0.5, float, 0.2, 0.9, None,
        "AIMD 乘法减小因子：命中率不达标时 cwnd *= MD 因子"),
    "aimd.ssthresh": (0.6, float, 0.3, 1.0, None,
        "AIMD Slow Start 阈值：cwnd < ssthresh 时指数恢复（每次翻倍），>= 时线性恢复"),
    "aimd.slow_start_factor": (2.0, float, 1.2, 4.0, None,
        "AIMD Slow Start 指数增长因子：cwnd = cwnd * factor（直到 ssthresh）"),
    "aimd.small_pool_pct": (0.4, float, 0.1, 0.8, None,
        "Small Pool Bypass: chunk 数 < quota×此比例时跳过 AIMD（cwnd=max, policy=full）"),

    # ── Trace GC — recall_traces 生命周期管理（迭代63）──
    "gc.trace_max_age_days": (14, int, 3, 90, None,
        "recall_traces 最大保留天数，超过后 GC 清理"),
    "gc.trace_max_rows": (500, int, 50, 5000, None,
        "recall_traces 最大保留行数，超过后按时间淘汰"),

    # ── CRIU Checkpoint/Restore（迭代49）──
    "criu.max_checkpoints": (3, int, 1, 10, None,
        "每个项目保留的最大 checkpoint 数量（FIFO 淘汰最旧）"),
    "criu.max_age_hours": (72, int, 6, 720, None,
        "checkpoint 过期时间（小时），超过则不恢复"),
    "criu.max_hit_ids": (50, int, 3, 200, None,
        "checkpoint 保存的最近命中 chunk ID 数量（iter89: 10→50，支持大工作集）"),
    "criu.restore_boost": (0.12, float, 0.0, 0.5, None,
        "checkpoint 恢复时命中 chunk 的评分加权（叠加在 working_set_score 上）"),

    # ── Autotune（迭代51）──
    "autotune.enabled": (True, bool, None, None, None,
        "是否启用参数自动调优（SessionStart 时运行）"),
    "autotune.min_traces": (10, int, 3, 100, None,
        "触发 autotune 所需的最少 recall_traces 数量（样本不足时跳过）"),
    "autotune.step_pct": (10, int, 5, 30, None,
        "每次自动调整的最大幅度百分比（保守调参，避免振荡）"),
    "autotune.cooldown_hours": (6, int, 1, 168, None,
        "两次 autotune 之间的最小间隔（小时），防止频繁调参"),
    "autotune.hit_rate_low_pct": (20, int, 5, 50, None,
        "命中率低于此阈值时收缩 top_k / quota（减少噪声写入）"),
    "autotune.hit_rate_high_pct": (50, int, 30, 80, None,
        "命中率高于此阈值时 quota 适度扩大（迭代129：top_k 不再随高命中率增加，已修复逻辑反转）"),
    # ── Autotune top_k 上限（迭代129）──
    # OS 类比：TCP AIMD cwnd_max — 拥塞窗口有上限，防止 cwnd 无限增长
    # 根因：旧逻辑命中率高→扩大 top_k（方向错误），且无上限保护，
    #       导致 top_k 从默认 5 被推到 12，与 design_constraint 膨胀叠加造成 injected=14+
    # 修复后 top_k 只在命中率低时增加，且受此上限保护
    "autotune.top_k_max": (6, int, 3, 15, None,
        "autotune 允许调整的 retriever.top_k 上限（迭代129：防止高命中率反向推高 top_k）"),
    # ── Autotune deadline 上限（迭代136）──
    # OS 类比：TCP SYN_RETRIES max — 限制重试上限，防止指数退避无限膨胀
    # 根因：deadline_skip 轨迹的 duration_ms ≈ 当前 deadline_ms（自引用），
    #       p95 包含这些轨迹 → p95 > 2×baseline → autotune 推高 deadline_ms,
    #       → 新轨迹 duration 更高 → p95 再升 → 正反馈循环（每次 +10%）
    "autotune.deadline_max_ms": (100.0, float, 50.0, 300.0, None,
        "autotune 允许调整的 retriever.deadline_ms 上限（迭代136：防止 deadline_skip 自强化循环膨胀，default=100ms）"),
    # ── Autotune chunk_quota 上限（迭代137）──
    # OS 类比：Linux cgroup memory.max — 硬限制，cgroup 内存不能超过此值
    #   autotune 在高命中率（>50%）时每 6 小时 +10% quota，无上限则无限增长：
    #   gitroot 实测 200→389（约 19 次 +10%），balloon.max_quota=500 是全局上限
    #   但 autotune 不检查 balloon 上限，可一直增到 10000（extractor.chunk_quota 上限）
    # 修复：autotune.chunk_quota_max 作为 autotune 调参的软性上限
    #   不同于 balloon.max_quota（全局硬限），这是 autotune 不应超越的"合理范围"
    #   default=400：保留生产使用的合理增长空间，阻止无限推高
    "autotune.chunk_quota_max": (400, int, 50, 5000, None,
        "autotune 允许调整的 extractor.chunk_quota 上限（迭代137：防止高命中率无限推高 quota，default=400）"),
    # ── Autotune kswapd 水位回弹（迭代138）──
    # OS 类比：Linux vm.watermark_boost_factor — 内存压力消退后 watermark 自动恢复正常水位
    #   策略4 单方向降低 pages_low_pct（容量>90%时），但无回弹机制
    #   abspath:7e3095aef7a6 实测：80→72→64.8→58.3，capacity 恢复后 pages_low 永久偏低
    #   pages_low 过低 = kswapd 在 58% 就开始淘汰，不必要地频繁 eviction
    # 修复（迭代138）：capacity < 70% 时，pages_low 每次向默认值(80)回弹 step_pct%
    #   恢复路径（step_pct=10%）：58→63→69→76→80（4个 autotune 周期，24小时）
    # 无需额外 sysctl：复用已有 autotune.step_pct 控制回弹步长

    # ── Autotune Rollback Circuit Breaker（迭代494）──
    # OS 类比：Linux TCP anti-windup + perf_event overflow circuit breaker
    #   当控制回路本身产生负反馈（调参后指标持续恶化）时，断路并回滚到已知好状态。
    #   anti-windup：积分项饱和时停止累积，防止过冲；
    #   circuit breaker：连续 N 次恶化 → open（停止调参）+ rollback → half-open 试探 → close
    "autotune.cb_enabled": (True, bool, None, None, None,
        "是否启用 autotune 熔断回滚（迭代494：连续恶化时 open circuit + rollback 参数）"),
    "autotune.cb_consecutive_bad": (3, int, 2, 10, None,
        "连续多少次 autotune 后指标恶化才触发熔断（默认 3 次）"),
    "autotune.cb_degrade_pct": (10, int, 5, 50, None,
        "hit_rate 相对下降超过此百分比才判定为恶化（默认 10%，即 hit_rate 从 50% 跌到 45%）"),
    "autotune.cb_open_hours": (24, int, 6, 168, None,
        "熔断 open 状态持续时间（默认 24h，之后进入 half-open 试探）"),

    # ── DRR Fair Queuing（迭代50）──
    "retriever.drr_enabled": (True, bool, None, None, None,
        "是否启用 DRR 类型多样性保障（False 时退化为纯 score 排序）"),
    "retriever.drr_max_same_type": (2, int, 1, 10, None,
        "单一 chunk_type 在 Top-K 中的最大占比（绝对值，超出让位给其他类型）"),

    # ── Query-Conditioned Importance（迭代322）──
    # OS 类比：Linux CPUFreq P-state — 根据负载动态调整处理器频率
    # α_eff = qci_base_alpha - qci_relevance_slope × relevance
    #   relevance=1.0 → α_eff=0.30（recency 主导），relevance=0.0 → α_eff=0.55（importance 主导）
    "retriever.qci_base_alpha": (0.55, float, 0.1, 0.9, None,
        "QCI 基础 α：relevance=0 时的 importance 权重（迭代322，默认 0.55）"),
    "retriever.qci_relevance_slope": (0.25, float, 0.0, 0.5, None,
        "QCI slope：每单位 relevance 降低 α 的幅度（迭代322，默认 0.25）"),

    # ── MMR 边际信息量过滤（迭代321）──
    # OS 类比：Linux multiqueue block I/O merge — 物理地址相邻的请求合并，避免重复 I/O
    # MMR 在 DRR 之后对内容语义去冗余，λ 越大越偏 relevance，越小越偏 diversity
    "retriever.mmr_enabled": (True, bool, None, None, None,
        "是否启用 MMR 内容去冗余（在 DRR 之后对 summary 语义去重，迭代321）"),
    "retriever.mmr_lambda": (0.6, float, 0.0, 1.0, None,
        "MMR λ 参数：λ=1.0 纯 relevance，λ=0.0 纯 diversity，默认 0.6 略偏 relevance"),

    # ── Hybrid FTS5+BM25（迭代126）──
    # OS 类比：L1/L2 多级缓存协议 — L1(FTS5)命中不足时查 L2(BM25)补充长尾
    "retriever.hybrid_fts_min_count": (3, int, 1, 20, None,
        "FTS5 结果少于此值时触发 BM25 补充召回（迭代126：默认3，等于 top_k 保障下限）"),

    # ── 迭代334：IWCSI — Importance-Weighted Cold-Start Injection ──
    # OS 类比：Linux DAMON damos_action=PAGE_PROMOTE — 强制曝光 cold region 打破死锁
    # 信息论依据：零召回高imp chunk 期望信息增益最高（I = importance × 1.0），
    #   但语义鸿沟导致 FTS5 永不命中 → IWCSI 是 cold-start SNR 修复机制
    "retriever.cold_start_enabled": (True, bool, None, None, None,
        "是否启用 IWCSI 冷启动注入（FULL 模式 + positive 不足时强制曝光高 imp 零召回 chunk）"),
    "retriever.cold_start_imp_threshold": (0.50, float, 0.3, 1.0, None,
        "IWCSI 触发的 importance 下限：只强制曝光 importance >= 此值的零召回 chunk"),
    "retriever.cold_start_max_inject": (2, int, 1, 3, None,
        "IWCSI 每次最多强制注入的 chunk 数量（默认2，加速新导入知识曝光）"),
    "retriever.cold_start_ac_threshold": (1, int, 0, 10, None,
        "cold_start_probe 判定 chunk 为'冷'的 access_count 上限（ac<=此值视为未曝光）"),
    # ── iter376: Emotional Salience Retrieval Boost ──────────────────────────
    # OS 类比：Linux OOM Score 情绪加权 — 高情绪显著性记忆优先保留，类比 oom_adj=-800
    # 认知科学依据：McGaugh (2000) 情绪增强记忆巩固（amygdala-hippocampus interaction）
    #   情绪事件（高 arousal）触发杏仁核激活，通过 norepinephrine 增强海马编码强度。
    #   在 memory-os 中：emotional_weight > 0 的 chunk 代表高情绪显著性知识，
    #   检索时应优先，类比高 oom_adj 进程保留在内存中不被 kswapd 淘汰。
    "retriever.emotional_boost_factor": (0.08, float, 0.0, 0.5, None,
        "情绪显著性加分系数：score += emotional_weight * factor（emotional_weight > threshold 时）"),
    "retriever.emotional_boost_threshold": (0.4, float, 0.0, 1.0, None,
        "情绪显著性加分触发阈值：emotional_weight > 此值时才加分，防止低情绪度噪音"),

    # ── 迭代335：Ghost Reaper — zombie chunk FTS5 污染清除 ──
    # OS 类比：Linux wait4() — 回收 zombie 进程，释放进程表项
    # ghost chunk = importance=0 且 summary=[merged→...] 的已合并 chunk
    # 仍在 FTS5 索引中，消耗 result slot 并产生 false recall
    "retriever.ghost_filter_enabled": (True, bool, None, None, None,
        "是否在 fts_search 中过滤 importance=0 的 ghost chunk（Layer 2 软过滤防护）"),

    # ── iter388: Temporal Priming — 时间性启动效应 ──
    # 认知科学依据：Tulving & Schacter (1990) Priming Effect —
    #   最近在同会话中被召回的记忆，在随后的检索中被激活的阈值降低（启动效应）。
    #   神经基础：海马-新皮层投射维持短期激活状态（working memory buffer），
    #   最近命中的 chunk 仍处于"激活窗口"，再次相关时更易浮现。
    # OS 类比：CPU 时间局部性 (temporal locality) — 最近访问的 cache line 比
    #   未访问的有更高命中概率（L2/L3 temporal prefetch）。
    "retriever.priming_enabled": (True, bool, None, None, None,
        "是否启用会话内时间性启动效应：同会话最近召回的 chunk 得 priming_boost 加分（iter388）"),
    "retriever.priming_boost": (0.08, float, 0.0, 0.30, None,
        "启动效应加分幅度：同会话最近召回的 chunk score += priming_boost（iter388，默认 0.08）"),

    # ── iter389: Reconsolidation Window — 再巩固窗口 ──────────────────────────
    # 认知科学依据：Walker & Stickgold (2004) Memory Reconsolidation —
    #   记忆在每次被激活后进入不稳定的"可塑窗口"，然后重新巩固（reconsolidation）。
    #   间隔越长的重复激活，巩固效果越强（spacing effect, Ebbinghaus 1885）。
    #   短间隔内反复命中（< 1小时）= 工作记忆内刷新，不触发长时记忆巩固。
    #   长间隔后命中（> 1天）= 真正的间隔回忆（spaced retrieval），SM-2 质量最高。
    # OS 类比：Linux MGLRU page aging —
    #   刚被访问的页（youngest generation）再次访问不触发 generation 晋升（短时局部性），
    #   但跨 aging interval 后再次访问会晋升到 younger generation（真正的热页）。
    # 在 update_accessed() 中：根据 now - last_accessed 动态推断 SM-2 quality，
    #   替代之前固定 quality=4 的简化假设，实现真正的 spacing effect。
    "recon.short_gap_hours": (1.0, float, 0.0, 24.0, None,
        "再巩固短间隔阈值（小时）：gap < 此值时 SM-2 quality=3（无增益，仅更新访问时间）"),
    "recon.medium_gap_hours": (24.0, float, 1.0, 168.0, None,
        "再巩固中间隔阈值（小时）：short<=gap<medium 时 SM-2 quality=4（轻微加固）"),
    "recon.long_gap_quality": (5, int, 3, 5, None,
        "gap >= medium_gap_hours 时的 SM-2 quality（默认5=最大巩固，间隔回忆效果最强）"),
    "recon.enabled": (True, bool, None, None, None,
        "是否启用再巩固窗口动态 SM-2 quality（False 时回退到固定 quality=4）"),

    # ── iter412: Testing Effect — 高难度检索强化记忆巩固 ─────────────────────────
    # 认知科学依据：Roediger & Karpicke (2006) "Test-Enhanced Learning" —
    #   主动检索（而非被动重读）显著提升长期保留率（+50%）。
    #   Bjork (1994) "Desirable Difficulties" — 需要努力的检索（retrieval difficulty 高）
    #   形成更强、更持久的记忆痕迹（elaborative encoding 更深）。
    #   Kornell et al. (2011) — 难但成功的检索比容易的检索巩固效果更强。
    # 实现：R_at_recall = exp(-gap_hours / (stability × 24))，
    #   difficulty = max(0, 1 - R_at_recall)，
    #   quality_bonus = round(difficulty × scale)（仅在 recall_quality=None 时生效）
    # OS 类比：Linux L3 cache miss → aggressive LRU promotion —
    #   L1 命中（容易检索）不改变 LRU 位置；L3 miss（困难检索）→ 强制 cache line 晋升到 L1/L2
    "recon.testing_effect_enabled": (True, bool, None, None, None,
        "是否启用 iter412 Testing Effect：低 retrievability 时的检索难度 → 增加 SM-2 quality bonus"),
    "recon.testing_effect_scale": (2.0, float, 0.0, 4.0, None,
        "Testing Effect 难度-质量转换系数：quality_bonus = round(difficulty × scale)，最大 +2（iter412）"),

    # ── iter413: Sleep Consolidation — 离线记忆巩固 ──────────────────────────
    # 认知科学依据：Stickgold (2005) "Sleep-dependent memory consolidation" —
    #   NREM 睡眠中海马体重放最近学习的记忆，将其转移到新皮层（系统巩固理论）。
    #   Walker & Stickgold (2004) — 学习后睡眠使次日表现提升 20-30%。
    #   Diekelmann & Born (2010) — SWS 期间的主动系统巩固降低干扰敏感性。
    # 实现：SessionStart 时对上一 session（过去 24hr）访问的高重要性 chunk 应用轻微 stability 加成
    # OS 类比：Linux pdflush/writeback daemon — session 间隙（idle period）后台巩固 dirty pages，
    #   类比海马-新皮层离线重放（sleep replay）将 working memory → long-term storage
    "consolidation.enabled": (True, bool, None, None, None,
        "是否启用 iter413 Sleep Consolidation：SessionStart 时对上一 session 的高重要性 chunk 应用离线巩固"),
    "consolidation.boost_factor": (1.06, float, 1.0, 1.30, None,
        "离线巩固稳定性加成系数：stability × boost_factor（iter413，保守值 1.06 ≈ 6%）"),
    "consolidation.min_importance": (0.70, float, 0.3, 1.0, None,
        "触发离线巩固的重要性阈值：importance >= 此值的 chunk 才参与 sleep replay（iter413）"),
    "consolidation.window_hours": (24, int, 1, 168, None,
        "离线巩固的时间窗口（小时）：只对过去 N 小时内被访问的 chunk 进行巩固（iter413）"),
    "consolidation.max_chunks": (50, int, 5, 500, None,
        "每次 SessionStart 最多巩固的 chunk 数量（iter413，按 importance 排序取前 N 个）"),

    # ── iter428: Event Segmentation — Session Boundary Consolidation Gate ───────────────────
    # 认知科学依据：Zacks et al. (2007) Event Segmentation Theory (Psychological Science) —
    #   人类将连续经验分割为离散事件单元，边界处记忆编码最强（boundary advantage）。
    #   Radvansky & Copeland (2006) "Walking through doorways causes forgetting" —
    #   穿越事件边界（空间/时间）触发短暂记忆抑制（doorway effect）：
    #   旧情境末尾的信息被短暂压制（约 5 分钟），新情境开始后的信息获得额外编码加成。
    # OS 类比：ext4 jbd2 journal commit boundary —
    #   新 epoch 首批写入的 page（刚越过 commit point）= 最高一致性保证（boundary boost）；
    #   commit 前的 dirty page（旧 epoch 末尾）= 不稳定窗口（doorway penalty）。
    "consolidation.boundary_enabled": (True, bool, None, None, None,
        "是否启用 iter428 Event Segmentation：session boundary 处分叉 sleep consolidation 逻辑"),
    "consolidation.boundary_multiplier": (1.5, float, 1.0, 3.0, None,
        "iter428: boundary boost 乘子 — boundary_proximity=+1.0 时 stability × (boost_factor + (multiplier-1)×proximity)，"
        "默认 1.5：boundary chunk 比普通 chunk 多 +50% sleep consolidation 加成"),
    "consolidation.boundary_grace_secs": (300, int, 30, 3600, None,
        "iter428: session 开始后多少秒内写入的 chunk 被视为 boundary boost 候选（默认 5 分钟）"),
    "consolidation.doorway_penalty": (0.05, float, 0.0, 0.3, None,
        "iter428: doorway effect stability 惩罚系数（boundary_proximity < -0.5 时应用，"
        "默认 0.05 = 最多 5% stability 惩罚，模拟 Radvansky 2006 doorway forgetting）"),

    # ── iter429: Enactment Effect — 行动编码加成 ─────────────────────────────
    # 认知科学依据：Engelkamp & Zimmer (1989) Subject-Performed Tasks (SPT) —
    #   亲自执行动作（SPT）比仅语言描述（VT）的记忆留存率高约 40%；
    #   行动编码激活运动皮层 + 语义系统双路径，形成更强的多模态痕迹。
    # OS 类比：Linux writeback — 写操作（exec/write syscall）创建比读操作（read）
    #   更深的 page cache dirty state，需要更多 I/O 才能清除。
    # 检测：chunk 的 source_type='tool_result' 或 content 包含工具调用签名
    "store_vfs.enactment_enabled": (True, bool, None, None, None,
        "是否启用 iter429 Enactment Effect：agent 工具调用产生的 chunk 获得 stability 加成"),
    "store_vfs.enactment_boost": (1.4, float, 1.0, 3.0, None,
        "iter429: 行动编码 stability 乘子 — 执行工具调用的 chunk stability × enactment_boost，"
        "默认 1.4（对应 SPT 比 VT 高约 40% 的留存率优势，Engelkamp 1989）"),
    "store_vfs.enactment_cap": (365.0, float, 1.0, 365.0, None,
        "iter429: enactment effect 后 stability 上限（避免超过遗忘曲线最大值）"),
    "store_vfs.enactment_tool_types": (
        "Bash,Edit,Write,NotebookEdit",
        str, None, None, None,
        "iter429: 触发行动编码加成的工具名列表（逗号分隔），"
        "这些工具产生副作用（写磁盘/执行命令），比 Read/Glob 等只读工具有更强行动编码"),

    # ── iter390: Prospective Memory — 展望记忆触发 ───────────────────────────
    # 认知科学依据：Einstein & McDaniel (1990) Prospective Memory —
    #   意图性记忆（"记得在X时做Y"）需要在未来条件满足时主动提取。
    #   extractor 检测展望意图信号 → 注册 trigger_conditions；
    #   retriever 在 query 匹配时注入关联 chunk（提醒效果）。
    # OS 类比：Linux inotify — 注册事件监听，条件满足时唤醒等待进程。
    "prospective.enabled": (True, bool, None, None, None,
        "是否启用展望记忆触发（extractor 检测意图 + retriever 注入提醒，iter390）"),
    "prospective.max_inject": (2, int, 1, 5, None,
        "每次检索最多注入的展望记忆 chunk 数量（避免占满 Top-K，默认 2）"),
    "prospective.score_boost": (0.8, float, 0.3, 1.0, None,
        "展望记忆触发注入的初始评分（较高以确保注入，但低于 design_constraint）"),

    # ── iter391: Inhibition of Return — 返回抑制动态衰减 ─────────────────────
    # 认知科学依据：Posner (1980) Inhibition of Return —
    #   注意力访问一个位置后，有 ~300ms 的返回抑制（IOR）；对记忆系统同样适用：
    #   Klein (2000) IOR in memory search — 最近被检索的项目有短暂的检索抑制，
    #   防止搜索固着在同一位置，促进广度探索。
    # OS 类比：Linux CFQ fair queuing anti-starvation —
    #   刚被服务的请求在 timeslice 内被降优先级，让其他等待队列获得服务机会。
    # 实现：session 级 IOR 状态（chunk_id → last_inject_turn），
    #   score *= (1 - ior_penalty × exp(-ior_decay_rate × turns_since_inject))
    "retriever.ior_enabled": (True, bool, None, None, None,
        "是否启用 IOR 返回抑制（最近注入的 chunk 获得短暂的分数惩罚，iter391）"),
    "retriever.ior_penalty": (0.35, float, 0.0, 0.5, None,
        "IOR 峰值惩罚系数：刚被注入的 chunk 分数 × (1 - ior_penalty)（iter1451: 0.20→0.35，"
        "小库垄断 chunk 0.80×0.9=0.72 仍胜出，需 0.65×0.9=0.585 才让位）"),
    "retriever.ior_decay_turns": (5, int, 1, 20, None,
        "IOR 半衰期（检索轮次）：经过此轮次后惩罚衰减到一半（iter1451: 3→5，延长抑制窗口）"),
    "retriever.ior_exempt_types": ("", str, None, None, None,
        "IOR 豁免的 chunk_type（逗号分隔；iter1451: 移除 design_constraint 豁免——"
        "豁免导致高 ac constraint 垄断注入位，6h/24h/7d suppress 已够保护 constraint 不被遗忘）"),

    # ── iter1715: Cross-Session Recall Fatigue — 跨 session 去垄断 ──
    # 认知科学：Karpicke & Roediger (2008) 间隔效应 — 高频重复检索的边际收益递减；
    #   已高度内化的知识重复注入挤占新知识的注入槽位。
    # 实现：score *= 1 / (1 + fatigue_rate × max(0, ac - ac_threshold))
    "retriever.recall_fatigue_enabled": (True, bool, None, None, None,
        "iter1715: 是否启用跨 session 召回疲劳（access_count 高的 chunk 分数衰减）"),
    "retriever.recall_fatigue_ac_threshold": (4, int, 2, 20, None,
        "iter1720: 触发疲劳的 ac 阈值 6→4（更早衰减高频 chunk，为低频让路）"),
    "retriever.recall_fatigue_rate": (0.15, float, 0.01, 0.5, None,
        "iter1720: 衰减速率 0.08→0.15（ac=9→0.57x, ac=12→0.45x，打破垄断）"),

    # ── iter393：Semantic Distance Decay in Spreading Activation ──
    # 认知科学：Collins & Loftus (1975) Spreading Activation Theory —
    #   激活从锚点节点沿语义图扩散，激活量随语义距离（路径长度）衰减。
    #   距离越远，激活越低，形成自然的语义相关性梯度。
    # OS 类比：NUMA 局部性 — 本节点内存访问延迟低，跨 2 个 NUMA 节点的访问
    #   延迟呈指数增长（L1→L2→L3→DRAM→remote DRAM 约 3-10 倍梯度）。
    "retriever.sa_distance_decay_enabled": (True, bool, None, None, None,
        "是否对 spreading activation 应用语义距离衰减（iter393，默认启用）"),
    "retriever.sa_distance_decay_factor": (0.6, float, 0.1, 1.0, None,
        "每跳语义距离衰减系数：hop_distance 跳的激活分乘以此系数的 hop 次方（iter393，默认 0.6）"),
    "retriever.sa_max_hops": (2, int, 1, 4, None,
        "spreading activation 最大跳数（iter393，默认 2 跳；跳数越多计算越贵）"),

    # ── iter423: Fan Effect — IDF加权 Spreading Activation（Anderson 1974）──
    # 认知科学依据：Anderson (1974) Fan Effect —
    #   与一个概念关联的事实越多（fan-out 越大），检索每条具体事实越慢越难。
    #   高扇出节点（如"authentication"关联50个chunk）的激活传播效率低于
    #   低扇出节点（如"port_8080"只关联1-2个chunk）。
    # 实现：spreading activation 中，高 degree entity 的边贡献乘以 IDF 权重（降权）：
    #   IDF_weight = log(1 + median_degree / (1 + entity_degree))，归一化到 [0,1]
    #   entity_degree = 该 entity 在 entity_edges 中的总边数（in + out）
    #   degree >= fan_min_degree 时才应用惩罚（低扇出 entity 不惩罚）
    # OS 类比：Linux CPU cache set-associativity conflict —
    #   太多 cache line 映射到同一 set（高扇出）→ 频繁 eviction → 命中率下降。
    #   Fan Effect 惩罚 = 降低高扇出 entity 的"缓存命中率"（activation strength）。
    "retriever.fan_effect_enabled": (True, bool, None, None, None,
        "是否启用 Fan Effect IDF 加权（iter423：高扇出 entity 激活权重降低）"),
    "retriever.fan_effect_min_degree": (3, int, 1, 50, None,
        "iter423: Fan Effect 触发的最低 entity degree 阈值（低于此值的 entity 不惩罚）"),
    "retriever.fan_effect_idf_weight": (0.5, float, 0.0, 1.0, None,
        "iter423: IDF 权重混合系数：edge_score × (1 - fan_effect_idf_weight × (1 - idf_factor))，"
        "0=不惩罚，1=完全 IDF 权重"),

    # ── iter424: Mood-Congruent Memory — 情绪效价一致性检索增强（Bower 1981）──
    # 认知科学依据：Bower (1981) "Mood and memory" —
    #   人在某种情绪状态（情绪诱导实验）下，更容易回忆起与该情绪一致的记忆。
    #   正面情绪 → 优先检索正面内容；负面情绪 → 优先检索负面/危机内容。
    #   Bower (1981) Associative Network Theory：情绪节点（mood nodes）与记忆节点相连，
    #   情绪激活会扩散到同效价的记忆，降低其检索阈值。
    #   Matt et al. (1992) Meta-analysis: MCM effect is robust across recall + recognition tasks。
    # 应用：query 包含情绪效价词（崩溃/突破）→ 推断用户当前情绪状态 →
    #   chunk.emotional_valence 与 query 效价方向一致 → score += mcm_boost × |valence_match|。
    # OS 类比：Linux NUMA-aware page placement —
    #   进程有 preferred NUMA node（情绪状态），访问同 node 的 page（同效价 chunk）延迟最低。
    "retriever.mcm_enabled": (True, bool, None, None, None,
        "是否启用 iter424 Mood-Congruent Memory：query 情绪效价与 chunk 效价一致时检索加分"),
    "retriever.mcm_boost": (0.05, float, 0.0, 0.20, None,
        "iter424: 情绪效价一致时的 score boost（默认 +0.05，query_valence × chunk_valence > 0 时生效）"),
    "retriever.mcm_valence_threshold": (0.3, float, 0.0, 1.0, None,
        "iter424: query/chunk 情绪效价触发阈值（|valence| >= 此值才参与 MCM 匹配，避免弱情绪噪音）"),

    # ── iter394：Contextual Similarity Boost — 编码情境检索增强 ──
    # 认知科学：Tulving (1983) Encoding Specificity Principle +
    #   Godden & Baddeley (1975) Context-Dependent Memory —
    #   检索时的任务情境（session_type: debug/design/refactor/qa）与编码时越相似，
    #   记忆提取成功率越高。水下学习 → 水下更易回忆（情境再现效应）。
    # OS 类比：NUMA-aware scheduling — 进程在同一 NUMA 节点上运行时，
    #   访问该节点分配的内存延迟最低（情境局部性 ≈ NUMA 局部性）。
    # 实现：检索时从 query 提取 session_type/task_verbs，
    #   与 chunk.encoding_context.session_type/task_verbs 比对，
    #   匹配时加 context_type_boost（+0.05）+ task_verbs overlap boost（+0.03）。
    "retriever.context_type_boost_enabled": (True, bool, None, None, None,
        "是否启用 session_type 情境匹配 boost（iter394，默认启用）"),
    "retriever.context_type_boost": (0.05, float, 0.0, 0.15, None,
        "session_type 精确匹配时的 score boost（iter394，默认 +0.05）"),
    "retriever.task_verbs_boost": (0.03, float, 0.0, 0.10, None,
        "task_verbs Jaccard 交集加权 boost 上限（iter394，默认 +0.03）"),

    # ── BM25 Fallback Global Discount（迭代131）──
    # OS 类比：Linux NUMA Aware Scheduling — 当 local node 内存不足强制 cross-node 分配时，
    #   调度器施加 NUMA fault penalty（migratable page cost），阻止低相关性跨节点抢占。
    #   memory-os 对应：BM25 全表扫描时所有 72 global chunk 参与竞争，
    #   高 importance global chunk（kernel patch design_constraint, imp=0.95）
    #   通过偶发词汇重叠（如"记忆"）获得 relevance 虚高分，
    #   NUMA penalty(global)=0.05 无法阻止其排名第一。
    #   bm25_global_discount：BM25 fallback 路径中 global 项目 chunk 的 relevance 折扣系数
    #   default=0.4 — 远强于 FTS5 路径的 0.05 惩罚，匹配 BM25 不确定性高的事实
    "retriever.bm25_global_discount": (0.4, float, 0.1, 1.0, None,
        "BM25 全表扫描 fallback 路径中 global 项目 chunk 的 relevance 折扣（迭代131，默认0.4）"),

    # ── design_constraint 注入上限（迭代128）──
    # OS 类比：Linux mlock RLIMIT_MEMLOCK — 限制进程可以锁定的内存总量，
    # 防止单个进程无限 mlock 耗尽系统内存（所有 design_constraint 强制注入）。
    # 默认 3：确保最相关的约束能注入，但不会因约束数量增长导致注入膨胀。
    "retriever.max_forced_constraints": (3, int, 1, 16, None,
        "design_constraint 强制注入的最大数量（迭代128：防止约束膨胀，按 BM25 相关性择优注入）"),

    # ── Proactive Swap Probe（迭代355）──
    # OS 类比：Linux MGLRU (Multi-Generation LRU) 主动提升 swap 热页
    # 即使 FTS5 已有结果，仍检查 swap 中高 importance chunk 是否更相关
    "retriever.proactive_swap_enabled": (True, bool, None, None, None,
        "主动 swap 探针：即使 top_k 非空，仍检查 swap 中高 importance 的 chunk（迭代355）"),
    "retriever.proactive_swap_imp_threshold": (0.80, float, 0.5, 1.0, None,
        "proactive swap 探针的 importance 阈值：只恢复 importance >= 此值的 chunk"),
    "retriever.proactive_swap_max_restore": (3, int, 1, 10, None,
        "每次查询最多从 swap 恢复多少个 chunk（限制写连接切换开销）"),

    # ── Pin Decay + Cap（迭代356）──
    # OS 类比：Linux memcg pin_user_pages_lock + RLIMIT_MEMLOCK
    # 问题：chunk_pins 无过期机制，45% pin rate（47/105）阻塞 LRU 驱逐空间
    "pin.decay_enabled": (True, bool, None, None, None,
        "Pin 衰减开关：长期未访问的 soft pin 自动解除（迭代356）"),
    "pin.decay_days": (30, int, 7, 180, None,
        "soft pin 衰减阈值（天）：soft pin 的 chunk 超过 N 天未访问则自动解除"),
    "pin.cap_pct": (15, int, 5, 50, None,
        "项目 pin 上限（%）：pinned chunk 占项目总量不超过此比例（hard+soft 合计）"),
    "pin.cap_apply_on_pin": (True, bool, None, None, None,
        "新增 pin 时立即检查 cap，超限则驱逐最旧 soft pin（类比 RLIMIT_MEMLOCK enforcement）"),

    # ── Cross-Session KSM（迭代358）──
    # OS 类比：Linux KSM (Kernel Samepage Merging) ksmd 线程周期扫描
    # 问题：项目的 17 个 session 各自从 cold start 重新加载相同 chunk，
    # 无法共享跨 session 热点知识（KSM 缺失导致 knowledge locality 低）
    "ksm.enabled": (True, bool, None, None, None,
        "跨 Session KSM：扫描多 session working set 共享热点 chunk（迭代358）"),
    "ksm.min_access_count": (3, int, 1, 20, None,
        "chunk 在单 session 中的最低访问次数（才被视为热点候选）"),
    "ksm.min_sessions": (2, int, 2, 10, None,
        "chunk 必须出现在至少 N 个 session 才被提升（防止单 session 噪音）"),

    # ── TLB v2（迭代64）──
    "retriever.tlb_max_entries": (8, int, 1, 64, None,
        "TLB 最大 slot 数量（类比 CPU TLB 通常 64-1024 entries）"),
    # ── iter583: TLB Generation Age-Out ──
    "retriever.tlb_max_generation_age": (5, int, 1, 50, None,
        "TLB entry 最大存活代数（generation gap >= 此值时强制 miss，保证 scan_unevictable 有执行机会）"),

    # ── Memory Zones（迭代82）──
    "retriever.exclude_types": ("prompt_context,conversation_summary", str, None, None, None,
        "逗号分隔的 chunk_type 列表，从检索候选中排除（OS 类比：Linux ZONE_RESERVED）"),

    # ── iter427：Serial Position Effect（Murdock 1962）──
    # OS 类比：BFQ front-merge — 高优先级 I/O 置于 dispatch queue 首/尾位置
    "retriever.serial_position_enabled": (True, bool, None, None, None,
        "是否启用序列位置效应注入顺序优化（Murdock 1962 primacy+recency），"
        "将高价值 chunk 置于注入块首/尾，避免 LLM 输出干扰效应。"),
    "retriever.serial_position_imp_threshold": (0.85, float, 0.0, 1.0, None,
        "importance >= 此值的 chunk 视为 primacy/recency 候选（默认 0.85）"),
    "retriever.serial_position_recency_types": ("decision,design_constraint,reasoning_chain",
        str, None, None, None,
        "逗号分隔的 chunk_type 列表，这些类型的 chunk 优先候选 primacy/recency 位置"),

    # ── 迭代359：Session Injection Deduplication ──
    "retriever.session_dedup_threshold": (2, int, 1, 10, None,
        "同一 session 内 chunk 被注入 >= 此次数后从输出中去重（OS 类比：copy-on-write lazy page dedup，"
        "只有同一页被重复 mapped 达到阈值才触发物理页合并）。iter587: design_constraint 使用 2× 阈值（不再无条件豁免）。"),

    # ── Context Pressure Governor（迭代55）──
    "governor.turns_low": (5, int, 1, 20, None,
        "低压阈值：对话轮次 ≤ 此值时判定为 LOW（上下文充裕）"),
    "governor.turns_high": (15, int, 5, 50, None,
        "高压阈值：对话轮次 ≥ 此值时判定为 HIGH（接近 compaction）"),
    "governor.turns_critical": (25, int, 10, 80, None,
        "临界阈值：对话轮次 ≥ 此值时判定为 CRITICAL（极高 compaction 风险）"),
    "governor.compact_high": (2, int, 1, 10, None,
        "compaction 次数 ≥ 此值时判定为 HIGH"),
    "governor.compact_critical": (4, int, 2, 20, None,
        "compaction 次数 ≥ 此值时判定为 CRITICAL"),
    "governor.recent_compact_secs": (120, int, 30, 600, None,
        "compaction 后此秒数内视为高压（刚溢出，需要精简注入）"),
    "governor.scale_low": (1.5, float, 1.0, 3.0, None,
        "LOW 压力缩放因子（> 1.0 多注入，提升信息密度）"),
    "governor.scale_high": (0.6, float, 0.2, 1.0, None,
        "HIGH 压力缩放因子（< 1.0 精简注入）"),
    "governor.scale_critical": (0.3, float, 0.1, 0.8, None,
        "CRITICAL 压力缩放因子（最小注入，仅保留最关键信息）"),
    "governor.window_hours": (2.0, float, 0.5, 24.0, None,
        "信号时间窗口：只统计最近 N 小时内的 compaction/turns（防跨 session 累积误判）"),
    "governor.consecutive_decay_hours": (1.0, float, 0.25, 12.0, None,
        "consecutive_high 衰减窗口：超过此时间未更新则 reset（防历史锁死）"),

    # ── PSI（迭代36）──
    "psi.window_size": (20, int, 5, 100, None,
        "PSI 计算窗口：最近 N 次检索的统计样本数"),
    "psi.latency_baseline_ms": (30.0, float, 1.0, 200.0, None,
        "检索延迟固定基线（ms），超过此值视为 stall。adaptive_baseline 开启时仅作 fallback"),
    "psi.hit_rate_baseline_pct": (50.0, float, 10.0, 90.0, None,
        "命中率基线（%），低于此值视为 quality stall"),
    "psi.capacity_some_pct": (70, int, 40, 90, None,
        "容量压力 SOME 阈值（%），使用率超过此值开始感受压力"),
    "psi.capacity_full_pct": (90, int, 70, 100, None,
        "容量压力 FULL 阈值（%），使用率超过此值为严重压力"),

    # ── PSI Adaptive Baseline（迭代60）──
    "psi.adaptive_baseline": (1, int, 0, 1, None,
        "启用自适应延迟基线（1=开启，0=固定基线）。开启后用滑动窗口 P50×margin 替代固定 latency_baseline_ms"),
    "psi.adaptive_margin": (1.5, float, 1.1, 3.0, None,
        "自适应基线 margin 系数。实际基线 = P50 × margin。1.5 表示允许 50% 的延迟波动"),
    "psi.adaptive_min_samples": (5, int, 3, 20, None,
        "自适应基线最小样本数。样本不足时 fallback 到固定 latency_baseline_ms"),
    # ── iter495: Dual-Coding Effect (DCE) — Paivio 1971 ──
    "store_vfs.dce_enabled": (True, bool, None, None, None,
        "iter495: 是否启用 Dual-Coding Effect（默认 True）"),
    "store_vfs.dce_code_indicators": (
        ["```", "def ", "class ", "function ", "import ", "SELECT ", "CREATE ",
         "INSERT ", "http://", "https://", "/api/", ".py", ".js", ".ts"],
        list, None, None, None,
        "iter495: 代码/结构化指标关键词（表征'imagery'编码通道）"),
    "store_vfs.dce_stability_bonus": (0.06, float, 0.0, 0.20, None,
        "iter495: 双编码 chunk 的 stability 加成（默认 0.06 = 6%）"),
    "store_vfs.dce_max_boost": (0.12, float, 0.0, 0.30, None,
        "iter495: DCE 最大 stability 加成（默认 0.12 = 12%）"),
    "store_vfs.dce_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter495: 触发 DCE 的最低 importance 阈值（默认 0.20）"),
    "store_vfs.dce_min_content_len": (50, int, 10, 500, None,
        "iter495: 触发 DCE 的最小 content 长度（默认 50）"),
    # ── iter496: Survival Processing Effect (SPE) — Nairne 2007 ──
    "store_vfs.spe_enabled": (True, bool, None, None, None,
        "iter496: 是否启用 Survival Processing Effect（默认 True）"),
    "store_vfs.spe_survival_keywords": (
        ["critical", "urgent", "blocked", "broken", "crash", "fatal", "security",
         "deadline", "blocker", "emergency", "outage", "incident", "rollback",
         "紧急", "关键", "阻塞", "崩溃", "故障", "安全", "死锁", "回滚"],
        list, None, None, None,
        "iter496: 生存相关关键词（触发 SPE 加分）"),
    "store_vfs.spe_stability_bonus": (0.10, float, 0.0, 0.25, None,
        "iter496: 生存相关 chunk 的 stability 加成（默认 0.10 = 10%）"),
    "store_vfs.spe_importance_bonus": (0.05, float, 0.0, 0.15, None,
        "iter496: 生存相关 chunk 的 importance 加成（默认 0.05）"),
    "store_vfs.spe_max_boost": (0.15, float, 0.0, 0.35, None,
        "iter496: SPE 最大 stability 加成（默认 0.15 = 15%）"),
    "store_vfs.spe_min_importance": (0.15, float, 0.0, 1.0, None,
        "iter496: 触发 SPE 的最低 importance 阈值（默认 0.15）"),
    # ── iter497: Bizarreness Effect (BZE) — McDaniel & Einstein 1986 ──
    "store_vfs.bze_enabled": (True, bool, None, None, None,
        "iter497: 是否启用 Bizarreness Effect（默认 True）"),
    "store_vfs.bze_rare_type_threshold": (0.10, float, 0.01, 0.50, None,
        "iter497: chunk_type 频率低于该阈值视为'奇异'（默认 0.10 = 10%）"),
    "store_vfs.bze_stability_bonus": (0.08, float, 0.0, 0.20, None,
        "iter497: 奇异 chunk 的 stability 加成（默认 0.08 = 8%）"),
    "store_vfs.bze_max_boost": (0.14, float, 0.0, 0.30, None,
        "iter497: BZE 最大 stability 加成（默认 0.14 = 14%）"),
    "store_vfs.bze_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter497: 触发 BZE 的最低 importance 阈值（默认 0.20）"),
    # ── iter498: Concreteness Effect (CCE) — Paivio 1969 ──
    "store_vfs.cce_enabled": (True, bool, None, None, None,
        "iter498: 是否启用 Concreteness Effect（默认 True）"),
    "store_vfs.cce_concrete_indicators": (
        ["具体", "例如", "比如", "e.g.", "for example", "specifically",
         "数字", "百分比", "%", "ms", "MB", "GB", "次", "个",
         "http", "path:", "file:", "line:", "column:"],
        list, None, None, None,
        "iter498: 具体性指标关键词"),
    "store_vfs.cce_min_indicators": (2, int, 1, 10, None,
        "iter498: 触发 CCE 所需最少指标数（默认 2）"),
    "store_vfs.cce_stability_bonus": (0.05, float, 0.0, 0.15, None,
        "iter498: 具体 chunk 的 stability 加成（默认 0.05 = 5%）"),
    "store_vfs.cce_max_boost": (0.10, float, 0.0, 0.25, None,
        "iter498: CCE 最大 stability 加成（默认 0.10 = 10%）"),
    "store_vfs.cce_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter498: 触发 CCE 的最低 importance 阈值（默认 0.20）"),
    # ── iter499: Picture Superiority Effect (PSE) — Shepard 1967 ──
    "store_vfs.pse_enabled": (True, bool, None, None, None,
        "iter499: 是否启用 Picture Superiority Effect（默认 True）"),
    "store_vfs.pse_structure_indicators": (
        ["| ", "- [ ]", "- [x]", "1. ", "2. ", "3. ", "=>", "->",
         "┌", "├", "└", "│", "===", "---", "***", "```"],
        list, None, None, None,
        "iter499: 结构化/图示指标（table/list/diagram markers）"),
    "store_vfs.pse_min_indicators": (2, int, 1, 10, None,
        "iter499: 触发 PSE 所需最少指标数（默认 2）"),
    "store_vfs.pse_stability_bonus": (0.07, float, 0.0, 0.20, None,
        "iter499: 结构化 chunk 的 stability 加成（默认 0.07 = 7%）"),
    "store_vfs.pse_max_boost": (0.14, float, 0.0, 0.30, None,
        "iter499: PSE 最大 stability 加成（默认 0.14 = 14%）"),
    "store_vfs.pse_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter499: 触发 PSE 的最低 importance 阈值（默认 0.20）"),
    # ── iter500: Anchoring Effect (AE) — Tversky & Kahneman 1974 ──
    "store_vfs.ae_enabled": (True, bool, None, None, None,
        "iter500: 是否启用 Anchoring Effect（默认 True）"),
    "store_vfs.ae_early_percentile": (0.10, float, 0.01, 0.30, None,
        "iter500: 项目内最早 N% 的 chunk 视为 anchor（默认 10%）"),
    "store_vfs.ae_stability_bonus": (0.06, float, 0.0, 0.15, None,
        "iter500: anchor chunk 的 stability 加成（默认 0.06 = 6%）"),
    "store_vfs.ae_max_boost": (0.10, float, 0.0, 0.20, None,
        "iter500: AE 最大 stability 加成（默认 0.10 = 10%）"),
    "store_vfs.ae_min_importance": (0.25, float, 0.0, 1.0, None,
        "iter500: 触发 AE 的最低 importance 阈值（默认 0.25）"),
    "store_vfs.ae_min_project_chunks": (10, int, 5, 100, None,
        "iter500: 项目至少 N 个 chunk 才触发 AE（默认 10）"),
    # ── iter501: Negative Bias Effect (NBE) — Baumeister 2001 ──
    "store_vfs.nbe_enabled": (True, bool, None, None, None,
        "iter501: 是否启用 Negative Bias Effect（默认 True）"),
    "store_vfs.nbe_negative_keywords": (
        ["bug", "error", "failure", "crash", "broken", "regression", "issue",
         "wrong", "incorrect", "leak", "overflow", "timeout", "reject",
         "缺陷", "错误", "失败", "崩溃", "泄漏", "超时", "拒绝"],
        list, None, None, None,
        "iter501: 负面信息关键词"),
    "store_vfs.nbe_stability_bonus": (0.07, float, 0.0, 0.20, None,
        "iter501: 负面信息 chunk 的 stability 加成（默认 0.07 = 7%）"),
    "store_vfs.nbe_max_boost": (0.12, float, 0.0, 0.25, None,
        "iter501: NBE 最大 stability 加成（默认 0.12 = 12%）"),
    "store_vfs.nbe_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter501: 触发 NBE 的最低 importance 阈值（默认 0.20）"),
    # ── iter502: Temporal Landmark Effect (TLE) — Shum 1998 ──
    "store_vfs.tle_enabled": (True, bool, None, None, None,
        "iter502: 是否启用 Temporal Landmark Effect（默认 True）"),
    "store_vfs.tle_landmark_keywords": (
        ["deploy", "release", "merge", "ship", "launch", "milestone",
         "v1.", "v2.", "v3.", "hotfix", "rollout", "go-live",
         "上线", "发布", "部署", "合并", "里程碑"],
        list, None, None, None,
        "iter502: 时间地标关键词"),
    "store_vfs.tle_stability_bonus": (0.08, float, 0.0, 0.20, None,
        "iter502: 时间地标 chunk 的 stability 加成（默认 0.08 = 8%）"),
    "store_vfs.tle_max_boost": (0.12, float, 0.0, 0.25, None,
        "iter502: TLE 最大 stability 加成（默认 0.12 = 12%）"),
    "store_vfs.tle_min_importance": (0.20, float, 0.0, 1.0, None,
        "iter502: 触发 TLE 的最低 importance 阈值（默认 0.20）"),
    # ── iter503: Writeback Pressure — Zero-Access Ratio Admission Control ──
    "store_vfs.writeback_pressure_enabled": (True, bool, None, None, None,
        "iter503: 是否启用写入反压（默认 True）"),
    "store_vfs.writeback_dirty_ratio": (0.70, float, 0.0, 1.0, None,
        "iter503: 零访问率超过此阈值时触发反压（默认 0.70 = 70%）"),
    "store_vfs.writeback_dirty_bg_ratio": (0.50, float, 0.0, 1.0, None,
        "iter503: 零访问率超过此阈值时轻度降级（默认 0.50 = 50%）"),
    "store_vfs.writeback_throttle_factor": (0.6, float, 0.1, 1.0, None,
        "iter503: 超过 dirty_ratio 时 importance 乘以此因子（默认 0.6）"),
    "store_vfs.writeback_bg_throttle_factor": (0.85, float, 0.1, 1.0, None,
        "iter503: 超过 dirty_bg_ratio 时 importance 乘以此因子（默认 0.85）"),
    "store_vfs.writeback_min_chunks": (20, int, 1, 10000, None,
        "iter503: 至少 N 个 chunks 后才启用反压（避免冷启动误判，默认 20）"),

    # ── iter505: shrink_dcache — Cross-Project Stale Object Reclaim ──
    "shrink.min_age_days": (3, int, 1, 90, None,
        "iter505: 零访问 chunk 至少存活 N 天后才参与回收（默认 3）"),
    "shrink.max_reclaim_per_scan": (50, int, 5, 500, None,
        "iter505: 每次 SessionStart 最多回收 N 个 chunks（默认 50）"),
    "shrink.min_total_chunks": (30, int, 5, 1000, None,
        "iter505: 至少 N 个 chunks 后才启用 shrink（冷启动保护，默认 30）"),
    "shrink.demote_high_factor": (0.6, float, 0.1, 1.0, None,
        "iter505: importance >= 0.8 的 chunk 降级因子（默认 0.6）"),
    "shrink.demote_low_factor": (0.4, float, 0.1, 1.0, None,
        "iter505: importance < 0.8 的 chunk 降级因子（默认 0.4）"),
    "shrink.delete_threshold": (0.2, float, 0.05, 0.5, None,
        "iter505: 降级后 importance < 此值直接删除（默认 0.2）"),

    # ── oom_reaper（迭代508）──
    "oom_reaper.enabled": (True, bool, None, None, None,
        "iter508: 是否启用 oom_reaper 零访问率治理（默认 True）"),
    "oom_reaper.zero_access_threshold": (0.7, float, 0.3, 0.95, None,
        "iter508: 零访问率超过此比例时触发 oom_reaper（默认 0.7 = 70%）"),
    "oom_reaper.max_reap_per_scan": (30, int, 5, 200, None,
        "iter508: 每次扫描最多回收 N 个 chunks（默认 30）"),
    "oom_reaper.importance_decay": (0.5, float, 0.1, 0.9, None,
        "iter508: importance 降级因子（默认 0.5，即减半）"),
    "oom_reaper.min_total_chunks": (50, int, 10, 1000, None,
        "iter508: 至少 N 个 chunks 后才启用（冷启动保护，默认 50）"),
    "oom_reaper.protect_types": ("design_constraint,quantitative_evidence", str, None, None, None,
        "iter508: 受保护的 chunk_type（逗号分隔），即使零访问也不回收"),

    # ── iter542: oom_reaper_onfault — MLOCK_ONFAULT Demotion Reaper ──
    "oom_reaper_onfault.grace_sessions": (3, int, 1, 20, None,
        "iter542: ONFAULT chunk 宽限 session 数（默认 3，至少 N 轮曝光机会后才降级）"),
    "oom_reaper_onfault.max_per_scan": (10, int, 1, 50, None,
        "iter542: 单次扫描最大降级数（默认 10）"),

    # ── iter513: overcommit_kill — Global Layer Aggressive Reclaim ──
    "overcommit.zero_access_threshold": (0.6, float, 0.3, 0.95, None,
        "iter513: global 层零访问率超过此比例时触发（默认 0.6 = 60%）"),
    "overcommit.max_reap_per_scan": (50, int, 10, 200, None,
        "iter513: 每次扫描最多回收 N 个 global chunks（默认 50）"),
    "overcommit.importance_decay": (0.3, float, 0.1, 0.8, None,
        "iter513: importance 激进降级因子（默认 0.3，比 oom_reaper 的 0.5 更狠）"),
    "overcommit.min_global_chunks": (30, int, 5, 500, None,
        "iter513: global 层至少 N 个 chunks 后才启用（冷启动保护）"),
    "overcommit.delete_threshold": (0.35, float, 0.1, 0.8, None,
        "iter513: 降级后 importance < 此值直接删除（默认 0.35，比 oom_reaper 的 0.2 更积极）"),

    # ── iter510: vma_merge — Recall Trace Deduplication ──
    "vma_merge.jaccard_threshold": (0.8, float, 0.5, 1.0, None,
        "iter510: 相邻 traces Jaccard >= 此阈值时触发模糊合并（默认 0.8）"),
    "vma_merge.max_merge_per_scan": (100, int, 10, 500, None,
        "iter510: 每次扫描最多合并 N 条 traces（默认 100）"),

    # ── iter511: page_idle — 空闲页面追踪 ──
    "page_idle.demote_rounds": (3, int, 2, 10, None,
        "iter511: 连续 idle ≥ N 轮时执行 importance 降级（默认 3）"),
    "page_idle.delete_rounds": (5, int, 3, 15, None,
        "iter511: 连续 idle ≥ N 轮且降级后 importance<0.2 时删除（默认 5）"),
    "page_idle.decay_factor": (0.7, float, 0.3, 0.95, None,
        "iter511: 每次降级时 importance *= decay_factor（默认 0.7）"),
    "page_idle.demote_oom_adj": (200, int, 50, 500, None,
        "iter511: 每次降级时 oom_adj += N，加速后续回收（默认 200）"),

    # ── iter528: munlock_idle — 撤销过期 mlock 保护 ──
    # OS 类比：Linux munlock() + MADV_COLD (Minchan Kim, 2019) — 撤销不再活跃的 mlock 保护
    "munlock.idle_rounds": (5, int, 3, 20, None,
        "iter528: page_idle 连续 idle 轮次达此阈值时撤销 mlock（默认 5 轮）"),
    "munlock.grace_days": (7, int, 3, 30, None,
        "iter528: design_constraint 创建后 N 天内不 munlock（宽限期，默认 7 天）"),
    "munlock.max_per_scan": (20, int, 5, 50, None,
        "iter528: 单次 scan 最多 munlock 的 chunk 数（默认 20）"),

    # ── ksm_scan（迭代514）——同页合并扫描器 ──
    # OS 类比：Linux KSM (Andrea Arcangeli, 2009) — ksmd 扫描相同页面并合并为 COW 共享页
    "ksm_scan.min_group_size": (3, int, 2, 10, None,
        "相同前缀 fingerprint 的最小 chunk 数才触发合并（防误杀）"),
    "ksm_scan.max_merge_per_scan": (60, int, 10, 200, None,
        "单次扫描最多合并/删除的 chunk 数量（批次限制）"),
    "ksm_scan.prefix_chars": (20, int, 10, 50, None,
        "fingerprint 中 bracket topic 后取多少字符（越短越激进，越长越精确）"),
    "ksm_scan.protect_min_access": (2, int, 1, 10, None,
        "access_count >= N 的 chunk 不被合并（已有实战价值）"),

    # ── 迭代515：userfaultfd — Demand-Paged Import 按需导入 ──
    # iter599: import_importance_boost — 0.15→0.40 打破 cold-start 死锁
    # 根因（数据驱动，2026-05-03）：26 个 import chunk 全部 access_count=0。
    #   importance=0.15 时 retrieval_score ≈ relevance × 0.08，低于 min_score_threshold=0.3，
    #   永远进不了 top_k → 永远不触发 userfaultfd_promote → 死锁。
    #   0.50 使 score ≈ relevance × 0.635，rel=0.5 时 score=0.32 > min_threshold=0.30。
    #   rel≥0.5 的 FTS 命中即可进入 top_k 触发 userfaultfd_promote。
    "userfaultfd.import_base_importance": (0.50, float, 0.05, 0.6, None,
        "import_knowledge 写入 chunks 的基础 importance（iter599: 0.15→0.50 打破 cold-start 死锁）"),
    "userfaultfd.import_oom_adj": (300, int, 0, 800, None,
        "import 写入 chunks 的 oom_adj（高值 = 优先被回收，降低 reclaim 压力）"),
    "userfaultfd.promote_importance": (0.75, float, 0.5, 0.95, None,
        "首次检索命中 import chunk 时提升到的 importance（page fault 处理）"),
    "userfaultfd.promote_oom_adj": (0, int, -500, 300, None,
        "首次检索命中 import chunk 时设置的 oom_adj（0=默认保护级别）"),

    # ── 迭代516：MADV_FREE — 惰性页面回收 ──
    "madv_free.min_age_days": (7, int, 1, 30, None,
        "最短曝光窗口（天）：import chunk 创建后 N 天内不处理，给予充足检索机会"),
    "madv_free.delete_age_days": (21, int, 7, 90, None,
        "超长期无用删除阈值（天）：超过 N 天仍未被命中则直接删除"),
    "madv_free.lazy_threshold": (0.4, float, 0.1, 0.6, None,
        "lazy 状态 importance 上限：低于此值视为未被 promote 的 lazy page"),
    "madv_free.max_per_scan": (60, int, 10, 200, None,
        "单次扫描最大处理数：防止一次性大量修改导致 WAL 膨胀"),

    # ── iter518: migrate_pages — Cross-NUMA Page Migration ──
    # OS 类比：Linux migrate_pages() (Christoph Lameter, 2006)
    "migrate.max_per_scan": (50, int, 5, 200, None,
        "单次最大迁移 chunk 数：防止大事务"),
    "migrate.min_source_chunks": (2, int, 1, 10, None,
        "源 project 最少 chunk 数才值得迁移"),

    # ── iter519: mem_scrub — ECC Memory Patrol Scrub ──
    # OS 类比：Intel EDAC patrol scrub (2005) — 后台巡检 DRAM 修复 ECC CE
    "scrub.max_per_scan": (40, int, 5, 200, None,
        "单次最大修复 chunk 数：防止大事务"),
    "scrub.ue_oom_adj": (900, int, 500, 1000, None,
        "不可修复腐蚀(UE)的 oom_adj：高值加速回收"),

    # ── iter520: mmu_notifier — Inline Reference Invalidation ──
    # OS 类比：Linux mmu_notifier (Andrea Arcangeli, 2008) — page unmap 时同步清理 secondary TLB
    "criu.max_global_checkpoints": (10, int, 3, 50, None,
        "全局 checkpoint 上限：所有 session 合计不超过此数，防止 per-session 隔离导致全局膨胀"),

    # ── iter521: free_pages_ok — Dead Page Frame Final Reclaim ──
    "free_pages.dead_threshold": (0.20, float, 0.05, 0.5, None,
        "importance 低于此值视为 dead page frame（默认 0.2）"),
    "free_pages.max_per_scan": (40, int, 5, 200, None,
        "每次 SessionStart 最多释放 N 个 dead chunks（默认 40）"),

    # ── iter530: put_page — Unified Final Release + Bitmap Scrub ──
    "put_page.oom_max_decay": (0.4, float, 0.1, 0.8, None,
        "OOM_ADJ_MAX chunks 强制降级因子（默认 0.4：imp × 0.4）"),
    "put_page.oom_max_delete_threshold": (0.3, float, 0.1, 0.5, None,
        "OOM_ADJ_MAX chunks imp 低于此值直接删除（默认 0.3）"),

    # ── iter522: numa_balancing — Access-Pattern Importance Rebalancing ──
    "numa_balancing.promote_min_access": (3, int, 1, 20, None,
        "Promote 触发的最低 access_count（默认 3：至少被召回 3 次才算实战验证）"),
    "numa_balancing.promote_floor": (0.70, float, 0.3, 0.95, None,
        "Promote 后 importance 的下限值（默认 0.70）"),
    "numa_balancing.demote_min_importance": (0.70, float, 0.3, 0.99, None,
        "Demote 触发的最低 importance（默认 0.70：只下调高估值，不碰已经低的）"),
    "numa_balancing.demote_decay": (0.70, float, 0.3, 0.95, None,
        "Demote 衰减因子（默认 0.70：imp × 0.7）"),
    "numa_balancing.demote_min_age_days": (3, int, 1, 30, None,
        "Demote 最低存活天数（默认 3：新 chunk 有宽限期）"),
    "numa_balancing.max_per_scan": (30, int, 5, 100, None,
        "每次 SessionStart 最多 rebalance 的 chunk 数（默认 30）"),

    # ── iter524: mincore — Memory Residency Validation ──
    "mincore.high_importance_threshold": (0.70, float, 0.3, 0.99, None,
        "高 importance 门槛：只检查 >= 此值的 chunks 驻留状态（默认 0.70）"),
    "mincore.anomaly_ratio": (0.50, float, 0.2, 0.9, None,
        "异常比率：高 imp 中零访问占比超过此阈值时触发校准（默认 0.50）"),
    "mincore.calibration_decay": (0.75, float, 0.3, 0.95, None,
        "校准衰减因子：非驻留 chunk importance *= decay（默认 0.75）"),
    "mincore.max_per_scan": (30, int, 5, 100, None,
        "每次扫描最多校准的 chunk 数（默认 30）"),

    # ── iter532: cpuset — FTS5 Index Quarantine for Bandwidth Violators ──
    "cpuset.bw_quarantine_pct": (0.50, float, 0.30, 0.90, None,
        "召回率超过此阈值时触发 FTS5 隔离（默认 0.50：窗口内出现>50%即隔离）"),
    "cpuset.cooldown_sessions": (3, int, 1, 10, None,
        "隔离冷却期（session 数）：经过 N 次 SessionStart 后自动解除隔离恢复 FTS5"),
    "cpuset.max_quarantine": (5, int, 1, 20, None,
        "同时最多隔离的 chunk 数（防止过度隔离导致信息真空）"),
    "cpuset.min_traces": (10, int, 5, 50, None,
        "触发判定所需最低 recall_traces 数（样本不足时跳过）"),

    # ── iter533: vfs_write_protect — LSM Mandatory Write Check ──
    "vfs.write_protect_enabled": (True, bool, None, None, None,
        "VFS 层写保护开关（默认 True：拦截碎片写入）。测试/迁移时可设为 False 绕过"),

    # ── iter534: io_uring SQE validation — 写入时内容密度验证 ──
    "extractor.sqe_validate_enabled": (True, bool, None, None, None,
        "SQE 内容密度验证开关（默认 True）。验证 summary 信息密度，低密度降级 importance"),
    "extractor.sqe_low_density_cap": (0.60, float, 0.20, 0.90, None,
        "低密度内容的 importance 上限（默认 0.60）。信号不足的 chunk 不超过此值"),

    # ── iter539: ulimit_nproc — Per-Invocation Chunk Write Rate Limit ──
    "extractor.ulimit_nproc": (8, int, 2, 30, None,
        "单次 extractor 调用最多写入的 chunk 数（防止知识 fork bomb）。"
        "超过时按 importance 排序取 Top-N，低优先级 chunk 被丢弃"),

    # ── iter536: seccomp_filter — Summary Content Sanitizer ──
    "vfs.seccomp_filter_enabled": (True, bool, None, None, None,
        "seccomp BPF 过滤器开关（默认 True）。检测并清洗 summary 中的 JSON 残留/截断碎片"),

    # ── iter537: perf_counters — Retrieval Quality PMU Counters ──
    "perf.low_score_threshold": (0.40, float, 0.10, 0.80, None,
        "低质量注入判定阈值。score < 此值的注入 chunk 计入 low_score_count"),
    "perf.autotune_enabled": (True, bool, None, None, None,
        "perf_counters 驱动的 min_score_threshold 自适应调节开关"),
    "perf.raise_threshold_pct": (20.0, float, 5.0, 50.0, None,
        "low_score_ratio 超过此百分比时提高 min_score_threshold（默认20%：超1/5注入低分则收紧）"),
    "perf.lower_threshold_pct": (0.0, float, 0.0, 20.0, None,
        "low_score_ratio 低于此百分比且avg_score高时降低阈值（默认0%：必须完全无低分才放松）"),
    "perf.threshold_max": (0.40, float, 0.30, 0.80, None,
        "min_score_threshold 自动调节上限（iter695: 0.50→0.40，防止阈值过高导致72%空注入）"),
    "perf.threshold_min": (0.20, float, 0.05, 0.40, None,
        "min_score_threshold 自动调节下限（保证最低过滤标准）"),

    # ── iter543: refault_distance — Constraint Force-Injection Relevance Gate ──
    # OS 类比：Linux workingset.c refault_distance (Johannes Weiner, 2018, kernel 4.18)
    # 页面 refault 时，只有 refault_distance < working_set_size 才 promote 到 active list。
    # 否则视为 streaming/scanning access，保持 inactive 防止 cache pollution。
    # memory-os 等价：design_constraint 强制注入时，只有 query-Jaccard >= min_relevance 才注入，
    # 否则视为"不在工作集内"的无关约束，跳过以防止 Top-K 被同一约束跨 query 垄断。
    "retriever.constraint_min_relevance": (0.05, float, 0.0, 0.5, None,
        "design_constraint 强制注入的最低 Jaccard 相关性门槛（iter543：低于此值视为 refault_distance 过远，不注入）"),
    "retriever.constraint_thrash_max_pct": (0.20, float, 0.1, 0.8, None,
        "design_constraint 跨 query 出现率超此比例时触发 thrash dampener，降低注入优先级（iter543; iter587: 0.40→0.20 收紧反垄断）"),
    "retriever.constraint_inject_hard_cap": (0.30, float, 0.1, 0.9, None,
        "design_constraint 注入频率硬上限：recall_count/effective_window > 此值时无条件 suppress，不论 relevance 多高（iter596; iter598: 0.50→0.30 与 thrash_max_pct 对齐，加速垄断衰减）"),

    # ── iter544: trim_shadow_entries — Shadow Entry Expiry & Stale Ref Scrub ──
    # OS 类比：Linux shadow_lru_isolate() (Johannes Weiner, 2013, mm/workingset.c)
    # shadow entry 超过 active page count 时从 LRU 尾部批量回收最老条目。
    "shadow.max_entries": (100, int, 20, 1000, None,
        "shadow_traces 最大保留条目数，超出从最老开始淘汰（iter544）"),
    "shadow.max_expire_per_scan": (200, int, 10, 500, None,
        "单次扫描最大淘汰条目数（iter544：防止单次 GC 时间过长）"),

    # ── iter545: vmstat_scan — Scan Efficiency Accounting & Dark Page Demotion ──
    # OS 类比：/proc/vmstat pgscan/pgsteal counters (Mel Gorman, 2004)
    "vmstat.window_traces": (50, int, 10, 200, None,
        "vmstat 统计窗口大小（最近 N 条 recall_traces）"),
    "vmstat.min_traces_dark": (5, int, 2, 20, None,
        "触发 dark page 检测的最少 trace 数（新项目不误判）"),
    "vmstat.dark_demote_adj": (400, int, 100, 800, None,
        "dark page 降级 oom_adj 值（越高越容易被回收）"),
    "vmstat.max_demote_per_scan": (5, int, 1, 20, None,
        "单次扫描最大降级 dark page 数（渐进式，避免误杀）"),

    # ── iter546: shrink_slab — Periodic Slab Object Reaper ──
    # OS 类比：do_shrink_slab() (Dave Chinner, 2013, mm/vmscan.c)
    "shrink.min_adj": (400, int, 200, 800, None,
        "触发 slab 回收的最低 oom_adj 阈值（>=此值+零访问才回收）"),
    "shrink.max_scan_per_run": (5, int, 1, 20, None,
        "单次扫描最大回收数（渐进式，防止单次大量 swap_out）"),
    "shrink.grace_sessions": (3, int, 1, 10, None,
        "新创建 chunk 的宽限 session 数（最近 N session 内创建的跳过）"),

    # ── iter547: fstrim — Auxiliary Table Dead Block TRIM ──
    "fstrim.enabled": (True, bool, None, None, None,
        "是否启用 fstrim 辅助表死块清理"),

    # ── iter548: logrotate — Metadata Table Lifecycle Rotation ──
    "logrotate.enabled": (True, bool, None, None, None,
        "是否启用 logrotate 元数据表生命周期轮转"),
    "logrotate.ipc_msgq_max_age_hours": (48, int, 1, 720, None,
        "ipc_msgq 已消费消息的最大保留时间（小时）"),
    "logrotate.hook_txn_log_max_entries": (200, int, 50, 2000, None,
        "hook_txn_log 最大保留条数（FIFO 淘汰最旧）"),
    "logrotate.session_focus_max_age_hours": (72, int, 1, 720, None,
        "session_focus 过期时间（小时）"),
    "logrotate.priming_max_per_project": (100, int, 10, 1000, None,
        "priming_state 每个 project 最大条数（按 prime_strength 淘汰最弱）"),
    "logrotate.tool_patterns_max_entries": (300, int, 50, 2000, None,
        "tool_patterns 最大保留条数（按 frequency+recency 淘汰）"),
    "logrotate.entity_edges_orphan_max_age_hours": (72, int, 1, 720, None,
        "entity_edges 无 source_chunk_id 的 orphan edges 最大保留时间（小时）"),

    # ── iter585: tmpfiles_d — Per-Session State File Reaper ──
    "tmpfiles_d.enabled": (True, bool, None, None, None,
        "是否启用 tmpfiles_d per-session 状态文件清理"),
    "tmpfiles_d.max_age_hours": (24, int, 1, 168, None,
        "per-session 状态文件的最大保留时间（小时）"),
    "tmpfiles_d.max_cold_sync_entries": (200, int, 50, 2000, None,
        "cold_sync_state.json 最大保留条目数"),

    # ── iter586: proactive_compaction — Fragmentation Index Driven Chunk Consolidation ──
    # OS 类比：Linux proactive memory compaction (Nitin Gupta, 2019, kernel 5.9)
    # — 主动扫描 zone fragmentation index，在 OOM 前整理碎片
    "proactive_compaction.enabled": (True, bool, None, None, None,
        "是否启用 proactive_compaction 退化 chunk 碎片整理"),
    "proactive_compaction.frag_threshold": (0.25, float, 0.05, 0.80, None,
        "碎片指标阈值（退化+重复 / alive），超过才触发 compaction"),
    "proactive_compaction.demote_oom_adj": (150, int, 50, 250, None,
        "退化 chunk 降级目标 oom_adj（加速 OOM reaper 回收）"),
    "proactive_compaction.max_actions_per_scan": (20, int, 1, 100, None,
        "单次 compaction 最大操作数（删除+降级总计上限）"),

    # ── iter587: folio_referenced — Importance Spread via Rank-Percentile Mapping ──
    # OS 类比：Linux folio_referenced() (Nick Piggin, 2004; Matthew Wilcox, 2022)
    # — 周期性 clear + re-observe PTE Accessed bit，区分 hot 与 merely present
    "folio_referenced.enabled": (True, bool, None, None, None,
        "是否启用 folio_referenced importance 分布展开"),
    "folio_referenced.blend_ratio": (0.15, float, 0.05, 0.50, None,
        "融合比例 α：new_imp = old×(1-α) + target×α（越大越激进）"),
    "folio_referenced.imp_floor": (0.45, float, 0.20, 0.60, None,
        "rank-percentile 映射的 importance 下界"),
    "folio_referenced.imp_ceil": (0.95, float, 0.80, 1.00, None,
        "rank-percentile 映射的 importance 上界"),
    "folio_referenced.max_delta_per_chunk": (0.08, float, 0.02, 0.20, None,
        "单次最大 importance 调整幅度（防止剧烈波动）"),
    "folio_referenced.min_alive_chunks": (10, int, 3, 50, None,
        "最少 alive chunk 数量才执行（样本太少无意义）"),
    "folio_referenced.weight_access": (0.50, float, 0.0, 1.0, None,
        "composite score 中 access_count 权重"),
    "folio_referenced.weight_cum_score": (0.30, float, 0.0, 1.0, None,
        "composite score 中 cum_retrieval_score 权重"),
    "folio_referenced.weight_recency": (0.20, float, 0.0, 1.0, None,
        "composite score 中 recency（创建时间新近度）权重"),
    "folio_referenced.skip_types": (["task_state", "prompt_context"], list, None, None, None,
        "跳过不调整 importance 的 chunk 类型"),

    # ── iter563: prune_icache_sb — Metadata Table Proportional Reclaim ──
    "prune_icache_sb.enabled": (True, bool, None, None, None,
        "是否启用 prune_icache_sb 元数据引用/质量检查式清理"),
    "prune_icache_sb.min_entity_len": (4, int, 2, 10, None,
        "priming_state 实体名称最小长度（短于此值视为噪声 token 直接清除）"),
    "prune_icache_sb.max_txn_keep": (100, int, 20, 500, None,
        "hook_txn_log 最大保留条数（比 logrotate 更激进的 cap）"),

    # ── iter564: oom_score_adj_rebalance — Runtime OOM Score Recalibration ──
    "oom_rebalance.enabled": (True, bool, None, None, None,
        "是否启用 oom_score_adj_rebalance 运行时 OOM 分数重校准"),
    "oom_rebalance.max_adjustments": (20, int, 1, 100, None,
        "单次扫描最大调整 chunk 数"),
    "oom_rebalance.dead_min_age_days": (7.0, float, 1.0, 30.0, None,
        "R2 规则：零访问 chunk 必须超过此天数才升级 oom_adj（宽限期）"),
    "oom_rebalance.hot_min_access": (10, int, 3, 50, None,
        "R3 规则：access_count 达到此值才视为热 chunk 获 OOM 保护"),
    "oom_rebalance.r4_min_age_days": (1.0, float, 0.5, 30.0, None,
        "iter567 R4 规则：chunk 创建超过此天数 + 零访问 + _vma_validate 失败 → oom_adj=1000"),

    # ── iter568: shrink_dcache_sb — Immediate Fragment Reclaim ──
    "shrink_dcache_sb.enabled": (True, bool, None, None, None,
        "是否启用即时碎片回收（无 age 门控，直接删除 VFS 层拒绝的 zero-access chunk）"),
    "shrink_dcache_sb.max_delete": (20, int, 1, 100, None,
        "单次 shrink_dcache_sb 最大删除数量（防止误删过多）"),

    # ── iter569: anon_vma_prepare — Entity Map Backfill ──
    "anon_vma_prepare.enabled": (True, bool, None, None, None,
        "是否启用 entity_map 回填（为无 rmap 基础设施的孤儿 chunk 建立 entity 连接）"),
    "anon_vma_prepare.max_backfill": (30, int, 5, 100, None,
        "单次最多处理的孤儿 chunk 数量（防止 boot 延迟过长）"),
    "anon_vma_prepare.min_entities": (3, int, 1, 10, None,
        "chunk 提取实体数低于此值时跳过（内容太少无法建立有效连接）"),

    # ── iter570: populate_pte — Entity Edge Target PTE Population ──
    "populate_pte.enabled": (True, bool, None, None, None,
        "是否启用 entity_edges 目标实体 PTE 回填（修复 spreading_activate 72.8% 死路）"),
    "populate_pte.max_populate": (50, int, 10, 200, None,
        "单次最多建立 PTE 的实体数量（防止 boot 延迟过长）"),
    "populate_pte.min_entity_len": (3, int, 2, 10, None,
        "实体名最小长度（过滤噪声短词）"),

    # ── iter571: mmap_populate — Probabilistic Cold Page Promotion ──
    # OS 类比：MAP_POPULATE / madvise(MADV_WILLNEED) — 主动预填充 cold pages 到
    #   working set，打破 cold→no_access→cold 死锁循环
    # 与 IWCSI(iter334) 区别：IWCSI 只在 positive 不足时触发（被动），
    #   mmap_populate 每 N 次 FULL 召回无条件触发（主动），确保 dark pages 轮转曝光
    "mmap_populate.enabled": (True, bool, None, None, None,
        "是否启用 cold page 概率性轮转曝光（每 N 次 FULL 召回替换最低分 slot）"),
    "mmap_populate.interval": (3, int, 2, 10, None,
        "触发间隔：每 N 次 FULL 召回执行一次 cold page promotion（默认3，约1/3的召回会轮转）"),
    "mmap_populate.imp_threshold": (0.5, float, 0.3, 1.0, None,
        "cold page 最低 importance 门槛（只曝光有价值的 dark pages）"),
    "mmap_populate.exclude_types": ("prompt_context,conversation_summary", str, None, None, None,
        "排除的 chunk_type（逗号分隔）：这些类型不适合强制曝光"),

    # ── iter582: scan_unevictable — Round-Robin Dark Page Batch Exposure ──
    "scan_unevictable.enabled": (True, bool, None, None, None,
        "是否启用 round-robin dark page 批量曝光（每次 FULL 召回注入额外 diversity slots）"),
    "scan_unevictable.max_inject": (2, int, 1, 5, None,
        "每次 FULL 召回注入的 dark page 数量（额外 slot，不替换现有 top_k）"),
    "scan_unevictable.imp_threshold": (0.5, float, 0.2, 1.0, None,
        "dark page 最低 importance 门槛（只曝光有价值的 dark pages）"),
    "scan_unevictable.exclude_types": ("prompt_context,conversation_summary", str, None, None, None,
        "排除的 chunk_type（逗号分隔）：这些类型不适合强制曝光"),

    # ── iter572: kcompactd — Proactive Dead Page Reclaim ──
    # ── iter581: ksoftirqd — Runtime Reclaim Trigger ──
    "ksoftirqd.enabled": (True, bool, None, None, None,
        "是否启用写入路径 softirq（检测 zombie/高零访问率 → 标志文件触发下次 reclaim）"),
    "ksoftirqd.zero_threshold": (0.40, float, 0.20, 0.80, None,
        "零访问率阈值：超过此值时 raise softirq（强制下次 session reclaim）"),

    "kcompactd.enabled": (True, bool, None, None, None,
        "是否启用主动 dead page 回收（oom_adj 驱动，不受 kswapd watermark 门控）"),
    "kcompactd.oom_threshold": (300, int, 100, 1000, None,
        "触发回收的最低 oom_adj 值（R2 标记为 300，R4 标记为 1000）"),
    "kcompactd.imp_ceiling": (0.3, float, 0.1, 0.8, None,
        "importance 上限：只回收低价值 chunks（防止误删高价值 chunk）"),
    "kcompactd.min_age_days": (3.0, float, 0.5, 30.0, None,
        "最小年龄保护（天）：新 chunk 有时间通过 mmap_populate 获得曝光机会"),
    "kcompactd.max_delete": (20, int, 5, 50, None,
        "单次扫描最大删除量（防止批量删除冲击 FTS5 索引）"),

    # ── iter573: folio_batch_drain — Converging Signal Batch Reclaim ──
    "folio_batch.enabled": (True, bool, None, None, None,
        "是否启用多信号收敛批量回收（page_idle 确认 + oom_adj 标记 → 提前回收）"),
    "folio_batch.oom_threshold": (300, int, 100, 1000, None,
        "触发回收的最低 oom_adj 值（与 kcompactd 共用 R2 标记阈值）"),
    "folio_batch.imp_ceiling": (0.3, float, 0.1, 0.8, None,
        "importance 上限：只回收低价值 chunks"),
    "folio_batch.min_idle_rounds": (2, int, 1, 10, None,
        "page_idle bitmap 中最少空闲轮次（替代 kcompactd 的 min_age_days 时间门控）"),
    "folio_batch.max_drain": (20, int, 5, 50, None,
        "单次批量 flush 最大删除量"),

    # ── iter575: unlink_anon_vmas — Dead Edge Pruning ──
    "unlink_anon_vmas.enabled": (True, bool, None, None, None,
        "是否启用 entity_edges 死边清理（两端 entity 不可达 → 删除）"),
    "unlink_anon_vmas.max_prune": (50, int, 10, 200, None,
        "单次最大删除 edge 数量"),
    "unlink_anon_vmas.prune_half_dangling": (True, bool, None, None, None,
        "是否清理只有一端可达的 half-dangling edges（保守模式=False 只清理两端都断的）"),

    # ── iter576: flush_tlb_one — Entity Map Stale Entry Invalidation ──
    "flush_tlb_one.enabled": (True, bool, None, None, None,
        "是否启用 entity_map stale 条目清理（指向 dead/ghost/orphan chunk 的映射）"),
    "flush_tlb_one.oom_threshold": (300, int, 100, 1000, None,
        "oom_adj >= 此值的 chunk 对应 entity_map 条目视为 dead（与 kcompactd 共用阈值）"),
    "flush_tlb_one.max_flush": (200, int, 50, 1000, None,
        "单次最大 flush entity_map 条目数量"),

    # ── iter549: vacuum — Database File Compaction ──
    "vacuum.enabled": (True, bool, None, None, None,
        "是否启用 VACUUM（DB 文件物理收缩）"),
    "vacuum.threshold_pct": (40.0, float, 10.0, 90.0, None,
        "freelist 页占比阈值（%）：超过此值才触发 VACUUM"),
    "vacuum.cooldown_hours": (24, int, 1, 168, None,
        "两次 VACUUM 之间的最小间隔（小时）"),
    "vacuum.min_size_kb": (512, int, 64, 102400, None,
        "DB 文件最小大小（KB）：小于此值不值得 VACUUM"),

    # ── iter550: release_task — Per-Session Runtime State Cleanup ──
    "release_task.enabled": (True, bool, None, None, None,
        "是否启用 per-session 运行时状态清理"),
    "release_task.shadow_file_max_age_hours": (24, int, 1, 720, None,
        ".shadow_trace.*.json 文件最大保留时间（小时）"),
    "release_task.shadow_db_max_per_content": (2, int, 1, 10, None,
        "shadow_traces 表每种 top_k_ids 内容最多保留条数"),
    "release_task.episodes_max_age_hours": (72, int, 1, 720, None,
        "已注入 session_episodes 最大保留时间（小时）"),
    "release_task.checkpoint_max_age_hours": (48, int, 1, 720, None,
        "已消费 checkpoints 最大保留时间（小时）"),

    # ── iter552: timer_slack — Idle Subsystem Frequency Reduction ──
    # OS 类比：Linux timer_slack_ns (Arjan van de Ven, 2008, kernel 2.6.28)
    "timer_slack.idle_threshold": (3, int, 1, 10, None,
        "连续空转 N 次后开始降频跳过"),
    "timer_slack.max_skip_sessions": (4, int, 1, 10, None,
        "最大连续跳过 session 数（指数退避上限）"),
    "timer_slack.enabled": (True, bool, None, None, None,
        "是否启用 timer_slack 子系统降频调度"),

    # ── iter551: initcall_debug — Boot Subsystem Latency Instrumentation ──
    # OS 类比：Linux initcall_debug (Arjan van de Ven, 2008, kernel 2.6.24)
    "initcall_debug.enabled": (True, bool, None, None, None,
        "是否启用 SessionStart per-subsystem 延迟追踪"),
    "initcall_debug.top_n": (5, int, 1, 30, None,
        "blame 输出中展示的 Top-N 最慢子系统数"),

    # ── iter553: sched_deadline — Per-Subsystem Runtime Budget Enforcement ──
    # OS 类比：Linux SCHED_DEADLINE (Luca Abeni & Juri Lelli, 2014, kernel 3.14)
    "sched_deadline.enabled": (True, bool, None, None, None,
        "是否启用 per-subsystem 运行时预算强制执行"),
    "sched_deadline.budget_ms": (20.0, float, 1.0, 200.0, None,
        "单个子系统 EMA 运行时预算上限(ms)，超出则 throttle"),
    "sched_deadline.throttle_sessions": (3, int, 1, 10, None,
        "超预算子系统被节流的 session 数"),

    # ── iter554: cgroup_budget — Subsystem Group Budget Enforcement ──
    # OS 类比：Linux cgroup v2 memory.max (Tejun Heo, 2015, kernel 4.5)
    "cgroup_budget.enabled": (True, bool, None, None, None,
        "是否启用子系统分组预算强制执行"),
    "cgroup_budget.group_budget_ms": (60.0, float, 10.0, 500.0, None,
        "每组子系统合计 EMA 预算上限(ms)，超出则 throttle 整组"),
    "cgroup_budget.throttle_sessions": (2, int, 1, 5, None,
        "超预算组被节流的 session 数"),

    # ── iter555: schedstat — Unified Scheduler Statistics Accumulator ──
    "schedstat.enabled": (True, bool, None, None, None,
        "是否启用跨 session 调度统计累积"),
    "schedstat.max_history_sessions": (20, int, 5, 100, None,
        "boot_times_ms 环形缓冲区保留的最近 session 数"),

    # ── iter556: sched_autogroup — Adaptive Scheduler Parameter Tuning ──
    # OS 类比：Linux sched_autogroup (Mike Galbraith, 2010, kernel 2.6.38)
    "sched_autogroup.enabled": (True, bool, None, None, None,
        "是否启用基于 schedstat 历史数据的自动调参"),
    "sched_autogroup.cooldown_sessions": (3, int, 1, 10, None,
        "两次自动调整之间的最少间隔 session 数"),
    "sched_autogroup.min_sessions": (5, int, 3, 20, None,
        "启动自动调参所需的最少历史 session 数"),

    # ── iter557: bdi_writeback — Boot-Time Dirty Page Writeback Audit ──
    # OS 类比：Linux bdi_writeback (Jens Axboe, 2009, kernel 2.6.32)
    #   per-BDI writeback 线程在 boot 时审计并回写 dirty pages
    # ── iter558: pelt — Per-Entity Load Tracking ──
    "pelt.enabled": (True, bool, None, None, None,
        "是否启用 PELT 写入准入控制"),
    "pelt.window_traces": (50, int, 10, 200, None,
        "计算 util_avg 使用的最近 recall_traces 条数"),
    "pelt.low_util_threshold": (0.15, float, 0.05, 0.50, None,
        "低利用率阈值——低于此值触发 importance 折扣"),
    "pelt.min_discount_factor": (0.50, float, 0.20, 0.90, None,
        "最大折扣因子——util_avg=0 时 importance 乘以此值"),

    # ── iter559: fair_clock — Cumulative Retrieval Score Importance Calibration ──
    # OS 类比：Linux CFS vruntime (Ingo Molnár, 2007, kernel 2.6.23, sched/fair.c)
    #   CFS 为每个 sched_entity 维护 vruntime（累积虚拟运行时间），
    #   基于实际 CPU time / weight。vruntime 反映"公平份额消耗量"——
    #   只有实际运行过才能积累 vruntime，纯静态优先级无法体现。
    "fair_clock.enabled": (True, bool, None, None, None,
        "是否启用基于累积检索分数的 importance 校准"),
    "fair_clock.window_traces": (50, int, 10, 200, None,
        "统计窗口大小（最近 N 条 recall_traces）"),
    "fair_clock.min_traces": (5, int, 2, 30, None,
        "触发校准的最小 trace 数（冷启动保护）"),
    "fair_clock.demote_min_importance": (0.70, float, 0.3, 0.99, None,
        "只降级 importance >= 此值的 chunk（不碰已经低的）"),
    "fair_clock.demote_decay": (0.75, float, 0.3, 0.95, None,
        "降级衰减因子（importance *= decay）"),
    "fair_clock.demote_min_age_days": (3, int, 1, 30, None,
        "降级宽限期天数（新 chunk 不动）"),
    "fair_clock.promote_min_cum_score": (2.0, float, 0.5, 10.0, None,
        "Promote 所需最低累积检索分数"),
    "fair_clock.promote_target": (0.75, float, 0.5, 0.95, None,
        "Promote 后 importance 的目标值"),
    "fair_clock.max_per_scan": (20, int, 3, 50, None,
        "每次扫描最多校准的 chunk 数"),

    # ── iter560: cfs_bandwidth — Per-Chunk Retrieval Frequency Throttle ──
    # OS 类比：Linux CFS Bandwidth Control (Paul Turner, Google, 2011, kernel 3.2, sched/fair.c)
    # 每个 cgroup 分配 quota/period 带宽上限；超额 task 被 throttled（移出 runqueue）。
    # 类比：recall_count > quota 的 chunk 在评分时被乘法降权，防止单 chunk 垄断 Top-K。
    "cfs_bandwidth.enabled": (True, bool, None, None, None,
        "是否启用 per-chunk 检索频次带宽限制"),
    "cfs_bandwidth.quota": (8, int, 3, 30, None,
        "每个 chunk 在 window 内的最大检索次数配额（超额触发 throttle）"),
    "cfs_bandwidth.throttle_factor": (0.50, float, 0.10, 0.90, None,
        "超额时的乘法降权因子（score *= factor），越小惩罚越重"),
    "cfs_bandwidth.overflow_decay": (0.85, float, 0.50, 0.99, None,
        "超额越多 throttle 越重：factor *= decay^(rc - quota)，渐进压制"),

    # ── iter566: memcg_stat — Cross-Project Recall Accounting ──
    "memcg_stat.enabled": (True, bool, None, None, None,
        "是否启用 global chunk 跨项目召回计数聚合（anti-monopoly 跨 namespace 生效）"),
    "memcg_stat.window": (60, int, 20, 200, None,
        "跨项目 recall_traces 回溯窗口大小（覆盖更大时间范围以反映系统级压力）"),

    # ── iter561: place_entity — CFS 公平初始化 ──
    "place_entity.enabled": (True, bool, None, None, None,
        "是否启用新 chunk importance 公平初始化（bulk import 低 imp 提升到 min_vruntime）"),
    "place_entity.grace_days": (1, int, 0, 7, None,
        "宽限期天数：只对存在超过 N 天的 chunk 执行 place_entity"),
    "place_entity.max_per_scan": (30, int, 5, 100, None,
        "单次扫描最多提升的 chunk 数"),
    "place_entity.floor_percentile": (25, int, 10, 50, None,
        "取活跃 chunk importance 的 P-N 作为 min_vruntime（公平起点）"),
    "place_entity.min_active_chunks": (5, int, 2, 20, None,
        "活跃 chunk 最少需要 N 个才建立 min_vruntime（冷启动保护）"),

    "shmem_link.enabled": (True, bool, None, None, None,
        "是否启用 entity co-occurrence 共享内存激活（spreading_activate 补充路径）"),
    "shmem_link.max_results": (5, int, 1, 20, None,
        "co-occurrence 激活最多返回的 chunk 数"),
    "shmem_link.min_shared_entities": (2, int, 1, 10, None,
        "门控：至少共享 N 个 entity 才激活（防 false sharing 噪声）"),
    "shmem_link.activation_score": (0.25, float, 0.05, 0.5, None,
        "co-occurrence 激活最高分（归一化上限）"),
    "shmem_link.entity_idf_weight": (True, bool, None, None, None,
        "是否启用 entity IDF 加权（稀有 entity 共享权重更高）"),

    "bdi_writeback.enabled": (True, bool, None, None, None,
        "是否启用 boot-time 内容质量审计"),
    "bdi_writeback.max_per_scan": (30, int, 5, 100, None,
        "单次审计最大处理 chunk 数"),
    "bdi_writeback.min_summary_len": (15, int, 8, 50, None,
        "summary 最短长度阈值（低于此为碎片）"),
    "bdi_writeback.demote_importance": (0.30, float, 0.1, 0.6, None,
        "低质量 chunk 降级目标 importance 上限"),
    "bdi_writeback.demote_oom_adj": (400, int, 100, 900, None,
        "低质量 chunk 降级设置的 oom_adj 值"),
    # ── privacy (iter_new) ──
    "privacy.scrub_enabled": (True, bool, None, None, None,
        "VFS 写入路径隐私过滤（secret/token 自动脱敏为 [REDACTED:type]）"),
    "privacy.extra_patterns_json": ("[]", str, None, None, None,
        "用户自定义额外脱敏正则（JSON array of {pattern, label}）"),
    # ── precompact (iter_new) ──
    "precompact.enabled": (True, bool, None, None, None,
        "PreCompact hook 是否注入 pinned + critical chunks 到压缩后上下文"),
    "precompact.max_chars": (2000, int, 200, 5000, None,
        "PreCompact 注入最大字符数"),
    "precompact.decision_top_k": (3, int, 1, 10, None,
        "PreCompact 注入的 recent decision chunk 数"),
    "precompact.decision_min_importance": (0.6, float, 0.3, 1.0, None,
        "PreCompact decision chunk 最低 importance 阈值"),
    # ── scorer ebbinghaus (iter_new) ──
    "scorer.ebbinghaus_enabled": (False, bool, None, None, None,
        "使用 Ebbinghaus 遗忘曲线 R=e^(-t/S) 替代线性衰减 0.95^(t/7)"),
    "scorer.ebbinghaus_stability_cap": (365.0, float, 7.0, 3650.0, None,
        "stability 上限（天），防止超稳定 chunk 永不衰减"),
    # ── contradiction (iter_new) ──
    "contradiction.supersession_enabled": (True, bool, None, None, None,
        "Jaccard 超取代检测（新 chunk 语义重叠 >threshold 时 supersede 旧 chunk）"),
    "contradiction.jaccard_threshold": (0.85, float, 0.5, 1.0, None,
        "Jaccard token 重叠阈值（>= 此值触发 supersession）"),
    "contradiction.max_candidates": (50, int, 10, 500, None,
        "每次检测最多比较的候选 chunk 数（限制扫描范围）"),
    # ── replay (iter_new) ──
    "replay.enabled": (False, bool, None, None, None,
        "session replay 事件记录（ftrace ring buffer 类比，调试用）"),
    "replay.max_age_days": (30, int, 7, 365, None,
        "replay 事件最大保留天数（超过自动 GC）"),
    "replay.max_data_chars": (2000, int, 500, 10000, None,
        "每条 replay event 的 data 字段最大字符数"),
    # ── context offload (phase2) ──
    "offload.enabled": (True, bool, None, None, None,
        "context pressure 升高时自动切换为 compact reference 注入模式"),
    "offload.trigger_pressure": ("some", str, None, None, None,
        "触发 offload 的最低 pressure 级别（none/some/full）"),
    "offload.ref_max_chars": (30, int, 15, 80, None,
        "offload mode 下每条 chunk summary 的最大字符数"),
    # ── graph export (phase2) ──
    "graph_export.enabled": (True, bool, None, None, None,
        "检索注入时追加 top-k chunk 间的关系图（如有 edge）"),
    "graph_export.max_edges": (10, int, 3, 30, None,
        "关系图最多导出的边数"),
    # ── chunk aggregation (phase2) ──
    "aggregation.enabled": (True, bool, None, None, None,
        "SessionStart 时自动聚合相关 chunk 为 composite（hugepages 类比）"),
    "aggregation.min_cluster_size": (3, int, 2, 10, None,
        "触发聚合的最小簇大小"),
    "aggregation.max_composite_bullets": (7, int, 3, 15, None,
        "每条 composite chunk 最多包含的子项数"),
}

# ── 磁盘配置缓存（进程内只读一次）──
_disk_config: Optional[dict] = None


def _load_disk_config() -> dict:
    """加载 sysctl.json 配置文件（懒加载，进程内缓存）。"""
    global _disk_config
    if _disk_config is not None:
        return _disk_config
    if os.path.exists(SYSCTL_FILE):
        try:
            with open(SYSCTL_FILE, encoding="utf-8") as _f:
                _disk_config = json.loads(_f.read())
        except Exception:
            _disk_config = {}
    else:
        _disk_config = {}
    return _disk_config


def _invalidate_cache():
    """强制重新加载磁盘配置（sysctl_set 后调用）。"""
    global _disk_config
    _disk_config = None


def get(key: str, project: str = None) -> Any:
    """
    获取 tunable 值。
    优先级：环境变量 > namespace(project) > global sysctl.json > 默认值。

    迭代27 OS 类比：sysctl vm.swappiness 的读取路径 —
      先查 /proc/sys/vm/swappiness（运行时覆盖），再用编译时默认值。
    迭代37 OS 类比：Linux Namespaces —
      容器内进程看到的 /proc/sys/ 是 namespace 隔离后的视图，
      每个容器可以有独立的 sysctl 值（net.core.somaxconn 等）。
      get(key, project) 就是在 project namespace 视图中读取 tunable。
    """
    if key not in _REGISTRY:
        raise KeyError(f"sysctl: unknown tunable '{key}'")

    default, typ, lo, hi, env_key, desc = _REGISTRY[key]

    # 1. 环境变量（最高优先级，全局生效）
    env_names = []
    if env_key:
        env_names.append(env_key)
    env_names.append(f"MEMORY_OS_{key.upper().replace('.', '_')}")

    for env_name in env_names:
        env_val = os.environ.get(env_name)
        if env_val is not None:
            try:
                return _coerce(env_val, typ, lo, hi)
            except (ValueError, TypeError):
                break

    # 2. Per-project namespace 覆盖（迭代37 Namespaces）
    if project:
        disk = _load_disk_config()
        ns = disk.get("namespaces", {})
        if isinstance(ns, dict):
            proj_ns = ns.get(project, {})
            if isinstance(proj_ns, dict) and key in proj_ns:
                try:
                    return _coerce(proj_ns[key], typ, lo, hi)
                except (ValueError, TypeError):
                    pass

    # 3. sysctl.json 全局配置
    disk = _load_disk_config()
    if key in disk:
        try:
            return _coerce(disk[key], typ, lo, hi)
        except (ValueError, TypeError):
            pass

    # 4. 默认值
    return default


def sysctl_set(key: str, value: Any, project: str = None) -> None:
    """
    运行时修改 tunable 并持久化到 sysctl.json。
    OS 类比（迭代27）：sysctl -w vm.swappiness=60
    OS 类比（迭代37）：ip netns exec <ns> sysctl -w ...
      在指定 namespace 内设置 sysctl 值。

    project=None → 写入全局配置
    project=<id> → 写入 per-project namespace 覆盖
    """
    if key not in _REGISTRY:
        raise KeyError(f"sysctl: unknown tunable '{key}'")

    default, typ, lo, hi, env_key, desc = _REGISTRY[key]
    coerced = _coerce(value, typ, lo, hi)

    os.makedirs(MEMORY_OS_DIR, exist_ok=True)
    disk = _load_disk_config()

    if project:
        # 迭代37：写入 per-project namespace
        if "namespaces" not in disk:
            disk["namespaces"] = {}
        if project not in disk["namespaces"]:
            disk["namespaces"][project] = {}
        disk["namespaces"][project][key] = coerced
    else:
        disk[key] = coerced

    with open(SYSCTL_FILE, 'w', encoding='utf-8') as _f:
        _f.write(json.dumps(disk, ensure_ascii=False, indent=2))
    _invalidate_cache()


def sysctl_list(project: str = None) -> dict:
    """
    返回所有 tunable 的当前值（≈ sysctl -a）。
    迭代37：传入 project 时返回该 namespace 视图下的值。
    OS 类比：nsenter --target <pid> sysctl -a — 在指定 namespace 内列出所有参数。
    """
    result = {}
    for key in sorted(_REGISTRY.keys()):
        result[key] = {
            "value": get(key, project=project),
            "default": _REGISTRY[key][0],
            "type": _REGISTRY[key][1].__name__,
            "range": [_REGISTRY[key][2], _REGISTRY[key][3]],
            "description": _REGISTRY[key][5],
        }
    return result


# ── 迭代37：Namespace Management — Per-Project 配置隔离 ──────────

def ns_list(project: str) -> dict:
    """
    迭代37：列出指定项目 namespace 中的所有覆盖值。
    OS 类比：ip netns identify <pid> + nsenter sysctl -a
      查看容器内哪些 sysctl 被覆盖了。

    返回 dict：{key: value} 只包含被覆盖的 tunable（不含继承的全局值）。
    空 dict 表示该项目使用全局默认配置。
    """
    disk = _load_disk_config()
    ns = disk.get("namespaces", {})
    if not isinstance(ns, dict):
        return {}
    proj_ns = ns.get(project, {})
    if not isinstance(proj_ns, dict):
        return {}
    # 验证并返回合法的覆盖值
    result = {}
    for key, val in proj_ns.items():
        if key in _REGISTRY:
            default, typ, lo, hi, env_key, desc = _REGISTRY[key]
            try:
                result[key] = _coerce(val, typ, lo, hi)
            except (ValueError, TypeError):
                pass
    return result


def ns_clear(project: str) -> int:
    """
    迭代37：清除指定项目的 namespace（恢复使用全局配置）。
    OS 类比：ip netns delete <name> — 销毁 namespace，进程回到 init namespace。

    返回清除的覆盖项数量。
    """
    disk = _load_disk_config()
    ns = disk.get("namespaces", {})
    if not isinstance(ns, dict) or project not in ns:
        return 0
    count = len(ns[project]) if isinstance(ns[project], dict) else 0
    del ns[project]
    disk["namespaces"] = ns
    os.makedirs(MEMORY_OS_DIR, exist_ok=True)
    with open(SYSCTL_FILE, 'w', encoding='utf-8') as _f:
        _f.write(json.dumps(disk, ensure_ascii=False, indent=2))
    _invalidate_cache()
    return count


def ns_list_all() -> dict:
    """
    迭代37：列出所有已创建的 namespace（≈ ip netns list）。
    返回 dict：{project_id: {覆盖的 tunable 数量}}
    """
    disk = _load_disk_config()
    ns = disk.get("namespaces", {})
    if not isinstance(ns, dict):
        return {}
    return {proj: len(overrides) if isinstance(overrides, dict) else 0
            for proj, overrides in ns.items()}


def _coerce(value: Any, typ: type, lo: Any, hi: Any) -> Any:
    """类型转换 + 范围校验。"""
    if typ is bool:
        # bool 特殊处理：JSON 的 true/false、字符串 "true"/"false"、0/1
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    v = typ(value)
    if lo is not None and v < lo:
        v = lo
    if hi is not None and v > hi:
        v = hi
    return v


# ── 迭代47：sched_ext — Extensible Scheduler（可编程调度策略）──────────
#
# OS 类比：Linux sched_ext (Extensible Scheduler, Linux 6.12, 2024, Tejun Heo/Meta)
#
# Linux sched_ext 背景：
#   CFS/EEVDF 是内核硬编码的调度器——所有工作负载用同一套策略。
#   不同场景（延迟敏感 vs 吞吐优先 vs 大小核调度）需要不同策略，
#   但修改调度器需要改内核代码+重编译+重启。
#   sched_ext (Linux 6.12, 2024) 让用户通过 BPF 程序在用户态编写
#   自定义调度策略：
#     - 内核提供 struct_ops callback（enqueue/dequeue/dispatch/tick 等）
#     - 用户态 BPF 程序注册 callback 实现自定义逻辑
#     - 运行时动态加载/卸载，无需重编译内核
#     - fallback: BPF 程序 panic/timeout 时自动回退到内置 CFS
#
#   已有的 sched_ext 调度器（用户态实现）：
#     - scx_rusty: Rust 实现的 NUMA-aware scheduler
#     - scx_lavd: 延迟 vs 吞吐自适应
#     - scx_simple: 教学用最简实现
#
# memory-os 当前问题：
#   retriever.py 的 _classify_query_priority() 是硬编码规则：
#     - SKIP 模式列表是 Python 正则
#     - LITE/FULL 边界是字符数阈值
#     - 无法运行时扩展——新场景需要改 retriever.py 代码
#   等价于 Linux 只有 CFS 没有 sched_ext 的状态。
#
# 解决：
#   sysctl.json 新增 scheduler_ext_rules 数组，每条规则：
#     {pattern: "regex", priority: "SKIP|LITE|FULL", scope: "global|project_id"}
#   retriever.py 分类器优先评估自定义规则（用户态 BPF 策略），
#   无匹配时 fallback 到内置逻辑（内核态 CFS 默认策略）。
#   规则管理 API：sched_ext_add/sched_ext_remove/sched_ext_list/sched_ext_stats

_SCHED_EXT_KEY = "scheduler_ext_rules"


def sched_ext_list(project: str = None) -> list:
    """
    列出当前生效的 sched_ext 规则。
    OS 类比：bpftool struct_ops list — 列出已加载的 BPF 调度策略。

    参数：
      project — 只返回 global + 该 project scope 的规则（None = 全部）

    返回规则列表（按优先级排序：project scope > global scope）。
    """
    disk = _load_disk_config()
    rules = disk.get(_SCHED_EXT_KEY, [])
    if not isinstance(rules, list):
        return []

    valid = []
    for r in rules:
        if not isinstance(r, dict) or "pattern" not in r or "priority" not in r:
            continue
        priority = r["priority"].upper()
        if priority not in ("SKIP", "LITE", "FULL"):
            continue
        scope = r.get("scope", "global")
        if project and scope != "global" and scope != project:
            continue
        valid.append({
            "pattern": r["pattern"],
            "priority": priority,
            "scope": scope,
            "reason": r.get("reason", ""),
            "hits": r.get("hits", 0),
        })

    # 排序：project scope 优先于 global（更具体的规则先匹配）
    valid.sort(key=lambda x: (0 if x["scope"] != "global" else 1))
    return valid


def sched_ext_add(pattern: str, priority: str, scope: str = "global",
                  reason: str = "") -> dict:
    """
    添加一条 sched_ext 规则。
    OS 类比：bpftool struct_ops register — 注册新的 BPF 调度策略。

    参数：
      pattern  — 正则表达式（匹配 query 文本）
      priority — "SKIP" / "LITE" / "FULL"
      scope    — "global" 或 project_id（限定生效范围）
      reason   — 规则说明（可选，等价于 BPF 程序的 description）

    返回 dict：
      added — bool
      rule_count — 当前规则总数
      error — 错误信息（如果有）

    验证：
      - 正则必须可编译
      - priority 必须合法
      - 规则总数不超过 max_rules
    """
    # ── 迭代161：Lazy re import — 消除 config 模块级 re import 对 Stage 0+1 的污染 ──
    # OS 类比：dlopen(RTLD_LAZY) — 符号解析推迟到第一次调用时，不在 dlopen 时预绑定
    # sched_ext_add 只在 Stage 2（main() 已调用后）被调用，安全延迟 import
    import re as _re
    priority = priority.upper()
    if priority not in ("SKIP", "LITE", "FULL"):
        return {"added": False, "rule_count": 0,
                "error": f"invalid priority '{priority}', must be SKIP/LITE/FULL"}

    # 验证正则可编译（等价于 BPF verifier 检查程序安全性）
    try:
        _re.compile(pattern)
    except _re.error as e:
        return {"added": False, "rule_count": 0,
                "error": f"invalid regex: {e}"}

    max_rules = get("scheduler.ext_max_rules")

    os.makedirs(MEMORY_OS_DIR, exist_ok=True)
    disk = _load_disk_config()
    rules = disk.get(_SCHED_EXT_KEY, [])
    if not isinstance(rules, list):
        rules = []

    if len(rules) >= max_rules:
        return {"added": False, "rule_count": len(rules),
                "error": f"max rules reached ({max_rules})"}

    # 去重：相同 pattern + scope 不重复添加
    for r in rules:
        if isinstance(r, dict) and r.get("pattern") == pattern and r.get("scope", "global") == scope:
            return {"added": False, "rule_count": len(rules),
                    "error": "duplicate rule (same pattern+scope)"}

    rules.append({
        "pattern": pattern,
        "priority": priority,
        "scope": scope,
        "reason": reason,
        "hits": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    disk[_SCHED_EXT_KEY] = rules
    with open(SYSCTL_FILE, 'w', encoding='utf-8') as _f:
        _f.write(json.dumps(disk, ensure_ascii=False, indent=2))
    _invalidate_cache()

    return {"added": True, "rule_count": len(rules)}


def sched_ext_remove(pattern: str, scope: str = "global") -> dict:
    """
    移除一条 sched_ext 规则。
    OS 类比：bpftool struct_ops unregister — 卸载 BPF 调度策略。

    返回 dict：
      removed — bool
      rule_count — 剩余规则数
    """
    disk = _load_disk_config()
    rules = disk.get(_SCHED_EXT_KEY, [])
    if not isinstance(rules, list):
        return {"removed": False, "rule_count": 0}

    new_rules = [r for r in rules
                 if not (isinstance(r, dict) and r.get("pattern") == pattern
                         and r.get("scope", "global") == scope)]
    removed = len(rules) - len(new_rules)
    disk[_SCHED_EXT_KEY] = new_rules
    with open(SYSCTL_FILE, 'w', encoding='utf-8') as _f:
        _f.write(json.dumps(disk, ensure_ascii=False, indent=2))
    _invalidate_cache()

    return {"removed": removed > 0, "rule_count": len(new_rules)}


def sched_ext_match(query: str, project: str = None) -> Optional[dict]:
    """
    评估 query 是否匹配任何 sched_ext 规则。
    OS 类比：sched_ext 的 ops.enqueue() callback — BPF 程序决定任务入队策略。

    评估顺序（首条匹配即返回）：
      1. project-scope 规则（最具体）
      2. global-scope 规则

    返回匹配的规则 dict（含 priority/reason/pattern），None = 无匹配（fallback 到内置策略）。
    匹配时自动递增 hits 计数。
    """
    # ── 迭代161：Lazy re import — Stage 2-only 函数，不污染 Stage 0+1 冷启动路径 ──
    import re as _re
    if not get("scheduler.ext_enabled", project=project):
        return None

    disk = _load_disk_config()
    rules = disk.get(_SCHED_EXT_KEY, [])
    if not isinstance(rules, list) or not rules:
        return None

    # 按 scope 排序：project-specific > global
    sorted_rules = sorted(
        enumerate(rules),
        key=lambda x: (0 if isinstance(x[1], dict) and x[1].get("scope", "global") == project else 1)
    )

    for idx, rule in sorted_rules:
        if not isinstance(rule, dict):
            continue
        pattern = rule.get("pattern", "")
        priority = rule.get("priority", "").upper()
        scope = rule.get("scope", "global")

        if priority not in ("SKIP", "LITE", "FULL"):
            continue
        if scope != "global" and scope != project:
            continue

        try:
            if _re.search(pattern, query, _re.IGNORECASE):
                # 命中：递增 hits（异步持久化，不阻塞）
                try:
                    rules[idx]["hits"] = rule.get("hits", 0) + 1
                    disk[_SCHED_EXT_KEY] = rules
                    with open(SYSCTL_FILE, 'w', encoding='utf-8') as _f:
                        _f.write(json.dumps(disk, ensure_ascii=False, indent=2))
                    _invalidate_cache()
                except Exception:
                    pass

                return {
                    "priority": priority,
                    "pattern": pattern,
                    "scope": scope,
                    "reason": rule.get("reason", ""),
                    "hits": rule.get("hits", 0) + 1,
                }
        except Exception:
            continue  # 正则执行异常 → 跳过该规则（等价于 BPF panic → fallback）

    return None
