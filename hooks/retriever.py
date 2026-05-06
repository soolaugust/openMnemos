#!/usr/bin/env python3
"""
memory-os retriever — UserPromptSubmit hook（与 writer.py 并列）
职责：按当前 prompt + 任务主题做 BM25 召回，幂等注入 L2
目标：< 50ms

v19 迭代62+：Anti-Starvation — 反饥饿机制解决召回同质化
v18 迭代62：Query Truncation + PSI Import-aware Timing — 延迟治理
v17 迭代61：vDSO Fast Path — Lazy Import + 启动加速
v16 迭代57：TLB — Translation Lookaside Buffer 检索快速路径
v15 迭代41：Deadline I/O Scheduler — 检索时间预算保障
v11 迭代29：dmesg Ring Buffer — 结构化事件日志
v10 迭代28：Scheduler Nice Levels — Query Priority Classification
OS 类比：Linux CFS nice 值 (-20 ~ 19)
  CFS (2007) 给每个进程一个 nice 值，决定其获得的 CPU 时间片权重：
    nice -20 → weight 88761（最高优先级，获得最多时间片）
    nice   0 → weight  1024（默认）
    nice  19 → weight    15（最低优先级，几乎不分配）
  不同优先级对应不同的调度策略：
    SCHED_FIFO  → 实时任务，立即执行
    SCHED_OTHER → 普通任务，CFS 公平调度
    SCHED_BATCH → 批处理任务，低优先级后台执行
  类似地，memory-os 的检索请求并非等价：
    确认类 query（"好"/"继续"）→ SKIP（nice 19，零I/O，直接返回）
    普通 query → LITE（nice 0，只查 FTS5，跳过 knowledge_router）
    含缺页信号/多实体/长技术 query → FULL（nice -20，完整检索+router）
  这避免了对所有请求一视同仁地执行完整检索流程的浪费。

历史：
  v17 迭代61：vDSO Fast Path — SKIP/TLB 路径前置到 heavy import 之前
      SKIP: <1ms（零 import，只用 stdlib regex），TLB hit: <3ms（只读文件+stat）
      原因：import 链路（store+scorer+bm25+config+utils）冷启动 ~27ms，
      但 SKIP(42%) + TLB hit(~40%) 共占 ~80% 请求，不需要任何 heavy module。
  v16 迭代57：TLB — prompt_hash + db_mtime 缓存，TLB hit 时零 I/O 退出
  v15 迭代41：Deadline I/O Scheduler — 时间预算保障，各阶段按优先级分配时间
  v13 迭代34：Second Chance — freshness_bonus 新知识曝光公平性
  v12 迭代33：Swap Fault — 主表 miss 时检查 swap 分区并 swap in 恢复
  v11 迭代29：dmesg Ring Buffer（各关键路径写入结构化事件日志）
  v9 迭代24：Per-Request Connection Scope（task_struct files_struct）
  v8 迭代23：FTS5 索引召回（ext3 htree O(log N) 替代 O(N) 全表扫描）
"""
import sys
import json
import math
import os
import zlib
# ── 迭代159：Remove pathlib.Path — 消除 ~7ms import 开销 ──────────────────────
# OS 类比：Linux kernel vfs_stat() 直接调用 sys_stat()，不经 glibc 抽象层。
# pathlib.Path 是 os.path 的面向对象封装，os 模块在 Python 启动时已预加载（0ms）。
# retriever.py 是 vDSO Stage 0+1 快速路径（~80% 请求），pathlib ~7ms 全部浪费。
# 所有 Path 对象改为 str，所有方法调用改为 os.path.*/open() 等价操作。

# ── 迭代156：Replace hashlib with zlib for TLB prompt_hash ────────────────────
# OS 类比：Linux CRC32c hardware acceleration (SSE4.2, 2008) — 用内置硬件指令替代
#   软件实现的 SHA256，吞吐量从 ~1 GB/s 提升到 ~10 GB/s（10×）。
#   memory-os 等价：hashlib.sha256 模块独立 import 成本 ~2.25ms（含 _hashlib.so 加载），
#   而 zlib 模块在 Python 启动时已被 sqlite3/json 作为 transitive dependency 拉入，
#   后续 import zlib 近乎零成本（~0.09ms）。
#   TLB prompt_hash 不需要密码学强度（只用于缓存查找），CRC32 完全满足需求：
#     - 8 位 hex 输出（0xffffffff → 4字节，16^8=4B 个桶）
#     - CRC32 collision rate ≈ 1/2^32 — 与 sha256[:8] 实际可用碰撞率相当
#     - 0.674µs/call vs sha256 1.173µs/call（hash 计算也快 1.7×）
#   总节省：~2.11ms（import 成本）+ ~0.5µs/call（计算成本）
#   hashlib 仍在 _load_modules() 中懒加载（Stage 2 用于 md5 injection hash）

# config 轻量级 import（~3ms，远低于 store+scorer+bm25+utils 的 ~24ms）
# 多个模块级函数（_drr_select, _classify_query_priority）需要 _sysctl
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)
from config import get as _sysctl  # ~3ms, 模块级函数依赖
from config import sched_ext_match as _sched_ext_match  # 迭代47: sched_ext

# ── 迭代61：vDSO Fast Path — Lazy Import ──────────────────────────────────────
# OS 类比：Linux vDSO (Virtual Dynamic Shared Object, 2004)
#   gettimeofday() 是最高频系统调用之一（每秒数百万次）。
#   传统实现需要用户态→内核态切换（syscall 开销 ~100ns）。
#   vDSO 将内核只读数据页映射到用户态地址空间，
#   gettimeofday() 直接在用户态读取，无需 syscall（~5ns）。
#
#   memory-os 等价问题：
#     retriever.py import 链路（store+scorer+bm25+config+utils）冷启动 ~27ms，
#     但 SKIP(42%) + TLB hit(~40%) 共占 ~80% 请求，不需要任何 heavy module。
#     每次 hook 调用都是独立进程（无缓存），必须付 import 成本。
#
#   解决：两级 fast path（类比 vDSO + fast syscall return）
#     Stage 0：只用 stdlib 判断 SKIP → <1ms 退出（零 heavy import）
#     Stage 1：TLB 检查只需读文件+stat → <3ms 退出
#     Stage 2：_load_modules() 延迟加载全部模块 → 完整检索
#
# 将 memory-os 根目录加入 path（延迟到 Stage 2）— _ROOT/_HOOKS_DIR 已在上方定义（str）

# ── 路径常量（只用 os.path + os.environ，不触发 heavy import）──
# 迭代159：改为纯字符串路径，消除 pathlib 依赖
_mem_env = os.environ.get("MEMORY_OS_DIR")
MEMORY_OS_DIR = _mem_env if _mem_env else os.path.join(os.path.expanduser("~"), ".claude", "memory-os")
_db_env = os.environ.get("MEMORY_OS_DB")
STORE_DB = _db_env if _db_env else os.path.join(MEMORY_OS_DIR, "store.db")
HASH_FILE = os.path.join(MEMORY_OS_DIR, ".last_injection_hash")
TLB_FILE = os.path.join(MEMORY_OS_DIR, ".last_tlb.json")       # 迭代57→64: TLB v2 multi-slot
CHUNK_VERSION_FILE = os.path.join(MEMORY_OS_DIR, ".chunk_version")  # 迭代64: chunk_version
TLB_GENERATION_FILE = os.path.join(MEMORY_OS_DIR, ".tlb_generation")  # iter583: TLB generation counter
PAGE_FAULT_LOG = os.path.join(MEMORY_OS_DIR, "page_fault_log.json")
SHADOW_TRACE_FILE = os.path.join(MEMORY_OS_DIR, ".shadow_trace.json")  # 迭代85: Shadow Trace
SESSION_INJECTED_FILE = os.path.join(MEMORY_OS_DIR, ".session_injected")  # iter805: sync session_first_inject_guard
IOR_FILE = os.path.join(MEMORY_OS_DIR, ".ior_state.json")  # iter391: Inhibition of Return

# ── iter571: mmap_populate — session-level FULL recall counter ──
_mmap_populate_counter = 0

# ── Heavy modules — 延迟加载（迭代61 vDSO Fast Path）──
# 这些模块只在 Stage 2（完整检索）时才需要
_modules_loaded = False


def _load_modules():
    """延迟加载 heavy modules。只在 SKIP + TLB 都 miss 时才调用。"""
    global _modules_loaded
    if _modules_loaded:
        return
    _modules_loaded = True

    # 加入 path
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    if str(_HOOKS_DIR) not in sys.path:
        sys.path.insert(0, str(_HOOKS_DIR))

    # import heavy modules into global namespace
    import re as _re  # 迭代160：re 从模块级移至此处 — Stage 0/1 不再付 ~6-8ms re import
    import sqlite3 as _sqlite3
    import uuid as _uuid
    import hashlib as _hashlib  # 迭代156：Stage 2 才需要 md5 injection hash，延迟到此处加载
    from datetime import datetime as _datetime, timezone as _timezone
    from utils import resolve_project_id as _resolve_project_id
    from scorer import retrieval_score as _retrieval_score
    from scorer import recency_score as _recency_score
    from scorer import tmv_saturation_discount as _tmv_saturation_discount
    from store import (open_db as _open_db, ensure_schema as _ensure_schema,
                       get_chunks as _get_chunks, update_accessed as _update_accessed,
                       insert_trace as _insert_trace, fts_search as _fts_search,
                       dmesg_log as _dmesg_log, madvise_read as _madvise_read,
                       swap_fault as _swap_fault, swap_in as _swap_in,
                       psi_stats as _psi_stats, mglru_promote as _mglru_promote,
                       readahead_pairs as _readahead_pairs,
                       context_pressure_governor as _context_pressure_governor,
                       chunk_recall_counts as _chunk_recall_counts)
    from store_criu import chunk_recall_counts_memcg as _chunk_recall_counts_memcg
    from store import DMESG_INFO as _DMESG_INFO, DMESG_WARN as _DMESG_WARN, DMESG_DEBUG as _DMESG_DEBUG
    from bm25 import hybrid_tokenize as _hybrid_tokenize, bm25_scores as _bm25_scores, normalize as _normalize, bm25_scores_cached as _bm25_scores_cached
    from store_vfs import read_chunk_version as _read_chunk_version
    # config 已在模块级 import（_sysctl, _sched_ext_match），无需重复加载

    # 注入全局变量供后续函数使用
    g = globals()
    g['re'] = _re  # 迭代160：re 模块注入全局，供 Stage 2 函数使用

    # ── 迭代160：编译延迟的 Stage 2 正则（re 已可用）──
    g['_SKIP_PATTERNS'] = _re.compile(
        r'^(?:'
        r'好[的吧啊嗯哦]?'
        r'|[嗯恩哦噢]+'
        r'|ok(?:ay)?'
        r'|是[的吧]?'
        r'|对[的吧]?'
        r'|收到|了解|明白|可以|继续|开始|执行|确认|同意|谢谢'
        r'|thanks?|ye[sp]|no[pe]?|got\s*it|sure|lgtm'
        r')$',
        _re.IGNORECASE
    )
    g['_TECH_SIGNAL'] = _re.compile(
        r'(?:'
        r'`[^`]+`'
        r'|[\w./]+\.(?:py|js|ts|md|json|db|sql|yaml|toml|rs|go|java|cpp|h)\b'
        r'|(?:函数|类|模块|接口|方法|变量|配置|部署|迁移)'
        r'|\b(?:error|bug|fix|crash)\b'
        r'|\b(?:def|class|import|function|const)\b'
        r')'
    )
    g['_ACRONYM_SIGNAL'] = _re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')

    g['sqlite3'] = _sqlite3
    g['uuid'] = _uuid
    g['hashlib'] = _hashlib  # 迭代156：md5 injection hash 用（Stage 2 才需要）
    g['datetime'] = _datetime
    g['timezone'] = _timezone
    g['resolve_project_id'] = _resolve_project_id
    g['_unified_retrieval_score'] = _retrieval_score
    g['_unified_recency_score'] = _recency_score
    g['open_db'] = _open_db
    g['ensure_schema'] = _ensure_schema
    g['store_get_chunks'] = _get_chunks
    g['update_accessed'] = _update_accessed
    g['store_insert_trace'] = _insert_trace
    g['fts_search'] = _fts_search
    g['dmesg_log'] = _dmesg_log
    g['DMESG_INFO'] = _DMESG_INFO
    g['DMESG_WARN'] = _DMESG_WARN
    g['DMESG_DEBUG'] = _DMESG_DEBUG
    g['madvise_read'] = _madvise_read
    g['swap_fault'] = _swap_fault
    g['swap_in'] = _swap_in
    g['psi_stats'] = _psi_stats
    g['mglru_promote'] = _mglru_promote
    g['readahead_pairs'] = _readahead_pairs
    g['context_pressure_governor'] = _context_pressure_governor
    g['chunk_recall_counts'] = _chunk_recall_counts
    g['chunk_recall_counts_memcg'] = _chunk_recall_counts_memcg
    g['hybrid_tokenize'] = _hybrid_tokenize
    g['bm25_scores'] = _bm25_scores
    g['normalize'] = _normalize
    g['bm25_scores_cached'] = _bm25_scores_cached
    g['read_chunk_version'] = _read_chunk_version
    g['_tmv_saturation_discount'] = _tmv_saturation_discount
    # ── 迭代333：TMV 常量（模块加载时从 sysctl 读取，运行时直接用）──
    g['_tmv_acc_threshold'] = _sysctl("scorer.tmv_acc_threshold") or 50
    g['_tmv_session_density_gate'] = _sysctl("scorer.tmv_session_density_gate") or 4

    # ── 迭代152：VFS 惰性初始化 — LITE 路径跳过 vfs import/init ──────────────
    # OS 类比：Linux dlopen(RTLD_LAZY) — 符号解析推迟到第一次调用时
    #   RTLD_NOW: dlopen 立即解析所有符号（等价于旧版：_load_modules 里预热 vfs）
    #   RTLD_LAZY: 只加载 .so，符号在第一次调用时才绑定（等价于 lazy init）
    #
    #   旧问题：LITE 路径（占 ~60% 请求）从不使用 kr_route，但仍然付：
    #     vfs import: 23ms（ThreadPoolExecutor, concurrent.futures 等）
    #     _get_new_vfs() 预热: ~0.2ms（已初始化）
    #   总计 LITE 路径每次浪费 23ms 在永远不会用的 vfs import 上。
    #
    #   解决：
    #     _load_modules() 不 import vfs，只设置 _KR_AVAILABLE=True（哨兵）
    #     实际 vfs import + 初始化推迟到 kr_route 第一次被调用时（lazy closure）
    #     LITE 路径（run_router=False）永远不调 kr_route → 永远不付 23ms
    #     FULL 路径第一次调 kr_route 时付 ~23ms（但 FULL 本来就更慢，可接受）
    #
    #   注意：ThreadPoolExecutor 初始化的 34ms 现在在 kr_route 第一次调用时才付，
    #   但 kr_route 有 timeout_ms 参数，VFS 内部有 deadline 保护，不会阻塞主路径。
    _vfs_loaded = False
    try:
        # 只做 import 检测（看 vfs.py 是否存在），不实际 import 或初始化
        import importlib.util as _ilu
        if _ilu.find_spec("vfs") is not None:
            _PREFIX_NEW = {
                "decision": "[决策]", "excluded_path": "[排除]",
                "reasoning_chain": "[推理]", "rule": "[规则]",
                "reference": "[索引]", "knowledge": "[知识]",
            }

            def _new_vfs_search(query, sources=None, top_k=3, timeout_ms=100):
                """新 VFS 搜索（惰性初始化版），返回 knowledge_router 兼容格式"""
                # 惰性 import + 初始化：第一次调用时才触发（RTLD_LAZY 语义）
                from vfs import get_vfs as _lazy_get_vfs
                _vfs = _lazy_get_vfs()
                items = _vfs.search(query, top_k=top_k, deadline_ms=timeout_ms)
                if sources:
                    items = [i for i in items if i.source in sources]
                return [
                    {
                        "source": i.source,
                        "chunk_type": i.type,
                        "summary": i.summary,
                        "score": i.score,
                        "content": (i.content or "")[:300],
                        "path": i.path,
                    }
                    for i in items
                ]

            def _new_vfs_format(results):
                """格式化新 VFS 结果（兼容旧格式）"""
                if not results:
                    return ""
                lines = ["【知识路由召回】"]
                for r in results:
                    prefix = _PREFIX_NEW.get(r.get("chunk_type", ""), "")
                    src = r.get("source", "")
                    src_tag = f"({src})" if src else ""
                    lines.append(f"- {prefix} {r['summary']} {src_tag}".strip())
                return "\n".join(lines)

            g['kr_route'] = _new_vfs_search
            g['kr_format'] = _new_vfs_format
            g['_KR_AVAILABLE'] = True
            _vfs_loaded = True
    except Exception:
        pass

    if not _vfs_loaded:
        try:
            from knowledge_vfs_init import search as _kvfs_search, format_for_context as _kvfs_format, init_knowledge_vfs as _kvfs_init
            _kvfs_init()
            g['kr_route'] = _kvfs_search
            g['kr_format'] = _kvfs_format
            g['_KR_AVAILABLE'] = True
        except Exception:
            try:
                from knowledge_router import route as _kr_route, format_for_context as _kr_format
                g['kr_route'] = _kr_route
                g['kr_format'] = _kr_format
                g['_KR_AVAILABLE'] = True
            except Exception:
                g['_KR_AVAILABLE'] = False

# 迭代27：常量迁移至 config.py sysctl 注册表（运行时可调）
# 原硬编码：TOP_K=3, TOP_K_FAULT=5, MAX_CONTEXT_CHARS=600, MAX_CONTEXT_CHARS_FAULT=800


    # ── BM25 已迁移至 bm25.py（迭代22 Shared Library）──


# ── 迭代61：vDSO Fast Path — Stage 0 + Stage 1 ──────────────────────────────
# 在任何 heavy import 之前判断 SKIP 和 TLB hit，省掉 ~27ms import 开销。
# Stage 0：SKIP regex match（只用 re，<1ms）
# Stage 1：TLB file check（只用 json + os.stat，<3ms）

# ── 迭代160：Replace re.compile with pure-string data structures — 消除 ~6-8ms re import ──
# OS 类比：Linux iptables hash match (O(1) set lookup) vs regex match (O(N) NFA evaluation)
#   iptables -m set --match-set 替代 iptables --match string --algo bm — 对固定词集用 hash 表。
#   re 模块在 Python 冷启动时不预加载（~6-8ms），而 frozenset + str.in 操作只用 Python 内置类型。
#   SKIP path (~42%) + TLB hit (~40%) = ~82% 的请求受益，每次节省 ~6-8ms。
#
# 旧方案：_VDSO_SKIP_RE = re.compile(...) + _VDSO_TECH_RE = re.compile(...)
#   import re 在模块加载时执行（Stage 0 之前），即使 SKIP 后立刻退出也付 ~6-8ms。
# 新方案：frozenset + str.in + isalpha() 边界检查 — 零 import，纯内置操作。
#   Stage 2 仍需 re，但 import re 已移至 _load_modules()（只在完整检索时执行）。

_VDSO_SKIP_EXACT = frozenset([
    # 中文确认词（展开变体）
    '好', '好的', '好吧', '好啊', '好嗯', '好哦',
    '是', '是的', '是吧',
    '对', '对的', '对吧',
    '收到', '了解', '明白', '可以', '继续', '开始', '执行', '确认', '同意', '谢谢',
    # 英文确认词（小写）
    'ok', 'okay',
    'thanks', 'thank',
    'yes', 'yep',
    'no', 'nope',
    'got it', 'gotit',
    'sure', 'lgtm',
])
# 文件扩展名集合（只需包含 dot）
_VDSO_TECH_EXTS = frozenset([
    '.py', '.js', '.ts', '.md', '.json', '.db', '.sql',
    '.yaml', '.toml', '.rs', '.go', '.java', '.cpp', '.h',
])
# 中文技术词（直接包含检测，无边界需求）
_VDSO_TECH_CJK = frozenset(['函数', '类', '模块', '接口', '方法', '变量', '配置', '部署', '迁移'])
# 英文技术词（需要词边界检查，避免误匹配 "classic"→"class"）
_VDSO_TECH_EN = frozenset(['error', 'bug', 'fix', 'crash', 'def', 'class', 'import', 'function', 'const'])
# [嗯恩哦噢]+ 的有效字符集
_VDSO_SKIP_FILLER = frozenset('嗯恩哦噢')


def _vdso_is_skip(prompt: str) -> bool:
    """
    纯字符串 SKIP 检测（替代 _VDSO_SKIP_RE.match）。
    OS 类比：iptables hash match O(1) vs regex NFA O(N)。
    """
    p = prompt.lower()
    if p in _VDSO_SKIP_EXACT:
        return True
    # [嗯恩哦噢]+ — 全部由填充音组成的短句
    if prompt and all(c in _VDSO_SKIP_FILLER for c in prompt):
        return True
    return False


def _vdso_has_tech(prompt: str) -> bool:
    """
    纯字符串技术信号检测（替代 _VDSO_TECH_RE.search）。
    OS 类比：Bloom filter O(1) 预筛 + exact match，避免 NFA 遍历。
    """
    # 反引号代码（最快路径：单字符检测）
    if '`' in prompt:
        return True
    p_lower = prompt.lower()
    # 文件扩展名（.py/.js/... 出现即有技术信号）
    for ext in _VDSO_TECH_EXTS:
        if ext in p_lower:
            return True
    # 中文技术词（直接包含，无边界歧义）
    for w in _VDSO_TECH_CJK:
        if w in prompt:
            return True
    # 英文技术词（需要词边界：前后不能是字母）
    for w in _VDSO_TECH_EN:
        idx = p_lower.find(w)
        while idx >= 0:
            before_ok = (idx == 0 or not p_lower[idx - 1].isalpha())
            after_ok = (idx + len(w) >= len(p_lower) or not p_lower[idx + len(w)].isalpha())
            if before_ok and after_ok:
                return True
            idx = p_lower.find(w, idx + 1)
    return False


def _vdso_fast_exit() -> bool:
    """
    迭代61：vDSO Fast Path — 在 heavy import 之前处理 SKIP + TLB hit。
    返回 True 表示已处理（应 sys.exit(0)），False 表示需要继续完整流程。

    OS 类比：
      vDSO: 高频路径绕过内核，直接在用户态完成
      SKIP: 等价于 gettimeofday() 的 vDSO 快速路径
      TLB hit: 等价于 TLB + fast syscall return（不走完整 page table walk）
    """
    # ── 读 stdin ──
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except Exception:
        hook_input = {}

    # iter685: 兼容 Claude Code hook input 格式
    # Claude Code 发送 {"hookSpecificInput": {"userMessage": "..."}}
    # 旧格式用 "prompt" 字段（兼容保留）
    _hsi = hook_input.get("hookSpecificInput", {})
    prompt = (_hsi.get("userMessage", "") or hook_input.get("prompt", "") or "").strip()

    # ── Stage 0：SKIP 快速判断（零 I/O，<1ms）──
    # 条件：prompt 匹配 SKIP 模式 + 无技术信号 + 无未消费的缺页日志
    # 缺页时不 SKIP：缺页信号优先级最高（等价于 SCHED_DEADLINE 不可抢占）
    if not prompt:
        sys.exit(0)
    has_page_fault_file = os.path.exists(PAGE_FAULT_LOG)
    if not has_page_fault_file:
        if _vdso_is_skip(prompt) and not _vdso_has_tech(prompt):
            sys.exit(0)

    # iter805: session_first_inject_guard (sync path)
    # 根因（数据驱动，2026-05-05）：23/86 trace 为 skipped_same_hash，23/23 session 零注入。
    # TLB/HASH_FILE 跨 session 共享 → 新 session 命中前一 session 的缓存 → 零注入。
    # 修复：比对 .session_injected 文件中的 session_id，不匹配则跳过 TLB 缓存。
    _session_id_raw = hook_input.get("session_id", "") or os.environ.get("CLAUDE_SESSION_ID", "")
    _sid_has_inj = False
    if _session_id_raw:
        try:
            with open(SESSION_INJECTED_FILE, encoding="utf-8") as _f:
                _sid_has_inj = _session_id_raw in _f.read()
        except OSError:
            _sid_has_inj = False

    # ── Stage 1：TLB v2 快速路径（只读文件+stat，<3ms）──────────────────────
    # 迭代64：Multi-Slot TLB + chunk_version Selective Invalidation
    # OS 类比：N-Way Set-Associative TLB + NFS Weak Cache Consistency (WKC)
    #
    #   v1 问题：TLB 用 db_mtime 判断失效，但 writer（async）每次写入
    #   prompt_context 都改变 db_mtime → 42% 请求 TLB miss → 完整检索 →
    #   发现结果不变（skipped_same_hash），平均浪费 16.9ms/请求。
    #
    #   v2 解决：
    #     1. chunk_version 替代 db_mtime（只有 insert/delete/swap 递增，不含元数据更新）
    #     2. Multi-Slot 缓存（按 prompt_hash 索引，最多 MAX_TLB_ENTRIES 条目）
    #     3. 两级命中：
    #        L1：prompt_hash + chunk_version 完全匹配 → 零 I/O 退出
    #        L2：prompt_hash miss 但 chunk_version 匹配任意 slot 的 injection_hash
    #            = 当前 HASH_FILE → 结果未变，跳过（不管 prompt 怎么变）
    if not os.path.exists(STORE_DB):
        sys.exit(0)

    if not has_page_fault_file:
        # 迭代156：zlib.crc32 替代 hashlib.sha256（TLB 不需要密码学强度，CRC32 足够）
        prompt_hash = format(zlib.crc32(prompt.encode()) & 0xffffffff, '08x')
        try:
            # 读取 chunk_version（替代 db_mtime）
            chunk_ver = 0
            if os.path.exists(CHUNK_VERSION_FILE):
                try:
                    with open(CHUNK_VERSION_FILE, encoding="utf-8") as _f:
                        chunk_ver = int(_f.read().strip())
                except (ValueError, OSError):
                    chunk_ver = 0

            # ── iter583: TLB Generation Age-Out ──────────────────────────
            # OS 类比：Linux TLB generation counter (Andy Lutomirski, 2017,
            #   PCID/ASID generation tracking) — 每个 TLB entry 绑定
            #   写入时的 generation number，当 global generation 超过
            #   entry generation + max_age 时自动失效。
            #
            # 根因：chunk_version 只在 insert/delete/swap 递增。稳态下
            #   （无新写入）chunk_version 永不变 → TLB 永远 hit →
            #   scan_unevictable 永远不执行 → dark pages 永远不曝光。
            #
            # 方案：全局 generation 计数器（每次 FULL 检索完成递增）。
            #   TLB hit 检查：generation gap >= max_age → 强制 miss，
            #   让 scan_unevictable 有机会注入 diversity slots。
            _tlb_gen_current = 0
            try:
                if os.path.exists(TLB_GENERATION_FILE):
                    with open(TLB_GENERATION_FILE, encoding="utf-8") as _f:
                        _tlb_gen_current = int(_f.read().strip())
            except (ValueError, OSError):
                _tlb_gen_current = 0
            _tlb_max_gen_age = int(_sysctl("retriever.tlb_max_generation_age"))

            if os.path.exists(TLB_FILE):
                with open(TLB_FILE, encoding="utf-8") as _f:
                    tlb = json.loads(_f.read())
                slots = tlb.get("slots", {})
                tlb_ver = tlb.get("chunk_version", -1)
                # iter583: entry generation（TLB 上次被写入时的全局 generation）
                _tlb_entry_gen = tlb.get("generation", 0)
                _gen_expired = (_tlb_gen_current - _tlb_entry_gen) >= _tlb_max_gen_age

                # L1: prompt_hash + chunk_version 完全匹配
                # iter805: 新 session 首次请求不走 TLB 缓存（必须完整检索+注入）
                if chunk_ver == tlb_ver and prompt_hash in slots and not _gen_expired and _sid_has_inj:
                    # iter780: empty_result_tlb — 空结果缓存避免重复检索空转
                    if slots[prompt_hash].get("injection_hash") == "__empty__":
                        sys.exit(0)  # TLB L1 hit (empty result cached)
                    try:
                        with open(HASH_FILE, encoding="utf-8") as _f:
                            last_hash = _f.read().strip()
                    except Exception:
                        last_hash = ""
                    if slots[prompt_hash].get("injection_hash") == last_hash:
                        sys.exit(0)  # TLB L1 hit

                # L2: chunk_version 匹配（chunk 未变）+ HASH_FILE 匹配任意 slot
                # 当 prompt 变了但 DB 内容未变时，Top-K 结果仍然有效
                if chunk_ver == tlb_ver and not _gen_expired and _sid_has_inj:
                    try:
                        with open(HASH_FILE, encoding="utf-8") as _f:
                            last_hash = _f.read().strip()
                    except Exception:
                        last_hash = ""
                    if last_hash:
                        for _s in slots.values():
                            if _s.get("injection_hash") == last_hash:
                                sys.exit(0)  # TLB L2 hit
        except Exception:
            pass  # TLB 读取失败 → fallthrough 到完整流程

    # ── Stage 0+1 都 miss → 返回 hook_input 供 Stage 2 使用 ──
    # 将 hook_input 存储在模块级变量，避免 main() 重复读 stdin（stdin 已耗尽）
    global _vdso_hook_input
    _vdso_hook_input = hook_input
    return False


# 模块级变量：_vdso_fast_exit 传递 hook_input 给 main()
_vdso_hook_input = None


# ── 迭代28：Scheduler Nice Levels ─────────────────────────────────────────────
# OS 类比：Linux CFS nice 值 — 不同优先级 query 获得不同检索资源
# SKIP = nice 19（零 I/O），LITE = nice 0（仅 FTS5），FULL = nice -20（FTS5 + router）

# ── 迭代160：_SKIP_PATTERNS / _TECH_SIGNAL / _ACRONYM_SIGNAL 延迟编译 ────────────
# 这三个 re.compile 对象只在 Stage 2（_classify_query_priority / _has_real_tech_signal）使用。
# 迭代160 将 import re 移至 _load_modules()，模块级不再有 re 可用。
# 解决：用哨兵 None 延迟到 _load_modules() 内编译（re 注入 globals() 后立即编译）。
# OS 类比：Linux lazy module loading (RTLD_LAZY) — 符号在首次调用时才绑定。
_SKIP_PATTERNS = None   # 迭代160：延迟编译，由 _load_modules() 设置
_TECH_SIGNAL = None     # 迭代160：延迟编译，由 _load_modules() 设置
_ACRONYM_SIGNAL = None  # 迭代160：延迟编译，由 _load_modules() 设置

# 技术信号中需要排除的常见非技术缩写（避免误判）
_TECH_SIGNAL_EXCLUDE = {"LGTM", "ASAP", "RSVP", "TBD", "FYI", "IMO", "IMHO", "BTW", "WIP", "TIL", "AFAIK"}


def _has_real_tech_signal(text: str) -> bool:
    """
    检测文本是否包含真正的技术信号（排除常见非技术缩写）。
    OS 类比：中断控制器区分真正的设备中断和 spurious interrupt。

    两层检测：
      1. _TECH_SIGNAL：文件路径/代码关键字/中文技术词/错误关键词（无 IGNORECASE）
      2. _ACRONYM_SIGNAL：全大写缩写（严格大写，排除非技术缩写白名单）
    """
    # 层1：通用技术信号
    if _TECH_SIGNAL.search(text):
        return True
    # 层2：大写缩写（严格大写匹配，排除 LGTM/ASAP 等）
    for m in _ACRONYM_SIGNAL.finditer(text):
        if m.group(0) not in _TECH_SIGNAL_EXCLUDE:
            return True
    return False


def _is_generic_knowledge_query(query: str) -> bool:
    """
    迭代88：检测通用知识 query — 这类 query 不应注入项目知识。
    OS 类比：Linux NUMA distance — 远距离内存访问不如本地访问有价值，
    通用知识 query 与项目知识的"距离"极远，强行注入是噪音。

    特征：
      1. 问的是通用技术概念（"什么是 GIL"、"解释 TCP"、"如何写 Dockerfile"）
      2. 不含项目特定标识符（文件名、函数名、迭代号、模块名）
      3. 问句模式：什么是/如何/解释/怎么...

    返回 True 表示是通用知识 query（应提高注入门槛）。
    """
    # 通用问句模式（中英文）
    # 注意：末尾匹配要考虑中文标点（？！。）
    _GENERIC_PATTERNS = [
        r'^(?:什么是|解释|如何|怎么(?:写|用|做|实现)?|介绍)',   # 以这些词开头
        r'(?:是什么|怎么回事|如何实现|有什么区别|的区别|的原理)[？?！!。.]?\s*$',  # 以这些词结尾
        r'^(?:how\s+(?:to|do|does|is)|what\s+is|explain|describe|define)\s',
    ]
    # 项目特定标识符 — 包含这些说明是项目问题，不是通用知识
    _PROJECT_MARKERS = [
        # 模块/文件
        'memory.os', 'memory os', 'store.py', 'retriever', 'extractor',
        'loader', 'scorer', 'writer', 'config.py', 'bm25.py',
        # OS 子系统类比
        'kswapd', 'mglru', 'damon', 'checkpoint', 'swap_fault',
        'swap_in', 'swap_out', 'tlb', 'vdso', 'psi',
        # 项目概念
        '迭代', 'iteration', 'hook', 'feishu', '飞书',
        'knowledge_vfs', 'knowledge_router', 'sched_ext',
        'chunk', 'store.db', 'memory_chunks',
        # 项目特定缩写
        'drr', 'dmesg',
        # iter732: DB 实际领域词
        'kernel', 'patch', 'uclamp', 'cgroup', 'proxy exec',
        'eevdf', 'migration', 'binder', 'schedqos', 'directed yield',
        'task_rq', 'lkmm', 'commit', 'signed-off',
        '内核', '调度器', '补丁', '性能诊断', '约束', '决策',
    ]

    query_lower = query.lower().strip()
    # iter731: 长查询(>20 chars)不视为 generic（同 daemon iter710）
    if len(query_lower) > 20:
        return False
    has_generic_pattern = any(re.search(p, query_lower) for p in _GENERIC_PATTERNS)
    has_project_marker = any(m in query_lower for m in _PROJECT_MARKERS)

    return has_generic_pattern and not has_project_marker


def _classify_query_priority(prompt: str, query: str,
                             has_page_fault: bool, entity_count: int,
                             project: str = None) -> str:
    """
    迭代28+47：查询优先级分类器。
    OS 类比：sched_setscheduler() — 根据任务特征设置调度策略。
    迭代47 OS 类比：sched_ext (Linux 6.12, 2024) — 用户态 BPF 自定义策略优先于内核默认策略。

    返回值：
      "SKIP" — nice 19，无需检索（确认/闲聊类）
      "LITE" — nice 0，仅 FTS5 检索（普通 query）
      "FULL" — nice -20，完整检索 + knowledge_router（高价值 query）

    决策逻辑（优先级从高到低）：
      0. sched_ext 自定义规则（用户态 BPF，最高优先级）
      1. 有缺页信号 → FULL（demand paging 优先补全）
      2. 技术实体 >= N 个 → FULL（多维度检索有价值）
      3. prompt 匹配 SKIP 模式且无技术信号 → SKIP
      4. query 短于 skip 阈值且无技术信号 → SKIP
      5. query 短于 lite 阈值 → LITE
      6. 默认 → FULL
    """
    # 规则 0（迭代47）：sched_ext 自定义规则优先于内置逻辑
    # OS 类比：sched_ext 的 BPF 策略先于 CFS 默认策略评估
    # 缺页信号仍然不可降级（等价于 SCHED_DEADLINE 不受 BPF 影响）
    if not has_page_fault:
        try:
            ext_match = _sched_ext_match(query, project=project)
            if ext_match:
                return ext_match["priority"]
        except Exception:
            pass  # sched_ext 失败不影响主流程（fallback to builtin）

    # 规则 1：缺页信号 → FULL（不可降级）
    if has_page_fault:
        return "FULL"

    # 规则 2：多技术实体 → FULL
    if entity_count >= _sysctl("scheduler.min_entity_count_for_full"):
        return "FULL"

    prompt_stripped = prompt.strip()

    # 规则 2.5（迭代99）：通用知识 query → SKIP（不注入项目知识）
    # OS 类比：NUMA distance filter — 远距离内存请求不路由到本地 node
    # 根因：A/B 测试中 "如何写 Dockerfile"/"解释 TCP" 等通用问题
    #   被注入项目上下文产生噪音，B 组（无记忆）反而得分更高
    if _is_generic_knowledge_query(query):
        return "SKIP"

    # 规则 3：确认/闲聊模式匹配 → 检查是否有技术信号
    if _SKIP_PATTERNS.match(prompt_stripped):
        if not _has_real_tech_signal(query):
            return "SKIP"

    # 规则 4：极短 query 且无技术信号 → SKIP
    if len(prompt_stripped) <= _sysctl("scheduler.skip_max_chars"):
        if not _has_real_tech_signal(query):
            return "SKIP"

    # 规则 5：中等长度 query → LITE（跳过 knowledge_router）
    if len(query) <= _sysctl("scheduler.lite_max_chars"):
        return "LITE"

    # 规则 6：长 query / 默认 → FULL
    return "FULL"


# ── 迭代310：Spreading Activation — 关联激活扩散 ─────────────────────────────
# OS 类比：CPU L2 prefetch — FTS5 命中 chunk A 后，沿 entity_edges 预热邻居 chunk
# 到候选集，使后续相关 chunk 的召回代价降为零。
# 算法委托 store_vfs.spreading_activate（BFS 图遍历），
# 此处封装为 retriever 可直接调用的接口，处理未加载模块的情况。

def _spreading_activate(conn, hit_chunk_ids: list, project: str = None,
                        decay: float = 0.7, max_hops: int = 2,
                        existing_ids: set = None,
                        max_activation_bonus: float = 0.4) -> dict:
    """
    迭代310：从 FTS5 命中 chunk 沿 entity_edges 扩散激活邻居。
    委托 store_vfs.spreading_activate，此处为 retriever 的封装入口。

    Returns:
      {chunk_id: activation_score} — 新增邻居 chunk 的激活分
    """
    try:
        from store_vfs import spreading_activate as _sa
        return _sa(conn, hit_chunk_ids, project=project, decay=decay,
                   max_hops=max_hops, existing_ids=existing_ids,
                   max_activation_bonus=max_activation_bonus)
    except Exception:
        return {}


# ── 迭代310：构建式召回 — 按 intent 动态调整注入顺序（展示层，不修改 DB）───────
# OS 类比：CPU 指令重排（out-of-order execution）— 相同指令序列，根据数据依赖
# 和执行单元负载重新排序，让最"紧迫"的指令优先流水线。
# 类比：相同 top-K chunk，根据当前意图重排展示顺序，让最相关的先进入 LLM attention。
#
# Bartlett (1932) 构建式记忆：每次回忆时，记忆以当前目标为框架被重新建构，
# 而不是像播放录像一样原样输出。
#
# 意图 → 优先 chunk_type 映射（顺序即优先级）：
_CONSTRUCTIVE_INTENT_ORDER = {
    "understand":  ["reasoning_chain", "causal_chain", "conversation_summary", "decision"],
    "fix_bug":     ["excluded_path", "decision", "reasoning_chain", "procedure"],
    "implement":   ["procedure", "decision", "reasoning_chain", "task_state"],
    "code_review": ["decision", "design_constraint", "procedure", "reasoning_chain"],
    "optimize":    ["quantitative_evidence", "decision", "reasoning_chain", "causal_chain"],
    "explore":     ["conversation_summary", "reasoning_chain", "decision", "task_state"],
    "continue":    ["task_state", "decision", "reasoning_chain"],
}


def _constructive_reorder(chunks: list, intent: str) -> list:
    """
    迭代310：按意图重排 chunk 列表（纯展示层，不修改 DB）。

    Args:
      chunks: list of chunk dicts（含 chunk_type 字段）
      intent: 当前意图（来自 _predict_intent）

    Returns:
      重排后的 chunks（同一引用，顺序变化）
    """
    priority_order = _CONSTRUCTIVE_INTENT_ORDER.get(intent, [])
    if not priority_order:
        return chunks

    type_priority = {t: i for i, t in enumerate(priority_order)}
    default_priority = len(priority_order)

    return sorted(
        chunks,
        key=lambda c: type_priority.get(c.get("chunk_type", ""), default_priority),
    )


# ── 迭代50：DRR Fair Queuing — 类型多样性选择器 ──────────────────────────────
# OS 类比：Deficit Round Robin (M. Shreedhar & G. Varghese, 1996)
#   每个 flow class 有独立队列 + deficit counter，
#   轮询时 deficit += quantum，发送 deficit 范围内的包，
#   保证长期公平性（任何一个 flow 不能永久独占带宽）。

def _drr_select(candidates: list, top_k: int) -> list:
    """
    DRR Fair Queuing：从已排序候选集中选择 Top-K，保证类型多样性。

    算法：
      1. 从高到低扫描候选集
      2. 每个 chunk_type 最多占 max_same_type 个槽位
      3. 超出配额的 chunk 暂存 overflow 列表
      4. 如果多样性选择不满 top_k，从 overflow 补齐（回流）
         回流时每类型额外允许 max_same 个槽位（防止单一类型无限回流）

    复杂度：O(N) 单次扫描，N = len(candidates)

    迭代134 bugfix：回流阶段也跟踪 type_counts，防止 design_constraint 等高分
    类型通过 overflow 回流无限占满 top_k。
    OS 类比：Deficit Round Robin — 每个 flow 的 deficit counter 有上限（max_deficit），
    即使历史积累的 deficit 很大，也不能无限次连续调度。

    迭代337：Normative Pool 联合配额 — decision + design_constraint 语义上都是
    "规则/结论型知识"，合并计入同一 pool，总量不超过 max_same * 2。
    OS 类比：Linux cgroup unified memory.limit — 将同类型进程归入同一 cgroup，
    统一限制资源消耗，而不是每个进程独立限制（各自 max 导致总量失控）。
    """
    max_same = _sysctl("retriever.drr_max_same_type")
    # ── 迭代337：Normative Pool 联合配额 ──
    # decision 和 design_constraint 合并为 "normative" pool，总量 ≤ max_same * 2
    # 避免两类型各自允许 max_same 导致联合占满 top_k（实测 76% 注入率）
    _NORMATIVE_TYPES = frozenset({"decision", "design_constraint"})
    normative_pool_cap = max_same * 2  # 联合配额
    normative_count = 0               # 已选 normative 数量

    selected = []
    type_counts = {}  # chunk_type -> 已选数量（第一轮）
    overflow = []     # 超出配额的高分 chunk（回流候选）

    for score, chunk in candidates:
        if len(selected) >= top_k:
            break
        ctype = chunk.get("chunk_type", "task_state")
        count = type_counts.get(ctype, 0)
        # normative pool 联合检查
        if ctype in _NORMATIVE_TYPES and normative_count >= normative_pool_cap:
            overflow.append((score, chunk))
            continue
        if count < max_same:
            selected.append((score, chunk))
            type_counts[ctype] = count + 1
            if ctype in _NORMATIVE_TYPES:
                normative_count += 1
        else:
            overflow.append((score, chunk))

    # 回流：如果其他类型不足以填满 top_k，从 overflow 补齐
    # iter134 fix：回流时每类型额外允许 max_same 个槽位（overflow_quota = max_same × 2 总计）
    # 防止单一 chunk_type（如 design_constraint）通过回流无限占满 top_k
    overflow_type_counts = {}  # 回流阶段独立计数
    for score, chunk in overflow:
        if len(selected) >= top_k:
            break
        ctype = chunk.get("chunk_type", "task_state")
        # 回流配额：在已选 count 基础上，每个类型最多再额外回流 max_same 个
        already = type_counts.get(ctype, 0) + overflow_type_counts.get(ctype, 0)
        # 迭代337：回流时也检查 normative pool 联合上限（防止 overflow 回流绕过限制）
        if ctype in _NORMATIVE_TYPES:
            overflow_normative = sum(
                overflow_type_counts.get(t, 0) for t in _NORMATIVE_TYPES
            )
            if normative_count + overflow_normative >= normative_pool_cap * 2:
                continue
        if already < max_same * 2:  # 总上限 = 2× max_same（原配额 + 回流配额）
            selected.append((score, chunk))
            overflow_type_counts[ctype] = overflow_type_counts.get(ctype, 0) + 1

    return selected


def _mmr_rerank(candidates: list, top_k: int,
                lambda_mmr: float = 0.6,
                sim_threshold: float = 0.45) -> list:
    """
    迭代321：Maximal Marginal Relevance (MMR) 内容去冗余。

    信息论依据：贪心最大化边际互信息
      I(cᵢ; query | already_selected) ≈ relevance(cᵢ) - max_sim(cᵢ, selected)
    即：已选集合与候选的内容重叠越高，候选的边际贡献越低。

    算法（Carbonell & Goldstein 1998）：
      score_mmr(d) = λ × relevance(d) - (1-λ) × max_sim(d, selected)
      贪心选择 score_mmr 最大的 chunk，直到满 top_k。

    相似度计算：Jaccard（summary token 集合），O(N²) 但 N ≤ 50，实测 < 0.5ms。

    参数：
      lambda_mmr:      λ ∈ [0,1]，越大越倾向 relevance，越小越倾向 diversity
                       默认 0.6：略偏 relevance，但不牺牲多样性
      sim_threshold:   Jaccard 相似度超过此值才被视为"冗余"，避免误杀
                       默认 0.45：经验值，同义改写约 0.4~0.55

    OS 类比：Linux multiqueue block I/O scheduler (blk-mq, 2013) —
      多队列调度在同一 request 队列里做 merge：把物理地址相邻的请求合并，
      避免对同一磁盘区域重复 I/O；MMR 类比避免对同一语义区域重复注入。

    Returns:
      重排后的 [(score, chunk)] 列表，长度 ≤ top_k
    """
    import re as _re

    if not candidates or top_k <= 0:
        return []

    if len(candidates) <= top_k:
        return candidates

    def _tok(text: str) -> frozenset:
        tokens = set()
        for m in _re.finditer(r'[a-zA-Z0-9_\u4e00-\u9fff]{2,}', (text or '')):
            tokens.add(m.group().lower())
        # CJK bigram
        cn = _re.sub(r'[^\u4e00-\u9fff]', '', text or '')
        for i in range(len(cn) - 1):
            tokens.add(cn[i:i + 2])
        return frozenset(tokens)

    def _jaccard(a: frozenset, b: frozenset) -> float:
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union > 0 else 0.0

    # 预计算每个 candidate 的 token 集合
    tok_cache = []
    for score, chunk in candidates:
        text = (chunk.get("summary") or "") + " " + (chunk.get("content") or "")[:200]
        tok_cache.append(_tok(text))

    # 归一化 relevance score 到 [0.1, 1.0]（floor=0.1 防止最低分被归零）
    # 若 norm → 0，λ×0 - (1-λ)×0 = 0，多样低分候选无法胜过高相似度候选
    # floor 保证最低分候选仍有正 relevance contribution，让 diversity 能发挥
    scores = [s for s, _ in candidates]
    s_min, s_max = min(scores), max(scores)
    s_range = s_max - s_min if s_max > s_min else 1.0
    _floor = 0.1
    norm_scores = [_floor + (1.0 - _floor) * (s - s_min) / s_range for s in scores]

    selected_idx = []
    selected_toks = []
    remaining = list(range(len(candidates)))

    while len(selected_idx) < top_k and remaining:
        best_idx = None
        best_mmr = -1.0

        for idx in remaining:
            rel = norm_scores[idx]
            # 与已选集合的最大相似度
            if not selected_toks:
                max_sim = 0.0
            else:
                max_sim = max(_jaccard(tok_cache[idx], st) for st in selected_toks)

            # 只在超过 sim_threshold 时才惩罚（避免误杀弱相关 chunk）
            sim_penalty = max_sim if max_sim >= sim_threshold else 0.0
            mmr = lambda_mmr * rel - (1 - lambda_mmr) * sim_penalty

            if mmr > best_mmr:
                best_mmr = mmr
                best_idx = idx

        if best_idx is None:
            break

        selected_idx.append(best_idx)
        selected_toks.append(tok_cache[best_idx])
        remaining.remove(best_idx)

    return [candidates[i] for i in selected_idx]


# ── helpers ────────────────────────────────────────────────────────────────────

def _read_page_fault_log(limit: int = 5) -> list:
    """
    读取缺页日志，返回优先级最高的 N 条 query 字符串。
    缺页日志由 extractor.py Stop hook 写入，记录上轮推理中的知识缺口。
    v3 闭环：消费后标记 resolved=True 而非清空，保留热缺页计数信息。
    按 fault_count 降序消费（热缺页优先补入）。
    """
    if not os.path.exists(PAGE_FAULT_LOG):
        return []
    try:
        with open(PAGE_FAULT_LOG, encoding="utf-8") as _f:
            entries = json.loads(_f.read())
        if not entries:
            return []
        # 过滤未解决的条目，按 fault_count 降序（热缺页优先）
        unresolved = [e for e in entries
                      if isinstance(e, dict) and "query" in e
                      and not e.get("resolved", False)]
        unresolved.sort(key=lambda e: e.get("fault_count", 1), reverse=True)
        queries = [e["query"] for e in unresolved[:limit]]
        # 标记已消费的为 resolved（而非清空，保留统计信息）
        consumed_queries = set(q.lower().strip() for q in queries)
        for e in entries:
            if isinstance(e, dict) and e.get("query", "").lower().strip() in consumed_queries:
                e["resolved"] = True
        with open(PAGE_FAULT_LOG, 'w', encoding="utf-8") as _f:
            _f.write(json.dumps(entries, ensure_ascii=False, indent=2))
        return queries
    except Exception:
        return []


def _extract_key_entities(text: str) -> list:
    """
    从 prompt 中提取高信号实体用于 query expansion。
    提取规则：反引号包裹的标识符、大写缩写词、文件路径样式。
    """
    import re as _re_eke  # 迭代160：re 延迟加载，此函数可在 _load_modules 前调用
    entities = []
    # 反引号包裹的代码标识符
    for m in _re_eke.finditer(r'`([^`]{2,40})`', text):
        entities.append(m.group(1))
    # 全大写缩写词（>= 2字符，如 BM25, LRU, API）
    for m in _re_eke.finditer(r'\b([A-Z][A-Z0-9_]{1,10})\b', text):
        entities.append(m.group(1))
    # 文件路径样式（含 / 或 .py/.js/.md）
    for m in _re_eke.finditer(r'[\w./]+\.(?:py|js|md|json|db)\b', text):
        entities.append(m.group(0))
    return list(dict.fromkeys(entities))[:5]  # 去重，最多5个


def _build_causal_query(prompt: str) -> str:
    """
    迭代330：causal secondary query — 为 causal_chain 专属补充搜索构造查询。
    返回一个独立的 causal-focused query，在主 FTS5 搜索后作为第二轮补充搜索。

    OS 类比：Linux readahead ≥ 2 pass — 第一轮 VFS readahead 基于 offset，
    第二轮 ext4 readahead 基于 extent map — 两轮覆盖不同维度，
    结果合并进 page cache，不覆盖第一轮结果。

    策略（不追加到主 query，避免影响 FTS5 主排序）：
      含显式因果词 → 用 prompt + 核心因果语义词构造专属 causal query
      含技术实体   → 用 技术词 + "原因 导致 因为" 构造 causal query
      否则         → 返回空（不做第二轮搜索）
    """
    if not prompt:
        return ""

    import re as _re_cq  # 迭代330：局部 import，此函数可在 _load_modules 前调用
    _CAUSAL_QUERY_WORDS = _re_cq.compile(
        r'(?:为什么|原因|怎么|如何|导致|引起|根因|根本原因|'
        r'why|because|reason|how|cause|result|due to)',
        _re_cq.IGNORECASE
    )
    if _CAUSAL_QUERY_WORDS.search(prompt):
        # 已含因果词：原 prompt 就是好的 causal query，追加因果扩展词增强覆盖
        return f"{prompt[:100]} 原因 导致 因为 根因"

    # 含技术实体但无因果词：构造 "技术词 + 因果语义词" 的 causal query
    has_tech = bool(_re_cq.search(r'[A-Z]{2,}|[a-z]+_[a-z]+|\w+\.\w+|`[^`]+`|\d+ms', prompt))
    if has_tech:
        return f"{prompt[:80]} 原因 导致 因为"

    return ""


def _build_query(hook_input: dict) -> str:
    """
    v18 迭代62：Query Truncation — 限制 query 长度防止 FTS5 性能退化。
    OS 类比：Linux I/O scheduler request merging — 过大的 I/O request 会被拆分，
    因为 DMA 传输有硬件限制（max_sectors_kb），超过会退化为多次传输。
    同理，FTS5 对超长 query 的 token 匹配复杂度 O(T×D)（T=tokens, D=docs），
    1600字 query → ~800 tokens → 9 docs 匹配也要 200ms+。
    截断到 300 字（~150 tokens）可将 FTS5 时间从 200ms+ 降到 <10ms。
    """
    prompt = hook_input.get("prompt", "") or ""
    task_list = hook_input.get("task_list") or hook_input.get("tasks") or []
    if isinstance(task_list, str):
        try:
            task_list = json.loads(task_list)
        except Exception:
            task_list = []
    in_progress = []
    for t in task_list:
        if isinstance(t, dict) and t.get("status") == "in_progress":
            subj = t.get("subject") or t.get("title") or ""
            if subj:
                in_progress.append(subj)
    tasks_joined = " ".join(in_progress)

    # Query expansion：提取关键实体追加到查询，提升召回覆盖度
    entities = _extract_key_entities(prompt)
    entities_str = " ".join(entities)

    raw_query = f"{prompt} {tasks_joined} {entities_str}".strip()

    # 迭代62：Query Truncation — 截断超长 query
    max_query_chars = _sysctl("retriever.max_query_chars")
    if len(raw_query) > max_query_chars:
        raw_query = raw_query[:max_query_chars]

    return raw_query


    # ── _open_db / _get_chunks 已迁移至 store.py（迭代21 VFS 统一数据访问层）──


def _read_hash() -> str:
    try:
        with open(HASH_FILE, encoding="utf-8") as _f:
            return _f.read().strip()
    except Exception:
        return ""


def _write_hash(h: str) -> None:
    try:
        os.makedirs(MEMORY_OS_DIR, exist_ok=True)
        with open(HASH_FILE, 'w', encoding="utf-8") as _f:
            _f.write(h)
    except Exception:
        pass


def _mark_session_injected(session_id: str) -> None:
    """iter805: 记录已成功注入的 session_id，供 TLB 快捷路径判断。
    文件只保留最近 50 个 session_id（每行一个），避免无限增长。"""
    if not session_id or session_id == "unknown":
        return
    try:
        existing = set()
        try:
            with open(SESSION_INJECTED_FILE, encoding="utf-8") as _f:
                existing = set(_f.read().strip().split("\n"))
        except OSError:
            pass
        if session_id in existing:
            return
        existing.add(session_id)
        # 保留最近 50 个（文件末尾是最新的）
        lines = list(existing)[-50:]
        with open(SESSION_INJECTED_FILE, 'w', encoding="utf-8") as _f:
            _f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def _live_access_counts(chunk_ids: list) -> dict:
    """iter634: 用标准连接获取最新 access_count，绕过 immutable WAL 盲区。
    主连接 immutable=1 看不到 WAL 中的最新写入，导致 monopoly_post_filter
    读到过时的 access_count → 垄断 chunk 逃逸。
    """
    if not chunk_ids:
        return {}
    try:
        import sqlite3 as _lac_sql
        _lac_conn = _lac_sql.connect(str(STORE_DB))
        ph = ",".join("?" * len(chunk_ids))
        rows = _lac_conn.execute(
            f"SELECT id, COALESCE(access_count, 0) FROM memory_chunks WHERE id IN ({ph})",
            chunk_ids
        ).fetchall()
        _lac_conn.close()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}


# ── 迭代57：TLB — Translation Lookaside Buffer 检索快速路径 ──────────────────
# OS 类比：CPU TLB (1965, IBM System/360 Model 67)
#   虚拟地址→物理地址的映射缓存在 TLB（通常 64-1024 entries）。
#   TLB hit → 跳过 4 级页表 walk（~7ns vs ~100ns），命中率通常 >95%。
#   TLB miss → 完整 page table walk → 结果写回 TLB。
#   TLB 失效条件：页表更新（mmap/munmap/fork）时 flush。
#
#   memory-os 等价问题：
#     retriever 的 injection_hash 检查在 FTS5 + 评分 + madvise + readahead 之后，
#     发现结果和上次一样（skipped_same_hash），但已经花了 25ms。
#     这等价于"每次地址翻译都做完整 page table walk 再检查 TLB"。
#
#   解决：
#     TLB 缓存 {prompt_hash → injection_hash, db_mtime}。
#     TLB hit（相同 prompt_hash + db 未变）→ 直接比较 injection_hash，<1ms。
#     TLB miss → 完整检索流程 → 结果写回 TLB。
#     TLB 失效：db_mtime 变化（有新写入）→ 自动 flush。

def _tlb_read() -> dict:
    """
    读取 TLB v2 多 slot 缓存。返回 {} 如果不存在或损坏。
    迭代64：格式升级为 {chunk_version: int, slots: {prompt_hash: {injection_hash: str}}}
    """
    try:
        if os.path.exists(TLB_FILE):
            with open(TLB_FILE, encoding="utf-8") as _f:
                data = json.loads(_f.read())
            # 兼容 v1 格式：如果有 prompt_hash 字段说明是旧格式
            if "prompt_hash" in data and "slots" not in data:
                # 迁移 v1 → v2
                return {
                    "chunk_version": -1,  # 强制 miss，让下次正常检索后回填
                    "slots": {data["prompt_hash"]: {"injection_hash": data.get("injection_hash", "")}},
                }
            return data
    except Exception:
        pass
    return {}


def _tlb_write(prompt_hash: str, injection_hash: str, db_mtime: float) -> None:
    """
    写入 TLB v2 缓存。
    迭代64：multi-slot + chunk_version 替代 db_mtime。
    iter583：写入当前 generation，供 age-out 判定。
    保留 db_mtime 参数签名以保持向后兼容（不改调用方），但实际使用 chunk_version。
    """
    try:
        os.makedirs(MEMORY_OS_DIR, exist_ok=True)

        # 读取当前 chunk_version
        chunk_ver = 0
        if os.path.exists(CHUNK_VERSION_FILE):
            try:
                with open(CHUNK_VERSION_FILE, encoding="utf-8") as _f:
                    chunk_ver = int(_f.read().strip())
            except (ValueError, OSError):
                chunk_ver = 0

        # iter583: 读取当前 generation
        gen = 0
        try:
            if os.path.exists(TLB_GENERATION_FILE):
                with open(TLB_GENERATION_FILE, encoding="utf-8") as _f:
                    gen = int(_f.read().strip())
        except (ValueError, OSError):
            gen = 0

        # 读取现有 TLB 并更新 slot
        existing = _tlb_read()
        slots = existing.get("slots", {})

        # 写入/更新当前 prompt_hash 的 slot
        slots[prompt_hash] = {"injection_hash": injection_hash}

        # LRU 淘汰：超过 MAX 时删除最早的条目
        # 简单策略：保留最后 N 个 key（dict 在 Python 3.7+ 保持插入顺序）
        max_entries = _sysctl("retriever.tlb_max_entries")
        if len(slots) > max_entries:
            keys = list(slots.keys())
            for k in keys[:len(keys) - max_entries]:
                del slots[k]

        with open(TLB_FILE, 'w', encoding="utf-8") as _f:
            _f.write(json.dumps({
                "chunk_version": chunk_ver,
                "slots": slots,
                "generation": gen,  # iter583: 记录写入时的 generation
            }))
    except Exception:
        pass


def _tlb_bump_generation() -> int:
    """
    iter583: FULL 检索完成后递增全局 TLB generation 计数器。
    OS 类比：Linux flush_tlb_mm_range() 递增 mm_struct->context.ctx_id（generation），
      让其他 CPU 的 TLB 在下次 context switch 时发现 generation 不匹配而 flush。
    返回新的 generation 值。
    """
    try:
        gen = 0
        if os.path.exists(TLB_GENERATION_FILE):
            try:
                with open(TLB_GENERATION_FILE, encoding="utf-8") as _f:
                    gen = int(_f.read().strip())
            except (ValueError, OSError):
                gen = 0
        gen += 1
        os.makedirs(MEMORY_OS_DIR, exist_ok=True)
        with open(TLB_GENERATION_FILE, 'w', encoding="utf-8") as _f:
            _f.write(str(gen))
        return gen
    except Exception:
        return 0


def _get_db_mtime() -> float:
    """获取 store.db 的 mtime（迭代64 保留用于 fallback 兼容）。"""
    try:
        return os.stat(STORE_DB).st_mtime
    except Exception:
        return 0.0


def _read_chunk_version() -> int:
    """读取 chunk_version（迭代64: 替代 db_mtime 的 TLB 失效判据）。"""
    try:
        if os.path.exists(CHUNK_VERSION_FILE):
            with open(CHUNK_VERSION_FILE, encoding="utf-8") as _f:
                return int(_f.read().strip())
    except (ValueError, OSError):
        pass
    return 0


# ── trace ─────────────────────────────────────────────────────────────────────

def _write_trace(session_id: str, project: str, prompt_hash: str,
                 candidates_count: int, top_k_data: list,
                 injected: int, reason: str, duration_ms: float = 0.0,
                 conn=None) -> None:
    """
    写 recall_traces 记录。
    v8 迭代21：委托 store.py（VFS 统一数据访问层）。
    """
    # iter917: write_trace_empty_guard — injected=1 但 top_k 为空时降级为 injected=0
    # 根因：suppress 全灭后多个路径仍调用 _write_trace(injected=1, top_k=[])
    #   污染 recall_counts 统计（bw_window 分母膨胀→suppress 比例失真）。
    if injected and not top_k_data:
        injected = 0
    should_close = conn is None
    try:
        if conn is None:
            conn = open_db()
            ensure_schema(conn)
        store_insert_trace(conn, {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "project": project,
            "prompt_hash": prompt_hash,
            "candidates_count": candidates_count,
            "top_k_json": top_k_data,
            "injected": injected,
            "reason": reason,
            "duration_ms": duration_ms,
        })
        if should_close:
            conn.commit()
            conn.close()
    except Exception:
        if should_close and conn:
            try:
                conn.close()
            except Exception:
                pass


# ── 迭代85：Shadow Trace — perf_event 采样式工作集追踪 ─────────────────────
# OS 类比：Linux perf_event (2009, Ingo Molnár) — 即使进程不做系统调用，
#   PMU 采样仍能记录其活动状态。SKIP/TLB 快速路径不写 recall_traces，
#   但 save-task-state.py 需要 hit_ids 构建 swap_out 工作集。
#   shadow trace 在 write-back 阶段写入轻量级 JSON 文件（~0.1ms），
#   记录最后一次成功检索的 top_k IDs。swap_out 时 recall_traces 为空则 fallback。

def _write_shadow_trace(project: str, top_k_ids: list, session_id: str = "") -> None:
    """写入 shadow trace 文件，供 swap_out fallback 使用。"""
    try:
        with open(SHADOW_TRACE_FILE, 'w', encoding="utf-8") as _f:
            _f.write(json.dumps({
                "project": project,
                "top_k_ids": top_k_ids,
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }, ensure_ascii=False))
    except Exception:
        pass  # shadow trace 写入失败不影响正常流程


def _update_ior_state(top_k_ids: list, session_id: str, exempt_types: set = None,
                      chunk_types: dict = None) -> None:
    """
    iter391: 更新 IOR (Inhibition of Return) 状态文件。
    记录本次注入的 chunk_ids 和当前 turn，用于下次检索时施加返回抑制。
    OS 类比：Linux CFQ timeslice bookkeeping — 更新已服务字节数，调整下次服务权重。
    """
    try:
        _ior_data = {}
        try:
            with open(IOR_FILE, 'r', encoding="utf-8") as _ior_f:
                _ior_data = json.loads(_ior_f.read())
        except Exception:
            pass

        if _ior_data.get("session_id") != session_id:
            # 新 session — 重置 IOR 状态
            _ior_data = {"session_id": session_id, "injections": {}, "current_turn": 0}

        _ior_data["current_turn"] = _ior_data.get("current_turn", 0) + 1
        _cur_turn = _ior_data["current_turn"]
        _injs = _ior_data.get("injections", {})

        for cid in top_k_ids:
            # design_constraint 等豁免类型不记录 IOR
            if exempt_types and chunk_types and chunk_types.get(cid) in exempt_types:
                continue
            _injs[cid] = _cur_turn

        # 清理过旧的记录（> 50 turns ago，避免内存无限增长）
        _stale_cutoff = _cur_turn - 50
        _ior_data["injections"] = {k: v for k, v in _injs.items() if v > _stale_cutoff}

        with open(IOR_FILE, 'w', encoding="utf-8") as _ior_f:
            _ior_f.write(json.dumps(_ior_data, ensure_ascii=False))
    except Exception:
        pass  # IOR 状态更新失败不影响主流程


# ── main ──────────────────────────────────────────────────────────────────────

def _open_db_readonly():
    """
    迭代84：只读模式打开 DB，避免与 writer/extractor 锁竞争。
    OS 类比：open(O_RDONLY) — 只读 fd 不竞争 flock LOCK_EX。

    WAL 模式下 reader 不阻塞 writer、writer 不阻塞 reader，
    但 DDL（ensure_schema 的 CREATE TABLE IF NOT EXISTS）和
    dmesg_log（INSERT INTO dmesg）需要写锁，会被并发 writer 阻塞。
    immutable=1 完全避免写锁请求：连接只读，FTS5 查询正常工作。
    """
    import sqlite3 as _sq
    db_str = str(STORE_DB)
    try:
        uri = f"file:{db_str}?immutable=1"
        return _sq.connect(uri, uri=True)
    except Exception:
        conn = _sq.connect(db_str, timeout=2)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        return conn


class _DeferredLogs:
    """
    迭代84：dmesg 延迟写入缓冲区。
    OS 类比：Linux printk ring buffer (log_buf) — 内核打印先进 ring buffer，
    由 klogd/console 异步消费。

    检索阶段收集 dmesg 消息到内存缓冲区（零 I/O），
    输出后用写连接批量 flush（不影响用户感知延迟）。
    """
    __slots__ = ('_buf',)

    def __init__(self):
        self._buf = []

    def log(self, level, subsystem, message, session_id=None, project=None, extra=None):
        self._buf.append((level, subsystem, message, session_id, project, extra))

    def flush(self, conn):
        """Flush all buffered logs to DB via write connection."""
        for level, subsystem, message, session_id, project, extra in self._buf:
            try:
                dmesg_log(conn, level, subsystem, message,
                          session_id=session_id, project=project, extra=extra)
            except Exception:
                pass
        self._buf.clear()

    def __len__(self):
        return len(self._buf)


def main():
    import time as _time
    _t_wall_start = _time.time()  # 迭代62：wall clock 记录（含 import）

    # ── 迭代61：vDSO Fast Path 已在 __main__ 块处理 Stage 0 + Stage 1 ──
    # 如果到达这里，说明 SKIP + TLB 都 miss，需要完整检索
    # _vdso_hook_input 由 _vdso_fast_exit() 传入（stdin 已耗尽不能重读）
    _load_modules()

    # 迭代62：PSI Import-aware Timing — _t_start 在 import 之后重置
    # OS 类比：Linux perf_event exclude_kernel — 只统计用户态执行时间
    # Python import 是进程冷启动的固定开销（~25ms），不应计入检索延迟。
    # 之前 _t_start 在 import 前，导致 duration_ms 包含 import 开销：
    #   import(25ms) + FTS5(3ms) + scoring(0.3ms) = 记录 28.3ms，
    #   但 PSI baseline 是 17ms → 标记为 stall → PSI FULL 恶性循环。
    # 修复后 _t_start 在 import 后，只反映真实检索时间。
    _t_start = _time.time()

    hook_input = _vdso_hook_input or {}

    _hook_cwd = hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
    project = resolve_project_id(_hook_cwd if _hook_cwd else None)
    # 迭代66：从 hook stdin 获取 session_id（/proc/self/status PID Identity）
    # 之前从环境变量取，但 CLAUDE_SESSION_ID 未被设置 → 全部 "unknown"
    # hook stdin JSON 包含 session_id 字段，这是权威来源
    session_id = (hook_input.get("session_id", "")
                  or os.environ.get("CLAUDE_SESSION_ID", "")
                  or "unknown")

    prompt = hook_input.get("prompt", "") or ""
    query = _build_query(hook_input)

    # ── iter372: Context-Aware current context — cwd + focus keywords ──────────
    # OS 类比：NUMA topology — 本地节点的页面访问延迟更低，优先分配
    # 编码特异性原理（Tulving 1975）：编码时与检索时上下文越匹配，记忆提取越准确
    _current_cwd = (hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")).rstrip("/")
    _current_context = {"cwd": _current_cwd}
    # ── iter394: Contextual Similarity Boost — 从 query 提取当前任务情境 ──────
    # Tulving (1983) Encoding Specificity + Godden & Baddeley (1975):
    #   检索时的 session_type/task_verbs 与编码时越一致，记忆提取成功率越高。
    # OS 类比：NUMA-aware scheduler — 优先将进程调度到数据所在的 NUMA 节点。
    if query:
        try:
            from store_vfs import extract_encoding_context as _eec
            _q_ctx = _eec(query)
            _current_context["session_type"] = _q_ctx.get("session_type", "unknown")
            _current_context["task_verbs"] = _q_ctx.get("task_verbs", [])
            _current_context["query"] = query  # fallback for entity extraction
        except Exception:
            _current_context["query"] = query

    # 缺页日志：上轮推理标记的知识缺口，追加到查询
    page_fault_queries = _read_page_fault_log()
    if page_fault_queries:
        fault_text = " ".join(page_fault_queries)
        query = f"{query} {fault_text}".strip()

    if not query:
        sys.exit(0)

    if not os.path.exists(STORE_DB):
        sys.exit(0)

    # ── 迭代28：Scheduler Nice Levels — 查询优先级分类 ──
    # OS 类比：sched_setscheduler() 在进程创建时根据特征设置调度策略
    has_page_fault = bool(page_fault_queries)
    entities = _extract_key_entities(prompt)
    priority = _classify_query_priority(prompt, query, has_page_fault, len(entities), project=project)

    if priority == "SKIP":
        # nice 19：零 I/O，直接退出
        # 注：迭代61 vDSO 已在 heavy import 前拦截大部分 SKIP，这里是 defense in depth
        sys.exit(0)

    # ── 迭代57→64：TLB v2 — Multi-Slot + chunk_version ──
    # 迭代64 升级：vDSO Stage 1 已检查 chunk_version（无缺页时），这里做 defense-in-depth
    # 有缺页时不走 vDSO TLB → 这里是唯一的 TLB 检查点
    # 迭代156：zlib.crc32 — 与 vDSO Stage 1 保持一致（相同 prompt → 相同 hash）
    prompt_hash = format(zlib.crc32(prompt.encode()) & 0xffffffff, '08x')
    # iter805: session_first_inject_guard (main path, defense-in-depth)
    _sid_inj_main = False
    try:
        with open(SESSION_INJECTED_FILE, encoding="utf-8") as _f:
            _sid_inj_main = session_id in _f.read()
    except OSError:
        pass
    if not has_page_fault and _sid_inj_main:
        chunk_ver = _read_chunk_version()
        tlb = _tlb_read()
        tlb_ver = tlb.get("chunk_version", -1)
        slots = tlb.get("slots", {})
        last_hash = _read_hash()

        if chunk_ver == tlb_ver:
            # chunk_version 匹配 → DB 内容未变
            # L1: prompt_hash 在 slot 中且 injection_hash 一致
            if prompt_hash in slots and slots[prompt_hash].get("injection_hash") == last_hash:
                sys.exit(0)
            # L2: 任意 slot 的 injection_hash 与当前一致（结果未变）
            if last_hash:
                for _s in slots.values():
                    if _s.get("injection_hash") == last_hash:
                        sys.exit(0)

    # 自适应 Top-K：有缺页信号时扩大召回范围（demand paging）
    # 迭代27：从 sysctl 注册表读取（运行时可调）
    effective_top_k = _sysctl("retriever.top_k_fault") if has_page_fault else _sysctl("retriever.top_k")
    effective_max_chars = _sysctl("retriever.max_context_chars_fault") if has_page_fault else _sysctl("retriever.max_context_chars")

    # ── Adaptive K — Citation Rate 反馈驱动 top_k 动态调整 ──────────────────
    # OS 类比：Linux readahead 根据 sequential page fault 命中率动态调整
    #   readahead_max_sectors：命中率高 → 扩大预取窗口，命中率低 → 缩小预取窗口。
    # 心理学对应：工作记忆容量弹性 — 高度相关的信息可以 "chunking" 扩展有效容量。
    # 信噪比：citation_rate < 30% → 注入大量无用噪声，缩小 top_k；
    #          citation_rate > 65% → 大多数注入有效，可适度扩大 top_k。
    # 实现：读取轻量 citation_stats.{project}.json（无 DB 查询，<1ms），
    #        在 sysctl 配置值基础上微调 ±1~2，不超过安全边界。
    if not has_page_fault and _sysctl("retriever.adaptive_k_enabled"):
        try:
            import os as _os
            _proj_safe = project.replace("/", "_").replace(":", "_")[:40]
            _stats_file = _os.path.join(
                _os.path.expanduser("~"), ".claude", "memory-os",
                f"citation_stats.{_proj_safe}.json"
            )
            if _os.path.exists(_stats_file):
                import json as _json_ak
                _cr_data = _json_ak.loads(open(_stats_file, encoding="utf-8").read())
                _citation_rate = float(_cr_data.get("citation_rate", 0.5))
                _ak_min = max(2, _sysctl("retriever.top_k") - 2)
                _ak_max = min(10, _sysctl("retriever.top_k") + 3)
                if _citation_rate < 0.30:
                    # 低命中率 → 收缩（减少噪声注入）
                    effective_top_k = max(_ak_min, effective_top_k - 1)
                elif _citation_rate > 0.65:
                    # 高命中率 → 扩张（注入更多有价值记忆）
                    effective_top_k = min(_ak_max, effective_top_k + 2)
                # 30%-65% 区间：维持当前值（稳态）
        except Exception:
            pass  # adaptive_k 读取失败不影响主流程

    # ── 迭代36：PSI 反馈回路 — 压力驱动的动态降级 ──
    # OS 类比：Linux PSI triggers — cgroup 在压力超阈值时触发 OOM/throttle
    # 当检索系统处于高压力（FULL）时，scheduler 自动从 FULL 降级到 LITE
    # 这是从开环调度（迭代28）到闭环调度的升级：
    #   开环：根据 query 特征静态分类（无反馈）
    #   闭环：根据 query 特征 + 系统压力动态调整（有反馈）
    psi_downgraded = False
    # 注：PSI 检查需要 conn，延迟到连接打开后执行（见下方 PSI feedback 块）

    # 是否执行 knowledge_router（LITE 模式跳过）
    run_router = (priority == "FULL") and _KR_AVAILABLE

    # ── 迭代41：Deadline I/O Scheduler — 时间预算设定 ──
    # OS 类比：Linux Deadline I/O Scheduler (2002, Jens Axboe)
    #   每个 I/O 请求有 read_expire/write_expire deadline：
    #     read: 500ms, write: 5000ms — 读优先级高于写
    #   调度器在 deadline 前按效率排序（类似 elevator），
    #   接近 deadline 时强制 dispatch（避免 starvation）。
    #   mq-deadline (2019) 将单队列扩展为多队列（per-hw-queue），
    #   每个队列独立调度，消除全局锁竞争。
    #
    #   memory-os 等价问题：
    #     检索链路 FTS5 → scorer → madvise → swap_fault → router
    #     各阶段耗时不确定（取决于数据量和查询复杂度）。
    #     没有时间预算时，任何一个阶段慢都会拖累整体。
    #     hook timeout=10s 是硬限制但太宽松，实际要求 < 50ms。
    #
    #   解决：
    #     deadline_ms (30ms) — soft deadline，超过时跳过低优先级阶段
    #     deadline_hard_ms (80ms) — hard deadline，超过时立即返回已有结果
    #     阶段优先级（高→低）：FTS5 > scorer > madvise > swap_fault > router
    #     低优先级阶段在 soft deadline 后被跳过（graceful degradation）
    deadline_ms = _sysctl("retriever.deadline_ms")
    deadline_hard_ms = _sysctl("retriever.deadline_hard_ms")
    deadline_skipped = []  # 记录被 deadline 跳过的阶段

    def _elapsed_ms():
        return (_time.time() - _t_start) * 1000

    def _check_deadline(stage_name: str, is_hard: bool = False) -> bool:
        """检查是否超过 deadline。返回 True = 超时应跳过。"""
        elapsed = _elapsed_ms()
        if is_hard and elapsed >= deadline_hard_ms:
            deadline_skipped.append(f"{stage_name}(HARD)")
            return True
        if not is_hard and elapsed >= deadline_ms:
            deadline_skipped.append(stage_name)
            return True
        return False

    # ── 迭代84：Read-Only Fast Path — 检索阶段只读连接 ──────────────────
    # OS 类比：Linux O_RDONLY + write-back — read 路径用只读 fd（零锁竞争），
    #   dirty data 由 pdflush 异步写回。
    #
    #   根因：retriever (sync) 与 writer (async) 都是 UserPromptSubmit hook，
    #   几乎同时触发。writer 持有写锁执行 INSERT + commit (含 WAL checkpoint ~40-100ms)，
    #   retriever 的 ensure_schema() DDL 和 dmesg_log() INSERT 需要写锁 → 被阻塞 100-400ms
    #   → post_scoring hard_deadline 超时 (29/93 次，P95=435ms)。
    #
    #   解决：
    #   Phase 1 (read-only)：immutable=1 连接 + _DeferredLogs 缓冲区
    #     - FTS5 搜索、评分、排序 — 纯读操作，零锁竞争
    #     - dmesg 消息收集到内存缓冲区（<1μs），不写 DB
    #     - ensure_schema 完全跳过（只读连接无需 DDL）
    #   Phase 2 (write-back)：输出结果后打开写连接
    #     - 批量 flush dmesg + update_accessed + mglru_promote + insert_trace + commit
    #     - 不影响用户感知延迟（输出已发送）
    #
    # ── 迭代24 升级：Per-Request 拆为 read-conn + write-conn ──
    _deferred = _DeferredLogs()
    conn = _open_db_readonly()
    # 修复：_t_start 在 open_db 后重置，排除连接获取等待时间（WAL checkpoint 锁竞争）。
    # 根因：writer WAL checkpoint 触发 EXCLUSIVE 锁时，reader 的 connect() 需等待
    # 获得共享锁，这段等待时间不是检索本身的开销，不应计入 deadline。
    # cands=1 dur=522ms 的 hard_deadline 超时正是由此引起的。
    _t_start = _time.time()
    try:
        # 跳过 ensure_schema — 只读连接无需 DDL，schema 由 writer/extractor 维护
        candidates_count = 0  # trace 用：候选集大小

        # ── 迭代36：PSI feedback — 压力检测 + 动态降级 ──
        # 迭代41：PSI 检查受 deadline 约束（低优先级阶段）
        if priority == "FULL" and not _check_deadline("psi"):
            try:
                psi = psi_stats(conn, project)
                psi_overall = psi.get("overall", "NONE")
                if psi_overall == "FULL":
                    priority = "LITE"
                    run_router = False
                    psi_downgraded = True
                    _deferred.log(DMESG_WARN, "retriever",
                              f"PSI downgrade: FULL→LITE overall={psi_overall} "
                              f"ret={psi['retrieval']['level']} cap={psi['capacity']['level']} "
                              f"qual={psi['quality']['level']}",
                              session_id=session_id, project=project,
                              extra={"psi": psi})
            except Exception:
                pass  # PSI 失败不影响主流程

        # ── 迭代55：Context Pressure Governor — 动态注入窗口缩放 ──
        # OS 类比：TCP BBR pacing_rate = BtlBw × gain
        # effective_max_chars *= governor.scale
        gov_info = {"level": "NORMAL", "scale": 1.0}
        try:
            gov_info = context_pressure_governor(conn, project, session_id=session_id)
            gov_scale = gov_info.get("scale", 1.0)
            if gov_scale != 1.0:
                effective_max_chars = int(effective_max_chars * gov_scale)
                # 下限保护：至少 150 字（确保最关键信息能注入）
                effective_max_chars = max(effective_max_chars, 150)
        except Exception:
            pass  # governor 失败不影响主流程

        # 迭代29 dmesg：记录检索请求入口（迭代84：延迟写入）
        gov_tag = f" gov={gov_info['level']}({gov_info['scale']:.1f})" if gov_info.get("level") != "NORMAL" else ""
        _deferred.log(DMESG_DEBUG, "retriever",
                  f"priority={priority} query_len={len(query)} entities={len(entities)} page_faults={len(page_fault_queries)}"
                  + (f" psi_downgraded=Y" if psi_downgraded else "")
                  + gov_tag,
                  session_id=session_id, project=project)

        # ── 迭代62：Anti-Starvation — 加载 chunk 召回计数 ──
        # OS 类比：/proc/PID/sched nr_switches — 统计进程调度次数
        # ── iter565: rcu_dereference — Recall Counts Visibility Barrier ──
        # 根因：主连接是 immutable=1（不读 WAL），recall_traces 新记录在 WAL 中，
        #   导致 _recall_counts 为空 → bandwidth_throttle/cfs_bandwidth_throttle 失效
        #   → 垄断 chunk score 永远 ~0.99，anti-monopoly 机制全部短路。
        # OS 类比：rcu_dereference() (Paul McKenney, 2002) — RCU 读者必须通过
        #   memory barrier 看到 writer 的最新更新，否则读到 stale 数据。
        #   immutable=1 等价于缺失 read barrier 的 RCU reader。
        # 修复：用独立的标准 WAL 连接加载 recall_counts，确保看到最新 traces。
        _recall_counts = {}
        _recent_24h_counts = {}  # iter614: temporal_burst_suppression
        _recent_7d_counts = {}   # iter630: hoist default outside try — prevent NameError on connect failure
        _INJECTION_TIMELINE_FILE = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")  # iter647
        _injection_timeline = {}  # iter647: WAL-immune cross-session timeline
        _local_bw_window = 30  # iter610: fallback if outer try fails
        # iter797: db_chunk_count — 用 DB 中实际 chunk 总数判定 tiny/small，
        #   替代 candidates_count（FTS5 返回数）。
        #   根因（数据驱动，2026-05-04）：实际仅 36 chunks，但长 query 的
        #   FTS5 可返回 32 candidates → candidates_count>=30 → tiny_db=False
        #   → suppress 阈值收紧 + fallback noise_floor 提高(0.15→0.25)
        #   → 51% 空召回。chunk 总数才是"库大小"的真实度量。
        _db_chunk_count = 50  # fallback: 保守估计（走 small_db 路径）
        try:
            import sqlite3 as _rc_sql
            _rc_conn = _rc_sql.connect(str(STORE_DB))
            # iter797: 查询实际 chunk 总数
            try:
                _db_chunk_count = _rc_conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
                ).fetchone()[0] or 0
            except Exception:
                pass  # 保持 fallback=50
            _recall_counts = chunk_recall_counts(_rc_conn, project, window=30)
            # ── iter588: effective_bw_window — 实际 trace 数量（修复少 trace 项目窗口稀释） ──
            # 问题（数据驱动，2026-05-02）：项目只有 8 条 trace 时 rc=3/window=30=10% < 30%，
            # 但实际利用率 3/8=37% → bandwidth_throttle 失效，垄断 chunk 持续注入。
            # 修复：用 min(30, actual_trace_count) 作为有效窗口。
            try:
                # iter604: 与 chunk_recall_counts 对齐，只统计 injected=1 的 trace
                # iter669: bw_window_nonempty — 只统计 top_k_json 非空的 trace
                # 根因：60% injected trace 的 top_k_json 为 []（无 chunk 达到阈值），
                #   这些空 trace 膨胀了 _effective_bw_window 分母，导致 bandwidth
                #   utilization (_rc / _local_bw_window) 被严重低估。
                #   例：chunk 在 7 条有效 trace 中出现 4 次 = 57%，但分母被空 trace
                #   撑到 23 → 4/23=17%，远低于 hard_cap=30%，垄断逃逸。
                # 修复：分母只计算有实际 chunk 注入的 trace，与 chunk_recall_counts
                #   的分子（遍历 top_k_json 中的 chunk ID）语义对齐。
                _atc = _rc_conn.execute(
                    "SELECT COUNT(*) FROM recall_traces WHERE project=? AND injected=1"
                    " AND top_k_json IS NOT NULL AND top_k_json != '[]'", (project,)
                ).fetchone()[0]
                _effective_bw_window = min(30, max(1, _atc))
            except Exception:
                _effective_bw_window = 30
            # iter773: bw_window_floor — 统计不充分时不应过度 suppress
            # 根因（数据驱动，2026-05-04）：project 只有 12 条有效 inject trace，
            #   _effective_bw_window=12 + hard_cap=0.12 → rc>1.44 即 suppress。
            #   结果：任何 chunk 被注入 ≥2 次就被 suppress，导致 cands=10 全灭空召回。
            #   本质：12 条样本不足以判定"垄断"，过早惩罚压制了有价值的知识。
            # 修复：floor=20 确保 suppress 阈值至少 rc>2.4（rc>=3 才触发），
            #   让系统积累足够统计量后再做垄断判断。
            _effective_bw_window = max(_effective_bw_window, 20)
            # iter610: hard_cap_local_window — memcg inflate 前的 per-project window
            # 根因：iter606 memcg inflate 将 _effective_bw_window 从 19→39，
            #   导致 per-project 垄断 chunk (rc=12/39=0.31) 刚好逃脱 hard_cap=0.30。
            #   inflate 的目的是防止 soft throttle 误杀有价值的 global chunk，
            #   但 hard_cap 应使用严格的 per-project window 确保垄断不逃逸。
            _local_bw_window = _effective_bw_window
            # ── iter566: memcg_stat — Cross-Project Recall Accounting ──
            # OS 类比：cgroup v2 memory.stat hierarchical aggregation — 共享页面的
            # 跨 cgroup 访问计数聚合，反映真实系统级资源压力。
            # global chunk 被多项目共享召回，per-project 计数无法反映全局垄断程度。
            # 解决：取 max(per_project, cross_project) 确保 anti-monopoly 生效。
            if _sysctl("memcg_stat.enabled") is not False:
                _memcg_window = _sysctl("memcg_stat.window") or 60
                _memcg_counts = chunk_recall_counts_memcg(_rc_conn, project, window=_memcg_window)
                if _memcg_counts:
                    _memcg_inflated = False
                    for _mcid, _mcnt in _memcg_counts.items():
                        _existing = _recall_counts.get(_mcid, 0)
                        if _mcnt > _existing:
                            _recall_counts[_mcid] = _mcnt
                            _memcg_inflated = True
                    # iter606: bw_window parity — memcg counts 来自 window=60 的跨项目
                    # trace，但 _effective_bw_window 只反映本项目的 trace 数量。
                    # 当 memcg 合入了更大的 count 时，必须同步放大 bw_window，
                    # 否则 rc=9/ebw=19=0.47 > 0.30 会误杀有价值的 global chunk。
                    if _memcg_inflated:
                        try:
                            _xp_atc = _rc_conn.execute(
                                "SELECT COUNT(*) FROM recall_traces WHERE project!=? AND injected=1",
                                (project,)
                            ).fetchone()[0]
                            _effective_bw_window = max(_effective_bw_window,
                                                       min(60, max(1, _xp_atc)))
                        except Exception:
                            pass
            # ── iter647: WAL-immune injection timeline — 文件级跨 session 注入时间序列 ──
            # 根因（数据驱动，2026-05-03）：iter614/618 的 24h/7d suppress 依赖
            #   recall_traces 的 SELECT，但 WAL 模式下刚写入的 trace 对读连接不可见。
            #   实测：b50e0b54 在 5/2 连续 8 次 score=0.99 注入（跨 8 个 session），
            #   24h>=2 suppress 完全失效，因为 _recent_24h_counts 始终为 0。
            # 修复：用独立 JSON 文件记录 {chunk_id: [ts1, ts2, ...]}，
            #   写入在 write-back phase（与 session_injection_counts 同步），
            #   读取在此处直接从文件计算 24h/7d 计数，完全绕过 SQLite WAL。
            _INJECTION_TIMELINE_FILE = os.path.join(MEMORY_OS_DIR, ".injection_timeline.json")
            _recent_6h_counts = {}   # iter813: short_burst_suppress
            _recent_24h_counts = {}
            _recent_7d_counts = {}
            _injection_timeline = {}  # {chunk_id: [iso_ts, ...]}
            try:
                if os.path.exists(_INJECTION_TIMELINE_FILE):
                    with open(_INJECTION_TIMELINE_FILE, encoding="utf-8") as _itf:
                        _injection_timeline = json.loads(_itf.read())
                from datetime import datetime as _dt647, timezone as _tz647, timedelta as _td647
                _now647 = _dt647.now(_tz647.utc)
                _cutoff_6h = (_now647 - _td647(hours=6)).isoformat()  # iter813
                _cutoff_24h = (_now647 - _td647(hours=24)).isoformat()
                _cutoff_7d = (_now647 - _td647(days=7)).isoformat()
                _pruned = {}  # GC: 丢弃 >7d 的条目
                for _cid647, _ts_list in _injection_timeline.items():
                    _kept = [t for t in _ts_list if t > _cutoff_7d]
                    if _kept:
                        _pruned[_cid647] = _kept
                        _recent_7d_counts[_cid647] = len(_kept)
                        _cnt_24h = sum(1 for t in _kept if t > _cutoff_24h)
                        if _cnt_24h > 0:
                            _recent_24h_counts[_cid647] = _cnt_24h
                        # iter813: 6h burst count
                        _cnt_6h = sum(1 for t in _kept if t > _cutoff_6h)
                        if _cnt_6h > 0:
                            _recent_6h_counts[_cid647] = _cnt_6h
                _injection_timeline = _pruned
                # ── iter659: timeline_ghost_gc — 清理已删除 chunk 的 timeline 条目 ──
                # 根因：chunk 被删除/swap 后 timeline 残留幽灵条目（实测 27 条），
                #   浪费 JSON 读写 I/O 且污染 7d 计数上限估算。
                if _pruned:
                    _alive_ids = set()
                    try:
                        _id_list = list(_pruned.keys())
                        for _batch_start in range(0, len(_id_list), 50):
                            _batch = _id_list[_batch_start:_batch_start+50]
                            _ph = ",".join("?" for _ in _batch)
                            _alive_ids.update(
                                r[0] for r in _rc_conn.execute(
                                    f"SELECT id FROM memory_chunks WHERE id IN ({_ph})", _batch
                                ).fetchall()
                            )
                        _ghost_count = len(_pruned) - len(_alive_ids)
                        if _ghost_count > 0:
                            _injection_timeline = {k: v for k, v in _pruned.items() if k in _alive_ids}
                            _recent_24h_counts = {k: v for k, v in _recent_24h_counts.items() if k in _alive_ids}
                            _recent_7d_counts = {k: v for k, v in _recent_7d_counts.items() if k in _alive_ids}
                    except Exception:
                        pass
            except Exception:
                pass
            _rc_conn.close()
        except Exception:
            pass  # 统计失败不影响主流程
        # ── iter653: timeline_fallback — 始终从 recall_traces merge max 补充 24h/7d 计数 ──
        # 根因：iter652 的 guard "if not both empty" 在 timeline 只有 1 条时不触发 fallback，
        #   但该 1 条不是垄断 chunk → 垄断 chunk 的 24h/7d=0 → suppress 完全失效。
        #   实测：feishu CLI 24h 注入 9 次但 suppress 未触发。
        # 修复：无条件 merge（取 max），确保 suppress 数据源可靠。
        if True:
            try:
                import sqlite3 as _fb_sql
                from datetime import datetime as _dt652, timezone as _tz652, timedelta as _td652
                _fb_conn = _fb_sql.connect(str(STORE_DB))
                _fb_now = _dt652.now(_tz652.utc)
                _cut_7d = (_fb_now - _td652(days=7)).isoformat()
                _cut_24h = (_fb_now - _td652(hours=24)).isoformat()
                _cut_6h = (_fb_now - _td652(hours=6)).isoformat()  # iter813
                # iter653: 从 recall_traces 独立统计，再 merge max
                _rt_7d = {}
                _rt_24h = {}
                _rt_6h = {}  # iter813
                # iter835: suppress_final_gate_project_scope — per-project 计数
                # iter957: session_dedup_suppress — 7d count 按 unique session 去重
                _rt_7d_sessions = {}  # {chunk_id: set(session_ids)}
                for (_tk_json, _tk_ts, _tk_sid) in _fb_conn.execute(
                        "SELECT top_k_json, timestamp, session_id FROM recall_traces WHERE injected=1 AND project=? AND timestamp>?",
                        (project, _cut_7d,)).fetchall():
                    if not _tk_json: continue
                    try:
                        _ids = json.loads(_tk_json)
                    except Exception: continue
                    _is_24h = _tk_ts > _cut_24h if _tk_ts else False
                    _is_6h = _tk_ts > _cut_6h if _tk_ts else False  # iter813
                    for _it in (_ids if isinstance(_ids, list) else []):
                        _c = _it.get("id","") if isinstance(_it, dict) else (_it if isinstance(_it, str) else "")
                        if _c:
                            _rt_7d_sessions.setdefault(_c, set()).add(_tk_sid or "")
                            if _is_24h:
                                _rt_24h[_c] = _rt_24h.get(_c, 0) + 1
                            if _is_6h:
                                _rt_6h[_c] = _rt_6h.get(_c, 0) + 1  # iter813
                _rt_7d = {k: len(v) for k, v in _rt_7d_sessions.items()}
                # iter1033: 7d_merge_max — 取 max 而非覆盖，保留 timeline 实时性
                # 根因（数据驱动，2026-05-07）：iter957 覆盖语义将 timeline 实时 7d=5
                #   降级为 DB session-dedup 7d=4（WAL 延迟 + dedup 误差），
                #   致 local ac=7 chunk 逃逸 suppress（阈值=5）。
                #   import-90139(PE分析) 7d timeline=7 但 DB dedup=4→逃逸→累计注入 6 次。
                # 修复：与 24h/6h merge 统一为 max 语义，timeline 实时性不被 DB 滞后降级。
                for _mc, _mv in _rt_7d.items():
                    _recent_7d_counts[_mc] = max(_recent_7d_counts.get(_mc, 0), _mv)
                for _mc, _mv in _rt_24h.items():
                    _recent_24h_counts[_mc] = max(_recent_24h_counts.get(_mc, 0), _mv)
                # iter813: 6h merge
                for _mc, _mv in _rt_6h.items():
                    _recent_6h_counts[_mc] = max(_recent_6h_counts.get(_mc, 0), _mv)
                # iter1024: global_cross_project_suppress — global chunk 跨项目聚合 suppress 计数
                # 根因（数据驱动，2026-05-07）：global chunk (feishu CLI ac=4, memory验证 ac=6)
                #   分散在 2-3 项目各注入 1-2 次，per-project 计数均不触发 suppress（阈值=3），
                #   但用户实际 7d 内看到 4 次。per-project 隔离是 suppress 对 global chunk 失效的根因。
                # 修复：对 global chunk 做跨项目 24h/7d/6h 聚合，取所有项目总和。
                try:
                    _global_ids_set = set(r[0] for r in _fb_conn.execute(
                        "SELECT id FROM memory_chunks WHERE project='global' AND chunk_state='ACTIVE'"
                    ).fetchall())
                    if _global_ids_set:
                        for (_g_tk, _g_ts) in _fb_conn.execute(
                                "SELECT top_k_json, timestamp FROM recall_traces "
                                "WHERE injected=1 AND project!=? AND timestamp>?",
                                (project, _cut_7d,)).fetchall():
                            if not _g_tk: continue
                            try:
                                _g_ids = json.loads(_g_tk)
                            except Exception: continue
                            _g_is_24h = _g_ts > _cut_24h if _g_ts else False
                            _g_is_6h = _g_ts > _cut_6h if _g_ts else False
                            for _gi in (_g_ids if isinstance(_g_ids, list) else []):
                                _gc = _gi.get("id","") if isinstance(_gi, dict) else ""
                                if _gc and _gc in _global_ids_set:
                                    _recent_7d_counts[_gc] = _recent_7d_counts.get(_gc, 0) + 1
                                    if _g_is_24h:
                                        _recent_24h_counts[_gc] = _recent_24h_counts.get(_gc, 0) + 1
                                    if _g_is_6h:
                                        _recent_6h_counts[_gc] = _recent_6h_counts.get(_gc, 0) + 1
                except Exception:
                    pass
                _fb_conn.close()
            except Exception:
                pass
        # 迭代312：Session-scoped recall counts
        _session_recall_counts = {}
        try:
            from store_criu import chunk_session_recall_counts
            import sqlite3 as _sc_sql
            _sc_conn = _sc_sql.connect(str(STORE_DB))
            _session_recall_counts = chunk_session_recall_counts(_sc_conn, project, session_id, window=100)
            _sc_conn.close()
        except Exception:
            pass  # session 计数失败不影响主流程
        # 迭代333：Session Injection Counts — 本 session 每个 chunk 被注入的次数
        # OS 类比：per-page dirty_writeback_count — 统计同一页在当前写回周期的重复写入次数
        # 持久化到 .last_session_injections.json（跨请求维护 session 内计数）
        _SESSION_INJ_FILE = os.path.join(MEMORY_OS_DIR, ".last_session_injections.json")
        _session_injection_counts = {}
        # ── 迭代361：Session FULL-Injected Set — 本 session 已 FULL 注入过的 chunk ID 集合 ──
        # OS 类比：Linux page cache dirty bit — 已写入页面标记，重复写入时走快路径（LITE format）
        # 原理：同 session 第一次 FULL 注入 chunk（summary + raw_snippet）后，
        #   chunk 内容已在 LLM 的工作记忆中，后续注入时 raw_snippet 的边际价值为 0。
        #   降级为 LITE 格式（仅 summary）节省 ~30-80 tokens/chunk，
        #   长 session 中可节省 150-400 tokens（假设 3-5 个 chunk 被重复 FULL 注入）。
        # 实现：与 _session_injection_counts 共存于同一 JSON 文件（zero extra I/O）。
        _session_full_injected: set = set()
        try:
            if os.path.exists(_SESSION_INJ_FILE):
                with open(_SESSION_INJ_FILE, encoding="utf-8") as _sif:
                    _sij_data = json.loads(_sif.read())
                    # 只保留同一 session 的注入记录（session 切换时重置）
                    if _sij_data.get("session_id") == session_id:
                        _session_injection_counts = _sij_data.get("counts", {})
                        # 迭代361：恢复 full_injected 集合
                        _session_full_injected = set(_sij_data.get("full_injected", []))
        except Exception:
            pass

        # ── iter368: Attention Focus Stack — 会话注意焦点关键词加载 ─────────
        # OS 类比：CPU register file — 读取"热"寄存器，零额外 I/O
        # 人的记忆类比：focus of attention — 焦点中的概念激活阈值更低
        _focus_keywords: list = []
        try:
            from store_focus import ensure_focus_schema, get_focus
            ensure_focus_schema(conn)
            _focus_keywords = get_focus(conn, session_id)
        except Exception:
            pass  # 焦点加载失败不影响主流程

        # ── iter89: Tool Pattern Keywords — 工具模式关键词集 ──
        # 迭代101：从全局聚合改为意图感知过滤。
        # OS 类比：branch predictor history table — 只保留与当前 PC 相关的跳转历史，
        # 而非全局所有分支的混合预测（避免 aliasing 污染）。
        #
        # 旧版：取 freq>=5 的 top-10 模式全部关键词合集 → 任何 session 都注入相同词集
        # 新版：提取 prompt 的 n-gram 词集，与 context_keywords 有交集的模式才纳入
        #       → keyword_boost 精准命中当前任务相关 chunk
        _pattern_keywords: set = set()
        _matched_patterns: list = []  # 记录命中的模式（用于 Hint 注入）
        try:
            if priority in ("FULL", "LITE"):
                import json as _pj
                import re as _re
                # 提取 prompt 词集（英文词 + 中文双字）
                _prompt_words: set = set()
                for m in _re.finditer(r'[a-zA-Z][a-zA-Z0-9_]{2,}', query):
                    _prompt_words.add(m.group().lower())
                _cn = _re.sub(r'[^\u4e00-\u9fff]', '', query)
                for i in range(len(_cn) - 1):
                    _prompt_words.add(_cn[i:i+2])

                _tp_rows = conn.execute(
                    """SELECT tool_sequence, context_keywords, SUM(frequency) as frequency
                       FROM tool_patterns
                       WHERE frequency >= 1
                       GROUP BY tool_sequence
                       HAVING SUM(frequency) >= 3
                       ORDER BY frequency DESC LIMIT 30"""
                ).fetchall()
                for _tp_seq_json, _tp_kws_json, _tp_freq in _tp_rows:
                    if not _tp_kws_json:
                        continue
                    kws = _pj.loads(_tp_kws_json) if isinstance(_tp_kws_json, str) else _tp_kws_json
                    kw_set = {k.lower() for k in (kws or []) if isinstance(k, str) and len(k) >= 3}
                    # 意图感知：prompt 词集与 context_keywords 有交集才纳入
                    overlap = _prompt_words & kw_set
                    if overlap:
                        for kw in kw_set:
                            _pattern_keywords.add(kw)
                        seq = _pj.loads(_tp_seq_json) if isinstance(_tp_seq_json, str) else _tp_seq_json
                        _matched_patterns.append({
                            "seq": seq, "freq": _tp_freq,
                            "overlap": list(overlap)[:3]
                        })
        except Exception:
            pass  # tool pattern 加载失败不影响主流程

        # ── 迭代82：Memory Zones — 计算可检索 chunk_types（排除 ZONE_RESERVED 类型）──
        # OS 类比：Linux ZONE_DMA/ZONE_NORMAL/ZONE_HIGHMEM — 不同区域的内存用途隔离
        # 迭代98：加入 design_constraint — 系统级约束知识，强制优先级高
        # iter105：加入 quantitative_evidence / causal_chain 两个新精化类型
        # iter117：加入 procedure — wiki 导入的可复用操作协议，之前系统性不可见（_ALL_RETRIEVE_TYPES 遗漏）
        #   根因：import_knowledge.py 写入 chunk_type='procedure'，但检索侧从未过滤此类型
        #   后果：26/39 procedure chunks（67%）零访问率，等同于知识黑洞
        #   OS 类比：将 /lib/modules/procedure.ko 添加到 initrd，否则模块永远不会被 insmod
        _ALL_RETRIEVE_TYPES = ("decision", "reasoning_chain", "conversation_summary",
                               "excluded_path", "task_state", "prompt_context", "design_constraint",
                               "quantitative_evidence", "causal_chain", "procedure")
        _exclude_str = _sysctl("retriever.exclude_types")
        _exclude_set = set(t.strip() for t in _exclude_str.split(",") if t.strip()) if _exclude_str else set()
        _retrieve_types = tuple(t for t in _ALL_RETRIEVE_TYPES if t not in _exclude_set) or None

        # ── B14: Adaptive Oversample Factor — CPUFreq governor 类比 ──────────
        # OS 类比：Linux cpufreq ondemand governor — 根据 CPU 利用率（负载压力）
        #   动态调整 P-state（频率），高负载时提频，低负载时降频节能。
        # 这里：当最近检索延迟 p95 > 目标（50ms）时，降低超采样倍数（3x→2x），
        #   减少候选池大小，从而降低 _score_chunk 的调用次数。
        # 读取 sysctl 可控倍数（默认 3，延迟压力下 retriever_governor 可写为 2）
        _oversample_factor = _sysctl("retriever.oversample_factor") or 3
        _oversample_factor = max(2, min(4, int(_oversample_factor)))  # 钳制 [2, 4]
        # ── iter526: vm_flags — 读取 Loader Page Table，排除已注入 chunk IDs ──
        # OS 类比：find_vma() 检查目标地址是否已被映射，防止 MAP_FIXED 重叠
        _loader_exclude_ids: set = set()
        try:
            _pt_path = os.path.join(MEMORY_OS_DIR, ".loader_page_table.json")
            if os.path.exists(_pt_path):
                with open(_pt_path, encoding="utf-8") as _ptf:
                    _pt_data = json.loads(_ptf.read())
                # 只排除同 project 的 loader 注入（跨 project 不影响）
                if _pt_data.get("project") == project:
                    _loader_exclude_ids = set(_pt_data.get("injected_ids", []))
        except Exception:
            pass  # page table 读取失败不影响检索

        # ── FTS5 索引召回（迭代23 ext3 htree）──
        try:
            # iter685: 全库搜索（与 daemon iter657 对齐，消除 project 孤岛化）
            fts_results = fts_search(conn, query, None, top_k=effective_top_k * _oversample_factor,
                                     chunk_types=_retrieve_types)
            # iter526: 排除 loader 已注入的 chunk IDs（避免双重映射）
            if _loader_exclude_ids and fts_results:
                _pre_filter = len(fts_results)
                fts_results = [r for r in fts_results if r.get("id") not in _loader_exclude_ids]
                _vm_flags_filtered = _pre_filter - len(fts_results)
                if _vm_flags_filtered > 0:
                    _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter526 vm_flags: excluded {_vm_flags_filtered} loader-injected chunks",
                              session_id=session_id, project=project)
            use_fts = bool(fts_results)
        except Exception as _fts_err:
            fts_results = []
            use_fts = False
            # 迭代29 dmesg：FTS5 失败降级（迭代84：延迟写入）
            _deferred.log(DMESG_WARN, "retriever",
                      f"FTS5 fallback: {type(_fts_err).__name__}",
                      session_id=session_id, project=project)

        # ── 迭代126：FTS5 + BM25 混合召回（OS 类比：L1/L2 多级缓存）──────────────
        # OS 类比：CPU 多级缓存一致性协议（MESI）
        #   L1 cache（FTS5）：命中率高、精确词汇匹配、O(log N)
        #   L2 cache（BM25）：覆盖面广、捕获 FTS5 漏掉的长尾 chunk
        #
        # 旧设计问题：
        #   FTS5 有结果 → 仅用 FTS5（可能漏掉 BM25 能找到但 FTS5 tokenize 无法匹配的 chunk）
        #   FTS5 无结果 → 全表 BM25（失去 FTS5 精确排序优势）
        #   两者完全互斥，无法互补。
        #
        # 新设计：
        #   1. FTS5 先跑（保持精确匹配优势）
        #   2. 如果 FTS5 返回 < effective_top_k，从全表 BM25 补充差额（长尾救援）
        #   3. BM25 补充时跳过已在 FTS5 结果中的 chunk（去重）
        #   4. BM25 补充 chunk 的 relevance 降权（× hybrid_bm25_discount），避免劣质长尾挤掉 FTS5 精确结果
        #   5. 合并后统一用 _unified_retrieval_score 排序
        #
        # 触发条件：use_fts=True 且 FTS5 结果 < effective_top_k
        # 不触发条件：use_fts=False（FTS5 异常）→ 纯 BM25 fallback（原有逻辑）

        _hybrid_bm25_count = 0  # 记录 BM25 补充数（供 dmesg 日志）
        _bm25_global_discount = 1.0  # iter131: BM25 fallback 时全局项目折扣，默认 1.0（不折扣）

        def _compute_context_match(enc_ctx: dict, cur_ctx: dict) -> float:
            """
            iter372: NUMA-aware context match score — 0.0 ~ 0.20

            编码特异性原理（Tulving 1975 Encoding Specificity Principle）：
              编码时的上下文（cwd + 关注关键词）与检索时的上下文越接近，
              记忆提取的准确率越高。OS 类比：NUMA 本地节点优先分配，
              远端节点访问延迟更高（类比：上下文不匹配的 chunk 相关性折扣）。

            cwd 匹配：+0.10（最强信号，表明 chunk 在同一工作目录/项目下编码）
            关键词重叠：+0.05 × Jaccard（细粒度上下文相似度）
            iter385 实体重叠：+0.05 × entity_Jaccard（Godden & Baddeley 1975 情境再现）
              encoding_context.entities 与当前 query 实体词的交集越大 → boost 越高
              认知科学：情境再现原则 — 检索时复原编码情境可最大化回忆成功率。
              OS 类比：CPU LLC prefetch hint — 提示 prefetcher 预取与当前实体相关的 cache line。
            总计上限 0.20（避免 context boost 主导 FTS5 relevance）
            """
            if not enc_ctx or not cur_ctx:
                return 0.0
            boost = 0.0
            enc_cwd = (enc_ctx.get("cwd") or "").rstrip("/")
            cur_cwd = (cur_ctx.get("cwd") or "").rstrip("/")
            if enc_cwd and cur_cwd:
                if enc_cwd == cur_cwd or cur_cwd.startswith(enc_cwd + "/"):
                    boost += 0.10
            enc_kw = set(enc_ctx.get("keywords") or [])
            cur_kw = set(cur_ctx.get("keywords") or _focus_keywords)
            if enc_kw and cur_kw:
                intersection = len(enc_kw & cur_kw)
                union = len(enc_kw | cur_kw)
                if union > 0:
                    boost += (intersection / union) * 0.05
            # ── iter385: Entity-level Encoding Context Boost ──────────────────
            # Godden & Baddeley (1975) Context-Dependent Memory:
            #   当检索上下文（query 中的实体词）与编码上下文（enc_ctx.entities）重叠时，
            #   该 chunk 更可能是当前情境下的正确答案。
            #   实现：提取 query 中的英文标识符和 CJK bigram，与 enc_ctx.entities 计算 Jaccard
            enc_entities = set(e.lower() for e in (enc_ctx.get("entities") or []) if e)
            cur_entities = set(cur_ctx.get("entities") or [])
            if not cur_entities:
                # fallback: 从 query 中提取实体词
                import re as _re
                _q = cur_ctx.get("query", "")
                cur_entities = set(m.group().lower()
                                   for m in _re.finditer(r'[a-zA-Z][a-zA-Z0-9_\.]{2,}', _q))
                _cjk = _re.sub(r'[^\u4e00-\u9fff]', '', _q)
                for _i in range(len(_cjk) - 1):
                    cur_entities.add(_cjk[_i:_i + 2])
            if enc_entities and cur_entities:
                _ei = len(enc_entities & cur_entities)
                _eu = len(enc_entities | cur_entities)
                if _eu > 0:
                    boost += (_ei / _eu) * 0.05
            # ── iter394: Session Type + Task Verbs Boost ──────────────────────
            # Tulving (1983) Encoding Specificity + Godden & Baddeley (1975):
            #   任务情境类型（debug/design/refactor/qa）一致 → +context_type_boost
            #   task_verbs 词集交集越大 → +task_verbs_boost × Jaccard
            # OS 类比：NUMA-aware task scheduler — 同 NUMA 域的内存访问优先调度。
            if _sysctl("retriever.context_type_boost_enabled"):
                enc_stype = enc_ctx.get("session_type", "unknown")
                cur_stype = cur_ctx.get("session_type", "unknown")
                if (enc_stype and cur_stype and enc_stype != "unknown"
                        and cur_stype != "unknown" and enc_stype == cur_stype):
                    boost += _sysctl("retriever.context_type_boost")
                enc_verbs = set(enc_ctx.get("task_verbs") or [])
                cur_verbs = set(cur_ctx.get("task_verbs") or [])
                if enc_verbs and cur_verbs:
                    _vi = len(enc_verbs & cur_verbs)
                    _vu = len(enc_verbs | cur_verbs)
                    if _vu > 0:
                        boost += (_vi / _vu) * _sysctl("retriever.task_verbs_boost")
            return min(boost, 0.25)  # iter394: 上限从 0.20 提升到 0.25（新增两个 boost 维度）

        # ── iter424: Mood-Congruent Memory — 预计算 query 情绪效价（每次检索只算一次）──
        # OS 类比：Linux NUMA topology detection at boot — 一次性 probe，之后所有调度决策共用
        _mcm_query_valence: float = 0.0
        try:
            if _sysctl("retriever.mcm_enabled") is not False:
                from store_vfs import compute_emotional_valence as _cev
                _mcm_query_valence = _cev(query)
        except Exception:
            pass

        # iter642: per-request live ac cache — 绕过 immutable 连接的 WAL 盲区
        # 根因（数据驱动，2026-05-03）：_score_chunk 内 iter622 的 ac>=30 suppress
        #   用 chunk.get("access_count")，来自 immutable=1 连接，看不到 WAL 中的
        #   最新 ac。b50e0b54 在 5/2 连续 9 次逃逸（score=0.99）就是这个原因。
        #   iter641 只修了 constraint 通道；主路径 _score_chunk 仍用 stale ac。
        # 修复：lazy dict，首次查询时用标准连接批量获取所有 ac>=15 的 chunk live ac。
        _live_ac_cache = {}
        _live_ac_loaded = [False]

        def _get_live_ac(chunk_id):
            if not _live_ac_loaded[0]:
                _live_ac_loaded[0] = True
                try:
                    import sqlite3 as _lac2_sql
                    _lac2_conn = _lac2_sql.connect(str(STORE_DB))
                    for row in _lac2_conn.execute(
                        "SELECT id, COALESCE(access_count,0) FROM memory_chunks "
                        "WHERE COALESCE(access_count,0) >= 10"  # iter980: 15→10 支持渐进衰减
                    ).fetchall():
                        _live_ac_cache[row[0]] = row[1]
                    _lac2_conn.close()
                except Exception:
                    pass
            return _live_ac_cache.get(chunk_id, None)

        # iter1004: type_concentration_penalty — 同 chunk_type 群体垄断注入位衰减
        # 根因（数据驱动，2026-05-06）：PE 相关 6 条 chunk 各 7d=4-6 不触发 suppress，
        #   但群体占 kernel 项目 7d 注入的 ~48%。单 chunk suppress 无法解决群体垄断。
        # 修复：预计算 per-type 7d 注入占比，>40% 且该 type 有 >=3 个不同 chunk 时，
        #   对该 type chunk 的 diversity_penalty factor 额外 x1.5。
        _type_7d_conc = {}  # {chunk_type: (total_7d, n_chunks)}
        try:
            if _recent_7d_counts:
                import sqlite3 as _tc_sql
                _tc_conn = _tc_sql.connect(str(STORE_DB))
                _tc_ids = list(_recent_7d_counts.keys())
                _tc_type_map = {}  # chunk_id -> chunk_type
                for _tc_i in range(0, len(_tc_ids), 50):
                    _tc_batch = _tc_ids[_tc_i:_tc_i+50]
                    _tc_ph = ",".join("?" for _ in _tc_batch)
                    for (_tid, _ttype) in _tc_conn.execute(
                            f"SELECT id, chunk_type FROM memory_chunks WHERE id IN ({_tc_ph})", _tc_batch).fetchall():
                        _tc_type_map[_tid] = _ttype or ""
                _tc_conn.close()
                from collections import defaultdict as _tc_dd
                _tc_agg = _tc_dd(lambda: [0, set()])  # type -> [total_7d, {chunk_ids}]
                for _tcid, _tccnt in _recent_7d_counts.items():
                    _tct = _tc_type_map.get(_tcid, "")
                    if _tct:
                        _tc_agg[_tct][0] += _tccnt
                        _tc_agg[_tct][1].add(_tcid)
                _tc_total = sum(_recent_7d_counts.values()) or 1
                for _tct, (_tc_sum, _tc_set) in _tc_agg.items():
                    _type_7d_conc[_tct] = (_tc_sum / _tc_total, len(_tc_set))
        except Exception:
            pass  # 预计算失败不阻塞

        # iter1029: project_concentration_penalty — 同项目群体垄断注入位衰减
        # 根因（数据驱动，2026-05-07）：git:a0ab16e8cafc 7d 占 31/62=50% 注入位，
        #   但单 chunk max=3（在 suppress 阈值内），type 分散（decision/procedure/evidence）
        #   导致 type_concentration_penalty 不触发。用户体感"全是 kernel 知识"。
        # 修复：预计算 per-project 7d 注入占比，>45% 且 >=4 不同 chunk 时，
        #   对该项目 chunk score 额外 penalty = 0.75^(个体7d-1)。
        _proj_7d_conc = {}  # {project: (ratio, n_chunks)}
        try:
            if _recent_7d_counts:
                import sqlite3 as _pc_sql
                _pc_conn = _pc_sql.connect(str(STORE_DB))
                _pc_ids = list(_recent_7d_counts.keys())
                _pc_proj_map = {}  # chunk_id -> project
                for _pc_i in range(0, len(_pc_ids), 50):
                    _pc_batch = _pc_ids[_pc_i:_pc_i+50]
                    _pc_ph = ",".join("?" for _ in _pc_batch)
                    for (_pid, _pproj) in _pc_conn.execute(
                            f"SELECT id, project FROM memory_chunks WHERE id IN ({_pc_ph})", _pc_batch).fetchall():
                        _pc_proj_map[_pid] = _pproj or ""
                _pc_conn.close()
                from collections import defaultdict as _pc_dd
                _pc_agg = _pc_dd(lambda: [0, set()])  # project -> [total_7d, {chunk_ids}]
                for _pcid, _pccnt in _recent_7d_counts.items():
                    _pcp = _pc_proj_map.get(_pcid, "")
                    if _pcp:
                        _pc_agg[_pcp][0] += _pccnt
                        _pc_agg[_pcp][1].add(_pcid)
                _pc_total = sum(_recent_7d_counts.values()) or 1
                for _pcp, (_pc_sum, _pc_set) in _pc_agg.items():
                    _proj_7d_conc[_pcp] = (_pc_sum / _pc_total, len(_pc_set))
        except Exception:
            pass

        def _score_chunk(chunk, relevance):
            _hard_suppressed = False  # iter616: final_hard_gate flag
            # ── B13: Lazy Scoring Early Exit — 极低 relevance 跳过全量计算 ────
            # OS 类比：Linux speculative execution abort — 分支预测失败时丢弃管线，
            #   不把无效结果写入 register file；relevance≈0 的 chunk 即使算完也会被排出 top-K。
            # 实现：relevance < 0.005（FTS5 等效最小正分数）→ 直接用 importance 近似 score
            #   避免执行后面 15 个因子的计算（尤其 source_monitor、retroactive_interference
            #   等需要 DB 查询或 import 的步骤）。
            if relevance < 0.005:
                # iter601: early exit 也必须检查 bandwidth hard gate，否则垄断 chunk
                # 绕过后续 throttle 以 importance*0.1 持续进入 top_k（根因：feishu CLI
                # rc=26/30=87%，score=0.000092 仍入选因为候选池不足）
                _rc_ee = _recall_counts.get(chunk.get("id", ""), 0)
                _ee_hard_cap = _sysctl("retriever.constraint_inject_hard_cap") or 0.30
                # iter756: small_db_bw_tighten; iter774: tiny_db_bw_relax
                if _local_bw_window <= 30 and _ee_hard_cap > 0.12:
                    # iter801: micro_db_suppress_bypass (early exit path)
                    # iter861: small_db_bw_tighten — <50 收紧 0.25→0.15
                    _ee_hard_cap = 1.0 if _db_chunk_count <= 5 else (0.15 if _db_chunk_count < 50 else 0.12)
                if _rc_ee > 0 and _rc_ee / _local_bw_window > _ee_hard_cap:
                    return 0.0
                # iter617: early exit 也必须检查 24h_burst_suppression
                # 根因：高 importance chunk (0.9) 走 early exit 返回 0.09，跳过 2084 行的
                #   24h suppress → feishu CLI 7天12次注入全部逃逸（每次不同 session）。
                # iter619: 24h 阈值 3→2，同一天看过 2 次已足够
                # iter796: ee_suppress_sync_tinydb — early exit 阈值同步 tiny_db 放宽
                # 根因（数据驱动，2026-05-04）：评分路径 tiny_db 24h 阈值=4~5，但
                #   early exit 固定 >=2 → 34 chunk 小库中 24h=2 即全灭（56% 空召回）。
                #   early exit 是 relevance<0.005 路径，score 必然低，用低分阈值对齐。
                # iter801: micro_db (<=5) 跳过 24h/7d/saturation suppress
                if _db_chunk_count > 5:
                    # iter813: 6h burst suppress (early exit path)
                    # iter865: 6h_tighten_tiny — 统一阈值 2（数据驱动：6h=3 逃逸导致垄断）
                    if _recent_6h_counts.get(chunk.get("id", ""), 0) >= 2:
                        return 0.0
                    _r24_ee = _recent_24h_counts.get(chunk.get("id", ""), 0)
                    _ee_24h_thresh = 4 if _db_chunk_count < 50 else 3 if _db_chunk_count < 100 else 2  # iter818: 30→40
                    if _r24_ee >= _ee_24h_thresh:
                        return 0.0
                    # iter618: early exit 也检查 7d_rolling_suppress
                    # iter619: 8→5; iter664: 5→3，与评分阶段阈值统一
                    # iter796: 同步 tiny_db 放宽
                    _r7d_ee = _recent_7d_counts.get(chunk.get("id", ""), 0)
                    _ee_7d_thresh = 8 if _db_chunk_count < 50 else 5 if _db_chunk_count < 100 else 3  # iter818: 30→40
                    if _r7d_ee >= _ee_7d_thresh:
                        return 0.0
                    # iter621→622: saturation_absolute_suppress — 累积注入过饱和永久 suppress
                    # iter642: 用 live ac 替代 immutable 连接的 stale ac
                    _acc_ee = _get_live_ac(chunk.get("id", ""))
                    if _acc_ee is None:
                        _acc_ee = chunk.get("access_count", 0) or 0
                    if _acc_ee >= 12:  # iter981: 15→12 对齐主路径
                        return 0.0
                return float(chunk.get("importance", 0.5)) * 0.1  # 极低相关性：快速降权
            # 迭代322: Query-Conditioned Importance — 动态 α
            # OS 类比：CPUFreq P-state — 高负载（高 relevance）降低 importance 依赖；
            #   低负载（弱命中）升高 importance 依赖（靠先验筛选）
            # α = 0.55 - 0.25 × relevance：relevance=1.0 → α=0.30，relevance=0.0 → α=0.55
            # 效果：FTS5 强命中时 recency 权重上升（刚被用到的 chunk 更优先）
            #       BM25 弱命中时 importance 权重上升（靠领域知识先验筛选噪音）
            _dyn_alpha = _sysctl("retriever.qci_base_alpha") - _sysctl("retriever.qci_relevance_slope") * relevance
            score = _unified_retrieval_score(
                relevance=relevance,
                importance=float(chunk["importance"]),
                last_accessed=chunk["last_accessed"],
                access_count=chunk.get("access_count", 0) or 0,
                created_at=chunk.get("created_at", ""),
                chunk_id=chunk.get("id", ""),
                query_seed=query,
                recall_count=_recall_counts.get(chunk.get("id", ""), 0),
                session_recall_count=_session_recall_counts.get(chunk.get("id", ""), 0),
                lru_gen=chunk.get("lru_gen"),
                chunk_project=chunk.get("project", ""),
                current_project=project,
                query_alpha=_dyn_alpha,
                chunk_type=chunk.get("chunk_type", ""),  # iter375: type-differential decay
            )
            # ── iter369: Soft Forgetting — Ebbinghaus 遗忘曲线阈值 ──────────
            # OS 类比：DAMON cold page candidate — 低访问频率页面降低换入优先级
            # retrievability < 0.15 的 chunk 被视为"高度遗忘"状态：
            #   知识已经"淡出"工作记忆，score 折扣 × 0.55
            #   使其只在 FTS5 强命中（高 relevance）时才能出现在 top-K 中
            # 豁免：design_constraint（约束不受遗忘影响）
            _ret = float(chunk.get("retrievability") or 1.0)
            if (_ret < 0.15
                    and chunk.get("chunk_type") != "design_constraint"):
                score *= 0.55

            # ── iter482: Confidence Threshold Filter ────────────────────────
            # 心理学：Monitoring and Control Framework (Nelson & Narens 1990) —
            #   极低置信度的知识注入上下文会污染推理（garbage-in, garbage-out）；
            #   epistemically unreliable chunks 应被 metacognitive control 屏蔽。
            # OS 类比：ECC 内存中 uncorrectable error → 页面下线（offline_pages），
            #   不再参与任何内存分配，避免静默数据损坏。
            # 规则：confidence_score < 0.15 的 chunk 分数直接归零（不注入）
            # 豁免：design_constraint（架构约束即使低置信也需要可见）
            _conf = float(chunk.get("confidence_score") or 0.7)
            if (_conf < 0.15
                    and chunk.get("chunk_type") != "design_constraint"):
                score = 0.0

            # 迭代300：info_class 路由权重调整
            # ephemeral chunk 降权 0.3，避免临时状态挤掉 world/operational 知识
            # operational chunk 在跨项目召回时降权 0.1（偏好/规则有项目局部性）
            _ic = chunk.get("info_class", "world")
            if _ic == "ephemeral":
                score *= 0.70
            elif _ic == "operational" and chunk.get("project", "") != project:
                score *= 0.90
            if _pattern_keywords:
                _summary_lower = (chunk.get("summary", "") or "").lower()
                _matched = sum(1 for kw in _pattern_keywords if kw in _summary_lower)
                if _matched > 0:
                    score += min(0.10, _matched * 0.03)
            # ── iter622: saturation_absolute_suppress — 累积过饱和 suppress ──
            # iter642: 用 live ac 替代 immutable 连接的 stale ac，防止 WAL 盲区逃逸
            # iter801: micro_db (<=5) 跳过 saturation suppress
            _acc = _get_live_ac(chunk.get("id", ""))
            if _acc is None:
                _acc = chunk.get("access_count", 0) or 0
            # iter981→989: saturation_widen — 渐进衰减区间 ac>=7→ac>=5
            # iter989 根因（数据驱动，2026-05-06）：ac=5-6 的 3 个 chunk 在 iter981 后仍逃逸，
            #   "memory 验证路径"(ac=6) 5/6 后 2x 注入，因 ac<7 完全无衰减。
            #   85-chunk 库中 ac=5-6 仅 3 个，轻度衰减(*0.8/*0.7)不会空召回。
            # 修复：起始点 7→5，suppress 阈值保持 12。
            #   AC=5→*0.8, AC=6→*0.7, AC=7→*0.6, AC=8→*0.5, ..., AC=11→*0.2, AC>=12 suppress。
            if not _micro_db and _acc >= 12:
                score = 0.0
                _hard_suppressed = True
            elif not _micro_db and _acc >= 5:
                # 渐进衰减：AC=5→*0.8, AC=6→*0.7, AC=7→*0.6, ..., AC=11→*0.2
                score *= max(0.2, 0.8 - 0.1 * (_acc - 5))
            # ── 迭代333：TMV Multiplicative Saturation Discount ──────────────
            # 信息论基础：高 access_count chunk 已被 agent "内化"，边际信息趋零。
            # OS 类比：NUMA remote node penalty — acc 越高越像"远端内存"，成本高于收益。
            # 乘法折扣（vs saturation_penalty 的加法）才能真正降权高 relevance 的饱和 chunk。
            # design_constraint/semantic 类型保护：floor=0.55 确保不被完全排除。
            if _acc >= _tmv_acc_threshold:
                _tmv_mult = _tmv_saturation_discount(_acc)
                score *= _tmv_mult
            # ── iter613: Graduated Session Density Gate ──────────────────
            # 根因：固定 >=4 → *0.70 太温和，高 relevance chunk 仍排名第一。
            #   3192147e 在同 session 内被注入 3 次，0.70 惩罚不足以压下。
            # 修复：累进惩罚 >=2 → *0.40, >=4 → *0.05（近乎 suppress）。
            #   已见过的知识边际价值急剧递减，第 2 次后信息增量 ≈0。
            # iter788: tiny_db_session_hard_suppress — 小库 >=3 直接 hard suppress
            #   根因（数据驱动，2026-05-04）：import-90139 在 tiny_db(cands=5~6)
            #   同 session 被注入 3 次，*0.40 衰减不够（唯一高分候选仍入选）。
            #   24h suppress 阈值=5 未触发。用户已看过 2 次，第 3 次零信息增量。
            _sess_inj = _session_injection_counts.get(chunk.get("id", ""), 0)
            # iter989: micro_db_session_density_bypass — <=5 chunk 库跳过 session 衰减
            # 根因（数据驱动，2026-05-06）：git:78dc99a5695f 仅 2 chunks，session 注入 1 次后
            #   *0.40 衰减将 score 从 0.25→0.10 < min_thresh(0.18)，后续 6 次连续空召回。
            #   micro_db 无替代候选，session 衰减等于永久 suppress。
            # 修复：micro_db 完全跳过 session density gate（与 24h/7d bypass 对齐）。
            if not _micro_db:
                _sdg_hard = 3 if _tiny_db else _tmv_session_density_gate
                if _sess_inj >= _sdg_hard:
                    score = 0.0
                    _hard_suppressed = True
                elif _sess_inj >= _tmv_session_density_gate:   # >=4: near-suppress (non-tiny)
                    score *= 0.05
                elif _sess_inj >= 2:                          # >=2: strong decay
                    score *= 0.40
            # ── iter600+601+612: Effective Bandwidth Throttle ─────────────
            # iter612: graduated_bandwidth_penalty — 线性渐进惩罚 [soft_start, hard_cap]
            #   根因：3192147e（ac=89）在 project 窗口内 util=0.27 恰好低于 hard_cap，
            #   持续逃逸 → 25/58=43% 注入均含该 chunk。[0.15, 0.30] 区间完全无惩罚。
            #   修复：util ∈ [hard_cap*0.5, hard_cap] 线性插值 penalty ∈ [1.0, 0.0]
            _rc = _recall_counts.get(chunk.get("id", ""), 0)
            if _rc > 0:
                _hard_cap_val = _sysctl("retriever.constraint_inject_hard_cap") or 0.30
                # iter756: small_db_bw_tighten; iter774: tiny_db_bw_relax
                if _local_bw_window <= 30 and _hard_cap_val > 0.12:
                    # iter861: small_db_bw_tighten — <50 收紧 0.25→0.15
                    # 根因（数据驱动，2026-05-05）：38-chunk 库 hard_cap=0.25 → rc>7.5 才 suppress，
                    #   但最高 rc=6（20%集中度），无任何 chunk 触发 bw suppress。
                    #   84% 注入为不相关 kernel 知识，因从未被 suppress 持续霸占注入位。
                    # 修复：<50 库 0.25→0.15，rc>4.5 即 suppress。suppress_fallback 兜底空召回。
                    _hard_cap_val = 0.15 if _db_chunk_count < 50 else 0.12
                _hard_util = _rc / _local_bw_window
                if _hard_util > _hard_cap_val:
                    score = 0.0  # iter601: hard gate
                    _hard_suppressed = True  # iter616
                else:
                    _bw_soft_start = _hard_cap_val * 0.5  # 0.15 for default 0.30
                    if _hard_util > _bw_soft_start:
                        # iter612: linear ramp from 1.0 → 0.0 over [soft_start, hard_cap]
                        _bw_penalty = 1.0 - (_hard_util - _bw_soft_start) / (_hard_cap_val - _bw_soft_start)
                        score *= _bw_penalty
            # iter875: soft_diversity_penalty — 7d 注入次数越高，score 乘法衰减越强
            # iter876: factor 0.2→0.35 — 数据驱动：7d=6 的 pe_analysis 仍垄断（0.2 时衰减仅到 45%，
            #   高 FTS 基分仍胜出）。0.35 使 7d=5→36%, 7d=6→32%，有效让位给 7d=0 chunk。
            # iter898: small_db_diversity_boost — <50 库 factor 0.35→0.55
            #   根因（数据驱动，2026-05-05）：38-chunk 库 top6 chunk 各 7d=4-6 次注入，
            #   0.35 factor 仅衰减到 42-32%，高 FTS base(0.5+) 仍垄断。
            #   0.55 使 7d=4→31%, 7d=5→27%, 7d=6→23%，有效让位给低频 chunk。
            _r7d_dp = _recent_7d_counts.get(chunk.get("id", ""), 0)
            if _r7d_dp > 0 and _db_chunk_count > 5:
                # iter969: diversity_factor_align_small_db — <100 统一 0.55
                # 根因（数据驱动，2026-05-06）：51-chunk 库（刚越过 50 边界）
                #   用 0.35 导致 7d=6 衰减仅 32%，高 FTS base 仍垄断注入。
                #   <50 用 0.55 使 7d=6→23%，但 51 和 49 不应有跳变。
                #   统一 <100 用 0.55：7d=4→31%, 7d=5→27%, 7d=6→23%。
                _dp_factor = 0.55 if _db_chunk_count < 100 else 0.35
                # iter1003: global_chunk_diversity_boost — global chunk 跨项目 factor x2
                # 根因（数据驱动，2026-05-06）：feishu CLI/git commit/memory验证 等 global
                #   constraint 在 kernel 项目中 7d=3-4 仍占注入位（衰减仅 31-23%），
                #   因 "git"/"feishu" 等泛化词 FTS base 分高(0.4+)，衰减后仍胜出。
                #   用户在 kernel session 中反复看到无关工具约束。
                # 修复：global chunk 在非 global 目标项目中 factor x2，
                #   7d=3→1/(1+3*1.1)=23%, 7d=4→18%, 7d=5→15%。有效让位给项目相关知识。
                if chunk.get("project", "") == "global" and project != "global":
                    _dp_factor *= 2.0
                score *= 1.0 / (1.0 + _r7d_dp * _dp_factor)
                # iter1004: type_concentration_penalty — 群体垄断额外衰减
                # iter1005: progressive_type_penalty — 按个体 7d 计数累进衰减
                # 根因（数据驱动，2026-05-06）：固定 *0.6 对 7d=6 和 7d=1 一视同仁，
                #   高频 chunk 打折后仍胜出（6*0.6=3.6 vs 新知识 1*1.0），无法让位。
                # 修复：阈值放宽 >0.30 + >=2 chunk（覆盖更多垄断场景），
                #   penalty = 0.7^(个体7d-1)：7d=1→1.0, 7d=2→0.7, 7d=4→0.34, 7d=6→0.17
                _ct = chunk.get("chunk_type", "")
                _tc_info = _type_7d_conc.get(_ct)
                if _tc_info and _tc_info[0] > 0.30 and _tc_info[1] >= 2:
                    _chunk_7d = _recent_7d_counts.get(chunk.get("id", ""), 0)
                    if _chunk_7d > 1:
                        score *= 0.7 ** (_chunk_7d - 1)
                # iter1029: project_concentration_penalty — 同项目群体垄断衰减
                _cp_proj = chunk.get("project", "")
                _pc_info = _proj_7d_conc.get(_cp_proj)
                if _pc_info and _pc_info[0] > 0.45 and _pc_info[1] >= 4:
                    _chunk_7d_pc = _recent_7d_counts.get(chunk.get("id", ""), 0)
                    if _chunk_7d_pc > 1:
                        score *= 0.75 ** (_chunk_7d_pc - 1)
            # ── iter614: temporal_burst_suppression — 24h 注入频率 cap ─────────
            # 同一 chunk 在 24h 内注入 >=2 次 → suppress（score=0）
            # iter619: 阈值 3→2，同日看 2 次已足够，第 3 次起 suppress
            # iter672: relevance_exempt — 高相关性 chunk 放宽阈值，防止 suppress 过杀
            #   数据驱动：60% trace 输出 0 chunks，高分有价值 chunk 被过早 suppress
            # iter676: revert_relevance_exempt — 统一阈值，不再给高分 chunk 豁免
            #   根因（数据驱动）：iter672 放宽 24h→3, 7d→5 导致 "Corrections 类规则" chunk
            #   7d=3 + score>=0.5 → 阈值5 → 完全逃逸，全历史被注入 7 次（垄断榜第一）。
            #   iter670 suppress_fallback 已解决 suppress 过杀（全灭时降级注入最佳 1 条），
            #   不再需要放宽阈值来防过杀。
            _r24_cnt = _recent_24h_counts.get(chunk.get("id", ""), 0)
            # iter764: sync_small_db_relax — 同步 daemon iter703 小库放宽
            # 根因（数据驱动，2026-05-04）：retriever.py FULL 路径 68% 空注入（39/57），
            #   daemon 已有 iter703 小库放宽（24h:5/6, 7d:8/10）但 retriever.py 仍用 2/3。
            #   44 chunk 库中 24h>=2 即 suppress → 活跃 session 全部候选被封锁。
            # iter767: tiered_small_db — 分级小库阈值，防止 50 chunk 库垄断逃逸
            # 根因（数据驱动，2026-05-04）：52 chunk 库中 import-90139 7d=5 但阈值=8 → 逃逸
            #   iter703/764 一刀切 <100 放宽到 5/6,8/10 对 50+ chunk 库过于宽松
            # 修复：<30 极小库保持宽松；30-100 中小库收紧
            _micro_db = _db_chunk_count <= 5  # iter801: micro_db suppress bypass
            _tiny_db = _db_chunk_count < 50  # iter848: tiny_db boundary 40→50
            _small_db = _db_chunk_count < 100
            # iter781: tiny_db_suppress_tighten — 收紧 tiny_db suppress 阈值
            #   数据驱动（2026-05-04）：100% injected traces 的 candidates_count<30（全部 tiny_db）
            #   iter777 的 10/8 阈值导致 24h 内同一 chunk 被 5+ session 注入仍不 suppress
            #   （import-90139 在 21 分钟内被 3 个不同 session 注入）。
            #   iter776 suppress_zero_fallback 已解决空召回兜底，可安全收紧。
            # iter801: micro_db (<=5) 跳过 24h/7d suppress — 唯一知识不可 suppress
            if not _micro_db:
                # iter813: short_burst_suppress — 6h 内 >=N 次即 suppress
                # 根因（数据驱动，2026-05-05）：import-90139 在 38 分钟内被 3 session 注入，
                #   24h 阈值=3 因 writeback 延迟和进程重启丢失 inmem log 而逃逸。
                #   6h 窗口更紧，阈值=2 可捕获短期密集注入。
                # iter818: tiny_db_6h_relax — 34 chunk 库 6h>=2 过杀致 70% 注入仅 1 条
                #   数据驱动（2026-05-05）：7d 内 34 次注入中 24 次(70%) top_k=1，
                #   根因是 6h>=2 无差别 suppress 不区分库大小。
                #   修复：tiny_db(<40) 6h 阈值 2→3，与 24h 阈值对齐。
                _r6h_cnt = _recent_6h_counts.get(chunk.get("id", ""), 0)
                # iter1042: saturated_6h_cap — ac>=7 已内化 chunk 6h 仅允许 1 次
                # 数据驱动（2026-05-07）：session 6ca148eb 中 5 个 ac>=7 chunk 各被注入 2x，
                #   间隔 56min-5h。6h 阈值=2 意味着允许 2 次（count=1 < 2 不 suppress）。
                #   ac>=7 表明 agent 已多次内化，同 6h 窗口重复注入零信息增量。
                _6h_ac = chunk.get("access_count", 0) or 0
                _6h_thresh = 1 if _6h_ac >= 7 else 2  # iter865→1042: 高 ac 收紧
                if _r6h_cnt >= _6h_thresh:
                    score = 0.0
                    _hard_suppressed = True
                # iter806: small_db_suppress_tighten — 收紧 small_db 24h 阈值
                # 根因（数据驱动，2026-05-05）：35 chunk 库 import-90139 24h 内被
                #   3 个不同 session 注入（score>=0.5），阈值=4 恰好逃逸。
                #   35 chunk 库 24h 3 次注入同一 chunk = 8.6% 集中度，用户感知垄断。
                # 修复：small_db 24h 阈值 4/3 → 3/2；tiny_db 同步（unify 原则）。
                #   suppress_fallback 兜底确保不会空召回。
                # iter810: tiny_db_24h_relax — 小库统一阈值=3，不因 low-score 过早 suppress
                # 根因：22 chunk 库中 score=0.3 的有价值知识被 24h>=2 suppress，
                #   导致 14/20 次注入只有 1 条。小库知识密度高，重复注入是正常的。
                # iter837: tiny_db_24h_relax_v2 — 阈值 3→4
                # 根因（数据驱动，2026-05-05）：25-chunk 库中 6 个核心 chunk 24h=3 被 suppress，
                #   剩余 19 个 relevance 过低 → 空召回。日活跃项目每天使用 3 次同一知识是正常的。
                #   6h>=3 和 7d>=5 仍控制短期 burst 和长期垄断。
                # iter869: tiny_db_24h_sync_daemon — 与 daemon 对齐 4→3
                # 根因（数据驱动，2026-05-05）：36-chunk 库 top6 chunk 各 7d 注入 4-6 次，
                #   24h 阈值=4 导致同一 chunk 一天可注入 3 次仍不 suppress。
                #   daemon 已用阈值=3（iter810），retriever.py 滞后。同步消除不一致。
                # iter1019: saturated_24h_tighten — ac>=7 chunk 24h 阈值 -1
                # 根因（数据驱动，2026-05-07）：86-chunk 库 15 个高 ac chunk 占 7d 注入 103%。
                #   ac>=7 表明 agent 已多次内化，24h 阈值=3 允许同一 chunk 日注入 2 次仍不 suppress。
                #   收紧：ac>=7 阈值 -1（3→2），ac>=10 阈值 -1 再 -1 = max(1, base-2)。
                _sat_ac = _acc if _acc is not None else (chunk.get("access_count", 0) or 0)
                _24h_base = 3 if _tiny_db else (3 if score >= 0.5 else 2) if _small_db else (3 if score >= 0.5 else 2)
                if _sat_ac >= 10:
                    _24h_base = max(1, _24h_base - 2)
                elif _sat_ac >= 7:
                    _24h_base = max(1, _24h_base - 1)
                # iter1023: global_24h_saturated_cap — global ac>=4 已内化，24h cap=1
                elif chunk.get("project") == "global" and _sat_ac >= 4:
                    _24h_base = 1
                if _r24_cnt >= _24h_base:
                    score = 0.0
                    _hard_suppressed = True  # iter616
            # ── iter618: 7d_rolling_suppress — 长期慢性垄断 suppress ────────
            # iter767: tiered_small_db — 同步分级
            _r7d_cnt = _recent_7d_counts.get(chunk.get("id", ""), 0)
            # iter781: tiny_db 7d 阈值 20/15→10/8（同步收紧）
            if not _micro_db:
                # iter806: small_db_suppress_tighten — 7d 阈值同步收紧
                # small_db 7/5 → 5/4；tiny_db 同步（unify 原则）。
                # iter810: tiny_db_24h_relax — 小库 7d 统一阈值=5
                # iter816: small_db_7d_relax — 小库 7d 阈值 5/4→8/6
                # 根因（数据驱动，2026-05-05）：23-chunk 库中核心知识 7d=5 即 suppress，
                #   日活跃项目 <1次/天即封锁过于激进。24h>=3 和 6h>=2 仍有效控制 burst。
                # iter854: tiny_db_7d_relax_v2 — 阈值 5→7
                # 根因（数据驱动，2026-05-05）：33-chunk 库 7d=5 即 suppress，
                #   日均 <1 次使用就封锁核心知识 → 空召回。7 次/7d = 1次/天是正常频率。
                #   24h>=4 和 6h>=3 仍有效控制 burst。
                # iter909: score_7d_align_daemon — tiny_db 5→4 对齐 daemon(3) + final_gate(3)
                #   根因（数据驱动，2026-05-06）：_score_chunk 阈值=5 vs final_gate=3，
                #   14 个 chunk 7d>=4 仍通过评分阶段注入（fallback/pair 可绕过 final_gate）。
                #   收紧到 4 在评分阶段早期拦截，预计减少 21% 垄断注入。
                # iter928: score_7d_full_align — tiny_db 4→3 完全对齐 daemon(3)+final_gate(3)
                #   根因（数据驱动，2026-05-06）：阈值=4 vs final_gate=3 留 1 的缝隙，
                #   7d=3 的 chunk 通过评分进入 _pre_suppress_top_k → fallback/pair 逃逸。
                #   22-chunk 库有 15 个 7d>=3，其中 12 个>=4 被 iter909 拦截，
                #   但 3 个 7d=3 仍逃逸。统一到 3 堵死评分阶段逃逸口。
                # iter928: small_db 8/6→4/3 对齐 daemon iter882
                # iter952: tiny_db_7d_tighten 5→4（数据驱动：13/46 chunk 7d>=4 垄断）
                # iter990: small_db_7d_relax_v3 — small_db 4/3→6/4
                #   根因（数据驱动，2026-05-06）：85-chunk 库中 13/21 活跃 chunk 7d>=3 被 suppress，
                #   candidates=10 全灭 → 40% 空召回。85 chunk 库日均 1 session 使用同一知识是正常频率。
                #   6h/24h burst suppress 仍有效，7d 过紧导致核心知识被永久封锁。
                _suppress_7d_thresh = 5 if _tiny_db else (6 if score >= 0.5 else 4) if _small_db else (5 if score >= 0.5 else 3)  # iter1000: tiny_db 3→5 去垄断反转
                # iter993: global_chunk_suppress_tighten — global chunk 阈值 -1
                # iter1006: global_saturated_suppress_tighten — ac>=4 的 global chunk 阈值 -2
                # 根因（数据驱动，2026-05-06）：feishu CLI(ac=4,7d=4)、memory验证(ac=6,7d=4)、
                #   git commit(ac=9,7d=4) 等已内化的工具约束仍逃逸 7d suppress（阈值=4）。
                #   ac>=4 表明 agent 已多次见过该知识，边际信息为零，应更早 suppress。
                # 修复：ac>=4 的 global chunk 阈值 -2（与 cross 同级），ac<4 保持 -1。
                if chunk.get("project", "") == "global":
                    _g_ac = _acc if _acc is not None else (chunk.get("access_count", 0) or 0)
                    # iter1031: global_deep_saturated_suppress — ac>=7 深度内化强制阈值=2
                    # 根因（数据驱动，2026-05-07）：git commit(ac=9) 7d=4 仍逃逸（阈值=3）。
                    #   ac>=7 表明 agent 已深度内化，7d 仅允许 1 次注入后立即 suppress。
                    if _g_ac >= 7:
                        _suppress_7d_thresh = 2
                    else:
                        _suppress_7d_thresh = max(2, _suppress_7d_thresh - (2 if _g_ac >= 4 else 1))
                # iter1009: local_saturated_suppress — 本项目高 ac chunk 7d 阈值收紧
                # 根因（数据驱动，2026-05-06）：25-chunk 库中 PE分析(ac=7,7d=6)、
                #   Android诊断(ac=10,7d=5) 等高 ac 本项目 chunk 7d 阈值=5 仍逃逸。
                #   ac>=7 表明 agent 已充分内化，继续注入浪费 context window。
                # 修复：ac>=10 → -2，ac>=7 → -1（仅非 global 本项目 chunk）。
                elif chunk.get("project", "") != "global":
                    _l_ac = _acc if _acc is not None else (chunk.get("access_count", 0) or 0)
                    if _l_ac >= 10:
                        _suppress_7d_thresh = max(2, _suppress_7d_thresh - 2)
                    elif _l_ac >= 7:
                        _suppress_7d_thresh = max(2, _suppress_7d_thresh - 1)
                if _r7d_cnt >= _suppress_7d_thresh:
                    score = 0.0
                    _hard_suppressed = True
            # ── iter368: Attention Focus Bonus ─────────────────────────────
            # OS 类比：寄存器中的变量零访问延迟 bonus（vs 内存访问 200 cycles）
            # 当前焦点关键词命中 → chunk 进入"注意焦点"→ 激活阈值降低
            if _focus_keywords:
                try:
                    from store_focus import focus_score_bonus as _fsb
                    _fb = _fsb(_focus_keywords, chunk.get("summary", ""),
                               chunk.get("content", "")[:200])
                    score += _fb
                except Exception:
                    pass
            # ── iter376: Emotional Salience Retrieval Boost ─────────────────
            # OS 类比：Linux OOM Score — oom_adj=-800 高情绪显著性记忆优先保留
            # 认知科学依据：McGaugh (2000) 情绪增强记忆巩固 — 杏仁核激活增强海马编码
            # emotional_weight > threshold → score += weight × factor
            try:
                _ew = float(chunk.get("emotional_weight") or 0.0)
                _et = _sysctl("retriever.emotional_boost_threshold")  # default 0.4
                if _ew > (_et or 0.4):
                    _ef = _sysctl("retriever.emotional_boost_factor")  # default 0.08
                    score += _ew * (_ef or 0.08)
            except Exception:
                pass
            # ── iter424: Mood-Congruent Memory — 情绪效价一致性加分（Bower 1981）──
            # OS 类比：Linux NUMA-aware page placement — 访问同 NUMA node 的 page 延迟最低；
            #   query 情绪效价（positive/negative node）与 chunk 效价一致 → 检索优先
            # 认知科学：情绪激活扩散到同效价记忆，降低其检索阈值（Associative Network Theory）
            # query_valence × chunk_valence > 0 → 同向效价 → +mcm_boost × |product|
            try:
                if _mcm_query_valence != 0.0 and (_sysctl("retriever.mcm_enabled") is not False):
                    _chunk_val = float(chunk.get("emotional_valence") or 0.0)
                    _mcm_thresh = _sysctl("retriever.mcm_valence_threshold") or 0.3
                    if abs(_mcm_query_valence) >= _mcm_thresh and abs(_chunk_val) >= _mcm_thresh:
                        _val_product = _mcm_query_valence * _chunk_val
                        if _val_product > 0:  # 同向效价
                            _mcm_b = _sysctl("retriever.mcm_boost") or 0.05
                            score += _mcm_b * min(1.0, abs(_val_product))
            except Exception:
                pass
            # ── iter396: Source Monitoring Weight ──────────────────────────────
            # OS 类比：Linux LSM (Linux Security Modules) — 操作前检查来源 security context，
            #   不同 context 获得不同的访问权限（capability 粒度）。
            # 认知科学依据：Johnson (1993) Source Monitoring Framework —
            #   来源可信度（source credibility）影响记忆的检索优先级。
            #   hearsay < inferred < tool_output < direct（可信度递增）。
            # source_reliability ∈ [0.0, 1.0] → score *= source_monitor_weight()
            # weight ∈ [0.80, 1.15]，中间区间（0.60~0.85）保持不变（避免噪音误判）
            try:
                _sm_enabled = _sysctl("retriever.source_monitor_enabled")
                if _sm_enabled is None or _sm_enabled:  # default: enabled
                    _sr = float(chunk.get("source_reliability") or 0.7)
                    from store_vfs import source_monitor_weight as _smw
                    _sm_weight = _smw(_sr)
                    if abs(_sm_weight - 1.0) > 0.001:  # 避免无意义乘法
                        score *= _sm_weight
            except Exception:
                pass
            # ── iter403: Cue-Dependent Forgetting — Context Cue Weight ──────────
            # OS 类比：NUMA-aware memory access — 编码时 context = home node；
            #   检索时 context 越接近 home node → 访问延迟越低 → 优先返回。
            # 认知科学依据：Tulving & Thomson (1973) Encoding Specificity Principle —
            #   检索时上下文线索（cues）越接近编码时上下文，检索成功率越高。
            # encode_context（编码时关键词集）∩ 当前 retrieve_context → Jaccard overlap
            # overlap ∈ [0.50, 1.0] → weight ∈ [1.10, 1.20]（高匹配，提升优先级）
            # overlap ∈ [0.20, 0.50) → weight = 1.0（中等，不调整）
            # overlap < 0.20 → weight ∈ [0.85, 1.0)（低匹配，轻微降权）
            try:
                _cdf_enabled = _sysctl("retriever.context_cue_enabled")
                if _cdf_enabled is None or _cdf_enabled:  # default: enabled
                    _enc_ctx_str = chunk.get("encode_context") or ""
                    if _enc_ctx_str:
                        from store_vfs import (
                            compute_context_overlap as _ccoverlap,
                            context_cue_weight as _ccweight,
                            extract_encode_context as _ec_extract,
                        )
                        # 从当前 query 提取 retrieve_context
                        _ret_ctx = _ec_extract(query, chunk_type="")
                        if _ret_ctx:
                            _cc_overlap = _ccoverlap(_enc_ctx_str, _ret_ctx)
                            _cc_weight = _ccweight(_cc_overlap)
                            if abs(_cc_weight - 1.0) > 0.001:
                                score *= _cc_weight
            except Exception:
                pass
            # ── iter404: Semantic Priming Boost ────────────────────────────────
            # OS 类比：Linux page readahead cache hit — primed entity match → score 提升。
            # 认知科学依据：Collins & Loftus (1975) Spreading Activation Theory —
            #   当前活跃概念（primed）激活相关记忆的检索速度更快，优先级更高。
            # 仅在 project + chunk_id 已知时（memory_chunks 行存在）才计算。
            try:
                _pr_enabled = _sysctl("retriever.semantic_priming_enabled")
                if _pr_enabled is None or _pr_enabled:  # default: enabled
                    _pr_chunk_id = chunk.get("id") or chunk.get("chunk_id")
                    _pr_project = chunk.get("project", "")
                    if _pr_chunk_id and _pr_project and conn is not None:
                        from store_vfs import compute_priming_boost as _cpboost
                        _pr_boost = _cpboost(conn, _pr_chunk_id, _pr_project)
                        if _pr_boost > 0.001:
                            score += _pr_boost
            except Exception:
                pass
            # ── iter372: Context-Aware Retrieval Boost ─────────────────────────
            # OS 类比：NUMA-aware allocation — 本地节点优先（低延迟）
            # 编码特异性：chunk 编码时的 cwd + 关键词与当前越匹配，score 越高
            try:
                _enc_ctx = chunk.get("encoding_context") or {}
                if isinstance(_enc_ctx, str):
                    import json as _json
                    _enc_ctx = _json.loads(_enc_ctx) if _enc_ctx else {}
                _ctx_boost = _compute_context_match(_enc_ctx, _current_context)
                score += _ctx_boost
            except Exception:
                pass
            # ── iter405: Retroactive Interference — Recency Penalty ────────────
            # OS 类比：MGLRU generation demotion — 年龄较大的 pages 在新 pages 涌入时面临更大驱逐压力。
            # 认知科学依据：Underwood (1957) RI — 新记忆会干扰旧记忆的检索，相似度越高干扰越大。
            # 对年龄 > 7天 且有更新同主题 chunk 的旧 chunk 施加轻微罚分。
            try:
                _ri_enabled = _sysctl("retriever.retroactive_interference_enabled")
                if _ri_enabled is None or _ri_enabled:  # default: enabled
                    _ri_chunk_id = chunk.get("id") or chunk.get("chunk_id")
                    _ri_project = chunk.get("project", "")
                    _ri_created = chunk.get("created_at", "")
                    if _ri_chunk_id and _ri_project and _ri_created and conn is not None:
                        _ri_now = datetime.utcnow()
                        try:
                            _ri_ct = datetime.fromisoformat(_ri_created.replace("Z", "+00:00")).replace(tzinfo=None)
                        except Exception:
                            _ri_ct = _ri_now
                        _ri_age_days = max(0.0, (_ri_now - _ri_ct).total_seconds() / 86400)
                        if _ri_age_days > 7.0:
                            from store_vfs import (
                                get_newer_same_topic_count as _gntc,
                                compute_recency_penalty as _crp,
                            )
                            _ri_count, _ri_sim = _gntc(conn, _ri_chunk_id, _ri_project)
                            if _ri_count > 0:
                                _ri_penalty = _crp(_ri_age_days, _ri_count, _ri_sim)
                                if _ri_penalty > 0.001:
                                    score -= _ri_penalty
            except Exception:
                pass
            # ── B10: Global Cross-Project Relevance Gate ────────────────────
            # 问题：global 层 design_constraint 被豁免遗忘/置信过滤（iter369/iter482），
            #   低 relevance 的 global chunk 仍能靠高 importance 进入 top-K，污染当前项目。
            #   实测：aios 项目召回 "kernel patch 人名规则"（relevance≈0.05，importance≈0.85）
            # OS 类比：Linux cross-NUMA memory access penalty — remote node 访问延迟 ×2；
            #   global chunk 访问跨 "project namespace"，应有相应延迟惩罚。
            # 人类记忆：专业知识领域分区（domain-specific memory） — 外科医生在烹饪时
            #   手术室规程不自动激活，只有 query 显式触发（高 relevance）时才跨域迁移。
            # 机制：global chunk 在 project != "global" 时，若 relevance < 0.25（低相关性），
            #   施加 0.50 折扣（design_constraint 豁免阈值调高至 0.40，因其通常具有通用价值）。
            #   这样 global chunk 只有在 query 明确相关时才能进入 top-K，
            #   而不是靠 importance 常驻（解决当前问题的根因）。
            try:
                _chunk_proj = chunk.get("project", "")
                if _chunk_proj == "global" and project != "global":
                    _ctype = chunk.get("chunk_type", "")
                    # design_constraint 需要更低相关性才触发惩罚（它有更广泛通用价值）
                    _relevance_gate = 0.40 if _ctype == "design_constraint" else 0.25
                    if relevance < _relevance_gate:
                        score *= 0.50
            except Exception:
                pass
            # ── iter616: final_hard_gate — 防止 additive bonus 绕过 hard suppression ──
            # 根因：24h_burst_suppression (iter614) 和 bandwidth_hard_cap (iter601) 设
            #   score=0.0，但后续 focus_bonus/emotional_boost/priming_boost 是 += 操作，
            #   将 score 从 0.0 抬回 ~0.0001，使被 suppress 的 chunk 仍进入 top-K。
            #   实测：feishu CLI chunk 24h 注入 12 次 (>=3 应 suppress)，score=0.0001 仍入选。
            # 修复：在所有 bonus 之后、return 之前，硬性归零。
            if _hard_suppressed:
                return 0.0
            return score

        # ── 迭代357：Working Set TLB Probe（pre-FTS5 热数据快速命中）──
        # OS 类比：CPU TLB lookup before PTW (Page Table Walk)
        #   命中 TLB → 直接返回物理地址（~1ns，跳过完整页表 walk ~100ns）
        #   命中 Working Set → 直接返回缓存 chunk（~0.1ms，跳过 FTS5 ~5ms）
        #
        # 策略：对 session working set 做 in-memory BM25 快速扫描，
        #   结果作为高置信度候选并入 FTS5 final 列表（而非替代），
        #   避免 cold start 时 working set 为空导致召回降级。
        _ws_hits = []
        if priority == "FULL" and session_id:
            try:
                from agent_working_set import registry as _ws_registry
                from bm25 import bm25_normalized as _ws_bm25
                _ws = _ws_registry.get(session_id)
                if _ws is not None and _ws.size() > 0:
                    with _ws._lock:
                        _ws_cached = [(cid, e.chunk, e) for cid, e in _ws._lru.items()]
                    if _ws_cached:
                        _ws_docs = [f"{c.summary} {c.content[:80]}" for _, c, _ in _ws_cached]
                        _ws_scores_raw = _ws_bm25(query, _ws_docs)
                        _ws_threshold = _sysctl("router.min_score")
                        for i, (cid, chunk, entry) in enumerate(_ws_cached):
                            if _ws_scores_raw[i] >= _ws_threshold:
                                # 转成 retriever 内部 chunk dict 格式
                                _ws_chunk_dict = {
                                    "id": chunk.id,
                                    "project": chunk.project,
                                    "chunk_type": chunk.chunk_type,
                                    "content": chunk.content,
                                    "summary": chunk.summary,
                                    "importance": chunk.importance,
                                    "retrievability": chunk.retrievability,
                                    "stability": chunk.stability,
                                    "last_accessed": chunk.last_accessed or "",
                                    "created_at": chunk.created_at or "",
                                    "access_count": entry.access_count,
                                    "lru_gen": 0,
                                    "info_class": getattr(chunk, "info_class", "world") or "world",
                                    "tags": ",".join(chunk.tags) if chunk.tags else "",
                                    "oom_adj": 0,
                                    "fts_rank": 1.0,
                                }
                                _ws_score = _score_chunk(_ws_chunk_dict, _ws_scores_raw[i])
                                _ws_hits.append((_ws_score, _ws_chunk_dict))
                                # Mark accessed
                                entry.accessed = True
                                entry.access_count += 1
                                _ws._stats["hits"] += 1
            except Exception:
                _ws_hits = []  # TLB probe 失败不阻塞主路径

        if use_fts:
            candidates_count = len(fts_results)
            max_rank = max(c["fts_rank"] for c in fts_results) if fts_results else 1.0
            if max_rank <= 0:
                max_rank = 1.0

            final = []
            fts_ids = set()
            for chunk in fts_results:
                relevance = chunk["fts_rank"] / max_rank
                score = _score_chunk(chunk, relevance)
                final.append((score, chunk))
                fts_ids.add(chunk.get("id", ""))

            # 合并 Working Set TLB hits（去重）
            for _ws_score, _ws_chunk in _ws_hits:
                if _ws_chunk.get("id", "") not in fts_ids:
                    final.append((_ws_score, _ws_chunk))
                    fts_ids.add(_ws_chunk.get("id", ""))

            # ── 迭代310：Spreading Activation — 关联激活扩散补充 ──────────────
            # OS 类比：CPU L2 prefetch — FTS5 命中 chunk A 后，沿 entity_edges
            # 预热邻居 chunk 到候选集，形成认知网络式召回而非孤立 top-K
            if not _check_deadline("spreading_activate"):
                try:
                    _sa_result = _spreading_activate(
                        conn, list(fts_ids), project=project,
                        decay=0.7, max_hops=2,
                        existing_ids=fts_ids,
                        max_activation_bonus=0.4,
                    )
                    if _sa_result:
                        # 批量加载激活邻居 chunk
                        _sa_ids = list(_sa_result.keys())
                        _sa_ph = ",".join("?" * len(_sa_ids))
                        _sa_rows = conn.execute(
                            f"SELECT id, summary, content, chunk_type, importance, "
                            f"last_accessed, access_count, created_at, project, "
                            f"info_class, lru_gen "
                            f"FROM memory_chunks WHERE id IN ({_sa_ph})",
                            _sa_ids,
                        ).fetchall()
                        _sa_col = ("id","summary","content","chunk_type","importance",
                                   "last_accessed","access_count","created_at","project",
                                   "info_class","lru_gen")
                        for row in _sa_rows:
                            c = dict(zip(_sa_col, row))
                            activation_bonus = _sa_result.get(c["id"], 0.0)
                            # spreading activation 用较低基础 relevance，主要靠 activation_bonus
                            base_score = _score_chunk(c, relevance=0.2)
                            # iter639: hard_suppress → base_score=0.0，bonus 不得绕过
                            if base_score <= 0:
                                continue
                            final.append((base_score + activation_bonus, c))
                            fts_ids.add(c["id"])
                        candidates_count += len(_sa_rows)
                except Exception:
                    pass  # spreading activation 失败不阻塞主流程

            # ── iter577：shmem_link — Shared Memory Co-occurrence Activation ──────
            # OS 类比：shmem/tmpfs — 多进程通过映射同一物理页隐式共享，无需 IPC。
            # spreading_activate 只走 entity_edges（显式连接），但 95%+ entity 无 edge。
            # shmem_link 通过 entity co-occurrence 发现隐式关联（共享同一 entity 的 chunk）。
            if not _check_deadline("shmem_link"):
                try:
                    from store_vfs import shmem_link as _shmem
                    _shmem_result = _shmem(
                        conn, list(fts_ids), project=project,
                        existing_ids=fts_ids,
                    )
                    if _shmem_result:
                        _sh_ids = list(_shmem_result.keys())
                        _sh_ph = ",".join("?" * len(_sh_ids))
                        _sh_rows = conn.execute(
                            f"SELECT id, summary, content, chunk_type, importance, "
                            f"last_accessed, access_count, created_at, project, "
                            f"info_class, lru_gen "
                            f"FROM memory_chunks WHERE id IN ({_sh_ph})",
                            _sh_ids,
                        ).fetchall()
                        _sh_col = ("id","summary","content","chunk_type","importance",
                                   "last_accessed","access_count","created_at","project",
                                   "info_class","lru_gen")
                        for row in _sh_rows:
                            c = dict(zip(_sh_col, row))
                            shmem_bonus = _shmem_result.get(c["id"], 0.0)
                            base_score = _score_chunk(c, relevance=0.15)
                            # iter639: hard_suppress → base_score=0.0，bonus 不得绕过
                            if base_score <= 0:
                                continue
                            final.append((base_score + shmem_bonus, c))
                            fts_ids.add(c["id"])
                        candidates_count += len(_sh_rows)
                except Exception:
                    pass  # shmem_link 失败不阻塞主流程

            # ── iter380：Schema Spreading Activation — Bartlett (1932) Schema Theory ──
            # OS 类比：SLUB allocator partial list — 命中 chunk 所在 kmem_cache，
            # 同 slab 的相邻对象自动成为候选（schema-level prefetch）。
            # 在 entity_edges 图扩散（Collins & Loftus 1975）之后，
            # 再叠加 schema 框架级激活（更高层次语义聚合）。
            if not _check_deadline("schema_spread"):
                try:
                    from store_vfs import schema_spread_activate as _schema_sa
                    _schema_result = _schema_sa(
                        conn, list(fts_ids), project=project,
                        max_per_schema=3,
                        activation_score=0.25,
                        existing_ids=fts_ids,
                    )
                    if _schema_result:
                        _schema_ids = list(_schema_result.keys())
                        _schema_ph = ",".join("?" * len(_schema_ids))
                        _schema_rows = conn.execute(
                            f"SELECT id, summary, content, chunk_type, importance, "
                            f"last_accessed, access_count, created_at, project, "
                            f"info_class, lru_gen "
                            f"FROM memory_chunks WHERE id IN ({_schema_ph})",
                            _schema_ids,
                        ).fetchall()
                        _schema_col = ("id","summary","content","chunk_type","importance",
                                       "last_accessed","access_count","created_at","project",
                                       "info_class","lru_gen")
                        for row in _schema_rows:
                            c = dict(zip(_schema_col, row))
                            activation_bonus = _schema_result.get(c["id"], 0.0)
                            base_score = _score_chunk(c, relevance=0.15)
                            # iter639: hard_suppress → base_score=0.0，bonus 不得绕过
                            if base_score <= 0:
                                continue
                            final.append((base_score + activation_bonus, c))
                            fts_ids.add(c["id"])
                        candidates_count += len(_schema_rows)
                except Exception:
                    pass  # schema spreading 失败不阻塞主流程

            # ── 迭代330：Causal Secondary Search — causal_chain 专属二次检索 ──
            # OS 类比：Linux readahead ≥ 2 pass — 第一轮 VFS readahead 基于 offset，
            # 第二轮 ext4 readahead 基于 extent map，两轮覆盖不同维度。
            # 问题：主 query 扩展因果词会完全挤出 decision/design_constraint（实测 causal=8, decision=0）。
            # 解决：主 query 保持不变，在 spreading activation 后追加专属 causal 二次 FTS5 搜索，
            # 结果以低 base relevance（0.25）合入 final，不影响主结果排序。
            # 触发条件：FULL 优先级 + 未超 soft deadline + 有 causal secondary query
            if priority == "FULL" and not _check_deadline("causal_secondary"):
                try:
                    _causal_q = _build_causal_query(prompt)
                    if _causal_q:
                        _causal_results = fts_search(
                            conn, _causal_q, project,
                            top_k=3,
                            chunk_types=("causal_chain", "reasoning_chain"),
                        )
                        _causal_added = 0
                        for _cc in _causal_results:
                            if _cc.get("id", "") not in fts_ids:
                                # 低基础 relevance — 补充而非挤占主结果
                                _cc_score = _score_chunk(_cc, relevance=0.25)
                                final.append((_cc_score, _cc))
                                fts_ids.add(_cc.get("id", ""))
                                _causal_added += 1
                        if _causal_added:
                            candidates_count += _causal_added
                except Exception:
                    pass  # causal secondary search 失败不阻塞主流程

            # ── iter126: BM25 补充（仅当 FTS5 召回不足 effective_top_k 时）──
            # OS 类比：L1 cache miss 后查 L2（而非只在 L1 完全失效时才看 L2）
            try:
                _hybrid_threshold = _sysctl("retriever.hybrid_fts_min_count")
            except Exception:
                _hybrid_threshold = effective_top_k

            if len(fts_results) < _hybrid_threshold:
                # FTS5 召回不足，BM25 补充长尾
                # 迭代141：hybrid BM25 补充也受 soft deadline 保护（已超 deadline 时跳过）
                # OS 类比：Linux schedule_timeout() — 超时后不再等待，直接用已有结果
                # 已有 FTS5 结果时 BM25 补充是"锦上添花"，超时时直接用 FTS5 结果即可
                _need_extra = _hybrid_threshold - len(fts_results)
                try:
                    if _check_deadline("pre_hybrid_bm25"):
                        raise Exception("deadline_skip_hybrid_bm25")
                    _all_chunks = store_get_chunks(conn, project, chunk_types=_retrieve_types)
                    # iter526: vm_flags — 也排除 loader 已注入 IDs
                    _exclude_all = fts_ids | _loader_exclude_ids
                    _extra_chunks = [c for c in _all_chunks if c.get("id", "") not in _exclude_all]
                    if _extra_chunks:
                        _extra_texts = [f"{c['summary']} {c['content']}" for c in _extra_chunks]
                        _extra_raw = bm25_scores_cached(query, _extra_texts, chunk_version=read_chunk_version())
                        _extra_norm = normalize(_extra_raw)
                        # BM25 补充 chunk 降权：避免劣质长尾挤掉 FTS5 精确结果
                        # discount = 0.6 → BM25 补充 chunk 的 relevance 最高只有 FTS5 的 60%
                        _discount = 0.6
                        for i, chunk in enumerate(_extra_chunks):
                            relevance = _extra_norm[i] * _discount
                            score = _score_chunk(chunk, relevance)
                            final.append((score, chunk))
                        _hybrid_bm25_count = min(_need_extra, len(_extra_chunks))
                        candidates_count += _hybrid_bm25_count
                except Exception:
                    pass  # BM25 补充失败不影响已有 FTS5 结果

            # ── 迭代305：Curiosity-Driven 知识空白检测（FULL 模式专属）──────────
            # OS 类比：vmstat 检测到 free pages < WMARK_LOW 时触发 wakeup_kswapd()：
            #   FTS top-1 score < 0.25（知识低水位）= 知道有相关内容但不够用
            #   → 将 query 写入 curiosity_queue，deep-sleep 阶段异步补充知识
            #
            # 触发条件（三者同时满足）：
            #   1. FULL 模式（已在 `if use_fts:` 块内，priority==FULL 时才有 fts_results）
            #   2. FTS 召回数 >= 1（有相关内容，否则是"完全空白"而非"弱命中"）
            #   3. top-1 score < 0.25 且 query 长度 > 8 字符（过滤噪音和短确认词）
            #
            # 性能约束：enqueue_curiosity 必须非阻塞（try/except 包裹，失败静默）
            # 注意：此处 fts_results 是原始 FTS 召回，max_rank 已在上方计算
            if priority == "FULL" and fts_results:
                try:
                    _fts_top_score = fts_results[0]["fts_rank"] if fts_results else 0.0
                    _CURIOSITY_WMARK_LOW = 0.25   # 知识低水位阈值（类比 WMARK_LOW）
                    _CURIOSITY_MIN_QLEN  = 8      # 最小 query 长度（过滤短确认词）
                    if (_fts_top_score < _CURIOSITY_WMARK_LOW
                            and len(query) > _CURIOSITY_MIN_QLEN):
                        from store_vfs import enqueue_curiosity as _enqueue_curiosity
                        _eq_n = _enqueue_curiosity(conn, query, project,
                                                    top_score=_fts_top_score)
                        if _eq_n:
                            _deferred.log(DMESG_DEBUG, "curiosity",
                                          f"weak_hit enqueued: score={_fts_top_score:.3f} "
                                          f"qlen={len(query)} query={query[:40]}",
                                          session_id=session_id, project=project)
                except Exception:
                    pass  # 性能关键路径：enqueue 失败静默（不阻塞检索主流程）

        else:
            # ── 迭代135：LITE + FTS5 miss → Early Exit（BM25 noise suppression）──
            # OS 类比：Linux io_uring fixed-file IORING_REGISTER_FILES — 对低优先级任务
            #   不分配 kernel resource（直接返回 EAGAIN），防止低相关性请求耗尽资源。
            #
            # 问题：LITE 优先级（short query/低信号）的 FTS5 为空时，BM25 全表扫描会返回
            #   大量"词汇偶然重叠"的高 importance chunk（如 global 的 design_constraint）。
            #   实测 /intraday-scan（14chars, LITE）→ FTS5 无结果 → BM25 返回70个无关 chunk
            #   → 注入8条 git/kernel 约束 → 对 trading 项目造成严重噪音。
            #
            # 修复：LITE 路径 FTS5 miss → 直接 sys.exit(0)（不走 BM25 fallback）
            #   FULL 路径保留 BM25 fallback（FULL 表明用户需要全面检索，值得付出代价）
            #   LITE 路径 FTS5 miss 等价于"此 query 在 DB 中无相关知识"，
            #   BM25 全扫只会放大 importance 排序的噪音，不会找到真正相关内容。
            if priority == "LITE":
                # LITE + FTS5 miss: 无相关知识，直接退出（不注入噪音）
                conn.close()
                if len(_deferred) > 0:
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                    except Exception:
                        pass
                sys.exit(0)

            # ── iter425: Tip-of-the-Tongue (TOT) — FTS5 零命中边缘激活补救 ────────
            # OS 类比：Linux mincore(2) fallback to swap — page cache miss 后从 swap 恢复：
            #   FTS5 miss（无直接词汇匹配）→ 从 entity_map（倒排索引/swap）查 entity 关联 chunk。
            # 认知科学依据：Brown & McNeill (1966) Tip-of-the-Tongue (TOT) effect —
            #   完全回忆失败时（FTS5 zero hits），边缘激活仍保留语义线索：
            #   query 中的实体词在 entity_map 中可找到关联 chunk，触发"周边激活"恢复。
            # 触发条件：FULL 优先级 + FTS5 零命中（not use_fts 且非 deadline 超时）
            # 与 spreading_activate 的区别：
            #   SA 从已命中 chunk 沿 entity_edges 图扩散（需要非空 FTS5 结果）
            #   TOT 在 FTS5 完全失败时，直接从 query 实体词查 entity_map（零命中补救）
            _tot_fts_ids: set = set()
            if (priority == "FULL"
                    and not use_fts
                    and not _check_deadline("tot_activate")):
                try:
                    from store_vfs import tot_activate as _tot_activate
                    _tot_result = _tot_activate(
                        conn, query, project,
                        existing_ids=_tot_fts_ids,
                        top_k=effective_top_k,
                        base_score=0.25,
                    )
                    if _tot_result:
                        # 批量加载 TOT 激活 chunk
                        _tot_ids = list(_tot_result.keys())
                        _tot_ph = ",".join("?" * len(_tot_ids))
                        _tot_rows = conn.execute(
                            f"SELECT id, summary, content, chunk_type, importance, "
                            f"last_accessed, access_count, created_at, project, "
                            f"info_class, lru_gen, emotional_weight, emotional_valence "
                            f"FROM memory_chunks WHERE id IN ({_tot_ph})",
                            _tot_ids,
                        ).fetchall()
                        _tot_col = ("id", "summary", "content", "chunk_type", "importance",
                                    "last_accessed", "access_count", "created_at", "project",
                                    "info_class", "lru_gen", "emotional_weight", "emotional_valence")
                        _tot_final: list = []
                        for row in _tot_rows:
                            c = dict(zip(_tot_col, row))
                            # 为 _score_chunk 提供兼容字段
                            c.setdefault("fts_rank", 0.25)
                            c.setdefault("retrievability", 1.0)
                            c.setdefault("source_reliability", 0.7)
                            c.setdefault("verification_status", "pending")
                            c.setdefault("confidence_score", 0.7)
                            c.setdefault("encoding_context", {})
                            activation_bonus = _tot_result.get(c["id"], 0.0)
                            base = _score_chunk(c, relevance=0.2)
                            # iter639: hard_suppress → base=0.0，bonus 不得绕过
                            if base <= 0:
                                continue
                            _tot_final.append((base + activation_bonus, c))
                            _tot_fts_ids.add(c["id"])
                        if _tot_final:
                            # 仅在 TOT 激活有结果时跳过 BM25 全表扫描（减少噪音）
                            _tot_final.sort(key=lambda x: x[0], reverse=True)
                            top_k = _tot_final[:effective_top_k]
                            candidates_count = len(_tot_final)
                            use_fts = True  # 标记有结果，跳过 else 分支后续逻辑
                            final = _tot_final
                            _deferred.log(DMESG_DEBUG, "retriever",
                                          f"tot_activate: {len(_tot_final)} chunks from entity_map "
                                          f"query_entities={len(query.split())} tot_ids={_tot_ids[:3]}",
                                          session_id=session_id, project=project)
                            # 直接跳转到 scoring 之后的输出阶段（避免 BM25 全扫）
                except Exception:
                    pass  # TOT 失败不阻塞 BM25 fallback

            # ── 迭代141：BM25 Fallback Hard Deadline Pre-check ──────────────────
            # OS 类比：Linux kernel 长路径中的 need_resched() 检查点（schedule()）
            #   内核中长时间运行的路径（如 ext4 文件系统、内存压缩）会在每个"安全点"
            #   调用 cond_resched() / need_resched()，如果有更高优先级任务等待则主动 yield。
            #   memory-os 等价问题：
            #     BM25 全表扫描（store_get_chunks + bm25_scores）是 O(N) 全扫，
            #     95 chunks 时约 450-630ms。hard_deadline 在 post_scoring 才检查，
            #     等 BM25 完成后再检测到超时（等于"没有检查"——结果已计算完了）。
            #     实测 hard_deadline 轨迹：434ms, 490ms, 522ms, 627ms（全部超 deadline_hard_ms=200ms）。
            #   修复：在 BM25 全表扫描**之前**加一个抢占检查点：
            #     如果此时已超 hard_deadline，直接 sys.exit(0)（跳过整个 BM25 扫描）。
            #     效果等价于 cond_resched()——检测到"截止时间已到"时放弃昂贵操作。
            #   注意：pre_bm25 检查的 is_hard=True 直接退出（无结果），而不像 post_scoring
            #     那样返回已有结果——因为此路径 FTS5 已失败（use_fts=False），没有 FTS5 结果可返回。
            if not use_fts and _check_deadline("pre_bm25_fallback", is_hard=True):
                # hard deadline 到期 + FTS5 无结果：直接退出，不注入（优于等待 BM25 完成后再退出）
                conn.close()
                if len(_deferred) > 0:
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                    except Exception:
                        pass
                sys.exit(0)

            # Fallback：全表扫描 + Python BM25（FTS5 异常时，仅 FULL 优先级）
            # ── 迭代131：BM25 Fallback Global Discount — 跨项目噪音抑制 ──
            # iter425: TOT 已恢复结果时跳过 BM25 全表扫描（TOT 更精确，BM25 噪音更高）
            # OS 类比：Linux NUMA Aware Scheduling — 强制 cross-node 分配时施加 migration cost
            #   BM25 全表扫描无法区分语义相关性和词汇偶然重叠。
            #   解决：BM25 fallback 专用 global discount，relevance × bm25_global_discount (0.4)
            if use_fts:
                # iter425: TOT activated — skip BM25 full-table scan
                pass
            else:
                _bm25_global_discount = _sysctl("retriever.bm25_global_discount")
            if not use_fts:
                # iter425: use_fts=False → BM25 full-table scan (TOT did not activate)
                chunks = store_get_chunks(conn, project, chunk_types=_retrieve_types)
                # iter526: vm_flags — 排除 loader 已注入的 chunk IDs
                if _loader_exclude_ids and chunks:
                    chunks = [c for c in chunks if c.get("id") not in _loader_exclude_ids]
                if not chunks:
                    sys.exit(0)
                candidates_count = len(chunks)

                search_texts = [f"{c['summary']} {c['content']}" for c in chunks]
                _cv = read_chunk_version()
                raw_scores = bm25_scores_cached(query, search_texts, chunk_version=_cv)
                relevance_scores = normalize(raw_scores)

                final = []
                for i, chunk in enumerate(chunks):
                    relevance = relevance_scores[i]
                    # iter131: global 项目 chunk 在 BM25 fallback 路径中施加强化折扣
                    # 仅当当前 project 不是 global 时生效（global project 查询不折扣自身内容）
                    if (project != "global"
                            and chunk.get("project", "") == "global"
                            and _bm25_global_discount < 1.0):
                        relevance = relevance * _bm25_global_discount
                    score = _score_chunk(chunk, relevance)
                    final.append((score, chunk))
            # else: use_fts=True (TOT activated) — final/candidates_count already set above

        # ── 迭代41：Hard Deadline 检查 — 评分完成后如果已超 hard deadline，提前返回 ──
        # OS 类比：deadline scheduler 的 deadline_expired()——请求到期后立即 dispatch
        # 不再执行 madvise/swap_fault/router，直接返回 FTS5+scorer 的结果
        if _check_deadline("post_scoring", is_hard=True):
            # hard deadline 到期：跳过所有后续增强阶段
            # ── iter388: Temporal Priming（hard deadline 路径）──
            try:
                if session_id and _sysctl("retriever.priming_enabled"):
                    _priming_boost = _sysctl("retriever.priming_boost")
                    _shadow_data = None
                    try:
                        with open(SHADOW_TRACE_FILE, 'r', encoding="utf-8") as _sf:
                            _shadow_data = json.loads(_sf.read())
                    except Exception:
                        pass
                    if _shadow_data and _shadow_data.get("session_id") == session_id:
                        _primed_ids = set(_shadow_data.get("top_k_ids") or [])
                        if _primed_ids:
                            # iter623: priming 只应用于 s>0 的 chunk，防止 suppress 后被抬升
                            final = [
                                (s + _priming_boost if s > 0 and c.get("id") in _primed_ids else s, c)
                                for s, c in final
                            ]
            except Exception:
                pass
            # 迭代50：hard deadline 路径也使用 DRR 选择
            final.sort(key=lambda x: x[0], reverse=True)
            # 迭代86：最低相关性门槛 — A/B评测发现无关query注入噪音
            # 迭代88：自适应门槛 — 通用知识 query 用更高阈值防止误注入
            if _is_generic_knowledge_query(query):
                _min_thresh = _sysctl("retriever.generic_query_min_threshold")
            else:
                _min_thresh = _sysctl("retriever.min_score_threshold")
            # iter819: tiny_db_threshold_relax — 小库 BM25 分数天然偏低，0.30 阈值
            #   导致 70% 检索只返回 1 条（top_k=1 比例 70%，多知识组合缺失）。
            #   根因：36 chunk 库 FTS5 词汇覆盖不足，score 普遍在 0.15-0.25。
            #   修复：tiny_db 非 generic query 时 threshold 降至 0.18。
            if _db_chunk_count < 50 and not _is_generic_knowledge_query(query):
                _min_thresh = min(_min_thresh, 0.18)
            # iter578: mremap — hard deadline 路径也应用自适应地板
            if (final and _sysctl("retriever.adaptive_floor_enabled")
                    and not _is_generic_knowledge_query(query)):
                _top1_score = final[0][0]
                _af_min_top1 = _sysctl("retriever.adaptive_floor_min_top1")
                if _top1_score >= _af_min_top1:
                    _af_ratio = _sysctl("retriever.adaptive_floor_ratio")
                    # iter823: small_db_af_relax — 小库 BM25 分布稀疏，0.25 过滤 top2
                    if _db_chunk_count < 100:
                        _af_ratio = min(_af_ratio, 0.12)
                    _adaptive_floor = _top1_score * _af_ratio
                    _min_thresh = min(_min_thresh, max(_adaptive_floor, 0.10))
            # iter579: copy_page_range — hard deadline 路径也应用 gap bridging
            if (len(final) >= 3 and _sysctl("retriever.gap_bridge_enabled")
                    and not _is_generic_knowledge_query(query)):
                _gb_top1 = final[0][0]
                _gb_top2 = final[1][0] if final[1][0] > 0 else 0.001
                _gb_min_ratio = _sysctl("retriever.gap_bridge_min_ratio")
                if _gb_top1 / _gb_top2 >= _gb_min_ratio:
                    _gb_cluster_ratio = _sysctl("retriever.gap_bridge_cluster_ratio")
                    _gb_min_cluster = _sysctl("retriever.gap_bridge_min_cluster")
                    _gb_cluster_top = final[1][0]
                    _gb_cluster_floor = _gb_cluster_top * _gb_cluster_ratio
                    _gb_cluster_size = sum(
                        1 for s, _ in final[1:]
                        if s >= _gb_cluster_floor
                    )
                    if _gb_cluster_size >= _gb_min_cluster:
                        # iter863: gap_bridge_floor_raise — 0.05 允许 score<0.10 的不相关知识注入
                        #   数据驱动：7d 内 12 条 score<0.10 注入全为跨项目无关知识
                        _gb_new_thresh = max(_gb_cluster_floor, 0.10)
                        if _gb_new_thresh < _min_thresh:
                            _min_thresh = _gb_new_thresh
            # iter620: zero_score_absolute_gate — score=0 的 chunk 绝对不进入 positive
            # 根因：_hard_suppressed 将 score 设为 0.0，但 adaptive_floor/gap_bridge
            #   可将 _min_thresh 降到 0.10，而 focus_bonus 等 += 操作可能将 0.0 抬到
            #   0.00009 级别，恰好通过极低 threshold。绝对零分门槛不可绕过。
            positive = [(s, c) for s, c in final if s >= _min_thresh and s > 0]
            # iter826: single_result_pair_inject (hard_deadline path)
            # iter843: pair_dedup_aware — 配对时排除已达 session dedup 阈值的 chunk
            _pair_dedup_thresh_hd = _sysctl("retriever.session_dedup_threshold") or 2
            # iter960: hd_pair_7d_gate — hard_deadline pair 加 7d ceiling 防止垄断 chunk 逃逸
            # 根因（数据驱动，2026-05-06）：hard_deadline pair inject 仅检查 session_dedup，
            #   7d>=4 的 chunk 被 suppress_final_gate 拦截后经 pair 路径重新注入。
            _hd_pair_7d_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 6)  # iter1010: pair_ceiling_widen — 4/5→5/6 恢复 pair 候选池
            if len(positive) == 1 and len(final) >= 3:
                _pair_cands_hd = [(s, c) for s, c in final
                                  if s > 0.10 and s < _min_thresh
                                  and c.get("id") != positive[0][1].get("id")
                                  and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh_hd
                                  and _recent_7d_counts.get(c.get("id", ""), 0) < _hd_pair_7d_ceiling]
                if _pair_cands_hd:
                    _pair_best_hd = max(_pair_cands_hd, key=lambda x: x[0])
                    positive.append(_pair_best_hd)
                else:
                    # iter827: importance_pair_fallback (hard_deadline path)
                    _imp_pairs_hd = [(float(c.get("importance", 0) or 0), c) for _, c in final
                                     if c.get("id") != positive[0][1].get("id")
                                     and (c.get("access_count", 0) or 0) < 30
                                     and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh_hd
                                     and _recent_7d_counts.get(c.get("id", ""), 0) < _hd_pair_7d_ceiling]
                    if _imp_pairs_hd:
                        _imp_best_hd = max(_imp_pairs_hd, key=lambda x: x[0])
                        # iter941: imp_pair_top1_gate (hard_deadline path)
                        if _imp_best_hd[0] >= 0.3 and positive[0][0] >= 0.15:
                            positive.append((positive[0][0] * 0.3, _imp_best_hd[1]))
            # iter695: threshold_degrade — 阈值过高全灭时降级到默认 0.30
            if not positive and _min_thresh > 0.30:
                positive = [(s, c) for s, c in final if s >= 0.30 and s > 0]
            # iter759: 移除 candidates_rescue — 宁可不注入也不注入垃圾
            # 根因（用户可感知）：rescue 下限 0.15 导致 score=0.156 的不相关知识被注入，
            # 占用 context 空间干扰注意力。注入不相关内容比不注入更糟。
            # iter751: suppress 全灭兜底 (hard_deadline path)
            # iter770: fallback_noise_gate — fallback 也需硬性下限，防止低分垃圾注入
            #   根因（数据驱动，2026-05-04）：import-90139 score=0.15~0.22 通过 fallback
            #   连续 5 次注入（psi_downgrade 路径），全与当前 query 无关。
            #   修复：fallback 要求 score >= 0.25，低于此宁可空召回。
            # iter771: tiny_db_fallback_relax — 小库 FTS5 词汇覆盖低致 score 偏低，
            #   0.25 门槛导致 score 0.15-0.24 的有用 chunk 落入 dead zone（78% 空召回）。
            #   修复：tiny_db(<30 cands) 降至 0.15，保留大库 0.25 防垃圾。
            # iter852: sync tiny_db boundary 30→50 (同 iter848/iter819)
            _FALLBACK_NOISE_FLOOR = 0.15 if _db_chunk_count < 50 else 0.25
            if not positive and final:
                _sef_hd = max(final, key=lambda x: x[0])
                if _sef_hd[0] >= _FALLBACK_NOISE_FLOOR:
                    positive = [_sef_hd]
                else:
                    # iter772: dead_zone_fallback — 消除 (0, noise_floor) 死区
                    # iter775: dead_zone_min_score — 防止 FTS5 几乎无匹配时注入垃圾
                    # 根因（数据驱动，2026-05-04）：import-90139 score=0.0097 被注入，
                    #   与当前 query 完全不相关。max(final) < 0.05 说明 FTS5 词汇匹配
                    #   接近零，按 importance 选也无法保证相关性。
                    _sef_hd_max = _sef_hd[0]  # final 中最高 _score_chunk 输出
                    _DEAD_ZONE_MIN = 0.05
                    _sef_hd_imp = [(float(c.get("importance", 0) or 0), c) for _, c in final
                                   if (c.get("access_count", 0) or 0) < 30]
                    if _sef_hd_imp and _sef_hd_max >= _DEAD_ZONE_MIN:
                        _sef_hd_best = max(_sef_hd_imp, key=lambda x: x[0])
                        positive = [(_sef_hd_best[0] * 0.1, _sef_hd_best[1])]
                        _deferred.log(DMESG_WARN, "retriever",
                                      f"iter775_dead_zone_fallback_hd: imp={_sef_hd_best[0]:.2f} "
                                      f"max_s={_sef_hd_max:.4f} id={_sef_hd_best[1].get('id','')[:12]}",
                                      session_id=session_id, project=project)
                    # iter776→782: dead_zone_unified_fallback — 统一 [0, DEAD_ZONE_MIN) 兜底
                    # 根因（数据驱动，2026-05-04）：iter775 只覆盖 [DEAD_ZONE_MIN, noise_floor)，
                    #   iter776 只覆盖 ==0。score 在 (0, 0.05) 的"死区"两边都不触发。
                    #   用户 project abspath:51963532bc1b 9 次空召回（cands=10~14）均因此。
                    # 修复：条件从 ==0 放宽为 < DEAD_ZONE_MIN，与 iter775 无缝衔接。
                    elif _sef_hd_imp and _sef_hd_max < _DEAD_ZONE_MIN and candidates_count > 0:
                        _sef_hd_best = max(_sef_hd_imp, key=lambda x: x[0])
                        positive = [(_sef_hd_best[0] * 0.01, _sef_hd_best[1])]
                        _deferred.log(DMESG_WARN, "retriever",
                                      f"iter776_suppress_zero_fallback_hd: imp={_sef_hd_best[0]:.2f} "
                                      f"id={_sef_hd_best[1].get('id','')[:12]}",
                                      session_id=session_id, project=project)
            # ── iter840: fallback_pair_inject (hard_deadline path) ──
            # 根因：iter826 在 fallback 之前检查 positive==1，fallback 产出的单条不被覆盖。
            if len(positive) == 1 and len(final) >= 3:
                _fb_pair_hd_top1_id = positive[0][1].get("id", "")
                _fb_pair_hd_cands = [(float(c.get("importance", 0) or 0), c) for _, c in final
                                     if c.get("id") != _fb_pair_hd_top1_id
                                     and (c.get("access_count", 0) or 0) < 30
                                     and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh_hd]
                if _fb_pair_hd_cands:
                    _fb_pair_hd_best = max(_fb_pair_hd_cands, key=lambda x: x[0])
                    if _fb_pair_hd_best[0] >= 0.3:
                        _fb_pair_hd_score = positive[0][0] * 0.5
                        positive.append((_fb_pair_hd_score, _fb_pair_hd_best[1]))
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter840_fallback_pair_hd: paired {_fb_pair_hd_best[1].get('id','')[:12]} "
                                      f"imp={_fb_pair_hd_best[0]:.2f}",
                                      session_id=session_id, project=project)
            if _sysctl("retriever.drr_enabled") and len(positive) > effective_top_k:
                top_k = _drr_select(positive, effective_top_k)
            else:
                top_k = positive[:effective_top_k]
            # 迭代321：MMR 内容去冗余（hard deadline 路径也应用）
            if _sysctl("retriever.mmr_enabled") and len(top_k) > 1:
                top_k = _mmr_rerank(top_k, effective_top_k,
                                    lambda_mmr=_sysctl("retriever.mmr_lambda"))
            # ── iter670: suppress_fallback — hard_deadline 路径 suppress 前快照 ──
            _pre_suppress_top_k_hd = list(top_k)
            # ── iter630: monopoly_post_filter — hard_deadline 路径最终门禁 ──
            # iter634: 用标准连接获取最新 ac，防止 immutable WAL 盲区导致垄断逃逸
            _mpf_live = _live_access_counts([c["id"] for _, c in top_k])
            top_k = [(s, c) for s, c in top_k
                     if (_mpf_live.get(c["id"], c.get("access_count", 0) or 0)) < 30]
            # ── iter663: suppress_final_gate — 24h/7d suppress 在最终门禁兜底 ──
            # 根因（数据驱动，2026-05-04）：24h suppress 在 _score_chunk 内依赖
            #   闭包变量 _recent_24h_counts，但该变量在进程启动时一次性从 timeline
            #   文件+recall_traces 计算。并发 session 写入 timeline 无锁 → 读到旧值
            #   → 24h>=2 条件不满足 → suppress 被绕过。
            #   实测：import-6cc32f2ff 24h 注入 4 次（应在第 3 次被拦截）。
            # 修复：hard_deadline 路径用闭包变量做零成本兜底。
            # iter968: micro_db bypass — hard_deadline 路径同步
            if top_k and _db_chunk_count > 5:
                # iter767: tiered_small_db — 分级小库阈值
                _hd_tiny_db = _db_chunk_count < 50  # iter848: 边界 40→50
                _hd_small_db = _db_chunk_count < 100
                # iter806: final_gate 24h/7d 阈值同步 small_db_suppress_tighten
                # iter882: 7d_tighten_monopoly — tiny_db 20/15→3, small 8/6→4/3（sync daemon）
                #   根因：tiny_db 7d=20 允许同一 chunk 注入 19 次，垄断根源。
                # iter905: cross_project_suppress_tighten — hard_deadline 路径同步
                # iter908: final_gate_7d_align_score — tiny_db 4→3
                # iter990: small_db_7d_relax_v3 — hard_deadline 路径同步
                def _hd905_7d_thresh(s, c):
                    _cp = c.get("project", "")
                    _cross = (_cp != project and _cp != "global")
                    _is_global = (_cp == "global")
                    if _hd_tiny_db:
                        _t = 5  # iter1000: tiny 3→5 去垄断反转
                    elif _hd_small_db:
                        _t = 6 if s >= 0.5 else 4  # iter990: 4/3→6/4
                    else:
                        _t = 5 if s >= 0.5 else 3
                    # iter993: global_chunk_suppress_tighten — sync FULL path
                    # iter1006: global_saturated_suppress_tighten — sync hard_deadline
                    if _cross:
                        return max(2, _t - 2)
                    elif _is_global:
                        _g_ac = c.get("access_count", 0) or 0
                        # iter1031: global_deep_saturated_suppress — sync hard_deadline
                        if _g_ac >= 7:
                            return 2
                        return max(2, _t - (2 if _g_ac >= 4 else 1))
                    # iter1009: local_saturated_suppress — sync hard_deadline
                    _l_ac = c.get("access_count", 0) or 0
                    if _l_ac >= 10:
                        return max(2, _t - 2)
                    elif _l_ac >= 7:
                        return max(2, _t - 1)
                    return _t
                # iter1019: saturated_24h_tighten — sync suppress_final_gate
                def _hd1019_24h_thresh(s, c):
                    _b = 3 if _hd_tiny_db else (3 if s >= 0.5 else 2) if _hd_small_db else (3 if s >= 0.5 else 2)
                    _a = c.get("access_count", 0) or 0
                    if _a >= 10:
                        return max(1, _b - 2)
                    elif _a >= 7:
                        return max(1, _b - 1)
                    # iter1027: fallback_24h_align — sync iter1023 global_24h_saturated_cap
                    if c.get("project") == "global" and _a >= 4:
                        return 1
                    return _b
                # iter1042: saturated_6h_cap — hard_deadline 路径同步 ac>=7 → 6h 阈值=1
                def _hd1042_6h_thresh(c):
                    return 1 if (c.get("access_count", 0) or 0) >= 7 else 2
                top_k = [(s, c) for s, c in top_k
                         if _recent_6h_counts.get(c["id"], 0) < _hd1042_6h_thresh(c)  # iter1042
                         and _recent_24h_counts.get(c["id"], 0) < _hd1019_24h_thresh(s, c)
                         # iter904: 7d_rebalance_tiny — tiny_db 7d 2→4
                         # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                         and _recent_7d_counts.get(c["id"], 0) < _hd905_7d_thresh(s, c)]
            # iter842: post_suppress_pair_from_final (hard_deadline path)
            # iter851: suppress_aware_pair — 候选尊重 suppress_final_gate 阈值
            # iter1011: pair_saturated_cap — hard_deadline pair 路径同步
            _hd_pair_base = 4 if _hd_tiny_db else 5
            def _hd_pair_7d_cap(c):
                _cp = c.get("project", "")
                _cap = _hd_pair_base
                if _cp == "global":
                    _g_ac = c.get("access_count", 0) or 0
                    if _g_ac >= 4:
                        _cap = min(_cap, max(2, _hd_pair_base - 2))
                    elif _g_ac >= 2:
                        _cap = min(_cap, max(2, _hd_pair_base - 1))
                elif _cp != project:
                    _cap = min(_cap, max(2, _hd_pair_base - 2))
                else:
                    _l_ac = c.get("access_count", 0) or 0
                    if _l_ac >= 10:
                        _cap = min(_cap, max(2, _hd_pair_base - 2))
                    elif _l_ac >= 7:
                        _cap = min(_cap, max(2, _hd_pair_base - 1))
                return _cap
            if len(top_k) == 1 and len(final) >= 3:
                _ps842_hd_top1_id = top_k[0][1].get("id", "")
                _ps842_hd_cands = [(float(c.get("importance", 0) or 0), c) for _, c in final
                                   if c.get("id") != _ps842_hd_top1_id
                                   and (c.get("access_count", 0) or 0) < 30
                                   and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh_hd
                                   and _recent_6h_counts.get(c.get("id", ""), 0) < 2  # iter865
                                   and _recent_24h_counts.get(c.get("id", ""), 0) < (3 if _hd_tiny_db else 3)
                                   and _recent_7d_counts.get(c.get("id", ""), 0) < _hd_pair_7d_cap(c)]
                if _ps842_hd_cands:
                    _ps842_hd_best = max(_ps842_hd_cands, key=lambda x: x[0])
                    if _ps842_hd_best[0] >= 0.3:
                        _ps842_hd_score = top_k[0][0] * 0.25
                        top_k.append((_ps842_hd_score, _ps842_hd_best[1]))
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter842_pair_from_final_hd: paired "
                                      f"{_ps842_hd_best[1].get('id','')[:12]} "
                                      f"imp={_ps842_hd_best[0]:.2f}",
                                      session_id=session_id, project=project)
            # ── iter670: suppress_fallback — hard_deadline suppress 全灭降级 ──
            # iter829: fallback_rotation (hard_deadline path)
            # iter889: fallback_7d_decay — 按 7d 注入频率衰减排序，打破高频 chunk 垄断轮换
            #   根因（数据驱动，2026-05-05）：28-chunk 库 top5 chunk 占 38% 注入位，
            #   suppress 全灭后 fallback 按 score 选最佳 → 高频 chunk 反复被选中。
            #   修复：score/(1+0.5*7d_count) 使低频 chunk 优先，促进注入多样性。
            if not top_k and _pre_suppress_top_k_hd:
                # iter892: fallback_exp_decay — 线性→指数衰减，高频 chunk 衰减更快促进多样性
                # iter893: fallback_hard_ceiling — 7d>=5 绝对不选，防止垄断 chunk 经 fallback 逃逸
                # iter894: fallback_realtime_align — ceiling 对齐 suppress_final_gate 阈值
                # 根因（数据驱动，2026-05-05）：hard_deadline fallback ceiling=5 但 final_gate 阈值=3，
                #   7d=3-4 chunk 被 final_gate suppress 后被 fallback 重新选中。对齐消除逃逸。
                # iter911: pair_7d_tighten — fallback ceiling 4→3(tiny) 堵 suppress 后 fallback 逃逸
                _fb_hd_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 5)  # iter1000: tiny 3→5 sync final_gate
                # iter1008: fallback_global_ceiling_sync — 对齐 suppress_final_gate global 逻辑
                # 根因（数据驱动，2026-05-06）：global chunk (memory验证,ac=6,7d=4)
                #   被 suppress_final_gate 拦截(阈值=2)，但 fallback ceiling=5 → 逃逸。
                # 修复：global ac>=4 chunk 用 per-chunk ceiling = max(2, base-2)，对齐 final_gate。
                def _fb_hd_chunk_ceiling(c):
                    if c.get("project", "") == "global" and (c.get("access_count", 0) or 0) >= 4:
                        return max(2, _fb_hd_ceiling - 2)
                    # iter1009: local_saturated_suppress — fallback ceiling sync
                    _lac = c.get("access_count", 0) or 0
                    if _lac >= 10:
                        return max(2, _fb_hd_ceiling - 2)
                    elif _lac >= 7:
                        return max(2, _fb_hd_ceiling - 1)
                    return _fb_hd_ceiling
                # iter1027: fallback_24h_align — 对齐 _hd1019_24h_thresh 动态阈值
                _fb_hd_cap = [(s, c) for s, c in _pre_suppress_top_k_hd
                              if _recent_7d_counts.get(c.get("id", ""), 0) < _fb_hd_chunk_ceiling(c)
                              and _recent_24h_counts.get(c.get("id", ""), 0) < _hd1019_24h_thresh(s, c)]
                # iter1032: fallback_relax_24h — hard_deadline path sync
                # 根因（数据驱动，2026-05-07）：密集 session 24h burst 把所有 FTS 候选排除 → 空召回。
                # 修复：_fb_hd_cap 全灭时只保留 7d ceiling，去掉 24h 过滤。
                if not _fb_hd_cap:
                    _fb_hd_cap = [(s, c) for s, c in _pre_suppress_top_k_hd
                                  if _recent_7d_counts.get(c.get("id", ""), 0) < _fb_hd_chunk_ceiling(c)]
                # iter1038: fallback_ceiling_escalate — hard_deadline path sync
                if not _fb_hd_cap and _db_chunk_count < 100:
                    _fb_hd_cap = [(s, c) for s, c in _pre_suppress_top_k_hd
                                  if _recent_7d_counts.get(c.get("id", ""), 0) < _fb_hd_chunk_ceiling(c) + 2]
                # iter921: hd_fallback_no_unfiltered_pool — 对齐 FULL 路径 iter916
                # 根因（数据驱动，2026-05-06）：cap 为空时回退 _pre_suppress_top_k_hd（无过滤），
                #   7d>=3 的垄断 chunk 经此路径逃逸 suppress_final_gate。
                #   FULL 路径已在 iter916 修复（cap 空→None→db_ultimate_fallback）。
                # 修复：hard_deadline 对齐——cap 空时不选，让 iter677/db_fallback 接管。
                _fb_hd_pool = _fb_hd_cap if _fb_hd_cap else None
                # iter939: fallback_relevance_floor — hard_deadline 路径同步
                # iter940: floor_raise — 0.05→0.10 对齐 dead_zone_min/gap_bridge_floor
                #   数据驱动（2026-05-06）：PE chunk score=0.071 逃逸 0.05 floor，24h 被注入 5 次。
                #   score<0.10 说明 FTS5 词汇重叠极低（<1/10），注入无信息增量。
                # iter996: micro_db_floor_relax — sync hard_deadline path
                _fb_hd_floor = 0.01 if _db_chunk_count <= 5 else 0.10
                if _fb_hd_pool and max(s for s, _ in _fb_hd_pool) < _fb_hd_floor:
                    _fb_hd_pool = None
                if _fb_hd_pool:
                    _fb_hd_sorted = sorted(_fb_hd_pool,
                                           key=lambda x: x[0] * (0.5 ** (_recent_7d_counts.get(x[1].get("id", ""), 0) / 2)),
                                           reverse=True)
                    _fb_hd = _fb_hd_sorted[0]
                    _last_hash_hd = _read_hash()
                    if _last_hash_hd and len(_fb_hd_sorted) > 1:
                        _fb_hd_hash = hashlib.md5(_fb_hd[1].get("id", "").encode()).hexdigest()[:8]
                        if _fb_hd_hash == _last_hash_hd:
                            _fb_hd = _fb_hd_sorted[1]
                    top_k = [_fb_hd]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter670_suppress_fallback_hd: all {len(_pre_suppress_top_k_hd)} "
                                  f"suppressed, fallback to best={_fb_hd[1].get('id','')[:12]}",
                                  session_id=session_id, project=project)
            # ── iter677: positive_empty_best_fallback (hard_deadline) ──
            # iter681: 移除 24h/7d suppress 检查 — 最后防线不应被 suppress 过杀
            # iter945: fallback_monopoly_gate — 恢复 7d ceiling 防止垄断 chunk 经此逃逸
            #   根因（数据驱动，2026-05-06）：PE chunk 7d=5/6 时仍被注入，逃逸路径：
            #   suppress_final_gate 全灭 → iter670 fallback ceiling=3 也过滤 → iter677 无 7d 检查直取 final[0]。
            #   修复：从 final 中排除 7d >= ceiling 的 chunk，对齐 suppress_final_gate。
            if not top_k and final:
                _pebf_ceiling_hd = 4 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)  # iter952: sync 5→4
                # iter1008: fallback_global_ceiling_sync — iter677 path 同步
                def _pebf_chunk_ceiling_hd(c):
                    if c.get("project", "") == "global" and (c.get("access_count", 0) or 0) >= 4:
                        return max(2, _pebf_ceiling_hd - 2)
                    # iter1009: local_saturated_suppress — iter677 hd ceiling sync
                    _lac = c.get("access_count", 0) or 0
                    if _lac >= 10:
                        return max(2, _pebf_ceiling_hd - 2)
                    elif _lac >= 7:
                        return max(2, _pebf_ceiling_hd - 1)
                    return _pebf_ceiling_hd
                _pebf_cands_hd = [(s, c) for s, c in final
                                  if _recent_7d_counts.get(c.get("id", ""), 0) < _pebf_chunk_ceiling_hd(c)
                                  and s >= 0.20]
                if _pebf_cands_hd:
                    _pebf_best_hd = _pebf_cands_hd[0]
                    _pebf_score_hd = _pebf_best_hd[0]
                    _pebf_id_hd = _pebf_best_hd[1].get("id", "")
                    top_k = [_pebf_best_hd]
                    _deferred.log(DMESG_INFO, "retriever",
                                  f"iter677_positive_empty_best_fallback_hd: "
                                  f"score={_pebf_score_hd:.3f} id={_pebf_id_hd[:12]}",
                                  session_id=session_id, project=project)
            if top_k:
                # iter919: score_floor_gate_hd — hard_deadline 路径也需 score_floor 保护
                # 根因（数据驱动，2026-05-06）：12/81 注入 score<0.10 全来自 hard_deadline 路径，
                #   iter910 的 score_floor_gate 只在 FULL 路径生效，hard_deadline 完全跳过。
                #   adaptive_floor+gap_bridge 可将 _min_thresh 降到 0.10，fallback/pair 注入无下限。
                # 修复：复用 FULL 路径逻辑——低于 0.12 的过滤，全灭时保留最佳 1 条。
                _sf_hd = 0.12
                if _db_chunk_count > 5:
                    _sf_hd_above = [(s, c) for s, c in top_k if s >= _sf_hd]
                    if _sf_hd_above:
                        if len(_sf_hd_above) < len(top_k):
                            top_k = _sf_hd_above
                    else:
                        top_k = [max(top_k, key=lambda x: x[0])]
                # 快速路径：直接组装输出
                top_k_ids = sorted([c["id"] for _, c in top_k])
                current_hash = hashlib.md5("|".join(top_k_ids).encode()).hexdigest()[:8]
                top_k_data = [{"id": c["id"], "summary": c["summary"], "score": round(s, 4), "chunk_type": c.get("chunk_type", "")} for s, c in top_k]
                if current_hash != _read_hash():
                    # iter975: output_monopoly_filter (hard_deadline path)
                    # iter977: hard_deadline 无 _rt663_7d（无 DB 查询预算），用闭包 _recent_7d_counts
                    if len(top_k) > 1 and not _micro_db:
                        _omf_ceil_hd = 3 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                        _omf_filt_hd = [(s, c) for s, c in top_k
                                        if _recent_7d_counts.get(c.get("id", ""), 0) < _omf_ceil_hd]
                        if _omf_filt_hd:
                            top_k = _omf_filt_hd
                        else:
                            # iter987: omf_graduated_fallback (hard_deadline path)
                            _omf_sorted_hd = sorted(top_k, key=lambda x: _recent_7d_counts.get(x[1].get("id", ""), 0))
                            top_k = _omf_sorted_hd[:min(2, len(_omf_sorted_hd))]
                    # iter1013: topic_group_dedup (hard_deadline path)
                    if len(top_k) > 1 and not _micro_db:
                        _tgd_seen_hd = {}
                        _tgd_res_hd = []
                        for _ts, _tc in top_k:
                            _tsum = (_tc.get("summary") or "")
                            _tkey = _tsum.split("]")[0] + "]" if _tsum.startswith("[") and "]" in _tsum else None
                            if not _tkey or _tkey not in _tgd_seen_hd:
                                _tgd_res_hd.append((_ts, _tc))
                                if _tkey:
                                    _tgd_seen_hd[_tkey] = _tc.get("id", "")
                            else:
                                if _recent_7d_counts.get(_tc.get("id", ""), 0) < _recent_7d_counts.get(_tgd_seen_hd[_tkey], 0):
                                    _tgd_res_hd = [(s, c) for s, c in _tgd_res_hd if c.get("id", "") != _tgd_seen_hd[_tkey]]
                                    _tgd_res_hd.append((_ts, _tc))
                                    _tgd_seen_hd[_tkey] = _tc.get("id", "")
                        if _tgd_res_hd and len(_tgd_res_hd) < len(top_k):
                            top_k = _tgd_res_hd
                    _TYPE_PREFIX = {"decision": "[决策]", "excluded_path": "[排除]",
                                    "reasoning_chain": "[推理]", "conversation_summary": "[摘要]",
                                    "task_state": "", "design_constraint": "⚠️ [约束]"}
                    header = "【相关历史记录（BM25 召回）】"
                    inject_lines = [header]

                    # 迭代98：分离约束知识和普通知识，约束优先展示
                    # 迭代306：hard_deadline 路径也附加 raw_snippet（importance >= 0.75）
                    _hd_high_ids = [c["id"] for _, c in top_k if (c.get("importance") or 0) >= 0.75]
                    _hd_raw: dict = {}
                    if _hd_high_ids:
                        try:
                            _hd_ph = ",".join("?" * len(_hd_high_ids))
                            _hd_rows = conn.execute(
                                f"SELECT id, raw_snippet FROM memory_chunks WHERE id IN ({_hd_ph})",
                                _hd_high_ids,
                            ).fetchall()
                            _hd_raw = {r[0]: r[1] for r in _hd_rows if r[1]}
                        except Exception:
                            pass
                    constraint_items = []
                    normal_items = []
                    hard_deadline_forced = False
                    for s, c in top_k:
                        prefix = _TYPE_PREFIX.get(c.get("chunk_type", ""), "")
                        line = f"- {prefix} {c['summary']}".strip()
                        rs = _hd_raw.get(c["id"], "")
                        if rs:
                            line = f"{line}（原文：{rs[:150]}）"
                        if c.get("chunk_type") == "design_constraint":
                            # 在 hard_deadline 路径中，约束都是被强制注入的（因为评分可能不高）
                            constraint_items.append(line)
                            hard_deadline_forced = True
                        else:
                            normal_items.append(line)

                    # 约束先显示，后跟普通知识
                    if constraint_items:
                        inject_lines.append("")
                        inject_lines.append("【已知约束（系统级设计限制）】")
                        inject_lines.extend(constraint_items)
                        if hard_deadline_forced:
                            inject_lines.append("")
                            inject_lines.append("ℹ️ 注：上述约束经系统强制注入，代表已知设计决策。")
                            inject_lines.append("在时间压力下召回，可能未包含完整上下文。")
                        inject_lines.append("")
                        inject_lines.append("【相关知识】")
                        inject_lines.extend(normal_items)
                    else:
                        inject_lines.extend(normal_items)

                    context_text = "\n".join(inject_lines)
                    if len(context_text) > effective_max_chars:
                        context_text = context_text[:effective_max_chars] + "…"
                    _write_hash(current_hash)
                    _mark_session_injected(session_id)  # iter805
                    _tlb_write(prompt_hash, current_hash, _get_db_mtime())  # 迭代57: TLB
                    _tlb_bump_generation()  # iter583: FULL 完成后 bump generation
                    duration_ms = _elapsed_ms()
                    accessed_ids = [c["id"] for _, c in top_k]
                    # 迭代323: SM-2 recall_quality — 从 top_k 分数推断
                    # avg_score > 0.6 → FTS5 强命中 → quality=5
                    # avg_score 0.3-0.6 → 中等命中 → quality=4
                    # avg_score < 0.3 → 弱命中（BM25 fallback）→ quality=3
                    _hd_avg_score = (sum(s for s, _ in top_k) / len(top_k)) if top_k else 0.0
                    _hd_recall_quality = 5 if _hd_avg_score > 0.6 else (4 if _hd_avg_score > 0.3 else 3)
                    reason = f"{'first_call' if not current_hash else 'hash_changed'}|{priority.lower()}|hard_deadline"
                    _deferred.log(DMESG_WARN, "retriever",
                              f"hard_deadline: {duration_ms:.1f}ms skipped={'+'.join(deadline_skipped)}",
                              session_id=session_id, project=project)
                    # ── 迭代69+84：输出前置 + 只读连接关闭 ──
                    print(json.dumps({"hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": context_text}}, ensure_ascii=False))
                    sys.stdout.flush()
                    conn.close()  # 关闭只读连接
                    # ── 迭代84：Write-Back Phase — 写连接批量写入 ──
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        update_accessed(wconn, accessed_ids, recall_quality=_hd_recall_quality)
                        mglru_promote(wconn, accessed_ids)
                        # 迭代515：userfaultfd — import chunk 首次命中时 promote
                        try:
                            from store_mm import userfaultfd_promote as _uffd
                            _uffd(wconn, accessed_ids)
                        except Exception:
                            pass
                        # iter531：mlock_onfault — ONFAULT chunk 首次命中时升级为 PROTECTED
                        try:
                            from store_mm import mlock_onfault_promote as _mop
                            _mop(wconn, accessed_ids)
                        except Exception:
                            pass
                        # 迭代511：page_idle clear — 从 idle bitmap 移除被命中的 chunks
                        try:
                            from store_mm import page_idle_clear as _pic
                            _pic(accessed_ids, project)
                        except Exception:
                            pass
                        _write_trace(session_id, project, prompt_hash, candidates_count,
                                     top_k_data, 1, reason, duration_ms, conn=wconn)
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                    except Exception:
                        pass  # write-back 失败不影响已输出的结果
                    # 迭代85：Shadow Trace
                    _write_shadow_trace(project, accessed_ids, session_id)
                    # ── iter648: injection timeline write-back (hard_deadline path) ──
                    try:
                        from datetime import timedelta as _td648hd
                        _now648hd = __import__('datetime').datetime.now(__import__('datetime').timezone.utc)
                        _cut_7d = (_now648hd - _td648hd(days=7)).isoformat()
                        _itl_hd = {}
                        if os.path.exists(_INJECTION_TIMELINE_FILE):
                            with open(_INJECTION_TIMELINE_FILE, encoding="utf-8") as _itf_hd:
                                _itl_hd = json.loads(_itf_hd.read())
                        _itl_hd = {k: [t for t in v if t > _cut_7d] for k, v in _itl_hd.items()}
                        _itl_hd = {k: v for k, v in _itl_hd.items() if v}
                        _now_iso = _now648hd.isoformat()
                        for _aid in accessed_ids:
                            _itl_hd.setdefault(_aid, []).append(_now_iso)
                        with open(_INJECTION_TIMELINE_FILE, 'w', encoding="utf-8") as _itf_hw:
                            _itf_hw.write(json.dumps(_itl_hd, ensure_ascii=False))
                    except Exception:
                        pass
                    # iter391: IOR — hard deadline 路径也更新返回抑制状态
                    _update_ior_state(accessed_ids, session_id,
                                      exempt_types=set((_sysctl("retriever.ior_exempt_types") or "").split(",")),
                                      chunk_types={c["id"]: c.get("chunk_type", "") for _, c in top_k})
                    sys.exit(0)

        # ── 迭代32：madvise boost — 预热 hint 匹配加分 ──
        # 迭代41：madvise 受 soft deadline 约束（中优先级）
        hints = []
        if not _check_deadline("madvise"):
            hints = madvise_read(project)
        if hints:
            boost = _sysctl("madvise.boost_factor")
            hint_set = set(h.lower() for h in hints)
            boosted_count = 0
            for i, (score, chunk) in enumerate(final):
                text_lower = f"{chunk['summary']} {chunk.get('content', '')}".lower()
                # 匹配 hint 数量越多 boost 越大（但单个 chunk 最多 boost 一次 factor）
                matches = sum(1 for h in hint_set if h in text_lower)
                if matches > 0:
                    # 按匹配比例加分：match_ratio * boost_factor
                    match_ratio = min(1.0, matches / max(1, len(hint_set) * 0.3))
                    final[i] = (score + boost * match_ratio, chunk)
                    boosted_count += 1
            if boosted_count > 0:
                _deferred.log(DMESG_DEBUG, "retriever",
                          f"madvise: {boosted_count} chunks boosted by {len(hints)} hints",
                          session_id=session_id, project=project)

        # ── 迭代48：Readahead — Co-Access Prefetch ──
        # OS 类比：Linux readahead (generic_file_readahead, 2002→2004)
        #   顺序访问文件时，内核提前读入后续 block 到 page cache，不等请求。
        #   memory-os 等价：检索到 chunk A 时，如果 chunk B 历史上与 A 频繁共现，
        #   自动 prefetch B 进入候选集（给予 bonus 加分）。
        # 迭代41：readahead 受 soft deadline 约束（中优先级，madvise 之后）
        readahead_prefetched = 0
        if not _check_deadline("readahead"):
            try:
                # 取当前候选集中的 Top 临时排序 chunk ids
                _temp_sorted = sorted(final, key=lambda x: x[0], reverse=True)
                _temp_top_ids = [c["id"] for sc, c in _temp_sorted[:effective_top_k] if sc > 0]
                if _temp_top_ids:
                    ra_pairs = readahead_pairs(conn, project, hit_ids=_temp_top_ids)
                    if ra_pairs:
                        existing_ids = {c["id"] for _, c in final}
                        prefetch_bonus = _sysctl("readahead.prefetch_bonus")
                        max_prefetch = _sysctl("readahead.max_prefetch")
                        prefetch_candidates = []  # (partner_id, cooccurrence)
                        for _hit_id, partners in ra_pairs.items():
                            for pid, cnt in partners:
                                if pid not in existing_ids:
                                    prefetch_candidates.append((pid, cnt))
                        # 按共现次数降序，取 max_prefetch 条
                        prefetch_candidates.sort(key=lambda x: x[1], reverse=True)
                        prefetch_ids = [pid for pid, _ in prefetch_candidates[:max_prefetch]]
                        if prefetch_ids:
                            # 从 DB 加载 prefetch chunk
                            placeholders = ",".join("?" * len(prefetch_ids))
                            ra_chunks = conn.execute(
                                f"SELECT id, summary, content, chunk_type, importance, last_accessed, access_count, created_at "
                                f"FROM memory_chunks WHERE id IN ({placeholders}) AND project=? AND COALESCE(access_count,0) < 30",
                                prefetch_ids + [project]
                            ).fetchall()
                            for row in ra_chunks:
                                chunk_dict = {
                                    "id": row[0], "summary": row[1], "content": row[2],
                                    "chunk_type": row[3], "importance": row[4],
                                    "last_accessed": row[5], "access_count": row[6] or 0,
                                    "created_at": row[7] or "",
                                }
                                # 计算基础分 + prefetch_bonus
                                base_score = _unified_retrieval_score(
                                    relevance=0.3,  # 非直接匹配，给予基础 relevance
                                    importance=float(chunk_dict["importance"]),
                                    last_accessed=chunk_dict["last_accessed"],
                                    access_count=chunk_dict["access_count"],
                                    created_at=chunk_dict["created_at"],
                                    chunk_id=chunk_dict["id"],
                                    query_seed=query,
                                    recall_count=_recall_counts.get(chunk_dict["id"], 0),  # 迭代62
                                    chunk_project=chunk_dict.get("project", ""),  # 迭代111
                                    current_project=project,
                                )
                                # iter639: hard_suppress → base_score=0.0，bonus 不得绕过
                                if base_score <= 0:
                                    continue
                                final.append((base_score + prefetch_bonus, chunk_dict))
                                existing_ids.add(chunk_dict["id"])
                                readahead_prefetched += 1
                            if readahead_prefetched > 0:
                                _deferred.log(DMESG_DEBUG, "retriever",
                                          f"readahead: prefetched={readahead_prefetched} pairs_found={len(ra_pairs)}",
                                          session_id=session_id, project=project)
            except Exception:
                pass  # readahead 失败不影响主流程

        # ── 迭代92：Intent Prefetch — 意图预测性预加载 ──
        # OS 类比：readahead(2) 基于访问模式预测后续页面
        # 根据用户意图类型（continue/fix_bug/implement/...）预取对应标签的 chunk
        try:
            intent_chunks = _intent_prefetch(conn, project, prompt, top_k=3)
            intent_prefetched = 0
            if intent_chunks:
                existing_ids = {c["id"] for _, c in final}
                for ic in intent_chunks:
                    if ic["id"] not in existing_ids:
                        # 用 intent_boost 给意图匹配加分
                        score = _unified_retrieval_score(
                            relevance=0.3, importance=ic["importance"],
                            last_accessed=ic["last_accessed"],
                            access_count=ic["access_count"],
                            chunk_id=ic["id"], query_seed=prompt,
                            chunk_project=ic.get("project", ""),  # 迭代111
                            current_project=project,
                        ) + ic["intent_boost"]
                        final.append((score, {"id": ic["id"], "summary": ic["summary"],
                                              "chunk_type": ic["chunk_type"],
                                              "importance": ic["importance"],
                                              "last_accessed": ic["last_accessed"],
                                              "access_count": ic["access_count"],
                                              "embedding": "[]", "tags": "[]"}))
                        existing_ids.add(ic["id"])
                        intent_prefetched += 1
                if intent_prefetched > 0:
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"intent_prefetch: {intent_prefetched} chunks intent={intent_chunks[0]['intent_prefetch']}",
                                  session_id=session_id, project=project)
        except Exception:
            pass  # intent prefetch 失败不影响主流程

        # ── iter383：Spacing Effect Scheduler — 主动复习注入 ────────────────────
        # 认知科学：Ebbinghaus (1885) + SuperMemo SM-2 间隔效应
        #   知识的保留率随时间指数衰减，最优复习时机在遗忘前，
        #   每次成功复习后 stability 增大，下次遗忘窗口更宽（间隔效应）。
        # 触发条件：仅在 retrieval_mode='full' 且 session is_start=True 时
        #   检查高重要性 chunk 是否超过了 stability 天未被访问。
        # OS 类比：Linux pdflush proactive writeback — 不等内存压力，
        #   按 dirty_expire_interval 定期扫描并主动刷出 dirty pages。
        try:
            _is_session_start = (retrieval_mode == "full")
            if _is_session_start:
                from store_vfs import find_spaced_review_candidates
                _spacing_candidates = find_spaced_review_candidates(
                    conn, project, top_n=3, min_importance=0.70
                )
                _spacing_injected = 0
                _existing_ids_spacing = {c["id"] for _, c in final}
                for _sc in _spacing_candidates:
                    if _sc["id"] not in _existing_ids_spacing:
                        # score = 基础评分 + urgency 修正（urgency 越低越迫切，score 取中等值）
                        _sc_ac = _sc.get("access_count", 0) or 0
                        _sc_score = _unified_retrieval_score(
                            relevance=0.2, importance=_sc["importance"],
                            last_accessed=_sc["last_accessed"],
                            access_count=_sc_ac,
                            chunk_id=_sc["id"], query_seed=prompt,
                            chunk_project=project,
                            current_project=project,
                        )
                        final.append((_sc_score, {
                            "id": _sc["id"],
                            "summary": _sc["summary"],
                            "chunk_type": _sc["chunk_type"],
                            "importance": _sc["importance"],
                            "last_accessed": _sc["last_accessed"],
                            "access_count": _sc_ac,
                            "embedding": "[]", "tags": "[]",
                            "spacing_review": True,
                            "days_overdue": _sc.get("days_overdue", 0),
                        }))
                        _existing_ids_spacing.add(_sc["id"])
                        _spacing_injected += 1
                if _spacing_injected > 0:
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"spacing_review: {_spacing_injected} chunks injected "
                                  f"(overdue={[c.get('days_overdue',0) for c in _spacing_candidates[:_spacing_injected]]})",
                                  session_id=session_id, project=project)
        except Exception:
            pass  # spacing review 失败不影响主流程

        # ── 迭代98：强制注入 design_constraint — 符号匹配 ──
        # OS 类比：Linux mlock(2) — 标记的内存不可淘汰，总是驻留在 RAM
        # 检查 final 中是否有 design_constraint；若有，强制保留在 top_k 中
        # 并在注入文本中附加 ⚠️ 约束警告
        # iter632: constraint 提取时过滤 ac>=30 — 堵住 spreading_activate/shmem/schema 路径绕过
        all_constraints = [c for s, c in final if c.get("chunk_type") == "design_constraint"
                          and (c.get("access_count", 0) or 0) < 30]
        # ── iter691: global_constraint_supplement — FTS 未命中的 global constraint 补充 ──
        # 根因（数据驱动，2026-05-04）：4 个 zero-access constraint 中 2 个是 global
        #   (imp=0.9)，FTS5 词匹配无法命中（"用户偏好"vs"memory-os 迭代"零重叠）。
        #   fallback 路径仅在空召回时触发，而空召回率已降至 0% → 永远不被注入。
        # 修复：从 DB 补充 global + high-importance constraint 到候选池，
        #   后续 _ac_gated / 24h/7d suppress 仍正常控制垄断。
        try:
            _existing_ids = {c.get("id") for c in all_constraints}
            # iter1025: supplement_ac_internalized_gate — ac>=4 已内化不再 supplement
            # 根因（数据驱动，2026-05-07）：global constraint supplement 无条件拉取
            #   importance>=0.7 的 global constraint 到候选池。feishu CLI(ac=4,7d=4)、
            #   memory验证(ac=6,7d=4)、git commit(ac=9,7d=4) 等已内化约束仍通过
            #   supplement → Jaccard=0.02 也能逃逸 → 在 kernel 项目等不相关场景被注入。
            #   ac>=4 表明 agent 已多次见过该知识，supplement 路径不应再补充。
            # 修复：ac<4 才允许 supplement（新 constraint 仍可被发现）。
            _gc_sup_rows = conn.execute(
                "SELECT * FROM memory_chunks WHERE chunk_state='ACTIVE' "
                "AND project='global' AND chunk_type='design_constraint' "
                "AND importance >= 0.7 AND COALESCE(access_count, 0) < 4 "
                "ORDER BY importance DESC LIMIT 3"
            ).fetchall()
            if _gc_sup_rows:
                _gc_cols = [d[0] for d in conn.execute(
                    "SELECT * FROM memory_chunks LIMIT 0").description]
                for _r in _gc_sup_rows:
                    _gc_chunk = dict(zip(_gc_cols, _r))
                    if _gc_chunk.get("id") not in _existing_ids:
                        all_constraints.append(_gc_chunk)
                        _existing_ids.add(_gc_chunk.get("id"))
        except Exception:
            pass
        forced_constraints = []  # 记录强制注入的约束（不在自然 top_k 内的）

        # ── 迭代50：DRR Fair Queuing — 类型多样性保障 ──
        # OS 类比：Linux CFQ/DRR (Deficit Round Robin, 1996)
        #   CFQ 保证每个进程获得公平的 I/O 带宽份额。
        #   DRR 给每个 flow/class 独立队列，轮询时各队列获得 quantum 配额。
        #   效果：任何单一进程无法独占全部 I/O 带宽。
        #
        #   memory-os 等价问题：
        #     数据显示 93%+ 的 chunk 是 decision 类型。
        #     纯 score 排序导致 Top-K 全是 decision，
        #     reasoning_chain/conversation_summary 永远无法被召回（排挤效应）。
        #
        #   解决：DRR 公平调度
        #     1. 按 chunk_type 分流（类比 DRR 的 per-flow queue）
        #     2. 每个类型有 max_same_type 上限（类比 quantum 配额）
        #     3. 超出配额的 chunk 让位给其他类型的高分 chunk
        #     4. 如果其他类型不足以填满，配额回流给主类型
        # ── iter388: Temporal Priming — Tulving & Schacter (1990) ──
        # 认知科学：同会话最近召回的 chunk 处于"激活窗口"，再次相关时更易浮现。
        # OS 类比：CPU 时间局部性 — 最近访问的 cache line 有更高的 L2/L3 命中概率。
        try:
            if session_id and _sysctl("retriever.priming_enabled"):
                _priming_boost = _sysctl("retriever.priming_boost")
                _shadow_data = None
                try:
                    with open(SHADOW_TRACE_FILE, 'r', encoding="utf-8") as _sf:
                        _shadow_data = json.loads(_sf.read())
                except Exception:
                    pass
                if _shadow_data and _shadow_data.get("session_id") == session_id:
                    _primed_ids = set(_shadow_data.get("top_k_ids") or [])
                    if _primed_ids:
                        # iter623: priming 只应用于 s>0 的 chunk，防止 suppress 后被抬升
                        final = [
                            (s + _priming_boost if s > 0 and c.get("id") in _primed_ids else s, c)
                            for s, c in final
                        ]
        except Exception:
            pass  # priming 失败不影响主流程
        # ── iter391: Inhibition of Return — Posner (1980) ──────────────────────
        # 认知科学：最近被注入的 chunk 有短暂的返回抑制，促进检索多样性。
        # OS 类比：Linux CFQ anti-starvation — 刚被服务的请求在 timeslice 内降优先级。
        try:
            if session_id and _sysctl("retriever.ior_enabled"):
                _ior_penalty = _sysctl("retriever.ior_penalty")
                _ior_decay_turns = _sysctl("retriever.ior_decay_turns")
                _ior_exempt = set(_sysctl("retriever.ior_exempt_types").split(","))
                _ior_data = None
                try:
                    with open(IOR_FILE, 'r', encoding="utf-8") as _ior_f:
                        _ior_data = json.loads(_ior_f.read())
                except Exception:
                    pass
                if (_ior_data and _ior_data.get("session_id") == session_id
                        and isinstance(_ior_data.get("injections"), dict)):
                    _ior_injs = _ior_data["injections"]
                    _ior_cur_turn = _ior_data.get("current_turn", 0)
                    if _ior_injs:
                        final = [
                            (s * (1.0 - _ior_penalty * math.exp(
                                -math.log(2) / max(1, _ior_decay_turns) *
                                max(0, _ior_cur_turn - _ior_injs.get(c.get("id"), -999))
                            )) if (c.get("id") in _ior_injs and
                                   c.get("chunk_type") not in _ior_exempt) else s, c)
                            for s, c in final
                        ]
        except Exception:
            pass  # IOR 失败不影响主流程
        final.sort(key=lambda x: x[0], reverse=True)
        # 迭代86：最低相关性门槛 — A/B评测发现无关query注入噪音
        # 迭代88：自适应门槛 — 通用知识 query 用更高阈值防止误注入
        if _is_generic_knowledge_query(query):
            _min_thresh = _sysctl("retriever.generic_query_min_threshold")
        else:
            _min_thresh = _sysctl("retriever.min_score_threshold")
        # iter819: tiny_db_threshold_relax (FULL path) — 同 hard_deadline 路径
        if _db_chunk_count < 50 and not _is_generic_knowledge_query(query):
            _min_thresh = min(_min_thresh, 0.18)
        # ── iter578: mremap — Adaptive Score Floor ────────────────────────
        # OS 类比：Linux mremap() (Linus Torvalds, 1995, mm/mremap.c)
        #   固定 VMA 大小浪费虚拟地址空间或导致 OOM，mremap 动态调整映射大小。
        #   固定 min_score_threshold=0.3 在 top1=0.99 时过滤 90% 候选（信息损失），
        #   在 top1=0.2 时放行噪音。自适应地板 = top1 × ratio，随分布动态伸缩。
        # 效果：top1=0.99 → floor=0.25(允许更多次优结果)；top1=0.3 → floor=0.3(不变)
        if (final and _sysctl("retriever.adaptive_floor_enabled")
                and not _is_generic_knowledge_query(query)):
            _top1_score = final[0][0]
            _af_min_top1 = _sysctl("retriever.adaptive_floor_min_top1")
            if _top1_score >= _af_min_top1:
                _af_ratio = _sysctl("retriever.adaptive_floor_ratio")
                # iter823: small_db_af_relax — 小库 BM25 分布稀疏，0.25 过滤 top2
                if _db_chunk_count < 100:
                    _af_ratio = min(_af_ratio, 0.12)
                _adaptive_floor = _top1_score * _af_ratio
                _min_thresh = min(_min_thresh, max(_adaptive_floor, 0.10))
        # ── iter579: copy_page_range — Score Gap Bridging ─────────────────
        # OS 类比：Linux copy_page_range() (Andrea Arcangeli, 2004, mm/memory.c)
        #   fork() 复制父进程地址空间时，大 VMA 间的 gap 不阻止复制下一个有效 VMA。
        #   内核遍历 page table 各层级，跳过 unmapped region，复制下一个有效 PTE。
        #   没有 gap bridging，阈值将 gap > threshold 视为"有效数据终止"。
        # 问题：top1=0.99（精确关键词命中）vs top2=0.15（语义相关但词汇不匹配）
        #   adaptive_floor=0.247 过滤全部 top2+ 候选 → 永远只注入 1 个结果
        # 解法：检测 top1/top2 > gap_ratio（score gap），若 gap 后存在内聚 cluster
        #   （成员分数彼此在 cluster_ratio 内），将 threshold 降至 cluster_top × cluster_ratio
        if (len(final) >= 3 and _sysctl("retriever.gap_bridge_enabled")
                and not _is_generic_knowledge_query(query)):
            _gb_top1 = final[0][0]
            _gb_top2 = final[1][0] if final[1][0] > 0 else 0.001
            _gb_min_ratio = _sysctl("retriever.gap_bridge_min_ratio")
            if _gb_top1 / _gb_top2 >= _gb_min_ratio:
                # Gap detected — find cluster below the gap
                _gb_cluster_ratio = _sysctl("retriever.gap_bridge_cluster_ratio")
                _gb_min_cluster = _sysctl("retriever.gap_bridge_min_cluster")
                _gb_cluster_top = final[1][0]  # top of the lower cluster
                _gb_cluster_floor = _gb_cluster_top * _gb_cluster_ratio
                _gb_cluster_size = sum(
                    1 for s, _ in final[1:]
                    if s >= _gb_cluster_floor
                )
                if _gb_cluster_size >= _gb_min_cluster:
                    # iter863: gap_bridge_floor_raise (FULL path)
                    _gb_new_thresh = max(_gb_cluster_floor, 0.10)
                    if _gb_new_thresh < _min_thresh:
                        _min_thresh = _gb_new_thresh
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"gap_bridge: top1={_gb_top1:.3f} top2={_gb_top2:.3f} "
                                      f"ratio={_gb_top1/_gb_top2:.1f} cluster={_gb_cluster_size} "
                                      f"new_thresh={_gb_new_thresh:.3f}",
                                      session_id=session_id, project=project)
        # iter620: zero_score_absolute_gate (FULL path) — 同 hard_deadline 路径
        positive = [(s, c) for s, c in final if s >= _min_thresh and s > 0]
        # iter843: pair_dedup_aware — 配对候选预过滤 dedup threshold
        # 根因（数据驱动，2026-05-05）：55% 注入仅 1 条。iter826/827/840 配对成功后，
        #   session_dedup(iter359, threshold=2) 事后移除配对 chunk → 单条逃逸。
        #   配对选中的 chunk 在当前 session 已注入 >=threshold 次时，配对无效。
        # 修复：配对候选筛选时排除已达 dedup 阈值的 chunk，选真正"新鲜"的组合。
        _pair_dedup_thresh = _sysctl("retriever.session_dedup_threshold") or 2
        # iter826: single_result_pair_inject — 单条结果时补充次优候选
        # 根因（数据驱动，2026-05-05）：48h 内 50% 注入只有 1 条 chunk，
        #   cands=29-33 中仅 1 条过 _min_thresh（其余 score=0 被 suppress 或 relevance 极低）。
        #   单条注入缺乏上下文组合，用户感知记忆系统只能给"单点"知识。
        # 修复：positive=1 时从 final 中取 score>0 但 < _min_thresh 的次优候选补充 1 条，
        #   确保至少 2 条组合上下文。下限 0.10 防止噪声注入（iter863 从 0.05 提升）。
        # iter972: pair_suppress_align — 7d/24h 过滤堵逃逸口
        _pair_7d_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 6)  # iter1010: pair_ceiling_widen — 4/5→5/6 恢复 pair 候选池
        # iter1011: pair_saturated_cap — saturated chunk 的 pair ceiling 对齐 suppress 阈值
        # 根因（数据驱动，2026-05-06）：11 个 chunk 7d>=suppress_thresh 但 <pair_ceiling(5/6)，
        #   通过 pair/diversity_pair 逃逸注入。feishu CLI(ac=4,7d=4), memory验证(ac=6,7d=4) 等
        #   global 工具约束被 suppress_final_gate 拦截后仍经 pair 路径垄断注入。
        # 修复：per-chunk 动态 ceiling = min(base_ceiling, chunk 自身 suppress_thresh)。
        def _pair_7d_cap(c):
            _cp = c.get("project", "")
            _cap = _pair_7d_ceiling
            if _cp == "global":
                _g_ac = c.get("access_count", 0) or 0
                if _g_ac >= 4:
                    _cap = min(_cap, max(2, _pair_7d_ceiling - 2))
                elif _g_ac >= 2:
                    _cap = min(_cap, max(2, _pair_7d_ceiling - 1))
            elif _cp != project:  # cross-project
                _cap = min(_cap, max(2, _pair_7d_ceiling - 2))
            else:
                # iter1034: pair_context_relax — 本项目 pair cap 放宽
                # 根因（数据驱动，2026-05-07）：24-chunk 库 10/24 chunk 因 ac>=7/10 → cap=4/3
                #   被 pair 排除，导致 48% 注入为单条。本项目知识作为配对上下文有价值，
                #   suppress_final_gate 已控制垄断（score=0 不可能进 pair_candidates s>0.10）。
                # 修复：本项目 ac>=10 惩罚 -2→-1，ac>=7 移除惩罚。
                _l_ac = c.get("access_count", 0) or 0
                if _l_ac >= 10:
                    _cap = min(_cap, max(2, _pair_7d_ceiling - 1))
            return _cap
        if len(positive) == 1 and len(final) >= 3:
            _pair_candidates = [(s, c) for s, c in final
                                if s > 0.10 and s < _min_thresh
                                and c.get("id") != positive[0][1].get("id")
                                and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                                and _recent_7d_counts.get(c.get("id", ""), 0) < _pair_7d_cap(c)
                                # iter1027: fallback_24h_align — global ac>=4 阈值=1
                                and _recent_24h_counts.get(c.get("id", ""), 0) < (1 if c.get("project") == "global" and (c.get("access_count", 0) or 0) >= 4 else 3)]
            if _pair_candidates:
                _pair_best = max(_pair_candidates, key=lambda x: x[0])
                positive.append(_pair_best)
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter826_pair_inject: paired {_pair_best[1].get('id','')[:12]} "
                              f"s={_pair_best[0]:.3f} with top1 s={positive[0][0]:.3f}",
                              session_id=session_id, project=project)
            else:
                # iter827: importance_pair_fallback — suppress 清零后按 importance 补充
                # 根因（数据驱动，2026-05-05）：77% 注入为单条。suppress 把 top2+ 全部
                #   清零(score=0.0) → pair_inject 的 s>0.05 条件无候选 → 无法组合。
                # 修复：从 final 中按 importance 取非 top1 的最佳 chunk，给予 top1*0.3
                #   的象征性 score，确保组合上下文。排除 access_count>=30 的过饱和 chunk。
                _imp_pairs = [(float(c.get("importance", 0) or 0), c) for _, c in final
                              if c.get("id") != positive[0][1].get("id")
                              and (c.get("access_count", 0) or 0) < 30
                              and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                              and _recent_7d_counts.get(c.get("id", ""), 0) < _pair_7d_cap(c)
                              # iter1027: fallback_24h_align — global ac>=4 阈值=1
                              and _recent_24h_counts.get(c.get("id", ""), 0) < (1 if c.get("project") == "global" and (c.get("access_count", 0) or 0) >= 4 else 3)]
                if _imp_pairs:
                    _imp_best = max(_imp_pairs, key=lambda x: x[0])
                    # iter941: imp_pair_top1_gate — top1 score 过低时不配对
                    # 根因（数据驱动，2026-05-06）：12 条 score<0.10 注入中 8 条来自 imp_pair，
                    #   top1=0.20 → pair_score=0.06，用户感知为噪声。
                    #   单条中等相关 > 两条低相关。top1<0.15 时 pair_score<0.045 无信息增量。
                    if _imp_best[0] >= 0.3 and positive[0][0] >= 0.15:
                        _pair_score = positive[0][0] * 0.3
                        positive.append((_pair_score, _imp_best[1]))
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter827_imp_pair: paired {_imp_best[1].get('id','')[:12]} "
                                      f"imp={_imp_best[0]:.2f} with top1 s={positive[0][0]:.3f}",
                                      session_id=session_id, project=project)
        # iter864: diversity_pair_from_db — FTS 未命中的高 importance chunk 曝光
        # 根因（数据驱动，2026-05-05）：33-chunk 库中 6/20 从未被注入（imp 0.64~0.88），
        #   因 FTS 从未命中它们 → 不在 final → iter827 无法选到 → 永远零曝光。
        #   52% 注入为单条，组合上下文严重不足。
        # 修复：positive 仍为单条时，从 DB 查同 project 的、24h 未注入的、高 importance
        #   chunk 作为 diversity pair。给予 top1*0.25 的低 score，确保不喧宾夺主。
        #   排除 top1 自身、session 内已注入的 chunk。仅 tiny_db(<50) 启用（大库 FTS 覆盖足够）。
        if len(positive) == 1 and _db_chunk_count < 50:
            _top1_id = positive[0][1].get("id", "")
            try:
                from datetime import datetime as _dt864, timezone as _tz864
                _now_ts = _dt864.now(_tz864.utc).isoformat()
                import sqlite3 as _div_sql
                _div_conn = _div_sql.connect(str(STORE_DB))
                # 查同 project 中 importance >= 0.5、非 top1、未被 session 内注入的 chunk
                _div_rows = _div_conn.execute(
                    "SELECT id, summary, content, chunk_type, importance, access_count "
                    "FROM memory_chunks WHERE project = ? AND chunk_state = 'ACTIVE' "
                    "AND importance >= 0.5 AND id != ? "
                    "ORDER BY access_count ASC, importance DESC LIMIT 8",
                    (project, _top1_id)).fetchall()
                _div_conn.close()
                # 过滤 session 内已注入的 和 24h 已注入 >=3 次的
                # iter943: diversity_pair_7d_suppress — 对齐 suppress_final_gate 7d 阈值
                # 根因（数据驱动，2026-05-06）：PE chunk 7d=6 被 suppress_final_gate 拦截，
                #   但 diversity_pair_from_db 不检查 7d → 经分钟轮转逃逸注入。24h 5x。
                # 修复：排除 7d >= ceiling 的 chunk（同 suppress_final_gate 阈值）。
                _div_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                # iter947: pair_7d_tighten — diversity_pair 7d ceiling 对齐 suppress_final_gate(3/4/5)
                _div_7d_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 6)  # iter1010: pair_ceiling_widen — 4/5→5/6 恢复 pair 候选池
                _div_cands = []
                for _dr in _div_rows:
                    _dr_id = _dr[0]
                    if _session_injection_counts.get(_dr_id, 0) >= _pair_dedup_thresh:
                        continue
                    # iter1011: per-chunk saturated cap for diversity pair
                    # Note: _dr from query WHERE project=?, so always local project
                    # iter1034: pair_context_relax — 同步放宽（同 _pair_7d_cap 本项目逻辑）
                    _dr_ac = _dr[5]  # access_count from query
                    _dr_cap = _div_7d_ceiling
                    if _dr_ac >= 10:
                        _dr_cap = min(_dr_cap, max(2, _div_7d_ceiling - 1))
                    if _div_7d.get(_dr_id, 0) >= _dr_cap:
                        continue
                    _tl_24h = sum(1 for t in _injection_timeline.get(_dr_id, [])
                                  if t > (_now_ts[:10] if len(_now_ts) > 10 else _now_ts))  # rough 24h
                    if _tl_24h >= 3:
                        continue
                    _div_cands.append(_dr)
                if _div_cands:
                    # iter872: diversity_fine_rotation — 分钟级轮转替代小时级
                    # 根因（数据驱动，2026-05-05）：hour%len 同小时内永远选同一 chunk，
                    #   高频使用时 diversity pair 退化为固定注入。
                    # 修复：用 (hour*60+minute) % len，每分钟选不同候选。
                    _div_idx = (int(_now_ts[11:13]) * 60 + int(_now_ts[14:16])) % len(_div_cands) if len(_now_ts) > 16 else 0
                    _div_pick = _div_cands[_div_idx]
                    _div_chunk = {"id": _div_pick[0], "summary": _div_pick[1],
                                  "content": _div_pick[2], "chunk_type": _div_pick[3],
                                  "importance": _div_pick[4], "access_count": _div_pick[5]}
                    _div_score = positive[0][0] * 0.25
                    positive.append((_div_score, _div_chunk))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter864_diversity_pair: db_pick {_div_pick[0][:12]} "
                                  f"imp={_div_pick[4]:.2f} ac={_div_pick[5]} with top1 s={positive[0][0]:.3f}",
                                  session_id=session_id, project=project)
            except Exception:
                pass  # best-effort, don't break retrieval
        # iter695: threshold_degrade — 阈值过高全灭时降级到默认 0.30
        if not positive and _min_thresh > 0.30:
            positive = [(s, c) for s, c in final if s >= 0.30 and s > 0]
        # iter759: 移除 candidates_rescue（同 hard_deadline 路径）
        # ── iter700: score_empty_fallback (FULL path) ──
        # 根因（数据驱动，2026-05-04）：用户工作项目 15 次空召回，有 3-21 个 candidates
        #   但 top1 < 0.15 → rescue 不触发。hard_deadline 有 iter689，此处遗漏。
        # iter751: suppress 全灭兜底 — score=0 时用 importance 排序选最佳 1 条
        #   根因（数据驱动，2026-05-04）：13 次连续空召回 cands=3~10 全因 suppress
        #   score=0.0 → 原 > 0 条件阻止 fallback。空召回 = 系统零价值。
        # iter770: fallback_noise_gate — fallback 也需硬性下限
        # iter771: tiny_db_fallback_relax — 小库降至 0.15（同 hard_deadline 路径）
        # iter852: sync tiny_db boundary 30→50 (同 iter848/iter819)
        _FALLBACK_NOISE_FLOOR_FULL = 0.15 if _db_chunk_count < 50 else 0.25
        if not positive and final:
            _sef_full = max(final, key=lambda x: x[0])
            if _sef_full[0] >= _FALLBACK_NOISE_FLOOR_FULL:
                positive = [_sef_full]
                _deferred.log(DMESG_WARN, "retriever",
                              f"iter700_score_empty_fallback_full: fallback "
                              f"best={_sef_full[1].get('id','')[:12]} s={_sef_full[0]:.4f}",
                              session_id=session_id, project=project)
            else:
                # iter772: dead_zone_fallback — 消除 (0, noise_floor) 死区
                # iter775: dead_zone_min_score — 同 hard_deadline 路径
                _sef_full_max = _sef_full[0]
                _DEAD_ZONE_MIN_FULL = 0.05
                _sef_by_imp = [(float(c.get("importance", 0) or 0), c) for _, c in final
                               if (c.get("access_count", 0) or 0) < 30]
                if _sef_by_imp and _sef_full_max >= _DEAD_ZONE_MIN_FULL:
                    _sef_best = max(_sef_by_imp, key=lambda x: x[0])
                    positive = [(_sef_best[0] * 0.1, _sef_best[1])]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter775_dead_zone_fallback_full: imp={_sef_best[0]:.2f} "
                                  f"max_s={_sef_full_max:.4f} id={_sef_best[1].get('id','')[:12]}",
                                  session_id=session_id, project=project)
                # iter776→782: dead_zone_unified_fallback — 统一 [0, DEAD_ZONE_MIN) 兜底
                elif _sef_by_imp and _sef_full_max < _DEAD_ZONE_MIN_FULL and candidates_count > 0:
                    _sef_best = max(_sef_by_imp, key=lambda x: x[0])
                    positive = [(_sef_best[0] * 0.01, _sef_best[1])]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter776_suppress_zero_fallback_full: imp={_sef_best[0]:.2f} "
                                  f"id={_sef_best[1].get('id','')[:12]}",
                                  session_id=session_id, project=project)

        # ── iter840: fallback_pair_inject (FULL path) ──
        # 根因：iter826 只覆盖 positive=1(score 过阈)。45% 单条来自 positive=0→fallback=1。
        # iter972: pair_suppress_align — 对齐 suppress_final_gate 7d/24h 阈值堵逃逸
        #   根因（数据驱动，2026-05-06）：31-chunk 库 15 个 7d>=3 被 suppress_final_gate 拦截，
        #   但 fallback_pair 不检查 7d/24h → 垄断 chunk 经 pair 路径重新注入。
        _fb_pair_7d_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 6)  # iter1010: pair_ceiling_widen — 4/5→5/6 恢复 pair 候选池
        if len(positive) == 1 and len(final) >= 3:
            _fb_pair_top1_id = positive[0][1].get("id", "")
            _fb_pair_cands = [(float(c.get("importance", 0) or 0), c) for _, c in final
                              if c.get("id") != _fb_pair_top1_id
                              and (c.get("access_count", 0) or 0) < 30
                              and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                              and _recent_7d_counts.get(c.get("id", ""), 0) < _fb_pair_7d_ceiling
                              # iter1027: fallback_24h_align — global ac>=4 阈值=1
                              and _recent_24h_counts.get(c.get("id", ""), 0) < (1 if c.get("project") == "global" and (c.get("access_count", 0) or 0) >= 4 else 3)]
            if _fb_pair_cands:
                _fb_pair_best = max(_fb_pair_cands, key=lambda x: x[0])
                if _fb_pair_best[0] >= 0.3:
                    _fb_pair_score = positive[0][0] * 0.5
                    positive.append((_fb_pair_score, _fb_pair_best[1]))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter840_fallback_pair: paired {_fb_pair_best[1].get('id','')[:12]} "
                                  f"imp={_fb_pair_best[0]:.2f} with fallback top1={_fb_pair_top1_id[:12]}",
                                  session_id=session_id, project=project)

        # ── 迭代334：IWCSI — Importance-Weighted Cold-Start Injection ───────
        # 信息论依据（Shannon 1948）：高 importance + 零召回 chunk 的期望信息增益最高：
        #   I(chunk|context) ≈ H(chunk) × P(not_known) = importance × 1.0（从未被注入过）
        #   但语义鸿沟（encoding-retrieval mismatch, Tulving 1983）导致 P(retrieved|query) ≈ 0
        #   → 系统性信息损失：高价值知识被永久遮蔽在 top-K 之外
        # OS 类比：Linux DAMON damos_action=PAGE_PROMOTE (2022, SeongJae Park) —
        #   DAMON 检测到 cold region（长期无访问）→ 强制发起一次 access
        #   打破 cold-start 死锁（cold 不访问 → access_count=0 → LRU 永驻冷端）
        #   memory-os 等价：zero-recall → acc=0 → starvation_boost 无法补偿语义鸿沟
        #   → IWCSI 强制曝光1个最高 imp 的零召回 chunk（打破死锁）
        # 触发条件：FULL 模式 + positive 不足 effective_top_k + 未超 soft deadline
        _cold_start_injected = 0
        if (priority == "FULL"
                and _sysctl("retriever.cold_start_enabled")
                and len(positive) < effective_top_k
                and not _check_deadline("cold_start")):
            try:
                _cs_imp_threshold = _sysctl("retriever.cold_start_imp_threshold")
                _cs_max = _sysctl("retriever.cold_start_max_inject")
                _positive_ids = {c["id"] for _, c in positive}
                # 从 final 候选中筛选：高 imp、零访问、不在 positive 中
                _cold_candidates = [
                    (imp_val, c) for s, c in final
                    if c.get("id", "") not in _positive_ids
                    and (c.get("access_count", 0) or 0) == 0
                    and float(c.get("importance", 0) or 0) >= _cs_imp_threshold
                    for imp_val in [float(c.get("importance", 0) or 0)]
                ]
                if _cold_candidates:
                    # 按 importance 降序，取 top _cs_max 个
                    _cold_candidates.sort(key=lambda x: x[0], reverse=True)
                    for _cold_imp, _cold_chunk in _cold_candidates[:_cs_max]:
                        # 注入分数 = importance（让其能进入 positive，但不垫底也不顶替高分）
                        positive.append((_cold_imp, _cold_chunk))
                        _positive_ids.add(_cold_chunk["id"])
                        _cold_start_injected += 1
                    if _cold_start_injected > 0:
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"cold_start: injected={_cold_start_injected} "
                                      f"imp>={_cs_imp_threshold:.2f}",
                                      session_id=session_id, project=project)
            except Exception:
                pass  # cold_start 失败不阻塞主流程

        if _sysctl("retriever.drr_enabled") and len(positive) > effective_top_k:
            top_k = _drr_select(positive, effective_top_k)
        else:
            top_k = positive[:effective_top_k]
        # 迭代321：MMR 内容去冗余（在 DRR 多样性保障之后，对内容语义去重）
        # OS 类比：L2 cache dedup — 不同 cache line 指向相同物理页时合并
        if _sysctl("retriever.mmr_enabled") and len(top_k) > 1:
            top_k = _mmr_rerank(top_k, effective_top_k,
                                lambda_mmr=_sysctl("retriever.mmr_lambda"))

        # 迭代98+128+130：强制注入约束 — 将约束追加到 top_k
        # 迭代128 改进：添加 max_forced_constraints 上限 + BM25 相关性排序
        # 迭代130 改进：DRR 感知 — 计算自然 top_k 中已有的约束数量，动态调整 forced 配额
        # 迭代337 改进：Jaccard 内容重叠过滤 — 约束 summary 与 top_k 已选内容高度重叠时跳过
        # OS 类比：Linux RLIMIT_MEMLOCK + cgroup per-type 资源配额联合约束
        #   RLIMIT_MEMLOCK(iter128) 限制强制注入总量
        #   DRR-aware(iter130) 计算已用配额，防止自然+强制叠加后超限
        #   iter337: Page dedup (KSM) — 内容相似度 > threshold 的约束视为冗余，不重复注入
        # 问题：DRR 限制 natural top_k 中每类型最多 max_same_type=2，
        #       但 forced_constraints 在 DRR 之后 insert(0)，不受 DRR 约束。
        #       实测 04:42 日志: drr={'design_constraint':4,'decision':1} → 约束占 80%
        top_k_ids = {c["id"] for _, c in top_k}
        _max_forced = _sysctl("retriever.max_forced_constraints")
        _drr_max_same = _sysctl("retriever.drr_max_same_type")
        # 计算自然 top_k 中已有的 design_constraint 数量
        _natural_constraint_count = sum(1 for _, c in top_k if c.get("chunk_type") == "design_constraint")
        # 动态调整：允许强制注入的最多 = max_forced，但自然+强制总量不超过 DRR 配额 × 1.5
        # 乘以 1.5 是因为约束是优先级信息，允许比普通类型多一点配额，但不无限
        _constraint_total_cap = max(_drr_max_same, int(_drr_max_same * 1.5))
        _remaining_forced_slots = max(0, _constraint_total_cap - _natural_constraint_count)
        _effective_max_forced = min(_max_forced, _remaining_forced_slots)

        # 对不在自然 top_k 中的约束按 BM25 简单相关性排序（用 summary 与 query 的词重叠）
        _extra_constraints = [c for c in all_constraints if c["id"] not in top_k_ids]
        if _extra_constraints and _effective_max_forced > 0:
            # 快速 BM25-like 相关性：query 词与 summary 词的 Jaccard 相似度
            _query_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ', query.lower()).split())
            def _constraint_relevance(c):
                s_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ', (c.get("summary") or "").lower()).split())
                if not _query_words or not s_words:
                    return 0.0
                return len(_query_words & s_words) / len(_query_words | s_words)
            _extra_constraints.sort(key=_constraint_relevance, reverse=True)

            # ── iter543: refault_distance — Relevance Gate for Force-Injection ──
            # OS 类比：Linux workingset.c refault_distance (Johannes Weiner, 2018)
            # 页面 refault 时只有 distance < working_set_size 才 promote 到 active list，
            # 否则视为 streaming access 保持 inactive 防止 cache pollution。
            # 等价：constraint 的 query-Jaccard < min_relevance → 不在当前"工作集"内 → 不注入。
            _constraint_min_rel = _sysctl("retriever.constraint_min_relevance")
            _thrash_max_pct = _sysctl("retriever.constraint_thrash_max_pct")
            # Thrash detection: 用 recall_counts 作为 cross-query presence 的近似
            # recall_count/window > thrash_max_pct → 该 constraint 是 cache polluter
            _bw_window = _sysctl("scorer.bw_window") or 30
            _pre_gate_count = len(_extra_constraints)
            # iter595: access_count monopoly gate — 高频访问 chunk 提高 relevance 门槛
            # iter596: inject_hard_cap — 注入频率硬上限
            # iter598: zero_relevance_gate — Jaccard=0 绝对拦截 + hard_cap 0.50→0.30
            # 根因（数据驱动，2026-05-03）：b50e0b54 (feishu CLI) 在 memory-os 项目中
            #   Jaccard=0.02（仅 "cli"/"禁止" 偶然重叠），但 26/30=87% trace 中被注入。
            #   iter543 min_relevance=0.05 应拦截但特定 session 的 query 词集不同导致漏网。
            # 修复：
            #   1. Jaccard 严格为 0 → 无条件拦截（不依赖 min_relevance 阈值配置）
            #   2. hard_cap 从 0.50 降至 0.30，与 thrash_max_pct(0.20) 更紧密对齐
            _inject_hard_cap = _sysctl("retriever.constraint_inject_hard_cap")
            # iter756: small_db_bw_tighten (constraint path); iter774: tiny_db_bw_relax
            # iter801: micro_db_suppress_bypass — <=5 chunk 库禁用 bandwidth suppress
            if _local_bw_window <= 30 and (not _inject_hard_cap or _inject_hard_cap > 0.12):
                # iter861: small_db_bw_tighten — <50 收紧 0.25→0.15 (constraint path sync)
                _inject_hard_cap = 1.0 if _db_chunk_count <= 5 else (0.15 if _db_chunk_count < 50 else 0.12)
            # iter608: session_constraint_cap — 同 session 内同一 constraint 注入上限
            # 根因：_ac_gated 的全局 hard_cap 依赖 recall_count 累积到阈值才生效，
            #   但单次长 session（如 memory-os 迭代 agent）可连续触发多次 retrieval，
            #   同一 constraint 在 session 内被注入 4-10 次才被 dedup 拦截（threshold*2）。
            # 修复：constraint 在当前 session 已注入 ≥ 2 次 → 直接 suppress。
            _session_constraint_cap = 2
            # iter641: live ac for constraint gate — 绕过 chunk dict WAL 盲区
            _constraint_live_ac = _live_access_counts(
                [c.get("id", "") for c in _extra_constraints]
            ) if _extra_constraints else {}
            def _ac_gated(c):
                _cid = c.get("id", "")
                # iter641: constraint_ac_cap — 强制注入通道更严格的 ac 阈值
                # 根因（数据驱动，2026-05-03）：b50e0b54 在 5/2 从 ac=4 增长到 ac=46，
                #   主路径 ac>=30 需要 ~26 次注入才触发。constraint 通道 score=0.99
                #   绕过主路径打分，只受 _ac_gated 控制。
                #   24h_burst(>=2) 依赖 recall_traces WAL 可见性，实测 5/2 连续 12 次
                #   INJECTED 说明 _recent_24h_counts 可能因 WAL/timing 不完整。
                # 修复：constraint 通道 ac 阈值 30→15（用 live ac 绕过 WAL）。
                #   数据验证：11 个 design_constraint 中只有 ac=89/46 超 15，
                #   ac=11 (9a1c5b4f) 仍可通过。
                _ac_abs = _constraint_live_ac.get(_cid, c.get("access_count", 0) or 0)
                if _ac_abs >= 15:
                    return False
                # iter813: 6h burst suppress (constraint path)
                # iter818: tiny_db_6h_relax — 6h 分级
                _cst_tiny_db = _db_chunk_count < 50  # iter848: 边界 40→50
                if _recent_6h_counts.get(_cid, 0) >= 2:  # iter865: 6h_tighten_tiny
                    return False
                # iter617: 24h burst suppress 也在 constraint 通道生效
                # iter806: sync small_db_suppress_tighten
                # iter903: constraint_24h_tighten — tiny_db 3→2
                # 根因（数据驱动，2026-05-05）：39-chunk 库 24h 内 "Android 性能诊断"
                #   "git commit author" 等与当前工作无关的 constraint 各注入 3 次。
                #   constraint 通道只用 Jaccard>0.05 过滤（远弱于主路径 FTS5 评分），
                #   24h=3 允许不相关 constraint 每天注入 2 次 → 63% 注入为无关知识。
                #   收紧到 2：每个 constraint 24h 仅允许 1 次注入，第 2 次 suppress。
                _cst_small_db = _db_chunk_count < 100
                if _recent_24h_counts.get(_cid, 0) >= ((2 if _cst_tiny_db else 3) if _cst_small_db else 2):
                    return False
                # iter618: 7d rolling suppress 也在 constraint 通道生效
                # iter806: 7/5 → 5/4 sync
                # iter816: small_db_7d_relax — sync constraint path
                # iter854: tiny_db_7d_relax_v2 — 阈值 5→7（sync）
                # iter882: 7d_tighten_monopoly — tiny 7→3, small 8→4
                # iter903: constraint_7d_tighten — tiny 3→2（与 24h 联动）
                #   7d=3 允许不相关 constraint 一周注入 2 次，降到 2 限制为 1 次/周。
                # iter949: tiny_db_7d_relax — constraint 通道 2→3
                # iter1028: constraint_global_saturated_7d — global ac>=4 constraint 7d 阈值 -1
                # 根因（数据驱动，2026-05-07）：feishu CLI(ac=4,7d=4)、git commit(ac=9,7d=4)
                #   经 constraint 通道注入时 7d 阈值=4(small_db)，主路径 iter1006 已收紧(-2)
                #   但 constraint 通道未同步，形成逃逸。ac>=4 的 global 约束用户已内化。
                # 修复：global ac>=4 → 7d 阈值 -1（constraint 通道比主路径保守，仅 -1）。
                _cst_7d_thresh = (3 if _cst_tiny_db else 4) if _cst_small_db else 3
                if c.get("project") == "global" and _ac_abs >= 4:
                    _cst_7d_thresh = max(2, _cst_7d_thresh - 1)
                if _recent_7d_counts.get(_cid, 0) >= _cst_7d_thresh:
                    return False
                # iter608: session-level constraint dedup — 早于全局 cap 拦截
                _sinj = _session_injection_counts.get(_cid, 0)
                if _sinj >= _session_constraint_cap:
                    return False
                _rc = _recall_counts.get(_cid, 0)
                # hard cap: 注入频率超阈值直接 suppress，不论 relevance
                # iter610: 用 _local_bw_window 防止 memcg inflate 稀释垄断检测
                if _rc / max(_local_bw_window, 1) > _inject_hard_cap:
                    return False
                _rel = _constraint_relevance(c)
                # iter598: zero relevance gate — 与 query 零词重叠的 constraint 无条件拦截
                # iter850: remove global_high_imp_exempt — 数据驱动（2026-05-05）：
                #   feishu CLI (imp=0.95) 和 git commit author (imp=0.95) 通过此豁免
                #   在 memory-os/kernel 迭代中被无关注入 24h 4~5 次。
                #   根治：所有 constraint 统一要求最低 relevance，不再豁免。
                if _rel == 0:
                    return False
                _ac = _ac_abs
                # iter641: two_phase_relevance_gate — 阈值与 constraint_ac_cap 对齐
                # ac>15 进入陡斜率（constraint 通道比主路径更严格）
                import math as _m609
                if _ac <= 10:
                    _ac_penalty = 0.0
                elif _ac <= 15:
                    _ac_penalty = min(0.20, _m609.log1p(_ac - 10) * 0.04)
                else:
                    _ac_penalty = 0.20 + min(0.20, _m609.log1p(_ac - 15) * 0.06)
                _eff_min_rel = _constraint_min_rel + _ac_penalty
                # iter856: global_chunk_relevance_floor — global chunk 跨项目注入需更高相关性
                # 根因（数据驱动，2026-05-05）：feishu CLI (global) 在 kernel 项目中
                #   因 prompt 含 "feishu"+"禁止" 偶然词重叠 Jaccard=0.054 通过 min_rel=0.05。
                #   global chunk 在非 home 项目中需要更强的语义关联才值得注入。
                # 修复：global chunk 额外 +0.03 floor，使 eff_min_rel=0.08。
                #   真正相关时（如 git commit author 在 commit query 中）Jaccard>0.10 仍通过。
                # iter937: global_relevance_floor_tighten — 0.03→0.05
                #   根因（数据驱动，2026-05-06）：36-chunk 库 feishu CLI 7d 仍注入 3 次到 kernel 项目。
                #   Jaccard 0.054~0.09 的偶然词重叠仍通过 +0.03 floor（eff=0.08）。
                #   提高到 +0.05（eff=0.10）：git commit author 在 kernel query 中 Jaccard>0.13（仍通过），
                #   feishu CLI/memory 验证 在非相关项目中 Jaccard<0.10（被拦截）。
                if c.get("project") == "global":
                    _eff_min_rel += 0.05
                # iter850: 统一 min_rel gate（移除 global_high_imp 豁免）
                if _rel < _eff_min_rel:
                    return False
                return (_rc / max(_bw_window, 1)) <= _thrash_max_pct
            _extra_constraints = [c for c in _extra_constraints if _ac_gated(c)]
            _gated_count = _pre_gate_count - len(_extra_constraints)
            if _gated_count > 0:
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"refault_distance: gated={_gated_count} (min_rel={_constraint_min_rel} thrash_max={_thrash_max_pct} ac_gate=iter595)",
                              session_id=session_id, project=project)

            # ── 迭代337：Jaccard 内容重叠过滤 ──
            # 若约束 summary 与 top_k 中任一 chunk 的 Jaccard 相似度 ≥ 0.5，
            # 表示内容已被覆盖，再注入是纯冗余 → 跳过。
            # OS 类比：Linux KSM (Kernel Samepage Merging, 2009) —
            #   扫描物理页内容，哈希相同的页合并为 COW 共享页，节省内存。
            #   AIOS 版本：summary token 集合 Jaccard 相似度 > threshold → 内容冗余，不重复注入。
            _top_k_token_sets = []
            for _, _tc in top_k:
                _tc_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ',
                                       (_tc.get("summary") or "").lower()).split())
                if _tc_words:
                    _top_k_token_sets.append(_tc_words)

            def _is_content_redundant(c: dict) -> bool:
                """Jaccard > 0.5 与已选任一 chunk 内容高度重叠 → 冗余。"""
                c_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ',
                                     (c.get("summary") or "").lower()).split())
                if not c_words:
                    return False
                for existing_words in _top_k_token_sets:
                    union = existing_words | c_words
                    if union:
                        jaccard = len(existing_words & c_words) / len(union)
                        if jaccard >= 0.50:
                            return True
                return False

            # 只强制注入最多 _effective_max_forced 个（按相关性排序，受 DRR 感知 + Jaccard 过滤）
            for c in _extra_constraints[:_effective_max_forced]:
                if _is_content_redundant(c):
                    continue  # iter337: 内容冗余跳过
                forced_constraints.append(c["summary"])
                top_k.insert(0, (0.99, c))
                top_k_ids.add(c["id"])
                # 更新 token 集合供后续约束去重检查
                _c_words = set(re.sub(r'[^\w\u4e00-\u9fff]', ' ',
                                      (c.get("summary") or "").lower()).split())
                if _c_words:
                    _top_k_token_sets.append(_c_words)

        # ── 迭代355：Proactive Swap Probe（主动 swap 探针）──
        # OS 类比：Linux MGLRU (Multi-Generation LRU, 5.17+) 主动提升 swap 中的热页：
        #   即使当前 active_list 非空，kswapd 仍扫描 swap 中高频访问的匿名页，
        #   提前 swap_in 到 inactive_list，避免下次 page fault 时才恢复。
        #
        # 问题根因（v5 audit, 2026-04-28）：
        #   swap_chunks 中有 100 个 chunk（avg_importance=0.885），0 次 swap fault。
        #   原因：swap_fault 只在 `if not top_k:` 分支触发（FTS5 完全 miss 时），
        #   但 FTS5 几乎总有结果（即使低相关），导致这 100 个高价值 chunk 永远被跳过。
        #
        # 修复策略：
        #   top_k 非空时，仍检查 swap 中高 importance（>= imp_threshold）的匹配 chunk，
        #   恢复后合并到 top_k（不超过 max_restore 个）。
        if (priority == "FULL"
                and _sysctl("retriever.proactive_swap_enabled")
                and top_k
                and not _check_deadline("swap_fault")):
            try:
                _probe_imp_threshold = _sysctl("retriever.proactive_swap_imp_threshold")
                _probe_max_restore   = _sysctl("retriever.proactive_swap_max_restore")

                # swap_fault 已按 hit_ratio * importance 排序
                _probe_matches = swap_fault(conn, query, project)
                # 只处理高 importance 的 chunk
                _probe_matches = [m for m in _probe_matches
                                  if m.get("importance", 0) >= _probe_imp_threshold]

                if _probe_matches:
                    _probe_ids = [m["id"] for m in _probe_matches[:_probe_max_restore]]
                    # 切换到写连接执行 swap_in
                    conn.close()
                    conn = open_db()
                    ensure_schema(conn)
                    _probe_result = swap_in(conn, _probe_ids)
                    if _probe_result.get("restored_count", 0) > 0:
                        _deferred.log(DMESG_INFO, "retriever",
                                      f"proactive_swap: restored={_probe_result['restored_count']} "
                                      f"imp>={_probe_imp_threshold:.2f}",
                                      session_id=session_id, project=project)
                        conn.commit()
                        conn.close()
                        conn = _open_db_readonly()
                        # 补充检索已恢复的 chunk（通过 ID 直接获取，避免重跑完整 FTS5）
                        _already_ids = {c.get("id", "") for _, c in top_k}
                        for _pmatch in _probe_matches[:_probe_max_restore]:
                            _pid = _pmatch.get("id", "")
                            if _pid and _pid not in _already_ids:
                                _prow = conn.execute(
                                    "SELECT * FROM memory_chunks WHERE id=? LIMIT 1",
                                    (_pid,)
                                ).fetchone()
                                if _prow:
                                    _pc = dict(_prow)
                                    _pscore = _score_chunk(_pc, _pmatch.get("hit_ratio", 0.5))
                                    top_k.append((_pscore, _pc))
                                    _already_ids.add(_pid)
                        # 重排序（新注入的 chunk 按 score 排序合并）
                        top_k.sort(key=lambda x: x[0], reverse=True)
                        top_k = top_k[:effective_top_k]
                    else:
                        # swap_in 无结果，切回只读
                        conn.close()
                        conn = _open_db_readonly()
            except Exception:
                pass  # proactive swap 探针失败不阻塞主流程

        if not top_k:
            # ── 迭代33：Swap Fault — 检查 swap 分区是否有匹配的被换出 chunk ──
            # 迭代41：swap_fault 受 soft deadline 约束（低优先级）
            # 迭代84：swap_fault 需要写连接（swap_in 修改主表），临时切换
            if priority == "FULL" and not _check_deadline("swap_fault"):
                try:
                    swap_matches = swap_fault(conn, query, project)
                    if swap_matches:
                        swap_ids = [m["id"] for m in swap_matches]
                        # 需要写连接执行 swap_in
                        conn.close()  # 关闭只读连接
                        conn = open_db()  # 切换到写连接
                        ensure_schema(conn)
                        swap_result = swap_in(conn, swap_ids)
                        if swap_result["restored_count"] > 0:
                            _deferred.log(DMESG_INFO, "retriever",
                                      f"swap_fault: restored={swap_result['restored_count']} from swap",
                                      session_id=session_id, project=project)
                            _deferred.flush(conn)
                            conn.commit()
                            # swap_in 后切回只读连接重新检索
                            conn.close()
                            conn = _open_db_readonly()
                            # 重新检索（swap in 后主表有新数据）
                            fts_results = fts_search(conn, query, None, top_k=effective_top_k * 3,
                                                     chunk_types=_retrieve_types)
                            if fts_results:
                                max_rank = max(c["fts_rank"] for c in fts_results) if fts_results else 1.0
                                if max_rank <= 0:
                                    max_rank = 1.0
                                final = []
                                _swap_fts_ids = set()
                                for chunk in fts_results:
                                    relevance = chunk["fts_rank"] / max_rank
                                    score = _score_chunk(chunk, relevance)
                                    final.append((score, chunk))
                                    _swap_fts_ids.add(chunk.get("id", ""))
                                # iter126: swap_in 后也走 hybrid 补充
                                if len(fts_results) < effective_top_k:
                                    try:
                                        _sw_all = store_get_chunks(conn, project, chunk_types=_retrieve_types)
                                        _sw_extra = [c for c in _sw_all if c.get("id", "") not in _swap_fts_ids]
                                        if _sw_extra:
                                            _sw_raw = bm25_scores_cached(query, [f"{c['summary']} {c['content']}" for c in _sw_extra], chunk_version=read_chunk_version())
                                            _sw_norm = normalize(_sw_raw)
                                            for i, chunk in enumerate(_sw_extra):
                                                score = _score_chunk(chunk, _sw_norm[i] * 0.6)
                                                final.append((score, chunk))
                                    except Exception:
                                        pass
                                final.sort(key=lambda x: x[0], reverse=True)
                                top_k = [(s, c) for s, c in final[:effective_top_k] if s > 0]
                        else:
                            # swap_in 无结果，切回只读连接
                            conn.close()
                            conn = _open_db_readonly()
                except Exception:
                    pass

            # ── iter673: constraint_empty_fallback — positive=[] 时注入项目 constraint ──
            # 根因（数据驱动，2026-05-04）：66% trace 产出空 top_k，其中大量属于有
            #   design_constraint 的项目。constraint 价值不依赖 query 匹配度（是无条件
            #   安全约束），但当 FTS5 score 全部 < min_thresh 时，constraint 和其他
            #   chunk 一起被淘汰 → 项目约束从未被注入。
            # 修复：positive=[] 时，直接从 DB 取项目 constraint 注入最重要的 1 条。
            # iter681: 移除 24h/7d suppress 检查 — 此 fallback 是空召回最后防线，
            #   suppress 过杀导致 67% 空召回（54/80 trace）。空召回 = 系统无价值。
            #   垄断由上游 _score_chunk suppress + final_gate 控制，fallback 不需二次拦截。
            if not top_k:
                try:
                    # iter690: global_constraint_fallback — 同时查项目+global constraint
                    # 根因：4 个零访问 chunk 中 2 个 imp=0.9 global constraint 从未被注入，
                    #   因为 project=? 只匹配当前项目，global 约束永远被跳过。
                    _cef_rows = conn.execute(
                        "SELECT * FROM memory_chunks WHERE chunk_state='ACTIVE' "
                        "AND project IN (?, 'global') AND chunk_type='design_constraint' "
                        "ORDER BY importance DESC LIMIT 2", (project,)
                    ).fetchall()
                    if _cef_rows:
                        _cef_cols = [d[0] for d in conn.execute(
                            "SELECT * FROM memory_chunks LIMIT 0").description]
                        _cef_chunks = [dict(zip(_cef_cols, r)) for r in _cef_rows]
                        if _cef_chunks:
                            _cef_best = _cef_chunks[0]
                            top_k = [(0.99, _cef_best)]
                            _deferred.log(DMESG_INFO, "retriever",
                                          f"iter690_global_constraint_fallback: "
                                          f"injected {_cef_best['id'][:12]} "
                                          f"(positive=0, src={_cef_best.get('project','')})",
                                          session_id=session_id, project=project)
                except Exception:
                    pass

            # ── iter677: positive_empty_best_fallback — FTS 最高分兜底 ──────
            # 根因（数据驱动，2026-05-04）：FULL 路径 65% trace top_k=0。
            #   positive=[] 因 candidates 的 score 全部 < min_thresh(0.30)。
            #   constraint_fallback 只看 design_constraint 且受 7d suppress 限制。
            #   实测：score 0.25~0.29 的候选有 FTS5 词匹配、有一定相关性，
            #   全部丢弃导致用户从不看到记忆。
            # 修复：从 final 取最高分候选，score >= 0.20 即注入 1 条。
            # iter681: 移除 24h/7d suppress 检查 — 与 constraint_fallback 同理，
            #   此为最后防线。suppress 过杀是 67% 空召回的根因。
            # iter945: fallback_monopoly_gate — 恢复 7d ceiling 防止垄断 chunk 经此逃逸
            #   与 hard_deadline 路径对齐。排除 7d >= ceiling 后取最佳。
            if not top_k and final:
                _pebf_ceiling = 4 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)  # iter952: sync 5→4
                # iter1009: local_saturated_suppress — FULL iter677 ceiling sync
                def _pebf_chunk_ceil(c):
                    _lac = c.get("access_count", 0) or 0
                    if c.get("project", "") == "global" and _lac >= 4:
                        return max(2, _pebf_ceiling - 2)
                    if _lac >= 10:
                        return max(2, _pebf_ceiling - 2)
                    elif _lac >= 7:
                        return max(2, _pebf_ceiling - 1)
                    return _pebf_ceiling
                _pebf_cands = [(s, c) for s, c in final
                               if _recent_7d_counts.get(c.get("id", ""), 0) < _pebf_chunk_ceil(c)
                               and s >= 0.20]
                if _pebf_cands:
                    _pebf_best = _pebf_cands[0]  # final 已按 score desc 排序
                    _pebf_score = _pebf_best[0]
                    _pebf_id = _pebf_best[1].get("id", "")
                    top_k = [_pebf_best]
                    _deferred.log(DMESG_INFO, "retriever",
                                  f"iter677_positive_empty_best_fallback: "
                                  f"score={_pebf_score:.3f} id={_pebf_id[:12]}",
                                  session_id=session_id, project=project)

            # ── iter792: importance_ultimate_fallback — 消灭 FULL 路径空召回 ──
            # 根因（数据驱动，2026-05-04）：27% trace（27/100）走到此处 top_k=[]。
            #   FTS5 检索到 3-14 candidates 但 score 全 < min_thresh(0.30)。
            #   iter700/775/776 fallback 覆盖了 score<0.30 的情况，但仍有空召回，
            #   说明某些边界条件（异常路径/条件组合）导致 fallback 链被跳过。
            # 修复：在最终 exit 前，从 final 按 importance 选最佳 1 条兜底。
            #   空召回 = 系统零价值，注入低分但有用的知识远优于什么都不注入。
            if not top_k and final:
                _iuf_by_imp = [(float(c.get("importance", 0) or 0), s, c) for s, c in final
                               if (c.get("access_count", 0) or 0) < 30]
                if _iuf_by_imp:
                    _iuf_best = max(_iuf_by_imp, key=lambda x: x[0])
                    top_k = [(_iuf_best[0] * 0.01, _iuf_best[2])]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter792_importance_ultimate_fallback: "
                                  f"imp={_iuf_best[0]:.2f} orig_s={_iuf_best[1]:.4f} "
                                  f"id={_iuf_best[2].get('id','')[:12]} "
                                  f"final_len={len(final)} positive_was_empty",
                                  session_id=session_id, project=project)

            if not top_k:
                # iter902: db_ultimate_fallback — 直接从 DB 选 1 条兜底，消灭空召回
                # 根因（数据驱动，2026-05-05）：31% trace 空召回，candidates=10-14 全被
                #   suppress/gate 清空，iter792 依赖 in-memory final（也被清空）无法触发。
                # 修复：绕过 suppress，直接 DB 查最高 importance + 最低 access_count 的 chunk。
                #   空召回=系统零价值；注入 1 条有用知识远优于零注入。
                # iter1037: ultimate_fallback_global — 扩展查询范围到 global chunk
                # 根因（数据驱动，2026-05-07）：28 次空召回中 gitroot:ac59b4b36b2b(0 chunk)
                #   和 abspath:51963532bc1b(1 chunk 被 suppress) 无法兜底，因只查 project=?。
                #   constraint_fallback 已查 global 但限 design_constraint 类型。
                # 修复：IN (?, 'global') 扩展搜索范围，优先本项目，global 作兜底。
                try:
                    _dbuf_row = conn.execute(
                        "SELECT id, summary, content, chunk_type, importance "
                        "FROM memory_chunks WHERE project IN (?, 'global') AND chunk_state='ACTIVE' "
                        "ORDER BY importance DESC, access_count ASC LIMIT 1",
                        (project,)
                    ).fetchone()
                    if _dbuf_row:
                        _dbuf_chunk = {"id": _dbuf_row[0], "summary": _dbuf_row[1],
                                       "content": _dbuf_row[2], "chunk_type": _dbuf_row[3] or "",
                                       "importance": _dbuf_row[4] or 0.5}
                        top_k = [(0.001, _dbuf_chunk)]
                        _deferred.log(DMESG_WARN, "retriever",
                                      f"iter902_db_ultimate_fallback: "
                                      f"id={_dbuf_row[0][:12]} imp={_dbuf_row[4]:.2f} "
                                      f"bypassed_suppress project={project}",
                                      session_id=session_id, project=project)
                except Exception:
                    pass

            if not top_k:
                # 迭代84：关闭只读连接，flush deferred logs
                conn.close()
                if len(_deferred) > 0:
                    try:
                        wconn = open_db()
                        ensure_schema(wconn)
                        _deferred.flush(wconn)
                        wconn.commit()
                        wconn.close()
                    except Exception:
                        pass
                sys.exit(0)

        # ── 迭代316：Working Memory Budget — Cowan 2001 ──
        # OS 类比：mm/readahead.c 预读窗口管理，不是越大越好
        # 分层：active(L1)→直接注入，background(L2)→间接支撑，dormant(L3)→不注入
        try:
            from wmb import apply_wmb_budget as _wmb_budget, tier_chunks as _wmb_tier
            _wmb_pairs = [(s, c) for s, c in top_k]  # 格式：(score, chunk)
            _wmb_tier_result = _wmb_tier(_wmb_pairs, top_k=effective_top_k)
            _wmb_injected = _wmb_tier_result["active"] + _wmb_tier_result["background"]
            if _wmb_injected:
                _wmb_dormant_count = len(_wmb_tier_result["dormant"])
                # 重建 top_k 格式：[(score, chunk)]，保持原有分数
                _score_map = {c["id"]: s for s, c in top_k}
                top_k = [(_score_map.get(c["id"], 0.5), c) for c in _wmb_injected]
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"wmb_budget: active={len(_wmb_tier_result['active'])} "
                              f"background={len(_wmb_tier_result['background'])} "
                              f"dormant_suppressed={_wmb_dormant_count}",
                              session_id=session_id, project=project)
        except Exception:
            pass  # WMB 失败不影响主流程，降级使用原始 top_k

        # ── iter390: Prospective Memory Trigger — 展望记忆触发注入 ──────────────
        # 认知科学：Einstein & McDaniel (1990) Prospective Memory —
        #   当 query 匹配到之前记录的"未来意图"触发条件时，主动注入相关 chunk。
        # OS 类比：inotify 触发 — 注册的监听事件满足时唤醒等待进程。
        try:
            if priority == "FULL" and not _check_deadline("prospective"):
                from store_vfs import query_triggers as _query_triggers, fire_trigger as _fire_trigger
                _trig_matches = _query_triggers(conn, project, query, max_triggers=2)
                if _trig_matches:
                    _already_ids = {c.get("id") for _, c in top_k}
                    _trig_injected = 0
                    for _tcid, _tid, _tpat in _trig_matches:
                        if _tcid in _already_ids:
                            continue
                        _trow = conn.execute(
                            "SELECT * FROM memory_chunks WHERE id=? LIMIT 1", (_tcid,)
                        ).fetchone()
                        if _trow:
                            _tc = dict(_trow)
                            _tscore = _score_chunk(_tc, 0.8)  # 展望记忆固定较高初始分
                            top_k.append((_tscore, _tc))
                            _already_ids.add(_tcid)
                            _trig_injected += 1
                            # 触发计数（需要写连接，延迟处理）
                            try:
                                _wconn_trig = open_db()
                                ensure_schema(_wconn_trig)
                                _fire_trigger(_wconn_trig, _tid)
                                _wconn_trig.commit()
                                _wconn_trig.close()
                            except Exception:
                                pass
                    if _trig_injected > 0:
                        top_k.sort(key=lambda x: x[0], reverse=True)
                        top_k = top_k[:effective_top_k]
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter390 prospective_trigger: injected={_trig_injected}",
                                      session_id=session_id, project=project)
        except Exception:
            pass  # 展望记忆注入失败不阻塞主流程

        # ── iter571: mmap_populate — Probabilistic Cold Page Promotion ──────
        # OS 类比：MAP_POPULATE / madvise(MADV_WILLNEED) — 主动将 cold pages
        #   预填充到 working set，打破 cold→no_access→cold 死锁
        # 与 IWCSI(iter334) 区别：IWCSI 只在 positive 不足时被动触发，
        #   mmap_populate 每 N 次 FULL 召回无条件触发，确保 dark pages 轮转曝光
        global _mmap_populate_counter
        if priority == "FULL":
            _mmap_populate_counter += 1
        if (priority == "FULL"
                and top_k
                and _sysctl("mmap_populate.enabled")
                and not _check_deadline("mmap_populate")):
            try:
                from store_mm import mmap_populate as _mmap_populate
                _existing_ids = {c.get("id", "") for _, c in top_k}
                _cold_chunk = _mmap_populate(
                    conn, project, _existing_ids, _mmap_populate_counter)
                if _cold_chunk:
                    # 替换 top_k 中最低分的 slot（不增加注入总量）
                    if len(top_k) > 1:
                        top_k.sort(key=lambda x: x[0], reverse=True)
                        _evicted = top_k.pop()  # 移除最低分
                        _cold_score = float(_cold_chunk.get("importance", 0.5))
                        top_k.append((_cold_score, _cold_chunk))
                    else:
                        _cold_score = float(_cold_chunk.get("importance", 0.5))
                        top_k.append((_cold_score, _cold_chunk))
                    _deferred.log(DMESG_INFO, "retriever",
                                  f"mmap_populate: promoted chunk "
                                  f"imp={_cold_chunk.get('importance', 0):.2f} "
                                  f"type={_cold_chunk.get('chunk_type', '?')} "
                                  f"counter={_mmap_populate_counter}",
                                  session_id=session_id, project=project)
            except Exception:
                pass  # mmap_populate 失败不阻塞主流程

        # ── iter582: scan_unevictable — Round-Robin Dark Page Batch Exposure ──
        # OS 类比：Linux scan_unevictable_pages() (Lee Schermerhorn, 2008)
        # mmap_populate 每 interval(3) 次替换 1 个 slot → 覆盖慢；
        # scan_unevictable 每次 FULL 注入 max_inject(2) 到额外 diversity slots，
        # round-robin cursor 保证所有 dark pages 公平轮转。
        if (priority == "FULL"
                and _sysctl("scan_unevictable.enabled")
                and not _check_deadline("scan_unevictable")):
            try:
                from store_mm import scan_unevictable as _scan_unevictable
                _existing_ids = {c.get("id", "") for _, c in top_k}
                _dark_pages = _scan_unevictable(conn, project, _existing_ids)
                for _dp in _dark_pages:
                    _dp_score = float(_dp.get("importance", 0.5))
                    top_k.append((_dp_score, _dp))
                if _dark_pages:
                    _deferred.log(DMESG_INFO, "retriever",
                                  f"scan_unevictable: injected {len(_dark_pages)} dark pages "
                                  f"types={','.join(d.get('chunk_type','?') for d in _dark_pages)}",
                                  session_id=session_id, project=project)
            except Exception:
                pass  # scan_unevictable 失败不阻塞主流程

        # ── iter670: suppress_fallback — 记录 suppress 前快照 ──
        _pre_suppress_top_k = list(top_k)
        # ── iter630: monopoly_post_filter — FULL 路径最终门禁 ──
        # iter634: 用标准连接获取最新 ac，防止 immutable WAL 盲区导致垄断逃逸
        _mpf_live = _live_access_counts([c["id"] for _, c in top_k])
        top_k = [(s, c) for s, c in top_k
                 if (_mpf_live.get(c["id"], c.get("access_count", 0) or 0)) < 30]
        # ── iter663: suppress_final_gate — FULL 路径用实时 DB 查询兜底 ──
        # 根因（数据驱动，2026-05-04）：_score_chunk 内 24h suppress 依赖
        #   进程启动时一次性计算的 _recent_24h_counts。并发 session 写入
        #   timeline 文件无锁 → 读到旧值 → suppress 被绕过。
        #   实测：import-6cc32f2ff 24h 内注入 4 次（应在第 3 次被拦截）。
        # 修复：FULL 路径有时间预算，实时从 recall_traces 查询 24h/7d 计数。
        if top_k:
            try:
                import sqlite3 as _sf663
                from datetime import datetime as _dt663, timezone as _tz663, timedelta as _td663
                _sf663_conn = _sf663.connect(str(STORE_DB))
                _sf663_now = _dt663.now(_tz663.utc)
                _cut663_24h = (_sf663_now - _td663(hours=24)).isoformat()
                _cut663_7d = (_sf663_now - _td663(days=7)).isoformat()
                _rt663_24h = {}
                _rt663_7d = {}
                # iter835: suppress_final_gate_project_scope — 加 project 过滤
                # 根因（数据驱动，2026-05-05）：global chunk 跨多项目被注入时计数累加，
                #   如 a8f13757 在 2 个项目各注入 1-2 次 → 总计 3 次 → 达到 tiny_db 24h 阈值=3。
                #   同一 global constraint 在不同项目上下文中有独立价值，不应跨项目累加 suppress。
                # iter957: session_dedup_suppress — 7d count 按 unique session 去重
                # 根因（数据驱动，2026-05-06）：24-chunk 库 14/24=58% 被 7d suppress，
                #   因为同一 session 多次检索同一 chunk 重复计入 7d count。
                #   实测：session-dedup 后仅 5/24=20% 被 suppress，空召回率预期降 38%→20%。
                # 修复：7d count = unique sessions（同 session 多次触发只算 1 次暴露）。
                #   24h 保留 raw count（短窗口内重复即 burst，仍需 suppress）。
                _rt663_7d_sessions = {}  # {chunk_id: set(session_ids)}
                for (_tk663, _ts663, _sid663) in _sf663_conn.execute(
                        "SELECT top_k_json, timestamp, session_id FROM recall_traces "
                        "WHERE injected=1 AND project=? AND timestamp>?", (project, _cut663_7d,)).fetchall():
                    if not _tk663: continue
                    try:
                        for _it663 in json.loads(_tk663):
                            _c663 = _it663.get("id", "") if isinstance(_it663, dict) else ""
                            if _c663:
                                _rt663_7d_sessions.setdefault(_c663, set()).add(_sid663 or "")
                                if _ts663 and _ts663 > _cut663_24h:
                                    _rt663_24h[_c663] = _rt663_24h.get(_c663, 0) + 1
                    except Exception:
                        continue
                _rt663_7d = {k: len(v) for k, v in _rt663_7d_sessions.items()}
                # iter888: global_chunk_cross_project_suppress — global chunk 用全局计数
                # 根因（数据驱动，2026-05-05）：iter835 per-project 过滤导致 global chunk 逃逸。
                #   如 feishu-CLI constraint 在 3 个项目各注入 1-2 次 → per-project 计数不触发
                #   suppress，但用户实际看到 4-5 次相同内容。
                # 修复：对 project='global' 的 chunk，额外查全局计数取 max。
                _g888_ids = set(r[0] for r in _sf663_conn.execute(
                    "SELECT id FROM memory_chunks WHERE project='global'").fetchall())
                if _g888_ids:
                    _g888_24h_c = {}
                    _g888_7d_c = {}  # iter957: session-dedup for global chunks too
                    _g888_7d_sessions = {}
                    for (_tk888, _ts888, _sid888) in _sf663_conn.execute(
                            "SELECT top_k_json, timestamp, session_id FROM recall_traces "
                            "WHERE injected=1 AND timestamp>?", (_cut663_7d,)).fetchall():
                        if not _tk888: continue
                        try:
                            for _it888 in json.loads(_tk888):
                                _c888id = _it888.get("id", "") if isinstance(_it888, dict) else ""
                                if _c888id in _g888_ids:
                                    _g888_7d_sessions.setdefault(_c888id, set()).add(_sid888 or "")
                                    if _ts888 and _ts888 > _cut663_24h:
                                        _g888_24h_c[_c888id] = _g888_24h_c.get(_c888id, 0) + 1
                        except Exception:
                            continue
                    _g888_7d_c = {k: len(v) for k, v in _g888_7d_sessions.items()}
                    for _gid888 in _g888_ids:
                        _rt663_24h[_gid888] = max(_rt663_24h.get(_gid888, 0), _g888_24h_c.get(_gid888, 0))
                        _rt663_7d[_gid888] = max(_rt663_7d.get(_gid888, 0), _g888_7d_c.get(_gid888, 0))
                _sf663_conn.close()
                _pre663 = len(top_k)
                # iter764: sync_small_db_relax — 同步 daemon iter704 小库放宽
                _sf663_tiny_db = _db_chunk_count < 50  # iter848: 边界 40→50
                _sf663_small_db = _db_chunk_count < 100
                # iter810: tiny_db_24h_relax — sync FULL final_gate
                # iter837: tiny_db_24h_relax_v2 — 阈值 3→4（同步 _score_chunk）
                # iter883: full_final_gate_7d_sync — 对齐 hard_deadline iter882 的 7d 收紧
                #   根因（数据驱动，2026-05-05）：FULL 路径 tiny_db 7d<5 允许 4 次注入，
                #   但 hard_deadline 路径已收紧到 <3。top chunk 7d=6 仍可经 FULL 路径逃逸。
                #   主项目 23 chunk（tiny_db）中 top15 chunk 占 78% 注入位。
                #   修复：tiny 5→3，small 8/6→4/3（与 hard_deadline line 3268 对齐）。
                # iter905: cross_project_suppress_tighten — 跨项目非 global chunk 7d 阈值 -2
                #   根因（数据驱动，2026-05-05）：42-chunk 库中 29 个 kernel chunk 与 memory-os 无关，
                #   但因 FTS5 全库搜索 + session 恢复关键词匹配，7d=3-4 的 kernel chunk 持续注入。
                #   修复：非本项目非 global chunk 7d 阈值收紧 2，加速 suppress 无关知识。
                # iter908: final_gate_7d_align_score — tiny_db 4→3 对齐 _score_chunk(>=3)
                # iter990: small_db_7d_relax_v3 — FULL final_gate 路径同步
                def _sf663_7d_thresh(s, c):
                    _cp = c.get("project", "")
                    _cross = (_cp != project and _cp != "global")
                    _is_global = (_cp == "global")
                    if _sf663_tiny_db:
                        _t = 5  # iter1000: tiny 3→5 去垄断反转
                    elif _sf663_small_db:
                        _t = 6 if s >= 0.5 else 4  # iter990: 4/3→6/4
                    else:
                        _t = 5 if s >= 0.5 else 3
                    # iter993: global_chunk_suppress_tighten — global chunk 阈值 -1
                    # iter1006: global_saturated_suppress_tighten — ac>=4 的 global chunk -2
                    # 根因（数据驱动，2026-05-06）：feishu CLI(ac=4)/memory验证(ac=6)/git commit(ac=9)
                    #   已内化的工具约束 7d=4 仍逃逸（阈值=4），垄断注入位。
                    # 修复：ac>=4 的 global chunk 与 cross 同级(-2)，ac<4 保持 -1。
                    if _cross:
                        return max(2, _t - 2)
                    elif _is_global:
                        _g_ac = c.get("access_count", 0) or 0
                        # iter1031: global_deep_saturated_suppress — ac>=7 强制阈值=2
                        if _g_ac >= 7:
                            return 2
                        return max(2, _t - (2 if _g_ac >= 4 else 1))
                    # iter1009: local_saturated_suppress — sync suppress_final_gate
                    _l_ac = c.get("access_count", 0) or 0
                    if _l_ac >= 10:
                        return max(2, _t - 2)
                    elif _l_ac >= 7:
                        return max(2, _t - 1)
                    return _t
                # iter968: micro_db_final_gate_bypass — <=5 自有 chunk 库跳过 final_gate
                # 根因（数据驱动，2026-05-06）：git:78dc99a5695f（2 自有 chunk）空注入率 86%（6/7）。
                #   _score_chunk 阶段 micro_db bypass(line 2230) 让 global chunk 正常评分，
                #   但 suppress_final_gate 无 micro_db 豁免 → 7d>=4 的 global chunk 全灭。
                #   唯一知识源被 suppress = 系统对该项目完全无用。
                # 修复：与 _score_chunk micro_db bypass 对齐，<=5 chunk 库不执行 final_gate。
                # iter1020: suppress_final_gate_24h_saturated_sync — 同步 hard_deadline iter1019
                # 根因（数据驱动，2026-05-07）：ac=10 "Android 性能诊断核心规则" 同日注入 3 次。
                #   hard_deadline 路径 24h 阈值=1（iter1019 ac>=10: max(1,3-2)），
                #   但 suppress_final_gate FULL 路径 24h 阈值=3（硬编码），形成逃逸。
                # 修复：FULL 路径 24h 检查同步 iter1019 动态阈值。
                def _sf1020_24h_thresh(s, c):
                    _b = 3 if _sf663_tiny_db else (3 if s >= 0.5 else 2) if _sf663_small_db else (3 if s >= 0.5 else 2)
                    _a = c.get("access_count", 0) or 0
                    if _a >= 10:
                        return max(1, _b - 2)
                    elif _a >= 7:
                        return max(1, _b - 1)
                    # iter1023: global_24h_saturated_cap — global chunk ac>=4 已内化，24h 只允许 0 次
                    # 根因（数据驱动，2026-05-07）：memory验证路径(ac=6,global) 24h 内同 session 注入 2 次。
                    #   24h 阈值=2（max(1,3-1)）允许 1 次后第 2 次仍通过。ac>=4 的 global 约束用户已熟知。
                    # 修复：global ac>=4 → 阈值=1（24h 内注入过 1 次即 suppress 后续）。
                    if c.get("project") == "global" and _a >= 4:
                        return 1
                    return _b
                if _db_chunk_count > 5:
                    top_k = [(s, c) for s, c in top_k
                             if _rt663_24h.get(c["id"], 0) < _sf1020_24h_thresh(s, c)
                             # iter904: 7d_rebalance_tiny — tiny_db 7d 2→4
                             # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                             and _rt663_7d.get(c["id"], 0) < _sf663_7d_thresh(s, c)]
                if len(top_k) < _pre663:
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter663_suppress_final_gate: filtered "
                                  f"{_pre663 - len(top_k)} chunks (24h/7d realtime)",
                                  session_id=session_id, project=project)
            except Exception as _e663:
                _deferred.log(DMESG_WARN, "retriever",
                              f"iter663_suppress_final_gate_EXCEPTION: {type(_e663).__name__}: {_e663}",
                              session_id=session_id, project=project)
        # ── iter887: suppress_final_gate_closure_fallback — 闭包快照兜底 ──
        # 根因（数据驱动，2026-05-05）：suppress_final_gate 实时 DB 查询在 try/except
        #   中静默失败时，7d count≥3 的垄断 chunk 逃逸（实测 14 个 chunk 应被 suppress）。
        #   hard_deadline 路径有 _recent_7d_counts 闭包兜底（line 3266），FULL 路径缺失。
        # 修复：在实时 DB suppress 之后，用启动时闭包快照 _recent_6h/_24h/_7d_counts 二次过滤。
        # iter968: micro_db bypass 同步到 closure_fallback（与 suppress_final_gate 对齐）
        if top_k and _db_chunk_count > 5:
            _pre887 = len(top_k)
            _fg887_tiny = _db_chunk_count < 50
            _fg887_small = _db_chunk_count < 100
            # iter905: cross_project_suppress_tighten — 闭包路径同步跨项目收紧
            # iter908: final_gate_7d_align_score — tiny_db 4→3
            # iter990: small_db_7d_relax_v3 — closure_fallback 路径同步
            def _fg887_7d_thresh(s, c):
                _cp = c.get("project", "")
                _cross = (_cp != project and _cp != "global")
                _is_global = (_cp == "global")
                if _fg887_tiny:
                    _t = 5  # iter1000: tiny 3→5 去垄断反转（sync suppress_final_gate）
                elif _fg887_small:
                    _t = 6 if s >= 0.5 else 4  # iter990: 4/3→6/4
                else:
                    _t = 5 if s >= 0.5 else 3
                # iter993: global_chunk_suppress_tighten — sync closure_fallback
                # iter1006: global_saturated_suppress_tighten — sync closure_fallback
                if _cross:
                    return max(2, _t - 2)
                elif _is_global:
                    _g_ac = c.get("access_count", 0) or 0
                    # iter1031: global_deep_saturated_suppress — sync closure_fallback
                    if _g_ac >= 7:
                        return 2
                    return max(2, _t - (2 if _g_ac >= 4 else 1))
                # iter1009: local_saturated_suppress — sync closure_fallback
                _l_ac = c.get("access_count", 0) or 0
                if _l_ac >= 10:
                    return max(2, _t - 2)
                elif _l_ac >= 7:
                    return max(2, _t - 1)
                return _t
            # iter1020: suppress_final_gate_24h_saturated_sync — closure_fallback 同步
            def _fg1020_24h_thresh(s, c):
                _b = 3 if _fg887_tiny else (3 if s >= 0.5 else 2) if _fg887_small else (3 if s >= 0.5 else 2)
                _a = c.get("access_count", 0) or 0
                if _a >= 10:
                    return max(1, _b - 2)
                elif _a >= 7:
                    return max(1, _b - 1)
                return _b
            top_k = [(s, c) for s, c in top_k
                     if _recent_6h_counts.get(c["id"], 0) < 2
                     and _recent_24h_counts.get(c["id"], 0) < _fg1020_24h_thresh(s, c)
                     # iter904: 7d_rebalance_tiny — tiny_db 7d 2→4
                     # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                     and _recent_7d_counts.get(c["id"], 0) < _fg887_7d_thresh(s, c)]
            if len(top_k) < _pre887:
                _deferred.log(DMESG_WARN, "retriever",
                              f"iter887_closure_fallback_suppress: filtered "
                              f"{_pre887 - len(top_k)} chunks (closure 6h/24h/7d)",
                              session_id=session_id, project=project)
        # ── iter832: post_suppress_pair_inject — suppress 后单条时从快照补配对 ──
        # 根因（数据驱动，2026-05-05）：FULL 路径 44% 输出单条。iter826 pair_inject
        #   在 positive 阶段添加第 2 条，但 suppress_final_gate 事后砍掉 → 最终仍单条。
        # 修复：suppress 过滤后如果 top_k=1，从 _pre_suppress_top_k 中选不同 chunk 配对。
        # iter851: suppress_aware_pair — 配对候选尊重 suppress_final_gate 的 24h/7d 判定
        #   根因（数据驱动，2026-05-05）：iter832 从 _pre_suppress_top_k 恢复候选时不检查
        #   24h/7d suppress 计数，导致刚被 suppress_final_gate 移除的垄断 chunk 被重新注入。
        #   修复：候选过滤加入 _rt663_24h/_rt663_7d 检查（与 suppress_final_gate 阈值一致）。
        def _pair_suppress_ok(cid, score):
            """iter851: 检查候选是否被 suppress_final_gate 过滤（复用已计算的实时计数）。
            iter884: pair_suppress_relax — 配对候选放宽 7d 阈值（+2）
              根因（数据驱动，2026-05-05）：38-chunk 库 59% 注入为单条。
              _pair_suppress_ok 用与 suppress_final_gate 相同的 7d 阈值(tiny=3)，
              但活跃 chunk 7d>=3 极普遍 → 配对候选全被过滤 → 单条逃逸。
              配对是补充上下文非主注入，放宽 7d 阈值 +2 允许更多候选入选。"""
            try:
                _p24 = _rt663_24h.get(cid, 0)
                _p7d = _rt663_7d.get(cid, 0)
                _p24_lim = 3 if _sf663_tiny_db else (3 if score >= 0.5 else 2) if _sf663_small_db else (3 if score >= 0.5 else 2)
                # iter936: pair_7d_align_final_gate — 4/6/5/5→3/4/3/3 对齐 suppress_final_gate
                # iter947: pair_7d_tighten — 对齐 suppress_final_gate 堵 pair 逃逸
                # 数据驱动（2026-05-06）：7d=4 chunk 中 6/13 全部经 pair 路径逃逸（single=0, pair=4）
                #   iter946 将 pair 放宽到 5 导致 suppress_final_gate(3) 失效。回退对齐 daemon。
                # iter960: pair_7d_align_final_gate_v2 — tiny_db 5→4 堵 pair 逃逸
                # 根因（数据驱动，2026-05-06）：7d=4 chunk 被 suppress_final_gate(4) 拦截后
                #   经 pair 路径逃逸（pair lim=5 > final_gate=4）。对齐消除 1-gap 逃逸窗口。
                _p7d_lim = 6 if _sf663_tiny_db else (7 if score >= 0.5 else 5) if _sf663_small_db else (6 if score >= 0.5 else 4)  # iter1000: pair_7d sync final_gate+1
                return _p24 < _p24_lim and _p7d < _p7d_lim
            except NameError:
                return True  # suppress_final_gate 未执行（try 失败），不额外限制
        if len(top_k) == 1 and len(_pre_suppress_top_k) >= 2:
            _ps_top1_id = top_k[0][1].get("id", "")
            _ps_candidates = [(s, c) for s, c in _pre_suppress_top_k
                              if c.get("id", "") != _ps_top1_id and s > 0
                              and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                              and _pair_suppress_ok(c.get("id", ""), s)]
            if _ps_candidates:
                _ps_best = max(_ps_candidates, key=lambda x: x[0])
                top_k.append(_ps_best)
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter832_post_suppress_pair: paired {_ps_best[1].get('id','')[:12]} "
                              f"s={_ps_best[0]:.3f} with top1={_ps_top1_id[:12]}",
                              session_id=session_id, project=project)
        elif len(top_k) == 1 and len(final) >= 3:
            # iter842: post_suppress_pair_from_final — iter832 兜底失败时从 final 按 importance 配对
            # 根因（数据驱动，2026-05-05）：iter826/827 在 scoring 阶段未配对成功
            #   → _pre_suppress_top_k=1 → iter832 条件不满足 → 单条逃逸。
            #   37 cands 中仅 1 条过 threshold，其余全 score=0（suppress）。
            #   iter827 importance_pair 理论上应兜底，但在 adaptive_floor 将 _min_thresh
            #   降到 0.10 时 positive 可能已有多条（低分但 >0.10）导致 len(positive)!=1。
            # 修复：final_gate 后最终兜底——从 final 按 importance 选非 top1 chunk 配对。
            _ps842_top1_id = top_k[0][1].get("id", "")
            _ps842_cands = [(float(c.get("importance", 0) or 0), c) for _, c in final
                            if c.get("id") != _ps842_top1_id
                            and (c.get("access_count", 0) or 0) < 30
                            and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                            and _pair_suppress_ok(c.get("id", ""), 0.0)]
            if _ps842_cands:
                _ps842_best = max(_ps842_cands, key=lambda x: x[0])
                if _ps842_best[0] >= 0.3:
                    _ps842_score = top_k[0][0] * 0.25
                    top_k.append((_ps842_score, _ps842_best[1]))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter842_pair_from_final: paired {_ps842_best[1].get('id','')[:12]} "
                                  f"imp={_ps842_best[0]:.2f} with top1={_ps842_top1_id[:12]}",
                                  session_id=session_id, project=project)
        # ── iter895: db_diversity_pair — iter832/842 均失败时从 DB 选低频不同类型 chunk 配对 ──
        # 根因（数据驱动，2026-05-05）：54% 注入为单条。iter832 要求 _pre_suppress_top_k>=2（常=1），
        #   iter842 要求 final>=3 + importance>=0.3 + pair_suppress_ok（7d>=5 被过滤）。
        #   当 suppress 把所有候选干掉只剩 1 条时，两者均无法配对 → 单条逃逸。
        # 修复：从 DB 直接选 access_count 最低 + importance 最高的非 top1 chunk 作为补充上下文。
        #   限制：7d 注入 < suppress_final_gate 阈值 +3（比主注入更宽容），且 chunk_type 不同于 top1。
        if len(top_k) == 1:
            _dp895_top1 = top_k[0][1]
            _dp895_top1_id = _dp895_top1.get("id", "")
            _dp895_top1_type = _dp895_top1.get("chunk_type", "")
            try:
                # iter924: pair_type_relax — 放宽 chunk_type 限制为仅 id 去重
                # 根因（数据驱动，2026-05-06）：54% 单条注入。decision 占库 52%，
                #   chunk_type != top1_type 排除过半候选 → 配对失败。
                _dp895_exclude = f"'{_dp895_top1_id}'"
                _dp895_rows = conn.execute(
                    f"SELECT id, summary, content, chunk_type, importance, access_count "
                    f"FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                    f"AND id NOT IN ({_dp895_exclude}) "
                    f"ORDER BY importance DESC, access_count ASC LIMIT 5",
                    (project,)
                ).fetchall()
                # 过滤 7d 过高的候选
                _dp895_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                # iter920: fix NameError — _sf663_tiny_db 仅在 suppress_final_gate(line 4687) 内定义，
                #   LITE 路径或 try 失败时不存在 → NameError 被 except 吞掉 → pair 零触发。
                _dp895_tiny = _sf663_tiny_db if '_sf663_tiny_db' in dir() else (_db_chunk_count < 50)
                # iter947: pair_7d_tighten — 对齐 suppress_final_gate 堵 pair 逃逸
                # 数据驱动（2026-05-06）：pair 7d 放宽(5/5/6)使 suppress_final_gate(3/4/5)失效，
                #   6/13 高频 chunk 全经 pair 注入(single=0,pair=4)。回退对齐 daemon(3/4/5)。
                _dp895_small = _sf663_small_db if '_sf663_small_db' in dir() else (_db_chunk_count < 100)
                _dp895_lim = 3 if _dp895_tiny else (4 if _dp895_small else 5)
                _dp895_ok = [r for r in _dp895_rows
                             if _dp895_7d.get(r[0], 0) < _dp895_lim
                             and _session_injection_counts.get(r[0], 0) < _pair_dedup_thresh]
                if _dp895_ok:
                    _dp895_pick = _dp895_ok[0]
                    _dp895_chunk = {"id": _dp895_pick[0], "summary": _dp895_pick[1],
                                    "content": _dp895_pick[2], "chunk_type": _dp895_pick[3] or "",
                                    "importance": _dp895_pick[4] or 0.5}
                    _dp895_score = top_k[0][0] * 0.2  # 配对 score 为主条的 20%
                    top_k.append((_dp895_score, _dp895_chunk))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter895_db_diversity_pair: paired {_dp895_pick[0][:12]} "
                                  f"type={_dp895_pick[3]} imp={_dp895_pick[4]:.2f} "
                                  f"ac={_dp895_pick[5]} with top1={_dp895_top1_id[:12]}",
                                  session_id=session_id, project=project)
            except Exception:
                pass
        if not top_k:
            # ── iter670: suppress_fallback — suppress 全灭时降级注入最佳 1 条 ──
            # iter829: fallback_rotation — 避免 fallback 永远选同一 chunk 导致 same_hash 死循环
            # 根因（数据驱动，2026-05-05）：26% 空召回中 suppress_fallback 恢复的 chunk
            #   与上次注入的 hash 相同 → same_hash 跳过 → 用户永远看同一个知识。
            # 修复：排除上次已注入的 chunk 组合，选次优候选。若无次优则仍选最佳。
            if _pre_suppress_top_k:
                _last_hash = _read_hash()
                # iter892: fallback_exp_decay — 线性→指数衰减（同步 hard_deadline path）
                # iter893: fallback_hard_ceiling — 7d>=5 绝对不选（同步 hard_deadline path）
                # iter894: fallback_realtime_align — 优先用实时 DB 计数（与 suppress_final_gate 对齐）
                # 根因（数据驱动，2026-05-05）：fallback 用启动时闭包 _recent_7d_counts（滞后）+
                #   hard_ceiling=5，但 suppress_final_gate 用实时 DB + 阈值=3（tiny_db）。
                #   7d=3-4 的垄断 chunk 被 final_gate suppress 后又被 fallback 重新选中注入。
                #   修复：用 _rt663_7d（如已计算）替代 _recent_7d_counts，ceiling 对齐 final_gate。
                _fb_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                _fb_24h = _rt663_24h if '_rt663_24h' in dir() and _rt663_24h else _recent_24h_counts
                # iter1000: fallback_ceiling_align — tiny 3→5 sync final_gate
                _fb_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 5)
                # iter1008: fallback_global_ceiling_sync — FULL path 同步
                def _fb_chunk_ceiling(c):
                    if c.get("project", "") == "global" and (c.get("access_count", 0) or 0) >= 4:
                        return max(2, _fb_ceiling - 2)
                    # iter1009: local_saturated_suppress — FULL fallback ceiling sync
                    _lac = c.get("access_count", 0) or 0
                    if _lac >= 10:
                        return max(2, _fb_ceiling - 2)
                    elif _lac >= 7:
                        return max(2, _fb_ceiling - 1)
                    return _fb_ceiling
                _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                           if _fb_7d.get(c.get("id", ""), 0) < _fb_chunk_ceiling(c)
                           and _fb_24h.get(c.get("id", ""), 0) < 3]
                # iter1032: fallback_relax_24h — _fb_cap 全灭时放宽：只保留 7d ceiling，去掉 24h 过滤
                # 根因（数据驱动，2026-05-07）：31% 空召回。_fb_cap 同时检查 7d<ceiling AND 24h<3，
                #   密集 session 中 24h>=3 把所有 FTS 相关候选排除 → _fb_pool=None → db_ultimate_fallback
                #   盲查（无 FTS 相关性）→ score<0.10 被 _fb_floor 拦截 → 空召回。
                # 修复：_fb_cap 为空时二次筛选只保留 7d ceiling（24h burst 不应阻止 fallback 恢复）。
                if not _fb_cap:
                    _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                               if _fb_7d.get(c.get("id", ""), 0) < _fb_chunk_ceiling(c)]
                # iter1038: fallback_ceiling_escalate — small_db 全灭时放宽 ceiling +2 兜底
                # 根因（数据驱动，2026-05-07）：24-chunk 库 11/24 chunk 7d>=4，
                #   ceiling=4(ac>=7 local) 全灭 → _fb_pool=None → ultimate_fallback 盲选不相关知识。
                #   这些 chunk 是用户活跃项目的核心知识，suppress 全灭=系统对密集 session 无响应。
                # 修复：ceiling +2 重试，优先选最相关的被suppress知识（而非盲选全局无关知识）。
                if not _fb_cap and _db_chunk_count < 100:
                    _fb_cap = [(s, c) for s, c in _pre_suppress_top_k
                               if _fb_7d.get(c.get("id", ""), 0) < _fb_chunk_ceiling(c) + 2]
                # iter916: fallback_no_unfiltered_pool — 全灭时不回退无过滤池，走 db_ultimate_fallback
                _fb_pool = _fb_cap if _fb_cap else None
                # iter939: fallback_relevance_floor — 低相关性时不强制注入噪声
                # 根因（数据驱动，2026-05-06）：14.8% 注入 score<0.1，全来自 suppress_fallback。
                #   suppress 全灭不一定是频率过高，可能是当前 prompt 与库内知识本就无关。
                #   强制注入 score=0.06 的内容 = 用户感知噪声。
                # 修复：_fb_pool 最高分 < 0.05 时跳过此路径，落到 db_ultimate_fallback（有轮转多样性）。
                # iter940: floor_raise — 0.05→0.10 对齐 dead_zone_min/gap_bridge_floor
                #   数据驱动（2026-05-06）：PE chunk score=0.071 逃逸 0.05 floor，24h 5x 注入。
                # iter996: micro_db_floor_relax — <=5 自有 chunk 库 floor 0.10→0.01
                #   根因（数据驱动，2026-05-06）：abspath:51963532bc1b(1自有+6global)空召回率 100%(9/9)。
                #   global chunk FTS score 天然低(0.03-0.08)，0.10 floor 全灭 → ultimate_fallback
                #   ceiling=4 又排除 7d>=4 的 3 个 global → 空召回。小库有知识总比空好。
                _fb_floor = 0.01 if _db_chunk_count <= 5 else 0.10
                if _fb_pool and max(s for s, _ in _fb_pool) < _fb_floor:
                    _fb_pool = None  # 全部候选相关性极低，不强制注入
                if _fb_pool:
                    _fb_sorted = sorted(_fb_pool,
                                        key=lambda x: x[0] * (0.5 ** (_fb_7d.get(x[1].get("id", ""), 0) / 2)),
                                        reverse=True)
                    _fb = _fb_sorted[0]
                    if _last_hash and len(_fb_sorted) > 1:
                        _fb_hash = hashlib.md5(_fb[1].get("id", "").encode()).hexdigest()[:8]
                        if _fb_hash == _last_hash:
                            _fb = _fb_sorted[1]  # 选次优
                    top_k = [_fb]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter670_suppress_fallback: all {len(_pre_suppress_top_k)} "
                                  f"suppressed, fallback to best={_fb[1].get('id','')[:12]}",
                                  session_id=session_id, project=project)
            # iter916: fallback_no_unfiltered_pool 后 _fb_pool=None 也会落到这里
            if not top_k:
                # iter902+916: db_ultimate_fallback — 排除 7d 垄断 chunk
                _fb_7d_ult = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                # iter969: fallback_ceiling_align_final_gate — 对齐 suppress_final_gate 7d 阈值
                # 根因（数据驱动，2026-05-06）：tiny_db ceiling=3 比 suppress_final_gate(4) 更严格，
                #   导致主门禁放过的 7d=3 chunk 被 fallback 排除 → 21 次/7d 空召回（41%）。
                # 修复：ceiling 对齐 final_gate（tiny 3→4），fallback 不应比主门禁更紧。
                # iter1001: ult_ceiling_align_7d_thresh — tiny_db 4→5 对齐 _score_chunk 7d 阈值
                # 根因（数据驱动，2026-05-06）：26-chunk 库 _suppress_7d_thresh=5（iter1000），
                #   但 ult_ceiling=4 排除 7d=4 的 chunk → fallback 比主评分更严格 → 空召回。
                # 修复：ceiling 对齐 _suppress_7d_thresh（tiny 4→5）。
                _ult_ceiling = 5 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _ult_exclude = [cid for cid, cnt in _fb_7d_ult.items() if cnt >= _ult_ceiling]
                _ult_placeholders = ','.join(['?'] * len(_ult_exclude)) if _ult_exclude else ''
                _ult_where = f" AND id NOT IN ({_ult_placeholders})" if _ult_exclude else ''
                try:
                    # iter938: ultimate_fallback_rotation — 分钟级轮转打破固定选择
                    # 根因（数据驱动，2026-05-06）：suppress 全灭后 fallback 按 importance DESC
                    #   总选同一 chunk（最高 imp），直到 7d 达 ceiling 才换下一个。
                    #   36-chunk 库中 top3 imp chunk 轮流垄断 fallback 位。
                    # 修复：LIMIT 5 + minute%N 轮转，确保 fallback 多样性。
                    # iter969: fallback_include_global — 小库 fallback 包含 global chunks
                    # 根因（数据驱动，2026-05-06）：abspath:51963532bc1b（1 自有 chunk）9 次空召回。
                    #   WHERE project=? 排除 6 个 global chunk → fallback 空 → 空召回。
                    # 修复：查询条件加 OR project='global'，与 FTS 检索范围一致。
                    _dbuf_rows = conn.execute(
                        "SELECT id, summary, content, chunk_type, importance "
                        f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'{_ult_where} "
                        "ORDER BY importance DESC, access_count ASC LIMIT 5",
                        (project, *_ult_exclude)
                    ).fetchall()
                    if _dbuf_rows:
                        import time as _dbuf_time
                        _dbuf_idx = int(_dbuf_time.time() // 60) % len(_dbuf_rows)
                        _dbuf_row = _dbuf_rows[_dbuf_idx]
                        _dbuf_chunk = {"id": _dbuf_row[0], "summary": _dbuf_row[1],
                                       "content": _dbuf_row[2], "chunk_type": _dbuf_row[3] or "",
                                       "importance": _dbuf_row[4] or 0.5}
                        top_k = [(0.001, _dbuf_chunk)]
                        _deferred.log(DMESG_WARN, "retriever",
                                      f"iter938_db_ultimate_fallback_rotate: "
                                      f"id={_dbuf_row[0][:12]} imp={_dbuf_row[4]:.2f} "
                                      f"idx={_dbuf_idx}/{len(_dbuf_rows)} excluded={len(_ult_exclude)}",
                                      session_id=session_id, project=project)
                except Exception:
                    pass
                if not top_k:
                    # iter932: fallback_ceiling_escalation — 放宽 ceiling 重试
                    # 根因（数据驱动，2026-05-06）：23-chunk 活跃库 12 个 7d>=3，
                    #   ceiling=3 排除 52% → ultimate_fallback 空 → 空召回 16 条/7d。
                    # 修复：ceiling+3 重试，选 7d 较高但非极端垄断的 chunk。
                    # iter934: escalation_diversity_order — access_count ASC 优先
                    #   根因（数据驱动，2026-05-06）：escalation 用 importance DESC 排序，
                    #   高 imp 垄断 chunk（pe_analysis 7d=7）反复被选中。
                    #   改为低访问优先：用户看得少的知识优先注入，打破垄断轮换。
                    _esc_ceiling = _ult_ceiling + 3
                    _esc_exclude = [cid for cid, cnt in _fb_7d_ult.items() if cnt >= _esc_ceiling]
                    _esc_ph = ','.join(['?'] * len(_esc_exclude)) if _esc_exclude else ''
                    _esc_where = f" AND id NOT IN ({_esc_ph})" if _esc_exclude else ''
                    try:
                        # iter969: fallback_include_global — escalation 同步包含 global
                        _esc_row = conn.execute(
                            "SELECT id, summary, content, chunk_type, importance "
                            f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'{_esc_where} "
                            "ORDER BY access_count ASC, importance DESC LIMIT 1",
                            (project, *_esc_exclude)
                        ).fetchone()
                        if _esc_row:
                            _esc_chunk = {"id": _esc_row[0], "summary": _esc_row[1],
                                          "content": _esc_row[2], "chunk_type": _esc_row[3] or "",
                                          "importance": _esc_row[4] or 0.5}
                            top_k = [(0.001, _esc_chunk)]
                            _deferred.log(DMESG_WARN, "retriever",
                                          f"iter932_fallback_ceiling_escalation: "
                                          f"id={_esc_row[0][:12]} imp={_esc_row[4]:.2f} "
                                          f"ceiling={_ult_ceiling}→{_esc_ceiling}",
                                          session_id=session_id, project=project)
                    except Exception:
                        pass
                if not top_k:
                    return
        # ── iter914: post_fallback_pair — suppress_fallback 恢复单条后补配对 ──
        # 根因（数据驱动，2026-05-06）：52% 单条注入中多数因 suppress 全灭→fallback 恢复 1 条，
        #   但 iter895 在 fallback 之前执行（top_k=0 时条件不满足）→ 无配对机会。
        # 修复：fallback 恢复后再次从 DB 选不同类型低频 chunk 配对（复用 iter895 逻辑）。
        if len(top_k) == 1:
            _pf914_top1 = top_k[0][1]
            _pf914_top1_id = _pf914_top1.get("id", "")
            _pf914_top1_type = _pf914_top1.get("chunk_type", "")
            try:
                # iter924: pair_type_relax — 放宽 chunk_type 限制为仅 id 去重
                # 根因（数据驱动，2026-05-06）：54% 单条注入。24-chunk 库中 decision 占 52%，
                #   chunk_type != top1_type 排除过半候选 → 7d 过滤后常为空 → 配对失败。
                # 修复：仅排除 id 相同的 chunk，允许同类型不同知识配对。
                _pf914_rows = conn.execute(
                    f"SELECT id, summary, content, chunk_type, importance, access_count "
                    f"FROM memory_chunks WHERE project=? AND chunk_state='ACTIVE' "
                    f"AND id != ? "
                    f"ORDER BY importance DESC, access_count ASC LIMIT 5",
                    (project, _pf914_top1_id)
                ).fetchall()
                _pf914_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
                # iter923: pair_7d_align_final_gate — 对齐 suppress_final_gate 阈值
                # 根因（数据驱动，2026-05-06）：iter914 pair 的 7d 限制=6（tiny_db），
                #   而 suppress_final_gate 阈值=3。7d=4-5 的垄断 chunk 被 final_gate suppress
                #   后经 fallback→pair 路径复活注入（如 import-90139 7d=4 仍注入 6 次/7d）。
                # 修复：pair 7d 限制对齐 suppress_final_gate，阻止被 suppress 的 chunk 经配对逃逸。
                _pf914_lim = 3 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _pf914_ok = [r for r in _pf914_rows if _pf914_7d.get(r[0], 0) < _pf914_lim]
                if _pf914_ok:
                    _pf914_pick = _pf914_ok[0]
                    _pf914_chunk = {"id": _pf914_pick[0], "summary": _pf914_pick[1],
                                    "content": _pf914_pick[2], "chunk_type": _pf914_pick[3] or "",
                                    "importance": _pf914_pick[4] or 0.5}
                    top_k.append((top_k[0][0] * 0.2, _pf914_chunk))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter914_post_fallback_pair: paired {_pf914_pick[0][:12]} "
                                  f"type={_pf914_pick[3]} imp={_pf914_pick[4]:.2f} "
                                  f"with fallback_top1={_pf914_top1_id[:12]}",
                                  session_id=session_id, project=project)
            except Exception:
                pass
        # iter918: 确保 _pre_suppress_top_k 在 common path（FULL+LITE 合并点）有默认值
        # 根因：LITE 路径不经过 line 4606 的 FULL-only 赋值，到达 iter859 时 NameError
        #   被外层 try/except 吞掉 → diversity_probe 也在同一 try 块内 → 全部静默失败。
        # iter925: lite_rotation_use_pre_suppress — LITE 路径用 suppress 前快照
        #   根因（数据驱动，2026-05-06）：iter918 赋值 _pre_suppress_top_k = list(top_k)，
        #   但 LITE 路径此时 top_k 已被 suppress_final_gate_lite 缩减（与 FULL 路径 top_k 不同）。
        #   导致 len(_pre_suppress_top_k) == len(top_k) → iter859 条件永假 → rotation 零触发。
        #   实测：5月4日 5 次连续 same_hash 全是 import-90139，diversity_probe 是唯一出路。
        #   修复：LITE 路径优先用 _pre_suppress_top_k_lite（line 5124 的 suppress 前快照）。
        try:
            _pre_suppress_top_k
        except NameError:
            try:
                _pre_suppress_top_k = _pre_suppress_top_k_lite
            except NameError:
                _pre_suppress_top_k = list(top_k)
        top_k_ids = sorted([c["id"] for _, c in top_k])
        current_hash = hashlib.md5("|".join(top_k_ids).encode()).hexdigest()[:8]

        # prompt_hash 已在 TLB 检查时计算（迭代57）

        top_k_data = [
            {"id": c["id"], "summary": c["summary"], "score": round(s, 4), "chunk_type": c.get("chunk_type", "")}
            for s, c in top_k
        ]

        # iter805: session_first_inject_guard — 新 session 不走 same_hash 快捷路径
        _sid_inj_late = False
        try:
            with open(SESSION_INJECTED_FILE, encoding="utf-8") as _f:
                _sid_inj_late = session_id in _f.read()
        except OSError:
            pass
        if current_hash == _read_hash() and _sid_inj_late:
            # iter859: same_hash_rotation — hash 锁定时从 suppress 前快照选替代候选
            # 根因（数据驱动，2026-05-05）：git:a0ab16e8cafc 项目 33% trace 为 same_hash，
            #   suppress 后仅剩固定 1-2 条 → hash 永远相同 → 知识永不更新。
            # 修复：从 _pre_suppress_top_k 中选不在当前 top_k 的次优候选替换最低分条目。
            #   替换后重新计算 hash，若仍相同则放弃（真的没有新知识）。
            _sh_rotated = False
            _sh_top_k_ids_set = set(c["id"] for _, c in top_k)
            # iter918: relax s>0 → s>=0 — suppress 后 score=0 的候选也可参与 rotation
            # 根因（数据驱动，2026-05-06）：7d 内 22 次 same_hash skip 中 diversity_probe
            #   零触发。iter859 因 s>0 过滤排除了所有被 suppress 的候选（score=0），
            #   但这些候选本身有用户价值（只是因 7d/24h 频率被降权），作为 rotation 替代仍有意义。
            if _pre_suppress_top_k and len(_pre_suppress_top_k) > len(top_k):
                # iter931: rotation_suppress_aware — 排除 7d 高频 chunk（同 iter927 diversity_probe）
                # 根因（数据驱动，2026-05-06）：11/24 chunk 7d 注入 4 次（ceiling=3 应 suppress），
                #   suppress_final_gate 拦截后 same_hash → iter859 从 _pre_suppress_top_k 选候选
                #   不检查 7d → 垄断 chunk 经 rotation 逃逸 suppress。
                # 修复：候选过滤加 7d >= ceiling 排除（与 iter927 对齐）。
                _sh_7d_src = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else {}
                # iter992: rotation_7d_relax — 放宽 rotation 路径的 7d 排除阈值
                # 根因（数据驱动，2026-05-06）：22 次 skipped_same_hash 中 rotation 全未触发，
                #   因 7d_ceil=3 排除了 85-chunk 库中大部分活跃 chunk → 候选池枯竭。
                #   rotation 目的是打破 hash 锁定，不需要和 suppress 同样严格。
                # 修复：ceil 3→5（tiny_db）/ 5→7（small_db），给 rotation 更多候选空间。
                _sh_7d_ceil = 5 if _db_chunk_count < 50 else (7 if _db_chunk_count < 100 else 7)
                _sh_alt_cands = [(s, c) for s, c in _pre_suppress_top_k
                                 if c.get("id", "") not in _sh_top_k_ids_set
                                 and _sh_7d_src.get(c.get("id", ""), 0) < _sh_7d_ceil]
                if _sh_alt_cands:
                    _sh_best_alt = max(_sh_alt_cands, key=lambda x: x[0])
                    # 替换 top_k 中最低分的条目
                    _sh_min_idx = min(range(len(top_k)), key=lambda i: top_k[i][0])
                    top_k[_sh_min_idx] = _sh_best_alt
                    _sh_new_ids = sorted([c["id"] for _, c in top_k])
                    _sh_new_hash = hashlib.md5("|".join(_sh_new_ids).encode()).hexdigest()[:8]
                    if _sh_new_hash != current_hash:
                        current_hash = _sh_new_hash
                        top_k_data = [
                            {"id": c["id"], "summary": c["summary"], "score": round(s, 4),
                             "chunk_type": c.get("chunk_type", "")}
                            for s, c in top_k
                        ]
                        _sh_rotated = True
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter859_same_hash_rotation: swapped {_sh_best_alt[1].get('id','')[:12]} "
                                      f"s={_sh_best_alt[0]:.3f} breaking hash lock",
                                      session_id=session_id, project=project)
            if not _sh_rotated:
                # iter874→880: diversity_probe — same_hash 时从 DB 选低频高价值 chunk 打破 hash 锁定
                # 根因（数据驱动，2026-05-05）：20/22 same_hash 中 iter859 因 s>0 过滤全空未触发，
                #   diversity_probe 原先只对空 top_k 生效 → 非空 top_k same_hash 永远跳过。
                # iter880: minute_rotation — LIMIT 1 总选同一 chunk → 轮转失效 → hash 再次锁定。
                #   改用 LIMIT 10 + minute%N 分钟级轮转，确保每次选不同候选。
                _sh_top_k_ids = set(c.get("id", "") if isinstance(c, dict) else c["id"]
                                    for _, c in top_k) if top_k else set()
                try:
                    # iter927: diversity_probe_suppress_aware — 排除 7d 高频 chunk
                    # 根因（数据驱动，2026-05-06）：diversity_probe 选出的候选可能是已被
                    #   suppress_final_gate 拦截的垄断 chunk（7d>=3），轮转到的知识用户已反复看过。
                    # 修复：排除 7d >= suppress 阈值的 chunk，确保轮转到真正新鲜的知识。
                    _dp_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else {}
                    # iter992: rotation_7d_relax — 同步放宽 diversity_probe 的 7d 排除
                    _dp_7d_ceil = 5 if _db_chunk_count < 50 else (7 if _db_chunk_count < 100 else 7)
                    _dp_7d_exclude = set(cid for cid, cnt in _dp_7d.items() if cnt >= _dp_7d_ceil)
                    _dp_all_exclude = _sh_top_k_ids | _dp_7d_exclude
                    _dp_exclude = ",".join(f"'{x}'" for x in _dp_all_exclude) if _dp_all_exclude else "''"
                    # iter998: diversity_probe_include_global — 与 iter969 fallback_include_global 对齐
                    # 根因（数据驱动，2026-05-06）：22-chunk 库 20 次 skipped_same_hash，
                    #   diversity_probe 只查 project=? 排除 6 个 global chunk，候选池枯竭。
                    #   db_ultimate_fallback 已包含 global（iter969），此处遗漏。
                    # 修复：加 OR project='global'，扩大候选池打破 hash 锁定。
                    _dp_rows = conn.execute(
                        f"SELECT id, summary, content, chunk_type, importance, access_count "
                        f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE' "
                        f"AND id NOT IN ({_dp_exclude}) "
                        f"ORDER BY access_count ASC, importance DESC LIMIT 10",
                        (project,)
                    ).fetchall()
                    if _dp_rows:
                        # 分钟级轮转：per-request 进程无状态，用当前分钟做 round-robin
                        import time as _dp_time
                        _dp_idx = int(_dp_time.time() // 60) % len(_dp_rows)
                        _dp_row = _dp_rows[_dp_idx]
                        _dp_chunk = {"id": _dp_row[0], "summary": _dp_row[1],
                                     "content": _dp_row[2], "chunk_type": _dp_row[3] or "",
                                     "importance": _dp_row[4] or 0.5}
                        if top_k:
                            _sh_min_idx = min(range(len(top_k)), key=lambda i: top_k[i][0])
                            top_k[_sh_min_idx] = (0.01, _dp_chunk)
                        else:
                            top_k = [(0.01, _dp_chunk)]
                        top_k_data = [
                            {"id": c["id"], "summary": c["summary"], "score": round(s, 4),
                             "chunk_type": c.get("chunk_type", "")}
                            for s, c in top_k
                        ]
                        _sh_new_ids = sorted([c["id"] for _, c in top_k])
                        current_hash = hashlib.md5("|".join(_sh_new_ids).encode()).hexdigest()[:8]
                        _sh_rotated = True
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter880_diversity_probe_rotate: injecting "
                                      f"{_dp_chunk['id'][:12]} ac={_dp_row[5]} imp={_dp_row[4]:.2f} "
                                      f"idx={_dp_idx}/{len(_dp_rows)} "
                                      f"replacing={'empty' if not _sh_top_k_ids else 'lowest'}",
                                      session_id=session_id, project=project)
                except Exception as _dp_exc:
                    # iter918: 记录 diversity_probe 失败原因（此前 pass 导致零诊断）
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter918_diversity_probe_fail: {type(_dp_exc).__name__}: {_dp_exc}",
                                  session_id=session_id, project=project)
            if not _sh_rotated:
                _tlb_write(prompt_hash, current_hash, _get_db_mtime())  # 迭代57: TLB 回填
                _tlb_bump_generation()  # iter583: FULL 完成后 bump generation
                # 迭代61：PSI Noise Floor — skipped_same_hash 记录 duration_ms=0
                # 迭代84：切换到写连接记录 trace + flush deferred logs
                conn.close()
                try:
                    wconn = open_db()
                    ensure_schema(wconn)
                    _write_trace(session_id, project, prompt_hash,
                                 candidates_count, top_k_data, 0, "skipped_same_hash",
                                 0, conn=wconn)
                    _deferred.flush(wconn)
                    wconn.commit()
                    wconn.close()
                except Exception:
                    pass
                # 迭代85：Shadow Trace（same_hash 路径也知道工作集）
                _write_shadow_trace(project, [c["id"] for _, c in top_k], session_id)
                sys.exit(0)

        # 构造注入文本（按 chunk_type 加前缀标签）
        _TYPE_PREFIX = {
            "decision": "[决策]",
            "excluded_path": "[排除]",
            "reasoning_chain": "[推理]",
            "conversation_summary": "[摘要]",
            "task_state": "",
            "design_constraint": "⚠️ [约束]",
            "quantitative_evidence": "📊 [量化]",
            "causal_chain": "🔗 [因果]",
        }

        # ── iter758: suppress_final_gate_lite — LITE 路径 24h/7d suppress 兜底 ──
        # 根因（数据驱动，2026-05-04）：LITE 路径（含 psi_downgrade）缺少
        #   suppress_final_gate（仅 FULL 路径有 iter663）。_score_chunk 内的
        #   24h/7d suppress 依赖进程启动时缓存的 _recent_24h_counts，但跨 session
        #   快速连续请求时 timeline 文件竞态导致缓存过期。
        #   实测：import-90139 在 4 个不同 session（02:43/03:13/03:21/03:34）
        #   内连续注入 4 次，24h suppress(>=2) 未拦截。
        # 修复：注入前实时重读 injection_timeline 文件（<1ms, 27 entries），
        #   补充过滤已超 24h/7d 阈值的 chunk。
        _pre_suppress_top_k_lite = list(top_k)  # iter793: snapshot before suppress
        if top_k:
            try:
                _itl758 = {}
                if os.path.exists(_INJECTION_TIMELINE_FILE):
                    with open(_INJECTION_TIMELINE_FILE, encoding="utf-8") as _f758:
                        _itl758 = json.loads(_f758.read())
                from datetime import datetime as _dt758, timezone as _tz758, timedelta as _td758
                _now758 = _dt758.now(_tz758.utc)
                _cut758_24h = (_now758 - _td758(hours=24)).isoformat()
                _cut758_7d = (_now758 - _td758(days=7)).isoformat()
                _pre758 = len(top_k)
                # iter764: sync_small_db_relax — 同步 daemon iter703 小库放宽
                _sf758_tiny_db = _db_chunk_count < 50  # iter848: 边界 40→50
                _sf758_small_db = _db_chunk_count < 100
                # iter810: tiny_db_24h_relax — sync LITE final_gate
                # iter815: lite_6h_suppress_sync — LITE 路径补充 6h burst suppress（与 FULL 路径 iter813 对齐）
                # 根因（数据驱动，2026-05-05）：import-90139 在 psi_downgrade LITE 路径
                #   38 分钟内被 3 个不同 session 注入（02:43/03:13/03:21），因 LITE final_gate
                #   缺少 6h 检查而逃逸。FULL 路径第 3183 行有 6h<2 但 LITE 路径遗漏。
                # iter818: tiny_db_6h_relax — 6h 阈值分级
                _cut758_6h = (_now758 - _td758(hours=6)).isoformat()
                # iter837: tiny_db_24h_relax_v2 — 阈值 3→4（同步 _score_chunk）
                # iter905: cross_project_suppress_tighten — LITE 路径同步
                # iter908: final_gate_7d_align_score — tiny_db 4→3
                # iter990: small_db_7d_relax_v3 — LITE final_gate 路径同步
                def _lt905_7d_thresh(s, c):
                    _cp = c.get("project", "")
                    _cross = (_cp != project and _cp != "global")
                    _is_global = (_cp == "global")
                    if _sf758_tiny_db:
                        _t = 3
                    elif _sf758_small_db:
                        _t = 6 if s >= 0.5 else 4  # iter990: 4/3→6/4
                    else:
                        _t = 5 if s >= 0.5 else 3
                    if _cross:
                        return max(2, _t - 2)
                    elif _is_global:
                        _g_ac = c.get("access_count", 0) or 0
                        return max(2, _t - (2 if _g_ac >= 4 else 1))
                    # iter1021: lite_local_saturated_suppress — sync FULL/hd iter1009
                    _l_ac = c.get("access_count", 0) or 0
                    if _l_ac >= 10:
                        return max(2, _t - 2)
                    elif _l_ac >= 7:
                        return max(2, _t - 1)
                    return _t
                # iter1002: lite_micro_db_bypass — LITE 路径同步 FULL 的 micro_db bypass(line 4863)
                # 根因（数据驱动，2026-05-06）：git:78dc99a5695f（2 自有 chunk）LITE 路径 5/6 空召回。
                #   FULL 路径 iter968 已加 micro_db bypass，但 LITE 路径遗漏 → global chunk 被 7d suppress 全灭。
                # 修复：<=5 chunk 库跳过 suppress_final_gate_lite（与 FULL line 4863 对齐）。
                # iter1020: suppress_final_gate_24h_saturated_sync — LITE 路径同步
                def _lt1020_24h_thresh(s, c):
                    _b = 3 if _sf758_tiny_db else (3 if s >= 0.5 else 2) if _sf758_small_db else (3 if s >= 0.5 else 2)
                    _a = c.get("access_count", 0) or 0
                    if _a >= 10:
                        return max(1, _b - 2)
                    elif _a >= 7:
                        return max(1, _b - 1)
                    # iter1023: global_24h_saturated_cap — sync FULL path
                    if c.get("project") == "global" and _a >= 4:
                        return 1
                    return _b
                if _db_chunk_count > 5:
                    # iter1042: saturated_6h_cap — LITE 路径同步 ac>=7 → 6h 阈值=1
                    def _lt1042_6h_thresh(c):
                        _a6 = (c.get("access_count", 0) or 0)
                        return 1 if _a6 >= 7 else 2
                    top_k = [(s, c) for s, c in top_k
                             if sum(1 for t in _itl758.get(c["id"], []) if t > _cut758_6h) < _lt1042_6h_thresh(c)  # iter1042
                             and sum(1 for t in _itl758.get(c["id"], []) if t > _cut758_24h) < _lt1020_24h_thresh(s, c)
                             # iter885: lite_7d_sync_final_gate — 5/8/6→3/4/3 对齐 FULL suppress_final_gate iter883
                             # iter905: cross_project_suppress_tighten — 跨项目 7d -2
                             and sum(1 for t in _itl758.get(c["id"], []) if t > _cut758_7d) < _lt905_7d_thresh(s, c)]
                if len(top_k) < _pre758:
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter758_suppress_final_gate_lite: filtered "
                                  f"{_pre758 - len(top_k)} chunks (timeline re-read)",
                                  session_id=session_id, project=project)
                # ── iter793: suppress_fallback_lite — LITE 路径 suppress 全灭降级 ──
                # iter829: fallback_rotation (LITE path)
                # iter891: fallback_7d_decay_lite — 对齐 FULL/daemon 的 7d 频率衰减
                #   根因（数据驱动，2026-05-05）：LITE 路径 fallback 按纯 score 排序，
                #   高频 chunk（如 import-90139 7d=7x）每次被 fallback 选中 → 垄断逃逸。
                #   FULL 路径 (line 4707) 和 daemon 已有 score/(1+0.5*7d) 衰减。
                #   修复：用 _itl758 timeline 数据计算 7d count，应用相同衰减公式。
                if not top_k and _pre_suppress_top_k_lite:
                    # iter892: fallback_exp_decay — LITE 路径同步指数衰减
                    # iter893: fallback_hard_ceiling — 7d>=5 绝对不选（LITE 路径同步）
                    # iter894: fallback_realtime_align — ceiling 对齐 suppress_final_gate_lite 阈值
                    # iter911: pair_7d_tighten — fallback ceiling 4→3(tiny) 堵逃逸
                    _fb_lite_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 5)  # iter1000: tiny 3→5 sync
                    # iter1027: fallback_24h_align — 对齐 _lt1020_24h_thresh 动态阈值
                    _fb_lite_cap = [(s, c) for s, c in _pre_suppress_top_k_lite
                                    if sum(1 for t in _itl758.get(c.get("id", ""), []) if t > _cut758_7d) < _fb_lite_ceiling
                                    and sum(1 for t in _itl758.get(c.get("id", ""), []) if t > _cut758_24h) < _lt1020_24h_thresh(s, c)]
                    _fb_lite_pool = _fb_lite_cap if _fb_lite_cap else _pre_suppress_top_k_lite
                    # iter940: fallback_relevance_floor — LITE 路径同步（此前遗漏）
                    #   数据驱动（2026-05-06）：PE chunk score=0.071 走 LITE fallback 24h 3x 逃逸。
                    # iter996: micro_db_floor_relax — sync LITE path
                    _fb_lite_floor = 0.01 if _db_chunk_count <= 5 else 0.10
                    if _fb_lite_pool and max(s for s, _ in _fb_lite_pool) < _fb_lite_floor:
                        _fb_lite_pool = None
                    if _fb_lite_pool:
                        _fb_lite_sorted = sorted(
                            _fb_lite_pool,
                            key=lambda x: x[0] * (0.5 ** (sum(1 for t in _itl758.get(x[1].get("id", ""), []) if t > _cut758_7d) / 2)),
                            reverse=True)
                        _fb_lite = _fb_lite_sorted[0]
                        _last_hash_lite = _read_hash()
                        if _last_hash_lite and len(_fb_lite_sorted) > 1:
                            _fb_lite_hash = hashlib.md5(_fb_lite[1].get("id", "").encode()).hexdigest()[:8]
                            if _fb_lite_hash == _last_hash_lite:
                                _fb_lite = _fb_lite_sorted[1]
                        top_k = [_fb_lite]
                        _deferred.log(DMESG_WARN, "retriever",
                                      f"iter793_suppress_fallback_lite: all {_pre758} "
                                      f"suppressed, fallback to best={_fb_lite[1].get('id','')[:12]}",
                                      session_id=session_id, project=project)
            except Exception:
                pass  # timeline 读取失败不阻塞

        # ── iter988: db_ultimate_fallback_lite — LITE 路径 suppress 全灭兜底 ──
        # 根因（数据驱动，2026-05-06）：git:78dc99a5695f（2 chunks）连续 6 次 LITE 空召回。
        #   FULL 路径有 db_ultimate_fallback (line 5048) 兜底，但 LITE 路径遗漏。
        #   suppress_fallback_lite 因 relevance_floor(<0.10) 或 7d ceiling 全灭后无后续路径。
        # 修复：复用 FULL 路径逻辑——从 DB 选 importance 最高 + access_count 最低的 chunk，
        #   带分钟级轮转 + 7d ceiling 排除。消灭 LITE 路径空召回。
        if not top_k:
            try:
                _dbuf_lite_7d = {}
                try:
                    _dbuf_lite_7d = {cid: sum(1 for t in ts_list if t > _cut758_7d)
                                     for cid, ts_list in _itl758.items()}
                except NameError:
                    pass
                _dbuf_lite_ceiling = 4 if _db_chunk_count < 50 else (5 if _db_chunk_count < 100 else 5)
                _dbuf_lite_exclude = [cid for cid, cnt in _dbuf_lite_7d.items() if cnt >= _dbuf_lite_ceiling]
                _dbuf_lite_ph = ','.join(['?'] * len(_dbuf_lite_exclude)) if _dbuf_lite_exclude else ''
                _dbuf_lite_where = f" AND id NOT IN ({_dbuf_lite_ph})" if _dbuf_lite_exclude else ''
                _dbuf_lite_rows = conn.execute(
                    "SELECT id, summary, content, chunk_type, importance "
                    f"FROM memory_chunks WHERE (project=? OR project='global') AND chunk_state='ACTIVE'{_dbuf_lite_where} "
                    "ORDER BY importance DESC, access_count ASC LIMIT 5",
                    (project, *_dbuf_lite_exclude)
                ).fetchall()
                if _dbuf_lite_rows:
                    import time as _dbuf_lite_time
                    _dbuf_lite_idx = int(_dbuf_lite_time.time() // 60) % len(_dbuf_lite_rows)
                    _dbuf_lite_row = _dbuf_lite_rows[_dbuf_lite_idx]
                    _dbuf_lite_chunk = {"id": _dbuf_lite_row[0], "summary": _dbuf_lite_row[1],
                                        "content": _dbuf_lite_row[2], "chunk_type": _dbuf_lite_row[3] or "",
                                        "importance": _dbuf_lite_row[4] or 0.5}
                    top_k = [(0.001, _dbuf_lite_chunk)]
                    _deferred.log(DMESG_WARN, "retriever",
                                  f"iter988_db_ultimate_fallback_lite: "
                                  f"id={_dbuf_lite_row[0][:12]} imp={_dbuf_lite_row[4]:.2f} "
                                  f"idx={_dbuf_lite_idx}/{len(_dbuf_lite_rows)}",
                                  session_id=session_id, project=project)
            except Exception:
                pass

        # ── iter832: post_suppress_pair_inject — LITE 路径 suppress 后单条配对 ──
        # 同 FULL 路径逻辑：suppress_final_gate_lite 过滤后如果 top_k=1，
        # 从 _pre_suppress_top_k_lite 快照中选次优配对，确保多知识组合上下文。
        # iter851: suppress_aware_pair — 候选尊重 suppress_final_gate_lite 的 timeline 判定
        def _pair_suppress_ok_lite(cid, score):
            """iter851: LITE 路径检查候选是否被 suppress_final_gate_lite 过滤。
            iter884: pair_suppress_relax — 配对候选 7d 阈值放宽 +2（同 FULL 路径）。
            iter885: lite_7d_sync — pair 基础 7d 阈值同步收紧（tiny 5→3 base → pair 5）。"""
            try:
                _ts_list = _itl758.get(cid, [])
                _p6 = sum(1 for t in _ts_list if t > _cut758_6h)
                _p24 = sum(1 for t in _ts_list if t > _cut758_24h)
                _p7d = sum(1 for t in _ts_list if t > _cut758_7d)
                _p6_lim = 3 if _sf758_tiny_db else 2
                _p24_lim = 3 if _sf758_tiny_db else (3 if score >= 0.5 else 2) if _sf758_small_db else (3 if score >= 0.5 else 2)
                # iter911: pair_7d_tighten — tiny 5→4, small 6/5→5/4, large 7/5→5/5
                _p7d_lim = 5 if _sf758_tiny_db else (5 if score >= 0.5 else 4) if _sf758_small_db else (5 if score >= 0.5 else 5)  # iter952: LITE pair 6→5
                return _p6 < _p6_lim and _p24 < _p24_lim and _p7d < _p7d_lim
            except NameError:
                return True
        if len(top_k) == 1 and len(_pre_suppress_top_k_lite) >= 2:
            _ps_lite_top1_id = top_k[0][1].get("id", "")
            _ps_lite_cands = [(s, c) for s, c in _pre_suppress_top_k_lite
                              if c.get("id", "") != _ps_lite_top1_id and s > 0
                              and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                              and _pair_suppress_ok_lite(c.get("id", ""), s)]
            if _ps_lite_cands:
                _ps_lite_best = max(_ps_lite_cands, key=lambda x: x[0])
                top_k.append(_ps_lite_best)
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter832_post_suppress_pair_lite: paired "
                              f"{_ps_lite_best[1].get('id','')[:12]} s={_ps_lite_best[0]:.3f}",
                              session_id=session_id, project=project)
        elif len(top_k) == 1 and len(final) >= 3:
            # iter842: post_suppress_pair_from_final (LITE path)
            _ps842_lite_top1_id = top_k[0][1].get("id", "")
            _ps842_lite_cands = [(float(c.get("importance", 0) or 0), c) for _, c in final
                                 if c.get("id") != _ps842_lite_top1_id
                                 and (c.get("access_count", 0) or 0) < 30
                                 and _session_injection_counts.get(c.get("id", ""), 0) < _pair_dedup_thresh
                                 and _pair_suppress_ok_lite(c.get("id", ""), 0.0)]
            if _ps842_lite_cands:
                _ps842_lite_best = max(_ps842_lite_cands, key=lambda x: x[0])
                if _ps842_lite_best[0] >= 0.3:
                    _ps842_lite_score = top_k[0][0] * 0.25
                    top_k.append((_ps842_lite_score, _ps842_lite_best[1]))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter842_pair_from_final_lite: paired "
                                  f"{_ps842_lite_best[1].get('id','')[:12]} "
                                  f"imp={_ps842_lite_best[0]:.2f}",
                                  session_id=session_id, project=project)

        # ── iter868: final_single_pair — 最终单条配对安全网 ──────────────────
        # 根因（数据驱动，2026-05-05）：35% 注入仍为单条（12/34 traces），
        #   iter826/827/840/842/864 pair 逻辑全部 0 触发。
        #   原因：adaptive_floor 降低阈值后 positive>=2 进入 top_k，但后续
        #   constraint/DRR/MMR/suppress_final_gate 逐步移除到只剩 1 条。
        #   所有中间 pair 逻辑因 positive!=1 条件不满足而跳过。
        # 修复：dedup 之前最终检查——top_k==1 且库>=6 chunk 时，从 DB 查同 project
        #   低 access_count + 高 importance 的 chunk 补充配对。排除 top1 自身和
        #   session 内已注入的 chunk。仅 <50 chunk 库启用。
        if len(top_k) == 1 and _db_chunk_count >= 6 and _db_chunk_count < 50:
            _f868_top1_id = top_k[0][1].get("id", "")
            try:
                # iter1035: lite_pair_now_ts_fix — LITE 路径 _now_ts 未定义导致 NameError
                # 根因（数据驱动，2026-05-07）：LITE 50% 单条率。_now_ts 在 FULL 路径 line 4294
                #   定义（diversity_pair_from_db 内部），LITE 路径在 line 6626 才定义。
                #   iter868 在两者之间 → LITE 路径 NameError → except pass 静默吞掉 → 配对零触发。
                if '_now_ts' not in dir():
                    from datetime import datetime as _dt1035, timezone as _tz1035
                    _now_ts = _dt1035.now(_tz1035.utc).isoformat()
                import sqlite3 as _f868_sql
                _f868_conn = _f868_sql.connect(str(STORE_DB))
                _f868_rows = _f868_conn.execute(
                    "SELECT id, summary, content, chunk_type, importance, access_count "
                    "FROM memory_chunks WHERE project = ? AND chunk_state = 'ACTIVE' "
                    "AND importance >= 0.5 AND id != ? "
                    "ORDER BY access_count ASC, importance DESC LIMIT 6",
                    (project, _f868_top1_id)).fetchall()
                _f868_conn.close()
                _f868_cands = [r for r in _f868_rows
                               if _session_injection_counts.get(r[0], 0) < (_sysctl("retriever.session_dedup_threshold") or 2)]
                if _f868_cands:
                    # 轮转选择：用分钟数 % len 避免总选同一条
                    _f868_idx = int(_now_ts[14:16]) % len(_f868_cands) if len(_now_ts) > 16 else 0
                    _f868_pick = _f868_cands[_f868_idx]
                    _f868_chunk = {"id": _f868_pick[0], "summary": _f868_pick[1],
                                   "content": _f868_pick[2], "chunk_type": _f868_pick[3],
                                   "importance": _f868_pick[4], "access_count": _f868_pick[5]}
                    _f868_score = top_k[0][0] * 0.20
                    top_k.append((_f868_score, _f868_chunk))
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter868_final_single_pair: paired {_f868_pick[0][:12]} "
                                  f"imp={_f868_pick[4]:.2f} ac={_f868_pick[5]}",
                                  session_id=session_id, project=project)
            except Exception:
                pass  # best-effort

        # ── iter910: score_floor_gate — 低相关性注入拦截 ──────────────────
        # 根因（数据驱动，2026-05-06）：48% 注入 score<0.2，来源为 diversity_probe
        #   (score=0.01)、suppress_fallback、final_single_pair(score=top1*0.20) 等。
        #   低分 chunk 与用户当前上下文无关，注入后污染 context window、降低 SNR。
        # 修复：score < _score_floor 的 chunk 过滤掉。全部低于阈值时保留最高分 1 条
        #   （宁注入 1 条中低分也不注入 3 条极低分）。micro_db(<=5) 跳过。
        # iter913: score_floor_raise — 数据驱动提升阈值
        # 根因（数据驱动，2026-05-06）：73% 注入 score<0.15，useful feedback 最低=0.15。
        #   0.08 阈值过低未过滤任何噪声。提升到 0.12 过滤 40% 低相关性注入。
        _score_floor = 0.12
        if len(top_k) > 0 and _db_chunk_count > 5:
            _sf_pre_len = len(top_k)
            _sf_above = [(s, c) for s, c in top_k if s >= _score_floor]
            if _sf_above:
                if len(_sf_above) < len(top_k):
                    # iter926: pair_preserve — 保护配对不被 score_floor 砍到单条
                    # 根因（数据驱动，2026-05-06）：54% 注入为单条。iter868/895 配对
                    #   score=top1*0.20（如 top1=0.15 → pair=0.03），低于 floor=0.12 被移除。
                    #   导致 pair 机制零生效，用户始终只看到单点知识。
                    # 修复：过滤前 >=2 条 → 过滤后 =1 条时，保留被移除中最高分的 1 条配对。
                    if _sf_pre_len >= 2 and len(_sf_above) == 1:
                        _sf_below = [(s, c) for s, c in top_k if s < _score_floor]
                        if _sf_below:
                            _sf_kept_pair = max(_sf_below, key=lambda x: x[0])
                            _sf_above.append(_sf_kept_pair)
                            _deferred.log(DMESG_DEBUG, "retriever",
                                          f"iter926_pair_preserve: kept pair "
                                          f"{_sf_kept_pair[1].get('id','')[:12]} s={_sf_kept_pair[0]:.3f}",
                                          session_id=session_id, project=project)
                    _sf_removed = len(top_k) - len(_sf_above)
                    top_k = _sf_above
                    if _sf_removed > 0:
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter910_score_floor_gate: removed {_sf_removed} chunks "
                                      f"below score_floor={_score_floor}",
                                      session_id=session_id, project=project)
            else:
                # iter1043: floor_gate_skip — 全部低于阈值时不注入
                # 根因（数据驱动，2026-05-07）：24h 内 88% 注入 score<0.2，7/11 traces 全灭。
                #   全灭时 fallback 保留最高分 1 条（score=0.06~0.11）与用户上下文无关，
                #   注入 kernel/PE 知识到 memory-os Python 开发 session 纯属噪声。
                # 修复：全灭直接 skip，不强制注入无关知识。用户不看到噪声 > 少看到 1 条。
                _sf_best = max(top_k, key=lambda x: x[0])
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter1043_floor_gate_skip: all {len(top_k)} below "
                              f"floor={_score_floor}, best={_sf_best[0]:.3f} "
                              f"id={_sf_best[1].get('id','')[:12]}, skipping injection",
                              session_id=session_id, project=project)
                top_k = []

        # ── 迭代359：Session Injection Deduplication ──────────────────────
        # OS 类比：Linux copy-on-write page dedup（KSM kernel samepage merging）
        #   同一物理页被多次 map → 只在达到阈值后合并为单一只读页，避免重复 I/O。
        #   同一 chunk 在同一 session 被注入 >= threshold 次 → 从输出中剔除，
        #   避免 agent 每轮都收到已内化的知识（边际价值趋零）。
        #
        # iter587: 移除 design_constraint 无条件豁免 — 改为 2× threshold 宽松去重
        # 根因：'feishu CLI' 被注入 10/50 次、'memory 验证路径' 15/50 次，
        #   占 50% 注入槽位但多数与 query 无关。豁免导致垄断 chunk 永远无法被 dedup。
        # OS 类比：CFS sched_entity vruntime — 即使是 RT 任务也受 bandwidth throttle，
        #   否则单个 RT task 会饿死所有 SCHED_NORMAL 任务。
        # 修复：design_constraint 使用 2× 普通阈值（首次 session 仍可见，之后逐步降权）
        _iter359_dedup_threshold = _sysctl("retriever.session_dedup_threshold")
        _iter359_dedup_count = 0
        if _iter359_dedup_threshold > 0 and _session_injection_counts:
            _dedup_top_k = []
            _constraint_dedup_threshold = _iter359_dedup_threshold * 2  # iter587: 宽松阈值
            for _score, _chunk in top_k:
                _cid = _chunk.get("id", "")
                _ctype = _chunk.get("chunk_type", "")
                _inj_cnt = _session_injection_counts.get(_cid, 0)
                # iter587: design_constraint 使用宽松阈值（不再无条件豁免）
                # iter596: 高频 constraint (ac>30) 降回 1× — 已被用户内化，无需反复注入
                _ac = _chunk.get("access_count", 0) or 0
                if _ctype == "design_constraint" and _ac > 30:
                    _effective_threshold = _iter359_dedup_threshold  # 1× — 同普通 chunk
                elif _ctype == "design_constraint":
                    _effective_threshold = _constraint_dedup_threshold  # 2× — 低频约束仍宽松
                else:
                    _effective_threshold = _iter359_dedup_threshold
                if _inj_cnt >= _effective_threshold:
                    _iter359_dedup_count += 1
                    # 迭代29 dmesg 延迟日志
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter359 dedup chunk {_cid[:8]} inj_count={_inj_cnt}",
                                  session_id=session_id, project=project)
                else:
                    _dedup_top_k.append((_score, _chunk))
            if _iter359_dedup_count > 0:
                top_k = _dedup_top_k
        # ── iter671: dedup_empty_guard — dedup 后 top_k 为空时 early exit ──
        # 根因（数据驱动，2026-05-04）：suppress_fallback 给出 1 条 chunk，
        #   但该 chunk 在同 session 已被注入 >= threshold 次 → dedup 移除 → top_k=[]
        #   → 后续无条件 print(output) 注入只有 header 没有知识的空内容
        #   → _write_trace injected=1 但 top_k=[] → 污染 recall_traces 统计。
        #   实测：37/60 (62%) injected=1 trace 实际注入 0 条 chunk。
        # 修复：dedup 后 top_k 为空 → 视为"无有效知识"，不注入、不记录。
        if not top_k:
            conn.close()
            return
        # ─────────────────────────────────────────────────────────────────────

        # 迭代100：置信度标识（OS 类比：ECC status bit per cache line）
        def _conf_tag(c):
            vs = c.get("verification_status", "pending")
            cs = c.get("confidence_score", 0.7) or 0.7
            if vs == "disputed":
                return "❓"
            if vs == "verified" or cs >= 0.9:
                return "✅"
            # iter490: 阈值调整 0.50 → 0.30（减少噪音，只标记真正低可信）
            if cs < 0.3:
                return "⚠️"
            return ""

        # 迭代98：分离约束知识和普通知识，约束优先展示
        # 迭代306：批量取 raw_snippet（只对 importance >= 0.75 的 chunk 附加原文）
        _high_imp_ids = [c["id"] for _, c in top_k if (c.get("importance") or 0) >= 0.75]
        _raw_snippets: dict = {}
        if _high_imp_ids:
            try:
                _rs_ph = ",".join("?" * len(_high_imp_ids))
                _rs_rows = conn.execute(
                    f"SELECT id, raw_snippet FROM memory_chunks WHERE id IN ({_rs_ph})",
                    _high_imp_ids,
                ).fetchall()
                _raw_snippets = {r[0]: r[1] for r in _rs_rows if r[1]}
            except Exception:
                pass

        # ── iter472: Inject-Score 加权排序 ───────────────────────────────────────
        # 问题：top_k 只按 trigram_score 排序，低 importance 的噪声 chunk 可能排在高 importance
        #   的相关 chunk 之前，浪费 token 预算，降低 SNR。
        # 解决：inject_score = trigram_score × sqrt(importance) — 结合相关性和历史重要性。
        # sqrt（而非直接乘）：平衡相关性和 importance 的贡献（防止 importance 过度主导）。
        # OS 类比：Linux BFQ I/O 调度 — 综合 weight × throughput 计算 service budget，
        #   高 importance 进程（foreground app）在同等 I/O 请求时优先获得 dispatch 配额。
        # 注意：design_constraint chunk 不参与此排序（已有独立前置 header）。
        if _sysctl("retriever.inject_sort_enabled") and len(top_k) >= 2:
            try:
                import math as _math
                # iter644: constraint_inject_floor — design_constraint 也必须过绝对 score 门槛
                # 根因（数据驱动，2026-05-03）：b50e0b54 被各种 suppress 压到 score=0.0003，
                #   但 _inj_constraints 无条件收录 → 仍被注入。score<0.001 的 constraint
                #   已被 suppress 判定为当前无价值，不应占用 token 预算。
                _constraint_floor = 0.001
                _inj_constraints = [(s, c) for s, c in top_k
                                    if c.get("chunk_type") == "design_constraint"
                                    and s >= _constraint_floor]
                _inj_normal = [(s, c) for s, c in top_k
                               if c.get("chunk_type") != "design_constraint"]
                if len(_inj_normal) >= 2:
                    _inj_normal_scored = [
                        (s, c, s * _math.sqrt(max(0.01, float(c.get("importance") or 0.5))))
                        for s, c in _inj_normal
                    ]
                    _inj_normal_sorted_scored = sorted(_inj_normal_scored,
                                                       key=lambda x: x[2], reverse=True)
                    # iter475: min_inject_score 相对门槛过滤 — inject_score < ratio × max → 丢弃
                    # 防止无关噪声 chunk 占用 token 预算（相对阈值适应不同项目的 score 分布）
                    # OS 类比：Linux I/O scheduler budget exhaustion — BFQ 在 budget 用尽时
                    #   丢弃低优先级请求，而非无限排队（防止 latency spike）。
                    _min_ratio = _sysctl("retriever.inject_score_min_ratio") or 0.10
                    if _inj_normal_sorted_scored:
                        _max_score = _inj_normal_sorted_scored[0][2]
                        _score_threshold = _max_score * _min_ratio
                        _inj_normal_sorted_scored = [
                            item for item in _inj_normal_sorted_scored
                            if item[2] >= _score_threshold
                        ]
                    _inj_normal_sorted = [(s, c) for s, c, _ in _inj_normal_sorted_scored]
                    top_k = _inj_constraints + _inj_normal_sorted
            except Exception:
                pass  # inject_sort 失败不阻塞

        # ── iter427: Serial Position Effect — 注入顺序优化（Murdock 1962）──────────
        # OS 类比：Linux BFQ/CFQ front-merge — 最高优先级 I/O 请求置于 dispatch queue 头部；
        #   类比首因锚（primacy anchor）；recency anchor 在 queue 尾部确保最后被读取。
        # 认知科学依据：Murdock (1962) 序列位置曲线 — 首位和末位项目记忆最佳：
        #   首因效应（primacy）：首项经过多次 rehearsal，进入长期记忆
        #   近因效应（recency）：末项驻留 STM，即时可用
        #   中间项目受"输出干扰"（Roediger & McDermott 1995）抑制，记忆最差
        # 策略：将非约束 top_k 中 importance >= threshold 或特定 chunk_type 的 chunk
        #   重排到首位（primacy）和末位（recency），避免高价值 chunk 埋在中间。
        # 约束类型（design_constraint）已通过前置 header 机制获得首因位置，不参与此排序。
        if _sysctl("retriever.serial_position_enabled") and len(top_k) >= 3:
            try:
                _spe_threshold = _sysctl("retriever.serial_position_imp_threshold") or 0.85
                _spe_types = set((_sysctl("retriever.serial_position_recency_types") or "").split(","))
                # 分离约束和普通 chunk（约束已有首因优势，只对 normal 重排）
                _spe_constraints = [(s, c) for s, c in top_k if c.get("chunk_type") == "design_constraint"]
                _spe_normal = [(s, c) for s, c in top_k if c.get("chunk_type") != "design_constraint"]
                if len(_spe_normal) >= 3:
                    # 分出高价值候选（primacy/recency 锚点候选）
                    _spe_high = [(s, c) for s, c in _spe_normal
                                 if float(c.get("importance") or 0) >= _spe_threshold
                                 or c.get("chunk_type", "") in _spe_types]
                    _spe_mid = [(s, c) for s, c in _spe_normal
                                if (s, c) not in _spe_high]
                    if _spe_high:
                        # 首因锚：高价值 chunk 中最高 score → 首位
                        _spe_high_sorted = sorted(_spe_high, key=lambda x: x[0], reverse=True)
                        _primacy = _spe_high_sorted[:1]
                        _recency = _spe_high_sorted[1:2]  # 次高 → 末位
                        _spe_remaining_high = _spe_high_sorted[2:]
                        # 重排：[primacy] + mid + remaining_high + [recency]
                        # 中间保持 score 降序（BFQ 中优先级次高请求在 dispatch 中间位置）
                        _mid_ordered = sorted(_spe_mid + _spe_remaining_high,
                                              key=lambda x: x[0], reverse=True)
                        _spe_reordered = _primacy + _mid_ordered + _recency
                        top_k = _spe_constraints + _spe_reordered
                        _deferred.log(DMESG_DEBUG, "retriever",
                                      f"iter427 serial_position: primacy={_primacy[0][1].get('id','')[:8]} "
                                      f"recency={_recency[0][1].get('id','')[:8] if _recency else 'none'}",
                                      session_id=session_id, project=project)
            except Exception:
                pass  # serial position 失败不阻塞主流程

        # ── iter975: output_monopoly_filter — 最终输出前去垄断（single control point）──
        # 根因（数据驱动，2026-05-06）：suppress 分散在 _score_chunk/final_gate/fallback/pair
        #   十余处，每处阈值不同，垄断 chunk 总能通过某条路径逃逸。
        #   实测：top chunk 占 19.4% 注入（7d=7），前5占 74.2%。
        # 修复：在 inject_lines 构建前做最终过滤——7d >= ceiling 的 chunk 移除，
        #   但至少保留 1 条（防空召回）。这是所有逃逸路径的唯一汇聚点。
        # iter977: omf_realtime_source — 优先用 _rt663_7d（实时 DB + session-dedup），
        #   解决闭包快照 _recent_7d_counts 在 session 内不更新 + 无 session-dedup 的问题。
        if top_k and len(top_k) > 1 and not _micro_db:
            _omf_7d_src = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
            _omf_ceiling = 5 if _db_chunk_count < 50 else (6 if _db_chunk_count < 100 else 5)  # iter1000: tiny 3→5 sync
            _omf_filtered = [(s, c) for s, c in top_k
                             if _omf_7d_src.get(c.get("id", ""), 0) < _omf_ceiling]
            if _omf_filtered:
                if len(top_k) != len(_omf_filtered):
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"iter975_output_monopoly_filter: {len(top_k)}->{len(_omf_filtered)}",
                                  session_id=session_id, project=project)
                top_k = _omf_filtered
            else:
                # iter987: omf_graduated_fallback — 全灭时选 7d 最低的 top-2
                # 根因（数据驱动，2026-05-06）：23-chunk 库 13/21 chunk 7d>=3(ceiling)，
                #   只选 1 条过度限制多样性——用户每次只看到 1 条知识，信息量不足。
                # 修复：按 7d count 升序取前 min(2, len) 条，排除最高垄断者同时保留多样性。
                _omf_sorted = sorted(top_k, key=lambda x: _omf_7d_src.get(x[1].get("id", ""), 0))
                top_k = _omf_sorted[:min(2, len(_omf_sorted))]
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter987_omf_graduated_fallback: {len(_omf_sorted)}->{len(top_k)}, 7d={[_omf_7d_src.get(x[1].get('id',''), 0) for x in top_k]}",
                              session_id=session_id, project=project)

        # ── iter1013: topic_group_dedup — 同主题群体去垄断 ─────────────────────
        # 根因（数据驱动，2026-05-07）：3 条 quantitative_evidence（migration +125%）各 7d=4
        #   不触发 per-chunk suppress（ceiling=5），但群体占注入 12/62=19%。
        #   per-chunk suppress 无法解决"同主题多条各自不超阈值但群体垄断"。
        # 修复：用 summary 中 [topic] 前缀做 group key，同 topic 最多保留 1 条
        #   （7d 最低者优先），释放注入位给不同主题。micro_db 豁免。
        if top_k and len(top_k) > 1 and not _micro_db:
            _tgd_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
            _tgd_seen = {}  # topic_key -> chunk_id
            _tgd_result = []
            for _tgd_s, _tgd_c in top_k:
                _tgd_sum = (_tgd_c.get("summary") or "")
                # 提取 [xxx] 前缀作为 topic key
                _tgd_key = _tgd_sum.split("]")[0] + "]" if _tgd_sum.startswith("[") and "]" in _tgd_sum else None
                if not _tgd_key or _tgd_key not in _tgd_seen:
                    _tgd_result.append((_tgd_s, _tgd_c))
                    if _tgd_key:
                        _tgd_seen[_tgd_key] = _tgd_c.get("id", "")
                else:
                    _tgd_cur_7d = _tgd_7d.get(_tgd_c.get("id", ""), 0)
                    _tgd_exist_7d = _tgd_7d.get(_tgd_seen[_tgd_key], 0)
                    if _tgd_cur_7d < _tgd_exist_7d:
                        _tgd_result = [(s, c) for s, c in _tgd_result if c.get("id", "") != _tgd_seen[_tgd_key]]
                        _tgd_result.append((_tgd_s, _tgd_c))
                        _tgd_seen[_tgd_key] = _tgd_c.get("id", "")
            if len(_tgd_result) < len(top_k):
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter1013_topic_group_dedup: {len(top_k)}->{len(_tgd_result)}",
                              session_id=session_id, project=project)
                top_k = _tgd_result if _tgd_result else top_k[:1]

        # ── iter1014: type_group_cap — 同 chunk_type 群体占比限制 ─────────────────
        # 根因（数据驱动，2026-05-07）：79% 多条注入存在同 chunk_type >=2 条群体垄断。
        #   iter1013 topic_group_dedup 只看 [topic] 前缀（覆盖 18% chunk），
        #   causal_chain/reasoning_chain 等无前缀 chunk 完全逃逸。
        # 修复：同 chunk_type 最多保留 2 条（7d 最低优先），释放注入位给不同类型。
        #   design_constraint 豁免（本身就是高价值约束，不应被限制）。micro_db 豁免。
        # iter1016: dc_saturated_group_cap — ac>=7 的 design_constraint 不再豁免
        #   根因（数据驱动，2026-05-07）：11 个 design_constraint 占 7d 注入 52%（32/62）。
        #   ac>=7 表明 agent 已多次内化该约束（git commit ac=9, Android ac=10），无需每次注入。
        #   修复：仅 ac<7 的新鲜 constraint 无条件保留；ac>=7 进入正常 type_group_cap 竞争。
        if top_k and len(top_k) > 2 and not _micro_db:
            _tgc_7d = _rt663_7d if '_rt663_7d' in dir() and _rt663_7d else _recent_7d_counts
            _tgc_type_slots = {}  # chunk_type -> [(7d, idx)]
            _tgc_keep = set()
            for _tgc_i, (_tgc_s, _tgc_c) in enumerate(top_k):
                _tgc_ct = _tgc_c.get("chunk_type", "")
                # iter1016: only exempt fresh constraints (ac<7); saturated ones compete normally
                if _tgc_ct == "design_constraint" and (_tgc_c.get("access_count", 0) or 0) < 7:
                    _tgc_keep.add(_tgc_i)
                    continue
                _tgc_cid = _tgc_c.get("id", "")
                _tgc_r7d = _tgc_7d.get(_tgc_cid, 0)
                _tgc_type_slots.setdefault(_tgc_ct, []).append((_tgc_r7d, _tgc_i))
            for _tgc_ct, _tgc_slots in _tgc_type_slots.items():
                _tgc_slots.sort()  # 7d 升序，保留最低 2 条
                for _tgc_r7d, _tgc_idx in _tgc_slots[:2]:
                    _tgc_keep.add(_tgc_idx)
            if len(_tgc_keep) < len(top_k):
                _tgc_new = [top_k[i] for i in sorted(_tgc_keep)]
                _deferred.log(DMESG_DEBUG, "retriever",
                              f"iter1014_type_group_cap: {len(top_k)}->{len(_tgc_new)}",
                              session_id=session_id, project=project)
                top_k = _tgc_new if _tgc_new else top_k[:1]

        constraint_items = []
        normal_items = []
        for _, c in top_k:
            prefix = _TYPE_PREFIX.get(c.get("chunk_type", ""), "")
            conf = _conf_tag(c)
            # iter474: Token-budget aware summary truncation — importance tier 控制摘要长度
            # 高 importance chunk 保留完整摘要（细节更有价值）；低 importance 摘要截短（减少噪声 token）
            # OS 类比：Linux /proc/slabinfo — 高频对象（hot slab）保留完整元数据，
            #   低频对象（cold slab）元数据压缩存储，节省 slab cache 空间。
            _imp_val = float(c.get("importance") or 0.5)
            if _imp_val >= 0.75:
                _sum_limit = 200   # 高 importance：保留完整（含 raw_snippet）
            elif _imp_val >= 0.40:
                _sum_limit = 100   # 中等：适度截断
            else:
                _sum_limit = 60    # 低 importance：大幅截断，减少噪声
            _summary_truncated = c['summary'][:_sum_limit]
            line = f"{conf}{prefix} {_summary_truncated}".strip()
            # 迭代306：importance >= 0.75 且有 raw_snippet → 附加原文（≤150字）
            # 迭代361：已 FULL 注入过的 chunk 降级为 LITE（跳过 raw_snippet，节省 ~30-80 tokens）
            rs = _raw_snippets.get(c["id"], "")
            if rs and c["id"] not in _session_full_injected:
                rs_short = rs[:150]
                line = f"{line}（原文：{rs_short}）"
            if c.get("chunk_type") == "design_constraint":
                constraint_items.append(line)
            else:
                normal_items.append(line)

        header = "【相关历史记录（BM25 召回）】"
        if page_fault_queries:
            header += f"  ← 含上轮缺页补入"
        inject_lines = [header]

        # 约束先显示，后跟普通知识
        if constraint_items:
            inject_lines.append("")
            inject_lines.append("【已知约束（系统级设计限制）】")
            inject_lines.extend(constraint_items)

            # 迭代98：如果约束被强制注入（不在自然 top_k 中），加入置信度免责
            if forced_constraints:
                inject_lines.append("")
                inject_lines.append("ℹ️ 注：上述约束经系统强制注入（非检索相关性排序），")
                inject_lines.append("代表已知设计决策，但在本次会话的局部上下文中可能未出现信号词。")
                inject_lines.append("若约束与当前任务无关，可选择性忽略。")

            inject_lines.append("")
            inject_lines.append("【相关知识】")
            inject_lines.extend(normal_items)
        else:
            inject_lines.extend(normal_items)
        # KnowledgeVFS：追加跨系统召回
        # 迭代41：router 受 soft deadline 约束（最低优先级阶段）
        # 迭代B1：knowledge_router → knowledge_vfs_init.search() 迁移
        # 迭代B4：VFS LITE Fast Path — LITE 模式也查 VFS，用短 timeout（10ms）
        #   防止 LITE 路径错过 self-improving/wiki 和 MEMORY.md 知识。
        #   FULL: timeout=100ms（默认），LITE: timeout=10ms（快速失败不阻塞）。
        # 迭代357：FULL 路径升级为 scatter_gather_route（Domain-Aware 并发检索）
        if _KR_AVAILABLE and not _check_deadline("router"):
            try:
                if priority == "FULL":
                    # 迭代357：scatter_gather_route 并发检索所有知识源（domain-aware）
                    from hooks.knowledge_router import scatter_gather_route as _sg_route
                    _sg_timeout = 100
                    _sg_result = _sg_route(
                        query=query,
                        project=project,
                        timeout_ms=_sg_timeout,
                        conn=conn,
                    )
                    if _sg_result and _sg_result.get("results"):
                        # 格式化 scatter_gather 结果为注入文本
                        _sg_items = []
                        for r in _sg_result["results"][:6]:
                            _src = r.get("source", "")
                            _sum = (r.get("summary") or "")[:120]
                            if _sum:
                                _sg_items.append(f"[{_src}] {_sum}")
                        if _sg_items:
                            inject_lines.append("[跨系统知识]")
                            inject_lines.extend(_sg_items)
                else:
                    # LITE 路径沿用原来的 kr_route（10ms fast-fail）
                    _vfs_timeout = 10
                    kr_results = kr_route(query, sources=["memory-md", "self-improving"],
                                          timeout_ms=_vfs_timeout)
                    if kr_results:
                        kr_section = kr_format(kr_results)
                        inject_lines.append(kr_section)
            except Exception:
                pass  # VFS/scatter-gather 超时或无结果不阻塞主路径

        # ── 迭代101: Tool Pattern Hint — 意图感知工具模式建议 ──
        # OS 类比：CPU branch predictor hint (likely/unlikely) — 基于历史跳转记录预测执行路径
        #
        # 两层匹配策略：
        # L1 意图感知匹配：_matched_patterns 中选 unique_tools 最多的模式
        # L2 意图→工具类型映射：对特定意图（implement/fix_bug），查找含 TaskCreate/Read 的模式
        # 都无结果时：只在多样性工具模式存在时给出提示（不注入单调 Bash*N）
        try:
            if priority == "FULL":
                import json as _pj
                _hint_seq = None
                _hint_freq = 0
                _hint_reason = ""

                # L1: 意图感知命中模式 → 选 unique_tools 最多的
                if _matched_patterns:
                    best = max(
                        _matched_patterns,
                        key=lambda p: (len(set(p["seq"])), p["freq"])
                    )
                    if len(set(best["seq"])) >= 2:
                        _hint_seq = best["seq"]
                        _hint_freq = best["freq"]
                        _hint_reason = f"因 {','.join(best['overlap'][:2])} 匹配" if best.get("overlap") else ""

                # L2: 意图映射 — 对 implement/fix_bug/explore 额外查 TaskCreate/Read 模式
                if not _hint_seq:
                    intent_name, _ = _predict_intent(prompt)
                    if intent_name in ("implement", "fix_bug", "explore"):
                        _tp2 = conn.execute(
                            """SELECT tool_sequence, SUM(frequency) as frequency
                               FROM tool_patterns
                               GROUP BY tool_sequence
                               HAVING SUM(frequency) >= 3
                               ORDER BY frequency DESC LIMIT 50"""
                        ).fetchall()
                        for _s2_j, _f2 in _tp2:
                            s2 = _pj.loads(_s2_j) if isinstance(_s2_j, str) else _s2_j
                            # 优先含任务/读取工具的多样性序列
                            if len(set(s2)) >= 2 and any(t in s2 for t in ("TaskCreate", "Read", "Edit", "Write")):
                                _hint_seq = s2
                                _hint_freq = _f2
                                _hint_reason = f"意图={intent_name}"
                                break

                if _hint_seq:
                    hint = f"[工具模式] {' → '.join(_hint_seq)} (freq={_hint_freq}"
                    if _hint_reason:
                        hint += f"，{_hint_reason}"
                    hint += ")"
                    inject_lines.append(hint)
        except Exception:
            pass  # tool pattern hint 失败不阻塞

        # ── iter366: Knowledge Graph 1-hop expansion ────────────────────────
        # OS 类比：prefetch adjacent pages — BM25 命中后扩散邻边补充关联知识
        # 人的联想类比：语义网络扩散 — 从已激活节点扩散到强关联邻节点
        try:
            _graph_seed_ids = [c["id"] for _, c in top_k]
            if _graph_seed_ids:
                from store_graph import expand_with_neighbors, ensure_graph_schema
                ensure_graph_schema(conn)
                _graph_neighbors = expand_with_neighbors(
                    conn, _graph_seed_ids, top_n=2, min_weight=0.55,
                    exclude_types=["entity_stub", "tool_insight", "prompt_context"]
                )
                if _graph_neighbors:
                    _graph_lines = ["【关联知识（图扩散）】"]
                    for _gn in _graph_neighbors:
                        _et = _gn.get("edge_type", "related")
                        _gs = _gn.get("summary", "")[:80]
                        _graph_lines.append(f"  ↳[{_et}] {_gs}")
                    inject_lines.extend(_graph_lines)
        except Exception:
            pass  # graph 扩散失败不阻塞

        # ── iter471: Second-Chance Diversity Sampling ─────────────────────────
        # 问题：检索器只按 importance×retrievability 评分，高历史稳定性但当前 importance
        #   低的 chunk 永远排不到 top_k，形成"死锁衰减"——太冷检不到 → Ebbinghaus 继续衰减
        #
        # OS 类比：Linux MGLRU second-chance promotion (Yu Zhao 2022) —
        #   老代（gen=max）页面被 kswapd 扫到时，若 Accessed bit=1 → 晋升到最年轻代
        #   给旧热页一次"重新证明自己"的机会，避免 LRU 误淘汰热页
        #
        # 心理学：Spaced Retrieval Practice (Cepeda et al. 2006) —
        #   重新激活边缘记忆比重复强化已有记忆产生更大的长期增益
        #
        # 实现：以 10% 概率（_SECOND_CHANCE_PROB）随机采样 1 个 chunk：
        #   条件：stability >= 5（历史曾被频繁引用）AND importance < 0.20（当前低 importance）
        #   AND 不在当前 top_k 中（不重复注入）
        #   注入方式：在 inject_lines 末尾追加，标注 [历史相关]（区分于主检索结果）
        try:
            import random as _random
            _SECOND_CHANCE_PROB = 0.10   # 10% 触发概率（低概率避免噪声）
            _SECOND_CHANCE_STAB = 5.0    # stability 下限
            _SECOND_CHANCE_IMP_MAX = 0.20  # importance 上限（只给低 importance 的 chunk 机会）
            if (not has_page_fault
                    and _sysctl("retriever.second_chance_enabled")
                    and _random.random() < _SECOND_CHANCE_PROB):
                _current_ids = {c["id"] for _, c in top_k}
                _sc_skip_types = frozenset({
                    "task_state", "prompt_context", "conversation_summary",
                    "session_summary", "goal",
                })
                _sc_row = conn.execute(
                    """SELECT id, summary, importance, stability FROM memory_chunks
                       WHERE project=?
                         AND COALESCE(stability, 0) >= ?
                         AND importance < ?
                         AND importance > 0.05
                         AND chunk_type NOT IN ('task_state','prompt_context',
                             'conversation_summary','session_summary','goal')
                       ORDER BY RANDOM() LIMIT 1""",
                    (project, _SECOND_CHANCE_STAB, _SECOND_CHANCE_IMP_MAX)
                ).fetchone()
                if _sc_row and _sc_row[0] not in _current_ids:
                    _sc_id, _sc_summary, _sc_imp, _sc_stab = _sc_row
                    inject_lines.append(
                        f"\n[历史相关 · stability={_sc_stab:.1f}] {_sc_summary[:120]}"
                    )
                    # 加入 top_k（供 write-back 更新 access）
                    top_k = top_k + [(0.0, {"id": _sc_id, "summary": _sc_summary,
                                            "importance": _sc_imp, "chunk_type": "second_chance"})]
        except Exception:
            pass  # second-chance 失败不阻塞

        context_text = "\n".join(inject_lines)
        if len(context_text) > effective_max_chars:
            context_text = context_text[:effective_max_chars] + "…"

        reason_base = "first_call" if not _read_hash() else "hash_changed"
        reason = f"{reason_base}|{priority.lower()}"  # 迭代28：trace 中记录调度优先级
        if psi_downgraded:
            reason += "|psi_downgrade"  # 迭代36：PSI 反馈降级标记
        if deadline_skipped:
            reason += f"|deadline_skip:{'+'.join(deadline_skipped)}"  # 迭代41
        if _iter359_dedup_count > 0:
            reason += f"|dedup:{_iter359_dedup_count}"  # 迭代359：去重计数
        _write_hash(current_hash)
        _mark_session_injected(session_id)  # iter805
        _tlb_write(prompt_hash, current_hash, _get_db_mtime())  # 迭代57: TLB
        _tlb_bump_generation()  # iter583: FULL 完成后 bump generation

        output = {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": context_text,
            }
        }

        # ── 迭代69：Write-After-Response — 输出前置，写入后置 ──────────────
        # OS 类比：Linux write-back caching (2001, Andrew Morton)
        #   read() 从 page cache 直接返回（O_DIRECT bypass），不等 writeback。
        #   dirty pages 由 pdflush/writeback 线程异步刷盘。
        #   用户感知延迟 = read latency（~μs），不含 write latency（~ms）。
        #
        #   memory-os 等价问题：
        #     retriever 的读路径（FTS5+scorer）只需 ~7ms，
        #     但写路径（recall_traces INSERT + update_accessed + commit + close）~140ms：
        #       commit: ~40ms（WAL + synchronous=NORMAL）
        #       close: ~100ms（WAL auto-checkpoint）
        #     原来 print(output) 在 commit+close 之后 → 用户感知 ~200ms。
        #
        #   解决：
        #     print(output) + sys.stdout.flush() 移到 commit 之前。
        #     用户立即收到结果（~60ms），写入异步完成（进程退出前）。
        #     数据完整性不受影响：写入仍在同一进程内完成，只是顺序调整。
        # ── 迭代69+84：输出前置 + 只读连接关闭 ──
        print(json.dumps(output, ensure_ascii=False))
        sys.stdout.flush()  # 确保输出立即到达 Claude Code
        conn.close()  # 关闭只读连接

        # ── 迭代84：Write-Back Phase — 写连接批量写入 ──
        duration_ms = (_time.time() - _t_start) * 1000
        accessed_ids = [c["id"] for _, c in top_k]

        # ── 迭代333：Session Injection Counts Write-Back ──────────────────────
        # OS 类比：Linux dirty page writeback — pdflush 把内存中的 dirty_writeback_count
        #   写回磁盘，下次进程启动时从磁盘恢复，实现跨请求的会话内统计。
        # 每次注入后更新计数，持久化到 _SESSION_INJ_FILE，供下次 _score_chunk 读取。
        try:
            for _inj_c in accessed_ids:
                _session_injection_counts[_inj_c] = _session_injection_counts.get(_inj_c, 0) + 1
            # 迭代361：FULL 路径注入的 chunk 加入 full_injected 集合
            # OS 类比：Linux page cache dirty bit — 已写入页面标记，重复写入走快路径（LITE format）
            if priority == "FULL":
                _session_full_injected.update(accessed_ids)
            with open(_SESSION_INJ_FILE, 'w', encoding="utf-8") as _sif_w:
                _sif_w.write(json.dumps({"session_id": session_id,
                                         "counts": _session_injection_counts,
                                         "full_injected": list(_session_full_injected)},  # 迭代361
                                        ensure_ascii=False))
        except Exception:
            pass  # 计数写入失败不影响已输出的结果
        # ── iter647: injection timeline write-back ──
        try:
            from datetime import datetime as _dt647w, timezone as _tz647w
            _now_ts = _dt647w.now(_tz647w.utc).isoformat()
            for _inj_tid in accessed_ids:
                if _inj_tid not in _injection_timeline:
                    _injection_timeline[_inj_tid] = []
                _injection_timeline[_inj_tid].append(_now_ts)
            with open(_INJECTION_TIMELINE_FILE, 'w', encoding="utf-8") as _itf_w:
                _itf_w.write(json.dumps(_injection_timeline, ensure_ascii=False))
        except Exception:
            pass
        # 迭代323: SM-2 recall_quality — 从 top_k 平均分推断
        _avg_score = (sum(s for s, _ in top_k) / len(top_k)) if top_k else 0.0
        _recall_quality_main = 5 if _avg_score > 0.6 else (4 if _avg_score > 0.3 else 3)
        # FTS5 命中的 query 整体 quality 更高；BM25 fallback 降一级
        if not use_fts:
            _recall_quality_main = max(2, _recall_quality_main - 1)
        # 迭代29 dmesg：记录注入结果
        # 迭代41：deadline 信息加入日志
        deadline_info = f" deadline_skip={'+'.join(deadline_skipped)}" if deadline_skipped else ""
        # 迭代50：DRR 类型分布统计
        drr_types = {}
        for _, c in top_k:
            ct = c.get("chunk_type", "task_state")
            drr_types[ct] = drr_types.get(ct, 0) + 1
        drr_info = f" drr={drr_types}" if len(drr_types) > 1 else ""
        try:
            wconn = open_db()
            ensure_schema(wconn)
            update_accessed(wconn, accessed_ids, recall_quality=_recall_quality_main)
            mglru_promote(wconn, accessed_ids)  # 迭代45：MGLRU promote
            # 迭代515：userfaultfd — import chunk 首次命中时 promote
            try:
                from store_mm import userfaultfd_promote as _uffd
                _uffd(wconn, accessed_ids)
            except Exception:
                pass
            # iter531：mlock_onfault — ONFAULT chunk 首次命中时升级为 PROTECTED
            try:
                from store_mm import mlock_onfault_promote as _mop
                _mop(wconn, accessed_ids)
            except Exception:
                pass
            # 迭代511：page_idle clear — 从 idle bitmap 移除被命中的 chunks
            try:
                from store_mm import page_idle_clear as _pic
                _pic(accessed_ids, project)
            except Exception:
                pass

            # ── 迭代311-A：Reconsolidation — 召回触发 importance 强化 ────────
            # OS 类比：ARC T2 晋升 — 被反复命中的页面从 T1 晋升，淘汰优先级降低
            try:
                from store_vfs import reconsolidate as _reconsolidate
                _rc_n = _reconsolidate(wconn, accessed_ids, query=query, project=project)
                if _rc_n:
                    _deferred.log(DMESG_DEBUG, "retriever",
                                  f"reconsolidate: {_rc_n} chunks importance boosted",
                                  session_id=session_id, project=project)
            except Exception:
                pass  # reconsolidate 失败不影响主流程

            # iter668+678: top_k_data fallback — 防御空 top_k_data 导致 recall_counts 失准
            # 数据驱动（2026-05-04）：len(top_k_data) 与 len(accessed_ids) 不一致时重建
            _effective_top_k = top_k_data if (top_k_data and len(top_k_data) == len(accessed_ids)) else [{"id": cid} for cid in accessed_ids]
            # iter825: skip_empty_trace_sync — 对齐 daemon iter800，防止空 trace 污染统计
            # 根因（数据驱动，2026-05-05）：26% injected traces 的 top_k_json=[]，
            #   膨胀 bw_window 分母 → suppress 比例失真 → 垄断检测失效。
            if not _effective_top_k:
                _deferred.flush(wconn)
                dmesg_log(wconn, DMESG_WARN, "retriever",
                          f"iter825_skip_empty_trace: accessed_ids_empty={not accessed_ids}",
                          session_id=session_id, project=project)
                wconn.commit()
                wconn.close()
                sys.exit(0)
            _write_trace(session_id, project, prompt_hash,
                         candidates_count, _effective_top_k, 1, reason,
                         duration_ms, conn=wconn)
            _deferred.flush(wconn)
            _fts_tag = 'Y' if use_fts else f'N(glb_disc={_bm25_global_discount})'
            # ── B10: per-source injection stats (vmstat-style observability) ──
            # OS 类比：/proc/vmstat pgpgin/pgpgout — 内核 per-source 页面计数器，
            #   用于分析 page cache 热度分布和 swap 效率。
            _src_global = sum(1 for _, c in top_k if c.get("project") == "global")
            _src_local = len(top_k) - _src_global
            _src_tag = f' src=local:{_src_local}/global:{_src_global}'
            dmesg_log(wconn, DMESG_INFO, "retriever",
                      f"injected={len(top_k)} candidates={candidates_count} fts={_fts_tag}{'+bm25=' + str(_hybrid_bm25_count) if _hybrid_bm25_count > 0 else ''}{_src_tag} {duration_ms:.1f}ms{deadline_info}{drr_info}",
                      session_id=session_id, project=project,
                      extra={"top_k_ids": accessed_ids, "priority": priority,
                              "deadline_skipped": deadline_skipped,
                              "drr_type_distribution": drr_types,
                              "src_global": _src_global, "src_local": _src_local})
            # ── B14: Adaptive Oversample Governor ─────────────────────────
            # OS 类比：cpufreq ondemand governor — 自动调整超采样倍数
            # 连续 3 次 duration_ms > 60ms → 降低 oversample_factor（3→2）减少候选池
            # 连续 3 次 duration_ms < 30ms → 恢复 oversample_factor（2→3）提升召回率
            try:
                from config import sysctl_set as _sysctl_set
                _gov_key = "retriever.oversample_factor"
                _cur_factor = _sysctl(_gov_key) or 3
                if duration_ms > 60:
                    # 高延迟：降低采样倍数（节流）
                    if _cur_factor > 2:
                        _sysctl_set(_gov_key, _cur_factor - 1)
                elif duration_ms < 30 and _cur_factor < 3:
                    # 低延迟且当前已降级：恢复采样倍数
                    _sysctl_set(_gov_key, 3)
            except Exception:
                pass
            wconn.commit()
            wconn.close()
        except Exception:
            pass  # write-back 失败不影响已输出的结果
        # 迭代85：Shadow Trace — 记录最后一次成功检索的 top_k IDs
        _write_shadow_trace(project, accessed_ids, session_id)
        # iter391: IOR — 更新返回抑制状态（injection 后记录本次注入的 chunk turn）
        _update_ior_state(accessed_ids, session_id,
                          exempt_types=set((_sysctl("retriever.ior_exempt_types") or "").split(",")),
                          chunk_types={c["id"]: c.get("chunk_type", "") for _, c in top_k})
        sys.exit(0)
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    # ── 迭代61：vDSO Fast Path ──
    # Stage 0 (SKIP) + Stage 1 (TLB) 在 heavy import 之前执行
    # 如果 fast exit 成功，进程在 _vdso_fast_exit() 内 sys.exit(0)
    # 如果 fast exit 失败，_vdso_hook_input 已设置，继续到 main()
    _vdso_fast_exit()
    main()


# ══════════════════════════════════════════════════════════════════════════════
# 迭代92: Intent Prediction — 基于用户意图的预测性知识预加载
# OS 类比：Linux readahead(2) — 基于顺序访问模式预测后续页面，提前 DMA 读入 page cache
#         在实际 page fault 发生前就完成 I/O，消除首次访问延迟
#
# 意图识别：从用户 prompt 推断本轮意图类型，映射到对应的知识标签
# 预加载：匹配到高置信度意图时，在 FTS5 检索前先 pin 住对应标签的 chunk
# ══════════════════════════════════════════════════════════════════════════════

_INTENT_MAP = {
    "continue":     (r"^(继续|continue|接着|下一步|接下来|go on)", ["decision", "reasoning_chain"]),
    "fix_bug":      (r"(bug|fix|修复|错误|报错|exception|error|crash|fail)", ["excluded_path", "decision"]),
    # iter117: code_review 和 implement 加入 procedure（操作协议/SOP 在这两个意图下最相关）
    "code_review":  (r"(review|审查|代码|code|check|看一下)", ["decision", "procedure"]),
    "understand":   (r"(为什么|^why[^a-z]|^what |什么是|如何|how to|how does|解释|explain|分析|原理)", ["reasoning_chain", "conversation_summary"]),
    "implement":    (r"(实现|implement|开发|build|写|create|新增|add)", ["decision", "procedure"]),
    "optimize":     (r"(优化|optim|性能|performance|faster|slower|慢)", ["decision", "reasoning_chain"]),
    "explore":      (r"(探索|^explore|研究|^investigate|发现|find|搜索)", ["conversation_summary", "decision"]),
}


def _predict_intent(prompt: str) -> tuple[str, list[str]]:
    """
    从 prompt 预测意图类型，返回 (intent_name, preferred_chunk_types)。
    未匹配时返回 ("unknown", [])。
    """
    import re
    prompt_lower = prompt.lower()
    for intent, (pattern, preferred_types) in _INTENT_MAP.items():
        if re.search(pattern, prompt_lower):
            return intent, preferred_types
    return "unknown", []


def _intent_prefetch(conn, project: str, prompt: str, top_k: int = 3) -> list:
    """
    意图预测性预加载：根据意图类型预取对应标签的 chunk。
    返回预取的 chunk dicts 列表（格式与 _unified_retrieval_score 兼容）。
    """
    intent, preferred_types = _predict_intent(prompt)
    if intent == "unknown" or not preferred_types:
        return []

    try:
        type_placeholders = ",".join("?" * len(preferred_types))
        _ip_projects = [project] if project == "global" else [project, "global"]
        _ip_proj_ph = ",".join("?" * len(_ip_projects))
        rows = conn.execute(
            f"""SELECT id, summary, chunk_type, importance, last_accessed, access_count
                FROM memory_chunks
                WHERE project IN ({_ip_proj_ph})
                  AND chunk_type IN ({type_placeholders})
                  AND COALESCE(access_count, 0) < 30
                ORDER BY importance DESC, access_count DESC
                LIMIT ?""",
            [*_ip_projects, *preferred_types, top_k * 2]
        ).fetchall()
        if not rows:
            return []
        # 简单的 intent_boost: 0.05
        return [
            {
                "id": r[0], "summary": r[1], "chunk_type": r[2],
                "importance": r[3], "last_accessed": r[4],
                "access_count": r[5] or 0, "intent_prefetch": intent,
                "intent_boost": 0.05
            }
            for r in rows[:top_k]
        ]
    except Exception:
        return []
