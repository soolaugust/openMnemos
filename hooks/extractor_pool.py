#!/usr/bin/env python3
"""
memory-os extractor_pool — iter260 Async Extraction Worker Pool

OS 类比：Linux kworker pool + pdflush writeback
  - kworker pool: 多个预分配 worker 线程从 work_queue 取任务并行处理
  - pdflush / flush-X:Y: 后台 writeback 线程，解耦 I/O 等待与进程运行

问题：extractor.py Stop hook 是同步的。
  transcript parsing (_read_transcript_tail + _extract_from_tool_outputs + _extract_tool_patterns)
  平均消耗 50-150ms 的文件 I/O。Stop hook 运行期间 Claude 等待这段 I/O。

方案：
  1. Stop hook 只提交 extract_task 到 ipc_msgq（<5ms）→ 立即返回
  2. extractor_pool 常驻进程轮询 ipc_msgq → 取任务 → 完整提取 → 写 store.db → broadcast
  3. 多 session 并发时，各 session 的 extract_task 由独立 Worker 线程并行处理（kworker pool）

架构：
  ┌─ Stop hook ─────────────────────────────────────────────────────┐
  │  ipc_send(extract_task) → return 0                              │
  └─────────────────────────────────────────────────────────────────┘
                        ↓  ipc_msgq (SQLite)
  ┌─ extractor_pool (常驻进程) ────────────────────────────────────────┐
  │  MainLoop: poll every POLL_INTERVAL_SECS                          │
  │   → ipc_recv(extract_task) → ThreadPoolExecutor.submit(worker_fn) │
  │                                                                     │
  │  worker_fn(task):                                                   │
  │   1. _run_extraction_pipeline(hook_input)   # 复用 extractor.py 逻辑│
  │   2. write to store.db                                              │
  │   3. broadcast_knowledge_update via net.agent_notify               │
  └─────────────────────────────────────────────────────────────────────┘

OS 类比细化：
  - ipc_msgq     ↔  kernel work_queue (work_struct 链表)
  - Worker thread ↔  kworker/N (预分配 kthread，取 work_struct 执行)
  - POOL_WORKERS  ↔  max_active (kworker pool 最大并发数)
  - poll interval ↔  timer interrupt 唤醒 ksoftirqd 频率

与 retriever_daemon 的差异：
  - retriever_daemon: Unix socket，每请求一线程（高频低延迟）
  - extractor_pool: ipc_msgq 轮询，ThreadPoolExecutor（低频高吞吐）
  - 选择 ipc_msgq 而非 Unix socket：提取任务需持久化（防止 pool 崩溃丢任务）
"""

import sys
import os
import json
import time
import logging
import signal
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

# ── 配置 ─────────────────────────────────────────────────────────────────────
MEMORY_OS_DIR = Path.home() / ".claude" / "memory-os"
STORE_DB = MEMORY_OS_DIR / "store.db"

POOL_WORKERS   = int(os.environ.get("EXTRACTOR_POOL_WORKERS", "3"))
POLL_INTERVAL  = float(os.environ.get("EXTRACTOR_POOL_POLL", "2.0"))   # seconds
TASK_BATCH     = int(os.environ.get("EXTRACTOR_POOL_BATCH", "5"))      # per poll
HEARTBEAT_FILE = MEMORY_OS_DIR / "extractor_pool.heartbeat"
PID_FILE       = MEMORY_OS_DIR / "extractor_pool.pid"
LOG_FILE       = MEMORY_OS_DIR / "extractor_pool.log"

POOL_AGENT_ID  = "extractor_pool"

# ── 日志 ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
log = logging.getLogger("extractor_pool")


# ── iter525: memfd_seal — Write Gate Integrity Seal ──────────────────────────
# OS 类比：Linux memfd_seal(F_SEAL_WRITE) (Jeff Xu, 2024) —
# sealed memory 拒绝损坏数据写入，在 write 入口强制完整性校验。
# 根因：extractor_pool._write_chunks() 缺少 _is_fragment()/_is_quality_chunk() 检查，
# 导致 table row fragments 和 JSON truncation artifacts 直接写入 DB。

import re as _re

def _seal_check_reject(text: str) -> bool:
    """返回 True 表示该文本是碎片/损坏数据，应拒绝写入。
    合并 extractor.py 中 _is_fragment() + _is_quality_chunk() 的核心检查。"""
    if not text or len(text) < 10:
        return True
    # _is_fragment 核心规则
    if text[0] in ('_', '|', ')', ']', '}', '>', '+', '=', ':', '：', '）', '】', '》',
                   ',', '，', '、', ';', '；', '#'):
        return True
    if _re.match(r'^[\d\s.,:;/×\-+=%]+$', text):
        return True
    if text.count('|') >= 2:
        return True
    stripped = text.rstrip()
    if stripped.endswith(':') or stripped.endswith('：'):
        return True
    # iter525 新增：JSON truncation fragments — 小写拉丁字母碎片开头
    # 特征：以小写拉丁字母开头 + 含 JSON 键值特征（": "）
    # 根因：assistant 输出含 JSON 结构，regex 捕获组截断到 value 中间
    if _re.match(r'^[a-z]', text) and _re.search(r'": "', text[:40]):
        return True
    # iter525 新增：裸小写词片段 + 紧跟下划线 — 无 () 的截断标识符
    # 排除合法函数引用如 "sleep_consolidate() ..."
    if _re.match(r'^[a-z]{2,}_', text) and '()' not in text[:30]:
        return True
    # _is_quality_chunk 核心规则
    if _re.match(r'^[\[\]\-|]', text):
        return True
    if text.count('|') >= 3:
        return True
    # JSON 键值对碎片
    if text.startswith('"') and _re.match(r'^"[\w_]+":', text):
        return True
    if len(_re.findall(r'"[\w_]+"\s*:', text)) >= 2:
        return True
    # iter593: self-referential noise — memory-os 自身实现细节不是用户知识
    # 根因：iterate.sh agent 修改代码时，extractor 把实现决策写成 chunk，87% 零访问。
    # 检测特征：含代码标识符（变量名/函数名格式）= 在描述代码实现而非领域知识。
    _code_idents = ('top_k', 'recall_count', 'thrash_max_pct', 'bw_window',
                    'same_hash', '_sysctl', '_effective', 'chunk_type',
                    'retriever.', 'extractor.', 'retriever_daemon',
                    'pre_hash_thrash', 'thrash_suppress', '_write_chunk',
                    '_seal_check', '_vma_validate', 'insert_chunk',
                    # iter757: 补充 memory-os 内部变量名漏网
                    'hard_cap', 'inject_hard', 'suppress_fallback',
                    'bandwidth_throttle', 'score_chunk', 'final_gate',
                    # iter890: iterator_param_tuning_noise — 漏网的迭代器参数/机制名
                    'diversity_pair', 'suppress', 'fallback_rotation',
                    'closure_fallback', 'pair_dedup',
                    # iter1052: self_impl_hook_names — hook 组件名逃逸
                    'posttool_guard', 'output_compressor', 'thrashing_detector',
                    'x5 gate', 'x5_gate')
    _tl = text.lower()
    if any(ci in _tl for ci in _code_idents):
        return True
    # iter594: operational_noise — 操作确认和迭代器自我分析
    if _re.search(r'已(?:追加|更新|删除|记录|写入).*iter\d+', _tl):
        return True
    if '迭代器' in text:
        return True
    if len(text.strip()) <= 30 and not _re.search(r'[A-Za-z0-9/_.→:：]', text):
        return True
    # iter607: memoryos_meta — 中文内部概念关键词拦截
    # 根因：_code_idents 拦截英文标识符，但中文描述的内部概念（"注入垄断"、"零访问"）漏网。
    _META_CN = ('注入垄断', '零访问', '写入门控', '噪声写入', '去垄断',
                '垄断现象', '垄断 chunk',
                # iter890: iterator_param_tuning — 衰减/阈值/触发率 调参记录
                '衰减到', '触发率', '垄断率', '注入位')
    if any(m in text for m in _META_CN):
        return True
    # iter786: memoryos_arch_selfref — 拦截 memory-os 架构自描述
    # 根因（数据驱动，2026-05-04）：extractor 写入 memory-os 自身架构概览（L4 SQLite、
    #   BM25/FTS5、daemon 常驻等）— 用户不需要知道记忆系统内部架构。
    #   swap 中 24%（16/66）是此类自描述，active 中有 2 个。
    _ARCH_KW = ('Memory-OS', 'memory-os', 'recall_traces', 'memory_chunks',
                'hybrid_tokenize', 'SessionStart预热', 'UserPromptSubmit注入',
                'daemon 常驻', 'extractor_pool', 'retriever_daemon',
                'chunk_version', 'store.db', 'swap_chunks')
    if any(ak in text for ak in _ARCH_KW):
        return True
    # iter786: ephemeral_dir_structure — 拦截项目目录结构描述
    # 根因：目录结构可随时 ls 获取，不需持久记忆；且结构频繁变化导致过期。
    if _re.search(r'(?:项目目录|目录结构|主工作目录|工作区).{0,20}(?:含|包含|子项目|子目录)', text):
        return True
    # iter631: iterator_quantitative_selfeval — 迭代器量化自评模式拦截
    # 根因：迭代 agent 写入自身度量变化（"X → Y", "PA 10/10", "chunks N→M"），
    #   这些是 point-in-time 运行日志，不是可复用领域知识。零访问率 100%。
    # 特征：含 "→" + 量化指标词 + 无用户领域锚点
    if '→' in text and _re.search(r'(?:PA\s*\d+/\d+|chunks?\s*\d+|zero_access|test.*pass)', _tl):
        return True
    # "量化改善" / "量化:" 开头 — 迭代器自评总结
    if _re.match(r'^量化[：:改]', text):
        return True
    # iter974: contextless_assertion_gate — 指示/连接词开头短句碎片
    if _re.match(r'^(?:所以|一样的|也就是|这样|那么|这个|那个|同样|确实|其实|用的|人会|'
                 r'就是说|说白了|总之就是|换句话说|简单来说)\s*', text) and len(text) < 60:
        if not _re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml|sh|md)\b', text) \
           and not _re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个|行|倍|x)', text) \
           and not _re.search(r'`[^`]+`', text):
            return True
    return False


# ── 心跳 + PID 管理 ──────────────────────────────────────────────────────────

def _write_pid() -> None:
    try:
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except Exception:
        pass


def _write_heartbeat() -> None:
    try:
        HEARTBEAT_FILE.write_text(
            json.dumps({"pid": os.getpid(),
                        "ts": datetime.now(timezone.utc).isoformat()}),
            encoding="utf-8",
        )
    except Exception:
        pass


def _cleanup_pid() -> None:
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ── 数据库辅助 ───────────────────────────────────────────────────────────────

def _open_conn() -> sqlite3.Connection:
    """Open store.db with WAL + reasonable timeout."""
    from store import open_db, ensure_schema
    conn = open_db()
    ensure_schema(conn)
    return conn


def _dequeue_tasks(conn: sqlite3.Connection, limit: int) -> list:
    """从 ipc_msgq 取 extract_task 消息（QUEUED→CONSUMED 原子）。"""
    from store_vfs import ipc_recv
    return ipc_recv(conn, POOL_AGENT_ID, msg_type="extract_task", limit=limit)


# ── Worker：运行提取 pipeline ─────────────────────────────────────────────────

def _run_extraction_pipeline(payload: dict) -> dict:
    """
    复用 extractor.py 中的所有提取函数，在 pool worker 线程中执行。

    payload 字段（由 Stop hook 构造）：
      - session_id: str
      - project: str
      - text: str               (last_assistant_message，已截断)
      - transcript_path: str    (用于 _extract_from_tool_outputs 等)
      - hook_input_raw: dict    (完整 hook_input，fallback 使用)
      - submitted_at: str       (ISO)

    返回：{status, decisions, excluded, reasoning, constraints,
           causal_chains, conv_summaries, page_faults, elapsed_ms}
    """
    import time as _time
    t0 = _time.time()

    session_id     = payload.get("session_id", "unknown")
    project        = payload.get("project", "unknown")
    text           = payload.get("text", "")
    transcript_path = payload.get("transcript_path", "")
    hook_input_raw = payload.get("hook_input_raw", {})

    result = {
        "status": "ok",
        "session_id": session_id,
        "project": project,
        "decisions": 0,
        "excluded": 0,
        "reasoning": 0,
        "constraints": 0,
        "causal_chains": 0,
        "conv_summaries": 0,
        "page_faults": 0,
        "elapsed_ms": 0.0,
    }

    try:
        # ── import extractor symbols（在 worker 线程内延迟 import 节省主线程启动时间）
        from hooks.extractor import (
            _sysctl,
            _cow_prescan,
            _is_quality_chunk,
            _is_quality_decision,
            _is_selfref_noise,
            _is_metric_report_noise,
            DECISION_SIGNALS, EXCLUDED_SIGNALS, REASONING_SIGNALS,
            _extract_by_signals,
            _extract_structured_decisions,
            _extract_comparisons,
            _extract_causal_chains,
            _extract_quantitative_conclusions,
            _extract_constraints,
            _extract_conversation_summary,
            _extract_from_tool_outputs,
            _extract_tool_patterns,
            _extract_page_fault_candidates,
            _write_page_fault_log,
            _extract_topic,
            _write_madvise_hints,
            _deduplicate,
            _read_transcript_tail,
        )
        from store import (open_db, ensure_schema, insert_chunk,
                           already_exists, merge_similar,
                           kswapd_scan, cgroup_throttle_check,
                           dmesg_log, DMESG_INFO, DMESG_DEBUG, DMESG_WARN,
                           aimd_window)
        from schema import MemoryChunk

        if not text or len(text) < _sysctl("extractor.min_length"):
            result["status"] = "skip_too_short"
            return result

        # COW prescan
        _text_long = len(text) > 500
        cow_hit = _text_long or _cow_prescan(text)
        if not cow_hit:
            page_faults = _extract_page_fault_candidates(text)
            _write_page_fault_log(page_faults, session_id)
            topic = _extract_topic(text)
            _write_madvise_hints(text, [], [], [], [], project, session_id, topic)
            result["status"] = "cow_skip"
            result["page_faults"] = len(page_faults)
            return result

        # ── 提取各类 chunk（复用 extractor.py 逻辑）─────────────────────────
        decisions = (
            _extract_by_signals(text, DECISION_SIGNALS)
            + _extract_structured_decisions(text)
        )
        excluded  = _extract_by_signals(text, EXCLUDED_SIGNALS)
        reasoning = _extract_by_signals(text, REASONING_SIGNALS)

        comp_decisions, comp_exclusions = _extract_comparisons(text)
        decisions.extend(comp_decisions)
        excluded.extend(comp_exclusions)

        causal_chains     = _deduplicate(_extract_causal_chains(text))
        quant_conclusions = _extract_quantitative_conclusions(text)
        decisions.extend(quant_conclusions)
        constraints = _extract_constraints(text)

        decisions = _deduplicate(decisions)
        excluded  = _deduplicate(excluded)
        reasoning = _deduplicate(reasoning)
        constraints = _deduplicate(constraints)

        _transcript_extra = _read_transcript_tail(transcript_path) if transcript_path else []
        conv_summaries = _extract_conversation_summary(text, extra_texts=_transcript_extra)
        page_faults    = _extract_page_fault_candidates(text)

        # AIMD 策略（仅过滤，不影响写入路径）
        try:
            _aimd_conn = open_db()
            ensure_schema(_aimd_conn)
            aimd_info   = aimd_window(_aimd_conn, project)
            aimd_policy = aimd_info["policy"]
            _aimd_conn.close()
        except Exception:
            aimd_policy = "full"

        if aimd_policy == "conservative":
            excluded = []; conv_summaries = []
        elif aimd_policy == "moderate":
            conv_summaries = []

        if not decisions and not excluded and not reasoning and not conv_summaries and not constraints and not causal_chains:
            _write_page_fault_log(page_faults, session_id)
            result["status"] = "nothing_extracted"
            result["page_faults"] = len(page_faults)
            return result

        # ── 从 transcript 补充提取 tool 模式 ─────────────────────────────────
        tool_decisions = []
        tool_excluded  = []
        tool_constraints = []
        if transcript_path:
            try:
                _tc = open_db()
                ensure_schema(_tc)
                _extract_from_tool_outputs(transcript_path, session_id, project, _tc)
                _extract_tool_patterns(transcript_path, _tc, project, session_id)
                _tc.commit()
                _tc.close()
            except Exception:
                pass

        # ── 批量写入 ─────────────────────────────────────────────────────────
        conn = open_db()
        ensure_schema(conn)

        incoming_count = (len(decisions) + len(excluded) + len(reasoning)
                          + len(conv_summaries) + len(constraints) + len(causal_chains))

        ksw = kswapd_scan(conn, project, incoming_count)
        if ksw["evicted_count"] > 0:
            conn.commit()
        throttle = cgroup_throttle_check(conn, project, incoming_count)
        throttle_active   = throttle["throttled"]
        importance_factor = throttle.get("importance_factor", 1.0)
        oom_adj_delta     = throttle.get("oom_adj_delta", 0)

        # iter631: ephemeral_type_gate — 与 extractor.py iter596 同步
        # 根因：extractor_pool._write_chunks 缺少 chunk_type 级过滤，
        #   conversation_summary/prompt_context 绕过 extractor.py 的 gate 写入 DB，
        #   实测 4 条 conversation_summary + 2 条 prompt_context 零访问。
        # iter1082: tool_insight_ephemeral — 同步 extractor.py
        _EPHEMERAL_TYPES = {"prompt_context", "conversation_summary", "tool_insight"}

        def _write_chunks(texts, chunk_type, base_importance):
            if chunk_type in _EPHEMERAL_TYPES:
                return 0
            written = 0
            for t in texts:
                if not t or not t.strip():
                    continue
                # iter645: min_content_length_gate — 拒绝碎片 chunk 写入
                # 根因：content<50字节的 chunk 检索命中后无法提供足够上下文，
                #   summary 已包含全部信息，raw content 无增量价值。
                #   实测：5 个 len<50 的 chunk 全部 access_count=0。
                if len(t.strip()) < 50:
                    continue
                # iter1096: pool_table_sysdata_gate — 表格行+系统数据碎片拒绝
                # 根因（数据驱动，2026-05-07）：16 个 ac=0 噪声全经 pool 路径写入，
                #   含表格行碎片（|开头）和命令输出快照（KB/GB/mm_stat/Swap 数值）。
                #   extractor.py _write_chunk 有 table_fragment_gate，pool 路径缺失。
                # 修复：同步 table gate + 新增 sysdata gate（数值+单位 无决策动词）。
                _ts = t.strip()
                if _ts.startswith('|'):
                    continue
                if _re.search(r'(?:\d+\s*(?:KB|kB|MB|GB|TB|bytes)|\bmm_stat\b|Swap(?:Total|Free|Cached))', _ts) \
                   and not _re.search(r'(?:应该|必须|决定|选择|改为|方案|建议|原因|因为|所以|优化|问题)', _ts):
                    continue
                # ── iter525: memfd_seal — Write Gate Integrity Seal ──
                # OS 类比：Linux memfd_seal(F_SEAL_WRITE) (Jeff Xu, 2024) —
                # sealed memory region 拒绝写入损坏数据，在 write 入口强制校验
                if _seal_check_reject(t.strip()):
                    continue
                # iter900: quality_gate_sync — 统一调用 _is_quality_chunk
                # 根因（数据驱动，2026-05-05）：extractor_pool 路径缺少 _is_quality_chunk，
                #   导致噪声 chunk（如 "真菌感染或接触性皮炎"）绕过 extractor.py 的门控写入 DB。
                #   summary = t[:120]，需与 extractor.py _write_chunk 保持同等过滤。
                if not _is_quality_chunk(t[:120]):
                    continue
                # iter956: pool_causal_reasoning_gate — 对齐 extractor.py 的碎片门控
                # 根因（数据驱动，2026-05-06）：extractor_pool 路径缺少 causal_chain/reasoning_chain
                #   的 120 字门控和结论词拦截，21 条碎片 chunk（avg 55 字）逃逸写入 DB。
                #   extractor.py line 3795-3797 有独立的结论词+长度门控，此处同步。
                # iter999: excluded_path_gate_sync — excluded_path 同等门控
                if chunk_type in ("causal_chain", "reasoning_chain", "excluded_path"):
                    _t_stripped = t.strip()
                    # 结论词开头 → 不完整因果链
                    if _re.match(r'^(?:所以|因此|故此|于是|故而|答案[：:])', _t_stripped):
                        continue
                    # <120 字短句 → 独立碎片无检索价值
                    if len(_t_stripped) < 120:
                        continue
                    # 连接词短句（推理过渡）
                    if _re.match(r'^(?:但是|不过|然而|而且|并且|也就是说|换言之|即)\s*', _t_stripped) and len(_t_stripped) < 80:
                        continue
                # iter1183: decision_conversational_fragment_gate — sync extractor.py
                if chunk_type == "decision":
                    _td_stripped = t.strip()
                    if len(_td_stripped) < 120 and _re.match(
                        r'^(?:\d+\.\s*)?(?:所以|因此|但[是]?|而且|或者|之前|有一个|如果是|对[，,]|问题[：:])',
                        _td_stripped):
                        continue
                # iter1054: pool_decision_full_gate — 直接调用 _is_quality_decision
                # 根因（数据驱动，2026-05-07）：pool 路径 decision gate 只复制了通过条件(B)，
                #   缺少排除条件(X5:self_impl_gate, X6:ephemeral_market_gate)。
                #   导致 6/10 ac=0 噪声 chunk 经此路径逃逸写入（含数字度量绕过排除）。
                # 修复：直接调用完整的 _is_quality_decision（含全部排除+通过条件）。
                if chunk_type == "decision":
                    if not _is_quality_decision(t.strip()):
                        continue
                # iter1117: pool_selfref_gate_sync — 对齐 extractor.py selfref gate
                # 根因（数据驱动，2026-05-08）：pool 路径缺少 selfref gate，
                #   "量化预期：大库 suppress 全灭后空召回率降 ~50%"(ac=0) 逃逸写入。
                if _is_selfref_noise(t[:120], chunk_type):
                    continue
                # iter1118: pool_metric_gate_sync — 对齐 extractor.py metric_report_gate
                # 根因（数据驱动，2026-05-08）：pool 路径缺少 metric_report_gate，
                #   "zero-access: 11.8% → 0%"(ac=0,decision) 逃逸写入。
                if _is_metric_report_noise(t[:120], chunk_type):
                    continue
                imp = base_importance
                if throttle_active:
                    imp = round(imp * importance_factor, 3)
                # iter950: pool_dedup_gate — 写入前去重（与 extractor.py _write_chunk 对齐）
                # 根因（数据驱动，2026-05-06）：extractor_pool 路径缺少 already_exists/merge_similar，
                #   导致同一 session 内相同内容重复写入（实测 3 条重复 conversation_summary）。
                _summ950 = t[:120]
                if already_exists(conn, _summ950, chunk_type=chunk_type):
                    continue
                if merge_similar(conn, _summ950, chunk_type, imp, project=project):
                    continue
                chunk = MemoryChunk(
                    project=project,
                    source_session=session_id,
                    chunk_type=chunk_type,
                    content=t,
                    summary=_summ950,
                    tags=[chunk_type, project],
                    importance=imp,
                    retrievability=0.5,
                )
                insert_chunk(conn, chunk.to_dict())
                written += 1
            return written

        _write_chunks(decisions,     "decision",             0.8)
        _write_chunks(excluded,      "excluded_path",        0.6)
        _write_chunks(reasoning,     "reasoning_chain",      0.75)
        _write_chunks(conv_summaries,"conversation_summary", 0.65)
        _write_chunks(constraints,   "design_constraint",    0.85)
        _write_chunks(causal_chains, "causal_chain",         0.7)
        conn.commit()

        # ── Goals 进度更新（per-session 幂等，来自 extractor.py P2 修复）──────
        try:
            from datetime import datetime as _dt, timezone as _tz
            _now_iso = _dt.now(_tz.utc).isoformat()
            conn.execute("ALTER TABLE goals ADD COLUMN last_progress_session TEXT DEFAULT ''")
        except Exception:
            pass
        try:
            conn.execute(
                """UPDATE goals SET progress = MIN(1.0, progress + 0.05),
                   updated_at = ?, last_progress_session = ?
                   WHERE project = ? AND status = 'active'
                     AND (last_progress_session IS NULL OR last_progress_session != ?)""",
                [datetime.now(timezone.utc).isoformat(), session_id, project, session_id]
            )
            conn.commit()
        except Exception:
            pass

        # ── dmesg ────────────────────────────────────────────────────────────
        elapsed = (_time.time() - t0) * 1000
        dmesg_log(conn, DMESG_INFO, "extractor_pool",
                  f"extracted: d={len(decisions)} e={len(excluded)} r={len(reasoning)} "
                  f"s={len(conv_summaries)} c={len(constraints)} cc={len(causal_chains)} "
                  f"pf={len(page_faults)} {elapsed:.1f}ms",
                  session_id=session_id, project=project)
        conn.commit()
        conn.close()

        # ── Page fault log ──────────────────────────────────────────────────
        _write_page_fault_log(page_faults, session_id)

        # ── iter581: ksoftirqd — 写入后检查 DB 健康度，不健康时 raise softirq ──
        if incoming_count > 0:
            try:
                _sirq_conn = open_db()
                ensure_schema(_sirq_conn)
                from store_mm import raise_softirq
                raise_softirq(_sirq_conn, project)
                _sirq_conn.close()
            except Exception:
                pass

        # ── 广播知识更新 ─────────────────────────────────────────────────────
        try:
            from net.agent_notify import broadcast_knowledge_update
            stats = {
                "decisions":   len(decisions),
                "constraints": len(constraints),
                "chunks":      incoming_count,
            }
            broadcast_knowledge_update(project, session_id, stats)
        except Exception:
            pass

        result.update({
            "decisions":    len(decisions),
            "excluded":     len(excluded),
            "reasoning":    len(reasoning),
            "constraints":  len(constraints),
            "causal_chains":len(causal_chains),
            "conv_summaries":len(conv_summaries),
            "page_faults":  len(page_faults),
            "elapsed_ms":   round(elapsed, 1),
        })

    except Exception as e:
        result["status"] = f"error: {e}"
        log.exception("worker pipeline error for session=%s", session_id)

    result["elapsed_ms"] = round((_time.time() - t0) * 1000, 1)
    return result


# ── 主循环 ────────────────────────────────────────────────────────────────────

_shutdown = threading.Event()


def _signal_handler(sig, frame):
    log.info("signal %s received, shutting down", sig)
    _shutdown.set()


def run_pool():
    """
    常驻进程主循环。
    OS 类比：kworker/u16:X — 绑定到特定 workqueue，持续取 work 执行。
    """
    _write_pid()
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    log.info("extractor_pool started: pid=%d workers=%d poll=%.1fs",
             os.getpid(), POOL_WORKERS, POLL_INTERVAL)

    executor = ThreadPoolExecutor(max_workers=POOL_WORKERS,
                                  thread_name_prefix="ext-worker")
    active_futures: list[Future] = []

    try:
        while not _shutdown.is_set():
            _write_heartbeat()

            # 清理已完成 futures，记录结果
            done = [f for f in active_futures if f.done()]
            for f in done:
                active_futures.remove(f)
                try:
                    res = f.result()
                    log.info("task done: status=%s session=%s elapsed=%.1fms",
                             res.get("status"), res.get("session_id"), res.get("elapsed_ms", 0))
                except Exception as e:
                    log.error("task raised exception: %s", e)

            # 若 worker slots 已满，等下次 poll
            if len(active_futures) >= POOL_WORKERS:
                _shutdown.wait(timeout=POLL_INTERVAL)
                continue

            # 从 ipc_msgq 取任务
            available = POOL_WORKERS - len(active_futures)
            batch     = min(available, TASK_BATCH)
            tasks     = []
            try:
                conn = _open_conn()
                tasks = _dequeue_tasks(conn, batch)
                conn.commit()
                conn.close()
            except Exception as e:
                log.warning("dequeue error: %s", e)

            for msg in tasks:
                payload = msg.get("payload", {})
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except Exception:
                        payload = {}
                future = executor.submit(_run_extraction_pipeline, payload)
                active_futures.append(future)

            if not tasks:
                _shutdown.wait(timeout=POLL_INTERVAL)

    finally:
        log.info("extractor_pool shutting down, waiting for %d active tasks",
                 len(active_futures))
        executor.shutdown(wait=True, cancel_futures=False)
        _cleanup_pid()
        log.info("extractor_pool stopped")


# ── CLI 辅助：健康检查 ────────────────────────────────────────────────────────

def check_health() -> dict:
    """检查 extractor_pool 是否运行中。可被管理脚本调用。"""
    if not HEARTBEAT_FILE.exists():
        return {"running": False, "reason": "no heartbeat file"}
    try:
        data = json.loads(HEARTBEAT_FILE.read_text(encoding="utf-8"))
        pid  = data.get("pid", 0)
        ts   = data.get("ts", "")
        # 检查进程是否存活
        if pid:
            try:
                os.kill(pid, 0)
                alive = True
            except (ProcessLookupError, PermissionError):
                alive = False
        else:
            alive = False
        # 检查心跳是否过期（> 30s 认为 hung）
        stale = False
        if ts:
            from datetime import datetime, timezone
            last = datetime.fromisoformat(ts)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - last).total_seconds()
            stale = age > 30
        return {"running": alive and not stale, "pid": pid, "ts": ts, "stale": stale}
    except Exception as e:
        return {"running": False, "reason": str(e)}


def submit_extract_task(hook_input: dict, project: str, session_id: str) -> bool:
    """
    Stop hook 调用此函数提交异步提取任务。
    返回 True 表示成功入队，False 表示 pool 未运行（需 fallback 同步执行）。

    OS 类比：queue_work(pool, &my_work) — 提交 work_struct 到 workqueue，
    如果 workqueue 未初始化则返回 -EINVAL（调用方同步执行）。
    """
    health = check_health()
    if not health.get("running"):
        return False

    # 构造 extract_task payload
    text = hook_input.get("last_assistant_message", "")
    from config import get as _sysctl

    # ── 入队前 min_length 门控（最轻量检查，< 0.01ms）──────────────────────────
    # COW prescan 不在此处做：COW miss 应静默退出而非 fallback 到同步路径；
    # extractor.py main() 在 pool check 之前已做 min_length 检查，此处保持一致。
    _min_len = _sysctl("extractor.min_length")
    if not text or len(text) < _min_len:
        return True  # 过短，无内容可提取，但告知 Stop hook "已处理"（不触发 fallback）

    MAX_CHARS = _sysctl("extractor.max_input_chars")
    if len(text) > MAX_CHARS:
        # 与 extractor.py main() 相同的截断逻辑
        import re
        signal_words = r'(?:选择|决定|推荐|结论|采用|排除|不用|放弃|根本原因|为什么|核心)'
        filtered_lines = []
        in_code = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith('```'):
                in_code = not in_code
                if len('\n'.join(filtered_lines)) < MAX_CHARS:
                    filtered_lines.append(line)
                continue
            if in_code:
                continue
            if (stripped.startswith('#') or re.search(signal_words, stripped)
                    or stripped.startswith('>') or stripped.startswith('|')):
                filtered_lines.append(line)
        text = '\n'.join(filtered_lines)[:MAX_CHARS]

    payload = {
        "type":            "extract_task",
        "session_id":      session_id,
        "project":         project,
        "text":            text,
        "transcript_path": hook_input.get("transcript_path", ""),
        "hook_input_raw":  hook_input,
        "submitted_at":    datetime.now(timezone.utc).isoformat(),
    }

    try:
        from store import open_db, ensure_schema
        from store_vfs import ipc_send
        conn = open_db()
        ensure_schema(conn)
        ipc_send(conn, source=session_id, target=POOL_AGENT_ID,
                 msg_type="extract_task", payload=payload,
                 priority=5, ttl_seconds=300)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("submit_extract_task failed: %s", e)
        return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="memory-os extractor pool")
    parser.add_argument("cmd", choices=["start", "health", "status"],
                        nargs="?", default="start")
    args = parser.parse_args()

    if args.cmd == "health":
        h = check_health()
        print(json.dumps(h, ensure_ascii=False))
        sys.exit(0 if h.get("running") else 1)
    elif args.cmd == "status":
        h = check_health()
        status = "running" if h.get("running") else "stopped"
        print(f"extractor_pool: {status}")
        if h.get("pid"):
            print(f"  pid: {h['pid']}")
        if h.get("ts"):
            print(f"  last heartbeat: {h['ts']}")
        sys.exit(0)
    else:
        run_pool()
