#!/usr/bin/env python3
"""
memory-os extractor — Stop hook
从 last_assistant_message 提取决策链 chunk + 对话摘要

v5 策略（迭代39 升级）：
- v4 全部能力保留（决策/排除/推理链/对比/因果/量化/conversation_summary）
- 新增 COW 预扫描：先做 O(1) 快速检测，无信号词时跳过完整提取
  （OS 类比：Linux fork() COW — 只在真正写入时才复制页面）
- 目标 < 150ms（不调用 LLM），无信号消息 < 0.5ms
"""
import sys
import os
import re
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
from schema import MemoryChunk
from utils import resolve_project_id
from store import open_db, ensure_schema, insert_chunk, already_exists, merge_similar, get_project_chunk_count, evict_lowest_retention, kswapd_scan, dmesg_log, DMESG_INFO, DMESG_WARN, DMESG_DEBUG, madvise_write, set_oom_adj, OOM_ADJ_PROTECTED, OOM_ADJ_ONFAULT, OOM_ADJ_PREFER, cgroup_throttle_check, checkpoint_dump, checkpoint_collect_hits, aimd_window, pin_chunk
from config import get as _sysctl  # 迭代27: sysctl Runtime Tunables

MEMORY_OS_DIR = Path.home() / ".claude" / "memory-os"
STORE_DB = MEMORY_OS_DIR / "store.db"

# 迭代27：常量迁移至 config.py sysctl 注册表（运行时可调）
# 原硬编码：_sysctl("extractor.min_length")=10, _sysctl("extractor.max_summary")=120, _sysctl("extractor.chunk_quota")=200

# ── 决策信号词 ──────────────────────────────────────────────
DECISION_SIGNALS = [
    r'(?:选择|决定|采用|推荐|最终方案|方案选定)[：:]\s*(.{10,120})',
    r'(?:推断|结论|因此)[：:]\s*(.{10,120})',
    r'(?:选择|决定)\s*(.{5,60})\s*(?:而非|不选|放弃)',
    r'\*\*(?:推荐|选择|决定|结论)[：:]?\*\*\s*(.{10,100})',
    r'→\s*(.{5,80})\s*(?:是正确|更合适|最优|更好)',
    # 方向性结论
    r'(?:方向\s*[A-Za-z])[：:]\s*(.{10,120})',
    r'(?:核心洞察|关键洞察)[：:]\s*(.{10,120})',
    # 英文
    r'(?:decided?|chosen?|adopted?|recommended?)[：:]\s*(.{10,100})',
    r'(?:conclusion|therefore)[：:]\s*(.{10,100})',
]

# ── 排除路径信号词 ────────────────────────────────────────────
EXCLUDED_SIGNALS = [
    r'(?:不用|放弃|排除|废弃|不推荐|不选|跳过)\s*(.{3,60})',
    r'(.{3,60})\s*(?:不适合|效果差|有问题|不可行|被放弃)',
    r'(?:deprecated|abandoned|rejected|skipped)[：:]?\s*(.{3,60})',
    r'\*\*不推荐\*\*[：:]?\s*(.{10,80})',
    # 带原因的排除
    r'(?:排除|不选)\s*(.{3,60})\s*[，,]\s*(?:因为|原因)',
]

# ── 推理链信号 ──────────────────────────────────────────────
REASONING_SIGNALS = [
    r'(?:根本原因|root cause)[：:]\s*(.{10,120})',
    r'(?:为什么|Why)[：:]\s*(.{10,120})',
    r'(?:核心问题|核心差距|真正差距)[：:]\s*(.{10,120})',
    r'(?:第一性原理)[：:]\s*(.{10,120})',
    # 扩充：更多推理标记（覆盖实际内容中高频但被漏掉的模式）
    r'(?:根本问题|根本差距|本质问题|根因)[在是]?[：:在于]?\s*(.{10,120})',
    r'(?:原因[：:是]|问题在于)[：:]?\s*(.{10,120})',
    r'(?:这是因为|发现根因|真正原因)[：:]?\s*(.{10,120})',
    r'(?:关键发现|核心发现|分析显示)[：:]\s*(.{10,120})',
    r'(?:诊断结论|性能瓶颈|瓶颈在于)[：:]?\s*(.{10,120})',
    # 英文推理标记
    r'(?:root cause|key finding|the reason|because)[:\s]+(.{10,120})',
    r'(?:analysis shows|discovered that|found that|turns out)[,:\s]+(.{10,120})',
    # 迭代120：覆盖现代中文 LLM 回复高频推理表达（A/B 分析显示完全缺失）
    # 这说明/这表明/这意味着 — 结论性推理句（最高频但缺失）
    r'(?:这说明|这表明|这意味着|这反映了)[：,，]?\s*(.{10,120})',
    # 关键在于/症结在于 — 核心问题诊断
    r'(?:关键在于|症结在于|核心在于|问题在于)\s*(.{10,120})',
    # 实质上/本质上 — 深层解释
    r'(?:实质上|本质上|根本上)[，,：:]?\s*(.{10,120})',
    # 因此 + 结论（单独使用，无前置因为的推理终结句）
    r'(?:^|\n)因此[，,：:]?\s*(.{10,100})',
    # 由此可见/可见 — 归纳推理
    r'(?:由此可见|由此可得|可以看出)[，,：:]?\s*(.{10,100})',
    # 证明了/验证了 + 核心结论
    r'(?:这证明了|这验证了|实验证明|测试证明)\s*(.{10,100})',
]

# ── v3 新增：对比句式（捕获隐式决策）────────────────────────
COMPARISON_SIGNALS = [
    # "X 而非 Y" / "X 而不是 Y" → 决策含完整对比
    r'(?:使用|用|采用|选)\s*(.{3,40})\s*(?:而非|而不是|不是)\s*(.{3,40})',
    # "相比 X，Y 更…" → 决策 "相比 X，Y 更…"
    r'(?:相比|比起|对比)\s*(.{3,30})[，,]\s*(.{3,60}?更.{2,30})',
    # "X 比 Y 好/快/稳定" → 决策 "X 比 Y …"
    r'(.{3,30})\s*比\s*(.{3,30})\s*(好|快|稳定|合适|简单|可靠|高效).{0,30}',
    # "不用 X 改用 Y" / "放弃 X 改用 Y"
    r'(?:不用|放弃|弃用)\s*(.{3,30})\s*(?:改用|换成|用)\s*(.{3,40})',
]

# ── v3 新增：因果链（保留 why 维度）─────────────────────────
# 迭代122：重构 CAUSAL_SIGNALS — 覆盖真实 LLM 因果表达模式
# 迭代127：修复低命中率 — 放宽约束覆盖真实 LLM 输出结构
#   问题1：模式[0]要求逗号分隔，"因为X所以Y"（无逗号）不匹配
#   问题2："这导致了..." 前缀"这"只有1字，旧最小3字限制阻断
#   问题3："原因：..." / "根因：..." 冒号式未覆盖
#   问题4："由于X，需要Y" 后半无"所以/因此"，旧双组模式不匹配
# OS 类比：信号处理器的 syscall 过滤表 — 太严的 seccomp 规则会阻断合法调用，
#   需要基于实测 trace 校准过滤粒度（strace → seccomp profile）。
# 新设计分两类：
#   A. 双组（cause + effect）：格式化为 "cause → effect"
#   B. 单组（完整因果句）：直接存储完整句子（含因果连接词上下文足够语义）
CAUSAL_SIGNALS = [
    # ── 类型A：双组（因 + 果）——正式书面因果 ──
    # "因为 X，所以 Y" / "由于 X，因此 Y"（迭代127：允许逗号可选）
    r'(?:因为|由于|原因是)\s*(.{5,60}?)[，,；;]?\s*(?:所以|因此|故|于是)\s*(.{5,60})',
    # "由于 X，Y"（迭代127新增：后半不要求"所以"，覆盖"由于限制，需要额外补充"）
    r'(?:由于|因为)\s*(.{5,60})[，,；;]\s*(.{5,60})',
    # "X 是因为 Y"
    r'(.{5,40})\s*是因为\s*(.{5,60})',
    # "之所以 X，是因为 Y"
    r'之所以\s*(.{5,40})[，,]\s*(?:是因为|因为)\s*(.{5,60})',

    # ── 类型B：单组（完整因果句）——LLM 高频表达 ──
    # 决策 + 原因（最常见："选择X，因为Y"）
    r'(.{5,80}?)[，,]\s*(?:因为|原因是|由于)\s*.{5,60}',
    # 迭代127新增：冒号式原因说明（"原因：X" / "根因：X" — 最常见 LLM 诊断格式）
    r'(?:原因|根因|根本原因|问题原因)[：:]\s*(.{10,100})',
    # 导致/造成/引发（迭代127：放宽前缀到1字，覆盖"这导致了..."）
    r'(.{1,60})\s*(?:导致了?|造成了?|引发了?|触发了?|引起了?)\s*.{5,60}',
    # 是由...导致/引发的（被动因果）
    r'(.{3,60})\s*是由\s*.{3,40}\s*(?:导致|引发|造成)的?',
    # X，根本原因是 Y（诊断性因果）
    r'(.{3,60})[，,]\s*根本原因(?:是|在于)\s*.{5,60}',
    # 因此/所以 + 结论（单向）
    r'(?:因此|所以|故此|于是)[，,]?\s*(.{10,80})',
    # 英文因果
    r'(.{5,60})\s*(?:because|due to|caused by|resulted in|leads to)\s*.{5,60}',
]

# ── v3 新增：量化证据模式 ────────────────────────────────────
QUANTITATIVE_PATTERN = re.compile(
    r'(?:'
    r'\d+(?:\.\d+)?%'                          # 百分比
    r'|\d+(?:\.\d+)?\s*(?:ms|s|秒|毫秒)'       # 时间
    r'|\d+(?:\.\d+)?\s*(?:MB|GB|KB|字节)'       # 大小
    r'|[<>≤≥]\s*\d+'                            # 不等式约束
    r'|\d+/\d+\s*(?:cases?|测试)'               # 测试结果
    r'|hit_rate[=:]\s*\d'                        # 指标
    r'|noise_rate[=:]\s*\d'
    r'|precision[=:]\s*\d'
    r')',
    re.IGNORECASE
)

# ── 迭代98+102：设计约束信号（design_constraint）────────────────
# 系统中"为什么不这样做"的约束知识——违反会产生语义错误但表面合理的修改
# 迭代102 扩展：从8个模式扩展到22个，覆盖工程中常见约束表达
CONSTRAINT_SIGNALS = [
    # ── 原有模式（迭代98）—— 为什么不能/why must not 提前，避免被短模式[0]抢占 ──
    r'(?:为什么.*不能.*?|why.*must not.*?)[：:]\s*(.{10,100})',  # 提前：.*? 允许冒号前有额外词语
    r'(?:不能|禁止|不允许|must not|should not)\s*(.{5,80})\s*(?:因为|，因为|because|，because)',
    r'(?:这样做会|这会导致|this would|will cause)\s*(.{5,80})',
    r'(?:会导致|会产生|会引发|会造成)\s*(.{5,80})',
    r'(?:破坏|违反|corrupt|violate)\s*(.{5,80})',
    r'(?:设计约束|invariant|不变量|design constraint)[：:]\s*(.{10,120})',
    r'(?:之所以|正是因为)\s*(.{5,60})\s*(?:绕过|skip)',
    r'(?:前提条件|prerequisite|assumption)[：:]\s*(.{10,100})',
    # ── 迭代102 新增：中文警告句式 ──
    r'(?:注意不要|小心不要|务必不要|千万不要|切勿)\s*(.{5,80})',
    r'(?:注意[：:]\s*)(.{10,120})',   # "注意：此处不能..." 标题式警告
    r'(?:警告[：:]\s*)(.{10,120})',   # "警告：..." markdown 警告块
    r'(?:危险[：:]\s*)(.{10,120})',   # "危险：..." 高危警告
    # ── 迭代102 新增：markdown 警告标记 ──
    r'(?:⚠️|⚠|🚫|❌)\s*(.{5,100})',  # emoji 警告前缀
    r'(?:WARNING:|CAUTION:|DANGER:|IMPORTANT:)\s*(.{10,120})',  # 英文警告标记
    r'(?:> \[!WARNING\]|> \[!CAUTION\]|> \[!DANGER\])[^\n]*\n+(.{10,120})',  # GitHub alert 格式
    # ── 迭代102 新增：英文约束句式 ──
    r'(?:never|avoid|do not|don\'t)\s+(.{5,80})\s+(?:because|as|since|—|--)',
    r'(?:always\s+(?:ensure|check|verify|call|use))\s+(.{5,80})\s+(?:before|first|or)',
    r'(?:requires?|must\s+(?:be|have|call|use))\s+(.{5,80})\s+(?:before|first|to)',
    # ── 迭代102 新增：前置条件 / 顺序约束 ──
    r'(?:只有.*才能|必须先.*再|先.*后才能)\s*(.{5,80})',
    r'(?:assert|ensure|guarantee|require)[（(](.{5,80})[）)]',  # assert(条件) 格式
    r'(?:不变式|invariant|precondition|postcondition)[：:]?\s*(.{10,100})',
    # ── 迭代102 新增：后果/副作用 ──
    r'(?:否则会|否则将|不然会|不然将)\s*(.{5,80})',
    r'(?:race condition|deadlock|memory leak|data corruption|undefined behavior|竞态|死锁|内存泄漏|数据损坏)\s*(?:will|would|可能|将会|的风险)?(.{0,60})',
]

# ── 上下文标记（帮助判断 chunk 属于哪个任务/主题）──────────
TOPIC_HEADER = re.compile(r'^#{1,3}\s+(.{5,60})$', re.MULTILINE)


def _extract_topic(text: str) -> str:
    """从最近的 markdown 标题提取话题。"""
    headers = TOPIC_HEADER.findall(text)
    if headers:
        return headers[-1].strip()[:60]
    return ""


def _extract_by_signals(text: str, patterns: list) -> list:
    results = []
    for pattern in patterns:
        for m in re.finditer(pattern, text):
            captured = m.group(1).strip()
            # 截断到第一个换行或句号
            captured = re.split(r'[\n。！？]', captured)[0].strip()
            # 去掉 markdown 格式符
            captured = re.sub(r'\*{1,3}|`{1,3}', '', captured).strip()
            # 迭代73：碎片过滤 — 截断的代码/表格/标题不入库
            if _is_fragment(captured):
                continue
            if len(captured) >= _sysctl("extractor.min_length"):
                results.append(captured[:_sysctl("extractor.max_summary")])
    return _deduplicate(results)


def _extract_structured_decisions(text: str) -> list:
    """
    从结构化 markdown 提取决策：
    - 标题下的第一段结论
    - 有序列表中的关键项（数字开头）
    - callout / blockquote 中的结论
    """
    results = []

    # 提取 blockquote 中的关键句（> **xxx**: yyy）
    blockquote = re.finditer(r'^>\s*\*\*(.{2,20})\*\*[：:]\s*(.{10,100})$', text, re.MULTILINE)
    for m in blockquote:
        label = m.group(1).strip()
        content = m.group(2).strip()
        if label in ('核心洞察', '关键预测', '结论', '推断', '最终方案', '核心命题'):
            results.append(f"{label}：{content}"[:_sysctl("extractor.max_summary")])

    # 提取有序列表中包含决策词的项
    ordered_items = re.finditer(r'^\d+[.。]\s+(.{10,100})$', text, re.MULTILINE)
    for m in ordered_items:
        item = m.group(1).strip()
        # 只保留含有决策信号的列表项
        if re.search(r'(?:选择|决定|推荐|结论|采用|方向|核心)', item):
            results.append(re.sub(r'\*{1,3}|`', '', item)[:_sysctl("extractor.max_summary")])

    return _deduplicate(results)


def _extract_comparisons(text: str) -> tuple:
    """
    v3 对比句式提取。返回 (decisions, exclusions)。
    从 "X 而非 Y" 类句式同时提取决策和排除路径。
    """
    decisions = []
    exclusions = []
    for pattern in COMPARISON_SIGNALS:
        for m in re.finditer(pattern, text):
            groups = m.groups()
            full_match = m.group(0).strip()
            full_clean = re.sub(r'\*{1,3}|`{1,3}', '', full_match).strip()
            # 对比句式产出完整决策（含对比上下文）
            if len(full_clean) >= _sysctl("extractor.min_length"):
                decisions.append(full_clean[:_sysctl("extractor.max_summary")])
            # "不用 X 改用 Y" 模式：第一个捕获组是排除项
            if len(groups) >= 2 and re.match(r'(?:不用|放弃|弃用)', pattern[:20]):
                excluded = re.sub(r'\*{1,3}|`{1,3}', '', groups[0]).strip()
                if len(excluded) >= 5:
                    exclusions.append(excluded[:_sysctl("extractor.max_summary")])
    return _deduplicate(decisions), _deduplicate(exclusions)


def _extract_causal_chains(text: str) -> list:
    """
    v3 因果链提取。返回 causal_chain chunks。
    迭代122：重构以支持两类模式：
      类型A（双组）：格式化为 "cause → effect"
      类型B（单组/完整句）：直接存储完整因果句（含触发词语义上下文）

    两类均需要 → 分隔符（类型A显式格式化，类型B用完整匹配替代）。
    """
    results = []
    for pattern in CAUSAL_SIGNALS:
        for m in re.finditer(pattern, text):
            # iter1215: causal_pipe_filter — 拦截表格行碎片（同 quant iter540）
            _mline = m.group(0).strip()
            if _mline.startswith('|') or _mline.count('|') >= 3:
                continue
            groups = m.groups()
            if len(groups) >= 2:
                # 类型A：双组（因 + 果），格式化为 "cause → effect"
                cause = re.sub(r'\*{1,3}|`{1,3}', '', groups[0]).strip()
                effect = re.sub(r'\*{1,3}|`{1,3}', '', groups[1]).strip()
                cause = re.split(r'[\n]', cause)[0].strip()
                effect = re.split(r'[\n]', effect)[0].strip()
                if len(cause) >= 5 and len(effect) >= 5:
                    chain = f"{cause} → {effect}"
                    results.append(chain[:_sysctl("extractor.max_summary")])
            elif len(groups) == 1:
                # 类型B：单组（完整因果句）
                # 使用完整匹配（m.group(0)）保留触发词上下文，不只取捕获组
                full_match = m.group(0).strip()
                full_match = re.sub(r'\*{1,3}|`{1,3}', '', full_match)
                full_match = re.split(r'[\n]', full_match)[0].strip()
                # 须包含因果语义词（防止误匹配）
                # 迭代127：扩展语义词 + 加入"原因"系词（冒号式模式的全匹配包含"原因："）
                if re.search(r'(?:因为|由于|导致了?|造成了?|引发了?|触发了?|引起了?|'
                             r'根本原因|因此|所以|原因[：:]|根因[：:]|问题原因[：:]|'
                             r'because|due to|caused by|resulted in|leads to)',
                             full_match):
                    # 迭代127：min_length 从15→10→6（"这导致了性能下降"=8字，需≥6才能通过）
                    if len(full_match) >= 6:
                        results.append(full_match[:_sysctl("extractor.max_summary")])
    return _deduplicate(results)


def _extract_constraints(text: str) -> list:
    """
    迭代98：设计约束提取 — "为什么不这样做"的系统级约束知识。

    特征：
    - 隐性：正常代码里不写，只在 maintainer 解释/code review 时出现
    - 跨时间有效：架构级约束，长期稳定不过期
    - 高保护：违反会产生语义错误但表面合理的修改

    format: "路径/符号 不能 做 Y，因为会 Z"
    """
    _CONSTRAINT_SEMANTIC = re.compile(
        r'(?:不能|禁止|不允许|不应该|must not|should not|cannot|'
        r'会导致|会产生|会引发|会造成|导致|破坏|违反|corrupt|violate|'
        r'前提|必须先|只有.*才能|否则|不变量|invariant|precondition|'
        r'race condition|deadlock|memory leak|data corruption|'
        r'竞态|死锁|内存泄漏|数据损坏|'
        r'never|avoid|don\'t|always ensure|requires?.*before|must.*before|'
        r'unsafe|incorrect|incorrect|wrong|error|fail|危险|风险|'
        r'without.*lock|without.*holding|without.*acquiring|'
        r'因为|由于|以免|以防)',  # iter119: 因果说明也是约束知识的核心载体
        re.IGNORECASE
    )
    results = []
    for pattern in CONSTRAINT_SIGNALS:
        for m in re.finditer(pattern, text):
            full_match = m.group(0)  # 完整匹配（含触发词）
            captured = m.group(1).strip() if m.groups() else full_match.strip()
            # 截断到句号/换行
            captured = re.split(r'[\n。！？]', captured)[0].strip()
            # 去 markdown 格式
            captured = re.sub(r'\*{1,3}|`{1,3}', '', captured).strip()
            # iter119: 修复 "race condition: ..." 类 pattern — 去除 captured 开头的冒号残留
            # 原因：CONSTRAINT_SIGNALS pattern 22 匹配 "race condition: ..." 时
            # 捕获组从冒号后开始，但 re.finditer 可能包含前导冒号+空格
            captured = re.sub(r'^[：:\s]+', '', captured).strip()
            if len(captured) < 10 or len(captured) > _sysctl("extractor.max_summary"):
                continue
            # iter119: 碎片过滤 — 残缺句/截断句不入库
            if _is_fragment(captured):
                continue
            # iter119: 通用质量过滤 — 拦截状态快照/噪声行
            # 注意：约束知识允许以介词开头（如"在 X 里调用 Y 会导致 Z"），
            # 但 _is_quality_chunk 有介词开头过滤规则。对约束类 chunk，改为对
            # full_match 做质量验证（触发词提供足够上下文，不应因 captured 以介词
            # 开头而丢弃真正的约束知识）。
            # 对 full_match 做质量检验，同时 captured 必须非碎片且有实质内容
            if not _is_quality_chunk(full_match):
                continue
            # iter119: 约束语义门控 — 完整匹配文本（含触发词）必须含约束语义词
            # 宽泛模式（注意:/警告:/⚠️）容易误匹配调试输出，用完整上下文验证
            if not _CONSTRAINT_SEMANTIC.search(full_match):
                continue
            results.append(captured)
    return _deduplicate(results)


def _extract_quantitative_conclusions(text: str) -> list:
    """
    v3 量化证据保留。含数字度量的结论行自动提取。
    保留带性能数据、测试结果、指标的句子——这些是"可重建性"最低的信息。

    v6 迭代71：Generational GC 后过滤 — 排除纯验证/测试报告类句子。
    OS 类比：分代 GC 中的 young generation 过滤。
    这些句子虽含量化数据，但本质是过程性记录而非可复用决策。
    """
    # 迭代71：低价值模式排除（纯验证报告、纯测试通过数、纯回归报告）
    LOW_VALUE_QUANT = re.compile(
        r'^(?:'
        r'\d+/\d+\s*(?:通过|passed|全绿|green)'  # "33/33 通过"
        r'|验证[：:]\s*\d+/\d+'                    # "验证：33/33..."
        r'|回归.*全绿'                              # "回归全绿"
        r'|\d+\s*(?:passed|failed)'                # "11 passed"
        r'|测试[：:]\s*\d+'                         # "测试：11..."
        r')',
        re.IGNORECASE
    )
    # iter1383: self_referential_quant_gate — 拦截 memory-os 迭代器自身的量化记录
    _SELF_REF_QUANT_RE = re.compile(
        r'(?:zero_access|chunk|inject|suppress|recall|retriever|extractor|'
        r'迭代器|噪声降|空召回|注入率|命中率|coverage|hit.?rate)',
        re.IGNORECASE
    )
    # 代码行特征：Python/shell 关键字 + 函数调用/f-string 组合
    _CODE_LINE_RE = re.compile(
        r'\bfor\b.+\bin\b|\bprint\s*\(|f[\'"][^\'\"]*\{|'
        r'\bimport\b|\bdef\b|\bif\b.+:|\.append\(|sys\.path|'
        r'^\s*[a-z_]+\s*=\s*(?:open|conn|cursor)\b|'
        r'^\$\s*\w|^#\s*!/'  # shell shebang/变量
    )

    results = []
    for line in text.splitlines():
        stripped = line.strip()
        # 跳过表头行、纯分隔符、代码块标记
        if not stripped or stripped.startswith('```') or stripped.startswith('|---'):
            continue
        if stripped.startswith('#'):
            continue
        # ── iter540: pipe_filter — 表格单元格泄漏拦截 ────────────────────
        # OS 类比：Linux pipe(2) SIGPIPE — 管道读端关闭时 kill 写端，防止数据泄漏到死管道。
        # 根因：markdown 表格行 `| col1 | col2 |` 含数字+结论动词，通过量化检测门控，
        #   被误提取为 quantitative_evidence（生产 DB 实证：2 条 `| 根因 |`/`| 清理 |` 碎片）。
        #   表头检查 `startswith('|---')` 只拦截分隔线，不拦截数据行。
        # 修复：以 `|` 开头或含 2+ 个 `|`（表格结构特征）→ 跳过。
        if stripped.startswith('|') or stripped.count('|') >= 2:
            continue
        # V11: 跳过代码行（Python/shell 语法特征）— 防止 f-string/:25s 被误判为量化数据
        if _CODE_LINE_RE.search(stripped):
            continue
        # 必须包含量化证据
        if not QUANTITATIVE_PATTERN.search(stripped):
            continue
        # 必须包含结论性动词或标点（不是纯数据行）
        if not re.search(r'[：:→✅❌=]|(?:实测|验证|结果|通过|达到|降至|提升|稳定)', stripped):
            continue
        clean = re.sub(r'\*{1,3}|`{1,3}', '', stripped).strip()
        clean = re.sub(r'^[-*•]\s*', '', clean)  # 去列表符号
        # 迭代71：排除纯验证/测试报告
        if LOW_VALUE_QUANT.search(clean):
            continue
        # iter1383: 排除 memory-os 自身量化噪声
        if _SELF_REF_QUANT_RE.search(clean):
            continue
        if _sysctl("extractor.min_length") <= len(clean) <= _sysctl("extractor.max_summary"):
            results.append(clean)
    return _deduplicate(results)[:5]  # 量化结论最多5条


def _quant_semantic_concepts(summary: str) -> str:
    """
    迭代336：从量化证据 summary 中提取语义概念词，追加到 content 末尾。

    信息论根因（Encoding-Retrieval Mismatch, Tulving 1973）：
      quantitative_evidence summary 含数字/符号/迭代编号（如 "11.4us→1.35us"），
      但查询时用概念词（"如何优化性能"/"召回率提升"），形成语义鸿沟。
      FTS5 的 BM25 是词汇匹配引擎，无法跨越此鸿沟 → 14/18 (78%) 零召回。

    修复策略（Query Expansion 的反向：Document Expansion）：
      在写入时预计算并追加概念词，让 FTS5 能按概念词索引量化证据。
      类比：搜索引擎对商品标题自动追加品类词（"iPhone 15" → "手机 智能手机 苹果"）。

    OS 类比：Linux /proc/[pid]/wchan — 内核将进程等待通道名（符号地址）
      与人类可读的系统调用名映射，让 "ps" 输出人类可理解的状态而非裸地址。

    规则优先级：越具体的规则越先匹配，最多追加 3 类概念，避免语义污染。
    """
    import re as _re
    if not summary:
        return ""
    concepts: list = []
    s = summary

    # ── 类别 1：性能优化（数值降低方向）──
    # "X→Y" 且含时间单位/延迟词，判定为性能优化
    if _re.search(r'\d.*→.*\d', s) or '→' in s:
        # 尝试判断方向：提取箭头两侧的第一个数字
        _nums = _re.findall(r'[\d.]+', s)
        if len(_nums) >= 2:
            try:
                _before = float(_nums[0])
                _after = float(_nums[-1])
                if _before > _after and _after > 0:
                    # 数值降低 → 优化/加速
                    concepts.append("性能优化 速度提升 延迟降低 optimize latency improve")
                elif _after > _before:
                    # 数值升高 → 提升/增长
                    concepts.append("性能提升 改善 increase improve recall")
            except (ValueError, IndexError):
                concepts.append("性能优化 improve optimize 量化提升")

    # ── 类别 2：检索/召回类 ──
    if _re.search(r'召回|recall|FTS|BM25|检索|fts_rank|precision|hit.rate', s, _re.IGNORECASE):
        concepts.append("检索优化 召回率提升 search retrieve FTS5 BM25 recall precision")

    # ── 类别 3：启动/导入/延迟类 ──
    if _re.search(r'import|启动|冷启动|加载|startup|load|ms|us|μs|latency', s, _re.IGNORECASE):
        concepts.append("启动性能 冷启动 import overhead latency ms startup")

    # ── 类别 4：修复/Bug 类 ──
    if _re.search(r'修复|fix|bug|错误|error|crash|回归|regression', s, _re.IGNORECASE):
        concepts.append("修复 bug修复 fix repair regression")

    # ── 类别 5：内存/swap/淘汰类 ──
    if _re.search(r'内存|memory|swap|evict|淘汰|chunk|kswapd|oom', s, _re.IGNORECASE):
        concepts.append("内存优化 淘汰 eviction memory chunk kswapd")

    # ── 类别 6：迭代版本关联 ──
    _iter_match = _re.search(r'iter(\d+)', s, _re.IGNORECASE)
    if _iter_match:
        concepts.append(f"迭代优化 iter{_iter_match.group(1)} 版本改进")

    # 最多取前 3 类，去重，追加为 concept 注释行
    if not concepts:
        # fallback: 通用量化证据概念
        concepts.append("量化优化 性能改进 benchmark optimize improve")

    unique_concepts = list(dict.fromkeys(concepts))[:3]
    return " | ".join(unique_concepts)


def _is_quality_reasoning(summary: str) -> bool:
    """
    迭代113：reasoning_chain 专用质量门控 — 最小语义密度校验。

    reasoning_chain 表达的是因果关系/推理过程，必须含以下任一信号：
      A. 因果词：因为/由于/导致/→/所以/故/原因/根因/因此
      B. 发现词：发现/诊断/确认/问题是/根本/核心问题
      C. 推理标记：root cause / because / therefore / key finding
      D. 长度 ≥ 25 chars（长句通常包含足够上下文）

    过滤目标：纯名词短语（如 "enqueue 阶段"、"sub-sched 激活机制"）
    这类碎片是提取模式误匹配 "xxx阶段" / "xxx机制" 等后缀词产生的，
    独立存储时没有任何可复用的因果知识。

    OS 类比：TCP segment 的 payload 必须包含有效数据，不接受空 payload（纯 ACK 除外）。
    """
    if not summary:
        return False
    s = summary.strip()
    # 长句通常自带足够上下文
    if len(s) >= 25:
        return True
    # 含因果/推理/发现信号词
    if re.search(
        r'(?:因为|由于|导致|→|所以|故|原因|根因|因此|'
        r'发现|诊断|确认|问题是|根本|核心问题|'
        r'root cause|because|therefore|key finding|'
        r'理解有误|理解错误|误以为|实际上)',
        s
    ):
        return True
    return False


def _is_fragment(text: str) -> bool:
    """
    迭代73+78+80+B17：碎片检测。排除截断的代码片段、表格行、markdown 标题等非完整句。
    OS 类比：TCP checksum — 数据完整性校验，丢弃损坏的 segment。
    迭代78：新增冒号碎片检测（leading/trailing ：/:）
    迭代80：新增架构层级标签碎片检测（/L4/L5...、/层级名...）
    迭代B17：新增中文句中开头字符检测（性/等/时/中/里 等 = 截断中文从句）
    """
    if not text or len(text) < 8:
        return True
    # 以特殊字符开头 = 截断的代码/表格/markdown/续行（含全角变体）
    if text[0] in ('_', '|', ')', ']', '}', '>', '+', '=', ':', '：', '）', '】', '》'):
        return True
    # 以逗号/顿号/分号开头 = 截断残缺句（上一句的后半段）
    if text[0] in (',', '，', '、', ';', '；'):
        return True
    # markdown 标题行本身不是摘要
    if text.startswith('#'):
        return True
    # 纯数字/符号行
    if re.match(r'^[\d\s.,:;/×\-+=%]+$', text):
        return True
    # 以 | 分隔的表格行
    if text.count('|') >= 2:
        return True
    # 迭代78：以冒号结尾 = 标题/标签碎片（"核心成果："）
    stripped = text.rstrip()
    if stripped.endswith(':') or stripped.endswith('：'):
        return True
    # 迭代80：/大写字母 或 /中文 开头 = 架构层级标签碎片（"/L4/L5..."、"/层级名..."）
    # 保留真正的文件路径（/home/...、/etc/...、/var/... 等小写开头）
    if text[0] == '/' and len(text) > 1 and re.match(r'^/[A-Z\u4e00-\u9fff]', text):
        return True
    # 迭代B17+B18：中文从句尾部字符开头 = 截断中文句（"性重构等）时，..."、"等）时"）
    # 这些字符在中文语法中不能作为独立句子的开头，出现在 position-0 说明是句子中间截断的。
    # 典型情形：正则捕获组匹配到从句尾部 "性" / "等" 等助词或形容词词尾。
    # OS 类比：TCP sequence number validation — 起始 seq 不在合法窗口内，丢弃 segment。
    _CN_MID_SENTENCE_STARTERS = frozenset('性等时中里上下内外到从着过了地得把被让向以于的是句')
    if text[0] in _CN_MID_SENTENCE_STARTERS:
        # 仅当第一个字是纯中文助词/尾词时判定为碎片
        # 保护：首字是"中文名词+助词"组合的合法句（如"中文分词策略"的"中"）
        # 策略：若第2个字是中文且构成常见词语开头（如"中文"/"时间"/"的确"），则保留
        if len(text) < 2 or not re.match(r'^[\u4e00-\u9fff]', text[1:2]):
            return True
        # 第2字也是中文时：检查是否是合法词语开头（词频最高的双字中文技术词）
        # 放行条件：双字前缀在常见技术词白名单中
        # B18: 新增 '空转'（"是空转" → A06 migration 线程场景）
        _SAFE_CN_PAIRS = frozenset({
            '中文', '时间', '时序', '时钟', '等待', '等效', '等价',
            '下游', '下载', '下层', '上游', '上层', '内核', '内存',
            '外部', '外层', '到达', '从而', '性能', '性质',
            '空转', '是否', '是因', '是空',  # B18: 新增 — 技术分析场景中合法的"是"开头词对
        })
        pair = text[:2]
        if pair not in _SAFE_CN_PAIRS:
            return True
    # B18: 以右括号结尾 = 提取自括号表达式内部，是截断的补充说明
    # 典型：'Running 但慢 = 频率受限 → 资源管控）' — 尾部 '）' 说明这是括号内容被截断
    # 注意：完整句也可能以括号结尾（如"（推荐方案 A）"），所以只过滤中文全角括号结尾
    stripped = text.rstrip()
    if stripped.endswith('）') or stripped.endswith(')'):
        # 只过滤：以右括号结尾且括号没有对应左括号（孤立右括号 = 截断）
        left_count = text.count('（') + text.count('(')
        right_count = text.count('）') + text.count(')')
        if right_count > left_count:
            return True
    # ── iter525: memfd_seal — JSON truncation fragment detection ──────────
    # OS 类比：Linux memfd_seal(F_SEAL_WRITE) (Jeff Xu, 2024) — 内容完整性密封
    # 根因：assistant 输出含 JSON 结构体，regex 捕获组截断到 value 中间，
    # 产生 "ommended_action": "xxx"、"tion": "..." 等碎片
    # 检测：小写拉丁字母开头 + JSON 键值特征 = 截断的 JSON value
    if re.match(r'^[a-z]', text) and re.search(r'": "', text[:40]):
        return True
    # 裸小写词片段 + 紧跟下划线 — 无 () 的截断标识符（排除合法函数引用如 "sleep_consolidate()"）
    if re.match(r'^[a-z]{2,}_', text) and '()' not in text[:30]:
        return True
    return False


def _extract_conversation_summary(text: str, extra_texts: list = None) -> list:
    """
    v4+v5 对话摘要提取。从助手回复中提取核心行动/结论句。
    目标：捕获非决策类的有价值信息（解决了什么、做了什么、发现了什么）。

    提取策略（3 层）：
      S1 完成动作：已完成/已修复/已创建/已更新 + 对象
      S2 发现/诊断：发现/诊断/定位/确认 + 问题描述
      S3 markdown 总结标题下的首句（## 总结/## Summary 后的第一段）

    v5 迭代73：碎片过滤 — _is_fragment() 校验捕获结果完整性。
    增强1：extra_texts — transcript 尾部最近 5 轮 assistant 消息，也参与提取。
    """
    # 合并 last_assistant_message 和 transcript 尾部额外轮次
    all_texts = [text]
    if extra_texts:
        all_texts.extend(t for t in extra_texts if t and t != text)

    results = []

    # S1: 完成动作
    action_patterns = [
        r'(?:已完成|已修复|已创建|已更新|已实现|已添加|已删除|已重构|已迁移|已升级|已部署)[：:：]?\s*(.{5,100})',
        r'(?:完成了|修复了|创建了|更新了|实现了|添加了|重构了)[：:：]?\s*(.{5,100})',
        r'(?:successfully|completed|fixed|created|implemented|deployed)[：:：]?\s*(.{5,100})',
    ]
    # S2: 发现/诊断
    diag_patterns = [
        r'(?:发现|诊断|定位|确认|排查)[：:]\s*(.{10,100})',
        r'(?:问题是|原因是|根因是|bug 是)[：:]\s*(.{10,100})',
        r'(?:found|diagnosed|confirmed|identified)[：:]\s*(.{10,100})',
    ]

    # 增强1：对 last_assistant_message + transcript 尾部 5 轮消息都做 S1/S2/S3 提取
    for src_text in all_texts:
        for pat in action_patterns:
            for m in re.finditer(pat, src_text, re.IGNORECASE):
                captured = m.group(1).strip()
                captured = re.split(r'[\n。！？]', captured)[0].strip()
                captured = re.sub(r'\*{1,3}|`{1,3}', '', captured).strip()
                if _is_fragment(captured):
                    continue
                if _sysctl("extractor.min_length") <= len(captured) <= _sysctl("extractor.max_summary"):
                    results.append(captured)

        for pat in diag_patterns:
            for m in re.finditer(pat, src_text, re.IGNORECASE):
                captured = m.group(1).strip()
                captured = re.split(r'[\n。！？]', captured)[0].strip()
                captured = re.sub(r'\*{1,3}|`{1,3}', '', captured).strip()
                if _is_fragment(captured):
                    continue
                if _sysctl("extractor.min_length") <= len(captured) <= _sysctl("extractor.max_summary"):
                    results.append(captured)

        # S3: 总结标题下的首句
        summary_sections = re.finditer(
            r'^#{1,3}\s*(?:总结|Summary|结论|完成|结果|验证)[^\n]*\n+(.{10,200})',
            src_text, re.MULTILINE | re.IGNORECASE
        )
        for m in summary_sections:
            first_line = m.group(1).strip()
            first_line = re.split(r'[\n]', first_line)[0].strip()
            first_line = re.sub(r'\*{1,3}|`{1,3}', '', first_line).strip()
            first_line = re.sub(r'^[-*•]\s*', '', first_line)
            if _is_fragment(first_line):
                continue
            if _sysctl("extractor.min_length") <= len(first_line) <= _sysctl("extractor.max_summary"):
                results.append(first_line)

    return _deduplicate(results)[:6]  # 增强1后最多 6 条（原 3 × 最多 2 轮有效内容）


def _read_transcript_tail(transcript_path: str, max_bytes: int = 200 * 1024) -> list:
    """
    增强1：读取 transcript JSONL 尾部，返回最近 5 轮 assistant 消息文本列表。
    只读文件末尾 max_bytes 字节（seek，不全量读取），控制延迟 < 50ms。

    transcript 格式（每行一个 JSON）：
      assistant 轮次：type="assistant", message.role="assistant", content=[{type="text",text="..."}]
    """
    try:
        path = Path(transcript_path)
        if not path.exists() or path.stat().st_size == 0:
            return []
        file_size = path.stat().st_size
        read_size = min(max_bytes, file_size)
        with open(path, 'rb') as f:
            f.seek(-read_size, 2)
            raw = f.read(read_size)
        text = raw.decode('utf-8', errors='replace')
        lines = text.split('\n')
        # 第一行可能被截断，跳过
        if read_size < file_size:
            lines = lines[1:]

        results = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get('type') != 'assistant':
                continue
            msg = d.get('message', {})
            if not isinstance(msg, dict) or msg.get('role') != 'assistant':
                continue
            content = msg.get('content', [])
            if not isinstance(content, list):
                continue
            for c in content:
                if isinstance(c, dict) and c.get('type') == 'text':
                    t = c.get('text', '')
                    if t and len(t) >= 20:
                        results.append(t)
        # 返回最近 5 轮（列表末尾是最新的）
        return results[-5:]
    except Exception:
        return []


def _extract_from_tool_outputs(transcript_path: str, session_id: str,
                               project: str, conn: sqlite3.Connection) -> int:
    """
    增强2：从 transcript JSONL 尾部提取 Bash tool_result 关键结论。
    chunk_type = "tool_insight"（新类型）。

    策略：
    - 只读尾部 200KB（seek，不全量读取）
    - 找 user 类型条目中对应 Bash 工具的 tool_result
    - 提取含量化数据（通过/失败/性能指标/百分比变化）的行

    返回写入的 chunk 数（上限 5）。
    """
    _TOOL_INSIGHT_PATTERN = re.compile(
        r'(?:'
        # 测试通过/失败计数
        r'\d+/\d+\s*(?:通过|passed|failed|tests?)'
        r'|(?:PASSED|FAILED|ERROR)\s+\d+'
        r'|\d+\s+(?:passed|failed|error)'
        # 测试摘要行（"N passed, M failed"）
        r'|\d+\s+passed.*\d+\s+(?:failed|warning|error)'
        # 性能数据
        r'|P\d+\s*[=:]\s*\d+\s*(?:ms|s)'
        r'|\d+(?:\.\d+)?\s*ms\b'
        # 指标变化
        r'|\+\d+(?:\.\d+)?%|-\d+(?:\.\d+)?%'
        r'|(?:hit_rate|coverage|precision|recall)[=:]\s*\d'
        r')',
        re.IGNORECASE
    )

    try:
        path = Path(transcript_path)
        if not path.exists() or path.stat().st_size == 0:
            return 0
        file_size = path.stat().st_size
        read_size = min(200 * 1024, file_size)
        with open(path, 'rb') as f:
            f.seek(-read_size, 2)
            raw = f.read(read_size)
        text_raw = raw.decode('utf-8', errors='replace')
        lines = text_raw.split('\n')
        if read_size < file_size:
            lines = lines[1:]

        # 第一遍：收集 Bash tool_use id 集合
        bash_tool_ids: set = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get('type') != 'assistant':
                continue
            msg = d.get('message', {})
            if not isinstance(msg, dict):
                continue
            for c in (msg.get('content') or []):
                if isinstance(c, dict) and c.get('type') == 'tool_use':
                    if c.get('name') == 'Bash':
                        bash_tool_ids.add(c.get('id', ''))

        if not bash_tool_ids:
            return 0

        # 第二遍：提取 Bash 工具的 tool_result
        written = 0
        seen_summaries: set = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get('type') != 'user':
                continue
            msg = d.get('message', {})
            if not isinstance(msg, dict):
                continue
            for c in (msg.get('content') or []):
                if not isinstance(c, dict) or c.get('type') != 'tool_result':
                    continue
                if c.get('tool_use_id', '') not in bash_tool_ids:
                    continue
                # 提取输出文本
                raw_content = c.get('content', '')
                if isinstance(raw_content, str):
                    output_text = raw_content
                elif isinstance(raw_content, list):
                    parts = []
                    for item in raw_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            parts.append(item.get('text', ''))
                    output_text = '\n'.join(parts)
                else:
                    continue

                if not output_text or len(output_text) < 20:
                    continue

                # 逐行扫描含量化数据的行
                for out_line in output_text.splitlines():
                    stripped = out_line.strip()
                    if not stripped or len(stripped) < 10:
                        continue
                    if not _TOOL_INSIGHT_PATTERN.search(stripped):
                        continue
                    # 去 ANSI 颜色码，去多余空白
                    clean = re.sub(r'\x1b\[[0-9;]*m', '', stripped)
                    clean = re.sub(r'\s+', ' ', clean).strip()
                    if len(clean) < 10 or len(clean) > 200:
                        continue
                    if not _is_quality_chunk(clean):
                        continue
                    # tool_insight 专用过滤：排除纯调试/系统输出噪音
                    # 这些行含量化数据但没有可复用决策价值
                    if _is_tool_insight_noise(clean):
                        continue
                    # iter1288: fragment_completeness_gate — 拒绝不完整句子片段
                    if re.search(r'[,，、;；]\s*$', clean):
                        continue
                    key = re.sub(r'\s+', '', clean.lower())
                    if key in seen_summaries:
                        continue
                    seen_summaries.add(key)
                    _write_chunk("tool_insight", clean, project, session_id,
                                 topic="", conn=conn,
                                 importance_override=0.75)
                    written += 1
                    if written >= 5:
                        return written
        return written
    except Exception:
        return 0


def _extract_tool_patterns(transcript_path: str, conn: sqlite3.Connection,
                           project: str, session_id: str,
                           context_text: str = "") -> int:
    """
    工具使用模式学习 — 从本轮 transcript 中提取工具调用序列并写入 tool_patterns 表。
    OS 类比：perf_event 采样 — 在会话结束时提取 CPU 热点调用链，供下轮预测和预热。

    策略：
    - 只读 transcript JSONL 尾部 200KB（seek，不全量读取）
    - 收集 assistant 类型条目中所有 tool_use 的 name 字段（按出现顺序）
    - 滑动窗口（3/4/5 个工具一组）切分为子序列
    - 对每个子序列：
        hash(JSON序列) → 已存在则 UPDATE frequency+1/last_seen，否则 INSERT
    - context_keywords：从 context_text（last_assistant_message）提取英文技术词和中文双字词

    返回写入/更新的 pattern 数（上限 30）。
    """
    import hashlib

    if not transcript_path:
        return 0

    try:
        path = Path(transcript_path)
        if not path.exists() or path.stat().st_size == 0:
            return 0
        file_size = path.stat().st_size
        read_size = min(200 * 1024, file_size)
        with open(path, 'rb') as f:
            f.seek(-read_size, 2)
            raw = f.read(read_size)
        text_raw = raw.decode('utf-8', errors='replace')
        lines = text_raw.split('\n')
        if read_size < file_size:
            lines = lines[1:]  # 跳过可能截断的首行

        # 按顺序收集本轮所有 tool_use 名称
        tool_names: list = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get('type') != 'assistant':
                continue
            msg = d.get('message', {})
            if not isinstance(msg, dict):
                continue
            for c in (msg.get('content') or []):
                if isinstance(c, dict) and c.get('type') == 'tool_use':
                    name = c.get('name', '')
                    if name:
                        tool_names.append(name)

        if len(tool_names) < 2:
            return 0  # 少于 2 个工具调用，无模式可提取

        # 提取 context_keywords（用于模式的上下文标注）
        keywords: list = []
        if context_text:
            seen_kw: set = set()
            # 英文技术词（驼峰/下划线/短横线）
            for m in re.finditer(r'\b([A-Z][a-zA-Z0-9_]{2,20}|[a-z][a-z0-9_]{3,20})\b', context_text[:3000]):
                w = m.group(1)
                if w.lower() not in _MADVISE_STOPWORDS and w not in seen_kw:
                    seen_kw.add(w)
                    keywords.append(w)
                    if len(keywords) >= 8:
                        break
            # 中文双字词（高频）
            if len(keywords) < 8:
                cn = re.sub(r'[^\u4e00-\u9fff]', '', context_text[:3000])
                freq: dict = {}
                for i in range(len(cn) - 1):
                    bg = cn[i:i+2]
                    freq[bg] = freq.get(bg, 0) + 1
                for bg, cnt in sorted(freq.items(), key=lambda x: -x[1]):
                    if cnt >= 2 and len(keywords) < 8:
                        keywords.append(bg)

        kw_json = json.dumps(keywords, ensure_ascii=False)

        now_iso = datetime.now(timezone.utc).isoformat()
        written = 0

        # 滑动窗口：3/4/5 个工具一组
        for window in (3, 4, 5):
            if len(tool_names) < window:
                continue
            for i in range(len(tool_names) - window + 1):
                seq = tool_names[i:i + window]
                seq_json = json.dumps(seq, ensure_ascii=False)
                # 修复：hash 只用 seq_json，不含 project
                # 原因：project ID 随路径/git remote 变化，同一序列在不同 project 各存
                # 一份导致频率被稀释（无法累积到推荐阈值），跨 project 学习失效。
                h = hashlib.md5(seq_json.encode()).hexdigest()

                existing = conn.execute(
                    "SELECT id, frequency FROM tool_patterns WHERE pattern_hash=?", (h,)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE tool_patterns SET frequency=frequency+1, last_seen=? WHERE pattern_hash=?",
                        (now_iso, h)
                    )
                else:
                    conn.execute(
                        """INSERT INTO tool_patterns
                           (pattern_hash, tool_sequence, context_keywords, frequency,
                            avg_duration_ms, success_rate, first_seen, last_seen, project)
                           VALUES (?, ?, ?, 1, 0, 1.0, ?, ?, ?)""",
                        (h, seq_json, kw_json, now_iso, now_iso, project)
                    )
                    written += 1
                    if written >= 30:
                        conn.commit()
                        return written

        conn.commit()
        return written
    except Exception:
        return 0


def _extract_page_fault_candidates(text: str) -> list:
    """
    提取"推理中途需要但可能没有的知识"——用于缺页日志。
    识别模式分 3 级（v3 扩展）：
      P0 显式缺口：假设/待验证/需要确认
      P1 隐式缺口：之前/上次/历史中提到过
      P2 探索性缺口：TODO/需要了解
      P3 v3新增：上下文引用缺失（提到文件/函数但没读取内容）
    """
    candidates = []
    patterns = [
        # P0: 显式知识缺口
        r'(?:假设|待验证|需要确认|需要验证)[：:]\s*(.{5,80})',
        r'(?:需要查看|需要读|应该先看|先检查)\s*(.{5,60})',
        r'(?:我不确定|不清楚|需要了解|尚不明确)\s*(.{5,60})',
        # P1: 隐式引用（暗示之前有相关决策/讨论）
        r'(?:之前|上次|此前|历史上)(?:决定|选择|讨论|分析)(?:过|了)\s*(.{5,60})',
        r'(?:根据之前的|按照此前的)\s*(.{5,60})',
        # P2: 探索性
        r'TODO[：:]\s*(.{5,80})',
        r'(?:待调查|待研究|待确认)\s*(.{5,60})',
        # P3: v3 上下文引用（提到概念但可能没有完整上下文）
        r'(?:参考|见|详见|参见)\s*(.{5,60})',
        r'(?:上文|前文|之前提到的)\s*(.{5,60})',
        r'(?:还需要|另外需要|同时需要)\s*(?:了解|确认|检查)\s*(.{5,60})',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text):
            candidates.append(m.group(1).strip()[:80])
    return _deduplicate(candidates)


def _deduplicate(items: list) -> list:
    seen = set()
    result = []
    for item in items:
        key = re.sub(r'\s+', '', item.lower())
        if key not in seen and len(key) > 3:
            seen.add(key)
            result.append(item)
    return result


# ── iter370: Uncertainty Signal Extraction ──────────────────────────────────
# 认知科学背景：Metcognition / TOT (Tip-of-the-Tongue) 现象
#   人类在知识检索失败时会产生"感觉知道但说不出"的元认知信号。
#   这类信号如果被捕获并存入外部记忆，下次检索时可定向补充知识空白。
# OS 类比：MMU soft page fault — CPU 访问 valid VMA 内的未映射页时，
#   产生 #PF 异常（中断），OS 记录缺页地址，后台 mmap/swap-in 补充；
#   这里 Claude 说"我不确定X"= soft page fault，X = 缺页地址，
#   DB 中写入 [不确定] X chunk = fault 记录，下次 SessionStart prefetch 补充。

_UNCERTAINTY_PATTERNS = [
    # 中文强不确定（P0）
    r'(?:我不确定|不确定是否|不清楚|尚不明确)\s*[：:]?\s*(.{5,80})',
    r'(?:需要验证|待验证|待确认|需要确认)\s*[：:]?\s*(.{5,80})',
    r'(?:可能|也许|或许)\s*(?:需要|要)(?:确认|验证|查看)\s*(.{5,60})',
    # 中文隐式不确定（P1）
    r'(?:我(?:猜|认为可能)|这里假设)\s*(.{5,60})\s*(?:，|，但|，不过)',
    r'(?:假设|假定)\s*(.{5,60})\s*(?:成立|正确|是对的)',
    # 英文（P0/P1）
    r'(?:I\'m not sure|not certain|unclear)[,\s]+(?:about\s+)?(.{5,80})',
    r'(?:need to verify|need to check|need to confirm)[,\s]+(.{5,80})',
    r'(?:I assume|assuming)[,\s]+(.{5,60})\s*(?:,|but|though)',
]

_UNCERTAINTY_RE = [re.compile(p, re.IGNORECASE) for p in _UNCERTAINTY_PATTERNS]


def _extract_uncertainty_signals(text: str) -> list:
    """
    iter370：从 assistant 消息中提取强不确定性信号。
    返回 [(topic_str, confidence_level)] 列表。
    confidence_level: 'low' (显式不确定) / 'medium' (隐式假设)
    """
    results = []
    seen: set = set()
    for i, pat in enumerate(_UNCERTAINTY_RE):
        level = 'low' if i < 5 else 'medium'
        for m in pat.finditer(text):
            topic = m.group(1).strip()
            # 清理 markdown 标记
            topic = re.sub(r'\*{1,3}|`{1,3}', '', topic).strip()
            # 截断到第一个标点或换行
            topic = re.split(r'[。！？\n]', topic)[0].strip()[:80]
            # iter B16：碎片过滤 — 以逗号/引号/标点开头的 = 截断残缺句
            if topic and topic[0] in (',', '，', '、', '"', "'", '\u201c', '\u201d', '\u2018', '\u2019'):
                continue
            # iter B16：过短的不确定信号无实际检索价值
            if len(topic) < 8:
                continue
            key = re.sub(r'\s+', '', topic.lower())
            if len(topic) >= 5 and key not in seen:
                seen.add(key)
                results.append((topic, level))
    return results[:6]  # 最多 6 条（避免噪声过多）


def _write_uncertainty_chunks(
    conn, signals: list, project: str, session_id: str
) -> int:
    """
    iter370：将不确定性信号写入 DB 作为 reasoning_chain chunk。
    summary = "[不确定] {topic}"，importance = 0.55（低于正常决策 0.7，但高于噪声）。
    chunk_type = "reasoning_chain"，info_class = "episodic"（会话级，快速衰减）。
    OS 类比：MMU page_fault_log 写入 — /proc/vmstat pgfault 计数器递增，
      同时记录 fault address 到 vm_fault 结构体供后续 swap-in 使用。
    """
    if not signals:
        return 0
    import uuid as _uuid
    now_iso = datetime.now(timezone.utc).isoformat()
    written = 0
    for topic, level in signals:
        summary = f"[不确定] {topic}"
        # 幂等：同项目内相同 summary 不重写
        if already_exists(conn, summary, "reasoning_chain"):
            continue
        chunk_id = "uf_" + _uuid.uuid4().hex[:16]
        importance = 0.50 if level == 'medium' else 0.55
        chunk = {
            "id": chunk_id,
            "created_at": now_iso,
            "updated_at": now_iso,
            "project": project,
            "source_session": session_id,
            "chunk_type": "reasoning_chain",
            "info_class": "episodic",
            "content": f"Claude 在会话 {session_id[:8]} 中表示不确定：{topic}",
            "summary": summary,
            "tags": ["uncertainty", "page_fault"],
            "importance": importance,
            "retrievability": 1.0,
            "last_accessed": now_iso,
            "access_count": 0,
            "oom_adj": 50,    # 比正常 chunk 更易被淘汰（临时信号）
            "lru_gen": 0,
            "stability": 0.5,  # 低稳定性，快速衰减
            "raw_snippet": "",
            "encoding_context": {},
        }
        try:
            insert_chunk(conn, chunk)
            written += 1
        except Exception:
            pass
    return written


def _is_selfref_noise(summary: str, chunk_type: str) -> bool:
    """iter1117: pool_selfref_gate_sync — 系统自描述噪声检测（可复用函数）。
    返回 True 表示是 selfref 噪声，应拒绝写入。
    根因（数据驱动，2026-05-08）：extractor_pool._write_chunks 路径缺少 selfref gate，
      导致 decision chunk "量化预期：大库 suppress 全灭后空召回率降 ~50%"(ac=0) 逃逸。
      提取为独立函数供 extractor.py _write_chunk 和 extractor_pool.py 共用。
    """
    _strict_types = ("decision", "reasoning_chain", "causal_chain", "excluded_path", "conversation_summary")
    _is_constraint = chunk_type == "design_constraint"
    if chunk_type not in _strict_types and not _is_constraint:
        return False
    hits = len(re.findall(
        r'(?:_score_chunk|suppress|fallback|top.?k|候选全灭|空召回|recall_count|'
        r'hard_suppressed|relevance_fallback|iter\d{3,4}|cooldown|bandwidth|'
        r'hard_deadline|inject|scored|cands|FTS.*miss|BM25.*noise|'
        r'噪声率?|ac[=≥]\d+|\bac\b.{0,3}chunk|chunk.?type|selfref|gate|逃逸|垄断|注入率?|单条注入|'
        r'注入资格|\d+d\s*(?:cooldown|循环|窗口)|7d|24h|6h|量化[预改效结影响：:].{0,6}|SWAPPED|timeline|suppress_final|'
        r'token.?overlap|子串检测|LCS|dedup|去重|碎片拦截|写入门控|拦截率|'
        r'diversity|健康度|same.hash|归零|e2e.*pass|迭代器|chunk.清理|密度.*→|'
        # iter1127: chunk_type_ref_gate — chunk 类型名/内部字段名作为讨论主题时拦截
        r'causal_chain|reasoning_chain|excluded_path|design_constraint|'
        r'zero.access|access.count|拒绝写入|一律拒绝|chunk\s*数|'
        # iter1141: iteration_report_gate — 迭代器自检/量化报告拦截
        # 根因（数据驱动，2026-05-08）："量化：zero_access 0%…PA 10/10 HEALTHY…8/8 pass"
        #   selfref hits=1（仅 zero_access），不足 2 阈值逃逸。
        #   "PA"/"HEALTHY"/"pass"/"production_assert" 是典型迭代器自检输出。
        r'PA\s+\d+/\d+|HEALTHY|production.?assert|tests?\s+\d+/\d+\s*pass|'
        r'extractor\s+tests?|闭包快照|closure.?snapshot|'
        # iter1148: internal_var_gate — 内部变量名/db分级标识逃逸
        # 根因（数据驱动，2026-05-08）："_db_chunk_count…micro_db(<=5)" hits=0 逃逸。
        #   micro_db/tiny_db/small_db/chunk_count 是 retriever 内部分级变量。
        r'micro_db|tiny_db|small_db|chunk_count|_db_chunk|bypass|误判|'
        # iter1184: mm_subsystem_selfref — memory-os 回收/MM 子系统内部术语
        r'swap_out|kswapd|pd_scan|_reclaim|cold_born|store_mm|oom_adj|lru_gen|'
        # iter1186: retriever_internal_var_gate — retriever 内部函数/变量名
        # 根因（数据驱动，2026-05-08）："pair_preserve（iter926）保护低分 pair 不被 score_floor 过滤"
        #   hits=1（仅 iter926），pair_preserve/score_floor 未覆盖 → 逃逸。
        # 修复：补充 retriever 内部函数名和评分变量。
        r'pair_preserve|score_floor|_ac_gated|pair_from_db|diversity_pair|'
        r'imp_pair|suppress_fallback|bw_window|hard_cap|_min_thresh|'
        r'_effective_top_k|top_k_data|accessed_ids|_pre_suppress|'
        r'candidates?全灭|候选池|'
        # iter1218: cross_project_analysis_gate — 跨项目注入分析噪声
        # 根因（数据驱动，2026-05-09）：2 条 causal_chain 描述跨项目聚合逻辑（"不走跨项目聚合"
        #   "管道符号过滤"）hits=1 逃逸。含 project=git:/abspath: + 聚合/注入动词是迭代器分析特征。
        r'跨项目聚合|project[=:].{0,5}(?:git|abspath)|管道符号过滤|'
        r'burst.suppress|daemon.*(?:注入|进程内)|retriever_daemon|'
        r'recall_trace|shadow_trace|注入质量|可观测性退化|'
        r'MEMORY\.md|悬挂链接|FTS5|memory.chunks|store\.db|'
        # iter1261: direct_cap_final_gate — retriever 内部路径对齐术语
        r'direct.cap|final_gate|_score_chunk|base[=-]\d|'
        # iter1278: iterator_stats_report_gate — 迭代器统计报告/效果描述逃逸
        r'top.?\d+.*(?:share|占比?|降)|[Zz]ero.access|'
        r'(?:释放|残留).{0,15}(?:注入位|chunk|知识)|注入\s*\d+%|空召回率|'
        r'\d+%\s*[\(（].*→\s*\d+%|'
        # iter1306: effect_prediction_gate — 迭代器效果预测/垄断度量逃逸
        r'预期效果.{0,10}(?:垄断|注入|suppress)|垄断.{0,10}[→>]\s*[<\d]|'
        r'\d+\.?\d*%\s*→\s*[<>]?\s*\d+\.?\d*%|'
        r'rs\[:\d+\]|截取.{0,5}token|'
        # iter1329: recall_behavior_gate — memory-os 检索行为讨论术语
        r'无法被召回|恢复路径|注入资格|召回路径|知识库可达性|可达性\s*\d+%|'
        # iter1346: internal_maintenance_gate — FTS5/index 维护 + 效果量化描述逃逸
        r'orphan|self.heal|index.修复|重建$|检索竞争力|importance\s*[+\-]|'
        # iter1348: sql_diag_gate — 内部 SQL 诊断/rowid 操作逃逸
        r'rowid\s+NOT\s+IN|DELETE\s+FROM\s+memory|INSERT\s+INTO\s+memory|清空了.*表|'
        # iter1373: pair_internal_gate — pair/候选/单条注入 内部检索概念逃逸
        r'\bpair\b.*(?:候选|失败|排除|不包含)|候选[池=]|单条注入率?|预期改善[：:]|'
        # iter1408: selfref_component_gate — extractor/retriever 组件名 + 碎片写入逃逸
        # iter1414: anchor_internal_gate — memory-os 内部检索概念（noise chunk/domain anchor）
        r'\bextractor\b|碎片写入|无条件拒绝|noise.?chunk|domain.?anchor|'
        # iter1417: store_vfs_internal_gate — store_vfs 内部函数/路径逃逸
        r'store_vfs|_write_trace|insert_trace|ghost.*(?:inject|注入)|empty.*guard|'
        r'writeback|trace.*标记|pollut|污染.*(?:count|统计)|'
        r'scoring\s*崩溃|traces\b.*\d+/\d+|'
        # iter1429: cold_start_selfref_gate — cold_start/零访问/曝光死锁 逃逸
        r'cold_start|零访问|曝光死锁|首次曝光|候选池|'
        # iter1463: lite_full_path_gate — "LITE/FULL 路径" 是 retriever 内部概念
        r'LITE\s*路径|FULL\s*路径|hard_deadline\s*路径|'
        # iter1463: effect_prediction_arrow — "预期：X→Y" 百分比箭头是迭代器效果预测
        r'预期[：:].{0,30}→|'
        # iter1475: sparse_internal_var_gate — retriever 内部分级/保护变量逃逸
        r'_local_sparse|local_sparse|sparse_shield|lifetime\s*suppress|额外保护|'
        # iter1481: diag_report_gate — 迭代器诊断报告逃逸
        # 根因（数据驱动，2026-05-11）：2 条 ac=0 chunk "诊断：35 ACTIVE chunks，7d 注入覆盖 62%，
        #   …suppress 机制已有效控制垄断" hits=0 逃逸。含 ACTIVE chunks/suppress 机制/注入覆盖/控制垄断
        #   均为 retriever 内部诊断概念，非用户知识。
        r'ACTIVE\s*chunks?|suppress\s*机制|注入覆盖|控制垄断|分布合理|'
        # iter1498: pool_internal_gate — "池"作为 chunk pool 内部概念逃逸
        # 数据驱动（2026-05-11）："global 池 18→10（-44%），高价值 constraint 占比 56%→100%"
        #   hits=1 不够阈值 2。"池"+占比/注入/chunk 是 memory-os 内部概念。
        r'(?:global|注入|候选|知识)\s*池|池\s*\d+\s*→|'
        # iter1526: retriever_diag_term_gate — retriever 内部诊断术语逃逸
        # 数据驱动（2026-05-11）：540dd383 "FULL 请求全空召回…BM25 阈值" hits=1 逃逸。
        #   "FULL 请求"≠已有"FULL 路径"；"BM25"/"thresh" 未覆盖。均为 retriever 内部概念。
        r'FULL\s*请求|BM25\s*阈值|thresh[=\d]|封杀|'
        # iter1561: chunk_state_selfref_gate — DEAD/SWAPPED chunk state + weekly stats 逃逸
        # 数据驱动（2026-05-12）："78dc 项目只有 1 条 ACTIVE chunk，其余 18 条 DEAD"
        #   hits=1(ACTIVE chunks) 不够 decision 阈值 2。"DEAD"/"SWAPPED" 是 memory-os 内部状态。
        # "W18 空召回率 46%，W17 69%" — weekly 注入统计是 retriever 内部指标。
        r'(?:DEAD|SWAPPED)\b|W\d+\s*空召回|chunk_state|ACTIVE\s*(?:池|chunk|数)|'
        r'存活率|写入存活)',
        summary
    ))
    # iter1325: constraint_selfref_gate — design_constraint 用更严格阈值(>=3)防误杀
    # iter1373: conversation_summary 阈值降为 1 — 对话摘要 + 任何内部术语即拒绝
    _min_hits = 3 if _is_constraint else (1 if chunk_type == "conversation_summary" else 2)
    if hits < _min_hits:
        if hits == 1 and len(summary) < 30 and not _is_constraint and not re.search(
                r'(?:kernel|sched|CPU|Android|feishu|飞书|patch|commit|git\b)', summary, re.I):
            return True
        return False
    # iter1212: selfref_high_hits_override — hits>=3 时外部锚点大概率是偶然命中
    # 数据驱动（2026-05-08）："MCP direct 写入路径绕过 extractor gate（daemon 进程未热加载）"
    #   hits=3(gate,selfref,噪声) 但"进程"触发 ext_anchor 误放行。
    #   验证：全库 hits=3+ext_anchor 仅 2 条(ac=0 噪声)，无误杀风险。
    if hits >= 3:
        return True
    has_ext_anchor = re.search(
        r'(?:kernel|sched|CPU|Android|feishu|飞书|patch|线程|进程|调度|'
        r'binder|LKMM|scx|qos|migration|MTK|vendor|AOSP|'
        r'Proxy.Execution|uclamp|cpufreq|thermal|cgroup|'
        r'公众号|微信|curl|HTTP|API|gRPC)',
        summary, re.I
    )
    return not has_ext_anchor


def _is_metric_report_noise(summary: str, chunk_type: str) -> bool:
    """iter1118: pool_metric_gate_sync — 迭代器数值报告噪声检测（可复用函数）。
    返回 True 表示是纯指标变化/统计报告，应拒绝写入。
    根因（数据驱动，2026-05-08）：extractor_pool._write_chunks 路径缺少 metric_report_gate，
      "zero-access: 11.8% → 0%"(ac=0,decision) 逃逸写入——含 N%→M% 模式但无外部锚点。
      提取为独立函数供 extractor.py _write_chunk 和 extractor_pool.py 共用。
    """
    if chunk_type not in ("decision", "reasoning_chain", "causal_chain"):
        return False
    _has_metric = re.search(
        r'(?:\d+%?\s*[→➜→>]\s*\d+%?'
        r'|\d+/\d+\s*[=＝(（]'
        r'|残留\s*\d+%'
        r'|iter\d{3}.*(?:已|自愈|清理|修复)'
        r'|(?:占比|注入率|命中率|逃逸率)\s*[:：]?\s*\d+%'
        r'|(?:旧|新)公式.*\d+%'
        r'|\d+%\s*(?:降到|升到|降至|升至)'
        r'|(?:从|自)\s*\d+%\s*(?:降|升|变)'
        r'|\d+\s*次.*\(\d+%\)'
        r'|\d+\s*次.*\d+\s*次.*\d+%)',
        summary
    )
    if not _has_metric:
        return False
    _has_ext = re.search(
        r'(?:kernel|sched|CPU|Android|feishu|飞书|patch|线程|进程|调度|'
        r'binder|LKMM|scx|qos|migration|MTK|vendor|AOSP|'
        r'Proxy.Execution|uclamp|cpufreq|thermal|cgroup|'
        r'公众号|微信|curl|HTTP|API|gRPC)',
        summary, re.I
    )
    if not _has_ext:
        return True
    # 外部锚点+系统内部术语共存 → 仍拒绝
    if re.search(
        r'(?:chunk|注入|suppress|fallback|top.?k|触发|阈值|垄断|逃逸|空召回)',
        summary
    ):
        return True
    return False


def _is_quality_chunk(summary: str) -> bool:
    """
    写入前质量过滤——返回 False 则丢弃。
    拦截以下噪声：
    - ] [ - | 开头（截断/前缀污染/列表项/表格行）
    - 纯 markdown 符号
    - 过短（< 10字）
    - 以助词/连词开头（说明是句子中间的截断）
    - 元数据泄漏关键词
    - 占位符
    - v4 迭代17：markdown 表格行、纯指标/数据行
    - v7 迭代74：纯验证报告、纯性能数据、无主语截断句
    - v8 迭代79：纯状态快照、模糊方向声明（无具体技术锚点）
    """
    s = summary.strip()
    if len(s) < 10:
        return False
    # iter1162: short_contextless_gate — 超短无技术锚点碎片
    # 数据驱动（2026-05-08）：caf855dc "已有的失败，与本次改动无关"(13字) 无独立语义。
    #   <=15 字且不含技术名词/代码标识符/完整判断句的碎片不构成可检索知识。
    #   豁免：含否定判断（"不存在/没有/不能"）、技术概念（4+汉字+关键后缀）或代码标识。
    if len(s) <= 15 and not re.search(r'[A-Z_]{2,}|[a-z_]{3,}\(|不[存能可]|没有.{2,}|[\u4e00-\u9fff]{4,}(?:规则|约束|协议|工作流|验证|调用链)', s):
        return False
    # iter769: numbered_list_fragment — 拦截编号列表项碎片
    # 根因（数据驱动，2026-05-04）：同一事件（proxy 20MB limit 调试）被 3 个提取器
    #   各自逐行提取，产生 8 个碎片 chunk（占总库 17%）。每个碎片以 "1. xxx" 格式
    #   开头，缺乏独立语义上下文（编号暗示它属于更大列表，单条不可独立检索）。
    # 豁免：含决策动词的列表项保留（_extract_structured_decisions 已正确过滤）。
    if re.match(r'^\d+[.。]\s+', s):
        if not re.search(r'(?:选择|决定|推荐|结论|采用|方向|核心|必须|禁止|不[能可得])', s):
            return False
    # iter1444: slash_fragment_gate — 以 / 开头的截断碎片拦截
    # 数据驱动（2026-05-10）：2 条 ac=0 causal_chain 以 "/chunk/score/suppress" 开头，
    #   是从长文本中间截断出的碎片。/ 开头不是自然语言句首。
    # 豁免：文件路径（含扩展名）或 Linux 系统路径（/proc/sys/dev/etc）。
    if s.startswith('/') and not re.match(r'^/(?:[\w\-./]+\.\w{1,5}\b|(?:proc|sys|dev|etc|tmp|var|home|usr)/)', s):
        return False
    # iter753: 豁免 [topic] 格式（wiki import summary），只拦截裸 [ ] - | 开头的碎片
    if re.match(r'^[\[\]\-|]', s):
        # [word] 后跟中日韩/拉丁内容 = wiki topic tag，不是碎片
        if not re.match(r'^\[[^\[\]]{1,30}\]\s*\S', s):
            return False
    if re.match(r'^[-=*`#>]{2,}$', s):
        return False
    # iter753: 移除 '向' — "向 maintainer 报告" 是完整句（动词用法），非截断碎片
    # iter1036: 移除 '被'/'让' — "被现有...推荐"是被动句/"让 X 有机会"是使役句，非截断碎片
    if re.match(r'^[了的地得把从以在对和与或]', s):
        return False
    # iter755: 单字母开头截断碎片拦截
    # 数据驱动：2b704212 "k 时会提升 importance" — "look" 被截断只剩 "k"
    # 特征：单个拉丁小写字母 + 空格 + 中文/标点 = 句子中间截断
    if re.match(r'^[a-z]\s', s):
        return False
    # iter791+1415: 多字母截断碎片拦截
    # 原 iter791："eshold 注入..." — threshold 截断尾部+中文=碎片。
    # iter1415 修正：cgroup/memory/task_rq 等合法术语被 <40 字条件误杀。
    #   截断碎片首 word 非完整术语；合法术语在豁免列表中。
    _trunc_m = re.match(r'^([a-z][a-z_]*)\s+[\u4e00-\u9fff]', s)
    if len(s) < 40 and _trunc_m:
        _first_w = _trunc_m.group(1)
        if not re.match(r'(?:memory|kernel|sched|task|scx|cpu|bpf|cgroup|mutex|futex|rcu|pid|git|mm)', _first_w):
            return False
    # ── iter B12：JSON 键值对碎片过滤 ──────────────────────────────────
    # 以双引号开头 = JSON 字符串值（"recommended_action": "..."、"if_wrong": "..."）
    # 这些是从包含 JSON 格式输出的 assistant 回复中误提取的片段，无法被自然语言检索命中
    # OS 类比：TCP payload 的 framing check — 裸 JSON fragment 不是有效的 knowledge chunk
    if s.startswith('"') and re.match(r'^"[\w_]+":', s):  # JSON key: "key": ...
        return False
    # "xxx" → "yyy" 格式（JSON value 片段拼接）
    if re.match(r'^"[^"]{2,30}"\s*→\s*"', s):
        return False
    # 含 JSON 键值对特征：多个 "key": "value" 组合
    if len(re.findall(r'"[\w_]+"\s*:', s)) >= 2:
        return False
    # 表格行：含 2+ 个 | 分隔符（iter656: 降低阈值，2 个 pipe 的行也是表格碎片）
    if s.count('|') >= 2:
        return False
    # 纯数据/指标行：全是数字、符号、单位，没有中文动词
    if not re.search(r'[\u4e00-\u9fff]{2,}', s) and re.match(r'^[\d\s.%ms/=<>×+\-,()]+$', s):
        return False
    noise_kw = ["← project 字段", "(importance=", "Stop extractor", "路径被重复写入",
                "【相关历史", "hookSpecificOutput", "additionalContext",
                "chunk_count", "recall_traces",
                # iter649: 迭代器自身度量/诊断记录 — 这些是 memory-os 迭代器
                # 写入的内部诊断信息（suppress 效果、注入统计、PA 通过率），
                # 对用户零价值且占用 FTS 和 Top-K 槽位
                "注入垄断", "injection_timeline",
                "零访问率", "e2e 测试通过", "production assertions",
                # iter673: 迭代器工作汇报模式 — "+N/-M 行"改动量报告
                "改动 +", "改动 -",
                # iter656: 对话诊断/审计输出碎片 — AI 分析 AIOS 时产出的数据行
                "边际收益在递减", "存量清理：swap_out", "Active chunks",
                # iter696: memory-os 迭代器自身实现细节 — retriever/daemon 内部机制
                # 数据驱动：8 条零访问 chunk 含 retriever.py/suppress/threshold 等自引用
                "retriever.py", "retriever_daemon.py", "空注入率",
                "burst suppress", "suppress_fallback", "zero_relevance_gate",
                # iter699: extractor_noise_gate_v2 — 漏网的迭代器诊断指标
                # 数据驱动：id=61cd3637 "空召回率 72.5%" 含 trace/candidates/全灭，
                #   通过了 iter696 的过滤（只拦 "空注入率" 未拦 "空召回率"）
                "空召回率", "candidates_rescue", "iter69", "iter70",
                "hard_deadline", "score_chunk", "top_k_data",
                # iter701: content_echo_gate — 拦截 content=summary 的残留噪声
                # 数据驱动：6d4f68bb "降级注入 1 条最佳结果" content=summary，
                #   描述 memory-os 内部降级策略，对用户零价值（ac=0）。
                "降级注入", "降级阈值", "空返回", "注入策略",
                "score_empty_fallback", "suppress_pierce",
                # iter752: 迭代器度量/内部机制通用拦截
                # 数据驱动：7 个 ac=0 噪声 chunk 含 suppress/全库锁死/误标率/注入率/轮迭代
                "全库锁死", "饥饿螺旋", "误标率", "注入率",
                "轮迭代", "连续空召回", "allzero_fallback",
                # iter755: memory-os 内部参数/路径描述
                # 数据驱动：bdbcdc29 "daemon 是主检索路径"、2b704212 "importance（0.44→0.75）"
                "主检索路径", "检索路径没有", "imp 0.",
                # iter766: proxy/guard 实现细节 — 对用户无检索价值的参数描述
                # 数据驱动：8c78b2f3 "proxy 已加 client_max_size=0"(ac=0)、
                #   a24c657a "filesize_guard：只拦截单文件 Read"(ac=0) — 代码里已体现
                "client_max_size", "filesize_guard", "body size 日志",
                "下次再触发",
                # iter795: self_arch_noise — memory-os 自身架构/目标/路径描述
                # 数据驱动：e76579b5 "空召回：27%→预期~0%"(ac=1)、42d826ac "AIOS架构"(ac=1)、
                #   2876c5bb "项目目录结构"(ac=1) — 系统内部细节，用户不需要
                "空召回：", "Memory-OS 架构", "memory-os 架构",
                "项目目录结构", "主工作区", "子项目",
                # iter817: iterator_fix_noise — 迭代器 fix/验证/阈值调整记录
                # 数据驱动：6 个噪声 chunk 含 "修复: 增加 _cut" / "确认：7d suppress 阈值"
                # / "验证：PA" 模式，描述迭代器自身的代码修改，对用户无检索价值
                "suppress 阈值", "_cut758", "_cut6h", "suppress_final_gate",
                # iter824: iterator_tuning_noise — 迭代器调参/度量快照记录
                # 数据驱动：13 个 ac=1 噪声 chunk 含 top_k=1/af_ratio/adaptive_floor/
                #   cands→top_k/min_score_threshold 等内部参数调整描述
                "af_ratio", "adaptive_floor", "cands→top_k", "top_k=1",
                "min_score_threshold", "_db_chunk_count",
                # iter828: iterator_mechanism_noise — 迭代器内部机制/度量/自评
                # 数据驱动：9 条 ac=1 噪声含 pair_inject/single-chunk/suppress 分母/
                #   FTS/BM25 权重提升/闭包捕获/检索稀疏性 — 系统自引用无用户价值
                "pair_inject", "single-chunk", "suppress 分母",
                # iter1065: lite_suppress_tolerance_noise — 逃逸的阈值容忍度/路径描述
                # 数据驱动（2026-05-07）：2 条 ac=0 噪声 "容忍度 +67%"/"LITE 路径 7d=3 即"
                #   描述 suppress 参数对齐的效果量化，对用户零检索价值。
                "容忍度", "LITE 路径", "PSI downgrade",
                "检索稀疏性", "闭包捕获", "闭包快照", "importance_pair",
                "注入为单条", "组合上下文", "预期量化",
                # iter833: iterator_metric_noise_v3 — 漏网的迭代器自评/度量快照
                # 数据驱动：7 个 ac=1 噪声含 "有价值知识占比"/"迭代器自己写入"/
                #   "access_bonus"/"access_count=" — 系统内部度量，对用户零价值
                "有价值知识占比", "迭代器自己写入", "access_bonus",
                "access_count=", "chunk 库中", "单条注入率",
                # iter834: metric_snapshot_noise — 纯度量快照逃逸
                # 数据驱动：2 条 ac=1 噪声 "zero_access_rate：0%"/"噪声占比：17%→0%"
                #   特征：内部度量指标名 + 百分比值，无决策上下文
                "zero_access_rate", "噪声占比", "空召回率", "注入垄断",
                # iter839: test_result_noise — 测试结果快照和迭代器修复行摘要
                # 数据驱动：4 条 ac=0 噪声 "14/14 测试通过"/"修复：extractor.py +5 行"
                "测试通过", "tests passed",
                # iter841: iterator_ops_log_noise — 迭代器操作日志/SQL片段逃逸
                # 数据驱动：7 条 ac=1 噪声含 "数据改动：删除"/"WHERE injected="
                #   — 迭代器操作记录和内部 SQL 代码片段，对用户零价值
                "数据改动", "WHERE injected", "WHERE chunk_ids",
                # iter847: inventory_snapshot_noise — 库存/chunk数量快照逃逸
                # 数据驱动：2 条 ac=1 噪声 "库存：50 → 42 chunks"/"chunk 总数"
                #   特征：memory-os 自身库存描述，纯状态快照无决策价值
                "库存：", "chunk 总数", "chunks（",
                # iter855: iterator_impl_detail_noise — 迭代器修复/验证/阈值变更记录逃逸
                # 数据驱动（2026-05-05）：7 条 ac=1 噪声在 iter853 gc 后被重新写入，
                #   包含 NOISE_FLOOR/noise_chunk_rate/constraint 豁免逻辑 等内部实现描述
                "NOISE_FLOOR", "noise_chunk", "chunk_rate",
                "豁免逻辑", "_is_global", "constraint 无条件豁免",
                "修复：移除", "修复：6 处",
                # iter877: iterator_self_eval_noise — 迭代器自评效果预测/度量预期
                # 数据驱动（2026-05-05）：2 条 ac=0/1 噪声 "效果：7d=5-6 的垄断 chunk 评分降至..."
                #   "预期效果：7d=4 的 chunk 评分降至 56%..." — 自评预期，对用户零检索价值
                "零注入 chunk", "注入机会", "评分降至", "知识覆盖多样性",
                "垄断 chunk",
                # iter890: iterator_param_tuning_noise — 迭代器参数调优/内部机制度量
                "衰减到", "触发率", "垄断率", "注入位",
                "diversity_pair", "fallback_rotation", "closure_fallback",
                "pair_dedup",
                # iter906: suppress_tuning_noise — 漏网的 suppress 调参/效果记录
                # 数据驱动（2026-05-05）：6 条 ac=1 噪声逃逸，含 suppress 调参记录
                #   "修复：阈值 2→4"/"tiny_db (<50"/"7d 内 31% 完整检索返回空结果"
                "7d>=", "7d >=", "tiny_db", "完整检索返回空", "全被 suppress",
                # iter912: expected_effect_noise — 迭代器"预期效果"预测逃逸
                # 数据驱动（2026-05-06）：3 条 ac=1 噪声 "预期效果：额外 suppress 14 次/7d"
                #   / "预期效果：约 15% 极低分注入被拦截" — 迭代器自评预测，用户零价值。
                #   逃逸原因：不含 suppress_fallback/注入率/tiny_db 等精确关键词。
                "预期效果", "预期量化效果", "量化改善",
                # iter929: quantitative_effect_noise — 迭代器量化效果/候选池分析逃逸
                # 数据驱动（2026-05-06）：1 条 ac=1 噪声 "量化效果：候选池从含 14 个高频 chunk"
                #   逃逸原因："量化效果" ≠ "预期量化效果"；"候选池" 是内部算法概念。
                "量化效果", "候选池", "高频 chunk",
                # iter935: quantitative_expectation_noise — "量化预期" 词序逃逸
                # 数据驱动（2026-05-06）：2 条 ac=0 噪声 "量化预期：空召回 16→0 条/7d"
                #   逃逸原因："预期量化效果"已拦截但 "量化预期" 词序不同漏网。
                "量化预期",
                # iter942: impl_fix_detail_noise — 迭代器修复细节/代码片段逃逸
                # 数据驱动（2026-05-06）：5 条 ac=0 噪声逃逸：
                #   "修复（4 处，<10 行改动）"/"条件：positive[0][0] >= 0.15"
                #   "imp_pair_top1_gate"/"score<0.10 占比从 14.8%"
                #   根因："修复：" 前缀只拦截冒号形式，括号形式逃逸；代码索引 [0][0] 无覆盖。
                "修复（", "score<", "占比从",
                # iter948: gc_5_residual_noise — 5 条 ac=0 噪声逃逸根因补漏
                # 数据驱动（2026-05-06）：
                #   "top5 chunk 垄断度" — "垄断 chunk" 拦截不到 "垄断度"
                #   "/.spec-workflow/approvals/" — 纯文件路径 tool_insight 无知识价值
                #   "因：昨天创建这条待办时只打了 travel" — todo 标签调试记录
                "垄断度", ".spec-workflow/", "status-pending 标签",
                # iter1012: ceiling_active_noise — 迭代器度量快照逃逸
                # 数据驱动（2026-05-07）："FTS5 噪声密度降 12%（94→83 active chunks）"
                #   逃逸原因："active chunks" 是 memory-os 内部度量关键词。
                "active chunks", "pair 路径", "噪声密度",
                # iter1098: iterator_metric_en_gate — 英文形式的迭代器度量指标逃逸
                # 数据驱动（2026-05-07）：07e299e5 "zero_access: 20% → 0%" ac=0 逃逸，
                #   因 "零访问率" 只匹配中文形式。补充英文变体。
                "zero_access", "zero-access",
                # iter1018: daemon_expectation_noise — 迭代器效果预测/内部逻辑缺失描述逃逸
                # 数据驱动（2026-05-07）：2 条 ac=0 噪声：
                #   "daemon 路径高 ac chunk 重复注入减少 ~30%" — 效果预测
                #   "缺少 local_saturated_suppress" — 内部逻辑缺失描述
                "重复注入减少", "saturated_suppress", "daemon 路径高",
                # iter1100: iterator_metric_residual_gate — 漏网的迭代器度量快照
                # 数据驱动（2026-05-07）：5 条 ac=0 噪声：
                #   "活跃 chunk: 79→63" / "session 内重复注入极低" / "跨项目注入 8%"
                #   逃逸原因："活跃 chunk"(中文) ≠ "active chunks"(英文)；"重复注入"无完整匹配。
                "活跃 chunk", "重复注入极", "跨项目注入",
                # iter1168: ac_threshold_noise — "ac>=N" 格式是内部 access_count 阈值描述
                # 数据驱动（2026-05-08）：486dfa84 "跨项目/global ac>=7 chunk"(ac=0)
                #   excluded_path 描述内部 suppress 规则，不含其他 noise_kw 而逃逸。
                #   "ac>=N" 只出现在 memory-os 内部（用户对话不会用此格式）。
                "ac>=", "ac=0",
                # iter1257: chunk_structure_diag_noise — chunk 数据结构诊断逃逸
                # 数据驱动（2026-05-09）：ef7ff2e7 "54% chunk 的 content 等于 summary，FTS5 检索面窄"
                #   combo hits=2(chunk+FTS) < 阈值3 逃逸。描述 chunk 字段关系是纯迭代器诊断。
                "content 等于 summary", "检索面窄",
                # iter1263: iterator_deploy_timing_noise — gate 部署时序/PA 报告逃逸
                # 数据驱动（2026-05-09）：3 条 ac=0 噪声逃逸：
                #   "量化：zero_access 3→1/55 (1.8%)，PA 10/10 HEALTHY" — 迭代器 PA 报告
                #   "chunk 在同一 session 的 gate 部署前写入（时序问题）" — 内部时序描述
                #   逃逸原因："量化：" prefix gate 只匹配 "量化[：:]" 紧跟特定后缀，
                #   "gate 部署" 不在 noise_kw 列表中。
                "PA 10/10", "gate 部署", "HEALTHY",
                # iter1348: iterator_pa_report_noise — 迭代器 PA 报告通用拦截
                # 数据驱动（2026-05-10）：e28920cd "量化：检索能力 0%→100%，噪声率 8%→4%，PA 14/14 pass"
                #   逃逸原因："PA 10/10" 只精确匹配 10/10 不拦 14/14；"量化：" prefix 未覆盖。
                # 修复：用 "PA " + 数字 pattern 覆盖所有 PA 报告；"rowid NOT IN" 拦截 SQL 片段。
                "PA 14/14", "PA 12/12", "PA 13/13", "PA 15/15", "PA 16/16",
                "rowid NOT IN",
                # iter1348: 通用 "量化：" + 度量指标组合 — 迭代器自评快照
                "检索能力", "噪声率",
                # iter1355: selfref_gate — 迭代器讨论自身 gate 机制的自引用
                "noise_kw", "知识密度", "tests pass",
                # iter1364: quantitative_expectation_gate — 迭代器"量化预期"自评噪声
                # 数据驱动（2026-05-10）：306890f5 "量化预期：7d 内 global constraint..."
                #   ac=0，纯迭代器工作日志。"量化预期" 不在 noise_kw 且 PA 在 content 非 summary。
                "量化预期", "无测试回归",
                # iter1374: iterator_selfdiag_noise — 迭代器自诊断结论/量化快照逃逸
                # 数据驱动（2026-05-10）：97e5ea9a "量化：zero_access 4/37→3/37"(ac=0)
                #   0b39e8e4 "关键诊断结论：痛点描述已过时"(ac=0) — 迭代器自评记录。
                "诊断结论", "痛点描述", "zero_access",
                # iter1389: iterator_change_log_noise — "改动：" 前缀是迭代器修改记录
                # 数据驱动（2026-05-10）：ee83725a "改动：extractor.py 1 行 < 80 → <= 80"(ac=0)
                #   逃逸原因："改动 +"只匹配加号形式，"改动："冒号形式漏网。
                "改动：", "extractor.py",
                # iter1410: iterator_result_report_noise — "Result:"量化报告 + orphan 诊断逃逸
                "orphaned references", "orphaned entries"]
    if any(kw in s for kw in noise_kw):
        return False
    # iter1348: pa_regex_gate — 通用 PA 报告正则拦截（"PA N/N" 任意数字）
    import re as _re_ng
    if _re_ng.search(r'PA \d+/\d+', s):
        return False
    # iter1354: metric_transition_gate — 迭代器统计变化摘要拦截
    # 数据驱动（2026-05-10）：3 条 ac=0 噪声 "知识密度: 73%→100%"/"碎片占比: 27%→0%"/
    #   "活跃 chunk: 51→37" 逃逸所有 noise_kw（关键词组合不在列表中）。
    #   共性模式：短中文标签 + 冒号 + 数字 → 数字（纯状态变化记录，无决策上下文）。
    if _re_ng.match(r'^[一-鿿\w\s]{1,15}[:：]\s*\d+[%\w]*\s*(?:→|->)\s*\d+[%\w]*', s):
        return False
    # iter1374: quantitative_prefix_gate — "量化：" 前缀通用拦截
    # 数据驱动（2026-05-10）：97e5ea9a "量化：zero_access 4/37 → 3/37 (8.1%)"(ac=0)
    #   逃逸 metric_transition_gate（冒号后非数字开头）。"量化：" 前缀是迭代器度量快照标志。
    if _re_ng.match(r'^量化[：:]', s):
        return False
    # iter1026: iterator_combo_gate — memory-os 运行时术语组合检测
    # 数据驱动（2026-05-07）：9 个 ac=0 噪声逃逸所有单关键词 gate，根因是含外部领域词
    #   （如 "feishu CLI"）作为示例时豁免 metric gate。但这些 summary 同时含 2+
    #   memory-os 运行时概念（"次注入"/"chunk"/"ac="/"suppress"/"7d"/"per-project"/"候选"）。
    #   合法用户知识至多偶尔含 1 个（如"chunk"出现在非 memory-os 语境中）。
    # 修复：检测 ≥3 个运行时术语命中 → 拒绝（无外部领域豁免）。
    # iter1069: combo_gate_widen — 补充遗漏的 NLP/tokenizer/度量术语
    # 数据驱动（2026-05-07）：3 条 ac=0 噪声逃逸 combo_gate：
    #   "方案：中文 bigram + 英文 word tokenize，同 batch 内 overlap >60% 跳过"（0 hits）
    #   "量化预期：同事件碎片从 ~10 条降至 ~5 条（-50%）"（0 hits）
    #   根因：bigram/tokenize/overlap/碎片/traces 等 memory-os 内部 NLP 处理术语不在列表中。
    # 修复：扩展术语列表 + 添加"量化预期"模式拦截（无用户知识以此开头）。
    _mos_terms = sum(1 for _t in (
        '次注入', '注入中', 'chunk', 'suppress', 'per-project',
        '候选池', '内化', '阈值', 'ac=', 'ac<', 'ac>',
        '7d ', '24h ', '注入位', 'global chunk', 'supplement',
        '全路径', 'FTS', 'final_gate', '空召回',
        # iter1069: 遗漏术语补充
        'bigram', 'tokenize', 'overlap', 'traces', '碎片',
        'score ', 'top_k', 'recall', 'batch 内',
        # iter1114: cooldown_selfref_gate — 迭代器 cooldown/selfref 概念逃逸
        # 数据驱动（2026-05-08）：4 条 ac=0 噪声逃逸 combo_gate：
        #   "ac=4-6 non-global cooldown 仍用 48h"（hits=1, 缺 cooldown/FULL 路径）
        #   "方案：在 retriever 候选评分前增加运行时 selfref 检测"（hits=0）
        'cooldown', 'selfref', 'hard_deadline', 'FULL 路径',
        'non-global', 'retriever', 'daemon',
        # iter1135: combo_gate_internal_fn — 逃逸的迭代器内部函数/变量名
        # 数据驱动（2026-05-08）：7 条 ac=0 噪声逃逸 combo_gate，含 diversity_probe/
        #   skipped_same_hash/7d_exclude/fallback escalate/cands= 等内部实现标识。
        'diversity_probe', 'skipped_same_hash', '7d_exclude',
        'fallback escalate', 'cands=', '候选枯竭', '注入率',
        # iter1137: retriever_fn_name_gate — retriever 内部函数名逃逸 combo gate
        # 数据驱动（2026-05-08）：2 条 ac=0 噪声含 diversity_pair_from_db/fallback_pair/
        #   _pre_suppress_top_k 等内部函数名，combo hits=2 未达阈值 3。
        'diversity_pair', 'fallback_pair', '_pre_suppress', 'positive=0',
        # iter1153: injection_quota_noise — 注入配额/slot 规划描述逃逸
        # 数据驱动（2026-05-08）：95774dc1 "ac=5-6 chunk 每周最多注入 3 次...释放 ~8 slot/周"
        #   逃逸 combo_gate（hits=2: chunk+次注入），因 "slot/周" 不在术语表。
        'slot/', '低频知识', '最多注入',
        # iter1159: combo_suppress_jitter — 逃逸的 jitter/逃逸/概率 组合
        # 数据驱动（2026-05-08）：3f20e465 "高 ac chunk ~30% 概率获得短 jitter → cooldown 缩短 → 逃逸 suppress"
        #   hits=1（仅 cooldown），因 jitter/逃逸 不在 combo terms。
        #   注意：'suppress' 已在 line 1464 存在，不重复添加。
        # 修复：加入 jitter/逃逸/概率 作为 combo term，与 cooldown/suppress 共现即拦截。
        'jitter', '逃逸', '概率',
        # iter1162: combo_ceiling_escape — 截断碎片逃逸（ceiling/最后防线/escape tier）
        # 数据驱动（2026-05-08）：bdee49f7 "levance>=0.5 时去除 ceiling" hits=1(ac<)，
        #   因 ceiling/最后防线/escape tier 不在术语表。这些是 retriever 内部兜底机制名称。
        'ceiling', '最后防线', 'escape tier', '兜底',
        # iter1164: combo_gate_diag_report — 系统状态诊断报告术语逃逸
        # 数据驱动（2026-05-08）：3 条 ac=0 噪声逃逸 combo_gate：
        #   "系统当前状态健康——垄断(top-5=16%)、空召回(0%)、零访问(0%)均已修复"(hits=1)
        #   "82→79 chunks (-3.7%)，释放 3 个 top-k 候选位给新知识"(hits=1)
        #   "skipped_same_hash 20 条是 iter805 之前的历史遗留"(hits=1)
        #   根因：这些是迭代器的系统健康诊断/度量变化报告，含百分比/chunk 数量变化等。
        # 修复：加入 垄断/零访问/top-k/候选位/历史遗留 作为 combo term。
        '垄断', '零访问', 'top-k', '候选位', '历史遗留',
        # iter1263: gate 部署/PA 报告术语
        'gate 部署', 'PA ', 'HEALTHY',
    ) if _t in s)
    # iter1114: regex 补充 — iter+3~4位数字是迭代器自引用标识
    # iter1164: 扩展 \d{4}→\d{3,4} 覆盖 iter805 等 3 位迭代号逃逸
    if re.search(r'iter\d{3,4}', s):
        _mos_terms += 2
    if _mos_terms >= 3:
        return False
    # iter1162: truncated_combo_gate — 截断碎片 + combo 术语共现
    # 数据驱动（2026-05-08）：bdee49f7 "levance>=0.5 时去除 ceiling"(hits=2)
    #   以小写英文开头（截断标志） + 含 combo term = 迭代器内部描述碎片。
    #   合法知识以小写开头时不含 memory-os 术语（如 "memory 引用前必须验证"）。
    if _mos_terms >= 2 and re.match(r'^[a-z]', s) and not re.match(r'^(?:memory|kernel|sched|task|scx|cpu|bpf)', s):
        return False
    # iter1069: quantitative_forecast_gate — "量化预期"开头 = 迭代器效果预测
    # 数据驱动：用户真实知识从不以"量化预期"开头，这是迭代器自评模板。
    if s.startswith('量化预期'):
        return False
    # iter1410: result_prefix_gate — "Result:" + chunks/zero_access 是迭代器量化输出
    if re.match(r'^Result\s*[:：]', s) and re.search(r'(?:chunk|zero.access|PA\s)', s):
        return False
    # iter1144: iterator_prefix_gate — 迭代器自评/修复/附带发现模板前缀拦截
    # 数据驱动（2026-05-08）：6 条 ac=0 噪声逃逸，前缀分别为：
    #   "量化："(非"量化预期")、"附带发现："、"修复：阈值按 ac 分级"。
    #   这些是迭代器固定模板输出，用户真实知识不以此开头。
    # iter1369: expand "附带发现" → "附带" — "附带：清理 2 条零访问 thin chunk" 也是迭代器自操作日志
    if re.match(r'^(?:量化[：:]|附带[：:]|附带发现[：:]|修复[：:](?:阈值|在|补充|同步|最后))', s):
        return False
    # iter1162: root_cause_internal_gate — "根因：" + retriever 内部概念
    # 数据驱动（2026-05-08）：df756f99 "根因：suppress/cooldown 过严导致 relevance_fallback"
    #   combo hits=3 应被拦截但在 gate 更新前已写入。现 combo 已覆盖，此处加前缀加速拦截。
    if re.match(r'^根因[：:]', s) and _mos_terms >= 2:
        return False
    # iter944: code_expr_gate — 代码条件表达式/数组索引碎片拦截
    # 数据驱动（2026-05-06）：1 条 ac=0 噪声 "条件：positive[0][0] >= 0.15 — top1 < 0.15 时不配对"
    #   逃逸所有 gate。特征：含方括号数组索引 [N] + 比较运算符，是代码片段非知识。
    # 修复：检测 [digit] 数组索引 + 比较运算符共存 → 拒绝。
    #   豁免：含 kernel/sched 等外部领域关键词的合法代码引用。
    if re.search(r'\[\d+\]', s) and re.search(r'[><=!]{1,2}\s*\d', s):
        if not re.search(r'(?:kernel|sched|CPU|task_|rq_|ctx\.|binder|scx_)', s, re.I):
            return False
    # iter853: internal_var_gate — 含 memory-os 内部变量名/常量名的 summary 拦截
    # 数据驱动（2026-05-05）：2 条截断碎片（"LLBACK_NOISE_FLOOR 的 tiny_db 边界"、
    #   "lobal && importance>=0.9 的 constraint 无条件豁免 _rel == 0"）逃逸所有关键词匹配。
    # 根因：截断导致 FALLBACK→LLBACK、global→lobal 绕过关键词；但 summary 仍含
    #   memory-os 内部标识符（_NOISE_FLOOR、tiny_db、_rel）。
    # 修复：检测 Python 私有变量 (_xxx)、全大写常量 (XXX_YYY)、snake_case 标识符 (xxx_yyy)
    #   出现 ≥2 个 → 拒绝。安全性：用户真实知识至多含 1 个（如 task_rq_lock）。
    _internal_var_hits = len(re.findall(r'(?:_[a-z]\w+|[A-Z]{2,}_[A-Z]{2,}|\b[a-z]+_[a-z]+\b)', s))
    if _internal_var_hits >= 2:
        # iter890: wiki_topic_exempt — [topic] 前缀或含 () 的 kernel 函数引用是合法知识
        # iter1138: kernel_macro_exempt — kernel 大写宏/API 名不是 memory-os 内部变量
        # 数据驱动（2026-05-08）：4 条 ac>0 kernel 知识被误杀：
        #   d2028e2a "SCX_TASK_OFF_TASKS 已合入 for-next"(ac=7)、
        #   875b11e6 "list_empty 检查和 SCX_TASK_OFF_TASKS"(ac=4)。
        #   根因：SCX_TASK_OFF_TASKS 匹配 [A-Z]{2,}_[A-Z]{2,}，list_empty 匹配 snake_case。
        #   这些是 kernel API 名称，不是 memory-os 内部变量。
        # 修复：含 kernel 大写宏前缀（SCX_/TASK_/SCHED_/CONFIG_/RQ_/CPU_）的 summary 豁免。
        if not re.search(r'(?:选择|决定|采用|因为|根因|必须|禁止)', s) \
           and not re.match(r'^\[[^\[\]]{1,30}\]', s) \
           and '()' not in s \
           and not re.search(r'\b(?:SCX|TASK|SCHED|CONFIG|RQ|CPU|BPF|NUMA|IRQ)_[A-Z]', s):
            return False
    # ── iter974: contextless_assertion_gate — 拦截对话碎片短句 ──
    # 数据驱动（2026-05-06）：7 个 chunk 以指示/连接词开头 + <60字 + 无技术锚点，
    #   脱离对话上下文不可独立理解（如 "所以 sched store 也已经 globally complete"）。
    #   这些碎片被 FTS 宽泛匹配后高频注入，挤占真正有价值的知识槽位。
    # 修复：指示/连接词开头 + 短于 60 字 + 无文件路径/量化/代码引用 → 拒绝。
    _CONTEXTLESS_STARTS = re.compile(
        r'^(?:所以|一样的|也就是|这样|那么|这个|那个|同样|确实|其实|用的|人会|'
        r'就是说|说白了|总之就是|换句话说|简单来说|这是|你已有|你已经有)\s*')
    # iter1301: widen_contextless_gate — 60→150 字，覆盖中长对话碎片
    # 数据驱动（2026-05-09）：6 个逃逸碎片 72-130 字以连接词开头+无技术锚点
    if _CONTEXTLESS_STARTS.match(s) and len(s) < 150:
        if not re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml|sh|md)\b', s) \
           and not re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个|行|倍|x)', s) \
           and not re.search(r'`[^`]+`', s):
            return False
    placeholders = {"方案 X 是最优解", "extractor 升级", "KnowledgeRouter"}
    if s in placeholders:
        return False
    # iter1055: ephemeral_market_sync — 同步 _is_quality_decision X6 到通用 gate
    # 根因（数据驱动，2026-05-07）：市场短时效数据（"市场情绪过滤通过了(5日+3.01%)"）
    #   通过 causal_chain 路径绕过 _is_quality_decision 的 X6 gate 写入 DB。
    #   这些日级数据快照次日过期，对未来检索零价值。
    if re.search(r'(?:日[涨跌]幅|[涨跌]幅[：:]\s*[+-]?\d|连板|市场情绪.*[过通]|'
                 r'扫描时间[点是]|下一个扫描|收盘后|开盘前|今[日天]行情|今[日天]无信号)', s):
        if not re.search(r'(?:策略调整|规则变更|规则[：:]|参数.*(?:从|改为)|选择|决定|因为|必须|禁止)', s):
            return False
    # iter1055: trailing_colon_fragment — 以冒号结尾的不完整句是列表/段落前奏
    # 根因（数据驱动，2026-05-07）："背景文档的 47% 提效估算 vs 多维表格推算的 20–30%，差距来自："
    #   以冒号结尾暗示后续有展开内容，单独存储脱离上下文不可检索。
    if re.search(r'[：:]\s*$', s) and len(s) < 100:
        if not re.search(r'(?:必须|禁止|不[能可得]|规则|约束|要求)', s):
            return False
    # ── 迭代74：Promotion Filter — 拦截不可复用的过程性记录 ──
    # OS 类比：Generational GC promotion filter — young gen 短命对象不提升到 old gen
    # V1 纯验证/测试报告（"N/N 通过"、"回归全绿"、"ALL PASSED"）
    if re.match(r'^\d+/\d+\s*(?:测试)?(?:通过|passed|全绿|green|新测试)', s, re.I):
        return False
    if re.match(r'^(?:验证|回归|测试|ALL\s*PASSED)[：:]\s*\d+', s, re.I):
        return False
    # V2 纯性能/延迟数据（性能/延迟前缀 + 无决策动词 = 纯报告）
    if re.match(r'^(?:性能|延迟|耗时|avg|p\d+|latency)[：:]', s, re.I):
        # 含决策动词的保留（如"性能：采用 X 后提升 3x"）
        if not re.search(r'(?:选择|决定|采用|推荐|因为|替代|改用)', s):
            return False
    if re.match(r'^[\w_]+\s*(?:延迟|耗时)[：:]\s*[\d.]+\s*(?:ms|s)', s):
        return False
    # iter839: fix_line_gate — 迭代器修复行摘要 "修复：file.py +N 行，..."
    if re.match(r'^修复[：:]\s*\S+\.\w+\s*\+\d+\s*行', s):
        return False
    # V3 HTML/XML 标签泄漏
    if s.startswith('<') and re.match(r'^<[a-z-]+', s):
        return False
    # ── 迭代79：Seed Pruning — 拦截不可复用的状态快照和模糊声明 ──
    # OS 类比：do_exit() → exit_mmap() — 进程退出时释放不再需要的页面
    # V4 纯状态快照（"数据规模：N chunks..."、"当前状态：..."）
    # 这些是某时刻的 point-in-time 数据，随时间失效，不是可复用决策
    if re.match(r'^(?:数据规模|当前状态|系统状态|chunk\s*数|统计|现状)[：:]', s, re.I):
        if not re.search(r'(?:选择|决定|采用|推荐|因为|替代|改用|应该)', s):
            return False
    # V5 模糊方向声明（"X — Y" 格式，且无具体技术锚点）
    # 如 "精简重构 — Less is More" — 是战略口号，不是可执行决策
    # 具体技术锚点：文件路径、函数名、数字度量、具体工具/库名
    # iter753: 豁免 [topic] 格式 wiki summary（"[schedqos] X — Y > Z"）
    if re.search(r'^.{3,20}\s*[—–]\s*.{3,}$', s) and not re.match(r'^\[', s):
        has_anchor = bool(
            re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml)\b', s)  # 文件路径
            or re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个)', s)      # 数字度量
            or re.search(r'`[^`]+`', s)                                      # 代码标识符
            or re.search(r'(?:→|->)\s*\d', s)                               # 量化变化
        )
        if not has_anchor:
            return False
    # ── iter631: iterator_quantitative_selfeval — 迭代器量化自评拦截 ──
    # 根因：迭代 agent 写入自身度量（"X→Y", "PA 10/10", "chunks N→M"），100% 零访问。
    if '→' in s and re.search(r'(?:PA\s*\d+/\d+|chunks?\s*\d+|zero_access|test.*pass)', s, re.I):
        return False
    # iter1425: quantify_prefix_gate_widen — 对齐 _is_selfref_noise 字符集
    # 根因（数据驱动，2026-05-10）：[：:改] 遗漏 量化预期/量化影响/量化结果/量化效果 格式
    if re.match(r'^量化[预改效结影响：:]', s):
        return False
    # ── iter795: goal_declaration_noise — 纯指标目标声明拦截 ──
    # 根因（数据驱动）：e76579b5 "空召回：27% → 预期 ~0%" (ac=1) — 不是决策是目标宣言
    # 特征："X：N% → 预期/目标 ~M%"，只声明期望值无执行方案
    if '→' in s and re.search(r'(?:预期|目标|期望|理想)[：:\s]*~?\d', s):
        if not re.search(r'(?:选择|决定|采用|因为|方案|通过)', s):
            return False
    # ── iter636: iterator_diagnostic_noise — 迭代器诊断结论拦截 ──
    # 根因（数据驱动）：13bed2d8 "问题：top2 垄断 chunk（feishu CLI ac=46...）占总注入的 62.8%"
    #   通过了 quality gate（含数字锚点），但这是迭代器自身对 memory-os 内部状态的诊断，
    #   对用户无检索价值（ac=0）。特征：含 memory-os 内部指标术语 + 无决策动词。
    _ITERATOR_DIAG_KW = re.compile(
        r'(?:垄断\s*chunk|注入的?\s*\d|access.count|recall.count|zero.access|零访问|'
        r'top_k|anti.monopoly|bandwidth.throttle|hard.cap|suppress|'
        # iter661: 补充逃逸模式 — daemon 指标行/幽灵 chunk/项目孤岛化
        r'injected=\d|candidates=\d|幽灵\s*chunk|幽灵条目|项目孤岛化|'
        # iter662: 中文形式 memory-os 指标术语 — 迭代器用中文描述内部状态
        r'Timeline\s*条目|知识完全不可见|存量噪声|迭代器.*噪声|noise.gate|'
        # iter679: retriever 内部逻辑术语 — 迭代器描述自身算法修改
        r'FTS5\s*scor|min_thresh|positive=\[\]|constraint_fallback|'
        r'空率|_score_chunk|fallback.*inject|suppress.*全[灭空]|'
        # iter1041: internal_tuning_noise — 迭代器调参/内部通道术语逃逸
        # 根因（数据驱动，2026-05-07）：6 个 ac=0 中 2 条逃逸：
        #   "inmem fallback 窗口 2s→30s" / "daemon 路径 trace 只记录 {id:...}"
        #   fallback 单独不匹配 fallback.*inject，daemon/trace/inmem 均不在词表。
        r'inmem\s*(?:fallback|suppress)|daemon\s*(?:路径|侧|inject)|'
        r'recall.trace|top_k_json|writeback\s*(?:竞争|排队|延迟)|'
        # iter930: meta_self_ref — 知识库自述/系统内部组件名逃逸
        # 根因：b2b446a1 "量化改善：知识库纯度 100%...extractor 阶段被拦截" 逃逸所有 gate
        r'知识库\s*(?:纯度|质量|健康)|零价值\s*chunk|噪声\s*(?:写入|注入|逃逸)|'
        r'extractor\s*(?:阶段|拦截|过滤)|retriever\s*(?:阶段|注入|召回)|'
        # iter1285: quantify_selfref_gate — "量化改善：..." 迭代器自我总结逃逸
        # iter1286: quantify_broad_gate — 不依赖特定关键词，有数字变化格式即拦截
        r'量化改善[：:].*[\d.]+%?\s*→)',
        re.I
    )
    if _ITERATOR_DIAG_KW.search(s):
        if not re.search(r'(?:选择|决定|采用|替代|改用|放弃|因为|根因|阈值.*设为|设.*阈值)', s):
            return False
    # ── iter640: iterator_ops_report — 迭代器操作结果/度量变化报告拦截 ──
    # 根因（数据驱动）："零访问率: 27.4% → 23.3% (-4.1pp)"、"删除 5 个明确噪声 chunk"
    #   通过了 quality gate（含数字锚点），但这是迭代器自身的操作汇报，
    #   对用户无检索价值（100% ac=0）。特征：
    #   A. 内部度量变化格式：X率/X比/X数 + 百分比/数字 + → + 百分比/数字
    #   B. 操作动词 + memory-os 内部对象（chunk/trace/FTS/噪声）
    _ITER_METRIC_CHANGE = re.compile(
        r'(?:访问率|零访问|噪声比|命中率|skip.rate|注入率)\s*[：:]\s*[\d.]+%?[\s()\/\d]*→',
        re.I
    )
    # iter978: fix \S{0,6} regex gap — "零访问 chunk" 有空格在中间导致不匹配
    _ITER_OPS_REPORT = re.compile(
        r'^(?:删除|清理|移除|GC)\s*\d+\s*(?:个|条)?\s*\S{0,10}\s*(?:噪声|chunk|trace|碎片|知识|条目)|'
        r'^数据改动[：:]\s*(?:删除|清理|移除|新增|合并)',
        re.I
    )
    # iter755: 列表项+度量变化 — "2. 数据：5 个 AC≥7 的 chunk imp 0.44 → 0.71"
    _ITER_LISTITEM_METRIC = re.compile(
        r'^\d+[.、]\s*(?:数据|结果|效果|改善)[：:].{0,30}→',
        re.I
    )
    # iter643: iterator_confirm_gate — 迭代器操作确认消息拦截
    # 根因（数据驱动）："memory-os.md：✅ 已追加 iter552 条目" (ac=0,inject=2)
    #   通过了 self-ref gate（只含 1 个 iter\d+ 匹配），但本质是迭代器操作日志。
    # 特征：✅/✓ + 操作动词（已追加/已完成/已修复/已清理/已更新）
    #   或 iter\d+ + 操作动词 — 均为迭代器自动确认消息，对用户无检索价值。
    _ITER_CONFIRM = re.compile(
        r'(?:✅|✓|☑)\s*已(?:追加|完成|修复|清理|更新|执行|删除|写入)|'
        r'iter\d{2,}\s*(?:条目|记录|完成|已)',
        re.I
    )
    # iter858: iter_prefix_gate — 拦截 "iterNNN: snake_case_name" 格式
    # 根因（数据驱动，2026-05-05）：0fb5b43d "iter856: global_chunk_relevance_floor"
    #   逃逸所有已有 gate（_internal_var_hits=1, noise_kw 无覆盖）。
    #   特征：迭代器 commit message 标题被 conversation_summary 提取器捕获。
    #   iter\d+[：:] 开头 100% 是迭代器版本标识，不含用户知识。
    _ITER_PREFIX = re.compile(r'^iter\d+[：:_\s]', re.I)
    _ITER_FIX_DESC = re.compile(
        r'^修复[：:].*(?:\.py|阈值|cap\b|suppress|双路径|代码路径|cooldown|threshold|gate|从\s*\d+.*[到→])',
        re.I
    )
    if (_ITER_METRIC_CHANGE.search(s) or _ITER_OPS_REPORT.search(s)
            or _ITER_CONFIRM.search(s) or _ITER_LISTITEM_METRIC.search(s)
            or _ITER_PREFIX.match(s) or _ITER_FIX_DESC.match(s)):
        return False
    # ── iter896: iter_table_and_prediction_gate — 迭代器表格行/公式对比/预期效果 ──
    # 根因（数据驱动，2026-05-05）：10 个噪声 chunk(ac=0-1)逃逸现有 gate：
    #   A. "| 噪声 chunk 占比 | 19% | 3% |" — markdown 表格格式的迭代指标
    #   B. "预期效果：单条注入率从 54% 降到 ~30%" — 迭代器预测
    #   C. "top1 chunk 7d=11x，旧公式残留 17%，新公式残留 5.6%" — 公式对比
    # 三类均为迭代器自身分析产物，对用户零检索价值。
    _ITER_TABLE_ROW = re.compile(
        r'^\|\s*(?:噪声|注入|same.hash|单条|占比|访问|命中|空召回|exp.decay|除数)',
        re.I
    )
    _ITER_PREDICTION = re.compile(
        r'预期效果[：:]\s*.*(?:率|%|降|升|→)',
        re.I
    )
    _ITER_FORMULA_CMP = re.compile(
        r'(?:旧公式|新公式).*(?:残留|衰减)|(?:残留|衰减).*(?:旧公式|新公式)',
        re.I
    )
    if (_ITER_TABLE_ROW.match(s) or _ITER_PREDICTION.search(s)
            or _ITER_FORMULA_CMP.search(s)):
        return False
    # ── iter638: wiki_section_heading_fragment — 碎片式 wiki 标题拦截 ──
    # 根因（数据驱动）：/migrate-memory 批量导入切分 wiki 时产出纯索引碎片，
    #   如 "[topic] xxx > 参考链接"、"[topic] xxx > 相关文件"、"[topic] xxx > 影响范围"。
    #   这些 summary 是 wiki heading 路径，单独无知识价值（ac=0）。
    # 检测："> 纯中文标题词" 结尾，且不含技术细节（数字/代码/文件路径）
    if re.search(r'>\s*(?:[一二三四五六七八九十\d]+[、.]\s*)?(?:参考链接|相关文件|影响范围|引用|附录|索引|目录|链接)\s*$', s):
        return False
    # ── iter834: bare_metric_value_gate — 纯度量标签+值行拦截 ──
    # 根因（数据驱动）："zero_access_rate：0%"、"噪声占比：17% → 0%（...）"
    #   特征：全文 = 度量名（含下划线或中文率/比/数） + 冒号 + 百分比/数字，无决策
    # 匹配：word_metric：N% 或 X率/比/数：N%
    if re.match(r'^[\w_]*(?:rate|ratio|count|访问率|噪声|占比|命中率|注入率|空召回)[：:]\s*\d', s, re.I):
        if not re.search(r'(?:选择|决定|采用|因为|方案|根因|改为)', s):
            return False
    # ── 迭代116：ftrace/调试计数器行过滤 ──
    # OS 类比：ftrace ring buffer 中的 event 数据，只在 debug session 有意义
    # 模式：word_cnt=N word_cnt=N ... — 多个 word=数字 键值对，是内核调试输出
    # 目标：过滤 "sub_enq_cnt=0 sub_deq_cnt=0" 类调试行
    if re.match(r'^[\w_]+=\d+(?:\s+[\w_]+=\d+)+', s):
        return False
    # 纯数值单位换算行（"N ns = M s ≈ Xh Ym" — point-in-time 计算，无决策价值）
    if re.match(r'^\d[\d\s.]*(?:ns|ms|s)\s*[=≈]', s):
        return False
    # ── iter656: raw_metric_label_line — 纯指标行拦截 ──
    # 根因（数据驱动，2026-05-04）：对话中 AI 输出的数据行被误提取为 causal_chain/decision
    #   如 "single-session-user: 87.1% → 100%"、"Count: 62, Avg: 45.26ms"。
    # 拦截：(1) "label: N%" / "label: N% → N%" 格式的纯指标行
    #        (2) "Count/Avg/Min/Max: N" 格式的统计行
    #        (3) "label 一直 N%" 格式的断言行
    if re.match(r'^[\w-]+(?:\s*[\w-]+)?:\s+[\d.]+%?\s*(?:→\s*[\d.]+%?)?\s*$', s):
        return False
    if re.match(r'^(?:Count|Avg|Min|Max|P\d+|Total)[：:]\s*[\d.,]+', s, re.I):
        return False
    if re.search(r'^[\w-]+\s+一直\s+\d+%?$', s):
        return False
    # ── 迭代88：OOM Killer V9 — 主动杀死不产出价值的知识 ──
    # OS 类比：Linux OOM Killer (Andries Brouwer, 2000) — 选择性终止消耗资源但无产出的进程
    # V6 编号列表项作为独立 decision（"2. XXX"、"3. YYY"） → 上下文碎片
    # 编号项只有在列表内才有意义，独立存储时丢失上下文
    if re.match(r'^\d+\.\s', s):
        # 保留：含具体技术锚点的编号项（文件路径/数字度量/代码标识符/量化变化）
        has_anchor = bool(
            re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml)\b', s)
            or re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个)', s)
            or re.search(r'`[^`]+`', s)
            or re.search(r'(?:→|->)\s*\d', s)
        )
        if not has_anchor:
            return False
    # V7 纯迭代完成报告（"迭代N xxx 完成/修复/通过"） → 是进度日志不是决策
    # "内容：迭代86 ..." 格式的保存建议摘要
    if re.match(r'^(?:内容：)?迭代\s*\d+', s):
        # 保留含具体技术决策动词的
        if not re.search(r'(?:选择|决定|采用|替代|改用|放弃|因为|根因)', s):
            return False
    # V8 指标快照（"命中率：当前 X%"、"P99=Xms"、"性能微调"） → point-in-time 数据
    if re.match(r'^(?:命中率|覆盖率|利用率|零访问率|候选池|性能微调)[：:]', s, re.I):
        if not re.search(r'(?:选择|决定|采用|替代|改用|因为|所以)', s):
            return False
    # V9 回归验证报告 — 非 V1 格式但本质相同（"回归验证: N/N 通过 ✅"）
    if re.search(r'(?:回归|验证|regression)\s*[:：]?\s*\d+/\d+', s, re.I):
        return False
    if re.search(r'\d+/\d+\s*(?:测试|tests?)\s*(?:通过|passed|✅|全绿)', s, re.I):
        return False
    # V9b 以 N/N 开头的测试计数（"15/15 新测试"、"38/38 新测试全绿"）
    if re.match(r'^\d+/\d+\s', s):
        return False
    # ── iter89: OOM V10 — 补充三类漏网碎片 ──
    # V10a 进度条碎片（含 ████ Unicode 块字符 — 视觉展示，无语义）
    if '█' in s or '░' in s:
        return False
    # V10b 字母列表项（"A. xxx"、"B. xxx" — 与编号列表项同理，脱离上下文无意义）
    if re.match(r'^[A-Z]\.\s', s) and len(s) < 40:
        return False
    # V10c 截断残缺句（末尾以引号/逗号结尾，且无技术锚点）
    if re.search(r'[",，]$', s):
        has_anchor = bool(
            re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql)\b', s)
            or re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个)', s)
            or re.search(r'`[^`]+`', s)
        )
        if not has_anchor:
            return False
    # V10d iter90：pytest 测试输出碎片（"====...passed..."、"::Test"、"PASSED [%]"）
    if any(pattern in s for pattern in [
        "passed in",      # "12 passed in 2.77s"
        "::Test",         # pytest test path
        "PASSED [",       # "PASSED [33%]"
        "FAILED [",       # "FAILED [20%]"
    ]):
        return False
    if re.match(r'^={2,}', s):  # "====== separator"
        return False
    # ── iter506: seccomp-bpf Content Domain Filter ──────────────────────────
    # OS 类比：Linux seccomp-bpf (Will Drewry, 2012) — 系统调用入口强制访问控制。
    # 拦截非技术域内容（生活/日常对话/美食/旅行/情感）进入知识库。
    # 触发条件：无任何技术信号 AND 含生活域信号词。
    # 设计：宁可漏过（false negative）也不误杀技术内容（zero false positive 目标）。
    _TECH_SIGNALS = (
        # 代码/文件标识符
        re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml|sh|c|h|rs|go|java)\b', s),
        # 代码语法元素
        re.search(r'`[^`]+`|def |class |import |function |const |var |let ', s),
        # 技术术语（英文）
        # iter809: web_tech_signals — 扩展 curl/HTML/fetch/regex 等 web 开发术语
        # 根因：a8f13757 "微信公众号(curl+UA)获取方式" has_tech=False → 被 _LIFE_KEYWORDS 误杀
        re.search(r'\b(?:API|DB|SQL|FTS|BM25|CPU|RAM|OOM|GC|LRU|PID|hook|chunk|cache|mutex|thread|kernel|patch|commit|git|docker|nginx|redis|curl|HTML|JSON|XML|CLI|regex|fetch|playwright|UA|SDK|OAuth|JWT|WebSocket)\b', s, re.I),
        # 数字度量
        re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|KB|次|条|个|行)', s),
        # 技术中文术语
        re.search(r'(?:迭代|配置|数据库|索引|缓存|线程|进程|部署|编译|调试|接口|模块|组件|框架|架构|算法|延迟|吞吐|并发|性能|内存|磁盘|网络|协议)', s),
    )
    has_tech = any(_TECH_SIGNALS)
    # ── iter615: self-referential noise gate — 拒绝 memory-os 自身迭代实现细节 ──
    # 根因：迭代器在分析/修复注入垄断时生成的 decision/causal_chain（如 "score 降 95%"、
    # "session_density_gate 按 session 重置"）被写入 store，永远不会被用户检索。
    # 特征：同时含 ≥2 个 memory-os 内部术语 → 属于自引用噪声。
    _SELF_REF_TERMS = re.findall(
        r'(?:inject[_\s]|suppress|score\s*[×*降=]|bandwidth.penalty|session.density|'
        r'temporal.burst|recall.count|Jaccard|注入门槛|注入量|注入垄断|次注入|'
        r'access.count|chunk.{0,6}注入|min_rel|retriever|extractor.pool|'
        r'score.{0,3}0|hard.?cap|hard.?gate|oom_adj|'
        # iter624: 扩展 self-ref gate — 拦截迭代器决策记录中的高频漏网模式
        # 根因：ac>=50/逃逸率/垄断/iter\d+/zero_access 等迭代术语只匹配 0-1 次→漏网
        r'ac[>=]+\d|iter\d{3,}|垄断|逃逸|burst|saturation|'
        r'zero.access|relevance.{0,3}[<>0]|slot.?位|注入占比|'
        # iter661: ghost_gc/幽灵/孤岛化 — daemon 清理逻辑的常见漏网词
        r'ghost.?gc|幽灵条目|幽灵.*chunk|孤岛化|'
        r'daemon|priming|refault|thrash|'
        # iter665: meta_reflection — 迭代器元反思语言
        r'HOT.Tier|MEMORY\.md|memory\.md|Skill.Listing|'
        r'规则.*有效|复盘|迭代器.*元|元思考|self-improving|'
        # iter682: threshold_fix_gate — 迭代器修复阈值/suppress 参数的记录
        # 根因：'修复：同步两处阈值 24h<2, 7d<3' (ac=1) 逃逸，suppress/阈值各只匹配 0 次
        r'阈值|24h.{0,6}7d|7d.{0,6}24h|'
        # iter684: inject_verb_gate — 独立"不注入/注入/时注入"匹配
        # 根因：'raw max score < 6.0 时不注入' 逃逸，因原有模式只匹配"注入门槛"等复合词
        r'(?:不|时|被|已)注入|score\s*[<>]|'
        # iter795: arch_desc_gate — memory-os 架构描述/组件列表
        # 根因：42d826ac "AIOS Memory-OS 架构：L4 SQLite...memory_chunks" (ac=1) 逃逸
        r'memory.chunks|store\.db|recall.traces|chunk.version|SessionStart|UserPromptSubmit|FTS5|production_assertions|'
        # iter802: trace_metric_gate — 迭代器运维指标/DB字段名逃逸
        # 根因：'空 trace 率 37%→0%'、'recall_counts 统计基础'、'top_k_json=[]' 等逃逸
        #   原 pattern 缺少 memory-os 内部度量语言（空召回、trace 率、DB 列名）
        r'空召回|空.?trace|top_k|injected[=]|_accessed_ids|闭包捕获|self.ref|candidates.count|'
        # iter808: guard_gate_terms — 迭代器内部 guard/writeback 术语
        # 根因：'session_first_inject_guard' (1 match=inject_) 逃逸，TLB/hash/guard 是 retriever 内部术语
        r'inject.guard|final.gate|writeback|TLB.{0,4}cache|prompt.hash|零注入|'
        # iter809: extractor_internal_gate — extractor 内部函数名/指标逃逸
        # 根因：'_is_quality_chunk 误杀 2/34'（0 match）逃逸，内部函数名不在 pattern 中
        r'false.?positive|_is_quality|_should_block|_dedup|误杀.*chunk|漏网模式|'
        # iter862: selfref_gate_name + memory_os — 拦截 memory-os 内部 gate 名称和自引用
        # 数据驱动（2026-05-05）：bee09746 "incomplete_sentence_gate：拦截..."(ac=1)、
        #   ce1fc418 "memory-os v2 = 通用版"(ac=1) 逃逸所有现有模式。
        #   特征：含 _gate 后缀的内部规则名 或 "memory-os" 自引用。
        r'\w+_gate[：:]|memory.os|'
        # iter951: project_id_drift_gate — 拦截 project ID 漂移/内部去重逻辑
        # 根因（数据驱动，2026-05-06）：5 条 ac=0 reasoning_chain/causal_chain 全关于
        #   project ID 漂移机制，含 resolve_project/CLAUDE_CWD/insert_chunk 等内部术语。
        r'project.?ID|resolve_project|CLAUDE_CWD|insert_chunk|already_exists|merge_similar|'
        r'被动注入|注入覆盖率|'
        # iter958: session_suppress_internal_gate — 拦截 suppress 内部运维因果链
        # 根因（数据驱动，2026-05-06）：3 条 ac=0 causal_chain 关于 session-dedup/7d timeline
        #   内部机制，含 "7d timeline 记录"/"session 内多次检索"/"suppress 误杀" 等。
        r'timeline.*记录|session.*检索.*chunk|suppress.*误杀|session.dedup|'
        # iter1063: agent_infra_gate — hook/skill 内部实现细节拦截
        # 根因（数据驱动，2026-05-07）：2 条 ac=0 causal_chain 关于 coach skill 内部
        #   "Stop Hook 报错退出"/"prompt_scores 聚合"，不含用户领域知识。
        #   特征：Stop.?Hook/prompt_scores/growth_signals 等 agent infra 术语。
        r'Stop.?Hook|prompt_scores|growth_signals|hook.*报错|hook.*退出|'
        r'skill[：:].*(?:改为|聚合|触发)|/coach\s)',
        s, re.I
    )
    if len(_SELF_REF_TERMS) >= 2:
        return False
    # iter802: single_selfref_no_domain — 单 self-ref 词 + 无外部领域锚点 → block
    # 根因：'空 trace 率 37%→0%'（1 match）逃逸，因为阈值 >=2。
    #   但这类 summary 纯粹是 memory-os 运维指标，不含任何用户领域知识。
    #   加固：1 match + 无领域锚点（kernel/sched/feishu/Android/...）→ 仍拦截。
    if len(_SELF_REF_TERMS) == 1:
        _has_domain_anchor = re.search(
            r'(?:kernel|sched|CPU|Android|feishu|飞书|patch|线程|进程|调度|'
            r'binder|LKMM|scx|qos|migration|MTK|三星|vendor|AOSP|'
            r'公众号|微信|curl|HTTP|API|REST|gRPC|proto|'
            # iter809: claude_tool_anchor — Glob/Read/CLAUDE.md 是用户工作流约束
            # 根因：93cbc985 "memory 引用前必须用 Glob/Read 验证" 被误杀
            # iter1412: anchor_word_boundary — \bGlob\b 防止匹配 "global" 中的 "glob"
            # 根因（数据驱动，2026-05-10）：d2c9eb2b "空召回...global chunk 被 suppress"
            #   domain_anchor 误匹配 "global" 中的 "glob"(re.I) → 1-match 放行逃逸。
            r'\bGlob\b|\bRead\b|\bWrite\b|\bEdit\b|\bGrep\b|CLAUDE\.md|claude[\s-]code)',
            s, re.I
        )
        if not _has_domain_anchor:
            return False
    if not has_tech:
        # 检测生活域信号
        _LIFE_KEYWORDS = re.search(
            r'(?:餐厅|美食|旅行|旅游|酒店|外卖|快递|购物|淘宝|京东|抖音|微信|朋友圈|'
            r'榴莲|水果|蔬菜|做饭|烹饪|食谱|减肥|健身|瑜伽|'
            r'恋爱|约会|相亲|结婚|离婚|浪漫|表白|暧昧|社恐|'
            r'影楼|自拍|拍照|婚纱|化妆|穿搭|服装|'
            r'电影|综艺|追剧|明星|歌手|演唱会|KTV|'
            r'宠物|猫咪|狗狗|萌宠|'
            r'天气|下雨|晴天|出门|散步|逛街|'
            r'磕巴|笑场|面对服务员|纪念日|周年)',
            s
        )
        if _LIFE_KEYWORDS:
            return False
    # ── iter860: incomplete_sentence_gate — 拦截以冒号/省略号结尾的未完成句 ──
    # 根因（数据驱动，2026-05-05）：4 条 ac=0/1 碎片 causal_chain 如
    #   "所以产品化的真正目的是："（14字）— 引导词+冒号，缺少结论体。
    #   "原因：这个层太薄了——用户自己 100 行代码就能做个够用的版本" 是完整的（有结论）。
    # 拦截条件：(1) 以冒号/省略号结尾 且 (2) 总长 <30 字（完整句子通常>30字）
    if len(s) < 30 and re.search(r'[：:…]+\s*$', s):
        return False
    # ── iter860: selfref_health_metric_gate — 拦截 memory-os 健康度/自评 chunk ──
    # 根因：6 条 ac<=1 噪声含 "chunk 库"/"ac="/"注入率 86%"/"P50 延迟" 等自评指标。
    #   已有 noise_kw 拦截部分，但组合模式逃逸（如 "45 chunk 库，仅 1 条 ac=0"）。
    # 拦截：同时含 "chunk" + 数字度量的自引用句式
    if re.search(r'chunk\s*库|ac\s*[=＝]', s, re.I) and re.search(r'\d+\s*(?:条|个|%)', s):
        if not re.search(r'(?:kernel|sched|Android|feishu|飞书|patch)', s, re.I):
            return False
    # iter1289: dangling_tail_gate — 拦截以介词/连词/冠词结尾的截断片段
    if re.search(r'\b(?:from|to|in|on|with|for|at|by|of|the|a|an|that|which|who|whom|whose|where|when|and|or|but|nor|if|as|than|because|since|while|although|before|after|until|unless|into|onto|upon|about|between|through|during|without|within|among|across|against|along|toward|towards|under|over|below|above|beneath|beside|besides|beyond|despite|except|like|near|off|out|past|per|plus|via|versus)\s*$', s, re.I):
        return False
    # iter1458: iterator_selfref_combo_gate — 拦截 memory-os 迭代器自身度量/诊断组合模式
    # 数据驱动（2026-05-11）：删除 12 条 ac=0 噪声后，8 条曾逃逸 noise_kw，
    #   共同特征：含 memory-os 内部变量名/度量指标/iter 编号 + 系统自引用语境。
    #   堆积 noise_kw 是打地鼠，用组合正则拦截结构模式。
    _SELFREF_SIGNALS = re.compile(
        r'(?:ghost_purge|幽灵条目|density\s*gate|sess_cnt|min_thresh'
        r'|iter\d{3,4}|HEALTHY|PA\s+\d+/\d+'
        r'|(?:ac|AC)\s*[=:]\s*\d|(?:zero.?ac|Zero.?AC)\b'
        r'|用户触发[，,]不是\s*bug|痛点已在.*iter)', re.I)
    if _SELFREF_SIGNALS.search(s):
        if not re.search(r'(?:kernel|sched|Android|feishu|飞书|patch|cgroup|binder|thermal)', s, re.I):
            return False
    return True


def _is_quality_decision(summary: str) -> bool:
    """
    iter106: decision 类型专用质量过滤（SNR 提升）。
    iter107: 新增前置排除规则，防止规则文档复制品绕过过滤器。

    前置排除（优先于所有通过条件）：
      X1. [规则/...] 前缀 — 来自 self-improving wiki/memory 的规则条目，是文档行而非决策
      X2. [纠正] 前缀 — correction 记录，属于 excluded_path 语义，不应写为 decision
      X3. 以 ** 开头的 markdown 强调行（脱离文档上下文无意义）

    通过条件（满足任一）：
      A. 含决策动词（选择/决定/采用/推荐/替代/改用/放弃/因为/所以/根因）
      B. 含具体技术锚点（文件路径/数字度量/代码标识符/量化变化）
      C. 含对比句式（X 而非 Y / 相比 X，Y 更…）

    OS 类比：Promotion Filter — young gen 对象只有达到晋升条件才进入 old gen。
    """
    s = summary.strip()

    # ── 前置排除（短路，直接拒绝）──────────────────────────────
    # X1. 规则文档行（[规则/Capabilities]、[规则/Rules]、[规则/Wiki Triggers] 等）
    if re.match(r'^\[规则[/／]', s):
        return False
    # X2. 纠正记录（应写为 excluded_path，不是 decision）
    if re.match(r'^\[纠正\]', s):
        return False
    # X3. 纯 markdown 强调行（"**xxx**: yyy" 独立存储时丢失上下文）
    if re.match(r'^\*\*[^*]{2,30}\*\*[：:]\s', s) and len(s) < 80:
        return False
    # iter1129: decision_table_fragment_gate — 表格行碎片绕过 _is_quality_chunk 后兜底
    # 根因（数据驱动，2026-05-08）：9320c3d1 "| 修复 | 非 global 跨项目 chunk relevance..."
    #   含数字度量(0.30/+5)满足条件B，绕过 _is_quality_chunk(应被 pipe>=2 拦截但路径未调用)。
    #   pool 路径 _is_quality_decision 是最后防线，需自带 pipe 拦截。
    if s.count('|') >= 2:
        return False
    # X4. iter B14：memory-os/iterXX 进度日志（"✅ xxx 完成"、"[memory-os/iter42] ✅ ..."）
    # 这类进度日志是过程性记录，不是可复用决策，不应晋升到 global
    # OS 类比：/proc/kmsg 里的 printk(KERN_INFO "done") — 进度打印不是决策文档
    if re.match(r'^\[memory-os/iter\d+\]', s):
        return False
    if re.match(r'^✅\s', s) and re.search(r'(?:完成|修复|通过|升级|迭代|验证|实现)', s[:50]):
        return False
    # X5. iter954: self_impl_gate — memory-os 自身实现细节不是用户决策
    #   根因（数据驱动，2026-05-06）：9 条 ac=0 noise chunk 中 7 条为迭代器自身实现描述，
    #   如 "excluded_path 新增密度 gate"、"tiny_db 阈值 7d<3 太激进" 等。
    #   这些记录了系统内部调参过程，脱离开发上下文对用户检索零价值。
    #   检测：含 suppress/gate/阈值/extractor/retriever 等系统关键词 + 不含用户业务上下文。
    _SELF_IMPL_KW = re.compile(
        r'(?:suppress|_gate|阈值|threshold|extractor|retriever|recall_count'
        r'|zero_access|tiny_db|small_db|hard_cap|bandwidth|iter\d{3}'
        r'|excluded_path|chunk_type|conv_summary|density.gate|碎片.*拒绝|过渡句.*拒绝'
        r'|低质量注入|注入事件|注入率|空召回率|ac[≥>=]\d|chunk.*被.*inject'
        r'|2\s*处同步|[二三双]路径同步|FULL.*hard_deadline|hard_deadline.*FULL'
        r'|注入.*[降升→].*(?:次|条|%)|注入体积|inject.*[降升]'
        r'|posttool_guard|output_compressor|thrashing_detector'
        r'|X5.*gate|预期效果.*chunk|fallback.*(?:兜底|逃逸)|注入位.*(?:释放|给)'
        r'|disputed.*chunk|hard_suppress'
        r'|score_floor|BM25|max_score|ACTIVE\s*\d|chunk\s*库|空召回|逃逸路径|存活率)'
    )
    if _SELF_IMPL_KW.search(s):
        _x5_cn_exempt = re.search(r'[\u4e00-\u9fff]{8,}', s.split('：')[0] if '：' in s else '')
        # iter1546: selfref_multi_signal_override — 多信号自引用不受中文放行保护
        # 根因（数据驱动，2026-05-11）："GC 2 条 ac=0 迭代器状态快照噪声（当前状态良好：100个chunk..."
        #   "迭代器状态快照噪声" 9字连续中文触发放行，但含 ac=0 + chunk + 噪声 = 强自引用。
        # 修复：含迭代器自描述词时，中文放行无效。
        _x5_self_desc = re.search(r'(?:器噪声|快照|状态良好|GC\s*\d+\s*条|迭代器.*(?:清理|释放|状态))', s)
        if _x5_self_desc or not _x5_cn_exempt:
            if not re.match(r'^(?:决定|选择|采用|推荐|改用)', s):
                return False

    # X6. iter955: ephemeral_market_gate — 短期时效性市场数据不应持久化
    #   根因（数据驱动，2026-05-06）：3 条 ac=0 投资决策 chunk（"创业板指 5 日涨幅"、
    #   "当前市场情绪过滤通过了"等）含量化锚点（+2.36%）绕过 gate，
    #   但这些是日级数据快照，次日即过期，对未来检索零价值。
    #   检测：含金融时效关键词（涨幅/连板/扫描时间点/情绪过滤）。
    if re.search(r'(?:日[涨跌]幅|[涨跌]幅[：:]\s*[+-]?\d|连板|市场情绪.*[过通]|'
                 r'扫描时间[点是]|下一个扫描|收盘后|开盘前|今[日天]行情)', s):
        # 放行：含持久性决策（"因为X选择Y"、"策略调整"、"规则变更"）
        if not re.search(r'(?:策略调整|规则变更|参数.*(?:从|改为)|选择|决定|因为)', s):
            return False

    # ── 通过条件（满足任一即写入）─────────────────────────────
    # A. 决策动词
    _has_decision_verb = bool(re.search(r'(?:选择|决定|采用|推荐|替代|改用|放弃|因为|所以|根因|不选|不用|废弃|最终方案)', s))
    if _has_decision_verb:
        return True
    # iter1102: short_decision_standalone_gate — 短碎片仅靠数字度量不足以通过
    # 数据驱动（2026-05-07）：9 个 ac=0 decision 中 8 个 <80 字，
    #   全因含数字(16%/4ms/8.9%)匹配条件B通过，但无独立决策语义（表格行/预期数字/诊断快照）。
    #   有价值的短 decision（ac>0）多为 wiki import（[topic] 前缀）或含决策动词（条件A）。
    # 修复：<60 字 + 非 wiki import([前缀) 的 decision，仅条件 B(数字度量) 不足通过，
    #   须同时满足 A(决策动词) 或 C(对比句式)。条件 B 的文件路径/代码标识符仍独立通过。
    _is_short_fragment = len(s) < 60 and not re.match(r'^\[', s)
    # B. 具体技术锚点
    if re.search(r'[\w./]+\.(?:py|js|ts|json|db|sql|yaml|toml|sh|md)\b', s):  # 文件路径
        return True
    if re.search(r'\d+(?:\.\d+)?(?:%|ms|s|MB|GB|次|条|个|行|倍|x)', s):  # 数字度量
        if _is_short_fragment:
            pass  # 短碎片仅靠数字度量不通过，继续检查其他条件
        else:
            return True
    if re.search(r'`[^`]+`', s):  # 代码标识符
        return True
    if re.search(r'(?:→|->)\s*\d', s):  # 量化变化
        if _is_short_fragment:
            pass  # 短碎片仅靠量化变化不通过
        else:
            return True
    # C. 对比句式
    if re.search(r'(?:而非|而不是|不是.*而是|相比.*更|比.*更好)', s):
        return True
    return False


    # ── _already_exists / _find_similar 已迁移至 store.py（迭代21 VFS）──


def _is_tool_insight_noise(text: str) -> bool:
    """
    tool_insight 专用过滤：排除含量化数据但无决策价值的系统/调试输出。
    OS 类比：dmesg 过滤 — 内核日志中 printk(KERN_DEBUG) 不写入 audit log。

    过滤目标（经实际噪音归纳）：
    - 纯测试通过/失败行（"N passed"、"N/N 通过"）
    - 延迟测量行（"X.Xms | n=N | q=..."）
    - 系统状态快照（"decisions=N excluded=N ..."）
    - 进度/百分比行（"+85000.0% recall@3"、"Worst Queries (recall=0)"）
    - memory-os 内部日志行（"Injection avg=...ms"、"hash_changed|full"）
    - syslog/journald 行（时间戳 + 进程名 + 消息格式）
    """
    # iter114: syslog/journald 行过滤（"Apr 21 15:05:13 host process[pid]: ..."）
    # OS 类比：auditd 过滤 printk() kern.debug 级别消息
    if re.match(r'^[A-Za-z]+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+\[\d+\]:', text):
        return True
    # N passed / N warnings / N failed（pytest 输出）
    if re.search(r'\d+\s+(?:passed|failed|warnings?|errors?)\b', text, re.I):
        return True
    # X.Xms | n=N | q=... （检索延迟行）
    if re.match(r'[\d.]+ms\s*\|\s*n=\d+', text):
        return True
    # decisions=N excluded=N ... （extractor dmesg 行）
    if re.match(r'decisions=\d+', text):
        return True
    # Injection avg=... （retriever 统计行）
    if re.match(r'Injection\s+avg=', text):
        return True
    # hash_changed|... / skipped_same_hash / priority= （retriever reason 行）
    if re.search(r'hash_changed\||\bskipped_same_hash\b|\bpriority=(?:FULL|LITE|SKIP)\b', text):
        return True
    # 召回traces总数: ... （统计快照）
    if '召回traces总数' in text or '有效注入' in text:
        return True
    # Worst Queries / Improvement: +X% recall （eval 报告）
    if re.match(r'(?:Worst Queries|Improvement:)', text):
        return True
    # ✅/✗ + 纯延迟验证（"✅ dump 延迟 Xms < Yms"）— 过程性验证，非决策
    if re.match(r'^[✅✗❌]\s+\w+\s+延迟\s+[\d.]+ms', text):
        return True
    # "测试: N/N 通过" 或 "测试结果：N/N 通过" 格式
    if re.search(r'测试(?:结果)?\s*[:：]\s*\d+[/／]\d+\s*(?:通过|passed)', text, re.I):
        return True
    # "N/N 通过，N 失败" 格式
    if re.search(r'\d+[/／]\d+\s*通过', text):
        return True
    # CRIU/测试类完成报告
    if re.search(r'(?:Checkpoint|Restore)\s+测试\s*:\s*\d+/\d+', text):
        return True
    # iter106: eval recall 统计行（"category : recall=0.9 (N=10)"、"Q: id recall=1.0"）
    if re.search(r'recall=[01]\.\d+(?:\s*\(N=\d+\))?', text):
        return True
    # iter106: 单字母分类标签行（"R: recall=0.0"、"Q: hash recall=..."）
    if re.match(r'^[A-Z]:\s+\w', text) and 'recall' in text:
        return True
    # iter657: raw_metric_line_gate — 纯指标行（无决策上下文）
    # 根因（数据驱动，2026-05-04）：12 个 ac=0 chunk 是纯统计数据行
    #   如 "temporal-reasoning: 90.3% → 91.2%"、"Count: 62, Avg: 45.26ms"。
    #   特征：整行只是 "label: number" 或 "| col | col |" 格式，缺乏因果/决策语义。
    # 拦截：(1) "word: N%" 或 "word: N% → N%" 格式的纯指标行
    #        (2) markdown 表格行（以 | 开头含数字）
    #        (3) 原始 DB 行/日志行（以 tuple 或时间戳开头）
    if re.match(r'^[\w-]+:\s+[\d.]+%?\s*(?:→\s*[\d.]+%?)?\s*$', text.strip()):
        return True
    if re.match(r'^\|.*\|.*\d+.*\|', text.strip()):
        return True
    if re.match(r'^\(\d{4,}', text.strip()):
        return True
    # iter656: "Count: N, Avg: N, ..." / "Total: N" 格式统计行
    if re.match(r'^(?:Count|Avg|Min|Max|Total|P\d+)[：:]\s*[\d.,]+', text.strip(), re.I):
        return True
    # iter662: memory-os 迭代器自引用 — tool output 中的 extractor/retriever 调试行
    # 根因：f3be0440 "✅ should block blocked=True (diag=True selfref=1)" 逃逸，
    #   因为 tool_insight 路径不走 _should_block 的 self-ref gate。
    if re.search(r'should.block|selfref|_should_block|_ITERATOR_DIAG|chunk_state.*dead|存量噪声', text):
        return True
    # iter684: memory_lookup_echo_gate — 拦截 memory_lookup 结果回写
    # 根因（数据驱动，2026-05-04）：memory_lookup 返回 "N. [chunk_type] [id_prefix] summary"
    #   格式的结果行，被 _TOOL_INSIGHT_PATTERN 匹配（含百分比/数字）后写为新 chunk，
    #   产生与已有 chunk 完全重复的 tool_insight（实测 2 条 ac=0 垃圾）。
    # 特征：以 "数字. [" 开头（memory_lookup 编号格式）
    if re.match(r'^\d+\.\s*\[', text):
        return True
    # iter792: chunk_metadata_echo_gate — 拦截 chunk metadata 行回写
    # 根因（数据驱动，2026-05-04）：retriever 注入的 chunk 在对话中显示
    #   "imp=0.95 stab=365.00 age=0.0d type=quantitative_evidence | ..."
    #   被 _TOOL_INSIGHT_PATTERN 匹配后作为新 tool_insight 写入，
    #   产生与原 chunk 内容重复的回声（实测 3 条 ac=0）。
    # 特征：以 "imp=" 开头（chunk metadata 前缀格式）
    if re.match(r'^imp=[\d.]+\s+stab=', text):
        return True
    # iter958: build_error_gate — 拦截 make/compiler 构建错误行
    # 根因（数据驱动，2026-05-06）：1 条 ac=0 tool_insight "make: *** [Makefile:210: ..."
    #   构建错误是临时状态，修复后无复用价值。
    if re.match(r'^make\s*:', text) or re.search(r'(?:error|Error):\s+.*(?:undefined|redeclar|implicit|expected)', text):
        return True
    # iter951: retriever_perf_gate — 拦截 memory-os 自身性能/实现细节
    # 根因（数据驱动，2026-05-06）：4 条 ac=0 tool_insight 全是 retriever 性能指标
    #   如 "P50 从 32ms→10ms"、"lazy import subprocess（节省 ~17ms 冷启动）"、
    #   "busy-loops 10ms per task to widen the pre-INIT window"。
    #   特征：含 retriever/extractor 性能术语 + ms/冷启动/FULL/LITE 等度量词。
    if re.search(r'(?:P50|P95|P99|冷启动|cold.?start|FULL.*ms|LITE.*ms|pre.?INIT|lazy\s*import|busy.?loop)', text, re.I):
        if not re.search(r'(?:kernel|sched|Android|feishu|飞书|binder|migration|cgroup|uclamp|cpufreq|latency|延迟)', text, re.I):
            return True
    # iter959: diff_snippet_gate — 纯 diff/代码片段无独立检索价值
    # 根因（数据驱动，2026-05-06）：3 条 ac=0 tool_insight 为纯 diff 行
    #   "+ u64 end = bpf_ktime_get_ns()..."、"+ * root sched with bug6_slow_init=1..."
    #   脱离上下文后无法独立理解，且代码变更后即过时。
    # 检测：以 +/* 开头（diff/comment 行）且无中文解释
    if re.match(r'^\+\s*[\w*/]', text) and not re.search(r'[\u4e00-\u9fff]', text):
        return True
    # iter1188: transient_error_url_gate \u2014 \u62e6\u622a\u77ac\u6001\u5de5\u5177\u9519\u8bef\u548c\u7eaf URL \u767b\u5f55\u91cd\u5b9a\u5411
    # \u6839\u56e0\uff08\u6570\u636e\u9a71\u52a8\uff0c2026-05-08\uff09\uff1a2 \u6761 ac=0 tool_insight \u5206\u522b\u662f
    #   "URL: https://cas.mioffice.cn/login?service=..." (\u767b\u5f55\u91cd\u5b9a\u5411 URL)
    #   "playwright._impl._errors.TimeoutError: Page.goto: Timeout 30000ms exceeded."
    #   \u77ac\u6001\u9519\u8bef/\u767b\u5f55\u5899\u5728\u4e0b\u6b21\u8bbf\u95ee\u53ef\u80fd\u6d88\u5931\uff0c\u65e0\u8de8\u4f1a\u8bdd\u590d\u7528\u4ef7\u503c\u3002
    if re.search(r'TimeoutError|ConnectionError|ConnectionRefused|ECONNRESET|ETIMEDOUT|SSLError', text):
        return True
    if re.match(r'^(?:URL:\s*)?https?://\S+/(?:login|auth|sso|cas|oauth)\b', text, re.I):
        return True
    return False


# ── 迭代39：COW 预扫描 — 写入时惰性求值 ──────────────────────
# OS 类比：Linux fork() Copy-on-Write (1991)
#   fork() 不立即复制父进程的所有页面，而是共享并标记为只读。
#   只有当进程真正写入时才触发 page fault → 复制该页面。
#   大多数 fork+exec 场景中，子进程立即 exec 新程序，
#   父进程的页面从未被修改 → 节省了大量不必要的内存复制。
#
#   memory-os 等价问题：
#     extractor Stop hook 在每次会话结束时都执行完整提取流程：
#     6+ 种正则扫描 + already_exists 全表查询 + kswapd 水位检查。
#     但 ~60% 的消息是纯代码输出/简短确认/调试信息，不含任何有价值决策。
#     COW 预扫描：先做一次极轻量检测（单次正则，< 0.1ms），
#     只有检测到信号时才触发完整提取（"写入时复制"）。

# 合并所有信号词到一个预扫描正则（union of all signal patterns 的关键词）
_COW_PRESCAN = re.compile(
    r'(?:'
    # 决策信号关键词
    r'选择|决定|采用|推荐|最终方案|方案选定|推断|结论|因此'
    r'|decided?|chosen?|adopted?|recommended?|conclusion|therefore'
    # 排除信号关键词
    r'|不用|放弃|排除|废弃|不推荐|不选|跳过'
    r'|deprecated|abandoned|rejected|skipped'
    # 推理链信号（扩充：覆盖更多实际内容中的推理标记）
    r'|根本原因|root cause|核心问题|第一性原理'
    r'|根本问题|根因|本质问题|问题在于|原因[：:]|根本差距'
    r'|这是因为|发现根因|真正原因|关键发现|核心发现|分析显示'
    r'|诊断结论|性能瓶颈|瓶颈在于|key finding|the reason|analysis shows'
    # 迭代120：新增高频推理词
    r'|这说明|这表明|这意味着|关键在于|症结在于|实质上|本质上|由此可见|这证明了|这验证了'
    # 因果链（迭代122：扩充覆盖真实LLM因果表达）
    r'|因为.*所以|由于.*因此|是因为'
    r'|导致|造成|引发|触发|引起|是由.*导致'
    r'|because|due to|caused by|resulted in|leads to'
    # 对比句式
    r'|而非|而不是|相比|比起|改用|换成'
    # 量化证据
    r'|\d+(?:\.\d+)?%|\d+(?:\.\d+)?\s*ms|\d+/\d+\s*(?:cases?|测试)'
    # 完成动作
    r'|已完成|已修复|已创建|已更新|已实现|完成了|修复了'
    r'|successfully|completed|fixed|implemented'
    # 发现/诊断
    r'|发现|诊断|定位|确认.*问题|确认.*原因'
    r'|found|diagnosed|confirmed|identified'
    # 总结标题
    r'|##?\s*(?:总结|Summary|结论|完成|结果|验证)'
    # 迭代102：设计约束新增关键词
    r'|注意不要|小心不要|务必不要|千万不要|切勿'
    r'|⚠️|⚠|WARNING:|CAUTION:|DANGER:|IMPORTANT:'
    r'|never.*because|avoid.*because|don\'t.*because'
    r'|race condition|deadlock|memory leak|data corruption'
    r'|竞态|死锁|内存泄漏|数据损坏'
    r'|否则会|否则将|只有.*才能|必须先'
    r')',
    re.IGNORECASE
)


def _cow_prescan(text: str) -> bool:
    """
    迭代39：COW 预扫描 — 快速检测消息是否可能包含有价值内容。
    OS 类比：fork() 后 MMU 检查 PTE 的 Write bit，
    只有 Write bit 被触发时才执行 copy_page()。

    策略：
      对前 3000 字符执行单次正则匹配（union of all signal keywords）。
      命中 → 返回 True（触发完整提取 "copy-on-write"）
      未命中 → 返回 False（跳过提取，只保留 page_fault 和 madvise 写入）

    预期：~60-70% 的消息不含信号词，可以跳过整个提取流程。
    性能：< 0.1ms（单次正则匹配，无 I/O）。
    """
    # 只扫描前 N 字符（决策/结论通常在消息头部或中部）
    prescan_chars = _sysctl("extractor.cow_prescan_chars")
    sample = text[:prescan_chars]
    return bool(_COW_PRESCAN.search(sample))


def _detect_prospective_intent(text: str) -> str:
    """
    iter390: 检测文本中的展望记忆意图信号。
    认知科学：Einstein & McDaniel (1990) Prospective Memory —
      "记得在X时做Y"的意图性记忆，需要在未来触发时主动提取。
    OS 类比：inotify_add_watch() — 注册条件触发器，等待事件唤醒。

    返回 trigger_pattern（关键词或短语），None 表示无展望意图。
    trigger_pattern 将存入 trigger_conditions，用于后续 query 匹配。
    """
    import re as _re
    # 展望意图信号模式（中文 + 英文）
    _PM_PATTERNS = [
        # 中文展望意图
        (r'下次(?:用|访问|打开|遇到|处理|运行|启动|提交|部署)([^，。；\n]{2,20})', 1),
        (r'记得(?:在|下次|以后|下回)([^，。；\n]{2,20})', 1),
        (r'以后([^，。；\n]{2,20})(?:时|的时候)(?:注意|记得|需要|要)', 0),
        (r'(?:TODO|待办|备忘)[：:]\s*([^，。；\n]{3,40})', 1),
        (r'下一次([^，。；\n]{2,20})(?:时|需要|记得)', 1),
        (r'将来([^，。；\n]{2,20})(?:时|需要|记得|注意)', 1),
        # 英文展望意图
        (r'(?:remember to|TODO:|remind me to|next time)\s+([^\n.]{3,40})', 1),
        (r'when (?:you |I )?(?:next |again )?([^\n.]{3,30}),?\s*(?:remember|make sure)', 1),
    ]
    for pattern, group in _PM_PATTERNS:
        m = _re.search(pattern, text, _re.IGNORECASE)
        if m:
            try:
                matched_phrase = m.group(group).strip()
                if len(matched_phrase) >= 2:
                    return matched_phrase
            except IndexError:
                return m.group(0).strip()[:40]
    return None


def _sqe_validate_importance(importance: float, summary: str, chunk_type: str) -> float:
    """
    iter534: io_uring SQE flags validation — 写入时内容密度验证。

    OS 类比：Linux io_uring SQE flags validation (Jens Axboe, 2019)
    提交 I/O 请求到 submission queue 前验证 SQE flags，拒绝畸形请求浪费 ring buffer。

    只在 importance >= 0.85 时验证（高价值声称需要高密度证明）。
    检查 summary（剥离 [tag] 前缀后）的信息密度：

    密度信号（至少满足 2/5 才视为合格）：
    1. 唯一实体数 >= 2（文件路径/代码标识符/技术术语）
    2. 可操作动词存在
    3. 因果/条件关系存在
    4. 内容长度 >= 40 字符（剥离标签后）
    5. 具体量化数据（带单位的数字，排除编号如 "3."）

    不合格：importance = min(importance, cap)
    """
    import re as _re_sqe

    # 只验证高 importance（>= 0.85）—— 低值不需要证明
    if importance < 0.85:
        return importance

    # 快速路径：excluded_path/prompt_context 不需要高信息密度
    if chunk_type in ("excluded_path", "prompt_context", "conversation_summary"):
        return importance

    # 可通过 sysctl 禁用
    try:
        from config import get as _cfg534
        if not _cfg534("extractor.sqe_validate_enabled"):
            return importance
    except Exception:
        pass

    s = summary.strip() if summary else ""
    # 剥离 [tag] 前缀（如 [decisions]、[memory-os/iter76]）
    s_clean = _re_sqe.sub(r'^\[.*?\]\s*', '', s).strip()

    # ── 快速拒绝：明显碎片模式 ──────────────────────────────────────
    # 编号列表项开头（"3. xxx"、"Q1. xxx"）且剥离后内容短 → 直接降级
    if _re_sqe.match(r'^(?:\d+\.|Q\d+\.)\s', s_clean) and len(s_clean) < 60:
        try:
            from config import get as _cfg534c
            _cap = float(_cfg534c("extractor.sqe_low_density_cap") or 0.60)
        except Exception:
            _cap = 0.60
        return min(importance, _cap)

    # ── 5 个密度信号 ────────────────────────────────────────────────
    density_signals = 0

    # 1. 唯一实体数 >= 2（文件路径/代码标识符/技术术语/函数名）
    _entities = set()
    _entities.update(_re_sqe.findall(r'[a-zA-Z_][\w/\-]*\.(?:py|js|ts|rs|go|c|h|yaml|json|toml|sh)', s_clean))
    _entities.update(_re_sqe.findall(r'`([^`]{2,40})`', s_clean))
    _entities.update(_re_sqe.findall(r'\b[A-Z][a-z]+[A-Z]\w+\b', s_clean))  # CamelCase
    _entities.update(_re_sqe.findall(r'\b[a-z][a-z]+_[a-z_]+\b', s_clean))   # snake_case (tighter)
    # 点分标识符（p->scx.sched, obj.method）
    _entities.update(_re_sqe.findall(r'\b[a-z_]\w*(?:->|\.)[a-z_]\w*\b', s_clean))
    if len(_entities) >= 2:
        density_signals += 1

    # 2. 可操作动词（中/英文）
    _ACTION_VERBS = ('选择', '决定', '采用', '替代', '修复', '新增', '移除', '设置',
                     '改为', '替换', '禁止', '必须', '使用', '避免', '删除', '添加',
                     '实现', '配置', '调整', '优化', '迁移', '升级', '拆分', '合并',
                     '验证', '确认', '检查', '触发', '注入', '排除', '覆盖',
                     '不能', '不得',
                     'use', 'add', 'remove', 'fix', 'replace', 'set', 'avoid',
                     'require', 'implement', 'configure', 'migrate', 'must')
    if any(v in s_clean for v in _ACTION_VERBS):
        density_signals += 1

    # 3. 因果/条件/约束关系
    _CAUSAL = ('因为', '所以', '导致', '避免', '如果', '否则', '由于', '根因',
               '原因', '为了', '防止', '确保', '以免', '除非', '须',
               'because', 'since', 'when', 'unless', 'to avoid', 'to prevent',
               'otherwise', '→', '——', '—')
    if any(c in s_clean for c in _CAUSAL):
        density_signals += 1

    # 4. 足够长度（剥离标签后仍有实质内容）
    if len(s_clean) >= 40:
        density_signals += 1

    # 5. 具体量化数据（带单位的数字，排除纯编号 "3." 开头和纯日期）
    # 匹配：N ms, N%, N MB, N 次, N→M, N/M (分数) 等
    _quant = _re_sqe.findall(r'\d+(?:\.\d+)?(?:ms|%|MB|GB|KB|次|条|个|轮|层|步)', s_clean)
    _quant += _re_sqe.findall(r'\d+→\d+', s_clean)  # 变化量
    # 比率（排除纯日期 2026-05-02 和编号 3.）
    _ratios = _re_sqe.findall(r'(?<!\d{4}-)\d+/\d+', s_clean)
    _quant += _ratios
    if len(_quant) >= 1:
        density_signals += 1

    # ── 判定：信号 < 2/5 → 低密度 → 降级 ──────────────────────────
    if density_signals < 2:
        try:
            from config import get as _cfg534b
            _cap = float(_cfg534b("extractor.sqe_low_density_cap") or 0.60)
        except Exception:
            _cap = 0.60
        return min(importance, _cap)

    return importance


def _calculate_confidence(chunk_type: str, summary: str) -> float:
    """
    迭代100：ECC 初始置信度评估 — 从提取特征自动推断。
    OS 类比：CPU confidence estimation — 预测器根据历史准确率调整分支预测信心。
    """
    import re as _re
    # 量化证据（最高置信）
    if _re.search(r'\d+(?:\.\d+)?(?:ms|%|MB|GB|次|条|个)', summary):
        return 0.90
    if chunk_type == "design_constraint":
        return 0.95
    if chunk_type == "excluded_path":
        return 0.80
    if chunk_type == "reasoning_chain":
        return 0.65
    if chunk_type == "conversation_summary":
        return 0.50
    if chunk_type == "decision":
        if any(w in summary for w in ("因为", "所以", "根因", "because")):
            return 0.85
        return 0.75
    return 0.70


def _route_info_class(chunk_type: str, summary: str) -> str:
    """
    迭代300/319：五层路由 — 根据 chunk_type 和内容特征判断 info_class。

    迭代319：委托 store_vfs.classify_memory_type()，统一路由逻辑（DRY）。
    保留本函数作为兼容入口，行为与旧版相同但增加了情节/语义分层。

    五层路由：
      semantic   → decision/design_constraint/procedure/excluded_path（多次验证通用知识）
      episodic   → reasoning_chain/conversation_summary/causal_chain（会话内情节事件）
      operational → task_state/prompt_context（agent 操作配置）
      ephemeral  → 含"临时"/"本次"关键词（临时状态）
      world      → 其余（默认，中等保留）

    OS 类比：Linux VFS 文件类型路由（S_ISREG/S_ISDIR/S_ISLNK）——
      不同文件类型有不同的 page cache 策略和 eviction 优先级。
    """
    from store_vfs import classify_memory_type as _classify
    return _classify(chunk_type, summary)


def _vma_validate(summary: str) -> bool:
    """
    iter562: vma_validate — 写入时最终准入校验（insert_vm_struct 验证）。

    OS 类比：Linux insert_vm_struct() (kernel/mm/mmap.c) — mmap() 在插入 VMA
    到红黑树前的最终验证。即使 mmap_region() 已经做了权限/对齐检查，
    insert_vm_struct() 仍然检查 VMA 不与已有区间重叠、不超出地址空间限制。
    这是写路径的"最后关卡"——上游所有过滤器漏掉的碎片在这里被最终拦截。

    根因：_is_quality_chunk() 和 _is_fragment() 在提取阶段过滤，但某些代码路径
    （量化证据、因果链、design_constraint）有独立的提取逻辑绕过了这两个函数。
    生产 DB 中 6 个零访问高 importance chunk 就是漏网碎片：
      - 行号前缀（Read 工具输出泄漏）：'1260:- 性能：...'
      - 状态报告前缀（健康检查输出）：'⚠️ DEGRADED: 9/10 passed...'
      - markdown 表格单元格：'| 测试 | 22/22 通过，0.69s |'

    返回 True 表示通过验证（可写入），False 表示拒绝。
    """
    s = summary.strip()
    if not s or len(s) < 10:
        return False
    # V1 行号前缀：Read 工具输出（'1260:- 性能：...'、'547:  if text[0]...'）
    if re.match(r'^\d{1,5}[:：]\s*[-\s]', s):
        return False
    # V2 状态/健康报告：emoji + 状态关键词（'⚠️ DEGRADED:'、'✅ PASS:'）
    if re.match(r'^[⚠️✅❌🔴🟡🟢]+\s*(?:DEGRADED|PASS|FAIL|WARNING|OK|HEALTHY|ERROR)', s):
        return False
    # V3 markdown 表格行（任何含 2+ pipe 的行）— 加强 _is_fragment 的 >= 2 检查
    if s.count('|') >= 2:
        return False
    # V4 行号引用前缀（'line 547:'、'L1260:'、'第42行'）
    if re.match(r'^(?:line\s+\d+|L\d+|第\d+行)\s*[:：]', s, re.I):
        return False
    # V5 iter593: self-referential noise — memory-os 实现细节不是用户知识
    # iter798: +candidates_count, tiny_db — 拦截迭代器 FTS/路径选择决策记录
    _code_idents = ('top_k', 'recall_count', 'thrash_max_pct', 'bw_window',
                    'same_hash', '_sysctl', '_effective', 'chunk_type',
                    'retriever.', 'extractor.', 'retriever_daemon',
                    'pre_hash_thrash', 'thrash_suppress', '_write_chunk',
                    '_seal_check', '_vma_validate', 'insert_chunk',
                    'candidates_count', 'tiny_db')
    _sl = s.lower()
    if any(ci in _sl for ci in _code_idents):
        return False
    # V6 iter594: operational_noise — 操作确认和迭代器自我分析不是用户知识
    # 根因（数据驱动）：38 个零访问 chunk 中 6 个是迭代器对话噪声：
    #   - "已追加 iterN 条目"（操作确认）
    #   - "诊断：87% chunk 是迭代器自身实现细节"（自我分析）
    #   - 短纯中文通用句子（无技术锚点）
    if re.search(r'已(?:追加|更新|删除|记录|写入).*iter\d+', _sl):
        return False
    if '迭代器' in s:
        return False
    if len(s) <= 30 and not re.search(r'[A-Za-z0-9/_.→:：]', s):
        return False
    # V7 iter597: memory_os_meta_gate — 拦截迭代器对 memory-os 自身的分析产出
    # 根因（数据驱动）：41 个零访问 chunk 中 7 个是迭代器分析 memory-os 行为的"决策"，
    #   如 "注入垄断 — feishu CLI (ac=46, 注入14次)"、"session dedup 宽松系数"。
    #   V5 的 _code_idents 拦截了代码标识符，但中文描述的内部概念漏网。
    _MEMORYOS_META = (
        '注入垄断', '零访问', 'session dedup', '写入门控', '噪声写入',
        '去垄断', 'chunk 零', 'recall_trace', 'inject_hard_cap',
        'access_count', 'ephemeral_type', 'monopoly_gate',
        '迭代器自身', '迭代器噪声',
        # iter605: 补充遗漏的 memory-os 内部关键词
        'hard_cap', 'hard_gate', 'bandwidth_throttle', 'bw_window',
        'effective_bw_window', 'recall_count', 'soft throttle',
        'refault_distance', 'constraint_min_relevance',
        'feedback_loop_break', 'rc_cap', 'rc=',
        # iter626: iteration_metrics_gate — 拦截迭代器自身的量化验证/度量输出
        # 根因：5 个漏网噪声 chunk 各含 1 个 _SELF_REF_TERMS（阈值 >=2 漏网），
        #   但它们同时含 iteration metrics 语言（PA N/10, 信噪比, 注入槽位, zero_access_rate）。
        #   这些术语是迭代器自评的独有标志，单次匹配即可判定为自引用。
        'zero_access_rate', '量化改善', '注入槽位',
        'PA 9/', 'PA 10/', 'PA 11/', 'PA 12/', 'PA 13/', 'PA 14/', 'PA 15/', 'PA 16/',
        'sts pass', 'HEALTHY',
        # iter665: meta_reflection_gate — 拦截迭代器"元反思"语言
        # 根因：12 条逃逸噪声用的不是底层术语而是高层元语言
        #   如 "HOT Tier 检查""规则看起来是有效的""Query Expansion 语义改进"
        'HOT Tier',
        'Skill Listing Budget', 'Adaptive Complexity',
        'Query Expansion 语义', '规则看起来是',
        '触发条件：(a)', '决策值得复盘',
        # iter683: content_leak_gate — 补充 3 类逃逸的迭代器内部术语
        # 根因：f53fb4fa("extractor 写入质量加强")、c77ba0d2("suppress/阈值")
        #   逃过 V5(_code_idents 要求 'extractor.' 带点) 和 V7(无 suppress/阈值)。
        '阈值同步', 'extractor 写入', 'suppress_fallback',
        '写入质量', '写入拦截', 'final_gate', 'suppress_final',
        '被成功检索并注入', 'score=0.', 'threshold 0.',
        # iter685: chunk_ops_gate — 拦截迭代器 chunk 数量管理报告
        # 根因：'chunk 数量精简 5%（42→40）' (ac=0) 逃逸，因不含任何已有术语
        'chunk 数量', 'chunk数量', '精简 ', '清理 chunk',
        # iter791: iter_selfeval_gate — 拦截迭代器自评/验证指标语言
        # 根因（数据驱动，2026-05-04）：7 个 ac=1 噪声 chunk 含迭代器评估术语：
        #   "空召回率 49%""useful rate""保留率""store_vfs""验证稳定""高质量迭代"
        '空召回率', 'useful rate', '保留率', 'store_vfs',
        '验证稳定', '高质量迭代', '影响面大',
        'sub-threshold', 'noise_rate',
    )
    if any(m in s for m in _MEMORYOS_META):
        return False
    # iter792: soft_match_gate — 在非 memory-os 语境中合理出现的关键词需组合判定
    # 根因（数据驱动，2026-05-04）：3 个有价值 chunk 被单关键词误杀：
    #   - 95038a88(ac=2): "Kernel Patch 证据完整性...信噪比" — 命中 '信噪比'
    #   - 9a1c5b4f(ac=11): "Corrections/Patterns 规则...MEMORY.md" — 命中 'MEMORY.md'
    #   - 93cbc985(ac=3): "memory 路径验证规则...MEMORY.md" — 命中 'MEMORY.md'
    # 修复：这些词在用户知识中合法出现，改为 soft match（≥2 命中才拦截）。
    _SOFT_META = ('信噪比', 'memory.md', 'MEMORY.md', 'suppress')
    _soft_hits = sum(1 for m in _SOFT_META if m in s)
    if _soft_hits >= 2:
        return False
    # iter838: suppress_chunk_combo_gate — 拦截 suppress+chunk 组合的迭代器自引用
    # 根因（数据驱动，2026-05-05）：4 条 ac=0 噪声含 "24h suppress" + "chunk 被注入/触发"，
    #   逃过 _SOFT_META（'suppress' 单次只算 1 hit）。该组合仅在 memory-os 上下文出现。
    if 'suppress' in _sl and re.search(r'chunk.{0,40}(?:注入|被|触发|suppress|阈值|累积|垄断)', s):
        return False
    # iter794: code_var_cn_mix_gate — 拦截混合代码变量+中文说明的内部注释碎片
    # 根因（数据驱动，2026-05-04）：728d3c55 "ac>=30），score 设为 imp  0.01 确保不干扰"
    #   逃逸所有 gate：不含 'score=0.' (是 'score 设为')，不含 _code_idents 完整匹配。
    #   特征：同时含代码变量模式(ac>=N/score/imp*N)和中文动词——只有内部代码注释如此。
    if re.search(r'(?:ac[>=<]+\d|score\s*[设=]|imp\s*[*×\d])', s):
        return False
    # iter685: chunk_ops_report_gate — 拦截 "N→M" 格式的数量变化报告
    # 根因：迭代器产出 "42→40" 类量化操作日志，不含已有术语但有明确格式特征
    if re.search(r'\d+\s*[→→]\s*\d+', s) and re.search(r'chunk|精简|清理|删除|移除', s, re.I):
        return False
    # iter605: 拦截引用具体 chunk ID 的实现笔记（如 "b50e0b54 被注入 87%"）
    if re.search(r'[0-9a-f]{8}.*(?:被注入|注入|injected|rc=|trace)', s):
        return False
    # iter866: iter_retrieval_analysis_gate — 拦截迭代器对检索/pair 算法的因果分析
    # 根因（数据驱动，2026-05-05）：3 条近重复噪声逃逸所有 gate：
    #   "FTS 从未命中它们 → pair 逻辑（iter826/827）无法选到它们"
    #   特征：含 iter\d{3} 引用 + 检索逻辑关键词（候选/pair/FTS/命中/top_k）
    if re.search(r'iter\d{3}', s) and re.search(r'候选|pair|FTS.*命中|top_k|final.*列表', s):
        return False
    # iter687: truncated_fragment_gate — 截断碎片拦截
    # 根因（数据驱动，2026-05-04）：'daemon 工作 → 没人发现）'（17 chars）逃逸所有 gate。
    # 特征：不完整括号结尾 / 箭头结尾 + 短句（<60 chars）= 从长文中误截取的碎片。
    if len(s) < 60:
        if re.search(r'[）)】》]$', s) and not re.search(r'[（(【《]', s):
            return False
        if s.endswith('→') or s.endswith('->'):
            return False
    # iter688: gate_rule_description_filter — 拦截 gate 规则描述被误存为 decision
    # 根因（数据驱动，2026-05-04）：'<60 chars + 箭头结尾 → 断句碎片，拒绝' 逃逸所有 gate
    #   因为它是 gate 规则的文本描述，不含已有黑名单术语。
    # 特征：含 '→' + 末尾是判定动作词（拒绝/通过/reject/pass/skip）
    if '→' in s and re.search(r'(?:拒绝|通过|reject|pass|skip|suppress|拦截)$', s):
        return False
    # iter1445: hook_artifact_gate — 拦截 system-reminder/hook 输出泄漏
    if re.match(r'^\[[\w/ -]{2,20}\]\s*\d+/\d+', s):
        return False
    if re.search(r'coach_score|system-reminder|</?[a-z_-]+>', s, re.I):
        return False
    return True


_write_chunk_seen: set = set()  # iter963: in-process dedup — 防止同 batch 重复写入
_write_chunk_token_sets: list = []  # iter1066: semantic_overlap_gate token 缓存
_write_chunk_session_counts: dict = {}  # iter1126: session_write_freq_cap — per-session 写入计数


def _write_chunk(chunk_type: str, summary: str, project: str, session_id: str,
                 topic: str = "", conn: sqlite3.Connection = None,
                 importance_override: float = None,
                 _txn_managed: bool = False,
                 raw_snippet: str = "",
                 content_override: str = "") -> None:
    """v5 迭代21：委托 store.py VFS 统一数据访问层。
    _txn_managed=True 时跳过内部 commit（由外层事务统一管理）。
    迭代100：新增 confidence_score 自动评估。
    迭代300：新增 info_class 三层路由。
    迭代301：新增 stability 初始值（importance * 2.0）。
    迭代306：新增 raw_snippet（写入时保真原始片段，≤500字，可选）。
    """
    # iter963: in-process batch dedup — 同一进程内防止相同 summary 重复写入
    # 根因（数据驱动，2026-05-06）：2 条 causal_chain 完全相同（间隔 2ms），
    #   因 _txn_managed=True 跳过 commit → already_exists 查不到未提交行 → 重复写入。
    # 修复：进程内 set 记录已写入的 (chunk_type, summary_normalized)，无需等待 commit。
    # iter1062: cross_type_dedup — dedup key 去掉 chunk_type
    # 根因（数据驱动，2026-05-07）：4 个 ac=0 chunk 中 2 对内容相同但 chunk_type 不同
    #   （reasoning_chain vs conversation_summary），因 dedup key 含 type 未被拦截。
    # 修复：key 只看 normalized summary，同内容不同类型视为重复。
    import re as _re963
    _dedup_key = _re963.sub(r'\s+', '', summary.lower())
    if _dedup_key in _write_chunk_seen:
        return
    if len(_write_chunk_seen) > 500:
        _write_chunk_seen.clear()
    _write_chunk_seen.add(_dedup_key)
    # iter1066: semantic_overlap_gate — 同 batch 内 token 重叠度 >60% 视为碎片重复
    # 根因（数据驱动，2026-05-07）：同一 session 对同一教训产生 5-10 条碎片 chunk，
    #   精确去重无法拦截（"没有沿调用链验证" vs "写回复时没有grep确认"语义相同字符串不同）。
    #   82 chunk 库中 25 条来自同一事件的碎片化记录，稀释检索精度。
    # 修复：token-overlap >60%（基于较短方 token 数）跳过，保留最先写入的完整表述。
    global _write_chunk_token_sets
    # 中英混合 tokenize：英文按 word，中文按 bigram（单字太碎、长串不切分则太粗）
    _words1066 = _re963.findall(r'[a-z_][a-z0-9_]*', summary.lower())
    _cjk1066 = _re963.findall(r'[\u4e00-\u9fff]', summary)
    _bigrams1066 = [_cjk1066[i] + _cjk1066[i+1] for i in range(len(_cjk1066)-1)] if len(_cjk1066) >= 2 else _cjk1066
    _tok1066 = set(_words1066 + _bigrams1066)
    if len(_tok1066) >= 3:
        for _prev_toks in _write_chunk_token_sets:
            if len(_prev_toks) < 3:
                continue
            _overlap = len(_tok1066 & _prev_toks) / min(len(_tok1066), len(_prev_toks))
            if _overlap > 0.60:
                return
    _write_chunk_token_sets.append(_tok1066)
    if len(_write_chunk_token_sets) > 500:
        _write_chunk_token_sets = _write_chunk_token_sets[-200:]
    # iter1126: session_write_freq_cap — 单 session 写入频率递进门控
    # 根因（数据驱动，2026-05-08）：session 6ca148eb 48h 内写入 44 条 chunk，
    #   其中 30+ 条是 causal_chain/reasoning_chain 碎片推理步骤（"没有沿调用链验证"、
    #   "list_empty 检测比 SCX_TASK_OFF_TASKS 更早可用"）— 同话题不同表述绕过 overlap gate。
    #   单 session 爆写稀释检索精度：83 chunk 库中 53% 来自同一 session。
    # 修复：per-session 写入计数递进门控：
    #   >8 条：causal_chain/reasoning_chain 短于 80 字 → 拒绝
    #   >15 条：causal_chain/reasoning_chain 一律拒绝（只允许 decision/design_constraint/excluded_path）
    global _write_chunk_session_counts
    _swfc_cnt = _write_chunk_session_counts.get(session_id, 0)
    _write_chunk_session_counts[session_id] = _swfc_cnt + 1
    if len(_write_chunk_session_counts) > 100:
        _write_chunk_session_counts = {session_id: _write_chunk_session_counts[session_id]}
    _REASONING_TYPES = {"causal_chain", "reasoning_chain"}
    if chunk_type in _REASONING_TYPES:
        if _swfc_cnt > 15:
            return
        if _swfc_cnt > 8 and len(summary) < 80:
            return
    # iter596: ephemeral_type_gate — 拒绝写入临时/无跨会话价值的 chunk 类型
    # 根因（数据驱动）：38% chunk 零访问，其中 4 条 conversation_summary/prompt_context
    # 是迭代器自身写入的噪声（重复提示词、轮次计数），从未被用户召回。
    # 这些类型天然短暂（会话级），写入 store 只增加 FTS 噪声和 swap 压力。
    # iter1082: tool_insight_ephemeral — tool_insight 是工具执行快照，无跨会话持久价值
    # iter1582: excluded_path_ephemeral — 0% 存活率（1/1 DEAD），内容为迭代器调试碎片
    # iter1583: reasoning_chain_ephemeral — 0% 存活率（6/6 DEAD），对话中间推理无跨会话复用价值
    _EPHEMERAL_TYPES = {"prompt_context", "conversation_summary", "tool_insight", "excluded_path", "reasoning_chain"}
    if chunk_type in _EPHEMERAL_TYPES:
        return
    # iter1578: causal_chain_rich_content_gate — 碎片因果链拒绝写入
    # 数据驱动（2026-05-12）：19/20 causal_chain 的 content==summary（碎片），全部 DEAD（0%存活）。
    #   唯一存活的 1 条有 rich content（summary=115字, content=1300字, ac=12）。
    # 修复：causal_chain 必须有 rich content（content_override != summary 且 >200字）才允许写入。
    if chunk_type == "causal_chain":
        _cc_rich = content_override and content_override.strip() != summary.strip() and len(content_override) > 200
        if not _cc_rich:
            return
    # iter701: content_echo_gate — summary 无补充内容时拒绝写入
    # 数据驱动：6d4f68bb content=summary="选就会降级注入 1 条最佳结果"（ac=0）。
    # 根因：调用方未传 content_override，_write_chunk 自动生成 "[type] summary"，
    #   但 summary 本身是句子碎片（<15字），无法被 FTS 有效检索。
    # 阈值 15 字：生产中最短合法 chunk summary 为 19 字（test），wiki import 有 content_override 不受影响。
    # iter1377: echo_aware — content_override==summary 时视同无 override
    _co_is_echo = content_override and content_override.strip() == summary.strip()
    if (not content_override or _co_is_echo) and len(summary) < 15:
        return
    # iter1483: content_echo_write_gate — content==summary 源头拦截
    # 数据驱动（2026-05-11）：3 条 ac=0 噪声 content==summary（64-119字），
    #   占 ACTIVE 池 8%（3/38）。retriever 端 suppress 只是降权，仍占 FTS/候选池。
    # 修复：content_override==summary 的非 design_constraint chunk 直接拒绝写入。
    # iter1493: constraint_echo_semantic_gate — design_constraint echo 也需约束语义词
    #   数据驱动（2026-05-11）：2 条 dc echo ac=0，"fix（最小..."/"（PROC_EVENT..."
    #   是对话碎片被误标为 constraint。合法 constraint 必含约束动词。
    if _co_is_echo:
        if chunk_type != "design_constraint":
            return
        _CONSTRAINT_MARKERS = re.compile(
            r'必须|禁止|不得|不能|不要|不可|应该|shall|must|never|always|禁用|强制|仅用',
            re.IGNORECASE)
        if not _CONSTRAINT_MARKERS.search(summary):
            return
    # iter1494: iterator_self_ref_gate — 拦截迭代器描述自身操作的 chunk
    # 数据驱动（2026-05-11）：f981f998 "GC 11条echo噪声chunk" + f54e9cb2 "量化：零访问率"
    #   content==summary，记录迭代器 GC/量化结果，ac=0，对用户零价值。
    _ITER_SELF_PATTERNS = re.compile(
        r'GC\s*\d+\s*条|(?:ACTIVE|global|local)\s*(?:池|\d+\s*→)|\w*池\s*\d+\s*→\s*\d+|ac=0\s*率|零访问率|tests?\s*pass|净增|net$|迭代器|iter\d{3,4}[_:\s]'
        r'|retriever\.py|extractor\.py|memory.os不是|vDSO\s*Stage|import\s*链路|冷启动.{0,20}ms'
        r'|compaction的根因|tool\s*output\s*体积|pathlib.{0,20}import'
        r'|hit_rate:\s*[\d.]+%|用.{1,6}定位而非|这边没\s*$|量化改善[：:]|HEALTHY\s*$'
        r'|swap\s*\d+\s*条|noise\s*chunk|Swapped\s*\d+'
        r'|ac=\d+\s*rate|production\s*assertions?\s*\d+/\d+|ac=0\s*(?:chunk|比例)'
        r'|^\s*\|.*\|\s*\d+[\d.]*%.*\|'
        r'|_fallback_protected_ids|floor_gate|daemon\s*floor|score[<>=]\d|suppress_fallback'
        r'|PA\s*\d+/\d+[，,（(]|修复\s*\d+\s*处.*\+\d+\s*行|空召回.*修复'
        r'|MMR\s*无法|sim_threshold|diversity.penalty|Jaccard.{0,6}相似|注入位\s*\d+%|_cross_proj_floor'
        r'|量化[：:]\s*(?:PA|预期|ACTIVE|zero)'
        r'|content_override\s*[=≈]|echo_content|rich\s*content.{0,20}chunk|chunk_state|_write_chunk'
        r'|逃逸.*阈值.{0,20}chunk|合法\s*chunk\s*都有'
        r'|score_floor|BM25\s*vocabulary|空召回率.*降低|预期效果.*空召回'
        r'|pre.existing\s*failure|与本轮无关|同步.*retriever.*daemon|chunk\s*库.*floor'
        r'|_db_chunk_count|suppress.*阈值.*→|score_floor.*→'
        r'|空召回率.*\d+%|score\s*<\s*floor'
        r'|zero_access_rate|注入垄断|当前状态.*(?:chunk|ac=|zero_access)',
        re.IGNORECASE)
    if _ITER_SELF_PATTERNS.search(summary):
        return
    # iter1530: echo_content_universal_gate — 无 rich content 一律拒绝（除 dc+约束词）
    # 数据驱动（2026-05-11）：25 条 ac=0 噪声全部 content==summary，最长 106 字逃逸 <100 阈值。
    #   所有合法 >=100 字 chunk 都有 rich content（content_len >= 5x summary_len）。
    # 修复：去掉长度阈值，无 rich content 即拒绝。design_constraint 已由上方约束语义门控保护。
    _has_rich = (content_override and content_override.strip() != summary.strip()) or bool(raw_snippet)
    if not _has_rich and chunk_type != "design_constraint":
        return
    # iter1495: interrogative_causal_gate — 问句形式的因果链/推理链拒绝写入
    # 数据驱动（2026-05-11）：16 条 ac=0 causal_chain 中 5 条是对话追问/讨论：
    #   "这个 timing race 是否真实存在"、"好问题。上一个PR..."、"所以问题是：..."
    #   问句是对话过程而非可重用因果推理，写入只增噪。
    if chunk_type in ("causal_chain", "reasoning_chain") and not content_override:
        if re.search(r'[？?]\s*$', summary.rstrip()) or re.match(r'^(?:好问题|所以问题是)', summary.lstrip()):
            return
    # iter1508: task_execution_status_gate — 任务执行状态/进度报告拦截
    # 数据驱动（2026-05-11）：4 条 ac=0 chunk 是任务执行快照而非可复用知识：
    #   "手动触发的 /lore-track 执行了"、"下次定时执行时才会完整跑通"、"#2 merged"、"PR 状态 🗄️"。
    #   特征：含执行动作词 + 时效性进度状态，无可泛化因果/决策。
    if chunk_type in ("causal_chain", "decision", "reasoning_chain") and not (content_override and content_override.strip() != summary.strip()):
        if re.search(
            r'手动触发|执行了\s*\w+\s*部分|下次.*执行|定时执行|'
            r'(?:—|──)\s*merged|^\s*[✅❌🗄️⏳]+\s*#\d+\s+\S+.*(?:merged|closed|open)|'
            r'PR\s*状态|子会话.*跑通|forked\s*子会话',
            summary, re.IGNORECASE):
            return
    # iter1496: constraint_semantic_require — 无 content_override 的短 design_constraint 必含约束语义词
    # 数据驱动（2026-05-11）：SWAPPED 4f438de1 "（PROC_EVENT_EXEC 时..."(57字) + 5d1583a6 "fix（最小..."(56字)
    #   content==summary、无约束动词，是对话碎片被误标 constraint。绕过路径：
    #   content_override=None → _co_is_echo=False → 跳过 constraint_echo_semantic_gate。
    # 修复：无 rich content 的 design_constraint <=80 字时，要求含约束语义词。
    _has_rich_co = content_override and content_override.strip() != summary.strip()
    if chunk_type == "design_constraint" and not _has_rich_co and len(summary) <= 80:
        if not re.search(
            r'必须|禁止|不得|不能|不要|不可|应该|shall|must|never|always|禁用|强制|仅用|'
            r'不允许|只能|才能|不应|cannot|should not|do not|don.t|avoid',
            summary, re.IGNORECASE):
            return
    # iter1293: episodic_short_fragment_gate — 短于 80 字的 episodic chunk 拒绝写入
    # 数据驱动（2026-05-09）：14 条 ac=0 噪声全 <80 字且无 content_override。
    #   如 "Gap 1：飞轮的...闭环没有打通"(22字)、"所以第一性原理下的..."(14字)。
    #   design_constraint 除外（天然短句但有明确约束语义）。
    # iter1377: echo_aware_episodic_gate — content_override==summary 时不豁免
    #   数据驱动（2026-05-10）：ba436dc5 reasoning_chain 36字 content==summary ac=0。
    _EPISODIC_SHORT_TYPES = {"causal_chain", "reasoning_chain", "decision", "excluded_path", "conversation_summary"}
    _episodic_has_rich = content_override and content_override.strip() != summary.strip()
    # iter1515: episodic_echo_threshold_widen — 80→100 字拦截 content==summary 碎片
    # 数据驱动（2026-05-11）：f7165539(87字 causal_chain) 逃逸 80 字阈值，ac=0。
    _echo_threshold = 100 if not _episodic_has_rich else 80
    if not _episodic_has_rich and chunk_type in _EPISODIC_SHORT_TYPES and len(summary) <= _echo_threshold:
        return
    # iter844: table_fragment_gate — 表格行碎片拒绝写入
    # 数据驱动（2026-05-05）：e0bd5a39 content="| extractor gate 覆盖 | ... |"
    #   是 markdown 表格行碎片（44字，绕过 <15 阈值），ac=2 但零用户价值。
    #   被 retriever 连续 2 次单条注入，挤占了有价值知识的注入配额。
    # 修复：无 content_override 时，summary 以 '|' 开头 → 表格碎片 → 拒绝。
    if not content_override and summary.lstrip().startswith('|'):
        return
    # iter1292: leading_fragment_gate — 拦截从中间截断的句子碎片
    # 数据驱动（2026-05-09）：15f2c1cf "用，不是 Agent 自驱。飞轮需要：..." ac=0
    #   以单字+标点开头，表明从更长文本中间截取。
    # 修复：以 CJK单字+标点 或 纯标点 开头 → 截断碎片 → 拒绝。
    # iter1300: closing_quote_fragment — 右引号/括号开头也是截断碎片
    #   数据驱动（2026-05-09）：fc51691c "」作为占位..." ac=0，从引号句中间截取。
    if not content_override and re.match(r'^[」」）\)》\]】][^A-Z]', summary.lstrip()):
        return
    if not content_override and re.match(r'^[一-鿿][,，、;；:：]', summary.lstrip()):
        return
    # iter1369: bare_colon_prefix_gate — 全角冒号开头 = 从"标题：内容"截取了冒号后半段
    # 数据驱动（2026-05-10）：315ff97c "：local_sparse..." ac=0，从更长描述截断。
    if not content_override and summary.lstrip().startswith('：'):
        return
    # iter966: cmdline_fragment_gate — 命令行参数碎片拒绝写入
    # 数据驱动（2026-05-06）：8d3918ac "-in-reply-to=\"<20260429...\"" 逃逸所有 gate。
    # 特征：以 - 或 -- 开头的 CLI flag 格式，无知识价值。
    if not content_override and re.match(r'^-{1,2}[\w-]+=', summary.lstrip()):
        return
    # iter1096: sysdata_fragment_gate — 命令输出数值快照拒绝写入
    # 数据驱动（2026-05-07）：10 条 ac=0 噪声是命令输出（KB/GB/mm_stat/SwapFree 等），
    #   无跨会话决策价值，仅为一次性诊断快照。
    # 修复：含数值+存储单位且无决策动词 → 纯数据碎片 → 拒绝。
    if not content_override and re.search(
            r'(?:\d+\s*(?:KB|kB|MB|GB|TB|bytes)|\bmm_stat\b|Swap(?:Total|Free|Cached))', summary) \
       and not re.search(r'(?:应该|必须|决定|选择|改为|方案|建议|原因|因为|所以|优化|问题)', summary):
        return
    # iter1007: write_chunk_quality_gate — 统一入口质量门控
    # 根因（数据驱动，2026-05-06）：11 个 ac=0 噪声 chunk 全部通过 _is_quality_decision
    #   （含百分比数字即通过）但实为迭代器内部调参记录（"suppress 率：70%→26%"）。
    #   _is_quality_chunk 的 noise_kw 列表已能拦截，但 _write_chunk 入口未调用。
    #   extractor_pool(line 427) 有独立调用，extractor.py 各路径不统一。
    # 修复：_write_chunk 入口统一调用 _is_quality_chunk，作为最后防线。
    if not _is_quality_chunk(summary[:120]):
        return
    # iter984: ephemeral_realtime_gate — 实时行情/股票数据拒绝写入
    # 数据驱动（2026-05-06）：c05860a8 "创业板指 5日涨幅 -1.16%≤1%，跳过扫描"
    #   是纯实时市场数据快照，隔天即无效，无持久知识价值。
    # iter1080: realtime_gate_widen — 正则放宽，关键词+百分比共现即拦截
    # 根因（数据驱动，2026-05-07）：fedc79ef "创业板指 5 日涨幅 +3.01%..." 逃逸，
    #   因 "创业板" 后不紧跟数字（中间隔 "指 5 日涨幅"）。
    # 修复：关键词和百分比数值在同一 summary 中共现即拦截（不要求紧邻）。
    if re.search(r'(?:创业板|上证|深证|沪深|涨幅|跌幅|日线|K线|形态识别|通过硬过滤|换手率|成交额|连板|缩量回踩|放量反弹)', summary) \
       and re.search(r'[-+]?\d+\.?\d*%|→\d+|\d+只', summary):
        return
    # iter1097: device_data_snapshot_gate — 纯设备数据输出/proc stats 碎片拒绝
    # 数据驱动（2026-05-07）：16 个 ac=0 chunk 全是 zram/swap/RAM 配置读出，
    #   如 "SwapTotal: 2050496 kB"、"zram mm_stat: 4096/64/20480"、"RAM：3.6GB"。
    #   特征：含内存/存储单位关键词 + 数值参数，无推理结论。
    # 修复：检测 proc/sys 数据快照模式 → 拒绝。不影响含分析结论的 chunk。
    if chunk_type in ("decision", "causal_chain") and not content_override:
        if re.search(r'(?:kB|KB|MB|GB|mm_stat|SwapTotal|SwapFree|MemTotal|MemFree|zram\w*[：:])', summary) \
           and re.search(r'\d', summary) \
           and not re.search(r'(?:根因|原因|所以|因此|说明|表明|意味着|证明|意味|导致)', summary):
            return
    # iter1336+1415: truncated_fragment_gate — 截断碎片拦截
    # 原 iter1336 用 "小写 ascii 开头" 判断截断，误杀 cgroup/task_rq_lock/git/memory 等合法术语。
    # iter1415 修正：截断碎片特征=小写开头且首 token<3 字符（如 "ng（"/"ed "），完整单词不拦截。
    _stripped_summ = re.sub(r'^[-•*]\s*', '', summary)
    if _stripped_summ and _stripped_summ[0].islower() and _stripped_summ[0].isascii():
        _first_token = re.match(r'[a-z_]+', _stripped_summ)
        if _first_token and len(_first_token.group()) < 3:
            return
    # iter1228: quantitative_selfeval_gate — 迭代器量化自评前缀直接拦截
    # iter1231: iter_prefix_gate — iter\d{3,4}: 开头必为迭代器自记录
    # iter1233: iter_action_prefix_widen — 扩展前缀覆盖"量化结果/改动/预期效果/修复：/净增"
    # iter1316: list_prefix_tolerance — 允许可选的 markdown 列表前缀 "- "/"* "/"• "
    #   根因（数据驱动，2026-05-09）：d5fe4a0e "- 预期效果：ac=3 chunk..." 以列表前缀开头
    #   绕过 ^预期效果 匹配逃逸写入。迭代器输出常带列表前缀。
    if re.match(r'^(?:[-•*]\s*)?(?:量化结果[：:]|量化[：:改预效]|改动[：:]|预期效果[：:]|修复[：:]|净增|iter\d{3,4}\s*[：:_])', summary):
        return
    # iter1442: rootcause_iter_gate — "根因：/数据驱动根因：" + 内部指标 = 迭代器诊断报告
    #   数据驱动（2026-05-10）：5 条 ac=0 thin chunk 含 "kernel" 触发 DOMAIN_KW 豁免 iter1202，
    #   但实为迭代器分析报告（"25 次注入 100% 为不相关 kernel chunk"），非 kernel 技术知识。
    # 修复：检测"根因"前缀 + memory-os 内部指标共现 → 拦截（不检查 DOMAIN_KW）。
    if re.match(r'^(?:[-•*]\s*)?(?:数据驱动)?根因[：:]', summary) \
       and re.search(r'(?:注入|chunk|score|suppress|召回|FTS|relevance|ac[>=]|cold\s*chunk|veteran)', summary):
        return
    # iter1332: problem_statement_iter_gate — "问题：" + 系统指标 = 迭代器自诊断
    if re.match(r'^(?:[-•*]\s*)?问题[：:]', summary) \
       and re.search(r'(?:\d+%|注入|chunk|召回|suppress|score|gate|fallback|ac=|7d|24h)', summary):
        return
    # iter1341: data_statement_iter_gate — "数据：" + 系统指标 = 迭代器自诊断
    if re.match(r'^(?:[-•*]\s*)?数据[：:]', summary) \
       and re.search(r'(?:\d+%|注入|chunk|召回|suppress|score|gate|fallback|ac=|7d|24h|content|summary|iter\d{3,4})', summary):
        return
    # iter1342: quant_prefix_iter_gate — "量化：" 前缀 + 系统指标 = 迭代器自诊断
    if re.match(r'^(?:[-•*]\s*)?量化[：:]', summary) \
       and re.search(r'(?:\d+%|注入|chunk|召回|suppress|access|zero|gate|fallback|ac=|7d|24h)', summary):
        return
    # iter1342: short_title_iter_gate — <=10字纯标题 + 含 memory-os 内部概念 = 噪声
    if len(summary) <= 20 and re.search(r'(?:extractor|retriever|写入质量|注入质量|suppress|chunk)', summary):
        return
    # iter1343: iter_crud_ops_gate — 迭代器 CRUD 操作记录拦截
    # 根因（数据驱动，2026-05-10）：086163d3 "删除 4 条 access_count=0 的迭代器自诊断 chunk"
    #   逃逸原因：不以已拦截前缀开头，但本质是迭代器对 DB 的增删改操作日志。
    # 修复：检测 "删除/清理/新增/写入 N 条" + memory-os 内部术语共现 → 拒绝。
    if re.search(r'(?:删除|清理|新增|写入|移除)\s*\d+\s*条', summary) \
       and re.search(r'(?:chunk|access_count|迭代器|自诊断|zero_access|噪声|ac=|FTS)', summary):
        return
    # iter1447: scoring_phase_iter_gate — 评分/suppress 阶段描述 + 内部指标 = 迭代器实现细节
    if re.match(r'^(?:[-•*]\s*)?(?:\d+[.、]\s*)?(?:评分阶段|suppress 阶段|scoring)', summary) \
       and re.search(r'(?:relevance|score|chunk|suppress|注入|gate|→)', summary):
        return
    # iter1447: expectation_iter_gate — "预期：" + 系统指标 = 迭代器预期结论
    if re.match(r'^(?:[-•*]\s*)?预期[：:]', summary) \
       and re.search(r'(?:注入|chunk|suppress|score|降至|召回|gate|daemon|7d|24h|ac[>=])', summary):
        return
    # iter1447: iter_ref_prefix_gate — rNNNN/ 迭代引用前缀 = 迭代器因果链
    if re.match(r'^r\d{3,4}[/,]', summary) \
       and re.search(r'(?:gate|suppress|注入|chunk|irrelevance|daemon|score)', summary):
        return
    # iter1247: injection_stats_narrative_gate — 含注入统计叙事的迭代器量化结论
    # 根因（数据驱动，2026-05-09）：15e53f00(ac=0) "量化效果：过去 7d 的 16 次 global 注入中，
    #   6 次 score<0.25 的低相关性注入将被拦截（37.5% 降噪）"
    #   含 "kernel" → DOMAIN_KW 豁免 → iter1202 跳过。但 "N 次 X 注入" 是迭代器统计格式。
    # 修复：检测 "N 次.*注入" + "拦截/降噪/suppress/score" 共现 → 迭代器 meta → 拒绝。
    if re.search(r'\d+\s*次.*注入', summary) and re.search(r'(?:拦截|降噪|suppress|score[<>])', summary):
        return
    # iter1248: health_report_gate — 系统健康报告/PA结果拦截
    # 根因（数据驱动，2026-05-09）：6c2c1bd4(ac=0) "量化：zero_access 1.2%→0%, PA 10/10 HEALTHY, 假阳性 0/7"
    #   虽有 iter1144 prefix_gate 覆盖 "量化："，但 daemon 未 reload 时逃逸。
    #   defense-in-depth：含 "PA \d+/\d+" 或 "HEALTHY" + 度量格式 → 系统报告非用户知识。
    if re.search(r'(?:PA\s*\d+/\d+|HEALTHY|DEGRADED)', summary) and re.search(r'(?:\d+%|→|假阳性|precision|recall)', summary):
        return
    # iter1235: config_param_fragment_gate — 配置参数碎片拒绝
    # 数据驱动（2026-05-09）：3 个 ac=0 chunk 为纯配置值 "micro_db(≤5): 0.08" 等，
    #   逃逸 <15 阈值（18-19字）。特征：变量名+括号条件+冒号+数值，无解释。
    if not content_override and len(summary) < 30 \
       and re.match(r'^[\w_]+\s*[（(].{1,12}[）)]\s*[：:]\s*[\d.]+', summary):
        return
    # iter1235: internal_fix_log_gate — 内部修复/重建日志拒绝
    # 数据驱动（2026-05-09）："- 修复 FTS5 index（因删除操作导致 orphan 清理过度→重建对齐 ACTIVE=55）"
    #   以列表前缀开头 + 含内部子系统关键词 + 无用户领域知识 → 拒绝。
    if re.match(r'^\s*[-•]\s*(?:修复|重建|清理|对齐)', summary) \
       and re.search(r'(?:FTS5?|orphan|index|ACTIVE\s*=|对齐|chunk_version|writeback|daemon)', summary) \
       and not re.search(r'(?:kernel|sched|cpu|Android|飞书|git\s|用户|产品)', summary):
        return
    # iter1265: ai_metacognition_gate — AI 自我反思/元认知碎片拒绝
    if re.search(r'(?:我缺乏|我的推理是|正常人.*(?:会|的推理)|语言模型的典型|我[「""]知道[」""])', summary) \
       and not re.search(r'(?:必须|禁止|规则|约束|决策|结论[：:])', summary):
        return
    # iter1202: iterator_impl_gate — 拒绝写入迭代器/retriever/extractor 内部实现细节
    # 数据驱动（2026-05-08）：11 个 ac=0 chunk 全为迭代器自身的调参/bug/fix 记录
    #   （"suppress 率"、"空召回"、"relevance_floor"、"候选全被过滤"），用户永远不会检索这些。
    # 修复：summary 含 retriever/extractor 内部关键词 + 无外部领域知识 → 拒绝。
    _ITER_IMPL_KW = re.compile(
        r'(?:suppress|空召回|relevance.?floor|候选.*(?:过滤|全灭)|fallback.*注入|'
        r'iter\d{3,4}|hard.?cap|session.?inj|7d.?(?:阈值|thresh|注入)|'
        r'24h.?(?:burst|阈值)|_score_chunk|_write_chunk|extractor.*gate|'
        r'recall_count|bw_window|anti.?monopoly|注入配额|注入频次|注入\s*slot|释放.*注入|'
        r'FTS5?\s*(?:噪声|命中率|candidate)|candidate\s*池|'
        r'zero.?access|注入.*比例|注入率|注入仅\s*\d|注入\s*score|单条注入|diversity.?pair|production_assertions|'
        r'HEALTHY|chunk.*阈值.*触发|inject.*cap|cooldown.*escalat|'
        r'垄断\s*chunk|低频高价值|预期效果.*(?:注入|suppress|召回)|'
        r'注入仅含|(?:\d+\s*条\s*chunk|\d+\s*chunks).*(?:阈值|项目|库)|'
        r'[+\-]\d+\s*行.{0,10}[+\-]\d+\s*行|'
        r'迭代器.*(?:逃逸|自记录|gate)|_DOMAIN_KW|_ITER_IMPL|iterator_impl|'
        r'碎片.*逃逸.*gate|\w+_gate\s*[（(]|ACTIVE\s*\d+\s*→\s*\d+|PA\s*\d+/\d+|'
        r'gate.*(?:部署|覆盖|deploy)|时序问题.*(?:gate|写入)|'
        r'IOR.*豁免|豁免.*(?:注入|降分|suppress)|不降分|注入垄断.*根因)',
        re.IGNORECASE)
    _DOMAIN_KW = re.compile(
        r'(?:kernel|sched|cpu|proxy|\bPE\b|binder|Android|飞书|feishu|git(?![:r]oot:|:[0-9a-f])|patch|commit|'
        r'migration|thermal|uclamp|内存|进程|线程|设备|用户|产品|API|接口|函数)',
        re.IGNORECASE)
    _iter_match = _ITER_IMPL_KW.search(summary)
    # iter1450: domain_kw_density_override — domain_kw 豁免在 memory-os 术语密度≥3 时失效
    # 数据驱动（2026-05-11）：4 条 ac=0 噪声含 "barrier/on_cpu/find_proxy"（domain_kw）
    #   同时含 "suppress/注入位/去重/垄断/top_k/chunk"（memory-os 术语）。
    #   根因：1 个 domain_kw match 即可豁免，但内容主体是 memory-os 实现分析。
    # 修复：memory-os 术语 ≥3 个时 domain_kw 不再豁免。
    _MOS_DENSITY_TERMS = re.compile(
        r'(?:suppress|注入位|去重|垄断|top.k|注入.*阈值|chunk.*(?:保留|丢弃|上限)|'
        r'per.chunk|session.suppress|anti.monopoly|空召回|cooldown|'
        r'IOR|豁免|不降分|注入垄断)',
        re.IGNORECASE)
    _mos_density = len(_MOS_DENSITY_TERMS.findall(summary))
    if _iter_match and (_mos_density >= 3 or not _DOMAIN_KW.search(summary)):
        return
    # iter1269: memory_os_file_selfref_gate — 含 memory-os 源文件名的自引用强制拦截
    # 根因（数据驱动，2026-05-09）：4 条 ac=0 噪声含 "retriever.py"/"config.py" + memory-os
    #   内部概念（tunable/session_injected/oversample_factor），因 "用户"/"进程" 触发
    #   DOMAIN_KW 误豁免 iter1202。memory-os 源文件名 + 内部术语共现 = 必定自引用。
    if re.search(r'(?:retriever\.py|retriever_daemon|extractor\.py|config\.py)', summary) \
       and re.search(r'(?:tunable|session_inject|oversample|_sessions_with|same_hash|TLB.*保护|'
                     r'daemon.*崩溃|零知识注入|hook.*崩溃|chunk_recall|recall_trace)', summary):
        return
    # iter1450: chunk_mgmt_strategy_gate — 拦截讨论 chunk 去重/管理策略的迭代器分析
    # 数据驱动（2026-05-11）：832c22a9/566287c9 含 "[pe_analysis]" domain_kw 豁免 iter1202，
    #   但内容是 "强制 1 条去重导致用户查询...单一维度知识"——讨论 topic_dedup 策略。
    # 修复：chunk + 去重/dedup/上限/保留/垄断 策略词 ≥2 共现 → 拒绝。
    _CHUNK_MGMT = re.compile(
        r'(?:去重|dedup|上限\s*\d|保留.*最高|垄断.*注入|注入位|chunk.*轮番|per.chunk|同主题|单一维度)',
        re.IGNORECASE)
    if re.search(r'chunk', summary, re.IGNORECASE) and len(_CHUNK_MGMT.findall(summary)) >= 2:
        return
    # iter1210: iterator_meta_narrative_gate — 迭代器自身 bug/fix 元叙述即使含领域词也拦截
    if _iter_match and re.search(r'(?:迭代器.*(?:逃逸|自记录|假阳性)|让迭代器|iterator.*gate.*逃)', summary):
        return
    # iter1244: iterator_quantification_gate — 迭代器量化总结/执行结果拦截
    # 根因（数据驱动，2026-05-09）：9 个 ac=0 chunk 全为迭代器运行总结：
    #   "量化：zero_access 10%→0%"、"注入垄断已被 iter1232-1242 覆盖"、"FTS5 同步 57→55"
    #   特征：含 iter\d{3,4} 引用 + 系统指标词（或纯系统指标百分比变化）。
    if re.search(r'iter\d{3,4}', summary) and re.search(
            r'(?:覆盖|gate|suppress|zero_access|passed|HEALTHY|precision|一致性|'
            r'exempt|tighten|豁免|收紧|放宽|阈值|thresh)', summary):
        return
    # iter1485: iter_status_density_gate — memory-os 运维指标高密度 = 迭代器状态报告
    # 数据驱动（2026-05-11）：12 条 ac=0 噪声逃逸所有 gate，共同特征是
    #   含 ≥2 个 memory-os 运维指标词且不含用户领域知识。
    _MOS_STATUS_KW = re.compile(
        r'(?:ACTIVE\s*\d|DEAD|空召回|覆盖率|HEALTHY|DEGRADED|'
        r'ac[=≥]\s*0|zero.access|注入分布|分布合理|注入覆盖|'
        r'FTS\s*(?:索引|删除|重建)|chunk.?(?:标记|DEAD|SWAPPED)|'
        r'PA\s*\d+/\d+|production_assertions|'
        r'FULL\s*路径|daemon\s*查询失败)',
        re.IGNORECASE)
    if len(_MOS_STATUS_KW.findall(summary)) >= 2 and not _DOMAIN_KW.search(summary):
        return
    if re.search(r'(?:zero_access|chunk_count|tests?\s*passed|FTS5?\s*(?:索引|有效率)|一致性\s*\d+%|Active\s*pool)', summary):
        return
    # iter1311: quantification_summary_gate — "量化：X% → Y%" 格式必为迭代器执行结果
    if re.match(r'^\s*量化[：:]', summary):
        return
    # iter1357: action_prefix_iter_gate — 迭代器动作前缀 + 系统指标 = 执行日志
    if re.match(r'^\s*(?:清理|部署|同步|回滚|重建)[：:]', summary) \
       and re.search(r'(?:chunk|ac=|access|zero_access|FTS|gate|suppress|注入|召回|噪声)', summary):
        return
    # iter1243: iterator_stats_gate — 含 ac=/注入 N 次/7d= 统计标记的必为迭代器 meta
    # 根因（数据驱动，2026-05-09）："import-90139（PE barrier 知识）ac=3 却被周注入 6 次的垄断问题"
    #   含 \bPE\b 触发 DOMAIN_KW → iter1202 gate 跳过。但 "ac=3" 和 "注入 6 次" 是
    #   迭代器统计标记，真正的 PE 技术知识不会含 "ac=\d" 格式。
    # 修复：summary 含 retriever 统计格式标记 → 直接拦截（不检查 DOMAIN_KW）。
    if re.search(r'(?:\bac[=＝]\d|被.*注入.*\d+\s*次|7d[=＝]\d|周注入\s*\d)', summary):
        return
    # iter1309: chunk_count_project_stats_gate — "N-chunk 项目/库" 格式是迭代器统计
    # 根因（数据驱动，2026-05-09）：0647ccd6/bdae9fba(ac=0) "21-chunk kernel 项目 46% 空召回率..."
    #   含 "kernel" 触发 DOMAIN_KW 豁免 iter1202。但 "\d+-chunk.*项目" 是迭代器统计格式，
    #   真正的 kernel 技术知识不会以 "N-chunk 项目" 开头描述自己。
    if re.search(r'\d+-chunk\s*\S*\s*(?:库|项目)', summary):
        return
    # iter1361: injection_metric_narrative_gate — 含注入频次度量语言的迭代器 meta 叙述
    # 根因（数据驱动，2026-05-10）：62a83e1e/8864d5a2(ac=0) "三个 global constraint 各
    #   7d 注入 4 次，合计占 34.7% 注入位" 逃逸全部 gate：
    #   - iter1243 要求 "被.*注入" 或 "ac=" 前缀，此文无 "被" 无 "ac="
    #   - iter1247 要求 "拦截/降噪/suppress/score<>"，此文无
    #   真正用户知识不会用 "注入 N 次"/"占 N% 注入位" 度量语言。
    if re.search(r'(?:注入\s*\d+\s*次|占\s*\d+[\d.]*%\s*注入|7d\s*注入)', summary) \
       and re.search(r'(?:constraint|chunk|注入位|注入配额|阈值|逃逸|suppress|global)', summary):
        return
    # iter1321: tunable_param_change_gate — retriever/extractor 调参记录拦截
    # 根因（数据驱动，2026-05-09）：iter1320 写入 5 条 ac=0 噪声 chunk 描述 DC type_concentration
    #   参数调整（"DC 类 factor 0.7→0.5"、"DC 注入占比 55%→25%"）。
    #   iter1202 的 _ITER_IMPL_KW 未覆盖 "DC"（design_constraint 缩写）和 tunable 参数变更格式。
    # 修复：检测 DC/design_constraint 的迭代调参叙述 + tunable 参数箭头变更格式。
    if re.search(
            r'(?:\bDC\b.*(?:注入|占比|衰减|垄断|suppress)|type_concentration|'
            r'design_constraint\s*(?:群体|垄断|占|衰减)|'
            r'(?:penalty|factor|阈值|门槛|threshold)\s*[\d.]+\s*→\s*[\d.]|'
            r'(?:fallback|suppress|cooldown).*(?:排除|门槛).*\d+\s*→\s*\d+|'
            r'dc_type_conc|_tighten|_widen)', summary):
        return
    # iter1249: system_self_assessment_gate — 系统自我评估/健康声明拦截
    # 数据驱动（2026-05-09）：f2588920(ac=0) "系统整体健康：87% 7d 覆盖率，cooldown 正常工作，无垄断复发"
    #   全部现有 gate 未能匹配：cooldown 需 escalat 后缀，垄断需 chunk 后缀，覆盖率无 gate。
    # 修复：系统健康自评关键词（覆盖率/cooldown/垄断复发/正常工作）+ 无领域知识 → 拒绝。
    if re.search(r'(?:覆盖率|cooldown|垄断(?:复发|率|问题)|系统.*健康|正常工作|无.*复发)', summary) \
       and not _DOMAIN_KW.search(summary):
        return
    # iter1208: execution_status_gate — 执行状态日志/流水账拒绝写入
    # 数据驱动（2026-05-08）：3 个 ac=0 chunk 全为执行流水账：
    #   "Jira FDS trace 解析完成 issue=292604, 220052 chars — 220KB 内容传给 LLM"
    #   "— zip 已缓存，直接用"  "| 附件下载异常...| 加 try/except 包住"
    #   特征：含执行结果描述词（完成/缓存/传给/写入/下载）+ 无因果推理词 → 拒绝。
    if re.search(r'(?:解析完成|已缓存|传给\s*LLM|写入完成|下载完成|chars\b|bytes\b|\d+\s*KB\s*内容)', summary) \
       and not re.search(r'(?:根因|原因|所以|因此|说明|表明|导致|决策|约束|必须|禁止)', summary):
        return
    # iter1210: code_fix_action_gate — 纯代码修复动作描述拒绝
    if re.search(r'(?:加\s*try.?(?:except|catch)|(?:try|except|catch).*包住|异常未捕获.*加)', summary) \
       and not re.search(r'(?:根因|设计|架构|约束|原则|陷阱|必须|禁止)', summary):
        return
    # iter1098: url_only_summary_gate — 纯 URL summary 拒绝写入
    # 数据驱动（2026-05-07）：8f95425e conversation_summary 仅含 feishu URL（ac=0），
    #   FTS5 无法语义匹配 URL 字符串，检索价值为零。
    if re.match(r'^https?://\S+$', summary.strip()):
        return
    # iter1271: git_ref_snapshot_gate — 纯 git hash/origin 状态快照拒绝
    if re.search(r'(?:origin\)?[：:]\s*[0-9a-f]{6,}\.\.[0-9a-f]{6,}|^\s*-\s*GitLab|^\s*-\s*GitHub)', summary):
        return
    # iter985: en_short_fragment_gate — 纯英文短碎片 design_constraint 拒绝
    # 数据驱动（2026-05-06）：c61eaecc "need SCX_TASK_OFF_TASKS"(4词)、
    #   c60d1009 "and the existing sched_ext_dead() handles..."(英文对话片段)。
    #   无 content_override 的纯英文 chunk <50字 = 缺乏独立语义的邮件/对话碎片。
    if not content_override and len(summary) < 50 and not re.search(r'[\u4e00-\u9fff]', summary):
        return
    # iter961: summary_min_density_gate — 无 content_override 时 summary 过短拒绝
    # 根因（数据驱动，2026-05-06）：2 条 design_constraint ac=0（"内核 panic，不需要 counter"
    #   20字 / "- 这是 Tejun 明确要求的，无推断" 16字）通过 <15 门控但检索价值极低。
    #   无 content_override 时 content=[chunk_type]+summary，过短 chunk FTS 命中率趋近 0。
    # 修复：无 content_override 时 summary < 30 → 拒绝。有 content_override 时不受影响。
    # iter1220: decision_min_density_raise — decision 类型提高阈值 30→45
    # 数据驱动（2026-05-09）：4 条 decision 碎片（30-43字, ac<=2, content≈summary）逃逸：
    #   "v3 加的 SCX_TASK_OFF_TASKS 不是必要的"(30c)、"没找到时，必须去 upstream 确认"(43c)。
    #   孤立判断无上下文，FTS 检索命中后缺乏可操作信息。
    _min_density = 45 if chunk_type == "decision" else 30
    if not content_override and len(summary) < _min_density:
        return
    # iter1103: content_override_min_gate — content_override 路径也需最小长度
    # 根因（数据驱动，2026-05-07）：00bce5d7 conversation_summary content_override=14字
    #   "云端 Claude 怎么启动"（纯疑问句碎片），绕过 summary<30 gate（该 gate 只拦无 override）。
    #   content_override 路径由 conv_summary/causal_chain 聚合调用，
    #   聚合后仍 <30 字说明输入源本身就是不可独立检索的碎片。
    # 修复：content_override 非空时检查其长度 <30 → 拒绝。
    if content_override and len(content_override.strip()) < 30:
        return
    # iter607: _write_chunk 内置 quality gate — 最终防线
    # 根因（数据驱动，2026-05-03）：causal_chain/decision 绕过调用方的 _is_quality_chunk
    # 检查直接写入 store（6 个零访问迭代器噪声 chunk 在 gate 部署前写入）。
    # 修复：在 _write_chunk 内部统一检查，任何路径都无法绕过。
    if not _is_quality_chunk(summary):
        return
    # iter965: causal_reasoning_fragment_final_gate — 终极碎片拦截
    # 根因（数据驱动，2026-05-06）：extractor_pool 路径的 iter956 gate 在部署前写入 13 条碎片。
    #   iter836 在 extractor.py 的 _qualified_chains 路径有效，但 pool 路径和未来路径无法保证。
    # 修复：_write_chunk 内统一拦截 causal_chain/reasoning_chain <120 字 + 结论词开头碎片。
    #   有 content_override 且确实包含额外内容时才豁免（邻节点聚合 rich content）。
    # iter970: content_echo_bypass_fix — content_override==summary 时视同无 override
    #   根因（数据驱动，2026-05-06）：21 条碎片 ac=0，content==summary 但因 content_override
    #   参数非空绕过 <120 gate。修复：比较实际内容，echo 时不豁免。
    _has_rich_content = content_override and content_override.strip() != summary.strip()
    # iter999: excluded_path_gate_sync — excluded_path 纳入同等 <120 gate
    # 数据驱动（2026-05-06）：010d34ee excluded_path "67% 候选导致 rotation 全部失败→hash 锁定"
    #   52 字系统内部分析，逃逸 causal/reasoning gate（不在检查范围），ac=0 零用户价值。
    if chunk_type in ("causal_chain", "reasoning_chain", "excluded_path") and not _has_rich_content:
        _s_stripped = summary.strip()
        if re.match(r'^(?:所以|因此|故此|于是|故而|答案[：:]|总结[：:])', _s_stripped):
            return
        if len(_s_stripped) < 120:
            return
    # iter1183: decision_conversational_fragment_gate — decision 对话碎片拦截
    # 根因（数据驱动，2026-05-08）：session 5370cd43 写入 5 条 ac=0 decision，
    #   以对话口语前缀开头（"但测试结果…"、"而且…"、"有一个统计陷阱…"），
    #   是推理过程的中间步骤而非独立决策结论。
    #   iter965 的 <120 gate 仅覆盖 causal_chain/reasoning_chain/excluded_path，
    #   decision 类型逃逸导致同一对话碎片以不同 chunk_type 入库。
    # 修复：decision 类型 + 对话前缀 + <120 字 + 无 rich content → 拒绝。
    #   不影响有 content_override 的 wiki import 决策或长篇独立决策陈述。
    if chunk_type == "decision" and not _has_rich_content:
        _s_stripped_d = summary.strip()
        if len(_s_stripped_d) < 120 and re.match(
            r'^(?:\d+\.\s*)?(?:所以|因此|但[是]?|而且|或者|之前|有一个|如果是|对[，,]|问题[：:])',
            _s_stripped_d):
            return
    # iter1272: opinion_without_anchor_gate — 纯观点句拒绝写入
    # 根因（数据驱动，2026-05-09）：5 个 ac=0 decision，content==summary <80字，
    #   如 "这不是X问题"、"用户随时打断，这不是真问题"、"Agent OS 调度编排的现状与机会"。
    #   纯粹对话中的观点/判断/标题，无技术锚点，不可独立检索。
    # 修复：decision + 无 rich content + <80字 + 无技术锚点(API/函数/工具/配置/数值) → 拒绝。
    if chunk_type == "decision" and not _has_rich_content:
        _s_owa = summary.strip()
        if len(_s_owa) < 80 and not re.search(
            r'(?:[a-z_]{2,}\(|[A-Z][a-z]+[A-Z][a-z]|_[a-z]{2,}_|'  # func() / CamelCase / snake_case
            r'\b(?:api|cli|sdk|hook|gate|config|param)\b|'  # tool/tech terms
            r'\d+\s*(?:ms|us|ns|MB|KB|%|次/|条)|'  # numeric metrics
            r'(?:必须|禁止|规则|强制|不得|应当))',  # actionable directives
            _s_owa):
            return
    # iter1105: iter_progress_report_gate — 迭代器进度汇报拒绝写入
    # 根因（数据驱动，2026-05-07）：3 个 ac=0 decision chunk 是迭代器向飞书 append 的
    #   进度条目（"PA 10/10"、"2. 47% 零访问 → ✅ 当前仅 12%"），
    #   逃逸 selfref_gate（hits<2）和 iter_metric_report_gate（无 N→M 格式）。
    #   共性：含 PA 评分 / 序号+✅ 进度标记 / "测试零新增" 断言结果。
    # 修复：结构性模式检测，仅对 decision 类型生效。
    if chunk_type == "decision" and re.search(
        r'(?:PA\s*\d+/\d+'
        r'|^\d+\.\s.*[→✅]'
        r'|测试零新增失败'
        r'|零访问.*当前仅)',
        summary, re.M
    ):
        return
    # iter1193: iter_prefix_hardkill — "iterN" 开头的 summary 直接拒绝
    # iter1334: iter_prefix_widen — iter\d{2,4}\b 覆盖 "iter1333 总结：" 等变体逃逸
    if re.match(r'^iter\d{2,4}\b', summary):
        return
    # iter1085: internal_selfref_gate — 纯系统自描述 chunk 拒绝写入
    # 根因（数据驱动，2026-05-07）：4 个 ac=0 噪声逃逸 iter_metric_report_gate，
    #   因无指标变化模式（N→M）但含 ≥2 个系统内部术语（_score_chunk/suppress/候选全灭等）。
    #   iter_metric_report_gate 仅在 _has_metric_pattern 时才检查内部术语，遗漏纯文字描述。
    # 修复：独立 gate — summary 含 ≥2 个内部术语且无外部领域锚点 → 拒绝。
    #   对 decision/reasoning_chain/causal_chain/excluded_path 生效。
    # iter1094: selfref_gate_cn — 补充中文内部术语覆盖
    # 根因（数据驱动，2026-05-07）：3 个 ac=0 噪声 chunk 逃逸 —
    #   "高 ac chunk 每 14d 循环重获注入资格"(excluded_path,hits=0)
    #   "量化预期：global ac>=5 chunk 7d 注入从 4 次降至 ≤1 次"(decision,hits=0)
    #   问题：excluded_path 不在检查范围 + 中文"注入/chunk/7d"未匹配。
    # 修复：扩展 type + 补充中文术语。
    # iter1117: pool_selfref_gate_sync — 使用独立函数（与 extractor_pool 共用）
    if _is_selfref_noise(summary, chunk_type):
        return
    # iter1561: qe_selfref_gate — quantitative_evidence 类型的 retriever 内部指标拦截
    # 数据驱动（2026-05-12）："W18 空召回率 46%，W17 69%" / "7d write survival: 5/70 = 7%"
    #   quantitative_evidence 不在 _is_selfref_noise 范围（高保护类型），但含空召回/存活率/
    #   ACTIVE 池统计的内部指标仍逃逸。用高阈值（>=2 内部术语 + 无外部锚点）避免误杀。
    if chunk_type == "quantitative_evidence" and re.search(
        r'(?:空召回|存活率|write.?survival|ACTIVE\s*(?:池|chunk)|DEAD\b|SWAPPED\b|'
        r'W\d+\s*(?:空召回|注入|inject)|注入率|suppress|零访问率|ac=0\s*率)',
        summary
    ) and not re.search(
        r'(?:kernel|sched|CPU|Android|uclamp|cgroup|latency|P\d+|延迟|功耗|帧率)',
        summary, re.I
    ):
        return
    # iter1109: code_change_report_gate — 拦截代码改动描述和测试验证结果
    # 数据驱动（2026-05-07）：6 个 ac=0 decision chunk 逃逸 selfref_gate（hits<2），
    #   包括 "改动：extractor.py +21 行"、"正例：LCS=98% → 拦截 ✅"、"负例：<5% → 放行 ✅"。
    #   共性 A：描述代码文件改动（含 .py/.js/.ts + 行数/函数名）—— 纯实现日志。
    #   共性 B：测试验证标记（正例/负例 + ✅/拦截/放行）—— 一次性验证结果。
    # 修复：两个独立模式，任一命中 → 拒绝。仅对 decision 类型，不影响 procedure/qe。
    if chunk_type == "decision" and not content_override:
        # A: 代码改动描述 — "文件名.ext +N 行" 或 "文件名.ext 函数名"
        if re.search(r'\.(?:py|js|ts|rs|go|java|c|h)\b.*(?:\+\d+\s*行|[-+]\d+)', summary):
            return
        # B: 测试验证标记 — 正例/负例 + 通过标记
        if re.search(r'(?:正例|负例|测试[：:])', summary) and re.search(r'[✅✓→]', summary):
            return
    # iter897→1118: iter_metric_report_gate — 拦截迭代器数值对比/统计报告
    # iter1118: 提取为 _is_metric_report_noise() 可复用函数，与 extractor_pool 共用。
    if _is_metric_report_noise(summary, chunk_type):
        return
    importance_map = {
        "decision": 0.85,
        "reasoning_chain": 0.80,
        "excluded_path": 0.70,
        "quantitative_evidence": 0.90,  # 量化证据：最不可重建，高保护
        "causal_chain": 0.82,           # 因果链：与 reasoning_chain 同级但独立
        "procedure": 0.85,              # 可复用操作步骤/协议（wiki import 来源）
    }
    importance = importance_override if importance_override is not None else importance_map.get(chunk_type, 0.70)

    # iter1259: db_substring_dedup_gate — 跨 batch 子串去重
    # 根因（数据驱动，2026-05-09）：同一 session 不同 batch 产出同一信息的长/短表述，
    #   batch 内 token-overlap gate 无法跨 batch 拦截，3-4 对冗余 chunk 入库。
    # 修复：写入前查 DB 同 project 已有 chunk，子串包含关系 → 拒绝。
    if conn and project:
        _norm_new = re.sub(r'\s+', '', summary)
        if len(_norm_new) >= 15:
            _existing = conn.execute(
                'SELECT summary FROM memory_chunks WHERE project=? AND chunk_state=? LIMIT 200',
                (project, 'ACTIVE')).fetchall()
            for _row in _existing:
                _norm_ex = re.sub(r'\s+', '', (_row[0] or ''))
                if len(_norm_ex) < 15:
                    continue
                if _norm_new in _norm_ex or _norm_ex in _norm_new:
                    return

    # ── iter562: vma_validate — 写入时最终准入校验 ──────────────────────────────
    # OS 类比：Linux insert_vm_struct() — mmap 写路径最终关卡，拦截漏网碎片。
    if not _vma_validate(summary):
        return

    # ── iter534: io_uring SQE validation — 写入时内容密度验证 ──────────────────
    # OS 类比：Linux io_uring SQE flags validation (Jens Axboe, 2019) — 提交到 SQ 前
    # 验证 SQE flags 合法性，拒绝畸形请求浪费 ring buffer 槽位。
    # 根因：importance 按 chunk_type 分配（quantitative_evidence=0.90, design_constraint=0.95），
    # 但碎片内容（编号列表项、审计笔记、模糊短语）因含数字/技术词通过结构检查，
    # 获得高 importance + MLOCK_ONFAULT(-200) → 占据 Top-K 但永远不被检索命中。
    # 修复：在 importance 赋值后、写入前验证 summary 的信息密度，密度不足则降级。
    importance = _sqe_validate_importance(importance, summary, chunk_type)

    retrievability = 0.2 if chunk_type in ("reasoning_chain", "causal_chain") else 0.35

    tags = [chunk_type, project]
    if topic:
        tags.append(topic[:30])

    # 迭代324：content_override 允许调用方传入更丰富的检索内容（如因果链聚合）
    if content_override:
        content = content_override
    elif topic:
        content = f"[{chunk_type}|{topic}] {summary}"
    else:
        content = f"[{chunk_type}] {summary}"
    # iter1250: content_snippet_enrich — 无 content_override 时用 raw_snippet 扩展 FTS5 索引
    if not content_override and raw_snippet and raw_snippet.strip():
        _snippet_extra = raw_snippet.strip()[:200]
        if _snippet_extra not in content:
            content = f"{content}\n{_snippet_extra}"

    # 迭代100：ECC 置信度
    confidence = _calculate_confidence(chunk_type, summary)

    # 迭代300：三层路由
    info_class = _route_info_class(chunk_type, summary)
    # 迭代301：Ebbinghaus stability 初始值
    stability = importance * 2.0
    # ── iter392：Generation Effect — 主动生成类 chunk stability 加成 ──
    # Slamecka & Graf (1978): 自己生成的内容记忆留存率 +50%~+80%
    # agent 主动推理生成的 reasoning_chain/decision/causal_chain 受益于此效应
    # OS 类比：Linux CoW 触发后，进程私有页面加入 active_list（比继承页更高生成亲和性）
    try:
        from config import get as _cget
        if _cget("extractor.generation_boost_enabled"):
            _gen_types = set(t.strip() for t in
                             (_cget("extractor.generation_boost_types") or "").split(",") if t.strip())
            if chunk_type in _gen_types:
                _gen_factor = float(_cget("extractor.generation_boost_factor") or 1.2)
                stability = min(stability * _gen_factor, 365.0)
    except Exception:
        pass  # config 不可用时不影响主流程

    # 迭代306：raw_snippet 截断到 500 字
    raw_snippet = (raw_snippet or "")[:500]

    # iter503: Writeback Pressure — 写入反压
    # OS 类比：balance_dirty_pages_ratelimited() — 零访问率高时降级新 chunk importance
    try:
        from store_vfs import writeback_pressure as _writeback_pressure
        _wb_conn = conn if conn is not None else open_db()
        if conn is None:
            ensure_schema(_wb_conn)
        _wb = _writeback_pressure(_wb_conn, project, importance)
        if _wb["pressure_level"] != "none":
            importance = _wb["adjusted_importance"]
        if conn is None:
            _wb_conn.close()
    except Exception:
        pass

    # iter558: PELT — Per-Entity Load Tracking 写入准入折扣
    # OS 类比：Linux PELT (Vincent Guittot, 2012) — 按 sched_entity 历史利用率
    # 决定任务放置。低 util_avg 的 chunk_type importance 自动折扣。
    try:
        from store_mm import pelt_discount as _pelt_discount
        importance = _pelt_discount(project, chunk_type, importance)
    except Exception:
        pass

    # 迭代315：提取编码情境（Encoding Specificity, Tulving 1973）
    try:
        from store_vfs import extract_encoding_context as _extract_enc_ctx
        encoding_context = _extract_enc_ctx(summary)
    except Exception:
        encoding_context = {}

    chunk = MemoryChunk(
        project=project,
        source_session=session_id,
        chunk_type=chunk_type,
        info_class=info_class,
        content=content,
        summary=summary,
        raw_snippet=raw_snippet,
        tags=tags,
        importance=importance,
        retrievability=retrievability,
        stability=stability,
        encoding_context=encoding_context,
    )

    should_close = conn is None
    if conn is None:
        conn = open_db()
        ensure_schema(conn)

    try:
        # 迭代59：全类型 KSM Dedup — 传入 chunk_type 精确去重
        if already_exists(conn, summary, chunk_type=chunk_type):
            dmesg_log(conn, DMESG_DEBUG, "extractor",
                      f"ksm_skip: {chunk_type} exact dup '{summary[:40]}'",
                      session_id=session_id, project=project)
            if not _txn_managed:
                conn.commit()
            return
        if merge_similar(conn, summary, chunk_type, importance, project=project):
            dmesg_log(conn, DMESG_DEBUG, "extractor",
                      f"ksm_merge: {chunk_type} similar '{summary[:40]}'",
                      session_id=session_id, project=project)
            if not _txn_managed:
                conn.commit()
            return
        # iter964: substring_dedup_gate — 子串/超串去重
        # 根因（数据驱动，2026-05-06）：5 条 zero-access chunk 中 3 条是库内已有 chunk
        #   的子串片段。already_exists/merge_similar 无法捕获子串关系。
        # 修复：新 summary 与已有 chunk summary 存在子串包含关系（≥30字）→ 拒绝写入。
        # iter1104: cross_type_substring_dedup — 跨 chunk_type 子串去重
        # 根因（数据驱动，2026-05-07）：12 对重复 chunk 中 5 对 100% token overlap，
        #   3/5 对因不同 chunk_type（reasoning_chain vs causal_chain）逃逸 iter964。
        #   extractor 对同一事实常分配不同 type，type 隔离导致子串去重失效。
        # 修复：查询范围从 chunk_type=? 改为 project 范围（本项目+global），跨 type 去重。
        _s_norm = re.sub(r'\s+', '', summary)
        if len(_s_norm) >= 30:
            _existing_summaries = conn.execute(
                "SELECT summary FROM memory_chunks WHERE (project=? OR project='global') LIMIT 200",
                (project,)
            ).fetchall()
            for (_es,) in _existing_summaries:
                _es_norm = re.sub(r'\s+', '', _es)
                if len(_es_norm) >= 30:
                    # iter1108: lcs_ratio_dedup — 严格子串 + LCS 占比双重去重
                    # 根因（数据驱动，2026-05-07）：同一事实的变体碎片逃逸严格子串检测：
                    #   "记录——改进hypercode终端重用逻辑..." vs "hypercode终端重用逻辑..."
                    #   互不包含（前缀/后缀差异），但实质内容重叠 >90%。
                    #   13 个 ac=0 chunk 中 4 个属此类变体碎片。
                    # 修复：保留严格子串快速路径 + 新增 LCS ratio >70% 检测。
                    #   LCS 用 SequenceMatcher（difflib 内置，无需额外依赖），
                    #   以 min(len) 为分母避免短串被长串稀释。
                    if _s_norm in _es_norm or _es_norm in _s_norm:
                        dmesg_log(conn, DMESG_DEBUG, "extractor",
                                  f"iter964_substring_dedup: '{summary[:30]}' subset",
                                  session_id=session_id, project=project)
                        if not _txn_managed:
                            conn.commit()
                        return
                    _min_len = min(len(_s_norm), len(_es_norm))
                    if _min_len >= 40:
                        from difflib import SequenceMatcher as _SM
                        _lcs_size = _SM(None, _s_norm, _es_norm).find_longest_match(
                            0, len(_s_norm), 0, len(_es_norm)).size
                        if _lcs_size / _min_len > 0.70:
                            dmesg_log(conn, DMESG_DEBUG, "extractor",
                                      f"iter1108_lcs_dedup: '{summary[:30]}' lcs={_lcs_size}/{_min_len}",
                                      session_id=session_id, project=project)
                            if not _txn_managed:
                                conn.commit()
                            return
        # iter1181: session_total_write_cap — 同 session 同 type 总写入上限
        # 根因（数据驱动，2026-05-08）：session 5370cd43 写入 21 条 causal_chain（15min），
        #   burst_cap(5min窗口) 因同秒批量写入+窗口滑动而失效（COUNT看不到同事务前序写入）。
        #   21 条 causal_chain 全是同一分析对话的碎片推理步骤，互不子串但话题相同。
        #   占 ac=0 chunk 的 62%(21/34)，污染候选池、拖慢 FTS5 检索。
        # 修复：同 session 同 type 累计写入超阈值 → 直接丢弃（合并到巨大 chunk 同样无价值）。
        #   阈值按信息密度分层：causal/reasoning 碎片=5，其他=8。
        _SESSION_TYPE_CAP = {"causal_chain": 5, "reasoning_chain": 3}
        _SESSION_TYPE_CAP_DEFAULT = 8
        if session_id:
            try:
                _stc_cap = _SESSION_TYPE_CAP.get(chunk_type, _SESSION_TYPE_CAP_DEFAULT)
                _stc_cnt = conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks "
                    "WHERE source_session=? AND chunk_type=?",
                    (session_id, chunk_type)
                ).fetchone()[0]
                if _stc_cnt >= _stc_cap:
                    dmesg_log(conn, DMESG_INFO, "extractor",
                              f"iter1181_session_cap: {chunk_type} session total "
                              f"{_stc_cnt}>={_stc_cap}, drop '{summary[:30]}'",
                              session_id=session_id, project=project)
                    if not _txn_managed:
                        conn.commit()
                    return
            except Exception:
                pass
        # iter1283: project_affinity_gate — 拒绝写入与当前项目无关的其他项目领域知识
        # 根因（数据驱动，2026-05-09）：迭代器 agent 在 memory-os cwd 下讨论 szfreego 冷启动，
        #   extractor 将 12 条内核调度 chunk 写入 memory-os 项目（ac=0，从未被召回）。
        #   project ID 由 cwd 决定，无法区分"本项目知识"和"在本项目目录下讨论的他项目知识"。
        # 修复：写入前 token-overlap 检查：当前项目无任何 chunk 与新 summary 相关，
        #   但其他项目有高 overlap chunk → 拒绝（内容属于其他项目，不应污染本项目）。
        #   仅在当前项目 chunk 数 >= 1 且 < 50 时生效（大库有足够多样性不需此 gate）。
        if project and project != "global":
            try:
                _pa_proj_cnt = conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks WHERE project=?", (project,)
                ).fetchone()[0]
                if 0 <= _pa_proj_cnt < 50:
                    _pa_words = set(re.findall(r'[a-z_][a-z0-9_]{2,}', summary.lower()))
                    _pa_cjk = re.findall(r'[一-鿿]{2,4}', summary)
                    _pa_toks = _pa_words | set(_pa_cjk)
                    if len(_pa_toks) >= 4:
                        _pa_other_max = 0
                        _pa_other_rows = conn.execute(
                            "SELECT summary FROM memory_chunks WHERE project!=? AND project!='global' "
                            "ORDER BY access_count DESC LIMIT 100", (project,)
                        ).fetchall()
                        for (_pa_os,) in _pa_other_rows:
                            _pa_ow = set(re.findall(r'[a-z_][a-z0-9_]{2,}', _pa_os.lower()))
                            _pa_oc = re.findall(r'[一-鿿]{2,4}', _pa_os)
                            _pa_ot = _pa_ow | set(_pa_oc)
                            _pa_ovl = len(_pa_toks & _pa_ot) / len(_pa_toks) if _pa_toks else 0
                            if _pa_ovl > _pa_other_max:
                                _pa_other_max = _pa_ovl
                        if _pa_other_max >= 0.4:
                            _pa_self_max = 0
                            _pa_self_rows = conn.execute(
                                "SELECT summary FROM memory_chunks WHERE project=?", (project,)
                            ).fetchall()
                            for (_pa_ss,) in _pa_self_rows:
                                _pa_sw = set(re.findall(r'[a-z_][a-z0-9_]{2,}', _pa_ss.lower()))
                                _pa_sc = re.findall(r'[一-鿿]{2,4}', _pa_ss)
                                _pa_st = _pa_sw | set(_pa_sc)
                                _pa_sovl = len(_pa_toks & _pa_st) / len(_pa_toks) if _pa_toks else 0
                                if _pa_sovl > _pa_self_max:
                                    _pa_self_max = _pa_sovl
                            if _pa_self_max < 0.15 and _pa_other_max >= 0.4:
                                dmesg_log(conn, DMESG_INFO, "extractor",
                                          f"iter1283_affinity_gate: self_ovl={_pa_self_max:.2f} "
                                          f"other_ovl={_pa_other_max:.2f} drop '{summary[:40]}'",
                                          session_id=session_id, project=project)
                                if not _txn_managed:
                                    conn.commit()
                                return
            except Exception:
                pass
        # iter784: session_burst_cap — 同 session 同 chunk_type 短期写入过多时合并
        #   根因（数据驱动，2026-05-04）：session e3e4392b 在 2 分钟内写了 5 条 decision，
        #   4 条同秒写入。Jaccard 去重无法捕捉"同话题不同细节"的变体。
        #   修复：同 session 同 type 在 5 分钟内已写 >=3 条 → 合并到最近的同类 chunk。
        _BURST_CAP = 3
        if session_id:
            try:
                from datetime import timedelta as _td784
                _cut784 = (datetime.now(timezone.utc) - _td784(minutes=5)).isoformat()
                _burst_cnt784 = conn.execute(
                    "SELECT COUNT(*) FROM memory_chunks "
                    "WHERE source_session=? AND chunk_type=? AND created_at>?",
                    (session_id, chunk_type, _cut784)
                ).fetchone()[0]
                if _burst_cnt784 >= _BURST_CAP:
                    _burst784 = conn.execute(
                        "SELECT id, content FROM memory_chunks "
                        "WHERE source_session=? AND chunk_type=? AND created_at>? "
                        "ORDER BY created_at DESC LIMIT 1",
                        (session_id, chunk_type, _cut784)
                    ).fetchone()
                    if _burst784:
                        _merge_id784, _merge_content784 = _burst784
                        if summary not in (_merge_content784 or ""):
                            _new784 = ((_merge_content784 or "") + "\n" + summary).strip()[:2000]
                            conn.execute(
                                "UPDATE memory_chunks SET content=?, importance=MAX(importance,?), "
                                "updated_at=? WHERE id=?",
                                (_new784, importance, datetime.now(timezone.utc).isoformat(), _merge_id784))
                            from store_vfs import _fts5_sync_chunk
                            _fts5_sync_chunk(conn, _merge_id784, summary=None, content=_new784)
                        dmesg_log(conn, DMESG_INFO, "extractor",
                                  f"iter784_burst_cap: {chunk_type} merged into {_merge_id784[:12]} "
                                  f"(session burst {_burst_cnt784+1}>={_BURST_CAP})",
                                  session_id=session_id, project=project)
                        if not _txn_managed:
                            conn.commit()
                        return
            except Exception:
                pass  # burst cap 失败不阻塞正常写入
        insert_chunk(conn, chunk.to_dict())

        # ── 迭代318：Summary 三元组自动抽取 ────────────────────────────────
        # 每次写入 chunk 时，从 summary 提取关系边写入 entity_edges，
        # 使 spreading_activation 能沿图扩散而不是空转。
        # OS 类比：Linux inode 写入时同步更新 dentry cache —
        #   不是等批处理，而是在写路径上顺手维护索引。
        try:
            _new_row = conn.execute(
                "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type=? "
                "ORDER BY created_at DESC LIMIT 1",
                (summary, chunk_type),
            ).fetchone()
            _cid = _new_row[0] if _new_row else chunk.id
            extract_and_write_summary_triples(summary, _cid, project, conn)
        except Exception:
            pass  # 三元组抽取失败不影响主流程

        # ── iter380：Schema Anchoring — Bartlett (1932) Schema Theory ──────────
        # 写入 chunk 后，扫描 summary 匹配预定义 schema 规则，写入 schema_anchors 绑定行。
        # OS 类比：kmem_cache_alloc — 新对象分配时自动归属对应 kmem_cache。
        try:
            _schema_row = conn.execute(
                "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type=? "
                "ORDER BY created_at DESC LIMIT 1",
                (summary, chunk_type),
            ).fetchone()
            _schema_cid = _schema_row[0] if _schema_row else chunk.id
            from store_vfs import anchor_chunk_schema as _anchor_schema
            _anchor_schema(conn, _schema_cid, summary, project)
        except Exception:
            pass  # schema anchoring 失败不影响主流程

        # ── iter381: Auto-Supersede — Proactive Interference Control ─────────
        # OS 类比：Linux kernel module hot-reload — insmod 新版本模块时，
        #   kernel 将旧模块标记为 MODULE_STATE_GOING（降低其优先级），
        #   新模块成为权威版本。
        #
        # 认知科学依据：Proactive Interference (PI, McGeoch & McDonald 1931)
        #   新知识与旧知识语义冲突时，旧知识干扰新知识的提取。
        #   解决：写入新 chunk 时检测并标记冲突的旧 chunk，使检索层自动跳过。
        #
        # detect_conflict() + supersede_chunk() 存在于 store_vfs.py 但
        # 从未在写路径调用（孤儿函数）— iter381 修复此缺口。
        # 只对 decision + reasoning_chain（事实/规则类知识）做冲突检测，
        # 避免对 conversation_summary 等叙述性 chunk 误判。
        if chunk_type in ("decision", "reasoning_chain"):
            try:
                # _schema_cid 由 iter380 块设置；若 iter380 失败则退回 chunk.id
                _new_cid = locals().get("_schema_cid") or chunk.id
                from store_vfs import (detect_conflict as _detect_conflict,
                                       supersede_chunk as _supersede_chunk)
                _conflict_ids = _detect_conflict(conn, summary, chunk_type, project)
                for _old_id in _conflict_ids:
                    # 跳过 self-reference（不超越自身）
                    if _old_id != _new_cid:
                        _supersede_chunk(conn, _old_id, _new_cid,
                                         reason=f"superseded by newer: {summary[:60]}",
                                         project=project,
                                         session_id=session_id)
            except Exception:
                pass  # 冲突检测失败不影响主流程

        # ── 迭代320：情感显著性 importance 调整 ──────────────────────────────
        # 在写入后立即用情感唤醒词调整 importance，
        # 崩溃/关键/突破类信息自动上调，已解决/废弃类下调。
        # OS 类比：Linux OOM Killer oom_score_adj 写入 —
        #   fork 后进程可自我声明重要性，在 OOM 压力下决定存活顺序。
        try:
            _new_row2 = conn.execute(
                "SELECT id, importance FROM memory_chunks WHERE summary=? AND chunk_type=? "
                "ORDER BY created_at DESC LIMIT 1",
                (summary, chunk_type),
            ).fetchone()
            if _new_row2:
                _cid2, _cur_imp = _new_row2[0], _new_row2[1] or importance
                from store_vfs import apply_emotional_salience
                apply_emotional_salience(conn, _cid2, summary, _cur_imp)
        except Exception:
            pass  # 情感调整失败不影响主流程

        # ── iter371: Memory Conflict Detection — MESI 缓存一致性失效 ─────────────
        # OS 类比：MESI 协议 Modified → Invalidate — 新写入触发旧矛盾 chunk 降权
        # 认知科学：前向干扰（Retroactive Interference）— 新记忆降低旧矛盾记忆的提取
        try:
            from store_vfs import detect_and_invalidate_conflicts
            _conflict_count = detect_and_invalidate_conflicts(
                conn, summary, chunk_type, project
            )
        except Exception:
            pass  # conflict detection 失败不影响主流程

        # ── iter377: Proactive Interference Correction — 新 chunk 主动干预旧记忆 ──
        # OS 类比：Linux COW (Copy-on-Write) page split — 写入新页后，新页优先级更高
        # 认知科学：Proactive Interference (Wixted 2004 "重新巩固理论") —
        #   旧记忆干扰新记忆的编码，修正策略是强化新记忆以赢得检索竞争。
        # 实现：新 chunk 写入后，若 find_similar 发现语义相似的旧 chunk
        #   → 新 chunk importance × 1.1（cap 0.99），增强检索竞争力
        try:
            from store_vfs import find_similar as _find_sim_pi
            _old_sim_id = _find_sim_pi(conn, summary, chunk_type, project=project)
            if _old_sim_id:
                # 找到语义相似的旧 chunk → 新 chunk importance 上调
                _pi_row = conn.execute(
                    "SELECT id, importance FROM memory_chunks WHERE summary=? AND chunk_type=? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (summary, chunk_type),
                ).fetchone()
                if _pi_row:
                    _pi_id, _pi_cur_imp = _pi_row[0], _pi_row[1] or importance
                    _pi_boosted = min(0.99, _pi_cur_imp * 1.1)
                    if _pi_boosted > _pi_cur_imp:
                        conn.execute(
                            "UPDATE memory_chunks SET importance=? WHERE id=?",
                            (_pi_boosted, _pi_id)
                        )
                        dmesg_log(conn, DMESG_DEBUG, "extractor",
                                  f"iter377 proactive_correction: imp {_pi_cur_imp:.3f}"
                                  f"→{_pi_boosted:.3f} (similar={_old_sim_id[:8]})",
                                  session_id=session_id, project=project)
        except Exception:
            pass  # Proactive Interference Correction 失败不影响主流程

        # ── iter386: Interference Decay — 干扰式检索衰减 ────────────────────────
        # OS 类比：TLB Shootdown (INVLPG) — 写入新映射时广播旧映射失效
        # 认知科学：McGeoch (1932) Interference Theory — 新旧相似记忆相互干扰
        # 与 iter371 (MESI 语义矛盾失效) 互补：
        #   iter371：检测显式否定词（放弃/replaced by）→ importance × 0.8
        #   iter386：检测宽泛语义相似（Jaccard）→ retrievability -= penalty
        # 两者共同防止过时知识污染注入。
        try:
            from store_vfs import interference_decay as _interference_decay
            _chunk_dict_for_decay = {"id": locals().get("_pi_id") or chunk.id,
                                     "summary": summary,
                                     "chunk_type": chunk_type}
            _id_count = _interference_decay(conn, _chunk_dict_for_decay, project)
            if _id_count > 0:
                dmesg_log(conn, DMESG_DEBUG, "extractor",
                          f"iter386 interference_decay: {_id_count} chunks retrievability降低",
                          session_id=session_id, project=project)
        except Exception:
            pass  # interference_decay 失败不影响主流程

        # ── iter390: Prospective Memory Trigger — 展望记忆意图检测 ──────────────
        # 认知科学：Einstein & McDaniel (1990) Prospective Memory —
        #   意图性记忆：检测"下次/记得/以后/TODO"等延迟意图信号，注册 trigger 条件。
        #   当后续 query 匹配 trigger_pattern 时，注入该 chunk（提醒效果）。
        # OS 类比：inotify_add_watch() — 注册文件系统事件监听，触发时唤醒等待进程。
        try:
            _pm_pattern = _detect_prospective_intent(summary)
            if _pm_pattern:
                from store_vfs import insert_trigger as _insert_trigger
                import hashlib as _hashlib
                _tid = "trig_" + _hashlib.md5(
                    f"{chunk.id}:{_pm_pattern}".encode()
                ).hexdigest()[:12]
                _now_iso = __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat()
                _insert_trigger(conn, {
                    "id": _tid,
                    "chunk_id": chunk.id,
                    "project": project,
                    "session_id": session_id,
                    "trigger_pattern": _pm_pattern,
                    "trigger_type": "keyword",
                    "created_at": _now_iso,
                })
                dmesg_log(conn, DMESG_DEBUG, "extractor",
                          f"iter390 prospective_trigger: chunk={chunk.id[:8]} "
                          f"pattern='{_pm_pattern}'",
                          session_id=session_id, project=project)
        except Exception:
            pass  # 展望记忆检测失败不阻塞主流程

        # 迭代100：IPC 广播知识更新（OS 类比：inotify — 文件变更通知）
        try:
            from store_vfs import ipc_broadcast_knowledge_update
            ipc_broadcast_knowledge_update(conn, session_id, project,
                                           {"chunk_type": chunk_type, "action": "insert"})
        except Exception:
            pass  # IPC 失败不阻塞提取主流程
        if not _txn_managed:
            conn.commit()
    finally:
        if should_close:
            conn.close()


def _write_page_fault_log(candidates: list, session_id: str) -> None:
    """
    写缺页日志——下轮 UserPromptSubmit 优先加载这些知识缺口。
    v3 闭环升级：
    - fault_count: 同一缺口出现次数（热缺页识别）
    - resolved: 是否已被 retriever 消费并成功补入
    - 重复缺口自增 fault_count 而非重复添加

    iter259: per-session 文件——每个 agent/session 写独立文件，消除并发 overwrite 竞态。
    OS 类比：/proc/PID/pagemap — 每进程独立文件，不同进程间互不干扰。
    命名：page_fault_log.<session_id[:8]>.json（session_id 有效时）
          page_fault_log.json（session_id 为空/"unknown" 时，向后兼容）
    """
    if not candidates:
        return
    # iter259: per-session file — 消除多 agent 并发写竞态
    _sid_tag = session_id[:8] if (session_id and session_id != "unknown") else ""
    if _sid_tag:
        log_path = MEMORY_OS_DIR / f"page_fault_log.{_sid_tag}.json"
    else:
        log_path = MEMORY_OS_DIR / "page_fault_log.json"
    existing = []
    if log_path.exists():
        try:
            existing = json.loads(log_path.read_text())
        except Exception:
            existing = []

    # 建索引：query → entry（用于去重和自增 fault_count）
    query_index = {}
    for entry in existing:
        if isinstance(entry, dict) and "query" in entry:
            # 兼容旧格式（无 fault_count 字段）
            if "fault_count" not in entry:
                entry["fault_count"] = 1
            if "resolved" not in entry:
                entry["resolved"] = False
            q_key = re.sub(r'\s+', '', entry["query"].lower())
            query_index[q_key] = entry

    now_iso = datetime.now(timezone.utc).isoformat()
    for c in candidates:
        q_key = re.sub(r'\s+', '', c.lower())
        if q_key in query_index:
            # 已存在：自增 fault_count，更新时间戳
            query_index[q_key]["fault_count"] += 1
            query_index[q_key]["ts"] = now_iso
            query_index[q_key]["resolved"] = False  # 重新出现说明未真正解决
        else:
            query_index[q_key] = {
                "query": c, "session_id": session_id,
                "ts": now_iso, "fault_count": 1, "resolved": False,
            }

    # 按 fault_count 降序排列（热缺页优先），只保留最近 20 条未解决的
    all_entries = list(query_index.values())
    unresolved = [e for e in all_entries if not e.get("resolved", False)]
    unresolved.sort(key=lambda e: e.get("fault_count", 1), reverse=True)
    merged = unresolved[:20]

    log_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2))


def _extract_topic_entities(text: str, decisions: list, excluded: list,
                            reasoning: list, summaries: list,
                            topic: str) -> list:
    """
    迭代32：从对话内容提取主题实体，用于 madvise hint。
    OS 类比：应用程序分析访问模式，告知内核预读区域。

    提取策略（4 层，按信号强度排序）：
      H1 显式话题：markdown 标题中的关键词
      H2 决策实体：从 decisions/reasoning 中提取被引号/反引号包裹的标识符
      H3 技术词：文件路径、函数名、类名等代码标识符
      H4 高频中文主题词：出现 ≥ 2 次的中文双字词

    返回去重后的实体列表（最多 max_hints 个）。
    """
    entities = []
    seen = set()

    def _add(word):
        key = word.lower().strip()
        if len(key) >= 2 and key not in seen and key not in _MADVISE_STOPWORDS:
            seen.add(key)
            entities.append(word.strip())

    # H1: 话题标题
    if topic:
        for w in re.findall(r'[a-zA-Z][a-zA-Z0-9_]{2,20}', topic):
            _add(w)
        cn = re.sub(r'[^\u4e00-\u9fff]', '', topic)
        for i in range(len(cn) - 1):
            _add(cn[i:i + 2])

    # H2: 决策/推理中的标识符
    all_summaries = decisions + excluded + reasoning + summaries
    for s in all_summaries:
        # 反引号内容
        for m in re.finditer(r'`([^`]{2,30})`', s):
            _add(m.group(1))
        # 英文技术词
        for m in re.finditer(r'\b([a-zA-Z][a-zA-Z0-9_]{2,20})\b', s):
            _add(m.group(1))

    # H3: 原文中的文件路径和代码标识符
    for m in re.finditer(r'[\w./]+\.(?:py|js|ts|md|json|db|sql|yaml|toml)\b', text[:5000]):
        _add(m.group(0))
    for m in re.finditer(r'`([^`]{2,30})`', text[:5000]):
        _add(m.group(1))

    # H4: 高频中文双字词（出现 ≥ 2 次）
    cn_text = re.sub(r'[^\u4e00-\u9fff]', '', text[:5000])
    bigram_count = {}
    for i in range(len(cn_text) - 1):
        bg = cn_text[i:i + 2]
        bigram_count[bg] = bigram_count.get(bg, 0) + 1
    for bg, cnt in sorted(bigram_count.items(), key=lambda x: -x[1]):
        if cnt >= 2:
            _add(bg)

    return entities


# madvise 停用词（排除常见虚词和通用编程词）
_MADVISE_STOPWORDS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "has",
    "not", "but", "can", "will", "all", "one", "its", "had", "been", "each",
    "which", "their", "than", "other", "into", "more", "some", "such", "when",
    "use", "used", "using", "new", "old", "set", "get", "add", "run", "see",
    "now", "way", "may", "also", "per", "via", "yet", "out", "how", "why",
    "def", "class", "import", "return", "true", "false", "none", "self",
    "的", "了", "在", "是", "和", "有", "不", "这", "到", "我", "们",
})


def _write_madvise_hints(text: str, decisions: list, excluded: list,
                         reasoning: list, summaries: list,
                         project: str, session_id: str, topic: str) -> None:
    """
    迭代32：写入 madvise hints（MADV_WILLNEED）。
    从本轮对话内容提取主题实体，作为下一轮检索的预热 hint。
    """
    hints = _extract_topic_entities(text, decisions, excluded, reasoning,
                                    summaries, topic)
    if hints:
        madvise_write(project, hints, session_id)


def _detect_and_write_entities(text: str, project: str, session_id: str,
                               conn) -> int:
    """
    迭代303：轻量 NER — 识别新出现实体并写入 entity_stub chunk。

    OS 类比：Linux inotify/dnotify — 目录事件驱动，新文件（实体）出现时自动建立
      inode stub，后续对该实体的访问直接 dentry cache 命中，无需重新解析路径。

    三类实体（不调 LLM，纯正则，目标 < 3ms）：
      T1 GitHub 仓库：org/repo 格式（如 garrytan/gbrain）
      T2 技术项目名：首字母大写或全大写的英文词（≥4字符），排除常用英文词
      T3 中文专有词：被引号/书名号/「」包围的中文词（2-10字）

    去重：already_exists 检查，只写首次出现的实体。
    info_class 固定为 'world'（实体是关于世界的事实）。
    importance 低（0.40），stability 初始低（0.5），靠后续引用自然加固。
    """
    if not text:
        return 0

    entities = set()

    # T1: GitHub 仓库（owner/repo 格式）
    for m in re.finditer(r'\b([a-zA-Z0-9_-]{2,30}/[a-zA-Z0-9_.-]{2,40})\b', text):
        candidate = m.group(1)
        # 排除文件路径（含多个 /）和常见假阳性，增加更严格的字母检查
        if candidate.count('/') == 1 and not candidate.endswith(('.py', '.js', '.ts', '.md')):
            left, right = candidate.split('/', 1)
            # 两侧必须包含英文字母（排除中文片段误匹配）
            if (re.search(r'[a-zA-Z]', left) and re.search(r'[a-zA-Z]', right)
                    and 2 <= len(left) <= 20 and 2 <= len(right) <= 40):
                entities.add(('github_repo', candidate))

    # T2: 技术项目名（首字母大写英文，≥4字符，非常用词）
    # iter328: 加严过滤 — 必须满足以下任一"技术性"特征：
    #   a. 驼峰（含内嵌大写，如 MemoryChunk, FTS5, BM25）
    #   b. 含数字（FTS5, iter328）
    #   c. 含下划线（snake_case 工具名）
    #   d. 全大写缩写（≥3字，如 BM25, FTS, OOM）
    # 排除：纯首字母大写普通英文词（Best, Note, True, Walker 等）
    _COMMON_EN = frozenset({
        'This', 'That', 'When', 'With', 'From', 'Into', 'Over', 'Under',
        'After', 'Before', 'During', 'While', 'Since', 'Until', 'Through',
        'About', 'Because', 'Though', 'Although', 'However', 'Therefore',
        'True', 'False', 'None', 'Note', 'Also', 'Even', 'Just', 'Like',
        'Step', 'Type', 'List', 'Dict', 'String', 'Class', 'Model', 'Data',
    })
    for m in re.finditer(r'\b([A-Z][a-zA-Z0-9_]{3,25})\b', text):
        word = m.group(1)
        if word in _COMMON_EN:
            continue
        # 技术性特征检测
        _has_tech = (
            bool(re.search(r'[A-Z]', word[1:]))   # 驼峰（内嵌大写）
            or bool(re.search(r'\d', word))         # 含数字
            or '_' in word                           # 含下划线
            or word.isupper() and len(word) >= 3    # 全大写缩写
        )
        if _has_tech:
            entities.add(('tech_entity', word))

    # T3: 中文专有词（引号/书名号/「」包围）
    # iter328: 加严过滤 — 必须包含至少一个英文字母或数字（技术术语特征），
    # 排除纯中文普通短语（"早饭通常有什么"、"不留无用代码"）
    for m in re.finditer(r'[「「《""]([^\u0000-\u007f「」《》""]{2,10})[」」》""]', text):
        cn_word = m.group(1).strip()
        if cn_word and re.search(r'[a-zA-Z0-9_]', cn_word):
            # 必须含英文/数字才认为是技术命名概念
            entities.add(('named_concept', cn_word))

    if not entities:
        return 0

    count = 0
    for etype, name in entities:
        summary = f"[entity:{etype}] {name}"
        # 去重：只写首次出现
        if already_exists(conn, summary, chunk_type="entity_stub"):
            continue
        _write_chunk(
            "entity_stub", summary, project, session_id,
            topic=etype, conn=conn,
            importance_override=0.40,
            _txn_managed=True,
        )
        count += 1

    return count


# ── 迭代304：关系三元组提取（知识图谱边）────────────────────────────────
# OS 类比：Linux modprobe 依赖解析 — 从 modules.dep 文本提取 "A: B C" 格式的
#   依赖关系，写入内核模块依赖图。纯文本正则，不调 LLM，目标 < 5ms。
#
# 支持模式：
#   uses        — "X 使用/采用/基于 Y"
#   depends_on  — "X 依赖/需要 Y"
#   part_of     — "X 是 Y 的一部分/子模块/子系统"
#   implements  — "X 实现了 Y"

# 实体词 token（中英文标识符，1-40字符）
_ENTITY_PAT = r'[\w\u4e00-\u9fff][\w\u4e00-\u9fff\-\.\/]{0,39}'

_RELATION_PATTERNS = [
    # uses: X 使用/采用/基于 Y
    (re.compile(
        rf'({_ENTITY_PAT})\s*(?:使用|采用|基于|调用|依托)\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'uses'),
    # uses: X uses/utilizes/is built on Y (英文)
    (re.compile(
        rf'({_ENTITY_PAT})\s+(?:uses?|utilizes?|is built on|relies on)\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'uses'),
    # depends_on: X 依赖/需要 Y
    (re.compile(
        rf'({_ENTITY_PAT})\s*(?:依赖|需要|要求)\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'depends_on'),
    # depends_on: X depends on/requires Y (英文)
    (re.compile(
        rf'({_ENTITY_PAT})\s+(?:depends? on|requires?)\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'depends_on'),
    # part_of: X 是 Y 的一部分/子模块/子系统/组成部分
    (re.compile(
        rf'({_ENTITY_PAT})\s+是\s+({_ENTITY_PAT})\s*的(?:一部分|子模块|子系统|组成部分|模块)',
        re.UNICODE,
    ), 'part_of'),
    # part_of: X is part of / a submodule of Y (英文)
    (re.compile(
        rf'({_ENTITY_PAT})\s+is\s+(?:part of|a submodule of|a module of)\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'part_of'),
    # implements: X 实现了/实现 Y
    (re.compile(
        rf'({_ENTITY_PAT})\s+实现了?\s+({_ENTITY_PAT})',
        re.UNICODE,
    ), 'implements'),
    # implements: X implements Y (英文)
    (re.compile(
        rf'({_ENTITY_PAT})\s+implements?\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'implements'),

    # ── 迭代318：补充关系模式 — 覆盖浓缩句/陈述句结构 ──────────────────
    # superseded_by: X 被 Y 替代/取代
    (re.compile(
        rf'({_ENTITY_PAT})\s*(?:被|改为|换为|替换为|迁移到)\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'superseded_by'),
    # superseded_by: X replaced by / migrated to Y
    (re.compile(
        rf'({_ENTITY_PAT})\s+(?:replaced? by|migrated? to|superseded? by)\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'superseded_by'),
    # writes_to / reads_from: X 写入/读取 Y
    (re.compile(
        rf'({_ENTITY_PAT})\s*(?:写入|写到|存入|持久化到)\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'writes_to'),
    (re.compile(
        rf'({_ENTITY_PAT})\s*(?:读取|查询|检索自)\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'reads_from'),
    # writes_to (英文): X writes to / persists to Y
    (re.compile(
        rf'({_ENTITY_PAT})\s+(?:writes? to|persists? to|stores? in|inserts? into)\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'writes_to'),
    # calls: X 调用 Y（函数/模块级调用关系）
    (re.compile(
        rf'({_ENTITY_PAT})\s*调用\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'calls'),
    (re.compile(
        rf'({_ENTITY_PAT})\s+calls?\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'calls'),
    # related_to: X 与 Y 相关/关联
    (re.compile(
        rf'({_ENTITY_PAT})\s*与\s*({_ENTITY_PAT})\s*(?:相关|关联|配合|协同)',
        re.UNICODE,
    ), 'related_to'),
    # triggers: X 触发 Y
    (re.compile(
        rf'({_ENTITY_PAT})\s*触发\s*({_ENTITY_PAT})',
        re.UNICODE,
    ), 'triggers'),
    (re.compile(
        rf'({_ENTITY_PAT})\s+triggers?\s+({_ENTITY_PAT})',
        re.IGNORECASE | re.UNICODE,
    ), 'triggers'),
]

# 噪声实体过滤（太短、纯数字、常用停用词）
_ENTITY_STOPWORDS = frozenset({
    # 英文基础停用词
    'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'it', 'its', 'this', 'that', 'these', 'those', 'and', 'or', 'but',
    'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as',
    'true', 'false', 'none', 'null', 'not',
    # 英文扩展停用词
    'can', 'will', 'may', 'should', 'would', 'could', 'must', 'shall',
    'have', 'has', 'had', 'do', 'does', 'did', 'done', 'make', 'use',
    'get', 'set', 'add', 'new', 'old', 'all', 'any', 'each', 'some',
    'one', 'two', 'our', 'we', 'you', 'they', 'he', 'she',
    # 中文停用词（高频虚词）
    '选择', '决定', '推荐', '采用', '使用', '应该', '需要', '可以',
    '因为', '所以', '因此', '但是', '然而', '如果', '当然', '另外',
    '问题', '方案', '方法', '系统', '模块', '功能', '实现', '设计',
    '代码', '文件', '数据', '信息', '内容', '部分', '进行', '提供',
    '包括', '通过', '基于', '关于', '对于', '来自', '目前', '已经',
    '可能', '需要', '没有', '不是', '这个', '那个', '一个', '一种',
    '迭代', '版本', '测试', '验证', '修复', '添加', '删除', '更新',
    '注意', '警告', '结果', '分析', '总结', '说明', '解释', '描述',
})


def _is_noise_entity(s: str) -> bool:
    """过滤噪声实体：太短/纯数字/停用词/多词短语/过长。"""
    if len(s) < 2:
        return True
    if len(s) > 40:
        return True
    if s.isdigit():
        return True
    if s.lower() in _ENTITY_STOPWORDS:
        return True
    # 多词短语不是实体（超过2个空格分隔的词）
    if len(s.split()) > 2:
        return True
    # 纯中文词超过4字通常是句子片段，不是实体名
    cn_only = re.sub(r'[^\u4e00-\u9fff]', '', s)
    if len(cn_only) >= len(s) * 0.8 and len(cn_only) > 4:
        return True
    return False


def _extract_entity_relations(text: str, project: str, session_id: str, conn) -> int:
    """
    迭代304：从文本提取关系三元组并写入 entity_edges。
    纯正则，不调 LLM，目标 < 5ms。

    OS 类比：Linux modprobe 依赖解析 — 读取 modules.dep 文本，
      用正则提取 "module_a: module_b module_c" 依赖关系，
      构建内核模块加载顺序图（kmod_module_new_from_name + dep traversal）。

    返回写入的边数量。
    """
    if not text:
        return 0

    # 避免循环导入：延迟导入 insert_edge
    try:
        from store_vfs import insert_edge
    except ImportError:
        try:
            from store import insert_edge  # type: ignore
        except ImportError:
            return 0

    count = 0
    seen = set()  # 去重同一次提取中的重复三元组

    for pattern, relation in _RELATION_PATTERNS:
        for m in pattern.finditer(text):
            from_e = m.group(1).strip()
            to_e = m.group(2).strip()

            # 过滤噪声
            if _is_noise_entity(from_e) or _is_noise_entity(to_e):
                continue
            # 避免自指边（X uses X）
            if from_e.lower() == to_e.lower():
                continue

            triple = (from_e, relation, to_e)
            if triple in seen:
                continue
            seen.add(triple)

            try:
                insert_edge(conn, from_e, relation, to_e,
                            project=project, confidence=0.7)
                count += 1
            except Exception:
                pass  # 单边失败不影响整体

    return count


# ── 迭代318：Summary 专用三元组抽取 ─────────────────────────────────────────
# OS 类比：Linux /proc/net/dev — 针对网络接口统计的专用解析器，
#   不用通用的 sysfs 读取路径，因为格式不同，解析策略也不同。
#
# 问题：_RELATION_PATTERNS 是为长文本（assistant message）设计的；
#   chunk summary 是浓缩句（"BM25 检索性能足够"、"retriever 调用 FTS5"），
#   主语通常是第一个技术词，谓语在中间，宾语在最后。
#
# 策略：
#   1. 从 summary 中抽取候选技术实体（英文标识符 + 短 CJK 词）
#   2. 检测谓语关键词确定 relation
#   3. 将候选实体对 + relation 写入 entity_edges
#
# 实体候选标准：
#   - 英文词：长度 ≥ 3，非停用词，驼峰/下划线/全大写优先
#   - CJK 词：2-4 字，不在停用词表，通常是模块名/概念名

_SUMMARY_ENTITY_PAT = re.compile(
    r'(?:'
    r'[A-Z][a-zA-Z0-9_]{2,}'        # 驼峰/首字母大写（MemoryChunk, BM25）
    r'|[a-z][a-z0-9_]{3,}'           # 小写标识符（retriever, kswapd）
    r'|[A-Z]{2,}[0-9_]*[A-Z0-9]*'   # 全大写缩写（FTS5, BM25, VFS）
    r')',
    re.UNICODE,
)
# CJK 实体单独处理：只允许 2-3 字的技术词，且必须是纯汉字（不含数字/标点）
_SUMMARY_CJK_ENTITY_PAT = re.compile(r'[\u4e00-\u9fff]{2,3}')


# 谓语关键词 → relation 映射（短句专用）
_SUMMARY_PREDICATES = [
    # 使用/依赖
    (re.compile(r'(?:使用|采用|基于|调用|依赖|读取|查询|依托)'), 'uses'),
    (re.compile(r'(?:uses?|calls?|queries?|reads?|relies? on)', re.IGNORECASE), 'uses'),
    # 实现/包含
    (re.compile(r'(?:实现|包含|提供|支持)'), 'implements'),
    (re.compile(r'(?:implements?|provides?|supports?)', re.IGNORECASE), 'implements'),
    # 写入/存储
    (re.compile(r'(?:写入|存入|持久化|写到)'), 'writes_to'),
    (re.compile(r'(?:writes?|persists?|stores?)', re.IGNORECASE), 'writes_to'),
    # 替代/取代：主动句 "X 改用/换成 Y" 或 "X replaces Y"
    (re.compile(r'(?:改用|换成|迁移到|迁移至|替换为)'), 'superseded_by'),
    (re.compile(r'(?:replaces?|supersedes?|migrates? to)', re.IGNORECASE), 'superseded_by'),
    # 被动替代："X 被 Y 替代" — 谓语是"被 Y"整体（被+宾语），主动宾颠倒
    # 用独立正则直接抽取，不走通用谓语左右分割逻辑
    # 注意：此模式在下面 _PASSIVE_REPLACE_PAT 单独处理
    # 触发/唤醒
    (re.compile(r'(?:触发|唤醒|激活)'), 'triggers'),
    (re.compile(r'(?:triggers?|activates?|wakes?)', re.IGNORECASE), 'triggers'),
    # 依赖/需要
    (re.compile(r'(?:依赖|需要)'), 'depends_on'),
    (re.compile(r'(?:depends? on|requires?)', re.IGNORECASE), 'depends_on'),
]


def extract_summary_triples(summary: str) -> list:
    """
    迭代318：从 chunk summary 短句中抽取三元组列表。
    返回 [(from_entity, relation, to_entity), ...] 列表。
    不调 DB，纯文本处理，< 1ms。

    算法：
      1. 检测谓语关键词确定关系类型和分割点
      2. 以谓语为分界，左侧最后一个技术实体 = from，右侧第一个技术实体 = to
      3. 过滤噪声实体
    """
    if not summary or len(summary) < 5:
        return []

    triples = []
    seen = set()

    # ── 被动替代句专项处理："X 被 Y 替代/取代/替换" ─────────────────────────
    # 主动 to-entity 是 "被" 后面的词（Y），from-entity 是 "被" 前面的词（X）
    _PASSIVE_REPLACE_PAT = re.compile(
        r'([A-Z][a-zA-Z0-9_]{1,}|[a-z][a-z0-9_]{2,}|[A-Z]{2,}[0-9_]*)'
        r'\s+被\s+'
        r'([A-Z][a-zA-Z0-9_]{1,}|[a-z][a-z0-9_]{2,}|[A-Z]{2,}[0-9_]*)'
        r'\s*(?:替代|取代|替换)',
        re.UNICODE,
    )
    for m in _PASSIVE_REPLACE_PAT.finditer(summary):
        from_e = m.group(1).strip()
        to_e = m.group(2).strip()
        if not _is_noise_entity(from_e) and not _is_noise_entity(to_e):
            if from_e.lower() != to_e.lower():
                triple = (from_e, 'superseded_by', to_e)
                if triple not in seen:
                    seen.add(triple)
                    triples.append(triple)

    def _find_entities(text: str) -> list:
        """从文本中提取英文技术实体（不含 CJK 片段，CJK 实体另走严格路径）。"""
        candidates = _SUMMARY_ENTITY_PAT.findall(text)
        return [e for e in candidates if not _is_noise_entity(e)]

    for pred_re, relation in _SUMMARY_PREDICATES:
        for m in pred_re.finditer(summary):
            pred_start = m.start()
            pred_end = m.end()

            # 谓语左侧：找最近的技术实体（from）
            left_text = summary[:pred_start]
            left_entities = _find_entities(left_text)
            if not left_entities:
                continue
            from_e = left_entities[-1]  # 最近的

            # 谓语右侧：找第一个技术实体（to）
            right_text = summary[pred_end:]
            right_entities = _find_entities(right_text)
            if not right_entities:
                continue
            to_e = right_entities[0]  # 最近的

            # 两边都必须有英文标识符特征（至少一个含英文字母）
            # 防止纯中文片段噪声（"记录 → 的"）
            has_alpha_from = bool(re.search(r'[a-zA-Z]', from_e))
            has_alpha_to = bool(re.search(r'[a-zA-Z]', to_e))
            if not has_alpha_from and not has_alpha_to:
                continue  # 两边都是纯中文 → 跳过（质量差）

            # 过滤自指
            if from_e.lower() == to_e.lower():
                continue

            triple = (from_e, relation, to_e)
            if triple not in seen:
                seen.add(triple)
                triples.append(triple)

    return triples


def extract_and_write_summary_triples(
    summary: str,
    chunk_id: str,
    project: str,
    conn,
) -> int:
    """
    迭代318：从 chunk summary 提取三元组并写入 entity_edges。
    在 _write_chunk() 中调用，每次写 chunk 时自动触发。
    返回写入的边数。
    """
    if not summary or not project:
        return 0

    triples = extract_summary_triples(summary)
    if not triples:
        return 0

    try:
        from store_vfs import insert_edge
    except ImportError:
        try:
            from store import insert_edge  # type: ignore
        except ImportError:
            return 0

    count = 0
    for from_e, relation, to_e in triples:
        try:
            insert_edge(
                conn, from_e, relation, to_e,
                project=project,
                source_chunk_id=chunk_id,
                confidence=0.75,  # summary 来的比长文本更精确，稍高
            )
            count += 1
        except Exception:
            pass

    return count


def main():
    import time as _time
    _t_start = _time.time()

    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except Exception:
        hook_input = {}

    text = hook_input.get("last_assistant_message", "")
    if not text or len(text) < _sysctl("extractor.min_length"):
        sys.exit(0)

    # ── iter260: Async Pool Offload ──────────────────────────────────────────
    # OS 类比：queue_work(pool, &work) — Stop hook 提交 work_struct 到 kworker pool，
    #   立即返回（< 5ms），让 extractor_pool 常驻进程异步处理 I/O 密集的 transcript parsing。
    # pool 未运行（首次启动/崩溃）时退化到同步执行（fallback 路径，与旧行为等价）。
    try:
        _hook_cwd  = hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
        project    = resolve_project_id(_hook_cwd if _hook_cwd else None)
        session_id = (hook_input.get("session_id", "")
                      or os.environ.get("CLAUDE_SESSION_ID", "")
                      or "unknown")
        from hooks.extractor_pool import submit_extract_task
        if submit_extract_task(hook_input, project, session_id):
            # 成功入队 → Stop hook 立即返回
            sys.exit(0)
        # pool 未运行 → fallback 到下方同步路径
    except Exception:
        pass  # import 失败 / 任何异常都 fallback 到同步执行
    # ── 同步 fallback 路径（pool 未运行时） ─────────────────────────────────

    # ── 时间片调度：长消息自适应截断（OS 类比：scheduler time-slice）
    # 超过阈值时，只处理前 N 个最可能含决策的段落（标题+代码块+短段落）
    MAX_CHARS = _sysctl("extractor.max_input_chars")
    if len(text) > MAX_CHARS:
        # 保留：标题行、含信号词的行、代码块首尾行
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

    _hook_cwd = hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
    project = resolve_project_id(_hook_cwd if _hook_cwd else None)
    # 迭代66：优先从 hook stdin 获取 session_id（权威来源）
    session_id = (hook_input.get("session_id", "")
                  or os.environ.get("CLAUDE_SESSION_ID", "")
                  or "unknown")

    # 增强1+2：从 hook stdin 获取 transcript_path
    transcript_path = hook_input.get("transcript_path", "")

    # ── 迭代39：COW 预扫描 — 写入时惰性求值 ──
    # OS 类比：fork() COW — MMU 检查 Write bit，未触发则跳过 copy_page()
    # 快速检测消息是否可能包含有价值内容
    # 未命中时跳过完整提取流程，仅保留 page_fault 和 madvise 写入
    #
    # 增强3：长消息（> 500 字符）必然含有价值内容，跳过 prescan 直接进入完整提取
    # OS 类比：大分配请求（alloc_pages(order>=4)）绕过 per-CPU pageset 直接走 zone 分配
    _text_long = len(text) > 500
    cow_hit = _text_long or _cow_prescan(text)
    if not cow_hit:
        # COW miss：消息不含任何信号词，跳过完整提取
        # 仍然执行 page_fault 提取（知识缺口检测不依赖信号词）
        page_faults = _extract_page_fault_candidates(text)
        _write_page_fault_log(page_faults, session_id)
        # iter370: 即使 COW miss，也提取不确定性信号（soft fault 独立于信号词检测）
        try:
            _uf_signals_cow = _extract_uncertainty_signals(text)
            if _uf_signals_cow:
                _uf_conn_cow = open_db()
                ensure_schema(_uf_conn_cow)
                _uf_cnt_cow = _write_uncertainty_chunks(_uf_conn_cow, _uf_signals_cow, project, session_id)
                if _uf_cnt_cow > 0:
                    _uf_conn_cow.commit()
                _uf_conn_cow.close()
        except Exception:
            pass
        # 写入 madvise hints（即使无提取物，也记录话题趋势）
        topic = _extract_topic(text)
        _write_madvise_hints(text, [], [], [], [], project, session_id, topic)
        # dmesg: COW skip
        try:
            conn = open_db()
            ensure_schema(conn)
            dmesg_log(conn, DMESG_DEBUG, "extractor",
                      f"cow_skip: text_len={len(text)} prescan=miss long_msg={_text_long} faults={len(page_faults)} {(_time.time()-_t_start)*1000:.1f}ms",
                      session_id=session_id, project=project)
            conn.commit()
            conn.close()
        except Exception:
            pass
        sys.exit(0)

    topic = _extract_topic(text)

    # ── 迭代50：TCP AIMD — 查询当前拥塞窗口决定提取策略 ──
    # OS 类比：TCP 发送端在发包前检查 cwnd，cwnd 决定可发送的数据量
    # 先打开 conn 查询 AIMD（需要读 recall_traces 统计命中率）
    aimd_policy = "full"  # 默认全速
    aimd_info = None
    try:
        _aimd_conn = open_db()
        ensure_schema(_aimd_conn)
        aimd_info = aimd_window(_aimd_conn, project)
        aimd_policy = aimd_info["policy"]
        _aimd_conn.close()
    except Exception:
        pass  # AIMD 失败不影响主流程（fallback 到 full）

    # ── 提取各类 chunk（v3 多模式提取）── COW hit: 触发完整提取
    decisions = (
        _extract_by_signals(text, DECISION_SIGNALS)
        + _extract_structured_decisions(text)
    )

    excluded = _extract_by_signals(text, EXCLUDED_SIGNALS)
    reasoning = _extract_by_signals(text, REASONING_SIGNALS)

    # v3 新增：对比句式（同时产出决策和排除）
    comp_decisions, comp_exclusions = _extract_comparisons(text)
    decisions.extend(comp_decisions)
    excluded.extend(comp_exclusions)

    # v3 新增：因果链
    # iter105: causal_chain 独立类型，不混入 reasoning_chain
    causal_chains = _extract_causal_chains(text)
    causal_chains = _deduplicate(causal_chains)

    # v3 新增：量化证据（作为 decision，importance 最高）
    quant_conclusions = _extract_quantitative_conclusions(text)
    decisions.extend(quant_conclusions)

    # 迭代98 新增：设计约束（系统级"为什么不这样做"知识）
    constraints = _extract_constraints(text)

    # 全局去重
    decisions = _deduplicate(decisions)
    excluded = _deduplicate(excluded)
    reasoning = _deduplicate(reasoning)
    constraints = _deduplicate(constraints)

    # v4 新增：对话摘要
    # 增强1：从 transcript 尾部额外 5 轮消息补充提取
    _transcript_extra = _read_transcript_tail(transcript_path) if transcript_path else []
    conv_summaries = _extract_conversation_summary(text, extra_texts=_transcript_extra)

    page_faults = _extract_page_fault_candidates(text)

    # ── 迭代50：AIMD 策略过滤 — 根据 cwnd 策略裁剪提取物 ──
    # OS 类比：TCP cwnd 限制发送窗口，cwnd 小时只发高优先级数据
    # conservative: 只保留 decision + reasoning_chain + 量化证据（最不可重建的信息）
    # moderate: 保留上述 + excluded_path，跳过 conversation_summary
    # full: 全部保留
    if aimd_policy == "conservative":
        # 只保留量化结论 + 非量化 decision + reasoning，丢弃 excluded 和 summaries
        excluded = []
        conv_summaries = []
    elif aimd_policy == "moderate":
        # 跳过 conversation_summary（最低信息密度）
        conv_summaries = []

    # iter976: disable_conversation_summary — 生产数据证明 100% 零访问率
    # 根因（数据驱动，2026-05-06）：9/9 conversation_summary chunk access_count=0，
    #   内容为纯疑问句或推理碎片，不含答案无法独立检索。
    # 修复：全局禁用该类型写入，节省 ~10% 存储 + 消除垄断竞争。
    conv_summaries = []

    # iter1577: disable_reasoning_chain — 生产数据证明 0% 存活率
    # 数据驱动（2026-05-12）：6/6 reasoning_chain chunk 全部 DEAD（ac=-1），
    #   内容为推理过程碎片（"已经清楚：…"、"你需要的数据源…"），无法独立检索。
    #   唯一存活的因果知识走 causal_chain 类型（sem_c4531bbd, ac=12）。
    # 修复：全局禁用 reasoning_chain 写入。causal_chain 保留（5% 存活但含高价值）。
    reasoning = []

    if not decisions and not excluded and not reasoning and not conv_summaries and not constraints and not causal_chains:
        # 仍然写缺页日志（即使本轮没有提取物，也可能有知识缺口）
        _write_page_fault_log(page_faults, session_id)
        sys.exit(0)

    # ── iter539: ulimit_nproc — Per-Invocation Chunk Write Rate Limit ──────────
    # OS 类比：Linux RLIMIT_NPROC (setrlimit, 1983 BSD) — 限制单用户进程数，
    #   防止 fork bomb（while(1){fork();}) 耗尽 PID 空间。
    #   当 fork() 返回 -EAGAIN 时，内核按优先级保留已有进程，拒绝新 fork。
    #
    # 根因：单次 extractor 调用可产生无限 chunks（实测一次"aha moment"讨论
    #   在 1 秒内写入 14 个 chunks，大量是碎片化观察而非可操作决策），
    #   形成"知识 fork bomb"淹没高质量内容，零访问率从 17.6% 回升到 35.6%。
    #
    # 解决：设硬上限 ulimit_nproc（默认 8），超过时：
    #   1. 给每个候选 chunk 打 priority score（基于 chunk_type importance_map）
    #   2. 按 priority 降序排列
    #   3. 取 Top-N，丢弃低优先级 chunk
    #   4. dmesg 记录丢弃数量
    _ulimit = _sysctl("extractor.ulimit_nproc")
    _all_candidates = []
    # 优先级排序表（与 _write_chunk importance_map 一致，高 = 高优先保留）
    _type_priority = {
        "design_constraint": 0.95,
        "quantitative_evidence": 0.90,
        "decision": 0.85,
        "procedure": 0.85,
        "causal_chain": 0.82,
        "reasoning_chain": 0.80,
        "excluded_path": 0.70,
        "conversation_summary": 0.65,
    }
    for s in decisions:
        _all_candidates.append((s, "decision", _type_priority["decision"]))
    for s in excluded:
        _all_candidates.append((s, "excluded_path", _type_priority["excluded_path"]))
    for s in reasoning:
        _all_candidates.append((s, "reasoning_chain", _type_priority["reasoning_chain"]))
    for s in causal_chains:
        _all_candidates.append((s, "causal_chain", _type_priority["causal_chain"]))
    for s in conv_summaries:
        _all_candidates.append((s, "conversation_summary", _type_priority["conversation_summary"]))
    for s in constraints:
        _all_candidates.append((s, "design_constraint", _type_priority["design_constraint"]))

    if len(_all_candidates) > _ulimit:
        # 按 priority 降序，同 priority 按原始顺序（stable sort）
        _all_candidates.sort(key=lambda x: x[2], reverse=True)
        _dropped = len(_all_candidates) - _ulimit
        _all_candidates = _all_candidates[:_ulimit]
        # 重建各类型列表
        decisions = [s for s, t, _ in _all_candidates if t == "decision"]
        excluded = [s for s, t, _ in _all_candidates if t == "excluded_path"]
        reasoning = [s for s, t, _ in _all_candidates if t == "reasoning_chain"]
        causal_chains = [s for s, t, _ in _all_candidates if t == "causal_chain"]
        conv_summaries = [s for s, t, _ in _all_candidates if t == "conversation_summary"]
        constraints = [s for s, t, _ in _all_candidates if t == "design_constraint"]
        # dmesg 在事务打开后记录（此处暂存）
        _ulimit_dropped = _dropped
    else:
        _ulimit_dropped = 0

    # ── 迭代99：Hook 事务语义（OS 类比：ext4 journal 两阶段提交）──
    # Phase 1 (Prepare)：BEGIN IMMEDIATE — 独占写锁，防止并发写入污染
    # Phase 2 (Commit)：所有 chunk 写入成功后统一 COMMIT
    # Rollback：任意异常触发 ROLLBACK，保证原子性（全成功/全失败）
    # txn_log：记录事务状态供崩溃后诊断
    import uuid as _uuid
    _txn_id = _uuid.uuid4().hex[:16]

    # ── 批量写入（v5 迭代21：委托 store.py VFS 统一数据访问层）──
    conn = open_db()
    try:
        ensure_schema(conn)
        # 写入事务开始标记
        _txn_started_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT OR IGNORE INTO hook_txn_log
               (txn_id, hook, status, session_id, project, started_at)
               VALUES (?, 'extractor', 'pending', ?, ?, ?)""",
            (_txn_id, session_id, project, _txn_started_at)
        )
        conn.commit()

        # ── 迭代30：kswapd 水位线预淘汰（替代迭代25 的硬 OOM handler）──
        # OS 类比：kswapd 在 __alloc_pages_slowpath 前检查水位
        #   ZONE_OK  → 无需淘汰，直接写入
        #   ZONE_LOW → 预淘汰至 pages_high（后台回收，不阻塞分配）
        #   ZONE_MIN → 同步硬淘汰（direct reclaim，等价于旧 OOM handler）
        incoming_count = len(decisions) + len(excluded) + len(reasoning) + len(conv_summaries) + len(constraints) + len(causal_chains)

        # iter539: ulimit_nproc dmesg（在 conn 可用后记录）
        if _ulimit_dropped > 0:
            dmesg_log(conn, DMESG_WARN, "extractor",
                      f"ulimit_nproc: dropped={_ulimit_dropped} limit={_ulimit} "
                      f"kept={incoming_count} types=[d={len(decisions)} e={len(excluded)} "
                      f"r={len(reasoning)} cc={len(causal_chains)} cs={len(conv_summaries)} dc={len(constraints)}]",
                      session_id=session_id, project=project)

        ksw = kswapd_scan(conn, project, incoming_count)
        if ksw["evicted_count"] > 0:
            conn.commit()
            # dmesg：kswapd 淘汰事件
            dmesg_log(conn, DMESG_WARN, "extractor",
                      f"kswapd zone={ksw['zone']}: evicted={ksw['evicted_count']} stale={ksw['stale_evicted']} "
                      f"watermark={ksw['watermark_pct']}% quota={ksw['quota']} incoming={incoming_count}",
                      session_id=session_id, project=project)

        # ── 迭代40：cgroup v2 memory.high — Soft Quota Throttling ──
        # OS 类比：cgroup v2 memory.high (2015) — 超过软限制时 throttle 新写入
        # 检查水位是否在 memory_high 区间，如果是则降低新写入的 importance + 加 oom_adj
        throttle = cgroup_throttle_check(conn, project, incoming_count)
        throttle_active = throttle["throttled"]
        if throttle_active:
            dmesg_log(conn, DMESG_WARN, "extractor",
                      f"cgroup_throttle: zone={throttle['zone']} watermark={throttle['watermark_pct']}% "
                      f"factor={throttle['importance_factor']} oom_adj_delta={throttle['oom_adj_delta']}",
                      session_id=session_id, project=project)

        # 量化证据集合（用于 importance 提升判断）
        quant_set = set(quant_conclusions)
        # 迭代38：OOM Score — 量化证据自动高保护，临时摘要标记可优先淘汰
        written_chunk_ids = []  # 收集写入的 chunk id（用于 oom_adj 设置）
        quant_chunk_ids = []    # 量化证据 chunk ids
        throttled_chunk_ids = []  # 迭代40：被 throttle 的 chunk ids

        # iter1250: context_snippet_extract — 从原文定位 summary 周围上下文
        def _context_snippet(summary: str, radius: int = 100) -> str:
            # iter1253: fuzzy_context_snippet — 多级 fallback 提升 snippet 命中率
            # 根因：summary[:40] 精确匹配经常失败（54% chunk content=summary），
            #   因为 summary 经提取清洗后前缀与原文不完全一致。
            # 修复：40→20→关键词段 三级 fallback，命中率预期 +30-50%。
            _pos = -1
            for _nlen in (40, 20):
                _needle = summary[:_nlen]
                if _needle:
                    _pos = text.find(_needle)
                    if _pos >= 0:
                        break
            if _pos < 0:
                import re as _re_cs
                _frags = _re_cs.findall(r'[一-鿿]{4,}|[a-zA-Z_]\w{5,}', summary)
                for _f in sorted(_frags, key=len, reverse=True)[:3]:
                    _pos = text.find(_f)
                    if _pos >= 0:
                        break
            if _pos < 0:
                return ""
            _start = max(0, _pos - radius)
            _end = min(len(text), _pos + len(summary) + radius)
            _ctx = text[_start:_end].strip()
            if _ctx == summary.strip() or len(_ctx) < len(summary) + 20:
                return ""
            return _ctx[:300]

        def _throttled_importance(base_imp: float) -> float:
            """迭代40：throttle 区间内 importance 乘以衰减因子。"""
            if throttle_active:
                return round(base_imp * throttle["importance_factor"], 3)
            return base_imp

        def _track_throttled_chunk(summary: str, chunk_type: str):
            """迭代40：记录被 throttle 的 chunk id（用于 oom_adj 设置）。"""
            if throttle_active and throttle["oom_adj_delta"] > 0:
                row = conn.execute(
                    "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type=? ORDER BY created_at DESC LIMIT 1",
                    (summary, chunk_type)
                ).fetchone()
                if row:
                    throttled_chunk_ids.append(row[0])

        # ── 迭代326：quantitative_evidence content 富化 ──────────────────────────
        # 根因：quant_conclusions 平均 content 只有 103 chars（同 causal_chain 的
        # FTS5 token 不足问题）。修复：写入前先过滤出全部合格量化结论，
        # 然后为每个节点构建 "topic + 相邻量化结论" 的富 content。
        # 目标 content ≈ 200-350 chars，接近 decision（248 chars）的 FTS5 密度。
        # OS 类比：Linux huge page — 小页面（单条量化数据）合并成大页面（上下文丰富片段）
        _qualified_quant = [s for s in decisions if s in quant_set and _is_quality_chunk(s)]
        for _q_idx, summary in enumerate(decisions):
            if not _is_quality_chunk(summary):
                continue
            # iter105: 量化证据写成独立 chunk_type，不混入 decision
            if summary in quant_set:
                # 构建富 content：topic + 相邻量化结论（±1 邻居）
                _q_pos = _qualified_quant.index(summary) if summary in _qualified_quant else -1
                if _q_pos >= 0:
                    _q_parts = []
                    if _q_pos > 0:
                        _q_parts.append(_qualified_quant[_q_pos - 1])
                    _q_parts.append(summary)
                    if _q_pos < len(_qualified_quant) - 1:
                        _q_parts.append(_qualified_quant[_q_pos + 1])
                    _q_topic_tag = f"[quantitative_evidence|{topic}]" if topic else "[quantitative_evidence]"
                    _q_raw = f"{_q_topic_tag} {' | '.join(_q_parts)}"
                    # ── 迭代336：Document Expansion — 追加语义概念词 ──
                    # 信息论根因：quant summary 含数字/符号，查询用概念词 → encoding-retrieval mismatch
                    # 修复：写入时预计算概念词并追加到 content，让 FTS5 能按概念词索引量化证据
                    # OS 类比：Linux /proc/wchan — 将裸符号地址映射为人类可读的系统调用名
                    _q_concepts = _quant_semantic_concepts(summary)
                    _q_rich_content = (f"{_q_raw} [concepts: {_q_concepts}]" if _q_concepts
                                       else _q_raw)[:500]
                else:
                    # 无相邻节点时也追加概念词（保证 FTS5 可达）
                    _q_concepts = _quant_semantic_concepts(summary)
                    _q_rich_content = (f"[concepts: {_q_concepts}]" if _q_concepts else "")[:200]
                _write_chunk("quantitative_evidence", summary, project, session_id, topic, conn,
                             importance_override=0.90, _txn_managed=True,
                             content_override=_q_rich_content)
                row = conn.execute(
                    "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type='quantitative_evidence' ORDER BY created_at DESC LIMIT 1",
                    (summary,)
                ).fetchone()
                if row:
                    quant_chunk_ids.append(row[0])
                else:
                    # iter106: SNR Promotion Filter — decision 需有决策动词/技术锚点/对比才写入
                    if not _is_quality_decision(summary):
                        dmesg_log(conn, DMESG_DEBUG, "extractor",
                                  f"snr_filter: decision dropped (no anchor) '{summary[:40]}'",
                                  session_id=session_id, project=project)
                        continue
                    imp = _throttled_importance(0.85)
                    _write_chunk("decision", summary, project, session_id, topic, conn,
                                 importance_override=imp, _txn_managed=True,
                                 raw_snippet=_context_snippet(summary))
                    _track_throttled_chunk(summary, "decision")
        for summary in excluded:
            if _is_quality_chunk(summary):
                # iter953: excluded_path_min_density — 纯符号名无独立检索价值
                # 根因（数据驱动，2026-05-06）：d9aa66fa "scx_disable_and_exit_task"(ac=0)
                #   纯函数名无上下文说明，FTS5 无法命中自然语言查询。
                # 检测：无中文字符 + 无空格描述 → 只是一个标识符，不是排除路径知识。
                _ep_s = summary.strip()
                if not re.search(r'[\u4e00-\u9fff]', _ep_s) and ' ' not in _ep_s and len(_ep_s) < 40:
                    continue
                imp = _throttled_importance(0.70)
                _write_chunk("excluded_path", summary, project, session_id, topic, conn,
                             importance_override=imp, _txn_managed=True,
                             raw_snippet=_context_snippet(summary))
                _track_throttled_chunk(summary, "excluded_path")
        for summary in reasoning:
            if _is_quality_chunk(summary):
                # iter113: reasoning_chain 专用语义密度门控（必须含因果词或长度≥25）
                if not _is_quality_reasoning(summary):
                    dmesg_log(conn, DMESG_DEBUG, "extractor",
                              f"rsn_filter: reasoning_chain dropped (no causal signal) '{summary[:40]}'",
                              session_id=session_id, project=project)
                    continue
                imp = _throttled_importance(0.80)
                _write_chunk("reasoning_chain", summary, project, session_id, topic, conn,
                             importance_override=imp, _txn_managed=True,
                             raw_snippet=_context_snippet(summary))
                _track_throttled_chunk(summary, "reasoning_chain")
        # iter105: 因果链独立写入
        # ── 迭代324：causal_chain 写入前过滤，构建邻节点上下文 ─────────────────
        # OS 类比：Linux readahead + page clustering — 相邻 page 批量读入，
        # 避免每个 page 单独 I/O（等价于每个因果节点单独写入导致 content 碎片化）。
        # 根因：每个 causal_chain chunk 的 content = "[causal_chain] summary"（仅 ~89 字），
        # 而 decision 的 content 平均 248 字 — FTS5 token 不足，召回率极低（acc≈1.3 vs 43.8）。
        # 修复：对通过门控的因果节点，content 包含前一个+当前+后一个节点的聚合文本，
        # 保留因果推理的完整脉络，FTS5 可匹配到更丰富的语义 token。
        # summary 仍保留单节点（用于展示），content 作为检索索引（不展示）。
        _qualified_chains = []
        for _cc_summary in causal_chains:
            if not _is_quality_chunk(_cc_summary):
                continue
            # iterB17：拦截以结论词开头的截断句（"所以X"/"因此X" 缺少前提部分，不是完整因果链）
            # OS 类比：TCP 的 ACK-only segment 校验 — 无 data payload 的段不算有效信息
            # 人类记忆：encoding specificity — 没有"因为"的"所以"无法被因果查询检索命中
            # iter836: conclusion_fragment_widen — 拓宽结论词正则 + 短句门控
            # 根因（数据驱动，2026-05-05）：7 个零访问 causal_chain 碎片逃逸：
            #   "所以不会 crash" / "所以先设置 sched" — "所以"后非[，,\s]绕过旧正则。
            #   avg_len=51 chars（正常有价值 chain avg=708），独立碎片无检索价值。
            # 修复：(1) 结论词后不限定分隔符 (2) <120 字短句直接拒绝
            if re.match(r'^(?:所以|因此|故此|于是|故而|答案[：:])', _cc_summary):
                continue
            if len(_cc_summary) < 120:
                continue
            # 同理：以询问词开头的不是因果链（"你的判断是？"）
            if re.match(r'^你[的是]?', _cc_summary) and '？' in _cc_summary[:30]:
                continue
            has_arrow = '→' in _cc_summary
            has_causal_kw = bool(re.search(
                r'(?:因为|由于|导致了?|造成了?|引发了?|触发了?|引起了?|'
                r'根本原因|因此|所以|原因[：:]|根因[：:]|问题原因[：:]|'
                r'because|due to|caused by|resulted in|leads to)',
                _cc_summary
            ))
            if has_arrow:
                if len(_cc_summary.split('→')[0].strip()) < 3:
                    continue
            elif not has_causal_kw:
                continue
            _qualified_chains.append(_cc_summary)

        for _cc_idx, _cc_summary in enumerate(_qualified_chains):
            imp = _throttled_importance(0.82)
            # 构建聚合 content：前节点 + 当前 + 后节点（最多 ±1 邻居）
            # 聚合后 content ≈ 200-300 字，接近 decision 的 content 密度
            _ctx_parts = []
            if _cc_idx > 0:
                _ctx_parts.append(_qualified_chains[_cc_idx - 1])
            _ctx_parts.append(_cc_summary)
            if _cc_idx < len(_qualified_chains) - 1:
                _ctx_parts.append(_qualified_chains[_cc_idx + 1])
            _topic_tag = f"[causal_chain|{topic}]" if topic else "[causal_chain]"
            _rich_content = f"{_topic_tag} {' → '.join(_ctx_parts)}"[:400]
            _write_chunk("causal_chain", _cc_summary, project, session_id, topic, conn,
                         importance_override=imp, _txn_managed=True,
                         content_override=_rich_content)
            _track_throttled_chunk(_cc_summary, "causal_chain")
        # ── 迭代329：conversation_summary 写入前过滤，构建邻节点上下文 ──────────────
        # 根因：conversation_summary 平均 content=63 chars，FTS5 token 不足 → acc≈1.24。
        # 修复：同 iter324 causal_chain 策略，±1 邻居聚合，目标 content≈200 chars。
        # OS 类比：Linux readahead — 预读相邻 page，减少 random I/O。
        # iter845: conv_summary_min_density — 短摘要碎片拦截
        # 根因（数据驱动，2026-05-05）：4 条 ac=0 conversation_summary 长度 13~26 字，
        #   如 "Claude Code 的持久记忆插件"(13字)、"通用 AI 记忆引擎（SDK + API）"(17字)
        #   信息密度过低，无法独立检索命中。阈值 30 字 ≈ 一个完整中文句子最低要求。
        _cs_min_len = 30
        # iter953: conv_summary_connective_gate — 推理过渡句拦截
        # 根因（数据驱动，2026-05-06）：ee97d372 "scx_set_task_sched 移到前面并没有..."(ac=0)
        #   d3164ed0 "所以跳过 scx_disable_and_exit_task"(ac=0)
        #   以连接词开头的短句是推理中间步骤，脱离上下文无独立检索价值。
        # 检测：连接词开头 + 长度<50 → 只是推理过渡句。
        _CS_CONNECTIVE_RE = re.compile(
            r'^(?:所以|因此|但是|不过|然而|而且|并且|也就是说|换言之|即)\s*'
        )
        def _cs_has_standalone_value(s):
            _stripped = s.strip()
            if _CS_CONNECTIVE_RE.match(_stripped) and len(_stripped) < 50:
                return False
            # 纯否定句（"X 并没有 Y" / "X 不 Y"）短于 45 字 → 结论碎片
            if re.match(r'.{3,15}(?:并没有|没有|不会|不能|不是).{3,25}$', _stripped) and len(_stripped) < 45:
                return False
            # iter959: question_fragment_gate — 纯疑问句不含知识，无检索价值
            # 根因（数据驱动，2026-05-06）：2 条 ac=0 conversation_summary 为纯疑问句
            #   "sched_ext_dead() 在 state=INIT 时的行为是否正确——"(40字)
            #   "此时能拿 rq lock 吗"(14字) — 疑问句记录问题而非答案。
            # 检测：以疑问词/助词结尾 或 含"是否/能否/是不是" + 长度<60
            if _stripped.endswith(('吗', '呢', '？', '?', '——')) and len(_stripped) < 60:
                if re.search(r'是否|能否|是不是|可以吗|对吗|正确|能拿|能用', _stripped):
                    return False
            return True
        _qualified_summaries = [s for s in conv_summaries
                                if _is_quality_chunk(s) and len(s.strip()) >= _cs_min_len
                                and _cs_has_standalone_value(s)]
        for _cs_idx, summary in enumerate(_qualified_summaries):
            imp = _throttled_importance(0.65)
            # 构建聚合 content：前节点 + 当前 + 后节点（±1 邻居）
            _cs_parts = []
            if _cs_idx > 0:
                _cs_parts.append(_qualified_summaries[_cs_idx - 1])
            _cs_parts.append(summary)
            if _cs_idx < len(_qualified_summaries) - 1:
                _cs_parts.append(_qualified_summaries[_cs_idx + 1])
            _cs_topic_tag = f"[conversation_summary|{topic}]" if topic else "[conversation_summary]"
            _cs_rich_content = f"{_cs_topic_tag} {' | '.join(_cs_parts)}"[:400]
            _write_chunk("conversation_summary", summary, project, session_id, topic, conn,
                         importance_override=imp, _txn_managed=True,
                         content_override=_cs_rich_content)
            _track_throttled_chunk(summary, "conversation_summary")

        # 迭代98：设计约束写入（importance=0.95，oom_adj=-800 高保护）
        constraint_chunk_ids = []
        for summary in constraints:
            if _is_quality_chunk(summary):
                _write_chunk("design_constraint", summary, project, session_id, topic, conn,
                             importance_override=0.95, _txn_managed=True,
                             raw_snippet=_context_snippet(summary))  # 约束知识高价值
                row = conn.execute(
                    "SELECT id FROM memory_chunks WHERE summary=? AND chunk_type='design_constraint' ORDER BY created_at DESC LIMIT 1",
                    (summary,)
                ).fetchone()
                if row:
                    constraint_chunk_ids.append(row[0])

        # 迭代38+531：为量化证据 chunk 设置 OOM_ADJ_ONFAULT（延迟保护）
        # 迭代104：soft pin 到当前 project（保护 stale reclaim + DAMON DEAD，不挡 kswapd ZONE_MIN）
        # iter531: mlock2(MLOCK_ONFAULT) — 写入时仅标记为"可锁定"，首次检索命中后升级为 PROTECTED
        for cid in quant_chunk_ids:
            set_oom_adj(conn, cid, OOM_ADJ_ONFAULT)
            pin_chunk(conn, cid, project, pin_type="soft")  # 迭代104: 量化证据 → soft pin

        # 迭代98+531：为设计约束 chunk 设置 OOM_ADJ_ONFAULT（延迟保护）
        # 迭代104：同时 hard pin 到当前 project（VMA mlock 语义，跨 project 不互干扰）
        # iter531: mlock2(MLOCK_ONFAULT) — 首次检索命中后由 retriever 升级为 PROTECTED(-500)
        for cid in constraint_chunk_ids:
            set_oom_adj(conn, cid, OOM_ADJ_ONFAULT)
            pin_chunk(conn, cid, project, pin_type="hard")  # 迭代104: design_constraint → hard pin

        # 迭代40：为 throttled chunk 设置 oom_adj（加速未来回收）
        # OS 类比：cgroup v2 memory.high 下的分配会被计入 memory.stat.high 计数，
        # 这些页面在后续 kswapd 扫描中有更高的回收概率
        if throttled_chunk_ids and throttle["oom_adj_delta"] > 0:
            from store import batch_set_oom_adj
            batch_set_oom_adj(conn, throttled_chunk_ids, throttle["oom_adj_delta"])

        # 增强2：从 transcript Bash tool_result 提取量化结论（tool_insight 类型）
        tool_insight_count = 0
        if transcript_path and aimd_policy != "conservative":
            try:
                tool_insight_count = _extract_from_tool_outputs(
                    transcript_path, session_id, project, conn)
                conn.commit()
            except Exception:
                pass  # 失败不影响主流程

        # 工具使用模式学习 — perf_event 采样工具调用链
        # OS 类比：perf_event_open() 采样 CPU 调用栈，会话结束时 flush ring buffer
        tool_pattern_count = 0
        if transcript_path:
            try:
                tool_pattern_count = _extract_tool_patterns(
                    transcript_path, conn, project, session_id,
                    context_text=text)
            except Exception:
                pass  # 失败不影响主流程

        # 迭代303：Entity detection — NER 触发写入 entity_stub
        # OS 类比：Linux inotify — 文件系统事件触发，对每个新出现的"实体"建立 inode stub
        # 策略：轻量正则 NER（无 LLM 调用，< 2ms），识别三类实体：
        #   1. 项目/框架名（首字母大写英文词、含 - 的技术名词）
        #   2. GitHub 用户/仓库（xxx/yyy 格式）
        #   3. 中文专有词（首次在对话中出现，被「」/《》/""包围的词）
        # 只写入首次出现（already_exists 去重），避免刷写
        entity_stub_count = 0
        try:
            entity_stub_count = _detect_and_write_entities(
                text, project, session_id, conn)
        except Exception:
            pass  # entity detection 失败不影响主流程

        # 迭代304：Entity relations — 从文本提取关系三元组写入 entity_edges
        # OS 类比：modprobe modules.dep 解析 — 识别模块间依赖关系，建立加载顺序图
        # 策略：纯正则，不调 LLM，< 5ms
        edge_count = 0
        try:
            edge_count = _extract_entity_relations(
                text, project, session_id, conn)
        except Exception:
            pass  # edge extraction 失败不影响主流程

        # 迭代29 dmesg：提取汇总
        # 迭代50：AIMD 信息加入日志
        _dur = (_time.time() - _t_start) * 1000
        aimd_tag = ""
        if aimd_info:
            aimd_tag = f" aimd={aimd_policy}(cwnd={aimd_info['cwnd']:.2f} hr={aimd_info['hit_rate']:.2f} {aimd_info['direction']})"
        _long_tag = f" long_msg={_text_long} transcript_extra={len(_transcript_extra)}" if _transcript_extra or _text_long else ""
        dmesg_log(conn, DMESG_INFO, "extractor",
                  f"decisions={len(decisions)} excluded={len(excluded)} reasoning={len(reasoning)} causal={len(causal_chains)} summaries={len(conv_summaries)} constraints={len(constraints)} tool_insights={tool_insight_count} tool_patterns={tool_pattern_count} entities={entity_stub_count} edges={edge_count} faults={len(page_faults)} {_dur:.1f}ms{aimd_tag}{_long_tag}",
                  session_id=session_id, project=project)
        # ── 迭代99：原子提交 — 更新 txn_log 状态后统一 COMMIT ──
        # OS 类比：ext4 journal commit — 日志记录 committed 后才真正写入 data block
        _chunk_count = (len(decisions) + len(excluded) + len(reasoning)
                        + len(conv_summaries) + len(constraints)
                        + tool_insight_count + tool_pattern_count + entity_stub_count)
        conn.execute(
            """UPDATE hook_txn_log
               SET status='committed', chunk_count=?, committed_at=?
               WHERE txn_id=?""",
            (_chunk_count, datetime.now(timezone.utc).isoformat(), _txn_id)
        )
        conn.commit()  # 单一原子 COMMIT：txn_log + 所有 chunks

        # ── 迭代103：跨Agent知识广播（OS 类比：inotify IN_MODIFY 事件）──
        # commit 成功后广播本轮写入统计，其他 agent 的 loader 可在 SessionStart 消费
        if _chunk_count > 0:
            try:
                from net.agent_notify import broadcast_knowledge_update
                broadcast_knowledge_update(project, session_id, {
                    "decisions": len(decisions),
                    "constraints": len(constraints),
                    "chunks": _chunk_count,
                })
            except Exception:
                pass  # IPC 失败不影响主流程

    except Exception as _txn_err:
        # ── 迭代99：Rollback — 记录错误到 txn_log（在新连接中，因原连接可能已损坏）──
        try:
            conn.rollback()
            conn.execute(
                """UPDATE hook_txn_log SET status='failed', error=? WHERE txn_id=?""",
                (str(_txn_err)[:500], _txn_id)
            )
            conn.commit()
        except Exception:
            pass
        dmesg_log(conn, DMESG_WARN, "extractor",
                  f"txn_rollback: txn_id={_txn_id} err={type(_txn_err).__name__}:{str(_txn_err)[:80]}",
                  session_id=session_id, project=project)
    finally:
        conn.close()

    _write_page_fault_log(page_faults, session_id)

    # ── iter370: Uncertainty Signal Extraction — soft page fault 记录 ─────────
    # OS 类比：MMU soft page fault — 访问 valid VMA 内未映射地址 → 记录 fault address，
    #   后台 swap-in 补充（类比：下次 SessionStart prefetch 填补知识空白）。
    # 从 assistant 消息中提取 Claude 显式声明的不确定性，写入 DB 作为 episodic chunk，
    # 使后续会话 retriever 能 FTS5 命中并补充相关知识。
    try:
        _uf_signals = _extract_uncertainty_signals(text)
        if _uf_signals:
            _uf_conn = open_db()
            ensure_schema(_uf_conn)
            _uf_count = _write_uncertainty_chunks(_uf_conn, _uf_signals, project, session_id)
            if _uf_count > 0:
                _uf_conn.commit()
            _uf_conn.close()
    except Exception:
        pass  # 不确定性提取失败不影响主流程

    # ── 迭代32：madvise — 写入检索 hint（MADV_WILLNEED）──
    # OS 类比：应用程序在完成一轮处理后，通过 madvise 告知内核下一轮可能访问的区域
    # extractor 分析本轮对话内容，提取主题实体作为 hint
    _write_madvise_hints(text, decisions, excluded, reasoning, conv_summaries + constraints,
                         project, session_id, topic)

    # ── 迭代49：CRIU checkpoint — 会话结束时保存精确工作集快照 ──
    # OS 类比：CRIU dump — 在进程终止前序列化完整状态
    # 收集本次会话的 retrieval 命中 chunk IDs + madvise hints
    try:
        ckpt_conn = open_db()
        ensure_schema(ckpt_conn)
        hit_ids = checkpoint_collect_hits(ckpt_conn, project, session_id)
        if hit_ids:
            # 读取当前 madvise hints 作为 checkpoint 的一部分
            from store import madvise_read
            current_hints = madvise_read(project)
            hint_keywords = [h.get("keyword", "") for h in current_hints] if current_hints else []

            # 从本轮提取的实体作为 query_topics
            topic_entities = []
            if topic:
                topic_entities.append(topic)
            all_summaries = decisions[:3] + reasoning[:2]
            for s in all_summaries:
                for m in re.finditer(r'`([^`]{2,30})`', s):
                    topic_entities.append(m.group(1))
            topic_entities = list(dict.fromkeys(topic_entities))[:5]

            ckpt_result = checkpoint_dump(ckpt_conn, project, session_id,
                                          hit_ids, hint_keywords, topic_entities)
            if ckpt_result.get("checkpoint_id"):
                dmesg_log(ckpt_conn, DMESG_INFO, "extractor",
                          f"criu_dump: ckpt={ckpt_result['checkpoint_id']} ids={ckpt_result['saved_ids']} cleaned={ckpt_result['cleaned']}",
                          session_id=session_id, project=project)
            ckpt_conn.commit()
        ckpt_conn.close()
    except Exception:
        pass  # checkpoint 失败不影响主流程

    # ── 迭代94: 跨项目知识晋升 + 迭代95: 目标进度追踪 ──
    try:
        _pr_conn = open_db()
        ensure_schema(_pr_conn)
        promoted = _promote_to_global(_pr_conn, project, session_id)
        # 目标进度：有新决策写入 → progress 微增
        # iter_multiagent P2：session 级幂等防双计 — 同一 session 只增加一次
        if len(decisions) > 0:
            now_iso = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
            try:
                _pr_conn.execute("ALTER TABLE goals ADD COLUMN last_progress_session TEXT DEFAULT ''")
            except Exception:
                pass
            _pr_conn.execute(
                """UPDATE goals SET progress = MIN(1.0, progress + 0.05),
                   updated_at = ?,
                   last_progress_session = ?
                   WHERE project = ? AND status = 'active'
                     AND (last_progress_session IS NULL OR last_progress_session != ?)""",
                [now_iso, session_id, project, session_id]
            )
        _pr_conn.commit()
        _pr_conn.close()
    except Exception:
        pass

    # ── LRU 语义淘汰（超阈值时自动触发）──
    try:
        import importlib.util
        _evict_path = Path(__file__).parent.parent / "tools" / "memory_eviction.py"
        if _evict_path.exists():
            spec = importlib.util.spec_from_file_location("memory_eviction", _evict_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.run(dry_run=False)
    except Exception:
        pass  # 淘汰失败不影响主流程

    # ── 冷备份同步（新 chunk 自动推到 mm）──
    try:
        _cold_path = Path(__file__).parent.parent / "tools" / "cold_store.py"
        if _cold_path.exists():
            spec = importlib.util.spec_from_file_location("cold_store", _cold_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.cmd_sync(dry_run=False)
    except Exception:
        pass  # 冷备份失败不影响主流程（mm 可能离线）

    # ── 会话结束 GC：清除 prompt_context chunks（临时短暂信号，无跨会话召回价值）──
    # iter789: 改用 delete_chunks() 统一路径，自动触发 mmu_notifier 清理 stale refs
    try:
        _gc_conn = open_db()
        ensure_schema(_gc_conn)
        from store_vfs import delete_chunks as _gc_delete_chunks
        _gc_pc_ids = [r[0] for r in _gc_conn.execute(
            "SELECT id FROM memory_chunks WHERE chunk_type = 'prompt_context'"
        ).fetchall()]
        _gc_deleted = _gc_delete_chunks(_gc_conn, _gc_pc_ids) if _gc_pc_ids else 0
        # iter114: tool_insight GC — bash 输出量化结论是 point-in-time 数据，
        # 跨会话召回率极低（100% 从未访问），与 prompt_context 同级清除。
        # 保留逻辑：access_count >= 1 的 tool_insight 说明曾被实际使用，保留。
        # OS 类比：tmpfs — 进程退出时自动释放 VMA 映射的临时文件系统内容。
        _gc_ti_ids = [r[0] for r in _gc_conn.execute(
            "SELECT id FROM memory_chunks WHERE chunk_type = 'tool_insight' AND COALESCE(access_count,0) = 0"
        ).fetchall()]
        _gc_tool = _gc_delete_chunks(_gc_conn, _gc_ti_ids) if _gc_ti_ids else 0
        _gc_deleted += _gc_tool
        # iter328: entity_stub GC — NER 提取的实体存根 100% zero-access（噪声率高）
        # 策略：只保留 access_count >= 1 的（曾被实际用于检索），其余清除。
        # OS 类比：dentries 的 d_count=0 时被 dentry_cache 的 LRU 回收。
        _gc_es_ids = [r[0] for r in _gc_conn.execute(
            "SELECT id FROM memory_chunks WHERE chunk_type = 'entity_stub' AND COALESCE(access_count,0) = 0"
        ).fetchall()]
        _gc_entity = _gc_delete_chunks(_gc_conn, _gc_es_ids) if _gc_es_ids else 0
        _gc_deleted += _gc_entity
        _gc_conn.commit()
        if _gc_deleted > 0:
            dmesg_log(_gc_conn, DMESG_INFO, "extractor",
                      f"session_gc: deleted {_gc_deleted} temp chunks "
                      f"(prompt_context + {_gc_tool} tool_insight + {_gc_entity} entity_stub)",
                      session_id=session_id, project=project)
            _gc_conn.commit()
        _gc_conn.close()
    except Exception:
        pass  # GC 失败不影响主流程

    # ── 迭代110 P2: CRIU Session Intent Checkpoint ──────────────────────────
    # OS 类比：CRIU (Checkpoint/Restore in Userspace, 2012) — 在进程终止前
    #   序列化完整进程状态（寄存器、内存映射、文件描述符），下次 restore 时
    #   像什么都没发生一样继续。
    #
    # AIOS 类比：在 session 结束前，从 last_assistant_message 提取
    #   "incomplete intent" — Claude 在思考/执行过程中遇到的悬而未决的事项。
    #   下次 SessionStart 时注入，让新 session 像从断点继续一样工作。
    #
    # 提取目标（三类未完成信号）：
    #   I1 next_actions:  "接下来需要..." / "下一步..." / "还需要..."
    #   I2 open_questions: "需要验证..." / "待确认..." / "不确定..."
    #   I3 partial_work:  "正在..." / "目前..." / "已完成...但还需要..."
    try:
        _intent = _extract_session_intent(text)
        if _intent:
            # iter259: 从 DB shadow_traces 表读取（并发安全，替代单文件）
            _intent_chunk_ids: list = []
            _agent_id = session_id[:16] if session_id else ""
            try:
                _st_conn = open_db()
                ensure_schema(_st_conn)
                _st_row = _st_conn.execute(
                    "SELECT top_k_ids FROM shadow_traces WHERE session_id=? AND project=?",
                    (session_id, project)
                ).fetchone()
                if _st_row:
                    _intent_chunk_ids = json.loads(_st_row[0] or "[]")
                _st_conn.close()
            except Exception:
                # 兼容旧文件（逐步迁移期）
                try:
                    _shadow_file = MEMORY_OS_DIR / ".shadow_trace.json"
                    if _shadow_file.exists():
                        _st = json.loads(_shadow_file.read_text(encoding="utf-8"))
                        if _st.get("project", project) == project:
                            _intent_chunk_ids = _st.get("top_k_ids", [])
                except Exception:
                    pass

            # iter259: 写入 DB session_intents 表（替代单文件 session_intent.json）
            # OS 类比：per-process /proc/PID/status — 每个 session 独立一行
            _intent_conn = open_db()
            ensure_schema(_intent_conn)
            _intent_conn.execute(
                """INSERT OR REPLACE INTO session_intents
                   (session_id, project, agent_id, saved_at, intent_json, pinned_chunk_ids)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    session_id, project, _agent_id,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(_intent, ensure_ascii=False),
                    json.dumps(_intent_chunk_ids, ensure_ascii=False),
                )
            )
            _intent_conn.commit()

            # 同时保留旧文件以向后兼容（只写最新 session，不再是唯一数据源）
            try:
                _intent_file = MEMORY_OS_DIR / "session_intent.json"
                _intent_file.write_text(
                    json.dumps({
                        "session_id": session_id,
                        "project": project,
                        "saved_at": datetime.now(timezone.utc).isoformat(),
                        "intent": _intent,
                        "pinned_chunk_ids": _intent_chunk_ids,
                    }, ensure_ascii=False, indent=2),
                    encoding="utf-8"
                )
            except Exception:
                pass

            # iter259: soft-pin 关联 chunk，防止被 kswapd 在 24h 有效期内淘汰
            if _intent_chunk_ids:
                try:
                    from store_vfs import pin_chunk as _pin_chunk
                    _pinned = 0
                    for _cid in _intent_chunk_ids:
                        if _pin_chunk(_intent_conn, _cid, project, pin_type="soft"):
                            _pinned += 1
                    if _pinned:
                        _intent_conn.commit()
                        dmesg_log(_intent_conn, DMESG_DEBUG, "extractor",
                                  f"intent_soft_pin: pinned {_pinned} chunks for 24h (CRIU intent restore)",
                                  session_id=session_id, project=project)
                        _intent_conn.commit()
                except Exception:
                    pass  # soft-pin 失败不影响 intent 保存
            _intent_conn.close()
    except Exception:
        pass  # Intent 保存失败不影响主流程

    # ── 迭代311-B：Active Suppression — 注入未用则下调 importance ─────────────
    # OS 类比：vm.swappiness 主动换出冷页面
    # shadow_trace 记录上次 retriever 注入的 chunk IDs，本次回复未用的下调
    # iter259：优先从 shadow_traces DB 表读取（并发安全，替代单文件）
    try:
        _injected_ids = []
        _sup_loaded = False
        # 优先从 DB shadow_traces 表读取（per-session 隔离）
        try:
            _sup_db = open_db()
            ensure_schema(_sup_db)
            _sup_row = _sup_db.execute(
                "SELECT top_k_ids FROM shadow_traces WHERE session_id=? AND project=?",
                (session_id, project)
            ).fetchone()
            _sup_db.close()
            if _sup_row:
                _injected_ids = json.loads(_sup_row[0] or "[]")
                _sup_loaded = True
        except Exception:
            pass
        # 兼容旧文件（DB 读取失败时 fallback）
        if not _sup_loaded:
            _shadow_file = MEMORY_OS_DIR / ".shadow_trace.json"
            if _shadow_file.exists():
                _shadow = json.loads(_shadow_file.read_text(encoding="utf-8"))
                _shadow_proj = _shadow.get("project", project)
                if _shadow_proj == project:
                    _injected_ids = _shadow.get("top_k_ids", [])
        if _injected_ids:
            from store_vfs import suppress_unused as _suppress_unused
            _sup_conn = open_db()
            ensure_schema(_sup_conn)
            _sup_n = _suppress_unused(
                _sup_conn, _injected_ids, assistant_response=text, project=project
            )
            if _sup_n:
                dmesg_log(_sup_conn, DMESG_DEBUG, "extractor",
                          f"suppress_unused: {_sup_n} chunks penalized (not referenced in response)",
                          session_id=session_id, project=project)
            _sup_conn.commit()
            _sup_conn.close()
    except Exception:
        pass  # suppress_unused 失败不影响主流程

    # ── 迭代311-C：Sleep Consolidation — session 结束自动维护记忆 ──────────────
    # OS 类比：pdflush writeback + KSM — 进程退出时合并相似页、稳定活跃页、淘汰陈旧页
    try:
        from store_vfs import sleep_consolidate as _sleep_consolidate
        _slp_conn = open_db()
        ensure_schema(_slp_conn)
        _slp_result = _sleep_consolidate(_slp_conn, project=project, session_id=session_id)
        _slp_any = any(
            v > 0 for k, v in _slp_result.items()
            if isinstance(v, (int, float)) and k != "new_semantic_ids"
        )
        if _slp_any or _slp_result.get("new_semantic_ids"):
            dmesg_log(_slp_conn, DMESG_INFO, "extractor",
                      f"sleep_consolidate: merged={_slp_result['merged']} "
                      f"boosted={_slp_result['boosted']} decayed={_slp_result['decayed']} "
                      f"ep_promoted={_slp_result.get('episodic_promoted',0)} "
                      f"ep_inplace={_slp_result.get('episodic_inplace_promoted',0)} "
                      f"ep_decayed={_slp_result.get('episodic_decayed',0)}",
                      session_id=session_id, project=project)
        _slp_conn.commit()
        _slp_conn.close()
    except Exception:
        pass  # sleep_consolidate 失败不影响主流程

    # ── iter374: Chunk Coalescing — Slab Allocator 合并碎片化小 chunk ────────
    # OS 类比：Linux Slab Allocator — 合并碎片化对象，提升内存利用率
    # 人的记忆类比：Chunking (Miller 1956) — 将相关小记忆片段合并为有意义组块
    try:
        from store_vfs import coalesce_small_chunks as _coalesce
        _coal_conn = open_db()
        ensure_schema(_coal_conn)
        _coal_n = _coalesce(_coal_conn, project=project)
        if _coal_n > 0:
            dmesg_log(_coal_conn, DMESG_INFO, "extractor",
                      f"coalesce: merged_groups={_coal_n}",
                      session_id=session_id, project=project)
        _coal_conn.commit()
        _coal_conn.close()
    except Exception:
        pass  # coalesce 失败不影响主流程

    # ── iter366: Knowledge Graph — chunk_edges 构建 ──────────────────────────
    # OS 类比：/proc/[pid]/maps vm_area_struct 邻接 — 描述地址空间区域间关联
    # 人的记忆类比：语义网络（semantic network）— 知识节点间的有向关联边
    try:
        if written_chunk_ids and len(written_chunk_ids) >= 2:
            from store_graph import (add_cooccurrence_edges, infer_edges_from_summaries,
                                      ensure_graph_schema)
            _graph_conn = open_db()
            ensure_graph_schema(_graph_conn)

            # 1. 共现边：同 session 写入的 chunk 之间建立弱关联
            _cooc_count = add_cooccurrence_edges(_graph_conn, written_chunk_ids, weight=0.5)

            # 2. 规则推断边：从 chunk 类型和 summary 推断强关联
            _graph_chunks = []
            if written_chunk_ids:
                _gc_ids = ",".join("?" * len(written_chunk_ids))
                _gc_rows = _graph_conn.execute(
                    f"SELECT id, summary, chunk_type FROM memory_chunks WHERE id IN ({_gc_ids})",
                    written_chunk_ids
                ).fetchall()
                _graph_chunks = [{"id": r[0], "summary": r[1], "chunk_type": r[2]}
                                  for r in _gc_rows]
            _rule_count = infer_edges_from_summaries(_graph_conn, _graph_chunks)
            _graph_conn.close()
            dmesg_log(open_db(), DMESG_DEBUG, "extractor",
                      f"graph_edges: cooccurrence={_cooc_count} rule={_rule_count}",
                      session_id=session_id, project=project)
    except Exception:
        pass  # graph 构建失败不影响主流程

    # ── iter368: Attention Focus Update — 会话注意焦点栈更新 ─────────────────
    # OS 类比：register allocator — 高频变量进寄存器，低频出寄存器
    # 人的记忆类比：Cowan (2001) focus of attention — 当前正在处理的主题留在焦点中
    try:
        if session_id and session_id != "unknown" and text:
            from store_focus import ensure_focus_schema, update_focus
            _focus_conn = open_db()
            ensure_focus_schema(_focus_conn)
            # 从当前对话文本（最后 500 字）提取焦点关键词
            update_focus(_focus_conn, session_id, text[-500:])
            _focus_conn.close()
    except Exception:
        pass  # 焦点更新失败不影响主流程

    # ── iter367: Temporal Proximity Edges — 时序邻近性关联边 ─────────────────
    # OS 类比：Linux readahead sequential detection — 顺序访问的相邻 block 自动预取
    # 人的记忆类比：Temporal contiguity effect (Kahana 1996) — 时间上相邻编码的记忆
    #   更容易相互激活（自由回忆实验中，相邻词对的联想概率更高）
    # 实现：同 session 中时间相邻（<5min）写入的 chunk 之间建立 COOCCURS 弱边
    try:
        if written_chunk_ids and session_id and session_id != "unknown":
            from store_graph import add_edge, EdgeType, ensure_graph_schema
            _tp_conn = open_db()
            ensure_graph_schema(_tp_conn)
            # 查询同 session 中在本次写入之前 5 分钟内写入的 chunk
            _tp_cutoff = (datetime.now(timezone.utc)
                          .replace(tzinfo=None) if True else None)
            import datetime as _dt_mod
            _tp_since = (
                _dt_mod.datetime.now(_dt_mod.timezone.utc)
                - _dt_mod.timedelta(minutes=5)
            ).isoformat()
            _tp_rows = _tp_conn.execute(
                """SELECT id FROM memory_chunks
                   WHERE source_session=?
                     AND id NOT IN ({})
                     AND created_at >= ?
                   ORDER BY created_at DESC LIMIT 10""".format(
                    ",".join("?" * len(written_chunk_ids))
                ),
                [session_id, *written_chunk_ids, _tp_since]
            ).fetchall()
            _tp_recent_ids = [r[0] for r in _tp_rows]
            _tp_edge_count = 0
            if _tp_recent_ids:
                for _new_id in written_chunk_ids:
                    for _old_id in _tp_recent_ids:
                        # iter426: Temporal Contiguity Effect — 前向非对称关联（Kahana 1996）
                        # _old_id 先写入，_new_id 后写入 → 前向边：_old_id → _new_id（强）
                        # 后向边：_new_id → _old_id（弱，仅 COOCCURS）
                        # 前向 weight=0.60（>= expand_with_neighbors min_weight=0.55，确保被预取）
                        # 后向 weight=0.15（< 0.55，低于 expand 阈值，符合后向抑制原则）
                        # Kahana (1996) 前向:后向 = 2:1，weight 比约 0.60:0.15 = 4:1（略强于认知数据）
                        # OS 类比：readahead 只预取下一个 page（前向），不预取上一个（后向）
                        if add_edge(_tp_conn, _old_id, _new_id, EdgeType.TEMPORAL_FORWARD, 0.60,
                                    source="temporal"):
                            _tp_edge_count += 1
                        # 后向保持弱 COOCCURS 边（0.15，约为前向的 1/4，低于 expand 阈值）
                        if add_edge(_tp_conn, _new_id, _old_id, EdgeType.COOCCURS, 0.15,
                                    source="temporal"):
                            _tp_edge_count += 1
                _tp_conn.commit()
            _tp_conn.close()
    except Exception:
        pass  # 时序边构建失败不影响主流程

    # ── iter365: Workspace Todos — 前瞻性记忆提取 ────────────────────────────
    # OS 类比：inotify_add_watch — "当我回到这里时提醒我"
    # 人的记忆类比：前瞻性记忆（Prospective Memory）— 带未来意向的记忆
    try:
        _todo_cwd = hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
        if _todo_cwd:
            from store_todos import (extract_todos_from_text, add_todo,
                                     ensure_todos_schema)
            from store_workspace import _workspace_id as _ws_id_todo
            _todo_ws_id = _ws_id_todo(_todo_cwd)
            _todo_conn = open_db()
            ensure_todos_schema(_todo_conn)
            _todo_items = extract_todos_from_text(text)
            for _ti in _todo_items:
                add_todo(
                    _todo_conn,
                    workspace_id=_todo_ws_id,
                    project=project,
                    content=_ti["content"],
                    source_session=session_id,
                    due_hint=_ti.get("due_hint", ""),
                )
            _todo_conn.close()
    except Exception:
        pass  # todo 提取失败不影响主流程

    # ── iter364: Session Episode Write — 情节时间线 ──────────────────────────
    # OS 类比：ftrace ring buffer flush — session 结束时将本次行为记录写入持久化 ring。
    # 人的记忆类比：情节记忆（Episodic Memory）— 带时间戳的行为事件，
    #   下次 SessionStart 时可注入"上次在这里做了什么"。
    try:
        from store_episodes import (write_episode, build_episode_summary,
                                    ensure_episodes_schema)
        _ep_conn = open_db()
        ensure_episodes_schema(_ep_conn)

        # 收集修改的文件（从 transcript 中解析 Edit/Write tool calls）
        _ep_files = []
        if transcript_path:
            try:
                import re as _re_ep
                from pathlib import Path as _Path_ep
                _tp = _Path_ep(transcript_path)
                if _tp.exists():
                    _tail = _tp.read_bytes()[-300_000:]
                    _tail_text = _tail.decode("utf-8", errors="ignore")
                    # 提取 Edit/Write 工具的 file_path 参数
                    for _fm in _re_ep.finditer(
                        r'"tool_name"\s*:\s*"(?:Edit|Write)".*?"file_path"\s*:\s*"([^"]+)"',
                        _tail_text, _re_ep.DOTALL
                    ):
                        _fp = _fm.group(1)
                        if _fp not in _ep_files:
                            _ep_files.append(_fp)
            except Exception:
                pass

        # 工具调用统计（从 dmesg tool_profiler 获取，或简单计数）
        _ep_tools: dict = {}
        try:
            _ep_rows = _ep_conn.execute(
                """SELECT tool_name, COUNT(*) FROM tool_call_log
                   WHERE session_id=? GROUP BY tool_name""",
                (session_id,)
            ).fetchall()
            _ep_tools = {r[0]: r[1] for r in _ep_rows}
        except Exception:
            pass  # tool_call_log 可能不存在

        # chunk 数量
        _ep_chunk_count = (len(decisions) + len(excluded) + len(reasoning)
                           + len(conv_summaries) + len(constraints)
                           + len(causal_chains))

        _ep_summary = build_episode_summary(
            text, _ep_chunk_count, _ep_files, _ep_tools
        )

        # workspace_id — 从 cwd 派生
        _ep_ws_id = None
        try:
            _ep_cwd = hook_input.get("cwd", "") or os.environ.get("CLAUDE_CWD", "")
            if _ep_cwd:
                from store_workspace import _workspace_id as _ws_id_fn
                _ep_ws_id = _ws_id_fn(_ep_cwd)
        except Exception:
            pass

        write_episode(
            _ep_conn,
            session_id=session_id,
            project=project,
            summary=_ep_summary,
            workspace_id=_ep_ws_id,
            ended_at=datetime.now(timezone.utc).isoformat(),
            chunks_created=_ep_chunk_count,
            files_modified=_ep_files[:20],  # 最多记录 20 个文件
            tools_used=_ep_tools,
        )
        _ep_conn.close()
    except Exception:
        pass  # episode 写入失败不影响主流程

    # ── iter378: Persistent Working Set Serialization ────────────────────────
    # OS 类比：CRIU dump_task() — 序列化进程完整状态到磁盘，下次 restore 时无缝恢复。
    # 人的记忆类比：Denning (1968) Working Set Model — 工作集是进程"最近使用的页面集合"。
    #   每次项目切换（session 切换）后，人会自动带上该项目的工作集记忆（端口、配置、约束）。
    #   memory-os 等价：将本次会话中频繁访问的 chunk 序列化到 .ws_{project}.json，
    #   下次 SessionStart 时 loader.py 优先注入这些 hot chunks，而不是从 FTS5 冷启动重建。
    #
    # 直接解决"不记得端口"问题：
    #   端口/配置 chunk 每次被访问 → access_count 递增 → 进入 top-N 工作集 →
    #   下次会话开始时自动注入上下文 → Claude 无需每次重新检索。
    try:
        if _sysctl("loader.restore_working_set"):
            from agent_working_set import registry as _ws_registry
            _ws_obj = _ws_registry.get(session_id) if _ws_registry else None
            if _ws_obj is not None:
                _ws_chunks = _ws_obj.list_chunks()
                if _ws_chunks:
                    _ws_max = _sysctl("loader.ws_max_restore")
                    # 按 access_count 降序（热页优先），截取 top-N
                    _ws_sorted = sorted(
                        _ws_chunks,
                        key=lambda x: x.get("access_count", 0),
                        reverse=True,
                    )[:_ws_max]
                    # 序列化为精简格式（只保留检索需要的字段）
                    _ws_entries = []
                    for _wc in _ws_sorted:
                        _ws_entries.append({
                            "id": _wc.get("id", ""),
                            "summary": _wc.get("summary", ""),
                            "chunk_type": _wc.get("chunk_type", ""),
                            "importance": _wc.get("importance", 0.7),
                            "access_count": _wc.get("access_count", 0),
                        })
                    _ws_fname = f".ws_{project.replace(':', '_').replace('/', '_')}.json"
                    _ws_path = MEMORY_OS_DIR / _ws_fname
                    _ws_path.write_text(
                        json.dumps({
                            "project": project,
                            "session_id": session_id,
                            "saved_at": datetime.now(timezone.utc).isoformat(),
                            "chunks": _ws_entries,
                        }, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    try:
                        _ws_conn = open_db()
                        dmesg_log(_ws_conn, DMESG_INFO, "extractor",
                                  f"ws_serialize: {len(_ws_entries)} hot chunks → {_ws_fname}",
                                  session_id=session_id, project=project)
                        _ws_conn.commit()
                        _ws_conn.close()
                    except Exception:
                        pass
    except Exception:
        pass  # 工作集序列化失败不影响主流程

    # ── iter382: Reconsolidate on Stop — 召回触发重新巩固 ────────────────────
    # 神经科学依据：Nader et al. (2000) 再巩固理论 —
    #   记忆每次被检索后进入"不稳定窗口"（labile state），
    #   随后以更新形式重新巩固（re-stabilization）。
    #   重复且深度匹配的召回 → importance 上升（长期增强，LTP）。
    #
    # OS 类比：Linux ARC T1→T2 晋升 — 被反复命中的页面从"最近访问"
    #   晋升到"频繁访问"，淘汰优先级降低。
    #   session 结束时用本次 Stop hook 的 text 作为 query，
    #   对本次 session 中被注入（shadow trace）的 chunk 做再巩固。
    #
    # reconsolidate() 存在于 store_vfs.py 但从未在 Stop hook 调用（孤儿函数）
    # — iter382 修复此缺口：session 结束时自动强化被引用的记忆。
    try:
        # 获取本次 session 注入的 chunk IDs（shadow trace 或 recall_traces）
        _rc_injected_ids: list = []
        try:
            # 优先从 shadow trace 文件获取（最近检索工作集）
            import json as _rc_json
            _shadow_trace_path = MEMORY_OS_DIR / ".shadow_trace.json"
            if _shadow_trace_path.exists():
                _st_data = _rc_json.loads(_shadow_trace_path.read_text(encoding="utf-8"))
                if _st_data.get("project") == project:
                    _rc_injected_ids = _st_data.get("top_k_ids", [])
        except Exception:
            pass

        if not _rc_injected_ids:
            # Fallback: 从 recall_traces 获取本 session 的注入 IDs
            try:
                _rc_conn_ro = open_db()
                _rc_rows = _rc_conn_ro.execute(
                    """SELECT top_k_json FROM recall_traces
                       WHERE session_id=? AND project=? AND injected=1
                       ORDER BY timestamp DESC LIMIT 5""",
                    (session_id, project)
                ).fetchall()
                for _rc_row in _rc_rows:
                    if _rc_row[0]:
                        import json as _rc_json2
                        _rc_items = _rc_json2.loads(_rc_row[0])
                        for _rci in _rc_items:
                            _cid_r = _rci.get("id", "")
                            if _cid_r and _cid_r not in _rc_injected_ids:
                                _rc_injected_ids.append(_cid_r)
                _rc_conn_ro.close()
            except Exception:
                pass

        if _rc_injected_ids and text:
            from store_vfs import reconsolidate as _reconsolidate
            _rc_conn = open_db()
            ensure_schema(_rc_conn)
            _rc_n = _reconsolidate(
                _rc_conn,
                recalled_chunk_ids=_rc_injected_ids,
                query=text[-300:],   # 本轮 assistant 回复末尾作为 recall context
                project=project,
            )
            if _rc_n > 0:
                dmesg_log(_rc_conn, DMESG_DEBUG, "extractor",
                          f"reconsolidate: {_rc_n} chunks importance boosted",
                          session_id=session_id, project=project)
            _rc_conn.commit()
            _rc_conn.close()
    except Exception:
        pass  # reconsolidate 失败不影响主流程

    # ── Citation Detection — 使用反馈信号（CPU branch predictor feedback 类比）──
    # 检测 Claude 回复中实际引用了哪些被注入的 chunk，
    # 引用 → importance 微增；未引用 → importance 微减；级联更新 __semantic__ 层。
    # OS 类比：PMU branch misprediction counter — 每次推理结束后更新预测器权重。
    try:
        from tools.citation_detector import run_citation_detection
        run_citation_detection(
            reply_text=hook_input.get("last_assistant_message", ""),
            project=project,
            session_id=session_id,
        )
    except Exception:
        pass  # citation detection 失败不影响主流程

    sys.exit(0)


if __name__ == "__main__":
    main()


def _extract_session_intent(text: str) -> dict:
    """
    迭代110 P2: CRIU Session Intent Extraction — 提取会话末尾的未完成意图。

    OS 类比：CRIU dump_task() — 序列化进程当前执行状态（PC、stack、open files）。
    这里序列化的是 Claude 的"执行状态"：
      - 下一步要做什么（next_actions）
      - 还有哪些问题未解决（open_questions）
      - 正在进行中的工作（partial_work）

    返回 {"next_actions": [...], "open_questions": [...], "partial_work": [...]}
    任何列表为空则该字段不存在。
    """
    import re as _re

    NEXT_ACTION_PATTERNS = [
        r'(?:接下来(?:需要|要|应该)|下一步(?:是|需要|要)|还需要|然后(?:需要|要))[：:]?\s*(.{5,80})',
        r'(?:next[,:\s]+(?:step|action|task|we need)[s]?)[：:\s]+(.{5,80})',
        r'(?:TODO|待做|待完成|后续)[：:]\s*(.{5,80})',
        r'(?:^|\n)\d+\.\s+(?:然后|接着|再|最后)\s*(.{5,60})',
    ]
    OPEN_QUESTION_PATTERNS = [
        r'(?:需要验证|待验证|待确认|需要确认|不确定|还不清楚)[：:]?\s*(.{5,80})',
        r'(?:需要查看|需要读|需要了解|需要检查)[：:]?\s*(.{5,60})',
        r'(?:question|need to verify|not sure|unclear)[:\s]+(.{5,80})',
        r'(?:假设|假定)\s*(.{5,60})\s*(?:待验证|需要确认)',
    ]
    PARTIAL_WORK_PATTERNS = [
        r'(?:正在|目前正在|当前正在)[：:]?\s*(.{5,60})',
        r'(?:已完成[^，。\n]*?，?但(?:还|仍)(?:需要|要|未))\s*(.{5,80})',
        r'(?:partially|in progress|working on)[:\s]+(.{5,80})',
    ]

    result = {}

    # 只扫描文本的最后 2000 字符（意图通常在消息末尾）
    sample = text[-2000:] if len(text) > 2000 else text

    def _extract_pattern(patterns, sample_text):
        items = []
        seen = set()
        for pat in patterns:
            for m in _re.finditer(pat, sample_text, _re.MULTILINE | _re.IGNORECASE):
                captured = m.group(1).strip()
                captured = _re.split(r'[\n。！？]', captured)[0].strip()
                captured = _re.sub(r'\*{1,3}|`{1,3}', '', captured).strip()
                key = _re.sub(r'\s+', '', captured.lower())
                if len(captured) >= 5 and key not in seen:
                    seen.add(key)
                    items.append(captured[:80])
        return items[:3]  # 每类最多 3 条

    next_actions = _extract_pattern(NEXT_ACTION_PATTERNS, sample)
    open_questions = _extract_pattern(OPEN_QUESTION_PATTERNS, sample)
    partial_work = _extract_pattern(PARTIAL_WORK_PATTERNS, sample)

    if next_actions:
        result["next_actions"] = next_actions
    if open_questions:
        result["open_questions"] = open_questions
    if partial_work:
        result["partial_work"] = partial_work

    return result


def _promote_to_global(conn, project: str, session_id: str) -> int:
    """
    迭代94: Cross-Project Knowledge Promotion — 跨项目知识晋升

    OS 类比：Linux 内核模块（.ko）的跨进程共享 — 内核代码段被所有进程共享，
    而不是每个进程各自复制一份。高价值知识同理：不应被项目边界割裂。

    将本项目中高重要性（importance >= 0.85）且被多次访问（access_count >= 3）
    的知识晋升到全局层（project="global"），使所有项目都能检索到。

    条件：
    - importance >= 0.85（顶层知识）
    - access_count >= 3（经过实战验证）
    - chunk_type in (decision, reasoning_chain)（方法论类知识，而非 prompt_context）
    - 全局层尚无相同 summary
    """
    from datetime import datetime, timezone
    import json as _json, uuid as _uuid

    if project == "global":
        return 0  # 防止循环

    try:
        # iter B10：global capacity guard — 超配时暂停晋升
        global_count = conn.execute(
            "SELECT count(*) FROM memory_chunks WHERE project='global'"
        ).fetchone()[0]
        global_quota = 200
        if global_count >= global_quota:
            return 0  # 超配，不再晋升，让自然 eviction 回落

        candidates = conn.execute(
            """SELECT id, chunk_type, summary, content, importance, tags
               FROM memory_chunks
               WHERE project NOT IN ('global', 'test')
                 AND chunk_type IN ('procedure')
                 AND importance >= 0.92
                 AND access_count >= 5
               ORDER BY importance DESC, access_count DESC
               LIMIT 2"""
        ).fetchall()

        promoted = 0
        for row in candidates:
            src_id, ctype, summary, content, imp, tags = row
            # iter B14：过滤进度日志和低质量summary
            if re.match(r'^\[memory-os/iter\d+\]', summary):
                continue
            if re.match(r'^✅\s', summary):
                continue
            if re.match(r'^\[sched_ext\].*>\s', summary):  # sched_ext 子章节碎片
                continue
            # ── iter541: inode_permission — 全局晋升路径写入门控 ──
            # 此前直接 INSERT 绕过 _vfs_write_protect()，导致碎片泄漏
            try:
                from store_vfs import _vfs_write_protect
                if _vfs_write_protect(summary):
                    continue
            except ImportError:
                pass
            # 检查全局层是否已有
            exists = conn.execute(
                "SELECT id FROM memory_chunks WHERE project='global' AND summary=?",
                [summary]
            ).fetchone()
            if exists:
                continue
            now = datetime.now(timezone.utc).isoformat()
            global_id = f"global-{_uuid.uuid4().hex[:12]}"
            conn.execute("""
                INSERT INTO memory_chunks
                (id, created_at, updated_at, project, source_session,
                 chunk_type, content, summary, tags, importance,
                 retrievability, last_accessed, access_count, lru_gen, oom_adj)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [global_id, now, now, "global", f"promoted:{project}",
                  ctype, content, summary,
                  tags if isinstance(tags, str) else _json.dumps(["global", project]),
                  imp, 0.5, now, 0, 0, -400])
            promoted += 1

        if promoted > 0:
            dmesg_log(conn, DMESG_INFO, "extractor",
                      f"global_promote: {promoted} chunks from {project}",
                      session_id=session_id, project=project)
        return promoted
    except Exception:
        return 0
