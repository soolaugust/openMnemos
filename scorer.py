"""
memory-os Unified Scorer — 统一评分引擎

迭代 20：OS 类比 — Linux CFS (Completely Fair Scheduler, 2007)
迭代 34：OS 类比 — Linux Second Chance / Clock Algorithm (1994)
迭代 111：OS 类比 — Linux NUMA node distance penalty (numactl --hardware)

CFS 背景（迭代20）：
  早期 Linux 的 O(1) scheduler 有多个子系统各自计算优先级（实时/批处理/idle），
  导致优先级反转、评分不一致、代码重复三大问题。
  CFS 统一用 vruntime = actual_runtime / weight 一个值排序所有进程，
  所有调度决策基于同一棵红黑树，消除了分散评分的不一致。

Second Chance 背景（迭代34）：
  纯 LRU 页面替换的缺陷：新加载的页面如果不被立即再访问，
  很快就会被驱逐——即使它可能在不远的将来被需要。
  Second Chance (Clock) 算法给每个新页面一个初始的 Referenced bit，
  时钟扫描到时不立即驱逐，而是清除 bit 给"第二次机会"。
  只有在 Referenced=0 时才真正驱逐。

  memory-os 的等价问题：
    新写入的 chunk（access_count=0）在纯 BM25+recency 检索中排名靠后，
    被旧的高 access_count chunk 压制——信息茧房。
    freshness_bonus 给新 chunk 一个 grace period 内的加分（等价于 Second Chance），
    过了 grace period 后 bonus 衰减为 0，靠自身 importance+access 参与排序。

解决（迭代20）：
  1. 统一 base_score 计算：importance_with_decay, recency_score, access_bonus
  2. 按场景组合：retrieval_score / retention_score / working_set_score
  3. 消除 3 个文件中的重复函数定义

解决（迭代34 增量）：
  4. freshness_bonus(created_at) — 新 chunk 在 grace_days 内获得衰减加分
  5. retrieval_score 公式增加 freshness_bonus 项
"""
import math
import hashlib
from datetime import datetime, timezone

# 迭代27: sysctl Runtime Tunables — 延迟导入避免循环
def _sysctl(key):
    try:
        from config import get
        return get(key)
    except Exception:
        # fallback defaults（config.py 不可用时）
        _defaults = {
            "scorer.importance_decay_rate": 0.95,
            "scorer.importance_floor": 0.3,
            "scorer.access_bonus_cap": 0.2,
            "scorer.freshness_bonus_max": 0.15,
            "scorer.freshness_grace_days": 7,
            "scorer.saturation_factor": 0.04,
            "scorer.saturation_cap": 0.25,
            "scorer.starvation_boost_factor": 0.30,
            "scorer.starvation_min_age_days": 0.5,
            "scorer.starvation_ramp_days": 3.0,
        }
        return _defaults.get(key)

# ── iter259: 热路径常量预加载 ────────────────────────────────────
# _sysctl() 每次调用做 try/import/dict-lookup（~1.3us），热函数共调 8 次。
# 模块加载时一次性读取为常量，消除运行时开销。
_DECAY_RATE = _sysctl("scorer.importance_decay_rate")
_IMP_FLOOR = _sysctl("scorer.importance_floor")
_AB_CAP = _sysctl("scorer.access_bonus_cap")
_FB_MAX = _sysctl("scorer.freshness_bonus_max")
_FB_GRACE = _sysctl("scorer.freshness_grace_days")
_SAT_FACTOR = _sysctl("scorer.saturation_factor")
_SAT_CAP = _sysctl("scorer.saturation_cap")
_STARV_FACTOR = _sysctl("scorer.starvation_boost_factor")
_STARV_MIN_AGE = _sysctl("scorer.starvation_min_age_days")
_STARV_RAMP = _sysctl("scorer.starvation_ramp_days")
# ── 迭代333：TMV 常量预加载 ──
_TMV_ACC_THRESHOLD = _sysctl("scorer.tmv_acc_threshold") or 50
_TMV_DISCOUNT_WEIGHT = _sysctl("scorer.tmv_discount_weight") or 0.30
_TMV_DISCOUNT_FLOOR = _sysctl("scorer.tmv_discount_floor") or 0.55
# ── iter527: cgroup_cpu_max 带宽硬限常量预加载 ──
_BW_MAX_PCT = _sysctl("scorer.bw_max_pct") or 0.30
_BW_THROTTLE = _sysctl("scorer.bw_throttle") or 0.15
_BW_WINDOW = _sysctl("scorer.bw_window") or 30

# ── iter261: math.log2 查表 ──────────────────────────────────────
# access_bonus (access_count 1..270) 和 saturation_penalty (recall_count 1..270)
# 都调 math.log2(1+x)。预计算为 tuple，消除函数调用开销。
_LOG2_TABLE_SIZE = 271
_LOG2_1P = tuple(math.log2(1 + i) for i in range(_LOG2_TABLE_SIZE))

# ── iter260: _age_days now() 缓存 ────────────────────────────────
# retrieval_score 内 _age_days 被调 2~3 次，每次 datetime.now(utc)。
# 单次请求内 now 不变，缓存到模块级 _NOW_CACHE 由 _refresh_now() 刷新。
_NOW_CACHE = datetime.now(timezone.utc)
_NOW_TS = _NOW_CACHE.timestamp()

def _refresh_now():
    """在每次 retrieval_score 入口刷新一次 now 缓存。"""
    global _NOW_CACHE, _NOW_TS
    _NOW_CACHE = datetime.now(timezone.utc)
    _NOW_TS = _NOW_CACHE.timestamp()


# ── 基础评分原语 ─────────────────────────────────────────────────

def recency_score(iso_str: str) -> float:
    """
    时间衰减评分：越近分越高。
    公式：1 / (1 + age_days)，范围 [0, 1]。
    """
    age_days = _age_days(iso_str)
    return 1.0 / (1.0 + age_days)


def importance_with_decay(importance: float, last_accessed: str,
                          chunk_type: str = "") -> float:
    """
    OS 类比：page aging bit — 未被访问的页 age 递增。
    遗忘曲线：effective_importance = importance × decay(age)
    decay = 0.95^(age_days / 7)  →  每 7 天衰减 5%
    半衰期 ≈ 90 天，最低下限 0.3。

    iter375: Type-Differential Decay Rates — 人类记忆中情节记忆比语义记忆衰减更快
    (Tulving 1972 / Squire 1987 — 记忆系统双重过程理论)
    OS 类比：Linux MGLRU 按 generation 分级淘汰 — younger pages age faster
      - episodic (task_state, conversation_summary): 快速衰减，half-life 短
      - semantic (decision, design_constraint, reasoning_chain): 慢速衰减
      - procedural (procedure): 中速衰减
    实现：通过 per-type 的 decay_rate sysctl，覆盖全局 _DECAY_RATE
    """
    # iter375: 按 chunk_type 查找类型专属 decay_rate
    # 未配置时 fallback 到全局 _DECAY_RATE
    _TYPE_DECAY_SYSCTL = {
        "task_state":             "scorer.decay_rate_task_state",
        "conversation_summary":   "scorer.decay_rate_conversation_summary",
        "decision":               "scorer.decay_rate_decision",
        "design_constraint":      "scorer.decay_rate_design_constraint",
        "reasoning_chain":        "scorer.decay_rate_reasoning_chain",
        "quantitative_evidence":  "scorer.decay_rate_quantitative_evidence",
        "causal_chain":           "scorer.decay_rate_causal_chain",
        "excluded_path":          "scorer.decay_rate_excluded_path",
        "procedure":              "scorer.decay_rate_procedure",
    }
    effective_decay = _DECAY_RATE
    if chunk_type and chunk_type in _TYPE_DECAY_SYSCTL:
        try:
            _td = _sysctl(_TYPE_DECAY_SYSCTL[chunk_type])
            if _td is not None:
                effective_decay = float(_td)
        except Exception:
            pass  # fallback to global _DECAY_RATE

    age = _age_days(last_accessed)
    decay = effective_decay ** (age / 7.0)
    return max(_IMP_FLOOR, importance * decay)


def access_bonus(access_count: int) -> float:
    """
    OS 类比：MMU Accessed bit 置位 + kswapd 扫描计数。
    log2(1 + count) × 0.05，上限 0.2。
    避免线性增长导致高频 chunk 垄断。

    iter831: access_diminishing_return — ac>8 时衰减 bonus，
    防止高频 chunk 的 access_bonus 固化为 0.20 不变的永久优势。
    ac=10→0.83x, ac=12→0.71x, ac=20→0.45x
    """
    if access_count <= 0:
        return 0.0
    _l = _LOG2_1P[access_count] if access_count < _LOG2_TABLE_SIZE else math.log2(1 + access_count)
    ab = min(_AB_CAP, _l * 0.05)
    # iter831: diminishing return for over-exposed chunks
    if access_count > 8:
        ab *= 1.0 / (1.0 + (access_count - 8) * 0.1)
    return ab


def freshness_bonus(created_at: str) -> float:
    """
    迭代34：Second Chance — 新知识曝光公平性。
    OS 类比：Clock Algorithm 的 Referenced bit 初始置位。

    新 chunk 在 grace_days 内获得衰减加分，保证新知识有机会被召回：
      bonus = max_bonus × max(0, 1 - age / grace_days)
    效果：
      - 刚写入：bonus = max_bonus（满额加分，等价于 Referenced=1）
      - grace_days/2 时：bonus = max_bonus/2（半衰）
      - 超过 grace_days：bonus = 0（等价于 Referenced 被清除，靠自身竞争力）
    如果在 grace period 内被召回（access_count > 0），access_bonus 接力。
    """
    age = _age_days(created_at)
    if age >= _FB_GRACE:
        return 0.0
    return _FB_MAX * (1.0 - age / _FB_GRACE)


def saturation_penalty(recall_count: int) -> float:
    """
    迭代62：Anti-Starvation — 反复召回的 chunk 获得饱和惩罚。
    OS 类比：Linux CFS vruntime aging — 长期占用 CPU 的进程 vruntime 递增，
    排序后退让位给 vruntime 更小的进程。

    当同一 chunk 在最近 N 次检索中被反复选入 Top-K：
      penalty = factor × log2(1 + recall_count)
    效果：
      - recall_count=0: penalty=0（新入选无惩罚）
      - recall_count=3: penalty≈0.08（轻微后退）
      - recall_count=10: penalty≈0.14（明显后退，给其他 chunk 机会）
      - recall_count=30: penalty≈0.20（接近 cap）
    cap 防止热门知识被完全压制。
    """
    if recall_count <= 0:
        return 0.0
    _l = _LOG2_1P[recall_count] if recall_count < _LOG2_TABLE_SIZE else math.log2(1 + recall_count)
    penalty = _SAT_FACTOR * _l
    return min(_SAT_CAP, penalty)


def bandwidth_throttle(recall_count: int, window: int = 0) -> float:
    """
    iter527：cgroup_cpu_max — 硬性召回带宽限制器。
    OS 类比：Linux cgroup v2 cpu.max (Tejun Heo, 2015) — 每个 cgroup 声明
      MAX PERIOD（如 50000 100000 = 50% 带宽），超额则 throttle 直到下一周期。
      不同于 nice/weight（软优先级），cpu.max 是硬上限（hard cap）。

    问题（数据驱动）：
      chunk 3192147e (design_constraint, access=89) 出现在 43% 的 recall_traces 中。
      saturation_penalty caps at 0.25（对数曲线太缓），无法阻止该 chunk 持续垄断 Top-K。
      正反馈循环：高 recall → 高 access → 高 access_bonus → 更高 score → 更高 recall。

    解决：
      当 recall_count / window > bw_max_pct 时，返回乘法 throttle 因子。
      最终 score *= bandwidth_throttle(...)，将该 chunk 压制到极低分数。

    返回值：
      1.0 — 未超 bandwidth（正常参与评分）
      bw_throttle (默认0.15) — 超额后的乘法折扣（85% 削减）

    与 saturation_penalty 互补：
      saturation_penalty: 软惩罚，加法减去，上限 0.25，所有 recall_count>0 都触发
      bandwidth_throttle: 硬限制，乘法削减，仅超过 bw_max_pct 阈值时触发
      前者平滑降频，后者断路保护——类比 CPU throttle thermal trip 和 thermal warning 的关系。
    """
    if recall_count <= 0:
        return 1.0
    _w = window if window > 0 else _BW_WINDOW
    if _w <= 0:
        return 1.0
    # 带宽利用率 = recall_count / window_size
    utilization = recall_count / _w
    if utilization <= _BW_MAX_PCT:
        return 1.0  # 未超带宽上限
    # 超额：应用硬 throttle
    return _BW_THROTTLE


def cfs_bandwidth_throttle(recall_count: int,
                           quota: int = 8,
                           throttle_factor: float = 0.50,
                           overflow_decay: float = 0.85) -> float:
    """
    iter560: cfs_bandwidth — Per-Chunk Retrieval Frequency Throttle.

    OS 类比：Linux CFS Bandwidth Control (Paul Turner, Google, 2011, kernel 3.2,
    kernel/sched/fair.c, cfs_bandwidth.c)
      每个 cgroup 分配 quota μs / period μs 的 CPU 带宽。task 运行时消耗 quota；
      当 quota 耗尽，throttle_cfs_rq() 将整个 cgroup 的 runqueue dequeue，
      所有 task 停止调度直到下一个 period 的 do_sched_cfs_period_timer() refill。
      超额越多（burst），下一个 period 的 refill 被 clamp，惩罚递进。

    与 saturation_penalty / bandwidth_throttle 的区别：
      saturation_penalty (iter62):  加法 cap=0.25，log2 增长，无法压制 base>0.8
      bandwidth_throttle (iter527): 二值硬 throttle（1.0 或 0.15），无渐进过渡
      cfs_bandwidth (iter560):      乘法渐进 — score *= factor * decay^(rc-quota)
        rc=quota+1: 0.50 * 0.85^1 = 0.425  (57.5% 削减)
        rc=quota+5: 0.50 * 0.85^5 = 0.222  (77.8% 削减)
        rc=quota+10: 0.50 * 0.85^10 = 0.099 (90.1% 削减)
      渐进压制避免二值跳变，同时比 log2 加法强得多。

    返回值：
      1.0 — recall_count <= quota（未超额，正常评分）
      (0, 1) — 超额后的乘法因子，越超越小
    """
    if recall_count <= quota:
        return 1.0
    overflow = recall_count - quota
    return throttle_factor * (overflow_decay ** overflow)


def tmv_saturation_discount(access_count: int) -> float:
    """
    迭代333：Temporal Marginal Value (TMV) — 乘法饱和折扣。

    信息论背景（Shannon 1948 + Redundancy Theory）：
      多次召回后，chunk 携带的边际信息 I(chunk | already_known) 趋近于零。
      高频召回 = agent 已"内化"该知识 → 继续注入 = 纯冗余（高 redundancy，零 novelty）。
      形式化：H(chunk | context) ≈ H(chunk) × (1 - familiarity_factor)
      这里 familiarity_factor = log(acc/T) / log(∞) 的有界近似。

    OS 类比：Linux NUMA distance penalty (numactl, 2003) —
      访问 local node（acc 低 = 新知识）≈ local memory access（1x cost）
      访问 remote node（acc 高 = 饱和知识）≈ remote NUMA hop（1.2-3x latency）
      调度器在 score 中减去 distance_factor × numa_distance，让 local 优先。
      TMV 等价：score × (1 - discount) 让低 acc（新颖）chunk 相对得分更高。

    与 saturation_penalty 的区别：
      saturation_penalty：基于 recall_count（最近30次召回频次），加法减去，上限 0.25
      tmv_saturation_discount：基于 access_count（总生命周期），乘法折扣，直接缩放 score
      两者互补：saturation_penalty 防止热门 chunk 垄断检索，
                tmv 防止"已知"知识占用宝贵 context window。

    折扣公式：
      ratio = log(acc / threshold) / log(1000 / threshold)  [归一化到 0-1]
      discount = discount_weight × ratio
      multiplier = max(floor, 1.0 - discount)

    示例（threshold=50, weight=0.30, floor=0.55）：
      acc=50:   ratio=0.0  multiplier=1.00  （刚到阈值，无折扣）
      acc=100:  ratio=0.23 multiplier=0.93  （轻微折扣）
      acc=500:  ratio=0.70 multiplier=0.79  （明显折扣）
      acc=2044: ratio=1.04 multiplier≈0.69  （大幅折扣，上限 floor=0.55 保护）

    Returns:
      multiplier ∈ [floor, 1.0]，用于 score × multiplier
    """
    if access_count < _TMV_ACC_THRESHOLD:
        return 1.0  # 快速路径：低 acc chunk 不折扣
    # 对数归一化：log(acc/T) / log(1000/T)，acc=T → 0，acc=1000 → 1.0
    _log_ratio = math.log(access_count / _TMV_ACC_THRESHOLD) / max(
        0.001, math.log(1000.0 / _TMV_ACC_THRESHOLD)
    )
    _log_ratio = min(1.0, _log_ratio)  # 超过 1000 不额外惩罚
    discount = _TMV_DISCOUNT_WEIGHT * _log_ratio
    return max(_TMV_DISCOUNT_FLOOR, 1.0 - discount)


def starvation_boost(access_count: int, age_days: float) -> float:
    """
    迭代62：Anti-Starvation — 长期未被访问的 chunk 获得饥饿加分。
    OS 类比：O(1) scheduler dynamic priority boost — 长期未被调度的进程
    获得优先级提升（nice 值递减），防止低优先级进程永远无法执行。

    条件：access_count == 0 且存在超过 min_age_days
      boost = factor × min(1.0, (age_days - min_age_days) / ramp_days)
    效果：
      - age < min_age_days: boost=0（freshness_bonus 还在生效）
      - age = min_age_days + ramp_days/2: boost=factor/2
      - age >= min_age_days + ramp_days: boost=factor（满额）
    factor 默认 0.30 — 足以打破 relevance 0.15 对 relevance 1.0 的弱势。
    """
    if access_count > 0:
        return 0.0
    if age_days < _STARV_MIN_AGE:
        return 0.0
    progress = min(1.0, (age_days - _STARV_MIN_AGE) / max(0.1, _STARV_RAMP))
    return _STARV_FACTOR * progress


def exploration_bonus(chunk_id: str, access_count: int, query_seed: str = "") -> float:
    """
    迭代43：ASLR — 检索结果多样性随机化。
    OS 类比：Linux ASLR (Address Space Layout Randomization, 2005)

    ASLR 背景：
      攻击者利用固定的内存布局预测关键数据地址（如栈/堆/libc）。
      ASLR 在每次进程启动时随机化 mmap/stack/heap 基地址，
      使攻击者无法可靠预测地址 → 大幅提高漏洞利用难度。

    memory-os 等价问题：
      BM25+importance+recency 是确定性评分 → 对相似 query，
      相同 Top-K 永远被返回 → 信息茧房（只见旧热门 chunk）。
      低 access_count 的长尾知识永远无法被召回 → 知识遗忘。

    解决：
      对 access_count 低于阈值的 chunk 叠加确定性伪随机扰动：
        bonus = epsilon × (1 - access_count/threshold) × hash(chunk_id + query_seed)
      特性：
        - 确定性：同一 query + 同一 chunk → 相同 bonus（可复现）
        - 跨 query 差异：不同 query 产生不同排列（query_seed 变化）
        - 访问越多扰动越小：高 access_count chunk 几乎不受影响
        - access_count ≥ threshold 时 bonus=0（完全稳定）
    """
    threshold = _sysctl("scorer.aslr_access_threshold")
    if access_count >= threshold:
        return 0.0
    epsilon = _sysctl("scorer.aslr_epsilon")
    if epsilon <= 0:
        return 0.0
    # 确定性伪随机：hash(chunk_id + query_seed) → [0, 1)
    seed_str = f"{chunk_id}:{query_seed}"
    h = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)
    pseudo_random = (h % 10000) / 10000.0  # [0, 1)
    # 访问越少扰动越大
    access_ratio = access_count / threshold
    return epsilon * (1.0 - access_ratio) * pseudo_random


def access_frequency(access_count: int) -> float:
    """
    访问频率归一化（淘汰场景，范围 0-1）。
    log2(1 + count) / 4，上限 1.0。
    """
    if access_count <= 0:
        return 0.0
    return min(1.0, math.log2(1 + access_count) / 4.0)


# ── 组合评分 ─────────────────────────────────────────────────────

def verification_boost(confidence_score: float, verification_status: str) -> float:
    """
    迭代100：验证加分 — 高置信度或已验证 chunk 获得排序加分。
    OS 类比：ECC 校验通过的内存页可直接使用，不需重读。
    """
    if verification_status == "verified":
        return 0.12
    if confidence_score >= 0.9:
        return 0.08
    if confidence_score >= 0.8:
        return 0.04
    return 0.0


def verification_penalty(verification_status: str) -> float:
    """
    迭代100：验证惩罚 — 被标记为错误的 chunk 降低排序。
    OS 类比：ECC uncorrectable error — 标记页面为 poison，避免使用。
    """
    if verification_status == "disputed":
        return 0.18
    return 0.0


def lru_gen_boost(lru_gen: int, max_gen: int = 8) -> float:
    """
    iter106: MGLRU 语义 LRU 加权项。
    lru_gen=0 最热（最近被访问/promoted），gen 越大越冷。
    boost = 0.06 × (1 - gen/max_gen)  →  gen=0: +0.06, gen=4: +0.03, gen=8: 0
    OS 类比：Linux MGLRU folio_lru_gen() — 按代龄决定优先换出/保留优先级。
    """
    if lru_gen is None or lru_gen < 0:
        return 0.0
    gen = min(lru_gen, max_gen)
    return 0.06 * (1.0 - gen / max_gen)


def numa_distance_penalty(chunk_project: str, current_project: str) -> float:
    """
    NUMA node distance 惩罚项（迭代111）。

    OS 类比：Linux NUMA — numactl --hardware 输出 node distances 矩阵，
      同 node 访问 latency=10, 远 node=20-40+。
      调度器在分配内存时优先本地 node，跨 node 有延迟惩罚。

    memory-os 类比：
      chunk 的 project 就是 "NUMA node"。
      在当前 project 上下文中，跨项目 chunk 的"访问延迟"更高（相关性更低）。

    惩罚矩阵：
      same project  → 0.0   (本地 node，无惩罚)
      global project → 0.05  (共享 global tier，轻微惩罚)
      other project  → 0.25  (远端 node，较大惩罚)

    注：惩罚不是绝对拒绝，高 relevance 的跨项目 chunk 依然可以进入 top_k。
    仅阻止低相关性跨项目 chunk 通过"高 importance"挤占名额。
    """
    if not chunk_project or not current_project:
        return 0.0
    if chunk_project == current_project:
        return 0.0
    if chunk_project == "global":
        return 0.05
    return 0.25


def context_match_score(query_context: dict, chunk_context: dict) -> float:
    """
    迭代315: Encoding Specificity — 检索情境与编码情境匹配度。
    Tulving 1973: 检索线索与编码时线索重叠越高，记忆提取成功率越高。

    三维匹配：
      1. session_type 匹配：完全相同 +0.08，均为 unknown +0
      2. entities 重叠：Jaccard(query_entities, chunk_entities) × 0.12
      3. task_verbs 重叠：Jaccard(query_verbs, chunk_verbs) × 0.06

    总分上限 0.20（不超过 relevance 的影响范围）
    """
    if not query_context or not chunk_context:
        return 0.0
    score = 0.0
    # session_type
    qt = query_context.get("session_type", "unknown")
    ct = chunk_context.get("session_type", "unknown")
    if qt != "unknown" and qt == ct:
        score += 0.08
    # entities Jaccard
    qe = set(query_context.get("entities", []))
    ce = set(chunk_context.get("entities", []))
    if qe or ce:
        inter = len(qe & ce)
        union = len(qe | ce)
        if union > 0:
            score += (inter / union) * 0.12
    # task_verbs Jaccard
    qv = set(query_context.get("task_verbs", []))
    cv = set(chunk_context.get("task_verbs", []))
    if qv or cv:
        inter = len(qv & cv)
        union = len(qv | cv)
        if union > 0:
            score += (inter / union) * 0.06
    return min(0.20, score)


def retrieval_score(relevance: float, importance: float,
                    last_accessed: str, access_count: int = 0,
                    created_at: str = "",
                    chunk_id: str = "", query_seed: str = "",
                    recall_count: int = 0,
                    session_recall_count: int = 0,
                    confidence_score: float = 0.7,
                    verification_status: str = "pending",
                    lru_gen: int = None,
                    chunk_project: str = "",
                    current_project: str = "",
                    encoding_context: dict = None,
                    query_context: dict = None,
                    query_alpha: float = None,
                    chunk_type: str = "") -> float:
    """
    召回评分（retriever.py 使用）。
    score = relevance × (base_score + access_bonus + freshness_bonus)
            + exploration_bonus + starvation_boost - saturation_penalty
            + verification_boost - verification_penalty
            - numa_distance_penalty
    base_score = eff_importance × 0.55 + recency × 0.45

    迭代34：新增 freshness_bonus 项（Second Chance）。
    迭代43：新增 exploration_bonus 项（ASLR 多样性随机化）。
    迭代62：新增 saturation_penalty + starvation_boost（Anti-Starvation）。
    迭代100：新增 verification_boost + verification_penalty（ECC 可验证性）。
    迭代106：新增 lru_gen_boost（MGLRU 语义 LRU）。
    迭代111：新增 numa_distance_penalty（NUMA 节点距离惩罚）。
    迭代312：新增 session_recall 额外饱和惩罚（Session-scoped Familiarity Suppression）。
    迭代315：新增 context_match（情境匹配加分，Encoding Specificity）。

    十一项互补机制：
      freshness: 新 chunk 在 grace period 内获得初始曝光
      access:    被使用的 chunk 积累经验优势
      exploration: 低访问 chunk 获得伪随机偶发机会
      starvation: access_count=0 的老 chunk 获得递增加分
      saturation: 反复被召回的 chunk 获得递增惩罚（软 penalty，加法）
      bandwidth: 召回频率超 30% 带宽时硬性削减（硬 throttle，乘法）
      session_recall: session 内重复注入获得 2× 饱和惩罚（防止信息茧房）
      verification: 已验证 chunk 加分，disputed chunk 惩罚（ECC）
      lru_gen: gen=0(热) 加分最大，gen 越大惩罚递增（语义 LRU）
      numa_distance: 跨项目 chunk 获得 0.05-0.25 惩罚（本地 node 优先）
      context_match: 情境匹配加分（最高+0.20）
    """
    _refresh_now()  # iter260: 单次刷新 now 缓存，后续 _age_days 复用
    # iter375: type-differential decay — pass chunk_type for per-type decay rate
    eff_imp = importance_with_decay(importance, last_accessed, chunk_type=chunk_type)
    rec = recency_score(last_accessed)
    ab = access_bonus(access_count)
    fb = freshness_bonus(created_at) if created_at else 0.0
    eb = exploration_bonus(chunk_id, access_count, query_seed) if chunk_id else 0.0
    # 迭代62: Anti-Starvation
    age = _age_days(created_at) if created_at else 0.0
    sb = starvation_boost(access_count, age)
    sp = saturation_penalty(recall_count)
    # 迭代312: Session-scoped Familiarity Suppression
    # session 内重复注入的 chunk 额外 2× 饱和惩罚（防止信息茧房）
    if session_recall_count > 0:
        sp += saturation_penalty(session_recall_count) * 2.0
    # 迭代100: ECC Verification
    vb = verification_boost(confidence_score, verification_status)
    vp = verification_penalty(verification_status)
    # 迭代106: MGLRU lru_gen boost
    lgb = lru_gen_boost(lru_gen) if lru_gen is not None else 0.0
    # 迭代111: NUMA distance penalty
    ndp = numa_distance_penalty(chunk_project, current_project)
    # 迭代322: Query-Conditioned Importance — 动态 α 权重
    # OS 类比：Linux CPU frequency scaling (CPUFreq) — 根据负载动态调整频率
    #   高 relevance（强 query 命中）→ FTS5 rank 已是主信号，importance 降权（α 小）
    #   低 relevance（弱命中/BM25 fallback）→ 主要靠 importance 先验筛选（α 大）
    # α = query_alpha（外部传入）或默认固定值 0.55
    # base = eff_imp × α + rec × (1 - α)
    if query_alpha is not None:
        w_imp = float(query_alpha)
        w_imp = max(0.1, min(0.9, w_imp))  # clamp to [0.1, 0.9]
    else:
        w_imp = 0.55  # 默认值（向后兼容）
    base = eff_imp * w_imp + rec * (1.0 - w_imp)
    # 迭代315: Encoding Specificity — 情境匹配加分
    cm = context_match_score(query_context, encoding_context)
    score = relevance * (base + ab + fb) + eb + sb - sp + vb - vp + lgb - ndp + cm
    # iter527: cgroup_cpu_max — 硬性带宽限制（超额时乘法削减）
    # iter560: cfs_bandwidth — 渐进式频次 throttle（超 quota 后 score *= factor * decay^overflow）
    # cfs_bandwidth 是 bandwidth_throttle 的渐进替代：bandwidth_throttle 是二值（1.0 或 0.15），
    # cfs_bandwidth 是连续衰减（factor * decay^overflow）。两者取更强者（min），避免冗余堆叠。
    bw = bandwidth_throttle(recall_count)
    cbw = cfs_bandwidth_throttle(recall_count)
    return score * min(bw, cbw)


def working_set_score(importance: float, last_accessed: str) -> float:
    """
    工作集评分（loader.py 使用）。
    score = eff_importance × 0.55 + recency × 0.45
    与 retrieval_score 一致但不含 relevance 和 access_bonus。
    （迭代87：0.7/0.3 → 0.55/0.45）
    """
    eff_imp = importance_with_decay(importance, last_accessed)
    rec = recency_score(last_accessed)
    return eff_imp * 0.55 + rec * 0.45  # 迭代87: recency 提权


def retention_score(importance: float, last_accessed: str,
                    uniqueness: float, access_count: int = 0) -> float:
    """
    保留评分（memory_eviction.py 使用）。
    retention = importance × 0.4 + recency × 0.15 + uniqueness × 0.25 + access_freq × 0.2
    """
    rec = recency_score(last_accessed)
    af = access_frequency(access_count)
    return importance * 0.4 + rec * 0.15 + uniqueness * 0.25 + af * 0.2


# ── 内部工具 ─────────────────────────────────────────────────────

def _age_days(iso_str: str) -> float:
    """从 ISO 时间字符串计算距今天数。使用 _NOW_TS 缓存避免重复 syscall。"""
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (_NOW_TS - dt.timestamp()) / 86400)
    except Exception:
        return 30.0
