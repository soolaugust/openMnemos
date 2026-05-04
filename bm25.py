"""
memory-os BM25 Shared Library -- 统一文本检索引擎

迭代 22：OS 类比 -- Linux Shared Libraries (.so, 1988)

背景：
  早期 Unix 每个程序静态链接自己的 libc 副本（a.out 格式），
  libc 的 bug 修复需要重编译所有程序，磁盘和内存中存在大量重复代码。
  1988 年 SunOS 4.0 引入 .so (shared object)，多个进程 mmap 同一份物理页，
  修一处全局生效，新程序无需重编译即可获得修复。

当前问题（迭代 1-21）：
  - retriever.py：hybrid_tokenize() + bm25_scores() + normalize() 共 60 行
  - knowledge_router.py：_tokenize() + _bm25_norm() 共 40 行
  两份独立实现，算法参数一致（k1=1.5, b=0.75），tokenizer 逻辑相同但函数名不同。
  修 BM25 bug 或调参需同步改两处，且无法保证两份实现持续一致。

解决：
  1. 提取 hybrid_tokenize / bm25_scores / normalize 到 bm25.py 共享模块
  2. retriever.py 和 knowledge_router.py 统一从 bm25.py 导入
  3. 消除 ~100 行重复代码，修 bug / 调参只需改一处

迭代151：BM25 Document Token Index Cache — CPU data cache 快速路径
OS 类比：L1/L2 CPU data cache (1987 → L2 1995) — pre-computed results mapped by key
  Intel 486 (1989) 引入 8KB on-chip L1 cache：频繁访问的内存位置在 cache 命中时
  无需往返 DRAM（~300 clock cycles），直接从 cache 读取（~1 cycle）。
  缓存命中率 > 90% 时，CPU 有效速度提升 10× ~ 100×。

memory-os 问题：
  bm25_scores(query, 126_docs) 每次都对所有文档做 hybrid_tokenize()，
  重新构建 df (document frequency) 表和 doc_lengths 数组。
  实测 126 docs：tokenize = 9.8ms，总 BM25 = 22-26ms。
  但文档集只在 chunk_version 变化时才改变（每次 insert/delete +1）。
  大多数 UserPromptSubmit 之间知识库静止 → tokenize 结果可以复用。

修复：BM25Index 预计算文档索引，持久化到文件，按 chunk_version 作为 cache key。
  - 缓存命中（chunk_version 未变）：0.1ms 读文件 → 直接评分（仅 query tokenize）
  - 缓存未命中：全量 tokenize，写缓存文件，评分
  预期：LITE P50 27ms → ~7ms（节省 ~20ms，减少 tokenize 到仅 query = ~0.1ms）
"""
import math
import os
import re
from pathlib import Path


# 迭代99：English Stopword + Porter Stemmer — 提升英文 BM25 召回率
# OS 类比：ELF Dynamic Linker ld.so 的 symbol versioning — 同一接口，增强内部实现
# 根因：英文查询 recall 显著低于中文（benchmark 58.3% 中文 vs ~30% 英文）
#   - 无 stopword 过滤：the/is/to 等高频词消耗 IDF 权重
#   - 无 stemming：analyzing/analysis/analyze 三个 token 互不匹配
ENGLISH_STOPWORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "and", "but", "or",
    "not", "no", "if", "then", "than", "that", "this", "these", "those",
    "it", "its", "he", "she", "they", "we", "you", "i", "me", "my",
    "your", "his", "her", "our", "their", "what", "which", "who", "how",
    "when", "where", "why", "all", "each", "every", "both", "few",
    "more", "most", "other", "some", "such", "only", "own", "so",
    "very", "just", "about", "also", "here", "there",
})


def _porter_stem(word: str) -> str:
    """Minimal Porter stemmer (step 1+2) — covers 90% of common suffixes."""
    if len(word) <= 3:
        return word
    # Step 1a: plurals + special endings
    if word.endswith("ysis"):
        return word[:-4] + "yz"  # analysis→analyz, paralysis→paralyz (matches analyzing→analyz)
    if word.endswith("sis"):
        return word[:-2]  # synthesis→synthe, thesis→the — early return, no further rules
    if word.endswith("sses"):
        word = word[:-2]
    elif word.endswith("ies"):
        word = word[:-2]
    elif word.endswith("ss"):
        pass
    elif word.endswith("s") and len(word) > 4:
        word = word[:-1]
    # Step 1b: -izing, -ing, -ed, suffixes (longest match first)
    if word.endswith("ization"):
        stem = word[:-7]
        if len(stem) > 1:
            word = stem + "ize"
    elif word.endswith("izing"):
        stem = word[:-5]
        if len(stem) > 1:
            word = stem + "ize"
    elif word.endswith("ingly"):
        stem = word[:-5]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ying"):
        stem = word[:-4]
        if len(stem) > 1:
            word = stem + "y"
    elif word.endswith("ing"):
        stem = word[:-3]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ation"):
        stem = word[:-5]
        if len(stem) > 1:
            word = stem + "ate"
    elif word.endswith("ement"):
        stem = word[:-5]
        if len(stem) > 1:
            word = stem
    elif word.endswith("ment"):
        stem = word[:-4]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ness"):
        stem = word[:-4]
        if len(stem) > 2:
            word = stem
    elif word.endswith("able"):
        stem = word[:-4]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ible"):
        stem = word[:-4]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ive"):
        stem = word[:-3]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ful"):
        stem = word[:-3]
        if len(stem) > 2:
            word = stem
    elif word.endswith("al"):
        stem = word[:-2]
        if len(stem) > 3:
            word = stem
    elif word.endswith("ed") and not word.endswith("eed"):
        stem = word[:-2]
        if len(stem) > 2:
            word = stem
    elif word.endswith("ly"):
        stem = word[:-2]
        if len(stem) > 2:
            word = stem
    elif word.endswith("er") and not word.endswith("eer"):
        stem = word[:-2]
        if len(stem) > 2:
            word = stem
    return word


def hybrid_tokenize(text: str) -> list:
    """
    混合中英文 tokenizer。
    英文：全词（lowercase）+ stopword 过滤 + Porter stemming
    中文：bigram（去掉 unigram 以提高小语料库 IDF 区分度）

    OS 类比：libc 的 strtok() — 所有程序共用同一份分词实现。
    迭代99：新增 English stemmer + stopword，提升英文召回率 +50%（预期）。
    """
    tokens = []
    # 英文全词 + stemming + stopword filter
    for m in re.finditer(r'[a-zA-Z0-9_][-a-zA-Z0-9_.]*', text):
        word = m.group().lower()
        if word in ENGLISH_STOPWORDS:
            continue
        # iter714: skip stemming for hyphenated/underscored compound terms
        stemmed = word if ("-" in word or "_" in word) else _porter_stem(word)
        tokens.append(stemmed)
    # 中文 bigram only
    chinese = re.sub(r'[^\u4e00-\u9fff]', '', text)
    for i in range(len(chinese) - 1):
        tokens.append(chinese[i:i + 2])
    return tokens


def bm25_scores(query: str, docs: list, k1: float = 1.5, b: float = 0.75) -> list:
    """
    标准 BM25 评分（无外部依赖）。
    返回与 docs 等长的 float list。

    参数：
      query — 查询文本
      docs  — 文档文本列表
      k1    — term frequency saturation 参数（默认 1.5）
      b     — 文档长度归一化参数（默认 0.75）
    """
    if not docs:
        return []

    query_tokens = hybrid_tokenize(query)
    if not query_tokens:
        return [0.0] * len(docs)

    tokenized_docs = [hybrid_tokenize(d) for d in docs]
    doc_lengths = [len(td) for td in tokenized_docs]
    avg_dl = sum(doc_lengths) / len(doc_lengths) if doc_lengths else 1.0
    N = len(docs)

    # term -> document frequency
    df: dict = {}
    for td in tokenized_docs:
        for t in set(td):
            df[t] = df.get(t, 0) + 1

    scores = []
    for i, td in enumerate(tokenized_docs):
        tf_map: dict = {}
        for t in td:
            tf_map[t] = tf_map.get(t, 0) + 1
        dl = doc_lengths[i]
        score = 0.0
        for qt in query_tokens:
            if qt not in df:
                continue
            tf = tf_map.get(qt, 0)
            idf = _idf(N, df[qt])
            numerator = tf * (k1 + 1)
            denominator = tf + k1 * (1 - b + b * dl / avg_dl)
            score += idf * (numerator / denominator if denominator else 0.0)
        scores.append(score)
    return scores


def normalize(scores: list) -> list:
    """max-in-batch 归一化到 [0, 1]，max=0 时全返回 0.0。"""
    if not scores:
        return []
    max_s = max(scores)
    if max_s == 0.0:
        return [0.0] * len(scores)
    return [s / max_s for s in scores]


def bm25_normalized(query: str, docs: list, k1: float = 1.5, b: float = 0.75) -> list:
    """
    BM25 + max-normalize 一步完成。
    便利函数，等价于 normalize(bm25_scores(query, docs, k1, b))。
    knowledge_router.py 原来的 _bm25_norm() 即此函数。
    """
    return normalize(bm25_scores(query, docs, k1, b))


def _idf(N: int, df_t: int) -> float:
    """Robertson-Sparck Jones IDF（标准 BM25 对数版）。"""
    return max(0.0, math.log((N - df_t + 0.5) / (df_t + 0.5)))


# ── 迭代151：BM25 Document Token Index Cache ─────────────────────────
# OS 类比：CPU L1/L2 data cache — pre-computed results, invalidated by chunk_version

# 缓存文件路径（与 store_vfs 的 MEMORY_OS_DIR 同目录，不 import 避免循环依赖）
_MEMORY_OS_DIR = Path(os.environ["MEMORY_OS_DIR"]) if os.environ.get("MEMORY_OS_DIR") else Path.home() / ".claude" / "memory-os"
_BM25_INDEX_CACHE_FILE = _MEMORY_OS_DIR / ".bm25_index_cache.pkl"


class BM25Index:
    """
    预计算的 BM25 文档索引 — 按 chunk_version 缓存，避免重复 tokenize。
    OS 类比：CPU cache line — 内容固定，有效直到 cache miss（chunk_version 变化）。

    用法：
        index = BM25Index.load_or_build(docs, chunk_version)
        scores = index.score(query)
    """
    __slots__ = ("tokenized_docs", "doc_lengths", "avg_dl", "N", "df", "chunk_version")

    def __init__(self, docs: list, chunk_version: int = 0):
        """构建文档索引（仅在 cache miss 时调用）。"""
        self.chunk_version = chunk_version
        self.N = len(docs)
        self.tokenized_docs = [hybrid_tokenize(d) for d in docs]
        self.doc_lengths = [len(td) for td in self.tokenized_docs]
        self.avg_dl = sum(self.doc_lengths) / len(self.doc_lengths) if self.doc_lengths else 1.0
        # 构建 document frequency 表
        self.df: dict = {}
        for td in self.tokenized_docs:
            for t in set(td):
                self.df[t] = self.df.get(t, 0) + 1

    def score(self, query: str, k1: float = 1.5, b: float = 0.75) -> list:
        """
        使用预计算索引评分，只需 tokenize query（不重复 tokenize docs）。
        OS 类比：cache hit — 直接从 cache line 读数据，不往返 DRAM。
        """
        if self.N == 0:
            return []
        query_tokens = hybrid_tokenize(query)
        if not query_tokens:
            return [0.0] * self.N

        scores = []
        for i, td in enumerate(self.tokenized_docs):
            tf_map: dict = {}
            for t in td:
                tf_map[t] = tf_map.get(t, 0) + 1
            dl = self.doc_lengths[i]
            score = 0.0
            for qt in query_tokens:
                if qt not in self.df:
                    continue
                tf = tf_map.get(qt, 0)
                idf = _idf(self.N, self.df[qt])
                numerator = tf * (k1 + 1)
                denominator = tf + k1 * (1 - b + b * dl / self.avg_dl)
                score += idf * (numerator / denominator if denominator else 0.0)
            scores.append(score)
        return scores

    @classmethod
    def load_or_build(cls, docs: list, chunk_version: int = 0) -> "BM25Index":
        """
        Cache-aware 工厂方法：
          - cache hit（version 匹配）→ 从 pickle 文件加载（~0.1-0.3ms）
          - cache miss → 全量构建，写缓存（~10-25ms）
        OS 类比：cache lookup — hit 从 cache 读，miss 从 DRAM fetch + fill cache。
        """
        # 快速路径：读缓存文件
        try:
            if _BM25_INDEX_CACHE_FILE.exists():
                import pickle
                with open(_BM25_INDEX_CACHE_FILE, "rb") as f:
                    cached = pickle.load(f)
                if (isinstance(cached, cls)
                        and getattr(cached, "chunk_version", -1) == chunk_version
                        and getattr(cached, "N", -1) == len(docs)):
                    return cached  # cache hit
        except Exception:
            pass  # cache 损坏/不兼容 → 重建

        # 慢速路径：全量构建 + 写缓存
        index = cls(docs, chunk_version)
        try:
            _MEMORY_OS_DIR.mkdir(parents=True, exist_ok=True)
            import pickle
            with open(_BM25_INDEX_CACHE_FILE, "wb") as f:
                pickle.dump(index, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass  # 写缓存失败不影响主流程
        return index


def bm25_scores_cached(query: str, docs: list, chunk_version: int = 0,
                        k1: float = 1.5, b: float = 0.75) -> list:
    """
    迭代151：缓存加速版 bm25_scores()。
    与 bm25_scores() 签名兼容（多一个 chunk_version 参数）。

    cache hit（chunk_version 未变）：~0.3ms（读 pickle + query tokenize + 评分）
    cache miss（知识库有变化）：~25ms（全量 tokenize + 构建索引 + 写缓存 + 评分）

    retriever.py 使用此函数替代 bm25_scores()，传入当前 chunk_version。
    """
    if not docs:
        return []
    index = BM25Index.load_or_build(docs, chunk_version)
    return index.score(query, k1=k1, b=b)
