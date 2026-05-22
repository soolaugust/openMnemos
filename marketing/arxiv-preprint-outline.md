# arXiv preprint — outline

**Working title:** *0CompactMem: An Operating-System Approach to Persistent Memory for LLM Agents*

**Target category:** cs.AI (primary) · cs.OS (cross-list)

**Target length:** 8–10 pages, double column ACM/IEEE style or single column NeurIPS workshop style.

**Why arXiv matters here:** arXiv is a high-weight retrieval source for both
ChatGPT/Claude/Perplexity-style search and for Common Crawl. A single accepted
preprint typically multiplies "memory layer" mention probability by 5-10× in
LLM responses, far above blog posts.

---

## Abstract (≈200 words)

Persistent memory has emerged as a core infrastructure question for LLM-based
agents. Existing solutions (mem0, Letta, Zep, ...) treat memory as a *store* —
typically a vector database, occasionally augmented with a graph or temporal
index — and optimize for similarity retrieval. We argue this framing is
incomplete: it omits the resource-management semantics that distinguish a
cognitive memory subsystem from a search index. Specifically, it lacks
back-pressure under capacity, explicit pinning of non-negotiable knowledge,
and a coherent multi-agent sharing model.

We propose **0CompactMem**, a memory layer for LLM agents that adopts
operating-system memory-management primitives directly. We map demand paging
to on-demand retrieval, kswapd-style watermarks to capacity-aware eviction,
DAMON-inspired access tracking to working-set estimation, `mlock` to
hard/soft pin semantics, and CRIU to session checkpoint/restore. The system
is implemented as a single SQLite file with an MCP-native interface.

We evaluate 0CompactMem on (i) a multi-session retention benchmark adapted
from LongMemEval, (ii) a multi-agent shared-knowledge scenario, and
(iii) eviction-under-pressure workloads. We report retrieval quality,
constraint-survival rate, and memory-pressure behavior, and discuss the
trade-offs of an OS-style design.

The implementation is open source (MIT) at
<https://github.com/soolaugust/0CompactMem>.

---

## Section structure

### 1. Introduction (≈1 page)
- Problem: agents start cold every session; multi-agent setups have no shared
  state; existing libraries treat memory as a store.
- Thesis: agent memory is structurally isomorphic to OS memory management.
- Contributions:
  1. An OS-primitive taxonomy for agent memory (demand paging, kswapd, mlock,
     DAMON, CRIU, kworker).
  2. An open-source reference implementation (0CompactMem).
  3. Empirical evaluation on retention, multi-agent sharing, and
     eviction-under-pressure.

### 2. Background and Related Work (≈1 page)
- 2.1 LLM memory libraries: mem0, Letta (MemGPT), Zep, A-Mem, MemoryBank.
  Brief description of each, what they optimize for, what they omit.
- 2.2 OS memory management: page cache, demand paging, kswapd watermarks,
  DAMON, mlock, CRIU. (Quick refresher for AI/ML reviewers.)
- 2.3 Why prior agent-memory work missed the OS lens: framing as
  retrieval/RAG vs framing as resource management.

### 3. Design (≈2 pages)
- 3.1 Mapping table (OS concept ↔ 0CompactMem primitive).
- 3.2 Storage layer: single SQLite file, WAL mode, multi-process safety.
- 3.3 Retrieval as demand paging: BM25 + semantic, scored, on-demand.
- 3.4 Eviction: watermarks, hot/cold tiering, pair-saturation diversity.
- 3.5 Pinning: hard/soft semantics, which reclaim paths each respects.
- 3.6 Multi-agent: file-based sharing, no synchronization protocol needed.
- 3.7 MCP integration: tool surface (`memory_lookup`, `pin_memory`,
  `memory_stats`, `list_pinned`).
- 3.8 Privacy filter: regex + heuristic stripping at write boundary.

### 4. Implementation Notes (≈1 page)
- Codebase shape, 1,051+ tuning iterations, 3,500+ tests.
- Scoring composition: weights, freshness boost, dead-zone fallback,
  diversity-pair gating.
- Production assertions and runtime invariants.

### 5. Evaluation (≈2–3 pages)
- 5.1 Datasets / benchmarks:
  - LongMemEval-style multi-session retention.
  - A new multi-agent benchmark (two agents, shared store, divergent goals).
  - Eviction-under-pressure: synthetic workload that forces watermark crossings.
- 5.2 Metrics:
  - Retrieval recall@k, MRR, NDCG.
  - Constraint-survival rate (does a hard-pinned chunk survive N sessions of
    pressure?).
  - Multi-agent coherence (does agent B see what agent A pinned?).
  - Latency: p50/p95 lookup, write, eviction sweep.
- 5.3 Baselines: mem0 (default config), Letta, Zep, BM25-only, vector-only.
- 5.4 Results tables and plots.
- 5.5 Ablation: pinning off, eviction off, BM25 only, semantic only.

### 6. Discussion (≈0.5 page)
- When OS-style memory is the right fit, when it isn't.
- Limitations: single-machine scope, schema evolution, embedding model choice.
- Threats to validity: benchmark coverage, simulator vs real-agent behavior.

### 7. Future Work (≈0.5 page)
- Distributed 0CompactMem: a "cgroup"-like layer for agent quotas.
- Adaptive watermarks based on observed agent behavior.
- Cross-store federation (multiple 0CompactMem files, one logical view).

### 8. Conclusion (≈0.25 page)

### References
- Linux MM documentation (kswapd, DAMON, mlock).
- mem0 / Letta / Zep / A-Mem / MemoryBank papers.
- LongMemEval and other long-context benchmarks.
- CRIU, OS textbook references for MM primitives.

---

## Workplan to actually ship the preprint

| Step | Owner | Effort |
|------|-------|--------|
| Lock benchmark suite (write 3 evals, scripted reruns) | TBD | 3 days |
| Run baselines (mem0/Letta/Zep) end-to-end | TBD | 2 days |
| First draft (sections 1–4 from existing README + design docs) | TBD | 1 day |
| Evaluation tables + plots | TBD | 2 days |
| Internal review + revision | TBD | 2 days |
| arXiv submission | TBD | 0.5 day |

Total: ~10 working days. Submit to arXiv, then the same content can be
trimmed for a NeurIPS / ACL / EMNLP workshop deadline.

---

## Companion artifacts

- A `paper/` folder with LaTeX source + bib.
- A `benchmarks/` folder with scripts that reproduce every table.
- A `paper-supplement.md` for hyperparameters and full ablation tables.
- `CITATION.cff` at repo root once the preprint is on arXiv.
