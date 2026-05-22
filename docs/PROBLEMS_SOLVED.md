# Problems 0CompactMem solves

> Concrete pain points users hit with LLM agents, what we changed, and the
> measured impact. Mainly useful for prospective contributors and people
> evaluating whether 0CompactMem covers their case.

Each section names a specific problem and the iteration that resolved it.
You can `git log --grep="iter N"` for the actual change.

---

## No cross-session memory — starting from zero every time

Every new conversation loses every previous decision, pitfall, and
constraint. Significant warm-up time is wasted re-building context.

**Solution.** Knowledge extracted at session end (decisions, reasoning
chains, design constraints, quantitative evidence) → stored in `store.db`
→ retrieved and injected at the next session start.

```
Recall@3: +147%   MRR: +320%   A/B quality: +68%   Session recall: 94.2%
```

---

## High retrieval latency — noticeable lag on every prompt

Subprocess-based retrieval was P50 ≈ 54 ms per keystroke.

**Solution.** Persistent `retriever_daemon.py` over a Unix socket, plus a
three-level cache (FTS5 result cache + two-level TLB).

```
P50: 54 ms → 0.1 ms (540×)
```

---

## Context window fills up; forced compaction loses reasoning chains

**Solution.** Layered compression — zram-style output-compression hints
(`output_compressor.py`) + Context Pressure Governor with four watermark
levels + swap eviction of low-frequency chunks.

---

## Session interruption loses "what I was doing"

**Solution.** CRIU-style session checkpoint — unfinished intent extracted
at `Stop`, persisted to `session_intents`, auto-injected at the next
`SessionStart` (24h TTL).

---

## Architectural constraints scattered across history, easily violated

**Solution.** Auto-detect constraint patterns (22 patterns) → store as
`design_constraint` chunks with `importance = 0.95`,
`oom_adj = -800` (never evicted) → auto-injected on every
`UserPromptSubmit`.

```
21 active constraints, top constraint retrieved ×2,043 times
```

---

## Multiple agents overwriting each other's memory (iter 259)

Concurrent sessions caused last-writer-wins races on shared files.

**Solution.** Per-session `shadow_traces` and `session_intents` tables
(`PRIMARY KEY = session_id`), per-session named files
(`.shadow_trace.{sid[:16]}.json`). Verified by a 20-test isolation suite.

---

## Stop hook blocks on I/O-heavy transcript parsing (iter 260)

`extractor.py` spent 50–150 ms on file I/O inside the synchronous `Stop`
hook.

**Solution.** `submit_extract_task()` enqueues to `ipc_msgq` (< 5 ms) →
`extractor_pool.py` daemon processes via `ThreadPoolExecutor(3)`. Falls
back gracefully if the pool isn't running.

```
Stop hook: 50–150 ms (sync) → < 5 ms (async queue)
```

---

## Repeated injection wastes tokens (iter 359, 361)

Without dedup, the same chunk is injected with full `raw_snippet` on every
prompt in a long session — re-shipping content that's already in the
model's working memory.

**Solution: three-layer token-budget enforcement.**

- **FULL → LITE demotion (iter 361)** — once a chunk has been injected with
  full format (summary + raw_snippet) in this session, subsequent injections
  are demoted to LITE (summary only). Once the LLM has seen the raw text,
  the marginal value of re-shipping it is zero.
- **Session dedup (iter 359)** — chunks injected ≥ `session_dedup_threshold`
  (default 2) times are excluded from context entirely.
- **Same-hash TLB bypass** — identical prompt hashes return the cached
  result immediately. Zero DB queries, zero new tokens.

Measured (`tests/test_token_budget.py`):

```
Injection cost:           ~44 tokens / call  (avg 178 chars)
FULL → LITE saving:       ~62 tokens / repeat  (-69.6% per re-injection)
User re-explanation saved: ~300 tokens / call
Net token ROI:            +256 tokens / call
Context cap enforced:     ≤ 800 chars (max_context_chars sysctl)
```
