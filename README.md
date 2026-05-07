<div align="center">

# memory-os

**Kernel-grade persistent memory for Claude Code**

*Remembers decisions, constraints, and context across sessions — designed like an OS memory subsystem, not a database.*

[![Python](https://img.shields.io/badge/python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/storage-SQLite%20WAL-lightgrey?logo=sqlite)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-44%20passing-brightgreen)](#testing)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Iterations](https://img.shields.io/badge/iterations-374%2B-orange)](#roadmap)

[English](./README.md) · [中文](./README.zh.md)

</div>

---

> **⚡ One-line install via Claude Code:**
> ```
> /install-plugin github:soolaugust/memory-os
> ```

---

## The Problem

Every time you start a new conversation with an AI assistant, it starts from scratch. Every decision, every discovered pitfall, every architectural constraint — gone. You re-explain context. It re-learns the same lessons. And if you run multiple agents in parallel, they have no way to share what they've learned.

This is not a model limitation. It's a **missing infrastructure layer**.

---

## The Solution

Memory OS applies **operating system memory management philosophy** to AI cognitive resource management. The same principles that let Linux handle millions of processes with limited RAM now give AI agents persistent, retrievable, multi-agent-shared memory.

| OS Concept | Memory OS Equivalent |
|---|---|
| RAM (runtime working space) | Context window — what the AI sees right now |
| Disk (persistent storage) | Knowledge base — facts that survive across sessions |
| Demand paging | Smart retrieval — fetch relevant memories on-demand |
| Process scheduling | Multi-agent coordination — multiple AIs share one knowledge graph |
| CRIU checkpoint/restore | Session snapshots — save state, resume seamlessly |
| kworker thread pool | Async extraction pool — I/O offloaded from the critical path |

---

## How It Works

```
You speak
  → System retrieves relevant memories → injects into context
  → AI responds with full context
  → Session ends → decisions/insights auto-extracted → persisted to store.db
  → Next session starts → working set restored automatically
```

The entire pipeline runs inside **Claude Code hooks**. Zero manual memory management.

---

## Key Metrics

| Metric | Value |
|---|---|
| Retrieval latency P50 (TLB hit) | **~0.1 ms** |
| vs. subprocess baseline | **540× faster** (54 ms → 0.1 ms) |
| Recall@3 improvement (BM25 vs baseline) | **+147%** |
| MRR improvement | **+320%** |
| A/B answer quality uplift | **+68%** (3.55 vs 2.12) |
| Cross-session recall | **94.2%** |
| Knowledge base size | **427 chunks / 8 types** |
| Hot-path retrieval | **1.74 µs/op** (iter 258, −84.7% from baseline) |
| Total iterations | **374+** |
| **Token injection per call** | **~44 tokens** (avg 178 chars) |
| **Token net ROI per call** | **~+256 tokens** saved (inject 44, save ~300 re-explanation) |
| FULL→LITE demotion savings (iter 361) | **~62 tokens/repeat** (69.6% reduction on re-injection) |
| Session dedup excluded chunks (iter 359) | chunks injected ≥2× automatically excluded |
| Same-hash TLB bypass | **zero tokens** overhead on repeated prompts |

---

## Architecture

```
Claude Code
    ↕  hooks (syscall boundary)
┌─────────────────────────────────────────┐
│  hooks/                                  │
│  ├── loader.py        (SessionStart)     │  Working set restore + CRIU restore
│  ├── retriever_wrapper.sh (UserPrompt)   │→ retriever_daemon.py (persistent proc)
│  ├── writer.py        (UserPrompt)       │  Knowledge write + task state
│  ├── extractor.py     (Stop)             │  Knowledge extraction + CRIU dump
│  ├── extractor_pool.py                   │  Async kworker pool (iter 260)
│  ├── output_compressor.py (PostToolUse)  │  zram — large output compression hints
│  ├── tool_profiler.py     (PostToolUse)  │  eBPF-style tool call efficiency
│  └── parallel_hint.py    (UserPrompt)    │  CFS parallel task detection
└─────────────────────────────────────────┘
    ↕  VFS unified data layer
┌─────────────────────────────────────────┐
│  ~/.claude/memory-os/store.db            │
│  memory_chunks / swap_chunks             │
│  checkpoints / dmesg                     │
│  FTS5 full-text index (bigram CJK)       │
└─────────────────────────────────────────┘
    ↕  IPC (ipc_msgq)
┌─────────────────────────────────────────┐
│  net/agent_notify.py                     │  Cross-agent knowledge broadcast
│  extractor_pool (kworker ×3)             │  Async extraction worker (iter 260)
└─────────────────────────────────────────┘
```

Full architecture details: [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)

---

## Design Philosophy

Every subsystem maps to a Linux kernel mechanism:

| Feature | Linux Analogy | Iteration |
|---|---|---|
| Knowledge retrieval injection | Demand paging (page fault) | iter 1 |
| Working set preload | Denning Working Set Model | iter 18 |
| Knowledge eviction | kswapd + OOM Killer | iter 25, 38 |
| Session restore | CRIU Checkpoint/Restore | iter 49 |
| Congestion control | TCP AIMD + auto-tuning | iter 50, 51 |
| Multi-generation LRU | MGLRU (Linux 6.x) | iter 44 |
| Access pattern monitoring | DAMON | iter 42 |
| Output compression hints | zram | iter 110 |
| Persistent retrieval daemon | vDSO + Unix socket | iter 162 |
| Two-level TLB cache | CPU TLB L1/L2 | iter 179 |
| FTS result cache | Page cache | iter 205 |
| Multi-agent isolation | Linux namespace (PID/mount) | iter 259 |
| Async extraction pool | kworker thread pool + pdflush | iter 260 |
| FTS5 auto-optimize | ext4 online defrag | iter 360 |
| FULL→LITE injection demotion | page cache dirty bit fast-path | iter 361 |
| Proactive swap warmup | MGLRU proactive reclaim | iter 362 |
| Workspace-aware memory | exec() address space switch | iter 363 |
| Session episode timeline | Hippocampal sequential replay | iter 364 |
| Workspace prospective memory | Prefrontal prospective codes | iter 365 |
| Knowledge graph spreading activation | CPU cache prefetch L2 warm-up | iter 366 |
| Temporal proximity edges | Sequential readahead | iter 367 |
| Attention focus stack | CPU register file | iter 368 |
| Soft forgetting | DAMON cold page detection | iter 369 |
| Uncertainty signal extraction | MMU soft page fault | iter 370 |

---

## Problems Solved

<details>
<summary><strong>No cross-session memory — starting from zero every time</strong></summary>

Every new conversation loses all previous decisions, pitfalls, and constraints. Significant warm-up time is wasted rebuilding context.

**Solution:** Knowledge extracted at session end (decisions, reasoning chains, design constraints, quantitative evidence) → stored in `store.db` → retrieved and injected at next session start.

```
Recall@3: +147% | MRR: +320% | A/B quality: +68% | Session recall: 94.2%
```
</details>

<details>
<summary><strong>High retrieval latency — noticeable lag on every prompt</strong></summary>

Early subprocess-based retrieval: P50 ~54 ms per keystroke.

**Solution:** Persistent `retriever_daemon.py` via Unix socket + three-level cache (FTS5 result cache + two-level TLB).

```
P50: 54 ms → 0.1 ms (540× reduction)
```
</details>

<details>
<summary><strong>Context window fills up, forced compaction loses reasoning chains</strong></summary>

**Solution:** Multi-layer compression — zram-style output compression hints (`output_compressor.py`) + Context Pressure Governor (four watermark levels) + swap eviction of low-frequency chunks.
</details>

<details>
<summary><strong>Session interruption loses "what I was doing"</strong></summary>

**Solution:** CRIU-style session checkpoint — unfinished intent extracted at Stop, persisted to `session_intents` DB, auto-injected at next SessionStart (24h TTL).
</details>

<details>
<summary><strong>Architectural constraints scattered in history, easily violated</strong></summary>

**Solution:** Auto-detect constraint patterns (22 patterns) → `design_constraint` type with `importance=0.95`, `oom_adj=-800` (never evicted) → auto-injected at every UserPromptSubmit.

```
21 active constraints, top constraint retrieved ×2043 times
```
</details>

<details>
<summary><strong>Multiple agents overwriting each other's memory (iter 259)</strong></summary>

Concurrent sessions cause last-writer-wins races on shared files.

**Solution:** Per-session `shadow_traces` and `session_intents` tables (PRIMARY KEY = `session_id`), per-session named files (`.shadow_trace.{sid[:16]}.json`). Verified by 20-test isolation suite.
</details>

<details>
<summary><strong>Stop hook blocks on I/O-heavy transcript parsing (iter 260)</strong></summary>

`extractor.py` spent 50–150 ms on file I/O in the synchronous Stop hook.

**Solution:** `submit_extract_task()` enqueues to `ipc_msgq` (<5 ms) → `extractor_pool.py` persistent daemon processes in `ThreadPoolExecutor(3)`. Graceful fallback if pool not running.

```
Stop hook: 50–150 ms (sync) → <5 ms (async queue)
```
</details>

<details>
<summary><strong>Repeated injection wastes tokens — re-attaching full context every call (iter 359, 361)</strong></summary>

Without deduplication, the same chunk is injected with its full `raw_snippet` on every prompt in a long session, wasting tokens on content already in the model's working memory.

**Solution: Three-layer token budget enforcement**

- **FULL→LITE demotion (iter 361):** A chunk injected with full format (summary + raw_snippet) in this session is demoted to LITE (summary only) on subsequent injections — once the LLM has seen it, the raw text has zero marginal value.
- **Session dedup (iter 359):** Chunks injected ≥ `session_dedup_threshold` (default: 2) times are excluded entirely from context.
- **Same-hash TLB bypass:** Identical prompt hashes return the cached result immediately — zero DB queries, zero new tokens.

**Measured (validated by `tests/test_token_budget.py`):**
```
Injection cost:           ~44 tokens/call  (avg 178 chars)
FULL→LITE saving:         ~62 tokens/repeat (69.6% reduction per re-injected chunk)
User re-explanation saved: ~300 tokens/call
Net token ROI:            ~+256 tokens/call
Context cap enforced:     ≤ 800 chars (max_context_chars sysctl)
```
</details>

---

## Roadmap

| Phase | Status |
|---|---|
| Basic memory management — persist, evict, prioritize (iter 1–100) | ✅ Done |
| Persistent retrieval daemon + multi-level cache (iter 162–205) | ✅ Done |
| Data-driven precision tuning — 258 iterations, −84.7% latency (iter 235–258) | ✅ Done |
| Multi-agent isolation — per-session namespacing, IPC broadcast (iter 259) | ✅ Done |
| Async extraction pool — Stop hook offload, kworker pool (iter 260) | ✅ Done |
| Token budget optimization — FULL→LITE demotion, session dedup, swap warmup (iter 359–362) | ✅ Done |
| Workspace-aware memory — exec() address space switch, filesystem sensing (iter 363) | ✅ Done |
| Cognitive memory systems — episodes, workspace todos, knowledge graph spreading activation (iter 364–366) | ✅ Done |
| Temporal proximity, attention focus, soft forgetting, uncertainty signals (iter 367–370) | ✅ Done |
| Conflict detection, context-aware boost, timeline, chunk coalescing (iter 371–374) | ✅ Done |
| Distributed multi-agent shared memory — NUMA/RDMA analogy (iter 375+) | 🔜 Planned |

---

## Quick Start

### Prerequisites

- Python 3.12+
- SQLite (built-in)
- `nc` (netcat) and `flock`
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)

### Installation

```bash
# 1. Clone
git clone https://github.com/your-org/memory-os ~/codes/aios/memory-os
cd ~/codes/aios/memory-os

# 2. Create data directory (schema auto-created on first run)
mkdir -p ~/.claude/memory-os

# 3. Add hooks configuration to ~/.claude/settings.json (see below)
```

**`~/.claude/settings.json`:**

```json
{
  "hooks": {
    "SessionStart": [
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/loader.py", "timeout": 10 }
    ],
    "UserPromptSubmit": [
      { "type": "command", "command": "bash /path/to/memory-os/hooks/retriever_wrapper.sh", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/writer.py", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/parallel_hint.py", "timeout": 3, "async": false }
    ],
    "PostToolUse": [
      { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "python3 /path/to/memory-os/hooks/output_compressor.py", "timeout": 5 }] },
      { "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/memory-os/hooks/tool_profiler.py", "timeout": 5, "async": true }] }
    ],
    "Stop": [
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/extractor.py", "timeout": 10, "async": true }
    ]
  }
}
```

### Verify

```bash
# Test SessionStart hook
echo '{"session_id":"test","transcript_path":"/dev/null","cwd":"'$(pwd)'"}' \
  | python3 hooks/loader.py

# Test retriever (daemon starts automatically)
echo '{"session_id":"test","prompt":"test query","cwd":"'$(pwd)'"}' \
  | bash hooks/retriever_wrapper.sh

# Confirm daemon is running
ls /tmp/memory-os-retriever.sock && echo "daemon running"

# Run tests
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

### Daemon Management

```bash
# Retriever daemon: auto-starts on first request
tail -f ~/.claude/memory-os/daemon.log        # logs
pkill -f retriever_daemon.py                  # restart (auto-restarts next call)

# Extractor pool (iter 260 async extraction)
bash hooks/extractor_pool_wrapper.sh start
bash hooks/extractor_pool_wrapper.sh status
bash hooks/extractor_pool_wrapper.sh stop
```

---

## Testing

```bash
# Multi-agent isolation (A1–A20)
python3 -m pytest tests/test_agent_team.py -v

# Chaos / fault tolerance
python3 -m pytest tests/test_chaos.py -v

# All stable tests
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

Tests cover: per-session DB isolation, concurrent write safety, cross-agent IPC delivery, extractor pool queue semantics, CRIU checkpoint validation, goals progress idempotency.

---

## Dependencies

No GPU. No external API. Everything runs locally.

| Dependency | Purpose |
|---|---|
| Python 3.12+ | Core runtime |
| SQLite (built-in) | Primary store + FTS5 full-text index |
| `nc` (netcat) | Unix socket communication with retriever daemon |
| `flock` | Single-instance daemon startup |

---

## Contributing

Each subsystem is isolated behind a clean VFS interface — hooks call into `store.py` / `store_vfs.py` / `store_criu.py` — making components testable in isolation.

```bash
# Before submitting a PR
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

---

<div align="center">

Built on one idea: *if the OS solved it in hardware, we can apply the same principle in AI.*

**[English](./README.md) · [中文](./README.zh.md)**

</div>
