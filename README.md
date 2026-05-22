<div align="center">

# 0CompactMem

**Zero compaction. Infinite memory. For Claude Code and every LLM agent.**

*Your AI never forgets — no more "context compacted" interruptions.*

[![Python](https://img.shields.io/badge/python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/storage-SQLite%20WAL-lightgrey?logo=sqlite)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-3500%2B%20passing-brightgreen)](#testing)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Discussions](https://img.shields.io/badge/discuss-on%20GitHub-blue?logo=github)](https://github.com/soolaugust/0CompactMem/discussions)

[English](./README.md) · [中文](./README.zh.md)

</div>

> **One-line install via Claude Code:**
> ```
> /install-plugin github:soolaugust/0CompactMem
> ```

---

## The problem: context compaction kills your flow

If you use Claude Code, you know this pain:

```
⚠️ Auto-compact: conversation is approaching context limit...
```

Every time this happens, your AI loses track of decisions, constraints, and hard-won context. You re-explain. It re-learns. Hours of accumulated understanding — gone in one compaction event.

And if you run multiple agents? They can't share what they've learned. Each one starts from zero.

**This isn't a model limitation. It's a missing infrastructure layer.**

---

## The solution: persistent memory that survives compaction

0CompactMem gives your AI agents **persistent, retrievable memory** that lives outside the context window. When compaction happens, nothing is lost — because the important stuff was never only in the context window to begin with.

The result: **zero effective compaction**. Your AI retains every decision, constraint, and lesson across sessions, across compactions, across agents.

### How it works

```
You speak
  → 0CompactMem retrieves relevant memories → injects into context
  → AI responds with full context
  → Session ends → decisions and insights auto-extracted → persisted
  → Compaction happens? No problem — memories survive outside the window
  → Next session starts → working set restored automatically
```

The whole pipeline runs inside Claude Code hooks. There is no manual memory management.

---

## Why "0CompactMem"?

| What others see | What actually happens |
|---|---|
| "Context compacted" | Critical knowledge already persisted to memory store |
| New session starts | Working set auto-restored in <100ms |
| Multiple agents running | All share the same memory — no re-explanation |
| Constraint decided 3 weeks ago | Pinned in memory, guaranteed never evicted |

**Zero compaction impact. Zero context loss. Zero re-explanation.**

---

## Under the hood: OS memory management for AI

The secret sauce? We didn't invent new algorithms. We borrowed what the Linux kernel has been doing for 40 years:

| OS concept | 0CompactMem equivalent |
|---|---|
| RAM (working space) | Context window — what the AI sees right now |
| Disk (persistent storage) | Knowledge base — facts that survive across sessions |
| Demand paging | On-demand retrieval — fetch relevant memories at the right moment |
| `mlock` | Hard / soft pinning — guarantee a constraint is never evicted |
| kswapd watermarks | Capacity-aware eviction under pressure |
| CRIU checkpoint / restore | Session snapshots — pause and resume seamlessly |
| Process scheduling | Multi-agent coordination — many agents, one knowledge base |
| kworker thread pool | Async extraction — I/O off the critical path |

---

## How is this different from mem0 / Letta / Zep?

|                          | **0CompactMem**          | mem0           | Letta (MemGPT) | Zep            |
|--------------------------|--------------------------|----------------|----------------|----------------|
| Design metaphor          | OS memory subsystem      | Vector store   | Agent runtime  | Temporal graph |
| Zero-compact guarantee   | ✅ pinned memories survive| ❌             | ❌             | ❌             |
| Multi-agent shared       | ✅ native, single store  | ⚠️ via API     | ✅             | ✅             |
| MCP-native               | ✅ first-class           | ❌             | ❌             | ❌             |
| Single-file deploy       | ✅ SQLite, no service    | ❌ needs server| ❌ needs server| ❌ needs server|
| Demand-paging retrieval  | ✅ explicit              | implicit       | implicit       | implicit       |
| Eviction policy          | ✅ kswapd + DAMON        | TTL only       | recency        | recency + decay|
| Pin / mlock semantics    | ✅                       | ❌             | ❌             | ❌             |

> **TL;DR.** If you're tired of context compaction wiping your AI's memory, and you want a solution that's `pip install`, runs as a sidecar on a laptop, shares between several Claude Code / Cursor / custom agents, and never loses a pinned constraint — 0CompactMem is built for that.

---

## Performance at a glance

| Metric | Value |
|---|---|
| Retrieval latency (P50, hot path) | **~0.1 ms** (540x faster than the 54 ms subprocess baseline) |
| Recall@3 vs baseline | **+147%** |
| Cross-session recall | **94.2%** |
| Token cost per call | ~44 tokens injected, **+256 tokens net ROI** (avoided re-explanation) |
| Test suite | 3,500+ tests across retrieval, eviction, MCP, privacy filter |

---

## Quick start

**One-line install (recommended).**

```
/install-plugin github:soolaugust/0CompactMem
```

**Manual install.**

```bash
git clone https://github.com/soolaugust/0CompactMem
cd 0CompactMem
pip install -e .
mkdir -p ~/.claude/memory-os
```

Detailed Claude Code hook configuration, daemon management, and troubleshooting live in [`docs/SETUP.md`](./docs/SETUP.md).

---

## Architecture

Three layers:

1. **Hooks** — sit at the Claude Code syscall boundary (`SessionStart`, `UserPromptSubmit`, `Stop`, `PostToolUse`) and call into the store.
2. **Store** — single SQLite file (WAL mode) with FTS5 full-text index, behind a unified VFS interface (`store.py` / `store_vfs.py` / `store_criu.py`).
3. **Daemons & IPC** — persistent retriever daemon (Unix socket), async extractor pool (kworker-style), cross-agent notify bus.

For the full layered diagram, on-disk schema, and the rationale behind each subsystem, see [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md). For the comprehensive OS-and-cognitive-science primitive mapping, see [`docs/DESIGN_PHILOSOPHY.md`](./docs/DESIGN_PHILOSOPHY.md).

---

## Roadmap

- **Distributed 0CompactMem** — cgroup-style multi-agent quotas, network-replicated stores
- **Adaptive watermarks** — eviction tuning that follows observed agent behavior
- **arXiv preprint** — formal evaluation against mem0 / Letta / Zep
- **Per-chunk embedding routing** — different models for code vs prose

What landed already (1,051+ tuning iterations, eight major capability rounds) is summarized in [`CHANGELOG.md`](./CHANGELOG.md). Pain points it has resolved along the way are in [`docs/PROBLEMS_SOLVED.md`](./docs/PROBLEMS_SOLVED.md).

---

## Testing

```bash
# stable test subset
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

Coverage: per-session DB isolation, concurrent-write safety, cross-agent IPC delivery, extractor-pool queue semantics, CRIU checkpoint validation, goals-progress idempotency.

---

## Dependencies

No GPU. No external API. Everything runs locally.

| Dependency | Purpose |
|---|---|
| Python 3.12+ | Core runtime |
| SQLite (built-in) | Store + FTS5 full-text index |
| `nc`, `flock` | Daemon socket + single-instance startup |

---

## Contributing

Each subsystem hides behind a clean VFS interface, so components are testable in isolation. Issues, design proposals, and pull requests are welcome — see the [Discussions tab](https://github.com/soolaugust/0CompactMem/discussions) for design questions, and please run the test subset above before submitting a PR.

---

<div align="center">

*Context compaction is the #1 productivity killer in Claude Code.*
*0CompactMem makes it a non-event.*

**[English](./README.md) · [中文](./README.zh.md)**

</div>
