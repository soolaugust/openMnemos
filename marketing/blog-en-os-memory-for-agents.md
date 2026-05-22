---
title: "Why your AI agents need OS-style memory management (and not another vector DB)"
description: "Most LLM memory libraries are vector stores in disguise. The mental model that actually scales — for one agent, and especially for many — is the operating-system memory subsystem. Here's the case for it, and an open-source implementation."
tags: ["ai", "llm", "agents", "memory"]
canonical_url: "https://github.com/soolaugust/0CompactMem"
published: false
---

## TL;DR

LLM "memory" libraries — mem0, Letta, Zep, and friends — mostly model memory
as a **store**: vectors, graphs, episodic logs. That works for a single agent,
but it falls apart the moment you run multiple agents, want predictable
eviction, or need to pin a constraint so it never disappears.

The operating system solved exactly the same class of problems forty years ago.
Demand paging, kswapd, kworker pools, mlock, CRIU, DAMON — these are not
incidental Linux internals. They are the canonical answers to "limited fast
storage, unlimited slow storage, many concurrent consumers, predictable
guarantees under pressure."

LLM agents are *new* consumers of an *old* problem. We should not invent a new
abstraction. We should reuse the one that has been battle-tested for decades.

This post argues for that, then walks through how
[0CompactMem](https://github.com/soolaugust/0CompactMem) — an open-source memory
layer — implements the OS analogy concretely.

---

## The problem with "memory = store"

Open any popular LLM memory library and you will see roughly the same shape:

```python
mem.add(user_id, "the user prefers concise replies")
mem.search(user_id, query)
```

Underneath, it is a vector store, sometimes augmented with a graph or temporal
index. The mental model is **persistence**: things go in, things come out.

Three issues show up almost immediately:

1. **No back-pressure semantics.** What happens when the store is full? Most
   libraries either grow forever, or evict by TTL/recency without giving the
   user a way to say "this constraint is non-negotiable, don't touch it."
2. **No multi-consumer story.** When two agents share a memory, they fight
   over the same chunks. There is no scheduler, no priority, no quota.
3. **No demand-paging discipline.** Retrieval pulls "top-K similar," but the
   agent has no way to express "I might need X if I get further into the
   problem; keep it warm" or "I'm done with X for now; cool it down."

The deeper issue: vectors-in-a-store optimizes for **find similar things**.
Cognition needs more than that. It needs **resource management under
pressure**.

---

## What an OS already taught us

Look at how Linux manages RAM:

| Concern                              | Linux solution                          |
|--------------------------------------|------------------------------------------|
| Slow storage, fast working space     | Disk + RAM with page cache               |
| Pull only what you need              | Demand paging (`do_page_fault`)          |
| Reclaim under pressure               | kswapd watermarks + LRU                  |
| Track real working set               | DAMON (data access monitoring)           |
| Pin must-have data                   | `mlock` / `mlockall`                     |
| Snapshot / restore a process         | CRIU                                     |
| Async I/O off the critical path      | kworker thread pools                     |
| Multiple processes, one substrate    | Process scheduler + cgroups              |

Every one of these has a direct counterpart in agent memory:

| Agent concern                               | OS analogue                  |
|---------------------------------------------|------------------------------|
| Context window vs persistent knowledge      | RAM vs disk                  |
| "Pull relevant memories on demand"          | Demand paging                |
| Reclaim when DB grows past target           | kswapd                       |
| Track which memories are actually re-used   | DAMON                        |
| Lock down a hard constraint                 | mlock                        |
| Pause and resume a session                  | CRIU                         |
| Extract knowledge in the background         | kworker pool                 |
| Multiple agents sharing one knowledge base  | Process scheduling + cgroups |

The point is not that this is a clever metaphor. The point is that **the
problems are isomorphic**, so the solutions transfer. You don't have to invent
a new eviction policy for agent memory; you can adapt the kswapd watermark
algorithm and reason about it the same way kernel engineers have for years.

---

## A worked example: the "pin a constraint" problem

You're building a coding agent that has learned, the hard way, that **the
project's tests must hit a real database, not mocks** — because mocked tests
once let a broken migration ship to production.

In a vector-store memory:
- You write the lesson as a chunk.
- A month later it scores low on similarity for the current query, gets
  evicted by TTL or LRU, and the agent re-mocks the database.

In an OS-style memory:
- You write the lesson, then `pin_memory(chunk_id, kind="hard")`.
- `mlock`-equivalent semantics mean *no eviction path can touch this chunk*.
  Not LRU. Not kswapd. Not DAMON. Not stale-reclaim.
- The constraint survives across sessions and across agents.

The difference is not "more features." The difference is having a clear,
named primitive for "this must not be reclaimed," and a guarantee that every
reclaim path respects it.

---

## A worked example: multi-agent sharing

Two agents — one writing code, one reviewing it — should share the same
knowledge about the codebase. In most memory libraries the answer is "spin up
two stores and sync them," or "share a server and live with API latency."

OS-style answer: one store, multiple readers/writers, scheduler-aware
retrieval. The "coding" agent and the "review" agent see the same chunks.
When one agent learns a new constraint and pins it, the other agent picks it
up automatically. No syncing protocol, no cache coherence headaches — because
the underlying store is the single source of truth, exactly like a shared
filesystem.

This is what `0CompactMem` does in practice. It is a single SQLite file. Any
process that opens it joins the same memory namespace.

---

## Why SQLite, why a single file

The first reaction I usually get is "but vector DBs are faster." Two replies:

1. For agent-scale data (tens of thousands to a few million chunks), SQLite
   with FTS5 + a small embedding index is already fast enough. The bottleneck
   is the LLM call, not the lookup.
2. The single-file constraint is a **feature**, not a limitation. It means:
   - Zero-admin deploy: copy a file.
   - Easy backups: copy a file.
   - Trivial multi-agent sharing: open a file.
   - No DB server to babysit on a laptop.

You're trading peak throughput you don't need for operational simplicity you
absolutely do.

---

## What 0CompactMem actually implements

[0CompactMem](https://github.com/soolaugust/0CompactMem) (formerly `memory-os`)
is a small Python project that wires the OS analogy concretely:

- **Storage**: SQLite (WAL mode), single file, single source of truth.
- **Retrieval**: BM25 + semantic, scored, with explicit `memory_lookup`
  primitive — this is "demand paging."
- **Eviction**: kswapd-style watermarks, DAMON-inspired access tracking,
  cold-region reclamation. Hot chunks stay hot; cold chunks get cooler.
- **Pinning**: `pin_memory(kind="hard"|"soft")`. Hard pins survive every
  reclaim path; soft pins survive normal reclamation but yield under extreme
  pressure.
- **Multi-agent**: any process can open the file. Pinning, eviction, and
  retrieval all share the same underlying store.
- **MCP-native**: ships as a Model Context Protocol server, so any MCP-aware
  client (Claude Code, Cursor, custom agents) gets `memory_lookup`,
  `pin_memory`, `memory_stats` as tools out of the box.
- **Privacy filter**: regex + heuristic stripping of secrets/PII before write.
- **Tests**: 3,500+, because eviction logic is one of those domains where the
  bug never shows up in the demo and always shows up in production.

The codebase has been through 1,051+ tuning iterations. Many of them are tiny
(`iter1894: tiny_db ac>=4+lt>=4 non-dc lifetime threshold 8→6`), which is
exactly what eviction tuning looks like in real kernels too.

---

## When this is the wrong tool

Be honest about what OS-style memory is *not*:

- **Not a managed cloud service.** If you want a SaaS to call from anywhere,
  use mem0 cloud or Zep cloud.
- **Not a full agent runtime.** If you want LangGraph/Letta-style agents
  with built-in tool loops, 0CompactMem is just the memory layer; pair it
  with your runtime of choice.
- **Not a planet-scale vector DB.** If you have 100M+ chunks, use a real
  vector DB. 0CompactMem targets the laptop / single-server regime.

---

## Try it

```bash
# In Claude Code
/install-plugin github:soolaugust/0CompactMem
```

```bash
# Or manually
git clone https://github.com/soolaugust/0CompactMem
cd 0CompactMem
pip install -e .
python init/bootstrap.py
```

The README walks through the rest. The
[`llms.txt`](https://github.com/soolaugust/0CompactMem/blob/main/llms.txt) at
the repo root is a deliberately compact summary if you want to feed it to
your own model first.

---

## The broader bet

Agent memory will be a real infrastructure layer in 2026, the way databases
were in the 90s and message queues were in the 2010s. The teams who build
that layer well will steal ideas from operating systems, not from search
engines. Demand paging > "top-K similar." Pinning > TTL. Watermarks >
unbounded growth.

If that resonates, [come read the code](https://github.com/soolaugust/0CompactMem)
or open an issue. The interesting work is just starting.
