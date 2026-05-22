# GitHub Discussions — 起手帖（pinned welcome post）

发布在：https://github.com/soolaugust/0CompactMem/discussions

建议分两帖：
1. **Welcome / What this is** —— 在 "Announcements" 分类，pin 住
2. **Roadmap & open questions** —— 在 "Ideas" 分类，开放讨论

---

## Post #1 — Welcome (Announcements category, pinned)

**Title:** 👋 Welcome to 0CompactMem — what this is, and what it isn't

**Body:**

```markdown
Hi all — thanks for finding this project early.

**0CompactMem** is a memory infrastructure layer for LLM agents. The core bet
is that the right mental model for agent memory is the **operating-system
memory subsystem** — demand paging, kswapd-style eviction, `mlock` pinning,
CRIU snapshots, kworker pools — not "another vector database."

If you want the long version, the README has it. This post is a short
orientation for new visitors and a place to land questions.

## What it is

- A persistent memory layer that survives sessions and is shared across agents.
- A single SQLite file (WAL mode). Open it, you're in.
- An MCP server: Claude Code / Cursor / custom agents pick up `memory_lookup`,
  `pin_memory`, `unpin_memory`, `memory_stats`, `list_pinned` as tools.
- Hard / soft pin: hard pins are guaranteed to survive every reclaim path.
- kswapd-style watermarks + DAMON-inspired access tracking for eviction.
- 3,500+ tests; 1,051+ internal tuning iterations preceded v0.1.0.

## What it isn't

- A managed cloud service. (Look at mem0 cloud / Zep cloud.)
- A full agent runtime. (Pair with LangGraph / Letta / your own.)
- A planet-scale vector DB. 0CompactMem targets laptop / single-server scale.

## Where to start

- 🚀 **Try it:** `/install-plugin github:soolaugust/0CompactMem` in Claude Code,
  or follow the manual install in the README.
- 📖 **Why OS-style memory:** see "Design Philosophy" in the README, and the
  comparison table near the top.
- 🧠 **Compact summary for LLMs / your own agent:** `llms.txt` at repo root.

## Where to ask things

- 💬 **General questions / "how does X compare to Y":** post in this Discussions tab.
- 🐛 **Bug reports / regressions:** open an Issue.
- 💡 **Design proposals / new primitives:** Discussions → Ideas.
- 📦 **Pull requests:** very welcome. Tests are required for behavior changes.

## Roadmap snapshot

Short-term:
- arXiv preprint (technical evaluation vs mem0 / Letta / Zep)
- Adaptive watermarks based on observed agent behavior
- Distributed 0CompactMem (cgroup-style multi-agent quotas)

The full roadmap lives in the README. If something is missing that you'd find
valuable, please open an Idea — most direction so far has come from real use.

— @soolaugust
```

---

## Post #2 — Open Questions (Ideas category)

**Title:** 🧭 Open design questions for v0.2 — what should we tackle next?

**Body:**

```markdown
A few design questions where outside input would actually change my mind.
If any of these resonate, drop a reply or your own framing.

### 1. Distributed mode

A single SQLite file is great for laptops and single servers, terrible across
machines. The natural next step is "cgroup-style" multi-agent quotas with
network-replicated stores.

- Should we lean on Litestream / rqlite / SQLite-on-FUSE, or write our own
  CRDT-ish layer?
- Is "shared file via NFS / SMB" a degenerate solution that's good enough for 90% of users?

### 2. Embedding-model coupling

Currently the embedding model is configurable but not pluggable per-chunk.
Some teams will want different models for code vs prose.

- Worth supporting per-chunk embedding models with a routing function?
- Or is "one store = one model" a feature, not a bug?

### 3. What "session" means

OpenMnemos has session checkpoints (CRIU-style). But sessions in agent
frameworks are a leaky abstraction — sometimes a process, sometimes a
conversation, sometimes a tab.

- What's *your* unit of "session" in production? Help shape the primitive.

### 4. Eviction tuning

Eviction is currently kswapd watermarks + DAMON access tracking. The tuning
has come from ~1,000 iterations on my own data.

- If you've got a workload that breaks the current eviction policy, please
  share it (synthetic or real). New benchmarks beat new heuristics.

### 5. Privacy filter as a default

The privacy filter is regex + heuristics, opt-in.

- Should it be on by default? Where would you draw the line between
  "secrets/PII" (always strip) and "user content" (preserve)?

---

If you're using 0CompactMem in a real workflow — even a hacky one — I'd love
to hear about it in this thread. Concrete use-cases beat abstract roadmap
items every time.
```

---

## Posting tactics

- **Pin Post #1** to the top of Discussions. Set as Announcement.
- **Post #2 in Ideas category** — leave unpinned, it's a working thread.
- **Cross-link from README**: add a small badge at top of README:
  ```markdown
  [![Discussions](https://img.shields.io/badge/discuss-on%20GitHub-blue?logo=github)](https://github.com/soolaugust/0CompactMem/discussions)
  ```
- **Reply to every new Discussion thread within 24h** for the first 30 days —
  community signal that the project is alive matters more than any feature.
- When the Show HN goes live, **link the HN post in Discussions** ("we're
  on HN today, AMA here too"). Cross-pollinates audiences.

---

## Why two posts, not one

A pinned welcome answers "what is this," but doesn't invite engagement. A
separate "open questions" post explicitly says "your reply matters here."
The combination produces more replies than either alone.
