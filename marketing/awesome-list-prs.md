# Awesome-List Submission Pack

Five PRs to file. Each section has: target repo, suggested target file/section,
ready-to-paste line, and a 1-2 line PR description.

---

## 1. Shubhamsaboo/awesome-llm-apps

- Repo: https://github.com/Shubhamsaboo/awesome-llm-apps
- Likely section: "AI Memory" or "AI Agents"
- Entry:

```markdown
- [0CompactMem](https://github.com/soolaugust/0CompactMem) — OS-inspired persistent memory for LLM agents. Demand paging, multi-agent shared knowledge, MCP-native, single-file SQLite deploy.
```

- PR title: `Add 0CompactMem to AI Memory section`
- PR body:
  > Adding 0CompactMem — a memory layer for LLM agents that borrows OS memory-management primitives (demand paging, kswapd eviction, mlock pinning) instead of inventing new ones. SQLite-backed, MCP-native, multi-agent shared store. MIT licensed, 3,500+ tests.

---

## 2. e2b-dev/awesome-ai-agents

- Repo: https://github.com/e2b-dev/awesome-ai-agents
- Likely section: "Memory" / "Open-source agents tooling"
- Entry:

```markdown
- [0CompactMem](https://github.com/soolaugust/0CompactMem) — Persistent, multi-agent shared memory layer modeled on OS memory subsystems (demand paging, eviction watermarks, pin/mlock). MCP-native; runs as a single SQLite file.
```

- PR title: `Add 0CompactMem (memory layer)`
- PR body:
  > 0CompactMem provides a kernel-grade memory layer for LLM agents. Unlike vector-store memory libraries, it explicitly models RAM/disk/paging/eviction with operating-system semantics, which makes multi-agent coordination and pinning predictable. MCP-native; single-file SQLite deploy. MIT.

---

## 3. hesreallyhim/awesome-claude-code (or any Claude-Code awesome list)

- Repo candidates:
  - https://github.com/hesreallyhim/awesome-claude-code
  - https://github.com/zebbern/claude-code-guide (any list with a "memory" topic)
- Likely section: "MCP servers" / "Memory"
- Entry:

```markdown
- [0CompactMem](https://github.com/soolaugust/0CompactMem) — Persistent memory MCP server for Claude Code. Remembers decisions, constraints, and context across sessions; shareable between multiple Claude Code instances. One-line install: `/install-plugin github:soolaugust/0CompactMem`.
```

- PR title: `Add 0CompactMem memory MCP server`
- PR body:
  > 0CompactMem is a Claude-Code-native persistent memory MCP server. It models memory as an OS subsystem (demand paging, eviction, pinning) and lets multiple Claude Code sessions share the same knowledge base. Installable in one line via `/install-plugin`. MIT.

---

## 4. punkpeye/awesome-mcp-servers (or wong2/awesome-mcp-servers)

- Repo candidates:
  - https://github.com/punkpeye/awesome-mcp-servers
  - https://github.com/wong2/awesome-mcp-servers
  - https://github.com/appcypher/awesome-mcp-servers
- Likely section: "Memory" / "Knowledge Bases"
- Entry:

```markdown
- [0CompactMem](https://github.com/soolaugust/0CompactMem) 🐍 - Persistent memory MCP server with OS-style demand paging, kswapd-style eviction, and pin/mlock semantics. Multi-agent shared SQLite store.
```

- PR title: `Add 0CompactMem to Memory section`
- PR body:
  > Submitting 0CompactMem: a memory MCP server that exposes `memory_lookup`, `pin_memory`, `unpin_memory`, `memory_stats`, `list_pinned`. Designed as an OS memory subsystem (RAM/disk/paging analogy), runs as a single SQLite file, supports multi-agent shared knowledge.

---

## 5. Danielskry/Awesome-RAG (or hymie122/RAG-Survey)

- Repo candidates:
  - https://github.com/Danielskry/Awesome-RAG
  - https://github.com/frutik/Awesome-RAG
- Likely section: "Tools" / "Memory & Long-context"
- Entry:

```markdown
- [0CompactMem](https://github.com/soolaugust/0CompactMem) — Persistent memory layer that doubles as a lightweight RAG store for agents. BM25 + semantic recall, demand-paging retrieval, pinnable chunks, single-file SQLite deploy.
```

- PR title: `Add 0CompactMem as a memory + RAG store`
- PR body:
  > 0CompactMem can be used as a small, embeddable RAG store for AI agents: BM25 + semantic scoring, on-demand retrieval, eviction, pinning. Where it differs from typical vector DBs is that it explicitly models the OS memory hierarchy (RAM/disk/paging) for agent cognition. MIT.

---

## Submission tips

1. **Read each repo's CONTRIBUTING.md before opening the PR** — many awesome
   lists have strict alphabetical ordering, badge formatting, or require entries
   to be older than N days.
2. **Don't bulk-submit on the same day.** Spread across 1-2 weeks; reviewers
   notice patterns.
3. **Engage with one or two existing PRs in the same repo first** (genuine
   review/comment) — improves merge probability.
4. **Always link an alternative section** in your PR if you're unsure where the
   entry fits ("happy to move this to X if Y is more appropriate").
