# Changelog

All notable changes to **0CompactMem** are recorded here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions and
[Semantic Versioning](https://semver.org/) with one caveat: until v1.0.0, the
internal iteration counter (`iterN`) is the more granular changelog. Public
releases are cut from stable iteration milestones.

For day-to-day, per-iteration optimization notes, see
[`OPTIMIZATION_LOG.md`](./OPTIMIZATION_LOG.md).

## [Unreleased]

- Continuous tuning of recall floor / pair-saturation / eviction shields
  (iter1873 — current).

## [0.1.0] — 2026-05-20

First public-friendly cut. Project renamed from `memory-os` to **0CompactMem**
on 2026-05-19. Public repository: <https://github.com/soolaugust/0CompactMem>.

### Added
- **Project rename + dual-language READMEs.** English (`README.md`,
  `README.en.md`) and Simplified Chinese (`README.zh.md`).
- **Competitor comparison section** in all three READMEs (vs mem0, Letta, Zep).
- **`llms.txt`** at repo root — concise, LLM-crawler-friendly project summary.
- **GitHub repository topics** expanded to 20 entries covering `llm`,
  `llm-memory`, `mcp`, `model-context-protocol`, `rag`, `vector-database`,
  `agent-memory`, `multi-agent`, `persistent-memory`, etc.
- **Social preview asset** at `assets/social-preview.svg`.
- **MCP server** exposing `memory_lookup`, `pin_memory`, `unpin_memory`,
  `memory_stats`, `list_pinned` (`mcp_memory_lookup.py`).
- **Privacy filter** (`privacy_filter.py`) for secrets / PII heuristics.
- **Knowledge VFS** (`knowledge_vfs.py`, `knowledge_vfs_backends.py`,
  `knowledge_vfs_init.py`) — pluggable storage layer.
- **Eviction subsystem** with kswapd-style watermarks and DAMON-inspired
  access tracking.
- **Pin / mlock semantics** — hard and soft pinning protect chunks from
  eviction under pressure.
- **Pair-saturation diversity recall** to avoid redundant similar chunks.
- **Production assertions** (`production_assertions.py`) — runtime invariants
  that guard the hot path.
- **3,500+ test cases** under `tests/` covering core retrieval, scoring,
  eviction, MCP server, privacy filter, and integration paths.

### Changed
- Documentation polish across READMEs; clearer "How It Works" pipeline diagram.

### Notes
- This is an early-stage public release. APIs, CLI flags, and on-disk schema
  may evolve until v1.0.0. Pin to a specific commit if you need stability.
- 1,051+ internal iterations preceded this tag. The iteration history is
  preserved in git log and `OPTIMIZATION_LOG.md`.
