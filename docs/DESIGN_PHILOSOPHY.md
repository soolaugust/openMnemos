# Design Philosophy — OS / cognitive primitives behind 0CompactMem

> Every subsystem in 0CompactMem maps onto a known mechanism — most from the
> Linux kernel, some from cognitive science. This page is the full mapping,
> mainly for contributors and curious readers. The README only lists the
> top-level metaphor; the table below is the "long form."

The iteration numbers (`iter N`) point at the commit where each mechanism
landed, so you can `git log --grep="iter N"` to see the actual change.

## OS / kernel primitives

| Feature | Linux analogue | Iteration |
|---|---|---|
| Knowledge retrieval injection | Demand paging (page fault) | iter 1 |
| Working-set preload | Denning Working-Set Model | iter 18 |
| Knowledge eviction | kswapd + OOM killer | iter 25, 38 |
| Session restore | CRIU checkpoint / restore | iter 49 |
| Congestion control | TCP AIMD + auto-tuning | iter 50, 51 |
| Multi-generation LRU | MGLRU (Linux 6.x) | iter 44 |
| Access-pattern monitoring | DAMON | iter 42 |
| Output compression hints | zram | iter 110 |
| Persistent retrieval daemon | vDSO + Unix socket | iter 162 |
| Two-level TLB cache | CPU TLB L1 / L2 | iter 179 |
| FTS result cache | Page cache | iter 205 |
| Multi-agent isolation | Linux namespace (PID / mount) | iter 259 |
| Async extraction pool | kworker thread pool + pdflush | iter 260 |
| FTS5 auto-optimize | ext4 online defrag | iter 360 |
| FULL → LITE injection demotion | Page-cache dirty-bit fast-path | iter 361 |
| Proactive swap warmup | MGLRU proactive reclaim | iter 362 |
| Workspace-aware memory | `exec()` address-space switch | iter 363 |
| Loader page-table dedup | MMU page-table walk | iter 526 |
| CFS per-chunk bandwidth throttle | CFS bandwidth controller | iter 560 |
| Graduated bandwidth penalty | TCP congestion window | iter 600–612 |
| Temporal burst suppression (24h / 7d) | Token-bucket rate limiter | iter 614–618 |
| WAL-immune injection timeline | Journal WAL barrier | iter 647–648 |
| Timeline ghost GC | rmap reverse-mapping reclaim | iter 659–660 |
| Suppress-final gate | OOM-kill final adjuster | iter 663 |
| Cross-project recall accounting | cgroups memcg cross-ns stats | iter 566 |
| Long-query classifier bypass | TLB miss fast-path | iter 710 |
| CJK/EN bilingual signal expansion | iconv charset normalization | iter 722 |
| Session-first inject guard | `exec()` address-space reset | iter 804 |
| Short-burst suppress (6h window) | Swap-token fairness | iter 813 |
| Diversity counter round-robin | CFS group scheduling | iter 872 |
| Small-DB diversity boost | NUMA local allocation | iter 898 |
| Global cross-project suppress | cgroup v2 unified hierarchy | iter 1024 |
| Project-concentration penalty | NUMA topology distance | iter 1029 |
| Cross-type total hard cap | memcg hard limit | iter 1050 |

## Cognitive-science primitives

A handful of subsystems borrow from human-memory research where the OS
analogue ran out. These tend to govern *retrieval-quality* decisions
(which item to surface) rather than *resource-management* decisions (when
to evict).

| Feature | Cognitive analogue | Iteration |
|---|---|---|
| Session episode timeline | Hippocampal sequential replay | iter 364 |
| Workspace prospective memory | Prefrontal prospective codes | iter 365 |
| Knowledge-graph spreading activation | CPU cache prefetch (cross-domain) | iter 366 |
| Temporal proximity edges | Sequential read-ahead | iter 367 |
| Attention focus stack | CPU register file | iter 368 |
| Soft forgetting | DAMON cold-page detection | iter 369 |
| Uncertainty signal extraction | MMU soft page fault | iter 370 |
| Conflict detection + chunk coalescing | ext4 fsck + block merge | iter 371–374 |
| Emotional salience boost | DRD4 dopamine reward signal | iter 376 |
| Schema spreading activation | Bartlett schema theory | iter 380 |
| Spacing-effect scheduler | Ebbinghaus forgetting curve | iter 383 |
| Inhibition of return (IOR) | Posner (1980) attention shift | iter 391 |
| Contextual similarity boost | Context-dependent encoding | iter 394 |
| Tip-of-the-tongue (TOT) recovery | FTS5 zero-hit edge activation | iter 425 |
| Serial-position effect ordering | Murdock (1962) primacy / recency | iter 427 |
| Second-chance diversity sampling | Clock page replacement | iter 471 |
| Token-budget aware truncation | Memory pressure tiering | iter 474 |

## Why this matters

The point of the OS analogy isn't decoration. Operating systems solved an
isomorphic class of problems decades ago — limited fast storage, unlimited
slow storage, multiple concurrent consumers, predictable behavior under
pressure. We get to skip forty years of design exploration by reusing the
right primitive instead of inventing a new one.

When you read this list, the mental shift is: every row is a *named tool*
with known semantics. "Page fault" already tells you what should happen
on a miss. "mlock" already tells you what cannot be evicted. The job of
0CompactMem is just to keep that mapping honest.
