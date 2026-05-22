# Product Hunt launch package

Submission link: https://www.producthunt.com/posts/new

## Tagline (60 chars max)

Primary:

> Zero context compaction for Claude Code & LLM agents

Backups:

> Your AI never forgets — persistent memory that survives compaction
> End "context compacted" forever. OS-grade memory for AI.

## Topics (pick up to 4)

- Artificial Intelligence
- Developer Tools
- Open Source
- GitHub

## Description (260 chars max)

> 0CompactMem eliminates context compaction in Claude Code. Persistent memory
> that survives window resets — powered by OS memory-management primitives
> (demand paging, kswapd eviction, mlock pinning). Single SQLite file,
> MCP-native, multi-agent shared. MIT.

## First comment (Maker comment — post at launch)

> Hi PH — maker here.
>
> **The pain**: every Claude Code user has seen "context compacted." Hours of
> accumulated decisions, constraints, architectural knowledge — wiped. You
> re-explain. The model re-learns. Multiply by every agent you run.
>
> **The fix**: 0CompactMem gives your AI persistent memory that lives *outside*
> the context window. When compaction hits, nothing critical is lost.
>
> How it achieves "zero compaction":
>
> - **Demand paging** — `memory_lookup` fetches exactly what's relevant, on demand
> - **mlock pinning** — pin a constraint, it's *guaranteed* to survive every reclaim
> - **kswapd watermarks** — capacity-aware eviction, not arbitrary TTLs
> - **Multi-agent native** — one SQLite file, all your agents share it
> - **MCP server** — works with Claude Code, Cursor, custom agents out of the box
> - **3,500+ tests, 1,050+ tuning iterations** — battle-tested eviction logic
>
> One-line install in Claude Code:
>
>     /install-plugin github:soolaugust/0CompactMem
>
> Or pip install + bootstrap (README has the steps).
>
> **What it isn't**: a managed cloud service, a full agent runtime, or a
> planet-scale vector DB. It's the memory *layer* that makes compaction
> invisible.
>
> Repo: https://github.com/soolaugust/0CompactMem
>
> Happy to dig into the zero-compact guarantee, OS analogy, or multi-agent
> coherence model. Roast away.

## Hunter

If possible, find a hunter active in AI/dev-tools. If self-hunting, fine.

## Visuals checklist

- [ ] **Logo** — 240x240 PNG (the "0" in 0CompactMem prominently featured)
- [ ] **Gallery image 1** — hero shot: "Before vs After" — compaction pain
      vs smooth memory restoration
- [ ] **Gallery image 2** — animated GIF / screenshot of `memory_lookup`
      returning results after a compaction event
- [ ] **Gallery image 3** — diagram: OS concept -> 0CompactMem primitive
- [ ] **Optional video** — 30-60s screen recording showing: (1) context compacts,
      (2) new session starts, (3) 0CompactMem restores full context instantly

## Launch-day timing

- **Post at 00:01 PT** (PH resets daily at 00:00 PT).
- **Avoid Mondays and Fridays.** Tuesday/Wednesday are best.
- **Avoid major tech-news days** (Apple keynote, OpenAI launch, etc.).

## Engagement plan (first 24h)

- Reply to *every* comment within 30 minutes — PH ranks engagement.
- Don't ask friends to "vote." Do tell them you launched and link the post.
- Post a Twitter/X thread (3-4 tweets) with the PH link **2 hours after**
  launch.
- Cross-post to:
  - r/LocalLLaMA (after it's been on PH for a few hours)
  - r/ClaudeAI — these are the EXACT users who suffer from compaction
  - r/ChatGPTCoding — applies to any LLM coding tool
  - Twitter/X (#buildinpublic, #LLM, #ClaudeCode)
- Update the README with a "Featured on Product Hunt" badge after launch.

## Post-launch artifacts

- A "Day 1 retro" tweet/blog with numbers (votes, signups, GH stars).
- Pin the PH link on the GH repo for a week.
- Add a `# Press` section to README listing the launch and any coverage.
