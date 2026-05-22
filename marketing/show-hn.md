# Show HN package

Submission link: https://news.ycombinator.com/submit

## Title (80 chars max — HN auto-rejects longer)

Primary:

> Show HN: 0CompactMem – never lose context to compaction again (Claude Code)

Backup (more technical):

> Show HN: 0CompactMem – OS memory management for LLM agents (zero compaction)

> Show HN: I eliminated Claude Code's context compaction with kswapd and mlock

## URL

https://github.com/soolaugust/0CompactMem

## First comment (post immediately after submitting; HN expects this)

> Hi HN — author here.
>
> If you use Claude Code (or any long-session LLM tool), you've seen this:
>
>     ⚠️ Auto-compact: conversation is approaching context limit...
>
> At that point, your AI loses decisions, constraints, and context you spent
> hours building up. Next session? Start from zero. Multiple agents? Each
> re-learns everything independently.
>
> 0CompactMem fixes this by giving agents persistent memory that lives
> *outside* the context window. When compaction happens, nothing meaningful
> is lost — because the important stuff was already persisted.
>
> The design bet: treat agent memory as an OS memory-management problem, not
> a vector-search problem. Concretely:
>
>   - Single SQLite file (WAL mode). No service to run.
>   - MCP server: Claude Code / Cursor / custom agents get `memory_lookup`,
>     `pin_memory`, `unpin_memory`, `memory_stats` as native tools.
>   - Hard / soft pinning (mlock semantics): pin a constraint, guarantee it
>     survives every reclaim path — including compaction.
>   - kswapd-style watermarks + DAMON-inspired access tracking for eviction.
>   - Multi-agent shared: any process opening the file joins the same memory.
>   - 3,500+ tests; ~1,050 internal tuning iterations.
>
> Why "0CompactMem": the "0" means zero — zero effective compaction. Your
> critical knowledge is always there, even when the context window resets.
>
> Honest caveats:
>
>   - Single-laptop / single-server scale. Not a planet-scale vector DB.
>   - Not a managed cloud service. If you want SaaS, mem0/Zep cloud are good.
>   - Public release is v0.1.0; APIs may shift before v1.0.
>
> Happy to dig into the zero-compact guarantee, eviction policy,
> SQLite-vs-vector-DB choices, or the OS analogy. Roast away.

## Posting checklist

- [ ] Post Tuesday-Thursday, 09:00-11:00 ET (HN front page traffic peak)
- [ ] Verify GitHub repo is public, README is up-to-date, llms.txt is in
- [ ] Pre-warm: have 2-3 friends ready to upvote in the first 30 minutes
      (don't fake — this is just timing, not vote manipulation)
- [ ] Be online for 4 hours after posting to reply to every comment
- [ ] First comment posted within 60 seconds of submission
- [ ] Don't @mention anyone, don't link other social media in the post
- [ ] Set up a Twitter / X thread *before* posting; share the HN link there
      after the post settles for ~30 min
