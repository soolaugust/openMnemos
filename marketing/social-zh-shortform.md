# 中文社交平台 — 短版文案集

适用：X (中文圈)、微博、即刻、小红书短帖、知乎想法、V2EX、Telegram 频道。
长版博客在 `blog-zh-os-memory-for-agents.md`，这里只放卡片。

---

## A. 极简单条版（适合 X / 即刻 / V2EX 标题）

> 用 Claude Code 最烦的事：
> "⚠️ Auto-compact: conversation approaching context limit..."
>
> 几小时的上下文、决策、约束——一次压缩全没了。
>
> 0CompactMem：让记忆活在 context window 之外。Compact 随便来，什么都不丢。
>
> 单文件 SQLite，多 agent 共享，MCP 原生。MIT。
>
> https://github.com/soolaugust/0CompactMem

---

## B. 钩子版（适合微博/小红书前置 hook 抓眼球）

> 跟你打个赌：2026 年底，"context compacted" 会成为历史。
>
> 不是因为 context window 无限大——而是因为记忆不再住在 window 里。
>
> 0CompactMem：把 Linux 内核 40 年的内存管理搬给 AI 用。
> Demand paging > top-K 相似。Pin > TTL。水位线 > 无限增长。
>
> https://github.com/soolaugust/0CompactMem

---

## C. 痛点版（适合知乎想法 / 即刻 / 微信群 / r/ClaudeAI）

> 你有没有发现：
> 用 Claude Code 写代码，越写到后面越痛苦——因为 compact 来了。
>
> 之前讨论了两小时的架构决策？归零。
> 告诉它不要用某个 API？忘了。
> 开两个 agent 一起干活？互相不知道对方做了啥。
>
> 这不是模型的问题，是记忆不该只住在 context window 里。
>
> 我做了 0CompactMem：
> - 记忆持久化在 window 之外
> - Compact 来了也不丢
> - 关键约束可以 pin 死，永不被淘汰
> - 多 agent 共享同一份记忆
>
> 一行装：`/install-plugin github:soolaugust/0CompactMem`

---

## D. 技术细节版（适合 V2EX / 知乎正文 / Telegram 技术频道）

> 0CompactMem —— 让 Claude Code 的 context compaction 变成不存在的问题
>
> 核心思路：记忆不该只住在 context window 里。把它搬出去，compact 就不是问题了。
>
> 底层借鉴 Linux 内核的内存子系统：
>   • 上下文窗口 ↔ RAM
>   • 知识库     ↔ 磁盘
>   • 按需检索   ↔ Demand paging
>   • 容量淘汰   ↔ kswapd 水位线
>   • 钉死约束   ↔ mlock（hard/soft 两档）
>   • Session 快照 ↔ CRIU
>   • 后台抽取   ↔ kworker pool
>   • 多 agent 共享 ↔ 同一份 SQLite，零同步协议
>
> 性能：检索 P50 0.1ms，跨 session 召回 94.2%，3500+ 测试。MIT。
>
> https://github.com/soolaugust/0CompactMem

---

## E. 即刻 / 小红书 — 第一人称叙事版

> 做了个开源项目分享一下。
>
> 起因：我重度使用 Claude Code，每天跟它协作写代码。最大的痛点就是——
> "context compacted"。
>
> 累积两三小时的上下文，它说压缩就压缩了。之前的决策、约束、踩过的坑全没了。
> 开多个 agent 一起工作更惨，互相不知道对方做了什么。
>
> 后来我想通了：问题不是 context 太小，而是关键记忆不该只住在 context 里。
> 移出去，compact 就不是问题了。
>
> 怎么移？照搬 Linux 内核 40 年的经验：demand paging、kswapd 淘汰、mlock 钉死。
>
> 项目叫 0CompactMem，"0" 就是 Zero Compact 的意思。
> 单文件 SQLite，MCP 原生，多 agent 共享。
>
> 一行装：`/install-plugin github:soolaugust/0CompactMem`
>
> 仓库：https://github.com/soolaugust/0CompactMem

---

## F. Reddit r/ClaudeAI 版（英文，但列在这里方便一起管理）

> **Title**: I built 0CompactMem to fix my #1 frustration with Claude Code: context compaction
>
> **Body**:
>
> Like everyone here, I've hit "Auto-compact: conversation approaching context limit"
> more times than I can count. Every time it happens, Claude forgets what we decided,
> what constraints we set, what mistakes we already fixed.
>
> My fix: don't keep critical knowledge only in the context window. Persist it outside,
> restore it on demand.
>
> 0CompactMem does this using OS memory-management principles (demand paging for
> retrieval, mlock for pinning critical constraints, kswapd for smart eviction).
> It runs as an MCP server inside Claude Code — one-line install:
>
>     /install-plugin github:soolaugust/0CompactMem
>
> Key results:
> - Cross-session recall: 94.2%
> - Retrieval latency: ~0.1ms
> - Pinned constraints: guaranteed never evicted, even under pressure
> - Multi-agent: share memory across all your Claude Code sessions
>
> MIT, single SQLite file, no external service needed.
>
> Happy to answer questions. The name means "Zero Compact Memory" — because
> compaction should be invisible.

---

## 投放节奏建议

| 平台 | 用哪条 | 时间 |
|------|--------|------|
| 微博 | B (钩子版) | 工作日 12:00 / 21:00 |
| 即刻 | E (叙事版) | 工作日 21:00-23:00（即刻活跃高峰）|
| 知乎想法 | C (痛点版) | 工作日 09:00-10:00 |
| V2EX | D (技术细节版) | 周二/三 09:00 |
| 小红书 | E (叙事版改成"副业项目"口吻) | 周末 20:00 |
| r/ClaudeAI | F (Reddit 版) | 周二/三 09:00 ET |
| r/ChatGPTCoding | F (微调措辞) | 同上 |
| Telegram 中文技术频道 | A 或 D | 任意 |

---

## 标签

- 微博：#开源# #Claude Code# #AI Agent#
- 知乎话题：人工智能 / 大语言模型 / 开源软件 / Claude
- 即刻：圈子 → AI 探索站 / 独立开发者俱乐部
- V2EX：节点 → `share` 或 `programmer`
- 小红书：标签 #AI #Claude #程序员日常 #开源
- Reddit: 投 r/ClaudeAI (首选), r/ChatGPTCoding, r/LocalLLaMA

避免：#AI 大爆炸 / #ChatGPT（噪声大、流量不精准）。

---

## SEO 关键词矩阵（中英文）

文案中应自然融入这些关键词组合：

| 英文 | 中文 |
|------|------|
| claude code context compaction | claude code 上下文压缩 |
| claude code memory loss | claude code 记忆丢失 |
| llm agent persistent memory | AI agent 持久记忆 |
| context window limit solution | 上下文窗口限制 解决方案 |
| zero compaction ai memory | 零压缩 AI 记忆 |
| mcp memory server | MCP 记忆服务器 |
| multi agent shared memory | 多 agent 共享记忆 |
