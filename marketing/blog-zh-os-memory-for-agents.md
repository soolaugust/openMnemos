# 为什么 AI Agent 不需要又一个向量数据库 —— 它需要的是操作系统级的内存管理

> 给程序员的一个猜想：未来一年里，"agent memory" 会成为基础设施层。能赢的不会是又一个向量库，而是把操作系统内核里那套 demand paging / kswapd / mlock / kworker 搬过来的人。
>
> 本文是这个猜想的论证，附一个 [开源实现 0CompactMem](https://github.com/soolaugust/0CompactMem)。

## 一句话

主流 LLM 记忆库（mem0、Letta、Zep…）几乎都在做同一件事：把记忆当成一个 **存储**，向量化、丢进去、按相似度搜出来。这套思路对单 agent 还行，**一旦你做多 agent、做"硬性约束不能丢"、做受压力下的可预测淘汰，它就开始崩**。

操作系统四十年前就把这类问题解决干净了。Demand paging、kswapd 水位线、mlock、kworker、CRIU、DAMON——这些不是 Linux 的实现细节，而是 **"快存储有限、慢存储无限、多并发消费者、压力下需要可预测保证"** 这一类问题的标准答案。

LLM agent 是一个 **新的消费者**，遇到的却是一个 **老问题**。我们不应该再发明一套抽象，应该复用那套已经被打磨了几十年的。

---

## "把记忆当存储"哪里不够

随便翻开一个流行的 LLM 记忆库，结构大体长这样：

```python
mem.add(user_id, "用户喜欢简洁的回答")
mem.search(user_id, query)
```

底层是个向量库，可能加点图、加点时序索引。心智模型是 **持久化**：往里写，从里搜。

跑起来很快就能撞到三个问题：

1. **没有反压语义。** 库满了怎么办？大多数实现要么无限增长，要么按 TTL/最近访问简单淘汰。你没法说："这条约束是我用血换的，谁都别碰它。"
2. **没有多消费者模型。** 两个 agent 共用一个记忆库，它们抢的是同一批 chunk。没有调度器，没有优先级，没有配额。
3. **没有按需分页的纪律。** 检索能拿出 top-K 相似，但 agent 没有办法表达"我等会儿可能用 X，先把它热着"或者"我刚用完 Y，可以让它冷下去。"

更深的问题：**向量库优化的是"找相似"，但认知系统要的不只是这个，它要的是"压力下的资源管理"。**

---

## 操作系统其实已经把答案写好了

看一下 Linux 怎么管 RAM：

| 关切点                 | Linux 解法                |
|------------------------|---------------------------|
| 慢存储 + 快工作区      | 磁盘 + RAM + page cache   |
| 只在用的时候拉         | Demand paging             |
| 压力下回收             | kswapd 水位线 + LRU       |
| 跟踪真正的工作集       | DAMON                     |
| 锁住关键数据           | `mlock` / `mlockall`      |
| 进程快照恢复           | CRIU                      |
| 异步 I/O              | kworker 线程池             |
| 多进程共用底层资源     | 进程调度 + cgroups        |

每一项都有 agent memory 的对偶：

| Agent 的关切点                 | OS 类比               |
|--------------------------------|-----------------------|
| Context window vs 持久知识     | RAM vs 磁盘           |
| "按需取相关记忆"              | Demand paging         |
| 库长太大要回收                 | kswapd                |
| 跟踪哪些记忆真的被复用         | DAMON                 |
| 锁死一条硬约束                 | mlock                 |
| Session 暂停/恢复              | CRIU                  |
| 后台抽取知识                   | kworker pool          |
| 多 agent 共享一个知识库        | 进程调度 + cgroups    |

不是 metaphor 写得漂亮，而是 **问题同构，所以解能直接搬过来**。你不必为 agent memory 发明一套新的淘汰算法，把 kswapd 水位线那一套抄过来即可。它的正确性已经被几十年的内核工程验证过了。

---

## 一个具体例子：钉死一条约束

你在做一个写代码的 agent，它从生产事故里学到了一条铁律：**测试必须打真实数据库，绝对不能 mock**——因为有一次 mock 测试通过、迁移在生产挂了。

向量库式记忆里：
- 你把这条教训写进去。
- 一个月后，对当前问题的相似度不高，被 TTL/LRU 默默淘汰，agent 又开始 mock。

OS 风格记忆里：
- 写进去之后 `pin_memory(chunk_id, kind="hard")`。
- mlock 风格的语义保证 **任何回收路径都不能动这个 chunk**。LRU 不行，kswapd 不行，DAMON 不行，stale 回收不行。
- 这条约束跨 session、跨 agent 都在。

差别不是"功能更多"。差别是 **存在一个清晰命名的原语：'这个不准回收'，并且每条回收路径都尊重它**。

---

## 第二个例子：多 agent 共享

写代码的 agent + 审代码的 agent，应该共享同一份代码库知识。绝大多数记忆库给的回答是"开两个 store 然后同步"或者"挂一个 server，带着 API 延迟用"。

OS 思路的回答：**一个 store，多个读写者，调度器感知的检索**。两个 agent 看到完全一样的 chunk。一边学到新约束并钉住，另一边自动看到。没有同步协议、没有缓存一致性的烦恼——因为底层就一份事实，跟共享文件系统一样。

[0CompactMem](https://github.com/soolaugust/0CompactMem) 实际上就是这么做的：一个 SQLite 文件，任何打开它的进程就加入了同一个记忆命名空间。

---

## 为什么是 SQLite，为什么是单文件

会被立刻问："但向量库更快啊。"两个回应：

1. Agent 规模的数据（几万到几百万 chunk），SQLite + FTS5 + 一个小的 embedding 索引就够快了。瓶颈是 LLM 调用，不是查询。
2. 单文件不是限制，是 **特性**。它意味着：
   - 零运维：复制一个文件就完事
   - 备份简单：复制一个文件
   - 多 agent 共享平凡：打开一个文件
   - 笔记本上不需要再起一个数据库

你拿你不需要的"峰值吞吐"换你非常需要的"运维简洁"。这是好交易。

---

## 0CompactMem 实际做了什么

[0CompactMem](https://github.com/soolaugust/0CompactMem)（前身是 `memory-os`）是一个小的 Python 项目，把上述 OS 类比落到代码：

- **存储**：SQLite（WAL），单文件，单一事实源。
- **检索**：BM25 + 语义混合打分，显式的 `memory_lookup` 原语 = "demand paging"。
- **淘汰**：kswapd 风格水位线 + DAMON 风格访问跟踪，冷区域优先回收。
- **Pin**：`pin_memory(kind="hard"|"soft")`。Hard pin 在所有回收路径下都活着。
- **多 agent**：任何进程打开同一个文件即加入。
- **MCP-native**：作为 Model Context Protocol server 发布。Claude Code / Cursor / 自定义 agent 直接拿到 `memory_lookup`、`pin_memory`、`memory_stats` 这些工具。
- **隐私过滤器**：写入前走 regex + 启发式，剥掉 secret/PII。
- **测试**：3500+ 条。淘汰逻辑就是那种 **demo 永远不出问题、生产必出问题** 的领域，测试覆盖是必需品。

仓库经过 1051+ 次内部调参迭代。很多 commit 都是这种风格——`iter1894: tiny_db ac>=4+lt>=4 non-dc lifetime threshold 8→6`。这正是真实的内核淘汰调参的样子。

---

## 它不适合什么

- **托管云服务**：要 SaaS 用 mem0 / Zep cloud。
- **完整的 agent runtime**：要 LangGraph / Letta 那种带工具循环的，0CompactMem 只是记忆层，搭配你自己的 runtime。
- **百万级以上向量库**：100M+ chunk 用真正的向量 DB。0CompactMem 瞄准的是笔记本/单机规模。

---

## 上手

```bash
# Claude Code 里
/install-plugin github:soolaugust/0CompactMem
```

```bash
# 或者手动
git clone https://github.com/soolaugust/0CompactMem
cd 0CompactMem
pip install -e .
python init/bootstrap.py
```

README 里有完整指引。仓库根的 [`llms.txt`](https://github.com/soolaugust/0CompactMem/blob/main/llms.txt) 是一个很紧凑的项目摘要，可以喂给你自己的模型先看。

---

## 大胆一点的赌注

Agent memory 在 2026 会变成一个真正的基础设施层，就像 90 年代的数据库、2010 年代的消息队列。把这一层做好的团队，会从操作系统里偷思路，而不是从搜索引擎。Demand paging > "top-K 相似"。Pin > TTL。水位线 > 无限增长。

如果这套思路打动了你，[来看看代码](https://github.com/soolaugust/0CompactMem) 或开个 issue。有意思的工作才刚开始。
