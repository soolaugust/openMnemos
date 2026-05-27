<div align="center">

# 0CompactMem

**零压缩。无限记忆。为 Claude Code 和所有 LLM agent 而生。**

*你的 AI 永不失忆——告别 "context compacted" 的痛苦。*

[![Python](https://img.shields.io/badge/python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/storage-SQLite%20WAL-lightgrey?logo=sqlite)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-3500%2B%20passing-brightgreen)](#测试)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Discussions](https://img.shields.io/badge/讨论-GitHub-blue?logo=github)](https://github.com/soolaugust/0CompactMem/discussions)

[English](./README.md) · [中文](./README.zh.md)

</div>

> **Claude Code 一行装：**
> ```
> /install-plugin github:soolaugust/0CompactMem
> ```

---

## 问题：context compaction 毁掉你的心流

如果你用 Claude Code，你一定见过这个：

```
⚠️ Auto-compact: conversation is approaching context limit...
```

每次 compact，AI 丢失了你们之间积累的决策、约束、踩过的坑。你重新解释，它重新犯错。几小时的上下文积累——一次压缩全部归零。

多个 agent 一起工作？它们之间无法共享学到的东西。每个都从零开始。

**这不是模型的限制，是缺了一层基础设施。**

---

## 解法：让记忆在 compaction 之外持久存活

0CompactMem 给你的 AI agent **持久化、可检索的记忆**，活在 context window 之外。当 compaction 发生时，什么都不丢——因为重要的东西从一开始就不仅仅存在于 context window 里。

结果：**零有效压缩**。你的 AI 跨 session、跨 compaction、跨 agent 保留每一个决策、约束和教训。

### 工作流程

```
你说话
  → 0CompactMem 检索相关记忆 → 注入 context
  → AI 带着完整上下文回答
  → Session 结束 → 决策和洞察自动提取 → 持久化
  → Compaction 发生？没影响——记忆活在 window 外
  → 下次 session 启动 → 工作集自动恢复
```

整个管线跑在 Claude Code hooks 里，无需手动管理记忆。

---

## 为什么叫 "0CompactMem"？

| 别人看到的 | 实际发生的 |
|---|---|
| "Context compacted" | 关键知识早已持久化到记忆库 |
| 新 session 启动 | 工作集 <100ms 自动恢复 |
| 多个 agent 并行跑 | 共享同一份记忆——零重复解释 |
| 3 周前定的约束 | 钉死在记忆中，保证永不被淘汰 |

**零压缩影响。零上下文丢失。零重复解释。**

---

## 底层原理：OS 内存管理给 AI 用

秘密武器？我们没发明新算法，直接搬了 Linux 内核做了 40 年的东西：

| OS 概念 | 0CompactMem 对应 |
|---|---|
| RAM（工作区） | Context window — AI 当前看到的 |
| 磁盘（持久存储） | 知识库 — 跨 session 存活的事实 |
| Demand paging（按需分页） | 按需检索 — 在合适时刻取相关记忆 |
| `mlock` | Hard / soft pinning — 钉死不可淘汰的约束 |
| kswapd 水位线 | 容量感知淘汰 — 压力下的可预测回收 |
| CRIU 检查点 / 恢复 | Session 快照 — 暂停与无缝恢复 |
| 进程调度 | 多 agent 协调 — 多个 agent 共享同一个知识库 |
| kworker 线程池 | 异步提取 — I/O 从关键路径卸载 |

---

## 跟同类方案的对比

|                          | **0CompactMem**          | mem0           | Letta (MemGPT) | Zep            |
|--------------------------|--------------------------|----------------|----------------|----------------|
| 设计隐喻                 | OS 内存子系统            | 向量库         | Agent 运行时   | 时序图         |
| 零压缩保证               | ✅ pinned 记忆存活       | ❌             | ❌             | ❌             |
| 多 agent 共享            | ✅ 原生单库              | ⚠️ 需 API     | ✅             | ✅             |
| MCP 原生                 | ✅ 一等公民              | ❌             | ❌             | ❌             |
| 单文件部署               | ✅ SQLite，无需服务      | ❌ 需服务端    | ❌ 需服务端    | ❌ 需服务端    |
| Demand-paging 检索       | ✅ 显式                  | 隐式           | 隐式           | 隐式           |
| 淘汰策略                 | ✅ kswapd + DAMON        | 仅 TTL         | 仅 recency     | recency + decay|
| Pin / mlock 语义         | ✅                       | ❌             | ❌             | ❌             |

> **一句话**：如果你受够了 context compaction 清空你的 AI 记忆，想要一个 `pip install` 就能用、笔记本上跑、多 agent 共享、关键约束永不丢失的方案——0CompactMem 就是为你做的。

---

## 性能一览

| 指标 | 数值 |
|---|---|
| 检索延迟 (P50, 热路径) | **~0.1 ms**（比 54ms 子进程基线快 540 倍）|
| Recall@3 vs 基线 | **+147%** |
| 跨 session 召回率 | **94.2%** |
| 每次调用 token 开销 | ~44 tokens 注入，**+256 tokens 净 ROI**（省去重新解释）|
| 测试套件 | 3,500+ 测试覆盖检索、淘汰、MCP、隐私过滤 |

---

## 快速开始

**一行安装（推荐）**

```
/install-plugin github:soolaugust/0CompactMem
```

**手动安装**

```bash
git clone https://github.com/soolaugust/0CompactMem
cd 0CompactMem
pip install -e .
mkdir -p ~/.claude/memory-os
```

详细的 Claude Code hook 配置、daemon 管理和 troubleshooting 见 [`docs/SETUP.md`](./docs/SETUP.md)。

---

## 架构

三层：

1. **Hooks** — 位于 Claude Code 系统调用边界（`SessionStart`、`UserPromptSubmit`、`Stop`、`PostToolUse`），调用 store。
2. **Store** — 单一 SQLite 文件（WAL 模式）带 FTS5 全文索引，统一 VFS 接口（`store.py` / `store_vfs.py` / `store_criu.py`）。
3. **Daemons & IPC** — 持久检索 daemon（Unix socket）、异步提取池（kworker 风格）、跨 agent 通知总线。

完整分层图、磁盘 schema 和各子系统设计理由见 [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)。OS 与认知科学原语的完整映射见 [`docs/DESIGN_PHILOSOPHY.md`](./docs/DESIGN_PHILOSOPHY.md)。

---

## 测试

```bash
# 稳定测试子集
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

覆盖：per-session DB 隔离、并发写安全、跨 agent IPC 投递、提取池队列语义、CRIU checkpoint 验证、goals-progress 幂等性。

---

## 依赖

无 GPU。无外部 API。全部本地运行。

| 依赖 | 用途 |
|---|---|
| Python 3.12+ | 核心运行时 |
| SQLite（内置） | Store + FTS5 全文索引 |
| `nc`, `flock` | Daemon socket + 单实例启动 |

---

## 论文

📄 **[Beyond Eviction: Full OS Memory Semantics for LLM Agent Persistence](https://github.com/soolaugust/0CompactMem/releases/download/v0.1.0/main.pdf)** (PDF, 8 页)

技术论文，描述完整的 OS→agent-memory 映射：demand paging、kswapd、DAMON、mlock、CRIU、kworker、shared memory。

## 引用

```bibtex
@software{su2026compactmem,
  title = {0CompactMem: Full OS Memory Semantics for LLM Agent Persistence},
  author = {Su, Zhidao},
  year = {2026},
  url = {https://github.com/soolaugust/0CompactMem}
}
```

## 贡献

每个子系统藏在干净的 VFS 接口后面，可独立测试。欢迎 issue、设计提案和 PR — 设计问题见 [Discussions](https://github.com/soolaugust/0CompactMem/discussions)，提交 PR 前请跑一遍上面的测试子集。

---

<div align="center">

*Context compaction 是 Claude Code 的头号生产力杀手。*
*0CompactMem 让它变成一个不存在的问题。*

**[English](./README.md) · [中文](./README.zh.md)**

</div>
