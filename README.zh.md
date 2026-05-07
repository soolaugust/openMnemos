<div align="center">

# memory-os

**为 Claude Code 设计的内核级持久化记忆**

*跨会话记住决策、约束和上下文 — 像操作系统内存子系统一样设计，而非数据库。*

[![Python](https://img.shields.io/badge/python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/storage-SQLite%20WAL-lightgrey?logo=sqlite)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-44%20passing-brightgreen)](#测试)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Iterations](https://img.shields.io/badge/iterations-374%2B-orange)](#路线图)

[English](./README.md) · [中文](./README.zh.md)

</div>

---

> **⚡ Claude Code 一键安装：**
> ```
> /install-plugin github:soolaugust/memory-os
> ```

---

## 问题

每次启动与 AI 助手的新对话，它都从零开始。所有决策、发现的坑、架构约束——全部消失。你重新解释背景，它重新学习相同的教训。如果同时运行多个 Agent，它们更无法共享彼此学到的知识。

这不是模型限制，而是**缺失的基础设施层**。

---

## 解决方案

Memory OS 将**操作系统内存管理哲学**应用于 AI 认知资源管理。让 Linux 用有限 RAM 处理数百万进程的同一套原理，现在赋予 AI Agent 持久化、可检索、多 Agent 共享的记忆。

| OS 概念 | Memory OS 对应 |
|---|---|
| RAM（运行时工作区） | Context window — AI 当前能看到的内容 |
| 磁盘（持久存储） | 知识库 — 跨 session 存活的事实 |
| 按需分页（Demand Paging） | 智能检索 — 按需获取相关记忆 |
| 进程调度 | 多 Agent 协调 — 多个 AI 共享一个知识图 |
| CRIU 检查点/恢复 | Session 快照 — 保存状态，无缝恢复 |
| kworker 线程池 | 异步提取池 — I/O 从关键路径卸载 |

---

## 工作原理

```
用户输入
  → 系统检索相关记忆 → 注入上下文
  → AI 基于完整上下文响应
  → Session 结束 → 决策/洞察自动提取 → 持久化到 store.db
  → 下次 Session 启动 → 工作集自动恢复
```

整个流水线运行在 **Claude Code hooks** 内，零手动记忆管理。

---

## 关键指标

| 指标 | 数值 |
|---|---|
| 检索延迟 P50（TLB 命中） | **~0.1 ms** |
| vs. 子进程基线 | **540× 更快**（54 ms → 0.1 ms） |
| Recall@3 提升（BM25 vs 基线） | **+147%** |
| MRR 提升 | **+320%** |
| A/B 答案质量提升 | **+68%**（3.55 vs 2.12） |
| 跨 Session 召回率 | **94.2%** |
| 知识库规模 | **427 chunks / 8 种类型** |
| 热路径检索 | **1.74 µs/op**（iter 258，−84.7% vs 基线） |
| 总迭代次数 | **374+** |
| **每次调用注入消耗** | **~44 tokens**（平均 178 字符） |
| **每次调用净 Token ROI** | **~+256 tokens**（注入消耗 44，节省用户复述 ~300） |
| FULL→LITE 降级节省（iter 361） | **~62 tokens/次重复注入**（节省 69.6%） |
| Session 去重排除（iter 359） | 注入 ≥2 次的 chunk 自动排除，零 token 开销 |
| Same-hash TLB 旁路 | 相同 prompt 零 token 开销（直接返回缓存） |

---

## 架构

```
Claude Code
    ↕  hooks（系统调用边界）
┌─────────────────────────────────────────┐
│  hooks/                                  │
│  ├── loader.py        (SessionStart)     │  工作集恢复 + CRIU 恢复
│  ├── retriever_wrapper.sh (UserPrompt)   │→ retriever_daemon.py（常驻进程）
│  ├── writer.py        (UserPrompt)       │  知识写入 + 任务状态
│  ├── extractor.py     (Stop)             │  知识提取 + CRIU dump
│  ├── extractor_pool.py                   │  异步 kworker 池（iter 260）
│  ├── output_compressor.py (PostToolUse)  │  zram — 大输出压缩提示
│  ├── tool_profiler.py     (PostToolUse)  │  eBPF 风格工具调用效率
│  └── parallel_hint.py    (UserPrompt)    │  CFS 并行任务检测
└─────────────────────────────────────────┘
    ↕  VFS 统一数据层
┌─────────────────────────────────────────┐
│  ~/.claude/memory-os/store.db            │
│  memory_chunks / swap_chunks             │
│  checkpoints / dmesg                     │
│  FTS5 全文索引（bigram CJK）             │
└─────────────────────────────────────────┘
    ↕  IPC（ipc_msgq）
┌─────────────────────────────────────────┐
│  net/agent_notify.py                     │  跨 Agent 知识广播
│  extractor_pool（kworker ×3）            │  异步提取 worker（iter 260）
└─────────────────────────────────────────┘
```

完整架构细节：[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)

---

## 设计哲学

每个子系统都对应一个 Linux 内核机制：

| 功能 | Linux 类比 | 迭代 |
|---|---|---|
| 知识检索注入 | 按需分页（缺页中断） | iter 1 |
| 工作集预加载 | Denning 工作集模型 | iter 18 |
| 知识淘汰 | kswapd + OOM Killer | iter 25, 38 |
| Session 恢复 | CRIU 检查点/恢复 | iter 49 |
| 拥塞控制 | TCP AIMD + 自动调优 | iter 50, 51 |
| 多代 LRU | MGLRU（Linux 6.x） | iter 44 |
| 访问模式监控 | DAMON | iter 42 |
| 输出压缩提示 | zram | iter 110 |
| 常驻检索守护进程 | vDSO + Unix socket | iter 162 |
| 两级 TLB 缓存 | CPU TLB L1/L2 | iter 179 |
| FTS 结果缓存 | Page Cache | iter 205 |
| 多 Agent 隔离 | Linux namespace（PID/mount） | iter 259 |
| 异步提取池 | kworker 线程池 + pdflush | iter 260 |
| FTS5 自动优化 | ext4 在线碎片整理 | iter 360 |
| FULL→LITE 注入降级 | page cache dirty bit 快路径 | iter 361 |
| 主动 swap 预热 | MGLRU 主动回收 | iter 362 |
| 工作区感知记忆 | exec() 地址空间切换 | iter 363 |
| 情节时间线 | 海马顺序重放 | iter 364 |
| 工作区前瞻记忆 | 前额叶前瞻代码 | iter 365 |
| 知识图谱扩散激活 | CPU 缓存预取 L2 预热 | iter 366 |
| 时序邻近边 | 顺序预读 | iter 367 |
| 注意焦点栈 | CPU 寄存器文件 | iter 368 |
| 软遗忘 | DAMON 冷页检测 | iter 369 |
| 不确定性信号提取 | MMU 软缺页异常 | iter 370 |

---

## 已解决的问题

<details>
<summary><strong>无跨 Session 记忆 — 每次从零开始</strong></summary>

每次新对话都会丢失所有之前的决策、踩过的坑和架构约束。大量"热身"时间浪费在重建上下文上。

**解决方案：** Session 结束时自动提取知识（决策、推理链、设计约束、量化证据）→ 写入 `store.db` → 下次 Session 启动时检索并注入上下文。

```
Recall@3: +147% | MRR: +320% | A/B 质量: +68% | Session 召回率: 94.2%
```
</details>

<details>
<summary><strong>检索延迟高 — 每次提示都有明显卡顿</strong></summary>

早期基于子进程的检索：P50 约 54 ms，每次击键都有可见卡顿。

**解决方案：** 常驻 `retriever_daemon.py` 通过 Unix socket + 三级缓存（FTS5 结果缓存 + 两级 TLB）。

```
P50: 54 ms → 0.1 ms（540× 改善）
```
</details>

<details>
<summary><strong>Context window 满了，强制压缩后推理链丢失</strong></summary>

**解决方案：** 多层压缩 — zram 风格输出压缩提示（`output_compressor.py`）+ Context Pressure Governor（四水位级别）+ 低频 chunk 换出到 swap。
</details>

<details>
<summary><strong>Session 中断后丢失"我在做什么"</strong></summary>

**解决方案：** CRIU 风格 Session 检查点 — Stop 时从最后一条 assistant 消息提取未完成意图，持久化到 `session_intents` DB，下次 SessionStart 时自动注入（24h TTL）。
</details>

<details>
<summary><strong>架构约束散落在历史中，容易被违反</strong></summary>

**解决方案：** 自动检测约束模式（22 种模式）→ `design_constraint` 类型，`importance=0.95`，`oom_adj=-800`（最高保护，永不淘汰）→ 每次 UserPromptSubmit 自动注入。

```
21 条活跃设计约束，最高频约束被检索 ×2043 次
```
</details>

<details>
<summary><strong>多 Agent 互相覆盖记忆（iter 259）</strong></summary>

并发 Session 导致共享文件的 last-writer-wins 竞争条件。

**解决方案：** per-session `shadow_traces` 和 `session_intents` 表（PRIMARY KEY = `session_id`），per-session 命名文件（`.shadow_trace.{sid[:16]}.json`）。通过 20 个测试验证。
</details>

<details>
<summary><strong>Stop hook 阻塞在 I/O 密集的 transcript 解析上（iter 260）</strong></summary>

`extractor.py` 在 Stop hook 同步路径上花费 50–150 ms 读取和解析 transcript 文件。

**解决方案：** `submit_extract_task()` 入队到 `ipc_msgq`（<5 ms）→ `extractor_pool.py` 常驻守护进程在 `ThreadPoolExecutor(3)` 中处理。pool 未运行时优雅降级。

```
Stop hook: 50–150 ms（同步）→ <5 ms（异步队列）
```
</details>

<details>
<summary><strong>重复注入浪费 token — 长 session 中全量上下文每次都附加（iter 359, 361）</strong></summary>

没有去重机制时，同一个 chunk 在长 session 中每次都附加完整的 `raw_snippet`，而这段内容已经在 LLM 工作记忆中，重复注入的边际价值为零。

**解决方案：三层 token 预算执行**

- **FULL→LITE 降级（iter 361）：** 在本 session 已以完整格式（summary + raw_snippet）注入过的 chunk，后续注入自动降级为 LITE（仅 summary）——LLM 已见过原文，重复附加无意义。
- **Session 去重（iter 359）：** 注入次数 ≥ `session_dedup_threshold`（默认 2）次的 chunk 完全排除在上下文外。
- **Same-hash TLB 旁路：** 完全相同的 prompt hash 直接返回缓存结果，零 DB 查询，零新 token。

**量化数据（`tests/test_token_budget.py` 验证）：**
```
每次注入消耗：  ~44 tokens（平均 178 字符）
FULL→LITE 节省：~62 tokens/次重复注入（节省 69.6%）
节省用户复述：  ~300 tokens/次（无需重新交代背景）
净 Token ROI：  ~+256 tokens/次调用
上下文硬上限：  ≤ 800 字符（max_context_chars sysctl 可调）
```
</details>

---

## 路线图

| 阶段 | 状态 |
|---|---|
| 基础内存管理 — 持久化、淘汰、优先级（iter 1–100） | ✅ 完成 |
| 常驻检索守护进程 + 多级缓存（iter 162–205） | ✅ 完成 |
| 数据驱动精调 — 258 次迭代，−84.7% 延迟（iter 235–258） | ✅ 完成 |
| 多 Agent 隔离 — per-session 命名空间，IPC 广播（iter 259） | ✅ 完成 |
| 异步提取池 — Stop hook 卸载，kworker 池（iter 260） | ✅ 完成 |
| Token 预算优化 — FULL→LITE 降级、Session 去重、swap 预热（iter 359–362） | ✅ 完成 |
| 工作区感知记忆 — exec() 地址空间切换，文件系统扫描（iter 363） | ✅ 完成 |
| 认知记忆系统 — 情节记忆、工作区待办、知识图谱扩散激活（iter 364–366） | ✅ 完成 |
| 时序邻近、注意焦点、软遗忘、不确定性信号（iter 367–370） | ✅ 完成 |
| 冲突检测、上下文感知增强、时间线、碎片合并（iter 371–374） | ✅ 完成 |
| 分布式多 Agent 共享内存 — NUMA/RDMA 类比（iter 375+） | 🔜 计划中 |

---

## 快速开始

### 前置条件

- Python 3.12+
- SQLite（内置）
- `nc`（netcat）和 `flock`
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)

### 安装

```bash
# 1. 克隆
git clone https://github.com/your-org/memory-os ~/codes/aios/memory-os
cd ~/codes/aios/memory-os

# 2. 创建数据目录（schema 首次运行时自动创建）
mkdir -p ~/.claude/memory-os

# 3. 将 hooks 配置添加到 ~/.claude/settings.json（见下方）
```

**`~/.claude/settings.json`：**

```json
{
  "hooks": {
    "SessionStart": [
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/loader.py", "timeout": 10 }
    ],
    "UserPromptSubmit": [
      { "type": "command", "command": "bash /path/to/memory-os/hooks/retriever_wrapper.sh", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/writer.py", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/parallel_hint.py", "timeout": 3, "async": false }
    ],
    "PostToolUse": [
      { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "python3 /path/to/memory-os/hooks/output_compressor.py", "timeout": 5 }] },
      { "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/memory-os/hooks/tool_profiler.py", "timeout": 5, "async": true }] }
    ],
    "Stop": [
      { "type": "command", "command": "python3 /path/to/memory-os/hooks/extractor.py", "timeout": 10, "async": true }
    ]
  }
}
```

### 验证

```bash
# 测试 SessionStart hook
echo '{"session_id":"test","transcript_path":"/dev/null","cwd":"'$(pwd)'"}' \
  | python3 hooks/loader.py

# 测试检索守护进程（自动启动）
echo '{"session_id":"test","prompt":"test query","cwd":"'$(pwd)'"}' \
  | bash hooks/retriever_wrapper.sh

# 确认守护进程运行中
ls /tmp/memory-os-retriever.sock && echo "daemon running"

# 运行测试
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

### 守护进程管理

```bash
# 检索守护进程：首次请求时自动启动
tail -f ~/.claude/memory-os/daemon.log        # 日志
pkill -f retriever_daemon.py                  # 重启（下次调用时自动重启）

# 提取池（iter 260 异步提取）
bash hooks/extractor_pool_wrapper.sh start
bash hooks/extractor_pool_wrapper.sh status
bash hooks/extractor_pool_wrapper.sh stop
```

---

## 测试

```bash
# 多 Agent 隔离（A1–A20）
python3 -m pytest tests/test_agent_team.py -v

# 混沌 / 容错测试
python3 -m pytest tests/test_chaos.py -v

# 全部稳定测试
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

测试覆盖：per-session DB 隔离、并发写安全、跨 Agent IPC 投递、提取池队列语义、CRIU 检查点验证、目标进度幂等性。

---

## 依赖

无 GPU，无外部 API，全部本地运行。

| 依赖 | 用途 |
|---|---|
| Python 3.12+ | 核心运行时 |
| SQLite（内置） | 主存储 + FTS5 全文索引 |
| `nc`（netcat） | 与检索守护进程的 Unix socket 通信 |
| `flock` | 单实例守护进程启动锁 |

---

## 贡献

每个子系统都通过干净的 VFS 接口隔离 — hooks 调用 `store.py` / `store_vfs.py` / `store_criu.py` — 使各组件可独立测试。

```bash
# 提交 PR 前
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

---

<div align="center">

基于这一理念：*如果操作系统解决了它，我们可以借鉴相同的原理。*

**[English](./README.md) · [中文](./README.zh.md)**

</div>
