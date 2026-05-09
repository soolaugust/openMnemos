#!/usr/bin/env python3
"""
memory-os task_result_collector — PostToolUse(Agent) hook
iter1052: Agent 子任务结果持久化收集器

OS 类比: Linux wait4() + pdflush
  父进程 wait4() 等待子进程退出并收集退出状态；
  pdflush 把脏页刷回磁盘，确保数据持久化。
  本 hook 在每次 Agent tool 调用完成后：
    1. 把子 Agent 结果摘要写入 store.db（procedure chunk）
    2. 发送 task_handoff IPC 消息，通知其他 session 任务完成

设计约束:
  - PostToolUse hook，匹配 Agent tool
  - 不阻塞：异步执行（async: true）
  - 结果摘要截断至 500 chars（避免 chunk 过大）
  - 失败静默（不影响主流程）
  - 仅在并行任务场景下有意义，但对单 Agent 调用也安全

触发条件（避免噪音）:
  - tool_name == "Agent"
  - tool_response 非空且有实质内容
  - 输出长度 > 100 chars（过滤无效调用）
"""

import sys
import json
import re
from pathlib import Path
from datetime import datetime, timezone

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

MEMORY_OS_DIR = Path.home() / ".claude" / "memory-os"
STORE_DB = MEMORY_OS_DIR / "store.db"

_MAX_SUMMARY_LEN = 500    # 写入 store.db 的摘要最大长度
_MIN_OUTPUT_LEN  = 100    # 子 Agent 输出最小长度（过滤空调用）


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_response_text(tool_response) -> str:
    """从 PostToolUse tool_response 中提取纯文本。"""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        # Claude Code PostToolUse 格式: {"content": [...]} 或 {"output": "..."}
        content = tool_response.get("content", "")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    parts.append(item.get("text", "") or item.get("output", ""))
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        if isinstance(content, str):
            return content
        return tool_response.get("output", "") or tool_response.get("result", "")
    return ""


def _make_summary(text: str, task_desc: str) -> str:
    """
    从子 Agent 输出中提取摘要。
    优先提取最后几行（结论通常在末尾），截断至 _MAX_SUMMARY_LEN。
    """
    text = text.strip()
    if not text:
        return ""

    # 提取末尾 800 chars 作为候选（结论通常在末尾）
    tail = text[-800:] if len(text) > 800 else text

    # 清理 ANSI codes 和多余空白
    tail = re.sub(r'\x1b\[[0-9;]*m', '', tail)
    tail = re.sub(r'\n{3,}', '\n\n', tail).strip()

    summary = f"[子任务结果] {task_desc[:80]}\n{tail}"
    return summary[:_MAX_SUMMARY_LEN]


def _get_task_desc(tool_input: dict) -> str:
    """从 Agent tool input 提取任务描述。"""
    prompt = tool_input.get("prompt", "") or tool_input.get("description", "")
    return prompt[:100].strip() if prompt else "子任务"


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except Exception:
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Agent":
        sys.exit(0)

    tool_input    = hook_input.get("tool_input", {}) or {}
    tool_response = hook_input.get("tool_response", {})
    session_id    = hook_input.get("session_id", "")
    cwd           = hook_input.get("cwd", "")

    try:
        resp_text = _extract_response_text(tool_response)
        if len(resp_text) < _MIN_OUTPUT_LEN:
            sys.exit(0)  # 输出太短，无实质内容

        task_desc = _get_task_desc(tool_input)
        summary   = _make_summary(resp_text, task_desc)
        if not summary:
            sys.exit(0)

        # ── 写入 store.db ────────────────────────────────────────────
        from store_vfs import open_db, ensure_schema, insert_chunk, ipc_send
        from utils import resolve_project_id

        project_id = resolve_project_id(cwd or str(Path.cwd()))
        conn = open_db(STORE_DB)
        ensure_schema(conn)

        _ts = _now_iso()
        chunk = {
            "id":             f"agent_result_{session_id[:16]}_{int(datetime.now().timestamp())}",
            "project":        project_id,
            "chunk_type":     "procedure",
            "summary":        summary[:200],
            "content":        resp_text[:800],
            "importance":     0.70,
            "retrievability": 1.0,
            "last_accessed":  _ts,
            "lru_gen":        0,
            "stability":      0.6,
            "source_type":    "task_result_collector",
            "source_session": session_id,
            "created_at":     _ts,
            "updated_at":     _ts,
            "oom_adj":        0,
        }
        insert_chunk(conn, chunk)

        # ── 发送 IPC 通知：task_handoff ───────────────────────────────
        # 其他 session 的 loader.py 在 SessionStart 时会消费此消息
        ipc_send(conn, f"agent:{session_id[:16]}", "*", "task_handoff", {
            "task_desc":  task_desc,
            "project":    project_id,
            "session_id": session_id,
            "chunk_id":   chunk["id"],
            "summary":    summary[:200],
            "ts":         _now_iso(),
        })

        conn.commit()
        conn.close()

    except Exception:
        pass  # 永远不阻塞主流程

    sys.exit(0)


if __name__ == "__main__":
    main()
