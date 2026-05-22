# Setup — manual installation and Claude Code hook configuration

> If you're using Claude Code, the one-line install is the easiest path:
> `/install-plugin github:soolaugust/0CompactMem`. This page is for everyone
> else — manual installs, custom paths, hook configuration, and
> daemon-management.

## Prerequisites

- Python 3.12+
- SQLite (built into Python)
- `nc` (netcat) and `flock`
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (if integrating with Claude Code)

## Manual install

```bash
# 1. Clone
git clone https://github.com/soolaugust/0CompactMem ~/codes/0CompactMem
cd ~/codes/0CompactMem

# 2. Install Python package (editable)
pip install -e .

# 3. Create the data directory (schema is auto-created on first run)
mkdir -p ~/.claude/memory-os
```

## Claude Code hook configuration

Add the following to `~/.claude/settings.json`. Replace
`/path/to/0CompactMem` with the absolute path of your clone.

```json
{
  "hooks": {
    "SessionStart": [
      { "type": "command", "command": "python3 /path/to/0CompactMem/hooks/loader.py", "timeout": 10 }
    ],
    "UserPromptSubmit": [
      { "type": "command", "command": "bash /path/to/0CompactMem/hooks/retriever_wrapper.sh", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/0CompactMem/hooks/writer.py", "timeout": 10, "async": false },
      { "type": "command", "command": "python3 /path/to/0CompactMem/hooks/parallel_hint.py", "timeout": 3, "async": false }
    ],
    "PostToolUse": [
      { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "python3 /path/to/0CompactMem/hooks/output_compressor.py", "timeout": 5 }] },
      { "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /path/to/0CompactMem/hooks/tool_profiler.py", "timeout": 5, "async": true }] }
    ],
    "Stop": [
      { "type": "command", "command": "python3 /path/to/0CompactMem/hooks/extractor.py", "timeout": 10, "async": true }
    ]
  }
}
```

## Verify

```bash
# SessionStart hook
echo '{"session_id":"test","transcript_path":"/dev/null","cwd":"'$(pwd)'"}' \
  | python3 hooks/loader.py

# Retriever (the daemon starts on first request)
echo '{"session_id":"test","prompt":"test query","cwd":"'$(pwd)'"}' \
  | bash hooks/retriever_wrapper.sh

# Daemon socket should now exist
ls /tmp/memory-os-retriever.sock && echo "daemon running"

# Run the stable test subset
python3 -m pytest tests/test_agent_team.py tests/test_chaos.py -q
```

## Daemon management

```bash
# Retriever daemon (auto-starts on first request)
tail -f ~/.claude/memory-os/daemon.log     # logs
pkill -f retriever_daemon.py               # restart (auto-restarts on next call)

# Extractor pool (async extraction, iter 260)
bash hooks/extractor_pool_wrapper.sh start
bash hooks/extractor_pool_wrapper.sh status
bash hooks/extractor_pool_wrapper.sh stop
```

## Troubleshooting

- **Daemon socket not appearing.** Make sure `nc` and `flock` are on `$PATH`,
  and that `/tmp` is writable. The daemon log
  (`~/.claude/memory-os/daemon.log`) is the first thing to check.
- **Hooks not firing.** Confirm `~/.claude/settings.json` is valid JSON
  (`python3 -c 'import json,sys; json.load(open(sys.argv[1]))' ~/.claude/settings.json`)
  and that the absolute paths resolve.
- **Schema errors after upgrade.** The schema is forward-only and migrates
  itself on startup. If you see complaints about missing columns, delete
  `~/.claude/memory-os/store.db` and let it re-create — your in-flight
  knowledge will be re-extracted at the next `Stop`.
