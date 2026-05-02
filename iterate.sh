#!/usr/bin/env bash
# Memory-OS 持续迭代脚本
# 启动: nohup bash iterate.sh >> /tmp/memory-os-iterate.log 2>&1 &

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FEISHU_DOC="${FEISHU_DOC:?'请设置环境变量 FEISHU_DOC=<飞书文档ID>'}"
PROJECT_MD="${PROJECT_MD:-"$HOME/self-improving/projects/memory-os.md"}"
WORKSPACE="${WORKSPACE:-"$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"}"
MAX_ROUNDS=999999
FAIL_COUNT=0
MAX_FAILS=3

echo "========================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Memory-OS 持续迭代启动"
echo "========================================"

# ── iter260: 启动 extractor_pool 常驻进程 ────────────────────────────────────
# OS 类比：systemd service start — 确保后台 kworker pool 在迭代开始前就位
POOL_WRAPPER="${SCRIPT_DIR}/hooks/extractor_pool_wrapper.sh"
if [ -f "$POOL_WRAPPER" ]; then
    bash "$POOL_WRAPPER" ensure
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] extractor_pool: $(bash "$POOL_WRAPPER" status 2>&1 | head -1)"
fi

ROUND=0
while [ $ROUND -lt $MAX_ROUNDS ]; do
    ROUND=$((ROUND + 1))
    echo ""
    echo "========================================"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 迭代轮次 #${ROUND} 开始"
    echo "========================================"

    # 用 claude -p 执行一轮，--no-input 防止交互阻塞
    # 精简 prompt 避免超长
    if claude -p --dangerously-skip-permissions --model ppio/pa/claude-opus-4-6 \
        "Memory-OS迭代agent。工作目录:${WORKSPACE}。所有决策默认是，不停顿。

任务：从OS演化视角优化memory-os，实现→验证→写飞书。

步骤：
1. 读 ${PROJECT_MD} 看已完成迭代
2. 读 ${SCRIPT_DIR}/hooks/*.py 和 schema.py 了解代码
3. 选下一个OS演化方向（看待实现列表）
4. 实现并验证
5. feishu docx append ${FEISHU_DOC} 追加：标题/OS类比/问题/实现/验证
6. 更新 ${PROJECT_MD}
7. 打印摘要" 2>&1 | tail -80; then
        FAIL_COUNT=0
        echo ""
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 轮次 #${ROUND} 成功"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo ""
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 轮次 #${ROUND} 失败 (${FAIL_COUNT}/${MAX_FAILS})"
        if [ $FAIL_COUNT -ge $MAX_FAILS ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 连续失败 ${MAX_FAILS} 次，停止"
            break
        fi
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 休息 60 秒..."
    sleep 60
done

echo ""
echo "========================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 迭代结束，共 ${ROUND} 轮"
echo "========================================"
