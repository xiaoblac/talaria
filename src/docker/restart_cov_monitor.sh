#!/usr/bin/env bash
# Restart the coverage monitor as a single detached process.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MONITOR="$SCRIPT_DIR/monitor_cov.sh"
INTERVAL=1200
LOG="${HOME:-.}/chengyongkang/cov-monitor.log"

usage() {
    echo "用法: $0 [--interval 秒] [--log 文件]"
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interval) INTERVAL="$2"; shift 2 ;;
        --log)      LOG="$2";      shift 2 ;;
        *) usage ;;
    esac
done

[[ -x "$MONITOR" ]] || {
    echo "restart_cov_monitor: 找不到可执行监控脚本 $MONITOR" >&2
    exit 1
}
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || {
    echo "restart_cov_monitor: interval 必须是正整数: $INTERVAL" >&2
    exit 1
}

# The bracketed pattern matches monitor_cov.sh processes without matching
# pkill/pgrep's own command line.
pattern='[m]onitor_cov\.sh'
pkill -f "$pattern" 2>/dev/null || true

for _ in $(seq 1 50); do
    if ! pgrep -f "$pattern" >/dev/null; then
        break
    fi
    sleep 0.1
done

if pgrep -f "$pattern" >/dev/null; then
    echo "restart_cov_monitor: 旧监控进程未退出，拒绝启动重复实例:" >&2
    pgrep -af "$pattern" >&2 || true
    exit 1
fi

mkdir -p "$(dirname "$LOG")"
nohup "$MONITOR" --interval "$INTERVAL" --log "$LOG" >/dev/null 2>&1 &
monitor_pid=$!

# Catch argument/path/permission errors before returning success to the launcher.
sleep 1
if ! kill -0 "$monitor_pid" 2>/dev/null; then
    echo "restart_cov_monitor: 新监控启动失败，日志路径: $LOG" >&2
    exit 1
fi

echo "监控      restarted pid=$monitor_pid interval=${INTERVAL}s log=$LOG"
