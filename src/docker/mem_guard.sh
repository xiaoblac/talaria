#!/usr/bin/env bash
# mem_guard.sh — 内存水位守护：宿主已用内存 ≥ 阈值时，停止全部 cov-* 容器。
#
# 用法:
#   ./mem_guard.sh                          # 阈值 300G，每 30s 检查一次
#   ./mem_guard.sh --threshold 320 --interval 60 --log /tmp/mem.log
#   ./mem_guard.sh --once                   # 单次检查（适合 cron）
#
# 已用内存 = MemTotal - MemAvailable（/proc/meminfo），不含可回收 cache。
set -u

THRESHOLD_GB=300
INTERVAL_SEC=30
LOG="$HOME/chengyongkang/cov-mem-guard.log"
ONCE=0

usage() {
    echo "用法: $0 [--threshold GB] [--interval SEC] [--log FILE] [--once]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold) THRESHOLD_GB="$2"; shift 2 ;;
        --interval)  INTERVAL_SEC="$2"; shift 2 ;;
        --log)       LOG="$2"; shift 2 ;;
        --once)      ONCE=1; shift ;;
        *) usage ;;
    esac
done

die() { echo "mem_guard: $*" >&2; exit 1; }

command -v docker >/dev/null || die "没有 docker"
[[ "$THRESHOLD_GB" =~ ^[0-9]+$ ]] || die "--threshold 必须是整数 GB"
[[ "$INTERVAL_SEC" =~ ^[0-9]+$ ]] || die "--interval 必须是整数秒"
mkdir -p "$(dirname "$LOG")"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$LOG"; }

mem_used_gb() {
    local total avail
    total=$(awk '/MemTotal/{print int($2/1024/1024)}' /proc/meminfo)
    avail=$(awk '/MemAvailable/{print int($2/1024/1024)}' /proc/meminfo)
    echo $(( total - avail ))
}

cov_running() {
    docker ps -q --filter name=^cov- 2>/dev/null | wc -l
}

log "guard start threshold=${THRESHOLD_GB}G interval=${INTERVAL_SEC}s"

while true; do
    used=$(mem_used_gb)
    running=$(cov_running)

    if [[ "$running" -eq 0 ]]; then
        log "no cov containers running (used=${used}G), exit"
        exit 0
    fi

    if [[ "$used" -ge "$THRESHOLD_GB" ]]; then
        log "TRIGGER used=${used}G >= ${THRESHOLD_GB}G, stopping ${running} containers"
        docker stop $(docker ps -q --filter name=^cov-)
        log "STOPPED rc=$? remaining=$(cov_running)"
        exit 0
    fi

    [[ "$ONCE" -eq 1 ]] && exit 0
    sleep "$INTERVAL_SEC"
done
