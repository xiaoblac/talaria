#!/usr/bin/env bash
# monitor_cov.sh — 定时把覆盖率实验容器的进度快照追加到日志文件。
#
# 两种用法：
#   1) 后台常驻（推荐，不依赖 cron）：
#        nohup ./monitor_cov.sh --interval 1200 --log ~/chengyongkang/cov-monitor.log \
#              >/dev/null 2>&1 &
#   2) cron 每 20 分钟跑一次（--once 模式）：
#        */20 * * * * ~/chengyongkang/monitor_cov.sh --once --log ~/chengyongkang/cov-monitor.log
#
# 查看：tail -n 40 ~/chengyongkang/cov-monitor.log
# 停止常驻：pkill -f monitor_cov.sh
#
# 输出内容（每条快照）：
#   host: CPU / load / CPU pressure / 内存 / 磁盘
#   docker stats: 每个 cov-* 容器的 CPU% / 内存 / PIDs
#   每个 cov-* 容器: reFuzz | Syzkaller
set -uo pipefail

INTERVAL=1200          # 秒；1200 = 20 分钟
LOG="${HOME:-.}/cov-monitor.log"
FILTER='^(cov|rfz)-'
ONCE=0

usage() {
    sed -n '2,12p' "$0"
    echo
    echo "选项:"
    echo "  --interval N   快照间隔秒数（默认 1200，仅常驻模式生效）"
    echo "  --log FILE     日志文件（默认 \$HOME/cov-monitor.log）"
    echo "  --filter REGEX 容器名过滤（默认 ^(cov|rfz)-）"
    echo "  --once         只打一条快照就退出（给 cron 用）"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interval) INTERVAL="$2"; shift 2 ;;
        --log)      LOG="$2";      shift 2 ;;
        --filter)   FILTER="$2";   shift 2 ;;
        --once)     ONCE=1;        shift ;;
        -h|--help)  usage ;;
        *) echo "未知参数: $1" >&2; usage ;;
    esac
done

read_cpu_counters() {
    awk '/^cpu / {
        for (i = 2; i <= 11; ++i) {
            printf "%s%d", (i == 2 ? "" : " "), $i + 0
        }
        print ""
        exit
    }' /proc/stat
}

sample_host_cpu() {
    local before after
    before=$(read_cpu_counters)
    sleep 1
    after=$(read_cpu_counters)

    awk -v before="$before" -v after="$after" 'BEGIN {
        split(before, b, " ")
        split(after, a, " ")
        for (i = 1; i <= 10; ++i) {
            d[i] = a[i] - b[i]
            if (d[i] < 0) d[i] = 0
        }

        # /proc/stat user/nice already include guest/guest_nice. Subtract them
        # before reporting host userspace so us+sy+id+wa+st+gu is additive.
        total = d[1] + d[2] + d[3] + d[4] + d[5] + d[6] + d[7] + d[8]
        if (total <= 0) {
            print "unavailable"
            exit
        }
        guest = d[9] + d[10]
        user = d[1] + d[2] - guest
        if (user < 0) user = 0
        sys_cpu = d[3] + d[6] + d[7]

        printf "us=%.1f%% sy=%.1f%% id=%.1f%% wa=%.1f%% st=%.1f%% gu=%.1f%%", \
            user * 100 / total, sys_cpu * 100 / total, d[4] * 100 / total, \
            d[5] * 100 / total, d[8] * 100 / total, guest * 100 / total
    }'
}

snapshot() {
    local host_cpu cpu_count load_line cpu_pressure container_stats container_ids
    host_cpu=$(sample_host_cpu 2>/dev/null) || host_cpu="unavailable"
    cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)
    load_line=$(awk '{
        split($4, tasks, "/")
        printf "load=%s/%s/%s runnable=%s tasks=%s", \
            $1, $2, $3, tasks[1], tasks[2]
    }' /proc/loadavg)
    if [[ -r /proc/pressure/cpu ]]; then
        cpu_pressure=$(awk '{
            printf "%s%s", (NR == 1 ? "" : " | "), $0
        } END { print "" }' /proc/pressure/cpu)
    else
        cpu_pressure="unavailable"
    fi
    container_stats=$(docker stats --no-stream \
        --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}' \
        2>/dev/null || true)
    container_ids=$(docker ps -q --filter "name=$FILTER" 2>/dev/null || true)

    {
        echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="

        echo "--- host ---"
        echo "  cpu: cpus=$cpu_count $host_cpu $load_line"
        echo "  cpu-pressure: $cpu_pressure"
        echo "  mem: $(free -g | awk 'NR==2{print $3"/"$2"G used, "$7"G avail"}')"
        echo "  disk: $(df -h "${HOME:-/}" 2>/dev/null | awk 'NR==2{print $4" avail ("$5")"}')"

        echo "--- docker stats ---"
        if [[ -z "$container_ids" ]]; then
            echo "  (没有匹配 $FILTER 的运行中容器)"
        fi
        for cid in $container_ids; do
            name=$(docker inspect -f '{{.Name}}' "$cid" | sed 's#^/##')
            stats=$(awk -F '\t' -v wanted="$name" '
                $1 == wanted {
                    printf "cpu=%s memory=%s pids=%s", $2, $3, $4
                    exit
                }
            ' <<< "$container_stats")
            [[ -n "$stats" ]] || stats="cpu=NA memory=NA pids=NA"
            printf '  %-18s %s\n' "$name" "$stats"
        done

        for cid in $container_ids; do
            name=$(docker inspect -f '{{.Name}}' "$cid" | sed 's#^/##')
            line=$(docker exec "$name" sh -c '
                EV=$(ls -d /tmp/rfz_*/work/run-*/logs/host_events.txt 2>/dev/null | head -1)
                SYZ=$(ls -d /results/*/D_syz_run_01/syz-manager.log 2>/dev/null | head -1)
                out=""
                if [ -n "$EV" ]; then
                    life=$(grep -ao "lifecycle=[a-z]*" "$EV" | tail -1)
                    wk=$(grep -ao "workers=[0-9/]*" "$EV" | tail -1)
                    reb=$(grep -ac "evt=recovery_completed" "$EV")
                    cpc=$(grep -ao "Corpus PC total=[0-9]*" "$EV" | tail -1)
                    edge=$(grep -ao "Corpus Edge total=[0-9]*" "$EV" | tail -1)
                    # program/s 与 syscall/s：全程平均 —— 第一条到最后一
                    # 条 runtime_panel 的 completion/exec_calls 累计差值，
                    # 除以中间经过的 wall_us。避免 5s 窗口抖动。
                    FIRST=$(grep -a "evt=runtime_panel" "$EV" | head -1)
                    LAST=$(grep -a "evt=runtime_panel" "$EV" | tail -1)
                    fw=$(echo "$FIRST" | grep -ao "wall_us=[0-9]*" | head -1 | cut -d= -f2)
                    fc=$(echo "$FIRST" | grep -ao "completion=[0-9]*" | head -1 | cut -d= -f2)
                    fe=$(echo "$FIRST" | grep -ao "exec_calls=[0-9]*" | head -1 | cut -d= -f2)
                    lw=$(echo "$LAST" | grep -ao "wall_us=[0-9]*" | head -1 | cut -d= -f2)
                    lc=$(echo "$LAST" | grep -ao "completion=[0-9]*" | head -1 | cut -d= -f2)
                    le=$(echo "$LAST" | grep -ao "exec_calls=[0-9]*" | head -1 | cut -d= -f2)
                    prog="prog/s=NA"; sys="sys/s=NA"
                    if [ -n "$lw" ] && [ -n "$fw" ] && [ -n "$lc" ] && [ -n "$fc" ]; then
                        dt=$(( lw - fw ))
                        if [ "$dt" -gt 0 ] && [ "$lc" -ge "$fc" ]; then
                            # 乘 10 保留一位小数：155 个/5s = 31.0
                            pi=$(( (lc - fc) * 10 * 1000000 / dt ))
                            si=$(( (le - fe) * 10 * 1000000 / dt ))
                            prog="prog/s=$((pi/10)).$((pi%10))"
                            sys="sys/s=$((si/10)).$((si%10))"
                        fi
                    fi
                    out="rfz: $life $wk reboots=$reb $prog $sys $cpc $edge"
                fi
                if [ -n "$SYZ" ]; then
                    last=$(grep -a "candidates=" "$SYZ" | tail -1)
                    cov=$(echo "$last" | grep -ao "coverage=[0-9]*" | head -1)
                    # syz signal（corpus edge）不在 manager.log，在 -bench 文件里：
                    # syz-manager 每 60s 写一条 JSON（含 "signal"/"coverage"）。
                    BENCH=$(echo "$SYZ" | sed "s#syz-manager.log#syz_bench.txt#")
                    sig=$(grep -ao "\"signal\": [0-9]*" "$BENCH" 2>/dev/null | tail -1 | grep -ao "[0-9]*")
                    # syz 用自己的直观速率（manager.log 里已算好，快时
                    # (N/sec)、慢时 (N/min)），原样显示，不再换算。
                    # exec calls total = 执行的 syscall 数；exec total = 执行的
                    # program 数（两个字段都可能是 /sec 或 /min）。
                    rate=$(echo "$last" | grep -ao "exec calls total=[0-9]* ([0-9]*/\(sec\|min\))" | head -1)
                    prate=$(echo "$last" | grep -ao "exec total=[0-9]* ([0-9]*/\(sec\|min\))" | head -1)
                    cr=$(grep -ac "crash:" "$SYZ")
                    out="$out | syz: $cov signal=$sig $rate $prate crashes=$cr"
                fi
                echo "$out"
            ' 2>/dev/null) || line="(docker exec 失败，容器可能正在重启)"
            printf '  %-18s %s\n' "$name" "$line"
        done
    } >> "$LOG"
}

mkdir -p "$(dirname "$LOG")" || exit 1
touch "$LOG" || exit 1
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || {
    echo "monitor_cov: --interval 必须是正整数: $INTERVAL" >&2
    exit 2
}

if [[ "$ONCE" == "1" ]]; then
    snapshot
    exit 0
fi

echo "monitor_cov: 常驻模式，每 ${INTERVAL}s 一条快照 → $LOG (PID $$)"
while true; do
    snapshot
    sleep "$INTERVAL"
done
