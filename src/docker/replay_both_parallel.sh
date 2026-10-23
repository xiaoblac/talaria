#!/usr/bin/env bash
# replay_both_parallel.sh — 容器内运行：把 perf_sampling.sh 复制一份并做最小并行化
# 补丁（不动本地/镜像内原始脚本），然后以 replay-both 模式执行：
#   syzkaller 与 reFuzz 两个 VM 并行重放同一条 stream。
#
# 补丁只做三件事：
#   1. find_guest_port 支持按进程树过滤（syz job 只认 syz-manager 后代 QEMU，
#      rfz job 只认 refuzz 后代 QEMU），解决并行时两个 VM 端口互相拿错；
#   2. wait_guest_ssh / 两个 replay 的 fetch 都用各自的 watch pid 定位端口；
#   3. replay-both 主流程把 replay_syz 与 replay_rfz 改为后台并行 + wait。
set -euo pipefail

SRC="${SRC:-/opt/perf/scripts/perf_compare/perf_sampling.sh}"
OUT="${OUT:-/opt/perf/scripts/perf_compare/perf_sampling_parallel.sh}"

[ -f "${SRC}" ] || { echo "replay_both_parallel: missing ${SRC}" >&2; exit 1; }

python3 - "${SRC}" "${OUT}" <<'PY'
import sys

src, out = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()

def rep(old, new, label):
    global s
    if old not in s:
        raise SystemExit(f"PATCH-ANCHOR-MISSING: {label}")
    s = s.replace(old, new, 1)

# 1. find_guest_port：可选 WATCH_PID，按父进程链过滤到指定 job 的 QEMU。
rep(
"""find_guest_port() {
    ps -eo args | grep -o 'hostfwd=tcp:[0-9.]*:\\?[0-9]*-:22' \\
        | grep -o '[0-9]*-:22' | grep -o '^[0-9]*' | head -1
}""",
"""find_guest_port() {
    local watch="${1:-}" pid ppid args port cur
    while read -r pid ppid args; do
        port=$(printf '%s' "${args}" | grep -o 'hostfwd=tcp:[0-9.]*:\\?[0-9]*-:22' \\
            | grep -o '[0-9]*-:22' | grep -o '^[0-9]*' | head -1)
        [ -n "${port}" ] || continue
        if [ -n "${watch}" ]; then
            cur="${pid}"
            while [ -n "${cur}" ] && [ "${cur}" != "0" ]; do
                [ "${cur}" = "${watch}" ] && { echo "${port}"; return 0; }
                cur=$(ps -o ppid= -p "${cur}" 2>/dev/null | tr -d ' ')
                [ "${cur}" = "${pid}" ] && break
            done
        else
            echo "${port}"; return 0
        fi
    done < <(ps -eo pid,ppid,args)
    return 1
}""",
"find_guest_port",
)

# 2a. wait_guest_ssh：探测端口时带上 watch pid。
rep(
"""        port=$(find_guest_port)
        if [ -n "${port}" ] && ssh_cmd "${port}" true 2>/dev/null; then""",
"""        port=$(find_guest_port "${watch}")
        if [ -n "${port}" ] && ssh_cmd "${port}" true 2>/dev/null; then""",
"wait_guest_ssh",
)

# 2b. replay_syz 的 fetch 端口按 syz-manager 进程树过滤。
rep(
"""    log "[syz-replay] stream drained; VM held -- stopping and fetching the guest probe"

    local fetch_port
    fetch_port=$(find_guest_port)""",
"""    log "[syz-replay] stream drained; VM held -- stopping and fetching the guest probe"

    local fetch_port
    fetch_port=$(find_guest_port "${syz_pid}")""",
"replay_syz fetch",
)

# 2c. replay_rfz 的 fetch 端口按 refuzz 进程树过滤。
rep(
"""    local fetch_port
    fetch_port=$(find_guest_port)
    [ -n "${fetch_port}" ] || fetch_port="${port}"
    [ "${fetch_port}" = "${port}" ] \\
        || log "WARN: [rfz] guest ssh port changed ${port} -> ${fetch_port} (VM restarted); using the live one\"""",
"""    local fetch_port
    fetch_port=$(find_guest_port "${rfz_pid}")
    [ -n "${fetch_port}" ] || fetch_port="${port}"
    [ "${fetch_port}" = "${port}" ] \\
        || log "WARN: [rfz] guest ssh port changed ${port} -> ${fetch_port} (VM restarted); using the live one\"""",
"replay_rfz fetch",
)

# 3. replay-both 主流程：syz 与 rfz 并行启动，两个 job 都完成后继续。
rep(
"""    if [ "${MODE}" = replay-both ]; then
        replay_syz "${RUN_DIR}/syz/request_stream.bin"
        local_syz_log="${RUN_DIR}/syz_replay/syz_perf_serial.log"
        local_syz_probe="${RUN_DIR}/syz_replay/probe"
    fi
    replay_rfz "${RUN_DIR}/syz/request_stream.bin\"""",
"""    if [ "${MODE}" = replay-both ]; then
        replay_syz "${RUN_DIR}/syz/request_stream.bin" &
        syz_job_pid=$!
        replay_rfz "${RUN_DIR}/syz/request_stream.bin" &
        rfz_job_pid=$!
        syz_job_rc=0 rfz_job_rc=0
        wait "${syz_job_pid}"; syz_job_rc=$?
        wait "${rfz_job_pid}"; rfz_job_rc=$?
        if [ "${syz_job_rc}" -ne 0 ]; then
            kill -TERM "${rfz_job_pid}" 2>/dev/null || true
            wait "${rfz_job_pid}" 2>/dev/null || true
            die "[replay-both] syz replay failed rc=${syz_job_rc}"
        fi
        if [ "${rfz_job_rc}" -ne 0 ]; then
            kill -TERM "${syz_job_pid}" 2>/dev/null || true
            wait "${syz_job_pid}" 2>/dev/null || true
            die "[replay-both] rfz replay failed rc=${rfz_job_rc}"
        fi
        local_syz_log="${RUN_DIR}/syz_replay/syz_perf_serial.log"
        local_syz_probe="${RUN_DIR}/syz_replay/probe"
    else
        replay_rfz "${RUN_DIR}/syz/request_stream.bin"
    fi""",
"replay-both parallel",
)

open(out, "w", encoding="utf-8").write(s)
print(f"patched {src} -> {out}")
PY

chmod +x "${OUT}"
exec bash "${OUT}" replay-both
