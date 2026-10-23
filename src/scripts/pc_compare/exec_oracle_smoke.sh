#!/usr/bin/env bash
# V2 production-exec paired oracle PR2 smoke (plan §9.2).
#
# Boots one real VM via syz-manager against the kernel/image used by V1
# oracle. syz-manager runs `executor_bin_on_target=
# /usr/local/bin/syz-executor-proxied`, which spawns our in-VM proxy and
# delegates to the real syz-executor. qemu_args sets up a 9p mount of
# this run's trace dir so trace files land on the host in real time.
#
# After FUZZ_DURATION seconds we SIGINT syz-manager, wait for VM drain,
# then validate any trace files via syz_flatrpc_trace_dump.
#
# Prereqs (one-time): bash scripts/pc_compare/bake_exec_oracle_image.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # scripts/pc_compare/ → repo root
SYZKALLER_DIR="${SYZKALLER_DIR:-/workspace/syzkaller}"
SYZ_MANAGER_BIN="${SYZ_MANAGER_BIN:-${SYZKALLER_DIR}/bin/syz-manager}"
SYZ_FLATRPC_PROXY_BIN="${SYZ_FLATRPC_PROXY_BIN:-${ROOT_DIR}/build-llvm20/syz_flatrpc_proxy}"
SYZ_FLATRPC_TRACE_DUMP_BIN="${SYZ_FLATRPC_TRACE_DUMP_BIN:-${ROOT_DIR}/build-llvm20/syz_flatrpc_trace_dump}"

KERNEL_BZIMAGE="${KERNEL_BZIMAGE:-${SYZKALLER_DIR}/kernel/build-kasan/arch/x86/boot/bzImage}"
KERNEL_OBJ_DIR="${KERNEL_OBJ_DIR:-$(dirname "$(dirname "$(dirname "$(dirname "${KERNEL_BZIMAGE}")")")")}"
IMAGE_DIR="${IMAGE_DIR:-/workspace/images-test-linux5.14}"
IMAGE="${IMAGE:-${IMAGE_DIR}/bookworm-exec-oracle.img}"
SSH_KEY="${SSH_KEY:-${IMAGE_DIR}/bookworm.id_rsa}"

RUN_TS="${RUN_TS:-$(date +%s)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/run/exec-oracle-${RUN_TS}-$$}"
TRACE_HOST_DIR="${TRACE_HOST_DIR:-${RUN_DIR}/trace}"
if compgen -G "${TRACE_HOST_DIR}/exec_trace_*.bin" >/dev/null; then
    echo "exec_oracle_smoke: refusing stale trace files in ${TRACE_HOST_DIR}" >&2
    exit 1
fi
if [ -d "${RUN_DIR}/workdir" ] && \
   [ -n "$(find "${RUN_DIR}/workdir" -mindepth 1 -print -quit 2>/dev/null)" ]; then
    echo "exec_oracle_smoke: refusing non-empty workdir ${RUN_DIR}/workdir" >&2
    exit 1
fi
mkdir -p "${TRACE_HOST_DIR}" "${RUN_DIR}/workdir"

# §13.5 COV-B.6: force-collect-cover sentinel. The in-VM wrapper script
# (scripts/pc_compare/syz_executor_proxied_wrapper.sh) reads this file at proxy
# launch and exports REFUZZ_FORCE_COLLECT_COVER=1 to the proxy. Lives
# inside the 9p-mounted trace dir so a config change here doesn't need
# an image re-bake.
#
# Default ON for paired-oracle equivalence: without force-cover, only ~14%
# of requests carry CollectCover (syz-manager triage/signal jobs), biasing
# the jaccard sample toward high-cov-footprint programs. Force-cover ON
# pulls all requests into the comparison pool — required for any allowlist
# decision to rest on representative evidence. Unset/empty → ON; set to
# 0/false/off/no to explicitly disable (debug only).
SENTINEL="${TRACE_HOST_DIR}/.force_collect_cover"
case "${REFUZZ_FORCE_COLLECT_COVER:-1}" in
    "0"|"false"|"off"|"no")
        rm -f "$SENTINEL"
        ;;
    *)
        : > "$SENTINEL"
        ;;
esac

# Hard safety cap for the corpus-triage run. syz-manager normally exits on
# its own when CandidateTriageFinished() — this is the SIGKILL backstop in
# case the run wedges (e.g. VM hang, KCOV stuck). Sized generously: typical
# 733-seed triage finishes in ~5-10 min on a single VM/CPU=2 host.
TRIAGE_TIMEOUT_S="${TRIAGE_TIMEOUT_S:-1800}"
VM_COUNT="${VM_COUNT:-1}"
VM_CPU="${VM_CPU:-2}"
VM_MEM_MB="${VM_MEM_MB:-4096}"
# Number of syzkaller executor procs per VM. Default 1 matches the historical
# smoke shape (all reqs run on procid=0); set higher to capture a multi-proc
# trace so the paired-oracle replay path can exercise per-slot affinity.
# Replayer-side n_workers must be >= SYZ_PROCS or preflight rejects.
SYZ_PROCS="${SYZ_PROCS:-1}"

log() { echo "[$(date +%H:%M:%S)] smoke: $*" >&2; }

MANAGER_PID=""

cleanup_manager() {
    if [ -n "${MANAGER_PID}" ] && kill -0 "${MANAGER_PID}" 2>/dev/null; then
        log "terminating syz-manager pid=${MANAGER_PID} after script exit"
        kill -TERM "${MANAGER_PID}" 2>/dev/null || true
        sleep 1
        kill -KILL "${MANAGER_PID}" 2>/dev/null || true
        wait "${MANAGER_PID}" 2>/dev/null || true
    fi
}

trap cleanup_manager EXIT

preflight() {
    local missing=0
    local -a required=(
        "${SYZ_MANAGER_BIN}"
        "${SYZ_FLATRPC_PROXY_BIN}"
        "${SYZ_FLATRPC_TRACE_DUMP_BIN}"
        "${KERNEL_BZIMAGE}"
        "${IMAGE}"
        "${SSH_KEY}"
    )
    local f
    for f in "${required[@]}"; do
        if [ ! -e "$f" ]; then
            log "missing: $f"
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -gt 0 ]; then
        log "preflight FAILED (${missing} missing)"
        log "did you bake_exec_oracle_image.sh and build syz_flatrpc_proxy?"
        exit 1
    fi
    # .syzkaller-pin: ensures reproducible corpus + syscall set. syz-manager
    # bootstraps corpus from its own binary's enabled-syscall set; any drift
    # between repo pin and live syzkaller HEAD silently changes the input
    # distribution and breaks comparability between runs.
    local pin_file="${ROOT_DIR}/.syzkaller-pin"
    if [ ! -f "${pin_file}" ]; then
        log "preflight FAILED: ${pin_file} missing"
        exit 1
    fi
    local expected_sha actual_sha
    expected_sha=$(tr -d '[:space:]' < "${pin_file}")
    actual_sha=$(git -C "${SYZKALLER_DIR}" rev-parse HEAD 2>/dev/null || echo "")
    if [ "${expected_sha}" != "${actual_sha}" ]; then
        log "preflight FAILED: syzkaller pin mismatch"
        log "  ${pin_file}: ${expected_sha}"
        log "  ${SYZKALLER_DIR} HEAD: ${actual_sha}"
        log "either bump .syzkaller-pin or check out the pinned commit"
        exit 1
    fi
    log "preflight OK (syzkaller pin=${expected_sha:0:12})"
}

write_manager_config() {
    local cfg="${RUN_DIR}/syz-manager.cfg"
    # `executor_bin_on_target` skips host→VM copy of syz-executor; VM image
    # has been pre-baked with the wrapper. qemu_args adds a 9p fsdev/device
    # so /refuzz_trace_out in VM = ${TRACE_HOST_DIR} on host. mount tag
    # "refuzz_trace" must match REFUZZ_TRACE_MOUNT_TAG in the wrapper.
    cat > "$cfg" <<EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:0",
    "rpc": "127.0.0.1:0",
    "workdir": "${RUN_DIR}/workdir",
    "syzkaller": "${SYZKALLER_DIR}",
    "kernel_obj": "${KERNEL_OBJ_DIR}",
    "image": "${IMAGE}",
    "sshkey": "${SSH_KEY}",
    "sandbox": "none",
    "procs": ${SYZ_PROCS},
    "cover": true,
    "executor_bin_on_target": "/usr/local/bin/syz-executor-proxied",
    "type": "qemu",
    "vm": {
        "count": ${VM_COUNT},
        "kernel": "${KERNEL_BZIMAGE}",
        "cpu": ${VM_CPU},
        "mem": ${VM_MEM_MB},
        "snapshot": true,
        "qemu_args": "-enable-kvm -cpu host,migratable=off -fsdev local,id=refuzztrace,path=${TRACE_HOST_DIR},security_model=mapped-xattr -device virtio-9p-pci,fsdev=refuzztrace,mount_tag=refuzz_trace"
    }
}
EOF
    echo "$cfg"
}

run_session() {
    local cfg="$1"
    # -mode corpus-triage: syz-manager loads corpus, triages every candidate
    # exactly once, then exits on its own when CandidateTriageFinished()
    # (see syzkaller manager.go:1317). No mutate / smash / hint / generation
    # noise — input set is deterministic (.syzkaller-pin locks corpus seed
    # set), so two runs of this script produce comparable evidence.
    log "starting syz-manager (cfg=${cfg}, mode=corpus-triage, safety_cap=${TRIAGE_TIMEOUT_S}s)..."
    "${SYZ_MANAGER_BIN}" -config "$cfg" -mode corpus-triage \
        >"${RUN_DIR}/syz-manager.log" 2>&1 &
    MANAGER_PID=$!
    log "syz-manager pid=${MANAGER_PID}; waiting for natural exit (corpus drain)..."
    local waited=0
    local poll_interval=1
    local timed_out=0
    while kill -0 "${MANAGER_PID}" 2>/dev/null; do
        if [ "$waited" -ge "$TRIAGE_TIMEOUT_S" ]; then
            log "TRIAGE_TIMEOUT_S (${TRIAGE_TIMEOUT_S}s) exceeded — corpus-triage wedged?"
            log "  last 20 lines of syz-manager.log:"
            tail -n 20 "${RUN_DIR}/syz-manager.log" >&2 || true
            log "SIGTERM then SIGKILL"
            kill -TERM "${MANAGER_PID}" 2>/dev/null || true
            local grace=0
            while kill -0 "${MANAGER_PID}" 2>/dev/null && [ "${grace}" -lt 5 ]; do
                sleep 1
                grace=$((grace + 1))
            done
            kill -KILL "${MANAGER_PID}" 2>/dev/null || true
            timed_out=1
            break
        fi
        sleep "${poll_interval}"
        waited=$((waited + poll_interval))
    done
    local manager_status=0
    if wait "${MANAGER_PID}"; then
        manager_status=0
    else
        manager_status=$?
    fi
    MANAGER_PID=""
    if [ "${timed_out}" -eq 1 ]; then
        log "syz-manager timed out after ${waited}s"
        return 124
    fi
    if [ "${manager_status}" -ne 0 ]; then
        log "syz-manager exited non-zero: ${manager_status}"
        tail -n 20 "${RUN_DIR}/syz-manager.log" >&2 || true
        return "${manager_status}"
    fi
    log "syz-manager exited successfully (after ${waited}s)"
}

validate_trace() {
    local found=0 valid=0 invalid=0
    log "scanning ${TRACE_HOST_DIR} for trace files..."
    shopt -s nullglob
    for t in "${TRACE_HOST_DIR}"/exec_trace_*.bin; do
        found=$((found + 1))
        local sz
        sz=$(stat -c%s "$t" 2>/dev/null || echo 0)
        log "  trace: $(basename "$t") size=${sz}"
        if [ "$sz" -le 64 ]; then
            log "    WARN header-only; proxy probably never received frames"
            invalid=$((invalid + 1))
            continue
        fi
        local dump_out="${t}.dump.jsonl"
        # -allow-truncated-tail: the TRIAGE_TIMEOUT_S safety-cap SIGKILLs a
        # wedged manager rather than waiting for a natural corpus-drain exit,
        # so the final in-flight record can be mid-write when the 9p-mounted
        # proxy is torn down. The replayer's own trace reader already
        # tolerates this (on_truncated_tail); asking here for a hard EOF
        # failure would reject an otherwise-good capture for no reason.
        if ! "${SYZ_FLATRPC_TRACE_DUMP_BIN}" -f "$t" -json -allow-truncated-tail \
                >"${dump_out}" 2>"${t}.dump.err"; then
            log "    FAIL dump errored; see ${t}.dump.err"
            invalid=$((invalid + 1))
            continue
        fi
        local rec_count
        rec_count=$(wc -l < "${dump_out}")
        log "    records: ${rec_count}"
        if [ "$rec_count" -lt 4 ]; then
            log "    WARN <4 records (header/open/frame/close expected)"
            invalid=$((invalid + 1))
            continue
        fi
        valid=$((valid + 1))
    done
    shopt -u nullglob
    if [ "$found" -eq 0 ]; then
        log "no trace files produced — check ${RUN_DIR}/syz-manager.log and"
        log "VM serial output; verify 9p mount tag and that the wrapper script ran"
        exit 2
    fi
    log "trace files: found=${found} valid=${valid} invalid=${invalid}"
    if [ "$valid" -eq 0 ]; then
        log "no valid traces — see *.dump.err for details"
        exit 3
    fi
    if [ "$invalid" -ne 0 ]; then
        log "capture contains invalid or incomplete trace sessions"
        exit 3
    fi
    log "OK; run dir = ${RUN_DIR}"
}

main() {
    preflight
    local cfg
    cfg=$(write_manager_config)
    local manager_status=0
    run_session "${cfg}" && manager_status=0 || manager_status=$?
    if [ "${manager_status}" -ne 0 ]; then
        log "capture FAILED before trace validation (status=${manager_status})"
        exit "${manager_status}"
    fi
    validate_trace
    log "done"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
