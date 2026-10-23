#!/usr/bin/env bash
# Capture one six-proc Syzkaller corpus-triage lap, replay the exact requests
# through six reFuzz workers, and analyze only request identities observed by
# both guest timeline samplers.
#
# Common overrides:
#   RUN_DIR=...                    output directory
#   SKIP_CAPTURE=1 TRACE_DIR=... SYZ_PERF_LOG=...
#                                  reuse one fixed Syzkaller corpus/trace;
#                                  reFuzz still runs and writes fresh outputs
#   SYZ_CONFIG=...                 Syzkaller baseline config
#   REFUZZ_CONFIG=...              reFuzz baseline config
#   PACE=none|trace                replay pacing (default: none)
#   TRIAGE_TIMEOUT_S=...           capture safety cap

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build-llvm20}"
CAPTURE_SCRIPT="${CAPTURE_SCRIPT:-${ROOT_DIR}/scripts/pc_compare/exec_oracle_smoke.sh}"
REPLAYER_BIN="${REPLAYER_BIN:-${BUILD_DIR}/refuzz-exec-replayer}"
WORKER_BIN="${WORKER_BIN:-${BUILD_DIR}/executor/channel/worker/ivshmem_worker}"
SYZ_CONFIG="${SYZ_CONFIG:-${ROOT_DIR}/run/speed_compare/configs/syz_6proc.json}"
REFUZZ_CONFIG="${REFUZZ_CONFIG:-${ROOT_DIR}/run/speed_compare/configs/refuzz_mabB.json}"
SYZ_CAPTURE_IMAGE="${SYZ_CAPTURE_IMAGE:-${ROOT_DIR}/run/speed_compare/images/syz_exec_perf_rootfs.img}"
IMAGE_PREP_SCRIPT="${IMAGE_PREP_SCRIPT:-${ROOT_DIR}/scripts/perf_compare/prepare_syz_exec_perf_image.sh}"
ANALYZER="${ANALYZER:-${ROOT_DIR}/scripts/perf_compare/paired_exec_analyze.py}"

RUN_TS="${RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/run/exec-perf-${RUN_TS}-$$}"
PACE="${PACE:-none}"
PER_REQUEST_TIMEOUT_MS="${PER_REQUEST_TIMEOUT_MS:-5000}"
TRIAGE_TIMEOUT_S="${TRIAGE_TIMEOUT_S:-1800}"
SKIP_CAPTURE="${SKIP_CAPTURE:-0}"

RUN_STATE_FILE=""
RUN_COMPLETED=0

log() { echo "[$(date +%H:%M:%S)] paired-exec: $*" >&2; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

dir_is_nonempty() (
    shopt -s nullglob dotglob
    local -a entries=("$1"/*)
    ((${#entries[@]} > 0))
)

write_run_state() {
    local state="$1"
    local temporary_state="${RUN_STATE_FILE}.tmp.$$"
    printf 'state=%s\nupdated_utc=%s\n' \
        "${state}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${temporary_state}"
    mv -f "${temporary_state}" "${RUN_STATE_FILE}"
}

finish_run() {
    local status=$?
    trap - EXIT
    if [ -n "${RUN_STATE_FILE}" ]; then
        if [ "${status}" -eq 0 ] && [ "${RUN_COMPLETED}" = "1" ]; then
            write_run_state complete || true
        else
            write_run_state failed || true
        fi
    fi
    exit "${status}"
}

file_digest() {
    local digest_line
    digest_line=$(sha256sum -- "$1")
    printf '%s' "${digest_line%% *}"
}

materialize_file() {
    local source_path="$1"
    local target_path="$2"
    local source_abs target_dir target_abs
    [ -f "${source_path}" ] || die "missing input file: ${source_path}"
    source_abs=$(readlink -f "${source_path}")
    target_dir=$(dirname "${target_path}")
    mkdir -p "${target_dir}"
    target_dir=$(cd "${target_dir}" && pwd)
    target_abs="${target_dir}/$(basename "${target_path}")"
    if [ "${source_abs}" != "${target_abs}" ]; then
        cp "${source_abs}" "${target_abs}"
    fi
}

trace_files_exist() {
    local trace_dir="$1"
    compgen -G "${trace_dir}/exec_trace_*.bin" >/dev/null
}

preflight() {
    case "${SKIP_CAPTURE}" in
        0|1) ;;
        *) die "SKIP_CAPTURE must be 0 or 1 (got ${SKIP_CAPTURE})" ;;
    esac
    [[ "${PER_REQUEST_TIMEOUT_MS}" =~ ^[1-9][0-9]*$ ]] || \
        die "PER_REQUEST_TIMEOUT_MS must be a positive integer"
    [[ "${TRIAGE_TIMEOUT_S}" =~ ^[1-9][0-9]*$ ]] || \
        die "TRIAGE_TIMEOUT_S must be a positive integer"
    case "${PACE}" in
        trace|none) ;;
        *) die "PACE must be trace or none (got ${PACE})" ;;
    esac
    command -v python3 >/dev/null || die "python3 is required"
    command -v sha256sum >/dev/null || die "sha256sum is required"
    [ -f "${ANALYZER}" ] || die "missing analyzer: ${ANALYZER}"

    if [ "${SKIP_CAPTURE}" != "1" ]; then
        [ -f "${CAPTURE_SCRIPT}" ] || die "missing capture script: ${CAPTURE_SCRIPT}"
        [ -f "${IMAGE_PREP_SCRIPT}" ] || die "missing image preparation script: ${IMAGE_PREP_SCRIPT}"
        [ -f "${SYZ_CAPTURE_IMAGE}" ] || die \
            "missing capture image: ${SYZ_CAPTURE_IMAGE}; run ${IMAGE_PREP_SCRIPT} first"
        if ! IMAGE_DST="${SYZ_CAPTURE_IMAGE}" bash "${IMAGE_PREP_SCRIPT}" --check; then
            die "capture image verification failed: ${SYZ_CAPTURE_IMAGE}"
        fi
    fi
    [ -x "${REPLAYER_BIN}" ] || die "missing replayer binary: ${REPLAYER_BIN}"
    [ -x "${WORKER_BIN}" ] || die "missing worker binary: ${WORKER_BIN}"
    [ -f "${SYZ_CONFIG}" ] || die "missing Syzkaller config: ${SYZ_CONFIG}"
    [ -f "${REFUZZ_CONFIG}" ] || die "missing reFuzz config: ${REFUZZ_CONFIG}"
    if ! python3 - "${SYZ_CONFIG}" "${REFUZZ_CONFIG}" <<'PY'
import json
import pathlib
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        syz = json.load(stream)
    with open(sys.argv[2], encoding="utf-8") as stream:
        rfz = json.load(stream)
    syz_vm = syz["vm"]
    rfz_vm = rfz["channel"]["vm"]
    transport = rfz["channel"]["transport"]
    worker_perf = rfz["fuzzer"]["worker_perf"]
    target = rfz["target"]

    invariants = {
        "Syzkaller procs": (syz["procs"], 6),
        "Syzkaller VM count": (syz_vm["count"], 1),
        "reFuzz workers": (transport["n_workers"], 6),
        "reFuzz MSI-X vectors": (transport["ivshmem_vectors"], 6),
        "VM CPU parity": (rfz_vm["qemu"]["cpu"], syz_vm["cpu"]),
        "VM memory parity": (rfz_vm["qemu"]["mem"], syz_vm["mem"]),
        "kernel parity": (rfz_vm["kernel"], syz_vm["kernel"]),
        "threaded execution": (target["intra_task_mode"], "threaded"),
        "worker perf enabled": (worker_perf["enable"], True),
        "worker perf sample rate": (worker_perf["sample_rate"], 1),
    }
    mismatches = [
        f"{label}: got {actual!r}, expected {expected!r}"
        for label, (actual, expected) in invariants.items()
        if actual != expected
    ]
    if syz_vm["cpu"] != 2 or syz_vm["mem"] != 4096:
        mismatches.append(
            f"expected 2 vCPU/4096 MiB, got {syz_vm['cpu']} vCPU/{syz_vm['mem']} MiB"
        )
    if "-enable-kvm" not in syz_vm.get("qemu_args", ""):
        mismatches.append("Syzkaller qemu_args does not contain -enable-kvm")
    if mismatches:
        raise ValueError("; ".join(mismatches))
    required = {
        "Syzkaller image": syz["image"],
        "Syzkaller kernel": syz_vm["kernel"],
        "Syzkaller SSH key": syz["sshkey"],
        "reFuzz image": rfz_vm["image"],
        "reFuzz kernel": rfz_vm["kernel"],
        "reFuzz SSH key": rfz_vm["ssh_key"],
    }
except (KeyError, OSError, json.JSONDecodeError) as error:
    print(f"invalid paired configs: {error}", file=sys.stderr)
    raise SystemExit(1)
except ValueError as error:
    print(f"paired config mismatch: {error}", file=sys.stderr)
    raise SystemExit(1)

missing = [(label, path) for label, path in required.items() if not pathlib.Path(path).is_file()]
for label, path in missing:
    print(f"missing {label}: {path}", file=sys.stderr)
raise SystemExit(bool(missing))
PY
    then
        die "paired config preflight failed"
    fi
}

prepare_run_dir() {
    if [ -e "${RUN_DIR}" ] && [ ! -d "${RUN_DIR}" ]; then
        die "RUN_DIR exists but is not a directory: ${RUN_DIR}"
    fi
    if [ -d "${RUN_DIR}" ] && dir_is_nonempty "${RUN_DIR}"; then
        die "RUN_DIR is non-empty; every reFuzz repetition needs a fresh output directory"
    fi
    mkdir -p "${RUN_DIR}"
    RUN_DIR=$(cd "${RUN_DIR}" && pwd)
    RUN_STATE_FILE="${RUN_DIR}/run-state.txt"
    write_run_state running
    trap finish_run EXIT
    export RUN_DIR RUN_TS
}

prepare_syz_capture_config() {
    SYZ_CAPTURE_CONFIG="${RUN_DIR}/syz_capture_base_config.json"
    python3 - "${SYZ_CONFIG}" "${SYZ_CAPTURE_CONFIG}" "${SYZ_CAPTURE_IMAGE}" <<'PY'
import json
import sys

source, output, image = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    config = json.load(stream)
config["image"] = image
with open(output, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
PY
    export SYZ_CAPTURE_CONFIG
}

capture_syzkaller() {
    local target_log="${RUN_DIR}/syz_perf_serial.log"
    if [ "${SKIP_CAPTURE}" = "1" ]; then
        [ -n "${TRACE_DIR:-}" ] || die "SKIP_CAPTURE=1 requires TRACE_DIR"
        [ -d "${TRACE_DIR}" ] || die "TRACE_DIR is not a directory: ${TRACE_DIR}"
        TRACE_DIR=$(cd "${TRACE_DIR}" && pwd)
        trace_files_exist "${TRACE_DIR}" || die "no exec_trace_*.bin in ${TRACE_DIR}"
        local source_log="${SYZ_PERF_LOG:-$(dirname "${TRACE_DIR}")/syz_perf_serial.log}"
        materialize_file "${source_log}" "${target_log}"
        SYZ_PERF_LOG="${target_log}"
        log "capture skipped; trace=${TRACE_DIR}"
    else
        TRACE_DIR="${RUN_DIR}/trace"
        if [ -d "${TRACE_DIR}" ] && trace_files_exist "${TRACE_DIR}"; then
            die "fresh capture refuses existing trace files in ${TRACE_DIR}"
        fi
        export PERF_SERIAL_PATH="${target_log}"
        export TRIAGE_TIMEOUT_S
        prepare_syz_capture_config
        export SYZ_MANAGER_BASE_CONFIG="${SYZ_CAPTURE_CONFIG}"
        log "capturing Syzkaller requests with six procs"
        if ! bash "${CAPTURE_SCRIPT}"; then
            die "Syzkaller capture failed; see ${RUN_DIR}/syz-manager.log" 2
        fi
        trace_files_exist "${TRACE_DIR}" || die "capture produced no trace files" 2
        SYZ_PERF_LOG="${target_log}"
    fi
    [ -s "${SYZ_PERF_LOG}" ] || die "Syzkaller perf serial is empty: ${SYZ_PERF_LOG}" 2
    if ! grep -q '\[SyzTL\]' "${SYZ_PERF_LOG}"; then
        die "Syzkaller perf serial contains no [SyzTL] records" 2
    fi
    if ! grep -q '\[SyzExecCPU\]' "${SYZ_PERF_LOG}"; then
        die "Syzkaller perf serial contains no [SyzExecCPU] records; rebuild the executor and capture image" 2
    fi
    if ! grep -q '\[SyzRoleCPU\]' "${SYZ_PERF_LOG}"; then
        die "Syzkaller perf serial contains no [SyzRoleCPU] records" 2
    fi
    if ! grep -Eq '\[SyzCPU\].*hz=[1-9][0-9]*' "${SYZ_PERF_LOG}"; then
        die "Syzkaller perf serial contains no [SyzCPU] record with hz=" 2
    fi
    export TRACE_DIR SYZ_PERF_LOG
}

write_trace_manifest() {
    local manifest="${RUN_DIR}/trace.sha256"
    local temporary_manifest="${manifest}.tmp.$$"
    : > "${temporary_manifest}"
    local trace_file
    for trace_file in "${TRACE_DIR}"/exec_trace_*.bin; do
        printf '%s  %s\n' "$(file_digest "${trace_file}")" \
            "$(basename "${trace_file}")" >> "${temporary_manifest}"
    done
    mv -f "${temporary_manifest}" "${manifest}"
}

write_runtime_config() {
    RUNTIME_CONFIG="${RUN_DIR}/refuzz_replayer_config.json"
    REFUZZ_WORK_DIR="${RUN_DIR}/refuzz-work"
    local ipc_tag
    ipc_tag="rfz_ep_$(date +%s)_$$"
    IVSHMEM_PATH="/tmp/${ipc_tag}.ivshmem"
    DOORBELL_PATH="/tmp/${ipc_tag}.sock"

    python3 - "${REFUZZ_CONFIG}" "${RUNTIME_CONFIG}" "${REFUZZ_WORK_DIR}" \
        "${IVSHMEM_PATH}" "${DOORBELL_PATH}" "${WORKER_BIN}" <<'PY'
import json
import pathlib
import sys

source, output, work_dir, ivshmem, doorbell, worker = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    config = json.load(stream)

config["work_dir"] = work_dir
transport = config["channel"]["transport"]
transport["ivshmem_path"] = ivshmem
transport["doorbell_socket_path"] = doorbell
config["phase0_worker_bin"] = worker

for socket_path in (pathlib.Path(work_dir) / "serial.sock", pathlib.Path(doorbell)):
    if len(str(socket_path).encode()) >= 108:
        raise SystemExit(f"UNIX socket path is too long: {socket_path}")

with open(output, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
PY
    export RUNTIME_CONFIG REFUZZ_WORK_DIR IVSHMEM_PATH DOORBELL_PATH
}

replay_refuzz() {
    local target_result="${RUN_DIR}/ref_result.bin"
    local target_log="${RUN_DIR}/refuzz_worker.log"
    write_runtime_config
    REF_RESULT="${target_result}"
    local replayer_log="${RUN_DIR}/replayer.log"
    local -a args=(
        -trace-dir "${TRACE_DIR}"
        -output "${REF_RESULT}"
        -backend qemu_ivshmem_linux
        -config "${RUNTIME_CONFIG}"
        -per-request-timeout-ms "${PER_REQUEST_TIMEOUT_MS}"
        -pace "${PACE}"
    )
    log "replaying fixed corpus/trace through six reFuzz workers (pace=${PACE})"
    if ! "${REPLAYER_BIN}" "${args[@]}" >"${replayer_log}" 2>&1; then
        tail -n 40 "${replayer_log}" >&2 || true
        die "reFuzz replay failed" 3
    fi
    [ -s "${REF_RESULT}" ] || die "replay produced an empty ref_result.bin" 3
    local source_log="${REFUZZ_WORK_DIR}/worker.log"
    [ -s "${source_log}" ] || die "reFuzz worker log is missing: ${source_log}" 3
    materialize_file "${source_log}" "${target_log}"
    RFZ_PERF_LOG="${target_log}"
    if ! grep -q '\[RfzTL\]' "${RFZ_PERF_LOG}"; then
        die "reFuzz worker log contains no [RfzTL] records" 3
    fi
    if ! grep -q '\[RfzExecCPU\]' "${RFZ_PERF_LOG}"; then
        die "reFuzz worker log contains no [RfzExecCPU] records; rebuild ivshmem_worker" 3
    fi
    if ! grep -q '\[RfzRoleCPU\]' "${RFZ_PERF_LOG}"; then
        die "reFuzz worker log contains no [RfzRoleCPU] records" 3
    fi
    if ! grep -Eq '\[RfzCPU\].*hz=[1-9][0-9]*' "${RFZ_PERF_LOG}"; then
        die "reFuzz worker log contains no [RfzCPU] record with hz=" 3
    fi
    export REF_RESULT RFZ_PERF_LOG
}

write_metadata() {
    local metadata="${RUN_DIR}/run-metadata.txt"
    local temporary_metadata="${metadata}.tmp.$$"
    {
        printf 'run_ts=%s\n' "${RUN_TS}"
        printf 'syz_config=%s\n' "${SYZ_CONFIG}"
        printf 'syz_capture_config=%s\n' "${SYZ_CAPTURE_CONFIG:-reused}"
        printf 'syz_capture_image=%s\n' "${SYZ_CAPTURE_IMAGE:-reused}"
        printf 'refuzz_config=%s\n' "${REFUZZ_CONFIG}"
        printf 'trace_dir=%s\n' "${TRACE_DIR}"
        printf 'syz_perf_log=%s\n' "${SYZ_PERF_LOG}"
        printf 'rfz_perf_log=%s\n' "${RFZ_PERF_LOG}"
        printf 'ref_result=%s\n' "${REF_RESULT}"
        printf 'syz_procs=6\nrefuzz_workers=6\nvm_cpu=2\nvm_mem_mb=4096\n'
        printf 'pace=%s\n' "${PACE}"
        printf 'per_request_timeout_ms=%s\n' "${PER_REQUEST_TIMEOUT_MS}"
        printf 'triage_timeout_s=%s\n' "${TRIAGE_TIMEOUT_S}"
        printf 'skip_capture=%s\n' "${SKIP_CAPTURE}"
    } > "${temporary_metadata}"
    mv -f "${temporary_metadata}" "${metadata}"
}

analyze_pairs() {
    REPORT="${RUN_DIR}/paired_perf_report.md"
    log "joining req_id to executor_id and analyzing exact pairs"
    if ! python3 "${ANALYZER}" \
        --syz-log "${SYZ_PERF_LOG}" \
        --rfz-log "${RFZ_PERF_LOG}" \
        --ref-result "${REF_RESULT}" \
        --output "${REPORT}"; then
        die "paired analysis failed; inspect ${REPORT}" 4
    fi
    log "report=${REPORT}"
}

main() {
    preflight
    prepare_run_dir
    capture_syzkaller
    write_trace_manifest
    replay_refuzz
    write_metadata
    analyze_pairs
    log "done"
    printf '%s\n' "${REPORT}"
    RUN_COMPLETED=1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
