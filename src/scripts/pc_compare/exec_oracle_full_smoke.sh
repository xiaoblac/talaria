#!/usr/bin/env bash
# V2 production-exec paired oracle — full smoke (capture → replay → oracle).
#
# One-shot pipeline gluing the three PR ships from the design constitution
# `docs/plans/production-exec-paired-oracle.md`:
#
#   stage 1 (PR1+PR2):  scripts/pc_compare/exec_oracle_smoke.sh
#                       boots one VM via syz-manager, the proxied executor
#                       wrapper captures flatrpc frames to ${RUN_DIR}/trace.
#   stage 2 (PR3):      build-llvm20/refuzz-exec-replayer
#                       feeds the captured trace through reFuzz ivshmem
#                       channel + worker; emits ${RUN_DIR}/ref_result.bin.
#   stage 3 (PR4):      build-llvm20/refuzz_exec_oracle
#                       joins both streams, emits
#                       ${RUN_DIR}/exec-oracle-report.json.
#   stage 4:            §13.1 ship-gate verdict printed to the console.
#
# Common knobs (env):
#   RUN_TS, RUN_DIR              — same as capture script; auto if unset.
#   TRIAGE_TIMEOUT_S             — hard safety cap for corpus-triage (1800s).
#                                  syz-manager exits naturally on triage drain;
#                                  this only fires if the run wedges.
#   VM_COUNT, VM_CPU, VM_MEM_MB  — capture VM shape.
#   REFUZZ_FORCE_COLLECT_COVER   — default ON (force every ExecRequest to
#                                  carry CollectCover). Set 0/false/off/no
#                                  to disable (debug only).
#   SKIP_CAPTURE=1 TRACE_DIR=...
#                                — reuse an existing capture; bypass stage 1.
#   SKIP_REPLAY=1 REF_RESULT=...
#                                — reuse an existing ref_result.bin; bypass
#                                  stage 2 (implies SKIP_CAPTURE+TRACE_DIR).
#   REPLAYER_BACKEND             — `qemu_ivshmem_linux` (default) or `echo`.
#   REPLAYER_CONFIG              — JSON config (only used for qemu backend).
#   PER_REQUEST_TIMEOUT_MS       — replayer per-request budget (default 5000).
#   MAX_SAMPLES                  — oracle mismatch sample cap (default 30).
#
# Exit codes:
#   0  pipeline ran AND all three §13.1 gates passed
#   1  preflight / invocation error
#   2  capture lap failed (no trace produced)
#   3  replay lap failed
#   4  oracle ran but at least one ship gate failed
#
# Prereqs: bake_exec_oracle_image.sh has been run once;
# build-llvm20/{syz_flatrpc_proxy,refuzz-exec-replayer,refuzz_exec_oracle}
# are built (`cmake --build . --target refuzz_exec_replayer refuzz_exec_oracle`).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # scripts/pc_compare/ → repo root
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build-llvm20}"

REPLAYER_BIN="${REPLAYER_BIN:-${BUILD_DIR}/refuzz-exec-replayer}"
ORACLE_BIN="${ORACLE_BIN:-${BUILD_DIR}/refuzz_exec_oracle}"
CAPTURE_SCRIPT="${CAPTURE_SCRIPT:-${ROOT_DIR}/scripts/pc_compare/exec_oracle_smoke.sh}"

REPLAYER_BACKEND="${REPLAYER_BACKEND:-qemu_ivshmem_linux}"
# Default to the COV-A threaded config so Threaded production requests
# (which the replayer no longer skips) actually reach a worker that has
# thread_count > 1. The sample config has thread_count default = 1, so
# Threaded requests there would hit Driver/threaded `reject tag=bad_cfg`
# and fall to exec_error — silently inflating result/coverage gate noise.
REPLAYER_CONFIG="${REPLAYER_CONFIG:-${ROOT_DIR}/configs/exec_oracle_replayer_threaded_config.json}"
PER_REQUEST_TIMEOUT_MS="${PER_REQUEST_TIMEOUT_MS:-5000}"
MAX_SAMPLES="${MAX_SAMPLES:-30}"

# vmlinux for the cold-fault classifier (plan §13.5 finding E,
# tools/refuzz_exec_oracle/main.go::classifyProcessColdFault). Without
# this the classifier is a no-op and call#0 fork-child page-fault outliers
# (do_user_addr_fault family) flood the actionable_low_band bucket — see
# diagnostic 2026-05-20: 511 call#0 outliers all in page-fault PCs.
# Pass empty string to disable explicitly.
VMLINUX="${VMLINUX:-${ROOT_DIR}/../kernel/build-kasan/vmlinux}"
if [ ! -f "${VMLINUX}" ] && [ -n "${VMLINUX}" ]; then
    # Fall back to the well-known absolute location used by exec_oracle_smoke.sh.
    VMLINUX="/workspace/syzkaller/kernel/build-kasan/vmlinux"
fi

RUN_TS="${RUN_TS:-$(date +%s)}"
RUN_DIR="${RUN_DIR:-${ROOT_DIR}/run/exec-oracle-${RUN_TS}}"
export RUN_TS RUN_DIR
mkdir -p "${RUN_DIR}"

log() { echo "[$(date +%H:%M:%S)] full-smoke: $*" >&2; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

preflight() {
    local missing=0
    local check=("${ORACLE_BIN}")
    if [ "${SKIP_REPLAY:-0}" != "1" ]; then
        check+=("${REPLAYER_BIN}")
        if [ "${REPLAYER_BACKEND}" = "qemu_ivshmem_linux" ]; then
            check+=("${REPLAYER_CONFIG}")
        fi
    fi
    if [ "${SKIP_CAPTURE:-0}" != "1" ] && [ "${SKIP_REPLAY:-0}" != "1" ]; then
        check+=("${CAPTURE_SCRIPT}")
    fi
    for f in "${check[@]}"; do
        if [ ! -e "$f" ]; then
            log "missing: $f"
            missing=$((missing + 1))
        fi
    done
    if [ "$missing" -gt 0 ]; then
        die "preflight FAILED (${missing} missing); did you build the V2 targets?"
    fi
    log "preflight OK (backend=${REPLAYER_BACKEND})"
}

stage1_capture() {
    # SKIP_REPLAY implies the user already has both inputs to stage3, so
    # the capture lap is unconditionally skipped too.
    if [ "${SKIP_REPLAY:-0}" = "1" ] || [ "${SKIP_CAPTURE:-0}" = "1" ]; then
        if [ -z "${TRACE_DIR:-}" ]; then
            die "SKIP_CAPTURE/SKIP_REPLAY requires TRACE_DIR=..."
        fi
        if [ ! -d "${TRACE_DIR}" ]; then
            die "TRACE_DIR=${TRACE_DIR} not a directory"
        fi
        log "stage1: SKIPPED (reusing TRACE_DIR=${TRACE_DIR})"
        return
    fi
    log "stage1: capture lap → ${RUN_DIR}/trace"
    # Capture script inherits RUN_TS/RUN_DIR via env (mkdir already done).
    if ! bash "${CAPTURE_SCRIPT}"; then
        die "capture lap failed; see ${RUN_DIR}/syz-manager.log" 2
    fi
    TRACE_DIR="${RUN_DIR}/trace"
    if ! ls "${TRACE_DIR}"/exec_trace_*.bin >/dev/null 2>&1; then
        die "capture lap produced no trace files in ${TRACE_DIR}" 2
    fi
    log "stage1: OK ($(ls "${TRACE_DIR}"/exec_trace_*.bin | wc -l) trace file(s))"
}

stage2_replay() {
    if [ "${SKIP_REPLAY:-0}" = "1" ]; then
        if [ -z "${REF_RESULT:-}" ]; then
            die "SKIP_REPLAY=1 requires REF_RESULT=..."
        fi
        if [ ! -s "${REF_RESULT}" ]; then
            die "REF_RESULT=${REF_RESULT} missing or empty"
        fi
        log "stage2: SKIPPED (reusing REF_RESULT=${REF_RESULT})"
        return
    fi
    local ref_result="${RUN_DIR}/ref_result.bin"
    local replayer_log="${RUN_DIR}/replayer.log"
    local replayer_args=(
        -trace-dir "${TRACE_DIR}"
        -output "${ref_result}"
        -backend "${REPLAYER_BACKEND}"
        -per-request-timeout-ms "${PER_REQUEST_TIMEOUT_MS}"
    )
    if [ "${REPLAYER_BACKEND}" = "qemu_ivshmem_linux" ]; then
        replayer_args+=(-config "${REPLAYER_CONFIG}")
    fi
    # T2: optional strict-equivalence pacing mode (-pace=trace stalls each
    # Submit to land at the trace's E2H Executing wall-clock, reproducing
    # syzkaller's per-proc start cadence so EBUSY-on-/dev/loop<procid>
    # divergence isn't masked by reFuzz's natural burst submit timing).
    if [ -n "${REPLAYER_PACE:-}" ]; then
        replayer_args+=(-pace "${REPLAYER_PACE}")
    fi
    log "stage2: replay lap → ${ref_result} (backend=${REPLAYER_BACKEND})"
    if ! "${REPLAYER_BIN}" "${replayer_args[@]}" \
            >"${replayer_log}" 2>&1; then
        log "replayer failed; tail of ${replayer_log}:"
        tail -n 30 "${replayer_log}" >&2 || true
        die "replay lap failed" 3
    fi
    if [ ! -s "${ref_result}" ]; then
        die "replay lap produced empty ${ref_result}" 3
    fi
    REF_RESULT="${ref_result}"
    log "stage2: OK ($(stat -c%s "${ref_result}") bytes)"
}

stage3_oracle() {
    local report="${RUN_DIR}/exec-oracle-report.json"
    local per_call_jsonl="${RUN_DIR}/per-call.jsonl"
    local -a oracle_args=(
        -trace-dir "${TRACE_DIR}"
        -ref-result "${REF_RESULT}"
        -output "${report}"
        -max-samples "${MAX_SAMPLES}"
        -per-call-jsonl "${per_call_jsonl}"
    )
    # Cold-fault classifier opt-in: pass -vmlinux only if the file actually
    # exists, otherwise oracle would log a load failure and run with the
    # classifier disabled anyway (gate behavior identical to old smoke runs).
    if [ -n "${VMLINUX}" ] && [ -f "${VMLINUX}" ]; then
        oracle_args+=(-vmlinux "${VMLINUX}")
        log "stage3: vmlinux=${VMLINUX} (cold-fault classifier enabled)"
    else
        log "stage3: vmlinux not found (${VMLINUX:-unset}) — cold-fault classifier disabled"
    fi
    log "stage3: oracle → ${report}"
    if ! "${ORACLE_BIN}" "${oracle_args[@]}" \
            2>"${RUN_DIR}/oracle.stderr"; then
        log "oracle failed; tail of stderr:"
        tail -n 30 "${RUN_DIR}/oracle.stderr" >&2 || true
        die "oracle lap failed" 3
    fi
    REPORT="${report}"
    PER_CALL_JSONL="${per_call_jsonl}"
    # Sanity check: oracle reported request_total > 0 so jsonl must have rows.
    if [ -s "${per_call_jsonl}" ]; then
        local rows
        rows=$(wc -l < "${per_call_jsonl}")
        log "stage3: OK (per-call jsonl ${rows} rows)"
    else
        log "stage3: OK (per-call jsonl empty — no compared requests?)"
    fi
}

stage4_verdict() {
    # Parse the §13.1 gates out of the report and print a human-readable
    # verdict. Use python3 — present on every reFuzz dev host and avoids a
    # hard jq dependency.
    log "stage4: §13.1 ship-gate verdict"
    set +e
    python3 - "${REPORT}" <<'PY' >&2
import json, sys
r = json.load(open(sys.argv[1]))
g = r.get("ship_gate_passed", {})
wire = g.get("wire", {})
result = g.get("result", {})
cov = g.get("coverage", {})
print("  schema_version   :", r.get("schema_version"))
print("  total / compared : %d / %d  (raw_rate=%.3f comparable_rate=%.3f)" % (
    r["request_total"], r["request_compared"],
    r["raw_compared_rate"], r["comparable_rate"]))
print("  skip_unsupported :", r["request_skipped_unsupported"])
print("  replay_holes     :", r["request_skipped_replay_holes"])
print("  call_count_mis   :", r["call_count_mismatch"])
print("  call_flag_mis    :", r["call_flag_mismatch"])
print("  errno_mismatch   :", r["errno_mismatch"])
print("  abnormal_buckets :", r["abnormal_kind_buckets"])
print("  --- §13.1 three-tier gate ---")
print("  wire     : replay_holes_clean=%s call_count_matches=%s call_flag_matches=%s → passed=%s" % (
    wire.get("replay_holes_clean"), wire.get("call_count_matches"),
    wire.get("call_flag_matches"), wire.get("passed")))
print("  result   : errno_matches=%s → passed=%s" % (
    result.get("errno_matches"), result.get("passed")))
print("  coverage : status=%s avail_rate=%.3f jaccard=%.4f (n=%d, both_empty=%d) → passed=%s" % (
    cov.get("status"), cov.get("coverage_available_rate", 0.0),
    cov.get("jaccard_mean", 0.0), cov.get("jaccard_sample_count", 0),
    r.get("kcov_jaccard_both_empty_count", 0),
    cov.get("passed")))
# §13.5 COV-B.5 jaccard distribution (p25/p50/p95/p99 + low/high band) — the
# single mean above can hide bimodal patterns (90% near 1.0 + 10% near 0).
# The bands give the path-divergence red-zone counter alongside.
dist = cov.get("jaccard_distribution", {}) or {}
if dist.get("sample_count", 0) > 0:
    print("             distribution: min=%.4f p25=%.4f p50=%.4f p95=%.4f p99=%.4f" % (
        dist.get("min", 0.0), dist.get("p25", 0.0), dist.get("p50", 0.0),
        dist.get("p95", 0.0), dist.get("p99", 0.0)))
    print("             bands: low(<0.5)=%d  high(>=0.9)=%d  (of %d)" % (
        dist.get("low_band_count", 0), dist.get("high_band_count", 0),
        dist.get("sample_count", 0)))
# §13.5 COV-B.4 divergence dump count (samples with reason=coverage_divergence).
div_count = sum(1 for s in r.get("samples", []) if s.get("reason") == "coverage_divergence")
if div_count > 0:
    print("             coverage_divergence samples: %d (j<0.5; see samples[] for syscall attribution)" % div_count)
print("  == overall                      : %s" % g.get("overall"))
if cov.get("status") in ("insufficient_data", "pending_thresholds"):
    print("  NOTE: coverage gate not satisfied — V2 equivalence not yet proven.")
    print("        See docs/plans/production-exec-paired-oracle.md §13.4 / §13.5.")
sys.exit(0 if g.get("overall") else 4)
PY
    local rc=$?
    set -e
    case "$rc" in
        0) log "OK: §13.1 ship gates all PASS. report=${REPORT}" ;;
        4) log "FAIL: §13.1 ship gate(s) failed. report=${REPORT}"
           exit 4 ;;
        *) die "verdict parser crashed (rc=${rc}); report=${REPORT}" 1 ;;
    esac
}

preflight
stage1_capture
stage2_replay
stage3_oracle
stage4_verdict
log "done"
