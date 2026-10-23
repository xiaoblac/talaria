#!/usr/bin/env bash
# In-image launcher for a single reFuzz replay performance run.
#
# Usage:
#   /opt/perf/run_replay.sh --workload W1|W2 --workers 6|7 [--out-dir /results]
set -euo pipefail

ROOT=/opt/perf
OUT_ROOT="${OUT_ROOT:-/results}"
WORKLOAD=""
WORKERS=""

die() { echo "run_replay: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workload) WORKLOAD="${2:-}"; shift 2 ;;
        --workers)  WORKERS="${2:-}";  shift 2 ;;
        --out-dir)  OUT_ROOT="${2:-}"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$WORKLOAD" in
    W1) STREAM_ID="syz-a" ;;
    W2) STREAM_ID="rfz-a" ;;
    *) die "--workload must be W1 or W2" ;;
esac
case "$WORKERS" in
    6) RFZ_CFG_NAME="refuzz_mabB_perf.json" ;;
    7) RFZ_CFG_NAME="refuzz_mabB_perf_w7.json" ;;
    *) die "--workers must be 6 or 7" ;;
esac

REUSE_ID="${WORKLOAD}w${WORKERS}"
SYZ_CFG_NAME="syz_${WORKERS}proc_cpu_closure.json"
NAME="rfz-w${WORKERS}__on-${STREAM_ID}__$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/e3-scale/${NAME}"

export RUN_DIR
export EXPERIMENT="e3-scale"
export STREAM_ID
export REUSE_SYZ_FROM="${ROOT}/reuse/${REUSE_ID}"
export STREAM_OVERRIDE="${ROOT}/streams/${STREAM_ID}/stream.bin"
export RFZ_CONFIG="${ROOT}/configs/${RFZ_CFG_NAME}"
export SYZ_CONFIG="${ROOT}/configs/${SYZ_CFG_NAME}"
export SSHK="${ROOT}/id_rsa"
export BUILD_DIR="${ROOT}/build"

mkdir -p "$RUN_DIR"
exec bash "${ROOT}/scripts/perf_compare/perf_sampling.sh" replay
