#!/usr/bin/env bash
# run_matrix.sh — 容器入口：一次完整实验轮次。
# 串行跑 4 个作业：W1×6 → W1×7 → W2×6 → W2×7；
# 每个作业内 syzkaller 与 reFuzz 并行重放同一条 stream（replay_both_parallel.sh）。
set -euo pipefail

ROOT="${ROOT:-/opt/perf}"
OUT_ROOT="${OUT_ROOT:-/results}"
MATRIX_DIR="${MATRIX_DIR:-/matrix}"

export SSHK="${ROOT}/id_rsa"
export BUILD_DIR="${ROOT}/build"
export EXPERIMENT="e3scale-matrix"
# 3 个容器 × 每作业 2 个 VM 同时 boot，CPU 竞争会让单 VM 的 1200s 预算吃紧；
# 放宽到 40 分钟（wedged run 仍由 REPLAY_SAFETY_CAP_S 兜底）。
export REPLAY_BOOT_TIMEOUT_S="${REPLAY_BOOT_TIMEOUT_S:-2400}"

START_COMBO="${START_COMBO:-W1-6}"
MAX_RETRY="${MAX_RETRY:-2}"

declare -A STREAM=( [W1]=syz-a [W2]=rfz-a )
declare -A REUSE=( [W1-6]=W1w6 [W1-7]=W1w7 [W2-6]=W2w6 [W2-7]=W2w7 )
COMBOS=(W1-6 W1-7 W2-6 W2-7)

started=0
for combo in "${COMBOS[@]}"; do
    if [ "${started}" -eq 0 ] && [ "${combo}" != "${START_COMBO}" ]; then
        continue
    fi
    started=1

    wl="${combo%-*}"
    wk="${combo#*-}"
    stream="${STREAM[$wl]}"
    reuse="${REUSE[$combo]}"
    rfz_cfg="refuzz_mabB_perf.json"
    syz_cfg="syz_6proc_cpu_closure.json"
    if [ "${wk}" = "7" ]; then
        rfz_cfg="refuzz_mabB_perf_w7.json"
        syz_cfg="syz_7proc_cpu_closure.json"
    fi

    rc=1
    attempt=0
    while [ "${rc}" -ne 0 ] && [ "${attempt}" -le "${MAX_RETRY}" ]; do
        attempt=$(( attempt + 1 ))
        run_dir="${OUT_ROOT}/e3scale-matrix/${combo}-$(date -u +%Y%m%dT%H%M%SZ)"
        echo "=== matrix job ${combo} (attempt ${attempt}/${MAX_RETRY}): stream=${stream} workers=${wk} -> ${run_dir} ==="
        RUN_DIR="${run_dir}" \
        REUSE_SYZ_FROM="${ROOT}/reuse/${reuse}" \
        STREAM_OVERRIDE="${ROOT}/streams/${stream}/stream.bin" \
        STREAM_ID="${stream}" \
        RFZ_CONFIG="${ROOT}/configs/${rfz_cfg}" \
        SYZ_CONFIG="${ROOT}/configs/${syz_cfg}" \
        bash "${MATRIX_DIR}/replay_both_parallel.sh"
        rc=$?
        echo "=== matrix job ${combo} attempt ${attempt} rc=${rc} ==="
        if [ "${rc}" -ne 0 ] && [ "${attempt}" -le "${MAX_RETRY}" ]; then
            echo "=== retrying ${combo} in 30s ==="
            sleep 30
        fi
    done
    [ "${rc}" -eq 0 ] || exit "${rc}"
done

echo "=== matrix round complete ==="
