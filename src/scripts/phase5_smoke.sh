#!/usr/bin/env bash
# phase5_smoke.sh
#
# Phase 5 smoke script:
#   Stage 1: executor run (VM + KCOV, syz_balanced mutator end-to-end)
#
# Usage: ./scripts/phase5_smoke.sh
#   always uses configs/phase5_sample_config.json
#
# Env overrides:
#   REFUZZ_BUILD_DIR      — CMake build directory (default: <root>/build-llvm20)
#   REFUZZ_CC / REFUZZ_CXX — C/C++ compiler for Stage 0 (default: clang-20 / clang++-20)
#   REFUZZ_CMAKE_EXTRA    — extra args passed to cmake -S/-B (e.g. -DREFUZZ_BUILD_TESTS=ON)
#   PHASE5_KEEP_STATE     — set 1 to keep corpus/coverage between runs (default: 0)
#   PHASE5_SKIP_EXECUTOR  — set 1 to skip Stage 1 VM run (default: 0)
#
# Stage 0 always runs: cmake configure + full cmake --build (no incremental-only shortcut).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Stage 0: LLVM/Clang 20 + build-llvm20 — see docs/BUILDING.md
REFUZZ_BUILD_DIR="${REFUZZ_BUILD_DIR:-${ROOT_DIR}/build-llvm20}"
REFUZZ_CC="${REFUZZ_CC:-clang-20}"
REFUZZ_CXX="${REFUZZ_CXX:-clang++-20}"

RUN_DIR="${ROOT_DIR}/run/phase5"
LOG_DIR="${RUN_DIR}/logs"
STATE_DIR="${RUN_DIR}/state"
COVERAGE_DIR="${RUN_DIR}/coverage"
ARTIFACTS_DIR="${RUN_DIR}/vm_artifacts"
IVSHMEM_PATH="${ARTIFACTS_DIR}/ivshmem"
IVSHMEM_SOCKET="${ARTIFACTS_DIR}/ivshmem.sock"

# [FUP-PSEUDO-METRIC-TELEMETRY 2026-05-10] PHASE5_CONFIG_PATH env override.
# Default = phase5_sample_config.json (sandbox=setuid, mount_capable=false →
# Run A in row #18 Phase 3 evidence). Set to mount_image_sample_config.json
# for Run B (sandbox=none, mount_capable=true → mount-image dispatchers
# actually reach mount(2); KVM stub reaches KVM_RUN). Per-config evidence
# rides MetricRegistry now (pseudo.dispatch.* counters in run_summary.json),
# not a VM-side file dump — no SSH-pull or virtfs gymnastics required.
CONFIG_PATH="${PHASE5_CONFIG_PATH:-${ROOT_DIR}/configs/phase5_threaded_sample_config.json}"

# refuzz 可执行文件（装配与入口在 control/orchestrator）
RUNNER="${REFUZZ_BUILD_DIR}/control/orchestrator/refuzz"

KEEP_STATE="${PHASE5_KEEP_STATE:-0}"
SKIP_EXECUTOR="${PHASE5_SKIP_EXECUTOR:-0}"
TUI_MODE="${PHASE5_TUI_MODE:-0}"
TMUX_CHILD="${PHASE5_TMUX_CHILD:-0}"

VALIDATE_LOG="${LOG_DIR}/phase5_validate.log"
RUN_LOG="${LOG_DIR}/phase5_run.log"
METRICS_LOG="${LOG_DIR}/phase5_metrics.log"
QEMU_SERIAL_LOG="${LOG_DIR}/qemu_serial_vm0.log"
EXIT_CODE_FILE="${STATE_DIR}/phase5_smoke_last_exit_code"

config_wants_dashboard() {
  local path="$1"
  python3 - <<'PYCFG' "$path"
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding='utf-8') as f:
        root = json.load(f)
except Exception:
    print('0')
    raise SystemExit(0)

telemetry = root.get('telemetry', {})
dashboard = telemetry.get('dashboard', {})
print('1' if dashboard.get('enable', True) else '0')
PYCFG
}

launch_tmux_dashboard() {
  local child_cmd tail_cmd session_name window_target_id

  printf -v child_cmd 'cd %q && PHASE5_TMUX_CHILD=1 PHASE5_TUI_MODE=1 %q'     "${ROOT_DIR}" "${ROOT_DIR}/scripts/phase5_smoke.sh"
  # tmux 下方 pane 默认跟随执行日志，便于观察 Stage 1 实时输出。
  printf -v tail_cmd 'mkdir -p %q && touch %q && tail -F %q'     "${LOG_DIR}" "${RUN_LOG}" "${RUN_LOG}"

  if [[ -n "${TMUX:-}" ]]; then
    window_target_id="$(tmux new-window -P -F '#{window_id}' -n phase5-smoke "bash -lc ${child_cmd@Q}")"
    tmux setw -t "${window_target_id}" remain-on-exit on
    tmux split-window -v -t "${window_target_id}" "bash -lc ${tail_cmd@Q}"
    tmux select-layout -t "${window_target_id}" even-vertical >/dev/null
    tmux select-window -t "${window_target_id}"
    echo "[phase5-smoke] launched tmux window=${window_target_id}" >&2
    exit 0
  fi

  session_name="phase5-smoke-$$"
  tmux new-session -d -P -F '#S' -s "${session_name}" "bash -lc ${child_cmd@Q}" >/dev/null
  tmux setw -t "${session_name}:0" remain-on-exit on
  tmux split-window -v -t "${session_name}:0" "bash -lc ${tail_cmd@Q}"
  tmux select-layout -t "${session_name}:0" even-vertical >/dev/null
  echo "[phase5-smoke] launched tmux session=${session_name}" >&2
  exec tmux attach-session -t "${session_name}"
}

if [[ "${TMUX_CHILD}" != "1" && "${SKIP_EXECUTOR}" != "1" && -f "${CONFIG_PATH}" ]]; then
  dashboard_enable="$(config_wants_dashboard "${CONFIG_PATH}")"
  if [[ "${dashboard_enable}" == "1" ]]; then
    if command -v tmux >/dev/null 2>&1 && [[ -n "${TMUX:-}" || -t 1 || -t 2 ]]; then
      launch_tmux_dashboard
    fi
  fi
fi

mkdir -p "${LOG_DIR}" "${STATE_DIR}" "${COVERAGE_DIR}" "${ARTIFACTS_DIR}"

cleanup() {
  local code=$?
  echo "${code}" >"${EXIT_CODE_FILE}"
}
trap cleanup EXIT

# 清理当前日志 + 兼容旧命名日志，避免历史残留影响排查。
rm -f \
  "${VALIDATE_LOG}" \
  "${RUN_LOG}" \
  "${METRICS_LOG}" \
  "${LOG_DIR}/phase5_smoke.log" \
  "${LOG_DIR}/phase5_smoke_summary.log" \
  "${LOG_DIR}/phase5_runner.log" \
  "${LOG_DIR}/phase5_chain.log" \
  "${LOG_DIR}/phase5_bench.log" \
  "${QEMU_SERIAL_LOG}"
rm -rf "${ARTIFACTS_DIR}"
mkdir -p "${ARTIFACTS_DIR}"
if [[ "${KEEP_STATE}" != "1" ]]; then
  rm -rf "${STATE_DIR}/corpus" "${STATE_DIR}/coverage.bin" "${COVERAGE_DIR}"
  mkdir -p "${COVERAGE_DIR}"
fi

{
  echo "[phase5-smoke] config=${CONFIG_PATH}"
  echo "[phase5-smoke] build_dir=${REFUZZ_BUILD_DIR}"
  echo "[phase5-smoke] CC=${REFUZZ_CC} CXX=${REFUZZ_CXX}"
  echo "[phase5-smoke] runner=${RUNNER}"
  echo "[phase5-smoke] keep_state=${KEEP_STATE}"
  echo "[phase5-smoke] skip_executor=${SKIP_EXECUTOR}"
  echo "[phase5-smoke] artifacts_dir=${ARTIFACTS_DIR}"
} | tee "${VALIDATE_LOG}"

# ── Stage 0: configure + full build (every run; Clang 20 — works on empty or existing build dir) ──
echo "[phase5-smoke] [Stage 0] cmake configure + full build (LLVM 20)..." | tee -a "${VALIDATE_LOG}"
if ! command -v "${REFUZZ_CC}" >/dev/null 2>&1; then
  echo "[phase5-smoke] FATAL: C compiler not found: ${REFUZZ_CC} (install clang-20 or set REFUZZ_CC)" \
    | tee -a "${VALIDATE_LOG}"
  exit 2
fi
if ! command -v "${REFUZZ_CXX}" >/dev/null 2>&1; then
  echo "[phase5-smoke] FATAL: C++ compiler not found: ${REFUZZ_CXX} (install clang++-20 or set REFUZZ_CXX)" \
    | tee -a "${VALIDATE_LOG}"
  exit 2
fi
mkdir -p "${REFUZZ_BUILD_DIR}"
# shellcheck disable=SC2086
if ! cmake -S "${ROOT_DIR}" -B "${REFUZZ_BUILD_DIR}" \
      -DCMAKE_C_COMPILER="${REFUZZ_CC}" \
      -DCMAKE_CXX_COMPILER="${REFUZZ_CXX}" \
      ${REFUZZ_CMAKE_EXTRA:-} \
      >>"${VALIDATE_LOG}" 2>&1; then
  echo "[phase5-smoke] CMAKE CONFIGURE FAILED" | tee -a "${VALIDATE_LOG}"
  exit 2
fi
if ! cmake --build "${REFUZZ_BUILD_DIR}" -- -j"$(nproc)" >>"${VALIDATE_LOG}" 2>&1; then
  echo "[phase5-smoke] BUILD FAILED" | tee -a "${VALIDATE_LOG}"
  exit 2
fi
echo "[phase5-smoke] build OK" | tee -a "${VALIDATE_LOG}"

# ── Stage 1: executor run (optional) ────────────────────────────────────────
if [[ "${SKIP_EXECUTOR}" == "1" ]]; then
  echo "" | tee -a "${VALIDATE_LOG}"
  echo "[phase5-smoke] [Stage 1] SKIPPED (PHASE5_SKIP_EXECUTOR=1)" | tee -a "${VALIDATE_LOG}"
  echo "[phase5-smoke] PASS (executor skipped)" | tee -a "${VALIDATE_LOG}"
  exit 0
fi

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "[phase5-smoke] Stage 1 SKIPPED: config not found: ${CONFIG_PATH}" | tee -a "${VALIDATE_LOG}"
  echo "[phase5-smoke] PASS (executor skipped)" | tee -a "${VALIDATE_LOG}"
  exit 0
fi
if [[ ! -x "${RUNNER}" ]]; then
  echo "[phase5-smoke] Stage 1 FAILED: runner not found: ${RUNNER}" | tee -a "${VALIDATE_LOG}"
  exit 2
fi

echo "" | tee -a "${VALIDATE_LOG}"
echo "[phase5-smoke] [Stage 1] executor run (using fixed config) ..." | tee -a "${VALIDATE_LOG}"

if ! python3 - <<'PY' "${CONFIG_PATH}"
import json, sys
path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    json.load(f)
print('ok')
PY
then
  echo "[phase5-smoke] Stage 1 FAILED: invalid json config: ${CONFIG_PATH}" | tee -a "${VALIDATE_LOG}"
  exit 1
fi

set +e
if [[ "${TUI_MODE}" == "1" ]]; then
  if [[ "${TMUX_CHILD}" != "1" ]]; then
    {
      echo "[phase5-smoke] [Stage 1] TUI mode enabled"
      echo "[phase5-smoke] [Stage 1] dashboard owns /dev/tty; runner logs stream to ${RUN_LOG}"
    } | tee -a "${VALIDATE_LOG}"
  fi
  "${RUNNER}" "${CONFIG_PATH}" 2>&1 | tee "${RUN_LOG}" >/dev/null
  runner_code=${PIPESTATUS[0]}
else
  "${RUNNER}" "${CONFIG_PATH}" 2>&1 | tee "${RUN_LOG}"
  runner_code=${PIPESTATUS[0]}
fi
set -e

if [[ ${runner_code} -ne 0 ]]; then
  echo "[phase5-smoke] Stage 1 FAILED (runner code=${runner_code})" | tee -a "${VALIDATE_LOG}"
  echo "[phase5-smoke] inspect ${RUN_LOG}" | tee -a "${VALIDATE_LOG}"
  if [[ "${TUI_MODE}" == "1" ]]; then
    echo "[phase5-smoke] Stage 1 last runner log lines:" | tee -a "${VALIDATE_LOG}"
    tail -n 40 "${RUN_LOG}" | tee -a "${VALIDATE_LOG}" || true
  fi
  exit ${runner_code}
fi

# [v2 run_summary redesign] orchestrator 不再落 run_summary 单行到 host_events,
# 改成在 Stop() 结束时把 final RunSummary 写到 <session_root>/logs/run_summary.json。
# 这里用 jq 从 json 读字段,运行时不变式已由 orchestrator 侧执行并体现在
# .invariants.status 上。
if ! command -v jq >/dev/null 2>&1; then
  echo "[phase5-smoke] Stage 1 FAILED: jq not found on host" | tee -a "${VALIDATE_LOG}"
  exit 1
fi

# work_dir 来自 config;从 json 解析以避免 smoke 脚本硬写路径。
WORK_DIR="$(python3 - <<'PYWD' "${CONFIG_PATH}"
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    print(json.load(f).get('work_dir', ''), end='')
PYWD
)"
if [[ -z "${WORK_DIR}" ]]; then
  echo "[phase5-smoke] Stage 1 FAILED: config missing work_dir" | tee -a "${VALIDATE_LOG}"
  exit 1
fi

# 选最近一次 session 的 logs 目录。
SESSION_ROOT="$(ls -td "${WORK_DIR}"/run-* 2>/dev/null | head -n1 || true)"
SUMMARY_JSON="${SESSION_ROOT}/logs/run_summary.json"
if [[ -z "${SESSION_ROOT}" || ! -s "${SUMMARY_JSON}" ]]; then
  echo "[phase5-smoke] Stage 1 FAILED: run_summary.json not found (expected ${SUMMARY_JSON})" \
    | tee -a "${VALIDATE_LOG}"
  exit 1
fi

inv_status="$(jq -r .invariants.status "${SUMMARY_JSON}")"
if [[ "${inv_status}" != "ok" && "${inv_status}" != "disabled" ]]; then
  echo "[phase5-smoke] Stage 1 FAILED: invariants.status=${inv_status}" | tee -a "${VALIDATE_LOG}"
  jq -r '.invariants.failures // []' "${SUMMARY_JSON}" | tee -a "${VALIDATE_LOG}" || true
  exit 1
fi

# 读关键字段(jq 失败时默认 0,便于下面 arithmetic 不炸)。
jq_field() { jq -r ".fields.\"$1\" // 0" "${SUMMARY_JSON}"; }

generated="$(jq_field generated)"
completion="$(jq_field completion)"
abnormal="$(jq_field abnormal)"
fault="$(jq_field fault)"
terminal="$(jq_field terminal)"
crash="$(jq_field crash)"
elapsed_ms="$(jq_field elapsed_ms)"

if [[ "${generated}" -lt 1 || "${terminal}" -lt 1 ]]; then
  echo "[phase5-smoke] Stage 1 FAILED: no progress generated=${generated} terminal=${terminal}" \
    | tee -a "${VALIDATE_LOG}"
  exit 1
fi

echo "[phase5-smoke] Stage 1 PASS (summary=${SUMMARY_JSON})" | tee -a "${VALIDATE_LOG}"

# ── Final summary(给后续阶段 / retention 看)──────────────────────────────────
{
  echo "summary_json=${SUMMARY_JSON}"
  echo "invariant_status=${inv_status}"
  echo "generated=${generated}"
  echo "completion=${completion}"
  echo "abnormal=${abnormal}"
  echo "fault=${fault}"
  echo "terminal=${terminal}"
  echo "crash=${crash}"
  echo "elapsed_ms=${elapsed_ms}"
  echo "new_cov=$(jq_field new_cov)"
  echo "corpus_growth=$(jq_field corpus_growth)"
  echo "exec_s=$(jq_field exec_s)"
  echo "submit_rate_net=$(jq_field submit_rate_net)"
  echo "per_slot_rate=$(jq_field per_slot_rate)"
  echo "slot_count=$(jq_field slot_count)"
  echo "backoff_wait_s=$(jq_field backoff_wait_s)"
  echo "backoff_episodes=$(jq_field backoff_episodes)"
} | tee "${METRICS_LOG}"

echo "[phase5-smoke] PASS" | tee -a "${VALIDATE_LOG}"
echo "[phase5-smoke] validate_log=${VALIDATE_LOG}" | tee -a "${VALIDATE_LOG}"
echo "[phase5-smoke] run_log=${RUN_LOG}" | tee -a "${VALIDATE_LOG}"
echo "[phase5-smoke] metrics_log=${METRICS_LOG}" | tee -a "${VALIDATE_LOG}"
echo "[phase5-smoke] qemu_serial_log=${QEMU_SERIAL_LOG}" | tee -a "${VALIDATE_LOG}"

# ── Optional: render coverage_PC_series.log as a PNG ──────────────────────────
# Gated by config.coverage.export.enabled. The file is sampled every 10s and a
# final point is written at shutdown.
EXPORT_ENABLED="$(python3 - <<'PYEXP' "${CONFIG_PATH}"
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        root = json.load(f)
except Exception:
    print('0'); raise SystemExit(0)
cov = root.get('coverage', {})
exp = cov.get('export', {}) if isinstance(cov, dict) else {}
print('1' if isinstance(exp, dict) and exp.get('enabled', False) else '0')
PYEXP
)"

if [[ "${EXPORT_ENABLED}" == "1" ]]; then
  COVERAGE_LOG_PATH="${SESSION_ROOT}/logs/coverage_PC_series.log"
  PNG_PATH="${SESSION_ROOT}/logs/coverage_series.png"

  # ── vmlinux baseline:算 total instrumented PCs(分母),给 plot 算 % ──
  # 算法跟 syzkaller pkg/cover/backend/elf.go 一致:数 'call <__sanitizer_cov_trace_pc>'
  # callsite。一次 objdump ~12s 在 5.14 KASAN 上数到 ~689k。结果按 vmlinux mtime
  # 缓存到 <vmlinux>.total_pcs,后续 mtime 不变直接 hit。
  VMLINUX_PATH="$(python3 - <<'PYVMX' "${CONFIG_PATH}"
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        root = json.load(f)
    print(root.get('repro', {}).get('vmlinux_path', ''), end='')
except Exception:
    print('', end='')
PYVMX
)"
  TOTAL_PCS=0
  if [[ -n "${VMLINUX_PATH}" && -r "${VMLINUX_PATH}" ]]; then
    CACHE_FILE="${VMLINUX_PATH}.total_pcs"
    # 缓存有效条件:存在 + 比 vmlinux 新(避免内核重 build 后用旧数)
    if [[ -s "${CACHE_FILE}" && "${CACHE_FILE}" -nt "${VMLINUX_PATH}" ]]; then
      TOTAL_PCS="$(cat "${CACHE_FILE}")"
      echo "[phase5-smoke] vmlinux total PCs (cached): ${TOTAL_PCS}" \
        | tee -a "${VALIDATE_LOG}"
    else
      echo "[phase5-smoke] computing vmlinux total PCs (objdump, ~12s)..." \
        | tee -a "${VALIDATE_LOG}"
      TOTAL_PCS="$(objdump -d "${VMLINUX_PATH}" 2>/dev/null \
        | grep -cE 'call.*<__sanitizer_cov_trace_pc>' || echo 0)"
      if [[ "${TOTAL_PCS}" -gt 0 ]]; then
        echo "${TOTAL_PCS}" > "${CACHE_FILE}" 2>/dev/null || true
        echo "[phase5-smoke] vmlinux total PCs: ${TOTAL_PCS} (cached to ${CACHE_FILE})" \
          | tee -a "${VALIDATE_LOG}"
      fi
    fi
  else
    echo "[phase5-smoke] vmlinux not readable; skipping cov% baseline" \
      | tee -a "${VALIDATE_LOG}"
  fi

  if [[ -s "${COVERAGE_LOG_PATH}" ]]; then
    set +e
    python3 - <<'PYPLOT' "${COVERAGE_LOG_PATH}" "${PNG_PATH}" "${TOTAL_PCS}"
import sys

coverage_log_path = sys.argv[1]
png_path = sys.argv[2]
# total_pcs = 0 表示没分母,plot 退化为绝对 unique count(没 % 图)
total_pcs = int(sys.argv[3]) if len(sys.argv) > 3 else 0

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.stderr.write(
        "[phase5-smoke] matplotlib not installed; "
        "coverage log is at " + coverage_log_path + " — skip PNG render\n")
    raise SystemExit(0)

# Columns: # tick  all_pc  corpus_pc. Delta is derived offline for plotting.
ticks = []
series = {"all_pc": [], "corpus_pc": []}
with open(coverage_log_path, encoding="utf-8") as f:
    for line in f:
        if not line or line.startswith("#"):
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 3:
            continue
        tick, all_pc, corpus_pc = map(int, parts)
        ticks.append(tick)
        series["all_pc"].append(all_pc)
        series["corpus_pc"].append(corpus_pc)

if not ticks:
    sys.stderr.write(
        "[phase5-smoke] " + coverage_log_path + " has no rows — skip PNG render\n")
    raise SystemExit(0)

xs = [tick - ticks[0] for tick in ticks]

fig, (ax_unique, ax_delta) = plt.subplots(
    2, 1, figsize=(10, 6), sharex=True)

last_unique_summary = []
for sid in sorted(series):
    values = series[sid]
    deltas = [values[0]] + [max(0, values[i] - values[i - 1])
                            for i in range(1, len(values))]
    label = sid
    if total_pcs > 0:
        ys = [u * 100.0 / total_pcs for u in values]
        ax_unique.plot(xs, ys, label=label, linewidth=1.3)
        last_unique_summary.append((sid, values[-1], ys[-1]))
    else:
        ax_unique.plot(xs, values, label=label, linewidth=1.3)
        last_unique_summary.append((sid, values[-1], None))
    ax_delta.plot(xs, deltas, label=sid, linewidth=1.0)

if total_pcs > 0:
    ax_unique.set_ylabel("kernel coverage (%)")
    title = "kernel coverage vs vmlinux instrumented PCs (total=" + format(total_pcs, ',') + ")"
    summary_lines = [
        sid + ": " + format(u, ',') + " PCs (" + format(p, '.3f') + "%)"
        for sid, u, p in last_unique_summary
    ]
else:
    ax_unique.set_ylabel("unique covered PCs")
    title = "kernel coverage over time (no vmlinux baseline)"
    summary_lines = [sid + ": " + format(u, ',') + " PCs" for sid, u, _ in last_unique_summary]

ax_unique.set_title(title)
ax_unique.grid(True, alpha=0.3)
ax_unique.legend(loc="upper left")

ax_delta.set_ylabel("per-tick new PCs (delta)")
ax_delta.set_xlabel("elapsed time (s)")
ax_delta.grid(True, alpha=0.3)
ax_delta.legend(loc="upper left")

# 右上角文字注释 final number(let users see exact figure even if axis is %)
ax_unique.text(0.99, 0.05,
               "\n".join(summary_lines),
               transform=ax_unique.transAxes,
               ha='right', va='bottom',
               fontsize=8,
               bbox=dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='gray', alpha=0.8))

fig.tight_layout()
fig.savefig(png_path, dpi=120)
sys.stderr.write("[phase5-smoke] coverage plot written: " + png_path + "\n")
PYPLOT
    plot_rc=$?
    set -e
    if [[ ${plot_rc} -eq 0 && -s "${PNG_PATH}" ]]; then
      echo "[phase5-smoke] coverage_plot=${PNG_PATH}" | tee -a "${VALIDATE_LOG}"
    fi
  else
    echo "[phase5-smoke] coverage.export.enabled=true but ${COVERAGE_LOG_PATH} empty/missing — skip plot" \
      | tee -a "${VALIDATE_LOG}"
  fi
fi
