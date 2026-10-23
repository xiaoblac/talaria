#!/usr/bin/env bash
# Epic 6 PR-6-C — fault-injection module-boundary gate.
#
# Plan `docs/plans/syzkaller-capability-closure-epic-6.md` §6.2 binds
# the fault-inject algorithm helper to `mutator/linux/syz_v2/fault_inject/`
# and the orchestration to `control/{include,src}/.../stages/fault_injection_stage.{hpp,cpp}`
# + `control/src/stage/builtin_stages.cpp` (registry only). All other
# trees stay out.
#
# Two pattern families are enforced:
#
#   (1) ALGO_PATTERN — algorithm helper. mutator/ + tests/ + the
#       fault_injection_stage.cpp control-side single-call-site may
#       reference. (Unlike Epic 5 hints which goes through a
#       `IMutatorEngine::MutateWithHints` virtual, fault-inject is a
#       cross-cutting orchestrator helper called DIRECTLY from
#       fault_injection_stage's Producer/Consumer per plan §3 D-9 — no
#       new IMutatorEngine virtual added; that would be API inflation
#       for what is a pure clone+set helper. Allowlist explicit + tight.)
#       `MakeFaultInjectVariant` is the sole free function exposed.
#
#   (2) TYPE_PATTERN — control-side types + algorithm subdir path
#       substring. `FaultInjectionInflightRegistry` /
#       `FaultInjectionInflightEntry` / `kFaultInjectMaxNth` /
#       `FaultInjectionConsumerStage` are control-internal.
#       `mutator/linux/syz_v2/fault_inject` path is the algorithm subdir.
#       Allowlist restricts these to the fault_injection_stage files +
#       the registry-only include site in builtin_stages.cpp.
#
# Scan covers feedback/ + executor/ + program/ + control/. mutator/ +
# tests/ are out-of-scope (definers / parity oracles).
#
# Active-code projection mirrors `tools/check_hints_module_boundaries.sh`:
# skip `#if 0`...`#endif` blocks and full-line `//` comments.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCAN_DIRS=(
    "${REPO_ROOT}/feedback"
    "${REPO_ROOT}/control"
    "${REPO_ROOT}/executor"
    "${REPO_ROOT}/program"
    # PR-6-D review fix — corpus/ added to SCAN_DIRS. The original P1 review
    # found that corpus_disk_io.cpp directly inspected typed syz views to
    # check FailNth, breaking the artifact.hpp:111 D2 contract. The gate
    # now lives in the syz-owned materializer, not corpus. Including
    # corpus/ here ensures future leaks of fault-injection symbols
    # (MakeFaultInjectVariant / kFaultInjectMaxNth / FaultInjectionInflight*)
    # into corpus/ are caught at lint time. (A broader corpus-must-not-
    # include-syz/ lint is a separate cleanup outside Epic 6 scope.)
    "${REPO_ROOT}/corpus"
)

# Pattern (1): algorithm helper — mutator-private + fault_injection_stage.cpp single-site.
ALGO_PATTERN='MakeFaultInjectVariant'

# Allowlist for ALGO_PATTERN: only fault_injection_stage.cpp may call it
# from the control/ tree (Producer + Consumer). Tightened from "no
# allowlist" pattern of hints because the design is direct-call (no
# IMutatorEngine virtual) per plan §3 D-9.
ALGO_ALLOWLIST=(
    "${REPO_ROOT}/control/src/stages/fault_injection_stage.cpp"
    # [job-loop Step 4a] fault-inject dependent loop migrated stage → job:
    # MakeFaultJob is the new sanctioned direct-call site (same direct-call
    # design per plan §3 D-9; the stage remains until Step 6 flag-off cleanup).
    "${REPO_ROOT}/control/src/job/fault_job.cpp"
)

# Pattern (2): types + path — control-allowlisted.
TYPE_PATTERN='FaultInjectionInflightRegistry|FaultInjectionInflightEntry|kFaultInjectMaxNth|FaultInjectionConsumerStage|mutator/linux/syz_v2/fault_inject'

# Allowlist for TYPE_PATTERN: file path substrings that may legitimately
# reference the fault-injection control types or algorithm subdir path.
TYPE_ALLOWLIST=(
    # Epic 6 PR-6-C: FaultInjectionConsumerStage + FaultInjectionProducerStage
    # live in fault_injection_stage; builtin_stages.cpp registers + shares
    # the inflight registry via shared_state.
    "${REPO_ROOT}/control/include/refuzz/control/stages/fault_injection_stage.hpp"
    "${REPO_ROOT}/control/src/stages/fault_injection_stage.cpp"
    "${REPO_ROOT}/control/src/stage/builtin_stages.cpp"
    # [job-loop Step 4a] fault-inject dependent loop migrated stage → job.
    # fault_job.{hpp,cpp} legitimately reference the fault_inject algo subdir
    # (MakeFaultInjectVariant include) + mirror kFaultInjectMaxNth as max_nth.
    "${REPO_ROOT}/control/include/refuzz/control/job/fault_job.hpp"
    "${REPO_ROOT}/control/src/job/fault_job.cpp"
)

is_path_allowlisted() {
    local file="$1"
    shift
    local entry
    for entry in "$@"; do
        if [[ "${file}" == "${entry}" ]]; then
            return 0
        fi
    done
    return 1
}

scan_active_hits() {
    local file="$1"
    local pattern="$2"
    awk -v fname="${file}" -v pattern="${pattern}" '
        BEGIN { in_if0 = 0 }
        /^[[:space:]]*#if[[:space:]]+0([[:space:]]|$)/ { in_if0 = 1; next }
        in_if0 == 1 && /^[[:space:]]*#endif/           { in_if0 = 0; next }
        in_if0 == 1                                     { next }
        /^[[:space:]]*\/\//                             { next }
        $0 ~ pattern                                    { print fname ":" NR ":" $0 }
    ' "${file}"
}

violations=0

for dir in "${SCAN_DIRS[@]}"; do
    if [[ ! -d "${dir}" ]]; then
        continue
    fi
    while IFS= read -r -d '' file; do
        # Pattern (1): algorithm helper — allowlisted for fault_injection_stage.cpp single-site.
        algo_hits=$(scan_active_hits "${file}" "${ALGO_PATTERN}")
        if [[ -n "${algo_hits}" ]]; then
            if ! is_path_allowlisted "${file}" "${ALGO_ALLOWLIST[@]}"; then
                echo "FORBIDDEN active fault-inject-algorithm-symbol ref(s) in ${file} (not in algo allowlist):" >&2
                echo "${algo_hits}" >&2
                violations=$((violations + 1))
            fi
        fi

        # Pattern (2): types + path — allowlisted for fault_injection_stage files.
        type_hits=$(scan_active_hits "${file}" "${TYPE_PATTERN}")
        if [[ -n "${type_hits}" ]]; then
            if ! is_path_allowlisted "${file}" "${TYPE_ALLOWLIST[@]}"; then
                echo "FORBIDDEN active fault-inject-type ref(s) in ${file} (not in type allowlist):" >&2
                echo "${type_hits}" >&2
                violations=$((violations + 1))
            fi
        fi
    done < <(find "${dir}" \
        \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.cc' \
           -o -name '*.c' \) \
        -print0)
done

if (( violations > 0 )); then
    echo "FAIL: PR-6-C fault-injection module-boundary violations — see above" >&2
    exit 1
fi

echo "OK: feedback/ control/ executor/ program/ corpus/ — MakeFaultInjectVariant mutator-private; FaultInjectionInflight*/Consumer/kFaultInjectMaxNth scoped to control/.../fault_injection_stage.{hpp,cpp} + builtin_stages.cpp"
