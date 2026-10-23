#!/usr/bin/env bash
# Epic 5 PR-5-C/D — hints module-boundary gate.
#
# Plan `docs/plans/syzkaller-capability-closure-epic-5.md` §6.2 binds
# the hints algorithm to `mutator/linux/syz_v2/hints/`. PR-5-D landed
# `control/src/stages/hints_stage.{hpp,cpp}` as the SOLE legitimate
# consumer outside mutator/ + tests/.
#
# Two pattern families are enforced:
#
#   (1) ALGO_PATTERN — algorithm helpers; ONLY mutator/ + tests/ may
#       reference. Includes MutateProgWithHints / GenerateArgHints /
#       Check{Const,Data,Compressed}ArgHints / ShrinkExpand /
#       CompressImage / MustDecompressImage / IsSpecialInt.
#       NO allowlist — control/ goes through `IMutatorEngine::MutateWithHints`,
#       not these helpers directly.
#
#   (2) TYPE_PATTERN — types + path substring; mutator/ + tests/ +
#       `control/{include,src}/.../stages/hints_stage.{hpp,cpp}` plus the
#       job-loop hints job only.
#       Includes CompMap / HintsLimiter / `mutator/linux/syz_v2/hints`
#       path substring. HintsConsumerStage uses CompMap + HintsLimiter
#       legitimately; everywhere else in control/ stays out.
#
# Scan covers feedback/ + executor/ + program/ + control/. mutator/ +
# tests/ are out-of-scope (definers / parity oracles).
#
# Active-code projection mirrors `tools/check_coverage_series_module_boundaries.sh`:
# skip `#if 0`...`#endif` blocks and full-line `//` comments.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCAN_DIRS=(
    "${REPO_ROOT}/feedback"
    "${REPO_ROOT}/control"
    "${REPO_ROOT}/executor"
    "${REPO_ROOT}/program"
)

# Pattern (1): algorithm helpers — mutator-private. NO allowlist.
# NOTE: CompressImage 用词边界前缀 (^|[^[:alnum:]_]) 匹配,避免子串误伤同名后缀的
# 无关函数(如 mount 模块的 ZstdCompressImage —— 不是 hints 的 image_zlib::CompressImage)。
ALGO_PATTERN='MutateProgWithHints|GenerateArgHints|CheckConstArgHints|CheckDataArgHints|CheckCompressedArgHints|ShrinkExpand|(^|[^[:alnum:]_])CompressImage|MustDecompressImage|IsSpecialInt'

# Pattern (2): types + path — control-allowlisted only for hints stage/job files.
TYPE_PATTERN='CompMap|HintsLimiter|mutator/linux/syz_v2/hints'

# Allowlist for TYPE_PATTERN: file path substrings that may legitimately
# reference CompMap / HintsLimiter / the hints subtree path. Each entry
# is a substring matched against the absolute file path.
TYPE_ALLOWLIST=(
    # Epic 5 PR-5-D: legacy HintsConsumerStage + HintsProducerStage.
    "${REPO_ROOT}/control/include/refuzz/control/stages/hints_stage.hpp"
    "${REPO_ROOT}/control/src/stages/hints_stage.cpp"
    # [job-loop Step 5] hints job owns collect-comps decode/intersect/limit and
    # emits hint-derived variants through ctx.emit.
    "${REPO_ROOT}/control/src/job/hints_job.cpp"
)

is_type_allowlisted() {
    local file="$1"
    local entry
    for entry in "${TYPE_ALLOWLIST[@]}"; do
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
        # Pattern (1): algorithm helpers — strict, no exceptions.
        algo_hits=$(scan_active_hits "${file}" "${ALGO_PATTERN}")
        if [[ -n "${algo_hits}" ]]; then
            echo "FORBIDDEN active hints-algorithm-symbol ref(s) in ${file}:" >&2
            echo "${algo_hits}" >&2
            violations=$((violations + 1))
        fi

        # Pattern (2): types + path — allowlisted for hints_stage files.
        type_hits=$(scan_active_hits "${file}" "${TYPE_PATTERN}")
        if [[ -n "${type_hits}" ]]; then
            if ! is_type_allowlisted "${file}"; then
                echo "FORBIDDEN active hints-type ref(s) in ${file} (not in allowlist):" >&2
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
    echo "FAIL: PR-5-C/D hints module-boundary violations — see above" >&2
    exit 1
fi

echo "OK: feedback/ control/ executor/ program/ — algorithm helpers mutator-private; CompMap/HintsLimiter/path scoped to hints stage/job allowlist"
