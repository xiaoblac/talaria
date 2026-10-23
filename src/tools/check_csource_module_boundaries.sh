#!/usr/bin/env bash
# Epic 4 PR-4-A — csource module-boundary structural test.
#
# csource module (crash/repro/csource/) MUST NOT include
# refuzz/mutator/... or refuzz/control/.... It may only depend on
# refuzz/program/syz/..., refuzz/crash/..., refuzz/core/...
#
# Per Epic 4 plan §3 (binding) and target_ownership.md §6.4. Run from
# CI (or as a CTest case post-PR-4-D) to keep the layer separation
# enforced.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSOURCE_ROOT="${REPO_ROOT}/crash/repro/csource"

if [[ ! -d "${CSOURCE_ROOT}" ]]; then
    echo "csource module dir not found at ${CSOURCE_ROOT}" >&2
    exit 1
fi

violations=0

scan_for_forbidden_includes() {
    local subtree="$1"
    local forbidden_pattern="$2"
    local label="$3"

    local hits
    hits=$(grep -rnE "${forbidden_pattern}" "${subtree}" \
        --include='*.hpp' --include='*.cpp' --include='*.h' --include='*.cc' \
        2>/dev/null || true)
    if [[ -n "${hits}" ]]; then
        echo "FORBIDDEN ${label} include in csource module:" >&2
        echo "${hits}" >&2
        violations=$((violations + 1))
    fi
}

# Match both quoted ("refuzz/...") and angle-bracket (<refuzz/...>)
# include forms. Bash regex character class allows either delimiter.
scan_for_forbidden_includes "${CSOURCE_ROOT}" \
    '#include[[:space:]]+["<]refuzz/mutator/' "mutator"
scan_for_forbidden_includes "${CSOURCE_ROOT}" \
    '#include[[:space:]]+["<]refuzz/control/' "control"

if (( violations > 0 )); then
    echo "FAIL: ${violations} module-boundary violation(s) in csource module" >&2
    exit 1
fi

echo "OK: crash/repro/csource/ has no forbidden includes"
