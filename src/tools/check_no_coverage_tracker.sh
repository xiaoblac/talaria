#!/usr/bin/env bash
# PR-K-0 (kcov-coverage-curve plan §4.4) — telemetry::CoverageTracker
# / core::ICoverageSink module-boundary gate.
#
# After PR-K-0, the duplicate aggregate truth-store
# (telemetry::CoverageTracker) and its sink interface
# (core::ICoverageSink) are gone. This script enforces that no active
# (non-commented, non-`#if 0`-gated) source line anywhere in
# core/, feedback/, control/, telemetry/, or tests/ re-introduces them.
#
# Per Rule A in docs/plans/kcov-coverage-curve.md §1.2:
#   "Coverage truth — the set of unique hashes seen by a run — and its
#    persistence are owned exclusively by feedback/."
#
# Scope rationale (vs plan §4.4 wording):
#   The plan listed feedback/ + control/ + telemetry/.../observation/
#   as the scan dirs. We additionally scan core/ + telemetry/coverage
#   + tests/ so that a future "rollback" — flipping the `#if 0`
#   surrounding the v1 deletion bodies in core/coverage.hpp or
#   telemetry/coverage/coverage_tracker.{hpp,cpp} back to `#if 1` — is
#   caught by this gate, not silently re-enabled.
#
# Inactive-code projection (per file):
#   1. `#if 0` ... `#endif` blocks are skipped (rollback bodies live
#      here today; flipping the directive exposes them and trips this
#      gate).
#   2. Full-line C++ `// ...` comments are skipped (line-leading,
#      whitespace-tolerant).
#   3. Full-line CMake `# ...` comments are skipped — note the
#      *required space* after `#`, so C/C++ preprocessor directives
#      like `#include`, `#if 1`, `#define` stay visible.
#
# A subsequent PR (PR-K-D) lands a complementary gate
# (check_coverage_series_module_boundaries.sh) for the new
# CoverageSeriesId substrate; this gate is purely about removing the
# old debt.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Scan dirs cover both the "no new references" surface (feedback/,
# control/, telemetry/non-coverage) and the rollback-trip surface
# (core/, telemetry/coverage, tests/).
SCAN_DIRS=(
    "${REPO_ROOT}/core"
    "${REPO_ROOT}/feedback"
    "${REPO_ROOT}/control"
    "${REPO_ROOT}/telemetry"
    "${REPO_ROOT}/tests"
)

# All symbols PR-K-0 retired. Each one in active code is a violation.
#   * CoverageTracker / ICoverageSink   — removed types
#   * coverage_tracker / coverage_sink  — removed field / parameter names
#   * OnCoverageHashes                  — removed virtual method
PATTERN='CoverageTracker|ICoverageSink|coverage_tracker|coverage_sink|OnCoverageHashes'

violations=0

# Print pattern hits in active code from $1 as `path:lineno:content`.
# Active = not inside `#if 0`...`#endif`, not a full-line `//` C++
# comment. C/C++ scope only (no CMake here), so lines starting with
# `#` are always preprocessor directives — never comments — and the
# `#if 0`...`#endif` strip is the one directive form we treat as
# inactive. `#include`, `#define`, `#if 1`, `# include` (legal
# whitespace-after-`#` form) all stay visible to grep.
#
# The pattern match runs INSIDE awk against the line content `$0` only
# — never against the filename prefix — so a path that itself contains
# substrings like "coverage_tracker" cannot create false positives.
scan_active_hits() {
    local file="$1"
    awk -v fname="${file}" -v pattern="${PATTERN}" '
        BEGIN { in_if0 = 0 }
        /^[[:space:]]*#if[[:space:]]+0([[:space:]]|$)/ { in_if0 = 1; next }
        in_if0 == 1 && /^[[:space:]]*#endif/           { in_if0 = 0; next }
        in_if0 == 1                                     { next }
        /^[[:space:]]*\/\//                             { next }
        $0 ~ pattern                                    { print fname ":" NR ":" $0 }
    ' "${file}"
}

for dir in "${SCAN_DIRS[@]}"; do
    if [[ ! -d "${dir}" ]]; then
        echo "scan dir missing: ${dir}" >&2
        exit 1
    fi

    # Iterate every relevant C++ source file under the dir. CMakeLists.txt
    # and *.cmake are intentionally excluded — those carry test names /
    # script paths (e.g. `add_test(... check_no_coverage_tracker.sh)`)
    # that legitimately mention the symbol substring, but cannot
    # introduce a real C++ semantic dependency. The PR-K-0 deletion files
    # (telemetry/CMakeLists.txt comment + the v1 #if 0 wrap in core/
    # telemetry headers) are already protected by D-6 commenting + the
    # `#if 0` strip.
    while IFS= read -r -d '' file; do
        active_hits=$(scan_active_hits "${file}")
        if [[ -n "${active_hits}" ]]; then
            echo "FORBIDDEN active ref(s) in ${file}:" >&2
            echo "${active_hits}" >&2
            violations=$((violations + 1))
        fi
    done < <(find "${dir}" \
        \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.cc' \
           -o -name '*.c' \) \
        -print0)
done

if (( violations > 0 )); then
    echo "FAIL: PR-K-0 module-boundary violations — see above" >&2
    exit 1
fi

echo "OK: no active references to CoverageTracker / ICoverageSink / coverage_sink / OnCoverageHashes"
