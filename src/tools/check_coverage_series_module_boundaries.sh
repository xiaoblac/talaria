#!/usr/bin/env bash
# PR-K-D (kcov-coverage-curve plan §1.2 Corollary D #2 / §7.2) —
# coverage-series module boundary gate.
#
# Per Rule R-2 (§1): "coverage-series state lives only in telemetry/.
# feedback/, control/, mutator/, and the worker remain ignorant of
# series existence — they continue emitting counters as today; the
# series is an *adapter* over those counters, owned by
# ObservabilityProjector."
#
# This gate enforces that contract: feedback/, control/, mutator/, and
# executor/ source trees contain ZERO active references to the four
# series symbols. Only telemetry/ and tests/ may name them.
#
# Patterns:
#   * CoverageSeriesId      — the typed series-id wrapper
#   * coverage_series       — generic snake_case substring (catches
#                             coverage_series_capacity / coverage_series_logs_dir
#                             / a hypothetical CoverageSeriesSink misuse —
#                             but NOT CoverageSeriesSink type uses
#                             that should also be confined to telemetry/)
#   * RegisterCoverageSeries — registration entry point
#   * CoverageSamplePoint    — sample value type
#
# Active-code projection (same shape as the other coverage gates):
# skip `#if 0`...`#endif` blocks, full-line `//` comments, and full-line
# `# ` CMake/whitespace-prefixed comments. C/C++ preprocessor directives
# stay visible (an active `#include "...coverage_series.hpp"` in
# control/ would trip the gate, which is the desired behavior).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCAN_DIRS=(
    "${REPO_ROOT}/feedback"
    "${REPO_ROOT}/control"
    "${REPO_ROOT}/mutator"
    "${REPO_ROOT}/executor"
)

PATTERN='CoverageSeriesId|coverage_series|RegisterCoverageSeries|CoverageSamplePoint'

# Active-code projection. C/C++ files only — no shell-style `# comment`
# filter, because in *.c/.cpp/.h/.hpp the `#` column is always a
# preprocessor directive (`#include`, `#if 1`, `#define`, ...). The
# `#if 0`...`#endif` block is the one preprocessor form we DO want to
# treat as inactive; everything else stays visible.
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
        # Some trees may not have all four (e.g., a slim checkout); not fatal.
        continue
    fi
    while IFS= read -r -d '' file; do
        active_hits=$(scan_active_hits "${file}" "${PATTERN}")
        if [[ -n "${active_hits}" ]]; then
            echo "FORBIDDEN active series-symbol ref(s) in ${file}:" >&2
            echo "${active_hits}" >&2
            violations=$((violations + 1))
        fi
    done < <(find "${dir}" \
        \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.cc' \
           -o -name '*.c' \) \
        -print0)
done

if (( violations > 0 )); then
    echo "FAIL: PR-K-D coverage-series module-boundary violations — see above" >&2
    exit 1
fi

echo "OK: feedback/ control/ mutator/ executor/ have no active series-symbol references"
