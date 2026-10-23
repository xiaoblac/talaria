#!/usr/bin/env bash
# PR-K-B (kcov-coverage-curve plan §1.2 Corollary D #1) — render-binding gate.
#
# Per Rule B (§1.2): renderer code does NOT read coverage data by metric
# name. All coverage display flows through the CoverageSeriesDescriptor
# indirection (RegisteredSeries + LatestSeriesPoint + SeriesSnapshot).
#
# Scope (deviation from plan §1.2 Corollary D #1 literal "telemetry/"):
# Rule E (§1.2) explicitly exempts non-renderer consumers — RunSummary,
# RunSummaryJsonSink, and any policy / control / feedback code that
# reads `fuzzer.cov.*` for non-display purposes. Policy code in
# telemetry/policy/ falls under that spirit (not display, just policy
# decisions). The gate therefore enumerates renderer files
# explicitly rather than scanning all of telemetry/. This is also
# robust against PR-K-A's projector binding (which legitimately names
# the metrics `fuzzer.cov.new_total` / `fuzzer.cov.unique` once at
# RegisterBuiltinCoverageSeries — that IS the adapter definition).
#
# Files in scope:
#   * telemetry/src/observation/run_state_renderer.cpp (live terminal display)
#
# Patterns forbidden in the in-scope files (active code only):
#   * `fuzzer\.cov\.` — any direct mention of the metric name
#   * `CounterValue.*fuzzer\.cov` — the helper-form lookup
#
# Active-code projection (same shape as check_no_coverage_tracker.sh):
# skip `#if 0`...`#endif` blocks, full-line `//` comments, and full-line
# `# ` CMake/whitespace-prefixed comments.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RENDER_SINK_FILES=(
    "telemetry/src/observation/run_state_renderer.cpp"
)

PATTERN='fuzzer\.cov\.|CounterValue.*fuzzer\.cov'

# Active-code projection. C/C++ files only (RENDER_SINK_FILES are .cpp);
# `#` lines are preprocessor directives, never comments, so we only
# strip `#if 0`...`#endif` blocks and full-line `//` comments.
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

for relpath in "${RENDER_SINK_FILES[@]}"; do
    file="${REPO_ROOT}/${relpath}"
    if [[ ! -f "${file}" ]]; then
        # Allow listed-but-not-yet-landed files (e.g., PR-K-C sink).
        continue
    fi
    hits=$(scan_active_hits "${file}" "${PATTERN}")
    if [[ -n "${hits}" ]]; then
        echo "FORBIDDEN active fuzzer.cov.* / CounterValue(fuzzer.cov.*) ref(s) in ${file}:" >&2
        echo "${hits}" >&2
        violations=$((violations + 1))
    fi
done

if (( violations > 0 )); then
    echo "FAIL: PR-K-B render-binding violations — see above" >&2
    exit 1
fi

echo "OK: renderer is descriptor-driven; no active fuzzer.cov.* references"
