#!/bin/sh
# Collect one bounded guest-wide diagnostic profile and its exact /proc envelope.

set -eu

PREFIX="${1:-/tmp/guest-perf}"
DURATION="${2:-60}"
FREQUENCY="${3:-49}"
PERF_BIN="${PERF_BIN:-/usr/local/bin/perf}"

case "${DURATION}" in
    ''|*[!0-9]*|0) echo "duration must be a positive integer" >&2; exit 2 ;;
esac
case "${FREQUENCY}" in
    ''|*[!0-9]*|0) echo "frequency must be a positive integer" >&2; exit 2 ;;
esac
[ -x "${PERF_BIN}" ] || {
    echo "missing perf executable: ${PERF_BIN}" >&2
    exit 1
}

mkdir -p "$(dirname "${PREFIX}")"

snapshot_proc() {
    suffix="$1"
    cp /proc/stat "${PREFIX}.proc-stat.${suffix}"
    cp /proc/interrupts "${PREFIX}.interrupts.${suffix}"
    cp /proc/softirqs "${PREFIX}.softirqs.${suffix}"
    cp /proc/uptime "${PREFIX}.uptime.${suffix}"
}

{
    date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
    uname -a
    "${PERF_BIN}" --version
    printf 'duration_s=%s\nfrequency_hz=%s\n' "${DURATION}" "${FREQUENCY}"
    printf 'clk_tck=%s\n' "$(getconf CLK_TCK)"
    printf 'perf_event_paranoid='
    cat /proc/sys/kernel/perf_event_paranoid
} >"${PREFIX}.meta"

snapshot_proc before
set +e
"${PERF_BIN}" record -a -g -F "${FREQUENCY}" -e cpu-clock \
    -o "${PREFIX}.data" -- sleep "${DURATION}" \
    2>"${PREFIX}.record.stderr"
record_status=$?
set -e
snapshot_proc after

if [ "${record_status}" -ne 0 ]; then
    echo "perf record failed with status ${record_status}" >&2
    exit "${record_status}"
fi
[ -s "${PREFIX}.data" ] || {
    echo "perf produced an empty data file" >&2
    exit 1
}

cp /proc/kallsyms "${PREFIX}.kallsyms"
PERF_PAGER=cat "${PERF_BIN}" buildid-list -i "${PREFIX}.data" \
    >"${PREFIX}.buildids" 2>"${PREFIX}.buildids.stderr" || true
PERF_PAGER=cat "${PERF_BIN}" report --stdio --sort comm,dso,symbol \
    --percent-limit 0.1 -i "${PREFIX}.data" \
    >"${PREFIX}.report.txt" 2>"${PREFIX}.report.stderr"
sync
printf 'profile=%s.data\nreport=%s.report.txt\n' "${PREFIX}" "${PREFIX}"
