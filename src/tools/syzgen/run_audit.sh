#!/bin/sh
# Phase A audit wrapper used by the refuzz-syz-audit CMake target.
# Args:
#   $1  go executable
#   $2  reFuzz source root (must contain .syzkaller-pin and tools/syzgen)
#   $3  syzkaller checkout root
#   $4  reports output directory
#
# All it does is exec `tools/syzgen audit` with the canonical Phase A
# argument set and a pinned, timestamped output filename. There must not
# be a second audit implementation in this script.

set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <go> <refuzz-root> <syzkaller-root> <reports-dir>" >&2
    exit 2
fi

GO_EXEC="$1"
REFUZZ_ROOT="$2"
SYZ_ROOT="$3"
REPORTS_DIR="$4"

PIN_FILE="${REFUZZ_ROOT}/.syzkaller-pin"
if [ ! -r "${PIN_FILE}" ]; then
    echo "missing pin file ${PIN_FILE}" >&2
    exit 1
fi

PIN="$(cat "${PIN_FILE}")"
UTC="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${REPORTS_DIR}"
OUT="${REPORTS_DIR}/phase_a_audit_linux-amd64_${PIN}_${UTC}.json"

cd "${REFUZZ_ROOT}"
exec "${GO_EXEC}" run ./tools/syzgen audit \
    -os linux -arch amd64 \
    -syzkaller-root "${SYZ_ROOT}" \
    -out "${OUT}" \
    -pin-file "${PIN_FILE}"
