#!/usr/bin/env bash
# Build a guest-compatible perf from the same source version as the test kernel.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KERNEL_SRC="${KERNEL_SRC:-/workspace/syzkaller/kernel/linux-6.19.13}"
BUILD_ROOT="${BUILD_ROOT:-${ROOT_DIR}/build-guest-perf}"
OBJ_DIR="${OBJ_DIR:-${BUILD_ROOT}/obj}"
OUTPUT_BIN="${OUTPUT_BIN:-${BUILD_ROOT}/perf}"
MAKE_JOBS="${MAKE_JOBS:-8}"

log() { echo "[$(date +%H:%M:%S)] build-guest-perf: $*" >&2; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

preflight() {
    [ -f "${KERNEL_SRC}/tools/perf/Makefile" ] || \
        die "invalid kernel source: ${KERNEL_SRC}"
    command -v make >/dev/null || die "make is required"
    command -v strip >/dev/null || die "strip is required"
    command -v ldd >/dev/null || die "ldd is required"
    command -v sha256sum >/dev/null || die "sha256sum is required"
    [[ "${MAKE_JOBS}" =~ ^[1-9][0-9]*$ ]] || \
        die "MAKE_JOBS must be a positive integer"
}

build_perf() {
    mkdir -p "${OBJ_DIR}" "$(dirname "${OUTPUT_BIN}")"
    local build_log="${BUILD_ROOT}/build.log"
    log "building from ${KERNEL_SRC}"
    if ! make -C "${KERNEL_SRC}/tools/perf" \
        O="${OBJ_DIR}" -j"${MAKE_JOBS}" WERROR=0 \
        NO_LIBPYTHON=1 NO_LIBPERL=1 NO_SLANG=1 NO_GTK2=1 \
        NO_LIBNUMA=1 NO_LIBUNWIND=1 NO_LIBDW=1 \
        NO_LIBDW_DWARF_UNWIND=1 NO_LIBTRACEEVENT=1 \
        NO_LIBBPF=1 NO_LIBLLVM=1 NO_DEMANGLE=1 NO_LZMA=1 \
        NO_AIO=1 NO_JVMTI=1 NO_CAPSTONE=1 NO_LIBPFM4=1 \
        NO_LIBDEBUGINFOD=1 BUILD_BPF_SKEL=0 \
        >"${build_log}" 2>&1; then
        tail -n 80 "${build_log}" >&2 || true
        die "perf build failed; see ${build_log}"
    fi

    local temporary_bin="${OUTPUT_BIN}.tmp.$$"
    strip --strip-unneeded -o "${temporary_bin}" "${OBJ_DIR}/perf"
    chmod 0755 "${temporary_bin}"
    mv -f "${temporary_bin}" "${OUTPUT_BIN}"
}

verify_perf() {
    [ -x "${OUTPUT_BIN}" ] || die "missing built perf: ${OUTPUT_BIN}"
    local kernel_version perf_version
    kernel_version=$(make -s -C "${KERNEL_SRC}" kernelversion)
    perf_version=$("${OUTPUT_BIN}" --version)
    [ "${perf_version}" = "perf version ${kernel_version}" ] || \
        die "version mismatch: kernel=${kernel_version}, ${perf_version}"

    local dependencies
    dependencies=$(ldd "${OUTPUT_BIN}")
    if printf '%s\n' "${dependencies}" | grep -q 'not found'; then
        printf '%s\n' "${dependencies}" >&2
        die "built perf has unresolved host dependencies"
    fi
    if printf '%s\n' "${dependencies}" | \
        grep -Eq 'libpython|libdw|libLLVM|libstdc\+\+|libtraceevent|libnuma'; then
        printf '%s\n' "${dependencies}" >&2
        die "built perf retained a dependency absent from the guest image"
    fi
    local commands
    commands=$("${OUTPUT_BIN}" --help 2>&1)
    printf '%s\n' "${commands}" | grep -q '^   record '
    printf '%s\n' "${commands}" | grep -q '^   report '
    log "verified ${perf_version}: $(sha256sum "${OUTPUT_BIN}" | cut -d' ' -f1)"
}

preflight
build_perf
verify_perf
printf '%s\n' "${OUTPUT_BIN}"
