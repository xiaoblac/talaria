#!/usr/bin/env bash
# Build the dedicated Syzkaller capture image used by perf_sampling.sh.
# The source image is never modified. The destination receives the patched
# Syzkaller executor, FlatRPC capture proxy, and target-side wrapper.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYZKALLER_DIR="${SYZKALLER_DIR:-/workspace/syzkaller}"
IMAGE_SRC="${IMAGE_SRC:-${ROOT_DIR}/run/speed_compare/images/syz_rootfs.img}"
IMAGE_DST="${IMAGE_DST:-${ROOT_DIR}/run/speed_compare/images/syz_exec_perf_rootfs.img}"
SYZ_EXECUTOR_BIN="${SYZ_EXECUTOR_BIN:-${SYZKALLER_DIR}/bin/linux_amd64/syz-executor}"
SYZ_FLATRPC_PROXY_BIN="${SYZ_FLATRPC_PROXY_BIN:-${ROOT_DIR}/build-llvm20/syz_flatrpc_proxy}"
WRAPPER_SRC="${WRAPPER_SRC:-${ROOT_DIR}/scripts/pc_compare/syz_executor_proxied_wrapper.sh}"
GUEST_PERF_BUILD_SCRIPT="${GUEST_PERF_BUILD_SCRIPT:-${ROOT_DIR}/scripts/perf_compare/build_guest_perf.sh}"
GUEST_PERF_BIN="${GUEST_PERF_BIN:-${ROOT_DIR}/build-guest-perf/perf}"
PERF_CAPTURE_SRC="${PERF_CAPTURE_SRC:-${ROOT_DIR}/scripts/perf_compare/guest_perf_capture.sh}"

log() { echo "[$(date +%H:%M:%S)] prepare-syz-image: $*" >&2; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

verify_guest_file() {
    local image="$1"
    local guest_path="$2"
    local source_path="$3"
    local dump_dir="$4"
    local dumped
    dumped="${dump_dir}/$(basename "${guest_path}")"
    local stat_output
    stat_output=$(debugfs -R "stat ${guest_path}" "${image}" 2>&1) || return 1
    printf '%s\n' "${stat_output}" | grep -q 'Mode:  0755' || return 1
    debugfs -R "dump ${guest_path} ${dumped}" "${image}" >/dev/null 2>&1 || return 1
    cmp -s "${source_path}" "${dumped}"
}

verify_image() (
    local image="$1"
    [ -f "${image}" ] || return 1
    local dump_dir
    dump_dir=$(mktemp -d /tmp/refuzz-syz-image-check.XXXXXX)
    trap 'rm -rf "${dump_dir}"' EXIT
    verify_guest_file "${image}" /usr/local/bin/syz-executor \
        "${SYZ_EXECUTOR_BIN}" "${dump_dir}" || return 1
    verify_guest_file "${image}" /usr/local/bin/syz_flatrpc_proxy \
        "${SYZ_FLATRPC_PROXY_BIN}" "${dump_dir}" || return 1
    verify_guest_file "${image}" /usr/local/bin/syz-executor-proxied \
        "${WRAPPER_SRC}" "${dump_dir}" || return 1
    verify_guest_file "${image}" /usr/local/bin/perf \
        "${GUEST_PERF_BIN}" "${dump_dir}" || return 1
    verify_guest_file "${image}" /usr/local/bin/guest-perf-capture \
        "${PERF_CAPTURE_SRC}" "${dump_dir}" || return 1
    debugfs -R 'stat /refuzz_trace_out' "${image}" 2>&1 | grep -q 'Type: directory'
)

preflight() {
    command -v debugfs >/dev/null || die "debugfs is required"
    command -v cmp >/dev/null || die "cmp is required"
    [ -x "${GUEST_PERF_BUILD_SCRIPT}" ] || \
        die "missing perf build script: ${GUEST_PERF_BUILD_SCRIPT}"
    if [ ! -x "${GUEST_PERF_BIN}" ]; then
        "${GUEST_PERF_BUILD_SCRIPT}" >/dev/null
    fi
    local path
    for path in "${IMAGE_SRC}" "${SYZ_EXECUTOR_BIN}" \
                "${SYZ_FLATRPC_PROXY_BIN}" "${WRAPPER_SRC}" \
                "${GUEST_PERF_BIN}" "${PERF_CAPTURE_SRC}"; do
        [ -f "${path}" ] || die "missing input: ${path}"
    done
    [ "$(readlink -f "${IMAGE_SRC}")" != "$(readlink -m "${IMAGE_DST}")" ] || \
        die "IMAGE_DST must differ from IMAGE_SRC"
}

build_image() {
    if [ -e "${IMAGE_DST}" ] && [ "${FORCE:-0}" != "1" ]; then
        if verify_image "${IMAGE_DST}"; then
            log "already prepared: ${IMAGE_DST}"
            return
        fi
        die "destination exists but verification failed; rerun with FORCE=1"
    fi

    mkdir -p "$(dirname "${IMAGE_DST}")"
    local temporary_image="${IMAGE_DST}.tmp.$$"
    rm -f "${temporary_image}"
    trap 'rm -f "${temporary_image}"' EXIT
    log "copying ${IMAGE_SRC} to ${IMAGE_DST}"
    cp --reflink=auto --sparse=always "${IMAGE_SRC}" "${temporary_image}"

    local commands="${IMAGE_DST}.debugfs.$$"
    cat > "${commands}" <<EOF
write ${SYZ_EXECUTOR_BIN} /usr/local/bin/syz-executor
set_inode_field /usr/local/bin/syz-executor mode 0100755
set_inode_field /usr/local/bin/syz-executor uid 0
set_inode_field /usr/local/bin/syz-executor gid 0
write ${SYZ_FLATRPC_PROXY_BIN} /usr/local/bin/syz_flatrpc_proxy
set_inode_field /usr/local/bin/syz_flatrpc_proxy mode 0100755
set_inode_field /usr/local/bin/syz_flatrpc_proxy uid 0
set_inode_field /usr/local/bin/syz_flatrpc_proxy gid 0
write ${WRAPPER_SRC} /usr/local/bin/syz-executor-proxied
set_inode_field /usr/local/bin/syz-executor-proxied mode 0100755
set_inode_field /usr/local/bin/syz-executor-proxied uid 0
set_inode_field /usr/local/bin/syz-executor-proxied gid 0
write ${GUEST_PERF_BIN} /usr/local/bin/perf
set_inode_field /usr/local/bin/perf mode 0100755
set_inode_field /usr/local/bin/perf uid 0
set_inode_field /usr/local/bin/perf gid 0
write ${PERF_CAPTURE_SRC} /usr/local/bin/guest-perf-capture
set_inode_field /usr/local/bin/guest-perf-capture mode 0100755
set_inode_field /usr/local/bin/guest-perf-capture uid 0
set_inode_field /usr/local/bin/guest-perf-capture gid 0
mkdir /refuzz_trace_out
EOF
    if ! debugfs -w -f "${commands}" "${temporary_image}" \
        >"${IMAGE_DST}.debugfs.log" 2>&1; then
        rm -f "${commands}"
        die "debugfs deployment failed; see ${IMAGE_DST}.debugfs.log"
    fi
    rm -f "${commands}"

    if ! verify_image "${temporary_image}"; then
        die "deployed image verification failed; see ${IMAGE_DST}.debugfs.log"
    fi
    mv -f "${temporary_image}" "${IMAGE_DST}"
    trap - EXIT
    log "prepared: ${IMAGE_DST}"
}

preflight
if [ "${1:-}" = "--check" ]; then
    if verify_image "${IMAGE_DST}"; then
        log "verified: ${IMAGE_DST}"
        exit 0
    fi
    log "verification failed: ${IMAGE_DST}"
    exit 1
fi
build_image
