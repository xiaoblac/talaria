#!/usr/bin/env bash
# One-time image bake for V2 production-exec paired oracle (plan §9.2).
#
# Injects three artifacts into a copy of the V1 bookworm image so that
# subsequent exec_oracle_smoke.sh runs can find them at fixed paths:
#
#   /usr/local/bin/syz-executor           — upstream syz-executor binary
#   /usr/local/bin/syz_flatrpc_proxy      — PR1 proxy binary
#   /usr/local/bin/syz-executor-proxied   — Seam A wrapper (this PR2)
#   /refuzz_trace_out/                    — 9p mount point for trace output
#
# Idempotent: re-running on an already-baked image is fine.
#
# Default tool: libguestfs virt-customize. If unavailable, exit 2 with a
# qemu-nbd manual fallback printed.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # scripts/pc_compare/ → repo root
SYZKALLER_DIR="${SYZKALLER_DIR:-/workspace/syzkaller}"
SYZ_EXECUTOR_BIN="${SYZ_EXECUTOR_BIN:-${SYZKALLER_DIR}/bin/linux_amd64/syz-executor}"
SYZ_FLATRPC_PROXY_BIN="${SYZ_FLATRPC_PROXY_BIN:-${ROOT_DIR}/build-llvm20/syz_flatrpc_proxy}"
WRAPPER_SRC="${WRAPPER_SRC:-${ROOT_DIR}/scripts/pc_compare/syz_executor_proxied_wrapper.sh}"
IMAGE_SRC="${IMAGE_SRC:-/workspace/images-test-linux5.14/bookworm.img}"
IMAGE_DST="${IMAGE_DST:-/workspace/images-test-linux5.14/bookworm-exec-oracle.img}"

log() { echo "[$(date +%H:%M:%S)] bake: $*" >&2; }

missing=0
for f in "${SYZ_EXECUTOR_BIN}" "${SYZ_FLATRPC_PROXY_BIN}" "${WRAPPER_SRC}" "${IMAGE_SRC}"; do
    if [ ! -e "$f" ]; then
        log "missing: $f"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    log "preflight FAILED"
    exit 1
fi

if [ "${IMAGE_SRC}" != "${IMAGE_DST}" ] && [ ! -e "${IMAGE_DST}" ]; then
    log "cp ${IMAGE_SRC} → ${IMAGE_DST}"
    cp --reflink=auto "${IMAGE_SRC}" "${IMAGE_DST}"
fi

if ! command -v virt-customize >/dev/null; then
    log "virt-customize not found (apt install libguestfs-tools)"
    cat >&2 <<EOF
manual fallback (qemu-nbd; needs root):
  sudo modprobe nbd
  sudo qemu-nbd -c /dev/nbd0 ${IMAGE_DST}
  sudo partprobe /dev/nbd0   # if image is partitioned
  sudo mount /dev/nbd0p1 /mnt # or /dev/nbd0 if no partition table
  sudo cp ${SYZ_EXECUTOR_BIN}      /mnt/usr/local/bin/syz-executor
  sudo cp ${SYZ_FLATRPC_PROXY_BIN} /mnt/usr/local/bin/syz_flatrpc_proxy
  sudo install -m 0755 ${WRAPPER_SRC} /mnt/usr/local/bin/syz-executor-proxied
  sudo chmod +x /mnt/usr/local/bin/syz-executor /mnt/usr/local/bin/syz_flatrpc_proxy
  sudo mkdir -p /mnt/refuzz_trace_out
  sudo umount /mnt && sudo qemu-nbd -d /dev/nbd0
EOF
    exit 2
fi

log "virt-customize → ${IMAGE_DST}"
virt-customize -a "${IMAGE_DST}" \
    --upload "${SYZ_EXECUTOR_BIN}:/usr/local/bin/syz-executor" \
    --upload "${SYZ_FLATRPC_PROXY_BIN}:/usr/local/bin/syz_flatrpc_proxy" \
    --upload "${WRAPPER_SRC}:/usr/local/bin/syz-executor-proxied" \
    --chmod "0755:/usr/local/bin/syz-executor" \
    --chmod "0755:/usr/local/bin/syz_flatrpc_proxy" \
    --chmod "0755:/usr/local/bin/syz-executor-proxied" \
    --mkdir /refuzz_trace_out \
    --no-network

log "done; baked image at ${IMAGE_DST}"
log "next: bash ${ROOT_DIR}/scripts/pc_compare/exec_oracle_smoke.sh"
