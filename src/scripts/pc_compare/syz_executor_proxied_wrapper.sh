#!/bin/sh
# syz-executor-proxied — V2 production-exec paired oracle PR2 Seam A wrapper.
#
# Installed into the VM image at /usr/local/bin/syz-executor-proxied by
# bake_exec_oracle_image.sh, then referenced from syz-manager config as
# `executor_bin_on_target`. syz-manager invokes us via SSH with:
#
#     /usr/local/bin/syz-executor-proxied runner <vm_idx> <host> <port>
#
# We spawn syz_flatrpc_proxy locally inside the VM, listening on a fixed
# port, dialing the manager's <host>:<port> (which SSH -R has already
# tunneled to the host-side rpcserver). Then exec into the real
# syz-executor pointing at the local proxy. Trace lands at
# /refuzz_trace_out/exec_trace_<idx>_<unix_ns>_<pid>.bin via a 9p mount
# of the host run dir (qemu_args wires this up; see
# scripts/pc_compare/exec_oracle_smoke.sh).
#
# Each wrapper invocation gets its own trace file (unique unix_ns + pid
# suffix). Multiple invocations within one host-side session — VM
# restart, syz-manager instance recycle, etc. — produce multiple trace
# files in the same dir; the comparator merges them in created-ns order.
# Without the unique suffix the second invocation would truncate the
# first via os.Create() and drop all earlier records.
#
# Mount tag must match qemu_args mount_tag and exec_oracle_smoke.sh.

set -e

ARG_RUNNER="$1"
ARG_IDX="$2"
ARG_HOST="$3"
ARG_PORT="$4"

PROXY_PORT="${REFUZZ_PROXY_PORT:-60000}"
TRACE_MOUNT="${REFUZZ_TRACE_MOUNT:-/refuzz_trace_out}"
PROXY_BIN="${REFUZZ_PROXY_BIN:-/usr/local/bin/syz_flatrpc_proxy}"
EXECUTOR_BIN="${REFUZZ_EXECUTOR_BIN:-/usr/local/bin/syz-executor}"
MOUNT_TAG="${REFUZZ_TRACE_MOUNT_TAG:-refuzz_trace}"

mkdir -p "$TRACE_MOUNT"
if ! mountpoint -q "$TRACE_MOUNT" 2>/dev/null; then
    mount -t 9p -o trans=virtio,version=9p2000.L "$MOUNT_TAG" "$TRACE_MOUNT" 2>/dev/null || true
fi

# Unique trace file + session-id per wrapper invocation. unix_ns alone
# would still collide if two wrappers fire in the same nanosecond on the
# same VM — vanishingly unlikely, but pid suffix makes it impossible.
SESSION_NS="$(date +%s%N)"
TRACE_FILE="${REFUZZ_TRACE_FILE:-${TRACE_MOUNT}/exec_trace_${ARG_IDX}_${SESSION_NS}_$$.bin}"

# Stale proxy from a previous run on the same VM (Proc restart, etc.) —
# kill it so port 60000 is free for our new proxy. Its trace file is
# already on disk and won't be touched (unique-suffix naming above).
pkill -f "$PROXY_BIN" 2>/dev/null || true

# §13.5 COV-B.6: force-collect-cover toggle, driven by a host-side sentinel
# that lives in the 9p-mounted trace dir. The host smoke script
# (scripts/pc_compare/exec_oracle_smoke.sh) touches/removes this file based on its
# own REFUZZ_FORCE_COLLECT_COVER env, so we don't need to re-bake the
# image when flipping the knob.
PROXY_FORCE_COVER_ENV=""
if [ -e "${TRACE_MOUNT}/.force_collect_cover" ]; then
    PROXY_FORCE_COVER_ENV="REFUZZ_FORCE_COLLECT_COVER=1"
fi

set -- "$PROXY_BIN" \
    -listen "127.0.0.1:$PROXY_PORT" \
    -dial "$ARG_HOST:$ARG_PORT" \
    -trace "$TRACE_FILE" \
    -vm-index "$ARG_IDX" \
    -session-id "$SESSION_NS"
if [ -e "${TRACE_MOUNT}/.perf_sampling_enabled" ]; then
    set -- "$@" -perf-control-dir "$TRACE_MOUNT"
fi
env $PROXY_FORCE_COVER_ENV "$@" >>/var/log/syz_flatrpc_proxy.log 2>&1 &

# Wait up to ~5s for proxy to bind; if ss not available, fall back to a
# short sleep — proxy bind is fast on this VM regardless.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ss -ltn 2>/dev/null | grep -q ":$PROXY_PORT "; then
        break
    fi
    sleep 0.5
done

exec "$EXECUTOR_BIN" "$ARG_RUNNER" "$ARG_IDX" 127.0.0.1 "$PROXY_PORT"
