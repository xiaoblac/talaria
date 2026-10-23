#!/usr/bin/env bash
# Independent performance-sampling flow (docs/plans/rtt-zone-measurement.md §6.10-2).
#
# Separate from speed_compare (throughput benchmark): this flow exists to
# attribute CPU, so it deliberately instruments the guest. Two modes, both
# strictly serial (one system owns the host at a time):
#
#   standalone   — each tool runs its own online fuzz; the guest is sampled for
#                  the whole measured span.
#   capture-syz  — syzkaller runs a NORMAL fuzz session for DURATION_S and its
#                  host-side sink writes request_stream.bin (inputs only: no
#                  timestamps, identities, or results). Nothing replays.
#   capture-rfz  — the mirror: reFuzz runs a NORMAL fuzz session and its own
#                  host-side sink writes dispatched.jsonl, which
#                  tools/syz-stream-from-jsonl converts to the same canonical
#                  stream format. Exists so the 2x2 has a reFuzz-generated
#                  column. Both capture modes are the SAME run as their
#                  standalone counterpart plus one driver switch -- capture must
#                  never be a forked config, or the capture run stops being
#                  comparable to the baseline it is supposed to feed.
#   replay       — capture as above, then reFuzz replays the whole stream via
#                  its own run_mode=replay producer.
#   replay-both  — capture, then BOTH systems replay the identical stream
#                  (syzkaller via -mode stream-replay, reFuzz via
#                  run_mode=replay). This is the mode that isolates the
#                  execution mechanism: `replay` still has syzkaller generating
#                  and triaging on its side, so it mixes mechanism with program
#                  source.
#
# Each side reports only its OWN native performance data; nothing is paired
# per-request. The old refuzz-exec-replayer / ref_result.bin cross-system
# pairing pipeline (and its paired_compare.md, and the requirement to build
# WORKER_BIN with ExecTimelineSampled() forced true) is GONE -- it could never
# exceed ~5-6% paired coverage because the two systems sample independently.
# Both sides now sample at 100% into their own logs instead.
#
# Probe policy: full-span sampling, one fetch at the end, BEFORE VM teardown.
# The guest only collects raw data (perf.data / kallsyms / proc snapshots);
# every report is generated on the host afterwards.
#
# Usage:
#   scripts/perf_compare/perf_sampling.sh standalone [rfz] [syz]
#   scripts/perf_compare/perf_sampling.sh replay
#
# Common env overrides:
#   RUN_DIR=...            output root (default run/perf_sampling_<UTC>)
#   DURATION_S=3600        syz capture length / standalone measured span
#   PERF_HZ=19             full-span cpu-clock sample rate
#   FETCH_MARGIN_S=900     standalone: extra driver runtime beyond the span.
#                          HARD deadline, not slack: the driver tears the VM
#                          down at fuzz-start + DURATION_S + FETCH_MARGIN_S,
#                          and everything after the span -- the guest-side
#                          stop script (perf SIGINT flush, /proc/kallsyms
#                          copy while workers still fuzz at full load, split)
#                          plus the whole chunked fetch -- must finish inside
#                          it or the fetch dies mid-scp with the VM. Measured
#                          at 1h/19Hz scale: stop ~4min + fetch of ~140MB
#                          over SLIRP ~3-5min, so 180 was a guaranteed loss
#                          and even short runs only cleared it by 23-95s.
#   PER_REQUEST_TIMEOUT_MS=5000  replay per-request timeout
#   HOLD_S=900             replay: max VM hold for the final fetch
#   FETCH_CHUNK_BYTES=8388608  cap on any single guest->host transfer (8MiB);
#                          gp.data is split into parts of at most this size
#                          before fetch and reassembled on the host, so no
#                          one scp ever has to move the whole (tens-to-
#                          hundreds of MB) recording in one shot
#   BOOT_TIMEOUT_S=300     max wait for first guest SSH reachability; observed
#                          boot-to-probe is ~117-119s on an idle host, so this
#                          carries real margin under contention rather than
#                          the ~120s floor it would otherwise race against
#   SYZ_MAX_SPAN_S=3240    standalone syz span cap: syz-manager hard-restarts
#                          each VM at 1h uptime (non-configurable), and the
#                          probe + stop + fetch must fit inside one VM's life
#   MIN_FREE_DISK_GB=15    replay: floor on RUN_DIR's filesystem free space.
#                          The replay path no longer writes ref_result.bin (that
#                          belonged to the deleted per-request-pairing pipeline),
#                          but worker.log, host_events.txt and the guest gp.data
#                          still grow with replayed request count -- hundreds of
#                          MB per run -- and a long stream can overrun any static
#                          budget. So this polls every 10s during replay and
#                          SIGTERMs the orchestrator the moment free space crosses
#                          the floor: a cleanly-stopped partial run still has
#                          analyzable logs; an ENOSPC mid-write does not
#   REUSE_SYZ_FROM=<dir>   replay: import that prior run's syz/ artifacts
#                          (request_stream.bin + native perf serial + probe)
#                          instead of re-capturing. For rerunning ONLY the rfz
#                          half after an rfz-side failure: the syz capture costs
#                          ~70min at a 1h span and nothing reFuzz does can
#                          invalidate an already-published, footer-sealed stream

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT}/build-llvm20}"
SSHK="${SSHK:-/workspace/images-test-linux5.14/bookworm.id_rsa}"
SYZ_CONFIG="${SYZ_CONFIG:-${ROOT}/run/speed_compare/configs/syz_6proc_cpu_closure.json}"
RFZ_CONFIG="${RFZ_CONFIG:-${ROOT}/run/speed_compare/configs/refuzz_mabB_perf.json}"
WORKER_BIN="${WORKER_BIN:-${BUILD_DIR}/executor/channel/worker/ivshmem_worker}"
HOST_PERF="${HOST_PERF:-${ROOT}/scripts/perf_compare/perf}"
JEMALLOC_SO="${JEMALLOC_SO:-/usr/lib/x86_64-linux-gnu/libjemalloc.so.2}"
# speed_compare.py's per-run default cache dir is <out-dir>/../{corpus,images}
# — since standalone_one gives each phase a fresh out-dir, leaving these unset
# would rebuild the (deterministic) seed corpus and re-copy the multi-GB VM
# image on every invocation. Point both at the shared, already-populated
# run/speed_compare/ caches instead.
CORPUS_CACHE_DIR="${CORPUS_CACHE_DIR:-${ROOT}/run/speed_compare/corpus}"
IMAGE_CACHE_DIR="${IMAGE_CACHE_DIR:-${ROOT}/run/speed_compare/images}"
RARITY_ALPHA="${RARITY_ALPHA:-8}"

DURATION_S="${DURATION_S:-3600}"
PERF_HZ="${PERF_HZ:-19}"
FETCH_MARGIN_S="${FETCH_MARGIN_S:-900}"
FETCH_CHUNK_BYTES="${FETCH_CHUNK_BYTES:-8388608}"
PER_REQUEST_TIMEOUT_MS="${PER_REQUEST_TIMEOUT_MS:-5000}"
HOLD_S="${HOLD_S:-900}"
BOOT_TIMEOUT_S="${BOOT_TIMEOUT_S:-300}"
# Separate, much larger budget for the replay paths. BOOT_TIMEOUT_S bounds
# "process launched -> guest ssh answers", and on the reFuzz replay path that
# span is dominated by work that happens BEFORE the VM is even started: the
# orchestrator loads and StrictTyped-decodes the whole seed corpus
# (run/seed_base, ~219MB) first. Measured from host_events.txt on
# 2026-07-26: corpus_loaded at +273.0s, `boot` at +273.0s, guest ssh ~117s
# later -- ~390s total, against a 300s budget.
#
# It only ever passed because of the page cache: the run right after another
# reFuzz run finished the same sequence in 236s (warm), while the same command
# 1.5h later, after a full syz replay had evicted the corpus, took >304s and
# was killed 30s short of a healthy guest. A budget that depends on page-cache
# state is a coin flip, not a timeout.
#
# Kept generous rather than tuned: this bounds readiness only, and a genuinely
# wedged replay is still caught by REPLAY_SAFETY_CAP_S.
REPLAY_BOOT_TIMEOUT_S="${REPLAY_BOOT_TIMEOUT_S:-1200}"
SYZ_MAX_SPAN_S="${SYZ_MAX_SPAN_S:-3240}"
MIN_FREE_DISK_GB="${MIN_FREE_DISK_GB:-15}"
# replay: reFuzz's run_mode=replay is expected to self-terminate (Fixed
# InputProducerJob's on_fully_drained -> RequestStop() once the stream
# drains and every completion is observed). This is only a backstop against
# a wedged run, not a normal-path timer -- a real replay run should exit
# well before this fires.
REPLAY_SAFETY_CAP_S="${REPLAY_SAFETY_CAP_S:-7200}"
# replay: set to a PRIOR run dir to import its syz/ artifacts instead of
# re-capturing. The syz capture (~70min at 1h span) is independent of the rfz
# side -- a published, footer-sealed request stream cannot be invalidated by
# anything reFuzz does -- so an rfz-only failure should not pay for it twice.
REUSE_SYZ_FROM="${REUSE_SYZ_FROM:-}"
# replay/replay-both: replay THIS stream instead of the one that came with the
# capture (or with REUSE_SYZ_FROM). Exists for the corpus-trim experiment, where
# both sides must replay a stream derived from a capture rather than the capture
# itself -- tools/syz-stream-filter writes those. Copied into the run directory
# like any other input so the run stays a self-contained record; still validated
# by stream_header_info, so a v1 or malformed file is refused up front.
STREAM_OVERRIDE="${STREAM_OVERRIDE:-}"
# Set by the capture-rfz mode only; standalone_one() appends the driver switches
# when it is non-empty. Not a user knob -- the mode sets it so the JSONL always
# lands inside the run directory rather than at a shared path a later run would
# clobber.
CAPTURE_RFZ_STREAM=""
# RUN.json's experiment slot. Derived from MODE when unset (capture/standalone ->
# e1-collect, replay -> e2-replay); set explicitly for the two classes the mode
# alone cannot distinguish -- a replay-both at w8 is e3-scale, and a replay-both
# on a trimmed stream is e4-trim, but both look like a plain replay-both here.
EXPERIMENT="${EXPERIMENT:-}"
# The streams/ registry id of the workload, e.g. syz-a / rfz-a / syz-a-drop10.
# Recorded verbatim; the path it came from is recorded separately, so a run stays
# identifiable even before its stream has been filed into run/perf/streams/.
STREAM_ID="${STREAM_ID:-}"
# Distinct from any port speed_compare.py hands a capture run (http_port_base+run_id,
# 57541+), so a syz replay can never collide with a capture's manager.
SYZ_REPLAY_HTTP="${SYZ_REPLAY_HTTP:-127.0.0.1:57599}"
# syz-manager restarts every VM at 1h (sys/targets/targets.go, not settable from the
# manager config). A replay must NOT be cut by that: reFuzz replays the whole stream
# in one VM, the in-guest perf recording dies with the VM, and syzkaller replays at
# roughly the rate it captured at -- so a stream captured over ~1h needs ~1h+ to
# replay and hits the wall every time (observed 2026-07-25 at 85.6% of the stream,
# exactly 1h in). Raised well past REPLAY_SAFETY_CAP_S so the script's own cap, not
# the VM lifetime, is what bounds a wedged run.
SYZ_REPLAY_VM_LIFETIME="${SYZ_REPLAY_VM_LIFETIME:-4h}"
# The reFuzz-side counterpart of SYZ_REPLAY_VM_LIFETIME. The base RFZ_CONFIG is a
# fuzzing config whose phase1_runtime_seconds says how long to FUZZ; a replay ends
# when the stream is empty, so that value must be replaced, not inherited. Default
# is the script's safety cap, so a replay is bounded by the harness rather than by
# a number that belongs to a different mode.
RFZ_REPLAY_RUNTIME_S="${RFZ_REPLAY_RUNTIME_S:-${REPLAY_SAFETY_CAP_S}}"
# Escape hatch for the two build-freshness guards below
# (assert_go_binary_current / assert_cmake_target_current). Set only when their
# toolchain query is wrong for a reason you have checked.
SKIP_BUILD_FRESHNESS="${SKIP_BUILD_FRESHNESS:-}"
# Filled in by the replay path once the stream is validated, then reported in
# metadata.txt: which stream this run actually measured, and in what format.
STREAM_VERSION=""
STREAM_RECORDS=""
STREAM_BYTES=""

log() { echo "[$(date -u +%H:%M:%S)] perf-sampling: $*" >&2; }
die() { log "FATAL: $*"; exit "${2:-1}"; }

# assert_go_binary_current BINARY LABEL MODULE_ROOT PACKAGE
#
# Go counterpart of assert_cmake_target_current, and exact for the same reason:
# it asks the toolchain which packages the binary is actually built from
# (`go list -deps`, ~0.3s) instead of comparing mtimes across the whole tree.
#
# The tree-wide mtime form was tried first and misfired three times in one day --
# on reFuzz it accused `refuzz` because a unit test was newer and `ivshmem_worker`
# because host-side recovery code was newer, and on syzkaller it aborted a launched
# replay-both because tools/syz-stream-filter/, a separate main package, had just
# been added. None of those files are inputs to the binary they blamed. A guard
# that keeps crying wolf gets waived permanently and then catches nothing, so the
# heuristic is gone rather than tuned.
assert_go_binary_current() {
    local bin="$1" label="$2" root="$3" pkg="$4"
    [ -x "${bin}" ] || die "${label}: missing binary ${bin}"
    [ -z "${SKIP_BUILD_FRESHNESS}" ] || return 0
    local dirs
    dirs=$(cd "${root}" && go list -f '{{.Dir}}' -deps "${pkg}" 2>/dev/null)
    if [ -z "${dirs}" ]; then
        log "WARN: ${label}: could not resolve ${pkg} dependencies; skipping freshness check"
        return 0
    fi
    # Only the module's own packages can be edited here; the module cache is
    # read-only and its mtimes are meaningless.
    local newer
    newer=$(printf '%s\n' "${dirs}" | grep "^${root}/" \
                | xargs -r -I{} find {} -maxdepth 1 -name '*.go' -newer "${bin}" -print 2>/dev/null \
                | head -3)
    [ -n "${newer}" ] || return 0
    log "FATAL: ${label}: ${bin} is older than a package it is built from -- rebuild before measuring."
    log "       newer than the binary:"
    printf '         %s\n' ${newer} >&2
    log "       (override with SKIP_BUILD_FRESHNESS=1)"
    exit 1
}

# assert_cmake_target_current BUILD_DIR TARGET BINARY LABEL
#
# The reFuzz-side counterpart of assert_go_binary_current: same contract, same
# reason for asking the build system rather than comparing mtimes (see that
# function for the three false positives that motivated both).
#
# Discriminator: a dry run of an up-to-date target emits only recursive sub-make
# and progress-echo lines; a stale one additionally emits real compile (` -c `)
# or link (`cmake_link_script`) commands. Verified against a forced rebuild:
# 2 such lines when stale, 0 immediately after building.
assert_cmake_target_current() {
    local build_dir="$1" target="$2" bin="$3" label="$4"
    [ -x "${bin}" ] || die "${label}: missing binary ${bin}"
    [ -z "${SKIP_BUILD_FRESHNESS}" ] || return 0
    [ -f "${build_dir}/CMakeCache.txt" ] || {
        log "WARN: ${label}: no CMake build tree at ${build_dir}; cannot verify ${target} is current"
        return 0
    }
    local pending
    pending=$(cmake --build "${build_dir}" --target "${target}" -- -n 2>/dev/null \
                  | grep -cE 'cmake_link_script| -c ')
    [ "${pending}" -eq 0 ] && return 0
    log "FATAL: ${label}: CMake target '${target}' is out of date (${pending} pending build steps)."
    log "       ${bin} does not match the sources -- run:"
    log "         cmake --build ${build_dir} --target ${target} -j \$(nproc)"
    log "       (override with SKIP_BUILD_FRESHNESS=1)"
    exit 1
}

# stream_header_info PATH -> echoes "<version> <records> <bytes>"
#
# Validates BOTH ends of the request stream. Checking only the footer is not
# enough and was an actual hole: FooterMagic is "RFZEND01" in v1 AND v2, so a
# v1 stream (SerializeForExec bytes) passes a footer-only check and is then
# handed to readers that only understand v2 (canonical syzlang ProgText). The
# version lives in the HEADER -- "RFZREQS2" + u32 version, see
# pkg/requeststream/request_stream.go writeHeader().
#
# The record count comes out of the same parse so callers stop re-deriving it.
stream_header_info() {
    python3 - "$1" <<'PY' || die "request stream failed validation: $1"
import struct, sys
path = sys.argv[1]
with open(path, "rb") as f:
    head = f.read(32)
    if len(head) < 32:
        raise SystemExit("header truncated")
    magic, version, header_size = head[:8], *struct.unpack_from("<II", head, 8)
    if magic != b"RFZREQS2":
        raise SystemExit(
            f"bad header magic {magic!r} (expected RFZREQS2); a v1 stream cannot be "
            "replayed by the current readers -- recapture it")
    if version != 2 or header_size != 32:
        raise SystemExit(f"unsupported stream version={version} header_size={header_size}")
    f.seek(0, 2)
    size = f.tell()
    f.seek(-36, 2)
    foot = f.read(36)
marker = struct.unpack_from("<I", foot, 0)[0]
if marker != 0xffffffff or foot[4:12] != b"RFZEND01":
    raise SystemExit(f"bad footer: marker=0x{marker:x} magic={foot[4:12]!r}")
count, last = struct.unpack_from("<QQ", foot, 20)
if count == 0 or last + 1 != count:
    raise SystemExit(f"footer count/last mismatch: count={count} last={last}")
print(f"{version} {count} {size}")
PY
}

# A `die` mid-flight (probe failure, driver crash, etc.) must not orphan the
# still-running driver/replayer and its QEMU guest -- each phase records its
# background job PID here right after launch and clears it right after a
# clean `wait`, so any exit path (normal or die) sweeps up whatever is left.
ACTIVE_JOB_PID=""
# Unique to this script instance and embedded in every path replay_rfz hands
# QEMU (-chardev socket paths, -drive, work dir), so it can be used to identify
# THIS run's guest without matching anyone else's.
RFZ_TAG="rfz_rs_$$"
cleanup_active_job() {
    local pid="${ACTIVE_JOB_PID}"
    [ -n "${pid}" ] || return 0
    if kill -0 "${pid}" 2>/dev/null; then
        log "cleanup: terminating orphaned job pid=${pid}"
        kill -TERM "${pid}" 2>/dev/null || true
        local waited=0
        while kill -0 "${pid}" 2>/dev/null && [ "${waited}" -lt 10 ]; do
            sleep 1; waited=$((waited + 1))
        done
        kill -KILL "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
    # Killing the orchestrator is NOT enough: it launches QEMU as a separate
    # process and only tears it down on its own graceful shutdown path, so a
    # SIGKILL leaves the guest running. Observed 2026-07-26: a boot-timeout
    # abort left QEMU alive, and the next run's stray-VM preflight then refused
    # to start on an otherwise-idle host.
    #
    # Matched on this instance's own RFZ_TAG, never on "any qemu": a bare
    # `pkill qemu-system-x86` would take out an unrelated VM on a shared host.
    local stray
    stray=$(pgrep -f "${RFZ_TAG}" 2>/dev/null | grep -vx "$$" || true)
    [ -n "${stray}" ] || return 0
    log "cleanup: killing leaked guest process(es) for ${RFZ_TAG}: $(echo ${stray} | tr '\n' ' ')"
    # shellcheck disable=SC2086  # deliberate word splitting: one pid per arg
    kill -KILL ${stray} 2>/dev/null || true
}
trap cleanup_active_job EXIT

# Set (scoped, via a function-local `trap ... RETURN`) by whichever function
# is currently multiplexing its ssh/scp calls over a shared control-master
# connection -- see ssh_master_start below. Empty by default: every OTHER
# caller of ssh_cmd is unaffected and keeps opening its own one-off
# connection exactly as before.
SSH_MUX_OPTS=()

ssh_cmd() { # ssh_cmd PORT CMD...
    local port="$1"; shift
    ssh -i "${SSHK}" -p "${port}" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=15 -o ServerAliveInterval=15 "${SSH_MUX_OPTS[@]}" \
        root@127.0.0.1 "$@"
}

# ssh_master_start PORT -> echoes a ControlPath on success, non-zero on
# failure. Opens ONE authenticated connection in the background
# (ControlPersist keeps it alive briefly after the last multiplexed client
# disconnects, in case of back-to-back calls); every subsequent ssh/scp
# invocation that adds `-o ControlPath=<path> -o ControlMaster=auto` reuses
# it as a cheap new channel instead of a full TCP+crypto handshake +
# guest-sshd-fork. Opening a fresh connection per file/chunk in a fetch loop
# with a dozen-plus entries has been observed to be enough load on a 2-vCPU
# guest to make it stop responding entirely mid-fetch.
ssh_master_start() { # ssh_master_start PORT
    local port="$1"
    local control_path="/tmp/perf_sampling_ctrl_${port}_$$"
    rm -f "${control_path}"
    ssh -i "${SSHK}" -p "${port}" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=15 -o ControlMaster=yes -o ControlPath="${control_path}" \
        -o ControlPersist=120 -N -f root@127.0.0.1 2>/dev/null || return 1
    echo "${control_path}"
}

ssh_master_stop() { # ssh_master_stop CONTROL_PATH
    local control_path="$1"
    [ -n "${control_path}" ] || return 0
    ssh -o ControlPath="${control_path}" -O exit root@127.0.0.1 2>/dev/null || true
    rm -f "${control_path}" 2>/dev/null || true
}

find_guest_port() {
    ps -eo args | grep -o 'hostfwd=tcp:[0-9.]*:\?[0-9]*-:22' \
        | grep -o '[0-9]*-:22' | grep -o '^[0-9]*' | head -1
}

wait_guest_ssh() { # wait_guest_ssh TIMEOUT_S [WATCH_PID] -> echoes port
    # WATCH_PID: bail out immediately (instead of polling the full timeout)
    # if this process has already exited -- e.g. the replayer's preflight
    # trace parse can fail before it ever calls Boot(), in which case no VM
    # will EVER come up and polling for the full timeout just wastes time.
    # Wall-clock deadline (not an integer step counter) so the poll interval
    # can be sub-second: this loop sits directly on the standalone-mode
    # warm-up gap (fuzz already started, probe not attached yet), and a 3s
    # step there meant up to 3s of pure polling slop on top of the real SSH
    # handshake cost every single run.
    local timeout="$1" watch="${2:-}" port=""
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if [ -n "${watch}" ] && ! kill -0 "${watch}" 2>/dev/null; then
            return 1
        fi
        port=$(find_guest_port)
        if [ -n "${port}" ] && ssh_cmd "${port}" true 2>/dev/null; then
            echo "${port}"
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# ---------------------------------------------------------------------------
# Guest probe lifecycle. Raw collection only — no processing in the guest.
# ---------------------------------------------------------------------------

probe_guest_start() { # probe_guest_start PORT
    local port="$1"
    ssh_cmd "${port}" "HZ=${PERF_HZ} bash -s" <<'EOS'
set -e
mkdir -p /root/probe && rm -rf /root/probe/* 2>/dev/null || true
cd /root/probe
cat /proc/stat > st.before
cat /proc/interrupts > int.before
cat /proc/softirqs > si.before
# -B/--no-buildid: at exit perf otherwise re-reads the ENTIRE data file to
# collect build-ids -- ~105MB at 1h/19Hz on a loaded IDE disk, which is why
# a 60s flush wait used to expire and SIGKILL left the header unsealed
# (data-size field 0, host perf report refused the file). Build-ids buy us
# nothing here: kernel symbols come from the fetched gp.kallsyms and the
# guest's userspace binaries are not available host-side either way.
nohup /usr/local/bin/perf record -a -g -B -F "$HZ" -e cpu-clock \
    -o /root/probe/gp.data -- sleep 864000 \
    > /root/probe/perf.out 2>&1 &
sleep 1
pgrep -f "perf record" >/dev/null || { echo "PROBE-START-FAILED"; exit 1; }
echo "PROBE-STARTED hz=$HZ"
EOS
}

probe_guest_stop_fetch() { # probe_guest_stop_fetch PORT PROBE_DIR
    local port="$1" probe_dir="$2"
    mkdir -p "${probe_dir}"
    # Every ssh_cmd/scp call below multiplexes over one shared connection
    # instead of opening its own -- see ssh_master_start's comment. Falls
    # back to the old one-connection-per-call behavior (SSH_MUX_OPTS stays
    # empty) if the master itself fails to start; still correct, just back
    # to paying full handshake cost per call. `trap ... RETURN` is
    # function-scoped (bash 4.4+): it fires on every path out of this
    # function -- normal fall-through or any of the early `return`s below --
    # so the master and the mux-options toggle can't leak past this call.
    local ctrl=""
    ctrl=$(ssh_master_start "${port}") \
        || { log "WARN: could not start ssh control master on port ${port}, falling back to per-call connections"; ctrl=""; }
    [ -n "${ctrl}" ] && SSH_MUX_OPTS=(-o "ControlPath=${ctrl}" -o "ControlMaster=auto")
    # ctrl must expand now (double-quoted), not when the trap fires later --
    # it is a local variable that would be out of scope by then.
    # shellcheck disable=SC2064
    trap "SSH_MUX_OPTS=(); ssh_master_stop '${ctrl}'" RETURN

    ssh_cmd "${port}" "CHUNK_BYTES=${FETCH_CHUNK_BYTES} bash -s" <<'EOS'
set -e
cd /root/probe
# Snapshot the /proc/stat closure endpoint BEFORE signaling perf to stop, not
# after. perf itself stops sampling the instant it receives SIGINT; the
# pkill-wait-KILL sequence below is only for reliably fetching a fully
# written gp.data, and can take minutes of ITS OWN CPU/exit overhead --
# counting that into the accounting window would inflate busy ticks the
# perf sample stream never covers, and misattribute perf's own teardown
# cost as unexplained residual.
cat /proc/stat > st.after
cat /proc/interrupts > int.after
cat /proc/softirqs > si.after
pkill -INT -f "perf record" 2>/dev/null || true
# 300s cap, not 60: a SIGKILLed perf leaves the header's data-size field 0
# and the whole recording unreadable without manual repair. With -B the exit
# is normally seconds; the long cap is pure insurance and the margin math
# (FETCH_MARGIN_S=900) accommodates it.
waited=0
while pgrep -f "perf record" >/dev/null 2>&1 && [ "$waited" -lt 300 ]; do
    sleep 1; waited=$((waited + 1))
done
pgrep -f "perf record" >/dev/null 2>&1 && pkill -KILL -f "perf record" || true
cp /proc/kallsyms gp.kallsyms
{ getconf CLK_TCK; uname -r; date -u '+%FT%TZ'; } > gp.meta
# gp.data is whole-run perf.data (tens-to-hundreds of MB at DURATION_S=3600):
# a single scp of that size over this VM's usermode/SLIRP network has been
# observed to abort mid-transfer with no other symptom. Retrying the SAME
# oversized transfer just gives repeated shots at the same fragile operation
# -- cap what any ONE transfer ever has to move instead: split every file
# over CHUNK_BYTES into fixed-size parts here, on the guest, before the host
# ever asks for it. Small files (st.before, gp.meta, ...) pass through
# unsplit.
for f in *; do
    [ -f "$f" ] || continue
    sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
    if [ "$sz" -gt "$CHUNK_BYTES" ]; then
        split -d -a 4 -b "$CHUNK_BYTES" "$f" "${f}.part"
        rm -f "$f"
    fi
done
ls -la /root/probe | tail -n +2
echo "PROBE-STOPPED"
EOS
    local rc=$?
    [ "${rc}" -ne 0 ] && log "WARN: guest probe stop reported rc=${rc}"
    # `scp -r host:/dir/.` (copy-contents-of trick) errors "unexpected
    # filename: ." under modern OpenSSH scp's default SFTP-protocol backend.
    # List remote files explicitly and fetch each — the pattern already
    # proven working in this environment (superseded probe_tools/probe_run.sh).
    local files file failed=0
    files=$(ssh_cmd "${port}" "ls -1 /root/probe" 2>/dev/null) \
        || { log "WARN: cannot list /root/probe on port ${port}"; return 1; }
    # Each entry here is already bounded to at most CHUNK_BYTES (see the
    # guest-side split above), so a lone transient blip only costs a small
    # re-transfer, not the whole run's perf.data. The retry is still worth
    # keeping on top of chunking -- ordinary packet loss can hit a small
    # transfer too -- but it is no longer the thing standing between success
    # and losing an hour of capture.
    local attempt scp_err
    for file in ${files}; do
        attempt=1
        while :; do
            scp_err=$(scp -i "${SSHK}" -P "${port}" -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
                "${SSH_MUX_OPTS[@]}" \
                "root@127.0.0.1:/root/probe/${file}" "${probe_dir}/${file}" 2>&1) \
                && break
            if [ "${attempt}" -ge 3 ]; then
                log "WARN: fetch failed after ${attempt} attempts: ${file}: ${scp_err}"
                failed=1
                break
            fi
            log "WARN: fetch attempt ${attempt} failed for ${file}, retrying: ${scp_err}"
            attempt=$((attempt + 1))
            sleep 2
        done
    done
    [ "${failed}" -eq 0 ] || { log "WARN: one or more probe files failed to fetch for ${probe_dir}"; return 1; }
    # Reassemble: any <name>.partNNNN group becomes <name> again, in numeric
    # (= transfer) order, then the parts are removed locally. cat's own
    # failure (disk full, permissions) is fatal -- a probe dir with only
    # some files reassembled is worse than an explicit error here.
    local base parts
    for file in "${probe_dir}"/*.part[0-9][0-9][0-9][0-9]; do
        [ -e "${file}" ] || continue
        base="${file%.part[0-9][0-9][0-9][0-9]}"
        [ -e "${base}" ] && continue  # already reassembled via an earlier match
        parts=("${base}".part[0-9][0-9][0-9][0-9])
        cat "${parts[@]}" > "${base}" || die "reassembling ${base} from ${#parts[@]} parts failed"
        rm -f "${parts[@]}"
    done
    log "probe artifacts fetched -> ${probe_dir}"
}

host_report() { # host_report PROBE_DIR
    local probe_dir="$1"
    [ -x "${HOST_PERF}" ] || { log "WARN: no host perf at ${HOST_PERF}"; return 0; }
    [ -s "${probe_dir}/gp.data" ] || { log "WARN: no gp.data in ${probe_dir}"; return 0; }
    # --kallsyms is required for kernel symbol resolution: gp.data was
    # recorded against the GUEST kernel, this report runs on the HOST, and
    # without an explicit kallsyms path perf has no kernel symbol table to
    # resolve against (the host's own live /proc/kallsyms is a different
    # kernel/KASLR layout entirely) -- every [k] row then silently prints as
    # an unresolved raw address instead of erroring. But `perf report
    # --kallsyms <missing-file>` hard-fails (exit 234, empty stdout) rather
    # than degrading, so only pass it when the file actually landed; a failed
    # fetch should still yield a comm-level/address-level report, not none.
    local -a kallsyms_flag=()
    if [ -s "${probe_dir}/gp.kallsyms" ]; then
        kallsyms_flag=(--kallsyms "${probe_dir}/gp.kallsyms")
    else
        log "WARN: no gp.kallsyms in ${probe_dir}; kernel symbols will not resolve"
    fi
    LC_ALL=C PERF_PAGER=cat "${HOST_PERF}" report --stdio --no-children \
        -g none -n --sort comm --field-separator ';' --percent-limit 0 \
        "${kallsyms_flag[@]}" \
        -i "${probe_dir}/gp.data" \
        > "${probe_dir}/gp.comm.report.txt" \
        2> "${probe_dir}/gp.comm.report.stderr" \
        && log "host comm report -> ${probe_dir}/gp.comm.report.txt"
    LC_ALL=C PERF_PAGER=cat "${HOST_PERF}" report --stdio --no-children \
        -g none -n --sort comm,dso,symbol --field-separator ';' \
        --percent-limit 0.02 "${kallsyms_flag[@]}" \
        -i "${probe_dir}/gp.data" \
        > "${probe_dir}/gp.hot-symbols.report.txt" \
        2> "${probe_dir}/gp.hot-symbols.report.stderr" \
        && log "host hotspot report -> ${probe_dir}/gp.hot-symbols.report.txt"
}

# ---------------------------------------------------------------------------
# standalone mode — online fuzz via speed_compare, full-span probe.
# ---------------------------------------------------------------------------

standalone_one() { # standalone_one rfz|syz
    local tool="$1"
    local out="${RUN_DIR}/${tool}"
    local drv="${out}/driver"
    local probe="${out}/probe"
    mkdir -p "${out}" "${probe}"
    # syz-manager hard-restarts every VM at 1h of VM uptime (sys/targets/
    # targets.go: VMRunningTime defaults to time.Hour, per-target struct, NOT
    # exposed in the manager config json). The probe rides a single VM, so
    # attach offset (~15s after the VM clock starts) + span + stop+fetch
    # (~260s measured) must all fit inside that hour or the recording dies
    # with the VM -- a 3600s span loses by seconds, deterministically
    # (observed 2026-07-21: "VM 0: running for 1h0m0.0006s, restarting" nine
    # seconds before span end). Clamp rather than fail: proportions and
    # busy-core figures are span-normalized, so a shorter syz span stays
    # comparable; boundary.txt records the actual span.
    local span="${DURATION_S}"
    if [ "${tool}" = syz ] && [ "${span}" -gt "${SYZ_MAX_SPAN_S}" ]; then
        span="${SYZ_MAX_SPAN_S}"
        log "[syz] span clamped ${DURATION_S}s -> ${span}s (syz-manager 1h VM lifetime; see comment)"
    fi
    local drv_duration=$((span + FETCH_MARGIN_S))
    log "[${tool}] standalone: driver=${drv_duration}s sampled span=${span}s"

    # No wrapping subshell: launch python3 directly so $! is ITS pid (not a
    # `(cd X && cmd) &` subshell whose signal-forwarding to the real child is
    # not guaranteed) -- kill -TERM on $! then reliably reaches
    # speed_compare.py's own SIGTERM handler, which killpg()s its detached
    # syz-manager/refuzz-orchestrator child group (incl. QEMU) on the way
    # down. Absolute script path since we deliberately skip `cd`.
    local -a launch
    if [ "${tool}" = rfz ]; then
        launch=(env "LD_PRELOAD=${JEMALLOC_SO}"
                "REFUZZ_SEED_RARITY_PRIOR_ALPHA=${RARITY_ALPHA}"
                python3 "${ROOT}/scripts/speed_compare/speed_compare.py" --arms D
                --only refuzz --runs 1 --duration "${drv_duration}"
                --refuzz-config "${RFZ_CONFIG}" --out-dir "${drv}" --skip-build
                --corpus-cache-dir "${CORPUS_CACHE_DIR}"
                --image-cache-dir "${IMAGE_CACHE_DIR}")
        # capture-rfz: same run, same RFZ_CONFIG, one extra switch -- exactly
        # how capture_syz_request_stream() relates to `standalone syz`. The
        # trace rate rides along for the same reason it does there: the stream
        # this run publishes is only useful for a trim experiment if the run
        # also recorded what each program cost (stream_trim_scores.py reads
        # host_events.txt), and that is injected by the driver flag, never by
        # the config file.
        if [ -n "${CAPTURE_RFZ_STREAM}" ]; then
            launch+=(--refuzz-request-stream "${CAPTURE_RFZ_STREAM}"
                     --rtt-trace-sample-rate 1)
        fi
    else
        launch=(python3 "${ROOT}/scripts/speed_compare/speed_compare.py" --arms D
                --only syzkaller --runs 1 --duration "${drv_duration}"
                --syz-config "${SYZ_CONFIG}" --out-dir "${drv}" --skip-build
                --corpus-cache-dir "${CORPUS_CACHE_DIR}"
                --image-cache-dir "${IMAGE_CACHE_DIR}")
    fi
    "${launch[@]}" > "${out}/driver.log" 2>&1 &
    local driver=$!
    ACTIVE_JOB_PID="${driver}"
    local driver_launched_us
    driver_launched_us=$(date -u +%s%6N)
    log "[${tool}] driver pid=${driver}"

    # No fuzz-start signal to wait for. Standalone has no production-code
    # hook to gate the workload behind (speed_compare.py drives syz-manager
    # / control/orchestrator/refuzz directly, neither goes through
    # syz_flatrpc_proxy or refuzz-exec-replayer -- see
    # docs/plans/rtt-zone-measurement.md §6.10-4), so there is no precise
    # request-level event to align on in the first place. Waiting for the
    # first completed-request log line before attaching only added its own
    # SSH round-trip on top without producing an actually-precise start
    # point (it aligns on "first COMPLETION observed", which is later than
    # "fuzzing began" by an unmeasured amount too). The boundary here is
    # wall-clock time instead: attach as early as technically
    # possible -- the instant the guest is reachable at all -- and report
    # exactly when that was, rather than approximate a semantic event this
    # mode cannot observe.
    local port
    port=$(wait_guest_ssh "${BOOT_TIMEOUT_S}" "${driver}") || die "[${tool}] guest ssh unreachable"
    probe_guest_start "${port}" || die "[${tool}] probe start failed"
    local probe_started_us
    probe_started_us=$(date -u +%s%6N)
    local boot_to_probe_ms=$(( (probe_started_us - driver_launched_us) / 1000 ))
    echo "driver_launched_us=${driver_launched_us}
probe_started_us=${probe_started_us}
boot_to_probe_ms=${boot_to_probe_ms}" > "${probe}/boundary.txt"
    log "[${tool}] full-span sampling for ${span}s on port ${port} (boot-to-probe: ${boot_to_probe_ms}ms)"

    # Wall-clock sleep, not a drain wait: unlike replay mode's finite,
    # closeable request stream, standalone fuzzing is continuous and
    # open-ended, so there is no instant with "zero in-flight work" to wait
    # for -- some request WILL be mid-execution whenever this loop ends.
    # That is the nature of the workload, not a bug in this script.
    # probe_guest_stop_fetch (task #2 fix) still snapshots /proc/stat
    # immediately before signaling perf to stop, so the accounting endpoint
    # matches perf's actual last sample as precisely as this mode allows.
    local elapsed=0
    while [ "${elapsed}" -lt "${span}" ]; do
        kill -0 "${driver}" 2>/dev/null || { tail -8 "${out}/driver.log" >&2; die "[${tool}] driver died mid-span (guest data lost with VM)"; }
        sleep 5
        elapsed=$((elapsed + 5))
    done
    # Everything from here until the fetch completes races the driver's
    # teardown deadline (fuzz-start + span + FETCH_MARGIN_S); log the
    # consumed time so future runs can see how much margin actually remains.
    local stop_begin_s
    stop_begin_s=$(date +%s)
    probe_guest_stop_fetch "${port}" "${probe}" || die "[${tool}] probe fetch failed"
    log "[${tool}] stop+fetch took $(( $(date +%s) - stop_begin_s ))s of the ${FETCH_MARGIN_S}s teardown margin"
    host_report "${probe}"

    log "[${tool}] waiting for driver to finish (margin tail)"
    wait "${driver}"
    local rc=$?
    ACTIVE_JOB_PID=""
    log "[${tool}] driver exit rc=${rc}"
    # Archive the ledger log next to the probe. Resolved here, lazily,
    # rather than polled for earlier: the run is over by this point, so the
    # file is either already there or never will be -- no waiting needed
    # either way. syz's ledger (syz_perf_serial.log) already lives at a
    # fixed, known path under drv and needs no discovery or copy.
    if [ "${tool}" = rfz ]; then
        local cfgj="${drv}/D_refuzz_run_01/refuzz_config.json"
        local wd="" tl=""
        if [ -f "${cfgj}" ]; then
            wd=$(python3 -c "import json;print(json.load(open('${cfgj}'))['work_dir'])" 2>/dev/null)
        fi
        [ -n "${wd}" ] && tl=$(ls "${wd}"/run-*/vm-*/worker.log 2>/dev/null | head -1)
        if [ -n "${tl}" ]; then
            cp -f "${tl}" "${out}/worker.log" 2>/dev/null || log "WARN: worker.log archive failed"
        else
            log "WARN: could not locate worker.log for archiving (work_dir=${wd:-<unresolved>})"
        fi
        # [RTT] Same archive for host_events.txt, using speed_compare.py's own
        # discovery pattern (newest_host_events()) the way replay_rfz() does.
        # Without this a standalone/capture run's RTT trace stays buried in the
        # orchestrator work dir under a per-run timestamped path, where nothing
        # downstream looks -- so the run silently fails the "same instrumentation
        # as a replay" bar even with --rtt-trace-sample-rate on. Absent unless
        # that flag was passed, hence no WARN when it is missing.
        local he=""
        [ -n "${wd}" ] && he=$(ls "${wd}"/run-*/logs/host_events.txt 2>/dev/null | head -1)
        if [ -n "${he}" ] && [ -s "${he}" ]; then
            cp -f "${he}" "${out}/host_events.txt" 2>/dev/null \
                || log "WARN: host_events.txt archive failed"
        fi
    fi
    return "${rc}"
}

# ---------------------------------------------------------------------------
# capture-syz-request-stream — independent syz capture for a later reFuzz
# fixed-input replay (docs/plans/fixed-request-stream-performance-replay.md).
# Deliberately NOT the old proxy-based capture: syz-executor deploys via
# syz-manager's normal host->VM copy, no executor_bin_on_target override, no
# 9p mount, no syz_flatrpc_proxy anywhere in the path. The program/order
# syz-manager's own source.Next() pulled is captured entirely on the HOST by
# syz-manager's own async sink (-request-stream, wired through
# speed_compare.py's --syz-request-stream -- see pkg/rpcserver/
# request_stream_sink.go). Native [SyzTL]/[SyzExecCPU]/[SyzRoleCPU]/[SyzCPU]
# performance telemetry needs no extra wiring either: speed_compare.py's
# make_syz_manager_config() already pipes the guest's ttyS1 into
# syz_perf_serial.log for every syz-manager it launches, unconditionally.
# This function only adds guest-wide perf record over the same wall-clock
# span as standalone_one(), whose syz branch it otherwise mirrors exactly
# (same VM-lifetime clamp, same attach/detach mechanism -- both are facts
# about the fuzzing VM, independent of how the request stream is captured).
# ---------------------------------------------------------------------------

capture_syz_request_stream() {
    local out="${RUN_DIR}/syz"
    local drv="${out}/driver"
    local probe="${out}/probe"
    mkdir -p "${out}" "${probe}"
    local request_stream="${out}/request_stream.bin"
    [ -e "${request_stream}" ] && die "[syz] refusing stale request_stream at ${request_stream}"

    # The capture is the most expensive single step here (~70min at a 1h span)
    # and it is the step that DEFINES the stream format: a syz-manager built
    # before the v1->v2 change writes an RFZREQS1 stream that neither current
    # reader accepts, and the failure would only surface an hour later. Driven
    # with --skip-build, so nothing else checks this.
    local syz_root
    syz_root=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["syzkaller"])' \
                   "${SYZ_CONFIG}") || die "[syz] cannot read syzkaller root from ${SYZ_CONFIG}"
    assert_go_binary_current "${syz_root}/bin/syz-manager" "[syz]" "${syz_root}" ./syz-manager

    # Same syz-manager 1h VM-lifetime wall as standalone_one() -- see its
    # comment. A fuzzing-VM fact, independent of how the stream is captured.
    local span="${DURATION_S}"
    if [ "${span}" -gt "${SYZ_MAX_SPAN_S}" ]; then
        span="${SYZ_MAX_SPAN_S}"
        log "[syz] span clamped ${DURATION_S}s -> ${span}s (syz-manager 1h VM lifetime)"
    fi
    local drv_duration=$((span + FETCH_MARGIN_S))
    log "[syz] request-stream capture: driver=${drv_duration}s sampled span=${span}s"

    # No wrapping subshell -- see standalone_one()'s comment on the same
    # pattern; $! must be speed_compare.py's own pid for kill -TERM to reach
    # its SIGTERM handler and killpg() the detached syz-manager/QEMU group.
    local -a launch=(python3 "${ROOT}/scripts/speed_compare/speed_compare.py" --arms D
            --only syzkaller --runs 1 --duration "${drv_duration}"
            --syz-config "${SYZ_CONFIG}" --out-dir "${drv}" --skip-build
            --syz-request-stream "${request_stream}"
            --rtt-trace-sample-rate 1
            --corpus-cache-dir "${CORPUS_CACHE_DIR}"
            --image-cache-dir "${IMAGE_CACHE_DIR}")
    "${launch[@]}" > "${out}/driver.log" 2>&1 &
    local driver=$!
    ACTIVE_JOB_PID="${driver}"
    log "[syz] driver pid=${driver}"

    local port
    port=$(wait_guest_ssh "${BOOT_TIMEOUT_S}" "${driver}") || die "[syz] guest ssh unreachable"
    probe_guest_start "${port}" || die "[syz] probe start failed"
    log "[syz] full-span sampling for ${span}s on port ${port}"

    local elapsed=0
    local mgr_log=""
    while [ "${elapsed}" -lt "${span}" ]; do
        kill -0 "${driver}" 2>/dev/null || { tail -8 "${out}/driver.log" >&2; die "[syz] driver died mid-span (guest data lost with VM)"; }
        # A mid-span VM replacement is unrecoverable for this probe and must be
        # caught HERE, not at fetch time: perf is recording inside that guest,
        # so its recording dies with the VM, and syz-manager's replacement gets
        # a fresh hostfwd port -- the fetch below would then fail with a bare
        # "connection refused" a full span later, with nothing pointing at the
        # real cause. Observed 2026-07-25: "BUG: MAX_LOCKDEP_KEYS too low!" →
        # syz-manager replaced VM 0 → stale port at fetch, 20min wasted.
        [ -n "${mgr_log}" ] || mgr_log=$(ls "${drv}"/D_syz_run_*/syz-manager.log 2>/dev/null | head -1)
        if [ -n "${mgr_log}" ] \
           && grep -qE 'VM [0-9]+: (crash|running for .*restarting)' "${mgr_log}" 2>/dev/null; then
            grep -nE 'VM [0-9]+: (crash|running for .*restarting)' "${mgr_log}" | head -3 >&2
            die "[syz] guest VM replaced ${elapsed}s into the ${span}s span; the perf recording died with it -- retry the capture"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    local stop_begin_s
    stop_begin_s=$(date +%s)
    probe_guest_stop_fetch "${port}" "${probe}" || die "[syz] probe fetch failed"
    log "[syz] stop+fetch took $(( $(date +%s) - stop_begin_s ))s of the ${FETCH_MARGIN_S}s teardown margin"
    host_report "${probe}"

    log "[syz] waiting for driver to finish (margin tail)"
    wait "${driver}"
    local rc=$?
    ACTIVE_JOB_PID=""
    [ "${rc}" -eq 0 ] || die "[syz] driver failed rc=${rc}"

    [ -s "${request_stream}" ] || die "[syz] request_stream.bin missing or empty: ${request_stream}"

    # Locate by glob, not a hardcoded "D_syz_run_01" -- that literal only
    # happens to be right because this function always passes --runs 1;
    # reaching into speed_compare.py's internal naming convention from
    # outside is fragile. Copy to a stable, well-known path under ${out} so
    # nothing downstream needs to know speed_compare.py's layout either.
    local found_perf_log
    found_perf_log=$(ls "${drv}"/D_syz_run_*/syz_perf_serial.log 2>/dev/null | head -1)
    [ -n "${found_perf_log}" ] && [ -s "${found_perf_log}" ] \
        || die "[syz] missing native perf serial under ${drv}/D_syz_run_*/"
    local syz_perf_log="${out}/syz_perf_serial.log"
    cp -f "${found_perf_log}" "${syz_perf_log}"
    for m in SyzTL SyzExecCPU SyzRoleCPU SyzCPU; do
        grep -q "\[${m}\]" "${syz_perf_log}" || die "[syz] syz_perf_serial.log missing [${m}] records"
    done

    local found_task_trace
    found_task_trace=$(ls "${drv}"/D_syz_run_*/syz_task_trace.jsonl 2>/dev/null | head -1)
    local syz_task_trace=""
    if [ -n "${found_task_trace}" ] && [ -s "${found_task_trace}" ]; then
        syz_task_trace="${out}/syz_task_trace.jsonl"
        cp -f "${found_task_trace}" "${syz_task_trace}"
    else
        log "WARN: [syz] no syz_task_trace.jsonl found under ${drv}/D_syz_run_*/ (RTT E1-E9 data missing)"
    fi

    log "[syz] capture complete: request_stream=${request_stream} perf_serial=${syz_perf_log} task_trace=${syz_task_trace:-<missing>}"
}

# capture-rfz — the mirror of capture_syz_request_stream(). reFuzz fuzzes
# normally for DURATION_S; its host-side sink (control/src/request_stream_sink.cpp)
# writes dispatched.jsonl, which is then converted to the SAME canonical stream
# format capture-syz publishes, so the two capture modes are interchangeable
# inputs to replay/replay-both.
#
# Deliberately a thin wrapper over standalone_one rfz: the capture run must be
# the baseline run plus one switch, nothing else. The first attempt at this used
# a forked config file instead, which silently diverged (it dropped
# task_trace_sample_rate, so the capture carried no per-program durations) and
# left a capture run that could not be compared to the standalone baseline it
# was meant to feed.
capture_rfz_request_stream() {
    local out="${RUN_DIR}/rfz"
    local jsonl="${out}/dispatched.jsonl"
    local request_stream="${out}/request_stream.bin"
    [ -e "${jsonl}" ] && die "[rfz] refusing stale capture at ${jsonl}"
    [ -e "${request_stream}" ] && die "[rfz] refusing stale request_stream at ${request_stream}"
    mkdir -p "${out}"

    # The converter is the step that DEFINES the stream format on this side --
    # same argument as capture_syz_request_stream's syz-manager check, since it
    # writes through pkg/requeststream's Go writer.
    local syz_root
    syz_root=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["syzkaller"])' \
                   "${SYZ_CONFIG}") || die "[rfz] cannot read syzkaller root from ${SYZ_CONFIG}"
    local converter="${syz_root}/bin/syz-stream-from-jsonl"
    assert_go_binary_current "${converter}" "[rfz]" "${syz_root}" ./tools/syz-stream-from-jsonl

    CAPTURE_RFZ_STREAM="${jsonl}"
    standalone_one rfz || die "[rfz] capture run failed"

    # The sink publishes by rename on graceful close and publishes nothing at
    # all if the capture was invalidated, so "the file exists" already means
    # "the stream is complete". Check anyway: a config that never reached the
    # sink would also produce no file, and the two are worth telling apart.
    [ -s "${jsonl}" ] || die "[rfz] no dispatched.jsonl published -- capture invalidated or never armed; grep RequestStreamSink in ${out}/driver/D_refuzz_run_*/refuzz.log"

    log "[rfz] converting ${jsonl} -> ${request_stream}"
    "${converter}" -in "${jsonl}" -out "${request_stream}" \
        || die "[rfz] stream conversion failed"
    local ver recs bytes
    read -r ver recs bytes <<<"$(stream_header_info "${request_stream}")" || exit 1
    log "[rfz] capture complete: request_stream=${request_stream} (v${ver}, ${recs} records, ${bytes} bytes)"
}

reuse_syz_capture() { # reuse_syz_capture PRIOR_RUN_DIR
    # Import a previous run's syz-side artifacts instead of re-capturing. The
    # syz capture is the expensive half (a 1h span plus its fetch margin is
    # ~70min), and it is INDEPENDENT of the reFuzz side: nothing reFuzz does
    # can invalidate a request stream that syz-manager already published and
    # sealed with a footer. When only the rfz half failed, recapturing is pure
    # waste.
    #
    # Copies rather than symlinks so each run directory stays a self-contained,
    # immutable record of what it measured.
    local prior="$1"
    local src="${prior%/}/syz"
    local out="${RUN_DIR}/syz"
    [ -d "${src}" ] || die "REUSE_SYZ_FROM=${prior}: no syz/ under it"
    [ -s "${src}/request_stream.bin" ] || die "REUSE_SYZ_FROM: missing/empty ${src}/request_stream.bin"
    [ -s "${src}/syz_perf_serial.log" ] || die "REUSE_SYZ_FROM: missing ${src}/syz_perf_serial.log"
    [ -s "${src}/probe/gp.data" ] || die "REUSE_SYZ_FROM: missing ${src}/probe/gp.data (no kernel profile to compare against)"
    mkdir -p "${out}"
    log "[syz] reusing prior capture from ${src} (no re-capture)"
    cp -f "${src}/request_stream.bin" "${src}/syz_perf_serial.log" "${out}/" || die "[syz] reuse copy failed"
    [ -s "${src}/syz_task_trace.jsonl" ] \
        && { cp -f "${src}/syz_task_trace.jsonl" "${out}/" || die "[syz] reuse copy failed"; }
    cp -a "${src}/probe" "${out}/" || die "[syz] reuse probe copy failed"
    # Header AND footer. An imported stream is the one input this run does not
    # produce itself, so it is exactly where a v1 file can walk in unnoticed --
    # the footer magic alone cannot tell v1 from v2. See stream_header_info.
    local info
    info=$(stream_header_info "${out}/request_stream.bin") || exit 1
    log "[syz] reused stream: v$(echo "${info}" | cut -d' ' -f1), $(echo "${info}" | cut -d' ' -f2) records"
}

# ---------------------------------------------------------------------------
# replay_rfz — reFuzz side of the new replay mode. Fixed-input replay via
# control/orchestrator/refuzz's own run_mode=replay (FixedInputProducerJob),
# NOT refuzz-exec-replayer: no IChannel::Submit() bypass, no ref_result.bin.
# Every request enters through the SAME producer contract ExploreJob uses
# (ctx.emit() -> JobScheduler -> InMemoryTaskQueue -> dispatcher -> Channel ->
# worker -> FuzzerLoop::ProcessEventFeedback()), so worker.log's native
# [RfzTL]/[RfzExecCPU]/[RfzRoleCPU]/[RfzCPU] and the RTT E1-E9 pipeline (if
# RFZ_CONFIG sets telemetry.logging.task_trace_sample_rate) are exactly what
# a normal fuzz run already produces -- nothing new to wire up here.
#
# run_mode=replay also forces catch_all_triage_enabled=false and
# suppress_default_producer=true (orchestrator.cpp), so ExploreJob and every
# completion-derived task (triage/smash/retry/mutation) are already off;
# this function does not need to (and must not) touch that.
#
# The run self-terminates: SpawnFixedInputProducerJob's on_fully_drained
# calls RequestStop() once the stream is drained and every emitted request's
# completion has been observed -- the SAME signal-safe atomic flag a SIGINT
# handler sets (confirmed: orchestrator.cpp's fuzzer_thread loop polls this
# flag and exits through the identical shutdown path either way). This
# function waits for natural process exit, not a fixed sleep; REPLAY_SAFETY_
# CAP_S is only a wedged-run backstop.
# ---------------------------------------------------------------------------

# [fixed request stream] Replay the SAME stream through syzkaller's own normal
# request path (-mode stream-replay). Structurally a mirror of replay_rfz():
# drive the binary directly, sample its guest for the whole span, and hand over
# on the drained-marker handshake.
#
# Why syzkaller must replay at all, rather than reusing its capture run as the
# baseline: the capture run is syzkaller doing its whole job -- generating,
# mutating, triaging -- while reFuzz's replay only executes. Comparing those two
# mixes the execution mechanism with the program source. Replaying the identical
# ordered stream on both sides is what isolates the mechanism.
replay_syz() {
    local request_stream="$1"
    [ -s "${request_stream}" ] || die "[syz-replay] missing/empty request_stream: ${request_stream}"
    local out="${RUN_DIR}/syz_replay"
    local probe="${out}/probe"
    mkdir -p "${out}" "${probe}"
    local cfg="${out}/syz_replay_config.json"
    local work="${out}/work"
    local perf_log="${out}/syz_perf_serial.log"
    local task_trace="${out}/syz_task_trace.jsonl"
    local drained_marker="${out}/.replay_drained"
    local release_marker="${out}/.replay_release"
    rm -rf "${work}"; mkdir -p "${work}"
    rm -f "${drained_marker}" "${release_marker}" "${perf_log}" "${task_trace}"

    # Same three overrides speed_compare.py's make_syz_manager_config applies, so
    # the replay starts from the identical machine shape as a capture: a private
    # empty workdir, a private http port, and no corpus carried across runs. The
    # <run_dir> placeholder in qemu_args is what routes the guest's [SyzTL]
    # records to THIS run's serial file instead of the capture's.
    local syz_root
    syz_root=$(python3 "${ROOT}/scripts/perf_compare/materialize_syz_replay_config.py" \
                   "${SYZ_CONFIG}" "${cfg}" "${work}" "${out}" "${SYZ_REPLAY_HTTP}") \
        || die "[syz-replay] config materialization failed"

    local manager="${syz_root}/bin/syz-manager"
    assert_go_binary_current "${manager}" "[syz-replay]" "${syz_root}" ./syz-manager

    # A rough feasibility check before committing an hour: syzkaller replays at
    # roughly its own capture rate, so record_count/8 is a usable lower bound on
    # the replay's wall time. Log only -- the rate depends on the program mix,
    # and a wrong guess should not block a run.
    if [ -n "${STREAM_RECORDS}" ]; then
        log "[syz-replay] ${STREAM_RECORDS} records imply roughly $((STREAM_RECORDS / 8 / 60)) min of replay (VM lifetime raised to ${SYZ_REPLAY_VM_LIFETIME})"
    fi
    log "[syz-replay] replaying request stream via -mode stream-replay (normal request path)"
    "${manager}" -config "${cfg}" -mode stream-replay \
        -replay-stream "${request_stream}" \
        -replay-drained-marker "${drained_marker}" \
        -replay-release "${release_marker}" \
        -task-trace "${task_trace}" -task-trace-sample-rate 1 \
        -replay-vm-running-time "${SYZ_REPLAY_VM_LIFETIME}" \
        -bench "${out}/syz_bench.txt" \
        > "${out}/syz-manager.log" 2>&1 &
    local syz_pid=$!
    ACTIVE_JOB_PID="${syz_pid}"

    local port
    port=$(wait_guest_ssh "${REPLAY_BOOT_TIMEOUT_S}" "${syz_pid}") || die "[syz-replay] guest ssh unreachable after ${REPLAY_BOOT_TIMEOUT_S}s (seed-corpus load happens BEFORE the VM boots -- see REPLAY_BOOT_TIMEOUT_S)"
    probe_guest_start "${port}" || { kill "${syz_pid}" 2>/dev/null; die "[syz-replay] probe start failed"; }
    log "[syz-replay] perf started; waiting for the stream to drain (hold handshake)"

    # Wait for the MARKER, not for process exit: syz-manager tears the VM down
    # ~10s after the replay finishes, which cannot cover a 25-60s probe fetch.
    local elapsed=0
    while [ ! -e "${drained_marker}" ]; do
        if ! kill -0 "${syz_pid}" 2>/dev/null; then
            tail -15 "${out}/syz-manager.log" >&2
            die "[syz-replay] syz-manager exited before publishing the drained marker"
        fi
        # A replaced VM is unrecoverable for this probe, exactly as in the
        # capture path: perf is recording inside that guest.
        if grep -qE 'VM [0-9]+: (crash|running for .*restarting)' "${out}/syz-manager.log" 2>/dev/null; then
            grep -nE 'VM [0-9]+: (crash|running for .*restarting)' "${out}/syz-manager.log" | head -3 >&2
            die "[syz-replay] guest VM replaced ${elapsed}s into the replay; the perf recording died with it"
        fi
        if [ "${elapsed}" -ge "${REPLAY_SAFETY_CAP_S}" ]; then
            tail -15 "${out}/syz-manager.log" >&2
            kill -TERM "${syz_pid}" 2>/dev/null
            die "[syz-replay] replay exceeded REPLAY_SAFETY_CAP_S=${REPLAY_SAFETY_CAP_S}s (wedged?)"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    # Marker CONTENT is the verdict -- it is written for BOTH a full drain and a
    # truncated one, so its mere existence says nothing.
    local drain_verdict
    drain_verdict=$(head -1 "${drained_marker}" 2>/dev/null | tr -d '[:space:]')
    if [ "${drain_verdict}" = "incomplete" ]; then
        log "WARN: [syz-replay] replay did NOT cover the whole stream (marker=incomplete);"
        log "WARN:              fetching the probe anyway, but this run will be failed"
    fi
    log "[syz-replay] stream drained; VM held -- stopping and fetching the guest probe"

    local fetch_port
    fetch_port=$(find_guest_port)
    [ -n "${fetch_port}" ] || fetch_port="${port}"
    probe_guest_stop_fetch "${fetch_port}" "${probe}" || log "WARN: [syz-replay] probe fetch failed"
    : > "${release_marker}"
    host_report "${probe}"

    wait "${syz_pid}"
    local rc=$?
    ACTIVE_JOB_PID=""

    # Validate the timeline BEFORE judging rc, so a late non-zero exit still
    # leaves a diagnosable artifact set.
    [ -s "${perf_log}" ] || die "[syz-replay] missing native perf serial: ${perf_log}"
    for m in SyzTL SyzExecCPU SyzRoleCPU SyzCPU; do
        grep -q "\[${m}\]" "${perf_log}" || die "[syz-replay] ${perf_log} missing [${m}] records"
    done

    [ "${rc}" -eq 0 ] \
        || die "[syz-replay] syz-manager failed rc=${rc} (artifacts archived under ${out})"
    [ "${drain_verdict}" != "incomplete" ] \
        || die "[syz-replay] replay truncated (artifacts archived under ${out}, do NOT use its numbers)"
    # FATAL, not a warning. RTT is the first of the three metric classes this
    # whole flow exists to produce, and the run is passed -task-trace-sample-rate 1
    # explicitly -- an empty trace means the data is simply not there, and a run
    # that reports success without it burns two hours of VM time to deliver two
    # thirds of its purpose. (Observed 2026-07-25, zero-byte trace from a stale
    # binary; assert_go_binary_current above now catches that specific cause up front,
    # but this backstop catches every other one.)
    [ -s "${task_trace}" ] \
        || die "[syz-replay] syz_task_trace.jsonl is empty -- no RTT data (artifacts archived under ${out})"
    log "[syz-replay] replay complete: perf_serial=${perf_log} task_trace=${task_trace}"
}

replay_rfz() {
    local request_stream="$1"
    [ -s "${request_stream}" ] || die "[rfz] missing/empty request_stream: ${request_stream}"
    local out="${RUN_DIR}/rfz"
    local probe="${out}/probe"
    mkdir -p "${out}" "${probe}"
    local runtime_cfg="${out}/refuzz_replay_config.json"
    local tag="${RFZ_TAG}"   # same value; cleanup_active_job needs it globally
    # /tmp, not ${out}/work: the orchestrator appends its own run-<ts>-<pid>/
    # vm-0/ under work_dir before serial.sock, so work_dir itself must leave
    # ~50 bytes of headroom under the 108-byte UNIX socket path limit. A
    # RUN_DIR-nested path (this script's descriptive timestamped names) does
    # not fit that headroom -- confirmed by an actual qemu launch failure
    # ("UNIX socket path ... is too long") on the first smoke test. Same
    # reasoning already applied to ivshmem/doorbell below.
    local work="/tmp/${tag}/work"
    local ivshmem="/tmp/${tag}.ivshmem"
    local doorbell="/tmp/${tag}.sock"
    local drained_marker="${out}/.replay_drained"
    local release_marker="${out}/.replay_release"
    rm -f "${drained_marker}" "${release_marker}"
    python3 - "${RFZ_CONFIG}" "${runtime_cfg}" "${work}" \
        "${ivshmem}" "${doorbell}" "${WORKER_BIN}" "${request_stream}" \
        "${drained_marker}" "${release_marker}" "${RFZ_REPLAY_RUNTIME_S}" <<'PY'
import json, pathlib, sys
(src, out, work, ivshmem, doorbell, worker, stream, drained_marker, release_marker,
 runtime_cap) = sys.argv[1:]
with open(src, encoding="utf-8") as f:
    cfg = json.load(f)
cfg["work_dir"] = work
t = cfg["channel"]["transport"]
t["ivshmem_path"] = ivshmem
t["doorbell_socket_path"] = doorbell
cfg["phase0_worker_bin"] = worker
# [fixed request stream] see docs/plans/fixed-request-stream-performance-
# replay.md §6 -- orchestrator_config.cpp parses these under root.run_mode /
# root.replay.stream_path.
cfg["run_mode"] = "replay"
# [hold-before-teardown] The VM dies inside registry.StopAll() a few seconds
# after the stream drains, but stopping perf + scp'ing its data takes tens of
# seconds -- polling from out here can never win that race. The orchestrator
# publishes drained_marker_path once quiesced (VM still up) and blocks on
# release_path, which is what makes the guest probe fetch possible at all.
cfg["replay"] = {
    "stream_path": stream,
    "drained_marker_path": drained_marker,
    "release_path": release_marker,
    "hold_timeout_s": 1800,
}
# [RTT] force full task-trace sampling for this replay regardless of what
# RFZ_CONFIG set -- a replay run is specifically for performance data, so
# host_events.txt / the E1-E9 pipeline must be on, not left to the base
# config's default (refuzz_mabB_perf.json currently omits this field).
cfg.setdefault("telemetry", {}).setdefault("logging", {})["task_trace_sample_rate"] = 1
# [replay must drain] The base config is a FUZZING config: phase1_runtime_seconds
# bounds how long to fuzz, which is the right knob there and exactly the wrong one
# here. A replay is done when the stream is empty, not when a clock expires, and
# leaving the fuzzing value in place silently truncates the run -- observed
# 2026-07-27: an 86717-record stream stopped at 70709 (81.5%) after exactly 3600s
# and the producer correctly reported `incomplete`, discarding an hour of work.
# This is the same failure the syz side already guards against by raising the
# per-VM running time (SYZ_REPLAY_VM_LIFETIME); the reFuzz side had no equivalent.
# Raised to the script's own safety cap so that cap, not the config, is what bounds
# a wedged run.
cfg["phase1_run_limit_mode"] = "runtime"
cfg["phase1_runtime_seconds"] = int(runtime_cap)
# The orchestrator nests work_dir/run-<20-char-UTC-timestamp>-<pid>/vm-0/
# before serial.sock -- checking work_dir + "/serial.sock" alone missed that
# and let an actually-too-long path through (confirmed by a real qemu
# launch failure). Budget the worst realistic timestamp+pid suffix instead.
worst_case_suffix = "/run-20260101T000000Z-9999999/vm-0/serial.sock"
for p in (str(pathlib.Path(work)) + worst_case_suffix, doorbell):
    if len(str(p).encode()) >= 108:
        raise SystemExit(f"UNIX socket path too long: {p}")
with open(out, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2); f.write("\n")
PY

    local runner="${BUILD_DIR}/control/orchestrator/refuzz"
    # Both binaries, not just the host one: worker.log's [RfzTL]/[RfzExecCPU]/
    # [RfzRoleCPU]/[RfzCPU] records all come out of WORKER_BIN inside the guest,
    # so a stale worker silently costs the CPU-sampling half of the run the same
    # way a stale syz-manager cost the RTT half.
    assert_cmake_target_current "${BUILD_DIR}" refuzz "${runner}" "[rfz]"
    assert_cmake_target_current "${BUILD_DIR}" ivshmem_worker "${WORKER_BIN}" "[rfz worker]"
    log "[rfz] replaying request stream via run_mode=replay (native producer path)"
    # jemalloc, matching standalone_one()'s rfz branch. A replay holds the WHOLE
    # decoded stream resident -- 86717 records came to 8.6GB RSS under glibc
    # malloc on 2026-07-27, against a 950MB stream on a 20GB host -- and that
    # working set is what pushes the host into swap. The measurement then reads
    # the consequence rather than the mechanism: swap thrash starves the qemu
    # vCPU threads and the guest reports `rcu_preempt detected stalls`, which
    # kills the VM and takes the in-guest perf recording with it (observed the
    # same day, run e3-scale/both-p7w7). This is the one launch path that was
    # still missing it.
    #
    # REFUZZ_SEED_RARITY_PRIOR_ALPHA is deliberately NOT set here: it steers the
    # seed MAB, and a fixed-input replay has no seed selection to steer.
    env "LD_PRELOAD=${JEMALLOC_SO}" "${runner}" "${runtime_cfg}" > "${out}/refuzz.log" 2>&1 &
    local rfz_pid=$!
    ACTIVE_JOB_PID="${rfz_pid}"

    local port
    port=$(wait_guest_ssh "${REPLAY_BOOT_TIMEOUT_S}" "${rfz_pid}") || die "[rfz] guest ssh unreachable after ${REPLAY_BOOT_TIMEOUT_S}s (seed-corpus load happens BEFORE the VM boots -- see REPLAY_BOOT_TIMEOUT_S)"
    probe_guest_start "${port}" || { kill "${rfz_pid}" 2>/dev/null; die "[rfz] probe start failed"; }
    log "[rfz] perf started; waiting for the stream to drain (orchestrator hold handshake)"

    # Wait for the DRAINED MARKER, not for process exit: by the time the
    # process exits the VM is long gone. The marker means "all requests
    # completed, fuzzer thread joined, VM still alive and holding for us".
    local elapsed=0
    local rfz_events=""
    while [ ! -e "${drained_marker}" ]; do
        if ! kill -0 "${rfz_pid}" 2>/dev/null; then
            tail -15 "${out}/refuzz.log" >&2
            die "[rfz] orchestrator exited before publishing the drained marker"
        fi
        # A mid-replay channel recovery is fatal to the kernel profile and must
        # be caught HERE. Recovery reboots the VM, and the config runs the image
        # with snapshot=on, so the guest's `perf record` process AND /root/probe
        # are both destroyed with the old guest -- there is nothing left to
        # fetch afterwards no matter what we do. (Observed 2026-07-25: recovery
        # at replay+44min, then the fetch at +56min failed on a stale port and
        # an empty /root/probe.) `evt=phase_transition` must be on the matched
        # line: RuntimePanel snapshot messages also contain "to=..." text.
        [ -n "${rfz_events}" ] || rfz_events=$(ls "${work}"/run-*/logs/host_events.txt 2>/dev/null | head -1)
        if [ -n "${rfz_events}" ] \
           && grep -q 'evt=phase_transition.*to=\(recovering\|closed\)' "${rfz_events}" 2>/dev/null; then
            grep -o 'evt=phase_transition.*to=[a-z]*' "${rfz_events}" | tail -3 >&2
            die "[rfz] channel left 'running' ${elapsed}s into the replay; the guest perf recording died with that VM -- rerun"
        fi
        if [ "${elapsed}" -ge "${REPLAY_SAFETY_CAP_S}" ]; then
            tail -15 "${out}/refuzz.log" >&2
            kill -TERM "${rfz_pid}" 2>/dev/null
            die "[rfz] replay exceeded REPLAY_SAFETY_CAP_S=${REPLAY_SAFETY_CAP_S}s (wedged?)"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    # [replay drain verdict] The marker exists for BOTH exit paths: the producer's
    # on_fully_drained (whole stream emitted and completed) and the ordinary
    # run-limit backstop. Its content is the only thing that separates them, so a
    # truncated replay cannot masquerade as a complete one. Fetch the probe either
    # way -- the data already on disk is worth keeping -- but refuse to report the
    # run as good. (Observed 2026-07-25: a 7-worker replay leaked 16 in-flight
    # requests through single-worker restarts, idled 421s, and would have been
    # published as a full run.)
    local drain_verdict
    drain_verdict=$(head -1 "${drained_marker}" 2>/dev/null | tr -d '[:space:]')
    if [ "${drain_verdict}" = "incomplete" ]; then
        log "WARN: [rfz] replay did NOT cover the whole stream (marker=incomplete);"
        log "WARN:       fetching the probe anyway, but this run will be failed"
    fi
    log "[rfz] stream drained; VM held -- stopping and fetching the guest probe"
    # Re-resolve the port instead of reusing the one cached at attach time:
    # reFuzz allocates the guest ssh port dynamically per VM start
    # (vm_instance.cpp: ReserveUnusedPort(10000, 65535)), so any VM restart
    # invalidates the cached value. find_guest_port reads it live.
    local fetch_port
    fetch_port=$(find_guest_port)
    [ -n "${fetch_port}" ] || fetch_port="${port}"
    [ "${fetch_port}" = "${port}" ] \
        || log "WARN: [rfz] guest ssh port changed ${port} -> ${fetch_port} (VM restarted); using the live one"
    probe_guest_stop_fetch "${fetch_port}" "${probe}" || log "WARN: [rfz] probe fetch failed"
    # Release teardown regardless of fetch outcome: the run's own results are
    # already complete, so a failed fetch must not strand the VM until the
    # orchestrator's own hold_timeout_s backstop expires.
    : > "${release_marker}"
    host_report "${probe}"

    wait "${rfz_pid}"
    local rc=$?
    ACTIVE_JOB_PID=""

    # Archive BEFORE judging rc. worker.log / host_events.txt are this run's
    # actual measurements and live under a /tmp work_dir; a late non-zero exit
    # must not strand them there.
    local worker_log
    worker_log=$(ls "${work}"/run-*/vm-*/worker.log 2>/dev/null | head -1)
    [ -n "${worker_log}" ] && [ -s "${worker_log}" ] || die "[rfz] missing worker.log under ${work}"
    cp -f "${worker_log}" "${out}/worker.log" 2>/dev/null || log "WARN: worker.log archive failed"

    # [RTT] host_events.txt is speed_compare.py's own discovery pattern
    # (newest_host_events(): work_dir.glob("run-*/logs/host_events.txt"));
    # mirrored here since this function drives the orchestrator directly.
    local host_events
    host_events=$(ls "${work}"/run-*/logs/host_events.txt 2>/dev/null | head -1)
    local rtt_log=""
    if [ -n "${host_events}" ] && [ -s "${host_events}" ]; then
        rtt_log="${out}/host_events.txt"
        cp -f "${host_events}" "${rtt_log}" 2>/dev/null || log "WARN: host_events.txt archive failed"
    fi

    [ "${rc}" -eq 0 ] || die "[rfz] orchestrator failed rc=${rc} (artifacts archived under ${out})"
    [ "${drain_verdict}" != "incomplete" ] \
        || die "[rfz] replay truncated: the producer never signalled full drain (artifacts archived under ${out}, do NOT use its throughput/CPU numbers)"
    # FATAL for the same reason as the syz side: this function force-sets
    # task_trace_sample_rate=1 above, so a missing host_events.txt is a broken
    # run, not a configuration choice. Checked after the archive step so the
    # artifacts that DO exist are already safely out of the /tmp work_dir.
    [ -n "${rtt_log}" ] \
        || die "[rfz] no host_events.txt under ${work}/run-*/logs/ -- no RTT data (artifacts archived under ${out})"
    log "[rfz] replay complete: worker.log=${out}/worker.log host_events=${rtt_log:-<missing>}"
}

# compute_code_id — the fingerprint that decides which runs may be pooled.
#
# Every artifact that can change what a run MEASURES goes in: the three binaries
# that execute the workload, and the two scripts that drive and instrument it.
# Configs are deliberately NOT in here -- they are per-run inputs recorded
# separately, and two runs that differ only by worker count are still mutually
# comparable (that IS experiment 3).
#
# Exists because the old metadata.txt recorded configs but no code identity at
# all, so "the sink was rewritten, does the previous capture still count?" had no
# answer inside the data. Now it does: same code.id, comparable; different, not.
CODE_ID=""
CODE_JSON=""
compute_code_id() {
    [ -z "${CODE_ID}" ] || return 0
    local syz_root
    syz_root=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["syzkaller"])' \
                   "${SYZ_CONFIG}" 2>/dev/null) || syz_root=""
    CODE_JSON=$(python3 - "${BUILD_DIR}/control/orchestrator/refuzz" \
                          "${WORKER_BIN}" \
                          "${syz_root}/bin/syz-manager" \
                          "${ROOT}/scripts/perf_compare/perf_sampling.sh" \
                          "${ROOT}/scripts/speed_compare/speed_compare.py" \
                          "${ROOT}" "${syz_root}" <<'PY'
import hashlib, json, subprocess, sys

def sha(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

def git(root, *args):
    if not root:
        return None
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip()
    except Exception:
        return None

refuzz, worker, manager, ps, sc, rfz_root, syz_root = sys.argv[1:8]
bins = {"refuzz": sha(refuzz), "ivshmem_worker": sha(worker), "syz-manager": sha(manager)}
scripts = {"perf_sampling.sh": sha(ps), "speed_compare.py": sha(sc)}
# Ordered concatenation so the id is reproducible; a missing artifact hashes as
# the literal "None" rather than being skipped, so "the binary was not built"
# cannot silently collide with some other state.
digest = hashlib.sha256("|".join(
    f"{k}={v}" for k, v in list(bins.items()) + list(scripts.items())).encode()).hexdigest()[:12]
print(json.dumps({
    "id": digest,
    "refuzz_git": git(rfz_root, "rev-parse", "--short", "HEAD"),
    "refuzz_dirty": bool(git(rfz_root, "status", "--porcelain")),
    "syzkaller_git": git(syz_root, "rev-parse", "--short", "HEAD"),
    "syzkaller_dirty": bool(git(syz_root, "status", "--porcelain")),
    "bins": bins,
    "scripts": scripts,
}, ensure_ascii=False))
PY
) || die "code fingerprint failed"
    CODE_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "${CODE_JSON}")
    # Refreshed on every run rather than at build time: a stale CODEVER.json is
    # worse than none, and this is the only moment the harness is guaranteed to
    # be looking at the binaries it is about to run.
    mkdir -p "${ROOT}/run/perf"
    printf '%s\n' "${CODE_JSON}" > "${ROOT}/run/perf/CODEVER.json"
    log "code.id=${CODE_ID}"
}

# write_run_json STATUS — the run's identity card. Written as `running` the
# moment the run directory exists and rewritten on the way out, so an aborted
# run is self-identifying instead of being inferred from a MISSING file (the old
# rule "no metadata.txt means it died" also flagged every speed_compare-driven
# run, which never wrote one to begin with).
write_run_json() { # write_run_json running|complete|failed
    local status="$1"
    local stream_path="${RUN_DIR}/syz/request_stream.bin"
    local experiment="${EXPERIMENT}"
    if [ -z "${experiment}" ]; then
        case "${MODE}" in
            standalone|capture-syz|capture-rfz) experiment="e1-collect" ;;
            replay|replay-both)                 experiment="e2-replay"  ;;
        esac
    fi
    compute_code_id
    python3 - "${RUN_DIR}/RUN.json" "${status}" "${experiment}" "${MODE}" \
              "${CODE_JSON}" "${SYZ_CONFIG}" "${RFZ_CONFIG}" "${stream_path}" \
              "${STREAM_ID}" "${STREAM_VERSION}" "${STREAM_RECORDS}" "${STREAM_BYTES}" \
              "${STREAM_OVERRIDE}" "${REUSE_SYZ_FROM}" "${DURATION_S}" "${PERF_HZ}" \
              "${PER_REQUEST_TIMEOUT_MS}" "${RUN_DIR}" <<'PY'
import hashlib, json, os, sys, datetime

(out, status, experiment, mode, code_json, syz_cfg, rfz_cfg, stream_path,
 stream_id, sver, srecs, sbytes, override, reuse, duration, hz, timeout, run_dir) = sys.argv[1:19]

def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}

def dig(d, *keys):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d

def sha(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

prev = load(out)
rfz, syz = load(rfz_cfg), load(syz_cfg)

# who ran: derived from the mode, not asserted, so it cannot drift from what the
# script actually did.
who = {"capture-syz": "syz", "capture-rfz": "rfz", "replay": "rfz",
       "replay-both": "both"}.get(mode)
if mode == "standalone":
    who = "rfz" if os.path.isdir(os.path.join(run_dir, "rfz")) else "syz"
    if os.path.isdir(os.path.join(run_dir, "rfz")) and os.path.isdir(os.path.join(run_dir, "syz")):
        who = "both"

# Instruments are CHECKED, never claimed: the question this answers is "does this
# run carry the three measurements", and only the files on disk can answer it.
def side(d, rtt, wall):
    root = os.path.join(run_dir, d)
    if not os.path.isdir(root):
        return None
    return {
        "rtt":            os.path.isfile(os.path.join(root, rtt)),
        "wall_cpu":       os.path.isfile(os.path.join(root, wall)),
        "kernel_profile": os.path.isfile(os.path.join(root, "probe", "gp.data")),
    }

instruments = {"syz": side("syz_replay", "syz_task_trace.jsonl", "syz_perf_serial.log")
                      or side("syz", "syz_task_trace.jsonl", "syz_perf_serial.log"),
               "rfz": side("rfz", "host_events.txt", "worker.log")}

stream = None
if srecs:
    stream = {"id": stream_id or None, "version": int(sver) if sver else None,
              "records": int(srecs), "bytes": int(sbytes) if sbytes else None,
              "source": override or (reuse or None),
              # Hashing a ~1GB stream costs a few seconds and is only worth
              # paying once the run is over.
              "sha256": sha(stream_path) if status != "running" else prev.get("stream", {}).get("sha256")}

doc = {
    "experiment": experiment,
    "who": who,
    "status": status,
    "mode": mode,
    "stream": stream,
    "knobs": {"rfz_workers": dig(rfz, "channel", "transport", "n_workers"),
              "syz_procs": syz.get("procs"),
              "perf_hz": int(hz) if hz else None,
              "per_request_timeout_ms": int(timeout) if timeout else None,
              "duration_s": None if reuse and mode != "standalone" else int(duration)},
    "instruments": instruments,
    "code": json.loads(code_json),
    "configs": {"syz": syz_cfg, "rfz": rfz_cfg},
    "reuse_syz_from": reuse or None,
    "started_utc": prev.get("started_utc") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "finished_utc": None if status == "running"
                    else datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(out, "w") as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
    # WARN, not die: this also runs from the EXIT trap, where dying would recurse,
    # and losing the identity card is not worth discarding an hour of measurement.
    # It is loud in the log either way.
    [ $? -eq 0 ] || log "WARN: RUN.json (${status}) write failed"
}

write_metadata() {
    {
        echo "mode=${MODE}"
        # Only meaningful when THIS run captured: with REUSE_SYZ_FROM the span
        # belongs to the prior run, and recording it unqualified made a reused
        # run look like it had captured for an hour itself.
        if [ -n "${REUSE_SYZ_FROM}" ]; then
            echo "capture_duration_s=<inherited>"
            echo "reuse_syz_from=${REUSE_SYZ_FROM}"
        else
            echo "capture_duration_s=${DURATION_S}"
        fi
        echo "perf_hz=${PERF_HZ}"
        echo "syz_config=${SYZ_CONFIG}"
        echo "syz_baseline=$([ "${MODE}" = replay-both ] && echo replay || echo capture)"
        echo "rfz_config=${RFZ_CONFIG}"
        echo "per_request_timeout_ms=${PER_REQUEST_TIMEOUT_MS}"
        # The workload's identity. stream_version above all: v1 (SerializeForExec
        # bytes) and v2 (canonical syzlang ProgText) runs measure DIFFERENT things
        # on the reFuzz side and must never be pooled -- without it recorded here
        # nothing in the run directory says which one this was.
        [ -z "${STREAM_OVERRIDE}" ] || echo "stream_override=${STREAM_OVERRIDE}"
        if [ -n "${STREAM_VERSION}" ]; then
            echo "stream_version=${STREAM_VERSION}"
            echo "stream_records=${STREAM_RECORDS}"
            echo "stream_bytes=${STREAM_BYTES}"
        fi
        echo "generated_utc=$(date -u +%FT%TZ)"
    } > "${RUN_DIR}/metadata.txt"
}

# ---------------------------------------------------------------------------

MODE="${1:-}"
case "${MODE}" in
    standalone)
        shift
        TOOLS=("$@")
        [ "${#TOOLS[@]}" -gt 0 ] || TOOLS=(rfz syz)
        ;;
    capture-syz) ;;
    capture-rfz) ;;
    replay) ;;
    replay-both) ;;
    *)
        echo "usage: $0 standalone [rfz] [syz] | capture-syz | capture-rfz | replay | replay-both" >&2
        exit 2
        ;;
esac

RUN_DIR="${RUN_DIR:-${ROOT}/run/perf_sampling_$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${RUN_DIR}"
RUN_DIR=$(cd "${RUN_DIR}" && pwd)
log "mode=${MODE} run_dir=${RUN_DIR} duration=${DURATION_S}s hz=${PERF_HZ}"

for f in "${SSHK}" "${SYZ_CONFIG}" "${RFZ_CONFIG}"; do
    [ -e "${f}" ] || die "missing: ${f}"
done

# RUN.json goes down BEFORE any VM starts, and the EXIT trap demotes it to
# `failed` unless the normal path has already marked it `complete`. So every run
# directory carries its own verdict from the first second, and a run killed
# mid-flight never looks like one that merely lacks a summary file.
RUN_STATUS_FINAL=""
write_run_json running
finalize_run_json() { write_run_json "${RUN_STATUS_FINAL:-failed}"; }
trap 'cleanup_active_job; finalize_run_json' EXIT
# find_guest_port grabs whichever hostfwd pattern it sees first; a stray VM
# left over from a prior aborted run would make it attach to the wrong guest.
#
# Matched on comm, exactly -- NOT on full argv. An argv scan (`ps -eo args |
# grep '[q]emu-system'`) also matches any unrelated process that merely
# MENTIONS the string, e.g. a supervising retry loop that contains a
# `pkill qemu-...` line, and then refuses to start against a perfectly clean
# host (observed 2026-07-25). Note comm is truncated to 15 bytes by Linux, so
# the real process shows up as "qemu-system-x86", not "qemu-system-x86_64".
if pgrep -x qemu-system-x86 >/dev/null 2>&1; then
    log "FATAL: stray qemu VM process(es) already running:"
    pgrep -ax qemu-system-x86 >&2
    log "clean up before a fresh perf_sampling run"
    exit 1
fi

if [ "${MODE}" = standalone ]; then
    for tool in "${TOOLS[@]}"; do
        case "${tool}" in rfz|syz) ;; *) die "unknown tool ${tool}" ;; esac
        standalone_one "${tool}" || die "standalone ${tool} failed"
    done
elif [ "${MODE}" = capture-syz ]; then
    capture_syz_request_stream
elif [ "${MODE}" = capture-rfz ]; then
    capture_rfz_request_stream
else
    # [2026-07-24] replay mode rebuilt on the fixed-request-stream pipeline
    # (docs/plans/fixed-request-stream-performance-replay.md): syz captures
    # via the host-side async sink (no guest proxy, no 9p trace), reFuzz
    # replays via its own run_mode=replay producer (no refuzz-exec-replayer,
    # no ref_result.bin, no cross-system result pairing). Each side reports
    # only its own native performance data; nothing is paired here.
    if [ -n "${REUSE_SYZ_FROM}" ]; then
        reuse_syz_capture "${REUSE_SYZ_FROM}"
    else
        capture_syz_request_stream
    fi
    # Substituted AFTER the capture/reuse step so everything else about the run
    # directory is unchanged, and BEFORE validation so the replayed stream is the
    # one that gets checked and recorded in metadata.
    if [ -n "${STREAM_OVERRIDE}" ]; then
        [ -s "${STREAM_OVERRIDE}" ] || die "STREAM_OVERRIDE=${STREAM_OVERRIDE}: missing or empty"
        log "workload: replacing the captured stream with ${STREAM_OVERRIDE}"
        cp -f "${STREAM_OVERRIDE}" "${RUN_DIR}/syz/request_stream.bin" \
            || die "STREAM_OVERRIDE copy failed"
    fi
    # Validate the workload ONCE, before either replay commits a VM to it, and
    # keep the result: everything downstream (the syz feasibility estimate, the
    # run's metadata) reads these instead of re-deriving the count from the
    # footer in three different places.
    read -r STREAM_VERSION STREAM_RECORDS STREAM_BYTES \
        <<<"$(stream_header_info "${RUN_DIR}/syz/request_stream.bin")" || exit 1
    [ -n "${STREAM_RECORDS}" ] || die "request stream validation produced no record count"
    log "workload: stream v${STREAM_VERSION}, ${STREAM_RECORDS} records, ${STREAM_BYTES} bytes"
    # replay-both additionally replays the stream through syzkaller itself, so the
    # comparison is replay-vs-replay rather than syzkaller-fuzzing-vs-reFuzz-
    # replaying. `replay` keeps the older shape: syzkaller's own capture run is
    # the baseline, which still answers "how does each system behave doing its
    # normal job" but mixes program generation into syzkaller's side.
    local_syz_log="${RUN_DIR}/syz/syz_perf_serial.log"
    local_syz_probe="${RUN_DIR}/syz/probe"
    if [ "${MODE}" = replay-both ]; then
        replay_syz "${RUN_DIR}/syz/request_stream.bin"
        local_syz_log="${RUN_DIR}/syz_replay/syz_perf_serial.log"
        local_syz_probe="${RUN_DIR}/syz_replay/probe"
    fi
    replay_rfz "${RUN_DIR}/syz/request_stream.bin"
    python3 "${ROOT}/scripts/perf_compare/paired_exec_analyze.py" \
        --syz-log "${local_syz_log}" \
        --rfz-log "${RUN_DIR}/rfz/worker.log" \
        --output "${RUN_DIR}/independent_compare.md" \
        || log "WARN: independent performance report failed; raw native logs are preserved"
    # Kernel-profile attribution: the closure residual is UNEXPLAINED by design
    # (see independent_compare.md), and this comm/symbol breakdown is what
    # explains it. It was being run by hand after every run; a report nobody
    # generates is a report nobody reads.
    python3 "${ROOT}/scripts/perf_compare/probe_attribute.py" \
        "syz=${local_syz_probe}" "rfz=${RUN_DIR}/rfz/probe" \
        > "${RUN_DIR}/probe_attribution.txt" 2>&1 \
        || log "WARN: probe attribution failed; probe dirs are preserved"
    # RTT zones. The zone accounting (RTT_SUBINTERVALS/RTT_ZONE/
    # compute_rtt_percentiles) lives in speed_compare.py and is reached here
    # through its --rtt-report entry point rather than reimplemented, so the two
    # harnesses can never disagree about what a zone is. Only replay-both has a
    # syz-side trace to compare against: in plain `replay` mode syzkaller is
    # fuzzing, so its RTT includes generation/triage and is not the same
    # quantity as reFuzz's replay RTT.
    if [ "${MODE}" = replay-both ]; then
        python3 "${ROOT}/scripts/speed_compare/speed_compare.py" --rtt-report \
            "${RUN_DIR}/syz_replay/syz_task_trace.jsonl" \
            "${RUN_DIR}/rfz/host_events.txt" \
            "${RUN_DIR}/rtt_zones.md" \
            || log "WARN: RTT zone report failed; both task traces are preserved"
    fi
fi
write_metadata
RUN_STATUS_FINAL=complete   # read by the EXIT trap's finalize_run_json
log "done; artifacts under ${RUN_DIR}"
