#!/usr/bin/env bash
# Server-side launcher for the refuzz-perf image.
#
# Starts the four replay performance runs in parallel:
#   W1 (syz-a) x w6, W1 x w7, W2 (rfz-a) x w6, W2 x w7
#
# Usage:
#   bash docker/launch_perf_containers.sh \
#       --results /data/perf-results \
#       --image refuzz-perf:latest \
#       [--only W1-6|W1-7|W2-6|W2-7] \
#       [--perf-hz 19] [--cpuset 0-15] [--wait 60] [--force]
set -euo pipefail

RESULTS="${RESULTS:-/data/perf-results}"
IMAGE="${IMAGE:-refuzz-perf:latest}"
ONLY=""
PERF_HZ="${PERF_HZ:-19}"
PER_REQUEST_TIMEOUT_MS="${PER_REQUEST_TIMEOUT_MS:-5000}"
RFZ_REPLAY_RUNTIME_S="${RFZ_REPLAY_RUNTIME_S:-7200}"
REPLAY_BOOT_TIMEOUT_S="${REPLAY_BOOT_TIMEOUT_S:-3600}"
WAIT="${WAIT:-60}"
CPUSET=""
FORCE=0

die() { echo "launch_perf_containers: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --results) RESULTS="${2:-}"; shift 2 ;;
        --image)   IMAGE="${2:-}";   shift 2 ;;
        --only)    ONLY="${2:-}";    shift 2 ;;
        --perf-hz) PERF_HZ="${2:-}"; shift 2 ;;
        --boot-timeout) REPLAY_BOOT_TIMEOUT_S="${2:-}"; shift 2 ;;
        --cpuset)  CPUSET="${2:-}";  shift 2 ;;
        --wait)    WAIT="${2:-}";    shift 2 ;;
        --force)   FORCE=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done

command -v docker >/dev/null || die "docker not found"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not loaded"
[[ -c /dev/kvm ]] || die "/dev/kvm missing"
if [[ ! -w /dev/kvm ]]; then
    echo "warning: /dev/kvm not writable by $USER; relying on root docker daemon" >&2
fi
KVM_GID=$(stat -c %g /dev/kvm)

mkdir -p "$RESULTS"
avail_mb=$(df -Pm "$RESULTS" | awk 'NR==2{print $4}')
[[ "$avail_mb" -ge 10240 ]] || die "results disk too small: ${avail_mb}MB free (need >=10GB)"

ALL_COMBOS=("W1 6" "W1 7" "W2 6" "W2 7")
COMBOS=()
if [[ -n "$ONLY" ]]; then
    case "$ONLY" in
        W1-6) COMBOS=("W1 6") ;;
        W1-7) COMBOS=("W1 7") ;;
        W2-6) COMBOS=("W2 6") ;;
        W2-7) COMBOS=("W2 7") ;;
        *) die "--only must be W1-6|W1-7|W2-6|W2-7" ;;
    esac
else
    COMBOS=("${ALL_COMBOS[@]}")
fi

MANIFEST="$RESULTS/launch_manifest.txt"
: > "$MANIFEST"

names=()
for combo in "${COMBOS[@]}"; do
    wl=${combo% *}
    wk=${combo#* }
    name="refuzz-perf-${wl}-w${wk}"
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
        if [[ "$FORCE" -eq 1 ]]; then
            docker rm -f "$name" >/dev/null
        else
            die "container $name already exists (use --force to remove)"
        fi
    fi

    args=(docker run -d --name "$name"
          --device /dev/kvm --group-add "$KVM_GID"
          --shm-size 4g --cap-add SYS_PTRACE --network none)
    [[ -n "$CPUSET" ]] && args+=(--cpuset-cpus "$CPUSET")
    args+=(-v "$RESULTS:/results"
           -e OUT_ROOT=/results
           -e PERF_HZ="$PERF_HZ"
           -e PER_REQUEST_TIMEOUT_MS="$PER_REQUEST_TIMEOUT_MS"
           -e RFZ_REPLAY_RUNTIME_S="$RFZ_REPLAY_RUNTIME_S"
           -e REPLAY_BOOT_TIMEOUT_S="$REPLAY_BOOT_TIMEOUT_S")
    args+=("$IMAGE" --workload "$wl" --workers "$wk")

    "${args[@]}" >/dev/null
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$wl" "$wk" "$RESULTS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MANIFEST"
    names+=("$name")
done

echo "waiting ${WAIT}s for startup..."
sleep "$WAIT"

fail=0
for name in "${names[@]}"; do
    st=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo gone)
    if [[ "$st" != "running" ]]; then
        echo "[FAIL] $name status=$st"
        docker logs --tail 30 "$name" 2>&1 | sed 's/^/    /'
        fail=1
    else
        echo "[ok]   $name"
    fi
done
[[ "$fail" -eq 0 ]] || exit 1

echo
echo "all containers running; manifest: $MANIFEST"
echo "outputs: $RESULTS/e3-scale/"
