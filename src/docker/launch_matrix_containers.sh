#!/usr/bin/env bash
# launch_matrix_containers.sh — 宿主侧启动脚本：
# 并行起 N（默认 3）个 refuzz-perf 容器，每个容器内跑完整矩阵轮次
# （W1×6 → W1×7 → W2×6 → W2×7，作业内 syz+rfz 并行）。
# 用法:
#   bash docker/launch_matrix_containers.sh \
#       --results /home/iic/chengyongkang/perf-matrix \
#       --scripts /home/iic/chengyongkang/jiaoben \
#       [--n 3] [--image refuzz-perf:latest] [--force]
#       [--start-index 2] [--start-combo W2-6] [--max-retry 2]
#   --start-index: 容器序号起点（默认 1）。补跑时用 --n 1 --start-index 2 只重建
#                  refuzz-perf-matrix-2，不影响 1/3。
#   --start-combo: 从指定作业开始（断点续跑，跳过已完成作业），默认 W1-6
#   --max-retry:   单作业失败重试次数（syzkaller 高并发概率性 SYZFAIL），默认 2
set -euo pipefail

RESULTS="${RESULTS:-/home/iic/chengyongkang/perf-matrix}"
SCRIPTS="${SCRIPTS:-/home/iic/chengyongkang/jiaoben}"
IMAGE="${IMAGE:-refuzz-perf:latest}"
N="${N:-3}"
FORCE=0
START_COMBO="${START_COMBO:-}"
MAX_RETRY="${MAX_RETRY:-}"
START_INDEX="${START_INDEX:-1}"

die() { echo "launch_matrix_containers: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --results) RESULTS="${2:-}"; shift 2 ;;
        --scripts) SCRIPTS="${2:-}"; shift 2 ;;
        --image)   IMAGE="${2:-}";   shift 2 ;;
        --n)       N="${2:-}";       shift 2 ;;
        --force)   FORCE=1; shift ;;
        --start-combo) START_COMBO="${2:-}"; shift 2 ;;
        --max-retry)   MAX_RETRY="${2:-}";   shift 2 ;;
        --start-index) START_INDEX="${2:-}"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done

command -v docker >/dev/null || die "docker not found"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not loaded"
[[ -c /dev/kvm ]] || die "/dev/kvm missing"
KVM_GID=$(stat -c %g /dev/kvm)

for f in run_matrix.sh replay_both_parallel.sh; do
    [[ -f "$SCRIPTS/$f" ]] || die "missing $SCRIPTS/$f"
done

mkdir -p "$RESULTS"
avail_mb=$(df -Pm "$RESULTS" | awk 'NR==2{print $4}')
[[ "$avail_mb" -ge 20480 ]] || die "results disk too small: ${avail_mb}MB free (need >=20GB)"

names=()
for i in $(seq "$START_INDEX" $(( START_INDEX + N - 1 ))); do
    name="refuzz-perf-matrix-${i}"
    if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
        if [[ "$FORCE" -eq 1 ]]; then
            docker rm -f "$name" >/dev/null
        else
            die "container $name already exists (use --force to remove)"
        fi
    fi
    mkdir -p "${RESULTS}-${i}"
    docker run -d --name "$name" \
        --device /dev/kvm --group-add "$KVM_GID" \
        --shm-size 4g --cap-add SYS_PTRACE --network none \
        -v "${RESULTS}-${i}:/results" \
        -v "$SCRIPTS:/matrix:ro" \
        -e OUT_ROOT=/results \
        ${START_COMBO:+-e START_COMBO="$START_COMBO"} \
        ${MAX_RETRY:+-e MAX_RETRY="$MAX_RETRY"} \
        --entrypoint /bin/bash \
        "$IMAGE" /matrix/run_matrix.sh >/dev/null
    names+=("$name")
    echo "[started] $name -> ${RESULTS}-${i}"
done

echo
echo "started $N matrix containers: ${names[*]}"
echo "outputs: ${RESULTS}-<i>/e3scale-matrix/"
echo "monitor: docker logs -f ${names[0]}"
