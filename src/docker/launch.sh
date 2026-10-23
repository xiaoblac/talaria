#!/usr/bin/env bash
# launch.sh — 在服务器上并行起覆盖率实验容器（reFuzz ‖ syzkaller）。
#
# 一个容器 = 一个 (内核, run) 组合，容器内两侧 --d-parallel 同时跑。
# 本文件是 launch_6.sh / launch_7_1.sh / launch_9.sh / launch_rfz_only.sh 的
# 唯一合并入口：内核集合、run 数、单侧模式都用参数表达，不再维护四份拷贝。
#
# 用法:
#   docker/launch.sh                                  # 3 内核 × 3 run，各 48h（旧 launch_9）
#   docker/launch.sh --kernels v6.12,v6.18            # 只跑两个内核（旧 launch_6）
#   docker/launch.sh --kernels v7.1                   # 只跑 v7.1（旧 launch_7_1）
#   docker/launch.sh --only refuzz --runs 1           # 单 reFuzz-only 复测（旧 launch_rfz_only）
#
# 环境变量（与命令行参数等价，批量覆盖时用）:
#   KERNELS / RUNS / ONLY / DURATION / SCRATCH_PER / IMAGE / RESULTS /
#   TMP_ROOT / MONITOR_INTERVAL / MONITOR_LOG / SYZ_PERF_SERIAL / PREFIX /
#   RUN_START（旧 launch_rfz_only 的 RUN_ID 语义：从哪个 run id 开始）
#
# CPU 和内存不设置 cgroup 上限，所有容器由宿主调度器统一调度。容器使用
# 镜像默认的 root 用户；宿主启动脚本仍由 iic 账户直接执行。
#
# 为什么同一内核的 3 次 run 可以分到不同容器:
#   交付物是三张独立的图，跨版本覆盖率绝对值本不可比，同内核 3 次 run 之间只做
#   中位数 + min-max 带，不做跨容器的时刻对齐。真正要严格公平的是 reFuzz vs syz
#   这一对，而 --d-parallel 让它们始终在同一容器、同一时刻。
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MONITOR_INTERVAL="${MONITOR_INTERVAL:-1200}"
MONITOR_LOG="${MONITOR_LOG:-$HOME/chengyongkang/cov-monitor.log}"
IMAGE="${IMAGE:-refuzz-cov:latest}"
RESULTS="${RESULTS:-$HOME/chengyongkang/cov-results}"
TMP_ROOT="${TMP_ROOT:-$RESULTS/.container-tmp}"
SCRATCH_PER="${SCRATCH_PER:-8g}"
DURATION="${DURATION:-172800}"
RUNS="${RUNS:-3}"
RUN_START="${RUN_START:-1}"
SYZ_PERF_SERIAL="${SYZ_PERF_SERIAL:-0}"
ONLY="${ONLY:-both}"
PREFIX="${PREFIX:-auto}"
WAIT="${WAIT:-60}"
KERNELS="${KERNELS:-}"

die() { echo "launch: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernels)          KERNELS="${2:-}"; shift 2 ;;
        --runs)             RUNS="${2:-}"; shift 2 ;;
        --run-start)        RUN_START="${2:-}"; shift 2 ;;
        --only)             ONLY="${2:-}"; shift 2 ;;
        --duration)         DURATION="${2:-}"; shift 2 ;;
        --scratch-per)      SCRATCH_PER="${2:-}"; shift 2 ;;
        --prefix)           PREFIX="${2:-}"; shift 2 ;;
        --image)            IMAGE="${2:-}"; shift 2 ;;
        --results)          RESULTS="${2:-}"; shift 2 ;;
        --tmp-root)         TMP_ROOT="${2:-}"; shift 2 ;;
        --monitor-interval) MONITOR_INTERVAL="${2:-}"; shift 2 ;;
        --monitor-log)      MONITOR_LOG="${2:-}"; shift 2 ;;
        --wait)             WAIT="${2:-}"; shift 2 ;;
        *) die "未知参数: $1" ;;
    esac
done

# 旧 launch_rfz_only.sh 用单数 KERNEL/RUN_ID；显式命令行/环境没给 KERNELS 时沿用。
[[ -n "${KERNELS:-}" ]] || KERNELS="${KERNEL:-}"
KERNELS="${KERNELS:-v6.12,v6.18,v7.1}"
[[ -n "${RUN_ID:-}" && "$RUN_START" == "1" ]] && RUN_START="$RUN_ID"

case "$ONLY" in
    both|refuzz|syzkaller) ;;
    *) die "非法 --only: $ONLY（允许 both/refuzz/syzkaller）" ;;
esac
[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || die "--runs 必须是正整数: $RUNS"
[[ "$RUN_START" =~ ^[1-9][0-9]*$ ]] || die "--run-start 必须是正整数: $RUN_START"

# 容器名前缀：默认 cov-（双侧/单 syz）；--only refuzz 用 rfz-，避免与已有
# cov- 容器撞名（旧 launch_rfz_only.sh 行为）。显式 --prefix 覆盖。
if [[ "$PREFIX" == "auto" ]]; then
    [[ "$ONLY" == "refuzz" ]] && PREFIX="rfz" || PREFIX="cov"
fi

IFS=',' read -r -a KERNEL_LIST <<< "$KERNELS"
[[ ${#KERNEL_LIST[@]} -gt 0 ]] || die "--kernels 为空"

command -v docker >/dev/null || die "没有 docker"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "镜像 $IMAGE 不存在"
[[ -c /dev/kvm ]] || die "/dev/kvm 不存在"

KVM_GID=$(stat -c %g /dev/kvm)
NCONT=$(( ${#KERNEL_LIST[@]} * RUNS ))

mkdir -p "$RESULTS" "$TMP_ROOT"
avail_disk=$(df -Pm "$RESULTS" | awk 'NR==2{print $4}')
if [[ ! "$SCRATCH_PER" =~ ^([0-9]+)([mMgG]?)$ ]]; then
    die "SCRATCH_PER 格式错误: $SCRATCH_PER（支持 8192、8192m、8g）"
fi
scratch_value=${BASH_REMATCH[1]}
case "${BASH_REMATCH[2]}" in
    g|G) scratch_mb=$(( scratch_value * 1024 )) ;;
    m|M|"") scratch_mb=$scratch_value ;;
esac
need_disk=$(( NCONT * (20480 + scratch_mb) ))
[[ $avail_disk -ge $need_disk ]] || \
    die "$RESULTS 只剩 ${avail_disk}MB，$NCONT 个容器要 ${need_disk}MB（结果 20G + scratch ${SCRATCH_PER}/容器）"

echo "=============================================================="
echo "镜像      $IMAGE"
echo "容器数    $NCONT (${KERNELS} × $RUNS run，从 run $RUN_START 起)"
echo "容器名    ${PREFIX}-<kernel>-r<run>"
echo "容器身份  root（宿主脚本请由 iic 直接执行）"
echo "核心      UNBOUND（不设置 cpuset 或 CPU quota）"
echo "内存      UNBOUND（不设置 memory/memory-swap）"
echo "共享内存  /dev/shm 上限 4g（按需占用，不预分配）"
echo "临时目录  $TMP_ROOT/<容器名> → /tmp（磁盘 bind）"
echo "syz采样    ${SYZ_PERF_SERIAL}（1=开 0=关，覆盖率实验建议 0）"
echo "时长      ${DURATION}s ($(( DURATION / 3600 ))h)"
echo "结果      $RESULTS"
echo "=============================================================="

# 先检查有没有同名容器残留，避免 docker run 报错到一半、起了几个停在那。
for k in "${KERNEL_LIST[@]}"; do
    for r in $(seq "$RUN_START" $(( RUN_START + RUNS - 1 ))); do
        name="${PREFIX}-${k}-r${r}"
        if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
            die "容器 $name 已存在。先 docker rm -f \$(docker ps -aq -f name=^${PREFIX}-)"
        fi
    done
done

launched=()
for k in "${KERNEL_LIST[@]}"; do
    for r in $(seq "$RUN_START" $(( RUN_START + RUNS - 1 ))); do
        name="${PREFIX}-${k}-r${r}"
        outdir="$RESULTS/${k}-r${r}"
        tmpdir="$TMP_ROOT/$name"
        mkdir -p "$outdir" "$tmpdir"
        chmod 1777 "$tmpdir"

        # 每个容器把独立的宿主磁盘目录 bind 到 /tmp：保留 Unix socket 所需的
        # 短路径，同时让 workdir、日志和 QEMU 临时写层直接落盘。
        # --network none — 两侧的 ssh 和 http 都走回环，namespace 里的 lo 够用；
        #   物理上排除跨容器端口撞车，也断掉 48h 无人值守时的外联面。
        # --cap-add SYS_PTRACE — syz-manager 符号化要读 /proc/<pid>/mem。
        docker run -d \
            --name "$name" \
            --device /dev/kvm \
            --group-add "$KVM_GID" \
            --mount "type=bind,src=$tmpdir,dst=/tmp" \
            -e SYZ_PERF_SERIAL="$SYZ_PERF_SERIAL" \
            --shm-size 4g \
            --cap-add SYS_PTRACE \
            --network none \
            --restart no \
            -v "$outdir:/results/${k}-r${r}" \
            "$IMAGE" \
            --kernel "$k" --run-id "$r" --duration "$DURATION" --only "$ONLY" \
            > /dev/null

        echo "  起 $name  container=root CPU/MEM UNBOUND → $outdir"
        launched+=("$name")
    done
done

bash "$SCRIPT_DIR/restart_cov_monitor.sh" \
    --interval "$MONITOR_INTERVAL" --log "$MONITOR_LOG"

echo
echo "$NCONT 个容器已起。等 ${WAIT}s 看有没有秒退的。"
sleep "$WAIT"

fail=0
for name in "${launched[@]}"; do
    st=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo gone)
    if [[ "$st" != "running" ]]; then
        code=$(docker inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null || echo ?)
        echo "  [失败] $name status=$st exit=$code"
        echo "         最后 15 行:"
        docker logs --tail 15 "$name" 2>&1 | sed 's/^/           /'
        fail=$(( fail + 1 ))
    else
        echo "  [ok] $name"
    fi
done

if [[ $fail -gt 0 ]]; then
    echo
    echo "$fail 个容器没起来。自检失败的原因看上面 —— 常见是 /dev/kvm 权限"
    echo "或 /tmp noexec。修完 docker rm -f \$(docker ps -aq -f name=^${PREFIX}-) 重来。"
    exit 1
fi

cat <<EOF

全部运行中。预计 $(date -u -d "+$(( DURATION / 3600 + 1 )) hours" +%Y-%m-%dT%H:%MZ) 前后结束。

盯进度:
  docker ps --filter name=^${PREFIX}- --format 'table {{.Names}}\t{{.Status}}'
  tail -f $RESULTS/${KERNEL_LIST[0]}-r${RUN_START}/harness.log
  for d in $RESULTS/*/; do echo "\$d \$(grep -c . "\$d"/D_cov_*.csv 2>/dev/null | head -1)"; done

跑完收数据:
  docker/collect.sh $RESULTS
EOF
