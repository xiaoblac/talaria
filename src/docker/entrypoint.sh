#!/usr/bin/env bash
# entrypoint.sh — 容器里跑一个 (内核, run) 组合的 48h coverage 实验。
#
# 用法: entrypoint.sh --kernel v6.12 --run-id 1 [--duration 172800]
#
# 一个容器 = 一个内核的一次 run，内含 reFuzz ‖ syzkaller 一对（--d-parallel）。
# 为什么 --runs 1 而不是 --runs 3: 9 个容器已经把 run 维度展开了，run 之间的
# 并行由 docker 提供。这样 3 次 run 落在 3 个独立的 /results 目录，最后由
# plot_cov_runs.py 跨目录聚合。
set -euo pipefail

KERNEL=""
RUN_ID=""
DURATION="${DURATION:-172800}"   # 48h
WARMUP="${WARMUP:-0}"            # 覆盖率曲线锚在首次 fuzz exec，不需要预热窗口
ONLY="${ONLY:-both}"             # both | refuzz | syzkaller（单侧调试/复测用）

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)   KERNEL="$2"; shift 2 ;;
        --run-id)   RUN_ID="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --warmup)   WARMUP="$2"; shift 2 ;;
        --only)     ONLY="$2"; shift 2 ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
done

die() { echo "entrypoint: $*" >&2; exit 1; }

[[ -n "$KERNEL" ]] || die "缺 --kernel"
[[ -n "$RUN_ID" ]] || die "缺 --run-id"
case "$ONLY" in
    both|refuzz|syzkaller) ;;
    *) die "非法 --only: $ONLY（允许 both/refuzz/syzkaller）" ;;
esac

ART=/opt/artifacts
CFG=/opt/configs
OUT="/results/${KERNEL}-r${RUN_ID}"

# ── 启动自检 ─────────────────────────────────────────────────────────────
# 48h 的实验，任何一项缺失都要在第一分钟失败，而不是跑完才发现。
echo "=== 自检 ==="

[[ -c /dev/kvm ]] || die "/dev/kvm 不存在 —— 忘了 --device /dev/kvm？"
# 可写性比存在性更重要：--device 挂进来但 gid 不对时，open() 会 EACCES，
# 而 QEMU 会静默退回 TCG，所有超时被 10× 放大，数据全废且不报错。
[[ -w /dev/kvm ]] || die "/dev/kvm 不可写 —— 需要 --group-add \$(stat -c %g /dev/kvm)"

RFZ_CFG="$CFG/refuzz_${KERNEL}.json"
SYZ_CFG="$CFG/syz_${KERNEL}.json"
[[ -f "$RFZ_CFG" ]] || die "缺配置 $RFZ_CFG"
if [[ "$ONLY" == "both" || "$ONLY" == "syzkaller" ]]; then
    [[ -f "$SYZ_CFG" ]] || die "缺配置 $SYZ_CFG"
fi

VMLINUX="$ART/kernels/$KERNEL/vmlinux"
BZIMAGE="$ART/kernels/$KERNEL/bzImage"
[[ -f "$VMLINUX" ]] || die "缺 $VMLINUX"
[[ -f "$BZIMAGE" ]] || die "缺 $BZIMAGE"

# /tmp 使用宿主磁盘 bind 或其他文件系统均可，但必须可执行；reFuzz 的
# short_root 在这里（见 speed_compare.py，108 字节 Unix socket 限制）。
# 挂载源所在文件系统若是 noexec，会在 VM 启动时才失败。
TMPTEST=$(mktemp /tmp/xt.XXXXXX)
printf '#!/bin/sh\nexit 0\n' > "$TMPTEST"
chmod +x "$TMPTEST"
"$TMPTEST" 2>/dev/null || die "/tmp 是 noexec —— 请改用允许执行的磁盘挂载目录"
rm -f "$TMPTEST"

# 磁盘：48h × 两侧的 rawcover 转储不小，满了会在最后一步丢数据。
avail_mb=$(df -Pm /results | awk 'NR==2{print $4}')
[[ "$avail_mb" -ge 20480 ]] || die "/results 只剩 ${avail_mb}MB，48h 跑不下（要 ≥20G）"

echo "  /dev/kvm         可读写"
echo "  /tmp             exec ok ($(df -Pm /tmp | awk 'NR==2{print $2}')MB)"
echo "  /results         ${avail_mb}MB 可用"
echo "  qemu             $(cat /opt/QEMU_VERSION.txt)"
echo "  kernel           $KERNEL"
sed 's/^/                   /' "$ART/kernels/$KERNEL/KERNEL.txt" 2>/dev/null | head -4

mkdir -p "$OUT"

# ── 身份卡 ───────────────────────────────────────────────────────────────
# 跑完之后要能说清这份数据是什么条件下产生的。事后补写等于把"无从证明"
# 伪装成"已证明"，所以在运行当时写。
{
    echo "kernel=$KERNEL"
    echo "run_id=$RUN_ID"
    echo "duration_s=$DURATION"
    echo "warmup_s=$WARMUP"
    echo "syz_perf_serial=${SYZ_PERF_SERIAL:-1}"
    echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "container=$(hostname)"
    echo "cpuset=$(cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null || echo unknown)"
    echo "mem_limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
    echo "qemu=$(cat /opt/QEMU_VERSION.txt)"
    echo "--- kernel ---"
    cat "$ART/kernels/$KERNEL/KERNEL.txt" 2>/dev/null || true
    echo "--- refuzz ---"
    cat "$ART/refuzz/REFUZZ.txt" 2>/dev/null || true
    echo "--- syzkaller ---"
    cat "$ART/syzkaller/SYZKALLER.txt" 2>/dev/null || true
} > "$OUT/RUN.txt"

# ── 跑 ───────────────────────────────────────────────────────────────────
# --coverage-domains 是数据来源开关，不是分析开关：它在 reFuzz 侧注入
# edge_series_enabled + corpus_signal_path/all_signal_path，在 syz 侧多抓
# /corpusrawpc /corpussignal /maxsignal。不开就没有边覆盖时间序列，三张图里
# 的边覆盖那条画不出来。
#
# --skip-build 是必须的：镜像里没有编译器，二进制都是预编好的。
# COV_COMPARE_BIN 让 build_cov_compare 走拷贝而不是 go build（没有 Go）。
export COV_COMPARE_BIN="$ART/refuzz/cov-compare"

# jemalloc 和 rarity prior 不在这里 export —— 那样会一起灌给 syz-manager。
# speed_compare.py 的 refuzz_child_env() 只把它们给 reFuzz 那个 Popen。
# 这里只声明 .so 位置，由那个函数决定给谁。
export JEMALLOC_SO="${JEMALLOC_SO:-/usr/lib/x86_64-linux-gnu/libjemalloc.so.2}"
export RARITY_ALPHA="${RARITY_ALPHA:-8}"
# syzgen 与 cov-compare 一样：镜像里没有 Go，两个都走预编拷贝（见
# speed_compare.py 的 SYZGEN_BIN / COV_COMPARE_BIN 处理）。
export SYZGEN_BIN="$ART/refuzz/syzgen_speed"

# http 端口按 run_id 错开。容器有独立 net namespace，跨容器本不会撞，但同一
# 容器内 --d-parallel 的两侧要各自的端口；单侧模式只用一个基口也互不冲突。
HTTP_BASE=$((56941 + RUN_ID * 10))

echo
echo "=== 开跑: $KERNEL run $RUN_ID, ${DURATION}s ==="
echo "    out=$OUT"

# 不用 exec：要 tee 一份日志，还要在结束时写完成标记。pipefail 已开，所以
# 管道里 python 的非零退出码会传出来（不是 tee 的 0）。
set -x
D_PARALLEL=()
if [[ "$ONLY" == "both" ]]; then
    D_PARALLEL+=(--d-parallel)
fi
SYZ_ARGS=()
if [[ "$ONLY" == "both" || "$ONLY" == "syzkaller" ]]; then
    SYZ_ARGS+=(--syz-config "$SYZ_CFG")
fi
python3 scripts/speed_compare/speed_compare.py \
    --only "$ONLY" \
    "${D_PARALLEL[@]}" \
    --coverage-domains \
    --duration "$DURATION" \
    --warmup "$WARMUP" \
    --runs 1 \
    --skip-build \
    --refuzz-root "$ART/refuzz" \
    --refuzz-build-dir "$ART/refuzz/build-llvm20" \
    --syzkaller-root "$ART/syzkaller" \
    --base-config "$CFG/refuzz_${KERNEL}.json" \
    --refuzz-config "$RFZ_CFG" \
    "${SYZ_ARGS[@]}" \
    --vmlinux "$VMLINUX" \
    --http-port-base "$HTTP_BASE" \
    --out-dir "$OUT" \
    2>&1 | tee -a "$OUT/harness.log"
rc=${PIPESTATUS[0]}
set +x

# 完成标记：collect.sh 和 plot_cov_runs.py 靠它区分"跑完了"和"还在跑/挂了"。
# 48h × 9 个容器，不可能靠人盯着，所以状态必须落盘。
{
    echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit_code=$rc"
    echo "status=$([[ $rc -eq 0 ]] && echo complete || echo failed)"
} >> "$OUT/RUN.txt"

echo "=== $KERNEL run $RUN_ID 结束, exit=$rc ==="
exit "$rc"
