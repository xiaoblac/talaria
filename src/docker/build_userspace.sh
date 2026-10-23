#!/usr/bin/env bash
# build_userspace.sh — 本地编 reFuzz + syzkaller，连同 rootfs 一起收进 artifacts。
#
# 为什么 syzkaller 不能在服务器上 git clone: 本地 syzkaller 工作树有 10 个脏文件，
# 含 pkg/manager/http.go 和 pkg/rpcserver/rpcserver.go —— coverage 实验依赖的
# /corpusrawpc、/corpussignal、/maxsignal 三个 endpoint 和 syz_exec_calls_total
# 计数器大概率就在这些改动里，上游没有。clone 干净的 08ab31164 编出来的
# syz-manager 跑不了这个实验。所以传的是工作树快照，不是 commit。
#
# 产出:
#   $ART/refuzz/       —— refuzz + ivshmem_worker + scripts/ + 源码快照
#   $ART/syzkaller/    —— bin/ + sys/ 描述 + 脏改动记录
#   $ART/images/       —— rootfs ×2 + ssh key
set -euo pipefail

REFUZZ_ROOT="${REFUZZ_ROOT:-/workspace/talaria}"
SYZ_ROOT="${SYZ_ROOT:-/workspace/syzkaller}"
ART="${ART:-/workspace/cov-artifacts}"
JOBS="${JOBS:-8}"
SSH_KEY="${SSH_KEY:-/workspace/images-test-linux5.14/bookworm.id_rsa}"

die() { echo "build_userspace: $*" >&2; exit 1; }

mkdir -p "$ART"/{refuzz,syzkaller,images}

# ── reFuzz ───────────────────────────────────────────────────────────────
echo "=== reFuzz ==="
BUILD_DIR="$REFUZZ_ROOT/build-llvm20"
if [[ "${SKIP_REFUZZ_BUILD:-0}" != "1" ]]; then
    cmake -S "$REFUZZ_ROOT" -B "$BUILD_DIR" \
        -DCMAKE_C_COMPILER="${REFUZZ_CC:-clang-20}" \
        -DCMAKE_CXX_COMPILER="${REFUZZ_CXX:-clang++-20}" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    cmake --build "$BUILD_DIR" -j"$JOBS"
else
    echo "SKIP_REFUZZ_BUILD=1，用现有产物"
fi

RFZ_BIN="$BUILD_DIR/control/orchestrator/refuzz"
RFZ_WORKER="$BUILD_DIR/executor/channel/worker/ivshmem_worker"
RFZ_EXECUTOR="$BUILD_DIR/executor/channel/worker/refuzz_executor"
[[ -x "$RFZ_BIN" ]]    || die "缺 $RFZ_BIN"
[[ -x "$RFZ_WORKER" ]] || die "缺 $RFZ_WORKER"
[[ -x "$RFZ_EXECUTOR" ]] || die "缺 $RFZ_EXECUTOR"

# 容器里保持和本地同构的相对布局，这样配置里的路径只需换前缀。
mkdir -p "$ART/refuzz/build-llvm20/control/orchestrator" \
         "$ART/refuzz/build-llvm20/executor/channel/worker" \
         "$ART/refuzz/scripts"
cp "$RFZ_BIN"    "$ART/refuzz/build-llvm20/control/orchestrator/refuzz"
cp "$RFZ_WORKER" "$ART/refuzz/build-llvm20/executor/channel/worker/ivshmem_worker"
# refuzz_executor 是 ns_runner 里写死的部署名（ivshmem_worker 把同目录的这个
# 二进制 scp 进 guest），漏了它 DeployArtifacts 会直接失败。
cp "$RFZ_EXECUTOR" "$ART/refuzz/build-llvm20/executor/channel/worker/refuzz_executor"
cp -r "$REFUZZ_ROOT/scripts/speed_compare" "$ART/refuzz/scripts/"
[[ -d "$REFUZZ_ROOT/scripts/pc_compare" ]] && \
    cp -r "$REFUZZ_ROOT/scripts/pc_compare" "$ART/refuzz/scripts/"

# cov-compare 是 Go 写的，speed_compare.py:2194 (build_cov_compare) 默认在每次
# 运行时 `go build` 现编到 out_dir。运行镜像里不装 Go 工具链，所以这里预编好，
# 由 entrypoint 放到 out_dir 让 speed_compare 直接用（见 docker/entrypoint.sh 里
# 的 PREBUILT_COV_COMPARE 处理）。源码也带上，万一要现场重编。
echo "  预编 cov-compare"
( cd "$REFUZZ_ROOT/tools/cov_compare" && \
  CGO_ENABLED=0 go build -o "$ART/refuzz/cov-compare" . ) || \
    die "cov-compare 预编失败 —— 运行镜像里没有 Go，这个必须在本地编成"

# syzgen（seeds-unpack / corpus-unpack-db）也是 Go 写的。运行镜像里没有 Go，
# speed_compare.py 的 build_syzgen_binary 在 SYZGEN_BIN 设置时直接拷贝预编产物。
echo "  预编 syzgen_speed"
( cd "$REFUZZ_ROOT" && \
  CGO_ENABLED=0 go build -o "$ART/refuzz/syzgen_speed" ./tools/syzgen ) || \
    die "syzgen 预编失败 —— 运行镜像里没有 Go，这个必须在本地编成"
mkdir -p "$ART/refuzz/tools"
cp -r "$REFUZZ_ROOT/tools/cov_compare" "$ART/refuzz/tools/"

# 源码快照：不是为了在服务器上编，是为了论文可复现 + 出问题时能对照。
tar -C "$REFUZZ_ROOT" --exclude=run --exclude=build-llvm20 --exclude=docs \
    --exclude=.git --exclude=cov-artifacts \
    -czf "$ART/refuzz/refuzz-src-snapshot.tar.gz" . 2>/dev/null || true

{
    echo "refuzz_head=$(git -C "$REFUZZ_ROOT" rev-parse HEAD)"
    echo "refuzz_dirty_files=$(git -C "$REFUZZ_ROOT" status --porcelain | grep -c '^ M' || true)"
    echo "refuzz_sha256=$(sha256sum "$RFZ_BIN" | cut -d' ' -f1)"
    echo "worker_sha256=$(sha256sum "$RFZ_WORKER" | cut -d' ' -f1)"
    echo "executor_sha256=$(sha256sum "$RFZ_EXECUTOR" | cut -d' ' -f1)"
    echo "syzgen_sha256=$(sha256sum "$ART/refuzz/syzgen_speed" | cut -d' ' -f1)"
    echo "cc=$(${REFUZZ_CC:-clang-20} --version | head -1)"
} > "$ART/refuzz/REFUZZ.txt"
git -C "$REFUZZ_ROOT" diff > "$ART/refuzz/refuzz-dirty.patch" || true

# ── syzkaller ────────────────────────────────────────────────────────────
echo "=== syzkaller ==="
if [[ "${SKIP_SYZ_BUILD:-0}" != "1" ]]; then
    make -C "$SYZ_ROOT" manager executor \
        TARGETOS=linux TARGETVMARCH=amd64 TARGETARCH=amd64 -j"$JOBS"
else
    echo "SKIP_SYZ_BUILD=1，用现有产物"
fi

[[ -x "$SYZ_ROOT/bin/syz-manager" ]] || die "缺 bin/syz-manager"
[[ -x "$SYZ_ROOT/bin/linux_amd64/syz-executor" ]] || die "缺 bin/linux_amd64/syz-executor"

# syz-manager 运行时要 sys/ 下的描述和 bin/。整个 bin/ 一起收（syz-execprog
# 等在 repro 时用得上，体积不大）。
mkdir -p "$ART/syzkaller"
cp -r "$SYZ_ROOT/bin" "$ART/syzkaller/"
for d in sys pkg; do
    [[ -d "$SYZ_ROOT/$d" ]] && cp -r "$SYZ_ROOT/$d" "$ART/syzkaller/" 2>/dev/null || true
done
mkdir -p "$ART/syzkaller/dashboard/config/linux"
cp "$SYZ_ROOT"/dashboard/config/linux/*.config "$ART/syzkaller/dashboard/config/linux/" 2>/dev/null || true

{
    echo "syz_head=$(git -C "$SYZ_ROOT" rev-parse HEAD)"
    echo "syz_dirty_files=$(git -C "$SYZ_ROOT" status --porcelain | grep -c '^ M' || true)"
    echo "manager_sha256=$(sha256sum "$SYZ_ROOT/bin/syz-manager" | cut -d' ' -f1)"
    echo "executor_sha256=$(sha256sum "$SYZ_ROOT/bin/linux_amd64/syz-executor" | cut -d' ' -f1)"
    echo "go=$(go version 2>/dev/null || echo unknown)"
} > "$ART/syzkaller/SYZKALLER.txt"
# 脏改动必须留档：论文里"我们的 baseline 是 syzkaller @08ab31164"这句话
# 需要这个 patch 才成立 —— 否则别人 clone 那个 commit 复现不出来。
git -C "$SYZ_ROOT" diff > "$ART/syzkaller/syzkaller-dirty.patch" || true

# ── rootfs ───────────────────────────────────────────────────────────────
echo "=== rootfs ==="
# 两侧各一份，不共享。snapshot=on 下 file.locking=off，共享 backing image 本来是
# POSIX 安全的，但两份拷贝把这个假设从"依赖 QEMU 行为"降级成"不需要假设"，
# 代价只是 2G 磁盘。
for pair in "refuzz_rootfs.img:refuzz_rootfs.img" "syz_rootfs.img:syz_rootfs.img"; do
    src_name="${pair%%:*}"; dst_name="${pair##*:}"
    src="$REFUZZ_ROOT/run/speed_compare/images/$src_name"
    [[ -f "$src" ]] || die "缺 rootfs $src（先用 syzkaller/tools/create-image.sh 生成）"
    cp "$src" "$ART/images/$dst_name"
done
[[ -f "$SSH_KEY" ]] || die "缺 ssh key $SSH_KEY"
cp "$SSH_KEY" "$ART/images/bookworm.id_rsa"
chmod 600 "$ART/images/bookworm.id_rsa"

{
    for f in "$ART/images"/*.img; do
        echo "$(basename "$f")_sha256=$(sha256sum "$f" | cut -d' ' -f1)"
    done
} > "$ART/images/IMAGES.txt"

echo
echo "=== 用户态就绪 ==="
du -sh "$ART"/* | sed 's/^/  /'
