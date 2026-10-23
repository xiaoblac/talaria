#!/usr/bin/env bash
# build_artifacts.sh — 本地一条命令备好全部产物，打成可传输的镜像 tar。
#
# 服务器不编译任何东西。这个脚本在本机（16 核 / 19G）顺序做完:
#   1. 三个内核         build_kernels.sh   -j8，约 2-3 小时
#   2. reFuzz + syz     build_userspace.sh 约 20 分钟
#   3. 六份配置         gen_configs.py
#   4. docker build     瘦运行镜像
#   5. docker save      → cov-image.tar.zst，scp 到服务器
set -euo pipefail

REFUZZ_ROOT="${REFUZZ_ROOT:-/workspace/talaria}"
ART="${ART:-/workspace/cov-artifacts}"
STAGE="${STAGE:-/workspace/cppro/cov-stage}"
IMAGE="${IMAGE:-refuzz-cov:latest}"
JOBS="${JOBS:-8}"
SHIP="${SHIP:-/workspace/cppro/cov-image.tar.zst}"

cd "$REFUZZ_ROOT"
die() { echo "build_artifacts: $*" >&2; exit 1; }

STEP="${1:-all}"

if [[ "$STEP" == "all" || "$STEP" == "kernels" ]]; then
    echo "############ 1/5 三个内核 (-j$JOBS，最久的一步) ############"
    ART="$ART" JOBS="$JOBS" docker/build_kernels.sh
fi

if [[ "$STEP" == "all" || "$STEP" == "userspace" ]]; then
    echo "############ 2/5 reFuzz + syzkaller + rootfs ############"
    ART="$ART" JOBS="$JOBS" docker/build_userspace.sh
fi

if [[ "$STEP" == "all" || "$STEP" == "image" ]]; then
    echo "############ 3/5 六份配置 ############"
    rm -rf "$STAGE"
    mkdir -p "$STAGE"
    python3 docker/gen_configs.py --out "$STAGE/configs"

    echo "############ 4/5 docker build ############"
    # clang-20 运行时库（libc++/libc++abi/libunwind）：reFuzz 二进制链的是自定义
    # LLVM-20 的 soname，bookworm 源里只有 LLVM 15（libc++1-15），可能缺新符号。
    # 跟二进制一样由 build 机预打包进镜像（COPY libcxx/ 层）。
    LLVM_LIBDIR="${LLVM_LIBDIR:-/usr/lib/llvm-20/lib}"
    mkdir -p "$STAGE/libcxx"
    for so in libc++.so.1.0 libc++abi.so.1.0 libunwind.so.1.0; do
        [[ -f "$LLVM_LIBDIR/$so" ]] || die "缺 $LLVM_LIBDIR/$so"
        cp "$LLVM_LIBDIR/$so" "$STAGE/libcxx/"
    done

    # 用硬链接而不是拷贝：artifacts 有 8G，docker build context 再复制一份纯浪费。
    # 同一文件系统上 cp -al 是常数时间。
    cp -al "$ART" "$STAGE/artifacts" 2>/dev/null || cp -a "$ART" "$STAGE/artifacts"
    cp docker/Dockerfile docker/entrypoint.sh "$STAGE/"

    for f in artifacts/kernels artifacts/images artifacts/syzkaller \
             artifacts/refuzz configs entrypoint.sh libcxx; do
        [[ -e "$STAGE/$f" ]] || die "build context 缺 $f"
    done

    # --network=host: 这台机器上 docker 默认 bridge 网络的 DNS 出不去
    # （容器里 resolv.conf 指向 192.168.76.2，从 netns 内解析 deb.debian.org
    # 一律 "Temporary failure resolving"，换 --dns 8.8.8.8/223.5.5.5 同样失败，
    # 说明是 netns 出站被拦，不是 resolver 选错）。宿主 netns 里解析和取包都正常，
    # 所以 apt 层借宿主网络。只影响 build 期取包，运行期仍是 --network none。
    docker build --network=host -t "$IMAGE" "$STAGE"
    echo "镜像 $IMAGE:"
    docker images "$IMAGE" --format '  {{.Size}}'
fi

if [[ "$STEP" == "all" || "$STEP" == "ship" ]]; then
    echo "############ 5/5 打包传输 ############"
    # zstd -10 -T0: 8G 的内核和 rootfs 压得下来（vmlinux 里大量调试信息可压），
    # 实测约 2-3G。比 gzip 快得多，服务器侧解压也快。
    # -f: 覆盖上一轮 ship 的 tar（zstd 从 stdin 读时默认拒绝覆盖已存在文件）
    docker save "$IMAGE" | zstd -f -10 -T0 -o "$SHIP"
    sz=$(du -h "$SHIP" | cut -f1)
    sha=$(sha256sum "$SHIP" | cut -d' ' -f1)
    echo "  $SHIP  ($sz)"
    echo "  sha256=$sha"
    echo "$sha  $(basename "$SHIP")" > "${SHIP}.sha256"

    cat <<EOF

############ 传到服务器 ############

  scp $SHIP ${SHIP}.sha256 user@server:/data/

服务器上:
  cd /data
  sha256sum -c $(basename "$SHIP").sha256   # 先验完整性
  zstd -d -c $(basename "$SHIP") | docker load
  docker images $IMAGE

然后把这三个脚本也传过去（很小）:
  scp docker/launch.sh docker/collect.sh \\
      scripts/speed_compare/plot_cov_runs.py user@server:/data/

起跑:
  /data/launch.sh   # 默认 3 内核 × 3 run 各 48h，写入 \$HOME/chengyongkang/cov-results
EOF
fi
