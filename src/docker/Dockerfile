# 覆盖率实验运行镜像。
#
# 只有运行期依赖：内核、reFuzz/syzkaller 二进制、rootfs 都是本地编好后由
# build_artifacts 收进 artifacts/ 的，这里 COPY 进来即用。镜像里没有编译器、
# 没有 Go、没有内核源码 —— 服务器不编译任何东西。
#
# 为什么 QEMU 要钉版本: ivshmem-doorbell 加 -snapshot 的行为跨 QEMU 大版本会变
# (executor/channel/substrate/src/runtime/vm/qemu_args.cpp 里已有针对
# host,migratable=off 和 RDTSC 的处理)。三个内核必须共用同一个 QEMU，否则
# QEMU 差异会混进覆盖率差异，而这个差异在数据里看不出来。
FROM debian:bookworm-slim

# 构建期 apt 镜像源。实验室外网到 deb.debian.org 不稳定（2026-08-04 实测
# 官方源不通/33KB/s，阿里镜像 743KB/s），默认走阿里镜像；网络恢复后可用
# `--build-arg APT_MIRROR=deb.debian.org` 切回官方源。只影响构建期取包，
# 运行期容器仍是 --network none。
ARG APT_MIRROR="mirrors.aliyun.com"

# qemu-system-x86: VM。bookworm 是 1:7.2+dfsg-7+deb12uN，三个容器同一份。
# libjemalloc2: reFuzz 侧 LD_PRELOAD (只给 reFuzz，见 refuzz_child_env())。
# openssh-client: syz-manager 用 ssh 进 guest 传 executor。
# binutils: addr2line，两侧的子系统分桶都要。
# python3: speed_compare.py 本体。matplotlib 用于出图。
# procps/psmisc: 48h 跑挂了要能看进程。
RUN sed -i "s#deb.debian.org#${APT_MIRROR}#g" /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 \
        qemu-utils \
        libjemalloc2 \
        openssh-client \
        binutils \
        python3 \
        python3-matplotlib \
        python3-numpy \
        ca-certificates \
        procps \
        psmisc \
        less \
    && rm -rf /var/lib/apt/lists/* \
    && qemu-system-x86_64 --version | head -1 > /opt/QEMU_VERSION.txt

# 产物。约 8G：3×(bzImage+vmlinux) 约 6G + rootfs ×2 约 2G。
# 分层 COPY 而不是一个 tar：改了配置只需重建最后一层，不用重传 6G 的内核。
COPY artifacts/kernels /opt/artifacts/kernels
COPY artifacts/images  /opt/artifacts/images
COPY artifacts/syzkaller /opt/artifacts/syzkaller
COPY artifacts/refuzz    /opt/artifacts/refuzz
COPY configs /opt/configs
COPY entrypoint.sh /opt/entrypoint.sh

# reFuzz 二进制链的是自定义 LLVM-20 的 libc++ 运行时（bookworm 源里只有 LLVM 15，
# 版本太低可能缺符号）。跟二进制一样由 build 机预打包进来，不用源里的旧包。
COPY libcxx/ /usr/lib/x86_64-linux-gnu/
RUN ln -sf libc++.so.1.0    /usr/lib/x86_64-linux-gnu/libc++.so.1 \
 && ln -sf libc++abi.so.1.0 /usr/lib/x86_64-linux-gnu/libc++abi.so.1 \
 && ln -sf libunwind.so.1.0  /usr/lib/x86_64-linux-gnu/libunwind.so.1 \
 && ldconfig

# speed_compare.py 的 --seeds-dir 默认值是 root.parent/sys/linux/test（本地布局：
# syzkaller 与 reFuzz 是兄弟目录）。容器里两者同在 /opt/artifacts 下，默认会落到
# /opt/artifacts/sys/linux/test（不存在），用软链把布局补成默认值期望的样子，
# 保持容器内调用与本地逐字一致。
RUN ln -s /opt/artifacts/syzkaller/sys /opt/artifacts/sys

# ssh key 权限：ssh 拒绝 group/other 可读的私钥，COPY 不保证权限。
# 二进制的可执行位同理 —— COPY 从 tar 恢复时偶有丢失。
RUN chmod 600 /opt/artifacts/images/bookworm.id_rsa \
    && chmod +x /opt/entrypoint.sh \
        /opt/artifacts/refuzz/build-llvm20/control/orchestrator/refuzz \
        /opt/artifacts/refuzz/build-llvm20/executor/channel/worker/ivshmem_worker \
        /opt/artifacts/refuzz/cov-compare \
        /opt/artifacts/syzkaller/bin/syz-manager \
        /opt/artifacts/syzkaller/bin/linux_amd64/syz-executor \
    && ls -l /dev/kvm >/dev/null 2>&1 || true

# 启动自检会用到的固定值，写进镜像好让 /results 里的记录能溯源到镜像本身。
LABEL refuzz.experiment="coverage-3kernel-n3"
LABEL refuzz.kernels="v6.12,v6.18,v7.1"

WORKDIR /opt/artifacts/refuzz
ENTRYPOINT ["/opt/entrypoint.sh"]
