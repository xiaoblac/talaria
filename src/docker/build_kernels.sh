#!/usr/bin/env bash
# build_kernels.sh — 本地编出 coverage 实验要的三个内核。
#
# 配置来源: docker/kernel_configs/linux-<tag>-llvm-kasan.config —— 从 syzbot
# bug 报告页的 KernelConfig 链接下载的单文件完整 .config（与各内核版本时代匹配，
# 见 docker/README 或 bug 页面 /text?tag=KernelConfig&x=...）。不再用本地 syzkaller
# checkout 里 dashboard/config/linux 的 base+top 成对文件：那份针对 linux-next/
# clang-22 时代生成，跨版本符号漂移大，按版本匹配的 syzbot build config 更干净。
#
# 为什么是 worktree 而不是 checkout: linux-git 当前停在 v7.1-rc6，三个 tag 顺序
# checkout 会反复重写整个工作树（每次几万个文件），而且一旦中途失败就说不清当前
# 是哪个版本。worktree 给每个 tag 一个独立目录、共享同一个 object store，三份
# 源码树只花一次 2.3G 的 .git。
#
# 为什么 -j8 而不是 -j$(nproc): 本机 16 核 / 19G 内存。KASAN + clang 的单个
# 编译单元峰值内存不小，-j16 在 19G 上会打到 swap，比 -j8 更慢。这是本地构建
# 阶段，不是 48h 实验，不值得为它冒 OOM 的风险。
#
# 产出（每个 tag）:
#   $ART/kernels/<tag>/bzImage   —— VM 启动用
#   $ART/kernels/<tag>/vmlinux   —— addr2line 分桶 + syz kernel_obj 符号化
# 构建树留在 $BUILD_ROOT/<tag>/ 不删，方便重跑；只有产物进 artifacts。
set -euo pipefail

LINUX_GIT="${LINUX_GIT:-/workspace/cppro/linux-git}"
SYZ_ROOT="${SYZ_ROOT:-/workspace/syzkaller}"
BUILD_ROOT="${BUILD_ROOT:-/workspace/cppro/kbuild-cov}"
ART="${ART:-/workspace/cov-artifacts}"
JOBS="${JOBS:-8}"
# 按版本匹配的单文件 syzbot config 所在目录。本脚本由 build_artifacts.sh 调用，
# REFUZZ_ROOT 有默认值，独立运行时用同样的默认。
REFUZZ_ROOT="${REFUZZ_ROOT:-/workspace/talaria}"
KCFG_DIR="${KCFG_DIR:-$REFUZZ_ROOT/docker/kernel_configs}"

CC=clang-20
LD=ld.lld-20

# tag:配置前缀。三者都走 syzbot 的 upstream-apparmor-kasan —— 配置前缀统一是
# 好事：跨版本覆盖率绝对值本来就不可比，再叠一层配置差异只会让"版本差异"和
# "配置差异"缠在一起。三者都是 clang 构建，与本地 CC 一致，不要混 gcc。
#
# 为什么不再有 v6.6（2026-08-02 移除）: v6.6 发布 tag ffc253263a13 早于上游修复
# 4f3951242ace（"Bluetooth: L2CAP: Fix not validating setsockopt user input"，
# 进的是 v6.10）。修复前 l2cap_sock_setsockopt 不校验 optlen 就
# copy_from_sockptr(&mtu, optval, sizeof(u16))，clang-20 在编译期看出源可能小于
# 目标，直接报 __bad_copy_from 硬错误。绕过它只有改内核源码或降 clang 两条路，
# 前者让实验跑在一个不对应任何真实 6.6 的树上，后者会让这个内核和另两个用不同
# 编译器 —— 两种偏差都比少一个版本严重。
#
# 为什么是 v7.1 而不是 v7.2-rc5: v7.1（2026-06-14）是当前最新正式版，v7.2 还在
# rc 阶段。rc 树带更多临时性 breakage，且在 rc 上测出来的覆盖率数字不好辩护。
# 注意 linux-git 上次 fetch 停在 2026-06-04，v7.1 是这次补拉 tag 才出现的 ——
# 选版本前先 fetch，别用陈旧的 clone 判断"最新"。
# 三个版本各自的 syzbot config 都在 $KCFG_DIR/linux-<tag>-llvm-kasan.config
# （从 syzbot bug 页下载的、与版本时代匹配的完整 .config）。
KERNELS=(
    "v6.12"
    "v6.18"
    "v7.1"
)

die() { echo "build_kernels: $*" >&2; exit 1; }

[[ -d "$LINUX_GIT/.git" ]] || die "$LINUX_GIT 不是 git 仓库"
command -v "$CC" >/dev/null || die "缺 $CC"
command -v "$LD" >/dev/null || die "缺 $LD"

mkdir -p "$BUILD_ROOT" "$ART/kernels"

for entry in "${KERNELS[@]}"; do
    tag="$entry"
    # TAGS 环境变量可过滤（如 TAGS="v6.12" 只编 v6.12），逗号分隔
    if [[ -n "${TAGS:-}" ]]; then
        case ",${TAGS}," in
            *,"$tag",*) ;;
            *) continue ;;
        esac
    fi
    src="$BUILD_ROOT/src-$tag"
    obj="$BUILD_ROOT/obj-$tag"
    out="$ART/kernels/$tag"

    echo "=============================================================="
    echo "[$tag]"
    echo "=============================================================="

    if [[ -f "$out/bzImage" && -f "$out/vmlinux" ]]; then
        echo "[$tag] 产物已存在，跳过。要重编就删 $out"
        continue
    fi

    # 单文件完整 config：直接 cp 为 .config，不再 merge base+top。
    kcfg="$KCFG_DIR/linux-${tag}-llvm-kasan.config"
    [[ -f "$kcfg" ]] || die "缺 $kcfg"

    # worktree：已存在就复用（重跑友好），不存在就建。--detach 因为我们要的是
    # tag 那个点，不需要分支。
    if [[ ! -d "$src" ]]; then
        echo "[$tag] 创建 worktree → $src"
        git -C "$LINUX_GIT" worktree add --detach "$src" "$tag"
    else
        echo "[$tag] 复用已有 worktree $src"
        have=$(git -C "$src" rev-parse HEAD)
        want=$(git -C "$LINUX_GIT" rev-parse "$tag^{commit}")
        [[ "$have" == "$want" ]] || die "$src 停在 $have，不是 $tag ($want)"
    fi

    mkdir -p "$obj"

    # 单文件 config 是 syzbot 最终 .config（已跑过 olddefconfig 的形态），
    # 直接复制。跨 tag 的符号差异（新增/消失）留给 olddefconfig 处理。
    echo "[$tag] 使用单文件 syzbot config"
    cp "$kcfg" "$obj/.config"

    # syzbot 的 .config 与我们要编的 tag 之间仍可能有新增/消失的 symbol。
    # olddefconfig 用默认值补齐缺的，不会交互提问 —— 无人值守必须用它而不是 oldconfig。
    echo "[$tag] olddefconfig"
    make -C "$src" O="$obj" CC="$CC" LD="$LD" olddefconfig

    # clang-20/lld-20 编 v6.12 的 x32 vdso 会报 ".note.gnu.property: data is too
    # short" 链接错误（x32 ABI 已废弃，syzbot 因测 x32 syscall 才开）。fuzz 实验
    # 用不到 x32，禁用后重跑 olddefconfig。
    if grep -q '^CONFIG_X86_X32_ABI=y' "$obj/.config" 2>/dev/null; then
        echo "[$tag] 禁用 CONFIG_X86_X32_ABI（clang-20 编 x32 vdso 失败，fuzz 不需要 x32）"
        ( cd "$src" && ./scripts/config --file "$obj/.config" --disable CONFIG_X86_X32_ABI )
        make -C "$src" O="$obj" CC="$CC" LD="$LD" olddefconfig
    fi

    # v7.1 的 syzbot config（clang-22 时代）开了 CONFIG_AUTOFDO_CLANG。clang-20
    # 的 -fdebug-info-for-profiling 生成的 .debug_line 被 elfutils/libdw 判为
    # invalid，gendwarfksyms 直接报错（is_definition_private: dwarf_getsrcfiles
    # failed），与 OOM 无关。无 profile 输入时 AutoFDO 只加 debug 元数据、不改
    # 代码生成，禁用是安全的；CONFIG_PROPELLER_CLANG 保留（clang>=20 下只加
    # -fbasic-block-address-map，与 syzbot 时代一致）。
    if grep -q '^CONFIG_AUTOFDO_CLANG=y' "$obj/.config" 2>/dev/null; then
        echo "[$tag] 禁用 CONFIG_AUTOFDO_CLANG（clang-20 的 -fdebug-info-for-profiling 触发 gendwarfksyms invalid .debug_line）"
        ( cd "$src" && ./scripts/config --file "$obj/.config" --disable CONFIG_AUTOFDO_CLANG )
        make -C "$src" O="$obj" CC="$CC" LD="$LD" olddefconfig
    fi

    # reFuzz 自己要的几个选项（KCOV 比较、DWARF、kallsyms 全量、关 KASLR）。
    # syzbot 配置大概率已经带了，但 apply-base.sh 是幂等的，跑一遍保证下界。
    # 注意 cd "$src"：apply-base.sh 内部调的是相对路径 scripts/config，
    # 必须在内核源码树里跑，否则找不到那个脚本。
    if [[ -x "$SYZ_ROOT/kernel/configs/apply-base.sh" ]]; then
        echo "[$tag] apply-base.sh"
        ( cd "$src" && "$SYZ_ROOT/kernel/configs/apply-base.sh" "$obj" ) || \
            echo "[$tag] 警告: apply-base.sh 非零退出，继续（syzbot 配置通常已覆盖）"
        make -C "$src" O="$obj" CC="$CC" LD="$LD" olddefconfig
    fi

    # 关键选项硬校验。少了任何一个，48h 跑完才发现就太晚了：
    #   KCOV/KCOV_ENABLE_COMPARISONS — 没有就完全没有覆盖率数据
    #   DEBUG_INFO                   — 没有 vmlinux 符号，addr2line 分桶失效
    #   KALLSYMS_ALL                 — syz 侧符号化不全
    #   RANDOMIZE_BASE 必须关         — 开了 PC 每次启动都变，跨 run 的 PC 集无法比较
    echo "[$tag] 校验关键配置"
    for opt in CONFIG_KCOV=y CONFIG_KCOV_ENABLE_COMPARISONS=y \
               CONFIG_DEBUG_INFO=y CONFIG_KALLSYMS_ALL=y CONFIG_KASAN=y; do
        grep -qx "$opt" "$obj/.config" || die "[$tag] $obj/.config 缺 $opt"
    done
    ! grep -qx 'CONFIG_RANDOMIZE_BASE=y' "$obj/.config" || \
        die "[$tag] RANDOMIZE_BASE 是开的 —— PC 会随启动漂移，跨 run 不可比"

    echo "[$tag] 编译 (-j$JOBS)，这一步几十分钟"
    make -C "$src" O="$obj" CC="$CC" LD="$LD" -j"$JOBS" bzImage

    [[ -f "$obj/arch/x86/boot/bzImage" ]] || die "[$tag] 没产出 bzImage"
    [[ -f "$obj/vmlinux" ]] || die "[$tag] 没产出 vmlinux"

    mkdir -p "$out"
    cp "$obj/arch/x86/boot/bzImage" "$out/bzImage"
    cp "$obj/vmlinux"               "$out/vmlinux"
    cp "$obj/.config"               "$out/kernel.config"
    # 身份卡：论文要能说清跑的到底是哪个内核、什么配置、谁编的。
    {
        echo "tag=$tag"
        echo "commit=$(git -C "$src" rev-parse HEAD)"
        echo "config_source=$KCFG_DIR/linux-${tag}-llvm-kasan.config"
        echo "cc=$($CC --version | head -1)"
        echo "ld=$($LD --version | head -1)"
        echo "kernelrelease=$(make -C "$src" O="$obj" -s kernelrelease 2>/dev/null || echo unknown)"
        echo "bzImage_sha256=$(sha256sum "$out/bzImage" | cut -d' ' -f1)"
        echo "vmlinux_sha256=$(sha256sum "$out/vmlinux" | cut -d' ' -f1)"
        echo "config_sha256=$(sha256sum "$out/kernel.config" | cut -d' ' -f1)"
    } > "$out/KERNEL.txt"

    echo "[$tag] 完成:"
    sed 's/^/    /' "$out/KERNEL.txt"
done

echo
echo "=============================================================="
echo "三个内核就绪:"
du -sh "$ART/kernels"/* 2>/dev/null | sed 's/^/  /'
echo "构建树留在 $BUILD_ROOT（可删，约 48G）"
