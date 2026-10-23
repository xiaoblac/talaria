// worker/sandbox.hpp — child 进程隔离层
//
// 背景：fuzzing 中随机生成的 syscall（如 kill(-1, SIGRTMIN)、reboot() 等）若在
// root / 无隔离下执行，会波及 VM 内的 sshd / systemd，导致 console 里出现
// "ssh.service: Main process exited" 之类假象并毁掉 serial 日志里真正的 crash
// 信息。sandbox 仅对 **child (fuzz exec)** 进程生效，parent (watchdog) 保持
// root 以便继续访问 /dev/uio*、/dev/kcov 等资源。
//
// 调用时机：在 ChildMain() 中 coverage.Init() + scratch 预分配之后、主循环之前
// 调用一次。kcov fd 已绑到 task_struct, setuid 之后仍可 ioctl/mmap。
//
// RLIMIT_AS 以 syzkaller 08ab31164 的经验预算为下限：200 MiB 非 KCOV
// 基线，加上 32 个 local KCOV 和一个 8 MiB extra KCOV，共 336 MiB。
// reFuzz 自身映射超过该默认几何时再动态上调：
//
//   - transport 映射 : exec loop 只 mmap 当前 worker window，默认约 18 MiB
//                      (4 MiB input + 14 MiB output + 4 KiB result page)
//   - syz_exec scratch : 16 MiB（linux/amd64 target exec data window; 每 child 一份）
//   - KCOV mmap     : local 4 MiB/collector，extra 8 MiB
//   - binary+libs   : libstdc++/libc 等，保守估 64 MiB
//   - heap/stacks/vdso 余量 + fuzz 程序触发的 mmap 头room : 64 MiB
//
// RLIMIT_AS 不要求 2 的幂，因此不再沿用 ivshmem BAR 的 pow2 rounding。

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace refuzz::worker {

enum class SandboxMode : uint8_t {
    kNone      = 0, // current-process syzkaller-style sandbox_common + NEWNET
    kSetuid    = 1, // current-process sandbox_common + NEWNET + nobody uid/gid
    kNamespace = 2, // legacy/experimental user+pid namespace trampoline mode
};

// 由 ChildMain 填充后传入 ApplySandbox。所有字段单位都是字节，不要 shift 化。
// 各分量来源（已知或可算）：
//   ivshmem_bytes   = adapter.SharedMemorySize() + adapter.SharedMemoryBar0Size()
//   scratch_bytes   = kSyzExecScratchBytes（syz_exec_runner 公开的常量）
//   coverage_bytes  = coverage.BufferBytes()（所有 local + extra；Null 返 0）
//
// "未知量"（binary+libs、fuzz 程序运行期新 mmap、heap 增长）由
// ComputeAddressSpaceLimit 内部的 syzkaller 基线和保守常量兜底。
struct SandboxSizing {
    size_t ivshmem_bytes  = 0;
    size_t scratch_bytes  = 0;
    size_t coverage_bytes = 0;
    uint32_t proc_id = 0;
    // [Brick 4a] When the sandbox runs in the TOP-LEVEL worker process (snapshot
    // mode: single process, no daemon/loop_child watchdog parent — launched via
    // `nohup ... &` so it is reparented to init, getppid()==1 by design, exactly
    // like syz's `nohup executor exec snapshot &`), skip the PR_SET_PDEATHSIG +
    // getppid()==1 parent-death guard, which only makes sense for a forked child
    // watched by a daemon. Default false = continuous forked-child behavior.
    bool no_parent_watchdog = false;
    // Host-only topology tests run without CAP_SYS_ADMIN and intentionally
    // exercise IPC/lifecycle behavior outside a real fuzzing sandbox. Production
    // must leave this false: LoopRuntime cleanup relies on owning a private
    // mount namespace rather than sweeping the whole namespace per program.
    // The same explicit test escape hatch also permits unavailable VHCI/TUN/
    // WiFi/tmpfs setup in non-privileged host topology tests.
    bool allow_no_private_mount_namespace_for_tests = false;
};

// 计算 child 进程 RLIMIT_AS 上限（字节）。
//
// 公式:
//   base = max(200 MiB,
//              sizing.ivshmem + sizing.scratch + 64 MiB + 64 MiB)
//   coverage = max(32 * 4 MiB + 8 MiB, sizing.coverage)
//   AS = base + coverage
//
// 默认配置和全 0 sizing 都返回 syzkaller 对齐的 336 MiB。
size_t ComputeAddressSpaceLimit(const SandboxSizing& sizing);

// 字符串 → SandboxMode；失败返回 false，*out 保持不变。
// 接受: "none" / "setuid" / "namespace"（大小写敏感）。
bool ParseSandboxMode(std::string_view s, SandboxMode* out);

// 反向映射，仅用于日志。
const char* SandboxModeName(SandboxMode m);

// 在 **child 进程** 内应用 sandbox。成功返回 0，失败返回 -errno。
// 调用者（ChildMain）拿到非 0 应立即 _exit()——这通常意味着隔离未生效，
// 宁可让 parent respawn 也不能继续以 root 身份跑 fuzz 程序。
//
// sizing 用于算 RLIMIT_AS。传 {} 时使用 syzkaller 对齐的 336 MiB 下限。
int ApplySandbox(SandboxMode mode, const SandboxSizing& sizing);

// 在 worker 主进程启动时预检 sandbox 模式是否可用。出 err_detail 字符串
// (最多 cap 字节)方便上层 log/fatal。成功返回 true。
//
// 预检规则:
//   kNone / kSetuid   → 必须能 unshare(NEWNS) 并递归设为 MS_PRIVATE
//   kNamespace        → 另外要求 NEWUSER，然后验证同样的 NEWNS/MS_PRIVATE
// 预检失败直接阻止 worker 启动，避免 child 反复退出。
//
// 放在 main() 的启动路径里，预检一次失败直接 return 2，比 child 循环崩好排查。
bool ProbeSandboxMode(SandboxMode mode, char* err_detail, size_t cap);

} // namespace refuzz::worker
