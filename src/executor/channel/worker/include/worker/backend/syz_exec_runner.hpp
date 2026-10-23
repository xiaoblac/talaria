// Worker child-side scratch buffer + result struct used by KernelWireDriver.
//
// After V1 retirement the V1 / 旧V2 typed-wire executors are gone; this
// header now only carries the shared scratch sizing constant + the
// thread-local mmap helper that the wire driver uses to materialize
// PTR_IN / PTR_OUT regions.

#pragma once

#include <cstddef>
#include <cstdint>

namespace refuzz::worker {

// Per-child thread-local scratch buffer size. This must cover the full
// syzkaller exec "data" window that top-level vma/vma64 args can point
// into. On linux/amd64 the generated target advertises:
//   page_size = 4096
//   num_pages = 4096
//   => 16 MiB addressable exec data window
//
// If this is smaller than target.num_pages()*page_size(), high VMA args
// (for example /dev/iommu IOMMU_IOAS_MAP$PAGES user_va near 0xffc000) are
// treated as unmapped literals instead of rebased scratch pointers, and
// the kernel returns -EFAULT. Keep the worker-side scratch at least as
// large as the target-visible data window.
constexpr size_t kSyzExecScratchBytes = 16 * 1024 * 1024;
constexpr std::uint64_t kSyzExecDataOffset = 35184372088832ull;  // linux/amd64 target.data_offset()
constexpr size_t kSyzExecGuardPageBytes = 4096;

// Trigger the AcquireScratch mmap on the current thread. Returns true
// when scratch is ready (or already existed); false on mmap failure —
// in which case the caller should _exit() because every subsequent task
// would surface as exec_error.
bool PreallocateSyzExecScratch();

// [v1 SyzExecResult.reserved 占位 — ROLLBACK: uncomment, remove v2]
// struct SyzExecResult {
//     int64_t  ret      = 0;
//     int32_t  err      = 0;
//     uint32_t reserved = 0;
// };
//
// [v2 Epic 6 D-4 — flags carries per-call CallFlag bits; mirror upstream]
// `flags` 复用 v1 的 `reserved` 字段位(同 4-byte slot,size 不变,前向序列化
// 兼容)。位定义跟 upstream pkg/flatrpc/flatrpc.fbs:212-218 字节对齐:
//
// [v2 batch 3 PR-X] cover_offset / cover_count 透出该 call 在 output buffer
// **coverage tail** 中的 KCOV PC slice。layout:
//   output = [SyzExecResult × n] [uint64 × total_cov] [...其它 packets...]
//   cover_offset = uint64 entry index in coverage tail(NOT byte offset)
//   cover_count  = entries 数;0 表示该 call 无 per-call cover(eg. CMP mode
//                  worker / KCOV 不可用 / driver 没 SetKcovCollector)
// 详 plan §3.PR-X step 3。struct size 16→24 字节;worker/host 单 build 同步升。
struct SyzExecResult {
    int64_t  ret          = 0;
    int32_t  err          = 0;
    uint32_t flags        = 0;  // bitwise-OR of kCallFlag* below
    uint32_t cover_offset = 0;  // [v2 batch 3 PR-X] uint64 index in output coverage tail
    uint32_t cover_count  = 0;
};

// Mirror upstream pkg/flatrpc/flatrpc.fbs:212-218 CallFlag bit_flags.
// 数值跟上游 byte-for-byte 一致 — operator-driven oracle 用 raw bytes
// 比对时不需要做 bit-table 翻译。
//
// 五个 bit 现在**全部**由 KernelWireDriver 写(kernel_wire_driver.cpp):
//   Executed|Finished  — 跑完的 call,serial :1430 / threaded :1845
//   Blocked            — :1847,threaded 下超过 per-call wait 才完成
//   FaultInjected      — :1445 / :1854
//   CoverageOverflow   — :1502 / :1818
//   Executed **单独**  — :1975 finish_unfinished_tid:per-call wait + end-drain
//                        都没等到的 call。等价 upstream write_call_output(th,false)
//                        (executor.cc:1152)。"Executed 有、Finished 无" 就是
//                        "起来了但没跑完",是正常预期结果而非错误 —— 消费侧不要
//                        据此判异常。
// 注:serial 模式没有 per-call wait,阻塞 call 会卡住整条 walk,交由上层
// program watchdog 处置(见 program_runtime.cpp),该路径下 Blocked 不会出现。
inline constexpr uint32_t kCallFlagExecuted         = 1u << 0;  // 1
inline constexpr uint32_t kCallFlagFinished         = 1u << 1;  // 2
inline constexpr uint32_t kCallFlagBlocked          = 1u << 2;  // 4
inline constexpr uint32_t kCallFlagFaultInjected    = 1u << 3;  // 8
inline constexpr uint32_t kCallFlagCoverageOverflow = 1u << 4;  // 16

} // namespace refuzz::worker
