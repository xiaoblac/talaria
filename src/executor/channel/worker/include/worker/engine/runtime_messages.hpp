// LoopRuntime ↔ ProgramRuntime / daemon ↔ loop child IPC 协议。
//
// 这两个 struct 之前各自被 ExecutionEngine 私有 nested 和 ChildMain 内 local
// 定义两次(byte layout 必须一致)。统一到单一 header 后,所有拓扑、所有
// runtime 都用同一份 typedef,消除 silent layout drift 风险。
//
// IPC 边界(见 docs/plans/double-fork-topology.md §"IPC 层次与 transport 边界"):
//   - L1 fork-tree 内部:daemon ↔ loop child 用 ReadyMsg/DoneMsg(本 header)
//   - L1 fork-tree 内部:loop child ↔ program child 用 V3 result/progress page
//   - L2 daemon ↔ 外部主控:transport adapter,不进 topology

#pragma once

#include "worker/program_buffers.hpp"

#include <cstdint>
#include <type_traits>

namespace refuzz::worker::engine {

// Internal execution outcome. Keep kNoResult as zero so value-initialized IPC
// structs fail closed instead of accidentally reporting success.
enum class RuntimeResultKind : uint32_t {
    // 真的没有任何结果(零 progress)。不是错误 —— 就是没产出,下游直接不消费。
    kNoResult = 0,
    kNormal = 1,
    kCrash = 2,
    // 程序自己提前结束(exit_group(任意码) / 无 handler 的信号),或被 program watchdog
    // SIGKILL(kTimeout)。两者 buffer 都未被 crash handler 动过 → progress cursors
    // 可信、数据照带;区别只在标签。
    kPartial = 3,
    kTimeout = 4,
    kHarnessFatal = 5,
    // [基础设施故障 — 程序无罪] 两个值映射到同一个 COMP_STATUS_INFRA_FAULT,只是
    // error_code 不同(见 domain_supervisor 的 switch):
    //   kInfraFault   → ERR_EXECUTOR_ERROR:worker 运行时故障(observation sink /
    //                   backend 执行失败)
    //   kInvalidInput → ERR_INVALID_INPUT:配置/协议错(wire 输入非法、exec flags
    //                   不被支持)。这类是确定性的 —— 同一请求重试必然同样失败。
    kInfraFault = 6,
    kInvalidInput = 7,
    // 兜底:走到了不该走到的分支(如 waitpid 状态既非 WIFEXITED 也非 WIFSIGNALED)。
    // 出现即 bug 信号,不是正常终态 —— 不要拿它当常规异常处理。
    kUnknown = 8,
};

enum class HarnessFatalReason : uint32_t {
    kNone = 0,
    kOuterForkEagain = 1,
    kOuterForkFailed = 2,
    kMainChildReapFailed = 3,
    kStoppedDescendantReapTimeout = 4,
    kForkServerProtocol = 5,
    kDomainWatchdogTimeout = 6,
    kExecutionDomainCleanupFailed = 7,
    kKcovStateInvalid = 8,
};

// daemon → loop child:发起一次 program execution。
struct ReadyMsg {
    uint32_t input_len;        // input_buf 有效长度
    uint32_t output_cap;       // output buffer 容量
    uint32_t flags;            // exec mode bits
    uint32_t dispatch_gen;     // stale-result guard with executor_id
    uint64_t executor_id;      // ObservationContext executor id
    uint64_t dispatch_seq;     // host-submitted per-worker stale-result ticket
    ::refuzz::worker::ProgramBufferDescriptor buffers;
};

static_assert(std::is_trivially_copyable_v<ReadyMsg>);
static_assert(std::is_standard_layout_v<ReadyMsg>);

// loop child → daemon:program execution 完成。
struct DoneMsg {
    uint32_t output_len; // output_buf 已写长度
    int32_t  status;     // 0=成功, -1=错误
    uint32_t flags;      // 保留
    // Explicit classification. status/output_len alone cannot distinguish
    // crash, recoverable partial, and no-result when the result page is not
    // committed.
    RuntimeResultKind result_kind = RuntimeResultKind::kNoResult;
    uint32_t crash_signal = 0;
    HarnessFatalReason fatal_reason = HarnessFatalReason::kNone;
    // Diagnostic per-program /dev/loop candidate mask. Cleanup follows
    // syzkaller reset_loop() and resets the worker's fixed /dev/loop<procid>
    // before the next request. UINT32_MAX means the publisher was not exact.
    uint32_t loop_devices_used_mask = 0;
    // [ExecTL] round-1 timeline stamps (CLOCK_MONOTONIC us) from the program
    // child: B = about to start program-level work, C = feedback packed.
    // Carried child→loop-child via the result page on the committed path;
    // 0 when the child died before stamping.
    uint64_t tl_b_ts_us = 0;
    uint64_t tl_c_ts_us = 0;
    // [ExecTL round-2, CPU dimension] child-side splits at the same stamps:
    // process CPU consumed and main-thread runqueue wait (/proc/self/schedstat,
    // both ~0 at fork). Each wall segment then divides into on-CPU /
    // waiting-for-CPU / waiting-for-events.
    uint64_t tl_b_cpu_us = 0;
    uint64_t tl_b_rq_us = 0;
    uint64_t tl_c_cpu_us = 0;
    uint64_t tl_c_rq_us = 0;
    // Parent(loop-child)-side accounting: fork() wall vs this-thread CPU, the
    // monotonic stamp when the main child was reaped, and the child's rusage
    // harvested by wait4 (utime+stime CPU, involuntary ctx switches, minor
    // faults ≈ COW). Zero when worker_perf is disabled or unavailable.
    uint64_t fork_wall_us = 0;
    uint64_t fork_cpu_us = 0;
    uint64_t reap_ts_us = 0;
    uint64_t child_cpu_us = 0;
    uint64_t child_nivcsw = 0;
    uint64_t child_minflt = 0;
};

} // namespace refuzz::worker::engine
