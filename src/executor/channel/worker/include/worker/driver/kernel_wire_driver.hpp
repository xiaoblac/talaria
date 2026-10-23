// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelWireDriver: kernel family driver for the syzkaller-equivalent
// exec wire (Layer-2 of §3.3).
//
// Composition: streaming exec-wire decode (WireStreamReader) +
// (IDispatcher=SyscallOrPseudoDispatcher). The driver pulls instructions
// straight from the input wire buffer in its exec loop — no ICodec, no
// materialized WireProgram (a direct port of syzkaller executor.cc
// execute_one / read_input).
//
// Behavior (mirror of upstream syzkaller executor parseProgram + execute):
//   - Allocates a writable scratch region (mmap, default kSyzExecScratchBytes).
//   - WireCopyin: writes the materialized arg bytes into scratch[addr..].
//     Const respects format / bitfield / pid_stride; Csum (inet) is
//     computed at runtime from chunks; Result reads copyout[idx] then
//     applies op_div / op_add (or default_val if the producer didn't run).
//   - WireCopyout: snapshots scratch[addr..addr+size] into copyout[idx].
//   - WireSetProps: explicit subset. FailNth is honored end-to-end via
//     `inject_fault` / `fault_injected` helpers (Epic 6 §3.14 PR-6-A).
//     Async and Rerun remain rejected (Epic 6 §10 N1 / N2 permanent
//     non-goals); non-zero `Async / Rerun` returns an execution error
//     rather than being silently dropped.
//   - WireCall: builds intptr_t args[], translates `call_id → SyscallMeta::nr`
//     via `Target::linux_amd64()`, dispatches via injected IDispatcher.
//     Stores ret/err in the per-call slot of `output[]`. Maintains a
//     parallel `call_rets[]` and feeds copyout_idx (when present) into the
//     copyout table so subsequent ResultArgs can reference the syscall return.
//
// Output format: same `SyzExecResult[n_calls]` layout as the v2 typed path,
// so the engine / control plane don't need to know which driver produced
// the result.

#pragma once

#include "worker/backend/exec_backend.hpp"
#include "worker/coverage/kcov_collector.hpp"            // KcovCollector type (per-call API)
#include "worker/coverage/kcov_collector_provider.hpp"   // [v2 Epic 7 PR-1] IKcovCollectorProvider
#include "worker/coverage/kcov_drain_sink.hpp"           // [v2 Epic 7 PR-4] IKcovDrainSink
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/fault_inject.hpp"

#include <cstdint>
#include <memory>

namespace refuzz::worker {

class KernelThreadPool;  // [v2 Epic 7 PR-4] forward decl;cpp #include 完整定义

class KernelWireDriver final : public IExecBackend {
public:
    // available_caps is threaded into PseudoRuntimeContext at construction and
    // gates cap-gated pseudo (mount-image/KVM/USB/needs_root) in the dispatcher.
    // [syscall-enable-whitelist] Profiles now pass ~0 (all caps) so the gate
    // never blocks a call the enable/disable_syscalls whitelist already
    // admitted; the param is retained for tests that exercise the gate directly.
    //
    // [v2 Epic 6 D-14 — fault-inject test seam]
    // `inject_fault_fn` / `fault_injected_fn` 默认绑到 fault_inject.hpp 的真
    // 实现;tests/kernel_wire_driver_fault_inject_test 用 mock 替换以验证
    // fail_fd<0 graceful、flag 置位/未置位等失败路径(无需真实 kernel
    // /proc/thread-self/fail-nth 支持)。Production 不应传 nullptr;
    // 构造时 fallback 自动绑真实函数。
    // [v2 Epic 7 PR-4] ctor 末尾新增 `thread_count` 参数。default 1 → driver
    // 内部不构造 KernelThreadPool(serial 路径不需要 thread pool 资源),与
    // Step 1~3 行为完全等价。> 1 时 driver 构造 KernelThreadPool(size=
    // thread_count),threaded path Execute 走 worker thread 调度。KCOV provider
    // 可以少于 thread_count;调度层会拒绝超出 opened KCOV fd 的 tid
    // closed,避免 tid>=slot 的 syscall 静默丢 coverage。
    //
    // 实际 spawn 是 lazy 的(KernelThreadPool::ScheduleCall 第一次调到该 tid
    // 才 pthread_create),所以 thread_count>1 但实际全跑 serial task 时
    // 也无 thread spawn 成本。
    // proc_slot_id: execution-resource identity, independent of the stable
    // channel worker slot. Used for: (a) ProcType pid_stride multiplier, (b)
    // pseudo handlers that mirror upstream's per-process resource naming
    // (/dev/loop<slot>, KVM CPU index, ifname suffix, ...). NOT a syzkaller
    // program attribute. See PseudoContext.proc_slot_id doc for the full
    // contract.
    KernelWireDriver(std::unique_ptr<IDispatcher> dispatcher,
                     uint32_t proc_slot_id = 0,
                     InjectFaultFn   inject_fault_fn   = nullptr,
                     FaultInjectedFn fault_injected_fn = nullptr,
                     uint32_t        thread_count      = 1);

    ~KernelWireDriver();  // [v2 Epic 7 PR-4] explicit ~ for unique_ptr<KernelThreadPool> fwd-decl

    int Execute(const uint8_t* input, uint32_t input_len,
                uint8_t* output, uint32_t output_cap,
                uint32_t* output_len,
                ExecMode mode = {}) override;

    const char* Name() const override { return "kernel_wire"; }

    void ConfigureProcId(uint32_t proc_id) override { proc_slot_id_ = proc_id; }

    // [Step A 2026-05-20] precision /dev/loop sweep mask (see IExecBackend).
    // Read-and-reset so the next Execute starts at 0.
    uint32_t TakeLoopDevicesUsedMask() override {
        const uint32_t m = loop_devices_used_mask_last_exec_;
        loop_devices_used_mask_last_exec_ = 0;
        return m;
    }

    RuntimeFailure RuntimeFailureState() const override {
        return runtime_failure_;
    }

    bool SetLoopDevicesUsedMaskCursor(uint32_t* cursor) override {
        loop_devices_used_mask_cursor_ = cursor;
        return true;
    }

    // [v2 Epic 7 PR-1 — 当前版本] provider-based wiring。driver 不再持单
    // collector,改持 IKcovCollectorProvider*;Execute() 入口按当前 thread
    // tid 取 collector。
    void SetKcovProvider(IKcovCollectorProvider* provider) { kcov_provider_ = provider; }

    // [v2 Epic 7 PR-4] threaded path 下 driver 通过该 sink 把每个 worker
    // thread 的 drained CMP records 推回 sink。PC coverage 通过 per-call
    // SyzExecResult tail 返回,不再由 sink emit program-level packet。serial
    // path 不使用此 sink,sink 自己通过 OnEvent(kSessionEnd) drain。thread_count==1
    // 时 driver 不构造 KernelThreadPool,此 sink 永远不被调用。
    //
    // 模块边界:driver 仅依赖 coverage/ (IKcovCollectorProvider +
    // IKcovDrainSink),不依赖 observation/ 具体类。
    void SetKcovDrainSink(IKcovDrainSink* drain_sink) { kcov_drain_sink_ = drain_sink; }

    // [v1 per-call shmem progress — 2026-05-13]
    // 在每条 program Execute 之前由 caller 注入两个 cursor 指针;Execute 内
    // serial path 每完成一个 syscall 后 RELEASE-store 当前进度。任一为 nullptr
    // 即跳过。caller 应在 Execute 返回后传 nullptr 复位,防 stale ptr。
    void SetProgressCursors(uint32_t* completed_calls,
                            uint32_t* output_len) override {
        progress_completed_ = completed_calls;
        progress_output_len_ = output_len;
    }

    void SetDiagnosticExecutorId(uint64_t executor_id) override {
        diagnostic_executor_id_ = executor_id;
    }

    // [当前版本 per-call-timeout-config] threaded path 下 WaitCallDone 的
    // per-call 超时。0 视作 "用默认 500ms" (QEMU fuzz 路径:targets.go:857
    // Syscall=50ms × QEMU slowdown=10;upstream stdio fallback 5000ms 跟实际
    // fuzz 不同源,不再作为默认)。serial path 不读此值。setter 形式跟
    // SetKcovProvider/SetKcovDrainSink 一致,避免再扩 ctor 签名;profile
    // factory 在构造 driver 后立刻调一次,后续不再变更。
    void SetPerCallTimeoutMs(uint32_t ms) {
        per_call_timeout_ms_ = (ms == 0) ? 500u : ms;
    }

    // [threaded end-drain parity] Program-level timeout (= host exec_timeout_ms,
    // syzkaller Program timeout). threaded path 末尾 drain 用它算等待上限:
    // 对齐 executor.cc:1134 `wait_end = max(wait_end, start + program_timeout_ms/6)`
    // ——给未完成 syscall 一个跟 program timeout 成比例的尾窗,而不是只
    // per_call_timeout × 2。0 视作默认 5000ms。serial path 不读此值;profile
    // 在构造 driver 后调一次(跟 SetPerCallTimeoutMs 并列),后续不变。
    void SetProgramTimeoutMs(uint32_t ms) {
        program_timeout_ms_ = (ms == 0) ? 5000u : ms;
    }

private:
    std::unique_ptr<IDispatcher> dispatcher_;
    uint32_t                     proc_slot_id_;  // runtime slot identity; see ctor doc
    InjectFaultFn                inject_fault_fn_;
    FaultInjectedFn              fault_injected_fn_;

    // [v2 Epic 7 PR-1] borrowed provider; Execute() resolves the active
    // collector via kcov_provider_->GetCollector(tid).
    IKcovCollectorProvider*      kcov_provider_ = nullptr;

    // [v2 Epic 7 PR-4] threaded path sink (push drained CMP records) + thread
    // pool (size = thread_count, lazy spawn)。Execute 入口会检查 provider
    // ThreadCount() 是 opened KCOV fd 数,可小于 logical thread_count。
    // thread_count==1 时 pool_=nullptr,Execute 走 serial fast path 不接触 drain_sink_。
    IKcovDrainSink*              kcov_drain_sink_ = nullptr;
    uint32_t                     thread_count_    = 1;
    // [当前版本 per-call-timeout-config] threaded WaitCallDone 超时(ms),
    // 见 SetPerCallTimeoutMs。0 在 setter 内规整成 500ms 默认 (QEMU fuzz
    // 路径 50ms×10,不是 stdio fallback 5000ms)。
    uint32_t                     per_call_timeout_ms_ = 500;
    // [threaded end-drain parity] program-level timeout (host exec_timeout_ms);
    // see SetProgramTimeoutMs. Default 5000 matches the engine default.
    uint32_t                     program_timeout_ms_ = 5000;
    std::unique_ptr<KernelThreadPool> pool_;

    // [v1 per-call shmem progress — 2026-05-13] 见 SetProgressCursors。
    uint32_t*                    progress_completed_  = nullptr;
    uint32_t*                    progress_output_len_ = nullptr;
    uint32_t*                    loop_devices_used_mask_cursor_ = nullptr;
    uint64_t                     diagnostic_executor_id_ = 0;
    RuntimeFailure               runtime_failure_ = RuntimeFailure::kNone;

    // [Step A 2026-05-20] per-program /dev/loop usage mask captured at end
    // of each Execute, drained by TakeLoopDevicesUsedMask. 0 default; serial
    // path copies from local pseudo_ctx; threaded path aggregates worker ctxs.
    uint32_t                     loop_devices_used_mask_last_exec_ = 0;

};

} // namespace refuzz::worker
