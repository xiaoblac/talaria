#pragma once

// refuzz::core::channel_contract — Channel 跨模块合同 schema
//
// 唯一对外 schema 归属：channel 模块 publish 这些类型；feedback / control /
// telemetry / queue / tests / crash 等消费者**直接** include 本头文件，
// 跟 channel 模块平级地拿类型；不要通过任何 channel-side 短名 alias 转发。
//
// .cpp 里推荐 `namespace cc = refuzz::core::channel_contract;` 缩写别名；
// header 用全名 `refuzz::core::channel_contract::Xxx` 保持自洽。
//
// 类型边界：本文件只装跨模块 schema（10 类合同 + 健康/恢复/运行时快照子结构）。
// channel 模块自有类型（IChannel / Channel / Result<T> / EventList /
// DispatchRecord / DispatchState）保留在 executor/channel/orchestration/，
// 其中 internal/dispatch_record.hpp 是 channel-private，不被外部 include。
//
// Wire / 实现细节隔离：
//   - 本文件不 include proto_wire/ivshmem_protocol.h
//   - CrashFragment::step_event_snapshot 使用独立 StepEventRecord
//   - 外部合同完全隔离 ivshmem 实现，便于换底层（virtio-vsock / KVM / BPF）

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// §3.10 D6/D8 follow-up — artifact-first universal contract.
// Forward-declared to avoid pulling refuzz/program/* into refuzz_core
// (which sits below refuzz_program in the link DAG). Consumers that
// actually dereference CompletionContext::artifact must include
// "refuzz/program/artifact.hpp" themselves.
namespace refuzz::program { class ProgramArtifact; }

namespace refuzz::core::channel_contract {

// ================================================================
// 0. 基础语义枚举（面 C/D）
// ================================================================

enum class FaultKind : uint8_t {
    kKernelCrash,
    kVmDead,
    kWorkerDead,
    // health-monitor internal fault (no external crash) — a source-side health check
    // triggered strong-recovery gating (e.g. heartbeat-miss). Distinct from kWorkerDead;
    // carried on the kFaultDetected observe event so telemetry no longer mislabels an
    // internal health fault as a worker death. Recovery keys on ChannelFaultReason, not
    // this field. Does NOT flow through the fuzzer fault path (no AbnormalCompletion).
    kHealthInternal,
    kNoOutput,
};

inline const char* FaultKindName(FaultKind kind)
{
    switch (kind) {
    case FaultKind::kKernelCrash: return "kernel_crash";
    case FaultKind::kVmDead:      return "vm_dead";
    case FaultKind::kWorkerDead:  return "worker_dead";
    case FaultKind::kHealthInternal: return "health_internal";
    case FaultKind::kNoOutput:    return "no_output";
    }
    return "unknown";
}

enum class ChannelLifecycleState : uint8_t {
    kStopped,
    kBooting,
    kRunning,
    kDegraded,
    kRecovering,
    kFailed,
    kClosed,
};

inline const char* ChannelLifecycleStateName(ChannelLifecycleState state)
{
    switch (state) {
    case ChannelLifecycleState::kStopped:    return "stopped";
    case ChannelLifecycleState::kBooting:    return "booting";
    case ChannelLifecycleState::kRunning:    return "running";
    case ChannelLifecycleState::kDegraded:   return "degraded";
    case ChannelLifecycleState::kRecovering: return "recovering";
    case ChannelLifecycleState::kFailed:     return "failed";
    case ChannelLifecycleState::kClosed:     return "closed";
    }
    return "unknown";
}

enum class ChannelFaultReason : uint8_t {
    kWorkerHeartbeatLost = 0,
    kKernelCrash,
    kVmDead,
    kGenerationReset,
    kInflightStale,
    kSubmitFailed,
    kHealthInternal,
    kWorkerHarnessFatal,
    kExecutionDomainHung,
    kNoOutput,
};

inline const char* ChannelFaultReasonName(ChannelFaultReason reason)
{
    switch (reason) {
    case ChannelFaultReason::kWorkerHeartbeatLost: return "worker_heartbeat_lost";
    case ChannelFaultReason::kKernelCrash:         return "kernel_crash";
    case ChannelFaultReason::kVmDead:              return "vm_dead";
    case ChannelFaultReason::kGenerationReset:     return "generation_reset";
    case ChannelFaultReason::kInflightStale:       return "inflight_stale";
    case ChannelFaultReason::kSubmitFailed:        return "submit_failed";
    case ChannelFaultReason::kHealthInternal:      return "health_internal";
    case ChannelFaultReason::kWorkerHarnessFatal:  return "worker_harness_fatal";
    case ChannelFaultReason::kExecutionDomainHung: return "execution_domain_hung";
    case ChannelFaultReason::kNoOutput:             return "no_output";
    }
    return "unknown";
}

enum class ChannelFaultSource : uint8_t {
    kHealthMonitor = 0,
    kInflightSweep,
    kSubmitPath,
    kChannelInternal,
};

// §3.11-A — Fault origin: which sensor / observation path produced
// this fault event. Carries `health::CrashEventOrigin` semantics
// across the channel-contract boundary so downstream classification
// (CrashPipeline ParseAndClassifyOp) can gate evidence-based
// coercions on whether the originating sensor actually saw kernel
// console output (kSerialPattern), vs. only worker heartbeat
// (kHeartbeat) — see Bug #1 in docs/typed-program-pipeline crash
// pipeline review.
//
// Mirrored verbatim from `health::CrashEventOrigin` to avoid pulling
// `health/` into core/. Channel.cpp does the 1:1 mapping; values are
// kept in numeric sync via the static_assert below.
enum class FaultOrigin : uint8_t {
    kHeartbeat       = 0,   // worker heartbeat sensor (no console evidence)
    kSerialEof       = 1,   // serial channel EOF (worker died mid-output)
    kSerialPattern   = 2,   // serial sensor matched a kernel crash pattern
    kVmLiveness      = 3,   // VM IsAlive() returned false
    kHealthInternal  = 4,   // sensor-internal failure (escalation)
    kInflightSweep   = 5,   // host-side inflight stale sweep
    kSubmitPath      = 6,   // host-side Submit failure
    kChannelInternal = 7,   // channel-internal recovery follow-up
    kUnknown         = 8,   // origin not propagated (legacy / placeholder)
    // [v2 PR-D — 当前版本]
    // abnormal completion 路径的 origin（worker 上报 abnormal /
    // channel recovery 后 EmitAbnormalCompletion）。数值与
    // proto::FaultOrigin::kAbnormalCompletion 同步(=9)。
    kAbnormalCompletion = 9,
};

inline const char* FaultOriginName(FaultOrigin origin) {
    switch (origin) {
    case FaultOrigin::kHeartbeat:       return "heartbeat";
    case FaultOrigin::kSerialEof:       return "serial_eof";
    case FaultOrigin::kSerialPattern:   return "serial_pattern";
    case FaultOrigin::kVmLiveness:      return "vm_liveness";
    case FaultOrigin::kHealthInternal:  return "health_internal";
    case FaultOrigin::kInflightSweep:   return "inflight_sweep";
    case FaultOrigin::kSubmitPath:      return "submit_path";
    case FaultOrigin::kChannelInternal: return "channel_internal";
    case FaultOrigin::kUnknown:         return "unknown";
    case FaultOrigin::kAbnormalCompletion: return "abnormal_completion";
    }
    return "unknown";
}

enum class ChannelAbortScope : uint8_t {
    kNone = 0,
    kSlot,
    kChannel,
};

enum class RecoveryAction : uint8_t {
    kNone = 0,
    kRestartSingleWorker,
    kRestartAllWorkers,
    kRebootVm,
    kFailChannel,
    kRestartHealthMonitor,
    // snapshot 模式专用：内核崩溃后**不重启 VM**（重启会重建 qcow2 overlay 毁掉
    // savevm S0），而是释放本次 in-flight + reset data plane，内核状态由下一次
    // loadvm S0 还原。对齐 syzkaller snapshot 的 "loadvm 即恢复" 模型。
    kReloadSnapshot,
};

inline const char* RecoveryActionName(RecoveryAction action)
{
    switch (action) {
    case RecoveryAction::kNone:                 return "none";
    case RecoveryAction::kRestartSingleWorker:  return "restart_single_worker";
    case RecoveryAction::kRestartAllWorkers:    return "restart_all_workers";
    case RecoveryAction::kRebootVm:             return "reboot_vm";
    case RecoveryAction::kFailChannel:          return "fail_channel";
    case RecoveryAction::kRestartHealthMonitor: return "restart_health_monitor";
    case RecoveryAction::kReloadSnapshot:       return "reload_snapshot";
    }
    return "unknown";
}

// ================================================================
// 1. 健康 / 恢复 / 运行时快照子结构
// ================================================================

// worker 任务槽的语义状态。**不透传后端 wire 值** —— ivshmem 的 TASK_EMPTY/READY/TAKEN 由
// 控制面翻译到这里，telemetry 与 renderer 不该认识某个具体传输的编码。
enum class WorkerSlotState : uint8_t {
    kUnknown = 0,   // 后端不支持此语义（如 xiuos UART 的 Ping/Pong 模型）
    kEmpty,         // host 没派活 / 上一个已收割
    kDispatched,    // host 派了，guest 还没取走 —— 停在这里 = daemon 没在 poll
    kExecuting,     // guest 取走了，正在跑
};

inline const char* WorkerSlotStateName(WorkerSlotState state)
{
    switch (state) {
    case WorkerSlotState::kEmpty:     return "empty";
    case WorkerSlotState::kDispatched:return "dispatched";
    case WorkerSlotState::kExecuting: return "executing";
    case WorkerSlotState::kUnknown:   break;
    }
    return "unknown";
}

struct WorkerLivenessEntry {
    uint32_t worker_id = 0;
    bool is_alive = false;

    // [心跳重定义] is_alive 是**判死之后的终态**，而判死要等满 silent_budget_s（300s）。
    //   光有它，面板上就是"299s 一直 alive，然后啪一下 dead" —— stall 完全没有过程可看。
    //   下面几个把 stall 从"状态跳变"变成"看着它涨的连续量"：
    //
    //     silent_s / silent_budget_s  进度令牌静止了多久 / 判死阈值
    //     proc_epoch                  daemon 轮换 domain 的代次
    //     recovering                  proc_epoch 在**本次静默期内**涨过
    //     slot                        这一刻这个 worker 手上的活到哪一步了
    //
    //   recovering 是能不能解读 silent_s 的关键：daemon 只要活着，程序 hang 到点必然去轮换
    //   domain（proc_epoch +1）。所以
    //     静默 + proc_epoch 在涨  → daemon 活着，卡的是**被测程序**，它正在自救（合法最长 65s）
    //     静默 + proc_epoch 冻着  → 连自救都没做 → 卡的是 **daemon 自己**
    //   没有它，"静默 60s"这条信息无法解读 —— 分不清是正在正确履职还是已经死了。
    //
    //   slot 提供一条独立且更快的旁证：daemon 的取活循环是 1ms 级的（poll_ms=1），所以
    //   **kDispatched 停留哪怕一秒**都意味着它没在 poll —— 不必等满 300s 就看得出来。
    uint32_t silent_s = 0;
    uint32_t silent_budget_s = 0;
    uint32_t proc_epoch = 0;
    bool recovering = false;
    WorkerSlotState slot = WorkerSlotState::kUnknown;
};

// [crash 计数已删] 这里曾有 CrashKindStats{kernel_crash, vm_dead, worker_dead,
//   internal_fault} 挂在 HealthMonitorSnapshot 上。它是第二套账本，填了从来没人读：
//   事件在 HealthMonitor::Publish / PublishCrashEvent 里已经按 kind 分类并 Inc 了源头
//   Counter（channel.health.crash{kind=kernel|vm|worker|internal}），那条路才是出数的；
//   PublishFromSnapshot 全程不碰 crash_stats，renderer 读的也是 Counter。
//   两套账本还语义不一致：snapshot 侧随 Start() 清零，Counter 侧本 run 内单调。

struct HealthMonitorSnapshot {
    std::vector<WorkerLivenessEntry> worker_liveness;
    uint64_t sampled_ts_us = 0;
};

struct PolicySnapshot {
    std::string policy_name;
    uint32_t max_runtime_restart_attempts = 0;
    uint32_t max_vm_reboot_attempts = 0;
    uint32_t max_single_worker_restart_attempts = 0;
    uint32_t unusable_ratio_reboot_threshold_pct = 0;
};

struct ChannelRecoverySnapshot {
    uint32_t runtime_restart_count = 0;
    uint32_t vm_reboot_count = 0;
    uint32_t consecutive_healthy = 0;
    uint64_t last_fault_ts_us = 0;
    bool offline = false;
    bool recovery_in_progress = false;
    RecoveryAction active_action = RecoveryAction::kNone;
    PolicySnapshot policy;
};

struct ChannelRuntimeSnapshot {
    uint32_t total_slots = 0;
    uint32_t free_slots = 0;
    uint32_t inflight = 0;
    uint32_t registered_workers = 0;
    uint32_t quarantined_workers = 0;
};

// ================================================================
// 2. ChannelSnapshot / ChannelObserveEvent（面 C / 面 D）
// ================================================================

struct ChannelSnapshot {
    uint32_t channel_id = 0;
    uint32_t generation = 0;
    ChannelLifecycleState lifecycle_state = ChannelLifecycleState::kStopped;
    uint64_t boot_ts_us = 0;
};

enum class ChannelObserveEventKind : uint8_t {
    kLifecycleChanged = 0,
    kFaultDetected,
    kRecoveryStarted,
    kRecoveryCompleted,
    kGenerationReset,
};

inline const char* ChannelObserveEventKindName(ChannelObserveEventKind kind)
{
    switch (kind) {
    case ChannelObserveEventKind::kLifecycleChanged: return "lifecycle_changed";
    case ChannelObserveEventKind::kFaultDetected:    return "fault_detected";
    case ChannelObserveEventKind::kRecoveryStarted:  return "recovery_started";
    case ChannelObserveEventKind::kRecoveryCompleted:return "recovery_completed";
    case ChannelObserveEventKind::kGenerationReset:  return "generation_reset";
    }
    return "unknown";
}

struct ChannelObserveEvent {
    ChannelObserveEventKind kind = ChannelObserveEventKind::kLifecycleChanged;
    uint64_t event_id = 0;
    uint64_t ts_us = 0;
    uint32_t channel_id = 0;
    uint32_t generation = 0;
    ChannelLifecycleState old_lifecycle_state = ChannelLifecycleState::kStopped;
    ChannelLifecycleState new_lifecycle_state = ChannelLifecycleState::kStopped;
    FaultKind fault_kind = FaultKind::kKernelCrash;
    ChannelFaultReason fault_reason = ChannelFaultReason::kWorkerHeartbeatLost;
    RecoveryAction recovery_action = RecoveryAction::kNone;
    bool recovery_success = false;
    uint32_t old_generation = 0;
    uint32_t new_generation = 0;
    // 恢复失败时携带具体 error message（r1/r3/r4 的 .error().message），
    // telemetry 将其渲染到 recovery_complete 事件 detail 字段。
    std::string error_message;
};

using ChannelObserveEventList = std::vector<ChannelObserveEvent>;

// ================================================================
// 3. Submit / Drain 合同（面 B）
// ================================================================

// Sentinel for ChannelDispatchRequest.target_worker_id meaning "let the
// channel pick" (round-robin). Any specific value < channel n_workers selects
// strict affinity to that worker slot — Channel.Submit returns kInvalid if
// the value is >= n_workers, and the request waits in the queue until the
// chosen worker is sendable rather than falling back to a peer. This is a
// transport/control placement constraint; resource identity uses
// target_proc_id below. Default kAnyWorkerId preserves round-robin
// behavior for callers that don't care.
inline constexpr uint32_t kAnyWorkerId =
    static_cast<uint32_t>(~uint32_t{0});
inline constexpr uint32_t kAnyProcId =
    static_cast<uint32_t>(~uint32_t{0});
inline constexpr uint32_t kMaxProcIds = 32;

struct ChannelDispatchRequest {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    std::vector<uint8_t> payload;
    uint32_t timeout_ms = 0;
    // [v2 Epic 5 PR-5-B] TaskSlot.flags wire encoding (NOT proto::ExecOpts.flags).
    // Channeldispatcher translates proto → wire when building the request;
    // Channel forwards it untouched into IDataPlane::SubmitInput.exec_flags;
    // IvshmemDataPlane writes it into TaskSlot.flags. See
    // proto/wire/include/refuzz/proto_wire/ivshmem_protocol.h for bit layout
    // (TASK_FLAG_INTRA_* / TASK_FLAG_SHAPE_* / TASK_FLAG_COLLECT_COMPS).
    uint32_t exec_flags = 0;
    // Optional strict worker-slot affinity. See kAnyWorkerId doc above.
    uint32_t target_worker_id = kAnyWorkerId;
    // Optional execution-resource identity. A specific proc ID is routed to
    // its lane owner (proc_id % n_workers), independently of worker affinity.
    // The worker rebinds its execution domain before dispatch when needed.
    uint32_t target_proc_id = kAnyProcId;
    refuzz::proto::TaskTrace trace{};
};

enum class ChannelSubmitStatus : uint8_t {
    kAccepted = 0,
    kBusy,
    kUnavailable,
    kInvalid,
};

struct ChannelSubmitResult {
    ChannelSubmitStatus status = ChannelSubmitStatus::kInvalid;
    uint32_t generation = 0;
};

// ChannelState — 用于 Fault.channel_ctx.state_before_fault 字段
enum class ChannelState {
    kUnknown,
    kReady,
    kDegraded,
    kDown,
};

// [v2 Epic 6 D-7 §3.10 fix — artifact-first universal contract for Fault path]
// 新增 `artifact` 字段(可选;Fault path 由 channeldispatcher::AttachArtifactToEvent
// 反查 inflight_artifacts_[executor_id] 填入,其它发送方留 nullptr 不破语义)。
// 让 fault-induced kernel crash 经过 BuildCombinedFromFault 时能把 ProgramArtifact
// 透传到 CombinedCrashEvent.crash_origin_artifact,下游 StageMinimize 不再因
// crash_origin_artifact==nullptr fail-close。
// 详见 docs/plans/syzkaller-capability-closure-epic-6.md §3 D-7。
struct ChannelTaskSnapshot {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    std::vector<uint8_t> payload;
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
};

struct CompletionContext {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    uint64_t origin_seed_id = 0;
    uint32_t worker_id = 0;
    uint32_t proc_id = kAnyProcId;
    uint32_t dispatch_gen = 0;
    uint32_t generation = 0;
    uint64_t submit_ts_us = 0;
    std::vector<uint8_t> program_payload;
    // §3.10 D6/D8 follow-up — artifact-first universal contract:
    //   `program_payload` is the executor's lowered execution cache (one-way
    //   from artifact via serialize_for_exec; not guaranteed to round-trip
    //   for typed targets and not round-trippable at all for raw-bytes /
    //   script / VM-snapshot future targets).
    //   `artifact` is the authoritative semantic representation propagated
    //   across the submit/completion boundary by channeldispatcher
    //   (Channel itself does not know ProgramArtifact — it's filled in
    //   ForwardEvents from the inflight map keyed by executor_id).
    //   Downstream V2 consumers (corpus admit, BuildContextOp, repro stage
    //   extract / minimize) MUST read `artifact`; they MUST NOT reverse-decode
    //   `program_payload`. See docs/syzkaller-parity-review/post_v1_retirement_followups.md.
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
    refuzz::proto::TaskTrace trace{};
};


// [v2 AbnormalKind +kChildAborted — 当前版本]
// 单独区分 "program 让 child 没按协议返回，worker daemon 健在" 这一类。
// 之前这类被错归到 kWorkerSignaled 并被 crash pipeline 错升级成 kWorkerDead；
// 与 syzkaller `non-kFailStatus → reply_execute(0) + Success` 的语义对齐。
enum class AbnormalKind : uint8_t {
    // [两层语义] kHang = **task hang**:daemon watchdog(worker 守护进程的 3×program-
    // timeout 看门狗)判定 execution domain 已经拿不到任何结果,或 host 侧判 worker 死。
    // wire 上是 COMP_STATUS_HUNG + ERR_DOMAIN_WATCHDOG_TIMEOUT（或执行阶段
    // 恢复失败的 ERR_DOMAIN_* / reap 类 ERR_HARNESS_*）；防御性兼容旧
    // TIMEOUT + ERR_DOMAIN_WATCHDOG_TIMEOUT。ERR_DOMAIN_OWNERSHIP_UNRECLAIMED
    // （error 15）防御性到达时同样按 kHang 结算（不 retained、不等内核输出），
    // 任务已进 hang 池；worker 侧当前维护错误走 error_latch 独立上报，不再
    // 伪装成第二条 completion。
    //
    // **不要**跟 program watchdog 的超时混淆:那一层是程序自己跑太久被 SIGKILL,worker
    // 健在、已发布的数据完整可信,走 Completion 侧的 CompletionKind::kTimeout。两者在
    // wire 上共用 COMP_STATUS_TIMEOUT,由 error_code 区分;Channel::DrainTransport 是
    // 唯一做这个分辨的地方 —— 从 channel 往下,timeout 与 hang 就是两个不同的东西,
    // 消费方直接按 kind 走,不需要再推导。
    kHang = 0,
    // 真的没有任何产出(零 progress)。**不是错误** —— 就是没结果,下游直接不消费,
    // 不需要再判 output 是否为空。worker 健在 → 不 hard_stop。
    kNoResult,
    kWorkerCrashed,
    kWorkerSignaled,
    kCancelled,
    kChildAborted,
    kHarnessFatal,
    // 域重建成功，但仅限 infra 类原始原因（6/7/10/13，程序已证明退出/从未创建）。
    // hang-evidence 原始原因（8/9/12）即使重建成功也保持 kHang —— 旧程序可能
    // 仍以 D 态残留在旧 namespace，必须进 hang 池。
    kHarnessRecovered,
    // [基础设施故障 — 程序无罪] 不是程序的执行结果,是 worker/wiring 的问题。
    // diagnostics.error_code 细分归属:
    //   ERR_EXECUTOR_ERROR — worker 运行时故障(observation sink / backend 失败)
    //   ERR_INVALID_INPUT  — 配置/协议错(wire 输入非法、exec flags 不被支持)
    // 两者都是**确定性**的:同一请求重试必然同样失败 → hard_stop,不要当"这次没跑成"
    // 去重试。
    kInfraFault,
    // 兜底:未知 wire status / 不该走到的分支。出现即 bug 信号,不是正常终态 →
    // hard_stop(协议已错位,继续跑无意义)。
    kUnknown,
};

struct WorkerDiagnostics {
    uint32_t worker_id = 0;
    uint32_t error_code = 0;
    uint32_t crash_signal = 0;
    std::vector<uint8_t> worker_log;
};

struct ChannelFaultContext {
    uint32_t channel_id = 0;
    uint32_t generation = 0;
    ChannelState state_before_fault = ChannelState::kUnknown;
    uint64_t detected_ts_us = 0;
};

struct WorkerTaskState {
    uint32_t worker_id = 0;
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    uint64_t seed_id = 0;
    std::vector<uint8_t> payload;
    uint64_t submit_ts_us = 0;
    bool was_inflight = false;
};

// ================================================================
// 4. Crash 现场原始数据（Fault 载荷子结构）
//
// [v3 Phase 3] 已引入独立 StepEventRecord，去 ivshmem 化：
//   - 与 proto_wire/ivshmem_protocol.h::StepEventSlot 解耦（wire 类型仅供 ShmInfra / worker 使用）
//   - ShmInfra::SnapshotStepEventRing() 在 ivshmem 实现内部完成 slot→record 转换
//   - 非 ivshmem 后端（virtio-vsock / ssh dmesg 等）可用同一 record 表达 step 事件，
//     或提供空快照；外部合同不变
// ================================================================

enum class CrashType : uint8_t {
    kUnknown = 0,
    kBug     = 1,
    kPanic   = 2,
    kKasan   = 3,
    kUbsan   = 4,
    kOops    = 5,
};

enum class CrashKind : uint8_t {
    kKernelCrash,
    kVmDead,
    kWorkerDead,
    kHealthInternalFault,
    // VM 级"无进展"（forward-progress frozen）：与 kVmDead 同源但语义不同——
    // QEMU 进程死亡 / console EOF 是 kVmDead（可佐证），聚合前进时钟冻结是
    // kNoOutput（推断型、可汇报 finding，对应 syzkaller "no output from test
    // machine"）。下游按 CrashKind 分支时必须同时处理这两个 VM 级类别。
    kNoOutput,
};

// StepEventRecord — worker 自述行为单条记录（core-neutral，不绑 ivshmem）
//
// 字段承接语义但不承接 wire 布局：
//   - 必选字段（所有后端均可填）：worker_id / seq / ts_us
//   - 语义字段（ivshmem-v2 场景填；其他后端可置 0）：actor_id / executor_id /
//     op_index / phase / status
//   - payload：为未来扩展保留（vendor-specific），定长 16B 避免动态分配
//
// 注：本 struct 不要求与 wire slot 字段一一对应；实现方（如 IvshmemStepEventSource）
// 负责把 wire 字段搬到本 struct；消费方（crash pipeline / telemetry）只看这里。
struct StepEventRecord {
    uint32_t worker_id   = 0;
    uint32_t actor_id    = 0;
    uint64_t executor_id = 0;
    uint32_t op_index    = 0;
    uint32_t phase       = 0;    // 来源于 worker 的 StepEventPhase，host 不解释
    uint32_t status      = 0;    // 来源于 worker 的 CompletionStatus，host 不解释
    uint32_t reserved0   = 0;
    uint64_t seq         = 0;    // 环形缓冲写入序号（ivshmem 使用；其他后端可用单调递增 ID）
    uint64_t ts_us       = 0;    // 单调时钟微秒时间戳
    std::array<uint8_t, 16> payload{};
};

struct CrashFragment {
    CrashKind kind = CrashKind::kKernelCrash;
    uint32_t source_worker_id = 0;
    std::vector<std::string> serial_lines;
    std::vector<StepEventRecord> step_event_snapshot;
    std::string title;
    std::string console_output;
    CrashType type = CrashType::kUnknown;
};

struct CrashScene {
    CrashFragment console;
    std::vector<WorkerTaskState> worker_states;
    std::vector<ChannelTaskSnapshot> candidate_window;
};

// ================================================================
// 5. ChannelEvent（面 B DrainEvents 出口）
// ================================================================

// Completion 侧的终态 —— **都是 data-bearing**:worker 已把 output 如实带出,覆盖照常
// 计入、不 hard_stop。kind 只回答"**为什么结束**",不决定下游怎么处理。
//
// [两层语义] kTimeout 是 **program watchdog**(worker 内 ForkingProgramExecutor 的
// per-program 看门狗,wire: COMP_STATUS_TIMEOUT + ERR_TIMEOUT)判的超时:程序被 SIGKILL,
// 但它在被杀前已按 RELEASE 序发布的 progress 数据完整可信,故与 kPartial 同等处理。
// 真正的 task hang 是 **worker 显式判定的 COMP_STATUS_HUNG**(daemon watchdog +
// ERR_DOMAIN_WATCHDOG_TIMEOUT,或执行阶段恢复失败的 ERR_DOMAIN_* / reap 类
// ERR_HARNESS_*),那一层走 AbnormalKind::kHang,不在本枚举里。TIMEOUT 不再承载
// daemon hang;防御性兼容旧 TIMEOUT + ERR_DOMAIN_WATCHDOG_TIMEOUT 仍按 hang 分流。
//
// [kChildAborted = 有覆盖、且程序自己崩了的一次执行] 被测程序自己 SIGSEGV/SIGABRT
// (用户态进程崩溃 ≠ 内核崩溃)。对齐 syzkaller:program-child 崩溃时 fork-server 照常
// reply_execute(0) = Success,crash 前已提交到 KCOV 的 coverage 有效
// (common.h:736-740)。所以它是 Completion(覆盖要消费),但**同时**是一个值得记录的
// crash 事实 —— 通过下面 Completion::crash_diagnostic 旁路携带诊断,让 FaultSignal
// 仍能建 crash_payload 落盘。这是 variant 单选事件模型下"一次执行同时产出覆盖信号 +
// crash 记录"的表达方式。
enum class CompletionKind : uint8_t {
    kNormal = 0,
    kPartial,
    kTimeout,
    kChildAborted,
};

// [方案 A — Completion 携带 crash 诊断] program-child 自身 crash 是 data-bearing 的
// Completion(覆盖有效),但它**也**是一个 crash 事实。event 是 variant 单选,无法既
// 是 Completion 又是 Abnormal,故把诊断作为可选载荷挂在 Completion 上。仅
// CompletionKind::kChildAborted 填;其余 kind 留 nullopt。FaultSignal 见到它就走与
// 旧 abnormal 路径等价的 BuildCombined 建 crash_payload,诊断落盘不丢。
struct CompletionCrashDiagnostic {
    uint32_t crash_signal = 0;   // 终止信号(SIGSEGV/SIGABRT/...)
    uint32_t error_code = 0;     // ErrorCode(通常 ERR_PROGRAM_CHILD_CRASHED)
};

struct Completion {
    CompletionContext ctx;
    CompletionKind kind = CompletionKind::kNormal;
    std::vector<uint8_t> output;
    // [v3 call-level oracle v1] Worker-side per-program diagnostic. XiUOS
    // backend fills this with the last call's kernel return code (RESULT
    // payload's `aux` field). Production wedge-only fuzz path ignores it;
    // XiuosFuzzSession::RunOracleSelfTest reads it to catch wedge-invisible
    // semantic bugs (errno mismatch, garbage-return UB, etc.). Other
    // backends keep this 0.
    int32_t vendor_aux = 0;
    // [v3 per-program oracle] Raw worker RESULT status byte (XiUOS:
    // XiuosResultStatus). Lets the campaign distinguish a STATE_VIOLATION
    // completion (silent heap/state corruption caught at a per-call check)
    // from a plain Ok, without inspecting `kind`. Other backends keep 0.
    uint32_t vendor_status = 0;
    // [v3 per-program oracle] Worker RESULT `flags` field. XiUOS uses it as the
    // LSan-style per-program leak delta (net heap bytes not reclaimed after the
    // program's own cleanup, saturated to u16) — a soft leak LEAD. 0 = none.
    uint32_t vendor_flags = 0;
    // [XiUOS leak 一等公民化 Phase 5] Worker-auto-measured RESOURCE residue after the
    // program's own cleanup, packed waitq | victim<<8 | delay<<16 (from the OK-status
    // RESULT trap_or_pc field). Parallel to vendor_flags (heap delta): a program can
    // leak both. 0 = none / non-XiUOS / old ELF.
    uint32_t vendor_resource_residue = 0;
    // [方案 A] program-child 自身 crash 的诊断旁路。仅 kind==kChildAborted 时有值:
    // 这次执行的覆盖照常走 Completion 消费,同时这里携带 crash 事实,让 FaultSignal
    // 建 crash_payload 落盘 —— 覆盖与诊断两不误。其余 kind 恒 nullopt。
    std::optional<CompletionCrashDiagnostic> crash_diagnostic;
};

struct AbnormalCompletion {
    CompletionContext ctx;
    // 默认值刻意选 kUnknown:发送方忘了设 kind 是 wiring bug,应当显形,而不是伪装成
    // 某种看似正常的执行错误(旧默认 kExecError 就是这个问题)。
    AbnormalKind kind = AbnormalKind::kUnknown;
    WorkerDiagnostics diagnostics;
    std::vector<uint8_t> output;
    // [XiUOS leak 一等公民化 Phase 4] Same per-program vendor fields as Completion.
    // A leaky program whose last call also returns an errno arrives here (not as a
    // success Completion), so its leak delta (vendor_flags) must survive the
    // abnormal path too — else leaky-AND-erroring programs lose the leak signal.
    // Mirrors Completion::{vendor_aux,vendor_status,vendor_flags}; other backends 0.
    int32_t vendor_aux = 0;
    uint32_t vendor_status = 0;
    uint32_t vendor_flags = 0;
    // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16),
    // mirrors Completion::vendor_resource_residue; a leaky-AND-erroring program must
    // keep its residue on the abnormal path too. 0 for other backends.
    uint32_t vendor_resource_residue = 0;
    // [v2 PR-B abnormal console snapshot — 当前版本]
    // Channel 在 EmitAbnormalCompletion 时从共享 ConsoleRingBuffer 取
    // 最近若干行 console 文本写入,让 abnormal path 也带上当时的 console
    // 上下文。下游 BuildCombinedFromAbnormal 透传到 CombinedCrashEvent,
    // BuildContextOp 第二分支据此填 ctx.console_log,落盘 report0 才有
    // [console] block / serial_log_tail.txt。
    // 空表示 ring buffer 为空或 channel 未配置 console_ring_。
    std::string console_snapshot;
};

struct Fault {
    uint64_t incident_id = 0;
    FaultKind kind = FaultKind::kKernelCrash;
    // §3.11-A — origin of this fault event. Channel.cpp maps from
    // health::CrashEventOrigin during EmitFaultEvent. Downstream
    // (CrashContext.fault_origin) uses this to gate evidence-coercion
    // logic in ParseAndClassifyOp.
    FaultOrigin origin = FaultOrigin::kUnknown;
    ChannelFaultContext channel_ctx;
    CrashScene scene;
};

struct ChannelEvent {
    enum class Kind : uint8_t {
        kCompletion = 0,
        kAbnormal,
        kFault,
    };

    Kind kind = Kind::kCompletion;
    uint64_t event_id = 0;
    uint32_t channel_id = 0;
    uint32_t generation = 0;

    std::variant<Completion, AbnormalCompletion, Fault> payload;

    bool IsCompletion() const noexcept { return kind == Kind::kCompletion; }
    bool IsAbnormal()   const noexcept { return kind == Kind::kAbnormal; }
    bool IsFault()      const noexcept { return kind == Kind::kFault; }
    bool IsDataPlane()  const noexcept { return IsCompletion() || IsAbnormal(); }

    const Completion* AsCompletion() const noexcept { return std::get_if<Completion>(&payload); }
    Completion*       AsCompletion()       noexcept { return std::get_if<Completion>(&payload); }
    const AbnormalCompletion* AsAbnormal() const noexcept { return std::get_if<AbnormalCompletion>(&payload); }
    AbnormalCompletion*       AsAbnormal()       noexcept { return std::get_if<AbnormalCompletion>(&payload); }
    const Fault* AsFault() const noexcept { return std::get_if<Fault>(&payload); }
    Fault*       AsFault()       noexcept { return std::get_if<Fault>(&payload); }
};

// ================================================================
// 6. BroadcastBus 类型别名（订阅者便捷用）
// ================================================================

using ChannelSnapshotBus = refuzz::core::BroadcastBus<ChannelSnapshot>;
using ChannelObserveBus  = refuzz::core::BroadcastBus<ChannelObserveEvent>;

} // namespace refuzz::core::channel_contract
