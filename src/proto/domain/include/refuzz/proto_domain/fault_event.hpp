#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::proto {

// 故障原因：观察层发现的具体异常类型
enum class FaultReason : uint8_t {
    kWorkerHeartbeatLost = 0,  // 心跳停止（HeartbeatChecker）
    kKernelCrash,              // 内核崩溃（SerialConsoleWatcher，携带 crash_fragment）
    kVmDead,                   // VM 进程退出（vm_instance->IsAlive()）
    kGenerationReset,          // generation 变化（transport TakeGenerationReset）
    kInflightStale,            // inflight 超龄（SweepStaleInflight）
    kSubmitFailed,             // 发送失败（Submit path）
    // [v2 PR-D — 当前版本]
    // abnormal completion 路径（worker 上报 abnormal / recovery 后清理 inflight）
    // 没有对应 fault sensor，但旧版本 BuildContextOp 第二分支不写 fault_reason
    // 导致 meta.json 误印 default 值 kWorkerHeartbeatLost（看起来像心跳丢失，
    // 实际是 worker 上报 ChildAborted / WorkerSignaled / Timeout）。
    // 现在显式标 kAbnormalExit，meta.json 的 fault_reason 字段才是真值。
    kAbnormalExit = 6,
    // [v2 PR-E — 当前版本]
    // 默认值占位:struct 字段未被任何分支显式写时落到 kUnknown,落盘 meta.json
    // 显示 "unknown" 而不是伪装成 kWorkerHeartbeatLost / kAbnormalExit 等"合法值"。
    // 任何漏填路径都直接暴露在 meta 上,便于 review。
    kUnknown = 7,
    // Full retained-classification window expired without a kernel report.
    kNoOutput = 8,
};

// 故障来源：哪个观察路径发现了故障
enum class FaultSource : uint8_t {
    kHealthMonitor = 0,        // HealthMonitor（心跳 / serial / vm alive）
    kInflightSweep,            // inflight 超龄扫描
    kSubmitPath,               // Submit 失败路径
    kChannelInternal,          // Channel 内部 follow-up / recovery 失败重观察
    // [v2 PR-D — 当前版本]
    // abnormal completion 通路（worker 数据plane 上报 / channel recovery 触发）
    // 不属于 health sensor 也不属于 channel internal recovery，单独标识。
    kAbnormalCompletion = 4,
    // [v2 PR-E — 当前版本]
    // 默认值占位,同 FaultReason::kUnknown:任何漏填路径暴露为 "unknown" 不伪装。
    kUnknown = 5,
};

// §3.11-A — Fault origin: which sensor produced the underlying
// crash event. Mirrors core::channel_contract::FaultOrigin and
// health::CrashEventOrigin verbatim. Carries the origin across the
// CombinedCrashEvent boundary to CrashPipeline so classification can
// gate evidence-coercions on origin (e.g. only allow
// kWorkerDead → kKernelCrash if origin == kSerialPattern).
enum class FaultOrigin : uint8_t {
    kHeartbeat       = 0,
    kSerialEof       = 1,
    kSerialPattern   = 2,
    kVmLiveness      = 3,
    kHealthInternal  = 4,
    kInflightSweep   = 5,
    kSubmitPath      = 6,
    kChannelInternal = 7,
    kUnknown         = 8,
    // [v2 PR-D — 当前版本]
    // abnormal completion 路径的 origin。CrashContext.fault_origin 据此让
    // ParseAndClassifyOp evidence-coercion gate 自然不命中(gate 仅认 kSerialPattern
    // 才把 worker_dead 升级为 kKernel_crash)。abnormal path 已在 BuildContextOp
    // 第二分支独立分类,不需要二次升级。
    // 数值与 core::channel_contract::FaultOrigin 同步(static_cast 直接转)。
    kAbnormalCompletion = 9,
};

// 故障事件：从 ChannelFaultTracker 导出的系统侧 fault 上下文。
// 在冷链路中由 CombinedCrashEvent 统一收集，不直接走热路径 result_queue。
struct FaultEvent {
    uint64_t incident_id = 0;
    uint32_t channel_id = 0;
    uint32_t slot_id = 0;
    uint32_t generation = 0;

    // [v1 默认 kWorkerHeartbeatLost/kHealthMonitor — ROLLBACK]
    // FaultReason reason = FaultReason::kWorkerHeartbeatLost;
    // FaultSource source = FaultSource::kHealthMonitor;
    // [v2 PR-E 默认 kUnknown 防止漏填伪装 — 当前版本]
    FaultReason reason = FaultReason::kUnknown;
    FaultSource source = FaultSource::kUnknown;
    // §3.11-A — origin of the underlying sensor signal. Used by
    // CrashPipeline ParseAndClassifyOp to gate evidence-coercion
    // (e.g. kWorkerDead → kKernelCrash only if origin == kSerialPattern).
    FaultOrigin origin = FaultOrigin::kUnknown;


    std::string crash_title;       // 非空 → 内核 crash
    std::string crash_console;     // console 只在 FaultEvent 保留一份

    uint64_t executor_id = 0;
    uint64_t submit_ts_us = 0;
    std::vector<uint8_t> program_payload;

    uint64_t created_ts_us = 0;    // incident freeze 时间
};

} // namespace refuzz::proto
