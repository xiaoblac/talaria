#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/adapter/repro_channel.hpp"

#include <chrono>

namespace refuzz::crash {
namespace {

bool SameGeneration(uint32_t expected, uint32_t actual)
{
    return expected == 0 || actual == 0 || expected == actual;
}

// [v1 5档标题 — ROLLBACK: uncomment below, remove v2]
// std::string SynthesizeCrashTitleFromAbnormal(refuzz::core::channel_contract::AbnormalKind kind)
// {
//     switch (kind) {
//     case refuzz::core::channel_contract::AbnormalKind::kHang:
//         return "exec-timeout";
//     case refuzz::core::channel_contract::AbnormalKind::kExecError:
//         return "exec-error";
//     case refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed:
//         return "worker-crashed";
//     case refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled:
//         return "worker-signaled";
//     case refuzz::core::channel_contract::AbnormalKind::kCancelled:
//         return "cancelled";
//     }
//     return "exec-error";
// }
// [v2 +kChildAborted — 当前版本]
std::string SynthesizeCrashTitleFromAbnormal(refuzz::core::channel_contract::AbnormalKind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::AbnormalKind::kHang:
        return "exec-timeout";
    case refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed:
        return "worker-crashed";
    case refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled:
        return "worker-signaled";
    case refuzz::core::channel_contract::AbnormalKind::kCancelled:
        return "cancelled";
    case refuzz::core::channel_contract::AbnormalKind::kChildAborted:
        return "child-aborted";
    case refuzz::core::channel_contract::AbnormalKind::kHarnessRecovered:
        return "harness-recovered";
    case refuzz::core::channel_contract::AbnormalKind::kHarnessFatal:
        return "harness-fatal";
    case refuzz::core::channel_contract::AbnormalKind::kNoResult:
        return "no-result";
    case refuzz::core::channel_contract::AbnormalKind::kInfraFault:
        return "infra-fault";
    case refuzz::core::channel_contract::AbnormalKind::kUnknown:
        return "unknown";
    }
    return "unknown";
}

CrashKind CrashKindFromFaultKind(refuzz::core::channel_contract::FaultKind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::FaultKind::kKernelCrash:
        return CrashKind::kKernelCrash;
    case refuzz::core::channel_contract::FaultKind::kNoOutput:
        return CrashKind::kNoOutput;
    case refuzz::core::channel_contract::FaultKind::kVmDead:
        return CrashKind::kVmDead;
    case refuzz::core::channel_contract::FaultKind::kWorkerDead:
        return CrashKind::kWorkerDead;
    case refuzz::core::channel_contract::FaultKind::kHealthInternal:
        return CrashKind::kUnknownIncident;  // repro 不处理 health_internal
    }
    return CrashKind::kUnknownIncident;
}

} // namespace

ReproChannel::ReproChannel(refuzz::channel::IChannel* channel,
                           std::chrono::milliseconds execute_timeout)
    : channel_(channel)
    , execute_timeout_(execute_timeout)
{}

void ReproChannel::RequestStop()
{
    stopping_.store(true, std::memory_order_release);
}

bool ReproChannel::StopRequested() const
{
    return stopping_.load(std::memory_order_acquire);
}

RunResult ReproChannel::Execute(const std::vector<uint8_t>& payload, uint64_t executor_id)
{
    // [v1 old lease flow ROLLBACK]
    // 旧流程：AcquireLease -> Submit(lease, request) -> 事件循环 -> ReleaseLease。

    // [v2 new atomic submit flow 当前版本]
    // 新流程：直接 Submit(request, wait_for_slot)，slot 分配由 channel 内部原子完成。
    RunResult result;
    if (channel_ == nullptr || StopRequested()) {
        result.error = true;
        return result;
    }

    refuzz::core::channel_contract::ChannelDispatchRequest request;
    request.executor_id = executor_id;
    request.payload = payload;
    request.timeout_ms = static_cast<uint32_t>(execute_timeout_.count());

    refuzz::core::channel_contract::ChannelSubmitResult submit_result;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const auto timeout = (attempt == 0) ? std::chrono::microseconds{0}
                                            : std::chrono::microseconds{1'000'000};
        submit_result = channel_->Submit(request, timeout);
        if (submit_result.status == refuzz::core::channel_contract::ChannelSubmitStatus::kAccepted) {
            break;
        }
        if (submit_result.status != refuzz::core::channel_contract::ChannelSubmitStatus::kBusy) {
            result.error = true;
            return result;
        }
    }
    if (submit_result.status != refuzz::core::channel_contract::ChannelSubmitStatus::kAccepted) {
        result.error = true;
        return result;
    }
    const uint32_t submit_generation = submit_result.generation;

    const auto deadline = std::chrono::steady_clock::now() + execute_timeout_;
    std::vector<refuzz::core::channel_contract::ChannelEvent> events;
    while (true) {
        if (StopRequested()) {
            result.error = true;
            return result;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            result.timed_out = true;
            return result;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        const auto wait_timeout = remaining < std::chrono::microseconds{250000}
            ? remaining
            : std::chrono::microseconds{250000};
        events.clear();
        const bool drained = channel_->DrainEvents(events, wait_timeout);
        if (!drained || events.empty()) {
            // 热状态探测：当代际变化或 channel down 时，立即按不可恢复错误返回。
            const auto current_snapshot = channel_->ObserveSnapshot();
            const uint32_t current_generation = current_snapshot.generation;
            const bool generation_reset =
                current_generation != 0 &&
                !SameGeneration(submit_generation, current_generation);
            const bool channel_unavailable =
                current_generation == 0 ||
                current_snapshot.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kStopped ||
                current_snapshot.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kBooting ||
                current_snapshot.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kFailed ||
                current_snapshot.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kClosed;
            if (generation_reset || channel_unavailable) {
                result.error = true;
                result.crash_kind = CrashKind::kUnknownIncident;
                return result;
            }
            continue;
        }

        // [v2 事件循环 — 使用新 variant payload 访问器，不依赖旧 optional 平铺字段]
        for (const auto& event : events) {
            if (!SameGeneration(submit_generation, event.generation)) {
                continue;
            }

            if (event.IsCompletion()) {
                // ERR_OK 正常完成：仅当 executor_id 匹配时才返回
                const auto* p = event.AsCompletion();
                if (p == nullptr || p->ctx.executor_id != executor_id) {
                    continue;
                }
                result.output = p->output;
                return result;
            }

            if (event.IsAbnormal()) {
                // timeout/exec-error 异常完成：executor_id 匹配才处理
                const auto* p = event.AsAbnormal();
                if (p == nullptr || p->ctx.executor_id != executor_id) {
                    continue;
                }
                result.output = p->output;
                if (p->kind == refuzz::core::channel_contract::AbnormalKind::kHang) {
                    result.timed_out = true;
                    result.crash_kind = CrashKind::kExecutionTimeout;
                } else if (p->kind == refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed ||
                           p->kind == refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled) {
                    result.error = true;
                    result.crashed = true;
                    result.crash_kind = CrashKind::kWorkerDead;
                    result.crash_title = SynthesizeCrashTitleFromAbnormal(p->kind);
                } else {
                    result.error = true;
                    result.crash_kind = CrashKind::kExecError;
                    result.crash_title = SynthesizeCrashTitleFromAbnormal(p->kind);
                }
                return result;
            }

            if (event.IsFault()) {
                const auto* fault = event.AsFault();
                if (fault == nullptr) {
                    continue;
                }
                result.crash_kind = CrashKindFromFaultKind(fault->kind);
                result.crashed = result.crash_kind == CrashKind::kKernelCrash ||
                                 result.crash_kind == CrashKind::kWorkerDead ||
                                 result.crash_kind == CrashKind::kVmDead;
                if (!fault->scene.console.title.empty() ||
                    !fault->scene.console.console_output.empty()) {
                    result.crash_title = fault->scene.console.title;
                    result.console_output = fault->scene.console.console_output;
                    result.crash_type = fault->scene.console.type;
                    result.crashed = true;
                }
                if (result.crashed && result.crash_title.empty()) {
                    result.crash_title = "exec-crash";
                }
                result.error = true;
                return result;
            }
        }
    }
}

bool ReproChannel::RestartBetweenRuns()
{
    return EnsureReady();
}

bool ReproChannel::EnsureReady()
{
    // [v1 old lease probing ROLLBACK]
    // 旧逻辑通过 AcquireLease/ReleaseLease 直接探测 slot 可用性。

    // [v2 new snapshot probing 当前版本]
    // 新逻辑仅基于 channel 状态判断可用性，不触发 lease/slot 语义。
    if (channel_ == nullptr || StopRequested()) {
        return false;
    }
    const auto observe = channel_->ObserveSnapshot();
    return observe.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kRunning ||
           observe.lifecycle_state == refuzz::core::channel_contract::ChannelLifecycleState::kRecovering;
}

} // namespace refuzz::crash
