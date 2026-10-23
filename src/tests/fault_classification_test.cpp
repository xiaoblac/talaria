#include "refuzz/feedback/aggregator/coverage_guided_aggregator.hpp"
#include "refuzz/feedback/signal/fault_signal.hpp"

#include <cassert>

namespace cc = refuzz::core::channel_contract;

cc::ChannelEvent MakeAbnormal(cc::AbnormalKind kind)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kAbnormal;
    cc::AbnormalCompletion ab{};
    ab.kind = kind;
    ab.ctx.executor_id = 7;
    ab.ctx.seed_id = 11;
    ev.payload = std::move(ab);
    return ev;
}

cc::ChannelEvent MakeFault(cc::FaultKind kind)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kFault;
    cc::Fault fault{};
    fault.kind = kind;
    fault.incident_id = 123;
    cc::ChannelTaskSnapshot task{};
    task.executor_id = 9;
    task.seed_id = 12;
    fault.scene.candidate_window.push_back(std::move(task));
    ev.payload = std::move(fault);
    return ev;
}

int main()
{
    refuzz::fuzzer::FaultSignal signal;
    refuzz::fuzzer::CoverageGuidedAggregator aggregator;

    // [v1 abnormal timeout/exec_error 不应有 crash_payload — ROLLBACK: revert]
    // auto timeout = signal.Sample(MakeAbnormal(cc::AbnormalKind::kHang));
    // assert(timeout.exec_code == refuzz::proto::ResultCode::kTimeout);
    // assert(!timeout.crash_payload.has_value());
    // ...
    // auto exec_error = signal.Sample(MakeAbnormal(cc::AbnormalKind::kExecError));
    // assert(exec_error.exec_code == refuzz::proto::ResultCode::kExecError);
    // assert(!exec_error.crash_payload.has_value());
    // [v2 PR-E timeout/exec_error 也要带 crash_payload 进 pipeline 落盘 — 当前版本]
    // 行为变化: PR-E 把 abnormal 非 kCrashed (kTimeout / kExecError / kChildAborted /
    // kWorkerSignaled) 都改成构造 crash_payload,让 BuildContextOp 第二分支按
    // result.result_code 分流到 exec_timeout / exec_error / worker_dead bucket。
    // 之前只有 kCrashed 进 pipeline,导致 exec_timeout / exec_error bucket 永远空。
    // is_crash 仍由 aggregator 仅看 exec_code == kCrashed 决定,timeout/exec_error
    // 不污染 corpus 决策。
    auto timeout = signal.Sample(MakeAbnormal(cc::AbnormalKind::kHang));
    assert(timeout.exec_code == refuzz::proto::ResultCode::kTimeout);
    assert(timeout.crash_payload.has_value());
    auto timeout_score = aggregator.Aggregate(MakeAbnormal(cc::AbnormalKind::kHang),
                                              std::span<const refuzz::fuzzer::SignalContribution>(&timeout, 1));
    assert(!timeout_score.is_crash);

    auto exec_error = signal.Sample(MakeAbnormal(cc::AbnormalKind::kInfraFault));
    assert(exec_error.exec_code == refuzz::proto::ResultCode::kExecError);
    assert(exec_error.crash_payload.has_value());
    auto exec_error_score = aggregator.Aggregate(MakeAbnormal(cc::AbnormalKind::kInfraFault),
                                                 std::span<const refuzz::fuzzer::SignalContribution>(&exec_error, 1));
    assert(!exec_error_score.is_crash);

    // [v2 PR-E kCancelled 是 host 主动取消,不应进 pipeline — 当前版本]
    // 单独 case:验证只有 kCancelled 不带 crash_payload。
    auto cancelled = signal.Sample(MakeAbnormal(cc::AbnormalKind::kCancelled));
    assert(cancelled.exec_code == refuzz::proto::ResultCode::kExecError);
    assert(!cancelled.crash_payload.has_value());
    auto cancelled_score = aggregator.Aggregate(MakeAbnormal(cc::AbnormalKind::kCancelled),
                                                std::span<const refuzz::fuzzer::SignalContribution>(&cancelled, 1));
    assert(!cancelled_score.is_crash);

    // [v1 vm_dead 不应有 crash_payload — ROLLBACK: revert assertions]
    // auto vm_dead = signal.Sample(MakeFault(cc::FaultKind::kVmDead));
    // assert(vm_dead.exec_code == refuzz::proto::ResultCode::kExecError);
    // assert(!vm_dead.crash_payload.has_value());
    // auto vm_dead_score = aggregator.Aggregate(MakeFault(cc::FaultKind::kVmDead),
    //                                           std::span<const refuzz::fuzzer::SignalContribution>(&vm_dead, 1));
    // assert(!vm_dead_score.is_crash);
    // [v2 PR-C vm_dead 也要带 crash_payload 进 pipeline 落盘 — 当前版本]
    // 行为变化: PR-C 让所有 fault kind 都构造 crash_payload,vm_dead 也能落盘到
    // diagnostics/vm_dead bucket。但 aggregator(PR-C 解耦后)只看 exec_code==kCrashed
    // 决定 is_crash,所以 vm_dead 仍然 is_crash=false(infra-fault 不污染 corpus 决策)。
    auto vm_dead = signal.Sample(MakeFault(cc::FaultKind::kVmDead));
    assert(vm_dead.exec_code == refuzz::proto::ResultCode::kExecError);
    assert(vm_dead.crash_payload.has_value());
    auto vm_dead_score = aggregator.Aggregate(MakeFault(cc::FaultKind::kVmDead),
                                              std::span<const refuzz::fuzzer::SignalContribution>(&vm_dead, 1));
    assert(!vm_dead_score.is_crash);

    auto kernel_crash = signal.Sample(MakeFault(cc::FaultKind::kKernelCrash));
    assert(kernel_crash.exec_code == refuzz::proto::ResultCode::kCrashed);
    assert(kernel_crash.crash_payload.has_value());
    auto crash_score = aggregator.Aggregate(MakeFault(cc::FaultKind::kKernelCrash),
                                            std::span<const refuzz::fuzzer::SignalContribution>(&kernel_crash, 1));
    assert(crash_score.is_crash);
    assert(crash_score.crash_payload.has_value());

    auto no_output = signal.Sample(MakeFault(cc::FaultKind::kNoOutput));
    assert(no_output.exec_code == refuzz::proto::ResultCode::kCrashed);
    assert(no_output.crash_payload.has_value());
    assert(no_output.crash_payload->fault_event.has_value());
    assert(no_output.crash_payload->fault_event->reason ==
           refuzz::proto::FaultReason::kNoOutput);
    auto no_output_score = aggregator.Aggregate(
        MakeFault(cc::FaultKind::kNoOutput),
        std::span<const refuzz::fuzzer::SignalContribution>(&no_output, 1));
    assert(no_output_score.is_crash);
    assert(no_output_score.crash_payload.has_value());

    return 0;
}
