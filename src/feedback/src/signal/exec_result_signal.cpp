// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/exec_result_signal.hpp"

namespace refuzz::fuzzer {

namespace {


// [v2 +kChildAborted — 当前版本]
// kChildAborted 是 program 行为致 child 没按协议返回 — 不应升级为 kCrashed。
// 视作 execution-level error（与 syzkaller `non-kFailStatus → reply_execute(0)` 语义对齐）。
proto::ResultCode MapAbnormalToResultCode(refuzz::core::channel_contract::AbnormalKind kind)
{
    // 注:proto::ResultCode 的粒度比 AbnormalKind 粗(没有 no_result/infra/unknown
    // 的独立值),这是一次刻意的降级投影 —— 精确分类留在 AbnormalKind 层,这里只把它
    // 折成 feedback 关心的 kTimeout/kCrashed/kExecError 三档。
    switch (kind) {
    case refuzz::core::channel_contract::AbnormalKind::kHang:
        return proto::ResultCode::kTimeout;
    case refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed:
    case refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled:
        return proto::ResultCode::kCrashed;
    case refuzz::core::channel_contract::AbnormalKind::kNoResult:
    case refuzz::core::channel_contract::AbnormalKind::kCancelled:
    case refuzz::core::channel_contract::AbnormalKind::kChildAborted:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessRecovered:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessFatal:
    case refuzz::core::channel_contract::AbnormalKind::kInfraFault:
    case refuzz::core::channel_contract::AbnormalKind::kUnknown:
        return proto::ResultCode::kExecError;
    }
    return proto::ResultCode::kExecError;
}

} // namespace

SignalContribution ExecResultSignal::Sample(const refuzz::core::channel_contract::ChannelEvent& event)
{
    SignalContribution c;
    c.id   = Id();
    c.kind = Kind();

    if (event.IsCompletion()) {
        c.fired     = true;
        c.exec_code = proto::ResultCode::kOk;
    } else if (event.IsAbnormal()) {
        c.fired = true;
        const auto* abnormal = event.AsAbnormal();
        c.exec_code = abnormal != nullptr
            ? MapAbnormalToResultCode(abnormal->kind)
            : proto::ResultCode::kExecError;
    } else if (event.IsFault()) {
        c.fired     = true;
        // [v1 所有 Fault → kCrashed — ROLLBACK: revert to unconditional kCrashed]
        // c.exec_code = proto::ResultCode::kCrashed;
        // [v2 PR-E 按 FaultKind 区分 — 当前版本]
        // 旧版本对所有 fault 统一返回 kCrashed,跟 PR-C 把 vm_dead/worker_dead 解耦
        // 出 is_crash 的方向矛盾(real engine 同时跑 ExecResultSignal + FaultSignal,
        // 这里设 kCrashed 会让 aggregator 在 ExecResult 信号里就把 score.is_crash 拉
        // 起来,污染 corpus 决策)。改为按 FaultKind 分:
        //   kKernelCrash → kCrashed (program 行为致 kernel crash,真 crash)
        //   kVmDead/kWorkerDead → kExecError (infra-fault,不归 program 错)
        const auto* fault = event.AsFault();
        if (fault != nullptr &&
            (fault->kind == refuzz::core::channel_contract::FaultKind::kKernelCrash ||
             fault->kind == refuzz::core::channel_contract::FaultKind::kNoOutput)) {
            c.exec_code = proto::ResultCode::kCrashed;
        } else {
            c.exec_code = proto::ResultCode::kExecError;
        }
    }

    c.decoded.exec_status = c.exec_code;
    return c;
}

} // namespace refuzz::fuzzer
