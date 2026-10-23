#pragma once

// NoopRecovery — IRecovery 的空实现（v3.5 Phase G）
//
// 供 MockAssembler 使用：ObserveFault 始终返回 kNone，Execute 返回空结果。
// 设计来源：docs/channel-redesign/v3.5/160_phase_G_health_recovery.md §G.6

#include "refuzz/channel/recovery/recovery_contract.hpp"

namespace refuzz::channel::recovery {

class NoopRecovery final : public IRecovery {
public:
    RecoveryObservationResult ObserveFault(
        uint64_t, cc::ChannelFaultReason,
        cc::ChannelFaultSource, const FaultContext&) override
    {
        RecoveryObservationResult r;
        r.recovery_action = cc::RecoveryAction::kNone;
        return r;
    }

    Result<RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason, cc::RecoveryAction, uint32_t) override
    {
        return Result<RecoveryResult>::Ok(RecoveryResult{});
    }

    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override {
        return true;
    }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}

    void NoteHealthy() override {}

    RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}
};

} // namespace refuzz::channel::recovery
