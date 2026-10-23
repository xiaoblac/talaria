#pragma once

// SnapshotRecovery — IRecovery for the snapshot channel backend.
//
// On any fault (kernel crash detected by ConsoleSensor, or VM-liveness), it does
// NOT reboot the VM — a reboot would re-create the qcow2 overlay and destroy the
// savevm S0. Instead it returns the snapshot-accurate action `kReloadSnapshot`:
// ExecuteRecovery releases the in-flight executor(s) + ResetAll the data plane
// (which clears SnapshotDataPlane's 1-in-flight gate), and the KERNEL is restored
// by the next program's `loadvm S0` (the SnapshotDataPlane Submit cycle). Mirrors
// syzkaller snapshot's "loadvm is the recovery" model.
//
// The Channel::HandleFault generic recovery loop drives this: it emits the Fault
// (→ CrashPipeline) + on success emits AbnormalCompletion for the returned
// inflight ids + resumes the data plane — no kRebootVm special-casing applies.

#include "refuzz/channel/recovery/recovery_contract.hpp"
#include "refuzz/channel/data/data_plane.hpp"

namespace refuzz::channel::recovery {

class SnapshotRecovery final : public IRecovery {
public:
    explicit SnapshotRecovery(data::IDataPlane* data_plane) noexcept
        : dp_(data_plane) {}

    RecoveryObservationResult ObserveFault(
        uint64_t, cc::ChannelFaultReason,
        cc::ChannelFaultSource, const FaultContext&) override
    {
        RecoveryObservationResult r;
        r.accepted        = true;
        r.recovery_action = cc::RecoveryAction::kReloadSnapshot;
        // abort_scope left kNone: the crashed in-flight is released by
        // ExecuteRecovery (returned as inflight_executor_ids → AbnormalCompletion),
        // not by scope-based AbortPendingByScope, to avoid double emission.
        return r;
    }

    Result<RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason, cc::RecoveryAction action, uint32_t) override
    {
        RecoveryResult res;
        res.action = action;
        if (dp_ != nullptr) {
            for (const auto& e : dp_->SnapshotInflight())
                res.inflight_executor_ids.push_back(e.executor_id);
            // Clears the inner ivshmem inflight + SnapshotDataPlane's busy_ gate.
            // No VM op here: the next Submit's loadvm S0 restores the clean kernel.
            dp_->ResetAll();
        }
        return Result<RecoveryResult>::Ok(std::move(res));
    }

    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override { return true; }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}
    void NoteHealthy() override {}
    RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}

private:
    data::IDataPlane* dp_;
};

} // namespace refuzz::channel::recovery
