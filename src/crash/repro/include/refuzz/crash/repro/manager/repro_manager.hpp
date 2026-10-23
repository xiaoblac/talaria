#pragma once

#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/repro/core/exec_adapter.hpp"
#include "refuzz/crash/repro/core/repro_config.hpp"
#include "refuzz/crash/repro/core/repro_engine.hpp"
#include "refuzz/crash/repro/core/repro_types.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"

#include <atomic>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::crash {

class KernelReproEngine;

namespace detail {

// Epic 4 PR-4-D B1 — apply MinimizeResult to ReproResult, including
// the new minimize-artifact propagation rule:
//
//   * Always copies minimize_attempts / minimize_commits /
//     minimize_stage from the MinimizeResult (those are reported
//     regardless of success).
//   * On success: replaces minimized_payload + original/minimized
//     call counts.
//   * On success AND minimize_result.artifact is a valid typed
//     handle: re-points result.selected_artifact at that handle so
//     downstream stages (StageProduceCSource, future smash/mut)
//     see the minimized typed authority. If the engine returned no
//     artifact (e.g., bytes-only minimize path), selected_artifact
//     stays at whatever StageExtract pointed it at — that's the
//     correct fallback per Epic 4 plan §3 "ReproManager wiring".
void ApplyMinimizeResult(MinimizeResult&& minimize_result,
                         ReproResult& result);

} // namespace detail

class ReproManager {
public:
    explicit ReproManager(IReproEngine* engine, IExecAdapter& exec_ops);
    ReproResult Run(const CrashContext& ctx);
    void RequestStop();

    bool SwitchPolicyByName(std::string_view name);
    bool MaybeApplyPendingSwitch();

    // Epic 4 PR-4-D — opt-in C reproducer config.
    void SetReproConfig(ReproConfig cfg);

    // Epic 4 PR-4-D — exposed for `crash_repro_csource_stage_test` case
    // (e): asserts `cfg.produce_c_reproducer == false` keeps the plan
    // free of `kProduceCSource` (PR-4-A regression net), and the flip
    // adds the stage post-Reliability.
    ReproPlan BuildPlanForCurrentConfig() const;

private:
    bool StopRequested() const;
    void SetupFromContext(const CrashContext& ctx);
    bool DispatchReproStage(ReproStageOp op, const CrashContext& ctx, ReproResult& result);
    bool StageExtract(const CrashContext& ctx, ReproResult& result,
                      const ExtractParams& ep, const VerdictParams& vp);
    bool StageMinimize(ReproResult& result, const MinimizeParams& mp);
    bool StageReliability(ReproResult& result, const ReliabilityParams& rp,
                          const VerdictParams& vp);
    bool StageSymbolize(const CrashContext& ctx, ReproResult& result);
    bool TryPayload(const std::vector<uint8_t>& payload,
                    const VerdictParams& vp, ReproResult& result);
    static size_t FindNextOp(const ReproPlan& plan, size_t from, ReproStageOp target);
    void SetAborted(ReproResult& result) const;
    // [repro modular seam] Returns the engine via the IReproEngine interface — the
    // manager is target-agnostic (KernelReproEngine for Linux/syz, XiuosReproEngine
    // for XiUOS wire programs). No concrete-type dynamic_cast.
    IReproEngine* CurrentEngine() const;

    IReproEngine* engine_;
    IExecAdapter& exec_ops_;
    std::unordered_map<std::string, int> policy_name_index_;
    std::atomic<int> next_policy_idx_{0};
    int policy_idx_ = 0;
    ReproConfig cfg_{};

    uint64_t next_exec_id_ = 0xA0000000ULL;
    std::atomic<bool> stop_requested_{false};
    std::string target_title_;
    std::unordered_set<std::string> observed_titles_;
    CrashKind crash_kind_ = CrashKind::kUnknownIncident;
    std::vector<std::string> alt_titles_;
};

} // namespace refuzz::crash
