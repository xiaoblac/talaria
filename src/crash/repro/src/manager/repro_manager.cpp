#include "refuzz/crash/repro/manager/repro_manager.hpp"

#include "refuzz/crash/repro/engine/linuxkernel/syz_engine/syz_repro_engine.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/csource/produce_csource_stage.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/program/program_concat.hpp"

#include "refuzz/program/artifact.hpp"     // ProgramArtifact::As<Prog>
#include "refuzz/program/syz/prog.hpp"      // syz::Prog (CollectTypedProgs)

#include <memory>
#include <vector>

namespace refuzz::crash {

namespace {

namespace syzv2 = ::refuzz::program::syz;

// ConcatTypedPrograms (typed V2-IR concat) lives in program_concat.{hpp,cpp} so it
// is unit-testable; this file only collects the typed Progs and drives bisect.

// Collect program_log entries' typed Progs (time order), skipping entries with no
// typed view. Drives the typed bisect/concat extract path.
std::vector<std::shared_ptr<const syzv2::Prog>> CollectTypedProgs(
    const CrashContext& ctx)
{
    std::vector<std::shared_ptr<const syzv2::Prog>> progs;
    progs.reserve(ctx.program_log.size());
    for (const auto& entry : ctx.program_log) {
        if (!entry.artifact) continue;
        auto prog = entry.artifact->As<syzv2::Prog>();
        if (prog) progs.push_back(std::move(prog));
    }
    return progs;
}

enum class BuiltinReproPolicy : int {
    kFull = 0,
    kFastTriage = 1,
    kDeep = 2,
};

bool RunRequiresRecovery(const RunResult& result)
{
    if (result.recovered_in_execute) {
        return false;
    }
    return result.crashed || result.timed_out || result.error;
}

ReproPlan BuildPlan(BuiltinReproPolicy policy, const ReproConfig& cfg)
{
    ReproPlan plan;
    switch (policy) {
    case BuiltinReproPolicy::kFastTriage:
        plan = {
            {ReproStageOp::kExtract},
            {ReproStageOp::kReliability},
            {ReproStageOp::kSymbolize},
        };
        break;
    case BuiltinReproPolicy::kFull:
    case BuiltinReproPolicy::kDeep:
        plan = {
            {ReproStageOp::kExtract},
            {ReproStageOp::kMinimize},
            {ReproStageOp::kReliability},
            {ReproStageOp::kSymbolize},
        };
        break;
    }
    // Epic 4 PR-4-D — opt-in C reproducer stage. Appended AFTER
    // Reliability/Symbolize so the plan reaches kProduceCSource only
    // when reliability passed (a non-reproducible repro short-circuits
    // the stage loop before it gets here). PR-4-A's null-config
    // behavior — never appending — is preserved when
    // cfg.produce_c_reproducer == false.
    if (cfg.produce_c_reproducer) {
        plan.push_back({ReproStageOp::kProduceCSource});
    }
    return plan;
}

ExtractParams ExtractConfig(BuiltinReproPolicy policy)
{
    ExtractParams params;
    switch (policy) {
    case BuiltinReproPolicy::kFastTriage:
        params.try_history_scan = false;
        params.try_bisect = false;
        params.try_concat = false;
        params.attempts_per_strategy = 1;
        break;
    case BuiltinReproPolicy::kDeep:
        params.attempts_per_strategy = 5;
        break;
    case BuiltinReproPolicy::kFull:
        break;
    }
    return params;
}

MinimizeParams MinimizeConfig(BuiltinReproPolicy, const ReproResult&)
{
    return {};
}

ReliabilityParams ReliabilityConfig(BuiltinReproPolicy policy, const ReproResult&)
{
    ReliabilityParams params;
    switch (policy) {
    case BuiltinReproPolicy::kFastTriage:
        params.runs = 3;
        params.early_exit = 1;
        params.threshold = 0.0;
        break;
    case BuiltinReproPolicy::kDeep:
        // [async-crash-reproduction Phase 2] race-friendly: many runs + a lenient
        // gate so a low-probability async race (e.g. the USB connect/disconnect
        // ath9k UAF) that reproduces even ~1/20 still passes reliability and
        // reaches the symbolize + C-reproducer stages, instead of being dropped as
        // "below threshold". The extract already proved it's a real repro.
        params.runs = 20;
        params.early_exit = 5;
        params.threshold = 0.05;
        break;
    case BuiltinReproPolicy::kFull:
        break;
    }
    return params;
}

VerdictParams VerdictConfig(BuiltinReproPolicy)
{
    return {};
}

NextAction OnStageComplete(BuiltinReproPolicy, ReproStageOp, const CrashContext&, const ReproResult&)
{
    return NextAction::kContinue;
}

} // namespace

ReproManager::ReproManager(IReproEngine* engine, IExecAdapter& exec_ops)
    : engine_(engine)
    , exec_ops_(exec_ops)
{
    policy_name_index_["full"] = static_cast<int>(BuiltinReproPolicy::kFull);
    policy_name_index_["fast_triage"] = static_cast<int>(BuiltinReproPolicy::kFastTriage);
    policy_name_index_["deep"] = static_cast<int>(BuiltinReproPolicy::kDeep);
}

bool ReproManager::SwitchPolicyByName(std::string_view name)
{
    auto it = policy_name_index_.find(std::string(name));
    if (it == policy_name_index_.end()) {
        return false;
    }
    next_policy_idx_.store(it->second, std::memory_order_release);
    return true;
}

bool ReproManager::MaybeApplyPendingSwitch()
{
    const int next = next_policy_idx_.load(std::memory_order_acquire);
    if (next == policy_idx_) {
        return false;
    }
    policy_idx_ = next;
    return true;
}

void ReproManager::RequestStop()
{
    stop_requested_.store(true, std::memory_order_release);
    exec_ops_.RequestStop();
}

bool ReproManager::StopRequested() const
{
    return stop_requested_.load(std::memory_order_acquire);
}

IReproEngine* ReproManager::CurrentEngine() const
{
    return engine_;
}

void ReproManager::SetupFromContext(const CrashContext& ctx)
{
    target_title_ = ctx.title;
    crash_kind_ = ctx.crash_kind;
    alt_titles_ = ctx.alt_titles;
    observed_titles_.clear();
    if (!ctx.title.empty()) {
        observed_titles_.insert(ctx.title);
    }
}

ReproResult ReproManager::Run(const CrashContext& ctx)
{
    MaybeApplyPendingSwitch();
    SetupFromContext(ctx);

    ReproResult result;
    result.incident_id = ctx.incident_id;
    result.crash_title = ctx.title;
    result.program_log_count = static_cast<uint32_t>(ctx.program_log.size());

    if (CurrentEngine() == nullptr) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kReproduceFailed;
        result.completed_at = std::chrono::system_clock::now();
        return result;
    }

    if (StopRequested()) {
        result.completion = ReproCompletionStatus::kInterrupted;
        result.completion_reason = ReproCompletionReason::kStopRequested;
        result.completed_at = std::chrono::system_clock::now();
        return result;
    }

    const auto policy = static_cast<BuiltinReproPolicy>(policy_idx_);
    const auto plan = BuildPlan(policy, cfg_);
    for (size_t i = 0; i < plan.size() && !StopRequested(); ++i) {
        const bool ok = DispatchReproStage(plan[i].op, ctx, result);
        if (!ok) {
            result.completed_at = std::chrono::system_clock::now();
            return result;
        }
        const auto action = OnStageComplete(policy, plan[i].op, ctx, result);
        if (action == NextAction::kAbort) {
            SetAborted(result);
            result.completed_at = std::chrono::system_clock::now();
            return result;
        }
        if (action == NextAction::kSkipToReliability) {
            const size_t j = FindNextOp(plan, i + 1, ReproStageOp::kReliability);
            i = (j < plan.size()) ? j - 1 : plan.size() - 1;
        } else if (action == NextAction::kSkipToSymbolize) {
            const size_t j = FindNextOp(plan, i + 1, ReproStageOp::kSymbolize);
            i = (j < plan.size()) ? j - 1 : plan.size() - 1;
        }
    }

    if (StopRequested()) {
        result.completion = ReproCompletionStatus::kInterrupted;
        result.completion_reason = ReproCompletionReason::kStopRequested;
        result.completed_at = std::chrono::system_clock::now();
        return result;
    }

    result.completion = ReproCompletionStatus::kCompleted;
    result.completion_reason = ReproCompletionReason::kNone;
    result.completed_at = std::chrono::system_clock::now();
    return result;
}

bool ReproManager::DispatchReproStage(ReproStageOp op, const CrashContext& ctx, ReproResult& result)
{
    const auto policy = static_cast<BuiltinReproPolicy>(policy_idx_);
    switch (op) {
    case ReproStageOp::kExtract:
        return StageExtract(ctx, result, ExtractConfig(policy), VerdictConfig(policy));
    case ReproStageOp::kMinimize:
        return StageMinimize(result, MinimizeConfig(policy, result));
    case ReproStageOp::kReliability:
        return StageReliability(result, ReliabilityConfig(policy, result), VerdictConfig(policy));
    case ReproStageOp::kSymbolize:
        return StageSymbolize(ctx, result);
    case ReproStageOp::kProduceCSource:
        // Epic 4 PR-4-D — wired to the StageProduceCSource free
        // function. BuildPlan only appends this op when
        // cfg_.produce_c_reproducer is true; the arm is reachable
        // only via that path.
        return repro::syz_ops::csource::ProduceCSourceStage(result, cfg_);
    }
    return true;
}

void ReproManager::SetReproConfig(ReproConfig cfg)
{
    cfg_ = std::move(cfg);
}

ReproPlan ReproManager::BuildPlanForCurrentConfig() const
{
    return BuildPlan(static_cast<BuiltinReproPolicy>(policy_idx_), cfg_);
}

bool ReproManager::StageExtract(const CrashContext& ctx, ReproResult& result,
                                const ExtractParams& ep, const VerdictParams& vp)
{
    if (ep.try_crash_program &&
        ctx.crash_program_index >= 0 &&
        ctx.crash_program_index < static_cast<int32_t>(ctx.program_log.size())) {
        const auto& entry = ctx.program_log[ctx.crash_program_index];
        if (!entry.payload.empty()) {
            for (uint32_t a = 0; a < ep.attempts_per_strategy; ++a) {
                if (StopRequested()) {
                    result.completion = ReproCompletionStatus::kInterrupted;
                    result.completion_reason = ReproCompletionReason::kStopRequested;
                    return false;
                }
                if (TryPayload(entry.payload, vp, result)) {
                    result.reproduced = true;
                    result.extract_source = "original";
                    result.minimized_payload = entry.payload;
                    result.original_call_count = CountCalls(entry.payload);
                    result.minimized_call_count = result.original_call_count;
                    result.last_completed_stage = ReproStage::kExtract;
                    // post-V1-retirement B-5: "original" 路径下，重现的 bytes 来自
                    // crash_program_index 对应的 entry，其 typed authority 就是
                    // ctx.origin_artifact（BuildContextOp 注入）。把它挂到
                    // ReproResult.selected_artifact，StageMinimize 直接 minimize 它。
                    result.selected_artifact = ctx.origin_artifact;
                    return true;
                }
            }
        }
    }

    if (ep.try_history_scan) {
        for (int32_t i = static_cast<int32_t>(ctx.program_log.size()) - 1; i >= 0; --i) {
            if (i == ctx.crash_program_index) {
                continue;
            }
            if (StopRequested()) {
                result.completion = ReproCompletionStatus::kInterrupted;
                result.completion_reason = ReproCompletionReason::kStopRequested;
                return false;
            }
            const auto& entry = ctx.program_log[i];
            if (entry.payload.empty()) {
                continue;
            }
            for (uint32_t a = 0; a < ep.attempts_per_strategy; ++a) {
                if (TryPayload(entry.payload, vp, result)) {
                    result.reproduced = true;
                    result.extract_source = "history_" + std::to_string(i);
                    result.minimized_payload = entry.payload;
                    result.original_call_count = CountCalls(entry.payload);
                    result.minimized_call_count = result.original_call_count;
                    // [async-crash-reproduction Phase 1] the history entry now
                    // carries its typed view (channeldispatcher recent-artifacts
                    // ring → program_log). Hand it to StageMinimize so a history
                    // extract is minimized + C-reproducible (no longer fail-closed).
                    result.selected_artifact = entry.artifact;
                    result.last_completed_stage = ReproStage::kExtract;
                    return true;
                }
            }
        }
    }

    if ((ep.try_bisect || ep.try_concat) && ctx.program_log.size() >= 2) {
        // [async-crash-reproduction Phase 1.5] typed bisect/concat. The V2
        // exec-wire can't be byte-concatenated; the merge happens on the typed IR
        // carried by each entry's artifact (Phase 1). Each candidate concat yields
        // both an exec-wire payload (for TryPayload) AND a typed ProgramArtifact
        // (for StageMinimize / C-repro) — so a multi-program async reproduction
        // (e.g. connect … disconnect) is minimizable, not just runnable.
        auto all_progs = CollectTypedProgs(ctx);
        if (all_progs.size() >= 2) {
            ConcatTypedResult full;
            if (ep.try_bisect && ConcatTypedPrograms(all_progs, full) &&
                TryPayload(full.payload, vp, result)) {
                size_t lo = 1;
                size_t hi = all_progs.size();
                while (lo < hi && !StopRequested()) {
                    const size_t mid = (lo + hi) / 2;
                    std::vector<std::shared_ptr<const syzv2::Prog>> prefix(
                        all_progs.begin(), all_progs.begin() + static_cast<long>(mid));
                    ConcatTypedResult pc;
                    if (ConcatTypedPrograms(prefix, pc) &&
                        TryPayload(pc.payload, vp, result)) {
                        hi = mid;
                    } else {
                        lo = mid + 1;
                    }
                }
                std::vector<std::shared_ptr<const syzv2::Prog>> final_set(
                    all_progs.begin(), all_progs.begin() + static_cast<long>(hi));
                ConcatTypedResult bisected;
                if (ConcatTypedPrograms(final_set, bisected)) {
                    result.reproduced = true;
                    result.extract_source = "bisect";
                    result.minimized_payload = std::move(bisected.payload);
                    result.original_call_count = bisected.call_count;
                    result.minimized_call_count = bisected.call_count;
                    // [Phase 1.5] merged typed view → minimize + C-repro enabled.
                    result.selected_artifact = std::move(bisected.artifact);
                    result.last_completed_stage = ReproStage::kExtract;
                    return true;
                }
            }

            if (ep.try_concat) {
                ConcatTypedResult concat_res;
                if (ConcatTypedPrograms(all_progs, concat_res) &&
                    TryPayload(concat_res.payload, vp, result)) {
                    result.reproduced = true;
                    result.extract_source = "concat";
                    result.minimized_payload = std::move(concat_res.payload);
                    result.original_call_count = concat_res.call_count;
                    result.minimized_call_count = concat_res.call_count;
                    result.selected_artifact = std::move(concat_res.artifact);
                    result.last_completed_stage = ReproStage::kExtract;
                    return true;
                }
            }
        }
    }

    result.completion = ReproCompletionStatus::kFailed;
    result.completion_reason = ReproCompletionReason::kExtractFailed;
    return false;
}

bool ReproManager::StageMinimize(ReproResult& result, const MinimizeParams& mp)
{
    auto* engine = CurrentEngine();
    if (engine == nullptr) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kReproduceFailed;
        return false;
    }
    if (StopRequested()) {
        result.completion = ReproCompletionStatus::kInterrupted;
        result.completion_reason = ReproCompletionReason::kStopRequested;
        return false;
    }
    if (!exec_ops_.EnsureReady()) {
        if (StopRequested()) {
            result.completion = ReproCompletionStatus::kInterrupted;
            result.completion_reason = ReproCompletionReason::kStopRequested;
        } else {
            result.completion = ReproCompletionStatus::kFailed;
            result.completion_reason = ReproCompletionReason::kChannelNotReady;
        }
        return false;
    }

    bool recovery_needed = false;
    const uint32_t retries = mp.test_retries;
    auto test_fn = [this, engine, retries, &recovery_needed](const std::vector<uint8_t>& payload)
        -> std::pair<bool, std::string>
    {
        for (uint32_t r = 0; r < retries; ++r) {
            if (StopRequested()) {
                return {false, {}};
            }
            if (recovery_needed && !exec_ops_.RestartBetweenRuns()) {
                return {false, {}};
            }
            auto run = exec_ops_.Execute(payload, next_exec_id_++);
            recovery_needed = RunRequiresRecovery(run);
            // Syzkaller's minimize callback uses the non-strict verdict: a
            // candidate is accepted based on the complete parsed report and
            // observed-title policy, not a second single-title comparison in
            // the minimizer adapter.
            if (engine->MatchVerdict(run, VerdictParams{}, false,
                                     target_title_, observed_titles_,
                                     alt_titles_, crash_kind_)) {
                for (const std::string& title : engine->ExtractCrashTitles(run)) {
                    observed_titles_.insert(title);
                }
                return {true, {}};
            }
        }
        return {false, {}};
    };

    // post-V1-retirement B-5 (review finding #3) — typed artifact entry.
    //   Minimize the artifact StageExtract actually reproduced
    //   (`result.selected_artifact`), NOT `ctx.origin_artifact`. They diverge
    //   when extract took history/bisect/concat paths: ctx.origin_artifact
    //   would represent the original crash_program (which didn't reproduce
    //   here), so minimizing it would emit unrelated minimized bytes.
    //   selected_artifact is null when extract used a non-original path
    //   (history entries don't yet carry typed views); in that case fail
    //   closed — we don't have the right typed view to minimize.
    //   Oracle #21 verifies no text-codec calls on the typed minimize path.
    // Linux/syz minimizes the typed artifact and fails closed when extract took a
    // history/bisect/concat path (no typed view); preserve that. Bytes-only targets
    // (XiUOS) declare RequiresTypedArtifactForMinimize()==false and minimize the
    // exec-wire payload directly.
    const auto& selected = result.selected_artifact;
    if (engine->RequiresTypedArtifactForMinimize() &&
        (selected == nullptr || !selected->valid())) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kReproduceFailed;
        return false;
    }
    MinimizeResult minimize_result = engine->Minimize(
        result.minimized_payload, selected.get(), test_fn,
        [this]() { return StopRequested(); }, mp);
    detail::ApplyMinimizeResult(std::move(minimize_result), result);
    result.last_completed_stage = ReproStage::kMinimize;
    return true;
}

namespace detail {

void ApplyMinimizeResult(MinimizeResult&& minimize_result, ReproResult& result)
{
    result.minimize_attempts = minimize_result.minimize_attempts;
    result.minimize_commits  = minimize_result.minimize_commits;
    result.minimize_stage    = minimize_result.minimize_stage;
    if (!minimize_result.success) {
        return;
    }
    result.minimized_payload    = std::move(minimize_result.payload);
    result.original_call_count  = minimize_result.original_call_count;
    result.minimized_call_count = minimize_result.minimized_call_count;
    // Epic 4 PR-4-D B1 — propagate minimized typed authority so
    // StageProduceCSource (when enabled) emits .c against the
    // minimized prog rather than the pre-minimize one. When the
    // minimizer didn't return a typed view (artifact null/invalid),
    // selected_artifact stays at what StageExtract pointed it at;
    // that's the documented fallback per Epic 4 plan §3.
    if (minimize_result.artifact != nullptr &&
        minimize_result.artifact->valid()) {
        result.selected_artifact = std::move(minimize_result.artifact);
    }
}

} // namespace detail

bool ReproManager::StageReliability(ReproResult& result, const ReliabilityParams& rp,
                                    const VerdictParams& vp)
{
    auto* engine = CurrentEngine();
    if (engine == nullptr) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kReproduceFailed;
        return false;
    }
    if (StopRequested()) {
        result.completion = ReproCompletionStatus::kInterrupted;
        result.completion_reason = ReproCompletionReason::kStopRequested;
        return false;
    }
    if (!exec_ops_.EnsureReady()) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kChannelNotReady;
        return false;
    }

    const auto& payload = result.minimized_payload;
    uint32_t crash_count = 0;
    uint32_t total = 0;
    bool recovery_needed = false;

    for (uint32_t i = 0; i < rp.runs; ++i) {
        if (recovery_needed && !exec_ops_.RestartBetweenRuns()) {
            result.completion = ReproCompletionStatus::kFailed;
            result.completion_reason = ReproCompletionReason::kRecoveryFailed;
            return false;
        }
        auto run = exec_ops_.Execute(payload, next_exec_id_++);
        recovery_needed = RunRequiresRecovery(run);
        ++total;
        result.total_attempts++;
        if (engine->MatchVerdict(run, vp, true, target_title_, observed_titles_,
                                 alt_titles_, crash_kind_)) {
            ++crash_count;
            result.crash_attempts++;
        }
        if (crash_count >= rp.early_exit) {
            break;
        }
    }

    result.reliability = total > 0
        ? static_cast<double>(crash_count) / static_cast<double>(total)
        : 0.0;
    if (result.reliability < rp.threshold) {
        result.reproduced = false;
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason = ReproCompletionReason::kReliabilityBelowThreshold;
        return false;
    }
    result.last_completed_stage = ReproStage::kReliability;
    return true;
}

bool ReproManager::StageSymbolize(const CrashContext& ctx, ReproResult& result)
{
    auto* engine = CurrentEngine();
    if (engine == nullptr) {
        return false;
    }
    if (StopRequested()) {
        return false;
    }
    if (!exec_ops_.EnsureReady()) {
        return true;
    }
    auto run = exec_ops_.Execute(result.minimized_payload, next_exec_id_++);
    result.total_attempts++;
    if (run.crashed) {
        result.crash_attempts++;
    }
    const auto& console = !run.console_output.empty() ? run.console_output : ctx.console_log;
    const auto report_text = engine->ParseAndSymbolize(console);
    if (!report_text.empty()) {
        result.symbolized_report = report_text;
    }
    result.last_completed_stage = ReproStage::kSymbolize;
    return true;
}

bool ReproManager::TryPayload(const std::vector<uint8_t>& payload,
                              const VerdictParams& vp, ReproResult& result)
{
    auto* engine = CurrentEngine();
    if (engine == nullptr) {
        return false;
    }
    if (StopRequested() || !exec_ops_.EnsureReady()) {
        return false;
    }
    bool recovery_needed = false;
    auto run = exec_ops_.Execute(payload, next_exec_id_++);
    recovery_needed = RunRequiresRecovery(run);
    result.total_attempts++;

    if (run.error && !run.crashed && !run.timed_out) {
        uint32_t error_retries = 0;
        while (error_retries < vp.error_retries && !StopRequested()) {
            ++error_retries;
            if (!exec_ops_.RestartBetweenRuns()) {
                break;
            }
            run = exec_ops_.Execute(payload, next_exec_id_++);
            result.total_attempts++;
            recovery_needed = RunRequiresRecovery(run);
            if (!run.error || run.crashed || run.timed_out) {
                break;
            }
        }
        if (run.error && !run.crashed && !run.timed_out) {
            return false;
        }
    }

    if (engine->MatchVerdict(run, vp, false, target_title_, observed_titles_,
                             alt_titles_, crash_kind_)) {
        result.crash_attempts++;
        for (const std::string& title : engine->ExtractCrashTitles(run)) {
            observed_titles_.insert(title);
        }
        return true;
    }

    if (!run.crashed && recovery_needed) {
        (void)exec_ops_.RestartBetweenRuns();
    }
    return false;
}

size_t ReproManager::FindNextOp(const ReproPlan& plan, size_t from, ReproStageOp target)
{
    for (size_t i = from; i < plan.size(); ++i) {
        if (plan[i].op == target) {
            return i;
        }
    }
    return plan.size();
}

void ReproManager::SetAborted(ReproResult& result) const
{
    result.completion = ReproCompletionStatus::kFailed;
    result.completion_reason = ReproCompletionReason::kStopRequested;
}

} // namespace refuzz::crash
