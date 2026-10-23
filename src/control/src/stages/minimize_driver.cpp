// Phase 3 Step 3.4 — MinimizeDriver implementation.

#include "refuzz/control/stages/minimize_driver.hpp"

#include "refuzz/logging/host_logger.hpp"

#include <algorithm>
#include <iterator>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::control {

namespace {

bool ContainsAllTargetSignals(
    const std::vector<std::uint64_t>& target,
    const std::vector<std::uint8_t>&  target_prios,
    const std::unordered_map<std::uint64_t, std::uint8_t>& observed)
{
    if (target.empty()) {
        return false;
    }
    if (observed.empty()) {
        return false;
    }
    for (std::size_t i = 0; i < target.size(); ++i) {
        const auto it = observed.find(target[i]);
        const std::uint8_t required =
            i < target_prios.size() ? target_prios[i] : 0;
        if (it == observed.end() || it->second < required) {
            return false;
        }
    }
    return true;
}

enum class TargetSignalGateReason {
    kOk,
    kExecStatus,
    kCallOutOfRange,
    kSyscallMismatch,
    kErrnoRegression,
    kEmptySignal,
};

struct ObservedTargetSignalResult {
    std::optional<std::vector<std::uint64_t>> signal;
    std::uint8_t priority = 0;
    TargetSignalGateReason reason = TargetSignalGateReason::kOk;
};

// The target's observed signal in ONE re-exec snapshot (the guilty call's edge/PC
// signal, or the program-level signal when there is no guilty call), or nullopt if
// this run fails the per-run gate (wrong exec status / syscall shape / success→fail
// / empty signal). Mirrors syz reexecutionSuccess + getSignalAndCover(job.go): a
// run that fails the gate must not contribute signal to the multi-attempt merge.
ObservedTargetSignalResult ObservedTargetSignal(
    const MinimizeDriver::StartArgs&          args,
    const MinimizeDriver::ExecSignalSnapshot& snapshot,
    int                                       candidate_call_index)
{
    if (snapshot.exec_status != args.target_exec_status) {
        return {.reason = TargetSignalGateReason::kExecStatus};
    }
    if (args.guilty_call_index >= 0) {
        const int call_index = candidate_call_index >= 0
                             ? candidate_call_index
                             : args.guilty_call_index;
        if (call_index < 0 ||
            call_index >= static_cast<int>(snapshot.per_call.size())) {
            return {.reason = TargetSignalGateReason::kCallOutOfRange};
        }
        const auto& call = snapshot.per_call[static_cast<std::size_t>(call_index)];
        if (args.target_syscall_id.has_value() &&
            call.syscall_id != *args.target_syscall_id) {
            return {.reason = TargetSignalGateReason::kSyscallMismatch};
        }
        if (args.target_errno_value.has_value() &&
            *args.target_errno_value == 0 &&
            call.errno_value != 0) {
            return {.reason = TargetSignalGateReason::kErrnoRegression};
        }
        auto signal = args.target_is_edge_signal ? call.edge_hashes : call.coverage_hashes;
        if (signal.empty()) {
            return {.reason = TargetSignalGateReason::kEmptySignal};
        }
        return {.signal = std::move(signal),
                .priority = call.signal_priority,
                .reason = TargetSignalGateReason::kOk};
    }
    // [Extra/-1] guilty_call_index<0 ⇒ target is Info.Extra, not "no call in
    //   particular". Must observe snapshot.extra_signal_hashes alone — the
    //   whole-program signal_hashes union also contains every ordinary call's
    //   coverage, so using it here would let a reduction that actually broke
    //   the Extra trigger pass by coincidentally matching on unrelated
    //   per-call PCs (raw PC domain; async/interrupt code paths do overlap
    //   with regular syscall execution).
    if (snapshot.extra_signal_hashes.empty()) {
        return {.reason = TargetSignalGateReason::kEmptySignal};
    }
    return {.signal = snapshot.extra_signal_hashes,
            .priority = 0,
            .reason = TargetSignalGateReason::kOk};
}

} // namespace

// ── ctor / dtor ──────────────────────────────────────────────────────────────
MinimizeDriver::MinimizeDriver()
    : minimizer_fn_([](const ::refuzz::program::ProgramArtifact& artifact,
                       refuzz::crash::CandidateTestFunc test_fn,
                       refuzz::crash::StopFunc stop_fn,
                       refuzz::crash::MinimizeMode mode,
                       int guilty_call_index) {
        refuzz::crash::ProgramMinimizer minimizer;
        return minimizer.MinimizeWithCandidateArtifacts(artifact,
                                                        std::move(test_fn),
                                                        std::move(stop_fn),
                                                        mode,
                                                        guilty_call_index);
    })
{}

MinimizeDriver::MinimizeDriver(MinimizerFn fn)
    : minimizer_fn_(std::move(fn))
{}

MinimizeDriver::InlineVerdict MinimizeDriver::RunInline(
    const StartArgs&             args,
    const InlineExecFn&          exec_fn,
    const std::function<bool()>& cancelled_fn)
{
    InlineVerdict verdict{};
    // Cover of the last MATCHED candidate (= committed minimized program's
    // cover), rebuilt on each match; the last match wins.
    std::vector<std::uint64_t> committed_cover;
    bool hard_stop = false;

    const auto external_cancelled = [&]() -> bool {
        return cancelled_fn && cancelled_fn();
    };
    const auto should_stop = [&]() -> bool {
        return hard_stop || external_cancelled();
    };

    refuzz::crash::CandidateTestFunc test_fn =
        [&](const refuzz::crash::CandidateTestInput& candidate)
            -> std::pair<bool, std::string>
    {
        if (external_cancelled()) {
            return {false, std::string{}};   // cancelled → don't exec
        }
        const Candidate cand{
            .exec_wire_payload = candidate.payload,
            .artifact          = candidate.artifact,
            .call_index        = candidate.call_index,
        };
        // [flaky-signal parity — syz job.go:361-392] target_signal_hashes 是 k-of-n
        //   稳定信号,不保证每次 re-exec 都出现。单次 re-exec 漏掉某条 flaky 目标 hash 会误判
        //   no-match —— 对 trailing/unrelated **整块**删(单 exec 全有或全无)尤其致命:一次漏
        //   → 整块 drop 被拒 → 退化成逐 call 删 O(calls)。故复跑最多 args.attempts 次、跨次
        //   **MERGE** 目标信号,合并信号覆盖全部目标即接受(提前返回)。非 flaky 步骤首跑即命中。
        const int attempts = args.attempts > 0 ? args.attempts : 1;
        std::unordered_map<std::uint64_t, std::uint8_t> merged_observed;
        bool matched = false;
        int attempts_used = 0;
        int last_exec_status = -1;
        std::size_t last_per_call_count = 0;
        for (int attempt = 0; attempt < attempts && !matched; ++attempt) {
            const ExecSignalSnapshot snapshot = exec_fn(cand);
            ++attempts_used;
            last_exec_status = static_cast<int>(snapshot.exec_status);
            last_per_call_count = snapshot.per_call.size();
            if (external_cancelled()) {
                return {false, std::string{}};   // exec was cancelled mid-flight
            }
            if (snapshot.hard_stop) {
                hard_stop = true;
                refuzz::logging::HostLogger::Instance().Log(
                    "Minimizer",
                    "minimize_hard_stop",
                    {refuzz::logging::Field("attempts_used", attempts_used),
                     refuzz::logging::Field("guilty_call_index", args.guilty_call_index),
                     refuzz::logging::Field("candidate_call_index", cand.call_index),
                     refuzz::logging::Field("last_exec_status", last_exec_status),
                     refuzz::logging::Field("last_per_call_count", last_per_call_count),
                     refuzz::logging::Field("payload_bytes", cand.exec_wire_payload.size())});
                return {false, std::string{}};
            }
            auto observed = ObservedTargetSignal(args, snapshot, cand.call_index);
            if (!observed.signal.has_value()) {
                continue;   // 本次未过 per-run gate(状态/形状不符)→ 不贡献信号(= syz reexecutionSuccess)
            }
            for (const std::uint64_t hash : *observed.signal) {
                auto it = merged_observed.find(hash);
                if (it == merged_observed.end() ||
                    observed.priority > it->second) {
                    merged_observed[hash] = observed.priority;
                }
            }
            if (ContainsAllTargetSignals(args.target_signal_hashes,
                                         args.target_signal_prios,
                                         merged_observed)) {
                matched = true;
                // committed_cover = 命中候选程序的 per-call cover 并集;last match wins。
                std::vector<std::uint64_t> cover;
                for (const auto& call : snapshot.per_call) {
                    std::vector<std::uint64_t> m;
                    m.reserve(cover.size() + call.coverage_hashes.size());
                    std::set_union(cover.begin(), cover.end(),
                                   call.coverage_hashes.begin(),
                                   call.coverage_hashes.end(),
                                   std::back_inserter(m));
                    cover = std::move(m);
                }
                committed_cover = std::move(cover);
            }
        }
        return {matched, std::string{}};
    };

    // stop_fn lets the minimizer bail early once the job is cancelled.
    refuzz::crash::StopFunc stop_fn = [&]() -> bool { return should_stop(); };

    static const ::refuzz::program::ProgramArtifact kEmptyArtifact;
    const auto& artifact_ref =
        args.initial_artifact != nullptr ? *args.initial_artifact : kEmptyArtifact;

    auto result = minimizer_fn_(artifact_ref,
                                std::move(test_fn),
                                std::move(stop_fn),
                                args.mode,
                                args.guilty_call_index);

    verdict.final_payload  = std::move(result.payload);
    verdict.final_artifact = std::move(result.artifact);
    verdict.final_cover    = std::move(committed_cover);
    verdict.remapped_guilty_call_index = result.remapped_guilty_call_index;
    verdict.hard_stopped = hard_stop;
    return verdict;
}

} // namespace refuzz::control
