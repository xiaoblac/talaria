#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"

#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/minimize_ctx.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/type.hpp"
#include "refuzz/logging/host_logger.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

namespace refuzz::crash {
namespace {

namespace syzv2 = ::refuzz::program::syz;

bool ShouldStop(StopFunc& stop_fn)
{
    return stop_fn && stop_fn();
}

// V2 typed adapter. Builds a `syz::MinimizeCtx` + pred wrapper
// (sanitize → assign sizes → serialize_for_exec → no-op short-circuit
// → payload-cache → TestFunc) and drives
// `syz::run_minimize_typed(ctx)`.
struct TypedMinimizeAdapterOutcome {
    std::unique_ptr<syzv2::Prog> prog;
    MinimizeResult               result;
};

TypedMinimizeAdapterOutcome RunTypedMinimizeViaCtx(
    const syzv2::Prog& source,
    CandidateTestFunc& test_fn,
    StopFunc&          stop_fn,
    MinimizeMode       mode,
    int                guilty_call_index,
    bool               build_candidate_artifacts)
{
    auto current = syzv2::DeepClone(source);
    if (current == nullptr || current->calls().empty()) {
        return {nullptr, MinimizeResult{}};
    }

    const uint32_t original_count = static_cast<uint32_t>(current->calls().size());

    std::unordered_map<std::string, bool> verdict_cache;
    std::string                           committed_payload;

    // Initial baseline so the no-op short-circuit recognizes "the
    // candidate is byte-equal to the source" as no progress.
    {
        auto initial_or = syzv2::serialize_for_exec(*current);
        if (initial_or.has_value() && !initial_or->empty()) {
            committed_payload.assign(
                reinterpret_cast<const char*>(initial_or->data()),
                initial_or->size());
        }
    }

    uint32_t test_fn_invocations = 0;

    syzv2::MinimizePred pred = [&verdict_cache, &committed_payload,
                                &test_fn_invocations,
                                &test_fn, &stop_fn,
                                build_candidate_artifacts]
        (syzv2::Prog& candidate, int idx) mutable -> bool {
        if (ShouldStop(stop_fn)) return false;

        syzv2::sanitize_fix(candidate);

        if (candidate.target() != nullptr) {
            for (auto& call : candidate.mutable_calls()) {
                if (call == nullptr || call->meta() == nullptr) continue;
                syzv2::assign_sizes_array(*candidate.target(),
                                          call->mutable_args(),
                                          call->meta()->args(),
                                          nullptr);
            }
        }

        auto payload_or = syzv2::serialize_for_exec(candidate);
        if (!payload_or.has_value() || payload_or->empty()) return false;
        std::string key(reinterpret_cast<const char*>(payload_or->data()),
                        payload_or->size());

        if (key == committed_payload) return false;

        bool matched;
        if (auto it = verdict_cache.find(key); it != verdict_cache.end()) {
            matched = it->second;
        } else {
            CandidateTestInput input;
            input.payload = *payload_or;
            input.call_index = idx;
            if (build_candidate_artifacts) {
                auto candidate_clone = syzv2::DeepClone(candidate);
                if (candidate_clone != nullptr) {
                    std::shared_ptr<const syzv2::Prog> prog_sp(candidate_clone.release());
                    auto art_value = syzv2::MakeArtifactFromTypedProg(std::move(prog_sp));
                    if (art_value.valid()) {
                        input.artifact =
                            std::make_shared<const ::refuzz::program::ProgramArtifact>(
                                std::move(art_value));
                    }
                }
            }
            // The callback already owns the complete reproduction verdict
            // (including parsed title/AltTitles and crash-kind policy). This
            // mirrors syzkaller's minimizeProg callback, which returns only
            // the boolean verdict and never re-parses a single title here.
            const auto verdict = test_fn(input);
            ++test_fn_invocations;
            matched = verdict.first;
            verdict_cache.emplace(key, matched);
        }

        if (matched) {
            committed_payload = std::move(key);
        }
        return matched;
    };

    const int guilty =
        (guilty_call_index >= 0 &&
         guilty_call_index < static_cast<int>(current->calls().size()))
            ? guilty_call_index
            : -1;

    syzv2::MinimizeMode syz_mode;
    switch (mode) {
    case MinimizeMode::kCallsOnly:     syz_mode = syzv2::MinimizeMode::kCallsOnly;     break;
    case MinimizeMode::kCrash:         syz_mode = syzv2::MinimizeMode::kCrash;         break;
    case MinimizeMode::kCrashSnapshot: syz_mode = syzv2::MinimizeMode::kCrashSnapshot; break;
    }

    syzv2::MinimizeCtx ctx(current->target(),
                           &current,
                           current.get(),
                           guilty,
                           syz_mode,
                           std::move(pred));

    syzv2::StopFunc syz_stop = [&stop_fn]() {
        return stop_fn && stop_fn();
    };

    auto outcome = syzv2::run_minimize_typed(ctx, syz_stop);

    const uint32_t minimized_count = static_cast<uint32_t>(current->calls().size());

    MinimizeResult result;
    result.original_call_count  = original_count;
    result.minimized_call_count = minimized_count;
    result.success              = outcome.succeeded;
    result.minimize_attempts    = test_fn_invocations;
    result.minimize_commits     = ctx.committed_count();
    result.minimize_stage       = outcome.last_stage;
    const int remapped_guilty = ctx.call_index0();
    if (remapped_guilty >= 0 &&
        remapped_guilty < static_cast<int>(current->calls().size())) {
        result.remapped_guilty_call_index = remapped_guilty;
    } else {
        result.remapped_guilty_call_index = -1;
    }
    return {std::move(current), std::move(result)};
}

MinimizeResult FinalizeTypedMinimizeResult(TypedMinimizeAdapterOutcome adapter_out,
                                           int guilty_call_index)
{
    if (adapter_out.prog == nullptr) {
        return MinimizeResult{};
    }
    auto payload_or = syzv2::serialize_for_exec(*adapter_out.prog);
    if (payload_or.has_value()) {
        adapter_out.result.payload = std::move(*payload_or);
    }

    // Wrap the minimized typed Prog in an artifact so downstream stages
    // (smash / mutational) can resume on V2 typed authority. Provider
    // computes canonical text lazily — minimize itself never reads it.
    std::shared_ptr<const syzv2::Prog> prog_sp(adapter_out.prog.release());
    auto art_value = syzv2::MakeArtifactFromTypedProg(prog_sp);
    if (art_value.valid()) {
        adapter_out.result.artifact =
            std::make_shared<const ::refuzz::program::ProgramArtifact>(
                std::move(art_value));
    }

    refuzz::logging::HostLineBuilder("Minimizer", "typed_prog_summary")
        << adapter_out.result.original_call_count << " → "
        << adapter_out.result.minimized_call_count
        << " calls (guilty=" << guilty_call_index
        << ", remapped_guilty=" << adapter_out.result.remapped_guilty_call_index
        << ", attempts=" << adapter_out.result.minimize_attempts
        << ", commits=" << adapter_out.result.minimize_commits
        << ", stage=" << adapter_out.result.minimize_stage << ")\n";
    return std::move(adapter_out.result);
}

} // namespace

// §3.11-C1 — typed artifact entry.
MinimizeResult ProgramMinimizer::Minimize(const ::refuzz::program::ProgramArtifact& artifact,
                                          TestFunc test_fn,
                                          StopFunc stop_fn,
                                          MinimizeMode mode,
                                          int guilty_call_index)
{
    CandidateTestFunc candidate_test_fn =
        [test_fn = std::move(test_fn)](const CandidateTestInput& input) mutable {
            return test_fn(input.payload);
        };
    if (!artifact.valid()) {
        return MinimizeResult{};
    }

    auto prog = artifact.As<syzv2::Prog>();
    if (prog == nullptr) {
        return MinimizeResult{};
    }

    auto adapter_out = RunTypedMinimizeViaCtx(*prog, candidate_test_fn,
                                              stop_fn, mode, guilty_call_index,
                                              /*build_candidate_artifacts=*/false);
    return FinalizeTypedMinimizeResult(std::move(adapter_out), guilty_call_index);
}

MinimizeResult ProgramMinimizer::MinimizeWithCandidateArtifacts(
                                          const ::refuzz::program::ProgramArtifact& artifact,
                                          CandidateTestFunc test_fn,
                                          StopFunc stop_fn,
                                          MinimizeMode mode,
                                          int guilty_call_index)
{
    if (!artifact.valid()) {
        return MinimizeResult{};
    }

    auto prog = artifact.As<syzv2::Prog>();
    if (prog == nullptr) {
        return MinimizeResult{};
    }

    auto adapter_out = RunTypedMinimizeViaCtx(*prog, test_fn,
                                              stop_fn, mode, guilty_call_index,
                                              /*build_candidate_artifacts=*/true);
    return FinalizeTypedMinimizeResult(std::move(adapter_out), guilty_call_index);
}

// §3.11-C1 P5 / oracle #24 — typed-output entry.
std::pair<std::unique_ptr<::refuzz::program::syz::Prog>, MinimizeResult>
ProgramMinimizer::MinimizeProgTyped(const ::refuzz::program::syz::Prog& source,
                                    TestFunc test_fn,
                                    StopFunc stop_fn,
                                    MinimizeMode mode,
                                    int guilty_call_index)
{
    CandidateTestFunc candidate_test_fn =
        [test_fn = std::move(test_fn)](const CandidateTestInput& input) mutable {
            return test_fn(input.payload);
        };
    auto adapter_out = RunTypedMinimizeViaCtx(source, candidate_test_fn,
                                              stop_fn, mode, guilty_call_index,
                                              /*build_candidate_artifacts=*/false);
    return {std::move(adapter_out.prog), std::move(adapter_out.result)};
}

} // namespace refuzz::crash
