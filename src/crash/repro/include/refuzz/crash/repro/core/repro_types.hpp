#pragma once

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/program/artifact.hpp"   // post-V1-retirement — selected_artifact carrier

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::crash {

enum class ReproStageOp : uint8_t {
    kExtract = 0,
    kMinimize,
    kReliability,
    kSymbolize,
    // Epic 4 PR-4-A — appended; opt-in via ReproConfig.produce_c_reproducer.
    kProduceCSource,
};

struct ReproStageNode { ReproStageOp op; };
using ReproPlan = std::vector<ReproStageNode>;

struct ExtractParams {
    bool try_crash_program = true;
    bool try_history_scan = true;
    bool try_bisect = true;
    bool try_concat = true;
    uint32_t attempts_per_strategy = 3;
};

struct MinimizeParams {
    MinimizeMode mode = MinimizeMode::kCrash;
    uint32_t test_retries = 3;
};

struct ReliabilityParams {
    uint32_t runs = 10;
    uint32_t early_exit = 3;
    double threshold = 0.15;
};

struct VerdictParams {
    bool check_crash_kind = true;
    uint32_t error_retries = 3;
};

enum class NextAction : uint8_t {
    kContinue = 0,
    kSkipToReliability = 1,
    kSkipToSymbolize = 2,
    kAbort = 3,
};

enum class ReproCompletionStatus : uint8_t {
    kCompleted = 0,
    kInterrupted = 1,
    kFailed = 2,
};

enum class ReproStage : uint8_t {
    kNone = 0,
    kExtract = 1,
    kMinimize = 2,
    kReliability = 3,
    kSymbolize = 4,
    // Epic 4 PR-4-A — appended.
    kProduceCSource = 5,
};

enum class ReproCompletionReason : uint8_t {
    kNone = 0,
    kStopRequested = 1,
    kExtractFailed = 2,
    kChannelNotReady = 3,
    kRecoveryFailed = 4,
    kMinimizeFailed = 5,
    kReliabilityBelowThreshold = 6,
    kReproduceFailed = 7,
    // Epic 4 PR-4-A — appended.
    kCReproNoMinimizedArtifact = 8,
    kCReproUnsupportedByEpic4  = 9,
    kCReproWriteFailed         = 10,
    kCReproBuildFailed         = 11,
};

struct ReproResult {
    uint64_t incident_id = 0;
    bool reproduced = false;
    double reliability = 0.0;
    std::vector<uint8_t> minimized_payload;
    uint32_t original_call_count = 0;
    uint32_t minimized_call_count = 0;
    std::string crash_title;
    std::string symbolized_report;
    uint32_t total_attempts = 0;
    uint32_t crash_attempts = 0;
    uint32_t minimize_attempts = 0;
    uint32_t minimize_commits = 0;
    std::string minimize_stage;
    std::string extract_source;
    uint32_t program_log_count = 0;
    ReproCompletionStatus completion = ReproCompletionStatus::kFailed;
    ReproStage last_completed_stage = ReproStage::kNone;
    ReproCompletionReason completion_reason = ReproCompletionReason::kNone;
    std::chrono::system_clock::time_point completed_at{};

    // post-V1-retirement artifact-first universal contract — review finding #3:
    //   The typed authority of the program StageExtract actually reproduced.
    //   StageMinimize MUST minimize this, not ctx.origin_artifact, otherwise
    //   when extract reproduced via history_i / bisect / concat we'd be
    //   minimizing an unrelated program. For the "original" extract path
    //   selected_artifact == ctx.origin_artifact. For history/bisect/concat
    //   the artifact is unknown today (history entries don't yet carry typed
    //   views) and selected_artifact stays null → StageMinimize fails closed,
    //   which is correct: we don't have the right typed view to minimize.
    //   Future work (history entry artifact propagation) lifts that.
    //   See docs/syzkaller-parity-review/post_v1_retirement_followups.md §5.2 B-5.
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> selected_artifact;

    // Epic 4 PR-4-A — C reproducer outputs.
    std::string c_reproducer_source;
    std::string c_reproducer_build_err;
};

} // namespace refuzz::crash
