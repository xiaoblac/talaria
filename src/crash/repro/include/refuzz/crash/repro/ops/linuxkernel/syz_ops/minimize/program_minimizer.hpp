#pragma once

// ProgramMinimizer — syscall 序列最小化（V2 typed-only）
//
// Drives `syz::run_minimize_typed` on a `program::syz::Prog`; serializes
// candidates with `serialize_for_exec` before calling TestFunc. The
// public entry takes a `ProgramArtifact` (must carry a `program::syz::Prog`
// typed view).

#include "refuzz/program/artifact.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace refuzz::program::syz {
class Prog;
} // namespace refuzz::program::syz

namespace refuzz::crash {

struct CandidateTestInput {
    std::vector<uint8_t> payload;
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
    int call_index = -1;
};

using TestFunc = std::function<std::pair<bool, std::string>(const std::vector<uint8_t>&)>;
using CandidateTestFunc =
    std::function<std::pair<bool, std::string>(const CandidateTestInput&)>;
using StopFunc = std::function<bool()>;

enum class MinimizeMode : uint8_t {
    kCallsOnly = 0,
    kCrash = 1,
    kCrashSnapshot = 2,
};

struct MinimizeResult {
    // Exec-wire bytes from `serialize_for_exec` on the minimized typed
    // Prog. Used by the driver state machine to feed test_fn /
    // OnExecResult and surfaced as the final candidate payload for the
    // executor submit path.
    std::vector<uint8_t> payload;

    // Typed view of the minimized program. Wraps the post-minimize
    // `program::syz::Prog` so downstream stages (smash / mutational)
    // can resume on V2 typed authority instead of falling back to
    // bytes mutate.
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;

    uint32_t original_call_count = 0;
    uint32_t minimized_call_count = 0;
    bool success = false;
    uint32_t minimize_attempts = 0;
    uint32_t minimize_commits = 0;
    std::string minimize_stage = "none";
    // Final index of the protected/guilty call after typed minimization remaps
    // call_index0 through accepted removals. -1 means there is no valid
    // per-call target in the minimized program.
    int remapped_guilty_call_index = -1;
};

class ProgramMinimizer {
public:
    // §3.11-C1 — typed artifact entry. Reads
    // `ProgramArtifact::As<program::syz::Prog>()` and keeps candidate
    // generation in typed IR; emits exec-wire bytes for TestFunc.
    MinimizeResult Minimize(const ::refuzz::program::ProgramArtifact& artifact,
                            TestFunc test_fn,
                            StopFunc stop_fn,
                            MinimizeMode mode = MinimizeMode::kCrash,
                            int guilty_call_index = -1);

    // Artifact-aware variant for the control minimizer. Each candidate
    // callback receives both exec-wire bytes and a typed artifact for
    // the exact candidate, so the executor completion can be correlated
    // back to per-call errno/syscall observations.
    MinimizeResult MinimizeWithCandidateArtifacts(
                            const ::refuzz::program::ProgramArtifact& artifact,
                            CandidateTestFunc test_fn,
                            StopFunc stop_fn,
                            MinimizeMode mode = MinimizeMode::kCrash,
                            int guilty_call_index = -1);

    // §3.11-C1 P5 / oracle #24 — typed-output entry. Returns the
    // minimized typed Prog directly so callers (the syzkaller-parity
    // test) can compare structurally via canonical text or per-call
    // traversal without going through the exec-wire round-trip.
    //
    // The returned MinimizeResult.payload is empty (typed result is in
    // the unique_ptr); other fields (counts, attempts, commits, stage)
    // are populated.
    std::pair<std::unique_ptr<::refuzz::program::syz::Prog>, MinimizeResult>
    MinimizeProgTyped(const ::refuzz::program::syz::Prog& source,
                      TestFunc test_fn,
                      StopFunc stop_fn,
                      MinimizeMode mode = MinimizeMode::kCrash,
                      int guilty_call_index = -1);
};

} // namespace refuzz::crash
