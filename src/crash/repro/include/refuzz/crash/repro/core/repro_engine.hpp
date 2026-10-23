#pragma once

// Per-target repro capability seam.
//
// Extract / replay / reliability are generic in ReproManager (they drive the
// program via IExecAdapter and read ctx.program_log). The ENGINE owns the
// target-specific bits:
//   - MatchVerdict           : did a replayed run reproduce the target crash?
//   - NormalizeTitle         : canonicalize a crash title
//   - Minimize               : shrink the reproducing program
//   - ParseAndSymbolize      : crash console → symbolized report (Linux dmesg)
//
// Implementations: KernelReproEngine (Linux / syz typed programs),
// XiuosReproEngine (XiUOS wire programs). ReproManager talks to the engine only
// through this interface — it is NOT coupled to any concrete target.

#include "refuzz/crash/infra/crash_context.hpp"     // CrashKind
#include "refuzz/crash/repro/core/exec_result.hpp"  // RunResult
#include "refuzz/crash/repro/core/repro_types.hpp"  // MinimizeParams / VerdictParams (+ MinimizeResult/TestFunc/StopFunc)
#include "refuzz/program/artifact.hpp"              // ProgramArtifact

#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::crash {

class IReproEngine {
public:
    virtual ~IReproEngine() = default;

    // Does a single replayed run count as reproducing the crash? Default: the
    // run reported a crash. XiUOS overrides to also accept timed_out, because a
    // worker that wedges/dies shows up as a per-program timeout on replay yet was
    // classified worker_dead/kernel_crash by the channel health path. Used by both
    // the extract verdict and the minimize test loop so they agree.
    virtual bool CountsAsRepro(const RunResult& run) const { return run.crashed; }

    // Do this target's findings leave the worker unusable for the next run (so the
    // VM must be hard-rebooted between repro candidates)? Default: false — Linux
    // kernel crashes kill the VM and the channel auto-recovers, so RestartBetweenRuns'
    // lifecycle probe suffices. XiUOS overrides to true: a wedge (forever-blocking
    // ecall) leaves the worker stuck but the VM "running", so without an explicit
    // reboot every later candidate also times out and minimize over-collapses.
    virtual bool RequiresHardRebootBetweenRuns() const { return false; }

    // Did `run` reproduce the target crash (title / crash_kind match)?
    virtual bool MatchVerdict(
        const RunResult& run,
        const VerdictParams& params,
        bool strict,
        const std::string& target_title,
        const std::unordered_set<std::string>& observed_titles,
        const std::vector<std::string>& alt_titles,
        CrashKind crash_kind) const = 0;

    // Canonicalize a crash title for observed-title accumulation. Default: identity.
    virtual std::string NormalizeTitle(const std::string& title) const { return title; }

    // Extract the semantic title set produced by one execution. Targets that
    // carry a structured crash report can override this to parse the execution's
    // own output and return its canonical and alternative titles.
    virtual std::vector<std::string> ExtractCrashTitles(const RunResult& run) const
    {
        const std::string title = NormalizeTitle(run.crash_title);
        return title.empty() ? std::vector<std::string>{}
                             : std::vector<std::string>{title};
    }

    // Whether Minimize needs a typed ProgramArtifact (Linux/syz) vs operating on
    // the raw exec-wire payload (XiUOS). Drives StageMinimize's null-artifact gate
    // so the Linux fail-closed behavior is preserved while bytes-only targets run.
    virtual bool RequiresTypedArtifactForMinimize() const { return true; }

    // Minimize the reproducing program. `artifact` is the typed authority (may be
    // null for bytes-only targets); `payload` is the exec-wire bytes StageExtract
    // reproduced. `test_fn` replays a candidate; its first result is the
    // complete reproduction verdict (the optional string is diagnostic
    // metadata only). `stop_fn` aborts.
    virtual MinimizeResult Minimize(
        const std::vector<uint8_t>& payload,
        const ::refuzz::program::ProgramArtifact* artifact,
        TestFunc test_fn,
        StopFunc stop_fn,
        const MinimizeParams& params) = 0;

    // Symbolize the crash console (Linux dmesg → addr2line). Default: no-op
    // (targets without a symbolizable console return empty).
    virtual std::string ParseAndSymbolize(const std::string& /*console*/) { return {}; }
};

} // namespace refuzz::crash
