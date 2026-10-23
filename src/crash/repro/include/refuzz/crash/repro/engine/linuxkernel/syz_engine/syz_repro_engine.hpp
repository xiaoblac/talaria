#pragma once

// KernelReproEngine — Linux kernel 的 repro 能力引擎（syz_engine）

#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/repro/core/exec_result.hpp"
#include "refuzz/crash/repro/core/repro_engine.hpp"
#include "refuzz/crash/repro/core/repro_types.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/program/artifact.hpp"

#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::crash {

class KernelReproEngine final : public IReproEngine {
public:
    explicit KernelReproEngine(Addr2lineSymbolizer* symbolizer = nullptr);

    bool MatchVerdict(
        const RunResult& run,
        const VerdictParams& params,
        bool strict,
        const std::string& target_title,
        const std::unordered_set<std::string>& observed_titles,
        const std::vector<std::string>& alt_titles,
        CrashKind crash_kind) const override;

    // §3.11-A/C1 — typed entry. Reads `artifact->As<syz::Prog>()`
    // (CrashContext::origin_artifact). ProgramMinimizer owns the syz-specific
    // typed candidate loop and emits exec-wire bytes for TestFunc. Linux requires
    // the typed artifact (RequiresTypedArtifactForMinimize defaults true, so
    // StageMinimize guarantees artifact != null here); `payload` is unused.
    MinimizeResult Minimize(
        const std::vector<uint8_t>& payload,
        const ::refuzz::program::ProgramArtifact* artifact,
        TestFunc test_fn,
        StopFunc stop_fn,
        const MinimizeParams& params) override;

    std::string ParseAndSymbolize(const std::string& console) override;
    std::string NormalizeTitle(const std::string& title) const override;
    std::vector<std::string> ExtractCrashTitles(const RunResult& run) const override;

private:
    std::string BuildSymbolizedReport(const ParsedCrashReport& report) const;
    KernelReportParser parser_;
    Addr2lineSymbolizer* symbolizer_;
    ProgramMinimizer minimizer_;
};

} // namespace refuzz::crash
