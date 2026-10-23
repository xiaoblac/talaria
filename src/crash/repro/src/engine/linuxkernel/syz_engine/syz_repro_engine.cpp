#include "refuzz/crash/repro/engine/linuxkernel/syz_engine/syz_repro_engine.hpp"

#include <algorithm>
#include <sstream>

namespace refuzz::crash {

KernelReproEngine::KernelReproEngine(Addr2lineSymbolizer* symbolizer)
    : symbolizer_(symbolizer)
{}

bool KernelReproEngine::MatchVerdict(
    const RunResult& run,
    const VerdictParams& params,
    bool strict,
    const std::string& target_title,
    const std::unordered_set<std::string>& observed_titles,
    const std::vector<std::string>& alt_titles,
    CrashKind crash_kind) const
{
    if (!run.crashed) {
        return false;
    }

    if (params.check_crash_kind &&
        crash_kind == CrashKind::kKernelCrash &&
        run.crash_kind != CrashKind::kUnknownIncident &&
        crash_kind != run.crash_kind) {
        return false;
    }

    if (!strict) {
        return true;
    }
    if (target_title.empty()) {
        return true;
    }

    const std::vector<std::string> candidates = ExtractCrashTitles(run);
    for (const std::string& candidate : candidates) {
        if (candidate == target_title ||
            observed_titles.count(candidate) > 0 ||
            std::find(alt_titles.begin(), alt_titles.end(), candidate) !=
                alt_titles.end()) {
            return true;
        }
    }
    return false;
}

// §3.11-A/C1 — artifact-aware entry. Delegates to ProgramMinimizer's
// typed overload; the minimizer keeps candidates in syz::Prog and emits
// exec-wire bytes for TestFunc. Oracle #21 verifies that no text codec
// calls are added in the candidate path.
MinimizeResult KernelReproEngine::Minimize(
    const std::vector<uint8_t>& payload,
    const ::refuzz::program::ProgramArtifact* artifact,
    TestFunc test_fn,
    StopFunc stop_fn,
    const MinimizeParams& params)
{
    (void)payload;  // Linux/syz minimizes the typed artifact, not raw bytes.
    if (artifact == nullptr || !artifact->valid()) {
        return {};  // no typed authority → nothing to minimize (fail-closed)
    }
    return minimizer_.Minimize(*artifact, std::move(test_fn),
                               std::move(stop_fn), params.mode, -1);
}

std::string KernelReproEngine::ParseAndSymbolize(const std::string& console)
{
    auto parsed = parser_.Parse(console);
    if (!parsed.has_value()) {
        return {};
    }
    if (symbolizer_ != nullptr && !parsed->frames.empty()) {
        symbolizer_->SymbolizeReport(*parsed);
    }
    return BuildSymbolizedReport(*parsed);
}

std::string KernelReproEngine::NormalizeTitle(const std::string& title) const
{
    return KernelReportParser::NormalizeTitle(title);
}

std::vector<std::string> KernelReproEngine::ExtractCrashTitles(
    const RunResult& run) const
{
    if (!run.console_output.empty()) {
        auto parsed = parser_.Parse(run.console_output);
        if (parsed.has_value() && !parsed->title.empty()) {
            std::vector<std::string> titles;
            titles.reserve(1 + parsed->alt_titles.size());
            titles.push_back(parsed->title);
            for (const std::string& title : parsed->alt_titles) {
                if (!title.empty() &&
                    std::find(titles.begin(), titles.end(), title) == titles.end()) {
                    titles.push_back(title);
                }
            }
            return titles;
        }
    }

    const std::string fallback = NormalizeTitle(run.crash_title);
    return fallback.empty() ? std::vector<std::string>{}
                            : std::vector<std::string>{fallback};
}

std::string KernelReproEngine::BuildSymbolizedReport(const ParsedCrashReport& report) const
{
    std::ostringstream oss;
    oss << "Title: " << report.title << "\n";
    if (!report.guilty_function.empty()) {
        oss << "Guilty: " << report.guilty_function << "\n";
    }
    oss << "Type: " << static_cast<int>(report.type) << "\n";
    oss << "Frames:\n";

    for (size_t i = 0; i < report.frames.size(); ++i) {
        const auto& f = report.frames[i];
        oss << "  #" << i << " ";
        if (!f.function.empty()) {
            oss << f.function;
            if (f.offset > 0 || f.size > 0) {
                oss << "+0x" << std::hex << f.offset << "/0x" << f.size << std::dec;
            }
        }
        if (f.pc != 0) {
            oss << " [0x" << std::hex << f.pc << std::dec << "]";
        }
        if (!f.file.empty()) {
            oss << " " << f.file << ":" << f.line;
        }
        if (!f.module.empty()) {
            oss << " [" << f.module << "]";
        }
        oss << "\n";
    }

    return oss.str();
}

} // namespace refuzz::crash
