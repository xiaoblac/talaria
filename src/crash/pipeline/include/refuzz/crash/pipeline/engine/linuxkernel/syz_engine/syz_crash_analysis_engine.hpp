#pragma once

#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/crash/pipeline/core/crash_analysis_engine.hpp"
#include "refuzz/channel/worker/mode.hpp"

namespace refuzz::crash {

class KernelCrashAnalysisEngine final : public ICrashAnalysisEngine {
public:
    explicit KernelCrashAnalysisEngine(Addr2lineSymbolizer* symbolizer = nullptr,
                                       refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode =
                                           refuzz::channel::worker::WorkerSanitizerMode::kNone);

    void RegisterOps(CrashPipelineRegistry& registry,
                     DiagnosticStore* diagnostic_store,
                     IReproQueue* repro_queue) override;

private:
    KernelReportParser parser_;
    Addr2lineSymbolizer* symbolizer_;
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode_ =
        refuzz::channel::worker::WorkerSanitizerMode::kNone;
};

} // namespace refuzz::crash
