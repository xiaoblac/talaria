#include "refuzz/crash/pipeline/engine/linuxkernel/syz_engine/syz_crash_analysis_engine.hpp"
#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"

namespace refuzz::crash {

KernelCrashAnalysisEngine::KernelCrashAnalysisEngine(
    Addr2lineSymbolizer* symbolizer,
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode)
    : symbolizer_(symbolizer)
    , sanitizer_mode_(sanitizer_mode)
{}

void KernelCrashAnalysisEngine::RegisterOps(CrashPipelineRegistry& registry,
                                            DiagnosticStore* diagnostic_store,
                                            IReproQueue* repro_queue)
{
    RegisterKernelCrashPipelineOps(
        registry,
        &parser_,
        symbolizer_,
        sanitizer_mode_,
        diagnostic_store,
        repro_queue);
}

} // namespace refuzz::crash
