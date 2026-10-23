// [XiUOS leak 一等公民化 Phase 1]

#include "refuzz/crash/pipeline/engine/xiuos/xiuos_crash_analysis_engine.hpp"

#include "refuzz/crash/pipeline/ops/xiuos/xiuos_pipeline_ops.hpp"

namespace refuzz::crash {

void XiuosCrashAnalysisEngine::RegisterOps(CrashPipelineRegistry& registry,
                                           DiagnosticStore* diagnostic_store,
                                           IReproQueue* repro_queue)
{
    RegisterXiuosCrashPipelineOps(registry, diagnostic_store, repro_queue);
}

}  // namespace refuzz::crash
