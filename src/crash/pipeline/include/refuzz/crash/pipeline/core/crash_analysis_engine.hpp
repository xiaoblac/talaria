#pragma once

#include "refuzz/crash/infra/diagnostic_store.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_registry.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"

namespace refuzz::crash {

class ICrashAnalysisEngine {
public:
    virtual ~ICrashAnalysisEngine() = default;

    virtual void RegisterOps(CrashPipelineRegistry& registry,
                             DiagnosticStore* diagnostic_store,
                             IReproQueue* repro_queue) = 0;
};

} // namespace refuzz::crash
