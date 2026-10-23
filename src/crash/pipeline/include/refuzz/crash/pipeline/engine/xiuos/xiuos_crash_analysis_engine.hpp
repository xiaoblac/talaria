#pragma once

// [XiUOS leak 一等公民化 Phase 1]
//
// XiuosCrashAnalysisEngine — the XiUOS family's OWN crash-analysis engine,
// parallel to KernelCrashAnalysisEngine. It implements the same
// ICrashAnalysisEngine::RegisterOps contract but registers the XiUOS-owned op
// chain (XiuosBuildContextOp + the reused target-agnostic dedup/persist/enqueue/
// report ops) via RegisterXiuosCrashPipelineOps.
//
// XiUOS has no kernel console / vmlinux, so there is no KernelReportParser or
// Addr2lineSymbolizer here — the XiUOS ops classify directly from the completion
// result_code + vendor-derived fields.

#include "refuzz/crash/pipeline/core/crash_analysis_engine.hpp"

namespace refuzz::crash {

class XiuosCrashAnalysisEngine final : public ICrashAnalysisEngine {
public:
    XiuosCrashAnalysisEngine() = default;

    void RegisterOps(CrashPipelineRegistry& registry,
                     DiagnosticStore* diagnostic_store,
                     IReproQueue* repro_queue) override;
};

}  // namespace refuzz::crash
