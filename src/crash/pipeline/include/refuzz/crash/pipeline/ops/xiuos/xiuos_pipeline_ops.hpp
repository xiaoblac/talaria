#pragma once

// [XiUOS leak 一等公民化 Phase 1]
//
// XiUOS-owned crash-pipeline ops. XiUOS is a first-class family with its OWN
// classification/routing component, NOT a borrower of the syz/linuxkernel ops.
//
// The only XiUOS-specific op is the context/classify op (XiuosBuildContextOp):
// it routes a XiUOS finding by XiUOS semantics — most importantly a
// ResultCode::kResourceLeak completion → CrashKind::kResourceLeak with the leak
// magnitude preserved in a dedicated carrier (NOT crash_signal). For all other
// result codes / fault reasons it replicates the target-agnostic routing so
// XiUOS wedges/errors still bucket correctly.
//
// The dedup / persist / enqueue / report ops are genuinely target-agnostic, so
// RegisterXiuosCrashPipelineOps REUSES the existing generic ones (built via the
// syz_ops factories) rather than cloning them. XiUOS has no kernel console log,
// so the serial-parsing ParseAndClassifyOp is a no-op for XiUOS — it is left out
// of the XiUOS plan-relevant registration (the XiuosBuildContextOp does the full
// title/kind assignment itself).

#include "refuzz/crash/infra/diagnostic_store.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_op.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_registry.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"

#include <memory>

namespace refuzz::crash {

void RegisterXiuosCrashPipelineOps(CrashPipelineRegistry& registry,
                                   DiagnosticStore* diagnostic_store,
                                   IReproQueue* repro_queue);

// test-friendly factory mirroring the syz_ops testing namespace.
namespace testing {

std::unique_ptr<ICrashPipelineOp> MakeXiuosBuildContextOpForTest();

}  // namespace testing

}  // namespace refuzz::crash
