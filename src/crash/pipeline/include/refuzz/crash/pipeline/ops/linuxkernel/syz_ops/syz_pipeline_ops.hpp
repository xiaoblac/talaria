#pragma once

#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/crash/infra/diagnostic_store.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_op.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_registry.hpp"
#include "refuzz/crash/pipeline/policy/linuxkernel/syz_xxx_policy/syz_triage_policy.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"
#include "refuzz/channel/worker/mode.hpp"

#include <memory>

namespace refuzz::crash {

void RegisterKernelCrashPipelineOps(CrashPipelineRegistry& registry,
                                    KernelReportParser* parser,
                                    Addr2lineSymbolizer* symbolizer,
                                    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode,
                                    DiagnosticStore* diagnostic_store,
                                    IReproQueue* repro_queue);

// [XiUOS leak 一等公民化 Phase 1] target-agnostic op factories.
//
// DedupOp / PersistOp / ReportOp / EnqueueOp operate purely on the generic
// CrashContext (no kernel/syz-specific state), so they are genuinely
// target-agnostic. These factories let other families (e.g. XiUOS) REUSE the
// single definition that lives in syz_pipeline_ops.cpp rather than cloning the
// op classes. The classification op (BuildContextOp / ParseAndClassifyOp) is
// NOT exposed here — each family owns its own routing/labeling op.
std::unique_ptr<ICrashPipelineOp> MakeDedupOp(DiagnosticStore* diagnostic_store);
std::unique_ptr<ICrashPipelineOp> MakePersistOp(DiagnosticStore* diagnostic_store);
std::unique_ptr<ICrashPipelineOp> MakeReportOp();
std::unique_ptr<ICrashPipelineOp> MakeEnqueueOp(IReproQueue* repro_queue);

// §3.11-A / §3.11-C — test-friendly factories.
namespace testing {

std::unique_ptr<ICrashPipelineOp>
MakeBuildContextOpForTest(refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode);

std::unique_ptr<ICrashPipelineOp>
MakeParseAndClassifyOpForTest(KernelReportParser* parser,
                              Addr2lineSymbolizer* symbolizer);

// §3.11-C — expose DedupDescription as a pure-function helper so unit
// tests can verify Bug #3 (coarse hash collision on generic titles)
// without spinning up the full DedupOp + DiagnosticStore pipeline.
std::string ComputeDedupDescriptionForTest(const CrashContext& ctx);

} // namespace testing

} // namespace refuzz::crash
