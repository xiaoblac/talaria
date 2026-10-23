#pragma once
// minimize admit / demux —— control 线程的 minimize 完成 admit + RunOnce 结果投影(loop-home)。
//
//   - AdmitMinimizedSeed:minimize 完成后用 StepVerdict 构 final Seed(继承 source/lineage/
//     stability/altitude/cover)→ admit corpus_inbox + DispatchElaboration + 记
//     minimize_completed。**必须 control 线程调**(core_path_job 经 ctx.retain 绑 admit_fn;
//     FuzzerLoop::TrySpawnCorePathTriage 注入闭包)。
//   - ProjectExecResult:RunOnce demux 把 ChannelEvent(+ 已算好的 EngineOutput)投影成
//     job::ExecResult,喂给 core-path job 的 minimize/deflake 复跑。

#include "refuzz/control/job/job_context.hpp"           // job::ExecResult / job::CallSignal
#include "refuzz/control/job/job_deps.hpp"              // JobDeps
#include "refuzz/control/stages/minimize_driver.hpp"    // MinimizeDriver::StepVerdict
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/feedback/feedback_engine.hpp"          // EngineOutput
#include "refuzz/core/channel_contract.hpp"             // ChannelEvent

#include <cstdint>

namespace refuzz::control {

// minimize 完成后构造 final Seed → admit corpus_inbox + DispatchElaboration
// + 记 minimize_completed。**必须 control 线程调**。
void AdmitMinimizedSeed(
    JobDeps&                            deps,
    const refuzz::fuzzer::Seed&         original_seed,
    MinimizeDriver::StepVerdict&        verdict,
    const refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate* finished_candidate,
    std::uint64_t                       origin_executor_id);

// deflake-stable seed direct admit: used for boot-corpus candidates that are
// already minimized/smashed in syzkaller's sense. The seed must already carry
// TriageStableSignalMetadata/CorpusCoverageMetadata from core_path_job.
void AdmitStableSeed(
    JobDeps&                    deps,
    const refuzz::fuzzer::Seed& stable_seed,
    bool                        dispatch_elaboration,
    std::uint64_t               origin_executor_id);

// event(+ 已算好的 EngineOutput)→ job::ExecResult 投影。RunOnce demux 用。out 可空。
job::ExecResult ProjectExecResult(
    const refuzz::core::channel_contract::ChannelEvent& event,
    const refuzz::fuzzer::EngineOutput*                 out);

} // namespace refuzz::control
