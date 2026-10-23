#include "worker/perf/worker_perf.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace perf = refuzz::worker::perf;

namespace {

void Check(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::abort();
    }
}

void TestLoopStagesAreAdditive()
{
    perf::LoopPerfSample sample{};
    perf::AddStage(&sample, perf::LoopStage::kPrepare, 11);
    perf::AddStage(&sample, perf::LoopStage::kExecutor, 70);
    perf::AddStage(&sample, perf::LoopStage::kDelivery, 3);
    perf::AddStage(&sample, perf::LoopStage::kCleanup, 16);

    Check(perf::LoopActiveUs(sample) == 100,
          "loop stages do not sum to active time");
    Check(perf::StageValue(sample, perf::LoopStage::kExecutor) == 70,
          "loop executor stage changed");
    Check(std::string_view(perf::LoopStageName(perf::LoopStage::kCleanup)) ==
              "cleanup",
          "loop stage name changed");
}

void TestCriticalPathBreakdown()
{
    perf::ProgramPerfSample sample{};
    sample.parent_valid = true;
    sample.child_valid = true;
    sample.parent.fork_start_ts_us = 100;
    sample.child.child_entry_ts_us = 110;
    sample.child.runtime_start_ts_us = 125;
    sample.child.runtime_end_ts_us = 175;
    sample.child.result_ready_ts_us = 183;
    sample.parent.child_reaped_ts_us = 200;
    perf::AddStage(&sample.parent, perf::ParentStage::kReclamation, 7);
    perf::AddStage(&sample.parent, perf::ParentStage::kResult, 5);

    const perf::ProgramStageBreakdown stages =
        perf::BuildProgramStageBreakdown(sample);
    Check(stages.valid, "valid cross-process timeline rejected");
    Check(stages.stage_us[perf::StageIndex(perf::ProgramStage::kIsolation)] ==
              10,
          "isolation stage is not fork-start to child-entry");
    Check(stages.stage_us[perf::StageIndex(perf::ProgramStage::kChildSetup)] ==
              15,
          "child setup stage is wrong");
    Check(stages.stage_us[perf::StageIndex(perf::ProgramStage::kExecution)] ==
              50,
          "execution stage is wrong");
    Check(stages.stage_us[
              perf::StageIndex(perf::ProgramStage::kResultPublish)] == 8,
          "result publish stage is wrong");
    Check(stages.stage_us[perf::StageIndex(perf::ProgramStage::kCompletion)] ==
              17,
          "completion stage is wrong");
    Check(stages.total_us == 112,
          "critical path stages do not sum to their total");

    sample.child.result_ready_ts_us = 205;
    Check(!perf::BuildProgramStageBreakdown(sample).valid,
          "non-monotonic cross-process timeline accepted");
}

void TestWireRoundTripPreservesStages()
{
    perf::WorkerPerfSample source{};
    for (std::size_t index = 0; index < perf::kWorkerStageCount; ++index) {
        perf::AddStage(&source,
                       static_cast<perf::WorkerStage>(index),
                       1000 + index);
    }
    source.child_entry_ts_us = 100;
    source.runtime_start_ts_us = 200;
    source.runtime_end_ts_us = 300;
    source.result_ready_ts_us = 400;
    source.calls = 4;
    source.copyins = 5;
    source.copyouts = 6;
    source.kcov_resets = 7;
    source.kcov_collects = 8;
    source.remote_kcov_settles = 9;
    source.cov_entries = 10;
    source.cov_taken = 11;
    source.blocked_calls = 12;
    source.output_len = 13;
    source.backend_status = -14;
    source.post_walk_drain_programs = 15;
    source.post_walk_drain_initial_calls = 16;
    source.post_walk_drain_completed_calls = 17;
    source.post_walk_drain_timed_out_calls = 18;
    source.post_walk_drain_deadline_per_call = 19;
    source.post_walk_drain_deadline_program = 20;
    source.post_walk_drain_deadline_extra = 21;

    ProgramPerfSampleV3 wire{};
    perf::StoreWorkerPerfSampleV3(&wire, source);
    const perf::WorkerPerfSample restored =
        perf::LoadWorkerPerfSampleV3(wire);

    for (std::size_t index = 0; index < perf::kWorkerStageCount; ++index) {
        Check(restored.stage_us[index] == source.stage_us[index],
              "wire round-trip lost a worker stage");
    }
    Check(restored.child_entry_ts_us == source.child_entry_ts_us &&
              restored.runtime_start_ts_us == source.runtime_start_ts_us &&
              restored.runtime_end_ts_us == source.runtime_end_ts_us &&
              restored.result_ready_ts_us == source.result_ready_ts_us,
          "wire round-trip lost timeline timestamps");
    Check(restored.calls == source.calls &&
              restored.copyins == source.copyins &&
              restored.copyouts == source.copyouts &&
              restored.kcov_resets == source.kcov_resets &&
              restored.kcov_collects == source.kcov_collects &&
              restored.remote_kcov_settles ==
                  source.remote_kcov_settles &&
              restored.cov_entries == source.cov_entries &&
              restored.cov_taken == source.cov_taken &&
              restored.blocked_calls == source.blocked_calls &&
              restored.output_len == source.output_len &&
              restored.backend_status == source.backend_status &&
              restored.post_walk_drain_programs ==
                  source.post_walk_drain_programs &&
              restored.post_walk_drain_initial_calls ==
                  source.post_walk_drain_initial_calls &&
              restored.post_walk_drain_completed_calls ==
                  source.post_walk_drain_completed_calls &&
              restored.post_walk_drain_timed_out_calls ==
                  source.post_walk_drain_timed_out_calls &&
              restored.post_walk_drain_deadline_per_call ==
                  source.post_walk_drain_deadline_per_call &&
              restored.post_walk_drain_deadline_program ==
                  source.post_walk_drain_deadline_program &&
              restored.post_walk_drain_deadline_extra ==
                  source.post_walk_drain_deadline_extra,
          "wire round-trip lost worker counters");
}

} // namespace

int main()
{
    TestLoopStagesAreAdditive();
    TestCriticalPathBreakdown();
    TestWireRoundTripPreservesStages();
    return 0;
}
