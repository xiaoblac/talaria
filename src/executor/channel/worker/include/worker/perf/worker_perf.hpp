#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

struct ProgramPerfSampleV3;

namespace refuzz::worker::perf {

enum class LoopStage : uint8_t {
    kPrepare,
    kExecutor,
    kDelivery,
    kCleanup,
    kCount,
};

enum class ParentStage : uint8_t {
    kPrepare,
    kIsolation,
    kWatch,
    kWaitForChild,
    kReclamation,
    kResult,
    kCount,
};

enum class WorkerStage : uint8_t {
    kChildBootstrap,
    kChildRuntime,
    kRuntimePrepare,
    kExecuteTask,
    kRuntimeFinalize,
    kResultPublish,
    kObservationStart,
    kBackendExecute,
    kProgramFdCleanup,
    kObservationEnd,
    kFeedbackPack,
    kDriverTotal,
    kDriverDecode,
    kScratchPrepare,
    kScratchClear,
    kWireWalk,
    kPostWalkDrain,
    kTaskCleanup,
    kCopyIn,
    kCopyOut,
    kArgResolve,
    kFaultInject,
    kFaultCheck,
    kDispatch,
    kKcovReset,
    kKcovCollect,
    kCoveragePack,
    kRemoteKcovSettleSleep,
    kThreadSchedule,
    kThreadWait,
    kThreadBlockWait,
    kThreadPoll,
    kThreadWorker,
    kKcovBegin,
    kThreadPickup,
    kThreadDone,
    kCount,
};

enum class ProgramStage : uint8_t {
    kIsolation,
    kChildSetup,
    kExecution,
    kResultPublish,
    kCompletion,
    kReclamation,
    kResult,
    kCount,
};

inline constexpr std::size_t kLoopStageCount =
    static_cast<std::size_t>(LoopStage::kCount);
inline constexpr std::size_t kParentStageCount =
    static_cast<std::size_t>(ParentStage::kCount);
inline constexpr std::size_t kWorkerStageCount =
    static_cast<std::size_t>(WorkerStage::kCount);
inline constexpr std::size_t kProgramStageCount =
    static_cast<std::size_t>(ProgramStage::kCount);

struct LoopPerfSample {
    std::array<uint64_t, kLoopStageCount> stage_us{};
    uint64_t input_bytes = 0;
    uint64_t output_bytes = 0;
};

struct WorkerPerfSample {
    std::array<uint64_t, kWorkerStageCount> stage_us{};

    uint64_t child_entry_ts_us = 0;
    uint64_t runtime_start_ts_us = 0;
    uint64_t runtime_end_ts_us = 0;
    uint64_t result_ready_ts_us = 0;

    uint32_t calls = 0;
    uint32_t copyins = 0;
    uint32_t copyouts = 0;
    uint32_t kcov_resets = 0;
    uint32_t kcov_collects = 0;
    uint32_t remote_kcov_settles = 0;
    uint32_t cov_entries = 0;
    uint32_t cov_taken = 0;
    uint32_t blocked_calls = 0;
    uint32_t output_len = 0;
    int32_t backend_status = 0;

    uint32_t post_walk_drain_programs = 0;
    uint32_t post_walk_drain_initial_calls = 0;
    uint32_t post_walk_drain_completed_calls = 0;
    uint32_t post_walk_drain_timed_out_calls = 0;
    uint32_t post_walk_drain_deadline_per_call = 0;
    uint32_t post_walk_drain_deadline_program = 0;
    uint32_t post_walk_drain_deadline_extra = 0;
};

struct ParentPerfSample {
    std::array<uint64_t, kParentStageCount> stage_us{};
    uint64_t total_us = 0;
    uint64_t fork_start_ts_us = 0;
    uint64_t child_reaped_ts_us = 0;
    uint64_t fork_cpu_us = 0;
    uint64_t fork_offcpu_us = 0;

    uint32_t timed_out = 0;
    uint32_t result_read = 0;
    uint32_t no_result = 0;
    uint32_t partial_shmem = 0;
    uint32_t output_len = 0;
    int32_t status = 0;
    uint32_t pidfd_used = 0;
    uint32_t fork_cpu_valid = 0;
};

struct ProgramPerfSample {
    LoopPerfSample loop;
    ParentPerfSample parent;
    WorkerPerfSample child;
    bool parent_valid = false;
    bool child_valid = false;
};

struct ProgramStageBreakdown {
    std::array<uint64_t, kProgramStageCount> stage_us{};
    uint64_t total_us = 0;
    bool valid = false;
};

constexpr std::size_t StageIndex(LoopStage stage)
{
    return static_cast<std::size_t>(stage);
}

constexpr std::size_t StageIndex(ParentStage stage)
{
    return static_cast<std::size_t>(stage);
}

constexpr std::size_t StageIndex(WorkerStage stage)
{
    return static_cast<std::size_t>(stage);
}

constexpr std::size_t StageIndex(ProgramStage stage)
{
    return static_cast<std::size_t>(stage);
}

uint64_t NowUs();
uint64_t ThreadCpuNowUs();

void Configure(bool enabled, uint32_t sample_rate, uint32_t report_every);
bool Enabled();
uint32_t SampleRate();
uint32_t ReportEvery();
bool ShouldSample(uint64_t sequence);

uint64_t StageValue(const LoopPerfSample& sample, LoopStage stage);
uint64_t StageValue(const ParentPerfSample& sample, ParentStage stage);
uint64_t StageValue(const WorkerPerfSample& sample, WorkerStage stage);
void AddStage(LoopPerfSample* sample, LoopStage stage, uint64_t elapsed_us);
void AddStage(ParentPerfSample* sample, ParentStage stage, uint64_t elapsed_us);
void AddStage(WorkerPerfSample* sample, WorkerStage stage, uint64_t elapsed_us);
uint64_t LoopActiveUs(const LoopPerfSample& sample);
ProgramStageBreakdown BuildProgramStageBreakdown(
    const ProgramPerfSample& sample);

const char* LoopStageName(LoopStage stage);
const char* ParentStageName(ParentStage stage);
const char* WorkerStageName(WorkerStage stage);
const char* ProgramStageName(ProgramStage stage);

void RecordProgramSample(uint32_t worker_id, const ProgramPerfSample& sample);

void StoreWorkerPerfSampleV3(ProgramPerfSampleV3* dst,
                             const WorkerPerfSample& src);
WorkerPerfSample LoadWorkerPerfSampleV3(const ProgramPerfSampleV3& src);

WorkerPerfSample* CurrentSample();
void SetCurrentSample(WorkerPerfSample* sample);

class ScopedCurrentSample {
public:
    explicit ScopedCurrentSample(WorkerPerfSample* sample);
    ~ScopedCurrentSample();

    ScopedCurrentSample(const ScopedCurrentSample&) = delete;
    ScopedCurrentSample& operator=(const ScopedCurrentSample&) = delete;

private:
    WorkerPerfSample* previous_;
};

class ScopedTimer {
public:
    ScopedTimer(WorkerPerfSample* sample, WorkerStage stage);
    ~ScopedTimer();

    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

private:
    WorkerPerfSample* sample_;
    WorkerStage stage_;
    uint64_t start_us_;
};

class ParentStageTimeline {
public:
    explicit ParentStageTimeline(ParentPerfSample* sample);
    ~ParentStageTimeline();

    ParentStageTimeline(const ParentStageTimeline&) = delete;
    ParentStageTimeline& operator=(const ParentStageTimeline&) = delete;

    void Transition(ParentStage stage);
    void Finish();

private:
    ParentPerfSample* sample_;
    ParentStage stage_;
    uint64_t total_start_us_;
    uint64_t stage_start_us_;
};

class RuntimeStageTimeline {
public:
    explicit RuntimeStageTimeline(WorkerPerfSample* sample);
    ~RuntimeStageTimeline();

    RuntimeStageTimeline(const RuntimeStageTimeline&) = delete;
    RuntimeStageTimeline& operator=(const RuntimeStageTimeline&) = delete;

    void Transition(WorkerStage stage);
    void Finish();

private:
    WorkerPerfSample* sample_;
    WorkerStage stage_;
    uint64_t total_start_us_;
    uint64_t stage_start_us_;
};

void AddSaturating(uint32_t* dst, uint64_t value);

} // namespace refuzz::worker::perf
