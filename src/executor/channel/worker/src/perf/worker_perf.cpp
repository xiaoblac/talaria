#include "worker/perf/worker_perf.hpp"

#include "worker/log/log_macros.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <algorithm>
#include <array>
#include <ctime>
#include <initializer_list>
#include <limits>

namespace refuzz::worker::perf {

namespace {

thread_local WorkerPerfSample* g_current_sample = nullptr;

struct Config {
    bool enabled;
    uint32_t sample_rate;
    uint32_t report_every;
};

Config& MutableConfig()
{
    static Config cfg{false, 1, 256};
    return cfg;
}

class TimingStat {
public:
    void Add(uint64_t us)
    {
        ++count_;
        sum_ += us;
        max_ = std::max(max_, us);
        ++buckets_[BucketFor(us)];
    }

    uint64_t Avg() const
    {
        return count_ == 0 ? 0 : sum_ / count_;
    }

    uint64_t Pct(uint32_t pct) const
    {
        if (count_ == 0) {
            return 0;
        }
        const uint64_t target = std::max<uint64_t>(
            1, (count_ * static_cast<uint64_t>(pct) + 99) / 100);
        uint64_t seen = 0;
        for (std::size_t index = 0; index < buckets_.size(); ++index) {
            seen += buckets_[index];
            if (seen >= target) {
                return BucketUpper(index);
            }
        }
        return max_;
    }

    uint64_t Count() const { return count_; }
    uint64_t Sum() const { return sum_; }
    uint64_t Max() const { return max_; }

private:
    static constexpr std::size_t kBucketCount = 64;

    static std::size_t BucketFor(uint64_t us)
    {
        std::size_t bucket = 0;
        while (us > 0 && bucket + 1 < kBucketCount) {
            ++bucket;
            us >>= 1;
        }
        return bucket;
    }

    static uint64_t BucketUpper(std::size_t bucket)
    {
        if (bucket == 0) {
            return 0;
        }
        if (bucket >= 63) {
            return std::numeric_limits<uint64_t>::max();
        }
        return (uint64_t{1} << bucket) - 1;
    }

    uint64_t count_ = 0;
    uint64_t sum_ = 0;
    uint64_t max_ = 0;
    std::array<uint64_t, kBucketCount> buckets_{};
};

uint64_t SumStages(const std::initializer_list<uint64_t>& values)
{
    uint64_t total = 0;
    for (const uint64_t value : values) {
        total += value;
    }
    return total;
}

uint64_t Residual(uint64_t total,
                  const std::initializer_list<uint64_t>& children)
{
    const uint64_t child_total = SumStages(children);
    return total > child_total ? total - child_total : 0;
}

uint64_t Delta(uint64_t begin, uint64_t end)
{
    return end >= begin ? end - begin : 0;
}

uint64_t Average(uint64_t total, uint64_t count)
{
    return count == 0 ? 0 : total / count;
}

uint64_t ShareBasisPoints(const TimingStat& stage, const TimingStat& total)
{
    if (total.Sum() == 0) {
        return 0;
    }
    const long double ratio = static_cast<long double>(stage.Sum()) /
                              static_cast<long double>(total.Sum());
    return static_cast<uint64_t>(ratio * 10000.0L);
}

void ReportTiming(uint32_t worker_id,
                  const char* scope,
                  const char* relation,
                  const char* stage_name,
                  const TimingStat& stage,
                  const TimingStat& total)
{
    const uint64_t share_bp = ShareBasisPoints(stage, total);
    ::refuzz::worker::log::WorkerLog(
        "[WorkerPerfStage] wid=%u scope=%s relation=%s stage=%s "
        "n=%llu avg_us=%llu p50_us=%llu p95_us=%llu max_us=%llu "
        "share=%llu.%02llu%%\n",
        worker_id,
        scope,
        relation,
        stage_name,
        static_cast<unsigned long long>(stage.Count()),
        static_cast<unsigned long long>(stage.Avg()),
        static_cast<unsigned long long>(stage.Pct(50)),
        static_cast<unsigned long long>(stage.Pct(95)),
        static_cast<unsigned long long>(stage.Max()),
        static_cast<unsigned long long>(share_bp / 100),
        static_cast<unsigned long long>(share_bp % 100));
}

void ReportTotal(uint32_t worker_id,
                 const char* scope,
                 const TimingStat& total)
{
    ReportTiming(worker_id, scope, "total", "total", total, total);
}

class ProgramPerfAccumulator {
public:
    void Add(uint32_t worker_id, const ProgramPerfSample& sample)
    {
        ++samples_;
        input_bytes_ += sample.loop.input_bytes;
        output_bytes_ += sample.loop.output_bytes;
        max_input_bytes_ = std::max(max_input_bytes_, sample.loop.input_bytes);
        max_output_bytes_ = std::max(max_output_bytes_, sample.loop.output_bytes);

        const uint64_t loop_total = LoopActiveUs(sample.loop);
        loop_total_.Add(loop_total);
        for (std::size_t index = 0; index < kLoopStageCount; ++index) {
            loop_[index].Add(sample.loop.stage_us[index]);
        }

        if (sample.parent_valid) {
            ++parent_samples_;
            timed_out_ += sample.parent.timed_out;
            result_read_ += sample.parent.result_read;
            no_result_ += sample.parent.no_result;
            partial_shmem_ += sample.parent.partial_shmem;
            pidfd_used_ += sample.parent.pidfd_used;
            if (sample.parent.status != 0) {
                ++nonzero_status_;
            }
            parent_total_.Add(sample.parent.total_us);
            uint64_t parent_accounted = 0;
            for (std::size_t index = 0; index < kParentStageCount; ++index) {
                parent_[index].Add(sample.parent.stage_us[index]);
                parent_accounted += sample.parent.stage_us[index];
            }
            parent_residual_.Add(sample.parent.total_us > parent_accounted
                                     ? sample.parent.total_us - parent_accounted
                                     : 0);
            if (sample.parent.fork_cpu_valid != 0) {
                fork_cpu_.Add(sample.parent.fork_cpu_us);
                fork_offcpu_.Add(sample.parent.fork_offcpu_us);
                ++fork_cpu_samples_;
            }
        }

        if (sample.child_valid) {
            ++child_samples_;
            calls_ += sample.child.calls;
            copyins_ += sample.child.copyins;
            copyouts_ += sample.child.copyouts;
            kcov_resets_ += sample.child.kcov_resets;
            kcov_collects_ += sample.child.kcov_collects;
            remote_kcov_settles_ += sample.child.remote_kcov_settles;
            cov_entries_ += sample.child.cov_entries;
            cov_taken_ += sample.child.cov_taken;
            blocked_calls_ += sample.child.blocked_calls;
            post_walk_drain_programs_ +=
                sample.child.post_walk_drain_programs;
            post_walk_drain_initial_calls_ +=
                sample.child.post_walk_drain_initial_calls;
            post_walk_drain_completed_calls_ +=
                sample.child.post_walk_drain_completed_calls;
            post_walk_drain_timed_out_calls_ +=
                sample.child.post_walk_drain_timed_out_calls;
            post_walk_drain_deadline_per_call_ +=
                sample.child.post_walk_drain_deadline_per_call;
            post_walk_drain_deadline_program_ +=
                sample.child.post_walk_drain_deadline_program;
            post_walk_drain_deadline_extra_ +=
                sample.child.post_walk_drain_deadline_extra;
            for (std::size_t index = 0; index < kWorkerStageCount; ++index) {
                child_[index].Add(sample.child.stage_us[index]);
            }

            const uint64_t runtime_total =
                StageValue(sample.child, WorkerStage::kChildRuntime);
            runtime_residual_.Add(Residual(
                runtime_total,
                {StageValue(sample.child, WorkerStage::kRuntimePrepare),
                 StageValue(sample.child, WorkerStage::kExecuteTask),
                 StageValue(sample.child, WorkerStage::kRuntimeFinalize)}));

            const uint64_t task_total =
                StageValue(sample.child, WorkerStage::kExecuteTask);
            task_residual_.Add(Residual(
                task_total,
                {StageValue(sample.child, WorkerStage::kObservationStart),
                 StageValue(sample.child, WorkerStage::kBackendExecute),
                 StageValue(sample.child, WorkerStage::kProgramFdCleanup),
                 StageValue(sample.child, WorkerStage::kObservationEnd),
                 StageValue(sample.child, WorkerStage::kFeedbackPack)}));

            const uint64_t driver_total =
                StageValue(sample.child, WorkerStage::kDriverTotal);
            driver_residual_.Add(Residual(
                driver_total,
                {StageValue(sample.child, WorkerStage::kDriverDecode),
                 StageValue(sample.child, WorkerStage::kScratchPrepare),
                 StageValue(sample.child, WorkerStage::kScratchClear),
                 StageValue(sample.child, WorkerStage::kWireWalk),
                 StageValue(sample.child, WorkerStage::kPostWalkDrain),
                 StageValue(sample.child, WorkerStage::kTaskCleanup)}));

            thread_sync_gap_.Add(Residual(
                StageValue(sample.child, WorkerStage::kThreadWait),
                {StageValue(sample.child, WorkerStage::kThreadWorker)}));
        }

        const ProgramStageBreakdown critical =
            BuildProgramStageBreakdown(sample);
        if (critical.valid) {
            ++critical_samples_;
            critical_total_.Add(critical.total_us);
            for (std::size_t index = 0; index < kProgramStageCount; ++index) {
                critical_[index].Add(critical.stage_us[index]);
            }
        }

        const uint32_t report_every = ReportEvery();
        if (report_every > 0 && samples_ % report_every == 0) {
            Report(worker_id);
        }
    }

private:
    void Report(uint32_t worker_id) const
    {
        ::refuzz::worker::log::WorkerLog(
            "[WorkerPerf] wid=%u samples=%llu parent_samples=%llu "
            "child_samples=%llu critical_samples=%llu nonzero=%llu "
            "timeout=%llu result=%llu missing=%llu partial_shmem=%llu "
            "pidfd=%llu/%llu fork_cpu=%llu/%llu "
            "avg_calls=%llu avg_copyin=%llu "
            "avg_copyout=%llu avg_kcov_reset=%llu avg_kcov_collect=%llu "
            "avg_cov_entries=%llu avg_cov_taken=%llu blocked_calls=%llu "
            "remote_kcov_settles=%llu remote_kcov_sleep_us=%llu "
            "avg_remote_kcov_sleep_us=%llu "
            "avg_in=%llu avg_out=%llu max_in=%llu max_out=%llu\n",
            worker_id,
            static_cast<unsigned long long>(samples_),
            static_cast<unsigned long long>(parent_samples_),
            static_cast<unsigned long long>(child_samples_),
            static_cast<unsigned long long>(critical_samples_),
            static_cast<unsigned long long>(nonzero_status_),
            static_cast<unsigned long long>(timed_out_),
            static_cast<unsigned long long>(result_read_),
            static_cast<unsigned long long>(no_result_),
            static_cast<unsigned long long>(partial_shmem_),
            static_cast<unsigned long long>(pidfd_used_),
            static_cast<unsigned long long>(parent_samples_),
            static_cast<unsigned long long>(fork_cpu_samples_),
            static_cast<unsigned long long>(parent_samples_),
            static_cast<unsigned long long>(Average(calls_, child_samples_)),
            static_cast<unsigned long long>(Average(copyins_, child_samples_)),
            static_cast<unsigned long long>(Average(copyouts_, child_samples_)),
            static_cast<unsigned long long>(Average(kcov_resets_, child_samples_)),
            static_cast<unsigned long long>(Average(kcov_collects_, child_samples_)),
            static_cast<unsigned long long>(Average(cov_entries_, child_samples_)),
            static_cast<unsigned long long>(Average(cov_taken_, child_samples_)),
            static_cast<unsigned long long>(blocked_calls_),
            static_cast<unsigned long long>(remote_kcov_settles_),
            static_cast<unsigned long long>(
                child_[StageIndex(WorkerStage::kRemoteKcovSettleSleep)].Sum()),
            static_cast<unsigned long long>(Average(
                child_[StageIndex(WorkerStage::kRemoteKcovSettleSleep)].Sum(),
                remote_kcov_settles_)),
            static_cast<unsigned long long>(Average(input_bytes_, samples_)),
            static_cast<unsigned long long>(Average(output_bytes_, samples_)),
            static_cast<unsigned long long>(max_input_bytes_),
            static_cast<unsigned long long>(max_output_bytes_));

        ::refuzz::worker::log::WorkerLog(
            "[WorkerPerfDrain] wid=%u child_samples=%llu programs=%llu "
            "initial_calls=%llu completed_calls=%llu timed_out_calls=%llu "
            "deadline_per_call=%llu deadline_program=%llu "
            "deadline_extra=%llu\n",
            worker_id,
            static_cast<unsigned long long>(child_samples_),
            static_cast<unsigned long long>(post_walk_drain_programs_),
            static_cast<unsigned long long>(post_walk_drain_initial_calls_),
            static_cast<unsigned long long>(post_walk_drain_completed_calls_),
            static_cast<unsigned long long>(post_walk_drain_timed_out_calls_),
            static_cast<unsigned long long>(
                post_walk_drain_deadline_per_call_),
            static_cast<unsigned long long>(
                post_walk_drain_deadline_program_),
            static_cast<unsigned long long>(post_walk_drain_deadline_extra_));

        ReportTotal(worker_id, "loop", loop_total_);
        for (std::size_t index = 0; index < kLoopStageCount; ++index) {
            ReportTiming(worker_id,
                         "loop",
                         "exclusive",
                         LoopStageName(static_cast<LoopStage>(index)),
                         loop_[index],
                         loop_total_);
        }

        if (parent_samples_ > 0) {
            ReportTotal(worker_id, "fork_parent", parent_total_);
            for (std::size_t index = 0; index < kParentStageCount; ++index) {
                ReportTiming(worker_id,
                             "fork_parent",
                             "exclusive",
                             ParentStageName(static_cast<ParentStage>(index)),
                             parent_[index],
                             parent_total_);
            }
            ReportTiming(worker_id,
                         "fork_parent",
                         "exclusive",
                         "unattributed",
                         parent_residual_,
                         parent_total_);
            ReportTiming(worker_id,
                         "fork_isolation",
                         "diagnostic",
                         "thread_cpu",
                         fork_cpu_,
                         parent_[StageIndex(ParentStage::kIsolation)]);
            ReportTiming(worker_id,
                         "fork_isolation",
                         "diagnostic",
                         "off_cpu",
                         fork_offcpu_,
                         parent_[StageIndex(ParentStage::kIsolation)]);
        }

        if (critical_samples_ > 0) {
            ReportTotal(worker_id, "critical_path", critical_total_);
            for (std::size_t index = 0; index < kProgramStageCount; ++index) {
                ReportTiming(worker_id,
                             "critical_path",
                             "exclusive",
                             ProgramStageName(static_cast<ProgramStage>(index)),
                             critical_[index],
                             critical_total_);
            }
        }

        if (child_samples_ > 0) {
            const TimingStat& runtime_total =
                child_[StageIndex(WorkerStage::kChildRuntime)];
            ReportTotal(worker_id, "child_runtime", runtime_total);
            ReportChildStage(worker_id, "child_runtime", "exclusive",
                             WorkerStage::kRuntimePrepare, runtime_total);
            ReportChildStage(worker_id, "child_runtime", "exclusive",
                             WorkerStage::kExecuteTask, runtime_total);
            ReportChildStage(worker_id, "child_runtime", "exclusive",
                             WorkerStage::kRuntimeFinalize, runtime_total);
            ReportTiming(worker_id, "child_runtime", "exclusive",
                         "unattributed", runtime_residual_, runtime_total);

            const TimingStat& task_total =
                child_[StageIndex(WorkerStage::kExecuteTask)];
            ReportTotal(worker_id, "execute_task", task_total);
            ReportChildStage(worker_id, "execute_task", "exclusive",
                             WorkerStage::kObservationStart, task_total);
            ReportChildStage(worker_id, "execute_task", "exclusive",
                             WorkerStage::kBackendExecute, task_total);
            ReportChildStage(worker_id, "execute_task", "exclusive",
                             WorkerStage::kProgramFdCleanup, task_total);
            ReportChildStage(worker_id, "execute_task", "exclusive",
                             WorkerStage::kObservationEnd, task_total);
            ReportChildStage(worker_id, "execute_task", "exclusive",
                             WorkerStage::kFeedbackPack, task_total);
            ReportTiming(worker_id, "execute_task", "exclusive",
                         "unattributed", task_residual_, task_total);
            const TimingStat& feedback_total =
                child_[StageIndex(WorkerStage::kFeedbackPack)];
            ReportChildStage(worker_id, "remote_kcov", "nested",
                             WorkerStage::kRemoteKcovSettleSleep,
                             feedback_total);

            const TimingStat& driver_total =
                child_[StageIndex(WorkerStage::kDriverTotal)];
            ReportTotal(worker_id, "driver", driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kDriverDecode, driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kScratchPrepare, driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kScratchClear, driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kWireWalk, driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kPostWalkDrain, driver_total);
            ReportChildStage(worker_id, "driver", "exclusive",
                             WorkerStage::kTaskCleanup, driver_total);
            ReportTiming(worker_id, "driver", "exclusive",
                         "unattributed", driver_residual_, driver_total);

            const TimingStat& wire_total =
                child_[StageIndex(WorkerStage::kWireWalk)];
            for (const WorkerStage stage : {
                     WorkerStage::kCopyIn,
                     WorkerStage::kCopyOut,
                     WorkerStage::kArgResolve,
                     WorkerStage::kFaultInject,
                     WorkerStage::kFaultCheck,
                     WorkerStage::kDispatch,
                     WorkerStage::kKcovReset,
                     WorkerStage::kKcovCollect,
                     WorkerStage::kCoveragePack}) {
                ReportChildStage(worker_id, "wire_detail", "nested",
                                 stage, wire_total);
            }

            for (const WorkerStage stage : {
                     WorkerStage::kThreadSchedule,
                     WorkerStage::kThreadWait,
                     WorkerStage::kThreadBlockWait,
                     WorkerStage::kThreadPoll,
                     WorkerStage::kThreadWorker,
                     WorkerStage::kKcovBegin,
                     WorkerStage::kThreadPickup,
                     WorkerStage::kThreadDone}) {
                ReportChildStage(worker_id, "thread_detail", "diagnostic",
                                 stage, wire_total);
            }
            ReportTiming(worker_id, "thread_detail", "diagnostic",
                         "sync_gap", thread_sync_gap_, wire_total);
        }
    }

    void ReportChildStage(uint32_t worker_id,
                          const char* scope,
                          const char* relation,
                          WorkerStage stage,
                          const TimingStat& total) const
    {
        ReportTiming(worker_id,
                     scope,
                     relation,
                     WorkerStageName(stage),
                     child_[StageIndex(stage)],
                     total);
    }

    uint64_t samples_ = 0;
    uint64_t parent_samples_ = 0;
    uint64_t child_samples_ = 0;
    uint64_t critical_samples_ = 0;
    uint64_t nonzero_status_ = 0;
    uint64_t timed_out_ = 0;
    uint64_t result_read_ = 0;
    uint64_t no_result_ = 0;
    uint64_t partial_shmem_ = 0;
    uint64_t pidfd_used_ = 0;
    uint64_t fork_cpu_samples_ = 0;

    uint64_t calls_ = 0;
    uint64_t copyins_ = 0;
    uint64_t copyouts_ = 0;
    uint64_t kcov_resets_ = 0;
    uint64_t kcov_collects_ = 0;
    uint64_t remote_kcov_settles_ = 0;
    uint64_t cov_entries_ = 0;
    uint64_t cov_taken_ = 0;
    uint64_t blocked_calls_ = 0;
    uint64_t post_walk_drain_programs_ = 0;
    uint64_t post_walk_drain_initial_calls_ = 0;
    uint64_t post_walk_drain_completed_calls_ = 0;
    uint64_t post_walk_drain_timed_out_calls_ = 0;
    uint64_t post_walk_drain_deadline_per_call_ = 0;
    uint64_t post_walk_drain_deadline_program_ = 0;
    uint64_t post_walk_drain_deadline_extra_ = 0;
    uint64_t input_bytes_ = 0;
    uint64_t output_bytes_ = 0;
    uint64_t max_input_bytes_ = 0;
    uint64_t max_output_bytes_ = 0;

    TimingStat loop_total_;
    std::array<TimingStat, kLoopStageCount> loop_{};
    TimingStat parent_total_;
    std::array<TimingStat, kParentStageCount> parent_{};
    TimingStat parent_residual_;
    TimingStat fork_cpu_;
    TimingStat fork_offcpu_;
    TimingStat critical_total_;
    std::array<TimingStat, kProgramStageCount> critical_{};
    std::array<TimingStat, kWorkerStageCount> child_{};
    TimingStat runtime_residual_;
    TimingStat task_residual_;
    TimingStat driver_residual_;
    TimingStat thread_sync_gap_;
};

ProgramPerfAccumulator& Accumulator()
{
    static ProgramPerfAccumulator accumulator;
    return accumulator;
}

constexpr std::array<const char*, kLoopStageCount> kLoopStageNames = {
    "prepare",
    "executor",
    "delivery",
    "cleanup",
};

constexpr std::array<const char*, kParentStageCount> kParentStageNames = {
    "prepare",
    "isolation",
    "watch",
    "wait_for_child",
    "reclamation",
    "result_read",
};

constexpr std::array<const char*, kWorkerStageCount> kWorkerStageNames = {
    "child_bootstrap",
    "child_runtime",
    "runtime_prepare",
    "execute_task",
    "runtime_finalize",
    "result_publish",
    "observation_start",
    "backend_execute",
    "program_fd_cleanup",
    "observation_end",
    "feedback_pack",
    "driver_total",
    "driver_decode",
    "scratch_prepare",
    "scratch_clear",
    "wire_walk",
    "post_walk_drain",
    "task_cleanup",
    "copy_in",
    "copy_out",
    "arg_resolve",
    "fault_inject",
    "fault_check",
    "dispatch",
    "kcov_reset",
    "kcov_collect",
    "coverage_pack",
    "remote_kcov_settle_sleep",
    "thread_schedule",
    "thread_wait",
    "thread_block_wait",
    "thread_poll",
    "thread_worker",
    "kcov_begin",
    "thread_pickup",
    "thread_done",
};

constexpr std::array<const char*, kProgramStageCount> kProgramStageNames = {
    "isolation",
    "child_setup",
    "execution",
    "result_publish",
    "completion",
    "reclamation",
    "result_read",
};

} // namespace

uint64_t NowUs()
{
    struct timespec ts {};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec / 1000);
}

uint64_t ThreadCpuNowUs()
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec / 1000);
}

void Configure(bool enabled, uint32_t sample_rate, uint32_t report_every)
{
    Config& cfg = MutableConfig();
    cfg.enabled = enabled;
    cfg.sample_rate = sample_rate == 0 ? 1 : sample_rate;
    cfg.report_every = report_every == 0 ? 256 : report_every;
}

bool Enabled()
{
    return MutableConfig().enabled;
}

uint32_t SampleRate()
{
    return MutableConfig().sample_rate;
}

uint32_t ReportEvery()
{
    return MutableConfig().report_every;
}

bool ShouldSample(uint64_t sequence)
{
    if (!Enabled()) {
        return false;
    }
    const uint32_t rate = SampleRate();
    return rate <= 1 || ((sequence - 1) % rate) == 0;
}

uint64_t StageValue(const LoopPerfSample& sample, LoopStage stage)
{
    return sample.stage_us[StageIndex(stage)];
}

uint64_t StageValue(const ParentPerfSample& sample, ParentStage stage)
{
    return sample.stage_us[StageIndex(stage)];
}

uint64_t StageValue(const WorkerPerfSample& sample, WorkerStage stage)
{
    return sample.stage_us[StageIndex(stage)];
}

void AddStage(LoopPerfSample* sample, LoopStage stage, uint64_t elapsed_us)
{
    if (sample != nullptr) {
        sample->stage_us[StageIndex(stage)] += elapsed_us;
    }
}

void AddStage(ParentPerfSample* sample, ParentStage stage, uint64_t elapsed_us)
{
    if (sample != nullptr) {
        sample->stage_us[StageIndex(stage)] += elapsed_us;
    }
}

void AddStage(WorkerPerfSample* sample, WorkerStage stage, uint64_t elapsed_us)
{
    if (sample != nullptr) {
        sample->stage_us[StageIndex(stage)] += elapsed_us;
    }
}

uint64_t LoopActiveUs(const LoopPerfSample& sample)
{
    uint64_t total = 0;
    for (const uint64_t elapsed : sample.stage_us) {
        total += elapsed;
    }
    return total;
}

ProgramStageBreakdown BuildProgramStageBreakdown(
    const ProgramPerfSample& sample)
{
    ProgramStageBreakdown result{};
    if (!sample.parent_valid || !sample.child_valid) {
        return result;
    }

    const ParentPerfSample& parent = sample.parent;
    const WorkerPerfSample& child = sample.child;
    if (parent.fork_start_ts_us == 0 || child.child_entry_ts_us == 0 ||
        child.runtime_start_ts_us == 0 || child.runtime_end_ts_us == 0 ||
        child.result_ready_ts_us == 0 || parent.child_reaped_ts_us == 0 ||
        child.child_entry_ts_us < parent.fork_start_ts_us ||
        child.runtime_start_ts_us < child.child_entry_ts_us ||
        child.runtime_end_ts_us < child.runtime_start_ts_us ||
        child.result_ready_ts_us < child.runtime_end_ts_us ||
        parent.child_reaped_ts_us < child.result_ready_ts_us) {
        return result;
    }

    result.stage_us[StageIndex(ProgramStage::kIsolation)] =
        Delta(parent.fork_start_ts_us, child.child_entry_ts_us);
    result.stage_us[StageIndex(ProgramStage::kChildSetup)] =
        Delta(child.child_entry_ts_us, child.runtime_start_ts_us);
    result.stage_us[StageIndex(ProgramStage::kExecution)] =
        Delta(child.runtime_start_ts_us, child.runtime_end_ts_us);
    result.stage_us[StageIndex(ProgramStage::kResultPublish)] =
        Delta(child.runtime_end_ts_us, child.result_ready_ts_us);
    result.stage_us[StageIndex(ProgramStage::kCompletion)] =
        Delta(child.result_ready_ts_us, parent.child_reaped_ts_us);
    result.stage_us[StageIndex(ProgramStage::kReclamation)] =
        StageValue(parent, ParentStage::kReclamation);
    result.stage_us[StageIndex(ProgramStage::kResult)] =
        StageValue(parent, ParentStage::kResult);
    for (const uint64_t elapsed : result.stage_us) {
        result.total_us += elapsed;
    }
    result.valid = true;
    return result;
}

const char* LoopStageName(LoopStage stage)
{
    const std::size_t index = StageIndex(stage);
    return index < kLoopStageNames.size() ? kLoopStageNames[index] : "invalid";
}

const char* ParentStageName(ParentStage stage)
{
    const std::size_t index = StageIndex(stage);
    return index < kParentStageNames.size() ? kParentStageNames[index] : "invalid";
}

const char* WorkerStageName(WorkerStage stage)
{
    const std::size_t index = StageIndex(stage);
    return index < kWorkerStageNames.size() ? kWorkerStageNames[index] : "invalid";
}

const char* ProgramStageName(ProgramStage stage)
{
    const std::size_t index = StageIndex(stage);
    return index < kProgramStageNames.size() ? kProgramStageNames[index] : "invalid";
}

void RecordProgramSample(uint32_t worker_id, const ProgramPerfSample& sample)
{
    Accumulator().Add(worker_id, sample);
}

void StoreWorkerPerfSampleV3(ProgramPerfSampleV3* dst,
                             const WorkerPerfSample& src)
{
    if (dst == nullptr) {
        return;
    }
    dst->child_setup_us = StageValue(src, WorkerStage::kChildBootstrap);
    dst->child_total_us = StageValue(src, WorkerStage::kChildRuntime);
    dst->child_finish_us = StageValue(src, WorkerStage::kResultPublish);
    dst->child_execute_task_us = StageValue(src, WorkerStage::kExecuteTask);
    dst->runtime_prepare_us = StageValue(src, WorkerStage::kRuntimePrepare);
    dst->runtime_finalize_us = StageValue(src, WorkerStage::kRuntimeFinalize);
    dst->bus_task_start_us = StageValue(src, WorkerStage::kObservationStart);
    dst->backend_execute_us = StageValue(src, WorkerStage::kBackendExecute);
    dst->program_fd_cleanup_us =
        StageValue(src, WorkerStage::kProgramFdCleanup);
    dst->bus_session_end_us = StageValue(src, WorkerStage::kObservationEnd);
    dst->bus_pack_us = StageValue(src, WorkerStage::kFeedbackPack);
    dst->remote_kcov_settle_sleep_us =
        StageValue(src, WorkerStage::kRemoteKcovSettleSleep);
    dst->driver_total_us = StageValue(src, WorkerStage::kDriverTotal);
    dst->driver_decode_us = StageValue(src, WorkerStage::kDriverDecode);
    dst->scratch_prepare_us = StageValue(src, WorkerStage::kScratchPrepare);
    dst->scratch_clear_us = StageValue(src, WorkerStage::kScratchClear);
    dst->wire_walk_us = StageValue(src, WorkerStage::kWireWalk);
    dst->post_walk_drain_us = StageValue(src, WorkerStage::kPostWalkDrain);
    dst->task_cleanup_us = StageValue(src, WorkerStage::kTaskCleanup);
    dst->copyin_us = StageValue(src, WorkerStage::kCopyIn);
    dst->copyout_us = StageValue(src, WorkerStage::kCopyOut);
    dst->arg_resolve_us = StageValue(src, WorkerStage::kArgResolve);
    dst->fault_inject_us = StageValue(src, WorkerStage::kFaultInject);
    dst->fault_check_us = StageValue(src, WorkerStage::kFaultCheck);
    dst->dispatch_us = StageValue(src, WorkerStage::kDispatch);
    dst->kcov_reset_us = StageValue(src, WorkerStage::kKcovReset);
    dst->kcov_collect_us = StageValue(src, WorkerStage::kKcovCollect);
    dst->coverage_tail_us = StageValue(src, WorkerStage::kCoveragePack);
    dst->threaded_schedule_us = StageValue(src, WorkerStage::kThreadSchedule);
    dst->threaded_wait_us = StageValue(src, WorkerStage::kThreadWait);
    dst->threaded_block_wait_us = StageValue(src, WorkerStage::kThreadBlockWait);
    dst->threaded_poll_us = StageValue(src, WorkerStage::kThreadPoll);
    dst->worker_total_us = StageValue(src, WorkerStage::kThreadWorker);
    dst->kcov_begin_us = StageValue(src, WorkerStage::kKcovBegin);
    dst->pickup_gap_us = StageValue(src, WorkerStage::kThreadPickup);
    dst->done_gap_us = StageValue(src, WorkerStage::kThreadDone);
    dst->child_entry_ts_us = src.child_entry_ts_us;
    dst->runtime_start_ts_us = src.runtime_start_ts_us;
    dst->runtime_end_ts_us = src.runtime_end_ts_us;
    dst->result_ready_ts_us = src.result_ready_ts_us;
    dst->calls = src.calls;
    dst->copyins = src.copyins;
    dst->copyouts = src.copyouts;
    dst->kcov_resets = src.kcov_resets;
    dst->kcov_collects = src.kcov_collects;
    dst->remote_kcov_settles = src.remote_kcov_settles;
    dst->cov_entries = src.cov_entries;
    dst->cov_taken = src.cov_taken;
    dst->blocked_calls = src.blocked_calls;
    dst->output_len = src.output_len;
    dst->backend_status = src.backend_status;
    dst->post_walk_drain_programs = src.post_walk_drain_programs;
    dst->post_walk_drain_initial_calls =
        src.post_walk_drain_initial_calls;
    dst->post_walk_drain_completed_calls =
        src.post_walk_drain_completed_calls;
    dst->post_walk_drain_timed_out_calls =
        src.post_walk_drain_timed_out_calls;
    dst->post_walk_drain_deadline_per_call =
        src.post_walk_drain_deadline_per_call;
    dst->post_walk_drain_deadline_program =
        src.post_walk_drain_deadline_program;
    dst->post_walk_drain_deadline_extra =
        src.post_walk_drain_deadline_extra;
}

WorkerPerfSample LoadWorkerPerfSampleV3(const ProgramPerfSampleV3& src)
{
    WorkerPerfSample dst{};
    AddStage(&dst, WorkerStage::kChildBootstrap, src.child_setup_us);
    AddStage(&dst, WorkerStage::kChildRuntime, src.child_total_us);
    AddStage(&dst, WorkerStage::kResultPublish, src.child_finish_us);
    AddStage(&dst, WorkerStage::kExecuteTask, src.child_execute_task_us);
    AddStage(&dst, WorkerStage::kRuntimePrepare, src.runtime_prepare_us);
    AddStage(&dst, WorkerStage::kRuntimeFinalize, src.runtime_finalize_us);
    AddStage(&dst, WorkerStage::kObservationStart, src.bus_task_start_us);
    AddStage(&dst, WorkerStage::kBackendExecute, src.backend_execute_us);
    AddStage(&dst, WorkerStage::kProgramFdCleanup,
             src.program_fd_cleanup_us);
    AddStage(&dst, WorkerStage::kObservationEnd, src.bus_session_end_us);
    AddStage(&dst, WorkerStage::kFeedbackPack, src.bus_pack_us);
    AddStage(&dst, WorkerStage::kRemoteKcovSettleSleep,
             src.remote_kcov_settle_sleep_us);
    AddStage(&dst, WorkerStage::kDriverTotal, src.driver_total_us);
    AddStage(&dst, WorkerStage::kDriverDecode, src.driver_decode_us);
    AddStage(&dst, WorkerStage::kScratchPrepare, src.scratch_prepare_us);
    AddStage(&dst, WorkerStage::kScratchClear, src.scratch_clear_us);
    AddStage(&dst, WorkerStage::kWireWalk, src.wire_walk_us);
    AddStage(&dst, WorkerStage::kPostWalkDrain, src.post_walk_drain_us);
    AddStage(&dst, WorkerStage::kTaskCleanup, src.task_cleanup_us);
    AddStage(&dst, WorkerStage::kCopyIn, src.copyin_us);
    AddStage(&dst, WorkerStage::kCopyOut, src.copyout_us);
    AddStage(&dst, WorkerStage::kArgResolve, src.arg_resolve_us);
    AddStage(&dst, WorkerStage::kFaultInject, src.fault_inject_us);
    AddStage(&dst, WorkerStage::kFaultCheck, src.fault_check_us);
    AddStage(&dst, WorkerStage::kDispatch, src.dispatch_us);
    AddStage(&dst, WorkerStage::kKcovReset, src.kcov_reset_us);
    AddStage(&dst, WorkerStage::kKcovCollect, src.kcov_collect_us);
    AddStage(&dst, WorkerStage::kCoveragePack, src.coverage_tail_us);
    AddStage(&dst, WorkerStage::kThreadSchedule, src.threaded_schedule_us);
    AddStage(&dst, WorkerStage::kThreadWait, src.threaded_wait_us);
    AddStage(&dst, WorkerStage::kThreadBlockWait, src.threaded_block_wait_us);
    AddStage(&dst, WorkerStage::kThreadPoll, src.threaded_poll_us);
    AddStage(&dst, WorkerStage::kThreadWorker, src.worker_total_us);
    AddStage(&dst, WorkerStage::kKcovBegin, src.kcov_begin_us);
    AddStage(&dst, WorkerStage::kThreadPickup, src.pickup_gap_us);
    AddStage(&dst, WorkerStage::kThreadDone, src.done_gap_us);
    dst.child_entry_ts_us = src.child_entry_ts_us;
    dst.runtime_start_ts_us = src.runtime_start_ts_us;
    dst.runtime_end_ts_us = src.runtime_end_ts_us;
    dst.result_ready_ts_us = src.result_ready_ts_us;
    dst.calls = src.calls;
    dst.copyins = src.copyins;
    dst.copyouts = src.copyouts;
    dst.kcov_resets = src.kcov_resets;
    dst.kcov_collects = src.kcov_collects;
    dst.remote_kcov_settles = src.remote_kcov_settles;
    dst.cov_entries = src.cov_entries;
    dst.cov_taken = src.cov_taken;
    dst.blocked_calls = src.blocked_calls;
    dst.output_len = src.output_len;
    dst.backend_status = src.backend_status;
    dst.post_walk_drain_programs = src.post_walk_drain_programs;
    dst.post_walk_drain_initial_calls =
        src.post_walk_drain_initial_calls;
    dst.post_walk_drain_completed_calls =
        src.post_walk_drain_completed_calls;
    dst.post_walk_drain_timed_out_calls =
        src.post_walk_drain_timed_out_calls;
    dst.post_walk_drain_deadline_per_call =
        src.post_walk_drain_deadline_per_call;
    dst.post_walk_drain_deadline_program =
        src.post_walk_drain_deadline_program;
    dst.post_walk_drain_deadline_extra =
        src.post_walk_drain_deadline_extra;
    return dst;
}

WorkerPerfSample* CurrentSample()
{
    return g_current_sample;
}

void SetCurrentSample(WorkerPerfSample* sample)
{
    g_current_sample = sample;
}

ScopedCurrentSample::ScopedCurrentSample(WorkerPerfSample* sample)
    : previous_(CurrentSample())
{
    SetCurrentSample(sample);
}

ScopedCurrentSample::~ScopedCurrentSample()
{
    SetCurrentSample(previous_);
}

ScopedTimer::ScopedTimer(WorkerPerfSample* sample, WorkerStage stage)
    : sample_(sample), stage_(stage), start_us_(sample != nullptr ? NowUs() : 0)
{
}

ScopedTimer::~ScopedTimer()
{
    if (sample_ != nullptr) {
        AddStage(sample_, stage_, NowUs() - start_us_);
    }
}

ParentStageTimeline::ParentStageTimeline(ParentPerfSample* sample)
    : sample_(sample), stage_(ParentStage::kPrepare), total_start_us_(0),
      stage_start_us_(0)
{
    if (sample_ != nullptr) {
        total_start_us_ = NowUs();
        stage_start_us_ = total_start_us_;
    }
}

ParentStageTimeline::~ParentStageTimeline()
{
    Finish();
}

void ParentStageTimeline::Transition(ParentStage stage)
{
    if (sample_ == nullptr || stage == stage_) {
        return;
    }
    const uint64_t now = NowUs();
    AddStage(sample_, stage_, now - stage_start_us_);
    stage_ = stage;
    stage_start_us_ = now;
}

void ParentStageTimeline::Finish()
{
    if (sample_ == nullptr) {
        return;
    }
    const uint64_t now = NowUs();
    AddStage(sample_, stage_, now - stage_start_us_);
    sample_->total_us = now - total_start_us_;
    sample_ = nullptr;
}

RuntimeStageTimeline::RuntimeStageTimeline(WorkerPerfSample* sample)
    : sample_(sample), stage_(WorkerStage::kRuntimePrepare), total_start_us_(0),
      stage_start_us_(0)
{
    if (sample_ != nullptr) {
        total_start_us_ = NowUs();
        stage_start_us_ = total_start_us_;
        if (sample_->child_entry_ts_us == 0) {
            sample_->child_entry_ts_us = total_start_us_;
        }
        sample_->runtime_start_ts_us = total_start_us_;
    }
}

RuntimeStageTimeline::~RuntimeStageTimeline()
{
    Finish();
}

void RuntimeStageTimeline::Transition(WorkerStage stage)
{
    if (sample_ == nullptr || stage == stage_) {
        return;
    }
    const uint64_t now = NowUs();
    AddStage(sample_, stage_, now - stage_start_us_);
    stage_ = stage;
    stage_start_us_ = now;
}

void RuntimeStageTimeline::Finish()
{
    if (sample_ == nullptr) {
        return;
    }
    const uint64_t now = NowUs();
    AddStage(sample_, stage_, now - stage_start_us_);
    AddStage(sample_, WorkerStage::kChildRuntime, now - total_start_us_);
    sample_->runtime_end_ts_us = now;
    sample_ = nullptr;
}

void AddSaturating(uint32_t* dst, uint64_t value)
{
    if (dst == nullptr || value == 0) {
        return;
    }
    const uint64_t current = *dst;
    const uint64_t maximum = std::numeric_limits<uint32_t>::max();
    *dst = static_cast<uint32_t>(
        current + value > maximum ? maximum : current + value);
}

} // namespace refuzz::worker::perf
