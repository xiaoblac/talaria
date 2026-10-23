#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/periodic_sample_gate.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>

namespace refuzz::telemetry {

// Periodic append-only export of completed job counters.
//
// Output path:
//   <logs_dir>/stats.txt
//
// The file intentionally carries no wall-clock timestamp. Periodic rows are
// labelled by the actual elapsed second at which the sample was taken. A late
// poll writes one current row and never backfills historical windows.
class FuzzerStatsSink {
public:
    static constexpr const char* kFilename = "stats.log";
    // key=value 每 window 一行(自描述,无需列头映射);仅一行 interval 注释。
    // t=<HH:MM:SS> 是采样时刻的墙钟本地时间(与 coverage_series.log 同口径);
    // final=1 那行 = shutdown 时刻。间隔判定仍走 steady_clock 门(60s)。
    static constexpr const char* kHeader =
        "# fuzzer job stats — key=value per window; t=<HH:MM:SS>; interval_s=60\n"
        "# xxx_task = 已收到 executor 真实 completion 的 fuzz task 数量(task 粒度,不是 job\n"
        "#   粒度,且严格 completion-side:只在结果真的回来后才 +1)。一个 job 可能发出多个\n"
        "#   task(triage/minimize/smash 一个 job 内部多次串行 re-exec,一次一个,等完成再发下一个)。\n"
        "# xxx_completed = xxx_job 本身完成(跑完整条链路)的数量,是 job 粒度,不是 task 粒度,\n"
        "#   跟同名 xxx_task 不是同一个分母,不能直接相除当命中率看。\n"
        "# xxx_job = 当前 inflight stackful job 数量(point-in-time gauge)。\n";

    explicit FuzzerStatsSink(
        std::filesystem::path logs_dir,
        std::chrono::steady_clock::time_point start_steady =
            std::chrono::steady_clock::now());

    void MaybeFlush(
        std::chrono::steady_clock::time_point now,
        std::chrono::system_clock::time_point now_wall,
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);
    void FlushFinal(
        std::chrono::steady_clock::time_point now,
        std::chrono::system_clock::time_point now_wall,
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);

    bool Degraded() const noexcept { return degraded_; }
    const std::filesystem::path& OutputPath() const noexcept { return output_path_; }

private:
    struct Snapshot {
        // per-job task_completed。
        std::uint64_t triage = 0;         // fuzzer.triage/task_completed
        std::uint64_t minimize = 0;       // fuzzer.minimize/task_completed
        std::uint64_t hints = 0;          // fuzzer.hints/task_completed
        std::uint64_t fault_inject = 0;   // fuzzer.fault_inject/task_completed
        // [smash observability] tier-aware arbitration 下 smash 档跟 hints/fault 共享同一个
        // Smash tier;smash_completed 要一个 seed 的 25 轮全部正常跑完才 +1,长期挂 0 时看不出
        // smash 到底有没有被 arbiter 选中过 —— smash(task_completed)逐变体 ctx.exec()
        // completion 后才 +1,是可信的细粒度信号,能单独看出 smash 的真实调度/执行节奏。
        std::uint64_t smash = 0;          // fuzzer.smash/task_completed
        std::uint64_t collide = 0;        // fuzzer.exec_collide (per-hit async-collide)
        // job outcome counters (cumulative)。
        std::uint64_t triage_completed = 0;   // fuzzer.triage/completed (finalized: stable+flaky)
        std::uint64_t triage_admit = 0;        // fuzzer.triage/admit_stable
        std::uint64_t triage_drop = 0;         // fuzzer.triage/drop_flaky
        std::uint64_t minimize_completed = 0;  // fuzzer.minimize/completed
        std::uint64_t smash_completed = 0;     // fuzzer.smash/completed (bursts finished)
        std::uint64_t hints_completed = 0;     // fuzzer.hints/completed (reached 3-of-3)
        // inflight gauges (point-in-time)。
        std::int64_t triage_job = 0;    // gauge fuzzer.triage_job
        std::int64_t minimize_job = 0;  // gauge fuzzer.minimize_job
        std::int64_t smash_job = 0;     // gauge fuzzer.smash_job
        std::int64_t hints_job = 0;     // gauge fuzzer.hints_job
        std::int64_t fault_job = 0;     // gauge fuzzer.fault_job
    };

    static Snapshot Collect(
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);
    bool WriteRow(std::chrono::system_clock::time_point now_wall, bool final,
                  const Snapshot& s);
    bool HeaderNeeded() const;

    std::filesystem::path output_path_;
    PeriodicSampleGate sample_gate_;
    bool header_checked_ = false;
    bool header_written_ = false;
    bool degraded_ = false;
};

} // namespace refuzz::telemetry
