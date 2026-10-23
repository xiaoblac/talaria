#include "refuzz/control/job/core_path_job.hpp"
#include "refuzz/control/job/job_scheduler.hpp"
#include "refuzz/control/loop/minimize_admit.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/program/raw_bytes_artifact.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace refuzz::control::job {
struct JobTestAccess {
    static void Launch(Job& job) { job.Launch(); }
    static bool Suspended(const Job& job) { return job.SuspendedWithRequest(); }
    static Request TakeRequest(Job& job) { return job.TakePendingRequest(); }
    static void Deliver(Job& job, ExecResult result) {
        job.Deliver(std::move(result));
    }
    static bool Done(const Job& job) { return job.Done(); }
    static void JoinDone(Job& job) { job.JoinDone(); }
    static std::vector<std::function<void()>> TakeRetains(Job& job) {
        return job.TakeRetains();
    }
};
}  // namespace refuzz::control::job

namespace {

using refuzz::control::CorePathChasedCall;
using refuzz::control::CorePathJobConfig;
using refuzz::control::MakeCorePathDiscoverySample;
using refuzz::control::MakeCorePathJob;
using refuzz::control::MinimizeDriver;
using refuzz::control::job::ExecResult;
using refuzz::control::job::Job;
using Access = refuzz::control::job::JobTestAccess;

ExecResult StableResult()
{
    ExecResult result;
    result.signal_hashes = {42};
    result.per_call.push_back({
        .coverage_hashes = {42},
        .edge_hashes = {},
        .novel_signal_hashes = {},
        .errno_value = 0,
        .syscall_id = 100,
        .fault_injected = false,
        .signal_priority = 2,
    });
    return result;
}

std::shared_ptr<refuzz::fuzzer::Seed> MakeSeed()
{
    auto seed = std::make_shared<refuzz::fuzzer::Seed>();
    auto artifact = refuzz::program::MakeRawBytesArtifact(
        {.os = "test", .arch = "test", .revision = "1"}, {1});
    seed->artifact = std::make_shared<const refuzz::program::ProgramArtifact>(
        std::move(artifact));
    return seed;
}

CorePathJobConfig BootConfig(const ExecResult& discovery)
{
    CorePathJobConfig config;
    config.min_runs = 4;
    config.max_runs = 6;
    config.total_runs = 20;
    config.min_votes = 2;
    config.deflake_mode = refuzz::control::DeflakeMode::kBootCorpus;
    config.skip_minimize = true;

    CorePathChasedCall chased;
    chased.call_index = 0;
    chased.new_signal_hashes = {42};
    chased.new_signal_prios = {2};
    chased.errno_value = 0;
    chased.syscall_id = 100;
    config.initial_calls.push_back(std::move(chased));
    config.discovery_sample = MakeCorePathDiscoverySample(discovery);
    return config;
}

template <typename ResultFactory>
int DriveJob(Job& job, ResultFactory&& make_result)
{
    Access::Launch(job);
    int reexecs = 0;
    while (!Access::Done(job)) {
        assert(Access::Suspended(job));
        (void)Access::TakeRequest(job);
        Access::Deliver(job, make_result(reexecs));
        ++reexecs;
    }
    Access::JoinDone(job);
    return reexecs;
}

void TestDiscoveryCountsAsFirstPriorityVote()
{
    auto seed = MakeSeed();

    CorePathJobConfig config;
    config.min_runs = 3;
    config.max_runs = 3;
    config.total_runs = 3;
    config.min_votes = 3;
    config.skip_minimize = true;

    CorePathChasedCall chased;
    chased.call_index = 0;
    chased.new_signal_hashes = {42};
    chased.new_signal_prios = {2};
    chased.errno_value = 0;
    chased.syscall_id = 100;
    config.initial_calls.push_back(std::move(chased));

    const ExecResult discovery = StableResult();
    config.discovery_sample = MakeCorePathDiscoverySample(discovery);

    bool admitted = false;
    config.stable_admit = [&](const refuzz::fuzzer::Seed&, bool) {
        admitted = true;
    };

    auto extract_stable = [](
        const std::vector<std::vector<std::uint64_t>>& runs,
        int min_votes) {
        if (min_votes != 3 || runs.size() < 3) {
            return std::vector<std::uint64_t>{};
        }
        for (const auto& run : runs) {
            if (run != std::vector<std::uint64_t>{42}) {
                return std::vector<std::uint64_t>{};
            }
        }
        return std::vector<std::uint64_t>{42};
    };

    Job job(1, MakeCorePathJob(
                   seed, std::make_shared<MinimizeDriver>(),
                   std::move(extract_stable), {}, std::move(config)));
    const int reexecs = DriveJob(job, [](int) { return StableResult(); });

    assert(reexecs == 2);
    const auto* metadata =
        seed->metadata.Get<refuzz::fuzzer::TriagePerCallCandidateMetadata>();
    assert(metadata != nullptr);
    assert(metadata->candidates.size() == 1);
    assert(metadata->candidates[0].new_stable_signal_prios ==
           std::vector<std::uint8_t>{2});

    for (auto& action : Access::TakeRetains(job)) {
        action();
    }
    assert(admitted);
}

void TestDiscoveryProjectionCarriesPriority()
{
    refuzz::fuzzer::KernelCallObservation call;
    call.coverage_hashes = {42};
    call.errno_value = 0;
    call.syscall_id = 100;
    call.signal_priority = 3;
    refuzz::fuzzer::KernelExecutionObservation observation;
    observation.per_call.push_back(std::move(call));

    refuzz::fuzzer::EngineOutput output;
    output.new_signal_hashes = {42};
    output.observation.Set(std::move(observation));
    refuzz::core::channel_contract::ChannelEvent event;
    event.payload = refuzz::core::channel_contract::Completion{};

    const ExecResult result = refuzz::control::ProjectExecResult(event, &output);
    assert(result.per_call.size() == 1);
    assert(result.per_call[0].signal_priority == 3);
    const auto sample = MakeCorePathDiscoverySample(result);
    assert(!sample.observation.contributes_cover);
    assert(sample.observation.per_call.size() == 1);
    assert(sample.observation.per_call[0].signal_priority == 3);
}

void TestBootStableStopsAtFourTotalSamples()
{
    auto seed = MakeSeed();
    auto config = BootConfig(StableResult());
    auto stable = [](const std::vector<std::vector<std::uint64_t>>&, int) {
        return std::vector<std::uint64_t>{42};
    };
    Job job(2, MakeCorePathJob(
                   seed, std::make_shared<MinimizeDriver>(),
                   std::move(stable), {}, std::move(config)));
    const int reexecs = DriveJob(job, [](int) { return StableResult(); });
    assert(reexecs == 3);
}

void TestBootNoSignalStopsAtSixTotalSamples()
{
    auto seed = MakeSeed();
    auto config = BootConfig(StableResult());
    auto flaky = [](const std::vector<std::vector<std::uint64_t>>&, int) {
        return std::vector<std::uint64_t>{};
    };
    Job job(3, MakeCorePathJob(
                   seed, std::make_shared<MinimizeDriver>(),
                   std::move(flaky), {}, std::move(config)));
    const int reexecs = DriveJob(job, [](int) {
        ExecResult result = StableResult();
        result.signal_hashes.clear();
        result.per_call[0].coverage_hashes.clear();
        return result;
    });
    assert(reexecs == 5);
}

void TestBootNovelSignalExtendsToTwentyTotalSamples()
{
    auto seed = MakeSeed();
    auto config = BootConfig(StableResult());
    auto stable = [](const std::vector<std::vector<std::uint64_t>>&, int) {
        return std::vector<std::uint64_t>{42};
    };
    Job job(4, MakeCorePathJob(
                   seed, std::make_shared<MinimizeDriver>(),
                   std::move(stable), {}, std::move(config)));
    const int reexecs = DriveJob(job, [](int run) {
        ExecResult result = StableResult();
        const std::uint64_t novel = 100 + static_cast<std::uint64_t>(run);
        result.signal_hashes.push_back(novel);
        result.per_call[0].coverage_hashes.push_back(novel);
        result.per_call[0].novel_signal_hashes = {novel};
        return result;
    });
    assert(reexecs == 19);
}

}  // namespace

int main()
{
    TestDiscoveryCountsAsFirstPriorityVote();
    TestDiscoveryProjectionCarriesPriority();
    TestBootStableStopsAtFourTotalSamples();
    TestBootNoSignalStopsAtSixTotalSamples();
    TestBootNovelSignalExtendsToTwentyTotalSamples();
    std::printf("core_path_deflake_test: all checks passed\n");
    return 0;
}
