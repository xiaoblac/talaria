#pragma once

#include "refuzz/crash/pipeline/manager/crash_pipeline_manager.hpp"
#include "refuzz/queue/crash_queue.hpp"

#include <atomic>
#include <chrono>
#include <thread>

namespace refuzz::crash {

class CrashPipelineWorker {
public:
    explicit CrashPipelineWorker(refuzz::queue::InMemoryCrashQueue& queue,
                                 CrashPipelineManager& manager,
                                 std::chrono::milliseconds pop_timeout =
                                     std::chrono::milliseconds(100));
    ~CrashPipelineWorker();

    void Start();
    void Stop();

    uint64_t ProcessedCount() const;

private:
    void Worker();

    refuzz::queue::InMemoryCrashQueue& queue_;
    CrashPipelineManager& manager_;
    std::chrono::milliseconds pop_timeout_{100};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> processed_count_{0};
    std::thread thread_;
};

} // namespace refuzz::crash
