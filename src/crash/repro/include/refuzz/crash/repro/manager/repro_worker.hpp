#pragma once

// ReproWorker — 异步 repro 消费线程
// 从 queue 取 CrashContext，调 ReproManager.Run()，持久化 ReproResult。

#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/repro/manager/repro_manager.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"
#include "refuzz/crash/repro/core/repro_types.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

namespace refuzz::crash {

class ReproWorker {
public:
    explicit ReproWorker(IReproQueue& queue,
                         ReproManager& manager,
                         std::string repros_dir,
                         std::chrono::milliseconds pop_timeout =
                             std::chrono::milliseconds(500));
    ~ReproWorker();

    void Start();
    void Stop();

    uint64_t ProcessedCount() const;
    uint64_t ReproducedCount() const;

private:
    void Worker();
    void PersistResult(const CrashContext& ctx, const ReproResult& result);

    IReproQueue& queue_;
    ReproManager& manager_;
    std::string repros_dir_;
    std::chrono::milliseconds pop_timeout_{500};
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<uint64_t> processed_count_{0};
    std::atomic<uint64_t> reproduced_count_{0};
    std::thread thread_;
};

} // namespace refuzz::crash

