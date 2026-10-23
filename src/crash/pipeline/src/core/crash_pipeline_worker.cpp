#include "refuzz/crash/pipeline/core/crash_pipeline_worker.hpp"
#include "refuzz/logging/host_logger.hpp"

#include <utility>

namespace refuzz::crash {

CrashPipelineWorker::CrashPipelineWorker(refuzz::queue::InMemoryCrashQueue& queue,
                                         CrashPipelineManager& manager,
                                         std::chrono::milliseconds pop_timeout)
    : queue_(queue)
    , manager_(manager)
    , pop_timeout_(pop_timeout)
{}

CrashPipelineWorker::~CrashPipelineWorker()
{
    Stop();
}

void CrashPipelineWorker::Start()
{
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    thread_ = std::thread([this]() { Worker(); });
}

void CrashPipelineWorker::Stop()
{
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    // 主动唤醒阻塞中的 Pop，不依赖 pop_timeout_ 到期
    queue_.Close();
    if (thread_.joinable()) {
        thread_.join();
    }
}

uint64_t CrashPipelineWorker::ProcessedCount() const
{
    return processed_count_.load(std::memory_order_acquire);
}

void CrashPipelineWorker::Worker()
{
    while (running_.load(std::memory_order_acquire)) {
        auto event = queue_.Pop(pop_timeout_);
        if (!event.has_value()) {
            continue;
        }
        const uint32_t channel_id = event->fault_event.has_value()
            ? event->fault_event->channel_id
            : 0;
        refuzz::logging::HostLogger::Instance().Log(
            "CrashPipeline",
            "crash_consume_begin",
            {refuzz::logging::Field("incident_id", event->incident_id),
             refuzz::logging::Field("channel_id", channel_id),
             refuzz::logging::Field("has_crash_program", event->crash_program.has_value()),
             refuzz::logging::Field("history_count", static_cast<uint64_t>(event->history.size()))});
        manager_.Process(*event);
        processed_count_.fetch_add(1, std::memory_order_relaxed);
    }

    while (true) {
        auto event = queue_.Pop(std::chrono::milliseconds::zero());
        if (!event.has_value()) {
            break;
        }
        const uint32_t channel_id = event->fault_event.has_value()
            ? event->fault_event->channel_id
            : 0;
        refuzz::logging::HostLogger::Instance().Log(
            "CrashPipeline",
            "crash_consume_begin",
            {refuzz::logging::Field("incident_id", event->incident_id),
             refuzz::logging::Field("channel_id", channel_id),
             refuzz::logging::Field("has_crash_program", event->crash_program.has_value()),
             refuzz::logging::Field("history_count", static_cast<uint64_t>(event->history.size()))});
        manager_.Process(*event);
        processed_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace refuzz::crash
