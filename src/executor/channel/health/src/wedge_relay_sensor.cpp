// WedgeRelaySensor 实现 — 见头文件设计说明。

#include "refuzz/channel/health/wedge_relay_sensor.hpp"

#include "refuzz/logging/host_logger.hpp"

#include <chrono>
#include <climits>
#include <utility>

namespace refuzz::channel::health {

WedgeRelaySensor::WedgeRelaySensor(std::function<bool()>  consume_wedge,
                                   WedgeRelaySensorConfig config) noexcept
    : consume_wedge_(std::move(consume_wedge))
    , config_(std::move(config)) {
}

WedgeRelaySensor::~WedgeRelaySensor() {
    Stop();
}

Result<void> WedgeRelaySensor::Start(HealthPublisher& publisher) {
    if (thread_running_) {
        return Error{ErrorKind::kInfra,
                     "WedgeRelaySensor::Start() called while already running"};
    }
    if (!consume_wedge_) {
        return Error{ErrorKind::kInfra,
                     "WedgeRelaySensor::Start(): consume_wedge closure is empty"};
    }
    publisher_ = &publisher;
    stop_flag_.store(false, std::memory_order_relaxed);
    thread_         = std::thread(&WedgeRelaySensor::ThreadMain, this);
    thread_running_ = true;
    return Result<void>::Ok();
}

void WedgeRelaySensor::Stop() {
    if (!thread_running_) return;
    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        stop_flag_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    thread_running_ = false;
}

void WedgeRelaySensor::Poke() {
    cv_.notify_all();
}

static uint64_t NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void WedgeRelaySensor::ThreadMain() {
    while (true) {
        {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, config_.check_interval, [this] {
                return stop_flag_.load(std::memory_order_acquire) ||
                       (publisher_ && publisher_->IsSuspended());
            });
        }

        if (stop_flag_.load(std::memory_order_acquire)) return;

        if (publisher_ && publisher_->IsSuspended()) {
            // Recovery 进行中:不消费 wedge flag(留给 ResetAll 清),park 等 resume。
            publisher_->ParkUntilResumed();
            if (stop_flag_.load(std::memory_order_acquire)) return;
            continue;
        }

        if (!consume_wedge_()) {
            continue;  // 没有新 wedge
        }

        const uint64_t now = NowUs();
        refuzz::logging::HostLogger::Instance().Log(
            "WedgeRelaySensor",
            "wedge_relayed",
            {refuzz::logging::Field("worker_id", config_.worker_id),
             refuzz::logging::Field("ts_us", now)});

        CrashFragment fragment;
        fragment.kind             = CrashKind::kWorkerDead;
        fragment.source_worker_id = config_.worker_id;
        fragment.type             = refuzz::channel::CrashType::kUnknown;
        fragment.title            = "xiuos worker wedged: program exceeded budget without RESULT";
        fragment.serial_lines.clear();
        fragment.step_event_snapshot.clear();

        CrashEvent ev;
        ev.event_id       = 0;  // HealthMonitor::Publish 填
        ev.origin         = CrashEventOrigin::kHeartbeat;  // worker 无响应,最贴近的 origin
        ev.vm_epoch       = 0;  // HealthMonitor::Publish 填
        ev.detected_ts_us = now;
        ev.fragment       = std::move(fragment);
        ev.checker_name.clear();
        ev.errno_value    = 0;
        if (publisher_) {
            publisher_->Publish(std::move(ev));
            publisher_->SetWorkerAlive(config_.worker_id, false);
        }
        // 继续循环;上层会 Suspend→recovery(reboot)→Resume,期间 ResetAll 清 flag。
    }
}

} // namespace refuzz::channel::health
