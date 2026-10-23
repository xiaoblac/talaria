// [v3 Phase 5] VmAliveSensor 实现
//
// 设计来源：docs/channel-redesign/v3/50_health.md §4.3

#include "refuzz/channel/health/vm_alive_sensor.hpp"

#include <chrono>
#include <climits>

namespace refuzz::channel::health {

VmAliveSensor::VmAliveSensor(std::function<bool()>    is_alive,
                             VmAliveSensorConfig       config,
                             evidence::ProgressClock*  progress_clock) noexcept
    : is_alive_(std::move(is_alive))
    , config_(std::move(config))
    , progress_clock_(progress_clock) {
}

VmAliveSensor::~VmAliveSensor() {
    Stop();
}

Result<void> VmAliveSensor::Start(HealthPublisher& publisher) {
    if (thread_running_) {
        return Error{ErrorKind::kInfra,
                     "VmAliveSensor::Start() called while already running"};
    }
    if (!is_alive_) {
        return Error{ErrorKind::kInfra,
                     "VmAliveSensor::Start(): is_alive closure is empty"};
    }
    publisher_ = &publisher;
    stop_flag_.store(false, std::memory_order_relaxed);
    thread_        = std::thread(&VmAliveSensor::ThreadMain, this);
    thread_running_ = true;
    return Result<void>::Ok();
}

void VmAliveSensor::Stop() {
    if (!thread_running_) return;
    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        stop_flag_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    thread_running_ = false;
}

void VmAliveSensor::Poke() {
    cv_.notify_all();
}

static uint64_t NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void VmAliveSensor::ThreadMain() {
    // 每个 Suspend/Resume 周期内最多上报一次 kVmDead；Resume 后重置
    bool reported = false;

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
            reported = false;  // Resume 后允许再次上报
            publisher_->ParkUntilResumed();
            if (stop_flag_.load(std::memory_order_acquire)) return;
            continue;
        }

        // [检测器 A] VM 存活两条判据，每个 Suspend/Resume 周期最多上报一次：
        //   (1) 佐证：is_alive()==false（qemu 进程退出）→ inferred=false，立即 reboot。
        //   (2) 推断：qemu 仍在，但聚合前进时钟冻结超 vm_dead_timeout（所有 worker
        //       都不前进、无 completion）→ kNoOutput + inferred=true，受 recovery
        //       阻尼治理，同时以 no_output bucket 作为可汇报 finding。
        //   per-worker 心跳完全不看 → 对单 worker 饿死天然免疫（只要有一个 worker
        //   在前进，聚合时钟就新鲜，本检测器静默）。
        if (!reported) {
            bool        emit     = false;
            bool        inferred = false;
            const char* title    = "";
            if (!is_alive_()) {
                emit  = true;
                title = "vm process not alive";          // 佐证：qemu 退出
            } else if (config_.vm_dead_timeout.count() > 0 && progress_clock_ != nullptr) {
                const uint64_t last = progress_clock_->LastUs();
                const uint64_t now  = NowUs();
                const uint64_t frozen_ms = (now > last) ? (now - last) / 1000ULL : 0ULL;
                if (frozen_ms >
                    static_cast<uint64_t>(config_.vm_dead_timeout.count())) {
                    emit     = true;
                    inferred = true;
                    title    = "guest forward-progress frozen"; // 推断：聚合冻结
                }
            }

            if (emit) {
                CrashFragment fragment;
                // frozen 是"机器活着但无进展"= no output（推断型）；只有 qemu
                // 进程死亡 / console EOF 才发布 kVmDead（佐证型）。
                fragment.kind             = inferred
                                                ? CrashKind::kNoOutput
                                                : CrashKind::kVmDead;
                fragment.source_worker_id = UINT32_MAX;
                fragment.type             = refuzz::channel::CrashType::kUnknown;
                fragment.title            = title;
                fragment.serial_lines.clear();
                fragment.step_event_snapshot.clear();

                CrashEvent ev;
                ev.event_id       = 0;
                ev.origin         = CrashEventOrigin::kVmLiveness;
                ev.vm_epoch       = 0;
                ev.detected_ts_us = NowUs();
                ev.fragment       = std::move(fragment);
                ev.checker_name.clear();
                ev.errno_value    = 0;
                ev.inferred       = inferred;
                if (publisher_) publisher_->Publish(std::move(ev));
                reported = true;
                // 继续循环；上层会 Suspend→recovery→Resume
            }
        }
    }
}

} // namespace refuzz::channel::health
