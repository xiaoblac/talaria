#pragma once

// [v3 Phase 5] VmAliveSensor — VM 存活探测 Sensor
//
// 设计来源：docs/channel-redesign/v3/50_health.md §4.3
//
// 职责：
//   - 后台线程周期性调用注入的 std::function<bool()>；返回 false 时 Publish kVmDead；
//     聚合前进时钟冻结超阈值时 Publish kNoOutput（forward-progress frozen）
//   - 与 VM 底座类型完全解耦：KVM / QEMU / 本地进程 均可提供自己的 is_alive closure
//
// 设计取舍：
//   - 不持有 runtime::Runtime* 或 substrate 指针；仅持 closure（lambda 捕获）
//   - 每 Suspend/Resume 周期内最多上报一次 VM 级事件（reported 标志）；Resume 时重置
//
// 线程安全：
//   - Start / Stop / Poke 由 HealthMonitor 串行调用
//   - is_alive closure 由调用方保证线程安全

#include "refuzz/channel/evidence/progress_clock.hpp"
#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>
#include <thread>

namespace refuzz::channel::health {

struct VmAliveSensorConfig {
    std::chrono::milliseconds check_interval{1'000};
    // [检测器 A] 聚合前进时钟冻结超过此值且 qemu 仍在 → 推断 no-output
    //   （kNoOutput, inferred）——与 qemu 进程死亡的 kVmDead（佐证）区分。
    //   死亡尺度，必须 ≫ 最坏的合法全局停顿（2 vCPU + KASAN 下的重 mount 等），
    //   起步 30s，实测调。0 = 关闭聚合冻结检测（仅保留 qemu 退出的佐证检测）。
    std::chrono::milliseconds vm_dead_timeout{30'000};
};

class VmAliveSensor final : public IHealthSensor {
public:
    // 构造：注入 is_alive closure（真正判断 VM 活着的动作）+ 可选聚合前进时钟。
    // closure 必须线程安全，可在任意时刻被后台线程调用。
    // progress_clock（检测器 A 读方）：非空时启用"聚合冻结超 vm_dead_timeout → 推断
    //   VM 死"；空时仅保留 qemu 退出的佐证检测（无聚合时钟的后端）。
    VmAliveSensor(std::function<bool()>     is_alive,
                  VmAliveSensorConfig       config,
                  evidence::ProgressClock*  progress_clock = nullptr) noexcept;

    ~VmAliveSensor() override;

    VmAliveSensor(const VmAliveSensor&)            = delete;
    VmAliveSensor& operator=(const VmAliveSensor&) = delete;

    std::string_view Name() const override { return "vm_alive"; }

    Result<void> Start(HealthPublisher& publisher) override;
    void         Stop() override;
    void         Poke() override;

private:
    void ThreadMain();

    std::function<bool()>     is_alive_;
    VmAliveSensorConfig       config_;
    HealthPublisher*          publisher_ = nullptr;
    // 检测器 A — 共享聚合前进时钟（Channel 拥有，只读）。
    evidence::ProgressClock*  progress_clock_ = nullptr;

    std::thread             thread_;
    std::atomic<bool>       stop_flag_{false};
    std::condition_variable cv_;
    std::mutex              cv_mutex_;
    bool                    thread_running_ = false;
};

} // namespace refuzz::channel::health
