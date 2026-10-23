#pragma once

// NoopHealthMonitor — IHealthMonitor 的空实现（v3.5 Phase G）
//
// 供 MockAssembler 使用：不启动任何线程，所有方法均无操作。
// 设计来源：docs/channel-redesign/v3.5/160_phase_G_health_recovery.md §G.3

#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/core/channel_contract.hpp"

#include <memory>

namespace refuzz::channel::health {

class NoopHealthMonitor final : public IHealthMonitor {
public:
    Result<void> Start() override { return Result<void>::Ok(); }
    void         Stop() noexcept override {}

    // Phase J：接口统一的 AddSensor；Noop 语义下直接 drop unique_ptr。
    void AddSensor(std::unique_ptr<IHealthSensor>) override {}

    void BindChannelSignals(HealthMonitorView) noexcept override {}
    void SetWorkerAlive(uint32_t, bool) noexcept override {}
    void RearmSingleWorker(uint32_t) override {}

    bool                    HasPendingCrashEvents() const noexcept override { return false; }
    std::vector<CrashEvent> DrainCrashEvents() override { return {}; }

    void SuspendMonitoring() override {}
    void ResumeMonitoring()  override {}

    Result<void> Reboot() override { return Result<void>::Ok(); }

    refuzz::core::channel_contract::HealthMonitorSnapshot GetSnapshot() const override {
        return {};
    }
};

} // namespace refuzz::channel::health
