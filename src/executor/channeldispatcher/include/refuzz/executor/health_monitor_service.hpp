#pragma once

#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/core/service.hpp"

namespace refuzz::executor {

// HealthMonitorService — 仅用于 ServiceRegistry 拓扑与 Tier-1 生命周期编排。
//
// 构造时 channel 可能尚未 Boot（HealthMonitor 在 Boot 内创建），故 Init() 在
// ChannelService::Init 之后运行时再 GetHealthMonitor()。
// Stop 不调用 HealthMonitor::Stop()（由 Channel::Close 统一停止）。
//
//构造参数与成员由 `QemuChannel*` 改名为 `Channel*`；
// 源码层面等价（`Channel` 就是旧 `QemuChannel` 的新名字），对非 QEMU 后端（mock
// / vsock / local_process 等不派生自 `Channel` 的 IChannel 实现）调用方应自行
// 判空：`dynamic_cast<Channel*>(ichannel)` 返回 null 就不要装此 service。
class HealthMonitorService : public refuzz::core::IService {
public:
    explicit HealthMonitorService(refuzz::channel::Channel* channel)
        : channel_(channel) {}

    std::string_view Name() const override { return "health_monitor"; }

    refuzz::core::ServiceResult Init() override
    {
        if (channel_ == nullptr) {
            return std::unexpected(
                refuzz::core::ComponentError::Init("health_monitor", "null Channel"));
        }
        monitor_ = channel_->GetHealthMonitor();
        if (monitor_ == nullptr) {
            return std::unexpected(
                refuzz::core::ComponentError::Init("health_monitor", "HealthMonitor not ready after Boot"));
        }
        return {};
    }

    refuzz::core::ServiceResult Start() override
    {
        running_ = true;
        return {};
    }

    refuzz::core::ServiceResult Stop() override
    {
        running_ = false;
        return {};
    }

    bool IsRunning() const override { return running_; }

    refuzz::channel::health::IHealthMonitor* Monitor() const { return monitor_; }

private:
    refuzz::channel::Channel*                channel_ = nullptr;
    refuzz::channel::health::IHealthMonitor* monitor_ = nullptr;
    bool                                     running_ = false;
};

static_assert(refuzz::core::ServiceLike<HealthMonitorService>);

} // namespace refuzz::executor
