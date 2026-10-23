#pragma once

#include "refuzz/core/service_registry.hpp"

#include <memory>
#include <vector>

namespace refuzz::channeldispatcher {
class Executor;
}

namespace refuzz::executor {
class ChannelService;
class HealthMonitorService;
} // namespace refuzz::executor

namespace refuzz::telemetry {
class TelemetryService;
}

namespace refuzz::crash {
class ReproWorkerService;
}

namespace refuzz::orchestrator {

// 显式注册 Tier-1 Service（避免 control ↔ telemetry 循环依赖；实现于 control/orchestrator）。
void RegisterBuiltinServices(
    refuzz::core::ServiceRegistry& registry,
    std::vector<std::unique_ptr<refuzz::executor::ChannelService>>& required_channel_services,
    std::vector<std::unique_ptr<refuzz::executor::ChannelService>>& optional_channel_services,
    refuzz::channeldispatcher::Executor& executor,
    const std::vector<std::string_view>& executor_dep_channel_names,
    std::unique_ptr<refuzz::executor::HealthMonitorService> health_monitor,
    std::unique_ptr<refuzz::crash::ReproWorkerService> repro_worker,
    std::unique_ptr<refuzz::telemetry::TelemetryService> telemetry);

} // namespace refuzz::orchestrator
