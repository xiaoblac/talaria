#include "refuzz/orchestrator/builtins.hpp"

#include "refuzz/crash/repro/repro_worker_service.hpp"
#include "refuzz/executor/channel_service.hpp"
#include "refuzz/executor/health_monitor_service.hpp"
#include "refuzz/telemetry/telemetry_service.hpp"
#include "channeldispatcher.hpp"

namespace refuzz::orchestrator {

void RegisterBuiltinServices(
    refuzz::core::ServiceRegistry& registry,
    std::vector<std::unique_ptr<refuzz::executor::ChannelService>>& required_channel_services,
    std::vector<std::unique_ptr<refuzz::executor::ChannelService>>& optional_channel_services,
    refuzz::channeldispatcher::Executor& executor,
    const std::vector<std::string_view>& executor_dep_channel_names,
    std::unique_ptr<refuzz::executor::HealthMonitorService> health_monitor,
    std::unique_ptr<refuzz::crash::ReproWorkerService> repro_worker,
    std::unique_ptr<refuzz::telemetry::TelemetryService> telemetry)
{
    std::vector<std::string_view> executor_deps = executor_dep_channel_names;
    if (required_channel_services.size() + optional_channel_services.size() > 1) {
        registry.Register(
            std::make_unique<refuzz::executor::ChannelGroupService>(
                "channels",
                std::move(required_channel_services),
                std::move(optional_channel_services)));
        executor_deps = {"channels"};
    } else {
        for (auto& ch : required_channel_services) {
            if (ch) {
                registry.Register(std::move(ch));
            }
        }
    }
    required_channel_services.clear();
    optional_channel_services.clear();

    registry.RegisterBorrowed(&executor, executor_deps);

    bool have_health = false;
    if (health_monitor) {
        registry.Register(std::move(health_monitor), {"executor"});
        have_health = true;
    }

    bool have_repro = false;
    if (repro_worker) {
        if (have_health) {
            registry.Register(std::move(repro_worker), {"health_monitor"});
        } else {
            registry.Register(std::move(repro_worker), {"executor"});
        }
        have_repro = true;
    }

    if (telemetry) {
        if (have_repro) {
            registry.Register(std::move(telemetry), {"repro_worker"});
        } else if (have_health) {
            registry.Register(std::move(telemetry), {"health_monitor"});
        } else {
            registry.Register(std::move(telemetry), {"executor"});
        }
    }
}

} // namespace refuzz::orchestrator
