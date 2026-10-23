#pragma once

#include "worker/backend/exec_backend.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/coverage/kcov_drain_sink.hpp"
#include "worker/observation/observation_bus.hpp"

#include <memory>
#include <variant>

namespace refuzz::worker {

struct DaemonOwnedExecutionComponents {
    std::unique_ptr<IExecBackend> backend;
    std::unique_ptr<IObservationBus> bus;
    std::unique_ptr<IKcovCollectorProvider> null_kcov_provider;
    std::unique_ptr<IKcovDrainSink> null_kcov_drain_sink;

    explicit operator bool() const {
        return backend != nullptr && bus != nullptr;
    }
};

struct ExecRebuiltExecutionComponents {};

using WorkerExecutionComponents = std::variant<
    ExecRebuiltExecutionComponents,
    DaemonOwnedExecutionComponents>;

} // namespace refuzz::worker
