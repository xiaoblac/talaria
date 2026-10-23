#include "worker/profile/kernel_syz_execution_domain.hpp"

#include "worker/coverage/null_kcov.hpp"
#include "worker/dispatcher/syscall_or_pseudo.hpp"
#include "worker/driver/kernel_wire_driver.hpp"
#include "worker/observation/ivshmem_step_event_sink.hpp"
#include "worker/observation/kcov_sink.hpp"
#include "worker/observation/observation_bus.hpp"

#include <algorithm>

namespace refuzz::worker {

KernelSyzExecutionDomain BuildKernelSyzExecutionDomain(
    const engine::LoopWorkerBootConfig& config,
    StepEventRingHeader* step_event_header,
    StepEventSlot* step_event_slots)
{
    KernelSyzExecutionDomain domain{};
    const uint32_t thread_count = std::clamp(config.thread_count, 1u, 32u);
    auto driver = std::make_unique<KernelWireDriver>(
        std::make_unique<SyscallOrPseudoDispatcher>(),
        config.worker_id,
        nullptr,
        nullptr,
        thread_count);
    driver->SetPerCallTimeoutMs(config.per_call_timeout_ms);
    driver->SetProgramTimeoutMs(config.exec_timeout_ms);

    auto bus = std::make_unique<ObservationBus>();
    const auto coverage_mode = static_cast<CoverageMode>(config.coverage_mode);
    if (coverage_mode == CoverageMode::kKcov) {
        const auto child_mode = config.kcov_child_mode ==
                static_cast<uint32_t>(engine::LoopKcovChildMode::kInheritedFromLoop)
            ? KcovChildMode::kInheritedFromLoop
            : KcovChildMode::kFreshPerProgram;
        auto kcov_sink = std::make_unique<KcovSink>(
            static_cast<int>(thread_count),
            config.kcov_entries,
            static_cast<int>(config.kcov_collector_count),
            static_cast<int>(config.kcov_premap_count),
            config.proc_id + 1u,
            child_mode);
        driver->SetKcovProvider(kcov_sink->provider());
        driver->SetKcovDrainSink(kcov_sink->drain_sink());
        bus->AddSink(std::move(kcov_sink));
    } else if (coverage_mode == CoverageMode::kNone) {
        auto null_provider =
            std::make_unique<NullKcovProvider>(static_cast<int>(thread_count));
        auto null_drain = std::make_unique<NullKcovDrainSink>();
        driver->SetKcovProvider(null_provider.get());
        driver->SetKcovDrainSink(null_drain.get());
        domain.null_kcov_provider = std::move(null_provider);
        domain.null_kcov_drain_sink = std::move(null_drain);
    } else {
        return {};
    }

    if ((config.flags & engine::kLoopBootEnableStepEvents) != 0) {
        if (step_event_header == nullptr || step_event_slots == nullptr ||
            config.step_ring_capacity == 0) {
            return {};
        }
        bus->AddSink(std::make_unique<IvshmemStepEventSink>(
            step_event_header,
            step_event_slots,
            config.step_ring_capacity,
            config.worker_id));
    }

    domain.backend = std::move(driver);
    domain.bus = std::move(bus);
    domain.backend->ConfigureProcId(config.proc_id);
    domain.bus->ConfigureProcId(config.proc_id);
    return domain;
}

} // namespace refuzz::worker
