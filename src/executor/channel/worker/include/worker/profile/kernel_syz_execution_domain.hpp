#pragma once

#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/profile/execution_components.hpp"

struct StepEventRingHeader;
struct StepEventSlot;

namespace refuzz::worker {

using KernelSyzExecutionDomain = DaemonOwnedExecutionComponents;

KernelSyzExecutionDomain BuildKernelSyzExecutionDomain(
    const engine::LoopWorkerBootConfig& config,
    StepEventRingHeader* step_event_header = nullptr,
    StepEventSlot* step_event_slots = nullptr);

} // namespace refuzz::worker
