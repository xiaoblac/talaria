#pragma once

#include "refuzz/channel/result.hpp"

#include <chrono>
#include <cstdint>

namespace refuzz::channel::control { class IControlPlane; }
namespace refuzz::channel::runtime { class ISubstrate; }

namespace refuzz::channel::internal {

Result<void> StartWorkersAndWaitReady(
    runtime::ISubstrate& substrate,
    control::IControlPlane& control_plane,
    uint32_t vm_index,
    uint32_t worker_count,
    std::chrono::milliseconds timeout);

} // namespace refuzz::channel::internal
