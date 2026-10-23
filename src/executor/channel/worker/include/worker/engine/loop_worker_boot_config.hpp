#pragma once

#include "worker/program_buffers.hpp"

#include <cstdint>
#include <type_traits>

namespace refuzz::worker::engine {

inline constexpr uint32_t kLoopWorkerBootMagic = 0x52465a45u; // RFZE
inline constexpr uint16_t kLoopWorkerBootVersion = 1;

enum LoopWorkerBootFlags : uint32_t {
    kLoopBootEnableStepEvents = 1u << 0,
    kLoopBootEnableWorkerLog = 1u << 1,
    kLoopBootEnableWorkerPerf = 1u << 2,
    kLoopBootAllowNoPrivateMountNamespaceForTests = 1u << 3,
};

enum class LoopKcovChildMode : uint32_t {
    kFreshPerProgram = 0,
    kInheritedFromLoop = 1,
};

struct LoopWorkerBootConfig {
    uint32_t magic = kLoopWorkerBootMagic;
    uint16_t version = kLoopWorkerBootVersion;
    uint16_t size = 0;

    uint32_t worker_id = 0;
    uint32_t proc_id = 0;
    uint32_t proc_epoch = 0;
    uint32_t profile_id = 0;

    uint32_t sandbox_mode = 0;
    uint32_t coverage_mode = 0;
    uint32_t thread_count = 1;
    uint32_t exec_timeout_ms = 5000;
    uint32_t per_call_timeout_ms = 500;

    uint32_t kcov_entries = 0;
    uint32_t kcov_collector_count = 0;
    uint32_t kcov_premap_count = 0;
    uint32_t flags = 0;

    uint32_t worker_perf_sample_rate = 1;
    uint32_t worker_perf_report_every = 256;
    uint32_t kcov_child_mode =
        static_cast<uint32_t>(LoopKcovChildMode::kFreshPerProgram);
    uint32_t reserved1 = 0;

    uint32_t buffer_source = 0;
    uint32_t reserved2 = 0;
    uint64_t window_resource_offset = 0;
    uint64_t window_size = 0;
    uint64_t input_resource_offset = 0;
    uint64_t input_size = 0;
    uint64_t output_resource_offset = 0;
    uint64_t output_size = 0;
    uint64_t result_resource_offset = 0;
    uint64_t result_size = 0;

    uint64_t step_ring_resource_offset = 0;
    uint64_t step_ring_size = 0;
    uint32_t step_ring_capacity = 0;
    uint32_t reserved3 = 0;
};

enum class LoopStartupStage : uint32_t {
    kUnknown = 0,
    kBootRead = 1,
    kNamespace = 2,
    kWindowMap = 3,
    kComponentBuild = 4,
    kKcovInit = 5,
    kFdAbi = 6,
    kScratch = 7,
    kSandbox = 8,
    kResultPage = 9,
    kReady = 10,
};

struct LoopStartupStatus {
    uint32_t magic = kLoopWorkerBootMagic;
    uint16_t version = kLoopWorkerBootVersion;
    uint16_t size = 0;
    uint32_t ready = 0;
    uint32_t proc_id = 0;
    LoopStartupStage stage = LoopStartupStage::kUnknown;
    int32_t error_number = 0;
};

inline bool LoopWorkerBootConfigValid(const LoopWorkerBootConfig& config)
{
    return config.magic == kLoopWorkerBootMagic &&
           config.version == kLoopWorkerBootVersion &&
           config.size == sizeof(LoopWorkerBootConfig) &&
           config.kcov_child_mode <=
               static_cast<uint32_t>(LoopKcovChildMode::kInheritedFromLoop) &&
           config.window_size != 0 &&
           config.input_size != 0 &&
           config.output_size != 0;
}

inline bool LoopWorkerBootRangeWithin(uint64_t offset,
                                      uint64_t size,
                                      uint64_t window_offset,
                                      uint64_t window_size)
{
    if (offset < window_offset) {
        return false;
    }
    const uint64_t relative = offset - window_offset;
    return relative <= window_size && size <= window_size - relative;
}

inline bool LoopWorkerBootGeometryValid(const LoopWorkerBootConfig& config,
                                        uint64_t minimum_result_size)
{
    const auto buffer_source =
        static_cast<ProgramBufferSource>(config.buffer_source);
    if (!LoopWorkerBootConfigValid(config) ||
        (buffer_source != ProgramBufferSource::kIvshmemWorkerArea &&
         buffer_source != ProgramBufferSource::kIvshmemDataWindowV3 &&
         buffer_source != ProgramBufferSource::kLinearSharedMemory) ||
        config.window_resource_offset > UINT64_MAX - config.window_size ||
        !LoopWorkerBootRangeWithin(config.input_resource_offset,
                                   config.input_size,
                                   config.window_resource_offset,
                                   config.window_size) ||
        !LoopWorkerBootRangeWithin(config.output_resource_offset,
                                   config.output_size,
                                   config.window_resource_offset,
                                   config.window_size)) {
        return false;
    }
    if (config.result_size != 0 &&
        (config.result_size < minimum_result_size ||
         !LoopWorkerBootRangeWithin(config.result_resource_offset,
                                    config.result_size,
                                    config.window_resource_offset,
                                    config.window_size))) {
        return false;
    }
    if ((config.flags & kLoopBootEnableStepEvents) != 0 &&
        (config.step_ring_size == 0 || config.step_ring_capacity == 0 ||
         config.step_ring_resource_offset >
             UINT64_MAX - config.step_ring_size)) {
        return false;
    }
    return true;
}

inline LoopWorkerBootConfig MakeLoopWorkerBootConfig()
{
    LoopWorkerBootConfig config{};
    config.size = static_cast<uint16_t>(sizeof(config));
    return config;
}

inline LoopStartupStatus MakeLoopStartupStatus()
{
    LoopStartupStatus status{};
    status.size = static_cast<uint16_t>(sizeof(status));
    return status;
}

static_assert(std::is_trivially_copyable_v<LoopWorkerBootConfig>);
static_assert(std::is_standard_layout_v<LoopWorkerBootConfig>);
static_assert(std::is_trivially_copyable_v<LoopStartupStatus>);
static_assert(std::is_standard_layout_v<LoopStartupStatus>);

} // namespace refuzz::worker::engine
