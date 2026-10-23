#pragma once

#include <cstddef>
#include <cstdint>

namespace refuzz::worker {

// Offsets in ProgramBufferDescriptor are backing-store absolute offsets.
// They never contain process virtual addresses. A consumer that maps only a
// subrange resolves an address as:
//
//   local_base + (descriptor_offset - mapping.resource_offset)
enum class ProgramBufferSource : uint32_t {
    kInheritedPointer = 0,
    kIvshmemWorkerArea = 1,
    kIvshmemDataWindowV3 = 2,
    kLinearSharedMemory = 3,
};

struct ProgramBufferDescriptor {
    ProgramBufferSource source = ProgramBufferSource::kInheritedPointer;
    uint32_t worker_id = 0;
    uint64_t input_offset = 0;
    uint64_t output_offset = 0;
    // crash_len 落在 ProgramResultPageV3 内，offset = result_page_offset +
    // offsetof(ProgramResultPageV3, crash_len)，consumer 自行派生，不再单列字段。
    uint64_t result_page_offset = 0;
};

// Process-local view of a shared backing-store mapping. The pointer is never
// serialized; only the scalar geometry is copied into LoopWorkerBootConfig.
struct ProgramBufferMapping {
    ProgramBufferSource source = ProgramBufferSource::kInheritedPointer;
    uint32_t worker_id = 0;
    uint8_t* local_base = nullptr;
    uint64_t resource_offset = 0;
    uint64_t mapped_size = 0;
    uint64_t input_offset = 0;
    uint64_t input_size = 0;
    uint64_t output_offset = 0;
    uint64_t output_size = 0;
    uint64_t result_page_offset = 0;
    uint64_t result_page_size = 0;
};

// Adapter-owned transport view used by the daemon when spawning an execution
// domain. backing_fd is borrowed and remains owned by the adapter.
struct ExecutionDomainTransport {
    ProgramBufferMapping mapping;
    int backing_fd = -1;
    uint64_t step_ring_offset = 0;
    uint64_t step_ring_size = 0;
    uint32_t step_ring_capacity = 0;
};

inline bool ResolveProgramBufferRange(const ProgramBufferMapping& mapping,
                                      uint64_t resource_offset,
                                      uint64_t length,
                                      uint64_t allowed_offset,
                                      uint64_t allowed_size,
                                      uint8_t** out)
{
    if (out == nullptr) {
        return false;
    }
    *out = nullptr;
    if (mapping.local_base == nullptr || length > allowed_size ||
        resource_offset < allowed_offset) {
        return false;
    }
    const uint64_t allowed_relative = resource_offset - allowed_offset;
    if (allowed_relative > allowed_size ||
        length > allowed_size - allowed_relative ||
        resource_offset < mapping.resource_offset) {
        return false;
    }
    const uint64_t mapping_relative =
        resource_offset - mapping.resource_offset;
    if (mapping_relative > mapping.mapped_size ||
        length > mapping.mapped_size - mapping_relative ||
        mapping_relative > SIZE_MAX) {
        return false;
    }
    *out = mapping.local_base + static_cast<std::size_t>(mapping_relative);
    return true;
}

} // namespace refuzz::worker
