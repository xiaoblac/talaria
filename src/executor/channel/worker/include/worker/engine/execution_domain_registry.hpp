#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstdint>

namespace refuzz::worker {

struct PersistedProcState {
    uint32_t proc_id = PROC_ID_ANY;
    uint32_t epoch = 0;
    bool valid = false;
    uint32_t dirty_proc_mask = 0;
};

class IExecutionDomainRegistry {
public:
    virtual ~IExecutionDomainRegistry() = default;

    virtual bool InitialCorpusTriaged() const { return true; }
    virtual uint32_t WorkerId() const { return 0; }
    virtual uint32_t WorkerCount() const { return 1; }
    virtual PersistedProcState LoadProcState() const { return {}; }
    virtual bool PublishProcState(uint32_t /*proc_id*/, uint32_t /*epoch*/) {
        return true;
    }
    virtual bool PublishDirtyProcMask(uint32_t /*dirty_proc_mask*/) {
        return true;
    }
    virtual bool PublishMaintenanceError(uint32_t /*error_code*/) {
        return true;
    }
};

} // namespace refuzz::worker
