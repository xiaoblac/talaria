#include "refuzz/crash/pipeline/core/crash_pipeline_registry.hpp"

namespace refuzz::crash {

void CrashPipelineRegistry::Register(std::unique_ptr<ICrashPipelineOp> op)
{
    if (op == nullptr) {
        return;
    }
    ops_[op->Kind()] = std::move(op);
}

ICrashPipelineOp* CrashPipelineRegistry::Find(CrashPipelineOp kind) const
{
    const auto it = ops_.find(kind);
    if (it == ops_.end()) {
        return nullptr;
    }
    return it->second.get();
}

} // namespace refuzz::crash
