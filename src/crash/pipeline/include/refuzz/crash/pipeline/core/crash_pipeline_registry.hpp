#pragma once

#include "refuzz/crash/pipeline/core/crash_pipeline_op.hpp"

#include <memory>
#include <unordered_map>

namespace refuzz::crash {

class CrashPipelineRegistry {
public:
    void Register(std::unique_ptr<ICrashPipelineOp> op);
    ICrashPipelineOp* Find(CrashPipelineOp kind) const;

private:
    std::unordered_map<CrashPipelineOp, std::unique_ptr<ICrashPipelineOp>> ops_;
};

} // namespace refuzz::crash
