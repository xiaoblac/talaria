#pragma once

#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/pipeline/policy/linuxkernel/syz_xxx_policy/syz_triage_policy.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"

namespace refuzz::crash {

class ICrashPipelineOp {
public:
    virtual ~ICrashPipelineOp() = default;

    virtual CrashPipelineOp Kind() const = 0;
    virtual void Execute(const refuzz::proto::CombinedCrashEvent& event,
                         CrashContext& ctx,
                         const CrashPipelineParams& params) = 0;
};

} // namespace refuzz::crash
