// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/profile/builtin_profiles.hpp"

namespace refuzz::profile {

void RegisterBuiltinProfiles(orchestrator::ProfileRegistry& registry)
{
    // [2026-05-08 swap rename] "kernel" 现在 = syzkaller-equivalent default(triage chain);
    // "kernel_no_triage" 是显式 opt-out 退化版。
    // 注册显式 opt-out 退化版(name="kernel_no_triage")。
    registry.Register(MakeKernelNoTriageProfile());
    // reFuzz 一等公民 default profile(name="kernel",triage chain 启用)。
    registry.Register(MakeKernelProfile());
    // [v2 Phase 4 Step 4.4 — 当前版本] 注册可选 full chain profile(name="kernel_full")。
    registry.Register(MakeKernelProfileFull());
    // [Stage 3 去山头] XiUOS RTOS profile(name="xiuos")。
    registry.Register(MakeXiuosProfile());
    // 未来新增 profile 在此追加一行 registry.Register(MakeXxxProfile());
}

} // namespace refuzz::profile
