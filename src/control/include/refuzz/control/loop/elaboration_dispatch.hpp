#pragma once
// Job-loop 重设计 Step 4d —— elaboration 触发 wiring。
//
// `AdmitMinimizedSeed` 入库 minimized seed 后的富化触发点。
// 运行在 FuzzerLoop 的 job-retain 路径,可安全触达 loop-owned job spawn seam /
// mutator / task_queue。
//
// jobs-only:smash 无栈 burst(`SubmitSmashVariants`,arbiter 下改 `MakeSmashJob`)+ spawn
// fault/hints job(`MakeFaultJob`/`MakeHintsJob`,经同一 loop spawn seam)。
//
// 非 kernel / 非 kcov_cmp 目标上 fault/hints job 优雅退化(fault 首发 nth 后 exhausted、
// hints 空 CompMap → 不产变异),故此处**不**再显式 gate enabled(实践上只在 kernel 跑)。

#include "refuzz/control/job/job_deps.hpp"
#include "refuzz/program/seed.hpp"

#include <cstdint>

namespace refuzz::control {

void DispatchElaboration(JobDeps&                     deps,
                         const refuzz::fuzzer::Seed&  followup_seed,
                         std::uint64_t                final_seed_id,
                         std::uint64_t                origin_executor_id);

} // namespace refuzz::control
