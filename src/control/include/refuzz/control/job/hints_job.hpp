#pragma once
// Job-loop 重设计 Step 4b/5 —— hints job body(3-collect 前缀 + hint 变体 emit)。
//
// hints job 全程都是 `ctx.exec`(串行、阻塞等真实 completion 回来再继续):
//   - 前缀:跑 replay_count 次 collect-comps re-exec,拿 raw output;
//   - 尾部:intersect 后的每个 hint 变体各自一次 ctx.exec,逐条等 completion 回来再决定
//     要不要继续生成下一个 —— 不再一次性批量交出去。
//
// collect-comps re-exec 的 crash 由控制环(spine)的事件级 crash 转发 surface(Step 4 crash
// 不变量,见 fuzzer_loop.cpp),job 本身不碰 crash pipeline —— 同 fault job。
//
// 见 docs/job-loop-redesign/050_step4_elaboration_migration.md。

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/core/engine_handle.hpp"
#include "refuzz/program/seed.hpp"

#include <cstdint>
#include <memory>

namespace refuzz::core::metrics { class Counter; class Gauge; }
namespace refuzz::fuzzer { class IMutatorEngine; }

namespace refuzz::control {

// Hints job 自己记录前缀重放、尾部变体和整条 job 完成指标。
//   hints_task_completed  前缀 collect-comps 每发 completion +1;尾部每个 hint 变体的
//                         ctx.exec() completion 也 +1(前后缀同一口径,不再有批量差异)。
//   hints_completed       前缀+尾部都正常跑完(或压根没有尾部要跑)+1;取消/abnormal
//                         提前停不计。
//   hints_job             当前 inflight hints job 数。
struct HintsJobMetrics {
    refuzz::core::metrics::Counter* hints_task_completed = nullptr;
    refuzz::core::metrics::Counter* hints_completed      = nullptr;
    refuzz::core::metrics::Gauge*   hints_job            = nullptr;
};

struct HintsJobConfig {
    int             replay_count = 3;   // = kHintsReplayCount(upstream collide=3)
    std::uint32_t   timeout_ms   = 0;
    HintsJobMetrics metrics;
    const refuzz::core::EngineHandle<refuzz::fuzzer::IMutatorEngine>* mutator_handle = nullptr;
};

// 造一条 hints job(返回 JobFn 交给 JobScheduler::TrySpawn)。
//   - seed **只读共享**(shared_ptr<const Seed>):job 只读它建 collect-comps 请求
//     (artifact-first;无 artifact 时仅在 profile 明确允许 bytes-only 路径后使用 payload)。
//   - call_index 由 spawn 点(triage/minimize follow-up)给;MutateWithHints 按它 per-call 应用 hint。
job::JobFn MakeHintsJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    int                                         call_index,
    HintsJobConfig                              config);

} // namespace refuzz::control
