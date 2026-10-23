#pragma once
// Job-loop 重设计 Step 4a —— fault-inject job body。
//
// 把 FaultInjection 的 producer + consumer **依赖循环**融成一条 job 栈:
//   for nth = 1..max_nth:
//     variant = MakeFaultInjectVariant(base_prog, call_index, nth)   // CallProps.fail_nth=nth
//     r = ctx.exec(variant)                                          // ← 唯一挂起点
//     取消          → unwind(不变量 #9);
//     abnormal      → 停链(timeout/crash/exec-error;程序到不了注入点,继续无意义);
//     per_call[call_index].fault_injected==true  → 内核仍在此注入点触发 → 继续 nth+1;
//                                        ==false  → 注入点耗尽 → 停链;
//     无 / 短观测    → log 后停链(观测链断裂,不猜);
//   cap(nth>=max_nth)→ 停链。
//
// 与 syzkaller 的 faultInjectionJob 依赖循环一致,但 reFuzz 不把缺失 per-call observation
// 当普通继续条件;这会掩盖 worker/decoder 链路错误。
// fault replay **不入库**(对齐上游拒 FailNth>0 入 corpus),故 **无 retain**;
// fault-induced kernel crash 由控制环(spine)的事件级 crash 转发 surface
// (见 fuzzer_loop.cpp 的 Step 4 crash 不变量),job 本身 **不碰** crash pipeline。
//
// config / metrics 经参数注入(不依赖 StageDeps)→ 可隔离单测(mock executor + recorder)。
// 见 docs/job-loop-redesign/050_step4_elaboration_migration.md。

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/program/seed.hpp"

#include <cstdint>
#include <memory>

namespace refuzz::core::metrics { class Counter; class Gauge; }

namespace refuzz::control {

// [Step 4a — 指标补全] fault job 替代 FaultInjection producer+consumer,自己发它们的计数
// (逐点镜像 fault_injection_stage.cpp 的 Inc 位)。指针取自 deps.metrics(4d 填;测试可
// 留空),job 线程直接 Inc/Add(Counter/Gauge 都是 lock-free atomic,任意线程可调)。
//   fault_task_completed        每完成一发 re-exec(= 旧 consumer 每消费一个本链 event)。
//   fault_job                   当前 inflight fault-injection job 数。
//   (reexec_tasks 已上移 loop build_task 按 tier 记:fault continuation=Smash→reexec。)
struct FaultJobMetrics {
    refuzz::core::metrics::Counter* fault_task_completed         = nullptr;
    refuzz::core::metrics::Gauge*   fault_job                    = nullptr;
};

struct FaultJobConfig {
    int             call_index = -1;    // 注入目标 call;必须由 per-call triage metadata 显式给出
    int             max_nth    = 100;   // = kFaultInjectMaxNth
    std::uint32_t   timeout_ms = 0;
    FaultJobMetrics metrics;
};

// 造一条 fault-inject job(返回 JobFn 交给 JobScheduler::TrySpawn)。
//   - seed **只读共享**(shared_ptr<const Seed>):job 只读它的 artifact/seed_id 建 variant,
//     不盖章、不入库 → const 足矣(有别于 core-path 的可变 shared_ptr<Seed>)。必须
//     artifact-first(typed syz::Prog);否则 job 空转即退(无法 mutate CallProps)。
job::JobFn MakeFaultJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    FaultJobConfig                              config);

} // namespace refuzz::control
