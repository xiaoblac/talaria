#pragma once
// Job-loop 重设计 Step 5 —— ExploreJob(⑤ = syz Callback(genFuzz))。
//
// "stage 退役出 runtime 调度路径,job 统一表达运行时工作":ExploreJob 是 gen/mut 探索的
// **运行时表达**。它自己**持有生产能力**(mab selector / mutator·scheduler handle / corpus /
// rng / metrics hooks / seed-归因 sink),并在 body 内**集成 MAB + generate + mutate + collide
// 语义** —— 不再是"薄壳 + FuzzerLoop lambda 里的胖 produce"。
//
// body 每轮:MAB.Select(gen/mut) → 按 arm 产 generate/mutate(逻辑就在 explore_job.cpp 内)→
// genFuzz never-empty 供给(强制 generate)→ collide(1/3 async 变体)→ ctx.emit(打 Explore 档,
// fire-and-forget)。emit = 唯一提交口:arbiter 在 submit funnel 里统一分配 executor_id + Push,
// 故 job **不**自己 next_executor_id++ / task_queue.Push(produce+submit 在 job 里统一)。归因经
// on_submitted:submit 后于 control 线程 RecordProduced(arm-MAB)+ 写 seed-credit sink(mutate
// 的 seed-MAB)。正常退出(engine 不支持 generation,基本不可达)经 on_done 复位 alive、自愈重 spawn。
//
// 过渡期 flag-off pass 2/3 仍走各自的 gen/mut/collide stage(未从 catalog 摘除,只退出 arbiter
// runtime 路径)。job handoff 由 FuzzerLoop 本线程驱动,job body 与 loop 的
// completion/catch-all/MAB/corpus 逻辑 strict-alternate。

#include "refuzz/control/job/job_context.hpp"
#include "refuzz/control/mab/mab_task_selector.hpp"   // MabTaskSelector(Select/RecordProduced/Pick)
#include "refuzz/core/engine_handle.hpp"              // EngineHandle<T>(mutator/scheduler)
#include "refuzz/fuzzer/seed_selection.hpp"           // SeedSelection(seed-credit sink 值类型)

#include <cstdint>
#include <functional>
#include <random>

namespace refuzz::fuzzer {
class IMutatorEngine;
class ISchedulerEngine;
class ICorpusStore;
}  // namespace refuzz::fuzzer

namespace refuzz::logging { class HostLogger; }
namespace refuzz::core::metrics { class Counter; }

namespace refuzz::control {

// ExploreJob 的生产能力(loop ctor 期把成员地址/句柄填进来;均为 loop 寿命,job 不长于 loop)。
// 所有指针非空即"有该能力";mab_selector==nullptr ⇒ MAB inactive ⇒ 强制 generate、不归因。
struct ExploreJobDeps {
    // ── MAB(arm 选择 + 归因)──
    mab::MabTaskSelector* mab_selector      = nullptr;  // Select(gen/mut) + RecordProduced
    // ── 生产能力 ──
    const refuzz::core::EngineHandle<refuzz::fuzzer::IMutatorEngine>*   mutator_handle   = nullptr;
    const refuzz::core::EngineHandle<refuzz::fuzzer::ISchedulerEngine>* scheduler_handle = nullptr;
    refuzz::fuzzer::ICorpusStore*  corpus  = nullptr;   // GetSeed / Size(mutate eligibility)
    std::mt19937_64*               rng     = nullptr;   // MAB Select + collide 掷币
    std::uint32_t                  exec_timeout_ms = 0;
    bool                           accept_bytes_only_fallback = false;
    refuzz::logging::HostLogger*   logger  = nullptr;   // mutate 空产出 skip-log
    // ── metrics hooks(job 自记 producer-slot 占用;可空)──
    // generated/mutated task 计数已上移到 loop build_task(按 tier 记 generated_tasks/reexec_tasks);
    // ExploreJob 只保留 collide 变换计数(非 task 计数)。
    refuzz::core::metrics::Counter* exec_collide    = nullptr;
    // ── on_submitted 归因 sink:exec_id → 被变异 seed 的 {seed_id,pr,γ}。
    //    loop 持有具体存储和同步;job 只通过回调记录,不共享裸 map。
    std::function<void(std::uint64_t, refuzz::fuzzer::SeedSelection)> record_mutate_seed;
    // ── MAB 观测 hook:MAB 是本 job 的运行时状态,观测 cadence 也绑本 job 的产出("调用一次触发
    //    一次")而非 loop 的独立周期 tick。body 每 kObserveEvery 次 emit 调一次;闭包由 loop 提供
    //    (捕获 logger/mab/metrics)。job body 与 loop handoff strict-alternate → 读安全。可空。
    std::function<void()> observe;
};

// 造一条 ExploreJob(返回 JobFn 交给 JobScheduler::TrySpawn)。
//   deps     生产能力(见上;按值拷贝一组指针/标量,均 loop 寿命)。
//   on_done  job **正常退出**(generate/mutate 都无法产出)后于 control 线程经 retain 跑(复位 alive →
//            RunOnce 重 spawn 自愈);**取消退出不跑**(不变量 #8,反正 shutdown)。
job::JobFn MakeExploreJob(ExploreJobDeps deps, std::function<void()> on_done);

}  // namespace refuzz::control
