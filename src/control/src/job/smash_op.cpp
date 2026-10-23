// Job-loop 重设计 Step 4c —— smash 无栈 op 实现。见 smash_op.hpp。

#include "refuzz/control/job/smash_op.hpp"

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"

#include <memory>
#include <utility>

namespace refuzz::control {

namespace {
// RAII:任何退出路径(取消 / done)都把 inflight gauge -1,与入口 +1 配平(同 core-path job)。
struct GaugeGuard {
    refuzz::core::metrics::Gauge* g = nullptr;
    ~GaugeGuard() { if (g != nullptr) g->Add(-1); }
};
}  // namespace

void SubmitSmashVariants(const refuzz::fuzzer::Seed& seed,
                         std::uint64_t               seed_id,
                         const SmashMutateFn&        mutate,
                         const SmashSubmitTaskFn&    submit,
                         SmashOpConfig               config)
{
    const auto& m     = config.metrics;
    const int   iters = config.iterations > 0 ? config.iterations : 1;

    for (int i = 0; i < iters; ++i) {
        std::optional<SmashVariant> variant = mutate(seed);
        if (!variant.has_value()) {
            continue;   // 本轮无有效变体 → 消耗一轮预算(同旧 stage skip 路径)
        }

        refuzz::queue::HostFuzzTask task;
        // executor_id 由 submit 绑定期分配(unrouted:不进 job router → 结果回 catch-all)。
        task.seed_id         = seed_id;
        task.origin_seed_id  = seed_id;
        task.opts.timeout_ms = config.timeout_ms;
        task.important       = false;
        if (variant->artifact.valid()) {
            task.artifact = std::move(variant->artifact);   // typed 路径
        } else {
            task.payload = std::move(variant->payload);      // profile-gated bytes-only path
        }

        if (!submit(std::move(task))) {
            break;   // 队列 backpressure → 中断 burst
        }
        // [smash observability] 每成功提交一个变体 +1(区别于下面等 N 轮全部跑完的 smash_completed)。
        if (m.smash_task_completed != nullptr) m.smash_task_completed->Inc();
    }

    // Legacy non-arbiter fallback (control/src/loop/elaboration_dispatch.cpp when
    // deps.job_arbiter/deps.spawn_job aren't wired up): direct-submit, no completion
    // observer at all, so smash_task_completed here is inherently submit-side, not
    // completion-side. NOT the syzkaller-faithful path — see MakeSmashJob below, which
    // mirrors syz smashJob.run()'s one-request-at-a-time, completion-gated model.
    // smash_completed is not reported here (never was — this path has no observer to hang it on).
}

// Arbiter model: mirrors syz smashJob.run() exactly — one variant per ctx.exec(), block until
// that request's real completion comes back, then count, then loop (fuzzer.go execute() +
// job.go smashJob.run() 454-476). Each of the `iterations` variants goes through its own
// ArbitrateJobs/SelectNextReadyJobIndex selection (TaskTier::Smash + Alternate(smash,3)),
// exactly like every other job type — no batch hand-off, no drifting queue independent of the
// job's own arbitration turn.
job::JobFn MakeSmashJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    std::uint64_t                               seed_id,
    SmashMutateFn                               mutate,
    SmashOpConfig                               config)
{
    return [seed = std::move(seed), seed_id, mutate = std::move(mutate), config]
           (job::JobContext& ctx) {
        const auto& m     = config.metrics;
        const int   iters = config.iterations > 0 ? config.iterations : 1;

        if (m.smash_job != nullptr) m.smash_job->Add(1);
        GaugeGuard smash_inflight_guard{m.smash_job};

        bool any_executed = false;
        for (int i = 0; i < iters; ++i) {
            std::optional<SmashVariant> variant = mutate(*seed);
            if (!variant.has_value()) {
                continue;   // 本轮无变体 → 消耗一轮预算(同 burst skip 路径)
            }
            job::Request req;
            req.opts.timeout_ms = config.timeout_ms;
            req.tier            = refuzz::queue::TaskTier::Smash;   // [Step 5] smash → syz smashQueue(④)
            req.seed_id         = seed_id;   // lineage → HostFuzzTask.seed_id / origin_seed_id
            req.origin_seed_id  = seed_id;
            if (variant->artifact.valid()) {
                req.artifact = std::make_shared<const refuzz::program::ProgramArtifact>(
                    std::move(variant->artifact));   // typed 路径
            } else {
                req.payload = std::move(variant->payload);   // profile-gated bytes-only path
            }
            // completion_triage_policy 留默认 kAllowCatchAllTriage:这是全新变体,不是既有
            // job 的续发,routed completion 回来时仍应能从新观测信号 spawn 新 core-path job,
            // 跟这条 request 走 catch-all 时的行为一致。

            job::ExecResult r = ctx.exec(std::move(req));   // ← 挂起点(syz smashJob.run 的 execute())
            if (r.cancelled) {
                return;   // 取消 unwind:不计 task/completed —— 不变量 #9
            }
            any_executed = true;
            if (m.smash_task_completed != nullptr) m.smash_task_completed->Inc();
            if (r.hard_stop) {
                return;   // worker/channel 层面已拿不到结果 → 停本 smash job 剩余轮次(同 syz
                          // result.Stop() 真正对应的那部分;程序自己 crash 不算,继续下一变体)
            }
        }
        if (any_executed && m.smash_completed != nullptr) {
            m.smash_completed->Inc();   // 25 轮正常跑完;全跳过(any_executed=false)不算完成,同旧语义
        }
    };
}

} // namespace refuzz::control
