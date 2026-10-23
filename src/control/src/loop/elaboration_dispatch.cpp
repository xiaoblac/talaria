// Job-loop 重设计 Step 4d —— elaboration 触发 wiring 实现。见 elaboration_dispatch.hpp。

#include "refuzz/control/loop/elaboration_dispatch.hpp"

#include "refuzz/control/job/fault_job.hpp"
#include "refuzz/control/job/hints_job.hpp"
#include "refuzz/control/job/smash_op.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/mutator/mutator_engine.hpp"        // MutateTyped / Mutate
#include "refuzz/program/seed.hpp"                    // AssertV2Authoritative
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/queue/host_fuzz_task.hpp"
#include "refuzz/queue/task_queue.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace refuzz::control {

void DispatchElaboration(JobDeps&                    deps,
                         const refuzz::fuzzer::Seed& followup_seed,
                         std::uint64_t               final_seed_id,
                         std::uint64_t               origin_executor_id)
{
    const std::uint32_t timeout_ms = static_cast<std::uint32_t>(deps.exec_timeout_ms);

    // fault/hints target must come from the core-path per-call candidate that
    // admitted this seed. Guessing from the artifact shape would hide broken
    // attribution and run enrich on the wrong syscall.
    int call_index = -1;
    if (const auto* stable =
            followup_seed.metadata.Get<refuzz::fuzzer::TriageStableSignalMetadata>();
        stable != nullptr) {
        call_index = stable->guilty_call_index;
    }
    const bool has_elaboration_target = call_index >= 0;
    if (!has_elaboration_target) {
        deps.logger.Log(
            "control.elaboration",
            "elaboration_missing_guilty_call",
            {refuzz::logging::Field("seed_id", final_seed_id),
             refuzz::logging::Field("origin_executor_id", origin_executor_id),
             refuzz::logging::Field(
                 "has_triage_stable_signal",
                 followup_seed.metadata
                         .Get<refuzz::fuzzer::TriageStableSignalMetadata>() != nullptr)});
    }

    // ── smash ──
    //   arbiter:一条 job,镜像 syz smashJob.run() —— 每变体一次 ctx.exec,阻塞等真实
    //   completion 回来才继续下一变体(routed → 结果回这条 job,catch-all 的 triage
    //   side-effect 仍照常触发;见 smash_op.cpp)。非 arbiter:原无栈 burst(直接 push,
    //   unrouted → catch-all)。变体生成 mutate 两路共用。
    {
        // arbiter 分支下这个 mutate 会被 MakeSmashJob 拷进**长寿命 job**,所以**不能捕获
        // JobDeps&**(违反 job_deps.hpp:5 "不能长期持有 JobDeps&";deps 虽指向 FuzzerLoop::deps_
        // 不是栈对象,但持有整个聚合引用是脆弱契约)。改为只捕获它真正用到的两样长期有效的东西:
        // mutator_handle(指针,owned by AssembledBundle,用时才 .Get() 以尊重 policy 切换 ——
        // 同 HintsJobConfig 用 &deps.mutator_handle 的做法)+ accept_bytes_only_fallback(装配期
        // 固定的 profile flag,按值)。
        const auto* mutator_handle             = &deps.mutator_handle;
        const bool  accept_bytes_only_fallback = deps.accept_bytes_only_fallback;
        SmashMutateFn mutate =
            [mutator_handle, accept_bytes_only_fallback](const refuzz::fuzzer::Seed& s)
            -> std::optional<SmashVariant> {
            if (!mutator_handle->HasValue()) return std::nullopt;
            auto& mutator = mutator_handle->Get();
            SmashVariant v;
            if (s.artifact != nullptr) {
                refuzz::program::seed::AssertV2Authoritative(s);
                auto result = mutator.MutateTyped(*s.artifact);
                if (result.artifact.valid()) {
                    v.artifact = std::move(result.artifact);
                    return v;
                }
            }
            if (accept_bytes_only_fallback) {
                v.payload = mutator.Mutate(s);
                if (!v.payload.empty()) return v;
            }
            return std::nullopt;   // 严格 profile:无 typed 变体 → skip(消耗一轮)
        };
        SmashOpConfig cfg;
        cfg.iterations                   = 25;   // = 旧 SmashProducerStage::Config::iterations
        cfg.timeout_ms                   = timeout_ms;
        cfg.metrics.smash_completed      = deps.metrics.smash_completed;
        cfg.metrics.smash_job            = deps.metrics.smash_job;
        cfg.metrics.smash_task_completed = deps.metrics.smash_task_completed;
        if (deps.job_arbiter && deps.spawn_job) {
            auto seed_sp = std::make_shared<const refuzz::fuzzer::Seed>(followup_seed);
            deps.spawn_job(MakeSmashJob(std::move(seed_sp), final_seed_id, mutate, cfg));
        } else {
            SmashSubmitTaskFn submit = [&deps](refuzz::queue::HostFuzzTask&& t) -> bool {
                t.executor_id = deps.next_executor_id++;   // unrouted → TryClaim 落空 → catch-all
                return deps.task_queue.Push(std::move(t));
            };
            SubmitSmashVariants(followup_seed, final_seed_id, mutate, submit, cfg);
        }
    }

    // ── fault:依赖循环 job(arbiter 无上限 → 恒 spawn,无 overflow 回落)──
    if (deps.spawn_job && has_elaboration_target) {
        FaultJobConfig cfg;
        cfg.call_index                           = call_index;
        cfg.timeout_ms                           = timeout_ms;
        cfg.metrics.fault_task_completed         = deps.metrics.fault_task_completed;
        cfg.metrics.fault_job                    = deps.metrics.fault_job;
        auto seed_sp = std::make_shared<const refuzz::fuzzer::Seed>(followup_seed);
        deps.spawn_job(MakeFaultJob(std::move(seed_sp), cfg));
    }

    // ── hints:3-collect 前缀 + hint 变体 emit(arbiter 无上限 → 恒 spawn)──
    if (deps.spawn_job && has_elaboration_target) {
        HintsJobConfig cfg;
        cfg.replay_count                 = 3;
        cfg.timeout_ms                   = timeout_ms;
        cfg.metrics.hints_task_completed = deps.metrics.hints_task_completed;
        cfg.metrics.hints_completed      = deps.metrics.hints_completed;
        cfg.metrics.hints_job            = deps.metrics.hints_job;
        cfg.mutator_handle               = &deps.mutator_handle;
        auto seed_sp = std::make_shared<const refuzz::fuzzer::Seed>(followup_seed);
        deps.spawn_job(MakeHintsJob(std::move(seed_sp), call_index, cfg));
    }
}

} // namespace refuzz::control
