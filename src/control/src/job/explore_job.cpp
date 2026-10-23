// Job-loop 重设计 Step 5 —— ExploreJob 实现。见 explore_job.hpp。
//
// "job 统一表达运行时工作":gen/mut/collide 的产出逻辑就写在**本文件**里(不再抽到独立 stage /
// producer_ops 单元)。job 自持生产能力,body 内:MAB.Select(gen/mut) → generate/mutate →
// genFuzz never-empty 供给 → collide(1/3)→ ctx.emit。emit 是唯一提交口 —— arbiter 在 submit
// funnel 里统一分配 executor_id + Push,故 job **不**自己 next_executor_id++ / task_queue.Push
// (produce+submit 在 job 里统一)。= syz genFuzz Callback:never-empty 末位供给 gen/mut。
//
// 归因经 on_submitted:submit 后于 control 线程 RecordProduced(arm-MAB)+ 写 seed-credit sink
// (mutate 的 seed-MAB)。正常退出(engine 不支持 generation,基本不可达)经 on_done 让 loop 复位
// alive、自愈重 spawn。job handoff 由 FuzzerLoop 本线程驱动,job body 与
// completion/catch-all/MAB/corpus 逻辑 strict-alternate。

#include "refuzz/control/job/explore_job.hpp"

#include "refuzz/core/metrics/counter.hpp"            // Counter::Inc(generated/mutated/collide)
#include "refuzz/fuzzer/interfaces.hpp"               // ICorpusStore::Size / GetSeed
#include "refuzz/logging/host_logger.hpp"             // HostLogger::Log / Field(mutate skip-log)
#include "refuzz/mutator/mutator_engine.hpp"          // IMutatorEngine(Generate/MutateTyped/Collide)
#include "refuzz/program/artifact.hpp"                // ProgramArtifact / MutationStatus[Name]
#include "refuzz/program/seed.hpp"                    // seed::AssertV2Authoritative
#include "refuzz/proto_domain/types.hpp"              // kExecFlagIntraThreaded
#include "refuzz/queue/host_fuzz_task.hpp"            // HostFuzzTask
#include "refuzz/scheduler/scheduler_engine.hpp"      // ISchedulerEngine::NextSeedId

#include <memory>
#include <optional>
#include <random>
#include <utility>

namespace refuzz::control {

namespace {

// ── generate 原语:产一个全新随机程序(mutator.Generate() → task)。────────────────
// executor_id 留 0(提交点分配,3a);seed_id/origin=0(无 source corpus seed)。
// nullopt = engine 不支持 generation(kSkipped)/ 本次失败(kEngineError / 无效 artifact)。
std::optional<refuzz::queue::HostFuzzTask>
GenerateProgram(refuzz::fuzzer::IMutatorEngine& mutator, std::uint32_t exec_timeout_ms)
{
    auto result = mutator.Generate();
    if (result.status != ::refuzz::program::MutationStatus::kOk ||
        !result.artifact.valid()) {
        return std::nullopt;   // **不**强行降级到 bytes-only。
    }
    refuzz::queue::HostFuzzTask task;
    task.seed_id         = 0;
    task.origin_seed_id  = 0;
    task.artifact        = std::move(result.artifact);
    task.opts.timeout_ms = exec_timeout_ms;
    task.important       = false;
    return task;
}

// ── mutate 原语:变异一个 scheduler 选中的 corpus seed。返回 task + 该次 seed 选择 ──
// {seed_id,pr,γ}(供 seed-MAB 归因)。nullopt = 无可选 seed / seed 失效 / typed-mutate 空
// 产出且 profile 关 bytes-only fallback(artifact-first strict:skip+log 暴露)。
struct MutateOut {
    refuzz::queue::HostFuzzTask   task;
    refuzz::fuzzer::SeedSelection seed_sel;
};
std::optional<MutateOut>
MutateProgram(refuzz::fuzzer::ISchedulerEngine& scheduler,
              refuzz::fuzzer::IMutatorEngine&   mutator,
              refuzz::fuzzer::ICorpusStore&     corpus,
              bool                              accept_bytes_only_fallback,
              std::uint32_t                     exec_timeout_ms,
              refuzz::logging::HostLogger&      logger)
{
    auto seed_sel = scheduler.NextSeedId();
    if (!seed_sel.has_value()) {
        return std::nullopt;
    }
    const std::uint64_t seed_id = seed_sel->seed_id;
    auto seed = corpus.GetSeed(seed_id);
    if (!seed) {
        return std::nullopt;
    }

    refuzz::queue::HostFuzzTask task;
    task.seed_id        = seed_id;
    task.origin_seed_id = seed_id;

    // §3.10 step 6 — prefer the typed pipeline when seed.artifact is populated
    // (v2 corpus-load path). v1 profiles leave seed.artifact null → bytes path.
    // 提交边界一次性从 task.artifact 物化 bytes(热路径无 encode_text)。
    ::refuzz::program::MutationStatus mutate_status =
        ::refuzz::program::MutationStatus::kOk;  // seed 无 artifact 时不调 MutateTyped,留默认
    if (seed->artifact != nullptr) {
        ::refuzz::program::seed::AssertV2Authoritative(*seed);
        auto result = mutator.MutateTyped(*seed->artifact);
        mutate_status = result.status;
        if (result.artifact.valid()) {
            task.artifact = std::move(result.artifact);
        }
    }
    // [artifact-first strict] 没拿到有效 typed artifact 又没现成 wire bytes:syz/kernel profile
    //   严格 accept_bytes_only_fallback=false,skip+log 暴露(不走 bytes fallback —— canonical
    //   text 当 wire 会让 worker 把 ASCII 当 varint 解出超大 reserve → SIGABRT)。
    if (task.payload.empty() && !task.artifact.valid()) {
        if (!accept_bytes_only_fallback) {
            logger.Log("control.stage", "mutational_typed_mutate_empty_skip", {
                refuzz::logging::Field("seed_id", seed_id),
                refuzz::logging::Field("status",
                    ::refuzz::program::MutationStatusName(mutate_status)),
                refuzz::logging::Field("reason",
                    "typed mutation produced no valid artifact; bytes-only "
                    "fallback disabled by profile (artifact-first strict)"),
            });
            return std::nullopt;
        }
        task.payload = mutator.Mutate(*seed);
    }
    task.opts.timeout_ms = exec_timeout_ms;
    task.important       = false;

    return MutateOut{std::move(task), *seed_sel};
}

// ── collide 原语:1/3 async 变体(mirror syz genFuzz `rnd.Intn(3)==0`),就地改 ──
// task.artifact + 置 kExecFlagIntraThreaded;命中成功时 exec_collide(可空)+1。
// **先判 valid 再掷币** —— 无效不耗 RNG(与旧 stage 同序)。
void CollideInPlace(refuzz::fuzzer::IMutatorEngine& mutator,
                    std::mt19937_64&                rng,
                    refuzz::queue::HostFuzzTask&     task,
                    refuzz::core::metrics::Counter*  exec_collide)
{
    if (!task.artifact.valid()) {
        return;   // bytes-only 无 typed Prog;Collide 内 CheckTargetOrDie 对无效 artifact 会 abort。
    }
    std::uniform_int_distribution<int> coin(0, 2);
    if (coin(rng) != 0) {
        return;   // 2/3:不 collide。
    }
    auto result = mutator.Collide(task.artifact);
    if (result.status == ::refuzz::program::MutationStatus::kOk &&
        result.artifact.valid()) {
        task.artifact = std::move(result.artifact);
        task.opts.flags |=
            static_cast<std::uint32_t>(::refuzz::proto::kExecFlagIntraThreaded);
        if (exec_collide != nullptr) {
            exec_collide->Inc();
        }
    }
}

// HostFuzzTask → job::Request(打 Explore 档;executor_id 由 arbiter submit 分配,不设)。
job::Request ToExploreRequest(refuzz::queue::HostFuzzTask&& task)
{
    job::Request req;
    if (task.artifact.valid()) {
        req.artifact = std::make_shared<const refuzz::program::ProgramArtifact>(
            std::move(task.artifact));
    }
    req.payload        = std::move(task.payload);
    req.opts           = task.opts;
    req.seed_id        = task.seed_id;
    req.origin_seed_id = task.origin_seed_id;
    req.tier           = refuzz::queue::TaskTier::Explore;
    return req;
}

}  // namespace

job::JobFn MakeExploreJob(ExploreJobDeps deps, std::function<void()> on_done)
{
    return [deps, on_done = std::move(on_done)](job::JobContext& ctx) {
        const bool has_mutator = deps.mutator_handle != nullptr;
        // [MAB observability] 绑本 job 产出 cadence:每 kObserveEvery 次 emit 触发一次 deps.observe()
        //   (loop 侧 MAB 打点)。emit 与 loop handoff strict-alternate → observe 读 loop 态安全。
        std::uint64_t produced = 0;
        constexpr std::uint64_t kObserveEvery = 64;
        while (!ctx.cancelled()) {
            // ── ① MAB.Select(gen/mut):选 arm + 抓抽样快照 pick(供 completion 结算)。──
            // mab_selector==nullptr(MAB inactive)⇒ 无 pick ⇒ 落 ③ genFuzz never-empty 供给。
            std::optional<mab::MabTaskSelector::Pick> pick;
            if (deps.mab_selector != nullptr) {
                mab::ArmEligibility elig;
                // jobs-only 默认模式:generate 恒可用;mutate 需 corpus 非空(有 seed 才能变异)。
                elig.generate = true;
                elig.mutate   = deps.corpus->Size() > 0;
                pick = deps.mab_selector->Select(elig, *deps.rng);
            }
            const bool want_mutate = pick.has_value() && pick->arm == mab::MabArm::kMutate;

            // ── ② 按 arm 产程序。attributed=该 emit 是否记 MAB(no-pick supply 不记)。──
            std::optional<refuzz::queue::HostFuzzTask> task;
            std::optional<refuzz::fuzzer::SeedSelection> seed_sel;   // 仅 mutate 有(seed-MAB)
            bool attributed = false;
            if (want_mutate) {
                if (deps.scheduler_handle->HasValue() && has_mutator &&
                    deps.mutator_handle->HasValue()) {
                    auto m = MutateProgram(
                        deps.scheduler_handle->Get(), deps.mutator_handle->Get(),
                        *deps.corpus, deps.accept_bytes_only_fallback,
                        deps.exec_timeout_ms, *deps.logger);
                    if (m.has_value()) {
                        task       = std::move(m->task);
                        seed_sel   = m->seed_sel;
                        attributed = true;   // 归 mutate pick(task 计数由 loop build_task 按 tier 记)
                    }
                }
            } else if (pick.has_value()) {   // pick.arm==generate → 归 generate pick
                if (has_mutator && deps.mutator_handle->HasValue()) {
                    task = GenerateProgram(deps.mutator_handle->Get(), deps.exec_timeout_ms);
                    if (task.has_value()) {
                        attributed = true;
                    }
                }
            }

            // ── ③ genFuzz never-empty supply:上面没产出(mutate 落空 / MAB 未选 generate /
            //    MAB inactive)→ 强制 generate,**不记 MAB**(非 bandit 决策,镜像旧 pass 3
            //    mab_pick.reset())。──
            if (!task.has_value()) {
                if (has_mutator && deps.mutator_handle->HasValue()) {
                    task = GenerateProgram(deps.mutator_handle->Get(), deps.exec_timeout_ms);
                }
                attributed = false;
                seed_sel.reset();
            }
            if (!task.has_value()) {
                break;   // 连 generate 都不产出(engine 不支持 generation,基本不可达)→ 正常退出。
            }

            // ── ④ collide(1/3 async 变体):就地改 artifact + threaded flag + exec_collide+1。
            //    jobs-only 默认模式:恒尝试 collide(不支持 collide 的 engine 内部 kSkipped → task
            //    原样提交;不再 profile 级 gate)。──
            if (has_mutator && deps.mutator_handle->HasValue()) {
                CollideInPlace(deps.mutator_handle->Get(), *deps.rng, *task, deps.exec_collide);
            }

            // ── ⑤ HostFuzzTask → Request(Explore 档)+ ⑥ 归因 on_submitted → emit。──
            //    emit = 唯一提交口:arbiter 在 submit funnel 里分配 executor_id + Push(job 不自己做)。
            job::Request req = ToExploreRequest(std::move(*task));
            task.reset();
            job::OnSubmitted on_sub;
            if (attributed && pick.has_value()) {
                // job 懂 MAB:自建归因闭包。arbiter submit 后于 control 线程跑(exec_id 已定):
                //   RecordProduced(exec_id, arm-pick) 记 arm-MAB 在途;mutate 另写 seed-credit
                //   sink(seed-MAB 的 {seed_id,pr,γ})。两者 pr/γ 不同源:arm-pick 是 arm 选择的,
                //   seed_sel 是 scheduler seed 选择的。
                const mab::MabTaskSelector::Pick p = *pick;
                mab::MabTaskSelector* const sel = deps.mab_selector;
                auto record_seed = deps.record_mutate_seed;
                const std::optional<refuzz::fuzzer::SeedSelection> s = seed_sel;
                on_sub = [sel, p, record_seed = std::move(record_seed), s](std::uint64_t exec_id) {
                    sel->RecordProduced(exec_id, p);
                    if (s.has_value() && record_seed) {
                        record_seed(exec_id, *s);
                    }
                };
            }

            if (!ctx.emit(std::move(req), std::move(on_sub))) {
                return;   // 取消 → unwind(不注册 on_done;不变量 #8/#9,反正 shutdown)。
            }
            if (deps.observe && (++produced % kObserveEvery == 0)) {
                deps.observe();   // MAB 观测:每 N 次 emit 触发一次(见 FuzzerLoop::EmitMabState)。
            }
        }
        if (on_done) {
            ctx.retain(std::move(on_done));   // 正常退出 → control 线程复位 alive → 自愈重 spawn。
        }
    };
}

}  // namespace refuzz::control
