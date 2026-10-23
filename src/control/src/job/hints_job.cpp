// Job-loop 重设计 Step 4b/5 —— hints job body 实现。见 hints_job.hpp。

#include "refuzz/control/job/hints_job.hpp"

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"
#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_limiter.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/proto_domain/types.hpp"   // kExecFlagCollectComps

#include <utility>
#include <vector>

namespace refuzz::control {

namespace {

namespace hints_alg = ::refuzz::mutator::syz_v2::hints;
namespace pr        = ::refuzz::program;

// RAII:任何退出路径(取消 / hard-stop / done)都把 inflight gauge -1,与入口 +1 配平。
struct GaugeGuard {
    refuzz::core::metrics::Gauge* g = nullptr;
    ~GaugeGuard() { if (g != nullptr) g->Add(-1); }
};

enum class HintTailOutcome {
    kCancelled,   // 取消,或某次变体 exec 回来 cancelled/abnormal 提前停 —— 不计 hints_completed
    kNoTailWork,  // 无 mutator / 无 replay 数据 / limit 后 comps 为空 —— 前缀自然收尾
    kCompleted,   // MutateWithHints 自然跑完(0..N 个变体都已通过 ctx.exec 完成)
};

// raw worker output → CompMap(全量 CmpRecord)。= 旧 HintsConsumer 批段
// 的 output 版:feedback engine 的 Process 只留去重增量,这里独立 decode 全量 cmp。
hints_alg::CompMap ExtractCompMapFromOutput(const std::vector<std::uint8_t>& output)
{
    hints_alg::CompMap out;
    if (output.empty()) {
        return out;
    }
    std::vector<std::uint8_t>             payload = output;
    refuzz::proto::FeedbackDelta          delta;
    refuzz::fuzzer::CoverageFeedbackCodec codec;
    if (codec.Extract(&payload, &delta) != refuzz::fuzzer::ParseFeedbackStatus::kOk) {
        return out;
    }
    for (const auto& rec : delta.cmp) {
        out.Add(rec.pc, rec.arg1, rec.arg2, rec.is_const);
    }
    return out;
}

struct HintsRunState {
    std::shared_ptr<const refuzz::fuzzer::Seed> seed;
    int                                         call_index = 0;
    HintsJobConfig                              config;

    // 一发 collect-comps re-exec 请求:同 seed(artifact-first / payload 退化)+
    // kExecFlagCollectComps(worker 切 KCOV CMP 模式,output 带 packed cmp records)。
    // 等价旧 HintsProducer 的 task 构建,只是产出 job::Request(submit 边界再拷进 task)。
    job::Request CollectCompsRequest() const
    {
        job::Request req;
        if (seed->artifact != nullptr && seed->artifact->valid()) {
            req.artifact = seed->artifact;
        } else {
            req.payload = seed->payload;   // spawn 点已按 profile 甄别 bytes-only path
        }
        req.opts.timeout_ms = config.timeout_ms;
        req.opts.flags =
            static_cast<std::uint32_t>(refuzz::proto::kExecFlagCollectComps);
        req.tier = refuzz::queue::TaskTier::Smash;   // [Step 5] enrich → syz smashQueue(④)
        req.completion_triage_policy =
            job::CompletionTriagePolicy::kSuppressCatchAllTriage;
        return req;
    }

    HintTailOutcome EmitHintVariants(
        job::JobContext& ctx,
        const std::vector<std::vector<std::uint8_t>>& replay_outputs) const
    {
        if (config.mutator_handle == nullptr || !config.mutator_handle->HasValue() ||
            replay_outputs.empty()) {
            return HintTailOutcome::kNoTailWork;
        }

        std::vector<hints_alg::CompMap> replays;
        replays.reserve(replay_outputs.size());
        for (const auto& out : replay_outputs) {
            replays.push_back(ExtractCompMapFromOutput(out));
        }

        // Intersect 去 flaky(镜像 hints_stage.cpp):replays[0] 播种,后续空 replay 跳过。
        hints_alg::CompMap final_comps = std::move(replays[0]);
        for (std::size_t i = 1; i < replays.size(); ++i) {
            if (replays[i].empty()) {
                continue;
            }
            final_comps.InplaceIntersect(replays[i]);
        }

        static hints_alg::HintsLimiter limiter;
        limiter.Limit(final_comps);
        if (final_comps.empty() || ctx.cancelled()) {
            return ctx.cancelled() ? HintTailOutcome::kCancelled
                                   : HintTailOutcome::kNoTailWork;
        }

        auto&               mutator = config.mutator_handle->Get();
        const std::uint64_t seed_id = seed->seed_id;
        // 镜像 syz hintsJob.run() 的 MutateWithHints 回调段:每个候选变体各自一次 ctx.exec,
        // 挂起等真实 completion 回来再决定要不要继续生成下一个(不再一次性 emit_batch 交出去
        // ——那会让这条 job 的 25 个变体绕开 ArbitrateJobs 的逐个重选,产出跟 completion 脱节
        // 的计数)。
        bool stopped_early = false;

        mutator.MutateWithHints(
            *seed, call_index, final_comps,
            [this, &ctx, seed_id, &stopped_early](pr::ProgramArtifact artifact) -> bool {
                if (ctx.cancelled()) {
                    stopped_early = true;
                    return false;
                }
                if (!artifact.valid()) {
                    return true;   // 本条无效 → 跳过,继续生成下一条(同旧逻辑)
                }
                job::Request req;
                req.artifact = std::make_shared<const pr::ProgramArtifact>(std::move(artifact));
                req.opts.timeout_ms = config.timeout_ms;
                req.opts.flags      = 0;
                req.tier            = refuzz::queue::TaskTier::Smash;
                req.seed_id         = seed_id;
                req.origin_seed_id  = seed_id;
                // completion_triage_policy 留默认 kAllowCatchAllTriage —— 同 smash 的理由:
                // 这是全新 hint 变体,routed completion 回来时仍应能从新观测信号 spawn 新
                // core-path job,跟这条 request 走 catch-all 时的行为一致。

                job::ExecResult r = ctx.exec(std::move(req));   // ← 挂起点,逐变体 execute()
                if (r.cancelled) {
                    stopped_early = true;
                    return false;
                }
                if (config.metrics.hints_task_completed != nullptr) {
                    config.metrics.hints_task_completed->Inc();
                }
                if (r.hard_stop) {
                    stopped_early = true;
                    return false;   // 同 smash:worker/channel 层面拿不到结果才停止继续 mutate
                }
                return true;
            });

        if (stopped_early || ctx.cancelled()) {
            return HintTailOutcome::kCancelled;
        }
        return HintTailOutcome::kCompleted;
    }

    void Run(job::JobContext& ctx)
    {
        const auto& m = config.metrics;
        const int   n = config.replay_count > 0 ? config.replay_count : 1;

        if (m.hints_job != nullptr) m.hints_job->Add(1);
        GaugeGuard hints_inflight_guard{m.hints_job};

        // 有状态前缀:n 发 collect-comps,逐发收 raw output(未 decode)。
        std::vector<std::vector<std::uint8_t>> replay_outputs;
        replay_outputs.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            job::ExecResult r = ctx.exec(CollectCompsRequest());   // ← 挂起点
            if (r.cancelled) {
                return;   // 取消 unwind:不 emit(同旧 consumer 只在 3-of-3 mutate)
            }
            if (m.hints_task_completed != nullptr) m.hints_task_completed->Inc();
            if (r.hard_stop) {
                return;   // worker/channel 层面已拿不到结果 → 停整条 hints job,不进入 tail
            }
            replay_outputs.push_back(std::move(r.output));
        }

        // hint 变体尾巴也属于同一个 hints job,现在跟前缀一样逐条 ctx.exec:tail 自然跑完
        // (kCompleted)或压根没有尾巴要跑(kNoTailWork)都算这条 job 正常结束;取消/abnormal
        // 提前停(kCancelled)不计。
        const HintTailOutcome tail = EmitHintVariants(ctx, replay_outputs);
        if ((tail == HintTailOutcome::kNoTailWork || tail == HintTailOutcome::kCompleted) &&
            m.hints_completed != nullptr) {
            m.hints_completed->Inc();
        }
    }
};

} // namespace

job::JobFn MakeHintsJob(
    std::shared_ptr<const refuzz::fuzzer::Seed> seed,
    int                                         call_index,
    HintsJobConfig                              config)
{
    auto st         = std::make_shared<HintsRunState>();
    st->seed        = std::move(seed);
    st->call_index  = call_index;
    st->config      = config;
    return [st](job::JobContext& ctx) { st->Run(ctx); };
}

} // namespace refuzz::control
