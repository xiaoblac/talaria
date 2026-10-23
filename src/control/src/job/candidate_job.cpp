// Job-loop 重设计 Step 3 —— CandidateFeederJob 实现。见 candidate_job.hpp。

#include "refuzz/control/job/candidate_job.hpp"

#include "refuzz/control/loop/pending_seed_map.hpp"  // PendingSeedMap::Peek(重试重取)
#include "refuzz/program/seed.hpp"                  // fuzzer::Seed(Peek 返回)

#include <utility>

namespace refuzz::control {

namespace {

// CandidateSeed / pending 种子 → ② job::Request(tier=Candidate;exec_id 由 arbiter 分配,
// 不设)。origin_seed_id=0:boot candidate 是 root(不是变异)→ 下游 lineage kGenerate。
job::Request BuildCandidateRequest(
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact,
    std::uint64_t seed_id, std::uint32_t exec_timeout_ms)
{
    job::Request req;
    req.artifact        = std::move(artifact);
    req.seed_id         = seed_id;
    req.origin_seed_id  = 0;
    req.opts.timeout_ms = exec_timeout_ms;
    req.tier            = ::refuzz::queue::TaskTier::Candidate;  // ②
    return req;
}

}  // namespace

job::JobFn MakeCandidateJob(CandidateJobDeps deps, std::function<void()> on_done)
{
    return [deps = std::move(deps), on_done = std::move(on_done)]
           (job::JobContext& ctx) {
        // ── ① bootstrap:emit 本轮全部 boot candidate(loop 已扫描+排序;respawn 时空)。──
        // 每个 emit fire-and-forget;on_submitted(arbiter 分配 exec_id 后于 control 线程)记
        // candidate_exec_[exec_id]={seed_id, attempt=0} → 其 completion 走 catch-all 的 candidate 分支。
        for (const CandidateSeed& cand : deps.initial) {
            if (ctx.cancelled()) {
                return;  // 取消 → unwind(不注册 on_done;不变量 #8/#9)。
            }
            const std::uint64_t seed_id = cand.seed_id;
            auto record = deps.record_exec;
            job::OnSubmitted on_sub =
                [record, seed_id](std::uint64_t exec_id) {
                    if (record) record(exec_id, seed_id, /*attempt=*/0);
                };
            if (!ctx.emit(BuildCandidateRequest(cand.artifact, seed_id, deps.exec_timeout_ms),
                          std::move(on_sub))) {
                return;  // 取消 → unwind。
            }
        }

        // ── ② 重试:取走本轮 flaky candidate,据 seed_id 从 pending 区重取程序、重 emit ②
        //    (attempt+1)。种子已被 admit / Erase(不在 pending)→ 跳过(= syz 该 candidate 已终结)。──
        if (deps.drain_retries && deps.pending) {
            for (const auto& [seed_id, attempt] : deps.drain_retries()) {
                if (ctx.cancelled()) {
                    return;
                }
                auto seed = deps.pending->Peek(seed_id);
                if (!seed.has_value() || seed->artifact == nullptr ||
                    !seed->artifact->valid()) {
                    continue;
                }
                std::shared_ptr<const ::refuzz::program::ProgramArtifact> art = seed->artifact;
                const std::uint64_t sid = seed_id;
                const int att = attempt;
                auto record = deps.record_exec;
                job::OnSubmitted on_sub =
                    [record, sid, att](std::uint64_t exec_id) {
                        if (record) record(exec_id, sid, att);
                    };
                if (!ctx.emit(BuildCandidateRequest(std::move(art), sid, deps.exec_timeout_ms),
                              std::move(on_sub))) {
                    return;
                }
            }
        }

        // ── ③ 本轮 candidate work 出清 → 正常退出。retain on_done:control 线程复位 alive;
        //    RunOnce 见还有 work(未 bootstrap / 新重试)时重 spawn(否则闲置不再起)。──
        if (on_done) {
            ctx.retain(std::move(on_done));
        }
    };
}

}  // namespace refuzz::control
