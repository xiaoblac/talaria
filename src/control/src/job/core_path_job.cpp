// Job-loop 重设计 Step 3 Slice C3 —— core-path job body 实现。见 core_path_job.hpp。

#include "refuzz/control/job/core_path_job.hpp"

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"
#include "refuzz/logging/host_logger.hpp"

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz::control {

namespace {

void SortUniqueU64(std::vector<std::uint64_t>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

void StampStableCorpusCoverage(
    refuzz::fuzzer::Seed& seed,
    const std::vector<deflake::RunObservation>& runs,
    const std::vector<PerCallCandidate>& candidates)
{
    refuzz::fuzzer::CorpusCoverageMetadata cc;
    cc.cover_hashes = deflake::ComputeFullStableCover(runs);
    for (const auto& c : candidates) {
        cc.signal_hashes_are_edges =
            cc.signal_hashes_are_edges || c.signal_hashes_are_edges;
        cc.signal_cover_hashes.insert(cc.signal_cover_hashes.end(),
                                      c.stable_signal_hashes.begin(),
                                      c.stable_signal_hashes.end());
        cc.signal_cover_prios.insert(cc.signal_cover_prios.end(),
                                     c.signal_cover_prios.begin(),
                                     c.signal_cover_prios.end());
    }
    if (!cc.signal_cover_hashes.empty()) {
        std::vector<std::uint64_t> signal = cc.signal_cover_hashes;
        SortUniqueU64(signal);
        std::vector<std::uint8_t> prios;
        prios.reserve(signal.size());
        for (const std::uint64_t h : signal) {
            std::uint8_t best = 0;
            for (std::size_t i = 0; i < cc.signal_cover_hashes.size(); ++i) {
                if (cc.signal_cover_hashes[i] == h) {
                    const std::uint8_t p =
                        i < cc.signal_cover_prios.size() ? cc.signal_cover_prios[i] : 0;
                    best = std::max(best, p);
                }
            }
            prios.push_back(best);
        }
        cc.signal_cover_hashes = std::move(signal);
        cc.signal_cover_prios = std::move(prios);
    }
    if (!cc.cover_hashes.empty() || !cc.signal_cover_hashes.empty()) {
        seed.metadata.Set(std::move(cc));
    }
}

const char* TaskTierName(::refuzz::queue::TaskTier tier)
{
    switch (tier) {
    case ::refuzz::queue::TaskTier::CandidateTriage: return "candidate_triage";
    case ::refuzz::queue::TaskTier::Candidate: return "candidate";
    case ::refuzz::queue::TaskTier::Triage: return "triage";
    case ::refuzz::queue::TaskTier::Smash: return "smash";
    case ::refuzz::queue::TaskTier::Explore: return "explore";
    }
    return "unknown";
}

// RAII:任何退出路径(取消/flaky/done)都把 inflight gauge -1,与入口的 +1 配平。
struct GaugeGuard {
    refuzz::core::metrics::Gauge* g = nullptr;
    ~GaugeGuard() { if (g != nullptr) g->Add(-1); }
};

enum class DeflakeExecOutcome {
    kOk,
    kCancelled,
    kHardStop,
    kDrop,
};

// ExecResult → MinimizeDriver::ExecSignalSnapshot(minimize 侧;同 minimize_job.cpp
// 的 SnapshotFrom —— 迁移期两处并存,Step 6 清场时收敛)。
MinimizeDriver::ExecSignalSnapshot SnapshotFrom(const job::ExecResult& r)
{
    MinimizeDriver::ExecSignalSnapshot s;
    s.signal_hashes       = r.signal_hashes;
    s.extra_signal_hashes = r.extra_signal_hashes;
    s.exec_status         = static_cast<refuzz::proto::ResultCode>(r.exec_status);
    s.hard_stop           = r.hard_stop;
    s.per_call.reserve(r.per_call.size());
    for (const auto& c : r.per_call) {
        s.per_call.push_back(MinimizeDriver::CallSignalObservation{
            .coverage_hashes = c.coverage_hashes,
            .errno_value     = c.errno_value,
            .syscall_id      = c.syscall_id,
            .edge_hashes     = c.edge_hashes,
            .signal_priority = c.signal_priority,
        });
    }
    return s;
}

// ExecResult → deflake::RunObservation(deflake 侧;等价旧 triage consumer 从
// FeedbackOutput 提取 RunObservation 的投影,只是源改成 ExecResult)。
deflake::RunObservation ObservationFrom(const job::ExecResult& r,
                                        bool contributes_cover = true)
{
    deflake::RunObservation obs;
    obs.exec_status = static_cast<refuzz::proto::ResultCode>(r.exec_status);
    obs.extra_cover = r.extra_cover;
    obs.extra_signal_hashes = r.extra_signal_hashes;
    obs.extra_signal_hashes_are_edges = r.extra_signal_hashes_are_edges;
    obs.contributes_cover = contributes_cover;
    obs.per_call.reserve(r.per_call.size());
    for (const auto& c : r.per_call) {
        obs.per_call.push_back(deflake::CallObservation{
            .coverage_hashes = c.coverage_hashes,
            .errno_value     = c.errno_value,
            .syscall_id      = c.syscall_id,
            .edge_hashes     = c.edge_hashes,
            .signal_priority = c.signal_priority,
        });
    }
    return obs;
}

// [per-call novelty — syz deflake()→deflakeCall→triageProgCall] merge one deflake
//   re-exec's per-call novel signal into the chased map. Grows job.calls[call].newSignal;
//   a call that first-owns signal on a later run gets added (syz discovers new candidate
//   calls mid-deflake). Keeps new_signal_hashes sorted+unique (candidate does sorted
//   intersection). extra(-1) handled too (currently always empty — see kcov signal).
void MergeReExecIntoChased(
    std::unordered_map<int, CorePathChasedCall>& chased,
    const job::ExecResult&                        r,
    std::size_t                                   run_index)
{
    auto grow = [](CorePathChasedCall& cc,
                   const std::vector<std::uint64_t>& add,
                   std::uint8_t priority) {
        if (add.empty()) return;
        std::unordered_map<std::uint64_t, std::uint8_t> merged;
        for (std::size_t i = 0; i < cc.new_signal_hashes.size(); ++i) {
            const std::uint8_t old_priority =
                i < cc.new_signal_prios.size() ? cc.new_signal_prios[i] : 0;
            merged[cc.new_signal_hashes[i]] = old_priority;
        }
        for (const std::uint64_t hash : add) {
            auto it = merged.find(hash);
            if (it == merged.end() || priority > it->second) {
                merged[hash] = priority;
            }
        }
        cc.new_signal_hashes.clear();
        cc.new_signal_prios.clear();
        cc.new_signal_hashes.reserve(merged.size());
        for (const auto& [hash, ignored] : merged) {
            (void)ignored;
            cc.new_signal_hashes.push_back(hash);
        }
        std::sort(cc.new_signal_hashes.begin(), cc.new_signal_hashes.end());
        cc.new_signal_prios.reserve(cc.new_signal_hashes.size());
        for (const std::uint64_t hash : cc.new_signal_hashes) {
            cc.new_signal_prios.push_back(merged.at(hash));
        }
    };
        for (std::size_t i = 0; i < r.per_call.size(); ++i) {
            const auto& call = r.per_call[i];
            if (call.novel_signal_hashes.empty()) {
                continue;
            }
        auto [it, inserted] = chased.try_emplace(static_cast<int>(i));
        auto& cc = it->second;
        if (inserted) {
            cc.first_run_index = run_index;
            cc.call_index = static_cast<int>(i);
            cc.errno_value = call.errno_value;
            cc.syscall_id = call.syscall_id;
        }
        // A replay with no edge hit must not turn an existing edge-domain
        // chase into the raw-PC domain. The discovery sample establishes the
        // domain; later replays can only confirm it.
        cc.signal_hashes_are_edges =
            cc.signal_hashes_are_edges || !call.edge_hashes.empty();
        grow(cc, call.novel_signal_hashes, call.signal_priority);
    }
    if (!r.extra_novel_signal_hashes.empty()) {
        auto [it, inserted] = chased.try_emplace(-1);
        auto& cc = it->second;
        if (inserted) {
            cc.first_run_index = run_index;
        }
        cc.call_index = -1;
        cc.signal_hashes_are_edges =
            cc.signal_hashes_are_edges || r.extra_signal_hashes_are_edges;
        grow(cc, r.extra_novel_signal_hashes, /*priority=*/0);
    }
}

MinimizeDriver::StartArgs BuildStartArgs(
    const refuzz::fuzzer::Seed& seed,
    int attempts,
    refuzz::crash::MinimizeMode mode,
    const PerCallCandidate& candidate)
{
    MinimizeDriver::StartArgs args;
    args.initial_artifact = seed.artifact;
    args.attempts         = attempts;
    args.mode             = mode;
    args.target_signal_hashes    = candidate.new_stable_signal_hashes;
    args.target_signal_prios     = candidate.new_stable_signal_prios;
    args.guilty_call_index       = candidate.call_index;
    args.target_errno_value      = candidate.errno_value;
    args.target_syscall_id       = candidate.syscall_id;
    args.target_is_edge_signal   = candidate.signal_hashes_are_edges;
    if (const auto* pcm =
            seed.metadata.Get<refuzz::fuzzer::TriagePerCallCandidateMetadata>();
        pcm != nullptr && pcm->exec_status.has_value()) {
        args.target_exec_status = *pcm->exec_status;
    } else {
        args.target_exec_status = refuzz::proto::ResultCode::kOk;
    }
    return args;
}

// [Step 5b] 单 per-call 候选 minimize:RunInline(job 线程内同步)+ 完成时 ctx.retain
// 在 control 线程 admit。false ⇒ 挂起期间被取消 → 调用方 unwind。没有 candidate
// 就没有 minimize 目标;不允许退回整程序/盲 minimize。
bool MinimizeOneCandidate(job::JobContext&            ctx,
                          MinimizeDriver&             driver,
                          const refuzz::fuzzer::Seed& seed,
                          const PerCallCandidate&     cand,
                          const MinimizeAdmitFn&      admit_fn,
                          const CorePathJobConfig&    config)
{
    const auto& m = config.metrics;
    auto args = BuildStartArgs(seed, config.attempts, config.mode, cand);
    bool cancelled = false;
    MinimizeDriver::InlineExecFn exec_fn =
        [&](const MinimizeDriver::Candidate& c) -> MinimizeDriver::ExecSignalSnapshot {
        job::Request req;
        if (c.artifact != nullptr && c.artifact->valid()) {
            req.artifact = c.artifact;
        }
        req.payload         = c.exec_wire_payload;   // driver wire bytes
        req.opts.timeout_ms = config.timeout_ms;
        req.tier            = config.tier;   // [Step 5] boot→CandidateTriage① / 现场→Triage③
        job::ExecResult r = ctx.exec(std::move(req));  // ← 挂起点
        if (r.cancelled) {
            cancelled = true;
            return {};
        }
        if (m.minimize_task_completed != nullptr) {
            m.minimize_task_completed->Inc();  // 每完成一发 minimize re-exec
        }
        return SnapshotFrom(r);
    };
    auto inline_verdict = driver.RunInline(
        args, exec_fn, [&] { return cancelled || ctx.cancelled(); });
    if (cancelled || ctx.cancelled()) {
        return false;
    }
    if (inline_verdict.hard_stopped) {
        return true;   // syz p==nil for this call: skip admit, continue sibling candidates.
    }
    // InlineVerdict → StepVerdict(复用 AdmitMinimizedSeed 的完成数据)。
    MinimizeDriver::StepVerdict sv;
    sv.final_payload  = std::move(inline_verdict.final_payload);
    sv.final_artifact = std::move(inline_verdict.final_artifact);
    sv.final_cover    = std::move(inline_verdict.final_cover);
    sv.remapped_guilty_call_index = inline_verdict.remapped_guilty_call_index;
    std::optional<PerCallCandidate> fin = cand;   // 值拷贝(job 结束后 decision 数组已亡)
    // admit 在 control 线程(retain):碰 corpus_inbox / next_seed_id / elaboration dispatch。
    ctx.retain([af = admit_fn, v = std::move(sv), fin]() mutable {
        af(std::move(v), fin);
    });
    return true;
}

struct CorePathRunState {
    std::shared_ptr<refuzz::fuzzer::Seed>  seed;   // 共享:job 盖章 + admit_fn 读同一份
    std::shared_ptr<MinimizeDriver>        driver;
    ExtractStableFn                        extract_stable;
    MinimizeAdmitFn                        admit_fn;
    CorePathJobConfig                      config;

    std::optional<job::Request> SeedRequest() const
    {
        if (seed->artifact == nullptr || !seed->artifact->valid()) {
            return std::nullopt;
        }
        job::Request req;
        // artifact-first(同 triage re-exec / minimize):留空 payload,让 executor
        // submit 边界 MaterializeExecWire。core-path 缺 typed artifact 是 wiring bug,
        // 不能用 raw payload 继续跑。
        req.artifact = seed->artifact;
        req.opts.timeout_ms = config.timeout_ms;
        req.tier            = config.tier;   // [Step 5] boot→CandidateTriage① / 现场→Triage③
        req.completion_triage_policy =
            job::CompletionTriagePolicy::kSuppressCatchAllTriage;
        return req;
    }

    void Run(job::JobContext& ctx)
    {
        // [Slice D 指标] core-path job 替代 triage+minimize 两 stage → 自己发它们的计数。
        const auto& m = config.metrics;
        auto retain_terminal = [&]() {
            if (config.on_terminal) {
                ctx.retain(config.on_terminal);
            }
        };
        // triage-job inflight +1(对应旧 triage producer 的 +1);-1 由 guard 在任何退出
        // 路径(取消 / flaky / done)兜底。
        if (m.triage_job != nullptr) m.triage_job->Add(1);
        GaugeGuard triage_inflight_guard{m.triage_job};

        std::vector<deflake::RunObservation>    runs;
        std::vector<std::vector<std::uint64_t>> per_run_hashes;
        // [per-call novelty — syz job.calls] chased map: seed from the discovery exec
        //   (config.initial_calls), grow per deflake re-exec (MergeReExecIntoChased).
        //   Drives per-call candidates instead of a program-level novel union reverse-scan.
        std::unordered_map<int, CorePathChasedCall> chased;
        const std::size_t initial_call_count = config.initial_calls.size();
        for (auto& call : config.initial_calls) {
            const int call_index = call.call_index;
            chased[call_index] = std::move(call);
        }
        config.initial_calls.clear();

        if (config.discovery_sample.has_value()) {
            CorePathDiscoverySample discovery =
                std::move(*config.discovery_sample);
            config.discovery_sample.reset();
            runs.push_back(std::move(discovery.observation));
            per_run_hashes.push_back(std::move(discovery.signal_hashes));
        }

        bool no_new_signal = false;

        // 一发 deflake re-exec;kCancelled ⇒ unwind 返回(不变量 #9),kDrop/kHardStop ⇒ log 后
        // 走 terminal cleanup(kHardStop = worker/channel 层面已拿不到结果,该发不进
        // runs/chased;程序自己 crash/这一次 task 没跑成不算 —— 正常折进 runs 走稳定性投票)。
        auto deflake_exec = [&]() -> DeflakeExecOutcome {
            auto req = SeedRequest();
            if (!req.has_value()) {
                refuzz::logging::HostLogger::Instance().Log(
                    "control.core_path",
                    "core_path_missing_artifact",
                    {refuzz::logging::Field("seed_id", seed ? seed->seed_id : 0),
                     refuzz::logging::Field("initial_calls",
                                            static_cast<std::uint64_t>(
                                                initial_call_count))});
                return DeflakeExecOutcome::kDrop;
            }
            job::ExecResult r = ctx.exec(std::move(*req));   // ← 挂起点
            if (r.cancelled) {
                return DeflakeExecOutcome::kCancelled;
            }
            if (m.triage_task_completed != nullptr) {
                m.triage_task_completed->Inc();  // 每完成一发 deflake re-exec(= 旧 triage task)
            }
            if (r.hard_stop) {
                refuzz::logging::HostLogger::Instance().Log(
                    "control.core_path",
                    "core_path_deflake_hard_stop",
                    {refuzz::logging::Field("seed_id", seed ? seed->seed_id : 0),
                     refuzz::logging::Field("runs_so_far",
                                            static_cast<std::uint64_t>(runs.size()))});
                return DeflakeExecOutcome::kHardStop;   // worker/channel 层面拿不到结果 → 整条中止
            }
            std::size_t chased_before = 0;
            for (const auto& [call_index, call] : chased) {
                (void)call_index;
                chased_before += call.new_signal_hashes.size();
            }
            const std::size_t run_index = runs.size();
            per_run_hashes.push_back(r.signal_hashes);
            runs.push_back(ObservationFrom(r));
            MergeReExecIntoChased(
                chased, r, run_index);  // 逐 call 补 newSignal(= syz deflake 内再 triageProgCall)
            std::size_t chased_after = 0;
            for (const auto& [call_index, call] : chased) {
                (void)call_index;
                chased_after += call.new_signal_hashes.size();
            }
            no_new_signal = chased_after == chased_before;
            return DeflakeExecOutcome::kOk;
        };

        // Initial min_runs is the total observation count. Discovery, when
        // present, already occupies sample 0 just like syzkaller signals[0].
        const int min_runs = config.min_runs > 0 ? config.min_runs : 1;
        while (static_cast<int>(runs.size()) < min_runs) {
            const auto outcome = deflake_exec();
            if (outcome == DeflakeExecOutcome::kCancelled) {
                return;
            }
            if (outcome == DeflakeExecOutcome::kDrop ||
                outcome == DeflakeExecOutcome::kHardStop) {
                retain_terminal();
                return;
            }
        }

        auto chased_snapshot = [&]() {
            std::vector<deflake::ChasedCall> out;
            out.reserve(chased.size());
            for (const auto& kv : chased) {
                const auto& src = kv.second;
                out.push_back(deflake::ChasedCall{
                    .call_index = src.call_index,
                    .new_signal_hashes = src.new_signal_hashes,
                    .new_signal_prios = src.new_signal_prios,
                    .errno_value = src.errno_value,
                    .syscall_id = src.syscall_id,
                    .signal_hashes_are_edges = src.signal_hashes_are_edges,
                    .first_run_index = src.first_run_index,
                });
            }
            std::sort(out.begin(), out.end(),
                      [](const deflake::ChasedCall& a, const deflake::ChasedCall& b) {
                          return a.call_index < b.call_index;
                      });
            return out;
        };

        // 自适应扩展:停止条件必须跟 syz stopDeflake 一样看 chased calls 的
        // newSignal ∩ stableSignal。整程序 intersection 非空只说明“程序某处稳定”,
        // 不能证明发现新信号的 call 已经稳定。
        std::vector<std::uint64_t>               intersection;
        std::optional<refuzz::proto::ResultCode> stable_exec_status;
        bool stable = false;
        for (;;) {
            intersection = extract_stable
                ? extract_stable(per_run_hashes, config.min_votes)
                : std::vector<std::uint64_t>{};
            stable_exec_status = deflake::SelectStableExecStatus(runs);
            stable = !intersection.empty() && stable_exec_status.has_value();
            const auto chased_vec = chased_snapshot();
            const bool stop_deflake = config.deflake_mode == DeflakeMode::kBootCorpus
                ? deflake::ShouldStopCorpusDeflake(
                      runs, chased_vec, config.min_votes, config.min_runs,
                      config.max_runs, config.total_runs, no_new_signal)
                : deflake::ShouldStopFuzzDeflake(
                      runs, chased_vec, config.min_votes, config.max_runs);
            if (stop_deflake) {
                break;
            }
            const int hard_max = config.total_runs > 0
                ? config.total_runs : config.max_runs;
            if (hard_max > 0 && static_cast<int>(runs.size()) >= hard_max) {
                break;
            }
            if (runs.empty() ||
                runs.back().exec_status != refuzz::proto::ResultCode::kOk) {
                break;   // 上次非 completion → 不扩展(避免反复 kill flaky-crashy)
            }
            const auto outcome = deflake_exec();
            if (outcome == DeflakeExecOutcome::kCancelled) {
                return;
            }
            if (outcome == DeflakeExecOutcome::kDrop ||
                outcome == DeflakeExecOutcome::kHardStop) {
                retain_terminal();
                return;
            }
        }

        // 判定完成(stable / flaky 均计,对应旧 triage consumer 的 triage_completed)。
        if (m.triage_completed != nullptr) m.triage_completed->Inc();
        if (!stable) {
            if (m.triage_drop_flaky != nullptr) m.triage_drop_flaky->Inc();
            // [List3] 把 flaky-drop 的**具体原因**日志化,而不是裸计数。区分:
            //   no_program_stable   —— 整程序 k-of-n 无稳定 signal(intersection 空)
            //   no_stable_exec_status —— 有稳定 signal,但所有 run 都是 no-result
            //                            (per_call 空),没有可稳定的 exec 结果
            refuzz::logging::HostLogger::Instance().Log(
                "control.core_path",
                "core_path_drop_flaky",
                {refuzz::logging::Field("seed_id", seed ? seed->seed_id : 0),
                 refuzz::logging::Field(
                     "reason", intersection.empty() ? "no_program_stable"
                                                    : "no_stable_exec_status"),
                 refuzz::logging::Field("runs",
                                        static_cast<std::uint64_t>(runs.size())),
                 refuzz::logging::Field("intersection",
                                        static_cast<std::uint64_t>(intersection.size())),
                 refuzz::logging::Field("has_stable_exec_status",
                                        stable_exec_status.has_value())});
            retain_terminal();
            return;   // flaky → drop(不 retain,seed 随 job 析构;不变量 #8)
        }

        // [per-call novelty] 收敛 chased map → 有序 vector(按 call_index)交给 decide。
        std::vector<deflake::ChasedCall> chased_vec = chased_snapshot();
        // 盖章:只接受 syz job.calls 风格的 per-call candidate。缺 attribution
        // 时打日志并 drop,不再回退到整程序 guilty-call/minimize。
        auto decision = deflake::DecideAndStampStableSeed(
            *seed, runs, intersection, *stable_exec_status,
            config.min_votes, config.seed_value_shadow_enabled, chased_vec);
        if (!decision.admit) {
            if (m.triage_drop_flaky != nullptr) m.triage_drop_flaky->Inc();  // stable 但无可准候选
            // [List3] 把 DecideAndStampStableSeed 算出的 drop_reason 日志化(此前它被
            // 计算却从不落日志):no_chased_calls = per-call attribution 链断(没有 syz
            // job.calls 等价物);no_per_call_candidate = 有 chased call 但没有一个的
            // newSignal ∩ stableSignal 非空。有了它才能量化"稳定却无候选"的丢弃占比。
            const char* reason =
                decision.drop_reason == deflake::StableSeedDropReason::kNoChasedCalls
                    ? "no_chased_calls"
                : decision.drop_reason == deflake::StableSeedDropReason::kNoPerCallCandidate
                    ? "no_per_call_candidate"
                    : "unspecified";
            refuzz::logging::HostLogger::Instance().Log(
                "control.core_path",
                "core_path_drop_no_candidate",
                {refuzz::logging::Field("seed_id", seed ? seed->seed_id : 0),
                 refuzz::logging::Field("reason", reason),
                 refuzz::logging::Field("runs",
                                        static_cast<std::uint64_t>(runs.size())),
                 refuzz::logging::Field("chased_calls",
                                        static_cast<std::uint64_t>(chased_vec.size())),
                 refuzz::logging::Field("intersection",
                                        static_cast<std::uint64_t>(intersection.size()))});
            retain_terminal();
            return;   // per-call-admit 但无候选 → drop
        }
        if (m.triage_admit_stable != nullptr) {
            m.triage_admit_stable->Inc(decision.admitted_units);  // +admitted_units(同旧)
        }
        if (config.skip_minimize) {
            if (seed != nullptr) {
                StampStableCorpusCoverage(*seed, runs, decision.per_call_candidates);
            }
            ctx.retain([admit = config.stable_admit, sd = seed,
                        dispatch = config.dispatch_elaboration,
                        done = config.on_terminal]() mutable {
                if (admit) {
                    admit(*sd, dispatch);
                }
                if (done) {
                    done();
                }
            });
            return;
        }
        // [Step 5b] 并发 fan-out:per-call 候选散成 N 个独立 child minimize job(control 线程
        // retain 派生;= syz triageJob wg.Go(handleCall))。spawn_child 为空只用于单测
        // seam;生产 wiring 必须提供它。
        if (config.spawn_child) {
            ctx.retain([spawn = config.spawn_child, sd = seed, af = admit_fn, cfg = config,
                        cands = std::move(decision.per_call_candidates)]() mutable {
                for (auto& cand : cands) {
                    std::vector<PerCallCandidate> one;
                    one.push_back(std::move(cand));
                    (void)spawn(MakeCorePathMinimizeJob(sd, af, std::move(one), cfg));
                }
            });
            return;
        }

        // parent 原地串行(test seam only):自持 minimize inflight + 逐 per-call 候选。
        if (m.minimize_job != nullptr) m.minimize_job->Add(1);
        GaugeGuard minimize_inflight_guard{m.minimize_job};
        for (const auto& cand : decision.per_call_candidates) {
            if (!MinimizeOneCandidate(ctx, *driver, *seed, cand, admit_fn, config)) {
                return;   // 取消 → 停止后续候选
            }
        }
    }
};

} // namespace

CorePathDiscoverySample MakeCorePathDiscoverySample(const job::ExecResult& result)
{
    CorePathDiscoverySample sample;
    sample.signal_hashes = result.signal_hashes;
    sample.observation = ObservationFrom(result, /*contributes_cover=*/false);
    return sample;
}

job::JobFn MakeCorePathJob(
    std::shared_ptr<refuzz::fuzzer::Seed>  seed,
    std::shared_ptr<MinimizeDriver>        driver,
    ExtractStableFn                        extract_stable,
    MinimizeAdmitFn                        admit_fn,
    CorePathJobConfig                      config)
{
    auto st            = std::make_shared<CorePathRunState>();
    st->seed           = std::move(seed);
    st->driver         = std::move(driver);
    st->extract_stable = std::move(extract_stable);
    st->admit_fn       = std::move(admit_fn);
    st->config         = std::move(config);
    return [st](job::JobContext& ctx) { st->Run(ctx); };
}

// [Step 5b] fan-out child factory(见 hpp)。每 child 自建独立 driver(工厂空 → 默认真
// driver,同 parent 生产用);对 candidates 逐个 MinimizeOneCandidate(与 parent 串行段同一
// 份)。minimize_job gauge 归 child(+1/-1)。
job::JobFn MakeCorePathMinimizeJob(
    std::shared_ptr<refuzz::fuzzer::Seed> seed,
    MinimizeAdmitFn                       admit_fn,
    std::vector<PerCallCandidate>         candidates,
    CorePathJobConfig                     config)
{
    return [seed = std::move(seed), admit_fn = std::move(admit_fn),
            cands = std::move(candidates), config](job::JobContext& ctx) {
        const auto& m = config.metrics;
        if (m.minimize_job != nullptr) m.minimize_job->Add(1);
        GaugeGuard minimize_inflight_guard{m.minimize_job};
        auto driver = config.make_child_driver
            ? config.make_child_driver()
            : std::make_shared<MinimizeDriver>();
        for (const auto& cand : cands) {
            if (!MinimizeOneCandidate(ctx, *driver, *seed, cand, admit_fn, config)) {
                return;   // 取消 → 停后续候选
            }
        }
    };
}

} // namespace refuzz::control
