#include "refuzz/control/fuzzer_loop.hpp"
#include "refuzz/control/job/job_scheduler.hpp"
#include "refuzz/queue/lifecycle_queue.hpp"       // [request-window] accepted 生命周期队列(DrainAll → MarkAccepted)
#include "refuzz/control/job/explore_job.hpp"    // [Step 5] ExploreJob(⑤ genFuzz):自持生产能力
#include "refuzz/control/job/candidate_job.hpp"  // [Step 3] CandidateFeederJob(② candidateQueue 喂入)
#include "refuzz/control/job/fixed_input_producer_job.hpp"  // [fixed request stream, Step 4]
#include "refuzz/program/syz/prog.hpp"           // [Step 3] syz::Prog::calls()(bootstrap shortest-first)
#include "refuzz/control/loop/minimize_admit.hpp"  // AdmitMinimizedSeed / ProjectExecResult
#include "refuzz/control/loop/pending_seed_map.hpp"  // [Step 6 清场] PendingSeedMap
#include "refuzz/control/job/core_path_job.hpp"  // [Step 6 Phase 1] MakeCorePathJob(catch-all 直接 spawn)
#include "refuzz/feedback/stability_oracle.hpp"  // [Step 6 Phase 1] IStabilityOracle::ExtractStable
#include "refuzz/feedback/retry_policy.hpp"      // [Step 6 Phase 1] IRetryPolicy deflake 档(kMutation 3-of-5)
#include "refuzz/corpus/corpus_manager.hpp"  // [Step 1 catch-all 迁 loop] CorpusManager::OfferVerdict
#include "refuzz/control/loop/seed_value_shadow_sink.hpp"  // [seed-value shadow] sink def
#include "refuzz/feedback/lineage/seed_lineage_yield_store.hpp"  // [seed-future-value] yield sidecar
#include "refuzz/feedback/binding/variant_handler_map.hpp"  // [variant-handler-binding] live per_call map
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/time.hpp"  // [mab Step 1] MonotonicNowUs(reward 时延 + T)
#include "refuzz/logging/host_logger.hpp"  // [RTT instrumentation] per-task sampled TaskTrace rows
#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/crash/pipeline/manager/crash_pipeline_manager.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/syz/target.hpp"  // [belief-graph] Target::linux_amd64() -> id->name table
#include "refuzz/proto_wire/error_codes.h"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace refuzz::control {

using refuzz::fuzzer::Seed;

namespace {

// [Step 3 candidate] 扫描候选区,收集 boot candidate(kBootCorpus + 非 inactive),按 call 数
// 升序(= syz manager.go:626-628 favorize-smaller:时间受限下小程序先 verify;字节数 key 会把大
// 内联镜像的 fs 种子推到队尾饿死,故用 call 数)。首次 spawn 时 pending 里只有 boot candidate
// (triage-pending 是首 tick 之后的事)→ 扫描干净、无污染。
std::vector<CandidateSeed> ScanBootCandidates(const PendingSeedMap& pending)
{
    std::vector<std::pair<std::size_t, CandidateSeed>> ordered;  // (call_count, seed)
    pending.ForEach([&](const refuzz::fuzzer::Seed& seed) {
        const auto* src = seed.metadata.Get<refuzz::fuzzer::SeedSourceMetadata>();
        if (src == nullptr || src->source != refuzz::fuzzer::SeedSource::kBootCorpus) {
            return;
        }
        if (const auto* admit =
                seed.metadata.Get<refuzz::fuzzer::SeedAdmissionStateMetadata>()) {
            if (admit->state == refuzz::fuzzer::SeedAdmissionState::kInactive) {
                return;
            }
        }
        if (seed.artifact == nullptr || !seed.artifact->valid()) {
            return;
        }
        std::size_t call_count = static_cast<std::size_t>(-1);  // null-artifact → tail
        if (auto prog = seed.artifact->As<refuzz::program::syz::Prog>()) {
            call_count = prog->calls().size();
        }
        ordered.emplace_back(call_count, CandidateSeed{seed.seed_id, seed.artifact});
    });
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<CandidateSeed> out;
    out.reserve(ordered.size());
    for (auto& [cost, cand] : ordered) {
        (void)cost;
        out.push_back(std::move(cand));
    }
    return out;
}

const char* SeedSourceName(refuzz::fuzzer::SeedSource source)
{
    switch (source) {
    case refuzz::fuzzer::SeedSource::kBootCorpus: return "boot_corpus";
    case refuzz::fuzzer::SeedSource::kMutation: return "mutation";
    case refuzz::fuzzer::SeedSource::kReplayHistory: return "replay_history";
    case refuzz::fuzzer::SeedSource::kFaultHistory: return "fault_history";
    }
    return "unknown";
}

void MergeDistinctCoverage(
    refuzz::fuzzer::IFeedbackStore* store,
    refuzz::core::metrics::Gauge* gauge,
    const std::vector<std::uint64_t>& hashes)
{
    if (store == nullptr || hashes.empty()) {
        return;
    }
    if (store->MergeCoverage(hashes, 0) != 0 && gauge != nullptr) {
        gauge->Set(static_cast<std::int64_t>(store->Count()));
    }
}

const char* TaskTierName(refuzz::queue::TaskTier tier)
{
    switch (tier) {
    case refuzz::queue::TaskTier::CandidateTriage: return "candidate_triage";
    case refuzz::queue::TaskTier::Candidate: return "candidate";
    case refuzz::queue::TaskTier::Triage: return "triage";
    case refuzz::queue::TaskTier::Smash: return "smash";
    case refuzz::queue::TaskTier::Explore: return "explore";
    }
    return "unknown";
}

struct CorpusCoverMergeResult {
    std::size_t admitted_gain = 0;
    bool measured = false;
};

// [exec-accounting 重构] raw-abnormal 细分计数(只对 abnormal event 生效)。
// 逐字段等价旧 MutationalConsumerStage::UpdateRawAbnormalStats —— 这本是 v1
// FuzzerLoop::UpdateRawAbnormalStats 的职责,现还给 loop。
void RecordRawAbnormalStats(refuzz::fuzzer::metrics::FuzzerMetrics& m,
                            const refuzz::core::channel_contract::ChannelEvent& event)
{
    namespace cc = refuzz::core::channel_contract;
    if (!event.IsAbnormal()) {
        return;
    }
    const auto* abnormal = event.AsAbnormal();
    if (abnormal == nullptr) {
        return;
    }
    if (abnormal->kind == cc::AbnormalKind::kHang) {
        if (m.results_raw_timeout) m.results_raw_timeout->Inc();
    } else {
        if (m.results_raw_executor_error) m.results_raw_executor_error->Inc();
        if (abnormal->kind == cc::AbnormalKind::kWorkerCrashed ||
            abnormal->kind == cc::AbnormalKind::kWorkerSignaled) {
            if (m.results_worker_crash_error) m.results_worker_crash_error->Inc();
        }
        if (abnormal->diagnostics.error_code == ERR_INVALID_INPUT) {
            if (m.results_invalid_input_error) m.results_invalid_input_error->Inc();
        } else if (abnormal->diagnostics.error_code == ERR_OUTPUT_TOO_LARGE) {
            if (m.results_output_too_large_error) m.results_output_too_large_error->Inc();
        }
    }
}

// [exec-accounting 重构] 据 verdict 写 cov gains + 终止分类计数。优先级顺序逐字段
// 搬自旧 MutationalConsumerStage::DispatchFeedback(leak 在 exec_error 前等语义保留)。
void RecordResultClassification(refuzz::fuzzer::metrics::FuzzerMetrics& m,
                                const refuzz::fuzzer::Verdict& v)
{
    if (v.cov_gain > 0 && m.cov_new_total) {
        m.cov_new_total->Inc(static_cast<uint64_t>(v.cov_gain));
    }
    if (v.cmp_gain > 0 && m.cov_cmp_new_total) {
        m.cov_cmp_new_total->Inc(static_cast<uint64_t>(v.cmp_gain));
    }
    if (v.is_crash && m.results_crash) {
        m.results_crash->Inc();
    } else if (v.is_timeout && m.results_timeout) {
        m.results_timeout->Inc();
    } else if (v.is_exec_error && m.results_exec_error) {
        m.results_exec_error->Inc();
    } else if (v.is_malformed && m.results_malformed_feedback) {
        m.results_malformed_feedback->Inc();
    } else if (v.is_coverage_empty && m.results_coverage_empty) {
        m.results_coverage_empty->Inc();
    }
}

} // namespace

FuzzerLoop::FuzzerLoop(queue::InMemoryTaskQueue& task_queue,
                       queue::InMemoryEventQueue& event_queue,
                       ICorpusStore& corpus,
                       const core::EngineHandle<IMutatorEngine>& mutator_handle,
                       const core::EngineHandle<ISchedulerEngine>& scheduler_handle,
                       const core::EngineHandle<IFeedbackEngine>& feedback_handle,
                       refuzz::logging::HostLogger&                             logger,
                       FuzzerLoopConfig config,
                       refuzz::core::metrics::MetricRegistry* metrics,
                       std::chrono::steady_clock::time_point                    session_start)
    : task_queue_(task_queue)
    , event_queue_(event_queue)
    , corpus_(corpus)
    , mutator_handle_(mutator_handle)
    , scheduler_handle_(scheduler_handle)
    , feedback_handle_(feedback_handle)
    , request_window_limit_(config.request_window_limit)
    , exec_timeout_ms_(config.exec_timeout_ms)
    , next_seed_id_(std::max<uint64_t>(2, config.initial_seed_id))
    , fuzzer_metrics_([&] {
        refuzz::fuzzer::metrics::FuzzerMetrics m{};
        if (metrics != nullptr) {
            m.Bind(*metrics);
        }
        return m;
    }())
    , corpus_manager_(corpus_,
                      scheduler_handle_,
                      corpus_inbox_,
                      config.corpus_max_drain,
                      metrics != nullptr ? &fuzzer_metrics_ : nullptr,
                      // [verdict 重构] admit_mode 决定准入策略(默认 kInteresting)。
                      config.admit_mode)
    , logger_(logger)
    // rng_ / next_job_id_ / mab_observation_seq_ 走声明侧默认值。
    // [v2 exectime split] session_start_ / fuzz_phase_started_:首次产 task 时用。
    , session_start_(session_start)
    // [v2 admit-worker async] worker 在 SetOnAdmit 之前必须 ready。Start() 在
    //   on_admit_ 回调装配前调用,首次 Enqueue 不会 race。
    , admit_worker_(std::make_unique<AsyncAdmitWorker>(
          config.corpus_persist_dir, &fuzzer_metrics_))
    // [Step 6 stage 清场] JobDeps —— 去 stage framework 死字段(feedback_handle/crash_pipeline/
    //   dispatcher/rng/high_watermark/next_job_id/pseudo_dispatch_telemetry;退役 stage 后无 reader)。
    , deps_{
          .mutator_handle    = mutator_handle_,
          .scheduler_handle  = scheduler_handle_,
          .corpus            = corpus_,
          .task_queue        = task_queue_,
          .corpus_inbox      = corpus_inbox_,
          .next_seed_id      = next_seed_id_,
          .logger            = logger_,
          .metrics           = fuzzer_metrics_,
          .exec_timeout_ms   = static_cast<uint64_t>(config.exec_timeout_ms),
          // core-path admit 经 SaveSeed 持久化 inactive metadata sidecar;empty=disable(test)。
          .corpus_persist_dir = config.corpus_persist_dir,
          // orchestrator 从 active_profile->capabilities.accept_bytes_only_fallback 拷入;
          //   smash/hints 的 profile-gated bytes-only path 读它决定 skip / 走 bytes 路径。
          .accept_bytes_only_fallback = config.accept_bytes_only_fallback,
          .seed_value_shadow_enabled = config.seed_value_shadow_enabled,
          .next_executor_id  = next_executor_id_,
          // [verdict 重构] core-path admit 经此调 OfferVerdict 让 corpus 自决准入。
          .corpus_admit      = &corpus_manager_,
      }
{
    // [SyzVegas baseline] task-MAB 决策器(默认模式,无 on/off 旋钮)。
    mab_task_selector_ = std::make_unique<mab::MabTaskSelector>(mab::MabTaskConfig{
        .time_cap_s = config.mab_time_cap_s,
    });
    // [Step 6 stage 清场] jobs-only 默认模式:ExploreJob 的 gen/mut/collide 三臂恒可用(无 flag
    //   判据)→ mab_active_ 恒 true(声明侧默认)。

    // [Step 1 catch-all 迁 loop] triage divert 闸(= 旧 mut_c triage_enabled)。pending 由
    // SetCatchAllPending 注入;两者都真时 catch-all 对 NewCov seed 走 divert + trampoline。
    catch_all_triage_enabled_ = config.catch_all_triage_enabled;

    // [v2 admit-worker async — 当前版本]
    //   on_admit_ 改成只 enqueue 到 AsyncAdmitWorker。worker 内部跑 SaveSeed +
    //   OnSeedAdmitted(后者会 RebuildChoiceTable,batch 内合并成最多一次)。
    //   语义保留:捕获**调用瞬间**的 mutator engine 指针(TryGet),所以即便随后切换
    //   engine,也是"admit-time active engine"被通知,与 v1 对齐。
    //   性能修复:整条 admit 链路(原同步阻塞主线程)→ 异步,主 fuzz 线程 O(1) 离开。
    admit_worker_->Start();
    auto merge_corpus_cover = [this](const refuzz::fuzzer::Seed& s)
        -> CorpusCoverMergeResult {
            // [Task A] merge the admitted program's full stable cover into the
            // corpus-only coverage store (syz_corpus_cover analog). Inline:
            // only corpus-admitted seeds reach here (post triage+minimize), so
            // it is not the per-execution hot path. The merge returns the NEW
            // corpus edges this admission added = the admitted-coverage signal.
            size_t admitted_gain = 0;
            bool   measured      = false;
            if (corpus_pc_feedback_store_ != nullptr) {
                if (const auto* cc =
                        s.metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>();
                    cc != nullptr && !cc->cover_hashes.empty()) {
                    admitted_gain =
                        corpus_pc_feedback_store_->MergeCoverage(cc->cover_hashes, 0);
                    if (fuzzer_metrics_.cov_corpus_new_total && admitted_gain > 0) {
                        fuzzer_metrics_.cov_corpus_new_total->Inc(
                            static_cast<uint64_t>(admitted_gain));
                    }
                    if (admitted_gain > 0) {
                        const auto count = static_cast<std::int64_t>(
                            corpus_pc_feedback_store_->Count());
                        if (fuzzer_metrics_.cov_corpus_pc) {
                            fuzzer_metrics_.cov_corpus_pc->Set(count);
                        }
                        if (fuzzer_metrics_.cov_corpus_unique) {
                            fuzzer_metrics_.cov_corpus_unique->Set(count);
                        }
                    }
                }
                measured = true;  // store present → admitted_gain is a real measurement (may be 0)
            }
            if (corpus_edge_feedback_store_ != nullptr) {
                if (const auto* cc =
                        s.metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>();
                    cc != nullptr && cc->signal_hashes_are_edges &&
                    !cc->signal_cover_hashes.empty()) {
                    const auto gain = corpus_edge_feedback_store_->MergeCoverage(
                        cc->signal_cover_hashes, 0);
                    if (gain > 0) {
                        const auto count = static_cast<std::int64_t>(
                            corpus_edge_feedback_store_->Count());
                        if (fuzzer_metrics_.cov_corpus_edge) {
                            fuzzer_metrics_.cov_corpus_edge->Set(count);
                        }
                        if (fuzzer_metrics_.cov_corpus_signal_unique) {
                            fuzzer_metrics_.cov_corpus_signal_unique->Set(count);
                        }
                    }
                }
            }
            return CorpusCoverMergeResult{admitted_gain, measured};
        };
    corpus_manager_.SetOnCoverMerge(
        [merge_corpus_cover](const refuzz::fuzzer::Seed& s) mutable {
            (void)merge_corpus_cover(s);
        });
    corpus_manager_.SetOnAdmit(
        [this, merge_corpus_cover](const refuzz::fuzzer::Seed& s) mutable {
            const CorpusCoverMergeResult cover_merge = merge_corpus_cover(s);
            // [SyzVegas baseline] reward 在 **completion** 结算(ProcessEventFeedback),不在
            // admission。这里只按 origin arm 记 admitted-coverage **诊断**(panel 的
            // found-vs-admitted 对照),不触 bandit、不做 lineage 回溯。
            if (cover_merge.measured && mab_active_) {
                const auto* lin0 = s.metadata.Get<refuzz::fuzzer::SeedLineageMetadata>();
                if (lin0 != nullptr) {
                    const mab::MabArm arm =
                        lin0->origin == refuzz::fuzzer::SeedOrigin::kMutate
                            ? mab::MabArm::kMutate : mab::MabArm::kGenerate;
                    mab_task_selector_->RecordAdmitDiagnostic(
                        arm, static_cast<double>(cover_merge.admitted_gain));
                }
            }
            // copy seed once for worker;mutator_handle TryGet 是 atomic acquire,
            // 取到的 engine* lifetime 由 Manager 保证 ≥ FuzzerLoop。
            refuzz::fuzzer::IMutatorEngine* engine =
                mutator_handle_.HasValue() ? mutator_handle_.TryGet() : nullptr;
            admit_worker_->Enqueue(s, engine);
        });

    // [v2 6b-1 — 当前版本] Bind policy publisher and publish startup policy names.
    // Must happen after handle+corpus_manager init so ActivePolicyName() is valid.
    if (metrics != nullptr) {
        policy_state_publisher_.Bind(*metrics);
        // Publish initial policy names so PolicyEngine::CurrentPoliciesMatch()
        // sees the right values on its first Evaluate() call.
        if (mutator_handle_.HasValue()) {
            policy_state_publisher_.Set("mutation",
                mutator_handle_.Get().ActivePolicyName());
        }
        if (scheduler_handle_.HasValue()) {
            policy_state_publisher_.Set("schedule",
                scheduler_handle_.Get().ActivePolicyName());
        }
        policy_state_publisher_.Set("corpus", corpus_manager_.ActivePolicyName());
    }
    // Publish boot-loaded corpus gauges before the first warm Tick. Runtime
    // corpus size/bytes publication stays owned by CorpusManager.
    corpus_manager_.PublishMetrics();

    // [Step 6] job 运行时不再由 env flag 门 —— fuzz loop 已删除 stage 路径(生产窗填 + consumer
    // chain),生产/消费全由 job 表达。原 REFUZZ_JOB_CORE_PATH / _ELABORATE / _ARBITER 三档恒开
    // (不再读 env),仍以 deps_.job_* 传给 job + 退役 stage(死码)+ core-path fanout 判据。
    // 所有 job env flag 已删:_PERCALL_ADMIT(per-call 恒开)+ _JOB_FANOUT(concurrent fan-out 恒开)。
    {
        // [request-stream capture] Built before the scheduler so the funnel hook
        // below can bind it. Off unless a path was configured, so a normal
        // measurement run pays nothing: no encoder, no file, no branch beyond one
        // null check per dispatch.
        if (!config.request_stream_capture_path.empty()) {
            RequestStreamSinkConfig scfg;
            scfg.path = config.request_stream_capture_path;
            request_stream_sink_ = std::make_unique<RequestStreamSink>(
                std::move(scfg), refuzz::program::syz::Target::linux_amd64());
        }

        job::JobScheduler::Deps jdeps;
        // [request-window] pull/window 窗口:scheduler 自持 awaiting-accept 集,上限
        //   dispatch_window_limit,由 accepted 生命周期事件(MarkAccepted)释放 credit —— 释放点
        //   从"task_queue 被 pop"精确到"Channel::Submit kAccepted"(= syz `requests − executing
        //   < 2·procs`)。
        jdeps.dispatch_window_limit = request_window_limit_;
        // [request-stream capture] TrySubmit is the one funnel both ctx.exec() and
        // ctx.emit() reach, so binding here records every dispatched request; binding
        // to either primitive alone would silently miss the other half of the workload.
        if (request_stream_sink_) {
            jdeps.observe_submit = [this](const job::Request& req) {
                request_stream_sink_->Record(req);
            };
        }
        // build_task:Request → HostFuzzTask(含通用 lineage 透传)。submit 两路共用。
        auto build_task = [this](std::uint64_t exec_id, const job::Request& req) {
            // [task 记账 —— loop 中央单点] 每个 arbiter task 过此一次,按 tier 分类:
            //   Explore(⑤)=ExploreJob gen/mut/collide 新产出 → generated_tasks;
            //   其余(①CandidateTriage/②Candidate/③Triage/④Smash = candidate 验证 / triage deflake /
            //   minimize / smash / hints / fault continuation)= 已有 seed 复跑 → reexec_tasks。
            //   取代 explore_job/fault_job 里散落的 Inc;run-limit 预算 executed=generated+reexec 据此。
            if (req.tier == refuzz::queue::TaskTier::Explore) {
                if (fuzzer_metrics_.generated_tasks) fuzzer_metrics_.generated_tasks->Inc();
            } else {
                if (fuzzer_metrics_.reexec_tasks) fuzzer_metrics_.reexec_tasks->Inc();
            }
            // [v2 exectime split] 首次 task 经此漏斗提交 = 迁移后"首次 produce 成功"的等价节点
            //   (jobs-only 下 producer stage 已删,ExploreJob gen/mut 产出也走 build_task)。
            //   一次性把 (now - session_start_).us 写入 fuzzer.fuzz_phase_started_us gauge,
            //   run_summary 据此派生 elapsed_fuzz_ms / exec_fuzz_s 剥离 Build/QEMU 启动开销;
            //   session_start_ = epoch(测试路径)时退化为 Set(0),口径与旧 producer 节点一致。
            if (!fuzz_phase_started_) {
                fuzz_phase_started_ = true;
                if (fuzzer_metrics_.fuzz_phase_started_us) {
                    int64_t offset_us = 0;
                    if (session_start_.time_since_epoch().count() != 0) {
                        offset_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - session_start_).count();
                        if (offset_us < 0) offset_us = 0;
                    }
                    fuzzer_metrics_.fuzz_phase_started_us->Set(offset_us);
                }
            }
            refuzz::queue::HostFuzzTask task;
            task.executor_id    = exec_id;
            if (req.artifact != nullptr && req.artifact->valid()) {
                task.artifact = *req.artifact;
            }
            task.payload        = req.payload;
            task.opts           = req.opts;
            task.seed_id        = req.seed_id;         // [Step 5] lineage(route-back job 留 0)
            task.origin_seed_id = req.origin_seed_id;
            task.important      = false;
            // [RTT] decide RTT-trace sampling ONCE here (submit time), sticky in
            // trace.sampled + gated wire flag, so guest start-ping and completion
            // emit use the SAME decision (mirrors syzkaller prepare()-time Sampled).
            const bool rtt_sampled =
                refuzz::logging::HostLogger::Instance().ShouldSampleTaskTrace(exec_id);
            task.trace.sampled = rtt_sampled;
            if (rtt_sampled) {
                task.opts.flags |=
                    static_cast<std::uint32_t>(refuzz::proto::kExecFlagTraceSampled);
            }
            return task;
        };
        jdeps.submit = [this, build_task](std::uint64_t exec_id, const job::Request& req) {
            // [Step 5] 入 req.tier 打的档(job 按语义打:core-path→Triage/CandidateTriage、
            // fault/hints continuation→Smash);Pop 侧严格 Order 定优先。未打档 job 默认 Triage。
            (void)task_queue_.Push(build_task(exec_id, req), req.tier);
        };
        // [Step 5] emit(fire-and-forget)提交口 → req.tier 档(smash→Smash、explore→Explore),
        // unrouted(不进 router → 结果回 catch-all)。
        jdeps.submit_exploration = [this, build_task](std::uint64_t exec_id, const job::Request& req) {
            (void)task_queue_.Push(build_task(exec_id, req), req.tier);
        };
        // [request-window] 不再用 task_queue.PendingSize() 当填窗门:executor Pop 走任务但尚未
        //   Channel::Submit accept 时,队列深度已经下降,会过早释放 credit。填窗门由
        //   dispatch_window_limit + awaiting-accept 窗口拥有;continuation(High)与 emit(Low)
        //   共用这一个窗,优先级由 tiered Pop 定。
        jdeps.alloc_exec_id = [this]() { return next_executor_id_++; };
        job_sched_ = std::make_unique<job::JobScheduler>(std::move(jdeps));
    }
    deps_.spawn_job = [this](job::JobFn fn) { return SpawnJob(std::move(fn)); };
    deps_.job_elaborate = true;
    deps_.job_arbiter   = true;

    if (!config.logs_dir.empty()) {
        // [seed-value signals shadow] opt-in JSONL of (signals, realized yield)
        // per mutation outcome. Default off → no file, no overhead.
        if (config.seed_value_shadow_enabled) {
            seed_value_shadow_ = std::make_unique<SeedValueShadowSink>(
                (std::filesystem::path(config.logs_dir) / "seed_value_shadow.jsonl")
                    .string());
            // [belief-graph Phase B] where to persist the calibrated (α,β) posterior at shutdown — the
            // frontier-corrected prior the per-seed belief_value can't capture. Same gate as the shadow.
            belief_posterior_path_ =
                (std::filesystem::path(config.logs_dir) / "belief_posterior.tsv").string();
            // [seed-future-value §5.1] value-realized downstream-yield sidecar:
            // shares the shadow gate + logs dir; RAII-dumps on dtor. Observation only.
            lineage_yield_store_ =
                std::make_unique<refuzz::fuzzer::SeedLineageYieldStore>(
                    (std::filesystem::path(config.logs_dir) / "seed_lineage_yield.jsonl")
                        .string());
            // [cluster-unit metric — Tier 1, §5.2a] page-bucketed sibling, same
            // lifecycle; lets us compare distinct-block vs distinct-cluster yield
            // offline (burst compression / race / future-rank-corr).
            lineage_yield_store_cluster_ =
                std::make_unique<refuzz::fuzzer::SeedLineageYieldStore>(
                    (std::filesystem::path(config.logs_dir) / "seed_lineage_yield_cluster.jsonl")
                        .string());
        }
        // [variant-handler-binding 2026-06-18] live per_call variant->handler map.
        // INDEPENDENT gate (own path; not tied to the shadow flag): builds the binding
        // entry-side of the structural-horizon region, dumped variant_handler_map.jsonl.
        if (!config.variant_handler_map_path.empty()) {
            variant_handler_map_ = std::make_unique<refuzz::fuzzer::VariantHandlerMap>(
                (std::filesystem::path(config.logs_dir) / "variant_handler_map.jsonl").string());
            variant_handler_map_->LoadFunctionMap(config.variant_handler_map_path);
        }
        // [belief-graph / variant-binding] one id->name table shared by both consumers:
        // the binding map's SetVariantNames AND EmitSeedValueShadow's executed_variants.
        // SyscallMeta::id() is the dense index into Target::syscalls(), so a flat vector
        // suffices. Built only when one of those is active (kernel/syz run) — for other
        // families the gates are off and linux_amd64() is never forced.
        if (seed_value_shadow_ != nullptr || variant_handler_map_ != nullptr) {
            const auto& tgt = refuzz::program::syz::Target::linux_amd64();
            variant_id_to_name_.assign(tgt.syscalls().size(), std::string{});
            for (const auto& sc : tgt.syscalls()) {
                if (sc && sc->id() < variant_id_to_name_.size()) {
                    variant_id_to_name_[sc->id()] = sc->name();
                }
            }
            if (variant_handler_map_ != nullptr) {
                variant_handler_map_->SetVariantNames(variant_id_to_name_);
            }
        }
    }

    // [event-driven spawn] ctor 末尾首 spawn ExploreJob(gen/mut 探索的运行时表达);之后由其 on_done
    //   自补一条(见 SpawnExploreJob),不再每 tick 轮询存活位。SpawnJob 只入队,首个 RunOnce 的
    //   PumpJobs 才 Launch。candidate feeder 不在此起(需 catch_all_pending_,由 SetCatchAllPending 起)。
    // [fixed request stream, Step 4] suppress_default_producer=true (fixed-input mode
    //   only) skips this -- the caller (Orchestrator::Build) calls
    //   SpawnFixedInputProducerJob() instead, making the stream the loop's sole
    //   task source (plan §6.2). Default false = every existing caller unchanged.
    if (!config.suppress_default_producer) {
        SpawnExploreJob();
    }
}

FuzzerLoop::~FuzzerLoop()
{
    // Closed first: the sink is fed from the scheduler's funnel, and the file has
    // to be complete even when the run ends through the stop path rather than a
    // clean drain (a truncated capture is indistinguishable from a short workload).
    if (request_stream_sink_) {
        request_stream_sink_->Close();
    }
    // Job retain actions capture deps_/corpus_manager_/next_seed_id_, so jobs must
    // be cancelled and joined before the rest of FuzzerLoop tears down. Cancelled
    // jobs intentionally do not run retain actions.
    for (auto& j : jobs_) {
        j->CancelAndJoin();
    }
    jobs_.clear();
    routed_jobs_.clear();
    while (!job_spawn_queue_.empty()) {
        job_spawn_queue_.pop();
    }
    if (job_sched_) {
        job_sched_->Shutdown();
    }
    // [v2 admit-worker async] 必须最先 StopAndDrain admit_worker_:
    //   (a) drain pending admit,确保所有 admitted seed 触发最后一次
    //       OnSeedAdmitted -> RebuildChoiceTable;
    //   (b) join worker 线程,确保它不再访问 mutator_handle_/corpus_store_。
    if (admit_worker_) {
        admit_worker_->StopAndDrain();
    }
    FinalizeCorpusForShutdown();
    // [persist-at-shutdown] corpus 一次性落盘(不再走 admit 热路径)。此刻 store 已是
    //   覆盖所有权不变量维护下的最小覆盖集(被驱逐的 seed 从不落盘,无需逐-drop 删盘)。
    //   语义提醒:进程被 SIGKILL 跳过本析构 → 该 run 的 corpus 不落盘(本用例可接受;
    //   需崩溃前持久化时再加周期 flush)。
    if (!deps_.corpus_persist_dir.empty()) {
        (void)refuzz::fuzzer::CorpusDiskIO::SaveAll(
            corpus_, deps_.corpus_persist_dir);
    }
}

void FuzzerLoop::FinalizeCorpusForShutdown()
{
    // [coverage-ownership bound] one final invariant pass before persist: re-run the
    // batch best-owner election so the persisted corpus and final metrics see the
    // tightest minimal covering set (and any drift is reconciled).
    corpus_manager_.EstablishInvariantFromStore();
    corpus_manager_.PublishMetrics();
    // [belief-graph Phase B] persist the frontier-calibrated (α,β) posterior (gated by the shadow opt-in).
    if (!belief_posterior_path_.empty() && scheduler_handle_.Get().BeliefActive()) {
        scheduler_handle_.Get().DumpBeliefPosterior(belief_posterior_path_);
    }
}

void FuzzerLoop::SetCrashPipeline(crash::CrashPipelineManager* manager)
{
    crash_pipeline_ = manager;
}

void FuzzerLoop::SetLifecycleQueue(queue::InMemoryLifecycleQueue* queue)
{
    lifecycle_queue_.store(queue, std::memory_order_release);
}

void FuzzerLoop::SetFeedbackStore(IFeedbackStore* store)
{
    feedback_store_ = store;
    if (store != nullptr && fuzzer_metrics_.cov_unique != nullptr) {
        fuzzer_metrics_.cov_unique->Set(static_cast<std::int64_t>(store->Count()));
    }
}
void FuzzerLoop::SetCmpFeedbackStore(IFeedbackStore* store)
{
    cmp_feedback_store_ = store;
    if (store != nullptr && fuzzer_metrics_.cov_cmp_unique != nullptr) {
        fuzzer_metrics_.cov_cmp_unique->Set(static_cast<std::int64_t>(store->Count()));
    }
}

void FuzzerLoop::SetAllPcFeedbackStore(IFeedbackStore* store)
{
    all_pc_feedback_store_ = store;
    if (store != nullptr && fuzzer_metrics_.cov_all_pc != nullptr) {
        fuzzer_metrics_.cov_all_pc->Set(static_cast<std::int64_t>(store->Count()));
    }
}

void FuzzerLoop::SetCorpusPcFeedbackStore(IFeedbackStore* store)
{
    corpus_pc_feedback_store_ = store;
    deps_.corpus_cover_store = store;
    if (store != nullptr) {
        const auto count = static_cast<std::int64_t>(store->Count());
        if (fuzzer_metrics_.cov_corpus_pc != nullptr) {
            fuzzer_metrics_.cov_corpus_pc->Set(count);
        }
        if (fuzzer_metrics_.cov_corpus_unique != nullptr) {
            fuzzer_metrics_.cov_corpus_unique->Set(count);
        }
    }
}

void FuzzerLoop::SetAllEdgeFeedbackStore(IFeedbackStore* store)
{
    all_edge_feedback_store_ = store;
    if (store != nullptr && fuzzer_metrics_.cov_all_edge != nullptr) {
        fuzzer_metrics_.cov_all_edge->Set(static_cast<std::int64_t>(store->Count()));
    }
}

void FuzzerLoop::SetCorpusEdgeFeedbackStore(IFeedbackStore* store)
{
    corpus_edge_feedback_store_ = store;
    if (store != nullptr) {
        const auto count = static_cast<std::int64_t>(store->Count());
        if (fuzzer_metrics_.cov_corpus_edge != nullptr) {
            fuzzer_metrics_.cov_corpus_edge->Set(count);
        }
        if (fuzzer_metrics_.cov_corpus_signal_unique != nullptr) {
            fuzzer_metrics_.cov_corpus_signal_unique->Set(count);
        }
    }
}

void FuzzerLoop::SetMabCandidateProbe(std::function<std::size_t()> probe)
{
    mab_candidate_probe_ = std::move(probe);
}

void FuzzerLoop::SetStabilityOracle(IStabilityOracle* oracle)
{
    deps_.stability_oracle = oracle;
}

void FuzzerLoop::SetRetryPolicy(IRetryPolicy* policy)
{
    deps_.retry_policy = policy;
}

void FuzzerLoop::SetPriorityCalculator(IPriorityCalculator* calc)
{
    deps_.priority_calculator = calc;
}


void FuzzerLoop::SetSaturationFilter(ISaturationFilter* filter)
{
    deps_.saturation_filter = filter;
}

void FuzzerLoop::ProcessEventFeedback(ConsumerCtx& cctx)
{
    namespace cc = refuzz::core::channel_contract;
    auto& event = cctx.event;
    auto& m     = fuzzer_metrics_;

    // 2. event-type 桶计数 —— **每个** event 都记。这正是修复点:旧代码在 catch-all
    //    stage 记,被 reexec stage 认领的 event 到不了那里 → 漏计;现在 loop 见每个
    //    event,triage/verify/minimize 的 reexec 也被算进 results_completion 等。
    if (event.IsCompletion()) {
        if (m.results_completion) m.results_completion->Inc();
        if (const auto* completion = event.AsCompletion(); completion != nullptr) {
            // [两层语义] Completion 侧三种终态各自计数;kTimeout = program watchdog
            // 判的超时(数据有效),与 fuzzer.results{kind=timeout}(= daemon watchdog
            // 判的 task hang)不是一回事。
            if (completion->kind == cc::CompletionKind::kPartial &&
                m.results_partial_completion) {
                m.results_partial_completion->Inc();
            } else if (completion->kind == cc::CompletionKind::kTimeout &&
                       m.results_program_timeout) {
                m.results_program_timeout->Inc();
            }
        }
    } else if (event.IsAbnormal()) {
        if (m.results_abnormal) m.results_abnormal->Inc();
    } else if (event.IsFault()) {
        if (m.results_fault) m.results_fault->Inc();
    }

    if (const auto* abnormal = event.AsAbnormal();
        abnormal != nullptr &&
        abnormal->kind == cc::AbnormalKind::kHarnessFatal) {
        // [harness-fatal 语义修正] 这里只做首次去重 + 计数/日志，**不再**把该事件
        // 当作全局终止信号，也不再提前 return：kHarnessFatal 是一条任务级 abnormal
        // 终态，必须走正常结算路径把结果投递给 owner job / catch-all，否则该
        // executor_id 的请求窗口永远不会释放。全局停止与否由 channel 恢复策略
        // （kFailChannel → lifecycle kFailed）决定，见 Orchestrator::ChannelFailed。
        bool expected = false;
        if (harness_fatal_seen_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            if (m.results_harness_fatal) {
                m.results_harness_fatal->Inc();
            }
            logger_.Log(
                "FuzzerLoop", "harness_fatal",
                {refuzz::logging::Field("executor_id", abnormal->ctx.executor_id),
                 refuzz::logging::Field("worker_id", abnormal->ctx.worker_id),
                 refuzz::logging::Field("error_code",
                                        abnormal->diagnostics.error_code)});
        }
    }

    if (const auto* abnormal = event.AsAbnormal();
        abnormal != nullptr &&
        abnormal->kind == cc::AbnormalKind::kHarnessRecovered) {
        logger_.Log(
            "FuzzerLoop", "harness_recovered",
            {refuzz::logging::Field("executor_id", abnormal->ctx.executor_id),
             refuzz::logging::Field("worker_id", abnormal->ctx.worker_id),
             refuzz::logging::Field("error_code",
                                    abnormal->diagnostics.error_code)});
    }

    // 3. raw-abnormal 细分(只对 abnormal 生效)。
    RecordRawAbnormalStats(m, event);

    // 4. Process **一次** → 存进 cctx 供 owner stage 复用,并据 verdict 写其余全局计数。
    if (!feedback_handle_.HasValue()) {
        // 无 engine(部分单测路径):只 event-type 计数;owner stage 经
        // FeedbackOutputFor 看到 nullopt → 自决跳过 feedback 依赖逻辑。
        return;
    }
    cctx.feedback_output = feedback_handle_.Get().Process(event);
    const auto& out = *cctx.feedback_output;
    if (feedback_store_ != nullptr && fuzzer_metrics_.cov_unique != nullptr) {
        fuzzer_metrics_.cov_unique->Set(
            static_cast<std::int64_t>(feedback_store_->Count()));
    }
    if (cmp_feedback_store_ != nullptr && fuzzer_metrics_.cov_cmp_unique != nullptr) {
        fuzzer_metrics_.cov_cmp_unique->Set(
            static_cast<std::int64_t>(cmp_feedback_store_->Count()));
    }

    // 数据平面事件(completion/abnormal,带 CompletionContext)才记执行计数 / 分类;
    // fault 无 ctx —— 镜像旧 DispatchFeedback 的 cc==nullptr early-return(fault 只
    // 计 results_fault,crash_payload 由 mutational catch-all 转发到 pipeline)。
    const auto* mab_cc = CompletionCtxOf(event);
    if (mab_cc == nullptr) {
        return;
    }
    // calls_executed:feedback 已在 observation 里数好(out.executed_calls),loop 直接
    //   写 —— **不**重 decode SyzExecResult。
    if (out.executed_calls != 0 && m.calls_executed) {
        m.calls_executed->Inc(out.executed_calls);
    }
    // [List3 — all_pc/all_edge 口径对齐 syz maxSignal] 只并入 **Completion**(非 abnormal)
    // 执行的覆盖。
    //   syz 的 maxSignal 只由 triageProgCall→addRawMaxSignal 累积,而那条路径被
    //   dontTriage(Hanged)/Info==nil(Crashed)挡住 → abnormal 执行的覆盖从不进 maxSignal。
    //   List2 的 kcov from_abnormal guard 也据此把 abnormal 挡在 admission 之外。此前
    //   all_pc/all_edge 却对**每个 event(含真 abnormal)**都并入,使这两个"全量"指标与
    //   admission/corpus 语义不一致:abnormal 的 PC 进了 all_* 却进不了 max-signal/corpus。
    //   现在统一:abnormal 执行对全量覆盖也 inert。
    //   注:program-child 自身 crash 现在是 CompletionKind::kChildAborted(List1 方案 A,
    //   覆盖有效),走 IsCompletion 分支,照常计入 —— 与它进 max-signal/corpus 的处理一致。
    if (event.IsCompletion()) {
        if (const auto* kco =
                out.observation.Get<refuzz::fuzzer::KernelExecutionObservation>();
            kco != nullptr) {
            MergeDistinctCoverage(all_pc_feedback_store_, fuzzer_metrics_.cov_all_pc,
                                  kco->program_raw_pcs);
            MergeDistinctCoverage(all_edge_feedback_store_, fuzzer_metrics_.cov_all_edge,
                                  kco->program_edge_hashes);
        }
    }
    RecordResultClassification(m, out.verdict);
    if (out.verdict.interesting && m.results_interesting) {
        m.results_interesting->Inc();
    }
}

void FuzzerLoop::SettleFeedbackCompletion(ConsumerCtx& cctx)
{
    // post-Process feedback 结算。JobScheduler 不承接业务 completion;这里仍由 FuzzerLoop
    // 统一处理 MAB reward / seed reward / shadow observation。
    if (!cctx.feedback_output.has_value()) {
        return;   // 无 engine / fault 在 FL 早退 → 无 output 可结算
    }
    auto&       event  = cctx.event;
    const auto& out    = *cctx.feedback_output;
    const auto* mab_cc = CompletionCtxOf(event);
    if (mab_cc == nullptr) {
        return;   // fault 无 CompletionContext
    }
    // [seed-value shadow] elapsed wall-clock since session start (negative when
    // session_start_ is the test-default epoch → sink is null there anyway).
    double ct_elapsed_s = -1.0;
    if (session_start_.time_since_epoch().count() != 0) {
        ct_elapsed_s = std::chrono::duration<double>(
                           std::chrono::steady_clock::now() - session_start_)
                           .count();
    }

    // [seed-value signals shadow] one row per mutation outcome. origin_seed_id!=0
    // ⟺ mutated from that parent corpus seed (generation = 0). Observation only.
    if (seed_value_shadow_ != nullptr && mab_cc->origin_seed_id != 0) {
        EmitSeedValueShadow(mab_cc->origin_seed_id, out, ct_elapsed_s);
    }
    // [belief-graph Phase B] region-precise live calibration — bump each edge's (α,β) from THIS exec, for
    // every execution with coverage (not just admitted-seed mutations: the unlock is real regardless of
    // the parent's corpus status). Per-call provenance: executed = variants whose calls ran (precondition
    // A ran); new_by_variant[B] = the globally-new PCs B's call produced (so the graph can test whether
    // B's new frontier landed in a SPECIFIC edge's gated slice R, not just "B produced new somewhere").
    // Gated on a loaded graph. Calibrates the posterior; drives no selection (shadow).
    if (scheduler_handle_.Get().BeliefActive()) {
        if (const auto* kco =
                out.observation.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
            const std::unordered_set<std::uint64_t> newpc(out.new_signal_hashes.begin(),
                                                          out.new_signal_hashes.end());
            std::unordered_set<std::string> executed;
            std::unordered_map<std::string, std::vector<std::uint64_t>> new_by_variant;
            for (const auto& call : kco->per_call) {
                if (!call.executed || call.syscall_id >= variant_id_to_name_.size()) {
                    continue;
                }
                const std::string& name = variant_id_to_name_[call.syscall_id];
                if (name.empty()) {
                    continue;
                }
                executed.insert(name);
                if (!newpc.empty()) {
                    for (const std::uint64_t pc : call.coverage_hashes) {
                        if (newpc.count(pc) != 0) {
                            new_by_variant[name].push_back(pc);  // B's globally-new PCs (tested against R)
                        }
                    }
                }
            }
            if (!executed.empty()) {
                scheduler_handle_.Get().ObserveBelief(executed, new_by_variant);
            }
        }
    }
    // [seed-future-value §5.1] attribute this outcome's coverage to its lineage
    // root base seed (depth-bucketed). Observation only — drives no selection.
    if (lineage_yield_store_ != nullptr && mab_cc->origin_seed_id != 0) {
        FeedLineageYield(mab_cc->origin_seed_id, out);
    }
    // [variant-handler-binding] accumulate this exec's per_call variant->handler map
    // (per_call[i].syscall_id -> functions of per_call[i].coverage_hashes). Every exec
    // (not just admits / mutations) so the binding grows with all observed dispatch.
    if (variant_handler_map_ != nullptr) {
        if (const auto* kobs =
                out.observation.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
            variant_handler_map_->OnExec(*kobs);
            constexpr std::uint32_t kVariantHandlerFlushEvery = 256;
            if (++variant_handler_flush_ctr_ % kVariantHandlerFlushEvery == 0) {
                variant_handler_map_->Flush();
            }
        }
    }

    // [reFuzz reward] reward 在 completion 结算(每个 producer 任务一次,win + miss)。
    //   task-MAB:OnEvent 用 found cov + 真实 t 结算产出 arm(miss=0→g=−t·R→Ĝ 回落)。
    //   seed-MAB:若本 executor 是 mutation 任务,用同一 found cov + t 结算被变异的 seed
    //             (mutate_seed_for_exec_ 在产出时记录;OnSeedReward 走相对货币 Cmut/Tmut)。
    //   off / 非 MAB 产出 → no-op。
    if (mab_active_) {
        const std::uint64_t exec_id = ExecutorIdOf(event);
        const double        found   = static_cast<double>(out.verdict.cov_gain);
        // [real triage-immune time] t = guest exec 窗(worker_done−worker_start),秒。host 墙钟
        //   (queue/submit)会被 forced-triage 抢 executor slot 污染;guest 内执行窗不受 host 侧
        //   triage 调度影响 → 干净的 per-task t。缺时间戳(非真实 backend / 漏 stamp)→ nominal
        //   task time,只影响 reward 观测。MabReward 内部按 mab_time_cap_s 截顶 outlier。
        constexpr double kNominalTaskTimeS = 0.05;
        double           task_time_s = kNominalTaskTimeS;
        if (mab_cc->trace.worker_done_ts_us > mab_cc->trace.worker_start_ts_us &&
            mab_cc->trace.worker_start_ts_us > 0) {
            task_time_s = static_cast<double>(mab_cc->trace.worker_done_ts_us -
                                              mab_cc->trace.worker_start_ts_us) /
                          1.0e6;
        }
        mab_task_selector_->OnEvent(exec_id, found, task_time_s);
        std::optional<refuzz::fuzzer::SeedSelection> seed_selection;
        {
            std::lock_guard<std::mutex> lk(mutate_seed_mu_);
            auto seed_it = mutate_seed_for_exec_.find(exec_id);
            if (seed_it != mutate_seed_for_exec_.end()) {
                seed_selection = seed_it->second;
                mutate_seed_for_exec_.erase(seed_it);
            }
        }
        if (seed_selection.has_value()) {
            if (scheduler_handle_.HasValue()) {
                const auto& s = *seed_selection;  // {seed_id, pr, γ} —— 本任务那次抽样的快照
                scheduler_handle_.Get().OnSeedReward(s.seed_id, s.pr, s.gamma, found,
                                                     task_time_s);
            }
        }
    }
}

void FuzzerLoop::SetCatchAllPending(std::shared_ptr<PendingSeedMap> pending)
{
    catch_all_pending_ = std::move(pending);
    // [event-driven] candidate 模式就绪(boot corpus 已在 pending 区)→ 触发一次 bootstrap:
    //   spawn candidate feeder(取代旧 RuntimeTick 里每 tick 轮询 candidate_feeder_alive_)。
    MaybeSpawnCandidateFeeder();
}

void FuzzerLoop::RecordCandidateExec(std::uint64_t exec_id, std::uint64_t seed_id,
                                     int attempt)
{
    // feeder on_submitted 登记在飞 candidate;completion path 据 exec_id 命中 →
    // 走 kBootCorpus 分支。scheduler 线程和 FuzzerLoop 线程并发,表内置锁。
    std::lock_guard<std::mutex> lk(candidate_mu_);
    candidate_exec_[exec_id] = CandidateExecInfo{seed_id, attempt};
}

std::vector<FuzzerLoop::CandidateExecInfo> FuzzerLoop::DrainCandidateRetries()
{
    // feeder 每轮取走本轮 flaky 重试(std::move + clear)→ 据 seed_id 从 pending 区重 emit ②。
    std::lock_guard<std::mutex> lk(candidate_mu_);
    std::vector<CandidateExecInfo> out = std::move(candidate_retry_);
    candidate_retry_.clear();
    return out;
}

void FuzzerLoop::ProcessCatchAllCompletion(
    ConsumerCtx& cctx, const job::ExecResult& result)
{
    namespace fuzzer = refuzz::fuzzer;
    auto& event = cctx.event;

    // [Step 2 candidate] 本 completion 是否 candidate re-verify(② exec):查在飞表(feeder 提交
    // 时经 RecordCandidateExec 记)。命中 → 走 kBootCorpus 分支(新覆盖 → tier① triage;flaky →
    // 重试/丢);未命中 → 普通 fuzz catch-all(kMutation → tier③)。
    const std::uint64_t exec_id = ExecutorIdOf(event);
    CandidateExecInfo cand_info{};
    bool is_candidate = false;
    {
        std::lock_guard<std::mutex> lk(candidate_mu_);
        auto cand_it = candidate_exec_.find(exec_id);
        if (cand_it != candidate_exec_.end()) {
            is_candidate = true;
            cand_info = cand_it->second;
            candidate_exec_.erase(cand_it);
        }
    }

    // feedback 已在 ProcessEventFeedback Process 过一次(有状态,绝不重复调)→ 复用缓存
    // verdict。三类 event 都进 —— fault 在 CompletionCtxOf==nullptr 时只转发 crash_payload
    // (等价旧 mut_c DispatchFeedback 的 cc==nullptr early-return)。
    const auto* out = cctx.feedback_output ? &*cctx.feedback_output : nullptr;
    if (out != nullptr &&
        (event.IsCompletion() || event.IsAbnormal() || event.IsFault())) {
        const auto& v = out->verdict;
        // crash → pipeline(fault 也可能携带 crash_payload)。
        if (out->crash_dispatch.has_value() && crash_pipeline_ != nullptr) {
            crash_pipeline_->Process(*out->crash_dispatch);
        }
        // 仅数据平面事件(completion/abnormal,含 CompletionContext)才编排 scheduler / admit。
        const auto* c = CompletionCtxOf(event);
        if (c != nullptr) {
            // scheduler disposition(scheduler 自映射 boost/cool/neutral)。
            if (scheduler_handle_.HasValue()) {
                scheduler_handle_.Get().OnFeedback(c->seed_id, v.disposition);
            }
            // interesting → mark(results_interesting 计数已在 ProcessEventFeedback 记)。
            if (v.interesting) {
                corpus_.MarkInteresting(c->seed_id);
            }
            // [Step 2 candidate] candidate re-verify 的 seed source = kBootCorpus → OfferVerdict
            // 盖 SeedSourceMetadata{kBootCorpus} → triage_stage 据此打 tier①(CandidateTriage);
            // 普通 fuzz 新程序 = kMutation → tier③。
            const auto source = is_candidate ? fuzzer::SeedSource::kBootCorpus
                                             : fuzzer::SeedSource::kMutation;
            // Core-path side-effect 的唯一入口:调用恰好一次
            // MaybeSpawnCorePathFromCompletion,避免和 RunOnce routed 分支重复 spawn。
            bool diverted = RouteCorePathFromCompletion(
                cctx, result, source, is_candidate, is_candidate ? cand_info.seed_id : 0,
                cand_info.attempt,
                /*allow_direct_inbox_admit=*/true);
            // [Step 2 candidate] flaky candidate(本次没截到可 triage 的 NewCov seed):给第二次
            // 机会 —— attempt+1 < 上限 → 排队让 feeder 重 emit ②(attempt+1);否则耗尽淘汰
            // (= syz fuzzer.go:198-213)。candidate 唯有经 triage(①)stable 才入 corpus。
            if (is_candidate && !diverted) {
                constexpr int kMaxCandidateAttempts = 3;  // = syz maxCandidateAttempts
                if (cand_info.attempt + 1 < kMaxCandidateAttempts) {
                    {
                        std::lock_guard<std::mutex> lk(candidate_mu_);
                        candidate_retry_.push_back(
                            CandidateExecInfo{cand_info.seed_id, cand_info.attempt + 1});
                    }
                    // [event-driven] 新 retry 入队 → feeder 空闲则补 spawn(锁外调,MaybeSpawn 内再锁)。
                    MaybeSpawnCandidateFeeder();
                } else if (catch_all_pending_ != nullptr) {
                    catch_all_pending_->Erase(cand_info.seed_id);
                }
            }
        }
    }

    // Per-task trace emission runs for the full terminal population via
    // EmitCompletionTaskTrace(), not only the catch-all completion path.
}

void FuzzerLoop::EmitCompletionTaskTrace(ConsumerCtx& cctx)
{
    auto& event = cctx.event;
    // Emit only the compact trace rows selected at task construction time.
    auto emit_task_trace = [&event](const refuzz::core::channel_contract::CompletionContext& ctx,
                                    const char* path, int kind) {
        auto& logger = refuzz::logging::HostLogger::Instance();
        // [RTT] use the sticky decision made at submit (build_task), NOT a fresh
        // ShouldSampleTaskTrace draw — the two must agree so a task that rang the
        // start-ping is exactly the one whose row we emit (and vice versa).
        if (!ctx.trace.sampled) {
            return;
        }
        const auto& tr = ctx.trace;
        std::vector<refuzz::logging::HostLogField> fields{
            refuzz::logging::Field("executor_id", ctx.executor_id),
            refuzz::logging::Field("channel_id", event.channel_id),
            refuzz::logging::Field("worker_id", ctx.worker_id),
            refuzz::logging::Field("path", path),
            refuzz::logging::Field("kind", kind),
            refuzz::logging::Field("submit_attempt", tr.submit_attempt),
            refuzz::logging::Field("worker_clock_guest", tr.worker_clock_is_guest_monotonic),
            refuzz::logging::Field("task_queue_push_ts_us", tr.task_queue_push_ts_us),
            refuzz::logging::Field("task_queue_pop_ts_us", tr.task_queue_pop_ts_us),
            refuzz::logging::Field("dispatch_prep_done_ts_us", tr.dispatch_prep_done_ts_us),
            refuzz::logging::Field("data_plane_call_ts_us", tr.data_plane_call_ts_us),
            refuzz::logging::Field("worker_start_ack_host_ts_us", tr.worker_start_ack_host_ts_us),
            refuzz::logging::Field("completion_observed_host_ts_us",
                                   tr.completion_observed_host_ts_us),
            refuzz::logging::Field("output_copied_host_ts_us",
                                   tr.output_copied_host_ts_us),
            refuzz::logging::Field("worker_start_ts_us", tr.worker_start_ts_us),
            refuzz::logging::Field("worker_done_ts_us", tr.worker_done_ts_us),
            refuzz::logging::Field("channel_event_queued_ts_us", tr.channel_event_queued_ts_us),
            refuzz::logging::Field("executor_event_forwarded_ts_us", tr.executor_event_forwarded_ts_us),
            refuzz::logging::Field("fuzzer_feedback_processed_ts_us", tr.fuzzer_feedback_processed_ts_us),
        };
        logger.Log("FuzzerLoop", "task_trace", std::move(fields));
    };
    if (auto* p = event.AsCompletion(); p != nullptr) {
        if (p->ctx.trace.sampled) {
            p->ctx.trace.fuzzer_feedback_processed_ts_us = refuzz::core::MonotonicNowUs();
        }
        emit_task_trace(p->ctx, "completion", static_cast<int>(p->kind));
    } else if (auto* p = event.AsAbnormal(); p != nullptr) {
        if (p->ctx.trace.sampled) {
            p->ctx.trace.fuzzer_feedback_processed_ts_us = refuzz::core::MonotonicNowUs();
        }
        emit_task_trace(p->ctx, "abnormal", static_cast<int>(p->kind));
    }
}

bool FuzzerLoop::MaybeSpawnCorePathFromCompletion(
    ConsumerCtx& cctx,
    const job::ExecResult& result,
    refuzz::fuzzer::SeedSource source,
    bool is_candidate,
    std::uint64_t candidate_seed_id,
    int candidate_attempt,
    bool allow_direct_inbox_admit)
{
    namespace fuzzer = refuzz::fuzzer;

    const auto* c = CompletionCtxOf(cctx.event);
    const auto* out = cctx.feedback_output ? &*cctx.feedback_output : nullptr;
    if (c == nullptr || out == nullptr || deps_.corpus_admit == nullptr) {
        return false;
    }

    // syz processResult only creates triage jobs when coverage collection found
    // new signal. In reFuzz this is represented by corpus OfferVerdict with
    // divert=true: build a transient seed for the core-path job, not an inbox
    // admission.
    const bool divert = catch_all_triage_enabled_ && catch_all_pending_ != nullptr;
    if (!divert && !allow_direct_inbox_admit) {
        return false;
    }

    // [per-call novelty — syz job.calls seed] discovery-exec per-call newSignal,
    // built from THIS exec's per-call observation.
    std::vector<CorePathChasedCall> initial_calls;
    if (const auto* kco = out->observation.Get<fuzzer::KernelExecutionObservation>()) {
        for (std::size_t i = 0; i < kco->per_call.size(); ++i) {
            const auto& call = kco->per_call[i];
            if (call.novel_signal_hashes.empty()) {
                continue;
            }
            CorePathChasedCall cc;
            cc.call_index              = static_cast<int>(i);
            cc.new_signal_hashes       = call.novel_signal_hashes;
            cc.new_signal_prios.assign(
                cc.new_signal_hashes.size(), call.signal_priority);
            cc.errno_value             = call.errno_value;
            cc.syscall_id              = call.syscall_id;
            cc.signal_hashes_are_edges = !call.edge_hashes.empty();
            cc.first_run_index         = 0;
            initial_calls.push_back(std::move(cc));
        }
        if (!kco->extra_novel_signal_hashes.empty()) {
            CorePathChasedCall cc;
            cc.call_index = -1;
            cc.new_signal_hashes = kco->extra_novel_signal_hashes;
            cc.new_signal_prios.assign(cc.new_signal_hashes.size(), 0);
            cc.signal_hashes_are_edges = kco->extra_signal_hashes_are_edges;
            cc.first_run_index = 0;
            initial_calls.push_back(std::move(cc));
        }
    }

    if (divert && initial_calls.empty()) {
        return false;
    }

    auto& v = out->verdict;
    const std::uint64_t lineage_parent = c->origin_seed_id;
    const auto lineage_origin = (lineage_parent == 0)
        ? fuzzer::SeedOrigin::kGenerate : fuzzer::SeedOrigin::kMutate;
    auto res = deps_.corpus_admit->OfferVerdict(
        c->program_payload, c->artifact, v,
        source, /*divert_to_caller=*/divert,
        next_seed_id_, lineage_origin, lineage_parent);

    if (res.inbox_full_drop && fuzzer_metrics_.inbox_drop_result) {
        fuzzer_metrics_.inbox_drop_result->Inc();
    }
    if (!divert || !res.built_seed.has_value()) {
        return false;
    }

    auto seed_sp = std::make_shared<fuzzer::Seed>(std::move(*res.built_seed));
    return TrySpawnCorePathTriage(seed_sp, source, candidate_seed_id,
                                  std::move(initial_calls),
                                  MakeCorePathDiscoverySample(result));
}

// Core-path side-effect 的唯一入口。两个调用点(ProcessCatchAllCompletion / RunOnce
// routed 分支)都必须走这里,避免各自单独调 MaybeSpawnCorePathFromCompletion 后对同一条
// completion 重复 OfferVerdict / 建 seed / spawn core-path job。
bool FuzzerLoop::RouteCorePathFromCompletion(
    ConsumerCtx&                    cctx,
    const job::ExecResult&          result,
    refuzz::fuzzer::SeedSource      source,
    bool                            is_candidate,
    std::uint64_t                   candidate_seed_id,
    int                              candidate_attempt,
    bool                             allow_direct_inbox_admit)
{
    return MaybeSpawnCorePathFromCompletion(
        cctx, result, source, is_candidate, candidate_seed_id, candidate_attempt,
        allow_direct_inbox_admit);
}

bool FuzzerLoop::TrySpawnCorePathTriage(std::shared_ptr<refuzz::fuzzer::Seed> seed,
                                        refuzz::fuzzer::SeedSource source,
                                        std::uint64_t pending_seed_id,
                                        std::vector<CorePathChasedCall> initial_calls,
                                        std::optional<CorePathDiscoverySample> discovery)
{
    // [Step 6 Phase 1] 吸收 triage_stage 的 core-path spawn 路径(= syz triageJob 构造):
    // build 一条融合 deflake+minimize 的 job 交给 loop-owned job runtime。逐字段与
    // triage_stage.cpp 的 job_core_path 分支等价(单一真值,Phase 4 删 triage_stage 那份)。
    // deflake 分档。所有 run 参数都表示“总样本数”，包含已经完成的
    // discovery sample；因此 normal=3-of-5 的窗口只额外复跑两次。
    int min_runs = 3, max_runs = 5, total_runs = 5, min_votes = 3;
    if (source == refuzz::fuzzer::SeedSource::kBootCorpus) {
        min_runs   = 4;   // syz deflakeMinCorpusRuns, discovery included
        max_runs   = 6;   // syz deflakeMaxCorpusRuns
        total_runs = 20;  // syz deflakeTotalCorpusRuns
        min_votes  = 2;   // 2-of-n(比现场 3-of-5 宽松)
    } else if (deps_.retry_policy != nullptr) {
        const auto src =
            static_cast<std::uint8_t>(refuzz::fuzzer::SeedSource::kMutation);
        const int vr = deps_.retry_policy->VerifyRuns(src);
        const int mr = deps_.retry_policy->MinVerifyRuns(src);
        const int mv = deps_.retry_policy->MinStableVotes(src);
        if (vr > 0) {
            max_runs = vr;
            total_runs = vr;
        }
        min_runs  = (mr > 0 && mr <= max_runs) ? mr : max_runs;
        min_votes = (mv > 0) ? mv : max_runs;
    }

    // admit 在未来某 RunOnce 经 retain 于 control 线程跑;捕获持久 deps_ 裸指针 + 同一
    // seed(shared)—— job 线程盖章与 control 线程 admit 由 strict-alternation 隔开。
    JobDeps* dp = &deps_;
    MinimizeAdmitFn admit =
        [dp, seed](MinimizeDriver::StepVerdict&& v,
                   std::optional<PerCallCandidate> fin) {
            AdmitMinimizedSeed(*dp, *seed, v, fin ? &*fin : nullptr,
                               /*origin_executor_id=*/0);
        };
    ExtractStableFn extract_stable =
        [oracle = deps_.stability_oracle](
            const std::vector<std::vector<std::uint64_t>>& per_run, int k)
            -> std::vector<std::uint64_t> {
            if (oracle == nullptr) return {};
            auto r = oracle->ExtractStable(per_run, k);
            return r.has_value() ? std::move(*r) : std::vector<std::uint64_t>{};
        };
    StableAdmitFn stable_admit =
        [dp](const refuzz::fuzzer::Seed& stable_seed, bool dispatch_elaboration) {
            AdmitStableSeed(*dp, stable_seed, dispatch_elaboration,
                            /*origin_executor_id=*/0);
        };

    CorePathJobConfig cfg;
    cfg.min_runs   = min_runs;
    cfg.max_runs   = max_runs;
    cfg.total_runs = total_runs;
    cfg.min_votes  = min_votes;
    // attempts/mode = minimize producer 默认(kCallsOnly, 3);= triage_stage。
    cfg.attempts   = 3;
    cfg.mode       = refuzz::crash::MinimizeMode::kCallsOnly;
    cfg.timeout_ms = static_cast<std::uint32_t>(deps_.exec_timeout_ms);
    cfg.seed_value_shadow_enabled = deps_.seed_value_shadow_enabled;
    cfg.initial_calls             = std::move(initial_calls);  // [per-call novelty] chased seed
    cfg.discovery_sample         = std::move(discovery);
    cfg.stable_admit              = std::move(stable_admit);
    if (source == refuzz::fuzzer::SeedSource::kBootCorpus) {
        cfg.deflake_mode         = DeflakeMode::kBootCorpus;
        cfg.skip_minimize        = true;
        cfg.dispatch_elaboration = false;
        auto pending = catch_all_pending_;
        const std::uint64_t boot_seed_id = pending_seed_id;
        cfg.on_terminal = [pending, boot_seed_id]() {
            if (pending != nullptr && boot_seed_id != 0) {
                pending->Erase(boot_seed_id);
            }
        };
    }
    // core-path job 替代 triage+minimize 两 stage → 自己发它们全部计数(否则 flag-on 恒 0)。
    cfg.metrics.triage_task_completed   = deps_.metrics.triage_task_completed;
    cfg.metrics.triage_completed        = deps_.metrics.triage_completed;
    cfg.metrics.triage_admit_stable     = deps_.metrics.triage_admit_stable;
    cfg.metrics.triage_drop_flaky       = deps_.metrics.triage_drop_flaky;
    cfg.metrics.triage_job              = deps_.metrics.triage_job;
    cfg.metrics.minimize_task_completed = deps_.metrics.minimize_task_completed;
    cfg.metrics.minimize_job            = deps_.metrics.minimize_job;
    // continuation 打档:boot 语料 → CandidateTriage(①),现场 → Triage(③)。
    cfg.tier = (source == refuzz::fuzzer::SeedSource::kBootCorpus)
                 ? refuzz::queue::TaskTier::CandidateTriage
                 : refuzz::queue::TaskTier::Triage;
    // [默认并发 fan-out] 每个 per-call 候选派生一个 child minimize job(= syz triageJob
    //   wg.Go(handleCall))。已删 REFUZZ_JOB_FANOUT env gate:生产路径 spawn_child 恒接;
    //   make_child_driver 留空 → child 默认构造真 MinimizeDriver(同 parent)。
    cfg.spawn_child = [this](job::JobFn f) { return SpawnJob(std::move(f)); };

    return SpawnJob(MakeCorePathJob(
        seed, std::make_shared<MinimizeDriver>(),
        std::move(extract_stable), std::move(admit), std::move(cfg)));
}

std::pair<std::uint64_t, std::uint32_t>
FuzzerLoop::ResolveLineageRoot(std::uint64_t seed_id) const
{
    // Walk SeedLineageMetadata parent-pointers: seed_id -> (root, depth). depth is
    // 1-based — 1 = seed_id is a base/non-mutate seed (it IS its own root), >= 2 = a
    // descendant. The loop owns the corpus walk so the feedback store stays seed-agnostic.
    constexpr std::uint32_t kMaxLineageWalk = 64;  // cycle / runaway guard
    std::uint64_t root  = seed_id;
    std::uint32_t depth = 1;
    for (std::uint32_t hop = 0; hop < kMaxLineageWalk; ++hop) {
        auto seed = corpus_.GetSeed(root);
        const auto* lin =
            seed ? seed->metadata.Get<refuzz::fuzzer::SeedLineageMetadata>() : nullptr;
        if (lin == nullptr ||
            lin->origin != refuzz::fuzzer::SeedOrigin::kMutate ||
            lin->parent_seed_id == 0) {
            break;
        }
        root = lin->parent_seed_id;
        ++depth;
    }
    return {root, depth};
}

void FuzzerLoop::EmitSeedValueShadow(std::uint64_t parent_seed_id,
                                     const refuzz::fuzzer::EngineOutput& out,
                                     double elapsed_s)
{
    // Scope to genuine mutations OF an admitted corpus seed. origin_seed_id!=0
    // also fires for triage / corpus_verify re-execution (the seed is still an
    // in-flight candidate, not yet in the store) — GetSeed returns null / no
    // artifact there, which would log an all-zero row. Skip those: they aren't
    // "mutate this corpus seed", just re-runs of a not-yet-admitted candidate.
    auto seed = corpus_.GetSeed(parent_seed_id);
    if (!seed || !seed->artifact || !seed->artifact->valid()) {
        return;
    }

    const refuzz::fuzzer::Verdict& verdict = out.verdict;
    SeedValueShadowSink::Row row;
    row.seed_id   = parent_seed_id;
    row.elapsed_s = elapsed_s;

    // Signal A (rarity) + baseline mab_ghat + signal C's TARGET (rare_cov_gain),
    // all from the scheduler. Rarity is read at OUTCOME time: pc_count drifts
    // from selection only when new seeds covering the same PCs are admitted in
    // that window — negligible for the discriminating rare-coverage seeds. See
    // docs/plans/seed-value-signals.md §6.
    if (scheduler_handle_.HasValue()) {
        auto& sched = scheduler_handle_.Get();
        row.rarity   = sched.SeedRarityScore(parent_seed_id);
        row.mab_ghat = sched.SeedMabGhat(parent_seed_id);
        row.future   = sched.SeedFutureValue(parent_seed_id);  // [seed-future-value]
        row.future_cht = sched.SeedTransitionValue(parent_seed_id);  // [future_cht / Psyzkaller]
        row.future_band2 = sched.SeedBand2Value(parent_seed_id);  // [future_band2 / kill-shot]
        row.belief_value = sched.SeedBeliefValue(parent_seed_id);  // [belief-graph] static prior under test

        // rare_cov_gain = Σ 1/pc_count over this mutation's full executed
        // footprint (per-call cover + program-level extra cover, raw PCs, same
        // basis as pc_count). High = the mutation drove execution into rare
        // corpus territory (depth proxy), distinct from raw cov_gain (new edges
        // only). Kernel-family observation only.
        if (const auto* kco =
                out.observation.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
            std::vector<std::uint64_t> cover;
            for (const auto& call : kco->per_call) {
                cover.insert(cover.end(), call.coverage_hashes.begin(),
                             call.coverage_hashes.end());
            }
            cover.insert(cover.end(), kco->extra_cover.begin(),
                         kco->extra_cover.end());
            std::sort(cover.begin(), cover.end());
            cover.erase(std::unique(cover.begin(), cover.end()), cover.end());
            row.rare_cov_gain = sched.CoverRarityScore(cover);
        }
    }

    // [belief-graph RAW facts] the offline attributor (scripts/seed_horizon/model/shadow_analyze.py)
    // does ALL judgment ("deep"/"frontier-fired" are derived there, multi-lens, soft) — emit
    // only raw facts: the globally-new PCs this exec unlocked + the variants whose calls
    // actually dispatched (the precond signal for soft frontier responsibility). new_signal_hashes
    // are raw KCOV PCs in raw_pc mode (same basis as band2/binding); in edge mode the attributor's
    // function-map join is meaningless, so this shadow presumes raw_pc=true like its siblings.
    row.new_pcs = out.new_signal_hashes;
    if (const auto* kco =
            out.observation.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
        std::vector<std::uint32_t> ids;
        ids.reserve(kco->per_call.size());
        for (const auto& call : kco->per_call) {
            if (call.executed) {
                ids.push_back(call.syscall_id);
            }
        }
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        row.executed_variants.reserve(ids.size());
        for (std::uint32_t id : ids) {
            if (id < variant_id_to_name_.size() && !variant_id_to_name_[id].empty()) {
                row.executed_variants.push_back(variant_id_to_name_[id]);
            }
        }
    }

    // [belief-graph lineage] resolve the mutation chain's root + generation so a LAGGED
    // payoff attributes to the high-belief ANCESTOR, not just the direct parent.
    const auto lineage = ResolveLineageRoot(parent_seed_id);
    row.root_seed_id  = lineage.first;
    row.lineage_depth = static_cast<int>(lineage.second);

    // Signal B — cross-run coverage variance stamped on the seed at deflake.
    if (const auto* sb =
            seed->metadata.Get<refuzz::fuzzer::SeedStabilityMetadata>()) {
        row.unstable_pc_count = sb->unstable_pc_count;
        row.union_pc_count    = sb->union_pc_count;
        row.observed_runs     = sb->observed_runs;
    }

    // Signal C — state-space altitude of the LIVE (post-minimize) program.
    if (mutator_handle_.HasValue()) {
        if (auto alt = mutator_handle_.Get().AnalyzeStateAltitude(*seed->artifact)) {
            row.altitude_valid = true;
            row.res_producers  = alt->resource_producers;
            row.res_consumers  = alt->resource_consumers;
            row.distinct_kinds = alt->distinct_kinds;
            row.max_depth      = alt->max_dependency_depth;
        }
    }

    // [Phase 1] PRE-minimize altitude stamped at minimize. Pairing it with the
    // live (post-minimize) fields above measures how much resource-chain
    // structure minimize destroyed for this seed.
    if (const auto* pre =
            seed->metadata.Get<refuzz::fuzzer::SeedPreMinAltitudeMetadata>()) {
        row.pre_min_valid = true;
        row.pre_res_prod  = pre->resource_producers;
        row.pre_res_cons  = pre->resource_consumers;
        row.pre_kinds     = pre->distinct_kinds;
        row.pre_depth     = pre->max_dependency_depth;
    }

    // Realized yield. cov_gain feeds A/C's target; the abnormal flags feed B's
    // race/crash-adjacency target.
    row.cov_gain              = verdict.cov_gain;
    row.interesting           = verdict.interesting;
    row.is_crash              = verdict.is_crash;
    row.is_timeout            = verdict.is_timeout;
    row.is_exec_error         = verdict.is_exec_error;
    row.is_resource_leak      = verdict.is_resource_leak;
    row.is_contract_violation = verdict.is_contract_violation;
    row.is_priority_inversion = verdict.is_priority_inversion;
    row.is_stack_overflow     = verdict.is_stack_overflow;

    seed_value_shadow_->Write(row);
}

void FuzzerLoop::FeedLineageYield(std::uint64_t origin_seed_id,
                                  const refuzz::fuzzer::EngineOutput& out)
{
    // [M1] Attribute only GLOBALLY-NEW coverage units (out.new_signal_hashes — the
    // deduped new-coverage snapshot). Events with no new coverage (the majority)
    // return here, BEFORE the lineage walk + GetSeed. This is also more correct than
    // the full executed footprint: it credits what the lineage FIRST unlocked, not
    // re-covers of boot / already-known PCs. (EmitSeedValueShadow needs the full
    // footprint for rare_cov_gain separately — no shared vector — but this path no
    // longer flattens per-call cover at all.)
    if (out.new_signal_hashes.empty()) {
        return;
    }

    // [guard] origin_seed_id != 0 also fires for triage / corpus_verify re-execs
    // of a NOT-yet-admitted candidate (same case EmitSeedValueShadow guards). Those
    // are re-runs of an in-flight candidate, not lineage outcomes of a real corpus
    // seed: GetSeed returns null, the walk would credit the candidate id at depth 1,
    // and global first-toucher would permanently steal those PCs from the genuine
    // root. Skip unless origin_seed_id resolves to a real admitted seed.
    {
        auto origin = corpus_.GetSeed(origin_seed_id);
        if (!origin || !origin->artifact || !origin->artifact->valid()) {
            return;
        }
    }

    // Walk SeedLineageMetadata parent-pointers: origin_seed_id -> (root, depth).
    // depth is 1-based — 1 = a direct mutation of the root base seed, >= 2 = a
    // mutation of a descendant (the value-realized downstream signal). The loop
    // owns the corpus walk so the feedback store stays seed-agnostic.
    const auto lineage = ResolveLineageRoot(origin_seed_id);
    const std::uint64_t root  = lineage.first;
    const std::uint32_t depth = lineage.second;

    // Credit the globally-new units to the lineage root (depth-bucketed). The
    // store's first-toucher set dedups across concurrent workers.
    lineage_yield_store_->Attribute(root, depth, out.new_signal_hashes);

    // [cluster-unit metric — Tier 1, §5.2a] same lineage (root, depth), but bucket
    // the SAME novel-edge stream by 4 KB text page (sig>>12 == pc>>12, valid because
    // raw_pc=true) — a cheap dependency-cluster proxy. Distinct PAGES instead of
    // distinct edges: a 50-block handler in one page → 1 unit (within-burst
    // dependency compressed), cross-page mass preserved, and the page is claimed
    // atomically by the first lineage to touch it (removes the per-block worker
    // race). Logged to seed_lineage_yield_cluster.jsonl beside the block-unit store
    // for offline comparison. NOT the final form (page != function); Tier 2 swaps
    // this map for raw-PC→function. See structural-horizon-seed-value.md §5.2a.
    if (lineage_yield_store_cluster_ != nullptr) {
        std::vector<std::uint64_t> pages;
        pages.reserve(out.new_signal_hashes.size());
        for (std::uint64_t h : out.new_signal_hashes) {
            pages.push_back(h >> 12);
        }
        lineage_yield_store_cluster_->Attribute(root, depth, pages);
    }

    // [periodic flush] the yield stores otherwise dump only in the dtor (RAII) → the
    // value-realized oracle is invisible mid-run and lost on SIGKILL. Re-dump both
    // every kLineageFlushEvery credited events (a full rewrite, O(#roots), cheap).
    // We returned early above when there was no new coverage, so a quiet stretch
    // costs nothing.
    constexpr std::uint32_t kLineageFlushEvery = 128;
    if (++lineage_flush_ctr_ % kLineageFlushEvery == 0) {
        lineage_yield_store_->Flush();
        if (lineage_yield_store_cluster_ != nullptr) {
            lineage_yield_store_cluster_->Flush();
        }
    }
}

bool FuzzerLoop::SpawnJob(job::JobFn fn)
{
    if (!fn) {
        return false;
    }
    job_spawn_queue_.push(std::move(fn));
    return true;
}

bool FuzzerLoop::DrainLifecycle()
{
    if (job_sched_ == nullptr) {
        return false;
    }
    auto* lifecycle_queue = lifecycle_queue_.load(std::memory_order_acquire);
    if (lifecycle_queue == nullptr) {
        return false;
    }
    bool progressed = false;
    for (const auto& ev : lifecycle_queue->DrainAll()) {
        job_sched_->MarkAccepted(ev.executor_id);
        progressed = true;
    }
    return progressed;
}

bool FuzzerLoop::ReclaimJob(job::Job* job)
{
    if (job == nullptr) {
        return false;
    }
    job->JoinDone();
    for (auto& action : job->TakeRetains()) {
        if (action) {
            action();
        }
    }
    auto it = std::find_if(jobs_.begin(), jobs_.end(),
                           [job](const std::unique_ptr<job::Job>& p) {
                               return p.get() == job;
                           });
    if (it == jobs_.end()) {
        return false;
    }
    jobs_.erase(it);
    return true;
}

bool FuzzerLoop::DeliverToJob(job::Job* job, job::ExecResult result)
{
    if (job == nullptr) {
        return false;
    }
    job->Deliver(std::move(result));
    if (job->Done()) {
        ReclaimJob(job);
    }
    return true;
}

std::optional<FuzzerLoop::RoutedJobEntry>
FuzzerLoop::TakeRoutedJobEntry(std::uint64_t exec_id)
{
    auto it = routed_jobs_.find(exec_id);
    if (it == routed_jobs_.end()) {
        return std::nullopt;
    }
    RoutedJobEntry entry = it->second;
    routed_jobs_.erase(it);
    return entry;
}

void FuzzerLoop::SettleEmitCompletion(std::uint64_t exec_id,
                                      const job::ExecResult& result)
{
    auto single = emit_completion_.find(exec_id);
    if (single != emit_completion_.end()) {
        job::OnCompleted cb = std::move(single->second);
        emit_completion_.erase(single);
        if (cb) {
            cb(result);
        }
    }
}

// [tier-aware arbitration] 镜像 syz fuzzer.Source = Order(triageCandidateQueue①,
//   candidateQueue②, triageQueue③, Alternate(smashQueue④,3), Callback(genFuzz)⑤)
//   (pkg/fuzzer/fuzzer.go)。语义前移到这个 pull 点,而不是等 request 进了 task_queue 才排
//   序——routed request(deflake/minimize/fault/hints 的 collect-comps)从不进 task_queue,
//   必须在这里按 Request::tier 选人。选中之后才看 PendingIsEmit() 决定 routed 提交(登记
//   routed_jobs_ + TrySubmit exploration=false)还是 emit 提交(TrySubmit exploration=true +
//   ResumeAfterEmit) —— routed/emit 是"怎么交货",不是"该轮到谁",两者不再分两段扫描,
//   否则 tier=Smash 的 routed job(HintsJob 的 collect-comps、FaultJob)会绕开 tier 顺序,
//   永远抢在其它档的 emit job 前面。
job::Job* FuzzerLoop::SelectNextReadyJob()
{
    job_arbitration_pending_.clear();
    job_arbitration_pending_.reserve(jobs_.size());
    for (const auto& j : jobs_) {
        job_arbitration_pending_.push_back(job::PendingJobView{j->PeekPendingTier()});
    }
    const auto idx = job::SelectNextReadyJobIndex(job_arbitration_pending_,
                                                  job_arbitration_state_);
    if (!idx.has_value()) {
        return nullptr;
    }
    return jobs_[*idx].get();
}

bool FuzzerLoop::ArbitrateJobs()
{
    if (job_sched_ == nullptr) {
        return false;
    }
    bool dispatched = false;
    while (job_sched_->HasRoom()) {
        job::Job* picked = SelectNextReadyJob();
        if (picked == nullptr) {
            break;
        }

        const std::uint64_t exec_id = job_sched_->AllocExecId();
        if (!picked->PendingIsEmit()) {
            const job::Request req = picked->TakePendingRequest();
            routed_jobs_[exec_id] = RoutedJobEntry{picked, req.completion_triage_policy};
            job_sched_->TrySubmit(exec_id, req, /*exploration=*/false);
        } else {
            const job::Request req = picked->TakePendingRequest();
            job::OnSubmitted on_sub = picked->TakePendingOnSubmitted();
            job::OnCompleted on_completed = picked->TakePendingOnCompleted();
            if (on_completed) {
                emit_completion_[exec_id] = std::move(on_completed);
            }
            job_sched_->TrySubmit(exec_id, req, /*exploration=*/true);   // unrouted → 结果回 catch-all
            if (on_sub) {
                on_sub(exec_id);
            }
            picked->ResumeAfterEmit();
            if (picked->Done()) {
                ReclaimJob(picked);
            }
        }
        dispatched = true;
    }
    return dispatched;
}

bool FuzzerLoop::PumpJobs()
{
    bool progressed = false;
    while (!job_spawn_queue_.empty()) {
        auto fn = std::move(job_spawn_queue_.front());
        job_spawn_queue_.pop();
        // [#3] 注入诊断:job 异常 fail-soft 时经 HostLogger 出 error + 计 fuzzer.job_aborted。
        auto j = std::make_unique<job::Job>(next_job_runtime_id_++, std::move(fn),
                                            &deps_.logger, fuzzer_metrics_.job_aborted);
        j->Launch();
        if (j->Done()) {
            j->JoinDone();
            for (auto& action : j->TakeRetains()) {
                if (action) {
                    action();
                }
            }
        } else {
            jobs_.push_back(std::move(j));
        }
        progressed = true;
    }
    progressed = ArbitrateJobs() || progressed;
    return progressed;
}

bool FuzzerLoop::RunOnce(std::chrono::milliseconds event_pop_timeout)
{
    bool progressed = RuntimeTick();
    progressed = DrainLifecycle() || progressed;
    progressed = PumpJobs() || progressed;
    // [单线程处理] 一次 RunOnce 只处理**一个** event —— 不在一次 tick 里 drain 多个;事件节奏由
    //   orchestrator 的 RunOnce 主循环驱动,更贴合单控制线程模型。Pop 带 timeout:idle 时让出 CPU。
    if (auto event = event_queue_.Pop(event_pop_timeout)) {
        progressed = true;

        ConsumerCtx cctx{};
        cctx.event = std::move(*event);
        ProcessEventFeedback(cctx);
        SettleFeedbackCompletion(cctx);

        const std::uint64_t exec_id = ExecutorIdOf(cctx.event);
        job::ExecResult result = ProjectExecResult(
            cctx.event, cctx.feedback_output ? &*cctx.feedback_output : nullptr);
        auto routed = TakeRoutedJobEntry(exec_id);
        if (routed.has_value()) {
            if (routed->policy == job::CompletionTriagePolicy::kAllowCatchAllTriage) {
                (void)RouteCorePathFromCompletion(
                    cctx, result, refuzz::fuzzer::SeedSource::kMutation,
                    /*is_candidate=*/false, /*candidate_seed_id=*/0,
                    /*candidate_attempt=*/-1,
                    /*allow_direct_inbox_admit=*/false);
            }
            DeliverToJob(routed->owner, std::move(result));
            if (crash_pipeline_ != nullptr &&
                cctx.feedback_output &&
                cctx.feedback_output->crash_dispatch.has_value()) {
                crash_pipeline_->Process(*cctx.feedback_output->crash_dispatch);
            }
        } else {
            ProcessCatchAllCompletion(cctx, result);
            SettleEmitCompletion(exec_id, result);
        }
        // [RTT instrumentation] emit THIS completion's per-task trace + feed the
        // aggregate histogram — placed after the owned/catch-all split so it
        // fires for EVERY completion (job-owned core path + catch-all), not just
        // the ~5% that reach ProcessCatchAllCompletion.
        EmitCompletionTaskTrace(cctx);
        // 处理完这一个 event 后:drain accepts(释放窗口)+ pump(派发该 job 恢复出的 continuation +
        //   catch-all 可能 spawn 的 core-path job)。
        progressed = DrainLifecycle() || progressed;
        progressed = PumpJobs() || progressed;
    }
    return progressed;
}

void FuzzerLoop::SpawnExploreJob()
{
    // [event-driven] 首次由 ctor 调,之后由 ExploreJob 正常退出的 on_done 自补一条 —— 不再每 tick
    //   轮询 explore_job_alive_。ExploreJob 是持续生产 loop,近乎永不正常退出(仅 engine 不支持
    //   generation 才退,~不可达)。SpawnJob 只入队,PumpJobs 再 Launch,不重入 jobs_。
    ExploreJobDeps ejd;
    ejd.mab_selector      = mab_active_ ? mab_task_selector_.get() : nullptr;
    ejd.mutator_handle    = &deps_.mutator_handle;
    ejd.scheduler_handle  = &deps_.scheduler_handle;
    ejd.corpus            = &deps_.corpus;
    ejd.rng               = &rng_;
    ejd.exec_timeout_ms   = static_cast<std::uint32_t>(deps_.exec_timeout_ms);
    ejd.accept_bytes_only_fallback = deps_.accept_bytes_only_fallback;
    ejd.logger            = &deps_.logger;
    ejd.exec_collide      = fuzzer_metrics_.exec_collide;
    ejd.record_mutate_seed =
        [this](std::uint64_t exec_id, refuzz::fuzzer::SeedSelection sel) {
            std::lock_guard<std::mutex> lk(mutate_seed_mu_);
            mutate_seed_for_exec_[exec_id] = std::move(sel);
        };
    // [MAB observability] 观测输出绑 ExploreJob 产出 cadence:job 每 kObserveEvery 次 emit 调它。
    ejd.observe = [this]() { EmitMabState(); };
    SpawnJob(MakeExploreJob(ejd, [this]() { SpawnExploreJob(); }));
}

void FuzzerLoop::SpawnFixedInputProducerJob(const refuzz::request_stream::RequestStream& stream,
                                            std::function<void()> on_fully_drained)
{
    // [fixed request stream, Step 4] Unlike SpawnExploreJob, called exactly
    // once by the caller (Orchestrator, fixed-input mode only) -- the job does
    // not self-respawn (see fixed_input_producer_job.cpp), so there is no
    // on_done closure here.
    FixedInputProducerJobDeps fipd;
    fipd.stream = &stream;
    fipd.exec_timeout_ms = static_cast<std::uint32_t>(deps_.exec_timeout_ms);
    fipd.on_fully_drained = std::move(on_fully_drained);
    SpawnJob(MakeFixedInputProducerJob(std::move(fipd)));
}

void FuzzerLoop::MaybeSpawnCandidateFeeder()
{
    // [event-driven] 触发点:SetCatchAllPending(bootstrap,boot corpus 已在 pending)、completion
    //   path push retry 后、feeder on_done(捞运行期间新入的 retry)。candidate_feeder_alive_ 只作
    //   "避免重复 spawn"的 guard,不再被每 tick 轮询。非 candidate profile 直接返回。
    if (catch_all_pending_ == nullptr || !catch_all_triage_enabled_) {
        return;
    }
    bool has_candidate_retry = false;
    {
        std::lock_guard<std::mutex> lk(candidate_mu_);
        has_candidate_retry = !candidate_retry_.empty();
    }
    if (candidate_bootstrapped_ && !has_candidate_retry) {
        return;   // 已 bootstrap 且当前无 retry → 无活
    }
    bool expected_candidate = false;
    if (!candidate_feeder_alive_.compare_exchange_strong(expected_candidate, true)) {
        return;   // feeder 已在飞
    }
    CandidateJobDeps cjd;
    if (!candidate_bootstrapped_) {
        candidate_bootstrapped_ = true;
        cjd.initial = ScanBootCandidates(*catch_all_pending_);
    }
    cjd.pending         = catch_all_pending_;
    cjd.exec_timeout_ms = static_cast<std::uint32_t>(deps_.exec_timeout_ms);
    cjd.record_exec     =
        [this](std::uint64_t exec_id, std::uint64_t seed_id, int attempt) {
            RecordCandidateExec(exec_id, seed_id, attempt);
        };
    cjd.drain_retries   = [this]() {
        std::vector<std::pair<std::uint64_t, int>> out;
        for (const auto& c : DrainCandidateRetries()) {
            out.emplace_back(c.seed_id, c.attempt);
        }
        return out;
    };
    if (!SpawnJob(MakeCandidateJob(std::move(cjd), [this]() {
            candidate_feeder_alive_.store(false);
            MaybeSpawnCandidateFeeder();   // on_done:捞 feeder 运行期间新入的 retry
        }))) {
        candidate_feeder_alive_.store(false);
    }
}

void FuzzerLoop::EmitMabState()
{
    // [MAB observability] 由 ExploreJob 的 ejd.observe 触发(每 kObserveEvery 次 emit 一次),
    //   绑 ExploreJob 产出 cadence,而非 loop 的周期 tick。运行在 job body 内 → 与 loop 的
    //   MAB/corpus/reward 逻辑 strict-alternate,读 mab_task_selector_/metrics 安全。
    if (!mab_active_) {
        return;
    }
    using A = mab::MabArm;
    const std::uint64_t pick_gen = mab_task_selector_->PickCount(A::kGenerate);
    const std::uint64_t pick_mut = mab_task_selector_->PickCount(A::kMutate);
    const std::uint64_t picks    = pick_gen + pick_mut;
    const double mut_share = picks > 0
        ? 100.0 * static_cast<double>(pick_mut) / static_cast<double>(picks) : 0.0;
    const std::uint64_t admits = fuzzer_metrics_.corpus_growth
        ? fuzzer_metrics_.corpus_growth->Value() : 0;
    const double mut_per_seed = admits > 0
        ? static_cast<double>(pick_mut) / static_cast<double>(admits) : 0.0;
    logger_.Log("control.mab", "mab_arm_state", {
        refuzz::logging::Field("seq",   static_cast<int64_t>(++mab_observation_seq_)),
        refuzz::logging::Field("epoch", static_cast<int64_t>(mab_task_selector_->Epoch())),
        refuzz::logging::Field("g_gen", mab_task_selector_->Ghat(A::kGenerate)),
        refuzz::logging::Field("g_mut", mab_task_selector_->Ghat(A::kMutate)),
        refuzz::logging::Field("pick_gen", static_cast<int64_t>(pick_gen)),
        refuzz::logging::Field("pick_mut", static_cast<int64_t>(pick_mut)),
        refuzz::logging::Field("mut_share", mut_share),
        refuzz::logging::Field("corpus_growth", static_cast<int64_t>(admits)),
        refuzz::logging::Field("mut_per_seed", mut_per_seed),
        refuzz::logging::Field("ev_gen",  static_cast<int64_t>(mab_task_selector_->EventCount(A::kGenerate))),
        refuzz::logging::Field("ev_mut",  static_cast<int64_t>(mab_task_selector_->EventCount(A::kMutate))),
        refuzz::logging::Field("cov_gen", mab_task_selector_->CovSum(A::kGenerate)),
        refuzz::logging::Field("cov_mut", mab_task_selector_->CovSum(A::kMutate)),
        refuzz::logging::Field("hit_gen", static_cast<int64_t>(mab_task_selector_->CovHits(A::kGenerate))),
        refuzz::logging::Field("hit_mut", static_cast<int64_t>(mab_task_selector_->CovHits(A::kMutate))),
        refuzz::logging::Field("t_gen", mab_task_selector_->TimeSum(A::kGenerate)),
        refuzz::logging::Field("t_mut", mab_task_selector_->TimeSum(A::kMutate)),
        refuzz::logging::Field("tg_p50", mab_task_selector_->TimePctlMs(A::kGenerate, 0.50)),
        refuzz::logging::Field("tg_p95", mab_task_selector_->TimePctlMs(A::kGenerate, 0.95)),
        refuzz::logging::Field("tg_p99", mab_task_selector_->TimePctlMs(A::kGenerate, 0.99)),
        refuzz::logging::Field("tm_p50", mab_task_selector_->TimePctlMs(A::kMutate, 0.50)),
        refuzz::logging::Field("tm_p95", mab_task_selector_->TimePctlMs(A::kMutate, 0.95)),
        refuzz::logging::Field("tm_p99", mab_task_selector_->TimePctlMs(A::kMutate, 0.99)),
        refuzz::logging::Field("admit_ev_gen", static_cast<int64_t>(mab_task_selector_->AdmitEventCount(A::kGenerate))),
        refuzz::logging::Field("admit_ev_mut", static_cast<int64_t>(mab_task_selector_->AdmitEventCount(A::kMutate))),
        refuzz::logging::Field("admit_cov_gen", mab_task_selector_->AdmitCovSum(A::kGenerate)),
        refuzz::logging::Field("admit_cov_mut", mab_task_selector_->AdmitCovSum(A::kMutate)),
    });
}

bool FuzzerLoop::RuntimeTick()
{
    // FuzzerLoop 侧外围维护:respawn explore/candidate feeder + corpus tick/gauge。
    // MAB 观测已移出(绑 ExploreJob 产出 cadence,见 EmitMabState / explore_job.cpp)。
    // JobScheduler 只负责 request-window + submit。
    // engine 切换完全异步 + 原子(Manager::SwitchEngineByName 直写 handle);
    // engine 内部 policy 切换由 engine 在热方法入口 lazy apply。
    // FuzzerLoop 此处只处理 corpus admission policy 的异步切换,
    // 这是 corpus_manager_ 内部的两阶段(尚未迁移到 handle 模型)。
    if (corpus_manager_.MaybeApplyPendingSwitch()) {
        if (fuzzer_metrics_.policy_switch_corpus) {
            fuzzer_metrics_.policy_switch_corpus->Inc();
        }
    }

    bool progressed = false;

    // [event-driven spawn] ExploreJob 的启动/自愈已移出**每-tick 存活位轮询**:ctor 首 spawn 一条,
    //   正常退出时 on_done 直接 SpawnExploreJob() 补一条(见 SpawnExploreJob),不再每 RunOnce CAS
    //   explore_job_alive_。

    // [event-driven spawn] candidate feeder 的 bootstrap/重启已移出每-tick 轮询(去掉 per-tick
    //   candidate_mu_ 加锁 + candidate_feeder_alive_ CAS):bootstrap 在 SetCatchAllPending 触发一次
    //   (boot corpus 已在 pending 区),flaky retry 由 completion path push 后触发,feeder on_done
    //   再检一次(捞运行期间新入的 retry)。见 MaybeSpawnCandidateFeeder。

    // [MAB observability] `mab_arm_state` 打点已从这里的周期 tick 移出 —— MAB 是 ExploreJob 的
    //   运行时状态,观测 cadence 必须绑到它的**产出**("调用一次触发一次"),而非 loop 的 RunOnce
    //   tick。改由 ExploreJob 每 kObserveEvery 次 emit 经 ejd.observe 触发 EmitMabState()(下方定义,
    //   job body 与 loop handoff strict-alternate,读 MAB/metrics 安全)。见 explore_job.cpp。

    // ── Corpus admission tick + syz-parity periodic sweep ──
    bool corpus_tick_ran = false;
    if (++warm_tick_ >= warm_interval_) {
        warm_tick_ = 0;
        corpus_manager_.Tick();
        corpus_tick_ran = true;
    }
    constexpr auto kCorpusSweepInterval = std::chrono::seconds(60);
    constexpr std::uint64_t kCorpusSweepGrowthPct = 3;  // syz manager.go minimizeCorpusLocked
    const auto now = std::chrono::steady_clock::now();
    if (next_corpus_sweep_at_ == std::chrono::steady_clock::time_point{}) {
        next_corpus_sweep_at_ = now + kCorpusSweepInterval;
    } else if (now >= next_corpus_sweep_at_) {
        next_corpus_sweep_at_ = now + kCorpusSweepInterval;
        if (!corpus_tick_ran) {
            corpus_manager_.Tick();
        }
        corpus_manager_.SweepIfGrowthExceeds(kCorpusSweepGrowthPct);
    }
    return progressed;
}

void FuzzerLoop::Drain(std::chrono::milliseconds event_pop_timeout, uint32_t max_loops)
{
    // Shutdown-only final drain. Normal runtime completion consumption happens in
    // RunOnce; here jobs are no longer allowed to claim completions.
    for (auto& j : jobs_) {
        j->CancelAndJoin();
    }
    jobs_.clear();
    routed_jobs_.clear();
    while (!job_spawn_queue_.empty()) {
        job_spawn_queue_.pop();
    }
    if (job_sched_) {
        job_sched_->Shutdown();
    }
    for (uint32_t i = 0; i < max_loops; ++i) {
        auto event = event_queue_.Pop(event_pop_timeout);
        if (!event.has_value()) {
            continue;
        }
        ConsumerCtx cctx{};
        cctx.event = std::move(*event);
        // [exec-accounting 重构] 同 RunOnce:drain 阶段的 event 也走全局记账 +
        // 单次 Process,保持计数对称(否则 shutdown drain 的执行会漏计)。
        ProcessEventFeedback(cctx);
        // shutdown drain:completion 直接由 catch-all 承接。
        job::ExecResult result = ProjectExecResult(
            cctx.event, cctx.feedback_output ? &*cctx.feedback_output : nullptr);
        ProcessCatchAllCompletion(cctx, result);
        // [RTT instrumentation] trace this drained completion too (parity with
        // RunOnce; ProcessCatchAllCompletion no longer stamps/emits).
        EmitCompletionTaskTrace(cctx);
        const std::uint64_t exec_id = ExecutorIdOf(cctx.event);
        SettleEmitCompletion(exec_id, result);
    }
    corpus_manager_.Tick();
}

void FuzzerLoop::SwitchMutationPolicy(std::string_view name)
{
    // IPolicyControl 只暴露 policy 语义;engine 级切换由 Telemetry 走
    // Manager::SwitchEngineByName。此处把请求下放到 handle 指向的当前 engine;
    // engine 在下一次 Mutate() 入口 lazy apply。

    // [v2 6b-1 — 当前版本] 先发布 metric(确保 registry 先更新),再切换 engine
    policy_state_publisher_.Set("mutation", name);

    if (!mutator_handle_.HasValue()) {
        return;
    }
    mutator_handle_.Get().SwitchPolicyByName(name);
}

void FuzzerLoop::SwitchSchedulingPolicy(std::string_view name)
{
    // [v2 6b-1 — 当前版本] 先发布 metric,再切换 engine
    policy_state_publisher_.Set("schedule", name);

    if (!scheduler_handle_.HasValue()) {
        return;
    }
    scheduler_handle_.Get().SwitchPolicyByName(name);
}

void FuzzerLoop::SwitchCorpusAdmissionPolicy(std::string_view name)
{
    // [v2 6b-1 — 当前版本] 先发布 metric,再切换 engine
    policy_state_publisher_.Set("corpus", name);

    corpus_manager_.SwitchAdmissionPolicyByName(name);
}

size_t FuzzerLoop::PendingCount() const
{
    // [v2 admit-worker async] PendingCount 含 admit_worker pending seed,
    //   让 orchestrator 的 drain 日志真实反映"是否还有 in-flight 工作"。
    const size_t worker_pending =
        admit_worker_ ? admit_worker_->PendingSize() : 0;
    return task_queue_.PendingSize() + worker_pending;
}

} // namespace refuzz::control
