#pragma once

#include "refuzz/control/request_stream_sink.hpp"
#include "refuzz/core/control.hpp"
#include "refuzz/core/coverage.hpp"
#include "refuzz/core/engine_handle.hpp"
#include "refuzz/corpus/corpus_manager.hpp"
#include "refuzz/corpus/inbox.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/core/metrics/policy_state_publisher.hpp"
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/mutator/mutator_engine.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"  // [mab Step C] SeedLineageMetadata (lineage map)
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/task_queue.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

// [Step 6 stage 清场] job/loop deps + completion ctx(stage framework 已物删)。
#include "refuzz/control/job/job_deps.hpp"               // JobDeps deps_
#include "refuzz/control/job/core_path_job.hpp"           // [per-call novelty] CorePathChasedCall
#include "refuzz/control/job/job_arbitration.hpp"
#include "refuzz/control/loop/completion_context.hpp"    // ConsumerCtx / CompletionCtxOf
#include "refuzz/control/mab/mab_task_selector.hpp"  // [mab Step 1] task-MAB 决策器
#include "refuzz/logging/host_logger.hpp"

// [v2 admit-worker async] AsyncAdmitWorker —— corpus admit 落盘 + ChoiceTable
//   rebuild 异步化。详见 async_admit_worker.hpp。
#include "refuzz/control/async_admit_worker.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>  // [mab] candidate-region probe (std::function)
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <queue>
#include <string>
#include <string_view>
#include <utility>  // [belief-graph] std::pair (ResolveLineageRoot return)
#include <unordered_map>
#include <vector>

namespace refuzz::crash {
class CrashPipelineManager;
}

namespace refuzz::queue {
// [request-window] pull/window 生命周期桥接队列;full def 在
// refuzz/queue/lifecycle_queue.hpp(.cpp include)。loop 只持裸指针,前置声明即可。
class InMemoryLifecycleQueue;
} // namespace refuzz::queue

namespace refuzz::fuzzer {
// [seed-future-value §5.1] per-base-seed lineage downstream-yield accumulator;
// full def in feedback/include/refuzz/feedback/lineage/seed_lineage_yield_store.hpp.
class SeedLineageYieldStore;
// [variant-handler-binding] live per_call variant->handler map; full def in
// feedback/include/refuzz/feedback/binding/variant_handler_map.hpp.
class VariantHandlerMap;
} // namespace refuzz::fuzzer

namespace refuzz::core::metrics {
class MetricRegistry;
}

namespace refuzz::request_stream {
// [fixed request stream, Step 4] full def in
// control/include/refuzz/control/request_stream_reader.hpp; only a fwd-decl is
// needed here since SpawnFixedInputProducerJob takes it by const reference.
struct RequestStream;
}  // namespace refuzz::request_stream

namespace refuzz::control {

namespace job {
class Job;
class JobScheduler;
}

// [seed-value signals shadow] JSONL sink; owned by FuzzerLoop via unique_ptr
// (out-of-line dtor), full def in seed_value_shadow_sink.hpp included by the .cpp.
class SeedValueShadowSink;

// [Step 1 catch-all 迁 loop] 候选区/triage-trampoline 的 pending seed map。full def
// 在 triage_stage.hpp(.cpp include);loop 只持 shared_ptr,故前置声明即可。
class PendingSeedMap;

using refuzz::fuzzer::CorpusInbox;
using refuzz::fuzzer::CorpusManager;
using refuzz::fuzzer::ICorpusStore;
using refuzz::fuzzer::IFeedbackEngine;
using refuzz::fuzzer::IFeedbackStore;
using refuzz::fuzzer::IMutatorEngine;
using refuzz::fuzzer::IPriorityCalculator;  // [v2 batch 3 PR-Y]
using refuzz::fuzzer::ISaturationFilter;    // [v2 batch 3 G5]
using refuzz::fuzzer::IRetryPolicy;
using refuzz::fuzzer::ISchedulerEngine;
using refuzz::fuzzer::IStabilityOracle;
using refuzz::fuzzer::Seed;
using refuzz::fuzzer::SeedDisposition;

struct FuzzerLoopConfig {
    // [request-window] scheduler pull/dispatch 窗口上限:最多允许多少个 request 处于
    // "已提交给执行侧但尚未 accepted 确认"的状态(= syz `requests − executing < 2·procs`)。
    // 透传给 JobScheduler::Deps.dispatch_window_limit;由 accepted 生命周期事件释放 credit。
    // 注:外部 JSON 配置键仍为历史名 "high_watermark"(config_parser 映射到此字段)。
    size_t request_window_limit = 64;
    int corpus_max_drain = 32;
    // [coverage-ownership bound] corpus 大小不再有固定容量上限,也不再有可选 minimize
    // 旋钮 —— 语料边界由 CorpusManager 的 SignalOwnershipIndex(覆盖所有权不变量)常驻
    // 维护。旧的 fuzzer.corpus.{capacity,minimize.*} 配置键仍被 parser 接受但忽略。
    uint32_t exec_timeout_ms = 1000;
    uint64_t initial_seed_id = 2;
    // [verdict 重构] corpus 准入模式。默认 kInteresting(= 旧 corpus_admit,所有真实
    // profile 走这条);kAlways = 旧 corpus_admit_all(blackbox baseline),kNever = shadow。
    refuzz::fuzzer::AdmitMode admit_mode = refuzz::fuzzer::AdmitMode::kInteresting;
    std::string corpus_persist_dir;
    // [v2 V1 fallback capability-gated — 当前版本] 镜像 ProfileCapabilities.
    // accept_bytes_only_fallback;由 orchestrator 从 active_profile->capabilities
    // 拷贝到这里, FuzzerLoop ctor 再透传到 JobDeps。默认 false = 严格
    // typed/artifact-first。
    bool accept_bytes_only_fallback = false;
    // [Step 1 catch-all 迁 loop] 镜像 ProfileCapabilities.triage_enabled;true 时
    // FuzzerLoop 承接的 catch-all 对 NewCov seed 走 divert + push "triage" follow-up
    // (= 旧 mut_c triage 路径)。orchestrator 从 active_profile->capabilities 拷入。
    bool catch_all_triage_enabled = false;
    // [config-selected scheduling policy] config 的 fuzzer.scheduling_policy 落点。
    // orchestrator 据此设 PolicyEngine 的 normal.scheduling_policy(真正驱动 active
    // policy 的层;FuzzerLoop 本身不消费它)。priority / round_robin / uniform /
    // size_weighted / rarity_weighted;空 = PolicyEngine 默认。
    std::string scheduling_policy;
    // [reFuzz reward] reward 任务时间成本 t(秒)的 outlier 截顶。t = guest exec 窗(真实、
    // triage-immune);截顶稳住罕见超长 exec/timeout 对 σ 的扰动(~2s)。task-MAB 本身无 on/off
    // 旋钮 —— chain 提供 gen+mut 两 arm 时即生效(见 FuzzerLoop 的 mab_active_),否则退化
    // first-wins。详 docs/plans/mab-stage-selection.md。
    double mab_time_cap_s = 2.0;
    // [choice-table feedback shadow] run logs dir (orchestrator c.layout.logs_dir).
    // Non-empty enables the per-target-syscall novelty persistence TSV dump
    // (choice_table_persist.tsv). Empty (tests / no telemetry) disables it.
    std::string logs_dir;
    // [seed-value signals shadow] when true AND logs_dir non-empty, the loop
    // writes one seed_value_shadow.jsonl row per mutation outcome (signals of
    // the mutated seed + realized verdict). Pure observation; default off.
    // docs/plans/seed-value-signals.md §4.
    bool seed_value_shadow_enabled = false;
    // [seed-future-value] when true, the assembler builds a SeedHorizon and the
    // scheduler caches future(seed) at admit (exposed via SeedFutureValue).
    // INDEPENDENT of the shadow json: horizon-on/shadow-off computes future for
    // the A/B (no json); shadow-on/horizon-off logs future=0. Default off — the
    // model build + per-admit cost stay out of baseline / speed-compare runs.
    bool seed_horizon_enabled = false;
    // [future_band2] path to function_block_map.tsv; when set (and seed_horizon on)
    // the band-② shadow candidate is built. Empty = off (SeedBand2Value=0).
    std::string seed_band2_map_path;
    // [variant-handler-binding 2026-06-18] path to function_block_map.tsv; when set (and
    // logs_dir non-empty) FuzzerLoop builds the live per_call variant->handler map and
    // dumps variant_handler_map.jsonl. Empty = off. Independent of shadow/horizon gates.
    std::string variant_handler_map_path;
    // [belief-graph] path to graph_M.tsv (static 8-mechanism belief prior, offline-produced
    // by scripts/seed_horizon/substrate). When set the assembler loads a StaticBeliefGraph and the
    // scheduler caches belief(seed) at admit (exposed via SeedBeliefValue, logged to the
    // shadow json as belief_value). Empty = off. Independent of the other gates. SHADOW ONLY.
    std::string belief_graph_path;
    // [fixed request stream, Step 4] docs/plans/fixed-request-stream-performance-replay.md
    // §6.2: "禁止启动正常 ExploreJob". When true, the ctor does not call
    // SpawnExploreJob() -- the caller (Orchestrator, in fixed-input mode) is
    // responsible for calling SpawnFixedInputProducerJob() instead, making the
    // request stream the loop's sole task source. Default false = unchanged
    // behavior for every existing caller.
    bool suppress_default_producer = false;
    // [request-stream capture] When non-empty, every request this loop dispatches
    // is appended to this file as one JSON line (control/src/request_stream_sink.cpp),
    // and tools/syz-stream-from-jsonl converts it into a replayable stream. Set
    // during a NORMAL fuzz run to capture reFuzz's own workload, which is the
    // mirror of syz-manager's -request-stream and the only way to fill the
    // "syzkaller executes reFuzz's programs" cell of the comparison.
    // Empty = off, zero cost. Must NOT be combined with run_mode=replay: capturing
    // a replay would just re-emit the stream it was given.
    std::string request_stream_capture_path;
};

// FuzzerLoop
//
// FuzzerLoop owns completion-side business logic: feedback processing, MAB
// settlement, catch-all admission, candidate retry, crash forwarding, and
// periodic corpus/metric ticks. It also owns job handoff; JobScheduler owns
// only the request-window submit funnel.
class FuzzerLoop : public core::IPolicyControl {
public:
    // [v2 exectime split — 当前版本] 新增 session_start:build_task 首次提交 task 时
    //   把 (now - session_start) 微秒数 Set 到 fuzzer.fuzz_phase_started_us gauge,
    //   run_summary 用它派生 elapsed_fuzz_ms / exec_fuzz_s 把启动开销剥离。
    //   session_start 必须 = orchestrator.started_at(同一 steady_clock 锚)。
    FuzzerLoop(queue::InMemoryTaskQueue& task_queue,
               queue::InMemoryEventQueue& event_queue,
               ICorpusStore& corpus,
               const core::EngineHandle<IMutatorEngine>& mutator_handle,
               const core::EngineHandle<ISchedulerEngine>& scheduler_handle,
               const core::EngineHandle<IFeedbackEngine>& feedback_handle,
               refuzz::logging::HostLogger&                             logger,
               FuzzerLoopConfig config = {},
               // v2: metric registry,nullptr 时跳过发布(独立于 stats_ 写入)
               refuzz::core::metrics::MetricRegistry* metrics = nullptr,
               // [v2 exectime split] session_start —— 与 orchestrator.started_at 同一锚。
               //   默认 epoch:测试不传时退化为"首次 produce 时打 0",
               //   gauge=0 → run_summary 派生字段输出 0(即 fuzz phase 视为未起步)。
               std::chrono::steady_clock::time_point session_start = {});

    ~FuzzerLoop() override;

    void SetCrashPipeline(crash::CrashPipelineManager* manager);
    // [request-window] 注入 pull/window 生命周期队列(orchestrator 与 Executor 共用同一实例)。
    // FuzzerLoop 排干它 → JobScheduler::MarkAccepted(释放 dispatch 窗口 credit)。
    void SetLifecycleQueue(queue::InMemoryLifecycleQueue* queue);
    void SetFeedbackStore(IFeedbackStore* store);
    // framework primitive injection — orchestrator 在 bundle 完整后
    // 调用,把 AssembledBundle.stability_oracle.get() 塞进 deps_.stability_oracle。
    // nullptr 视为未注入,core-path job 会按缺省行为处理。
    void SetStabilityOracle(IStabilityOracle* oracle);
    // [v2 SubT-B] 同上 pattern,IRetryPolicy。本批次仅搭骨架,批次 3 G6 才 read。
    void SetRetryPolicy(IRetryPolicy* policy);
    // [v2 batch 3 PR-Y] 同上 pattern,IPriorityCalculator。当前 stage 无 caller,
    // 字段保 7 步 canon 一致(future stage 消费时已就位)。
    void SetPriorityCalculator(IPriorityCalculator* calc);
    // [v2 batch 3 G5] 同上 pattern,ISaturationFilter。当前 stage 无 caller,
    // KcovCoverageSignal 经 SignalTraits::BuildContext 直接注入;字段保 canon。
    void SetSaturationFilter(ISaturationFilter* filter);
    // [v2 Epic 5 PR-5-B] cmp dedupe truth-store — used to publish
    // fuzzer.cov.cmp.unique gauge each tick. nullptr is tolerated:
    // gauge stays at its last value (0 for fresh runs).
    void SetCmpFeedbackStore(IFeedbackStore* store);
    void SetAllPcFeedbackStore(IFeedbackStore* store);
    void SetCorpusPcFeedbackStore(IFeedbackStore* store);
    void SetAllEdgeFeedbackStore(IFeedbackStore* store);
    void SetCorpusEdgeFeedbackStore(IFeedbackStore* store);

    // [mab — candidate drain] 候选区(PendingSeedMap)规模探针。orchestrator 用
    // bundle.pending_seed_map 注入;task-MAB 开启时,probe()>0 期间优先喂 boot
    // candidate(= syz WorkCandidate 优先处理),drain 完(probe()==0)MAB 才接管 steady-state。
    // 未注入(nullptr)→ 视为无候选区,直接走 MAB(空起 / 直接 admit profile)。
    void SetMabCandidateProbe(std::function<std::size_t()> probe);

    // [Step 1 catch-all 迁 loop] 注入 catch-all 的 pending 区。orchestrator 从
    // bundle.pending_seed_map 注入(同 SetMabCandidateProbe 源)。nullptr / 未注入 →
    // catch-all 不 divert(直接 inbox admit),等价 triage_enabled=false。
    void SetCatchAllPending(std::shared_ptr<PendingSeedMap> pending);

    // [fixed request stream, Step 4] Spawns the ONE producer job that feeds a
    // pre-validated request stream, in sequence order, through the same
    // request-window/JobScheduler/TaskQueue pipeline as any other producer.
    // Call once, after constructing this loop with
    // FuzzerLoopConfig::suppress_default_producer=true (so it becomes the
    // loop's sole task source) -- see plan §6.2. `stream` is not owned; it
    // must outlive this loop. `on_fully_drained` runs on the control thread,
    // at most once, once every record has been emitted AND every emitted
    // request's completion observed (plan Gate 4: "完成最后一条输入后等待
    // 全部已接收任务完成").
    void SpawnFixedInputProducerJob(const refuzz::request_stream::RequestStream& stream,
                                    std::function<void()> on_fully_drained);

    // [Step 2 candidate 结果处理] 一次 candidate ② 执行的追踪信息:被验证的 boot seed_id +
    // 该次 attempt(= syz progCandidate/ProgFromCorpus + attempt,fuzzer.go:382/208)。
    struct CandidateExecInfo {
        std::uint64_t seed_id = 0;
        int           attempt = 0;
    };
    // [Step 2/3 candidate] feeder(candidate job)emit ② 拿到 exec_id 后调:登记一个在飞
    // candidate,使其 completion 在 ProcessCatchAllCompletion 被识别为 candidate re-verify
    // (而非普通 fuzz 变异)→ 走 kBootCorpus 分支(新覆盖 → tier① triage;flaky → 重试/丢)。
    void RecordCandidateExec(std::uint64_t exec_id, std::uint64_t seed_id, int attempt);
    // [Step 2/3 candidate] feeder 每轮取走并清空本轮 flaky 重试({seed_id, attempt+1});
    // feeder 据 seed_id 从 pending 区重取程序、重 emit ②(= syz re-enqueue candidateQueue)。
    std::vector<CandidateExecInfo> DrainCandidateRetries();

    // [6b-3 — 当前版本] Stats()/RuntimeSnapshot()/CrashCount()/SetRuntimeSnapshotBus
    // 已删除, 消费方改读 MetricRegistry。

    // FL 线程入口:跑一拍 loop 侧 runtime tick,drain event_queue + feedback Process,
    // 再本地 demux completion:route-back 结果投本地 job runtime,未认领走 catch-all。
    bool RunOnce(std::chrono::milliseconds event_pop_timeout);
    void Drain(std::chrono::milliseconds event_pop_timeout, uint32_t max_loops);
    // Run the final forced corpus minimize pass and publish corpus gauges.
    // Orchestrator calls this before telemetry final summary.
    void FinalizeCorpusForShutdown();
    size_t PendingCount() const;

    void SwitchMutationPolicy(std::string_view name) override;
    void SwitchSchedulingPolicy(std::string_view name) override;
    void SwitchCorpusAdmissionPolicy(std::string_view name) override;

private:
    // [exec-accounting 重构] 全局逐-event 执行/结果记账还给控制环。
    //
    // RunOnce / Drain pop 出 event 后调一次:
    //   1. peel pseudo-dispatch 区(单一 chokepoint);
    //   2. feedback_handle_.Get().Process(event) **一次**(loop 直接引用 feedback);
    //   3. 写**全部**全局计数(results_* / raw-abnormal / calls.executed=
    //      out.executed_calls / cov.* / 结果分类 / interesting);
    //   4. 把 EngineOutput 存进 cctx.feedback_output,后续 route-back/catch-all 复用
    //      (绝不二次 Process —— 它有状态)。
    void ProcessEventFeedback(ConsumerCtx& cctx);

    // ProcessEventFeedback 的 post-Process 尾段(MAB reward / belief-shadow /
    // lineage observation)。由 FuzzerLoop completion path 本地调用;JobScheduler 不承接业务逻辑。
    void SettleFeedbackCompletion(ConsumerCtx& cctx);

    // 每次 RunOnce 的 loop 侧外围维护:确保常驻 explore/candidate feeder job 存活,
    // 应用 corpus policy switch,执行 corpus 周期维护。JobScheduler 只负责 request-window。
    bool RuntimeTick();
    // [MAB observability] mab_arm_state 打点。**不由周期 tick 驱动** —— MAB 是 ExploreJob 的运行时
    //   状态,观测 cadence 绑其产出:ExploreJob 每 kObserveEvery 次 emit 经 ejd.observe 调本函数
    //   (job body 内、与 loop handoff strict-alternate,读 MAB/metrics 安全)。
    void EmitMabState();
    // [event-driven spawn] 常驻 job 的启动/自愈,取代旧 RuntimeTick 的每-tick 存活位轮询。
    //   SpawnExploreJob:ctor 首 spawn + ExploreJob on_done 自补(无 alive gate)。
    //   MaybeSpawnCandidateFeeder:SetCatchAllPending(bootstrap)/ retry push / feeder on_done 触发。
    void SpawnExploreJob();
    void MaybeSpawnCandidateFeeder();

    bool SpawnJob(job::JobFn fn);
    bool DrainLifecycle();
    bool DeliverToJob(job::Job* job, job::ExecResult result);
    struct RoutedJobEntry {
        job::Job* owner = nullptr;
        job::CompletionTriagePolicy policy =
            job::CompletionTriagePolicy::kSuppressCatchAllTriage;
    };
    std::optional<RoutedJobEntry> TakeRoutedJobEntry(std::uint64_t exec_id);
    void SettleEmitCompletion(std::uint64_t exec_id,
                              const job::ExecResult& result);
    bool ReclaimJob(job::Job* job);
    // [tier-aware arbitration] 选下一条有 pending request 的 job(镜像 syz
    // Order(candidate_triage,candidate,triage,Alternate(smash,3),explore));见
    // fuzzer_loop.cpp 实现处的注释。无 ready job → nullptr(调用方应停止 ArbitrateJobs 的 while)。
    job::Job* SelectNextReadyJob();
    bool ArbitrateJobs();
    bool PumpJobs();

    // [Step 1 catch-all 迁 loop] catch-all completion actuation(搬自 MutationalConsumerStage:
    // crash→pipeline / scheduler.OnFeedback / corpus.MarkInteresting / OfferVerdict(divert) +
    // "triage" trampoline / link-trace)。只对**未被专用 consumer / job 认领**的 completion 调
    // (drain 里 !claimed && !event_consumed)。逐 event 一次的全局记账 + feedback Process 已在
    // ProcessEventFeedback。
    void ProcessCatchAllCompletion(ConsumerCtx& cctx,
                                   const job::ExecResult& result);
    // Emit one sampled trace row for every terminal task path.
    void EmitCompletionTaskTrace(ConsumerCtx& cctx);
    bool MaybeSpawnCorePathFromCompletion(ConsumerCtx& cctx,
                                          const job::ExecResult& result,
                                          refuzz::fuzzer::SeedSource source,
                                          bool is_candidate,
                                          std::uint64_t candidate_seed_id,
                                          int candidate_attempt,
                                          bool allow_direct_inbox_admit);

    // Core-path side-effect 的唯一入口。两个调用点(ProcessCatchAllCompletion / RunOnce
    // routed 分支)都必须走这里,避免对同一条 completion 重复 OfferVerdict/建 seed/
    // spawn core-path job。
    bool RouteCorePathFromCompletion(ConsumerCtx& cctx,
                                     const job::ExecResult& result,
                                     refuzz::fuzzer::SeedSource source,
                                     bool is_candidate,
                                     std::uint64_t candidate_seed_id,
                                     int candidate_attempt,
                                     bool allow_direct_inbox_admit);

    // [Step 6 Phase 1] catch-all = syz processResult → triageJob 的 spawn 点。截留的 NewCov
    // seed 直接 spawn 一条融合 deflake+minimize 的 core-path job(吸收 triage_stage 的 spawn
    // 路径,不经 "triage" follow-up / 生产窗)。source 决定 tier + deflake 档:kMutation(现场)
    // → tier③ + retry_policy 的 3-of-5;kBootCorpus(candidate retriage)→ tier① + syz
    // ProgFromCorpus 的宽松 2/6/2。返回是否进入 loop 本地 job runtime。
    bool TrySpawnCorePathTriage(std::shared_ptr<refuzz::fuzzer::Seed> seed,
                                refuzz::fuzzer::SeedSource source,
                                std::uint64_t pending_seed_id = 0,
                                // [per-call novelty] discovery-exec per-call newSignal
                                //   (syz job.calls seed). Empty is logged/dropped.
                                std::vector<CorePathChasedCall> initial_calls = {},
                                std::optional<CorePathDiscoverySample> discovery = std::nullopt);

    // [seed-value signals shadow] write one JSONL row for a mutation outcome:
    // the mutated parent seed's three signals (A rarity via scheduler, B stable-
    // metadata, C altitude via mutator) joined with this verdict. Only called
    // when seed_value_shadow_ exists. Observation only — no selection effect.
    void EmitSeedValueShadow(std::uint64_t parent_seed_id,
                             const refuzz::fuzzer::EngineOutput& out,
                             double elapsed_s);

    // [seed-future-value §5.1] attribute a mutation outcome's executed cover to
    // its lineage ROOT base seed at the lineage DEPTH (walks SeedLineageMetadata
    // parent-pointers), feeding lineage_yield_store_. Only when it exists.
    void FeedLineageYield(std::uint64_t origin_seed_id,
                          const refuzz::fuzzer::EngineOutput& out);

    // [belief-graph lineage] walk SeedLineageMetadata parent-pointers from `seed_id`
    // to its mutation-chain ROOT, returning {root, depth} (depth 1-based; 1 = seed_id
    // itself is a base / non-mutate). Shared by FeedLineageYield and EmitSeedValueShadow
    // so a lagged payoff attributes to the high-belief ancestor, not just the parent.
    std::pair<std::uint64_t, std::uint32_t> ResolveLineageRoot(std::uint64_t seed_id) const;

    queue::InMemoryTaskQueue& task_queue_;
    queue::InMemoryEventQueue& event_queue_;
    ICorpusStore& corpus_;
    const core::EngineHandle<IMutatorEngine>& mutator_handle_;
    const core::EngineHandle<ISchedulerEngine>& scheduler_handle_;
    const core::EngineHandle<IFeedbackEngine>& feedback_handle_;
    IFeedbackStore* feedback_store_ = nullptr;
    // [v2 Epic 5 PR-5-B] separate cmp dedupe instance, set by orchestrator.
    IFeedbackStore* cmp_feedback_store_ = nullptr;
    IFeedbackStore* all_pc_feedback_store_ = nullptr;
    IFeedbackStore* corpus_pc_feedback_store_ = nullptr;
    IFeedbackStore* all_edge_feedback_store_ = nullptr;
    IFeedbackStore* corpus_edge_feedback_store_ = nullptr;
    crash::CrashPipelineManager* crash_pipeline_ = nullptr;
    // [request-window] pull/window 生命周期队列(orchestrator 注入;与 Executor 同一实例)。
    //   FuzzerLoop DrainAll → JobScheduler::MarkAccepted。nullptr = 未注入(单测直构)。
    std::atomic<queue::InMemoryLifecycleQueue*> lifecycle_queue_{nullptr};

    uint64_t next_executor_id_ = 1;
    uint64_t next_seed_id_ = 2;
    // [request-window] 透传给 JobScheduler::Deps.dispatch_window_limit。外部 JSON 配置键仍为
    //   "high_watermark"(见 FuzzerLoopConfig)。
    size_t request_window_limit_ = 64;
    uint32_t exec_timeout_ms_ = 1000;
    int warm_tick_ = 0;
    int warm_interval_ = 32;
    std::chrono::steady_clock::time_point next_corpus_sweep_at_{};
    refuzz::fuzzer::metrics::FuzzerMetrics fuzzer_metrics_{};
    // [harness-fatal 语义修正] 只做“第一个 kHarnessFatal 事件去重”的计数器门。
    // 历史实现把它当全局退出 latch（Orchestrator 循环条件 !HarnessFatalLatched()），
    // 导致第一次 error 14 就整轮 Stop()，即使 channel 的恢复策略本来能救回来。
    // 现在全局终止只由 channel 真正进入 kFailed 驱动（见 Orchestrator::ChannelFailed），
    // 这里仅保证 results_harness_fatal 计数和 harness_fatal 日志只发一次。
    std::atomic<bool> harness_fatal_seen_{false};
    // [v1 important_budget_ — ROLLBACK: Phase 2 Step 2.4 删除]
    //   pre-Phase-2 全仓 grep 确认是死代码（仅有 fuzzer_loop.hpp 声明 + .cpp 三处 read，
    //   无任何写入路径）。Phase 1 Step 1.7 重写 RunOnce 后连 read 也消失。
    //   MutationalProducerStage 已硬编码 task.important = false（见 mutational_stage.cpp）。
    //   未来若需要 important task 路径，通过 stage_params 传入 budget，而非 FuzzerLoop 成员。
    // std::unordered_map<uint64_t, uint8_t> important_budget_;

    CorpusInbox corpus_inbox_;
    CorpusManager corpus_manager_;

    // [v2 6b-1 — 当前版本] One-hot policy Gauge publisher
    refuzz::core::metrics::PolicyStatePublisher policy_state_publisher_;

    // [Step 6 stage 清场] producer/consumer chain + follow_up_dispatcher 已从 loop 物删。
    //   注意：声明顺序就是初始化顺序——deps_ 必须放在所有它引用的成员之后。
    refuzz::logging::HostLogger&                              logger_;
    std::mt19937_64                                           rng_{std::random_device{}()};
    uint64_t                                                  next_job_id_ = 1;
    uint64_t                                                  mab_observation_seq_ = 0;
    // [v2 exectime split] session_start_:与 orchestrator.started_at 同源,steady 锚。
    //   fuzz_phase_started_:一次性闸,首次 task 经 build_task 提交后置 true,避免重复写 gauge。
    std::chrono::steady_clock::time_point                     session_start_{};
    bool                                                      fuzz_phase_started_ = false;
    // [v2 admit-worker async] 后端 admit 处理 worker。
    //   ctor 创建 + Start();SetOnAdmit lambda 把 SaveSeed + OnSeedAdmitted 委托给它;
    //   ~FuzzerLoop 最先调 StopAndDrain() 把 pending seed 清干净再走 stage shutdown。
    //   声明顺序约束:必须早于 deps_(deps_ 不引用它,但与 corpus_manager_ 同生命周期)。
    std::unique_ptr<AsyncAdmitWorker>                         admit_worker_;
    // [mab-stage-selection Step 1] task-MAB 决策器(default off)。ExploreJob 选 arm + 记
    // inflight,ProcessEventFeedback 回灌 reward。ctor body 据 FuzzerLoopConfig 重建。
    std::unique_ptr<mab::MabTaskSelector>                     mab_task_selector_;
    // [Step 6 stage 清场] jobs-only 默认模式:ExploreJob 的 gen/mut/collide 三臂恒可用(无 flag
    //   判据)→ gen-vs-mut MAB 恒 active。
    bool                                                     mab_active_ = true;
    // [mab — candidate drain] 候选区规模探针(orchestrator 注入)。空 = 无候选区。
    std::function<std::size_t()>                              mab_candidate_probe_;
    // [Step 1 catch-all 迁 loop] catch-all 的 triage-trampoline pending 区 + 是否 divert。
    // pending 由 SetCatchAllPending 注入(与 triage/minimize 共用);triage_enabled 从 config。
    // 两者都真时 catch-all 对 NewCov seed 走 divert + push "triage" follow-up。
    std::shared_ptr<PendingSeedMap>                          catch_all_pending_;
    bool                                                     catch_all_triage_enabled_ = false;
    // [seed-value signals shadow] ctor builds it iff config.logs_dir non-empty
    // AND config.seed_value_shadow_enabled; ProcessEventFeedback writes one row
    // per mutation outcome. RAII flush on dtor. Observation only.
    std::unique_ptr<SeedValueShadowSink>                     seed_value_shadow_;
    // [belief-graph Phase B] where DumpBeliefPosterior writes the calibrated (α,β) at shutdown; set in the
    // ctor alongside the shadow sink (empty ⇒ off). FinalizeCorpusForShutdown triggers the dump.
    std::string                                             belief_posterior_path_;
    // [seed-future-value §5.1] value-realized downstream-yield oracle sidecar.
    // Same gate + logs dir as seed_value_shadow_; RAII-dumps seed_lineage_yield.jsonl
    // on dtor. Fed by FeedLineageYield (lineage walk). Observation only.
    std::unique_ptr<refuzz::fuzzer::SeedLineageYieldStore>   lineage_yield_store_;

    // [cluster-unit metric — Tier 1, §5.2a] sibling fed the SAME novel-edge stream
    // bucketed by 4 KB text page (sig>>12 == pc>>12, raw_pc=true) — the dependency-
    // cluster de-bias probe. Counting distinct pages compresses within-handler bursts
    // while preserving cross-page mass. Dumps seed_lineage_yield_cluster.jsonl; both
    // stores fed in FeedLineageYield and compared offline. Null iff shadow gate off.
    std::unique_ptr<refuzz::fuzzer::SeedLineageYieldStore>   lineage_yield_store_cluster_;
    // [periodic flush] credited-event counter; FeedLineageYield re-dumps both yield
    // stores every kLineageFlushEvery hits so the value oracle is observable mid-run
    // and survives SIGKILL (RAII dtor otherwise the only dump).
    std::uint32_t                                           lineage_flush_ctr_ = 0;
    // [variant-handler-binding 2026-06-18] live per_call variant->handler map; RAII-dumps
    // variant_handler_map.jsonl. Fed by FeedVariantHandlerMap from ProcessEventFeedback;
    // re-flushed every kVariantHandlerFlushEvery execs. Null iff the path/logs gate is off.
    std::unique_ptr<refuzz::fuzzer::VariantHandlerMap>      variant_handler_map_;
    std::uint32_t                                           variant_handler_flush_ctr_ = 0;
    // [belief-graph / variant-binding] SyscallMeta::id -> variant name (id is the dense
    // index into Target::syscalls()). Built once in the ctor when the shadow sink or the
    // binding map is active; feeds VariantHandlerMap::SetVariantNames AND maps
    // per_call[i].syscall_id -> name for EmitSeedValueShadow's executed_variants. Empty
    // (non-kernel / both gates off) -> both consumers degrade to no-op.
    std::vector<std::string>                                variant_id_to_name_;
    // [SyzVegas baseline] mutation 任务的 executor_id → 该次 seed 抽样 {seed_id, pr, γ},产出时
    // 记、completion 时取(结算无状态 seed-MAB OnSeedReward),用完即删。**在途快照归 loop**:
    // 按 exec_id 分开 → 并发同 seed 不互相覆盖;corpus 调度侧不持任何 per-seed 在途态、不知 exec_id。
    std::mutex mutate_seed_mu_;
    std::unordered_map<std::uint64_t, refuzz::fuzzer::SeedSelection> mutate_seed_for_exec_;
    // [Step 2 candidate 结果处理] 在飞 candidate ② exec:exec_id → {boot seed_id, attempt}。
    // RecordCandidateExec 记(feeder 提交时,control 线程),ProcessCatchAllCompletion 查+删
    // (control 线程 drain);两者都 control 线程 → 无 race。命中即"本 completion 是 candidate"。
    std::mutex                                               candidate_mu_;
    std::unordered_map<std::uint64_t, CandidateExecInfo>     candidate_exec_;
    // [Step 2] flaky candidate 重试队列({seed_id, attempt+1});feeder 每轮 Drain 重 emit ②。
    std::vector<CandidateExecInfo>                           candidate_retry_;
    JobDeps                                                   deps_;
    // JobScheduler 是 request-window submit pump; job handoff/jobs_ 由 FuzzerLoop
    // 本线程持有,这样 job body 与 completion/catch-all/MAB/corpus 逻辑 strict-alternate。
    // [event-driven] ExploreJob 无存活标记:ctor 首 spawn + on_done 自补(SpawnExploreJob),
    //   任意时刻恰一条(补 spawn 前短暂零条),无需 alive gate、无每-tick 轮询。
    // [Step 3 candidate feeder] CandidateFeederJob(② = syz candidateQueue 喂入)存活标记 +
    // bootstrap 已扫标记。RunOnce 见 feeder 不在 且 还有 candidate work(未 bootstrap /
    // candidate_retry_ 非空)则 spawn。bootstrap 扫描(boot corpus kBootCorpus,shortest-first)
    // 只在首次 spawn 做一次(首 tick pending 里只有 boot candidate,无 triage-pending 污染)。
    std::atomic<bool>                                        candidate_feeder_alive_{false};
    bool                                                      candidate_bootstrapped_ = false;
    std::unique_ptr<job::JobScheduler>                        job_sched_;
    // [request-stream capture] Non-null only when cfg.request_stream_capture_path
    // is set. Owned here because it is fed from JobScheduler's submit funnel and
    // must outlive it; closed in the destructor so the file is complete even when
    // the run ends through the stop path rather than a clean drain.
    std::unique_ptr<RequestStreamSink>                        request_stream_sink_;
    std::uint64_t                                             next_job_runtime_id_ = 1;
    std::queue<job::JobFn>                                    job_spawn_queue_;
    std::vector<std::unique_ptr<job::Job>>                    jobs_;
    std::unordered_map<std::uint64_t, RoutedJobEntry>         routed_jobs_;
    // [tier-aware arbitration] syz Order(candidate_triage,candidate,triage,
    //   Alternate(smash,3),explore) 语义前移到 ArbitrateJobs 的 pull 点(而不是等 request 进了
    //   task_queue 才排序 —— routed request 从不进 task_queue,必须在这里做)。状态里每档一个
    //   轮转游标(避免同档内老 job 永远先赢);alternate 计数器镜像 syz Alternate(smash,3)。
    job::JobArbitrationState                                job_arbitration_state_;
    std::vector<job::PendingJobView>                         job_arbitration_pending_;
    std::unordered_map<std::uint64_t, job::OnCompleted> emit_completion_;
};

} // namespace refuzz::control
