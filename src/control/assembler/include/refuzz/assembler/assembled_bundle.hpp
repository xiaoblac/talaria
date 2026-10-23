// Copyright 2026 reFuzz project author -------youngkk.
//
// AssembledBundle
//
// Assembler 的输出:fuzzer 核心组件所有权集合。约定:
//
// 1. Orchestrator 接手 bundle 后必须 **整体 move 进长期存储**
//    (如 Impl 成员),不得暴露为临时变量——因为下游(FuzzerLoop 等)
//    会把 bundle 字段的 raw pointer 拿走,bundle 析构必须晚于所有 raw
//    pointer 的使用点。
// 2. 字段声明顺序按"依赖被依赖"排列:先声明 = 后析构。engine/manager
//    可能捕获 corpus_store / feedback_store 的裸指针,所以 store 放前面
//    (后析构),manager 放后面(先析构)。
// 3. 非 catalog 产物(HashFeedbackStore / SeedIdAllocator)也归 bundle——
//    它们是"装配结果"的一部分,不是运行时协调的 infra。

#pragma once

#include "refuzz/channel/channel.hpp"
#include "refuzz/control/loop/pending_seed_map.hpp"          // [Step 6] 显式运行时共享态
#include "refuzz/core/metrics/channel_metrics.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/corpus/seed_id_allocator.hpp"
#include "refuzz/crash/target_toolkit_catalog.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/feedback/signal/hash_feedback_store.hpp"
#include "refuzz/feedback/priority_calculator.hpp"  // [v2 batch 3 PR-Y] IPriorityCalculator
#include "refuzz/feedback/saturation_filter.hpp"    // [v2 batch 3 G5] ISaturationFilter
#include "refuzz/feedback/retry_policy.hpp"      // [v2 SubT-B] IRetryPolicy
#include "refuzz/feedback/stability_oracle.hpp"  // [v2 SubT-A] IStabilityOracle
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/scheduler/horizon/seed_horizon.hpp"  // [seed-future-value]
#include "refuzz/scheduler/horizon/seed_band2.hpp"    // [future_band2] shadow candidate
#include "refuzz/scheduler/horizon/static_belief_graph.hpp"  // [belief-graph] static prior
#include "refuzz/scheduler/manager/scheduler_manager.hpp"

#include <memory>
#include <vector>

namespace refuzz::assembler {

struct AssembledBundle {
    // ── "被捕获方"资源(最先声明 = 最后析构)────────────────────────
    // engine/manager 可能以裸指针捕获这些,必须比 manager 长寿。
    std::unique_ptr<fuzzer::ICorpusStore>      corpus_store;
    // [seed-future-value] scheduler engine captures this raw ptr (SetSeedHorizon)
    // → must outlive scheduler_manager. Null when seed_horizon_enabled is off.
    std::unique_ptr<fuzzer::SeedHorizon>       seed_horizon;
    // [future_band2] same lifetime constraint as seed_horizon (engine captures a raw ptr).
    std::unique_ptr<fuzzer::SeedBand2>         seed_band2;
    // [belief-graph] same lifetime constraint (engine captures a raw ptr via SetBeliefGraph).
    std::unique_ptr<fuzzer::StaticBeliefGraph> belief_graph;
    std::unique_ptr<fuzzer::HashFeedbackStore> feedback_store;
    // [v2 Epic 5 PR-5-B] cmp dedupe truth-store — sibling HashFeedbackStore
    // instance for KcovCmpSignal. Persisted at Stop alongside `feedback_store`
    // but to a distinct path (orchestrator: coverage_persist_path + ".cmp").
    std::unique_ptr<fuzzer::HashFeedbackStore> cmp_feedback_store;
    // Measurement-only distinct coverage sets. They are separate from
    // feedback_store because the latter is the priority-bearing max-signal
    // truth store used by admission.
    std::unique_ptr<fuzzer::HashFeedbackStore> all_pc_feedback_store;
    std::unique_ptr<fuzzer::HashFeedbackStore> corpus_pc_feedback_store;
    std::unique_ptr<fuzzer::HashFeedbackStore> all_edge_feedback_store;
    std::unique_ptr<fuzzer::HashFeedbackStore> corpus_edge_feedback_store;
    std::unique_ptr<fuzzer::SeedIdAllocator>   seed_id_alloc;

    // [v2 SubT-A] framework primitive — signal stability oracle。
    // kernel profile 装配时构造 SignalSetIntersectionOracle;其它 family
    // 装配时各自注入(PyTorch numerical tolerance / 协议响应等价等)。
    // 长寿命 unique_ptr,raw ptr 通过 StageDeps.stability_oracle 暴露给
    // triage_stage / corpus_verify_stage(批次 3 G6)等 consumer。
    std::unique_ptr<fuzzer::IStabilityOracle>  stability_oracle;
    // [v2 SubT-B] framework primitive — candidate retry policy。
    // 本批次仅搭骨架;批次 3 G6 corpus_verify_stage 才 read 决策。
    std::unique_ptr<fuzzer::IRetryPolicy>      retry_policy;
    // [v2 batch 3 PR-Y] framework primitive — priority calculator。
    // KcovCoverageSignal::Sample 经 SignalTraits::BuildContext.priority_calculator
    // 拿到 raw ptr 注入 ctor;其它消费者 future 走 StageDeps.priority_calculator。
    std::unique_ptr<fuzzer::IPriorityCalculator> priority_calculator;
    // [v2 batch 3 G5] framework primitive — signal-time saturation filter。
    // KcovCoverageSignal::Sample 经 SignalTraits::BuildContext.saturation_filter
    // 拿 raw ptr 注入 ctor;其它消费者 future 走 StageDeps.saturation_filter。
    std::unique_ptr<fuzzer::ISaturationFilter> saturation_filter;

    // ── target 能力包 ──
    // TargetToolkit 是 struct of lambdas,无反向引用,放中间。
    std::unique_ptr<crash::TargetToolkit>      target_toolkit;

    // ── Manager(先析构 = 后声明 → 其内 engine 先释放,再释 store)──
    std::unique_ptr<fuzzer::FeedbackManager>   feedback_manager;
    std::unique_ptr<fuzzer::SchedulerManager>  scheduler_manager;
    std::unique_ptr<fuzzer::MutatorManager>    mutator_manager;

    // ── Channel(独立,放最后)──
    std::unique_ptr<channel::IChannel>                     main_channel;
    std::vector<std::unique_ptr<channel::IChannel>>        additional_fuzz_channels;
    std::vector<std::unique_ptr<channel::IChannel>>        repro_channels;

    // ── ChannelMetrics (Step 5a) ──
    // 每个 channel 一份,Bind 后内部 Counter*/Gauge* 稳定指向 MetricRegistry。
    // 注意: repro_channel_metrics 必须在使用前 reserve(size) 以防 vector 重分配
    //       后指针失效 (Bind 后地址被持有)。
    core::metrics::ChannelMetrics                          main_channel_metrics;
    std::vector<core::metrics::ChannelMetrics>             additional_fuzz_channel_metrics;
    std::vector<core::metrics::ChannelMetrics>             repro_channel_metrics;

    // ── [Step 6 stage 清场] 显式运行时共享态(取代退役的 stage_shared_state / producer_chain /
    //   consumer_chain / follow_up_dispatcher)──
    //   唯一需保留为显式资源的运行时态:候选区 + triage-pending buffer。assembler 构造;
    //   orchestrator 物化 boot corpus 进它 + 注入 loop 的 catch-all trampoline。其余旧 stage 态
    //   (inflight registry / chain / dispatcher)已随 job 模型归并,不再存在。
    std::shared_ptr<refuzz::control::PendingSeedMap>                                                  pending_seed_map;
};

} // namespace refuzz::assembler
