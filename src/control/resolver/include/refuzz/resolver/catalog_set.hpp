// Copyright 2026 reFuzz project author -------youngkk.
//
// CatalogSet
//
// Resolver 的只读 catalog 视图聚合体。9 个领域 catalog 的 const* 一次性
// 注入,Resolver 用其 Find() 接口校验 LaunchPlan 里的所有 id 是否注册。
//
// 设计意图:
//   1. CatalogSet 不持有 catalog 实例(纯视图),所有权属于装配方
//      (Orchestrator 装配期 / 测试 fixture / 未来 BuiltinCatalogBundle)。
//   2. Resolver 不依赖任何 RegisterBuiltinXxx() 符号——保持为纯函数,
//      不污染分层。catalog 注册由调用方完成。
//   3. 字段全部 const*:nullptr 即代表"该领域未提供",Resolver 入口
//      统一诊断(见 resolver.cpp 的 FindFirstNullCatalog)。


#pragma once

// 9 个 catalog 头(顺序:mutator/scheduler/corpus_store/feedback engine + 3 子 catalog/channel/toolkit)
#include "refuzz/mutator/mutator_catalog.hpp"
#include "refuzz/scheduler/scheduler_catalog.hpp"
#include "refuzz/corpus/corpus_store_catalog.hpp"
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/feedback/signal/feedback_signal_catalog.hpp"
#include "refuzz/feedback/aggregator/feedback_aggregator_catalog.hpp"
#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/crash/target_toolkit_catalog.hpp"

namespace refuzz::resolver {

struct CatalogSet {
    const fuzzer::MutatorEngineCatalog*        mutator      = nullptr;
    const fuzzer::SchedulerEngineCatalog*      scheduler    = nullptr;
    const fuzzer::CorpusStoreCatalog*          corpus_store = nullptr;
    const fuzzer::FeedbackEngineCatalog*       feedback     = nullptr;
    const fuzzer::SignalCatalog*               signals      = nullptr;
    const fuzzer::AggregatorCatalog*           aggregators  = nullptr;
    const refuzz::channel::ChannelCatalog*     channel      = nullptr;
    const refuzz::crash::TargetToolkitCatalog* toolkit      = nullptr;
};

} // namespace refuzz::resolver
