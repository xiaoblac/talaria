// Copyright 2026 reFuzz project author -------youngkk.
//
// BuiltinCatalogBundle
//
// 9 个领域 catalog 的 "拥有者聚合 + RegisterBuiltinXxx 一次性注册 + View()
// 返回只读 CatalogSet"。消除测试/工具/P7 Orchestrator 里重复 9 行注册的
// 模板代码。
//
// 典型用法:
//   BuiltinCatalogBundle bundle;
//   bundle.RegisterBuiltins();
//   auto resolved = Resolver::Resolve(plan, registry, bundle.View());
//   auto assembled = Assembler::Assemble(*resolved, bundle.View(), ctx);
//
// 设计:
//   * 所有 catalog 按值持有(owning),RegisterBuiltins 调用 RegisterBuiltinXxx
//     的全部 9 个入口,填入所有项目内置条目。
//   * View() 返回 CatalogSet(9 个 const*),CatalogSet 本身只读,bundle 生命
//     周期内始终有效。
//   * 消费方如需注入自定义 entry(测试/插件),先 RegisterBuiltins(),再
//     bundle.mutator.Register(custom_entry)——View() 返回的指针不变,新增条目
//     自然可见。

#pragma once

#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/corpus/corpus_store_catalog.hpp"
#include "refuzz/crash/target_toolkit_catalog.hpp"
#include "refuzz/feedback/aggregator/feedback_aggregator_catalog.hpp"
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/feedback/signal/feedback_signal_catalog.hpp"
#include "refuzz/mutator/mutator_catalog.hpp"
#include "refuzz/resolver/catalog_set.hpp"
#include "refuzz/scheduler/scheduler_catalog.hpp"

namespace refuzz::resolver {

struct BuiltinCatalogBundle {
    fuzzer::MutatorEngineCatalog        mutator;
    fuzzer::SchedulerEngineCatalog      scheduler;
    fuzzer::CorpusStoreCatalog          corpus_store;
    fuzzer::FeedbackEngineCatalog       feedback;
    fuzzer::SignalCatalog               signals;
    fuzzer::AggregatorCatalog           aggregators;
    refuzz::channel::ChannelCatalog     channel;
    refuzz::crash::TargetToolkitCatalog toolkit;

    // 幂等:多次调用等价一次(catalog.Register 以最后一次为准,内置 id 不变)。
    void RegisterBuiltins() {
        fuzzer::RegisterBuiltinSignals(signals);
        fuzzer::RegisterBuiltinAggregators(aggregators);
        fuzzer::RegisterBuiltinFeedbackEngines(feedback);
        fuzzer::RegisterBuiltinMutatorEngines(mutator);
        fuzzer::RegisterBuiltinSchedulerEngines(scheduler);
        fuzzer::RegisterBuiltinCorpusStores(corpus_store);
        refuzz::channel::RegisterBuiltinChannels(channel);
        refuzz::crash::RegisterBuiltinTargetToolkits(toolkit);
    }

    // Resolver / Assembler 消费用的只读视图。bundle 生命周期内指针有效。
    CatalogSet View() const {
        return CatalogSet{
            .mutator      = &mutator,
            .scheduler    = &scheduler,
            .corpus_store = &corpus_store,
            .feedback     = &feedback,
            .signals      = &signals,
            .aggregators  = &aggregators,
            .channel      = &channel,
            .toolkit      = &toolkit,
        };
    }
};

} // namespace refuzz::resolver
