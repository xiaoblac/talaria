// Copyright 2026 reFuzz project author -------youngkk.
//
// KcovCmpSignal — kcov_trace_cmp 比较类信号。
//
// [v2 Epic 5 PR-5-B] 真实实现：
//   - 解码 ChannelEvent.output 中的 kCoverageKcovCmp 区段
//   - 每条 CmpRecord 经 fnv1a64 → uint64 hash
//   - 经 cmp 专属 IFeedbackStore (与 KcovCoverageSignal 用的 PC store 分离)
//     去重 → magnitude = 新增 cmp record 数
//   - kComparison 信号的 magnitude 由 aggregator 路由进 score.cmp_gain,
//     dispatcher 据此 +1 fuzzer.cov.cmp.new_total。
// store_=nullptr 时降级为 fired=false / magnitude=0 (catalog 容忍)。
//
// 接口与 KcovCoverageSignal 平行；feedback_codec 由内部持有,
// CoverageNormalizationConfig 暂用默认值 (cmp 不做 raw_pc 归一化)。

#pragma once

#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/feedback/signal/signal.hpp"

namespace refuzz::fuzzer {

class IFeedbackStore;

class KcovCmpSignal final : public ISignal {
public:
    // [v1 stub ctor — ROLLBACK: uncomment + remove v2 below]
    // explicit KcovCmpSignal(IFeedbackStore* store = nullptr);
    // [v2 Epic 5 PR-5-B — 当前版本] codec config 复用 PC 信号的同名结构,
    // raw_pc 默认 true 与 PC 一致 (KCOV_TRACE_CMP 数据本身不做归一化)。
    explicit KcovCmpSignal(IFeedbackStore* store = nullptr,
                           CoverageNormalizationConfig config = {});

    std::string Id() const override   { return "kcov_cmp"; }
    SignalKind  Kind() const override { return SignalKind::kComparison; }

    SignalContribution Sample(const refuzz::core::channel_contract::ChannelEvent& event) override;

private:
    IFeedbackStore*       store_ = nullptr;
    CoverageFeedbackCodec codec_;
};

} // namespace refuzz::fuzzer
