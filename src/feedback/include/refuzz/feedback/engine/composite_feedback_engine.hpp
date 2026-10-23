// Copyright 2026 reFuzz project author -------youngkk.
//
// CompositeFeedbackEngine — IFeedbackEngine 的唯一具体实现。
//
// 由 N 个 ISignal + 1 个 IFeedbackAggregator 组合而成。Process 纯函数:
// signals.Sample → aggregator.Aggregate → 返回 EngineOutput{verdict, ...}。
// 不再持有 dispatcher;admit/notify/metrics 的 actuation 归 control loop。
// 命名 engine（"kernel_kcov" / "null" / ...）通过 FeedbackEngineSpec 在
// FeedbackEngineCatalog 中注册，构造时由 BuildFromSpec 装配。

#pragma once

#include "refuzz/feedback/aggregator/feedback_aggregator.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/feedback/signal/signal.hpp"

#include <memory>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

class CompositeFeedbackEngine final : public IFeedbackEngine {
public:
    explicit CompositeFeedbackEngine(std::string name);

    // 装配阶段使用，运行时不再修改。
    void AddSignal(std::unique_ptr<ISignal> signal);
    void SetAggregator(std::unique_ptr<IFeedbackAggregator> aggregator);

    std::string  Name() const override { return name_; }
    EngineOutput Process(const refuzz::core::channel_contract::ChannelEvent& event) override;

    // 诊断 / 测试用。
    std::size_t SignalCount() const noexcept { return signals_.size(); }
    const std::string& AggregatorId() const noexcept { return aggregator_id_; }

private:
    std::string name_;
    std::vector<std::unique_ptr<ISignal>> signals_;
    std::unique_ptr<IFeedbackAggregator>  aggregator_;

    std::string aggregator_id_;

    // 复用 buffer，避免每次 Process 分配。
    std::vector<SignalContribution> contribs_buf_;
};

} // namespace refuzz::fuzzer
