// Copyright 2026 reFuzz project author -------youngkk.
//
// FaultSignal — 从 Fault / AbnormalCompletion 事件构建 CombinedCrashEvent。
//
// 旧 FaultObserver + FeedbackPipeline::BuildCombinedFromFault /
// BuildCombinedFromAbnormal 的合并产物。
// 输出 SignalContribution.crash_payload 由 aggregator 直接透传给 dispatcher。

#pragma once

#include "refuzz/feedback/signal/signal.hpp"

namespace refuzz::fuzzer {

class FaultSignal final : public ISignal {
public:
    std::string Id() const override   { return "fault"; }
    SignalKind  Kind() const override { return SignalKind::kFault; }

    SignalContribution Sample(const refuzz::core::channel_contract::ChannelEvent& event) override;
};

} // namespace refuzz::fuzzer
