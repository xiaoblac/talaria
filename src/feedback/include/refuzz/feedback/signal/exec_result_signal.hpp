// Copyright 2026 reFuzz project author -------youngkk.
//
// ExecResultSignal — 把 ChannelEvent 类型映射为执行结果码 + 标志位。
//
// 旧 ExecResultObserver + ExecResultEvaluator 的合并产物。

#pragma once

#include "refuzz/feedback/signal/signal.hpp"

namespace refuzz::fuzzer {

class ExecResultSignal final : public ISignal {
public:
    std::string Id() const override   { return "exec_result"; }
    SignalKind  Kind() const override { return SignalKind::kExecResult; }

    SignalContribution Sample(const refuzz::core::channel_contract::ChannelEvent& event) override;
};

} // namespace refuzz::fuzzer
