// Copyright 2026 reFuzz project author -------youngkk.
//
// IFeedbackEngine + FeedbackManager
//
// Engine 封装一整套 feedback 处理链（signals + aggregator + dispatcher）。
// Manager 只做注册表与 active 切换控制面（handle-based），不执行 Process。

#pragma once

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/fuzzer/feedback_verdict.hpp"   // Verdict + SeedDisposition（曾在 feedback/，已下沉 core/）
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"

#include "refuzz/feedback/observation/execution_observation.hpp"  // [v2 batch 3 PR-W2]

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

struct EngineOutput {
    // [verdict 重构 — 当前版本] feedback engine 的纯数据判定(interesting / cov_gain /
    // disposition / is_crash / ...)。control loop 取走后自行编排:disposition→scheduler、
    // interesting→corpus.OfferVerdict、crash→pipeline。feedback 自身不再据此产生副作用。
    Verdict verdict;

    // crash 载荷:= verdict.crash_payload 的镜像,保留独立字段让既有只读调用点
    // (mutational / hints / fault / xiuos) 不必改 out.crash_dispatch → out.verdict.crash_payload。
    std::optional<proto::CombinedCrashEvent> crash_dispatch;

    // [exec-accounting 重构] 本次执行真正跑过的 syscall 数(= per-call observation
    // 里 executed==true 的数量,即 kCallFlagExecuted)。feedback 在 decode worker
    // output 构 observation 时**已经**拿到 per-call executed flag(见
    // kernel_observation.hpp:35 / kcov_coverage_signal.cpp:211),这里把聚合数作为
    // 一等输出暴露,供控制环(FuzzerLoop)直接写 fuzzer.calls.executed —— 消费者
    // **不必**重新 decode SyzExecResult。无 per-call observation 的 family 留 0。
    std::uint64_t executed_calls = 0;

    // [Phase F / F3] Triage 求交集所需的 raw signal hash 快照。
    // 只要当前 event 自身携带 signal hash 就填，且 hashes 已去重（unique sorted）。
    // 不能依赖 score.interesting：coverage signal 的 stateful admission 会更新全局
    // store，重复评估同一 event 时 interesting 可能变 false，但 triage/minimize
    // 仍必须看到稳定信号。
    // backward-compat：默认 empty 表示"无 new-cov 信号"，旧 engine 实现不需改即
    // 可保 Phase 1/2 行为。
    std::vector<std::uint64_t> new_signal_hashes;

    // Discovery-time novelty diff for corpus admission parity with syzkaller:
    // brand-new signal hashes plus higher-prio upgrades. Unlike
    // new_signal_hashes, this is not a full event snapshot and is expected to be
    // empty when replaying an already-observed event.
    std::vector<std::uint64_t> novel_signal_hashes;

    // [v2 batch 3 PR-W2] 本次 event 的完整 transient observation;dispatcher /
    // 后续 stage 自决消费。composite engine 按 signal 注册顺序把每个 ISignal 的
    // contribs.observation MergeFrom 进此字段(后注册同类型 observation 覆盖前)。
    // distinct type 跟 Seed.metadata(durable)区分;event 处理完即消亡,
    // dispatcher 决定 materialize 哪些字段进 new_seed.metadata。
    ExecutionObservation observation;
};

class IFeedbackEngine {
public:
    virtual ~IFeedbackEngine() = default;
    virtual std::string Name() const = 0;
    // [verdict 重构] 纯函数:产 verdict + 副产物(hashes/observation/crash),无副作用。
    // 旧的 FeedbackActions& 参数已删,actuation(admit/notify/metrics)归 control loop。
    virtual EngineOutput Process(const refuzz::core::channel_contract::ChannelEvent& event) = 0;
};

// FeedbackManager
//
// 与 MutatorManager 职责同构；handle-based 访问模型详见 mutator_manager.hpp。
class FeedbackManager {
public:
    FeedbackManager() = default;

    int AddEngine(std::unique_ptr<IFeedbackEngine> engine);
    bool SwitchEngineByName(std::string_view name);

    const core::EngineHandle<IFeedbackEngine>& Handle() const noexcept { return engine_handle_; }

    bool HasActive() const noexcept { return engine_handle_.HasValue(); }
    std::string ActiveEngineName() const;
    std::vector<std::string> EngineNames() const;

private:
    std::vector<std::unique_ptr<IFeedbackEngine>> engines_;
    std::unordered_map<std::string, int> name_index_;

    core::EngineHandle<IFeedbackEngine> engine_handle_;
};

} // namespace refuzz::fuzzer
