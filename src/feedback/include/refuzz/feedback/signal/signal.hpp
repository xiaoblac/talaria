// Copyright 2026 reFuzz project author -------youngkk.
//
// ISignal — feedback 的最小可注册单位。
//
// 一个 ISignal 实现把"采样 → 解码 → 自评"三件事内聚到一起，
// 输出 SignalContribution 供 IFeedbackAggregator 合并。
//
// 旧设计中 IFeedbackCodec / IObserver / IFeedbackEvaluator 三层
// 强耦合于"这是哪种信号"，新设计把它们合并为一个接口，让任意
// 信号可以独立注册到 SignalCatalog 并按需组合进 engine。

#pragma once

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/observation/execution_observation.hpp"  // [v2 batch 3 PR-W2]
#include "refuzz/proto_domain/combined_crash_event.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

enum class SignalKind : uint16_t {
    kExecResult = 0,    // exec 结果码 / 执行标志
    kFault      = 1,    // 故障 / 崩溃 payload
    kCoverage   = 2,    // 通用覆盖类（kcov / sancov / edge bitmap）
    kComparison = 3,    // cmp 反馈（kcov_cmp / cmplog / value-profile）
    kSanitizer  = 4,    // ASan / UBSan / MSan 报告
    kResource   = 5,    // 资源消耗（peak rss / cpu / syscall count）
    kCustom     = 255,  // 用户自定义
};

// SignalContribution — 单个信号对一次事件的全部贡献。
//
// 各信号按需填充自身关心的字段，aggregator 按 kind / id 分发处理。
// 字段集合是 union-of-cases 风格：各信号实现只填一两个字段，其余保持默认。
struct SignalContribution {
    std::string id;                            // 来源信号 id, 与 ISignal::Id() 同
    SignalKind  kind = SignalKind::kCustom;

    // ── 元判定 ────────────────────────────────────────────────
    bool fired       = false;                  // 本次产出有效贡献
    bool interesting = false;                  // 自评 interesting（aggregator 可覆盖）
    bool malformed   = false;                  // 解码失败 / 数据损坏
    uint64_t magnitude = 0;                    // cov_gain / 新 cmp 数 / 资源峰值

    // ── 通用解码结果（仅事件含 output bytes 时填充） ──────────
    proto::FeedbackDelta decoded;

    // ── 信号专有载荷（按需取一两个字段） ──────────────────────
    std::vector<uint64_t> hashes;              // kcov / cmp / sanitizer hash 列表
    // Discovery-time DiffRaw output: hashes that were brand-new or upgraded in
    // this signal's stateful novelty store. Stable re-exec/minimize replays keep
    // `hashes` as the full snapshot but normally leave this empty.
    std::vector<uint64_t> novel_hashes;
    proto::ResultCode exec_code = proto::ResultCode::kOk;
    uint32_t exec_flags = 0;                   // 高位扩展标志（ObservationFlag* 类）

    // ── 故障信号专属，aggregator 透传给 dispatcher ────────────
    std::optional<proto::CombinedCrashEvent> crash_payload;

    // ── [v2 batch 3 PR-W2] 该 signal 本次 event 收集到的 transient observation ──
    // composite engine 按 signal 注册顺序 MergeFrom 进 EngineOutput.observation;
    // 后注册同类型 observation 覆盖前注册的。empty 默认无 observation 数据。
    ExecutionObservation observation;
};

// ISignal — 一种反馈信号的完整自包含描述。
class ISignal {
public:
    virtual ~ISignal() = default;

    // 稳定 id（与 SignalCatalog 中注册 id 一致）。
    virtual std::string Id() const = 0;
    virtual SignalKind  Kind() const = 0;

    // 单步处理：从一次 ChannelEvent 中抽样 / 解码 / 自评。
    // 不修改 event；不直接接触 corpus / scheduler。
    virtual SignalContribution Sample(const refuzz::core::channel_contract::ChannelEvent& event) = 0;

    // 可选钩子：上游已确认入库一个新 seed / 触发了 generation reset。
    virtual void OnSeedAdmitted(uint64_t /*seed_id*/) {}
    virtual void OnGenerationReset() {}
};

// 高位 flag：观察侧（曾在旧 feedback.hpp 的 ObservationFlags）保留位定义，
// 与 proto::FeedbackFlags（低 16 位）共存。FaultSignal / ExecResultSignal 使用。
enum SignalExecFlags : uint32_t {
    kSignalFlagFaultObserved              = 1u << 16,
    kSignalFlagFaultWorkerHeartbeatLost   = 1u << 17,
    kSignalFlagFaultKernelCrash           = 1u << 18,
    kSignalFlagFaultVmDead                = 1u << 19,
    kSignalFlagFaultGenerationReset       = 1u << 20,
    kSignalFlagFaultInflightStale         = 1u << 21,
    kSignalFlagFaultSubmitFailed          = 1u << 22,
    kSignalFlagFaultNoOutput              = 1u << 23,
};

} // namespace refuzz::fuzzer
