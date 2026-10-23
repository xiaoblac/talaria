// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedDisposition + Verdict — feedback 链路对外的中立结果词汇。
//
// 这两个类型曾住在 feedback/feedback_dispatch.hpp,导致 corpus/scheduler 反向
// #include feedback/。它们其实是跨模块共享的"执行结果判定"词汇:
//   - feedback(aggregator)是**生产者**;
//   - scheduler(OnFeedback)、corpus(admit 决策)、control(loop 编排)是**消费者**。
// 下沉到 core/fuzzer/ 后,生产者与消费者都只依赖 core,互不反向依赖。
//
// namespace 保持 refuzz::fuzzer,搬家只改 include 路径,不改类型名。

#pragma once

#include "refuzz/proto_domain/combined_crash_event.hpp"

#include <cstdint>
#include <optional>

namespace refuzz::fuzzer {

// scheduler 的优先级建议。feedback 只给值,scheduler 自映射成 boost/cool/neutral。
enum class SeedDisposition : uint8_t {
    kPromote,       // 值得更多关注（发现新覆盖等）
    kNeutral,       // 正常轮转
    kDemote,        // 降低优先级（timeout、exec error 等）
};

// Verdict — feedback 对一次执行事件的完整判定(旧 CompositeScore)。
//
// 这是 feedback engine 的纯数据产物:aggregator 把 N 个 SignalContribution 合成此
// 结构后,由 control loop 取走自行编排(crash→pipeline、admit→corpus、
// disposition→scheduler)。feedback 自身不再据此产生任何副作用。
struct Verdict {
    // ── 基本判定标志 ──────────────────────────────────────────
    bool interesting       = false;
    bool is_crash          = false;
    bool is_timeout        = false;
    bool is_exec_error     = false;
    // [XiUOS leak 一等公民化 Phase 1] a non-crash terminal: the program completed
    // but left a resource leak. It still dispatches its crash_payload (routed to
    // the resource_leak/ bucket) but must NOT mark the seed interesting-for-
    // coverage, like the other abnormal terminals.
    bool is_resource_leak  = false;
    // [Contract oracle §3.1] a non-crash terminal: a call violated its semantic
    // return contract. Dispatches crash_payload to contract_violation/ but, like
    // the other abnormal terminals, must NOT mark the seed interesting-for-coverage.
    bool is_contract_violation = false;
    // [Priority-inversion detector] non-crash terminal: priority-inheritance
    // invariant violated. Dispatches to priority_inversion/, non-interesting-for-cov.
    bool is_priority_inversion = false;
    // [Stack-overflow detector] non-crash terminal: stack high-water near/at depth.
    bool is_stack_overflow = false;
    bool is_malformed      = false;
    bool is_coverage_empty = false;

    // ── 累积量 ────────────────────────────────────────────────
    uint64_t cov_gain = 0;
    // cmp dedupe gain — KCOV_TRACE_CMP record-level newness。与 cov_gain 分开是因为
    // cmp records 与 PC entries 住在不同 truth-store(Q3 决议)。
    uint64_t cmp_gain = 0;

    // ── scheduler 的 disposition 建议 ─────────────────────────
    SeedDisposition disposition = SeedDisposition::kNeutral;

    // ── crash 载荷透传到 EngineOutput / crash pipeline ────────
    std::optional<proto::CombinedCrashEvent> crash_payload;
};

} // namespace refuzz::fuzzer
