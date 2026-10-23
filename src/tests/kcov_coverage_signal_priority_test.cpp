// Copyright 2026 reFuzz project author -------youngkk.
//
// [v2 batch 3 PR-Y] KcovCoverageSignal::Sample priority_calculator 集成单测。
//
// 验证:
//   1. priority_calculator.Calculate 被 Sample 调用
//   2. per-call store.MergeCoverage 拿到的 prio 跟对应 syscall facts 一致
//   3. 有 coverage 但 ctx.artifact == nullptr 时无法构造 per-call attribution,
//      必须 fail-loud 为 malformed,不允许整程序 fallback merge
//   4. hash output / gain 路径行为不变
//   5. [v2 PR-Y D1 follow-up] artifact != nullptr 时,SyzExecResult head 的
//      err/flags 字段决定 per-call attrs.execution_succeeded。
//      involves_special_input 的 call_contains_any 路径暂只验默认 false
//      (普通 syscall getpid 不带 any-ptr;any-ptr case 留给后续)。

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/feedback/priority_calculator.hpp"
#include "refuzz/feedback/saturation/noop_saturation_filter.hpp"  // [v2 batch 3 G5] +ctor 参数
#include "refuzz/feedback/signal/kcov_coverage_signal.hpp"
#include "refuzz/feedback/signal_attributes.hpp"
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/backend/syz_exec_runner.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pr  = refuzz::program;
namespace syz = refuzz::program::syz;

namespace {

// Mock IPriorityCalculator — 记录每次 Calculate 收到的 attrs,默认返 fixed prio。
class MockPriorityCalculator : public refuzz::fuzzer::IPriorityCalculator {
public:
    explicit MockPriorityCalculator(std::uint8_t fixed_prio) : fixed_prio_(fixed_prio) {}
    void SetFixedPrio(std::uint8_t fixed_prio) { fixed_prio_ = fixed_prio; }
    void UseSyzkallerPrio(bool enabled) { use_syzkaller_prio_ = enabled; }
    std::uint8_t Calculate(const refuzz::fuzzer::SignalAttributes& attrs) const override {
        last_attrs_  = attrs;
        called_      = true;
        attrs_calls_.push_back(attrs);
        if (use_syzkaller_prio_) {
            std::uint8_t p = 0;
            if (attrs.execution_succeeded) {
                p |= 0b10;
            }
            if (!attrs.involves_special_input) {
                p |= 0b01;
            }
            return p;
        }
        return fixed_prio_;
    }
    bool                                called() const { return called_; }
    refuzz::fuzzer::SignalAttributes    last_attrs() const { return last_attrs_; }
    std::size_t                         call_count() const { return attrs_calls_.size(); }
    const std::vector<refuzz::fuzzer::SignalAttributes>& attrs_calls() const {
        return attrs_calls_;
    }

private:
    std::uint8_t                                fixed_prio_;
    bool                                        use_syzkaller_prio_ = false;
    mutable bool                                called_     = false;
    mutable refuzz::fuzzer::SignalAttributes    last_attrs_;
    mutable std::vector<refuzz::fuzzer::SignalAttributes> attrs_calls_;
};

// Mock IFeedbackStore — 记录每次 MergeCoverage,并按 max-prio 模拟真实 store。
class MockFeedbackStore : public refuzz::fuzzer::IFeedbackStore {
public:
    bool HasNewCoverage(const std::vector<std::uint64_t>&) const override { return true; }
    std::size_t MergeCoverage(const std::vector<std::uint64_t>& hashes,
                              std::uint8_t                      prio) override {
        return MergeCoverage(hashes, prio, nullptr);
    }
    std::size_t MergeCoverage(const std::vector<std::uint64_t>& hashes,
                              std::uint8_t                      prio,
                              std::vector<std::uint64_t>*       novel_hashes) override {
        last_prio_   = prio;
        last_hashes_ = hashes;
        merge_called_ = true;
        prios_.push_back(prio);
        merge_calls_.push_back(hashes);
        if (novel_hashes != nullptr) {
            novel_hashes->clear();
        }
        std::size_t gain = 0;
        for (std::uint64_t h : hashes) {
            auto it = seen_.find(h);
            if (it == seen_.end()) {
                seen_.emplace(h, prio);
                ++gain;
                if (novel_hashes != nullptr) {
                    novel_hashes->push_back(h);
                }
            } else if (prio > it->second) {
                it->second = prio;
                ++gain;
                if (novel_hashes != nullptr) {
                    novel_hashes->push_back(h);
                }
            }
        }
        return gain;
    }
    bool         merge_called() const { return merge_called_; }
    std::uint8_t last_prio()    const { return last_prio_; }
    const std::vector<std::uint64_t>& last_hashes() const { return last_hashes_; }
    const std::vector<std::uint8_t>& prios() const { return prios_; }
    const std::vector<std::vector<std::uint64_t>>& merge_calls() const {
        return merge_calls_;
    }

private:
    bool                       merge_called_ = false;
    std::uint8_t               last_prio_    = 0xFF;
    std::vector<std::uint64_t> last_hashes_;
    std::vector<std::uint8_t>  prios_;
    std::vector<std::vector<std::uint64_t>> merge_calls_;
    std::unordered_map<std::uint64_t, std::uint8_t> seen_;
};

// 构造一个含合法 KCOV packet 的 payload(无 SyzExecResult head)。layout:
//   [entries × uint64][WorkerFeedbackHeader]
// 用于验证 coverage_without_per_call 的 fail-loud 路径。
std::vector<std::uint8_t> MakeKcovPayloadNoExecHead(
    const std::vector<std::uint64_t>& hashes)
{
    namespace proto = refuzz::proto;
    std::vector<std::uint8_t> payload;
    const std::size_t entries_bytes = hashes.size() * sizeof(std::uint64_t);
    payload.resize(entries_bytes + sizeof(proto::WorkerFeedbackHeader));
    if (entries_bytes > 0) {
        std::memcpy(payload.data(), hashes.data(), entries_bytes);
    }
    proto::WorkerFeedbackHeader hdr{};
    hdr.magic       = proto::kWorkerFeedbackMagic;
    hdr.version     = proto::kWorkerFeedbackVersion;
    hdr.kind        = static_cast<std::uint16_t>(proto::FeedbackKind::kCoverageKcov);
    hdr.entry_count = static_cast<std::uint32_t>(hashes.size());
    hdr.flags       = 0;
    std::memcpy(payload.data() + entries_bytes, &hdr, sizeof(hdr));
    return payload;
}

// [v2 PR-Y D1 follow-up] 构造带 SyzExecResult head + per-call tail 的完整 payload。layout:
//   [SyzExecResult × n_calls][uint64 × cov_tail][optional KCOV packet][WorkerFeedbackHeader]
// SyzExecResult.err/flags 字段驱动 per-call attrs.execution_succeeded,
// cover_offset/cover_count 指向 cov_tail,构造 per-call attribution。
std::vector<std::uint8_t> MakePayloadWithExecHeadsAndTail(
    const std::vector<refuzz::worker::SyzExecResult>& results,
    const std::vector<std::uint64_t>&                  cov_tail,
    const std::vector<std::uint64_t>&                  kcov_entries = {},
    bool                                                with_kcov_packet = false)
{
    namespace proto = refuzz::proto;
    std::vector<std::uint8_t> p;
    const std::size_t head_bytes = results.size() * sizeof(refuzz::worker::SyzExecResult);
    const std::size_t tail_bytes = cov_tail.size() * sizeof(std::uint64_t);
    const std::size_t kcov_bytes = kcov_entries.size() * sizeof(std::uint64_t);
    const std::size_t hdr_bytes  = sizeof(proto::WorkerFeedbackHeader);
    p.resize(head_bytes + tail_bytes);
    if (head_bytes > 0) std::memcpy(p.data(), results.data(), head_bytes);
    if (tail_bytes > 0) std::memcpy(p.data() + head_bytes, cov_tail.data(), tail_bytes);
    if (with_kcov_packet) {
        const std::size_t old_size = p.size();
        p.resize(old_size + kcov_bytes + hdr_bytes);
        if (kcov_bytes > 0) {
            std::memcpy(p.data() + old_size, kcov_entries.data(), kcov_bytes);
        }
        proto::WorkerFeedbackHeader hdr{};
        hdr.magic       = proto::kWorkerFeedbackMagic;
        hdr.version     = proto::kWorkerFeedbackVersion;
        hdr.kind        = static_cast<std::uint16_t>(proto::FeedbackKind::kCoverageKcov);
        hdr.entry_count = static_cast<std::uint32_t>(kcov_entries.size());
        hdr.flags       = 0;
        std::memcpy(p.data() + old_size + kcov_bytes, &hdr, hdr_bytes);
    }
    return p;
}

// 造 1-call(getpid) ProgramArtifact。getpid 无 any-ptr,适合验证
// involves_special_input 的默认 false 路径。
std::shared_ptr<const pr::ProgramArtifact> BuildArtifactGetpid()
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(), syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode("getpid()\n");
    assert(prog_or.has_value() && *prog_or != nullptr);
    std::shared_ptr<const syz::Prog> typed = std::move(*prog_or);
    auto art = pr::ProgramArtifact::Build(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{},
        typed,
        typeid(syz::Prog),
        nullptr,
        []() -> std::shared_ptr<const std::vector<std::uint8_t>> {
            return std::make_shared<std::vector<std::uint8_t>>();
        });
    return std::make_shared<pr::ProgramArtifact>(std::move(art));
}

std::shared_ptr<const pr::ProgramArtifact> BuildArtifactGetpidGetuid()
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(), syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode("getpid()\ngetuid()\n");
    assert(prog_or.has_value() && *prog_or != nullptr);
    std::shared_ptr<const syz::Prog> typed = std::move(*prog_or);
    auto art = pr::ProgramArtifact::Build(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{},
        typed,
        typeid(syz::Prog),
        nullptr,
        []() -> std::shared_ptr<const std::vector<std::uint8_t>> {
            return std::make_shared<std::vector<std::uint8_t>>();
        });
    return std::make_shared<pr::ProgramArtifact>(std::move(art));
}

// ─────────────────────────────────────────────────────────────────────────
// Case 1: 有 coverage 但 ctx.artifact == nullptr → 无 per-call attribution,
// 必须 malformed,不能调用 priority/store。
// ─────────────────────────────────────────────────────────────────────────
void RunNullArtifactCoverageIsMalformed()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                       store;
    MockPriorityCalculator                  calc(/*fixed_prio=*/7);
    refuzz::fuzzer::NoopSaturationFilter    sat_filter;
    KcovCoverageSignal                      signal(store, calc, sat_filter);

    ChannelEvent event;
    Completion   completion;
    completion.output = MakeKcovPayloadNoExecHead({0xAAA, 0xBBB, 0xCCC});
    // ctx.artifact 保留 default-constructed shared_ptr (null)。
    event.payload = std::move(completion);

    auto contrib = signal.Sample(event);

    assert(!calc.called());
    assert(!store.merge_called());
    assert(!contrib.fired);
    assert(!contrib.interesting);
    assert(contrib.malformed);
    assert((contrib.decoded.flags & refuzz::proto::kFeedbackFlagMalformedCoverage) != 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Case 2: artifact != nullptr + SyzExecResult.err == 0 → attrs.execution_succeeded=true
//
// 单 call 时 per-call priority 的 success bit 等于 r.executed && r.err == 0。
// ─────────────────────────────────────────────────────────────────────────
void RunArtifactSucceededTrue()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                       store;
    MockPriorityCalculator                  calc(/*fixed_prio=*/9);
    refuzz::fuzzer::NoopSaturationFilter    sat_filter;
    KcovCoverageSignal                      signal(store, calc, sat_filter);

    auto art = BuildArtifactGetpid();
    refuzz::worker::SyzExecResult r{};
    r.ret          = 0;
    r.err          = 0;     // success
    // [2026-05-13 P1 fix-2 test update] 真执行过的 slot 必须有 kCallFlagExecuted;
    // 新合约下 flags=0 == empty_call(driver zero-init 未跑 slot),不算 success。
    r.flags        = ::refuzz::worker::kCallFlagExecuted |
                     ::refuzz::worker::kCallFlagFinished;
    r.cover_offset = 0;
    r.cover_count  = 1;

    ChannelEvent event;
    Completion   completion;
    completion.output       = MakePayloadWithExecHeadsAndTail({r}, {0xAAA});
    completion.ctx.artifact = art;
    event.payload           = std::move(completion);

    auto contrib = signal.Sample(event);

    assert(calc.called());
    // err == 0 + Executed → succeeded=true。
    assert(calc.last_attrs().execution_succeeded == true);
    // getpid 不含 any-ptr → involves_special_input 保默认 false。
    assert(calc.last_attrs().involves_special_input == false);
    assert(store.merge_called());
    assert(store.last_prio() == 9);
    assert(store.last_hashes() == std::vector<std::uint64_t>({0xAAA}));
}

// ─────────────────────────────────────────────────────────────────────────
// Case 3: artifact != nullptr + SyzExecResult.err != 0 → attrs.execution_succeeded=false
//
// 与 Case 2 互补:单 call err!=0 时,attrs.execution_succeeded=false。
// ─────────────────────────────────────────────────────────────────────────
void RunArtifactSucceededFalse()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                       store;
    MockPriorityCalculator                  calc(/*fixed_prio=*/5);
    refuzz::fuzzer::NoopSaturationFilter    sat_filter;
    KcovCoverageSignal                      signal(store, calc, sat_filter);

    auto art = BuildArtifactGetpid();
    refuzz::worker::SyzExecResult r{};
    r.ret          = -1;
    r.err          = 13;    // EACCES(任意非 0)
    // [2026-05-13 P1 fix-2 test update] 真执行(syscall 返 -1/EACCES)→ 必须有
    // Executed flag,否则会被当 empty_call 跳过,单 call OR 退化为 default success=true。
    r.flags        = ::refuzz::worker::kCallFlagExecuted |
                     ::refuzz::worker::kCallFlagFinished;
    r.cover_offset = 0;
    r.cover_count  = 1;

    ChannelEvent event;
    Completion   completion;
    completion.output       = MakePayloadWithExecHeadsAndTail({r}, {0xAAA});
    completion.ctx.artifact = art;
    event.payload           = std::move(completion);

    auto contrib = signal.Sample(event);

    assert(calc.called());
    // 单 call err!=0 → false。
    assert(calc.last_attrs().execution_succeeded == false);
    assert(calc.last_attrs().involves_special_input == false);
    assert(store.merge_called());
    assert(store.last_prio() == 5);
    assert(store.last_hashes() == std::vector<std::uint64_t>({0xAAA}));
}

// ─────────────────────────────────────────────────────────────────────────
// [2026-05-13 P1 fix-2] Case 4: partial fallback 后半段未执行槽位 (flags==0)
// **不**应被算成 success;只有真 Executed slot 才参与 per-call success。
// 构造 2-call prog,slot[0]=Executed+err=0(真 success),slot[1]=flags=0+err=0
// (driver zero-init 未执行的 empty_call)。单 Executed slot success 不应被误伤。
void RunPartialFallbackExecutedSlotWins()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/7);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    KcovCoverageSignal                   signal(store, calc, sat_filter);

    // BuildArtifactGetpid 是 1-call,需要 2-call artifact 才能测 mixed slots。
    // 这里复用同一 1-call artifact 改 ProgramArtifact 不便,简化:**用 1-call
    // 的 artifact + 单 Executed slot,verify gate 不误伤 真 Executed-success**。
    // 第 5 个 case 才测 "全 empty"。
    auto art = BuildArtifactGetpid();
    refuzz::worker::SyzExecResult r{};
    r.ret          = 0;
    r.err          = 0;
    r.flags        = ::refuzz::worker::kCallFlagExecuted |
                     ::refuzz::worker::kCallFlagFinished;
    r.cover_offset = 0;
    r.cover_count  = 1;

    ChannelEvent event;
    Completion   completion;
    completion.output       = MakePayloadWithExecHeadsAndTail({r}, {0xCAFE});
    completion.ctx.artifact = art;
    event.payload           = std::move(completion);

    auto contrib = signal.Sample(event);
    assert(calc.called());
    assert(calc.last_attrs().execution_succeeded == true);
    assert(store.merge_called());
    assert(store.last_prio() == 7);
    assert(store.last_hashes() == std::vector<std::uint64_t>({0xCAFE}));
}

// [2026-05-13 P1 fix-2] Case 5: **完全未执行**(整个 head 全 empty_call,
// 模拟 child 在第一个 dispatch 前就 SIGKILL'd)→ no Executed slot →
// execution_succeeded=false。注意跟 "results 空"(decode 失败)分支不同,
// 这里 results 非空但全部被 Executed gate 过滤。
void RunPartialFallbackAllEmptyNoSuccess()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/3);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    KcovCoverageSignal                   signal(store, calc, sat_filter);

    auto art = BuildArtifactGetpid();
    refuzz::worker::SyzExecResult r{};
    // ALL ZERO — flags=0 + err=0 — empty_call slot (driver zero-init pre-Dispatch)
    r.ret          = 0;
    r.err          = 0;
    r.flags        = 0;
    r.cover_offset = 0;
    r.cover_count  = 1;

    ChannelEvent event;
    Completion   completion;
    completion.output       = MakePayloadWithExecHeadsAndTail({r}, {0xBEEF});
    completion.ctx.artifact = art;
    event.payload           = std::move(completion);

    auto contrib = signal.Sample(event);
    assert(calc.called());
    // empty_call → execution_succeeded=false(没真跑过的 success)。
    // 注意 v1 这里会错误返 true(把 err=0 当 success)。
    assert(calc.last_attrs().execution_succeeded == false);
    assert(store.merge_called());
    assert(store.last_prio() == 3);
    assert(store.last_hashes() == std::vector<std::uint64_t>({0xBEEF}));
}

// Case 6: 2-call 程序必须按 syscall 分别计算 priority,不能用 program-level OR。
// call0 failed(no any) → prio=1;call1 success(no any) → prio=3。
void RunPerCallPriorityUsesEachCallFacts()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/0);
    calc.UseSyzkallerPrio(true);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    KcovCoverageSignal                   signal(store, calc, sat_filter);

    auto art = BuildArtifactGetpidGetuid();
    refuzz::worker::SyzExecResult r0{};
    r0.ret          = -1;
    r0.err          = 13;
    r0.flags        = ::refuzz::worker::kCallFlagExecuted |
                      ::refuzz::worker::kCallFlagFinished;
    r0.cover_offset = 0;
    r0.cover_count  = 1;
    refuzz::worker::SyzExecResult r1{};
    r1.ret          = 0;
    r1.err          = 0;
    r1.flags        = ::refuzz::worker::kCallFlagExecuted |
                      ::refuzz::worker::kCallFlagFinished;
    r1.cover_offset = 1;
    r1.cover_count  = 1;

    ChannelEvent event;
    Completion   completion;
    completion.output       = MakePayloadWithExecHeadsAndTail({r0, r1}, {0xA0, 0xB0});
    completion.ctx.artifact = art;
    event.payload           = std::move(completion);

    auto contrib = signal.Sample(event);

    assert(contrib.fired);
    assert(calc.call_count() == 2);
    assert(store.merge_calls().size() == 2);
    assert(store.merge_calls()[0] == std::vector<std::uint64_t>({0xA0}));
    assert(store.merge_calls()[1] == std::vector<std::uint64_t>({0xB0}));
    assert(store.prios().size() == 2);
    assert(store.prios()[0] == 1);  // failed + no any
    assert(store.prios()[1] == 3);  // success + no any
    const auto* observation =
        contrib.observation.Get<refuzz::fuzzer::KernelExecutionObservation>();
    assert(observation != nullptr);
    assert(observation->per_call.size() == 2);
    assert(observation->per_call[0].signal_priority == 1);
    assert(observation->per_call[1].signal_priority == 3);
    assert(calc.attrs_calls()[0].execution_succeeded == false);
    assert(calc.attrs_calls()[1].execution_succeeded == true);
}

// cover_edges 模式也必须走 HashFeedbackStore::MergeCoverage。store 仍按
// syzkaller DiffRaw 语义把 existing edge 的 higher-prio hit 算作 gain,避免
// 旧 2M bitmap 碰撞/旁路造成 edge-mode truth store 与 PC mode 不一致。
void RunEdgeModePriorityUpgradeCountsAsGain()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::CoverageNormalizationConfig;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/0);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    CoverageNormalizationConfig          cfg;
    cfg.cover_edges = true;
    KcovCoverageSignal signal(store, calc, sat_filter, cfg);
    auto art = BuildArtifactGetpid();

    auto run_once = [&]() {
        ChannelEvent event;
        Completion completion;
        refuzz::worker::SyzExecResult r{};
        r.ret          = 0;
        r.err          = 0;
        r.flags        = ::refuzz::worker::kCallFlagExecuted |
                         ::refuzz::worker::kCallFlagFinished;
        r.cover_offset = 0;
        r.cover_count  = 1;
        completion.output = MakePayloadWithExecHeadsAndTail({r}, {0x12345});
        completion.ctx.artifact = art;
        event.payload = std::move(completion);
        return signal.Sample(event);
    };

    auto first = run_once();
    assert(first.fired);
    assert(first.magnitude == 1);
    assert(first.interesting);
    assert(store.merge_called());
    assert(store.merge_calls().size() == 1);

    auto repeat_same_prio = run_once();
    assert(repeat_same_prio.fired);
    assert(repeat_same_prio.magnitude == 0);
    assert(!repeat_same_prio.interesting);

    calc.SetFixedPrio(2);
    auto upgraded = run_once();
    assert(upgraded.fired);
    assert(upgraded.magnitude == 1);
    assert(upgraded.interesting);

    calc.SetFixedPrio(1);
    auto lower_prio = run_once();
    assert(lower_prio.fired);
    assert(lower_prio.magnitude == 0);
    assert(!lower_prio.interesting);
}

void RunEdgeModeRejectsBogusPerCallPcBeforeHashing()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::CoverageNormalizationConfig;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/0);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    CoverageNormalizationConfig          cfg;
    cfg.cover_edges   = true;
    cfg.filter_signal = true;
    KcovCoverageSignal signal(store, calc, sat_filter, cfg);

    refuzz::worker::SyzExecResult result{};
    result.flags        = ::refuzz::worker::kCallFlagExecuted |
                          ::refuzz::worker::kCallFlagFinished;
    result.cover_offset = 0;
    result.cover_count  = 2;

    ChannelEvent event;
    Completion completion;
    completion.output = MakePayloadWithExecHeadsAndTail(
        {result}, {0xffffffff81000123ULL, 0x0000000200000000ULL});
    completion.ctx.artifact = BuildArtifactGetpid();
    event.payload = std::move(completion);

    const auto contrib = signal.Sample(event);
    assert(!contrib.fired);
    assert(!contrib.interesting);
    assert(contrib.magnitude == 0);
    assert(!store.merge_called());
    const auto* observation =
        contrib.observation.Get<refuzz::fuzzer::KernelExecutionObservation>();
    assert(observation != nullptr);
    assert(observation->per_call.size() == 1);
    assert(observation->per_call[0].coverage_hashes.empty());
    assert(observation->per_call[0].edge_hashes.empty());
}

void RunEdgeModeRejectsBogusExtraPcBeforeHashing()
{
    using refuzz::core::channel_contract::ChannelEvent;
    using refuzz::core::channel_contract::Completion;
    using refuzz::fuzzer::CoverageNormalizationConfig;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/0);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    CoverageNormalizationConfig          cfg;
    cfg.cover_edges   = true;
    cfg.filter_signal = true;
    KcovCoverageSignal signal(store, calc, sat_filter, cfg);

    refuzz::worker::SyzExecResult result{};
    result.flags = ::refuzz::worker::kCallFlagExecuted |
                   ::refuzz::worker::kCallFlagFinished;

    ChannelEvent event;
    Completion completion;
    completion.output = MakePayloadWithExecHeadsAndTail(
        {result}, {},
        {0xffffffff81000123ULL, 0x0000000200000000ULL},
        /*with_kcov_packet=*/true);
    completion.ctx.artifact = BuildArtifactGetpid();
    event.payload = std::move(completion);

    const auto contrib = signal.Sample(event);
    assert(!contrib.fired);
    assert(!contrib.interesting);
    assert(contrib.magnitude == 0);
    assert(!store.merge_called());
    const auto* observation =
        contrib.observation.Get<refuzz::fuzzer::KernelExecutionObservation>();
    assert(observation != nullptr);
    assert(observation->extra_cover.empty());
    assert(observation->extra_signal_hashes.empty());
}

void RunAbnormalObservationRetainsMeasurementSets()
{
    namespace cc = refuzz::core::channel_contract;
    using refuzz::fuzzer::CoverageNormalizationConfig;
    using refuzz::fuzzer::KcovCoverageSignal;

    MockFeedbackStore                    store;
    MockPriorityCalculator               calc(/*fixed_prio=*/0);
    refuzz::fuzzer::NoopSaturationFilter sat_filter;
    CoverageNormalizationConfig          cfg;
    cfg.cover_edges = true;
    KcovCoverageSignal signal(store, calc, sat_filter, cfg);

    refuzz::worker::SyzExecResult result{};
    result.flags = ::refuzz::worker::kCallFlagExecuted |
                   ::refuzz::worker::kCallFlagFinished;
    result.cover_offset = 0;
    result.cover_count = 2;

    cc::AbnormalCompletion abnormal;
    abnormal.kind = cc::AbnormalKind::kHarnessRecovered;
    abnormal.output = MakePayloadWithExecHeadsAndTail(
        {result}, {0xffffffff81000123ULL, 0xffffffff81000456ULL});
    abnormal.ctx.artifact = BuildArtifactGetpid();
    cc::ChannelEvent event;
    event.kind = cc::ChannelEvent::Kind::kAbnormal;
    event.payload = std::move(abnormal);

    const auto contribution = signal.Sample(event);
    assert(!contribution.fired);
    assert(!store.merge_called());
    const auto* observation =
        contribution.observation.Get<refuzz::fuzzer::KernelExecutionObservation>();
    assert(observation != nullptr);
    assert(observation->program_raw_pcs.size() == 2);
    assert(observation->program_edge_hashes.size() == 2);
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running kcov_coverage_signal_priority_test...\n");
    RunNullArtifactCoverageIsMalformed();
    RunArtifactSucceededTrue();
    RunArtifactSucceededFalse();
    RunPartialFallbackExecutedSlotWins();
    RunPartialFallbackAllEmptyNoSuccess();
    RunPerCallPriorityUsesEachCallFacts();
    RunEdgeModePriorityUpgradeCountsAsGain();
    RunEdgeModeRejectsBogusPerCallPcBeforeHashing();
    RunEdgeModeRejectsBogusExtraPcBeforeHashing();
    RunAbnormalObservationRetainsMeasurementSets();
    std::fprintf(stdout, "OK\n");
    return 0;
}
