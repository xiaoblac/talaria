// Copyright 2026 reFuzz project author -------youngkk.
//
// [v2 Epic 5 PR-5-B — 当前版本]
// 真实路径:
//   1. event.AsCompletion()/AsAbnormal() → output bytes
//   2. CoverageFeedbackCodec.Extract → FeedbackDelta.cmp (vector<CmpRecord>)
//      (codec 已在 PR-5-A 加 kCoverageKcovCmp dispatch + sign-extend + 操作数交换)
//   3. 每条 CmpRecord fnv1a64 → uint64 → cmp store MergeCoverage 去重
//   4. magnitude=gain → aggregator 路由进 score.cmp_gain → dispatcher
//      +1 fuzzer.cov.cmp.new_total

#include "refuzz/feedback/signal/kcov_cmp_signal.hpp"

#include "refuzz/fuzzer/interfaces.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

namespace refuzz::fuzzer {

namespace {

// FNV-1a 64-bit primitives. Mirror of crash/incident `Fnv1a64Fold` shape;
// kept private here to avoid pulling crash/ headers into feedback/.
constexpr uint64_t kFnv1aOffset = 0xcbf29ce484222325ull;
constexpr uint64_t kFnv1aPrime  = 0x100000001b3ull;

uint64_t Fnv1aFoldBytes(uint64_t h, const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= kFnv1aPrime;
    }
    return h;
}

// Hash a CmpRecord into a stable uint64 dedupe key. Includes is_const so a
// (pc, op1, op2, const=true) record is distinguished from the same operands
// without const — matches upstream CompMap.Add tracking semantics.
uint64_t HashCmpRecord(const refuzz::proto::CmpRecord& r) {
    uint64_t h = kFnv1aOffset;
    h = Fnv1aFoldBytes(h, reinterpret_cast<const uint8_t*>(&r.pc),   sizeof(r.pc));
    h = Fnv1aFoldBytes(h, reinterpret_cast<const uint8_t*>(&r.arg1), sizeof(r.arg1));
    h = Fnv1aFoldBytes(h, reinterpret_cast<const uint8_t*>(&r.arg2), sizeof(r.arg2));
    const uint8_t cflag = r.is_const ? 1u : 0u;
    h = Fnv1aFoldBytes(h, &cflag, sizeof(cflag));
    return h;
}

} // namespace

KcovCmpSignal::KcovCmpSignal(IFeedbackStore* store, CoverageNormalizationConfig config)
    : store_(store)
    , codec_(config)
{}

SignalContribution KcovCmpSignal::Sample(const refuzz::core::channel_contract::ChannelEvent& event)
{
    SignalContribution c;
    c.id   = Id();
    c.kind = Kind();

    // 仅数据平面事件携带 output bytes 可解码 (与 KcovCoverageSignal 同形)。
    // from_abnormal:异常终止的 cmp 覆盖同样不进 cmp truth-store(对齐 syz,理由见下)。
    std::vector<uint8_t> payload;
    bool from_abnormal = false;
    if (event.IsCompletion()) {
        const auto* p = event.AsCompletion();
        if (p != nullptr) payload = p->output;
    } else if (event.IsAbnormal()) {
        from_abnormal = true;
        const auto* p = event.AsAbnormal();
        if (p != nullptr) payload = p->output;
    } else {
        // Fault 事件无 output，不参与 cmp 评估
        return c;
    }

    if (payload.empty()) {
        c.decoded.exec_status = proto::ResultCode::kOk;
        c.decoded.flags      |= proto::kFeedbackFlagEmptyCoverage;
        return c;
    }

    const auto status = codec_.Extract(&payload, &c.decoded);
    if (status == ParseFeedbackStatus::kMalformed) {
        c.malformed = true;
        c.decoded.flags |= proto::kFeedbackFlagMalformedCoverage;
        return c;
    }
    if (status == ParseFeedbackStatus::kNoFeedback || c.decoded.cmp.empty()) {
        // 区段不是 kCoverageKcovCmp（典型: PC-only task）或 0 record；
        // KcovCoverageSignal 会消费 PC 区段，本信号保持 fired=false。
        return c;
    }

    // [align syz — 异常执行的 cmp 不进 cmp store] 与 KcovCoverageSignal 同理:syzkaller
    // 对 Hanged/Crashed 不 addRawMaxSignal,异常运行的覆盖(含 cmp)不参与去重基线。
    // 提前返回:fired=false、不 MergeCoverage,异常运行对 cmp 信号完全 inert。
    if (from_abnormal) {
        return c;
    }

    c.fired = true;
    // store_=nullptr 表示 cmp store disabled/test mode:fired=true 但 gain=0,不污染
    // cmp truth-store。
    std::vector<uint64_t> hashes;
    hashes.reserve(c.decoded.cmp.size());
    for (const auto& rec : c.decoded.cmp) {
        hashes.push_back(HashCmpRecord(rec));
    }
    c.hashes = hashes;

    if (store_ == nullptr) {
        c.magnitude   = 0;
        c.interesting = false;
        return c;
    }

    // [v2 batch 3 PR-Y B3] interface 升级带 prio 参数 — KcovCmpSignal 传 neutral
    // prio=0(MakeKcovCmpEntry 不消费 IPriorityCalculator,cmp signal 无 prio 概念)。
    const size_t gain = store_->MergeCoverage(hashes, /*prio=*/0);
    c.magnitude   = static_cast<uint64_t>(gain);
    c.interesting = (gain > 0);
    return c;
}

} // namespace refuzz::fuzzer
