// Copyright 2026 reFuzz project author -------youngkk.

#pragma once

#include "refuzz/feedback/coverage_semantics.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::fuzzer {

enum class ParseFeedbackStatus : uint8_t {
    kNoFeedback = 0,
    kOk = 1,
    kMalformed = 2,
};

struct CoverageNormalizationConfig {
    bool raw_pc = true;
    uint32_t max_entries_per_exec = 0;
    double sample_rate = 1.0;
    // [P2 edge-signal admission] When true, the corpus-admission novelty unit is
    // the EDGE (consecutive-PC transition), mirroring syzkaller use_cover_edges
    // (executor.cc write_signal: sig = pc ^ (hash(prev)&0xfff)). The per-call
    // observation + corpus_pc reporting stay RAW PC; only the admission union fed
    // to feedback_store.MergeCoverage becomes edges. Edge novelty is a superset of
    // raw-PC novelty, so a program that traverses a new transition between two
    // already-seen blocks is admitted (raw-PC novelty would reject it). Default
    // false preserves legacy raw-PC admission for non-kernel engines.
    bool cover_edges = false;
    // [syz-parity convertCallInfo] Kernel-address sanity filter. Mirrors syzkaller
    // pkg/rpcserver/runner.go convertCallInfo (:494-511): a coverage slice that
    // contains any PC outside [kernel_text_start, kernel_text_end] is dropped WHOLE
    // — a bogus PC means corrupted VM memory or fuzzer-injected coverage, and such a
    // program must not enter the corpus. Applied on raw PCs BEFORE hashing, so it
    // works in both raw-PC and hash mode. Default off; range defaults = syz
    // linux/amd64 KernelAddresses (sys/targets/targets.go: 0xffffffff80000000 ..
    // 0xffffffffff000000) — a coarse "is this a kernel virtual address" window,
    // not a tight .text bound. Other arches should override the range.
    bool     filter_signal     = false;
    uint64_t kernel_text_start = 0xffffffff80000000ULL;
    uint64_t kernel_text_end   = 0xffffffffff000000ULL;
};

class IFeedbackCodec {
public:
    virtual ~IFeedbackCodec() = default;
    virtual ParseFeedbackStatus Extract(std::vector<uint8_t>* payload,
                                        refuzz::proto::FeedbackDelta* feedback) = 0;
};

class CoverageFeedbackCodec final : public IFeedbackCodec {
public:
    explicit CoverageFeedbackCodec(CoverageNormalizationConfig config = {});

    ParseFeedbackStatus Extract(std::vector<uint8_t>* payload,
                                refuzz::proto::FeedbackDelta* feedback) override;

    // [v2 batch 3 G5] 暴露内部 normalization config 给 KcovCoverageSignal,
    // 让 host-side per-call slice 走同一 NormalizeCoverageEntries(config),
    // 跟 codec 输出的 c.decoded.cov_hashes 同 normalization(避免 raw PC
    // 混进 store / saturation filter)。详 plan §3.G5 修正 #1。
    const CoverageNormalizationConfig& config() const { return config_; }

private:
    CoverageNormalizationConfig config_{};
};

class NullFeedbackCodec final : public IFeedbackCodec {
public:
    ParseFeedbackStatus Extract(std::vector<uint8_t>* /*payload*/,
                                refuzz::proto::FeedbackDelta* /*feedback*/) override
    {
        return ParseFeedbackStatus::kNoFeedback;
    }
};

} // namespace refuzz::fuzzer
