// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/feedback_codec.hpp"

#include <cstring>

namespace refuzz::fuzzer {

CoverageFeedbackCodec::CoverageFeedbackCodec(CoverageNormalizationConfig config)
    : config_(config)
{}

// [v2 Epic 5 PR-5-A] KCOV_CMP record decoder constants — kernel
// `executor.cc:447-452` semantics: KCOV_CMP_CONST = 1 (second operand
// is a compile-time constant); KCOV_CMP_SIZE_MASK = 6 covers 1/2/4/8B.
namespace {
constexpr uint64_t kKcovCmpConst    = 1;
constexpr uint64_t kKcovCmpSizeMask = 6;
constexpr size_t   kKcovCmpUint64sPerRecord = 4;

// [v2 PR-5-A review — current version]
// Match upstream executor.cc::convert: KCOV zero-extends operands to
// uint64 first, then syzkaller sign-extends the observed comparison width.
uint64_t ExtendCmpOperandToU64(uint64_t v, uint64_t size_bits) {
    switch (size_bits) {
    case 0: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(v)));
    case 2: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(v)));
    case 4: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(v)));
    case 6: return v;               // SIZE8
    default: return v;
    }
}

uint64_t ReadCmpWord(const uint8_t* base, size_t word_index) {
    uint64_t value = 0;
    std::memcpy(&value, base + word_index * sizeof(uint64_t), sizeof(value));
    return value;
}
} // namespace

ParseFeedbackStatus CoverageFeedbackCodec::Extract(std::vector<uint8_t>* payload,
                                                   refuzz::proto::FeedbackDelta* feedback)
{
    if (payload == nullptr || feedback == nullptr) {
        return ParseFeedbackStatus::kMalformed;
    }
    const size_t header_size = sizeof(refuzz::proto::WorkerFeedbackHeader);
    if (payload->size() < header_size) {
        return ParseFeedbackStatus::kNoFeedback;
    }

    refuzz::proto::WorkerFeedbackHeader hdr{};
    std::memcpy(&hdr, payload->data() + (payload->size() - header_size), header_size);
    if (hdr.magic != refuzz::proto::kWorkerFeedbackMagic ||
        hdr.version != refuzz::proto::kWorkerFeedbackVersion) {
        return ParseFeedbackStatus::kNoFeedback;
    }

    const auto kind = static_cast<refuzz::proto::FeedbackKind>(hdr.kind);

    // [v2 Epic 5 PR-5-A] Multi-kind dispatch. PC region path unchanged
    // from v1; cmp region path added below. Other kinds → kNoFeedback
    // (caller may peel further regions or treat as empty).
    if (kind == refuzz::proto::FeedbackKind::kCoverageKcov) {
        const size_t cov_bytes = static_cast<size_t>(hdr.entry_count) * sizeof(uint64_t);
        if (payload->size() < header_size + cov_bytes) {
            return ParseFeedbackStatus::kMalformed;
        }

        const size_t cov_begin = payload->size() - header_size - cov_bytes;
        std::vector<uint64_t> raw_entries(hdr.entry_count);
        if (cov_bytes > 0) {
            std::memcpy(raw_entries.data(), payload->data() + cov_begin, cov_bytes);
        }

        feedback->flags = static_cast<uint16_t>(hdr.flags);
        feedback->cov_hashes = NormalizeCoverageEntries(std::move(raw_entries), config_);
        if (!feedback->cov_hashes.empty()) {
            feedback->flags |= refuzz::proto::kFeedbackFlagHasCoverage;
        } else {
            feedback->flags |= refuzz::proto::kFeedbackFlagEmptyCoverage;
        }

        payload->resize(cov_begin);
        return ParseFeedbackStatus::kOk;
    }

    // [v2 Epic 5 PR-5-A] kCoverageKcovCmp region.
    //
    // Wire layout: `entry_count` records, each = 4 × uint64
    // (type, arg1, arg2, pc). Apply upstream stateless conversion from
    // `executor.cc:1828-1874` so host CompMap.Add sees the ComparisonRaw
    // operand order that upstream `makeCompMap` consumes.
    if (kind == refuzz::proto::FeedbackKind::kCoverageKcovCmp) {
        const size_t cmp_bytes =
            static_cast<size_t>(hdr.entry_count) * kKcovCmpUint64sPerRecord * sizeof(uint64_t);
        if (payload->size() < header_size + cmp_bytes) {
            return ParseFeedbackStatus::kMalformed;
        }

        const size_t cmp_begin = payload->size() - header_size - cmp_bytes;
        feedback->flags = static_cast<uint16_t>(hdr.flags);
        feedback->cmp.clear();
        feedback->cmp.reserve(hdr.entry_count);

        const uint8_t* raw = payload->data() + cmp_begin;
        for (uint32_t i = 0; i < hdr.entry_count; ++i) {
            const size_t base = static_cast<size_t>(i) * kKcovCmpUint64sPerRecord;
            const uint64_t type = ReadCmpWord(raw, base + 0);
            uint64_t       arg1 = ReadCmpWord(raw, base + 1);
            uint64_t       arg2 = ReadCmpWord(raw, base + 2);
            const uint64_t pc   = ReadCmpWord(raw, base + 3);

            // Drop malformed records (type out of range).
            if (type > (kKcovCmpConst | kKcovCmpSizeMask)) {
                continue;
            }
            const bool is_const = (type & kKcovCmpConst) != 0;
            const uint64_t size_bits = type & kKcovCmpSizeMask;

            // Drop noise records (executor.cc:1835 rule).
            if (arg1 == 0 && (arg2 == 0 || is_const)) {
                continue;
            }
            // Successful comparisons are not useful hints (executor.cc:1837).
            if (arg1 == arg2) {
                continue;
            }

            // [v2 PR-5-A review — current version]
            // Prog/hints expects operand 1 to be the value that may have come
            // from input, which is kernel arg2 after upstream conversion.
            const uint64_t op1 = ExtendCmpOperandToU64(arg2, size_bits);
            const uint64_t op2 = ExtendCmpOperandToU64(arg1, size_bits);

            refuzz::proto::CmpRecord rec;
            rec.pc       = pc;
            rec.arg1     = op1;
            rec.arg2     = op2;
            rec.is_const = is_const;
            feedback->cmp.push_back(rec);
        }

        if (!feedback->cmp.empty()) {
            feedback->flags |= refuzz::proto::kFeedbackFlagHasCoverage;
        } else {
            feedback->flags |= refuzz::proto::kFeedbackFlagEmptyCoverage;
        }

        payload->resize(cmp_begin);
        return ParseFeedbackStatus::kOk;
    }

    return ParseFeedbackStatus::kNoFeedback;
}

} // namespace refuzz::fuzzer
