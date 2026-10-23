#pragma once

#include <cstdint>

namespace refuzz::proto {

enum class FeedbackKind : uint16_t {
    kNone = 0,
    kCoverageKcov = 1,
    // [v2 Epic 5 PR-5-A] KCOV_TRACE_CMP comparison records.
    // Wire payload for this kind is a packed sequence of 4 × uint64
    // per record (upstream kernel order: type, arg1, arg2, pc).
    // `WorkerFeedbackHeader.entry_count` carries RECORD count
    // (i.e. uint64 count = 4 * entry_count), per Epic 5 plan §3 D-3.
    kCoverageKcovCmp = 2,
};

constexpr uint32_t kWorkerFeedbackMagic = 0x5246425A; // "RFBZ"
constexpr uint16_t kWorkerFeedbackVersion = 1;

struct WorkerFeedbackHeader {
    uint32_t magic = kWorkerFeedbackMagic;
    uint16_t version = kWorkerFeedbackVersion;
    uint16_t kind = static_cast<uint16_t>(FeedbackKind::kNone);
    uint32_t entry_count = 0;
    uint32_t flags = 0;
};

} // namespace refuzz::proto
