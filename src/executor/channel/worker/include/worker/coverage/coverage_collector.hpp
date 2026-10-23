#pragma once

#include "refuzz/proto_wire/feedback_wire.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

namespace refuzz::worker {

enum class CoverageMode : uint8_t {
    kNone = 0,
    kKcov,
};

enum class FeedbackAppendStatus : uint8_t {
    kSkippedNoCoverage = 0,
    kOk = 1,
    kNoSpace = 2,
};

class ICoverageCollector {
public:
    virtual ~ICoverageCollector() = default;
    virtual bool Init() = 0;
    virtual bool Enabled() const = 0;
    virtual refuzz::proto::FeedbackKind Kind() const = 0;
    virtual void Begin() = 0;
    virtual void End(std::vector<uint64_t>* out_entries) = 0;
    virtual uint32_t SnapshotFeedback(uint8_t* out, uint32_t out_cap) const = 0;

    // 返回 collector 在 child 进程里 mmap/拥有的缓冲区字节数。
    // 用于 ApplySandbox 计算 RLIMIT_AS——必须覆盖所有发生在 Init() 之后、
    // sandbox apply 之前已经生效的 mmap；kNone 返 0。
    virtual size_t BufferBytes() const = 0;
};

inline FeedbackAppendStatus AppendCoverageFeedback(uint8_t* out,
                                                   uint32_t out_cap,
                                                   uint32_t* inout_len,
                                                   refuzz::proto::FeedbackKind kind,
                                                   const std::vector<uint64_t>& cov_entries)
{
    if (out == nullptr || inout_len == nullptr || cov_entries.empty() ||
        kind == refuzz::proto::FeedbackKind::kNone) {
        return FeedbackAppendStatus::kSkippedNoCoverage;
    }

    const size_t cov_bytes = cov_entries.size() * sizeof(uint64_t);
    const size_t fb_size = sizeof(refuzz::proto::WorkerFeedbackHeader) + cov_bytes;
    if (static_cast<size_t>(*inout_len) + fb_size > out_cap) {
        return FeedbackAppendStatus::kNoSpace;
    }

    uint8_t* cov_dst = out + *inout_len;
    std::memcpy(cov_dst, cov_entries.data(), cov_bytes);

    refuzz::proto::WorkerFeedbackHeader header;
    header.kind = static_cast<uint16_t>(kind);
    header.entry_count = static_cast<uint32_t>(cov_entries.size());
    std::memcpy(cov_dst + cov_bytes, &header, sizeof(header));

    *inout_len += static_cast<uint32_t>(fb_size);
    return FeedbackAppendStatus::kOk;
}

inline FeedbackAppendStatus AppendCoverageFeedbackRaw(uint8_t* out,
                                                      uint32_t out_cap,
                                                      uint32_t* inout_len,
                                                      refuzz::proto::FeedbackKind kind,
                                                      const uint64_t* cov_entries,
                                                      uint32_t cov_count)
{
    if (out == nullptr || inout_len == nullptr || cov_entries == nullptr || cov_count == 0 ||
        kind == refuzz::proto::FeedbackKind::kNone) {
        return FeedbackAppendStatus::kSkippedNoCoverage;
    }

    const size_t cov_bytes = static_cast<size_t>(cov_count) * sizeof(uint64_t);
    const size_t fb_size = sizeof(refuzz::proto::WorkerFeedbackHeader) + cov_bytes;
    if (static_cast<size_t>(*inout_len) + fb_size > out_cap) {
        return FeedbackAppendStatus::kNoSpace;
    }

    uint8_t* cov_dst = out + *inout_len;
    std::memcpy(cov_dst, cov_entries, cov_bytes);

    refuzz::proto::WorkerFeedbackHeader header;
    header.kind = static_cast<uint16_t>(kind);
    header.entry_count = cov_count;
    std::memcpy(cov_dst + cov_bytes, &header, sizeof(header));

    *inout_len += static_cast<uint32_t>(fb_size);
    return FeedbackAppendStatus::kOk;
}

// [v2 Epic 5 PR-5-B fix #1] FilterCmpRecordsByOutputBuffer — worker-local
// pre-append filter. Mirrors upstream executor.cc:1841-1849 — drops cmp
// records whose arg1 OR arg2 lands within the worker's output region.
// Without this, the fuzzer can discover the output buffer's VA via
// hint-derived mutations and corrupt it.
//
// `in_records` is a packed flat sequence of 4 × uint64 per record in upstream
// kernel order (type, arg1, arg2, pc); `record_count` records on input.
// `out_records` receives the survivors as the same packed layout. Returns
// the number of records kept (out_records.size() / 4).
//
// Pure function — no allocation other than out_records growth, no I/O,
// no locks. Safe to call on the worker hot path.
inline uint32_t FilterCmpRecordsByOutputBuffer(
    const uint64_t* in_records, uint32_t record_count,
    uint64_t out_buf_start, uint64_t out_buf_end,
    std::vector<uint64_t>* out_records)
{
    constexpr size_t kUint64sPerRecord = 4;
    if (out_records == nullptr) {
        return 0;
    }
    out_records->clear();
    if (in_records == nullptr || record_count == 0) {
        return 0;
    }
    out_records->reserve(static_cast<size_t>(record_count) * kUint64sPerRecord);
    uint32_t kept = 0;
    for (uint32_t i = 0; i < record_count; ++i) {
        const uint64_t* r = in_records + i * kUint64sPerRecord;
        const uint64_t arg1 = r[1];
        const uint64_t arg2 = r[2];
        if ((arg1 >= out_buf_start && arg1 <= out_buf_end) ||
            (arg2 >= out_buf_start && arg2 <= out_buf_end)) {
            continue;
        }
        out_records->insert(out_records->end(), r, r + kUint64sPerRecord);
        ++kept;
    }
    return kept;
}

// [v2 Epic 5 PR-5-A] AppendKcovCmpFeedbackRaw — KCOV_TRACE_CMP records.
//
// `records` points to a packed sequence of 4 × uint64 per record
// in upstream kernel order (type, arg1, arg2, pc); `record_count` is
// the number of records (each record = 32 bytes = 4 × uint64).
// `WorkerFeedbackHeader.entry_count` carries the record count
// (NOT the uint64 count), per Epic 5 plan §3 D-3. Wire bytes on disk
// = sizeof(WorkerFeedbackHeader) + record_count * 32.
//
// PR-5-B is the only producer; PR-5-A ships this helper unwired so
// the round-trip ctest can exercise it without the worker path.
inline FeedbackAppendStatus AppendKcovCmpFeedbackRaw(uint8_t* out,
                                                     uint32_t out_cap,
                                                     uint32_t* inout_len,
                                                     const uint64_t* records,
                                                     uint32_t record_count)
{
    if (out == nullptr || inout_len == nullptr || records == nullptr || record_count == 0) {
        return FeedbackAppendStatus::kSkippedNoCoverage;
    }

    constexpr size_t kUint64sPerRecord = 4;
    const size_t cov_bytes = static_cast<size_t>(record_count) * kUint64sPerRecord * sizeof(uint64_t);
    const size_t fb_size = sizeof(refuzz::proto::WorkerFeedbackHeader) + cov_bytes;
    if (static_cast<size_t>(*inout_len) + fb_size > out_cap) {
        return FeedbackAppendStatus::kNoSpace;
    }

    uint8_t* cov_dst = out + *inout_len;
    std::memcpy(cov_dst, records, cov_bytes);

    refuzz::proto::WorkerFeedbackHeader header;
    header.kind = static_cast<uint16_t>(refuzz::proto::FeedbackKind::kCoverageKcovCmp);
    header.entry_count = record_count;
    std::memcpy(cov_dst + cov_bytes, &header, sizeof(header));

    *inout_len += static_cast<uint32_t>(fb_size);
    return FeedbackAppendStatus::kOk;
}

class NullCoverageCollector final : public ICoverageCollector {
public:
    bool Init() override { return true; }
    bool Enabled() const override { return false; }
    refuzz::proto::FeedbackKind Kind() const override { return refuzz::proto::FeedbackKind::kNone; }
    void Begin() override {}
    void End(std::vector<uint64_t>*) override {}
    uint32_t SnapshotFeedback(uint8_t*, uint32_t) const override { return 0; }
    size_t BufferBytes() const override { return 0; }
};

} // namespace refuzz::worker
