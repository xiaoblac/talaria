// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosCrashBucket — Phase 2 §C #18, XiUOS-only crash record + bucket layer.
//
// Consumes cc::AbnormalCompletion events produced by the XiUOS UART data
// plane when the worker reports XIUOS_STATUS_TRAP (CPU exception inside the
// guest). The XiUOS DP encodes the trap context into the existing
// AbnormalCompletion fields by XiUOS convention:
//
//     kind                       = kWorkerSignaled
//     diagnostics.error_code     = trap_pc   (decoded.trap_or_pc)
//     diagnostics.crash_signal   = mcause    ((uint32_t)decoded.aux)
//     output                     = raw RESULT payload (self-describing)
//
// The bucket re-decodes `output` as XiuosDecodedResult, treating its values
// as the canonical source of truth, and cross-checks against error_code /
// crash_signal. Bucket key:
//
//     "xiuos-trap-pc_0x%08x-mcause_0x%08x"  (lowercase hex, no spaces)
//
// On-disk layout (per bucket directory):
//     <dir>/<bucket_key>/<payload_hash16>.bin   — raw program_payload bytes
//     <dir>/<bucket_key>/<payload_hash16>.json  — metadata (trap_pc, mcause,
//                                                  status, ts_us, payload_size)
//
// Dedup is per-bucket: FNV-1a 64-bit hash of program_payload. A repeated
// payload landing in the same (trap_pc, mcause) bucket is not re-persisted.
// LoadFromDisk recovers the dedup state by scanning .bin filenames (filename
// stem == hex hash) — no payload rehashing on startup.
//
// Non-Trap events (kExecError / kTimeout / non-XiUOS RESULT payloads) are
// silently ignored: Record returns an outcome with empty bucket_key and
// persisted=false. Callers can rely on this to push all XiUOS abnormal
// events here without pre-filtering.

#pragma once

#include "refuzz/core/channel_contract.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer {

class XiuosCrashBucket {
public:
    struct RecordOutcome {
        bool persisted = false;          // a new .bin/.json file was written
        bool bucket_is_new = false;      // bucket dir didn't exist before this call
        std::string bucket_key;          // empty if event was ignored
        std::uint64_t payload_hash = 0;  // 0 if event was ignored
    };

    explicit XiuosCrashBucket(std::filesystem::path dir);

    // Scan dir_ and populate in-memory dedup state from existing
    // <bucket>/<hash>.bin files. Returns total seed files counted.
    std::size_t LoadFromDisk();

    // Record the trap behind `ab`. Returns an outcome with empty bucket_key
    // if `ab` is not a XiUOS Trap event (decoded output's status != Trap or
    // payload doesn't decode at all).
    RecordOutcome Record(
        const refuzz::core::channel_contract::AbnormalCompletion& ab);

    static std::string MakeBucketKey(std::uint32_t trap_pc,
                                     std::uint32_t mcause);

    // Read-only observers.
    std::size_t BucketCount() const;
    std::size_t TotalRecordedSeeds() const;
    const std::filesystem::path& Dir() const { return dir_; }

private:
    bool WriteRecord(const std::string& bucket_key,
                     std::uint64_t payload_hash,
                     std::uint32_t trap_pc,
                     std::uint32_t mcause,
                     std::uint8_t  status,
                     const std::vector<std::uint8_t>& program_payload);

    mutable std::mutex mu_;
    std::filesystem::path dir_;
    std::unordered_map<std::string, std::unordered_set<std::uint64_t>> buckets_;
};

}  // namespace refuzz::fuzzer
