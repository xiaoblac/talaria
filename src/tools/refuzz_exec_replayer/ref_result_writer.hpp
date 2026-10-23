#pragma once

// ref_result_writer — write the V2 oracle's reFuzz-side outcome file.
//
// File format mirrors exec_trace_*.bin (size-prefixed records) but with
// distinct magic and record types. Header (64 bytes):
//   "REFUZRR\0" (8)  version (4 LE)  created_unix_ns (8 LE)
//   syzkaller_git_rev (40, null-padded)  reserved (4)
//
// Record framing (same as proxy trace):
//   uint32 LE rec_size           (excludes prefix; includes type/seq/ts/body)
//   uint8     rec_type
//   uint64 LE monotonic_seq      (replayer's per-session seq)
//   uint64 LE ts_ns
//   ... body ...
//
// See docs/plans/production-exec-paired-oracle.md §6.6.

#include <chrono>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace refuzz::oracle::replayer {

constexpr uint8_t kRecReplaySessionOpen  = 0x20;
constexpr uint8_t kRecReplayOutcome      = 0x21;
constexpr uint8_t kRecReplaySkip         = 0x22;
constexpr uint8_t kRecReplaySessionClose = 0x23;

constexpr uint8_t kOutcomeNormal   = 0;
constexpr uint8_t kOutcomeAbnormal = 1;
constexpr uint8_t kOutcomeMissing  = 2;   // inflight at session_close, never resolved

constexpr uint8_t kSkipUnsupportedExecOpts = 1;
constexpr uint8_t kSkipParseError          = 2;
// Legacy value retained for parsing older ref_result files. Current replay
// does not skip requests that lack a Syzkaller proc ID.
constexpr uint8_t kSkipMissingProcId       = 3;

class RefResultWriter {
public:
    RefResultWriter() = default;
    ~RefResultWriter();

    bool Open(const std::string& path, const std::string& git_rev);
    bool Close();
    bool ok() const { return !write_failed_.load(std::memory_order_relaxed); }

    bool WriteSessionOpen(uint64_t trace_session_id,
                          uint32_t vm_index,
                          uint64_t file_created_unix_ns,
                          const std::string& source_trace_path);
    bool WriteSessionClose(uint8_t reason, uint64_t dropped_count, const std::string& note);

    // outcome_kind: kOutcomeNormal / kOutcomeAbnormal / kOutcomeMissing
    // For kOutcomeMissing, output may be empty.
    bool WriteOutcome(uint64_t seq,
                      uint64_t executor_id,
                      int64_t  req_id,
                      uint8_t  outcome_kind,
                      uint8_t  abnormal_kind,        // 0xFF if not abnormal
                      uint64_t submit_ns,
                      uint64_t complete_ns,
                      const std::vector<uint8_t>& output);

    bool WriteSkip(uint64_t seq,
                   int64_t  req_id,
                   uint8_t  skip_reason,
                   uint64_t exec_env_flags,
                   uint64_t exec_exec_flags);

private:
    bool WriteRecord(uint8_t rec_type, uint64_t seq, std::vector<uint8_t> body);

    std::mutex mu_;
    FILE*  fp_ = nullptr;
    std::string path_;
    std::atomic<bool> write_failed_{false};
};

uint64_t NowNs();

} // namespace refuzz::oracle::replayer
