#pragma once

// replayer — orchestrates trace-to-channel replay:
//   1. CollectAndSortTraces() to enumerate exec_trace_*.bin in created_ns order
//   2. For each session: ReplayOneFile(), pumping ExecRequests into Submit()
//      and reconciling Completions from DrainEvents() into ref_result.bin
//   3. Cross-session boundary: drain remaining inflight, then move on
//
// Backend is injected as `IChannel*` so tests can pass EchoChannel and
// production can pass the QemuIvshmemLinux-built Channel (PR3c).

#include "flag_translation.hpp"
#include "ref_result_writer.hpp"
#include "trace_reader.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

namespace refuzz::channel {
class IChannel;
}

namespace refuzz::oracle::replayer {

// Submit pacing mode. "none" submits requests in capture order and lets the
// channel schedule them at full speed. "trace" additionally reproduces the
// captured request-start cadence. Neither mode preserves Syzkaller proc or
// worker identity.
enum class PacingMode {
    kNone = 0,
    kTrace,
};

struct ReplayerConfig {
    std::string trace_dir;
    std::string output_path;
    std::string git_rev;

    // Pacing.
    std::chrono::milliseconds submit_wait_for_slot{50};
    std::chrono::milliseconds drain_poll_interval{20};
    std::chrono::seconds      per_request_timeout{30};
    std::chrono::seconds      session_drain_budget{60};
    PacingMode                pacing_mode = PacingMode::kNone;

    // Default false: a trace file ending mid-record is treated as a hard
    // preflight/replay failure (paired-oracle equivalence testing wants the
    // whole captured session or nothing). Performance-sampling replay
    // deliberately cuts capture off at an arbitrary wall-clock instant
    // (CAPTURE_MODE=fuzz in exec_oracle_smoke.sh), so its trailing record is
    // routinely mid-write; set true to drop that one partial request and
    // replay everything before it. Mirrors syz_flatrpc_trace_dump's
    // -allow-truncated-tail.
    bool                      allow_truncated_tail = false;

    // [perf-sampling probe] Invoked after Boot() has completed every worker
    // handshake and before the first replay session can submit a request.
    // Empty by default, so normal replay has no acquisition barrier.
    std::function<bool()>    post_boot_hook;

    // [perf-sampling probe] Invoked (if set), synchronously, after the last
    // session drains but BEFORE channel_.Close() -- i.e. while the VM is
    // still up. Run() owns the whole channel lifecycle (Boot()...Close()),
    // so a hold requested by the CALLER after Run() returns would always be
    // too late: the VM is already torn down by then. Kept as a callback
    // (rather than a duration+path pair) so the actual sleep/release-file
    // polling loop stays in main.cpp, not duplicated here.
    std::function<void()>    pre_close_hook;

    // Skip policy (plan §3 / COV-A).
    //   - CollectComps stays skipped: worker has CMP KCOV support but the
    //     output region differs from PC mode; the oracle comparator (PR4)
    //     only knows the PC region. Separate epic to lift this.
    //   - Threaded REMOVED from skip mask (COV-A, 2026-05-19): worker
    //     supports it (Epic 7 PR-4 ExecuteThreaded), wire flag now
    //     translated via TranslateFlatRpcExecFlagsToWire. Requires
    //     target.thread_count > 1 in the channel config to actually
    //     dispatch — see configs/exec_oracle_replayer_threaded_config.json.
    bool skip_unsupported_exec_opts = true;
    uint64_t unsupported_exec_flags_mask = kFlatRpcCollectComps;

};

struct ReplayerStats {
    uint64_t sessions_processed = 0;
    uint64_t exec_requests_seen = 0;
    uint64_t submissions_accepted = 0;
    uint64_t submissions_rejected = 0;
    uint64_t skips_unsupported = 0;
    uint64_t outcomes_normal = 0;
    uint64_t outcomes_abnormal = 0;
    uint64_t outcomes_missing_at_close = 0;
};

class Replayer {
public:
    Replayer(refuzz::channel::IChannel& channel,
             RefResultWriter& writer,
             ReplayerConfig cfg);

    // Run all trace files under cfg.trace_dir. Returns false on hard
    // error (writer open failed, no trace files, etc.). Per-record
    // failures are absorbed into ReplayerStats.
    bool Run();

    const ReplayerStats& stats() const { return stats_; }

private:
    bool RunOneSession(const SessionInfo& session, uint64_t& executor_id_cursor);
    bool DrainAndReconcile(std::chrono::milliseconds budget);
    void DrainUntilEmpty(std::chrono::seconds budget);

    refuzz::channel::IChannel& channel_;
    RefResultWriter& writer_;
    ReplayerConfig cfg_;
    ReplayerStats stats_{};

    // inflight: executor_id → request identity — needed to reconcile
    // out-of-order Completions back to the originating ExecRequest.
    struct Inflight {
        int64_t  req_id = 0;
        uint64_t submit_ns = 0;
    };
    std::unordered_map<uint64_t, Inflight> inflight_;
    uint64_t replay_seq_in_session_ = 0;
};

} // namespace refuzz::oracle::replayer
