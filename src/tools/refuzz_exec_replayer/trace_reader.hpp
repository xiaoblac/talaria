#pragma once

// trace_reader — read V2 exec_trace_*.bin (produced by syz_flatrpc_proxy)
// and surface a callback-style stream of session_open / ExecRequest /
// session_close events. ExecRequest payload bytes (= prog.SerializeForExec
// output) are extracted from the flatbuffers HostMessage frame_h2e body.
//
// See docs/plans/production-exec-paired-oracle.md §5 (trace schema) and
// reFuzz/tools/syz_flatrpc_proxy/trace.go (writer).

#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace refuzz::oracle::replayer {

struct TraceHeader {
    uint32_t version = 0;
    uint64_t created_unix_ns = 0;
    std::string syzkaller_git_rev;
};

struct ExecRequestEvent {
    // monotonic_seq from the underlying frame_h2e record. This sequence is
    // local to one proxy session and therefore cannot be used directly as a
    // batch-wide executor ID. ExecRequest.id (the syz-manager-assigned int64)
    // is in `req_id`.
    uint64_t seq = 0;
    int64_t  req_id = 0;
    uint64_t exec_env_flags = 0;
    uint64_t exec_exec_flags = 0;
    int64_t  sandbox_arg = 0;
    uint64_t request_flags = 0;
    uint64_t request_type = 0;
    std::vector<uint8_t> payload;   // ExecRequest.data == SerializeForExec bytes
};

// ExecutingMessage from the E2H side: the executor announces it started
// running request `req_id` on proc slot `proc_id`. Captured before the kernel
// even runs the program so the host knows which slot owns the in-flight job
// (used by syzkaller to attribute crashes that kill the executor process).
// Replayer uses the event timestamp for optional trace pacing. proc_id remains
// available to diagnostics, but replay scheduling does not preserve it.
//
// `ts_ns` is the record-level wall-clock the proxy stamped when the Executing
// frame arrived at the host (one-way VM→host latency away from when the
// executor actually called Executing()). It's the closest signal we have to
// "syzkaller per-proc start cadence" — strict-equivalence replay paces
// Submits against this so the kernel sees the same per-proc inter-arrival
// rate it saw under syzkaller, instead of reFuzz's natural burst submit.
struct ExecutingEvent {
    int64_t  req_id   = 0;
    int32_t  proc_id  = -1;
    int32_t  try_idx  = 0;     // ExecutingMessageRaw.try field
    uint64_t ts_ns    = 0;     // record-level proxy wall-clock; 0 = unset
};

struct SessionInfo {
    uint64_t session_id = 0;
    uint32_t vm_index = 0;
    uint32_t proxy_pid = 0;
    std::string manager_addr;
    // From the file header (set by syz_flatrpc_proxy.WriteHeader):
    uint64_t file_created_unix_ns = 0;
    std::string file_path;
};

struct SessionCloseInfo {
    uint8_t reason = 0;   // 0=eof, 1=error, 2=killed
    std::string error_msg;
};

struct TraceCallbacks {
    std::function<void(const SessionInfo&)>     on_session_open;
    std::function<void(const ExecRequestEvent&)> on_exec_request;
    // E2H ExecutingMessage emission. Optional — if unset, executing events are
    // dropped silently. Replayer uses it to build req_id -> timestamp pacing
    // anchors.
    std::function<void(const ExecutingEvent&)>   on_executing;
    std::function<void(const SessionCloseInfo&)> on_session_close;
    std::function<void(const std::string&)>      on_truncated_tail; // single warning at file end
};

// Glob trace files under dir matching exec_trace_*.bin, sort by file
// header created_unix_ns, return absolute paths. Files that fail header
// check are skipped (with a warning to stderr).
std::vector<SessionInfo> CollectAndSortTraces(
    const std::filesystem::path& dir,
    size_t* rejected_files = nullptr);

// Read one trace file and emit events through callbacks. Returns false on
// hard parse error (truncated header / bogus rec_size); true if file was
// consumed, even if the final record was a truncated_tail (which fires
// on_truncated_tail then returns true).
bool ReplayOneFile(const SessionInfo& session, const TraceCallbacks& cbs);

} // namespace refuzz::oracle::replayer
