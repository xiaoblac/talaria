// request_stream_sink — records every request reFuzz dispatches, so reFuzz's
// own workload can be replayed by BOTH systems the way syzkaller's already is.
//
// WHY THIS EXISTS
// Every symmetric measurement so far replays a stream captured from syzkaller.
// That fills one column of the 2x2:
//
//                    syzkaller's programs   reFuzz's programs
//   syzkaller runs          measured              MISSING
//   reFuzz runs             measured           (standalone only)
//
// The missing cell is the one a reviewer asks about first, because the two
// diagonal numbers disagree sharply: syzkaller runs at ~8.5 programs/s on
// either workload, while reFuzz drops from 23.5 to 13.3 when it executes
// syzkaller's. Whether that is a property of the corpus or of the mechanism
// cannot be told without running reFuzz's corpus through syzkaller.
//
// WHY JSONL AND NOT THE BINARY FORMAT
// The request-stream format already has two implementations that must agree
// byte for byte: pkg/requeststream (Go, reader+writer) and
// request_stream_reader.hpp (C++, reader). A C++ *writer* would be a third,
// and the v1->v2 change showed how easily one of them is missed. So this sink
// emits plain JSON lines and tools/syz-stream-from-jsonl turns them into a
// canonical stream through the Go writer -- format knowledge stays where it is,
// and the converter re-parses every program through prog.Deserialize before
// writing, so anything syzkaller cannot read fails at conversion instead of an
// hour into a replay.
//
// FIELDS reFuzz HAS NO PER-TASK EQUIVALENT FOR
// exec_env_flags / sandbox_arg / request_flags / the CollectSignal, CollectCover
// and DedupCover exec bits are per-run knobs in reFuzz, not per-request ones
// (the same asymmetry fixed_input_producer_job.cpp documents in the opposite
// direction). They are emitted as fixed values chosen to match what syzkaller's
// own captured stream carries, so that a replay of THIS stream asks syzkaller to
// do the same collection work its own stream would. Leaving them zero would
// silently disable coverage collection on the syzkaller side and make it look
// fast for the wrong reason -- the one difference between the two streams has to
// be the programs.
#pragma once

#include "refuzz/control/job/job_context.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace refuzz::program::syz {
class Target;
}

namespace refuzz::control {

// Defaults mirror the syzkaller-captured stream measured on 2026-07-26
// (34424 records): exec_env_flags was 0x3bf12 on 100% of records, request_flags
// 0 on 100%, sandbox_arg single-valued, and exec_flags carried CollectSignal|
// Threaded (65.8%) or CollectSignal|CollectCover|Threaded (32.0%).
struct RequestStreamSinkConfig {
    std::string path;
    std::uint64_t exec_env_flags = 0x3bf12ULL;
    std::uint64_t sandbox_arg    = 0;
    std::uint64_t request_flags  = 0;
    // Base exec flags every emitted record carries. bit0 CollectSignal,
    // bit1 CollectCover, bit4 Threaded -- reFuzz collects signal and coverage
    // unconditionally in its own feedback pipeline, so the request-level bits
    // that gate the same work on the syzkaller side are asserted here.
    std::uint64_t base_exec_flags = 0x13ULL;
};

class RequestStreamSink {
public:
    RequestStreamSink(RequestStreamSinkConfig cfg, const program::syz::Target& target);
    ~RequestStreamSink();

    RequestStreamSink(const RequestStreamSink&)            = delete;
    RequestStreamSink& operator=(const RequestStreamSink&) = delete;

    // Called from JobScheduler::TrySubmit -- the single submit funnel both
    // ctx.exec() and ctx.emit() pass through, so hooking it cannot miss a
    // dispatched request the way hooking either primitive would.
    //
    // Control thread only, matching TrySubmit. Encodes the program to canonical
    // text and hands the record to a background writer; JSON escaping, buffering
    // and file I/O all happen off the dispatch path. This mirrors syzkaller's
    // sink (pkg/rpcserver/request_stream_sink.go), which likewise keeps
    // req.Prog.Serialize() on the hot path -- the stream stores canonical text,
    // and the artifact is only guaranteed alive and immutable for this call --
    // while everything after the handoff is asynchronous.
    void Record(const job::Request& req);

    // Drains the writer and publishes the stream: fsync the temp file, then
    // rename it into place. Safe to call more than once. If the capture was
    // invalidated (backlog exceeded, write error, or the path already existed)
    // nothing is published and the partial file is removed, so a run can never
    // leave behind a stream that silently lost records.
    void Close();

    std::uint64_t written() const noexcept;
    // Requests whose artifact held no typed syz program, or that would not
    // text-encode. Counted and reported rather than substituted: a stream that
    // silently skips requests is a stream that no longer describes the run.
    std::uint64_t skipped() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace refuzz::control
