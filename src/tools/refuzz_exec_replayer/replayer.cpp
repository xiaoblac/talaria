#include "replayer.hpp"

#include "refuzz/channel/channel.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <thread>
#include <unordered_map>
#include <utility>

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace refuzz::oracle::replayer {

namespace cc = refuzz::core::channel_contract;

namespace {

// ── dirty-set measurement hook (snapshot PR0/PR1) ──────────────────────────
// Gated entirely by env: REFUZZ_DUMP_PREFIX + REFUZZ_DUMP_QMP="host:port".
// Around exactly one isolated program (REFUZZ_ONLY_REQ) we connect to the VM's
// fixed QMP monitor (nobody else uses it at runtime), `stop` the vcpu,
// `pmemsave` a guest-physical range to a host file, and `cont`. A page-diff of
// the before/after dumps (tools/snapshot_pr0/pagediff) is that program's exact
// guest dirty-set — the accurate per-program number the synthetic
// kvm_track_overhead curve cannot give. Range defaults to ~2 GB of low RAM
// (use a 2 GB measurement VM so all RAM is contiguous below the PCI hole).
bool MeasureQmpDump(const char* which) {
    const char* prefix = ::getenv("REFUZZ_DUMP_PREFIX");
    const char* qmp    = ::getenv("REFUZZ_DUMP_QMP");
    if (prefix == nullptr || *prefix == '\0' || qmp == nullptr || *qmp == '\0')
        return false;
    unsigned long long addr = 0x100000ULL, size = 0x7ff00000ULL;
    if (const char* a = ::getenv("REFUZZ_DUMP_ADDR")) addr = ::strtoull(a, nullptr, 0);
    if (const char* s = ::getenv("REFUZZ_DUMP_SIZE")) size = ::strtoull(s, nullptr, 0);

    std::string host(qmp);
    int port = 0;
    auto colon = host.find(':');
    if (colon != std::string::npos) { port = ::atoi(host.c_str() + colon + 1); host = host.substr(0, colon); }
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    ::inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        std::fprintf(stderr, "measure: QMP connect %s:%d failed (errno=%d)\n", host.c_str(), port, errno);
        ::close(fd);
        return false;
    }
    std::string acc;
    auto pump = [&]() {
        char b[8192];
        ssize_t n = ::recv(fd, b, sizeof(b), 0);
        if (n > 0) acc.append(b, static_cast<size_t>(n));
        return n > 0;
    };
    // Read complete '\n'-delimited JSON lines until one carries a command
    // result ("return"/"error"), skipping async events and the greeting.
    auto wait_return = [&]() {
        for (int guard = 0; guard < 100000; ++guard) {
            size_t nl;
            while ((nl = acc.find('\n')) != std::string::npos) {
                std::string line = acc.substr(0, nl);
                acc.erase(0, nl + 1);
                if (line.find("\"return\"") != std::string::npos ||
                    line.find("\"error\"") != std::string::npos)
                    return true;
            }
            if (!pump()) return false;
        }
        return false;
    };
    auto cmd = [&](const std::string& c) {
        std::string l = c + "\n";
        ::send(fd, l.data(), l.size(), 0);
        return wait_return();
    };
    cmd("{\"execute\":\"qmp_capabilities\"}");
    cmd("{\"execute\":\"stop\"}");
    std::string file = std::string(prefix) + "_" + which + ".raw";
    char pc[600];
    std::snprintf(pc, sizeof(pc),
                  "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":%llu,\"size\":%llu,\"filename\":\"%s\"}}",
                  addr, size, file.c_str());
    bool ok = cmd(pc);
    cmd("{\"execute\":\"cont\"}");
    ::close(fd);
    std::fprintf(stderr, "measure: dump %s -> %s (addr=0x%llx size=0x%llx) ok=%d\n",
                 which, file.c_str(), addr, size, ok);
    return ok;
}

bool g_measure_before_done = false;


// T2 pacing: pre-pass over a session trace file to extract req_id ->
// executing_ts_ns from E2H ExecutingMessage records. executing_ts_ns is the
// anchor for PacingMode::kTrace — each subsequent
//     Submit sleeps to reproduce the captured request-start cadence
//     (T2 step-6 investigation; production fast path keeps PacingMode::kNone
//     and ignores the ts).
struct TraceExecAnchor {
    uint64_t executing_ts_ns = 0;
};

bool BuildReqIdAnchor(
    const SessionInfo& session,
    std::unordered_map<int64_t, TraceExecAnchor>& out) {
    TraceCallbacks cbs;
    cbs.on_executing = [&](const ExecutingEvent& ev) {
        // Multiple Executing records can fire for the same req_id (try>0
        // retries). Keep the earliest start as the pacing anchor; worker/proc
        // identity is intentionally not reproduced.
        auto& slot = out[ev.req_id];
        if (slot.executing_ts_ns == 0 ||
            (ev.ts_ns != 0 && ev.ts_ns < slot.executing_ts_ns)) {
            slot.executing_ts_ns = ev.ts_ns;
        }
    };
    return ReplayOneFile(session, cbs);
}

uint64_t NowMonoNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

}  // namespace

Replayer::Replayer(refuzz::channel::IChannel& channel,
                   RefResultWriter& writer,
                   ReplayerConfig cfg)
    : channel_(channel), writer_(writer), cfg_(std::move(cfg)) {}

bool Replayer::Run() {
    size_t rejected_trace_files = 0;
    auto sessions = CollectAndSortTraces(cfg_.trace_dir, &rejected_trace_files);
    if (rejected_trace_files != 0) {
        std::fprintf(stderr,
                     "replayer: rejected %zu malformed or unsupported trace file(s)\n",
                     rejected_trace_files);
        return false;
    }
    if (sessions.empty()) {
        std::fprintf(stderr, "replayer: no exec_trace_*.bin files in %s\n",
                     cfg_.trace_dir.c_str());
        return false;
    }

    for (const auto& s : sessions) {
        bool truncated_tail = false;
        TraceCallbacks cbs;
        cbs.on_truncated_tail = [&](const std::string&) {
            truncated_tail = true;
        };
        const bool parse_ok = ReplayOneFile(s, cbs);
        if (!parse_ok || (truncated_tail && !cfg_.allow_truncated_tail)) {
            std::fprintf(stderr, "replayer: preflight parse failed: %s\n",
                         s.file_path.c_str());
            return false;
        }
        if (truncated_tail) {
            std::fprintf(stderr,
                "replayer: preflight: %s ends mid-record (allow_truncated_tail); "
                "the final in-flight request at capture cutoff will be dropped\n",
                s.file_path.c_str());
        }
    }

    auto boot = channel_.Boot();
    if (!boot.ok()) {
        std::fprintf(stderr, "replayer: channel boot failed: %s\n",
                     boot.error().message.c_str());
        return false;
    }
    if (cfg_.post_boot_hook && !cfg_.post_boot_hook()) {
        channel_.Close();
        return false;
    }
    uint64_t executor_id_cursor = 0;
    bool replay_ok = true;
    for (const auto& s : sessions) {
        if (!RunOneSession(s, executor_id_cursor)) {
            std::fprintf(stderr, "replayer: session %s aborted\n",
                         s.file_path.c_str());
            replay_ok = false;
        }
        ++stats_.sessions_processed;
        if (!replay_ok || !writer_.ok()) break;
    }
    if (cfg_.pre_close_hook) {
        cfg_.pre_close_hook();
    }
    channel_.Close();
    return replay_ok && writer_.ok();
}

bool Replayer::RunOneSession(const SessionInfo& session,
                             uint64_t& executor_id_cursor) {
    inflight_.clear();
    replay_seq_in_session_ = 0;

    const bool pace_trace = (cfg_.pacing_mode == PacingMode::kTrace);

    // Build req_id -> executing_ts_ns only for optional trace pacing. H2E
    // ExecRequest arrives before E2H Executing in the wire trace, so pacing
    // needs this pre-pass. Worker/proc identity is deliberately ignored.
    std::unordered_map<int64_t, TraceExecAnchor> anchor_by_req_id;
    if (pace_trace && !BuildReqIdAnchor(session, anchor_by_req_id)) {
        std::fprintf(stderr, "replayer: anchor parse failed: %s\n",
                     session.file_path.c_str());
        return false;
    }

    // T2 PacingMode::kTrace state. paced_anchor_wall_ns + paced_anchor_trace_ns
    // are the (wall-clock, trace-clock) pair captured on the FIRST Submit of
    // the session: every subsequent Submit then sleeps until wall ≥
    // anchor_wall + (req.executing_ts - anchor_trace).
    uint64_t paced_anchor_wall_ns  = 0;
    uint64_t paced_anchor_trace_ns = 0;

    bool emitted_open = false;
    bool emitted_close = false;
    bool callback_failed = false;
    bool truncated_tail = false;
    SessionInfo final_si = session;
    auto emit_open = [&](const SessionInfo& si) {
        if (emitted_open) return;
        emitted_open = true;
        final_si = si;
        if (!writer_.WriteSessionOpen(si.session_id, si.vm_index,
                                      si.file_created_unix_ns, si.file_path)) {
            callback_failed = true;
        }
    };

    auto finish_session = [&](uint8_t reason, const std::string& note) {
        if (emitted_close) {
            callback_failed = true;
            return;
        }
        DrainUntilEmpty(cfg_.session_drain_budget);

        const uint64_t dropped = inflight_.size();
        for (auto& [executor_id, info] : inflight_) {
            if (!writer_.WriteOutcome(replay_seq_in_session_++,
                                      executor_id,
                                      info.req_id,
                                      kOutcomeMissing,
                                      0xFF,
                                      info.submit_ns,
                                      NowNs(),
                                      {})) {
                callback_failed = true;
            }
            ++stats_.outcomes_missing_at_close;
        }
        inflight_.clear();

        if (!emitted_open) emit_open(session);
        if (!writer_.WriteSessionClose(reason, dropped, note)) {
            callback_failed = true;
        }
        emitted_close = true;
    };

    TraceCallbacks cbs;
    cbs.on_session_open = [&](const SessionInfo& si) {
        emit_open(si);
    };
    cbs.on_truncated_tail = [&](const std::string& phase) {
        truncated_tail = true;
        std::fprintf(stderr,
                     "replayer: %s: truncated_tail at %s\n",
                     session.file_path.c_str(), phase.c_str());
    };
    cbs.on_session_close = [&](const SessionCloseInfo& sc) {
        finish_session(sc.reason, sc.error_msg);
    };
    cbs.on_exec_request = [&](const ExecRequestEvent& ev) {
        if (callback_failed || !writer_.ok()) return;
        if (!emitted_open) emit_open(session);
        ++stats_.exec_requests_seen;

        // [measure] background-floor bracket: REFUZZ_DUMP_IDLE_MS=<ms> takes a
        // before-dump on the first request, lets the guest run idle (NO program
        // submitted) for <ms>, takes an after-dump, and exits. page-diff of
        // these = background churn (KASAN shadow / KCOV / worker threads /
        // timers) over <ms>, to subtract from a program-run's dirty-set.
        {
            static const char* idle_ms_env = ::getenv("REFUZZ_DUMP_IDLE_MS");
            static bool idle_done = false;
            if (idle_ms_env != nullptr && *idle_ms_env != '\0') {
                if (!idle_done) {
                    idle_done = true;
                    MeasureQmpDump("before");
                    std::this_thread::sleep_for(std::chrono::milliseconds(::atoi(idle_ms_env)));
                    MeasureQmpDump("after");
                    std::fprintf(stderr, "measure: idle bracket (%s ms) done; draining + clean close\n", idle_ms_env);
                }
                // Skip every program; the normal end-of-Run channel_.Close()
                // tears down the VM so we do NOT leak a qemu holding the fixed
                // QMP port (the std::exit path did — caused 'port unavailable').
                return;
            }
        }

        // [single-program isolation 2026-05-24] REFUZZ_ONLY_REQ=<id> replays
        // exactly one exec request (by flatrpc id == oracle req_id), skipping
        // all others, so the worker's dmesg/EP0 logs for one program don't
        // interleave with adjacent programs. Diagnostic knob; unset → no-op.
        static const char* only_req_env = ::getenv("REFUZZ_ONLY_REQ");
        if (only_req_env != nullptr && *only_req_env != '\0') {
            const long only_req = ::strtol(only_req_env, nullptr, 10);
            if (ev.req_id != only_req) {
                ++stats_.skips_unsupported;
                return;
            }
        }

        // [measure] dirty-set BEFORE snapshot for the one isolated program,
        // taken just before Submit so the program has not run yet. Gated by
        // REFUZZ_ONLY_REQ (single-program) + REFUZZ_DUMP_PREFIX/QMP env.
        if (!g_measure_before_done && only_req_env != nullptr && *only_req_env != '\0') {
            g_measure_before_done = MeasureQmpDump("before");
        }

        // Plan §3 (revised by COV-A): skip CollectComps only. Threaded is
        // now supported via wire flag translation + thread_count > 1.
        if (cfg_.skip_unsupported_exec_opts &&
            (ev.exec_exec_flags & cfg_.unsupported_exec_flags_mask) != 0) {
            if (!writer_.WriteSkip(replay_seq_in_session_++, ev.req_id,
                                   kSkipUnsupportedExecOpts,
                                   ev.exec_env_flags, ev.exec_exec_flags)) {
                callback_failed = true;
            }
            ++stats_.skips_unsupported;
            return;
        }

        const auto it = anchor_by_req_id.find(ev.req_id);
        const uint64_t executing_ts_ns =
            it == anchor_by_req_id.end() ? 0 : it->second.executing_ts_ns;

        // T2 PacingMode::kTrace: stall until wall-clock matches the captured
        // request-start cadence. A request without an Executing record has no
        // pacing anchor; submit it in trace order without sleeping.
        if (pace_trace && executing_ts_ns != 0) {
            if (paced_anchor_trace_ns == 0) {
                paced_anchor_wall_ns  = NowMonoNs();
                paced_anchor_trace_ns = executing_ts_ns;
            } else {
                // delta is uint64 — only positive if executing_ts is after
                // anchor; trace records are strictly monotonic per session
                // so this branch is the common case.
                if (executing_ts_ns > paced_anchor_trace_ns) {
                    const uint64_t target_wall =
                        paced_anchor_wall_ns +
                        (executing_ts_ns - paced_anchor_trace_ns);
                    const uint64_t now = NowMonoNs();
                    if (target_wall > now) {
                        std::this_thread::sleep_for(
                            std::chrono::nanoseconds(target_wall - now));
                    }
                }
            }
        }

        // Allocate one deterministic, non-zero ID across the complete trace
        // batch. Proxy record seq restarts at zero for every session, so using
        // ev.seq here would collide after a runner/VM restart.
        if (executor_id_cursor == std::numeric_limits<uint64_t>::max()) {
            std::fprintf(stderr, "replayer: executor ID space exhausted\n");
            callback_failed = true;
            return;
        }
        cc::ChannelDispatchRequest req;
        req.executor_id     = ++executor_id_cursor;
        req.seed_id         = req.executor_id;
        req.origin_seed_id  = req.executor_id;
        req.payload         = ev.payload;
        req.timeout_ms      = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(cfg_.per_request_timeout).count());
        req.exec_flags      = TranslateFlatRpcExecFlagsToWire(ev.exec_exec_flags);
        // Preserve only request order. reFuzz chooses the execution resource
        // through its normal scheduler; captured Syzkaller identities are not
        // replay constraints.
        req.target_worker_id = cc::kAnyWorkerId;
        req.target_proc_id   = cc::kAnyProcId;

        // Submit; if channel is full, drain a bit and retry.
        for (;;) {
            auto r = channel_.Submit(
                req,
                std::chrono::duration_cast<std::chrono::microseconds>(cfg_.submit_wait_for_slot));
            if (r.status == cc::ChannelSubmitStatus::kAccepted) {
                inflight_[req.executor_id] =
                    Inflight{ev.req_id, NowNs()};
                ++stats_.submissions_accepted;
                break;
            }
            if (r.status == cc::ChannelSubmitStatus::kBusy) {
                DrainAndReconcile(cfg_.drain_poll_interval);
                continue;
            }
            // kUnavailable / kInvalid — record as missing-with-context and move on.
            if (!writer_.WriteOutcome(replay_seq_in_session_++,
                                      req.executor_id,
                                      ev.req_id,
                                      kOutcomeMissing,
                                      0xFF,
                                      NowNs(),
                                      NowNs(),
                                      {})) {
                callback_failed = true;
            }
            ++stats_.submissions_rejected;
            break;
        }
        // [measure] one isolated program: synchronously wait for its result,
        // then AFTER-dump immediately — keeps the before→after window to ~the
        // program's own execution so the page-diff isolates ITS dirty-set
        // rather than seconds of background KASAN activity.
        if (g_measure_before_done && only_req_env != nullptr && *only_req_env != '\0') {
            DrainUntilEmpty(cfg_.session_drain_budget);
            MeasureQmpDump("after");
        }
        // Opportunistically drain anything completed while we were busy.
        DrainAndReconcile(std::chrono::milliseconds{0});
    };

    if (!ReplayOneFile(session, cbs)) {
        if (!emitted_open) emit_open(session);
        if (!emitted_close) {
            finish_session(1 /*error*/, "trace parse failed");
        }
        return false;
    }
    if (!emitted_close) {
        // ReplayOneFile is supposed to emit on_session_close on its own,
        // but be defensive in case of a future schema change.
        finish_session(0, "synthesized at file end");
    }
    (void)final_si;
    return !callback_failed && (!truncated_tail || cfg_.allow_truncated_tail) &&
           writer_.ok();
}

bool Replayer::DrainAndReconcile(std::chrono::milliseconds budget) {
    refuzz::channel::EventList events;
    bool got = channel_.DrainEvents(
        events,
        std::chrono::duration_cast<std::chrono::microseconds>(budget));
    if (!got) return false;

    for (auto& ev : events) {
        if (const auto* comp = ev.AsCompletion()) {
            auto it = inflight_.find(comp->ctx.executor_id);
            if (it == inflight_.end()) {
                // Unknown executor_id — likely a previous-session straggler.
                continue;
            }
            uint8_t okind = kOutcomeNormal;
            writer_.WriteOutcome(replay_seq_in_session_++,
                                 comp->ctx.executor_id,
                                 it->second.req_id,
                                 okind,
                                 0xFF,
                                 it->second.submit_ns,
                                 NowNs(),
                                 comp->output);
            inflight_.erase(it);
            ++stats_.outcomes_normal;
        } else if (const auto* ab = ev.AsAbnormal()) {
            auto it = inflight_.find(ab->ctx.executor_id);
            if (it == inflight_.end()) continue;
            writer_.WriteOutcome(replay_seq_in_session_++,
                                 ab->ctx.executor_id,
                                 it->second.req_id,
                                 kOutcomeAbnormal,
                                 static_cast<uint8_t>(ab->kind),
                                 it->second.submit_ns,
                                 NowNs(),
                                 ab->output);
            inflight_.erase(it);
            ++stats_.outcomes_abnormal;
        } else if (ev.IsFault()) {
            // Fault events affect the whole channel — don't try to reconcile
            // per-request. Replayer state stays as-is; on_session_close path
            // will mark surviving inflight as missing.
        }
    }
    return true;
}

void Replayer::DrainUntilEmpty(std::chrono::seconds budget) {
    auto deadline = std::chrono::steady_clock::now() + budget;
    while (!inflight_.empty()) {
        if (std::chrono::steady_clock::now() >= deadline) break;
        DrainAndReconcile(cfg_.drain_poll_interval);
    }
}

} // namespace refuzz::oracle::replayer
