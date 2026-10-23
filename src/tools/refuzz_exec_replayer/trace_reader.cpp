#include "trace_reader.hpp"

#include "pkg/flatrpc/flatrpc.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace refuzz::oracle::replayer {

namespace {

constexpr const char* kTraceMagic = "REFUZZTR";
constexpr size_t      kTraceHeaderLen = 64;
constexpr uint32_t    kTraceVersion = 1;
constexpr uint32_t    kMaxTraceRecordSize = 128U << 20;

constexpr uint8_t kRecSessionOpen      = 0x01;
constexpr uint8_t kRecFrameH2E         = 0x02;
constexpr uint8_t kRecFrameE2H         = 0x03;
constexpr uint8_t kRecSessionClose     = 0x04;
constexpr uint8_t kRecTraceOverflow    = 0x05;
constexpr uint8_t kRecDecodedSummary   = 0x10;

uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t ReadU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

bool ReadHeader(std::ifstream& f, TraceHeader& out) {
    uint8_t hdr[kTraceHeaderLen];
    f.read(reinterpret_cast<char*>(hdr), kTraceHeaderLen);
    if (f.gcount() != static_cast<std::streamsize>(kTraceHeaderLen)) return false;
    if (std::memcmp(hdr, kTraceMagic, 8) != 0) return false;
    out.version = ReadU32(hdr + 8);
    out.created_unix_ns = ReadU64(hdr + 12);
    size_t gr_len = 0;
    while (gr_len < 40 && hdr[20 + gr_len] != 0) ++gr_len;
    out.syzkaller_git_rev.assign(reinterpret_cast<const char*>(hdr + 20), gr_len);
    return true;
}

// Parse an E2H frame body and, if it carries an ExecutorMessage that wraps
// an ExecutingMessageRaw, populate `out` with req_id/proc_id/try. Returns
// false for any other message (ExecResult / State) or malformed input — the
// caller silently skips. Symmetric with ExtractExecRequest's HostMessageRaw
// dispatch.
bool ExtractExecuting(const std::vector<uint8_t>& frame_body, ExecutingEvent& out) {
    if (frame_body.size() < 4) return false;
    uint32_t inner_size = ReadU32(frame_body.data());
    if (static_cast<size_t>(inner_size) + 4 != frame_body.size()) return false;
    const uint8_t* body = frame_body.data() + 4;
    size_t body_len = inner_size;

    const auto* msg = flatbuffers::GetRoot<rpc::ExecutorMessageRaw>(body);
    if (msg == nullptr) return false;
    flatbuffers::Verifier::Options vopts;
    vopts.check_alignment = false;
    flatbuffers::Verifier verifier(body, body_len, vopts);
    if (!msg->Verify(verifier)) return false;
    const auto* executing = msg->msg_as_Executing();
    if (executing == nullptr) return false;  // ExecResult / State / etc.

    out.req_id  = executing->id();
    out.proc_id = executing->proc_id();
    out.try_idx = executing->try_();
    return true;
}

bool ExtractExecRequest(const std::vector<uint8_t>& frame_body, ExecRequestEvent& out) {
    // frame_body is the raw frame as captured by the proxy:
    //   [uint32 LE size_prefix | flatbuffer body of `size_prefix` bytes].
    // We pass the inner body to flatbuffers verifier/accessor (matches
    // pkg/flatrpc/conn.go:168 Parse signature).
    if (frame_body.size() < 4) return false;
    uint32_t inner_size = ReadU32(frame_body.data());
    if (static_cast<size_t>(inner_size) + 4 != frame_body.size()) return false;
    const uint8_t* body = frame_body.data() + 4;
    size_t body_len = inner_size;

    // flatrpc.fbs declares no root_type, so the codegen does not emit the
    // VerifyHostMessageRawBuffer / GetHostMessageRaw convenience wrappers.
    // Use the generic GetRoot<T> + table-level Verify directly.
    //
    // check_alignment=false: trace record bodies live in std::vector<uint8_t>
    // which is only byte-aligned, while flatbuffers' default Verifier requires
    // 4-byte buffer alignment. We trust the trace was produced byte-equal from
    // a properly-aligned syz-manager → runner wire; what we want from Verify
    // is offset/length sanity, not alignment.
    const auto* msg = flatbuffers::GetRoot<rpc::HostMessageRaw>(body);
    if (msg == nullptr) return false;
    flatbuffers::Verifier::Options vopts;
    vopts.check_alignment = false;
    flatbuffers::Verifier verifier(body, body_len, vopts);
    if (!msg->Verify(verifier)) return false;
    const auto* req = msg->msg_as_ExecRequest();
    if (req == nullptr) return false;  // not an ExecRequest (SignalUpdate / CorpusTriaged / StateRequest)

    out.req_id = req->id();
    out.request_type = static_cast<uint64_t>(req->type());
    out.request_flags = static_cast<uint64_t>(req->flags());
    if (const auto* opts = req->exec_opts()) {
        out.exec_env_flags = static_cast<uint64_t>(opts->env_flags());
        out.exec_exec_flags = static_cast<uint64_t>(opts->exec_flags());
        out.sandbox_arg = opts->sandbox_arg();
    }
    if (const auto* data = req->data()) {
        out.payload.assign(data->begin(), data->end());
    } else {
        out.payload.clear();
    }
    return true;
}

} // namespace

std::vector<SessionInfo> CollectAndSortTraces(
    const std::filesystem::path& dir,
    size_t* rejected_files) {
    std::vector<SessionInfo> sessions;
    if (rejected_files != nullptr) *rejected_files = 0;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return sessions;
    for (auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        auto name = entry.path().filename().string();
        if (name.rfind("exec_trace_", 0) != 0) continue;
        if (entry.path().extension() != ".bin") continue;
        std::ifstream f(entry.path(), std::ios::binary);
        if (!f) {
            if (rejected_files != nullptr) ++*rejected_files;
            continue;
        }
        TraceHeader h;
        if (!ReadHeader(f, h) || h.version != kTraceVersion) {
            std::fprintf(stderr,
                         "trace_reader: skip %s (bad or unsupported header)\n",
                         name.c_str());
            if (rejected_files != nullptr) ++*rejected_files;
            continue;
        }
        SessionInfo si;
        si.file_path = entry.path().string();
        si.file_created_unix_ns = h.created_unix_ns;
        sessions.push_back(std::move(si));
    }
    std::sort(sessions.begin(), sessions.end(),
              [](const SessionInfo& a, const SessionInfo& b) {
                  if (a.file_created_unix_ns != b.file_created_unix_ns) {
                      return a.file_created_unix_ns < b.file_created_unix_ns;
                  }
                  return a.file_path < b.file_path;
              });
    return sessions;
}

bool ReplayOneFile(const SessionInfo& seed, const TraceCallbacks& cbs) {
    std::ifstream f(seed.file_path, std::ios::binary);
    if (!f) return false;
    TraceHeader hdr;
    if (!ReadHeader(f, hdr)) return false;
    if (hdr.version != kTraceVersion) {
        std::fprintf(stderr, "trace_reader: %s: unsupported version=%u\n",
                     seed.file_path.c_str(), hdr.version);
        return false;
    }

    SessionInfo enriched = seed;
    enriched.file_created_unix_ns = hdr.created_unix_ns;

    bool emitted_open = false;
    bool emitted_close = false;
    auto emit_open_once = [&](const SessionInfo& si) {
        if (emitted_open) return;
        emitted_open = true;
        if (cbs.on_session_open) cbs.on_session_open(si);
    };

    while (true) {
        uint8_t size_buf[4];
        f.read(reinterpret_cast<char*>(size_buf), 4);
        auto got = f.gcount();
        if (got == 0) {
            if (!emitted_close) {
                if (cbs.on_truncated_tail) cbs.on_truncated_tail("session_close");
                if (cbs.on_session_close) {
                    SessionCloseInfo sc{1, "missing session_close"};
                    cbs.on_session_close(sc);
                }
            }
            return true;
        }
        if (got != 4) {
            if (cbs.on_truncated_tail) cbs.on_truncated_tail("record_size");
            if (!emitted_close && cbs.on_session_close) {
                SessionCloseInfo sc{1, "truncated_tail"};
                cbs.on_session_close(sc);
            }
            return true;
        }
        uint32_t rec_size = ReadU32(size_buf);
        if (rec_size < 17) {
            std::fprintf(stderr, "trace_reader: %s: rec_size=%u too small\n",
                         seed.file_path.c_str(), rec_size);
            return false;
        }
        if (rec_size > kMaxTraceRecordSize) {
            std::fprintf(stderr, "trace_reader: %s: rec_size=%u too large\n",
                         seed.file_path.c_str(), rec_size);
            return false;
        }
        std::vector<uint8_t> buf(rec_size);
        f.read(reinterpret_cast<char*>(buf.data()), rec_size);
        if (static_cast<uint32_t>(f.gcount()) != rec_size) {
            if (cbs.on_truncated_tail) cbs.on_truncated_tail("record_body");
            if (!emitted_close && cbs.on_session_close) {
                SessionCloseInfo sc{1, "truncated_tail"};
                cbs.on_session_close(sc);
            }
            return true;
        }
        uint8_t rec = buf[0];
        // Record header layout: rec(1) + seq(8) + ts_ns(8) + body. seq stays
        // unused at this layer (replayer reuses ExecRequest order as its own
        // seq), but ts_ns is now plumbed into ExecutingEvent so the
        // strict-equivalence replay can pace by per-proc start cadence.
        const uint64_t rec_ts_ns = ReadU64(buf.data() + 9);
        const uint8_t* body = buf.data() + 17;
        size_t body_len = rec_size - 17;

        if (emitted_close) {
            std::fprintf(stderr, "trace_reader: %s: record after session_close\n",
                         seed.file_path.c_str());
            return false;
        }

        switch (rec) {
        case kRecSessionOpen: {
            if (emitted_open || body_len < 8 + 4 + 4 + 2) return false;
            SessionInfo si = enriched;
            si.session_id = ReadU64(body);
            si.vm_index   = ReadU32(body + 8);
            si.proxy_pid  = ReadU32(body + 12);
            uint16_t addr_len = ReadU16(body + 16);
            if (18 + static_cast<size_t>(addr_len) != body_len) return false;
            si.manager_addr.assign(reinterpret_cast<const char*>(body + 18), addr_len);
            emit_open_once(si);
            break;
        }
        case kRecFrameH2E: {
            // Emit session_open lazily if the file's first record was
            // already a frame (no session_open record present yet).
            if (!emitted_open) emit_open_once(enriched);
            std::vector<uint8_t> frame_body(body, body + body_len);
            ExecRequestEvent ev;
            ev.seq = ReadU64(buf.data() + 1);
            if (ExtractExecRequest(frame_body, ev)) {
                if (cbs.on_exec_request) cbs.on_exec_request(ev);
            }
            // Non-ExecRequest HostMessages (SignalUpdate / CorpusTriaged /
            // StateRequest) are not interesting to the replayer; drop.
            break;
        }
        case kRecFrameE2H: {
            // E2H frames are ExecutorMessages. Replayer uses Executing
            // timestamps for optional pacing; proc_id is diagnostic only.
            // ExecResult is consumed elsewhere.
            if (cbs.on_executing) {
                std::vector<uint8_t> frame_body(body, body + body_len);
                ExecutingEvent ev;
                if (ExtractExecuting(frame_body, ev)) {
                    ev.ts_ns = rec_ts_ns;
                    cbs.on_executing(ev);
                }
            }
            break;
        }
        case kRecDecodedSummary:
        case kRecTraceOverflow:
            break;
        case kRecSessionClose: {
            if (body_len < 3) return false;
            SessionCloseInfo sc;
            sc.reason = body[0];
            uint16_t msg_len = ReadU16(body + 1);
            if (3 + static_cast<size_t>(msg_len) != body_len) return false;
            sc.error_msg.assign(reinterpret_cast<const char*>(body + 3), msg_len);
            emitted_close = true;
            if (cbs.on_session_close) cbs.on_session_close(sc);
            break;
        }
        default:
            // Unknown record types ignored — schema is forward-compatible.
            break;
        }
    }
}

} // namespace refuzz::oracle::replayer
