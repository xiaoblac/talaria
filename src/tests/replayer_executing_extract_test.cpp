// replayer_executing_extract_test — locks in the trace_reader's E2H
// ExecutingMessage parsing path added in PR3 step 3.
//
// The test fabricates a small exec_trace_*.bin file in /tmp containing the
// required REFUZZTR header + a session_open record + several E2H frames
// carrying ExecutingMessageRaw payloads, then runs ReplayOneFile with an
// on_executing callback and verifies (req_id, proc_id, try_idx) round-trip
// for every record. Catches regressions in:
//   * kRecFrameE2H dispatch firing on_executing at all
//   * ExtractExecuting flatbuffer parse not mis-tagging ExecResult / State
//   * Trace record framing (size + seq + ts + body layout)

#include "tools/refuzz_exec_replayer/trace_reader.hpp"

#include "pkg/flatrpc/flatrpc.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace rep = refuzz::oracle::replayer;
// `rpc` is already a top-level namespace inside pkg/flatrpc/flatrpc.h; no
// alias needed.

namespace {

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                            \
        }                                                                        \
    } while (0)

constexpr const char* kTraceMagic = "REFUZZTR";

// Trace-file record opcodes (mirror trace_reader.cpp's anon-ns constants —
// kept locally since they're not exported).
constexpr uint8_t kRecSessionOpen      = 0x01;
constexpr uint8_t kRecFrameE2H         = 0x03;
constexpr uint8_t kRecSessionClose     = 0x04;

void WriteU16LE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v));
    buf.push_back(static_cast<uint8_t>(v >> 8));
}
void WriteU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
void WriteU64LE(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

// Build an E2H frame body = [u32 inner_size][flatbuffer ExecutorMessageRaw with
// msg = Executing(id=req_id, proc_id, try=try_idx, wait_duration=0)].
std::vector<uint8_t> BuildExecutingFrameBody(int64_t req_id, int32_t proc_id,
                                              int32_t try_idx) {
    flatbuffers::FlatBufferBuilder fbb;
    auto executing = rpc::CreateExecutingMessageRaw(
        fbb,
        req_id,
        proc_id,
        try_idx,
        /*wait_duration=*/0);
    auto wrapped = rpc::CreateExecutorMessageRaw(
        fbb,
        rpc::ExecutorMessagesRaw::Executing,
        executing.Union());
    fbb.Finish(wrapped);

    const uint8_t* payload = fbb.GetBufferPointer();
    const uint32_t payload_size = fbb.GetSize();

    std::vector<uint8_t> body;
    body.reserve(4 + payload_size);
    WriteU32LE(body, payload_size);
    body.insert(body.end(), payload, payload + payload_size);
    return body;
}

void WriteRecord(std::vector<uint8_t>& out, uint8_t rec, uint64_t seq,
                 const std::vector<uint8_t>& body) {
    std::vector<uint8_t> record;
    record.push_back(rec);
    WriteU64LE(record, seq);                       // monotonic_seq
    WriteU64LE(record, /*ts_ns=*/12345);            // ts placeholder
    record.insert(record.end(), body.begin(), body.end());

    WriteU32LE(out, static_cast<uint32_t>(record.size()));
    out.insert(out.end(), record.begin(), record.end());
}

bool WriteFabricatedTraceFile(const std::string& path,
                               const std::vector<rep::ExecutingEvent>& evs) {
    std::vector<uint8_t> buf;
    // 64-byte header: 8 magic + 4 version + 8 unix_ns + 44 git_rev (NULL-padded).
    // git_rev starts at offset 20 (trace_reader.cpp uses hdr+20), so it occupies
    // 64-20 = 44 bytes.
    buf.insert(buf.end(), kTraceMagic, kTraceMagic + 8);
    WriteU32LE(buf, /*version=*/1);
    WriteU64LE(buf, /*created_unix_ns=*/0);
    for (int i = 0; i < 44; ++i) buf.push_back(0);

    // session_open record: 8 session_id + 4 vm_index + 4 proxy_pid + 2 addr_len + addr.
    std::vector<uint8_t> so_body;
    WriteU64LE(so_body, /*session_id=*/777);
    WriteU32LE(so_body, /*vm_index=*/0);
    WriteU32LE(so_body, /*proxy_pid=*/123);
    WriteU16LE(so_body, /*manager_addr_len=*/0);
    WriteRecord(buf, kRecSessionOpen, /*seq=*/0, so_body);

    // E2H frames carrying ExecutingMessage.
    uint64_t seq = 1;
    for (const auto& ev : evs) {
        auto frame = BuildExecutingFrameBody(ev.req_id, ev.proc_id, ev.try_idx);
        WriteRecord(buf, kRecFrameE2H, seq++, frame);
    }

    // session_close record: 1 reason + 2 msg_len + msg.
    std::vector<uint8_t> sc_body;
    sc_body.push_back(0);  // reason=eof
    WriteU16LE(sc_body, 0);
    WriteRecord(buf, kRecSessionClose, seq++, sc_body);

    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return static_cast<bool>(f);
}

std::string TempPath(const char* suffix) {
    std::string p = "/tmp/refuzz_executing_extract_test_";
    p += suffix;
    p += "_";
    p += std::to_string(::getpid());
    p += ".bin";
    return p;
}

// Single Executing record round-trips through ReplayOneFile → on_executing.
int TestExtractsSingleExecutingRecord() {
    const auto path = TempPath("single");
    std::vector<rep::ExecutingEvent> input = {
        rep::ExecutingEvent{/*req_id=*/42, /*proc_id=*/5, /*try_idx=*/0},
    };
    CHECK(WriteFabricatedTraceFile(path, input));

    rep::SessionInfo si;
    si.file_path = path;

    std::vector<rep::ExecutingEvent> got;
    rep::TraceCallbacks cbs;
    cbs.on_executing = [&](const rep::ExecutingEvent& ev) { got.push_back(ev); };
    CHECK(rep::ReplayOneFile(si, cbs));

    CHECK(got.size() == 1);
    CHECK(got[0].req_id == 42);
    CHECK(got[0].proc_id == 5);
    CHECK(got[0].try_idx == 0);

    ::unlink(path.c_str());
    return 0;
}

// Multiple Executing records, different proc_ids — exercises the per-record
// dispatch loop, makes sure we don't lose state across frames.
int TestExtractsMultipleExecutingRecords() {
    const auto path = TempPath("multi");
    std::vector<rep::ExecutingEvent> input = {
        rep::ExecutingEvent{/*req_id=*/100, /*proc_id=*/0, /*try_idx=*/0},
        rep::ExecutingEvent{/*req_id=*/101, /*proc_id=*/3, /*try_idx=*/0},
        rep::ExecutingEvent{/*req_id=*/102, /*proc_id=*/7, /*try_idx=*/1},
        rep::ExecutingEvent{/*req_id=*/103, /*proc_id=*/3, /*try_idx=*/0},
    };
    CHECK(WriteFabricatedTraceFile(path, input));

    rep::SessionInfo si;
    si.file_path = path;
    std::vector<rep::ExecutingEvent> got;
    rep::TraceCallbacks cbs;
    cbs.on_executing = [&](const rep::ExecutingEvent& ev) { got.push_back(ev); };
    CHECK(rep::ReplayOneFile(si, cbs));

    CHECK(got.size() == 4);
    for (size_t i = 0; i < input.size(); ++i) {
        CHECK(got[i].req_id == input[i].req_id);
        CHECK(got[i].proc_id == input[i].proc_id);
        CHECK(got[i].try_idx == input[i].try_idx);
    }

    ::unlink(path.c_str());
    return 0;
}

// No on_executing callback set → ReplayOneFile must still process the file
// cleanly without dropping subsequent records. Guards against a regression
// where E2H dispatch would crash if cbs.on_executing is unset.
int TestNullCallbackIsHarmless() {
    const auto path = TempPath("null_cb");
    std::vector<rep::ExecutingEvent> input = {
        rep::ExecutingEvent{/*req_id=*/1, /*proc_id=*/0, /*try_idx=*/0},
    };
    CHECK(WriteFabricatedTraceFile(path, input));

    rep::SessionInfo si;
    si.file_path = path;
    bool saw_close = false;
    rep::TraceCallbacks cbs;
    // intentionally leave on_executing unset
    cbs.on_session_close = [&](const rep::SessionCloseInfo&) { saw_close = true; };
    CHECK(rep::ReplayOneFile(si, cbs));
    CHECK(saw_close);

    ::unlink(path.c_str());
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stderr, "replayer_executing_extract_test\n");
#define RUN(fn) \
    do { \
        std::fprintf(stderr, "  [RUN] %s\n", #fn); \
        if (fn() != 0) { std::fprintf(stderr, "  [FAIL] %s\n", #fn); return 1; } \
        std::fprintf(stderr, "  [PASS] %s\n", #fn); \
    } while (0)
    RUN(TestExtractsSingleExecutingRecord);
    RUN(TestExtractsMultipleExecutingRecords);
    RUN(TestNullCallbackIsHarmless);
#undef RUN
    std::fprintf(stderr, "OK\n");
    return 0;
}
