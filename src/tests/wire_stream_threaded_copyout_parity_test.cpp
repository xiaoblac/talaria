// Copyright 2026 reFuzz project author -------youngkk.
//
// Threaded copyout-timing parity gate (S3).
//
// S3 moves the threaded path off the materialized WireProgram onto the
// streaming reader. The one subtle invariant it must preserve is the
// *deferred copyout* timing: a WireCopyout that follows a WireCall is applied
// only when that call completes, and a later call's WireResult must observe
// the value the copyout snapshotted. The materialized path recorded the
// trailing copyouts as instr-vector indices and replayed them on completion;
// the streaming path instead saves the wire cursor position right after the
// call's args and replays the copyouts from a fresh sub-reader (mirroring
// syzkaller executor.cc copyout_call_results reading th->copyout_pos).
//
// This test builds a producer→copyout→consumer chain by hand, drives it
// through the real KernelWireDriver, and asserts the consumer's dispatched
// arg equals the value the producer wrote into scratch — i.e. the copyout ran
// before the consumer resolved. It runs the SAME program through both the
// serial (verified streaming) and threaded paths and asserts they agree, so
// the threaded copyout replay is gated against the serial path directly.
//
// The threaded happy path (getpid-style, no copyouts) is already covered by
// kernel_wire_driver_threaded_smoke_test; this fills the resource-dependency
// gap that test leaves open.

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"       // serialize_for_exec
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/coverage/kcov_drain_sink.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/kernel_wire_driver.hpp"
#include "worker/exec_mode.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

namespace {

namespace syz = ::refuzz::program::syz;
namespace worker = ::refuzz::worker;

int g_failures = 0;

#define CHECK(expr)                                                          \
    do {                                                                     \
        if (!(expr)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #expr);                                             \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

// ---- Threaded-path plumbing (mirrors kernel_wire_driver_threaded_smoke) ----

class StubKcovProvider final : public worker::IKcovCollectorProvider {
public:
    explicit StubKcovProvider(int n) : n_(n) {}
    worker::KcovCollector* GetCollector(int /*tid*/) override { return nullptr; }
    int ThreadCount() const override { return n_; }
private:
    int n_;
};

class NullDrainSink final : public worker::IKcovDrainSink {
public:
    worker::KcovMode CurrentMode() const override { return worker::KcovMode::kPc; }
    void StartThreadedSession(worker::KcovMode) override {}
    void AppendThreadDrained(std::vector<std::uint64_t>) override {}
};

int  MockInjectFault(int /*nth*/) { return -1; }
bool MockFaultInjected(int /*fd*/) { return false; }

// Dispatcher that plays two roles keyed on the syscall nr:
//   - producer_nr: writes `writes[i]` (8 bytes) into *args[i] for each arg,
//     simulating a syscall that fills output memory the copyout will snapshot.
//   - consumer_nr: records args so the test can assert the resolved values.
// Order is deterministic here: the consumer is a non-async call scheduled after
// the producer, so the driver waits for the producer (applying its copyouts)
// before resolving the consumer's args.
class CopyoutChainDispatcher final : public worker::IDispatcher {
public:
    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        if (nr == producer_nr) {
            for (uint32_t i = 0; i < argc && i < writes.size(); ++i) {
                if (args[i] != 0) {
                    std::memcpy(reinterpret_cast<void*>(args[i]),
                                &writes[i], sizeof(uint64_t));
                }
            }
            return worker::PseudoResult{producer_ret, 0, nullptr};
        }
        if (nr == consumer_nr) {
            consumer_args.assign(args, args + argc);
            ++consumer_dispatches;
        }
        return worker::PseudoResult{0, 0, nullptr};
    }
    const char* Name() const override { return "copyout_chain"; }

    uint64_t producer_nr = 0;
    uint64_t consumer_nr = 0;
    intptr_t producer_ret = 0;
    std::vector<uint64_t> writes;
    std::vector<intptr_t> consumer_args;
    int consumer_dispatches = 0;
};

uint64_t CallId(const char* name) {
    const auto* meta = syz::Target::linux_amd64().find_syscall(name);
    CHECK(meta != nullptr);
    return meta ? meta->id() : 0;
}
uint64_t CallNr(const char* name) {
    const auto* meta = syz::Target::linux_amd64().find_syscall(name);
    CHECK(meta != nullptr);
    return meta ? meta->nr() : 0;
}

constexpr uint64_t kNoCopyout = ~uint64_t{0};

// Build: Producer(WireAddr×producer_addrs) + WireCopyout(idx,addr,8)×N +
//        Consumer(WireResult(idx)×N).
std::vector<uint8_t> BuildCopyoutChain(uint64_t producer_id,
                                       uint64_t consumer_id,
                                       const std::vector<uint64_t>& addrs,
                                       const std::vector<uint64_t>& idxs) {
    syz::WireProgram wp;
    wp.num_calls = 2;

    // Producer call: one WireAddr per scratch slot it fills.
    syz::WireCall producer;
    producer.call_id = producer_id;
    producer.copyout_idx = kNoCopyout;
    for (uint64_t a : addrs) {
        syz::WireAddr ptr;
        ptr.ptr_size = 8;
        ptr.addr = a;
        producer.args.emplace_back(ptr);
    }
    wp.instrs.emplace_back(std::move(producer));

    // Memory copyouts belonging to the producer (idx <- scratch[addr]).
    for (std::size_t i = 0; i < idxs.size(); ++i) {
        wp.instrs.emplace_back(
            syz::WireCopyout{idxs[i], addrs[i], /*size=*/8});
    }

    // Consumer call: one WireResult per produced resource.
    syz::WireCall consumer;
    consumer.call_id = consumer_id;
    consumer.copyout_idx = kNoCopyout;
    for (uint64_t idx : idxs) {
        syz::WireResult r;
        r.size = 8;
        r.idx = idx;
        r.op_div = 0;
        r.op_add = 0;
        r.default_val = 0xDEAD;  // must NOT appear if the copyout ran
        consumer.args.emplace_back(r);
    }
    wp.instrs.emplace_back(std::move(consumer));

    return syz::encode_wire_program(wp);
}

struct RunResult {
    int rc = 0;
    std::vector<intptr_t> consumer_args;
    int consumer_dispatches = 0;
};

RunResult RunChain(const std::vector<uint8_t>& bytes,
                   uint64_t producer_nr, uint64_t consumer_nr,
                   const std::vector<uint64_t>& writes,
                   bool threaded) {
    auto disp_owner = std::make_unique<CopyoutChainDispatcher>();
    disp_owner->producer_nr = producer_nr;
    disp_owner->consumer_nr = consumer_nr;
    disp_owner->writes = writes;
    auto* disp = disp_owner.get();

    StubKcovProvider provider(2);
    NullDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::move(disp_owner),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<uint8_t, 4096> output{};
    uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = threaded ? worker::IntraTaskMode::kThreaded
                          : worker::IntraTaskMode::kSerial;

    RunResult r;
    r.rc = driver.Execute(bytes.data(), static_cast<uint32_t>(bytes.size()),
                          output.data(), static_cast<uint32_t>(output.size()),
                          &output_len, mode);
    r.consumer_args = disp->consumer_args;
    r.consumer_dispatches = disp->consumer_dispatches;
    return r;
}

// ---- Tests ----------------------------------------------------------------

void TestSingleCopyoutResultThreadedMatchesSerial() {
    const uint64_t producer_id = CallId("read");
    const uint64_t consumer_id = CallId("write");
    const uint64_t producer_nr = CallNr("read");
    const uint64_t consumer_nr = CallNr("write");

    const std::vector<uint64_t> addrs = {0x100};
    const std::vector<uint64_t> idxs = {7};
    const std::vector<uint64_t> writes = {0x1122334455667788ULL};

    const auto bytes = BuildCopyoutChain(producer_id, consumer_id, addrs, idxs);

    auto serial = RunChain(bytes, producer_nr, consumer_nr, writes, false);
    auto threaded = RunChain(bytes, producer_nr, consumer_nr, writes, true);

    CHECK(serial.rc == 0);
    CHECK(threaded.rc == 0);
    CHECK(serial.consumer_dispatches == 1);
    CHECK(threaded.consumer_dispatches == 1);
    CHECK(serial.consumer_args.size() == 1);
    CHECK(threaded.consumer_args.size() == 1);
    // The consumer's WireResult must resolve to the copyout'd value, not the
    // default 0xDEAD — proving the copyout ran before the consumer resolved.
    CHECK(serial.consumer_args[0] ==
          static_cast<intptr_t>(0x1122334455667788ULL));
    CHECK(threaded.consumer_args[0] == serial.consumer_args[0]);
}

void TestMultiCopyoutResultThreadedMatchesSerial() {
    const uint64_t producer_id = CallId("read");
    const uint64_t consumer_id = CallId("write");
    const uint64_t producer_nr = CallNr("read");
    const uint64_t consumer_nr = CallNr("write");

    // Three contiguous copyouts after the producer; three consumer results.
    const std::vector<uint64_t> addrs = {0x100, 0x200, 0x300};
    const std::vector<uint64_t> idxs = {3, 4, 5};
    const std::vector<uint64_t> writes = {
        0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL, 0xCCCCCCCCCCCCCCCCULL};

    const auto bytes = BuildCopyoutChain(producer_id, consumer_id, addrs, idxs);

    auto serial = RunChain(bytes, producer_nr, consumer_nr, writes, false);
    auto threaded = RunChain(bytes, producer_nr, consumer_nr, writes, true);

    CHECK(serial.rc == 0);
    CHECK(threaded.rc == 0);
    CHECK(serial.consumer_args.size() == 3);
    CHECK(threaded.consumer_args.size() == 3);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(serial.consumer_args[i] == static_cast<intptr_t>(writes[i]));
        CHECK(threaded.consumer_args[i] == serial.consumer_args[i]);
    }
}

// ---- Corpus-driven serial-vs-threaded dispatch parity ---------------------
//
// Runs real resource-chain programs (copyin data blobs + return-value copyouts
// + WireResult consumers) through both the serial (verified streaming) and
// threaded paths, and asserts the dispatched (nr, args) sequence is identical.
// For non-async programs the threaded schedule is in-order and blocking, so any
// divergence in decode, arg resolution, or copyout timing shows up as a
// mismatched trace. The dispatcher returns a fixed non-negative fd so resource
// chains resolve deterministically in both paths.

struct CallRecord {
    uint64_t nr = 0;
    std::vector<intptr_t> args;
};

class RecordingDispatcher final : public worker::IDispatcher {
public:
    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        CallRecord rec;
        rec.nr = nr;
        rec.args.assign(args, args + argc);
        calls.push_back(std::move(rec));
        // Fixed non-negative "fd" so return-value copyouts apply (ret >= 0) and
        // resource chains resolve identically across both execution paths.
        return worker::PseudoResult{static_cast<intptr_t>(3), 0, nullptr};
    }
    const char* Name() const override { return "recording"; }
    std::vector<CallRecord> calls;
};

std::vector<uint8_t> DecodeAndSerialize(std::string_view text) {
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(text);
    CHECK(prog_or.has_value());
    if (!prog_or.has_value() || *prog_or == nullptr) return {};
    auto bytes_or = syz::serialize_for_exec(**prog_or);
    CHECK(bytes_or.has_value());
    if (!bytes_or.has_value()) return {};
    return std::move(*bytes_or);
}

struct TraceResult {
    int rc = 0;
    std::vector<CallRecord> calls;
};

TraceResult RunTrace(const std::vector<uint8_t>& bytes, bool threaded) {
    auto disp_owner = std::make_unique<RecordingDispatcher>();
    auto* disp = disp_owner.get();

    StubKcovProvider provider(2);
    NullDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::move(disp_owner),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<uint8_t, 8192> output{};
    uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = threaded ? worker::IntraTaskMode::kThreaded
                          : worker::IntraTaskMode::kSerial;

    TraceResult r;
    r.rc = driver.Execute(bytes.data(), static_cast<uint32_t>(bytes.size()),
                          output.data(), static_cast<uint32_t>(output.size()),
                          &output_len, mode);
    r.calls = disp->calls;
    return r;
}

void TestCorpusProgramsThreadedMatchesSerial() {
    // Resource chains with copyin data blobs, return-value copyouts, and
    // WireResult consumers — the constructs S3's copyout replay must preserve.
    const std::string_view programs[] = {
        // Resource chain: getpid's return value (a copyout) is consumed by
        // ptrace's second arg (a WireResult). This is the copyout→result
        // dependency S3 must keep, over a real decoded program.
        "r0 = getpid()\n"
        "ptrace(0x10, r0)\n",

        // Const args across several calls — arg-resolution parity.
        "close(0x3)\n"
        "close(0x4)\n"
        "close(0x5)\n",

        "getpid()\n"
        "getuid()\n"
        "getgid()\n",
    };

    for (std::string_view text : programs) {
        const auto bytes = DecodeAndSerialize(text);
        if (bytes.empty()) continue;  // CHECK already flagged the decode failure

        auto serial = RunTrace(bytes, /*threaded=*/false);
        auto threaded = RunTrace(bytes, /*threaded=*/true);

        CHECK(serial.rc == 0);
        CHECK(threaded.rc == 0);
        CHECK(serial.calls.size() == threaded.calls.size());
        const std::size_t nmin =
            std::min(serial.calls.size(), threaded.calls.size());
        for (std::size_t i = 0; i < nmin; ++i) {
            CHECK(serial.calls[i].nr == threaded.calls[i].nr);
            CHECK(serial.calls[i].args.size() == threaded.calls[i].args.size());
            const std::size_t amin = std::min(serial.calls[i].args.size(),
                                              threaded.calls[i].args.size());
            for (std::size_t a = 0; a < amin; ++a) {
                CHECK(serial.calls[i].args[a] == threaded.calls[i].args[a]);
            }
        }
    }
}

}  // namespace

int main() {
    TestSingleCopyoutResultThreadedMatchesSerial();
    TestMultiCopyoutResultThreadedMatchesSerial();
    TestCorpusProgramsThreadedMatchesSerial();
    if (g_failures != 0) {
        std::fprintf(stderr,
                     "wire_stream_threaded_copyout_parity_test: %d FAILURES\n",
                     g_failures);
        return 1;
    }
    std::fprintf(stderr, "wire_stream_threaded_copyout_parity_test: ALL OK\n");
    return 0;
}
