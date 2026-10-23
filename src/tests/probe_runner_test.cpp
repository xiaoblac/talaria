// [machine-check C4.2b] unit test for the trial-exec runner primitives.
//
//   BuildProbeTask        — produces the standard HostFuzzTask carrier
//                           (artifact-first, kSyzProg, executor_id + timeout),
//                           and the artifact lowers to exec-wire like the real
//                           Executor would.
//   DecodeProbeCompletion — reads the per-call errno block from a synthesized
//                           completion output buffer, aligned to the batch
//                           (order preserved, null metas skipped, ENOSYS errno
//                           surfaced raw — NOT interpreted).
//
// No VM/channel: the task builder uses the real linux/amd64 Target; the decoder
// is fed a hand-built SyzExecResult[] buffer (exactly what Completion.output
// carries at its head). The live submit/drain is integration-tested with C4.6.

#include "refuzz/control/support/machine_check/probe_runner.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"  // CreateSyzV2Materializer
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/syz_exec_runner.hpp"  // SyzExecResult, kCallFlag*

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace mc  = ::refuzz::control::support::machine_check;
namespace syz = ::refuzz::program::syz;

// Build a Completion-style output buffer from a list of SyzExecResult records
// (this is exactly the head layout the worker writes / Completion.output holds).
std::vector<std::uint8_t> MakeOutput(
    const std::vector<refuzz::worker::SyzExecResult>& recs) {
    std::vector<std::uint8_t> out(recs.size() *
                                  sizeof(refuzz::worker::SyzExecResult));
    if (!recs.empty()) {
        std::memcpy(out.data(), recs.data(), out.size());
    }
    return out;
}

refuzz::worker::SyzExecResult Rec(int err, std::int64_t ret, bool executed) {
    refuzz::worker::SyzExecResult r;
    r.err   = err;
    r.ret   = ret;
    // A finished probe call sets Executed|Finished; the decode trusts the errno
    // only when Finished is set (a blocked, un-finished call carries a sentinel).
    r.flags = executed
                  ? (refuzz::worker::kCallFlagExecuted | refuzz::worker::kCallFlagFinished)
                  : 0u;
    return r;
}

} // namespace

int main() {
    const auto& t = syz::Target::linux_amd64();

    // Collect 3 real, generatable syscalls (no name assumptions).
    std::vector<const syz::SyscallMeta*> calls;
    for (const auto& sc : t.syscalls()) {
        if (calls.size() >= 3) break;
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        calls.push_back(sc.get());
    }
    CHECK(calls.size() == 3);

    // ---- BuildProbeTask: standard data-plane carrier ----
    auto task = mc::BuildProbeTask(t, calls, /*executor_id=*/7, /*timeout_ms=*/1234);
    CHECK(task.executor_id == 7);
    CHECK(task.opts.timeout_ms == 1234);
    CHECK(task.artifact.valid());
    CHECK(task.artifact.format() == refuzz::fuzzer::ProgFormat::kSyzProg);

    auto pv = task.artifact.As<syz::Prog>();
    CHECK(pv != nullptr);
    CHECK(pv->calls().size() == calls.size());
    for (std::size_t i = 0; i < calls.size(); ++i) {
        CHECK(pv->calls()[i]->meta() == calls[i]);  // order preserved
    }

    // The artifact lowers to exec-wire exactly as the Executor would at submit.
    auto materializer = syz::CreateSyzV2Materializer();
    auto wire = materializer->LowerToExecWire(task.artifact);
    CHECK(wire.has_value());
    CHECK(!wire->empty());

    // ---- DecodeProbeCompletion: per-call errno, raw (not interpreted) ----
    std::vector<refuzz::worker::SyzExecResult> recs = {
        Rec(/*err=*/0,  /*ret=*/5,  /*executed=*/true),   // ok
        Rec(/*err=*/38, /*ret=*/-1, /*executed=*/true),   // ENOSYS surfaced raw
        Rec(/*err=*/1,  /*ret=*/-1, /*executed=*/false),  // never reached
    };
    auto results = mc::DecodeProbeCompletion(MakeOutput(recs), calls);
    CHECK(results.size() == 3);
    CHECK(results[0].meta == calls[0] && results[0].executed && results[0].err == 0 &&
          results[0].ret == 5);
    CHECK(results[1].meta == calls[1] && results[1].executed && results[1].err == 38);
    CHECK(results[2].meta == calls[2] && !results[2].executed && results[2].err == 1);

    // null-skip alignment: {c0, null, c1} → 2 results aligned to c0, c1.
    std::vector<const syz::SyscallMeta*> with_null = {calls[0], nullptr, calls[1]};
    std::vector<refuzz::worker::SyzExecResult> recs2 = {
        Rec(11, -1, true),
        Rec(22, -1, true),
    };
    auto r2 = mc::DecodeProbeCompletion(MakeOutput(recs2), with_null);
    CHECK(r2.size() == 2);
    CHECK(r2[0].meta == calls[0] && r2[0].err == 11);
    CHECK(r2[1].meta == calls[1] && r2[1].err == 22);

    // empty/short output → every entry executed=false (caller treats as unknown).
    auto r3 = mc::DecodeProbeCompletion({}, calls);
    CHECK(r3.size() == 3);
    for (const auto& r : r3) {
        CHECK(!r.executed);
    }

    std::fprintf(stdout, "probe_runner_test ALL PASS (wire=%zu bytes)\n",
                 wire->size());
    return 0;
}
