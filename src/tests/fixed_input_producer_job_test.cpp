// [fixed request stream, Step 4] Gate 4 test for FixedInputProducerJob.
// docs/plans/fixed-request-stream-performance-replay.md
//
// Drives the job body exactly the way job_coroutine_smoke_test.cpp drives any
// other Job: through the JobTestAccess friend seam declared in
// job_scheduler.hpp, with no FuzzerLoop/Channel/VM involved. Asserts:
//   1. emitted request order matches the stream's record order, and each
//      request carries a typed artifact whose program re-encodes to the exact
//      canonical text the stream record held. This is Gate 4 under the v2
//      format: the stream stores canonical text, each side rebuilds its own
//      typed program and lowers it with its own encoder, so the invariant is
//      "same program", checked through the round-trip, not "same bytes"
//      (which would only re-assert that a memcpy copies);
//   2. the flatrpc -> domain ExecFlag translation is correct and drops what
//      it should;
//   3. the job drains the stream exactly once and does not self-respawn (no
//      more requests, no more retains) -- the stream is the sole task source;
//   4. on_fully_drained fires exactly once, only after EVERY emitted
//      request's completion has been observed, regardless of completion
//      order (Gate 4: "完成最后一条输入后等待全部已接收任务完成");
//   5. cancellation mid-stream unwinds safely and does not fire
//      on_fully_drained (shutdown teardown, not a normal drain).

#include "refuzz/control/job/fixed_input_producer_job.hpp"
#include "refuzz/control/job/job_scheduler.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/queue/task_tier.hpp"

#include <cassert>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace refuzz::control::job {
// Friend seam: thin forwarders to Job's private control-side interface.
// Mirrors tests/job_coroutine_smoke_test.cpp -- each test binary gets its own
// instantiation of this name, and Job's `friend struct JobTestAccess;`
// declaration grants access regardless of which translation unit defines it.
struct JobTestAccess {
    static void Launch(Job& j) { j.Launch(); }
    static bool Suspended(const Job& j) { return j.SuspendedWithRequest(); }
    static Request TakeReq(Job& j) { return j.TakePendingRequest(); }
    static OnSubmitted TakeOnSub(Job& j) { return j.TakePendingOnSubmitted(); }
    static OnCompleted TakeOnComp(Job& j) { return j.TakePendingOnCompleted(); }
    static void ResumeAfterEmit(Job& j) { j.ResumeAfterEmit(); }
    static bool Done(const Job& j) { return j.Done(); }
    static void CancelAndJoin(Job& j) { j.CancelAndJoin(); }
    static void JoinDone(Job& j) { j.JoinDone(); }
    static std::vector<std::function<void()>> TakeRetains(Job& j) { return j.TakeRetains(); }
};
}  // namespace refuzz::control::job

namespace rs = refuzz::request_stream;
using refuzz::control::FixedInputProducerJobDeps;
using refuzz::control::MakeFixedInputProducerJob;
using refuzz::control::job::ExecResult;
using refuzz::control::job::Job;
using refuzz::control::job::JobContext;
using refuzz::control::job::Request;
using A = refuzz::control::job::JobTestAccess;

namespace {

rs::RequestRecord MakeRecord(std::uint64_t seq, std::vector<std::uint8_t> prog_text,
                             std::uint64_t exec_flags = 0)
{
    rs::RequestRecord r;
    r.sequence = seq;
    r.exec_flags = exec_flags;
    r.prog_text = std::move(prog_text);
    return r;
}

// v2 records hold canonical syzlang text, so the fixture must be text the
// decoder actually accepts -- a synthetic byte blob would fail to rebuild and
// the producer would (correctly) refuse to emit it.
std::string TextFor(int i)
{
    // Distinct, order-identifying program per record: the argument varies, so a
    // reordering shows up as a text mismatch rather than passing silently.
    return "mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x"
           + std::to_string(i) + ")\n";
}

std::vector<std::uint8_t> TextBytesFor(int i)
{
    const std::string t = TextFor(i);
    return std::vector<std::uint8_t>(t.begin(), t.end());
}

// Re-encode the request's typed artifact back to canonical text.
std::string CanonicalTextOf(const Request& req)
{
    assert(req.artifact != nullptr);
    auto prog = req.artifact->As<refuzz::program::syz::Prog>();
    assert(prog != nullptr);
    refuzz::program::syz::TextEncoder enc(refuzz::program::syz::Target::linux_amd64());
    return enc.encode(*prog);
}

}  // namespace

static void test_sequence_order_and_flag_translation()
{
    // flatrpc.ExecFlagCollectComps = 1<<3, ExecFlagThreaded = 1<<4 (pkg/flatrpc/flatrpc.go).
    constexpr std::uint64_t kFlatRpcCollectComps = 1ULL << 3;
    constexpr std::uint64_t kFlatRpcThreaded     = 1ULL << 4;
    constexpr std::uint64_t kFlatRpcCollectSignal = 1ULL << 0;  // must NOT translate

    rs::RequestStream stream;
    stream.records.push_back(MakeRecord(0, TextBytesFor(0), 0));
    stream.records.push_back(MakeRecord(1, TextBytesFor(1), kFlatRpcCollectComps));
    stream.records.push_back(MakeRecord(2, TextBytesFor(2), kFlatRpcThreaded));
    stream.records.push_back(
        MakeRecord(3, TextBytesFor(3), kFlatRpcCollectComps | kFlatRpcThreaded));
    stream.records.push_back(MakeRecord(4, TextBytesFor(4), kFlatRpcCollectSignal));

    FixedInputProducerJobDeps deps;
    deps.stream = &stream;
    deps.exec_timeout_ms = 1234;

    Job job(1, [fn = MakeFixedInputProducerJob(std::move(deps))](JobContext& ctx) { fn(ctx); });
    A::Launch(job);

    const std::uint32_t kDomainCollectComps =
        static_cast<std::uint32_t>(::refuzz::proto::kExecFlagCollectComps);
    const std::uint32_t kDomainIntraThreaded =
        static_cast<std::uint32_t>(::refuzz::proto::kExecFlagIntraThreaded);
    const std::vector<std::uint32_t> expected_flags = {
        0, kDomainCollectComps, kDomainIntraThreaded,
        kDomainCollectComps | kDomainIntraThreaded, 0};

    for (std::size_t i = 0; i < stream.records.size(); ++i) {
        assert(A::Suspended(job));
        Request req = A::TakeReq(job);
        // Gate 4 (v2): the rebuilt program must be the captured program. Checked
        // by re-encoding, since the dispatched bytes are now reFuzz's own
        // lowering rather than a copy of the stream.
        assert(CanonicalTextOf(req) == TextFor(static_cast<int>(i)));
        assert(!req.payload.empty());
        assert(req.opts.timeout_ms == 1234);
        assert(req.opts.flags == expected_flags[i]);
        assert(req.tier == refuzz::queue::TaskTier::Candidate);
        (void)A::TakeOnSub(job);
        (void)A::TakeOnComp(job);
        A::ResumeAfterEmit(job);
    }
    assert(A::Done(job));
    A::JoinDone(job);
    std::printf("[ok] sequence order preserved, rebuilt program == captured program, "
               "ExecFlag translation correct (CollectSignal dropped)\n");
}

static void test_no_self_respawn_and_no_retain()
{
    rs::RequestStream stream;
    stream.records.push_back(MakeRecord(0, TextBytesFor(0)));
    stream.records.push_back(MakeRecord(1, TextBytesFor(1)));

    FixedInputProducerJobDeps deps;
    deps.stream = &stream;

    Job job(2, [fn = MakeFixedInputProducerJob(std::move(deps))](JobContext& ctx) { fn(ctx); });
    A::Launch(job);
    for (int i = 0; i < 2; ++i) {
        assert(A::Suspended(job));
        (void)A::TakeReq(job);
        (void)A::TakeOnSub(job);
        (void)A::TakeOnComp(job);
        A::ResumeAfterEmit(job);
    }
    // Unlike ExploreJob (which retains an on_done closure that respawns it),
    // this job must be fully Done with nothing pending and nothing retained --
    // the stream is a ONE-SHOT sole task source (plan §6.2).
    assert(A::Done(job));
    assert(!A::Suspended(job));
    A::JoinDone(job);
    assert(A::TakeRetains(job).empty());
    std::printf("[ok] drains exactly once, no self-respawn, no retained continuation\n");
}

static void test_drain_signal_fires_once_after_all_completions_out_of_order()
{
    rs::RequestStream stream;
    for (int i = 0; i < 3; ++i) {
        stream.records.push_back(MakeRecord(static_cast<std::uint64_t>(i), TextBytesFor(i)));
    }

    int drained_calls = 0;
    FixedInputProducerJobDeps deps;
    deps.stream = &stream;
    deps.on_fully_drained = [&drained_calls] { ++drained_calls; };

    Job job(3, [fn = MakeFixedInputProducerJob(std::move(deps))](JobContext& ctx) { fn(ctx); });
    A::Launch(job);

    std::vector<refuzz::control::job::OnCompleted> completions;
    for (int i = 0; i < 3; ++i) {
        assert(A::Suspended(job));
        (void)A::TakeReq(job);
        (void)A::TakeOnSub(job);
        completions.push_back(A::TakeOnComp(job));
        A::ResumeAfterEmit(job);
    }
    assert(A::Done(job));  // producer has emitted everything; still draining completions
    A::JoinDone(job);
    assert(drained_calls == 0);  // no completion delivered yet

    // Delivered out of order (2, 0, 1) -- on_fully_drained must be count-based,
    // not order-based, and must fire exactly once, only after the LAST one.
    completions[2](ExecResult{});
    assert(drained_calls == 0);
    completions[0](ExecResult{});
    assert(drained_calls == 0);
    completions[1](ExecResult{});
    assert(drained_calls == 1);

    std::printf("[ok] on_fully_drained fires exactly once, only after every "
               "emitted request's completion, regardless of completion order\n");
}

static void test_cancel_mid_stream_unwinds_without_signaling()
{
    rs::RequestStream stream;
    for (int i = 0; i < 5; ++i) {
        stream.records.push_back(MakeRecord(static_cast<std::uint64_t>(i), TextBytesFor(i)));
    }

    int drained_calls = 0;
    FixedInputProducerJobDeps deps;
    deps.stream = &stream;
    deps.on_fully_drained = [&drained_calls] { ++drained_calls; };

    Job job(4, [fn = MakeFixedInputProducerJob(std::move(deps))](JobContext& ctx) { fn(ctx); });
    A::Launch(job);

    // Emit + immediately complete the first two records normally.
    for (int i = 0; i < 2; ++i) {
        assert(A::Suspended(job));
        (void)A::TakeReq(job);
        (void)A::TakeOnSub(job);
        auto on_comp = A::TakeOnComp(job);
        A::ResumeAfterEmit(job);
        on_comp(ExecResult{});
    }
    assert(drained_calls == 0);  // only 2/5 done, producer hasn't finished iterating

    // Cancel while the job is suspended on its 3rd emit -- shutdown teardown,
    // not a normal drain. Must unwind cleanly (invariant #9: no re-emit after
    // cancellation) and must NOT fire on_fully_drained.
    assert(A::Suspended(job));
    (void)A::TakeReq(job);
    A::CancelAndJoin(job);
    assert(A::Done(job));
    assert(drained_calls == 0);
    std::printf("[ok] cancellation mid-stream unwinds cleanly, does not fire "
               "on_fully_drained\n");
}

int main()
{
    test_sequence_order_and_flag_translation();
    test_no_self_respawn_and_no_retain();
    test_drain_signal_fires_once_after_all_completions_out_of_order();
    test_cancel_mid_stream_unwinds_without_signaling();
    std::printf("ALL OK\n");
    return 0;
}
