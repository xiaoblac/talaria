// Smoke test for the libaco stackful-coroutine Job runtime (control/src/job/job.cpp).
//
// Drives Job through its control-side interface exactly as FuzzerLoop does
// (Launch / TakePendingRequest / Deliver / ResumeAfterEmit / CancelAndJoin /
// JoinDone / TakeRetains) and asserts the coroutine handoff behaves like the
// old thread version:
//   1. exec() round-trips a value and preserves straight-line control flow
//   2. cancellation mid-exec returns {cancelled} and lets RAII unwind the body
//   3. emit() is fire-and-forget and resumes without a result
//   4. thousands of jobs suspend simultaneously on ONE thread / ONE shared stack
//   5. a job that never yields completes immediately at Launch
//   6. retains run on normal completion but not on cancellation (invariant #8)
//
// Job's control-side methods are private (friend FuzzerLoop); the test reaches
// them through the JobTestAccess friend seam declared in job_scheduler.hpp.

#include "refuzz/control/job/job_scheduler.hpp"

#include <cassert>
#include <cstdio>
#include <functional>
#include <memory>
#include <stdexcept>
#include <vector>

namespace refuzz::control::job {
// Friend seam: thin forwarders to Job's private control-side interface.
struct JobTestAccess {
    static void Launch(Job& j) { j.Launch(); }
    static bool Suspended(const Job& j) { return j.SuspendedWithRequest(); }
    static bool PendingIsEmit(const Job& j) { return j.PendingIsEmit(); }
    static Request TakeReq(Job& j) { return j.TakePendingRequest(); }
    static OnSubmitted TakeOnSub(Job& j) { return j.TakePendingOnSubmitted(); }
    static OnCompleted TakeOnComp(Job& j) { return j.TakePendingOnCompleted(); }
    static void Deliver(Job& j, ExecResult r) { j.Deliver(std::move(r)); }
    static void ResumeAfterEmit(Job& j) { j.ResumeAfterEmit(); }
    static bool Done(const Job& j) { return j.Done(); }
    static void CancelAndJoin(Job& j) { j.CancelAndJoin(); }
    static void JoinDone(Job& j) { j.JoinDone(); }
    static std::vector<std::function<void()>> TakeRetains(Job& j) { return j.TakeRetains(); }
};
}  // namespace refuzz::control::job

using refuzz::control::job::ExecResult;
using refuzz::control::job::Job;
using refuzz::control::job::JobContext;
using refuzz::control::job::Request;
using A = refuzz::control::job::JobTestAccess;

static void test_exec_round_trip() {
    std::vector<int> trace;
    Job job(1, [&](JobContext& ctx) {
        trace.push_back(10);
        ExecResult r1 = ctx.exec(Request{});
        assert(!r1.cancelled);
        assert(r1.exec_status == 42);
        trace.push_back(20);
        ExecResult r2 = ctx.exec(Request{});
        assert(!r2.cancelled);
        assert(r2.exec_status == 43);
        trace.push_back(30);
    });

    A::Launch(job);                      // runs to first exec() (yield)
    assert(!A::Done(job));
    assert(A::Suspended(job));
    (void)A::TakeReq(job);
    ExecResult d1; d1.exec_status = 42;
    A::Deliver(job, std::move(d1));       // resume → second exec()
    assert(!A::Done(job));
    assert(A::Suspended(job));
    (void)A::TakeReq(job);
    ExecResult d2; d2.exec_status = 43;
    A::Deliver(job, std::move(d2));       // resume → completion
    assert(A::Done(job));
    A::JoinDone(job);

    assert((trace == std::vector<int>{10, 20, 30}));
    std::printf("[ok] exec round-trip preserves control flow + values\n");
}

static void test_cancel_mid_exec() {
    bool cleaned = false;
    bool saw_cancel = false;
    bool reached_after = false;
    Job job(2, [&](JobContext& ctx) {
        struct Guard { bool* p; ~Guard() { *p = true; } } guard{&cleaned};
        ExecResult r = ctx.exec(Request{});
        if (r.cancelled) { saw_cancel = true; return; }  // must unwind, not re-exec
        reached_after = true;
    });

    A::Launch(job);
    assert(A::Suspended(job));
    (void)A::TakeReq(job);
    A::CancelAndJoin(job);                // resume w/ abort → exec returns {cancelled}

    assert(saw_cancel);
    assert(cleaned);          // RAII destructor ran during unwind
    assert(!reached_after);
    std::printf("[ok] cancel mid-exec returns {cancelled} + RAII unwind\n");
}

static void test_emit_fire_and_forget() {
    int emits = 0;
    Job job(3, [&](JobContext& ctx) {
        for (int i = 0; i < 3; ++i) {
            bool ok = ctx.emit(Request{});
            assert(ok);
            ++emits;
        }
    });

    A::Launch(job);                       // runs to first emit (yield)
    for (int i = 0; i < 3; ++i) {
        assert(A::Suspended(job));
        assert(A::PendingIsEmit(job));
        (void)A::TakeReq(job);
        (void)A::TakeOnSub(job);
        (void)A::TakeOnComp(job);
        A::ResumeAfterEmit(job);
    }
    assert(A::Done(job));
    A::JoinDone(job);
    assert(emits == 3);
    std::printf("[ok] emit fire-and-forget x3, ack-only resume\n");
}

// The memory-model money shot: N jobs all suspended at exec() at the same time,
// multiplexed onto ONE OS thread and ONE shared run-stack. In the old model this
// was N OS threads (8 MB stack each); here it is N tiny copy-stacks.
static void test_many_concurrent_suspended() {
    const int N = 5000;
    std::vector<std::unique_ptr<Job>> jobs;
    jobs.reserve(N);
    int completed = 0;

    for (int i = 0; i < N; ++i) {
        jobs.push_back(std::make_unique<Job>(
            100 + i, [&completed](JobContext& ctx) {
                // touch some stack so each co has a non-trivial save buffer
                volatile char scratch[512];
                for (int k = 0; k < 512; ++k) scratch[k] = static_cast<char>(k);
                ExecResult r = ctx.exec(Request{});
                if (!r.cancelled && scratch[0] == 0) ++completed;
            }));
        A::Launch(*jobs.back());
        assert(A::Suspended(*jobs.back()));
    }
    // all N are suspended simultaneously; now deliver to each.
    for (auto& j : jobs) {
        (void)A::TakeReq(*j);
        ExecResult ok;  // exec_status kOk(0); job set scratch[0]=0 above
        A::Deliver(*j, std::move(ok));
        assert(A::Done(*j));
        A::JoinDone(*j);
    }
    assert(completed == N);
    std::printf("[ok] %d jobs suspended concurrently on one thread/stack\n", N);
}

static void test_immediate_completion() {
    bool ran = false;
    Job job(9, [&](JobContext&) { ran = true; });  // never yields
    A::Launch(job);                                // should run to completion
    assert(A::Done(job));
    assert(ran);
    A::JoinDone(job);
    std::printf("[ok] non-yielding job completes at Launch\n");
}

static void test_retains() {
    // normal completion → retain runs
    {
        int ran = 0;
        Job job(10, [&](JobContext& ctx) {
            ctx.retain([&ran] { ++ran; });
            ExecResult r = ctx.exec(Request{});
            (void)r;
        });
        A::Launch(job);
        (void)A::TakeReq(job);
        A::Deliver(job, ExecResult{});
        assert(A::Done(job));
        A::JoinDone(job);
        for (auto& a : A::TakeRetains(job)) a();  // FuzzerLoop::ReclaimJob does this
        assert(ran == 1);
    }
    // cancellation → retain dropped (invariant #8)
    {
        int ran = 0;
        Job job(11, [&](JobContext& ctx) {
            ctx.retain([&ran] { ++ran; });
            ExecResult r = ctx.exec(Request{});
            if (r.cancelled) return;
        });
        A::Launch(job);
        (void)A::TakeReq(job);
        A::CancelAndJoin(job);   // does NOT take/run retains
        assert(ran == 0);
    }
    std::printf("[ok] retains run on completion, dropped on cancel\n");
}

// #2 hardening: a MISBEHAVING job that re-execs AFTER cancellation must still tear
// down cleanly — the abort_ entry-check makes the second exec return {cancelled}
// without yielding again, so the co reaches is_end and RAII fully unwinds. Without
// the fix the second exec would yield, CancelAndJoin would aco_destroy a live co,
// and the guard destructor would NOT run.
static void test_reexec_after_cancel_is_safe() {
    bool cleaned = false;
    int exec_calls = 0;
    Job job(20, [&](JobContext& ctx) {
        struct Guard { bool* p; ~Guard() { *p = true; } } guard{&cleaned};
        ExecResult r1 = ctx.exec(Request{});
        ++exec_calls;
        ExecResult r2 = ctx.exec(Request{});  // invariant #9 violation on purpose
        ++exec_calls;
        assert(r1.cancelled && r2.cancelled);
    });
    A::Launch(job);
    assert(A::Suspended(job));
    (void)A::TakeReq(job);
    A::CancelAndJoin(job);     // must not hang/assert/leak
    assert(cleaned);           // RAII ran → co fully unwound
    assert(exec_calls == 2);   // second exec returned immediately, did not suspend
    std::printf("[ok] re-exec after cancel torn down cleanly (#2)\n");
}

// #3 hardening: a throwing job is caught at the coroutine boundary (fail-soft):
// process survives, job becomes Done, RAII runs. No logger/metric injected here, so
// it takes the stderr fallback (one line to stderr is expected).
static void test_throwing_job_is_failsoft() {
    bool cleaned = false;
    Job job(21, [&](JobContext&) {
        struct Guard { bool* p; ~Guard() { *p = true; } } guard{&cleaned};
        throw std::runtime_error("boom");
    });
    A::Launch(job);            // throws inside → caught in RunBody → Done
    assert(A::Done(job));
    assert(cleaned);           // RAII ran during unwind
    A::JoinDone(job);
    std::printf("[ok] throwing job caught fail-soft, process survives (#3)\n");
}

int main() {
    test_exec_round_trip();
    test_cancel_mid_exec();
    test_emit_fire_and_forget();
    test_many_concurrent_suspended();
    test_immediate_completion();
    test_retains();
    test_reexec_after_cancel_is_safe();
    test_throwing_job_is_failsoft();
    std::printf("ALL OK\n");
    return 0;
}
