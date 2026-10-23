// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 7 PR-4 — KernelThreadPool smoke test.
//
// 不依赖 /sys/kernel/debug/kcov: 用 StubKcovCollectorProvider 返回 nullptr,
// 让 worker thread 内的 collector 路径全走 graceful no-op(Begin/Reset/
// Collect/End 全跳过)。这样可以纯 unit 验证 thread pool 的状态机、调度、
// timeout、reuse、drain 流程 — 在没有 KCOV 设备的 CI 环境也能跑。
//
// Cases:
//   1. BasicScheduleAndWait     — ScheduleCall + WaitCallDone 写 output
//   2. SequentialReuseOneThread — 同 tid 跑两条 call,thread 复用
//   3. ParallelTwoThreads       — tid 0 + tid 1 各一条 call
//   4. TimeoutLeaksThread       — dispatcher sleep > 100ms,WaitCallDone(50ms)
//                                  返 false;后续 ScheduleCall 该 tid 失败
//   5. EndTaskAllUsedDrainsEmpty— 无 kcov → drained 空 vector,but 调用安全
//   6. FaultInjectFnTraversesWorker — mock inject_fault 在 worker thread 内被调
//   7. TimeoutCanBePolledLater  — timeout 后 caller 可再 WaitCallDone(0)
//                                  ack 完成并复用 tid

#include "refuzz/program/syz/pseudo/limits.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"
#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/fault_inject.hpp"
#include "worker/driver/kernel_thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
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

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace worker = ::refuzz::worker;

class StubKcovProvider final : public worker::IKcovCollectorProvider {
public:
    explicit StubKcovProvider(int n) : n_(n) {}
    worker::KcovCollector* GetCollector(int /*tid*/) override { return nullptr; }
    int ThreadCount() const override { return n_; }
private:
    int n_;
};

class InvalidInheritedKcovProvider final
    : public worker::IKcovCollectorProvider {
public:
    InvalidInheritedKcovProvider()
        : collector_(1024, false,
                     worker::KcovChildMode::kInheritedFromLoop)
    {}

    worker::KcovCollector* GetCollector(int tid) override {
        return tid == 0 ? &collector_ : nullptr;
    }
    int ThreadCount() const override { return 1; }

private:
    worker::KcovCollector collector_;
};

class RecordingDispatcher final : public worker::IDispatcher {
public:
    static constexpr uint32_t kMaxArgs = ::refuzz::fuzzer::syz::kSyzMaxArgs;

    struct CallRecord {
        uint64_t nr = 0;
        uint32_t argc = 0;
        intptr_t args[kMaxArgs] = {};
    };

    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        CallRecord rec{};
        rec.nr = nr;
        rec.argc = argc;
        for (uint32_t i = 0; i < argc && i < kMaxArgs; ++i) {
            rec.args[i] = args[i];
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            records_.push_back(rec);
        }
        calls.fetch_add(1, std::memory_order_relaxed);
        if (sleep_ms_ > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms_));
        }
        return worker::PseudoResult{ret_, err_, nullptr};
    }
    const char* Name() const override { return "recording"; }

    std::atomic<int> calls{0};
    intptr_t ret_{0};
    int      err_{0};
    int      sleep_ms_{0};

    CallRecord LastRecord() const
    {
        std::lock_guard<std::mutex> lk(mu_);
        CHECK(!records_.empty());
        return records_.back();
    }

    bool SawNr(uint64_t nr) const
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& rec : records_) {
            if (rec.nr == nr) {
                return true;
            }
        }
        return false;
    }

private:
    mutable std::mutex mu_;
    std::vector<CallRecord> records_;
};

// Fault-inject mocks — fn-ptr trampolines (cannot capture, so use globals).
int  g_inject_fault_calls = 0;
int  g_inject_fault_last_nth = -1;
int  g_inject_fault_return = -1;          // -1 = skip; >=0 = fake fd
bool g_fault_injected_return = false;
int  g_fault_injected_calls = 0;
std::thread::id g_inject_fault_thread{};
std::thread::id g_fault_injected_thread{};

int MockInjectFault(int nth) {
    ++g_inject_fault_calls;
    g_inject_fault_last_nth = nth;
    g_inject_fault_thread = std::this_thread::get_id();
    return g_inject_fault_return;
}
bool MockFaultInjected(int /*fd*/) {
    ++g_fault_injected_calls;
    g_fault_injected_thread = std::this_thread::get_id();
    return g_fault_injected_return;
}
void ResetFaultMockState() {
    g_inject_fault_calls = 0;
    g_inject_fault_last_nth = -1;
    g_inject_fault_return = -1;
    g_fault_injected_return = false;
    g_fault_injected_calls = 0;
    g_inject_fault_thread = {};
    g_fault_injected_thread = {};
}

// ---- Tests --------------------------------------------------------

void TestBasicScheduleAndWait()
{
    ResetFaultMockState();
    StubKcovProvider provider(2);
    RecordingDispatcher disp;
    disp.ret_ = 42;
    disp.err_ = 0;

    worker::KernelThreadPool pool(
        /*size*/ 2,
        &provider,
        &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget,
        /*proc_slot_id*/ 0,
        &MockInjectFault,
        &MockFaultInjected);

    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0;
    in.call_nr    = 100;
    in.argc       = 2;
    in.args[0]    = 11;
    in.args[1]    = 22;
    CHECK(pool.ScheduleCall(0, in));

    worker::WorkerThreadOutput out{};
    const bool done = pool.WaitCallDone(
        0, std::chrono::milliseconds(1000), &out);
    CHECK(done);
    CHECK(out.ret == 42);
    CHECK(out.err == 0);
    CHECK(out.per_call_cov_size == 0);  // no kcov provider
    CHECK(disp.calls.load() == 1);
    const auto rec = disp.LastRecord();
    CHECK(rec.nr == 100);
    CHECK(rec.argc == 2);
    CHECK(rec.args[0] == 11);
    CHECK(rec.args[1] == 22);

    pool.EndTaskAllUsed();
}

void TestInheritedKcovFailureStopsBeforeDispatch()
{
    ResetFaultMockState();
    InvalidInheritedKcovProvider provider;
    RecordingDispatcher dispatcher;
    worker::KernelThreadPool pool(
        1, &provider, &dispatcher,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput input{};
    input.call_nr = 100;
    CHECK(pool.ScheduleCall(0, input));
    worker::WorkerThreadOutput output{};
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &output));
    CHECK(output.kcov_failed);
    CHECK(dispatcher.calls.load(std::memory_order_relaxed) == 0);
    pool.EndTaskAllUsed();
}

void TestSequentialReuseOneThread()
{
    ResetFaultMockState();
    StubKcovProvider provider(1);
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        1, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    for (int i = 0; i < 3; ++i) {
        worker::WorkerThreadInput in{};
        in.call_index = i;
        in.call_nr    = static_cast<uint64_t>(200 + i);
        in.argc       = 0;
        CHECK(pool.ScheduleCall(0, in));
        worker::WorkerThreadOutput out;
        CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &out));
    }
    CHECK(disp.calls.load() == 3);
    CHECK(disp.LastRecord().nr == 202);  // last call's nr

    pool.EndTaskAllUsed();
}

void TestParallelTwoThreads()
{
    ResetFaultMockState();
    StubKcovProvider provider(2);
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        2, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput a{};
    a.call_index = 0; a.call_nr = 300; a.argc = 0;
    worker::WorkerThreadInput b{};
    b.call_index = 1; b.call_nr = 301; b.argc = 0;
    CHECK(pool.ScheduleCall(0, a));
    CHECK(pool.ScheduleCall(1, b));

    worker::WorkerThreadOutput oa, ob;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &oa));
    CHECK(pool.WaitCallDone(1, std::chrono::milliseconds(500), &ob));
    CHECK(disp.calls.load() == 2);
    CHECK(disp.SawNr(300));
    CHECK(disp.SawNr(301));
    CHECK(pool.ThreadUsedInLastTask(0));
    CHECK(pool.ThreadUsedInLastTask(1));

    pool.EndTaskAllUsed();
}

void TestTimeoutLeaksThread()
{
    ResetFaultMockState();
    StubKcovProvider provider(2);
    RecordingDispatcher disp;
    disp.sleep_ms_ = 200;  // dispatch 比 wait timeout 长
    worker::KernelThreadPool pool(
        2, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0; in.call_nr = 400; in.argc = 0;
    CHECK(pool.ScheduleCall(0, in));

    worker::WorkerThreadOutput out;
    const bool done = pool.WaitCallDone(
        0, std::chrono::milliseconds(50), &out);
    CHECK(!done);  // timeout — thread 仍 busy

    // 后续 ScheduleCall 该 tid 应失败(state != kIdle)。
    worker::WorkerThreadInput in2{};
    in2.call_index = 1; in2.call_nr = 401; in2.argc = 0;
    CHECK(!pool.ScheduleCall(0, in2));

    // tid=1 仍可用。
    CHECK(pool.ScheduleCall(1, in2));
    worker::WorkerThreadOutput out2;
    CHECK(pool.WaitCallDone(1, std::chrono::milliseconds(500), &out2));

    // 等 leaked thread 自己跑完(避免析构时 join 卡死)。
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    pool.EndTaskAllUsed();

    // 关键 invariant:timed-out worker 即使后来跑完进入 kDone,
    // EndTaskAllUsed 也不能 ack 成 idle;否则 KCOV session 会跨 task 复用。
    worker::WorkerThreadInput in3{};
    in3.call_index = 2; in3.call_nr = 402; in3.argc = 0;
    CHECK(!pool.ScheduleCall(0, in3));
    CHECK(pool.ScheduleCall(1, in3));
    worker::WorkerThreadOutput out3;
    CHECK(pool.WaitCallDone(1, std::chrono::milliseconds(500), &out3));
}

void TestEndTaskAllUsedDrainsEmpty()
{
    ResetFaultMockState();
    StubKcovProvider provider(2);
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        2, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0; in.call_nr = 500; in.argc = 0;
    CHECK(pool.ScheduleCall(0, in));
    worker::WorkerThreadOutput out;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &out));

    pool.EndTaskAllUsed();

    auto drained = pool.TakeThreadDrained(0);
    CHECK(drained.empty());  // no kcov collector → no drain entries
    CHECK(pool.TakeThreadDrained(1).empty());  // tid=1 was never used

    // 跨 task 复用:再 StartTask 一次,used flag 应清零。
    pool.StartTask(worker::KcovMode::kPc);
    CHECK(!pool.ThreadUsedInLastTask(0));
    CHECK(!pool.ThreadUsedInLastTask(1));
}

void TestTimeoutCanBePolledLater()
{
    ResetFaultMockState();
    StubKcovProvider provider(1);
    RecordingDispatcher disp;
    disp.sleep_ms_ = 80;
    worker::KernelThreadPool pool(
        1, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0;
    in.call_nr = 700;
    CHECK(pool.ScheduleCall(0, in));

    worker::WorkerThreadOutput out;
    CHECK(!pool.IsCallDone(0));
    CHECK(!pool.WaitCallDone(0, std::chrono::milliseconds(10), &out));
    CHECK(!pool.ScheduleCall(0, in));

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    CHECK(pool.IsCallDone(0));
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(0), &out));
    CHECK(!pool.IsCallDone(0));
    CHECK(out.ret == 0);

    worker::WorkerThreadInput in2{};
    in2.call_index = 1;
    in2.call_nr = 701;
    CHECK(pool.ScheduleCall(0, in2));
    worker::WorkerThreadOutput out2;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(200), &out2));

    pool.EndTaskAllUsed();
}

void TestScheduleRejectsTidWithoutKcovSlot()
{
    ResetFaultMockState();
    StubKcovProvider provider(1);
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        3, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0;
    in.call_nr = 800;
    CHECK(pool.ScheduleCall(0, in));
    CHECK(!pool.ScheduleCall(1, in));
    CHECK(!pool.ScheduleCall(2, in));

    worker::WorkerThreadOutput out;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &out));
    pool.EndTaskAllUsed();
}

void TestFaultInjectFnTraversesWorker()
{
    ResetFaultMockState();
    const auto main_thread = std::this_thread::get_id();
    g_inject_fault_return   = 99;     // fake fd
    g_fault_injected_return = true;

    StubKcovProvider provider(1);
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        1, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);
    pool.StartTask(worker::KcovMode::kPc);

    worker::WorkerThreadInput in{};
    in.call_index = 0;
    in.call_nr    = 600;
    in.argc       = 0;
    in.fail_nth   = 3;  // > 0 → worker 调 inject_fault

    CHECK(pool.ScheduleCall(0, in));
    worker::WorkerThreadOutput out;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &out));

    CHECK(g_inject_fault_calls == 1);
    CHECK(g_inject_fault_last_nth == 3);
    CHECK(g_fault_injected_calls == 1);
    CHECK(g_inject_fault_thread != main_thread);
    CHECK(g_fault_injected_thread != main_thread);
    CHECK(g_inject_fault_thread == g_fault_injected_thread);
    CHECK(out.fault_injected);

    pool.EndTaskAllUsed();
}

// [lazy init — 对齐 syzkaller 固定 thread_t[32] + 懒初始化] 池起始 0 个 worker;
// 只有被 ScheduleCall 的 tid 才构造;调度前设的 Set*AllThreads 配置必须到达
// 懒构造的 worker;有空槽时全-worker 遍历/索引访问器都安全。
void TestLazyWorkerConstruction()
{
    ResetFaultMockState();
    StubKcovProvider provider(4);   // tids 0..3 有 kcov slot,可调度
    RecordingDispatcher disp;
    worker::KernelThreadPool pool(
        /*size*/ 32, &provider, &disp,
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 0,
        &MockInjectFault, &MockFaultInjected);

    // 1) 新池:32 个逻辑槽,0 个已构造。
    CHECK(pool.Size() == 32);
    CHECK(pool.ConstructedWorkerCountForTesting() == 0);

    // 2) 调度前设 per-thread 配置:不应强制构造任何 worker。
    uint32_t loop_mask = 0;
    pool.SetLoopDevicesUsedMaskCursorAllThreads(&loop_mask);
    pool.SetDeferMountTeardownAllThreads(true);
    CHECK(pool.ConstructedWorkerCountForTesting() == 0);

    pool.StartTask(worker::KcovMode::kPc);

    // 3) 只跑 tid 0 和 tid 2 → 只构造这两个,不是 32。
    worker::WorkerThreadInput in{};
    in.call_index = 0; in.call_nr = 900; in.argc = 0;
    CHECK(pool.ScheduleCall(0, in));
    in.call_index = 1; in.call_nr = 902; in.argc = 0;
    CHECK(pool.ScheduleCall(2, in));

    worker::WorkerThreadOutput out;
    CHECK(pool.WaitCallDone(0, std::chrono::milliseconds(500), &out));
    CHECK(pool.WaitCallDone(2, std::chrono::milliseconds(500), &out));

    CHECK(pool.ConstructedWorkerCountForTesting() == 2);  // 关键:不是 32
    CHECK(disp.calls.load() == 2);

    // 4) 调度前的配置到达了懒构造的 worker。
    CHECK(pool.WorkerDeferMountTeardownForTesting(0));
    CHECK(pool.WorkerDeferMountTeardownForTesting(2));

    // 5) 从未调度的 tid:null-guard 的访问器返回安全默认,不崩。
    CHECK(!pool.ThreadUsedInLastTask(1));
    CHECK(pool.TakeThreadDrained(1).empty());
    CHECK(!pool.WorkerDeferMountTeardownForTesting(1));

    // 6) 有空槽时,全-worker 遍历(EndTaskAllUsed / TakeAggregatedLoopMask)安全,
    //    且不会顺手构造新 worker。
    pool.EndTaskAllUsed();
    (void)pool.TakeAggregatedLoopMask();
    CHECK(pool.ConstructedWorkerCountForTesting() == 2);
}

}  // namespace

int main()
{
    RUN_TEST(TestBasicScheduleAndWait);
    RUN_TEST(TestInheritedKcovFailureStopsBeforeDispatch);
    RUN_TEST(TestSequentialReuseOneThread);
    RUN_TEST(TestParallelTwoThreads);
    RUN_TEST(TestTimeoutLeaksThread);
    RUN_TEST(TestEndTaskAllUsedDrainsEmpty);
    RUN_TEST(TestTimeoutCanBePolledLater);
    RUN_TEST(TestScheduleRejectsTidWithoutKcovSlot);
    RUN_TEST(TestFaultInjectFnTraversesWorker);
    RUN_TEST(TestLazyWorkerConstruction);
    std::fprintf(stderr, "kernel_thread_pool_smoke_test: ALL OK\n");
    return 0;
}
