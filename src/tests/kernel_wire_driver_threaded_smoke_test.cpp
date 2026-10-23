// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 7 PR-5 — KernelWireDriver threaded smoke test.
//
// 不依赖真 KCOV:用 stub IKcovCollectorProvider 声明 slot 数并返回 nullptr,
// worker thread 内 collector 路径 graceful no-op。validate:
//   1. mode.intra == kThreaded + thread_count > 1 + provider/drain_sink set
//      → 不再 -1,results layout 正常
//   2. mode.intra == kThreaded + thread_count == 1 → -1 (KernelThreadPool
//      不构造)
//   3. mode.intra == kThreaded + provider == nullptr → -1
//   3b. mode.intra == kThreaded + kcov slots < thread_count is accepted
//       until the actual workload needs more concurrent coverage slots.
//   4. drain_sink->StartThreadedSession + AppendThreadDrained 被调到位
//   5. threaded path 继承 IKcovDrainSink::CurrentMode() 的 PC/CMP 选择
//   6. mode.intra == kSerial 路径在 thread_count > 1 driver 下仍走 serial
//      fast path (回归保护)
//   7. [Epic 7 PR-7] 含 pseudo 的 program threaded path **不再** pre-flight
//      reject (对齐 upstream syzkaller — worker thread per-thread ctx 已消除
//      ctx race;kernel-side race 是 fuzz 目标)
//   8. async call 不 wait,下一条 call 可并发进入 dispatcher
//   9. never-completing non-async call (overruns even the end-drain deadline)
//      在 task end 写 Executed-only slot + errno=ENOSYS,不留 zero-init flags=0
//      tail (mirrors syzkaller write_call_output(false))
//  10. [threaded end-drain parity] non-async call 超 per-call wait 但在 end-drain
//      deadline 内背景完成 → 当作正常完成收 (Executed|Finished, 真 errno),
//      不是 #9 的 ENOSYS never-completer slot。coverage 那半(drain 收完整
//      per_call_cov)靠 exec-oracle smoke 验,stub provider 无真 KCOV。

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"   // serialize_for_exec
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/syz_exec_runner.hpp"  // SyzExecResult, kCallFlag*
#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/coverage/kcov_drain_sink.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/fault_inject.hpp"
#include "worker/driver/kernel_wire_driver.hpp"
#include "worker/exec_mode.hpp"
#include "worker/perf/worker_perf.hpp"

#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>
#include <thread>
#include <utility>
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

namespace syz = ::refuzz::program::syz;
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

// 记录 drain sink 的 calls,验证 driver 真的走了 threaded path 的 sink hooks。
class RecordingDrainSink final : public worker::IKcovDrainSink {
public:
    explicit RecordingDrainSink(worker::KcovMode mode = worker::KcovMode::kPc)
        : mode_(mode)
    {}

    worker::KcovMode CurrentMode() const override { return mode_; }
    void StartThreadedSession(worker::KcovMode mode) override
    {
        ++start_calls;
        mode_ = mode;
        accumulated_.clear();
    }
    void AppendThreadDrained(std::vector<std::uint64_t> entries) override
    {
        ++append_calls;
        accumulated_.insert(accumulated_.end(),
                            entries.begin(), entries.end());
    }
    int start_calls = 0;
    int append_calls = 0;
    std::vector<std::uint64_t> accumulated_;
private:
    worker::KcovMode mode_ = worker::KcovMode::kPc;
};

class NoopDispatcher final : public worker::IDispatcher {
public:
    worker::PseudoResult Dispatch(uint64_t /*nr*/,
                                  const intptr_t* /*args*/,
                                  uint32_t /*argc*/,
                                  worker::PseudoRuntimeContext*) override
    {
        ++calls;
        return worker::PseudoResult{0, 0, nullptr};
    }
    const char* Name() const override { return "noop"; }
    int calls = 0;
};

class SleepingDispatcher final : public worker::IDispatcher {
public:
    explicit SleepingDispatcher(std::chrono::milliseconds sleep)
        : sleep_(sleep)
    {}

    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* /*args*/,
                                  uint32_t /*argc*/,
                                  worker::PseudoRuntimeContext*) override
    {
        const int now = active.fetch_add(1, std::memory_order_acq_rel) + 1;
        int prev = max_active.load(std::memory_order_acquire);
        while (now > prev &&
               !max_active.compare_exchange_weak(
                   prev, now, std::memory_order_acq_rel,
                   std::memory_order_acquire)) {
        }
        calls.fetch_add(1, std::memory_order_acq_rel);
        std::this_thread::sleep_for(sleep_);
        active.fetch_sub(1, std::memory_order_acq_rel);
        return worker::PseudoResult{static_cast<intptr_t>(nr), 0, nullptr};
    }

    const char* Name() const override { return "sleeping"; }

    std::atomic<int> active{0};
    std::atomic<int> max_active{0};
    std::atomic<int> calls{0};

private:
    std::chrono::milliseconds sleep_;
};

int  g_inject_fault_calls = 0;
bool g_fault_injected_return = false;
int MockInjectFault(int /*nth*/) { ++g_inject_fault_calls; return -1; }
bool MockFaultInjected(int /*fd*/) { return g_fault_injected_return; }

std::unique_ptr<syz::Prog> DecodeProg(std::string_view text)
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(text);
    CHECK(prog_or.has_value());
    CHECK(*prog_or != nullptr);
    return std::move(*prog_or);
}

std::vector<std::uint8_t> SerializeForExec(const syz::Prog& prog)
{
    auto bytes_or = syz::serialize_for_exec(prog);
    CHECK(bytes_or.has_value());
    CHECK(!bytes_or->empty());
    return std::move(*bytes_or);
}

// ---- Tests --------------------------------------------------------

void TestThreadedHappyPath()
{
    g_inject_fault_calls = 0;
    g_fault_injected_return = false;

    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == 0);
    // 至少写了一个 SyzExecResult slot。
    CHECK(output_len >= sizeof(worker::SyzExecResult));
    // drain sink 必须被 driver 调到位:StartThreadedSession 一次。
    CHECK(drain_sink.start_calls == 1);
    // append_calls 应为 0 (无 kcov → 无 drained entries → driver 跳过 Append)
    // 或更确切:driver 仅在 thread used_in_task && drained 非空时 Append。
    // stub provider 返 nullptr → drained 永远空 → append=0。
    CHECK(drain_sink.append_calls == 0);
}

void TestInheritedKcovFailureBecomesBackendFatal()
{
    auto prog = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    InvalidInheritedKcovProvider provider;
    RecordingDrainSink drain_sink;
    auto dispatcher = std::make_unique<NoopDispatcher>();
    auto* dispatcher_ptr = dispatcher.get();
    worker::KernelWireDriver driver(
        std::move(dispatcher), 0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;
    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == -1);
    CHECK(driver.RuntimeFailureState() ==
          worker::RuntimeFailure::kKcovStateInvalid);
    CHECK(dispatcher_ptr->calls == 0);
}

void TestThreadedUsesCmpModeFromDrainSink()
{
    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink(worker::KcovMode::kCmp);

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == 0);
    CHECK(drain_sink.start_calls == 1);
    CHECK(drain_sink.CurrentMode() == worker::KcovMode::kCmp);
}

void TestThreadedAsyncOverlapsWithNextCall()
{
    auto prog = DecodeProg(
        "getpid() (async)\n"
        "getuid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;
    auto dispatcher = std::make_unique<SleepingDispatcher>(
        std::chrono::milliseconds(80));
    auto* dispatcher_ptr = dispatcher.get();

    worker::KernelWireDriver driver(
        std::move(dispatcher),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 512> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == 0);
    CHECK(dispatcher_ptr->calls.load(std::memory_order_acquire) == 2);
    CHECK(dispatcher_ptr->max_active.load(std::memory_order_acquire) >= 2);
    CHECK(output_len >= 2 * sizeof(worker::SyzExecResult));

    auto* results = reinterpret_cast<const worker::SyzExecResult*>(output.data());
    CHECK((results[0].flags & worker::kCallFlagExecuted) != 0);
    CHECK((results[0].flags & worker::kCallFlagFinished) != 0);
    CHECK((results[0].flags & worker::kCallFlagBlocked) != 0);
    CHECK((results[1].flags & worker::kCallFlagExecuted) != 0);
    CHECK((results[1].flags & worker::kCallFlagFinished) != 0);
}

void TestThreadedTimeoutWritesExecutedOnlySlot()
{
    // A call that never completes — even within the end-drain window — writes
    // an Executed-only slot with errno=ENOSYS (mirrors upstream
    // write_call_output(th, false) at executor.cc:1151). To keep it a genuine
    // never-completer under the syzkaller-formula drain deadline
    // (max(2*per_call, program_start+program_timeout/6, prog_extra)), we shrink
    // the program timeout so the drain floor stays well under the dispatch
    // sleep: per_call=10 → 2*10=20ms, program_timeout=60 → 60/6=10ms, so the
    // drain ends ~30ms after the per-call wait, while dispatch sleeps 200ms.
    auto prog = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(1);
    RecordingDrainSink drain_sink;
    auto dispatcher = std::make_unique<SleepingDispatcher>(
        std::chrono::milliseconds(200));

    worker::KernelWireDriver driver(
        std::move(dispatcher),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);
    driver.SetPerCallTimeoutMs(10);
    driver.SetProgramTimeoutMs(60);  // drain floor 10ms ≪ 200ms dispatch sleep

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    worker::perf::WorkerPerfSample perf_sample{};
    int rc = 0;
    {
        worker::perf::ScopedCurrentSample current_sample(&perf_sample);
        rc = driver.Execute(
            bytes.data(), static_cast<std::uint32_t>(bytes.size()),
            output.data(), static_cast<std::uint32_t>(output.size()),
            &output_len, mode);
    }

    CHECK(rc == 0);
    CHECK(output_len >= sizeof(worker::SyzExecResult));

    auto* results = reinterpret_cast<const worker::SyzExecResult*>(output.data());
    CHECK((results[0].flags & worker::kCallFlagExecuted) != 0);
    CHECK((results[0].flags & worker::kCallFlagFinished) == 0);
    CHECK(results[0].flags != 0);
    CHECK(results[0].err == ENOSYS);
    CHECK(perf_sample.post_walk_drain_programs == 1);
    CHECK(perf_sample.post_walk_drain_initial_calls == 1);
    CHECK(perf_sample.post_walk_drain_completed_calls == 0);
    CHECK(perf_sample.post_walk_drain_timed_out_calls == 1);
    CHECK(perf_sample.post_walk_drain_deadline_per_call == 1);
    CHECK(perf_sample.post_walk_drain_deadline_program == 0);
    CHECK(perf_sample.post_walk_drain_deadline_extra == 0);
}

void TestThreadedBlockedCallCompletesInDrain()
{
    // [threaded end-drain parity] A non-async call that overruns its per-call
    // wait but COMPLETES in the background before the end-drain deadline must
    // be collected as a normal completion at drain: Executed|Finished (plus
    // Blocked, since at drain last_scheduled_tid is cleared), with the real
    // syscall errno — NOT the Executed-only ENOSYS never-completer slot. This
    // is the scheduler-contract half of the fix; the *coverage* half (drain
    // collects the call's full per_call_cov) needs a real KCOV fd and is
    // covered by the exec-oracle smoke, since StubKcovProvider has none.
    //
    // per_call=10ms times out almost immediately; dispatch sleeps 40ms; the
    // default program_timeout (5000) gives a ~833ms drain floor, so the call
    // finishes (~40ms) well inside the drain and the 1ms poll loop picks it up.
    auto prog = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;
    auto dispatcher = std::make_unique<SleepingDispatcher>(
        std::chrono::milliseconds(40));
    auto* dispatcher_ptr = dispatcher.get();

    worker::KernelWireDriver driver(
        std::move(dispatcher),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);
    driver.SetPerCallTimeoutMs(10);
    // leave program timeout at the default 5000 → drain floor ~833ms ≫ 40ms

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    worker::perf::WorkerPerfSample perf_sample{};
    int rc = 0;
    {
        worker::perf::ScopedCurrentSample current_sample(&perf_sample);
        rc = driver.Execute(
            bytes.data(), static_cast<std::uint32_t>(bytes.size()),
            output.data(), static_cast<std::uint32_t>(output.size()),
            &output_len, mode);
    }

    CHECK(rc == 0);
    CHECK(output_len >= sizeof(worker::SyzExecResult));
    CHECK(dispatcher_ptr->calls.load(std::memory_order_acquire) == 1);

    auto* results = reinterpret_cast<const worker::SyzExecResult*>(output.data());
    // Collected as a real completion at drain — not the ENOSYS never-completer.
    CHECK((results[0].flags & worker::kCallFlagExecuted) != 0);
    CHECK((results[0].flags & worker::kCallFlagFinished) != 0);
    CHECK(results[0].err != ENOSYS);
    CHECK(worker::perf::StageValue(
              perf_sample,
              worker::perf::WorkerStage::kPostWalkDrain) >= 10'000);
    CHECK(perf_sample.post_walk_drain_programs == 1);
    CHECK(perf_sample.post_walk_drain_initial_calls == 1);
    CHECK(perf_sample.post_walk_drain_completed_calls == 1);
    CHECK(perf_sample.post_walk_drain_timed_out_calls == 0);
    CHECK(perf_sample.post_walk_drain_deadline_per_call == 0);
    CHECK(perf_sample.post_walk_drain_deadline_program == 1);
    CHECK(perf_sample.post_walk_drain_deadline_extra == 0);
    CHECK(worker::perf::StageValue(
              perf_sample,
              worker::perf::WorkerStage::kTaskCleanup) > 0);
}

void TestThreadedRejectsThreadCount1()
{
    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(1);
    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/1);  // 配置错误:threaded mode 要 > 1
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == -1);
    CHECK(drain_sink.start_calls == 0);
}

void TestThreadedAcceptsFewerKcovSlotsWhenDemandFits()
{
    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/3);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == 0);
    CHECK(drain_sink.start_calls == 1);
    CHECK(output_len >= sizeof(worker::SyzExecResult));
}

void TestThreadedFailsWhenKcovSlotsExhausted()
{
    auto prog = DecodeProg(
        "getpid() (async)\n"
        "getuid() (async)\n"
        "getgid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;
    auto dispatcher = std::make_unique<SleepingDispatcher>(
        std::chrono::milliseconds(80));
    auto* dispatcher_ptr = dispatcher.get();

    worker::KernelWireDriver driver(
        std::move(dispatcher),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/3);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 512> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == -1);
    CHECK(drain_sink.start_calls == 1);
    CHECK(dispatcher_ptr->calls.load(std::memory_order_acquire) == 2);
}

void TestThreadedRejectsNullProvider()
{
    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    // 不调 SetKcovProvider → kcov_provider_ 仍 nullptr
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == -1);
    CHECK(drain_sink.start_calls == 0);
}

void TestSerialPathUnchangedWhenThreadCountHigh()
{
    auto prog  = DecodeProg("getpid()\n");
    const auto bytes = SerializeForExec(*prog);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kSerial;  // serial,即使 pool size = 2

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    CHECK(rc == 0);
    // serial path 不进 ExecuteThreaded,drain_sink 不被 touch。
    CHECK(drain_sink.start_calls == 0);
}

void TestThreadedAcceptsPseudo()
{
    // [Epic 7 PR-7] 对齐 upstream syzkaller:**不再** pre-flight reject 含
    // pseudo 的 program。理由见 kernel_wire_driver.cpp 入口注释:
    //   - upstream 没有 ConcurrentSafe metadata,threaded mode 跑所有 pseudo
    //   - reFuzz worker thread 已持独立 PseudoRuntimeContext (ctx race 消除)
    //   - kernel 端 race 是 fuzz 目标,host 端不该屏蔽
    // 期望 driver Execute 返 0 (而不是 PR-7 之前的 -1) — drain_sink 被正常
    // 触发,worker thread 跑通 dispatch。
    auto prog_or = [&]() -> std::unique_ptr<syz::Prog> {
        syz::TextDecoder decoder(syz::Target::linux_amd64(),
                                 syz::DecodeMode::kNonStrict);
        auto p1 = decoder.decode("syz_emit_ethernet(0x0, 0x0, 0x0)\n");
        if (p1.has_value() && *p1 != nullptr) return std::move(*p1);
        auto p2 = decoder.decode("syz_open_dev$loop(0x0, 0x0, 0x0)\n");
        if (p2.has_value() && *p2 != nullptr) return std::move(*p2);
        return nullptr;
    }();
    CHECK(prog_or != nullptr);
    const auto bytes = SerializeForExec(*prog_or);

    StubKcovProvider provider(2);
    RecordingDrainSink drain_sink;

    worker::KernelWireDriver driver(
        std::make_unique<NoopDispatcher>(),
        0,
        &MockInjectFault, &MockFaultInjected,
        /*thread_count=*/2);
    driver.SetKcovProvider(&provider);
    driver.SetKcovDrainSink(&drain_sink);

    std::array<std::uint8_t, 256> output{};
    std::uint32_t output_len = 0;
    worker::ExecMode mode{};
    mode.intra = worker::IntraTaskMode::kThreaded;

    const int rc = driver.Execute(
        bytes.data(), static_cast<std::uint32_t>(bytes.size()),
        output.data(), static_cast<std::uint32_t>(output.size()),
        &output_len, mode);

    // PR-7 放宽后:含 pseudo 的 program 走通 threaded path,不返 -1。
    CHECK(rc == 0);
    // drain_sink 必须被 driver 调到位 (StartThreadedSession 一次)。
    CHECK(drain_sink.start_calls == 1);
}

}  // namespace

int main()
{
    RUN_TEST(TestThreadedHappyPath);
    RUN_TEST(TestInheritedKcovFailureBecomesBackendFatal);
    RUN_TEST(TestThreadedUsesCmpModeFromDrainSink);
    RUN_TEST(TestThreadedAsyncOverlapsWithNextCall);
    RUN_TEST(TestThreadedTimeoutWritesExecutedOnlySlot);
    RUN_TEST(TestThreadedBlockedCallCompletesInDrain);
    RUN_TEST(TestThreadedRejectsThreadCount1);
    RUN_TEST(TestThreadedAcceptsFewerKcovSlotsWhenDemandFits);
    RUN_TEST(TestThreadedFailsWhenKcovSlotsExhausted);
    RUN_TEST(TestThreadedRejectsNullProvider);
    RUN_TEST(TestSerialPathUnchangedWhenThreadCountHigh);
    RUN_TEST(TestThreadedAcceptsPseudo);
    std::fprintf(stderr, "kernel_wire_driver_threaded_smoke_test: ALL OK\n");
    return 0;
}
