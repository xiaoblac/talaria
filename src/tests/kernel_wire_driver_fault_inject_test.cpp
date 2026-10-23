// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 6 PR-6-A — KernelWireDriver fault-injection hook ctest.
//
// Covers (plan §6.1 #1, 6 harness cases):
//   1. TestHookHonorsFailNth        — FailNth=1 不再 -1 reject;dispatch 一次
//   2. TestGracefulOnOpenFailure    — inject_fault 返 -1,不 set flag,不 poison
//   3. TestFlagSetOnInjected        — fault_injected 返 true → flag 置位
//   4. TestFlagClearOnNotInjected   — fault_injected 返 false → flag 清空
//   5. TestAsyncStillRejected       — async 依然 -1 (§10 N1 永久非目标)
//   6. TestRerunStillRejected       — rerun 依然 -1 (§10 N2 永久非目标)
//
// Test seam: KernelWireDriver constructor 注入 inject_fault_fn /
// fault_injected_fn 两个 fn-ptr,test 用 mock 替换免依赖真实
// /proc/thread-self/fail-nth (CI 环境无 CONFIG_FAULT_INJECTION 也能跑)。

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/syz_exec_runner.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/fault_inject.hpp"
#include "worker/driver/kernel_wire_driver.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>
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

class MockDispatcher final : public worker::IDispatcher {
public:
    worker::PseudoResult Dispatch(uint64_t /*nr*/,
                                  const intptr_t* /*args*/,
                                  uint32_t /*argc*/,
                                  worker::PseudoRuntimeContext*) override
    {
        ++calls;
        return worker::PseudoResult{0, 0, nullptr};
    }
    const char* Name() const override { return "mock_fault_inject"; }
    int calls = 0;
};

// Module-local fn-ptr trampolines + state — fn-ptrs cannot capture,
// so each test resets these globals before driving.
int  g_inject_fault_calls   = 0;
int  g_inject_fault_last_nth = -1;
int  g_inject_fault_return   = -1;  // -1 = simulate open failure
bool g_fault_injected_return = false;
int  g_fault_injected_calls  = 0;

int MockInjectFault(int nth)
{
    ++g_inject_fault_calls;
    g_inject_fault_last_nth = nth;
    return g_inject_fault_return;
}

bool MockFaultInjected(int /*fd*/)
{
    ++g_fault_injected_calls;
    return g_fault_injected_return;
}

void ResetMockState()
{
    g_inject_fault_calls   = 0;
    g_inject_fault_last_nth = -1;
    g_inject_fault_return   = -1;
    g_fault_injected_return = false;
    g_fault_injected_calls  = 0;
}

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

worker::SyzExecResult ReadResult(const std::array<std::uint8_t, 64>& output)
{
    worker::SyzExecResult r{};
    std::memcpy(&r, output.data(), sizeof(r));
    return r;
}

void TestHookHonorsFailNth()
{
    ResetMockState();
    g_inject_fault_return   = 7;     // fake fd success
    g_fault_injected_return = true;  // kernel injected fault

    auto prog  = DecodeProg("getpid() (fail_nth: 1)\n");
    const auto bytes = SerializeForExec(*prog);

    auto dispatcher = std::make_unique<MockDispatcher>();
    auto* d = dispatcher.get();
    worker::KernelWireDriver driver(
        std::move(dispatcher),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);

    CHECK(rc == 0);
    CHECK(output_len == sizeof(worker::SyzExecResult));
    CHECK(d->calls == 1);
    CHECK(g_inject_fault_calls == 1);
    CHECK(g_inject_fault_last_nth == 1);
    CHECK(g_fault_injected_calls == 1);
    const auto r = ReadResult(output);
    CHECK((r.flags & worker::kCallFlagFaultInjected) != 0);
}

void TestGracefulOnOpenFailure()
{
    ResetMockState();
    g_inject_fault_return   = -1;    // simulate open() failure
    g_fault_injected_return = true;  // would have set if hook called it

    auto prog  = DecodeProg("getpid() (fail_nth: 3)\n");
    const auto bytes = SerializeForExec(*prog);

    auto dispatcher = std::make_unique<MockDispatcher>();
    auto* d = dispatcher.get();
    worker::KernelWireDriver driver(
        std::move(dispatcher),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);

    // Graceful: dispatch 照常进行,不 set flag。driver 不 -1。
    CHECK(rc == 0);
    CHECK(d->calls == 1);
    CHECK(g_inject_fault_calls == 1);
    CHECK(g_inject_fault_last_nth == 3);
    // open 失败 → fault_injected 不该被调
    CHECK(g_fault_injected_calls == 0);
    const auto r = ReadResult(output);
    CHECK((r.flags & worker::kCallFlagFaultInjected) == 0);
}

void TestFlagSetOnInjected()
{
    ResetMockState();
    g_inject_fault_return   = 11;
    g_fault_injected_return = true;

    auto prog  = DecodeProg("getpid() (fail_nth: 5)\n");
    const auto bytes = SerializeForExec(*prog);

    worker::KernelWireDriver driver(
        std::make_unique<MockDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);
    CHECK(rc == 0);
    const auto r = ReadResult(output);
    CHECK((r.flags & worker::kCallFlagFaultInjected) != 0);
}

void TestFlagClearOnNotInjected()
{
    ResetMockState();
    g_inject_fault_return   = 13;
    g_fault_injected_return = false;  // kernel did NOT fault this site

    auto prog  = DecodeProg("getpid() (fail_nth: 2)\n");
    const auto bytes = SerializeForExec(*prog);

    worker::KernelWireDriver driver(
        std::make_unique<MockDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);
    CHECK(rc == 0);
    CHECK(g_inject_fault_calls == 1);
    CHECK(g_fault_injected_calls == 1);
    const auto r = ReadResult(output);
    CHECK((r.flags & worker::kCallFlagFaultInjected) == 0);
}

void TestAsyncStillRejected()
{
    ResetMockState();
    auto prog  = DecodeProg("getpid() (async)\n");
    const auto bytes = SerializeForExec(*prog);

    worker::KernelWireDriver driver(
        std::make_unique<MockDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);
    // §10 N1 永久非目标 — async 依然 -1
    CHECK(rc != 0);
    CHECK(output_len == 0);
    CHECK(g_inject_fault_calls == 0);
}

void TestRerunStillRejected()
{
    ResetMockState();
    auto prog  = DecodeProg("getpid() (rerun: 2)\n");
    const auto bytes = SerializeForExec(*prog);

    worker::KernelWireDriver driver(
        std::make_unique<MockDispatcher>(),
        /*pid=*/0,
        &MockInjectFault, &MockFaultInjected);

    std::array<std::uint8_t, 64> output{};
    std::uint32_t output_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  output.data(),
                                  static_cast<std::uint32_t>(output.size()),
                                  &output_len);
    // §10 N2 永久非目标 — rerun 依然 -1
    CHECK(rc != 0);
    CHECK(output_len == 0);
    CHECK(g_inject_fault_calls == 0);
}

}  // namespace

int main()
{
    RUN_TEST(TestHookHonorsFailNth);
    RUN_TEST(TestGracefulOnOpenFailure);
    RUN_TEST(TestFlagSetOnInjected);
    RUN_TEST(TestFlagClearOnNotInjected);
    RUN_TEST(TestAsyncStillRejected);
    RUN_TEST(TestRerunStillRejected);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
