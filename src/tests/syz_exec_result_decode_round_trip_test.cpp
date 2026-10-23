// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 6 PR-6-A — DecodeSyzExecResults round-trip ctest.
//
// Covers (plan §6.1 #2, 3 harness cases):
//   1. TestRoundTrip      — pack 3 SyzExecResult bytes-for-byte → decode →
//                           flags preserved; per-call kCallFlagFaultInjected
//                           observable on the right index only
//   2. TestShortInput     — n_calls=4 但 buffer 只有 3 个 record 大小 →
//                           empty vector (Consumer 视为 "no observation")
//   3. TestEmptyAndZero   — output 空 / n_calls=0 → empty vector,never read
//
// 这是 P1-4 review fix 后的 round-trip — 不再走 FeedbackDelta codec,直接
// memcpy + size check (见 plan §3 D-8)。

#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"
#include "worker/backend/syz_exec_runner.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <span>
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
namespace decode = ::refuzz::feedback::decode;

void TestRoundTrip()
{
    std::array<worker::SyzExecResult, 3> packed{};
    packed[0].ret   = 0;
    packed[0].err   = 0;
    packed[0].flags = 0;
    packed[1].ret   = 42;
    packed[1].err   = 0;
    packed[1].flags = worker::kCallFlagFaultInjected;
    packed[2].ret   = -1;
    packed[2].err   = 22;  // EINVAL
    packed[2].flags = 0;

    std::vector<std::uint8_t> buf(sizeof(packed));
    std::memcpy(buf.data(), packed.data(), sizeof(packed));

    auto decoded = decode::DecodeSyzExecResults(
        std::span<const std::uint8_t>(buf), 3);

    CHECK(decoded.size() == 3);
    CHECK(decoded[0].ret   == 0);
    CHECK(decoded[0].flags == 0);
    CHECK(decoded[1].ret   == 42);
    CHECK((decoded[1].flags & worker::kCallFlagFaultInjected) != 0);
    CHECK(decoded[2].ret   == -1);
    CHECK(decoded[2].err   == 22);
    CHECK((decoded[2].flags & worker::kCallFlagFaultInjected) == 0);
}

void TestShortInput()
{
    // 3 entries' worth of bytes but ask for 4 → empty.
    std::array<worker::SyzExecResult, 3> packed{};
    std::vector<std::uint8_t> buf(sizeof(packed));
    std::memcpy(buf.data(), packed.data(), sizeof(packed));

    auto decoded = decode::DecodeSyzExecResults(
        std::span<const std::uint8_t>(buf), 4);
    CHECK(decoded.empty());
}

void TestEmptyAndZero()
{
    // 1) output empty
    std::vector<std::uint8_t> empty_buf;
    auto a = decode::DecodeSyzExecResults(
        std::span<const std::uint8_t>(empty_buf), 1);
    CHECK(a.empty());

    // 2) n_calls=0 — even with non-empty buffer, returns empty
    std::array<std::uint8_t, 64> non_empty{};
    auto b = decode::DecodeSyzExecResults(
        std::span<const std::uint8_t>(non_empty.data(), non_empty.size()), 0);
    CHECK(b.empty());
}

}  // namespace

int main()
{
    RUN_TEST(TestRoundTrip);
    RUN_TEST(TestShortInput);
    RUN_TEST(TestEmptyAndZero);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
