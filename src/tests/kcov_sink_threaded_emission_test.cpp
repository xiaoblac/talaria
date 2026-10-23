// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 7 PR-6 — KcovSink threaded packet emission correctness.
//
// 验证 sink 作为 IKcovDrainSink 的行为。PC coverage 现在由 driver 的
// per-call SyzExecResult tail 返回,所以 PackFeedback 不 emit PC program-level
// packet;CMP records 仍由 sink 累积并 emit。测试不需要真 /sys/kernel/debug/kcov:
// 本路径完全不经 collectors_,driver 直接 push 数据到 sink 内部的
// last_session_entries_。
//
// Cases:
//   1. PcModeEmitsNoProgramPacket — 2 次 Append(PC) → PackFeedback 写 0 字节
//   2. CmpEmission             — 2 次 Append(CMP records 4×uint64/record) →
//                                  kCoverageKcovCmp packet,entry_count = record 数
//   3. CmpFilterDropsOutBufPtr — record 的 arg1/arg2 落在 out buffer 范围
//                                  时被 FilterCmpRecordsByOutputBuffer 拒
//   4. EmptyEmitsNothing       — StartThreadedSession 后不 Append → PackFeedback
//                                  写 0 字节
//   5. SessionResetsBetweenTasks — 第二次 StartThreadedSession 清空累积器
//   6. ModeSwitchBetweenTasks  — PC task 后接 CMP task,PC no-op,CMP packet 正确
//   7. ConfiguredBufferBytes   — local 透传配置，remote 固定 syzkaller 1M entries
//   8. ThreadedCollectorCap    — thread_count=32 时 collector pool 按
//                                  syzkaller delayed-KCOV 上限裁剪到 8
//   9. AddressSpaceBudget      — 200 MiB base + 32 local + 1 extra = 336 MiB
//
// 不在 unit test 范围(需 VM / real KCOV):
//   - 真 worker thread 在 worker thread 上下文调 KCOV_ENABLE
//   - PC area_ syscall-boundary reset / collect 正确性
//   - crash 时 SnapshotForCrash 多 collector 路径(Step 4 first-cut 只读
//     collectors_[0],threaded crash snapshot 扩到 N 是 follow-up)

#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/coverage/kcov_collector.hpp"     // KcovMode
#include "worker/observation/kcov_sink.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/sandbox.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
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

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace worker = ::refuzz::worker;
namespace proto = ::refuzz::proto;

// 解码 packet 尾部 header(driver 写 layout: [body bytes][header])。
proto::WorkerFeedbackHeader ReadHeaderAtTail(const std::uint8_t* buf,
                                             std::uint32_t len)
{
    CHECK(len >= sizeof(proto::WorkerFeedbackHeader));
    proto::WorkerFeedbackHeader hdr{};
    std::memcpy(&hdr,
                buf + len - sizeof(proto::WorkerFeedbackHeader),
                sizeof(proto::WorkerFeedbackHeader));
    return hdr;
}

// ---- Tests --------------------------------------------------------

// PC mode: task-end/program-level sink packet is disabled. Per-call coverage
// is returned through SyzExecResult cover_offset/cover_count instead.
void TestPcModeEmitsNoProgramPacket()
{
    // sink ctor 创建 size=2 pool,但本测试不调 Init() — IKcovDrainSink path
    // 完全不经 collectors_,直接走 last_session_entries_。
    worker::KcovSink sink(/*thread_count=*/2);

    sink.StartThreadedSession(worker::KcovMode::kPc);
    sink.AppendThreadDrained({0x100, 0x200, 0x300});
    sink.AppendThreadDrained({0x400, 0x500});

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    std::uint32_t len = 0;
    sink.PackFeedback(buf.data(), static_cast<std::uint32_t>(buf.size()), &len);

    CHECK(len == 0);
}

// CMP mode: 2 个 worker drained 各 1 个 record (4 × uint64),合并 2 records。
void TestCmpEmission()
{
    worker::KcovSink sink(/*thread_count=*/2);

    sink.StartThreadedSession(worker::KcovMode::kCmp);
    // record layout: {type, arg1, arg2, pc} (upstream kernel order)。
    // arg1/arg2 故意远离 out buffer 范围,避免 FilterCmpRecordsByOutputBuffer
    // 误判 (host VA 通常远高于 0x100000)。
    sink.AppendThreadDrained({0u, 0x10u, 0x20u, 0x1111u});
    sink.AppendThreadDrained({0u, 0x30u, 0x40u, 0x2222u});

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    std::uint32_t len = 0;
    sink.PackFeedback(buf.data(), static_cast<std::uint32_t>(buf.size()), &len);

    // Layout: [2 records × 4 × uint64][WorkerFeedbackHeader]
    CHECK(len == 2 * 4 * sizeof(std::uint64_t) + sizeof(proto::WorkerFeedbackHeader));

    const auto* entries = reinterpret_cast<const std::uint64_t*>(buf.data());
    CHECK(entries[0] == 0u);       // record1.type
    CHECK(entries[1] == 0x10u);    // record1.arg1
    CHECK(entries[2] == 0x20u);    // record1.arg2
    CHECK(entries[3] == 0x1111u);  // record1.pc
    CHECK(entries[4] == 0u);       // record2.type
    CHECK(entries[5] == 0x30u);
    CHECK(entries[6] == 0x40u);
    CHECK(entries[7] == 0x2222u);

    const auto hdr = ReadHeaderAtTail(buf.data(), len);
    CHECK(hdr.kind == static_cast<std::uint16_t>(proto::FeedbackKind::kCoverageKcovCmp));
    CHECK(hdr.entry_count == 2);  // record count for CMP mode (NOT uint64 count)
}

// FilterCmpRecordsByOutputBuffer 在 threaded 合并后仍生效:
// 任一 record 的 arg1/arg2 落在 worker output buffer 范围内时丢弃。
void TestCmpFilterDropsOutBufPtr()
{
    worker::KcovSink sink(/*thread_count=*/2);

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    const std::uint64_t buf_start = reinterpret_cast<std::uint64_t>(buf.data());
    const std::uint64_t buf_end   = buf_start + buf.size();

    sink.StartThreadedSession(worker::KcovMode::kCmp);
    // record 1: arg1 在 buf 中间 → drop
    sink.AppendThreadDrained({0u, buf_start + 100u, 0xAAu, 0x1111u});
    // record 2: arg2 在 buf 末尾 → drop
    sink.AppendThreadDrained({0u, 0xBBu, buf_end - 8u, 0x2222u});
    // record 3: 两 arg 都安全 → keep
    sink.AppendThreadDrained({0u, 0x77u, 0x88u, 0x3333u});

    std::uint32_t len = 0;
    sink.PackFeedback(buf.data(), static_cast<std::uint32_t>(buf.size()), &len);

    // 仅 1 record 通过。
    CHECK(len == 1 * 4 * sizeof(std::uint64_t) + sizeof(proto::WorkerFeedbackHeader));

    const auto* entries = reinterpret_cast<const std::uint64_t*>(buf.data());
    CHECK(entries[1] == 0x77u);  // 通过的 record 是 record 3
    CHECK(entries[2] == 0x88u);

    const auto hdr = ReadHeaderAtTail(buf.data(), len);
    CHECK(hdr.entry_count == 1);
}

// 空 session: StartThreadedSession 后无 Append → PackFeedback 不写任何字节。
void TestEmptyEmitsNothing()
{
    worker::KcovSink sink(/*thread_count=*/2);

    sink.StartThreadedSession(worker::KcovMode::kPc);
    // 故意不 Append。

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    std::uint32_t len = 0;
    sink.PackFeedback(buf.data(), static_cast<std::uint32_t>(buf.size()), &len);

    CHECK(len == 0);
}

void TestRemoteSettlePerfCounters()
{
    worker::KcovSink sink(/*thread_count=*/2);
    sink.StartThreadedSession(worker::KcovMode::kPc);
    sink.SetProgramUsesRemoteCover(true);

    worker::perf::WorkerPerfSample perf_sample{};
    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    std::uint32_t len = 0;
    {
        worker::perf::ScopedCurrentSample current_sample(&perf_sample);
        sink.PackFeedback(
            buf.data(), static_cast<std::uint32_t>(buf.size()), &len);
    }

    CHECK(len == 0);
    CHECK(perf_sample.remote_kcov_settles == 1);
    CHECK(worker::perf::StageValue(
              perf_sample,
              worker::perf::WorkerStage::kRemoteKcovSettleSleep) > 0);
}

// 跨 task 复位:第二次 StartThreadedSession 应清空累积器。
void TestSessionResetsBetweenTasks()
{
    worker::KcovSink sink(/*thread_count=*/2);

    // task 1: 1 个 CMP record
    sink.StartThreadedSession(worker::KcovMode::kCmp);
    sink.AppendThreadDrained({0u, 0x10u, 0x20u, 0x1111u});

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf{};
    std::uint32_t len1 = 0;
    sink.PackFeedback(buf.data(), static_cast<std::uint32_t>(buf.size()), &len1);
    CHECK(len1 == 4 * sizeof(std::uint64_t) + sizeof(proto::WorkerFeedbackHeader));

    // task 2: 重新 StartThreadedSession,不 Append
    sink.StartThreadedSession(worker::KcovMode::kCmp);

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf2{};
    std::uint32_t len2 = 0;
    sink.PackFeedback(buf2.data(), static_cast<std::uint32_t>(buf2.size()), &len2);
    CHECK(len2 == 0);  // 累积器已清,无 entries
}

// Mode 跨 task 切换:PC task no-op,CMP task packet kind 正确。
void TestModeSwitchBetweenTasks()
{
    worker::KcovSink sink(/*thread_count=*/2);

    // task 1: PC
    sink.StartThreadedSession(worker::KcovMode::kPc);
    sink.AppendThreadDrained({0xAAu, 0xBBu});

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf1{};
    std::uint32_t len1 = 0;
    sink.PackFeedback(buf1.data(), static_cast<std::uint32_t>(buf1.size()), &len1);
    CHECK(len1 == 0);

    // task 2: CMP — StartThreadedSession 同时锁 mode + 清累积器
    sink.StartThreadedSession(worker::KcovMode::kCmp);
    sink.AppendThreadDrained({0u, 0x11u, 0x22u, 0x33u});  // 1 record

    alignas(std::uint64_t) std::array<std::uint8_t, 1024> buf2{};
    std::uint32_t len2 = 0;
    sink.PackFeedback(buf2.data(), static_cast<std::uint32_t>(buf2.size()), &len2);
    const auto hdr2 = ReadHeaderAtTail(buf2.data(), len2);
    CHECK(hdr2.kind == static_cast<std::uint16_t>(proto::FeedbackKind::kCoverageKcovCmp));
    CHECK(hdr2.entry_count == 1);
}

void TestConfiguredBufferBytes()
{
    constexpr std::size_t kEntries = 64u << 10;
    worker::KcovSink sink(/*thread_count=*/2, kEntries);
    const std::size_t expected =
        2u * kEntries * sizeof(std::uint64_t) +
        worker::kSyzkallerExtraKcovEntries * sizeof(std::uint64_t);
    CHECK(sink.BufferBytes() == expected);
}

void TestThreadedCollectorCap()
{
    constexpr std::size_t kEntries = 64u << 10;
    worker::KcovSink sink(/*thread_count=*/32, kEntries);
    CHECK(sink.ThreadCount() == worker::kDefaultThreadedKcovCollectorCount);
    const std::size_t expected =
        static_cast<std::size_t>(worker::kDefaultThreadedKcovCollectorCount) *
            kEntries * sizeof(std::uint64_t) +
        worker::kSyzkallerExtraKcovEntries * sizeof(std::uint64_t);
    CHECK(sink.BufferBytes() == expected);
}

void TestSyzkallerAddressSpaceBudget()
{
    constexpr std::size_t kMiB = 1u << 20;
    constexpr std::size_t kExpected =
        200u * kMiB +
        (32u * worker::kDefaultKcovEntries +
         worker::kSyzkallerExtraKcovEntries) * sizeof(void*);

    CHECK(worker::ComputeAddressSpaceLimit({}) == kExpected);

    worker::SandboxSizing current{};
    current.ivshmem_bytes = 18878464u;
    current.scratch_bytes = 16u * kMiB;
    current.coverage_bytes =
        8u * worker::kDefaultKcovEntries * sizeof(std::uint64_t) +
        worker::kSyzkallerExtraKcovEntries * sizeof(std::uint64_t);
    CHECK(worker::ComputeAddressSpaceLimit(current) == kExpected);

    worker::SandboxSizing larger_coverage{};
    larger_coverage.coverage_bytes = 200u * kMiB;
    CHECK(worker::ComputeAddressSpaceLimit(larger_coverage) == 400u * kMiB);
}

void TestChildMappingPolicy()
{
    worker::KcovCollector fresh(
        1024, false, worker::KcovChildMode::kFreshPerProgram);
    fresh.ResetMappingForChild();
    CHECK(fresh.NeedsReopenForTesting());

    worker::KcovCollector inherited(
        1024, false, worker::KcovChildMode::kInheritedFromLoop);
    inherited.ResetMappingForChild();
    CHECK(!inherited.NeedsReopenForTesting());
}

void TestInheritedSerialBeginFailureIsFatal()
{
    worker::KcovSink inherited(
        1, 1024, 1, 1, 1,
        worker::KcovChildMode::kInheritedFromLoop);
    CHECK(!inherited.UsesAtForkReset());
    worker::ObservationContext context{};
    context.exec_mode.intra = worker::IntraTaskMode::kSerial;
    inherited.OnEvent(worker::ObservationEvent::kTaskStart, context);
    CHECK(inherited.RuntimeFailureState() ==
          worker::RuntimeFailure::kKcovStateInvalid);

    worker::KcovSink fresh(
        1, 1024, 1, 1, 1,
        worker::KcovChildMode::kFreshPerProgram);
    CHECK(fresh.UsesAtForkReset());
    fresh.OnEvent(worker::ObservationEvent::kTaskStart, context);
    CHECK(fresh.RuntimeFailureState() == worker::RuntimeFailure::kNone);
}

}  // namespace

int main()
{
    ::setenv("REFUZZ_REMOTE_KCOV_SETTLE_MS", "1", 1);
    ::setenv("REFUZZ_REMOTE_KCOV_SETTLE_MAX_MS", "1", 1);
    RUN_TEST(TestPcModeEmitsNoProgramPacket);
    RUN_TEST(TestCmpEmission);
    RUN_TEST(TestCmpFilterDropsOutBufPtr);
    RUN_TEST(TestEmptyEmitsNothing);
    RUN_TEST(TestRemoteSettlePerfCounters);
    RUN_TEST(TestSessionResetsBetweenTasks);
    RUN_TEST(TestModeSwitchBetweenTasks);
    RUN_TEST(TestConfiguredBufferBytes);
    RUN_TEST(TestThreadedCollectorCap);
    RUN_TEST(TestSyzkallerAddressSpaceBudget);
    RUN_TEST(TestChildMappingPolicy);
    RUN_TEST(TestInheritedSerialBeginFailureIsFatal);
    std::fprintf(stderr, "kcov_sink_threaded_emission_test: ALL OK\n");
    return 0;
}
