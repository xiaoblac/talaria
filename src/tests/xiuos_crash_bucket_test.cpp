// xiuos_crash_bucket_test.cpp
//
// Unit tests for refuzz::fuzzer::XiuosCrashBucket (Phase 2 §C #18).
//
// All tests use synthetic cc::AbnormalCompletion events constructed by
// hand — no Channel / QEMU / worker required. The test mints a XiUOS
// RESULT payload that XiuosDecodeResult will accept by writing the wire
// bytes directly (mirroring xiuos_uart_protocol.h §"RESULT payload").

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/bucket/xiuos_crash_bucket.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace cc = refuzz::core::channel_contract;
using refuzz::fuzzer::XiuosCrashBucket;

namespace {

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                       \
    if (!(cond)) {                                                             \
        std::fprintf(stderr,                                                   \
                     "    CHECK failed: %s [line %d]\n",                       \
                     #cond, __LINE__);                                         \
        return false;                                                          \
    }                                                                          \
} while (0)

#define RUN_TEST(fn) do {                                                      \
    ++tests_run;                                                               \
    std::fprintf(stdout, "  %-60s ", #fn);                                     \
    std::fflush(stdout);                                                       \
    if (fn()) {                                                                \
        ++tests_passed;                                                        \
        std::fprintf(stdout, "PASS\n");                                        \
    } else {                                                                   \
        std::fprintf(stdout, "FAIL\n");                                        \
    }                                                                          \
} while (0)

// Build a minimal valid XiUOS RESULT payload (status=Trap). Mirrors the
// wire layout pinned by xiuos_uart_protocol.h §"RESULT payload" (all
// multi-byte fields are BIG-ENDIAN):
//   offset 0    1   result_version (=XIUOS_RESULT_VERSION)
//   offset 1    1   status (XiuosResultStatus)
//   offset 2    2   flags          (BE u16)
//   offset 4    2   calls_executed (BE u16)
//   offset 6    2   coverage_size  (BE u16)
//   offset 8    4   trap_or_pc     (BE u32)
//   offset 12   4   aux            (BE u32, signed on host)
//   offset 16   N   coverage bitmap (N = coverage_size)
std::vector<std::uint8_t> MakeTrapResultPayload(
        std::uint32_t trap_pc,
        std::int32_t  aux,
        std::uint16_t cov_size = XIUOS_COVERAGE_SIZE) {
    std::vector<std::uint8_t> p(XIUOS_RESULT_HEADER_SIZE + cov_size, 0);
    p[0] = XIUOS_RESULT_VERSION;
    p[1] = XIUOS_STATUS_TRAP;
    XiuosPutU16Be(p.data() + 2, /*flags=*/0);
    XiuosPutU16Be(p.data() + 4, /*calls_executed=*/0);
    XiuosPutU16Be(p.data() + 6, cov_size);
    XiuosPutU32Be(p.data() + 8, trap_pc);
    XiuosPutU32Be(p.data() + 12, static_cast<std::uint32_t>(aux));
    return p;
}

cc::AbnormalCompletion MakeTrapEvent(std::uint32_t trap_pc,
                                     std::int32_t  mcause_aux,
                                     std::vector<std::uint8_t> payload_bytes) {
    cc::AbnormalCompletion ab;
    ab.kind = cc::AbnormalKind::kWorkerSignaled;
    ab.ctx.executor_id = 0xAABB;
    ab.ctx.seed_id = 7;
    ab.ctx.origin_seed_id = 7;
    ab.ctx.worker_id = 0;
    ab.ctx.dispatch_gen = 1;
    ab.ctx.program_payload = std::move(payload_bytes);
    ab.diagnostics.worker_id = 0;
    ab.diagnostics.error_code = trap_pc;       // XiUOS convention
    ab.diagnostics.crash_signal = static_cast<std::uint32_t>(mcause_aux);
    ab.output = MakeTrapResultPayload(trap_pc, mcause_aux);
    return ab;
}

std::filesystem::path FreshTempDir(const std::string& tag) {
    std::random_device rd;
    std::mt19937_64 g(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "xiuos-bucket-%s-%016lx",
                  tag.c_str(),
                  static_cast<unsigned long>(g()));
    const auto p = std::filesystem::temp_directory_path() / buf;
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    std::filesystem::create_directories(p, ec);
    return p;
}

std::size_t CountBinFiles(const std::filesystem::path& dir) {
    std::size_t n = 0;
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) return 0;
    for (const auto& e :
            std::filesystem::recursive_directory_iterator(dir, ec)) {
        if (ec) break;
        if (e.is_regular_file(ec) && !ec &&
                e.path().extension() == ".bin") {
            ++n;
        }
    }
    return n;
}

bool TestBucketKeyFormat() {
    const auto k = XiuosCrashBucket::MakeBucketKey(0xdeadbeef, 0x0000000a);
    CHECK(k == "xiuos-trap-pc_0xdeadbeef-mcause_0x0000000a");
    return true;
}

bool TestRecordFirstTrap() {
    const auto dir = FreshTempDir("first");
    XiuosCrashBucket bucket(dir);

    const auto ev = MakeTrapEvent(
        /*trap_pc=*/0x80001234,
        /*mcause=*/2,
        /*payload=*/{0x01, 0x02, 0x03, 0x04});
    const auto rc = bucket.Record(ev);

    CHECK(rc.persisted);
    CHECK(rc.bucket_is_new);
    CHECK(rc.bucket_key == "xiuos-trap-pc_0x80001234-mcause_0x00000002");
    CHECK(rc.payload_hash != 0);
    CHECK(bucket.BucketCount() == 1);
    CHECK(bucket.TotalRecordedSeeds() == 1);
    CHECK(CountBinFiles(dir) == 1);

    return true;
}

bool TestRecordIdenticalIsDeduped() {
    const auto dir = FreshTempDir("dedup");
    XiuosCrashBucket bucket(dir);

    const auto ev = MakeTrapEvent(0x80002000, 5, {0xaa, 0xbb, 0xcc});
    const auto rc1 = bucket.Record(ev);
    CHECK(rc1.persisted);
    CHECK(rc1.bucket_is_new);

    // Same trap + same payload → no second file.
    const auto rc2 = bucket.Record(ev);
    CHECK(!rc2.persisted);
    CHECK(!rc2.bucket_is_new);
    CHECK(rc2.bucket_key == rc1.bucket_key);
    CHECK(rc2.payload_hash == rc1.payload_hash);

    CHECK(bucket.BucketCount() == 1);
    CHECK(bucket.TotalRecordedSeeds() == 1);
    CHECK(CountBinFiles(dir) == 1);
    return true;
}

bool TestRecordDifferentPayloadSameBucket() {
    const auto dir = FreshTempDir("samebucket");
    XiuosCrashBucket bucket(dir);

    const auto e1 = MakeTrapEvent(0xCAFEBABE, 7, {0x10, 0x20});
    const auto e2 = MakeTrapEvent(0xCAFEBABE, 7, {0x10, 0x21});
    const auto r1 = bucket.Record(e1);
    const auto r2 = bucket.Record(e2);

    CHECK(r1.persisted && r1.bucket_is_new);
    CHECK(r2.persisted && !r2.bucket_is_new);
    CHECK(r1.bucket_key == r2.bucket_key);
    CHECK(r1.payload_hash != r2.payload_hash);

    CHECK(bucket.BucketCount() == 1);
    CHECK(bucket.TotalRecordedSeeds() == 2);
    CHECK(CountBinFiles(dir) == 2);
    return true;
}

bool TestRecordDifferentTrapNewBucket() {
    const auto dir = FreshTempDir("newbucket");
    XiuosCrashBucket bucket(dir);

    const auto e1 = MakeTrapEvent(0x80001000, 2, {0x01});
    const auto e2 = MakeTrapEvent(0x80002000, 2, {0x01});  // same payload
    const auto e3 = MakeTrapEvent(0x80001000, 3, {0x01});  // same pc, diff mcause
    bucket.Record(e1);
    bucket.Record(e2);
    bucket.Record(e3);

    CHECK(bucket.BucketCount() == 3);
    CHECK(bucket.TotalRecordedSeeds() == 3);
    CHECK(CountBinFiles(dir) == 3);
    return true;
}

bool TestIgnoresNonWorkerSignaled() {
    const auto dir = FreshTempDir("ignored");
    XiuosCrashBucket bucket(dir);

    auto ev = MakeTrapEvent(0x80001000, 2, {0x01, 0x02});
    ev.kind = cc::AbnormalKind::kHang;  // not kWorkerSignaled
    const auto rc = bucket.Record(ev);

    CHECK(!rc.persisted);
    CHECK(rc.bucket_key.empty());
    CHECK(bucket.BucketCount() == 0);
    CHECK(CountBinFiles(dir) == 0);
    return true;
}

bool TestIgnoresNonTrapOutput() {
    const auto dir = FreshTempDir("nontrap");
    XiuosCrashBucket bucket(dir);

    // Build a RESULT payload with status=WorkerError (not Trap).
    auto payload = MakeTrapResultPayload(0x80001000, 2);
    payload[1] = XIUOS_STATUS_WORKER_ERROR;
    cc::AbnormalCompletion ev;
    ev.kind = cc::AbnormalKind::kWorkerSignaled;
    ev.ctx.program_payload = {0x09, 0x08};
    ev.output = std::move(payload);

    const auto rc = bucket.Record(ev);
    CHECK(!rc.persisted);
    CHECK(rc.bucket_key.empty());
    CHECK(bucket.BucketCount() == 0);
    return true;
}

bool TestIgnoresGarbageOutput() {
    const auto dir = FreshTempDir("garbage");
    XiuosCrashBucket bucket(dir);

    cc::AbnormalCompletion ev;
    ev.kind = cc::AbnormalKind::kWorkerSignaled;
    ev.ctx.program_payload = {0x01};
    ev.output = {0xff, 0xff, 0xff};  // too short to decode

    const auto rc = bucket.Record(ev);
    CHECK(!rc.persisted);
    CHECK(rc.bucket_key.empty());
    return true;
}

bool TestLoadFromDiskRecoversBucketSet() {
    const auto dir = FreshTempDir("reload");

    // Phase 1: write 3 entries across 2 buckets.
    {
        XiuosCrashBucket bucket(dir);
        bucket.Record(MakeTrapEvent(0x80001000, 2, {0x01}));
        bucket.Record(MakeTrapEvent(0x80001000, 2, {0x02}));   // same bucket
        bucket.Record(MakeTrapEvent(0x80002000, 2, {0x03}));   // new bucket
        CHECK(bucket.BucketCount() == 2);
        CHECK(bucket.TotalRecordedSeeds() == 3);
    }

    // Phase 2: fresh bucket pointed at same dir; LoadFromDisk recovers.
    {
        XiuosCrashBucket bucket(dir);
        const std::size_t loaded = bucket.LoadFromDisk();
        CHECK(loaded == 3);
        CHECK(bucket.BucketCount() == 2);
        CHECK(bucket.TotalRecordedSeeds() == 3);

        // Re-pushing the same events MUST dedupe — no disk growth.
        const std::size_t before_files = CountBinFiles(dir);
        bucket.Record(MakeTrapEvent(0x80001000, 2, {0x01}));
        bucket.Record(MakeTrapEvent(0x80001000, 2, {0x02}));
        bucket.Record(MakeTrapEvent(0x80002000, 2, {0x03}));
        CHECK(CountBinFiles(dir) == before_files);
        CHECK(bucket.TotalRecordedSeeds() == 3);
    }
    return true;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_crash_bucket_test...\n");
    RUN_TEST(TestBucketKeyFormat);
    RUN_TEST(TestRecordFirstTrap);
    RUN_TEST(TestRecordIdenticalIsDeduped);
    RUN_TEST(TestRecordDifferentPayloadSameBucket);
    RUN_TEST(TestRecordDifferentTrapNewBucket);
    RUN_TEST(TestIgnoresNonWorkerSignaled);
    RUN_TEST(TestIgnoresNonTrapOutput);
    RUN_TEST(TestIgnoresGarbageOutput);
    RUN_TEST(TestLoadFromDiskRecoversBucketSet);

    std::fprintf(stdout, "\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
