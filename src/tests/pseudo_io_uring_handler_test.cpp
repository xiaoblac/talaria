// PR-A1 — io_uring handler behavioral test (host-runnable, no kernel).
//
// IoUringSubmit / IoUringComplete operate on user-space ring buffers
// the handler does not allocate. Test by:
//   1. Building a fake ring buffer in a malloc'd block.
//   2. Setting the offsets the handler reads (sq_ring_mask, sq_tail,
//      cq_ring_mask, cq_head).
//   3. Calling Submit with a fake SQE; assert it landed in sqes[0] and
//      sq_tail advanced.
//   4. Setting up a fake CQE with openat tag; calling Complete and
//      asserting cqe.res is surfaced.
//   5. Setting up a fake CQE with non-openat tag; calling Complete and
//      asserting -1 (per upstream contract).
//
// IoUringSetup is kernel-dependent (issues io_uring_setup syscall +
// mmap); not exercised here. End-to-end NR routing through the wire
// driver is covered by pseudo_dispatch_oracle_test.

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace refuzz::worker::pseudo {
PseudoResult DispatchCorePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);
}

namespace {

// Mirror handler-side constants. KEEP IN SYNC with pseudo_core.cpp;
// values are kernel ABI (sys/linux/io_uring.txt).
constexpr std::size_t kSqTailOffset       = 64;
constexpr std::size_t kSqRingMaskOffset   = 256;
constexpr std::size_t kCqHeadOffset       = 128;
constexpr std::size_t kCqRingMaskOffset   = 260;
constexpr std::size_t kCqCqesOffset       = 320;
constexpr std::size_t kSqeSize            = 64;
constexpr std::size_t kCqeSize            = 16;

constexpr std::uint64_t kOpenatTag        = 0x12345;
constexpr std::uint64_t kOpenat2Tag       = 0x23456;

refuzz::fuzzer::syz::PseudoMeta MetaFor(const char* name)
{
    refuzz::fuzzer::syz::PseudoMeta m{};
    m.name = name;
    return m;
}

void TestSubmitWritesSqeAndAdvancesTail()
{
    std::vector<char> ring(1024, 0);
    std::vector<char> sqes(kSqeSize * 4, 0);
    std::vector<char> sqe(kSqeSize, 0);
    for (std::size_t i = 0; i < kSqeSize; ++i) {
        sqe[i] = static_cast<char>(0x40 + i);
    }

    auto* mask_ptr = reinterpret_cast<std::uint32_t*>(&ring[kSqRingMaskOffset]);
    auto* tail_ptr = reinterpret_cast<std::uint32_t*>(&ring[kSqTailOffset]);
    *mask_ptr = 0x3;
    *tail_ptr = 0;

    // [syz 08ab311] syz_io_uring_submit 现为 4 参 (params, ring, sqes, sqe);handler
    // 从 args[1] 取 ring(用固定 ring 偏移常量、忽略 params_ptr),传 0 占位 args[0]。
    intptr_t args[4] = {
        0,  // params_ptr (handler ignores)
        reinterpret_cast<intptr_t>(ring.data()),
        reinterpret_cast<intptr_t>(sqes.data()),
        reinterpret_cast<intptr_t>(sqe.data()),
    };
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_submit");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 4);
    assert(r.err == 0);
    assert(r.ret == 0);

    for (std::size_t i = 0; i < kSqeSize; ++i) {
        assert(sqes[i] == sqe[i]);
    }
    assert(*tail_ptr == 1);
}

void TestSubmitWrapsAtRingMask()
{
    // mask = 0x3 (4-entry ring); start tail at 5 → wraps to slot 1.
    std::vector<char> ring(1024, 0);
    std::vector<char> sqes(kSqeSize * 4, 0);
    std::vector<char> sqe(kSqeSize, 0x55);

    auto* mask_ptr = reinterpret_cast<std::uint32_t*>(&ring[kSqRingMaskOffset]);
    auto* tail_ptr = reinterpret_cast<std::uint32_t*>(&ring[kSqTailOffset]);
    *mask_ptr = 0x3;
    *tail_ptr = 5;

    // [syz 08ab311] syz_io_uring_submit 现为 4 参 (params, ring, sqes, sqe);handler
    // 从 args[1] 取 ring(用固定 ring 偏移常量、忽略 params_ptr),传 0 占位 args[0]。
    intptr_t args[4] = {
        0,  // params_ptr (handler ignores)
        reinterpret_cast<intptr_t>(ring.data()),
        reinterpret_cast<intptr_t>(sqes.data()),
        reinterpret_cast<intptr_t>(sqe.data()),
    };
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_submit");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 4);
    assert(r.err == 0);
    // Slot 1 (5 & 0x3) should now hold the SQE bytes; slot 0 should be untouched.
    for (std::size_t i = 0; i < kSqeSize; ++i) {
        assert(sqes[kSqeSize + i] == 0x55);
        assert(sqes[i] == 0);
    }
    assert(*tail_ptr == 6);
}

void TestCompleteOpenatTagReturnsRes()
{
    std::vector<char> ring(1024, 0);
    auto* mask_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqRingMaskOffset]);
    auto* head_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqHeadOffset]);
    *mask_ptr = 0x3;
    *head_ptr = 0;

    struct Cqe {
        std::uint64_t user_data;
        std::int32_t  res;
        std::uint32_t flags;
    };
    static_assert(sizeof(Cqe) == kCqeSize, "test cqe size mismatch");

    Cqe c{kOpenatTag, 42, 0};
    std::memcpy(&ring[kCqCqesOffset], &c, sizeof(c));

    // [syz 08ab311] syz_io_uring_complete 现为 2 参 (params, ring);ring 取 args[1]。
    intptr_t args[2] = {0, reinterpret_cast<intptr_t>(ring.data())};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_complete");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.err == 0);
    assert(r.ret == 42);
    assert(*head_ptr == 1);
}

void TestCompleteOpenat2TagReturnsRes()
{
    std::vector<char> ring(1024, 0);
    auto* mask_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqRingMaskOffset]);
    auto* head_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqHeadOffset]);
    *mask_ptr = 0x3;
    *head_ptr = 0;

    struct Cqe {
        std::uint64_t user_data;
        std::int32_t  res;
        std::uint32_t flags;
    };
    Cqe c{kOpenat2Tag, 99, 0};
    std::memcpy(&ring[kCqCqesOffset], &c, sizeof(c));

    // [syz 08ab311] syz_io_uring_complete 现为 2 参 (params, ring);ring 取 args[1]。
    intptr_t args[2] = {0, reinterpret_cast<intptr_t>(ring.data())};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_complete");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.ret == 99);
}

void TestCompleteNonOpenatTagReturnsMinusOne()
{
    std::vector<char> ring(1024, 0);
    auto* mask_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqRingMaskOffset]);
    auto* head_ptr = reinterpret_cast<std::uint32_t*>(&ring[kCqHeadOffset]);
    *mask_ptr = 0x3;
    *head_ptr = 0;

    struct Cqe {
        std::uint64_t user_data;
        std::int32_t  res;
        std::uint32_t flags;
    };
    Cqe c{0xdead, 99, 0};
    std::memcpy(&ring[kCqCqesOffset], &c, sizeof(c));

    // [syz 08ab311] syz_io_uring_complete 现为 2 参 (params, ring);ring 取 args[1]。
    intptr_t args[2] = {0, reinterpret_cast<intptr_t>(ring.data())};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_complete");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.err == 0);
    assert(r.ret == -1);
    assert(*head_ptr == 1);  // head still advances regardless of tag
}

void TestSubmitRejectsZeroArgs()
{
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_submit");
    intptr_t args[3] = {0, 0, 0};
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 3);
    assert(r.ret == -1);
    assert(r.err != 0);
}

void TestSubmitRejectsTooFewArgs()
{
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_submit");
    intptr_t args[1] = {0xdeadbeef};
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 1);
    assert(r.ret == -1);
    assert(r.err != 0);
}

void TestCompleteRejectsZeroArg()
{
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_io_uring_complete");
    intptr_t args[1] = {0};
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 1);
    assert(r.ret == -1);
    assert(r.err != 0);
}

} // namespace

int main()
{
    TestSubmitWritesSqeAndAdvancesTail();
    TestSubmitWrapsAtRingMask();
    TestCompleteOpenatTagReturnsRes();
    TestCompleteOpenat2TagReturnsRes();
    TestCompleteNonOpenatTagReturnsMinusOne();
    TestSubmitRejectsZeroArgs();
    TestSubmitRejectsTooFewArgs();
    TestCompleteRejectsZeroArg();
    return 0;
}
