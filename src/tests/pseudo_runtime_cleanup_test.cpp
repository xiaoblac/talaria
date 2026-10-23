#include "worker/backend/pseudo/pseudo_runtime.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace {

void TestCleanupCallbacksRun()
{
    int value = 1;
    {
        refuzz::worker::PseudoRuntimeContext ctx;
        ctx.RegisterCleanup([&value]() { value += 1; });
        ctx.RegisterCleanup([&value]() { value *= 10; });
        ctx.Cleanup();
        assert(value == 11);
    }
    assert(value == 11);
}

void TestCleanupRunsOnDestructor()
{
    int value = 0;
    {
        refuzz::worker::PseudoRuntimeContext ctx;
        ctx.RegisterCleanup([&value]() { value = 7; });
    }
    assert(value == 7);
}

void TestOwnedFdCleanup()
{
    int fds[2] = {-1, -1};
    assert(pipe(fds) == 0);
    const int read_fd = fds[0];
    const int write_fd = fds[1];
    {
        refuzz::worker::PseudoRuntimeContext ctx;
        ctx.RegisterOwnedFd(read_fd);
        ctx.RegisterOwnedFd(write_fd);
        ctx.Cleanup();
    }

    errno = 0;
    assert(fcntl(read_fd, F_GETFD) == -1);
    assert(errno == EBADF);
    errno = 0;
    assert(fcntl(write_fd, F_GETFD) == -1);
    assert(errno == EBADF);
}

void TestStartupReclaimsOnlyMarkedStaleRoots()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
                          ("refuzz-pseudo-cleanup-test-" + std::to_string(getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "stale");
    fs::create_directories(root / "current");
    fs::create_directories(root / "unmarked");

    assert(refuzz::worker::WritePseudoOwnershipMarker(
        (root / "stale").string(), "old-run", static_cast<int>(getpid())));
    assert(refuzz::worker::WritePseudoOwnershipMarker(
        (root / "current").string(), "current-run", static_cast<int>(getpid())));

    const uint32_t reclaimed = refuzz::worker::ReclaimStalePseudoRuntimeRoots(
        root.string(), "current-run");
    assert(reclaimed == 1);
    assert(!fs::exists(root / "stale"));
    assert(fs::exists(root / "current"));
    assert(fs::exists(root / "unmarked"));

    fs::remove_all(root);
}

// [PR-A1 §5.0] RegisterNamedRegion / LookupNamedRegion / Cleanup munmap.

void TestNamedRegionRegisterAndLookup()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    void* p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    const uint64_t key = reinterpret_cast<uint64_t>(p);

    ctx.RegisterNamedRegion(key, p, 4096);

    std::size_t len = 0;
    void* found = ctx.LookupNamedRegion(key, &len);
    assert(found == p);
    assert(len == 4096);

    assert(ctx.LookupNamedRegion(0xDEADBEEFULL) == nullptr);

    ctx.Cleanup();  // munmaps p; entry removed
    assert(ctx.LookupNamedRegion(key) == nullptr);
}

void TestNamedRegionRejectsInvalid()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    ctx.RegisterNamedRegion(1, nullptr, 4096);
    ctx.RegisterNamedRegion(2, MAP_FAILED, 4096);

    void* p = mmap(nullptr, 4096, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    ctx.RegisterNamedRegion(3, p, 0);

    assert(ctx.LookupNamedRegion(1) == nullptr);
    assert(ctx.LookupNamedRegion(2) == nullptr);
    assert(ctx.LookupNamedRegion(3) == nullptr);

    munmap(p, 4096);  // registration was rejected; we own the unmap
}

void TestNamedRegionVisibleDuringCleanupCallback()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    void* p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    const uint64_t key = reinterpret_cast<uint64_t>(p);

    bool saw_region = false;
    ctx.RegisterCleanup([&] {
        // Order-of-cleanup invariant (PR-A1): callbacks run BEFORE
        // named_regions get munmap'd, so a callback can still see /
        // touch the region.
        saw_region = (ctx.LookupNamedRegion(key) == p);
    });
    ctx.RegisterNamedRegion(key, p, 4096);

    ctx.Cleanup();
    assert(saw_region);
}

void TestPseudoContextDefaultIsNoOp()
{
    // Bare base-class PseudoContext accepts register calls (default
    // virtual no-op impls); LookupNamedRegion returns nullptr.
    refuzz::worker::PseudoContext bare;
    bare.RegisterCleanup([] {});
    bare.RegisterOwnedFd(-1);
    bare.RegisterNamedRegion(7, reinterpret_cast<void*>(0xDEAD), 8);
    assert(bare.LookupNamedRegion(7) == nullptr);
}

void TestLoopMaskPublishesExactBits()
{
    uint32_t cursor = 0;
    refuzz::worker::PseudoRuntimeContext first;
    refuzz::worker::PseudoRuntimeContext second;
    first.set_loop_devices_used_mask_cursor(&cursor);
    second.set_loop_devices_used_mask_cursor(&cursor);

    first.RecordLoopDeviceUsed(3);
    second.RecordLoopDeviceUsed(7);
    const uint32_t expected = (1u << 3) | (1u << 7);
    assert(first.LoopDevicesUsedMask() == (1u << 3));
    assert(second.LoopDevicesUsedMask() == (1u << 7));
    assert(__atomic_load_n(&cursor, __ATOMIC_ACQUIRE) == expected);

    first.RecordLoopDeviceUsed(32);
    assert(first.LoopDevicesUsedMask() == UINT32_MAX);
    assert(__atomic_load_n(&cursor, __ATOMIC_ACQUIRE) == UINT32_MAX);
}

void TestLoopSlotIsFixedToProcId()
{
    refuzz::worker::PseudoRuntimeContext ctx(
        &refuzz::fuzzer::syz::kDefaultSyzTarget, 6);
    assert(ctx.proc_slot_id == 6);
    assert(ctx.EffectiveLoopSlot() == 6);
}

} // namespace

int main()
{
    TestCleanupCallbacksRun();
    TestCleanupRunsOnDestructor();
    TestOwnedFdCleanup();
    TestStartupReclaimsOnlyMarkedStaleRoots();
    TestNamedRegionRegisterAndLookup();
    TestNamedRegionRejectsInvalid();
    TestNamedRegionVisibleDuringCleanupCallback();
    TestPseudoContextDefaultIsNoOp();
    TestLoopMaskPublishesExactBits();
    TestLoopSlotIsFixedToProcId();
    return 0;
}
