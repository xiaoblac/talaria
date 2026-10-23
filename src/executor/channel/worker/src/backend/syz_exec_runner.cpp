// Implementation of the worker child-side scratch buffer helpers used by
// KernelWireDriver. After V1 retirement no V1 / 旧V2 typed-wire executor
// lives here.

#include "worker/backend/syz_exec_runner.hpp"

#include <cstdlib>
#include <sys/mman.h>

namespace refuzz::worker {

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace {

bool UseFixedScratchLayout()
{
    // [当前版本 default-on]
    // 默认 true:跟 syzkaller executor 同款固定 scratch VA
    // (mmap MAP_FIXED_NOREPLACE 到 kSyzExecDataOffset = 0x200000000000),让
    //   (a) KCOV PC trace 不受 ASLR 漂 scratch_base 影响 → coverage 稳定
    //   (b) KASAN crash report 里的 user 端 VA 跨 VM / 跨次 run 一致 → repro 可比
    //   (c) L3 paired oracle vs syz-executor 的 mmap return value byte-equal
    // 之所以历史 default-off 是因为顾虑 user-side ASAN 套 worker 的兼容性。
    // 但 reFuzz 走 kernel-side KASAN + libc++,user-side 不 ASAN,跟 0x200000000000
    // 没冲突,production 启用是对的 default。
    //
    // 显式关:export REFUZZ_FIXED_SCRATCH_LAYOUT=0(ASAN debug 等边界场景)。
    // 未设 env / 任何非 "0" 值 → 启用。
    static const bool enabled = [] {
        const char* env = std::getenv("REFUZZ_FIXED_SCRATCH_LAYOUT");
        if (env != nullptr && env[0] == '0' && env[1] == '\0') {
            return false;
        }
        return true;
    }();
    return enabled;
}

bool MapFixedScratchWithGuards(uint8_t** out)
{
    if (out == nullptr) {
        return false;
    }

    auto* const data = reinterpret_cast<void*>(kSyzExecDataOffset);
    auto* const left = reinterpret_cast<void*>(kSyzExecDataOffset - kSyzExecGuardPageBytes);
    auto* const right = reinterpret_cast<void*>(kSyzExecDataOffset + kSyzExecScratchBytes);
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE;

    void* mapped_left = mmap(left, kSyzExecGuardPageBytes, PROT_NONE, flags, -1, 0);
    if (mapped_left != left) {
        if (mapped_left != MAP_FAILED) {
            munmap(mapped_left, kSyzExecGuardPageBytes);
        }
        return false;
    }

    void* mapped_data = mmap(data, kSyzExecScratchBytes,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             flags, -1, 0);
    if (mapped_data != data) {
        if (mapped_data != MAP_FAILED) {
            munmap(mapped_data, kSyzExecScratchBytes);
        }
        munmap(mapped_left, kSyzExecGuardPageBytes);
        return false;
    }

    void* mapped_right = mmap(right, kSyzExecGuardPageBytes, PROT_NONE, flags, -1, 0);
    if (mapped_right != right) {
        if (mapped_right != MAP_FAILED) {
            munmap(mapped_right, kSyzExecGuardPageBytes);
        }
        munmap(mapped_data, kSyzExecScratchBytes);
        munmap(mapped_left, kSyzExecGuardPageBytes);
        return false;
    }

    *out = static_cast<uint8_t*>(mapped_data);
    return true;
}

} // namespace

uint8_t* AcquireScratch()
{
    static thread_local uint8_t* scratch = nullptr;
    if (scratch != nullptr) {
        return scratch;
    }

    if (UseFixedScratchLayout()) {
        if (!MapFixedScratchWithGuards(&scratch)) {
            return nullptr;
        }
        return scratch;
    }

    void* mapped = mmap(nullptr, kSyzExecScratchBytes,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED) {
        return nullptr;
    }
    scratch = static_cast<uint8_t*>(mapped);
    return scratch;
}

bool PreallocateSyzExecScratch()
{
    return AcquireScratch() != nullptr;
}

} // namespace refuzz::worker
