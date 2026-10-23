// MemAlloc — bitmap-based allocator that tracks address ranges already
// claimed by program-level pointer args, and finds free slots for new
// AUTO-marked pointer allocations.
//
// Mirrors prog.memAlloc (alloc.go) at the bit-twiddle level.

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

namespace refuzz::program::syz {

class MemAlloc {
public:
    static constexpr uint64_t kGranule    = 64;          // 1 bit per 64 bytes
    static constexpr uint64_t kMaxMem     = 16ULL << 20; // 16 MiB
    static constexpr uint64_t kL0Size     = 64;          // uint64s per L0 bucket
    static constexpr uint64_t kBitsPerU64 = 64;
    static constexpr uint64_t kL0Mem      = kL0Size * kGranule * kBitsPerU64;
    static constexpr uint64_t kL1Size     = kMaxMem / kL0Mem;

    explicit MemAlloc(uint64_t total_mem_size);

    // Mark [addr, addr+size) as occupied.
    void note_alloc(uint64_t addr, uint64_t size);
    // Find the next free address of `size` bytes with the given alignment;
    // calls note_alloc on success. If memory is exhausted, the bitmap is
    // cleared and the search retries (matches upstream `bankruptcy`).
    uint64_t alloc(uint64_t size, uint64_t alignment);

    // [v2 PR-D — bankruptcy observability]
    // 全局静态计数器(atomic),所有 MemAlloc 实例共享。语义是 "fuzz session
    // 整体 bankruptcy 频次"。0 = 16MiB 充足;大量增长 = 单 Prog AUTO ptr
    // 数量异常,可能 mutator 路径有循环。reset 在多 worker 下有 race,
    // 但只给单测用,production 不调,无需加锁。
    // 未来需 per-instance 监控时改成 instance member,API 接口不变。
    static uint64_t bankruptcy_count();
    static void     reset_bankruptcy_count();

    // [v2 Epic 7 PR-12 B2 — Step 3] 清掉所有 note_alloc 记录,容量保留。
    // 由 mutator GenState::analyze_for_mutation_boundary 调用 ——
    // per-op rebuild 时需要把旧 prog 的分配踪迹清掉。原本是 bankruptcy
    // 路径的 private helper,公开化让 reset 流复用。
    void clear_all();

private:
    void set_bit(uint64_t idx);
    bool get_bit(uint64_t idx) const;

    uint64_t                                                size_ = 0; // in granules
    std::array<std::unique_ptr<std::array<uint64_t, kL0Size>>, kL1Size> l1_{};

    static std::atomic<uint64_t> bankruptcy_count_;
};

} // namespace refuzz::program::syz
