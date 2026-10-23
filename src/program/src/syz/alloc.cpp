#include "refuzz/program/syz/alloc.hpp"

#include <cstring>
#include <stdexcept>

namespace refuzz::program::syz {

MemAlloc::MemAlloc(uint64_t total_mem_size) {
    if (total_mem_size > kMaxMem) {
        throw std::runtime_error("MemAlloc: total mem too large");
    }
    if (total_mem_size % kL0Mem != 0) {
        // Round up to multiple of L0 chunk.
        total_mem_size = ((total_mem_size + kL0Mem - 1) / kL0Mem) * kL0Mem;
    }
    size_ = total_mem_size / kGranule;
}

void MemAlloc::note_alloc(uint64_t addr0, uint64_t size0) {
    if (size0 == 0) size0 = 1;
    const uint64_t addr = addr0 / kGranule;
    const uint64_t size = (addr0 + size0 + kGranule - 1) / kGranule - addr;
    for (uint64_t i = 0; i < size; ++i) {
        if (addr + i >= size_) return;
        set_bit(addr + i);
    }
}

uint64_t MemAlloc::alloc(uint64_t size0, uint64_t alignment0) {
    if (size0 == 0)      size0 = 1;
    if (alignment0 == 0) alignment0 = 1;
    const uint64_t size      = (size0 + kGranule - 1) / kGranule;
    const uint64_t alignment = (alignment0 + kGranule - 1) / kGranule;
    if (size > size_) {
        // Fits nowhere; report 0 to keep the program valid for this run.
        return 0;
    }
    const uint64_t end = size_ - size;
    for (uint64_t start = 0; start <= end; start += alignment) {
        bool empty = true;
        for (uint64_t i = 0; i < size; ++i) {
            if (get_bit(start + i)) { empty = false; break; }
        }
        if (empty) {
            const uint64_t start0 = start * kGranule;
            note_alloc(start0, size0);
            return start0;
        }
    }
    // [v1 silent bankruptcy — ROLLBACK: uncomment 3 行,移除 v2]
    // // Bankruptcy: clear and retry once.
    // clear_all();
    // note_alloc(0, size0);
    // return 0;
    //
    // [v2 PR-D — bankruptcy 可观测]
    // 行为与上游 prog/alloc.go:79-80 等价 (ma.bankruptcy() + 递归 alloc
    // 也最终返回 0 — bitmap 清零后第一次 alloc 命中 start=0)。reFuzz 当前
    // 直接 inline,递归调用语义没差。加 atomic counter 让 bankruptcy 可观测,
    // 现版完全静默,运维一无所知。详见
    // docs/plans/worker-special-pointer-fix/04_pr_d_draft.md Part 1。
    clear_all();
    note_alloc(0, size0);
    bankruptcy_count_.fetch_add(1, std::memory_order_relaxed);
    return 0;
}

void MemAlloc::set_bit(uint64_t idx) {
    const uint64_t i1  = idx / (kL0Size * kBitsPerU64);
    const uint64_t r1  = idx % (kL0Size * kBitsPerU64);
    const uint64_t i0  = r1 / kBitsPerU64;
    const uint64_t bit = 1ULL << (r1 % kBitsPerU64);
    if (i1 >= kL1Size) return;
    if (l1_[i1] == nullptr) {
        l1_[i1] = std::make_unique<std::array<uint64_t, kL0Size>>();
        std::memset(l1_[i1]->data(), 0, sizeof(uint64_t) * kL0Size);
    }
    (*l1_[i1])[i0] |= bit;
}

bool MemAlloc::get_bit(uint64_t idx) const {
    const uint64_t i1  = idx / (kL0Size * kBitsPerU64);
    const uint64_t r1  = idx % (kL0Size * kBitsPerU64);
    const uint64_t i0  = r1 / kBitsPerU64;
    const uint64_t bit = 1ULL << (r1 % kBitsPerU64);
    if (i1 >= kL1Size || l1_[i1] == nullptr) return false;
    return ((*l1_[i1])[i0] & bit) != 0;
}

void MemAlloc::clear_all() {
    for (auto& bucket : l1_) {
        if (bucket != nullptr) {
            std::memset(bucket->data(), 0, sizeof(uint64_t) * kL0Size);
        }
    }
}

// [v2 PR-D — bankruptcy observability storage + accessors]
std::atomic<uint64_t> MemAlloc::bankruptcy_count_{0};

uint64_t MemAlloc::bankruptcy_count() {
    return bankruptcy_count_.load(std::memory_order_relaxed);
}

void MemAlloc::reset_bankruptcy_count() {
    bankruptcy_count_.store(0, std::memory_order_relaxed);
}

} // namespace refuzz::program::syz
