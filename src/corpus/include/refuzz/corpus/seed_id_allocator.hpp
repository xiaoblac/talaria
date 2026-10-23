#pragma once

#include <algorithm>
#include <cstdint>

namespace refuzz::fuzzer {

// 非线程安全，仅用于单线程启动阶段（LoadAll / LoadCrashRepros / bootstrap）。
class SeedIdAllocator {
public:
    explicit SeedIdAllocator(uint64_t start = 2)
        : next_(start)
    {}

    uint64_t Allocate() { return next_++; }
    uint64_t Peek() const { return next_; }

    void BumpMinimum(uint64_t min)
    {
        next_ = std::max(next_, min);
    }

private:
    uint64_t next_;
};

} // namespace refuzz::fuzzer
