// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Regression for A7 (/dev/iommu IOMMU_IOAS_MAP$PAGES -> -EFAULT):
// the worker-side scratch/data window must cover the full linux/amd64
// target VMA window, not just low 4 MiB offsets.

#include "worker/backend/syz_exec_runner.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

namespace syz = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

void test_scratch_covers_linux_amd64_exec_window()
{
    const auto& target = syz::Target::linux_amd64();
    const std::size_t exec_window =
        static_cast<std::size_t>(target.num_pages() * target.page_size());
    std::fprintf(stderr,
                 "  scratch=%zu exec_window=%zu page_size=%llu num_pages=%llu\n",
                 ::refuzz::worker::kSyzExecScratchBytes,
                 exec_window,
                 static_cast<unsigned long long>(target.page_size()),
                 static_cast<unsigned long long>(target.num_pages()));
    CHECK(::refuzz::worker::kSyzExecScratchBytes >= exec_window);
}

} // namespace

int main()
{
    RUN_TEST(test_scratch_covers_linux_amd64_exec_window);
    return 0;
}
