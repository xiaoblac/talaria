// noop_saturation_filter_test.cpp
//
// [v2 batch 3 G5] NoopSaturationFilter 单测 — 永远 nullopt(透传)。
// 用于 kernel_no_triage profile 显式 wire(plan D4)。

#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/feedback/saturation/noop_saturation_filter.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

int main()
{
    std::fprintf(stdout, "Running noop_saturation_filter_test...\n");

    using refuzz::fuzzer::ExecutionObservation;
    using refuzz::fuzzer::KernelCallObservation;
    using refuzz::fuzzer::KernelExecutionObservation;
    using refuzz::fuzzer::NoopSaturationFilter;

    NoopSaturationFilter f;

    // empty obs → nullopt
    {
        ExecutionObservation obs;
        std::vector<std::uint64_t> ph;
        auto r = f.Filter(obs, ph);
        assert(!r.has_value());
    }

    // 大 program_hashes + per_call → 永远 nullopt
    {
        ExecutionObservation obs;
        KernelExecutionObservation kco;
        for (std::uint32_t i = 1; i <= 10; ++i) {
            kco.per_call.push_back({{0xA000 + i, 0xB000 + i, 0xC000 + i},
                                     /*errno=*/0,
                                     /*syscall_id=*/i});
        }
        obs.Set(std::move(kco));
        std::vector<std::uint64_t> ph;
        for (int i = 0; i < 1000; ++i) ph.push_back(static_cast<std::uint64_t>(i));
        auto r = f.Filter(obs, ph);
        assert(!r.has_value());
    }

    return 0;
}
