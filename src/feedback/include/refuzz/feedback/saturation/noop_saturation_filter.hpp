// Copyright 2026 reFuzz project author -------youngkk.
//
// NoopSaturationFilter —— G5 透传实现(永远 no-drop)。
//
// 用途:
//   - kernel_no_triage profile 显式 wire(plan D4 — P7 fail-loud 一致,而非
//     不 set factory)
//   - 测试 fixture(saturation pipeline 不应改变 c.hashes)
//   - future:operator 主动禁用 saturation 时切到此 impl
//
// 接口契约同 ISaturationFilter:返 nullopt = caller 走 byte-equal 路径
// (c.hashes = c.decoded.cov_hashes 原样)。
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.G5。

#pragma once

#include "refuzz/feedback/saturation_filter.hpp"

namespace refuzz::fuzzer {

class NoopSaturationFilter final : public ISaturationFilter {
public:
    std::optional<SaturationDecision> Filter(
        const ExecutionObservation& /*obs*/,
        std::span<const std::uint64_t> /*program_hashes*/) override
    {
        return std::nullopt;  // 永远 no-drop
    }
};

}  // namespace refuzz::fuzzer
