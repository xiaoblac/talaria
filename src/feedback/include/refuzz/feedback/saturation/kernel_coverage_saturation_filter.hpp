// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelCoverageSaturationFilter —— G5 kernel impl of ISaturationFilter。
//
// 算法(G5 第一版,YAGNI;详 plan §3.G5 D2):
//   - 维护 per-syscall 累计 normalized hash count(去重前 raw count;不维护
//     unique set 避免 mem 膨胀)
//   - 计数语义:对每 incoming call,**先 accept** 该 call 的 normalized
//     coverage_hashes,再**累加**该 syscall 的 count
//   - 超阈值后该 syscall 的后续 incoming call 直接 drop(coverage_hashes 不进
//     output union)
//   - 输出 filtered:**sort + unique**,跟 c.decoded.cov_hashes 同形态
//
// 现状:**默认禁用**(threshold = kDisabledThreshold = 0xFFFFFFFFu,累计永不到 → 从不 drop)。
//   per-syscall 覆盖丢弃会把 mutate 复执热门 syscall 上的**真·novel**边在 admission 前丢掉,压制
//   真实/mutate 覆盖,且当前 syzkaller(corpus.go Save 只 merge,无 per-syscall drop)并不这么做。
//   类与逻辑保留为**休眠的内部调试代码**:要重新启用,在构造时传一个真实 threshold(如 10000)。
//   不经 config / env 对外暴露。
//
// **drop 路径输出形态**:union of accepted per-call slices,sort + unique
//   - 跟 NormalizeCoverageEntries 输出语义对齐(sorted unique 是契约)
//   - store.MergeCoverage / NormalizeCoverageEntries 假设 sorted unique 输入
//   - 不去重会导致 store 计 gain 时重复 count
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.G5。

#pragma once

#include "refuzz/feedback/saturation_filter.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

class KernelCoverageSaturationFilter final : public ISaturationFilter {
public:
    // [内部调试用] per-syscall 饱和**禁用**哨兵:累计 hash count 永远到不了 → 从不 drop。
    // 默认即此值 = 功能关闭(见头注)。要调试时把构造参数换成真实 threshold(如 10000)重启用。
    static constexpr std::uint32_t kDisabledThreshold = 0xFFFFFFFFu;

    // threshold:per-syscall 累计 normalized hash count 上限。默认 kDisabledThreshold(禁用)。
    explicit KernelCoverageSaturationFilter(std::uint32_t threshold = kDisabledThreshold);

    std::optional<SaturationDecision> Filter(
        const ExecutionObservation& obs,
        std::span<const std::uint64_t> program_hashes) override;

    // Diagnostic accessor for tests / future metric publishing。
    std::uint64_t CountForSyscall(std::uint32_t syscall_id) const;

private:
    // syscall_id → 累计 normalized hash count。**不**维护 unique set。
    // accept-then-count 语义:incoming 先 accept(那 call 的 normalized_slice
    // 进 union),然后 count += slice.size()(下一 incoming 看 count 是否超
    // threshold)。
    std::unordered_map<std::uint32_t, std::uint64_t> per_syscall_count_;
    std::uint32_t threshold_;
};

}  // namespace refuzz::fuzzer
