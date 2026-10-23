// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelCoverageSaturationFilter —— G5 kernel impl。详 .hpp doc。

#include "refuzz/feedback/saturation/kernel_coverage_saturation_filter.hpp"

#include "refuzz/feedback/observation/kernel_observation.hpp"

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::fuzzer {

KernelCoverageSaturationFilter::KernelCoverageSaturationFilter(std::uint32_t threshold)
    : threshold_(threshold)
{}

std::optional<SaturationDecision> KernelCoverageSaturationFilter::Filter(
    const ExecutionObservation& obs,
    std::span<const std::uint64_t> program_hashes)
{
    // 拿 KernelExecutionObservation。kernel runtime 的缺/空 per-call observation
    // 应在 KcovCoverageSignal 记录并 malformed 返回;这里的 nullopt 仅覆盖非 kernel
    // observation、单测直接调用,或 no-drop 语义。
    const auto* kco = obs.Get<KernelExecutionObservation>();
    if (kco == nullptr || kco->per_call.empty()) {
        return std::nullopt;
    }

    // ── 决策每个 incoming call:keep / drop ──
    // 语义(plan D2 accept-then-count):
    //   for each call:
    //     if per_syscall_count_[sid] < threshold:
    //       accept(此 call 的 normalized_slice 进 union)
    //       per_syscall_count_[sid] += slice.size()
    //     else:
    //       drop
    bool any_drop = false;
    std::vector<bool> keep(kco->per_call.size(), true);
    for (std::size_t i = 0; i < kco->per_call.size(); ++i) {
        const auto& call = kco->per_call[i];
        const std::uint64_t cur = per_syscall_count_[call.syscall_id];
        if (cur >= threshold_) {
            keep[i] = false;
            any_drop = true;
            continue;
        }
        // accept;count += slice.size()(下一次再决定饱和)
        per_syscall_count_[call.syscall_id] = cur + call.coverage_hashes.size();
    }

    if (!any_drop) {
        // 无 drop → caller 用原 program_hashes(byte-equal)
        return std::nullopt;
    }

    // ── drop 发生 → 输出 sort+unique union of accepted per-call slices ──
    std::unordered_set<std::uint64_t> seen;
    std::vector<std::uint64_t> filtered;
    for (std::size_t i = 0; i < kco->per_call.size(); ++i) {
        if (!keep[i]) continue;
        for (std::uint64_t h : kco->per_call[i].coverage_hashes) {
            if (seen.insert(h).second) {
                filtered.push_back(h);
            }
        }
    }
    // sort 保持跟 c.decoded.cov_hashes(NormalizeCoverageEntries 输出)同形态。
    // store.MergeCoverage 没显式假设 sorted,但 byte-equal 测试比对依赖 stable order。
    std::sort(filtered.begin(), filtered.end());

    // 注意:即便 filtered 是 empty(全 drop / accepted slices 全 empty)也返回
    // SaturationDecision{hashes={}} → caller 走全 drop 路径(c.fired=false,
    // 详 G5 plan D3)。区别于 nullopt(no-drop passthrough)。
    (void)program_hashes;  // drop 路径不直接用 program-level
    SaturationDecision decision;
    decision.hashes = std::move(filtered);
    decision.keep_calls.reserve(keep.size());
    for (bool v : keep) {
        decision.keep_calls.push_back(v);
    }
    return decision;
}

std::uint64_t KernelCoverageSaturationFilter::CountForSyscall(std::uint32_t syscall_id) const
{
    auto it = per_syscall_count_.find(syscall_id);
    return it == per_syscall_count_.end() ? 0 : it->second;
}

}  // namespace refuzz::fuzzer
