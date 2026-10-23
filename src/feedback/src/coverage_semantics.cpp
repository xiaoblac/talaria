// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/coverage_semantics.hpp"

#include "refuzz/feedback/feedback_codec.hpp"

#include <algorithm>

namespace refuzz::fuzzer {

namespace {

uint32_t SyzkallerEdgeHash(uint32_t value)
{
    value = (value ^ 61U) ^ (value >> 16U);
    value = value + (value << 3U);
    value = value ^ (value >> 4U);
    value = value * 0x27d4eb2dU;
    value = value ^ (value >> 15U);
    return value;
}

} // namespace

bool CoverageEntriesPassSignalFilter(
    std::span<const uint64_t> entries,
    const CoverageNormalizationConfig& config)
{
    if (!config.filter_signal || config.kernel_text_start == 0) {
        return true;
    }
    return std::all_of(entries.begin(), entries.end(), [&](uint64_t entry) {
        return entry >= config.kernel_text_start && entry <= config.kernel_text_end;
    });
}

std::vector<uint64_t> NormalizeCoverageEntries(std::vector<uint64_t> entries,
                                               const CoverageNormalizationConfig& config)
{
    // [syz-parity convertCallInfo] A bogus raw PC means corrupted/injected
    // coverage, so drop the whole slice before sorting, sampling, or hashing.
    if (!CoverageEntriesPassSignalFilter(entries, config)) {
        return {};
    }

    std::sort(entries.begin(), entries.end());
    entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
    if (config.sample_rate > 0.0 && config.sample_rate < 1.0) {
        std::vector<uint64_t> sampled;
        sampled.reserve(entries.size());
        double acc = 0.0;
        for (uint64_t entry : entries) {
            acc += config.sample_rate;
            if (acc >= 1.0) {
                sampled.push_back(entry);
                acc -= 1.0;
            }
        }
        entries.swap(sampled);
    }

    // [List3 — 删除无逻辑的 PC 截断] 此前这里按固定数量 max_entries_per_exec 截断:
    //   `if (size > N) entries.resize(N);`
    // 但 entries 上面已 std::sort(按 PC 地址升序),resize 保留的是**地址最低的 N 个**
    // PC、丢弃所有高地址覆盖 —— 完全任意,会系统性丢掉高地址内核代码的覆盖,且只作用于
    // raw-PC 路径(edge 在 normalize 之前算,不受影响),导致 all_pc/corpus_pc 被截而
    // all_edge/corpus_edge 不截的口径不对称。syzkaller 没有任何 host 侧 sort-then-truncate
    // (它只有 wire buffer 溢出时置 CoverageOverflow flag,且是执行序不是地址序)。故删除。
    // config.max_entries_per_exec 保留可解析但不再生效(避免破坏既有 config)。

    if (!config.raw_pc) {
        for (uint64_t& entry : entries) {
            uint64_t h = entry;
            h ^= h >> 33;
            h *= 0xff51afd7ed558ccdULL;
            h ^= h >> 33;
            h *= 0xc4ceb9fe1a85ec53ULL;
            h ^= h >> 33;
            entry = h;
        }
    }

    return entries;
}

std::vector<uint64_t> ComputeEdgeSignal(const std::vector<uint64_t>& ordered_pcs)
{
    // [P2] syz-parity edge signal: sig = pc ^ (hash(prev_pc & 0xfff) & 0xfff). prev resets
    // to 0 per call (each slice is one call's ordered cover). A new transition
    // between two already-seen blocks -> new sig -> admitted; raw-PC novelty would
    // miss it. The admission feedback_store holds ONLY these sigs, so the overlap
    // between edge-sig space and raw-PC space is harmless (compared like-for-like).
    std::vector<uint64_t> edges;
    edges.reserve(ordered_pcs.size());
    uint64_t prev = 0;
    for (uint64_t pc : ordered_pcs) {
        constexpr uint64_t kEdgeMask = (1ULL << 12U) - 1ULL;
        const uint64_t mixed = SyzkallerEdgeHash(
            static_cast<uint32_t>(prev & kEdgeMask));
        edges.push_back(pc ^ (mixed & kEdgeMask));
        prev = pc;
    }
    return edges;
}

} // namespace refuzz::fuzzer
