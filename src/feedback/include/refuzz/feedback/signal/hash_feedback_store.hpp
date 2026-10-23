// Copyright 2026 reFuzz project author -------youngkk.
//
// HashFeedbackStore — IFeedbackStore 的内存哈希集实现。
//
// 用于 Coverage 类信号（KcovCoverageSignal / KcovCmpSignal …）做增量去重。
// 由 Assembler 创建并通过 SignalCatalog::BuildContext 注入到信号实例。

#pragma once

#include "refuzz/fuzzer/interfaces.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

class HashFeedbackStore final : public IFeedbackStore {
public:
    bool   HasNewCoverage(const std::vector<uint64_t>& cov_hashes) const override;
    // [v2 batch 3 PR-Y] +prio 参数; syz max-signal semantics: gain counts
    // brand-new hashes and existing hashes hit at higher prio.
    size_t MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                         std::uint8_t prio) override;
    size_t MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                         std::uint8_t prio,
                         std::vector<uint64_t>* novel_hashes) override;
    bool   SaveToFile(const std::string& path) const override;
    bool   LoadFromFile(const std::string& path) override;
    size_t Count() const override;

    // [corpus-pc-export] Dump distinct keys (raw PCs when raw_pc=true) sorted as
    // 0x%x/line — speed-compare D PC-set source (orchestrator Stop()). Text format,
    // not SaveToFile's binary CoverageFileEntryV2. Not part of IFeedbackStore.
    bool DumpPCsToFile(const std::string& path) const;

private:

    //seen_ map<uint64, uint8_t prio>。
    std::unordered_map<uint64_t, std::uint8_t> seen_;
};

} // namespace refuzz::fuzzer
