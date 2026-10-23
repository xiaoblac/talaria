// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedBand2 impl — see seed_band2.hpp.

#include "refuzz/scheduler/horizon/seed_band2.hpp"

#include "refuzz/program/artifact.hpp"   // ProgramArtifact::As<Prog>
#include "refuzz/program/syz/prog.hpp"   // syz::Prog (calls().size())

#include <algorithm>
#include <fstream>
#include <utility>

namespace refuzz::fuzzer {

bool SeedBand2::LoadFunctionMap(const std::string& tsv_path)
{
    std::ifstream in(tsv_path);
    if (!in.good()) {
        return false;
    }
    std::vector<std::pair<std::uint64_t, std::int32_t>> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        // "<hex_start>\t<block_count>\t<name>"
        const std::size_t t1 = line.find('\t');
        if (t1 == std::string::npos) {
            continue;
        }
        std::uint64_t addr = 0;
        try {
            addr = std::stoull(line.substr(0, t1), nullptr, 16);
        } catch (...) {
            continue;
        }
        const std::size_t t2 = line.find('\t', t1 + 1);
        const std::string bc = (t2 == std::string::npos)
                                   ? line.substr(t1 + 1)
                                   : line.substr(t1 + 1, t2 - t1 - 1);
        std::int32_t blocks = 0;
        try {
            blocks = std::stoi(bc);
        } catch (...) {
            blocks = 0;
        }
        rows.emplace_back(addr, blocks);
    }
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    func_starts_.clear();
    func_blocks_.clear();
    func_starts_.reserve(rows.size());
    func_blocks_.reserve(rows.size());
    for (const auto& [a, b] : rows) {
        func_starts_.push_back(a);
        func_blocks_.push_back(b);
    }
    covered_in_func_.assign(func_starts_.size(), 0);
    seen_pc_.clear();
    return !func_starts_.empty();
}

int SeedBand2::FuncOf(std::uint64_t pc) const
{
    // the function whose [start, next_start) contains pc
    auto it = std::upper_bound(func_starts_.begin(), func_starts_.end(), pc);
    if (it == func_starts_.begin()) {
        return -1;  // below the lowest function start
    }
    return static_cast<int>((it - func_starts_.begin()) - 1);
}

double SeedBand2::OnSeedAdmitted(const std::vector<std::uint64_t>& cover_pcs, int ncalls)
{
    if (!ready() || cover_pcs.empty()) {
        return 0.0;
    }
    // distinct functions the seed reaches
    std::unordered_set<int> reached;
    for (std::uint64_t pc : cover_pcs) {
        const int f = FuncOf(pc);
        if (f >= 0) {
            reached.insert(f);
        }
    }
    // score the uncovered residual against the CURRENT covered set (pre-fold)
    double resid = 0.0;
    for (int f : reached) {
        const std::int32_t r = func_blocks_[f] - covered_in_func_[f];
        if (r > 0) {
            resid += static_cast<double>(r);
        }
    }
    const double score =
        ncalls > 0 ? resid / static_cast<double>(ncalls) : resid;

    // fold: the seed's NEW PCs are now covered → the residual mask decays
    for (std::uint64_t pc : cover_pcs) {
        if (seen_pc_.insert(pc).second) {
            const int f = FuncOf(pc);
            if (f >= 0 && covered_in_func_[f] < func_blocks_[f]) {
                ++covered_in_func_[f];  // clamp at block_count (pc-5/count skew safe)
            }
        }
    }
    return score;
}

double SeedBand2::OnSeedAdmitted(const std::vector<std::uint64_t>& cover_pcs,
                                 const refuzz::program::ProgramArtifact& artifact)
{
    auto prog = artifact.As<refuzz::program::syz::Prog>();
    const int ncalls = prog ? static_cast<int>(prog->calls().size()) : 0;
    return OnSeedAdmitted(cover_pcs, ncalls);
}

} // namespace refuzz::fuzzer
