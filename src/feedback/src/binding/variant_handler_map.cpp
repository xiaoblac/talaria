// Copyright 2026 reFuzz project author -------youngkk.
//
// VariantHandlerMap impl — see variant_handler_map.hpp.

#include "refuzz/feedback/binding/variant_handler_map.hpp"

#include "refuzz/feedback/observation/kernel_observation.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace refuzz::fuzzer {

bool VariantHandlerMap::LoadFunctionMap(const std::string& tsv_path)
{
    func_starts_.clear();
    func_blocks_.clear();
    func_names_.clear();
    std::ifstream in(tsv_path);
    if (!in) {
        return false;
    }
    // rows of "<hex_start>\t<block_count>\t<name>"; sort by start ascending.
    std::vector<std::tuple<std::uint64_t, std::int32_t, std::string>> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream ss(line);
        std::string a, b, nm;
        if (!std::getline(ss, a, '\t')) {
            continue;
        }
        std::getline(ss, b, '\t');
        std::getline(ss, nm, '\t');
        std::uint64_t addr = 0;
        try {
            addr = std::stoull(a, nullptr, 16);
        } catch (...) {
            continue;
        }
        std::int32_t blk = 1;
        try {
            blk = b.empty() ? 1 : static_cast<std::int32_t>(std::stol(b));
        } catch (...) {
            blk = 1;
        }
        rows.emplace_back(addr, blk, nm);
    }
    std::sort(rows.begin(), rows.end(),
              [](const auto& x, const auto& y) { return std::get<0>(x) < std::get<0>(y); });
    func_starts_.reserve(rows.size());
    func_blocks_.reserve(rows.size());
    func_names_.reserve(rows.size());
    for (auto& r : rows) {
        func_starts_.push_back(std::get<0>(r));
        func_blocks_.push_back(std::get<1>(r));
        func_names_.push_back(std::move(std::get<2>(r)));
    }
    return !func_starts_.empty();
}

int VariantHandlerMap::FuncOf(std::uint64_t pc) const
{
    // largest start <= pc
    auto it = std::upper_bound(func_starts_.begin(), func_starts_.end(), pc);
    if (it == func_starts_.begin()) {
        return -1;
    }
    return static_cast<int>((it - func_starts_.begin()) - 1);
}

void VariantHandlerMap::OnExec(const KernelExecutionObservation& obs)
{
    if (func_starts_.empty()) {
        return;
    }
    for (const auto& call : obs.per_call) {
        if (!call.executed || call.coverage_hashes.empty()) {
            continue;
        }
        const std::uint32_t vid = call.syscall_id;
        ++exec_count_[vid];
        auto& funcs = per_variant_[vid];
        // dedup within this call: one exec contributes +1 per DISTINCT covered function.
        std::unordered_set<int> hit;
        for (std::uint64_t pc : call.coverage_hashes) {
            int f = FuncOf(pc);
            if (f >= 0 && hit.insert(f).second) {
                ++funcs[f];
            }
        }
    }
}

bool VariantHandlerMap::Flush(const std::string& path) const
{
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        return false;
    }
    // stable order by variant id
    std::vector<std::uint32_t> ids;
    ids.reserve(per_variant_.size());
    for (const auto& kv : per_variant_) {
        ids.push_back(kv.first);
    }
    std::sort(ids.begin(), ids.end());
    constexpr std::size_t kTopK = 16;
    for (std::uint32_t vid : ids) {
        const auto& funcs = per_variant_.at(vid);
        // top-K handler functions by hit-count
        std::vector<std::pair<int, std::uint32_t>> v(funcs.begin(), funcs.end());
        std::sort(v.begin(), v.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        std::uint32_t execs = 0;
        auto ec = exec_count_.find(vid);
        if (ec != exec_count_.end()) {
            execs = ec->second;
        }
        out << "{\"variant_id\":" << vid;
        if (vid < id_to_name_.size() && !id_to_name_[vid].empty()) {
            out << ",\"variant\":\"" << id_to_name_[vid] << "\"";
        }
        out << ",\"execs\":" << execs << ",\"n_handlers\":" << funcs.size()
            << ",\"handlers\":[";
        for (std::size_t i = 0; i < v.size() && i < kTopK; ++i) {
            if (i) {
                out << ",";
            }
            const std::string& nm =
                (v[i].first >= 0 && static_cast<std::size_t>(v[i].first) < func_names_.size())
                    ? func_names_[v[i].first]
                    : std::string{};
            out << "[\"" << nm << "\"," << v[i].second << "]";
        }
        out << "]}\n";
    }
    return true;
}

}  // namespace refuzz::fuzzer
