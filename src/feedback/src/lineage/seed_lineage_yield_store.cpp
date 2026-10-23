// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedLineageYieldStore impl — see seed_lineage_yield_store.hpp.

#include "refuzz/feedback/lineage/seed_lineage_yield_store.hpp"

#include <fstream>
#include <utility>

namespace refuzz::fuzzer {

SeedLineageYieldStore::SeedLineageYieldStore(std::string dump_path)
    : dump_path_(std::move(dump_path))
{
}

SeedLineageYieldStore::~SeedLineageYieldStore()
{
    if (!dump_path_.empty()) {
        DumpToFile(dump_path_);
    }
}

std::uint64_t SeedLineageYieldStore::RootYield::Direct() const
{
    auto it = by_depth.find(1);
    return it == by_depth.end() ? 0 : it->second;
}

std::uint64_t SeedLineageYieldStore::RootYield::Downstream() const
{
    std::uint64_t n = 0;
    for (const auto& [d, c] : by_depth) {
        if (d >= 2) {
            n += c;
        }
    }
    return n;
}

std::uint64_t SeedLineageYieldStore::RootYield::Total() const
{
    std::uint64_t n = 0;
    for (const auto& [d, c] : by_depth) {
        n += c;
    }
    return n;
}

std::uint32_t SeedLineageYieldStore::RootYield::MaxDepth() const
{
    return by_depth.empty() ? 0u : by_depth.rbegin()->first;
}

std::size_t SeedLineageYieldStore::Attribute(
    std::uint64_t root_seed_id, std::uint32_t depth,
    const std::vector<std::uint64_t>& executed_cover)
{
    if (depth == 0) {
        return 0;  // depth is 1-based; 0 is a caller bug, not a real lineage step
    }
    std::size_t credited = 0;
    RootYield* ry = nullptr;  // lazily bound on the first newly-credited unit, so
                              // a re-execution that covers nothing new adds no row
    for (std::uint64_t h : executed_cover) {
        if (!credited_.insert(h).second) {
            continue;  // some lineage already first-touched this unit
        }
        if (ry == nullptr) {
            ry = &by_root_[root_seed_id];
        }
        ry->by_depth[depth] += 1;
        ++credited;
    }
    return credited;
}

SeedLineageYieldStore::RootYield
SeedLineageYieldStore::Get(std::uint64_t root_seed_id) const
{
    auto it = by_root_.find(root_seed_id);
    return it == by_root_.end() ? RootYield{} : it->second;
}

bool SeedLineageYieldStore::DumpToFile(const std::string& path) const
{
    std::ofstream out(path, std::ios::out | std::ios::trunc);
    if (!out.good()) {
        return false;
    }
    for (const auto& [root, ry] : by_root_) {
        out << "{\"root\":" << root
            << ",\"direct\":" << ry.Direct()
            << ",\"downstream\":" << ry.Downstream()
            << ",\"total\":" << ry.Total()
            << ",\"max_depth\":" << ry.MaxDepth()
            << ",\"by_depth\":{";
        bool first = true;
        for (const auto& [d, c] : ry.by_depth) {
            if (!first) {
                out << ',';
            }
            out << '"' << d << "\":" << c;
            first = false;
        }
        out << "}}\n";
    }
    return out.good();
}

bool SeedLineageYieldStore::Flush() const
{
    return dump_path_.empty() ? true : DumpToFile(dump_path_);
}

} // namespace refuzz::fuzzer
