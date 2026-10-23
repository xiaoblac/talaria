// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedLineageYieldStore unit test (docs/plans/structural-horizon-seed-value.md §5.1).
//
// Cases:
//   1. first-toucher attribution + depth buckets (direct vs downstream) + Get
//   2. dedup within a single call + re-attribute-all-seen is a no-op (no row)
//   3. depth==0 guard: ignored, hashes left UNclaimed for a later valid call
//   4. multi-depth downstream sum + by_depth contents + MaxDepth
//   5. DumpToFile JSONL format
//   6. RAII dump on dtor (path set) vs no dump (path empty)

#include "refuzz/feedback/lineage/seed_lineage_yield_store.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string MakeTempFile(const std::string& tag)
{
    fs::path tmp = fs::temp_directory_path() / ("seed_lineage_yield_test_" + tag + ".jsonl");
    std::error_code ec;
    fs::remove(tmp, ec);
    return tmp.string();
}

std::string ReadFile(const std::string& path)
{
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

constexpr auto npos = std::string::npos;

}  // namespace

int main()
{
    using refuzz::fuzzer::SeedLineageYieldStore;
    std::fprintf(stdout, "Running seed_lineage_yield_store_test...\n");

    // ── Case 1: first-toucher + depth buckets + Get ──────────────────────
    {
        SeedLineageYieldStore s;
        // root 100, depth 1 (direct): {1,2,3} all new → 3 credited.
        assert(s.Attribute(100, 1, {1, 2, 3}) == 3);
        // root 100, depth 2 (downstream): {3,4,5} — 3 already credited → {4,5} → 2.
        assert(s.Attribute(100, 2, {3, 4, 5}) == 2);
        // root 200, depth 1: {4,6} — 4 already first-touched by root 100 → only 6 → 1.
        assert(s.Attribute(200, 1, {4, 6}) == 1);

        auto y100 = s.Get(100);
        assert(y100.Direct() == 3);      // depth 1 = {1,2,3}
        assert(y100.Downstream() == 2);  // depth 2 = {4,5}
        assert(y100.Total() == 5);
        assert(y100.MaxDepth() == 2);

        auto y200 = s.Get(200);
        assert(y200.Direct() == 1);      // {6}
        assert(y200.Downstream() == 0);
        assert(y200.Total() == 1);

        // Unknown root → zero-valued.
        auto y999 = s.Get(999);
        assert(y999.Total() == 0 && y999.MaxDepth() == 0);

        assert(s.RootCount() == 2);
        assert(s.CreditedUnits() == 6);  // {1,2,3,4,5,6}
    }

    // ── Case 2: intra-call dedup + re-attribute is a no-op (no spurious row)
    {
        SeedLineageYieldStore s;
        assert(s.Attribute(1, 1, {7, 7, 7, 8}) == 2);  // {7,8}
        // root 2 covers only already-seen units → 0 credited AND no row created.
        assert(s.Attribute(2, 1, {7, 8}) == 0);
        assert(s.RootCount() == 1);
        assert(s.Get(2).Total() == 0);
    }

    // ── Case 3: depth==0 guard — ignored, units left unclaimed ───────────
    {
        SeedLineageYieldStore s;
        assert(s.Attribute(5, 0, {10, 11}) == 0);
        assert(s.RootCount() == 0);
        assert(s.CreditedUnits() == 0);  // NOT credited → a later valid call can claim them
        assert(s.Attribute(5, 1, {10, 11}) == 2);
    }

    // ── Case 4: multi-depth downstream sum + by_depth + MaxDepth ──────────
    {
        SeedLineageYieldStore s;
        s.Attribute(1, 1, {1});
        s.Attribute(1, 2, {2, 3});
        s.Attribute(1, 3, {4});
        auto y = s.Get(1);
        assert(y.Direct() == 1);
        assert(y.Downstream() == 3);  // depth2(2) + depth3(1)
        assert(y.Total() == 4);
        assert(y.MaxDepth() == 3);
        assert(y.by_depth.at(1) == 1);
        assert(y.by_depth.at(2) == 2);
        assert(y.by_depth.at(3) == 1);
    }

    // ── Case 5: DumpToFile JSONL format ──────────────────────────────────
    {
        SeedLineageYieldStore s;
        s.Attribute(42, 1, {100, 101});
        s.Attribute(42, 2, {102});
        const std::string path = MakeTempFile("dump");
        assert(s.DumpToFile(path));
        const std::string c = ReadFile(path);
        assert(c.find("\"root\":42") != npos);
        assert(c.find("\"direct\":2") != npos);
        assert(c.find("\"downstream\":1") != npos);
        assert(c.find("\"total\":3") != npos);
        assert(c.find("\"max_depth\":2") != npos);
        assert(c.find("\"by_depth\":{\"1\":2,\"2\":1}") != npos);
        std::error_code ec;
        fs::remove(path, ec);
    }

    // ── Case 6: RAII dump on dtor (path set) vs none (path empty) ─────────
    {
        const std::string path = MakeTempFile("raii");
        {
            SeedLineageYieldStore s(path);
            s.Attribute(7, 1, {1, 2, 3});
        }  // dtor → DumpToFile(path)
        const std::string c = ReadFile(path);
        assert(c.find("\"root\":7") != npos);
        assert(c.find("\"direct\":3") != npos);
        std::error_code ec;
        fs::remove(path, ec);

        // Empty dump path → no RAII dump, no crash.
        {
            SeedLineageYieldStore s;
            s.Attribute(1, 1, {1});
        }
    }

    std::fprintf(stdout, "seed_lineage_yield_store_test: OK\n");
    return 0;
}
