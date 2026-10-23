// Copyright 2026 reFuzz project author -------youngkk.
//
// seed_band2_test — the band-② residual-per-call scorer: map load, score-then-fold
// decay, per-call normalization, bounds.

#include "refuzz/scheduler/horizon/seed_band2.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <string>

using refuzz::fuzzer::SeedBand2;

static bool close(double a, double b) { return std::fabs(a - b) < 1e-9; }

int main()
{
    // function_block_map.tsv: big_handler@0x1000 (10 blocks), small@0x2000 (2 blocks)
    const std::string path = "/tmp/seed_band2_test_map.tsv";
    {
        std::ofstream o(path);
        o << "0000000000001000\t10\tbig_handler\n"
          << "0000000000002000\t2\tsmall\n";
    }

    SeedBand2 b2;
    assert(b2.LoadFunctionMap(path));
    assert(b2.function_count() == 2);

    // unloaded component / empty cover → 0
    {
        SeedBand2 empty;
        assert(close(empty.OnSeedAdmitted({0x1000}, 1), 0.0));
    }
    assert(close(b2.OnSeedAdmitted({}, 1), 0.0));

    // seed A: 2 PCs in big_handler (uncovered), 1 call → residual 10 / 1 = 10
    assert(close(b2.OnSeedAdmitted({0x1000, 0x1004}, 1), 10.0));
    // fold covered 2 distinct blocks of big_handler → seed B (new PC in big) sees 10-2=8
    assert(close(b2.OnSeedAdmitted({0x1008}, 1), 8.0));  // decay (mask)

    // seed C reaches big (now 3 covered) + small (0 covered), ncalls=3:
    //   residual = (10-3) + (2-0) = 9 → 9/3 = 3.0   (per-call de-confound)
    assert(close(b2.OnSeedAdmitted({0x1000, 0x2000}, 3), 3.0));

    // ncalls=0 → raw residual (no division). small now has 1 covered (0x2000):
    //   reach small only → 2-1 = 1
    assert(close(b2.OnSeedAdmitted({0x2004}, 0), 1.0));

    // PC below the lowest function start → no function → 0 contribution
    assert(close(b2.OnSeedAdmitted({0x10}, 1), 0.0));

    std::remove(path.c_str());
    std::printf("seed_band2_test: OK\n");
    return 0;
}
