// §3.10 D6 — Seed authoritative-source assertion.
//
// v2 hot-path entries call this helper to catch the regression where
// `seed.payload` accidentally becomes the read source on the v2
// pipeline. Step 4 added `Seed::artifact`; this body now performs the
// real check.
//
// Debug-only: release builds compile to a no-op so production
// throughput is unaffected. The corresponding production-time
// enforcement is the codec_counters check in oracles #17 / #18 / #19.

#include "refuzz/program/seed.hpp"

#include <cstdio>
#include <cstdlib>

namespace refuzz::program::seed {

void AssertV2Authoritative(const refuzz::fuzzer::Seed& seed) {
#ifndef NDEBUG
    if (seed.artifact == nullptr) {
        std::fprintf(stderr,
                     "AssertV2Authoritative: seed.artifact is null on a v2 "
                     "hot-path entry (seed_id=%llu) — D6 requires the v2 "
                     "profile to keep artifact authoritative\n",
                     static_cast<unsigned long long>(seed.seed_id));
        std::abort();
    }
#else
    (void)seed;
#endif
}

} // namespace refuzz::program::seed
