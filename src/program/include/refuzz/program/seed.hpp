#pragma once

#include "refuzz/core/metadata.hpp"
#include "refuzz/program/artifact.hpp"   // §3.10 step 4 — Seed::artifact

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::fuzzer {

struct Seed {
    uint64_t seed_id = 0;

    // [v1 — bytes path. Stays as a compat cache while v1 paths remain
    //  compileable per §3.10 D1; v2 hot-path code MUST NOT read this
    //  field (oracle #19 enforces decode/encode counter == 0 across
    //  v2 hot path).]
    std::vector<uint8_t> payload;

    // [v2 — §3.10 D6 authority. v2 hot-path entries read `artifact`
    //  exclusively; v1 profile leaves it null and continues to use
    //  `payload`. Shared so a single artifact can fan out to follow-up
    //  queues / crash logs / repro candidates without copy.]
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;

    int32_t priority = 0;
    uint32_t interesting_hits = 0;
    refuzz::core::MetadataMap metadata;
};

// [6b-3 — 当前版本] using LoopStats 别名已随 LoopStats 删除

} // namespace refuzz::fuzzer

// -----------------------------------------------------------------
// §3.10 D6 — v2 hot-path entry assertion.
//
// Every v2 hot-path entry (SyzV2MutatorEngine::MutateTyped,
// MutationalProducerStage::Perform on a v2 active engine, smash /
// minimize on v2) MUST call AssertV2Authoritative(seed) so a
// regression that lets a v2 path read seed.payload is caught early.
//
// Step 4 replaced the step-1 no-op stub with the real check:
// debug builds abort if seed.artifact is null; release builds compile
// to a no-op (production-time enforcement is the codec_counters check
// in oracles #17 / #18 / #19).
// -----------------------------------------------------------------

namespace refuzz::program::seed {

void AssertV2Authoritative(const refuzz::fuzzer::Seed& seed);

} // namespace refuzz::program::seed
