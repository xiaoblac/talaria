// §3.10 oracle #17 — MutateTyped hot path is codec-free.
//
// After `program::codec_counters::ResetForTest()`, calling
// `SyzV2MutatorEngine::MutateTyped(artifact)` 1000× on a populated
// artifact records `decode_text_calls == 0` and `encode_text_calls == 0`
// and `encode_wire_calls == 0`.
//
// Acceptance criterion: oracle prints "ALL OK" only when all three
// counters stay at zero across the loop. Any non-zero is a regression
// that violates plan §3 D8 / §5.2 #17.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <vector>

namespace {

namespace pr  = refuzz::program;
namespace pcc = refuzz::program::codec_counters;
namespace syz = refuzz::program::syz;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

pr::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = syz::Target::linux_amd64();
    return pr::ProgramTargetKey{t.os(), t.arch(), t.revision()};
}

pr::ProgramArtifact BuildSeedArtifact() {
    refuzz::fuzzer::SyzV2MutatorEngine boot(syz::Target::linux_amd64(),
                                            nullptr, /*master_seed=*/0xC100E);
    refuzz::fuzzer::Seed empty;
    auto bytes = boot.Mutate(empty);
    CHECK(!bytes.empty());
    auto art = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg, LinuxAmd64Key(), std::move(bytes));
    CHECK(art.has_value());
    return std::move(*art);
}

} // namespace

int main() {
    pr::RegisterBuiltinArtifactMaterializers();

    auto seed_artifact = BuildSeedArtifact();
    refuzz::fuzzer::SyzV2MutatorEngine engine(syz::Target::linux_amd64(),
                                              nullptr, /*master_seed=*/2026);

    pcc::ResetForTest();
    constexpr int kIters = 1000;
    for (int i = 0; i < kIters; ++i) {
        auto result = engine.MutateTyped(seed_artifact);
        // Touch typed view; do NOT call canonical_payload (oracle gate).
        (void)result.artifact.As<syz::Prog>();
    }
    auto c = pcc::ReadForTest();

    std::fprintf(stderr,
                 "oracle #17 (mutate_typed_codec_free, %d iters): "
                 "decode_text=%llu encode_text=%llu "
                 "decode_wire=%llu encode_wire=%llu\n",
                 kIters,
                 (unsigned long long)c.decode_text_calls,
                 (unsigned long long)c.encode_text_calls,
                 (unsigned long long)c.decode_wire_calls,
                 (unsigned long long)c.encode_wire_calls);

    CHECK(c.decode_text_calls == 0);
    CHECK(c.encode_text_calls == 0);
    CHECK(c.encode_wire_calls == 0);

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
