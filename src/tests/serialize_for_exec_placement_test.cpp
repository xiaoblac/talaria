// §3.10 oracle #20 — `serialize_for_exec` placement check.
//
// Runtime-tracer form: drive a representative mutator/stage hot loop
// (1000× MutateTyped on an artifact) and assert that
// `program::codec_counters::encode_wire_calls` stays at zero. The
// allowed production callers of `serialize_for_exec` are
// `Executor::Submit` and §3.11-C1 repro/minimize candidate evaluation.
// This test invokes neither path.
//
// Tools / oracle binaries that legitimately call `serialize_for_exec`
// (refuzz-syz-v2-exec-wire / -roundtrip / -smoke / -trace, plus the
// repro_replay / wire_driver_real binaries) are exempt by allowlist
// per `docs/typed-program-pipeline/000_plan.md` §3 D8 + §5.2 #20.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
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
                                            nullptr, /*master_seed=*/0xBADF00D);
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
                                              nullptr, /*master_seed=*/0x501);

    pcc::ResetForTest();
    constexpr int kIters = 1000;
    for (int i = 0; i < kIters; ++i) {
        auto result = engine.MutateTyped(seed_artifact);
        (void)result.artifact.As<syz::Prog>();
        // canonical_payload() / MaterializeCanonicalText would bump
        // encode_text but NOT encode_wire — that's a separate counter
        // and only `serialize_for_exec` bumps it.
    }
    auto c = pcc::ReadForTest();
    std::fprintf(stderr,
                 "oracle #20 (serialize_for_exec_placement, %d mutator iters): "
                 "encode_wire_calls=%llu (expected 0; non-zero means a "
                 "production hot path called serialize_for_exec, which "
                 "violates D8 — only Executor::Submit and §3.11-C1 "
                 "repro/minimize may)\n",
                 kIters,
                 (unsigned long long)c.encode_wire_calls);
    CHECK(c.encode_wire_calls == 0);

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
