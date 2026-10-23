// §3.10 oracle #18 — Smash repeat decode count.
//
// Acceptance per `000_plan.md` §6 / §5.2 #18:
//   * a v2 fixture with one prepared seed in corpus (loaded eagerly so
//     decode_text == 1 at LoadAll time).
//   * Drive 1000 successive MutateTyped invocations on the same source
//     artifact (smash-style repeat smashing).
//   * After ResetForTest() + LoadAll: total decode_text_calls == 1
//     (load-time decode); per-iteration MutateTyped path adds zero
//     further decodes; encode_text_calls == 0 over the loop.
//
// Implementation note: the full SmashProducerStage::Perform path
// would also invoke channeldispatcher submit (which materializes
// canonical text and bumps encode_text). The §3.10 step-7 design
// places that materialization in the executor submit boundary, NOT in
// the stage itself. Plan §5.2 #18 measures "over the loop" of
// SmashProducerStage::Perform — that is, just the stage push side.
// Driving MutateTyped directly is the same hot-path call SmashProducer
// makes internally (after step 6), without the queue/submit
// machinery; it gives the same counter answer.

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

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

class TmpDir {
public:
    TmpDir() {
        char tmpl[] = "/tmp/refuzz_oracle18_XXXXXX";
        if (char* dir = mkdtemp(tmpl)) path_ = dir;
    }
    ~TmpDir() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

class StubScheduler final : public refuzz::fuzzer::ISchedulerEngine {
public:
    std::string Name() const override { return "stub"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
    void OnFeedback(uint64_t, refuzz::fuzzer::SeedDisposition) override {}
    void OnSeedAdded(uint64_t) override {}
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return "stub"; }
};

} // namespace

int main() {
    pr::RegisterBuiltinArtifactMaterializers();
    const auto& target = syz::Target::linux_amd64();

    // Prepare corpus: generate one payload + SaveSeed.
    refuzz::fuzzer::SyzV2MutatorEngine boot(target, nullptr, /*seed=*/0xC0FFEE);
    refuzz::fuzzer::Seed empty;
    auto payload = boot.Mutate(empty);
    CHECK(!payload.empty());

    TmpDir tmp;
    CHECK(!tmp.path().empty());
    refuzz::fuzzer::Seed prepared;
    prepared.seed_id  = 1;
    prepared.payload  = payload;
    prepared.priority = 1;
    prepared.metadata.Set(refuzz::fuzzer::SeedSourceMetadata{
        refuzz::fuzzer::SeedSource::kBootCorpus, /*attempt=*/0});
    prepared.metadata.Set(refuzz::fuzzer::SeedAdmissionStateMetadata{});
    CHECK(refuzz::fuzzer::CorpusDiskIO::SaveSeed(prepared, tmp.path()));

    // ResetForTest, then LoadAll (one decode at load). §3.10
    // follow-up: pass a registry-driven materializer for syz_v2 /
    // linux-amd64 — corpus disk layer is format-neutral now.
    pcc::ResetForTest();
    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(100);
    auto materializer = pr::MakeRegistryMaterializer(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{target.os(), target.arch(), target.revision()});
    CHECK(refuzz::fuzzer::CorpusDiskIO::LoadAll(
              store, scheduler, tmp.path(), ids, materializer) == 1);
    auto handle = store.GetSeed(100);
    CHECK(handle != nullptr);
    CHECK(handle->artifact != nullptr);

    // Drive 1000 successive MutateTyped — same artifact each iteration.
    refuzz::fuzzer::SyzV2MutatorEngine engine(target, nullptr, /*seed=*/0x5A5A);
    constexpr int kIters = 1000;
    for (int i = 0; i < kIters; ++i) {
        auto result = engine.MutateTyped(*handle->artifact);
        (void)result.artifact.As<syz::Prog>();
    }

    auto c = pcc::ReadForTest();
    std::fprintf(stderr,
                 "oracle #18 (smash repeat decode count, %d iters): "
                 "decode_text=%llu (expect 1) encode_text=%llu (expect 0) "
                 "decode_wire=%llu encode_wire=%llu\n",
                 kIters,
                 (unsigned long long)c.decode_text_calls,
                 (unsigned long long)c.encode_text_calls,
                 (unsigned long long)c.decode_wire_calls,
                 (unsigned long long)c.encode_wire_calls);

    CHECK(c.decode_text_calls == 1);
    CHECK(c.encode_text_calls == 0);
    CHECK(c.encode_wire_calls == 0);

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
