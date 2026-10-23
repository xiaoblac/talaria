// Unit test for resource_centric — port of rand.go::resourceCentric.
// Three deterministic cases:
//   1. EmptyCorpus      — null ICorpusStore → fallthrough.
//   2. CompatibleProducer — corpus with a producer seed, consumer
//                            ends up referencing the cloned producer.
//   3. Determinism      — same RNG seed + same corpus → same output.
// Probabilistic measurements live in tools/run_all_oracles.sh.

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "syz_v2_test_helpers.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;
namespace pr     = ::refuzz::program;
namespace fuz    = ::refuzz::fuzzer;
using ::refuzz::tests::syz_v2::find_resource_type;

// Production InMemoryCorpusStore (corpus/corpus_store.hpp) rejects
// payload-empty seeds, but resource_centric must be tested against
// an artifact-only corpus (no payload) to verify the artifact-first
// contract. So this fixture is intentionally minimal and duplicates
// AddSeed/ForEachSeed only.
class ArtifactOnlyCorpus final : public fuz::ICorpusStore {
public:
    bool AddSeed(fuz::Seed seed) override {
        seeds_.push_back(std::make_shared<const fuz::Seed>(std::move(seed)));
        return true;
    }
    fuz::SeedHandle GetSeed(uint64_t seed_id) const override {
        for (const auto& s : seeds_) {
            if (s->seed_id == seed_id) return s;
        }
        return nullptr;
    }
    void ForEachSeed(const fuz::SeedVisitor& visitor) const override {
        for (const auto& s : seeds_) visitor(*s);
    }
    std::optional<uint64_t> SampleSeedId(std::mt19937_64&) const override {
        if (seeds_.empty()) return std::nullopt;
        return seeds_.front()->seed_id;
    }
    void MarkInteresting(uint64_t) override {}
    size_t Size() const override { return seeds_.size(); }
private:
    std::vector<fuz::SeedHandle> seeds_;
};

// Build a synthetic corpus seed that contains a producer for `fd`.
// We generate a Prog from a deterministic seed via generate_program
// (which on success contains real syscalls). Then if any of those
// syscalls produces an `fd`, we wrap the Prog into an artifact and
// add as a seed. Caller may need to retry several seeds to find one
// that produces fd.
fuz::Seed build_corpus_seed_with_fd(const syz::Target& target,
                                    uint64_t prog_seed,
                                    uint64_t seed_id) {
    auto prog = mut_v2::generate_program(target, prog_seed,
                                         /*ncalls=*/8,
                                         /*ct=*/nullptr);
    CHECK(prog != nullptr);
    std::shared_ptr<const syz::Prog> shared_prog(std::move(prog));
    auto artifact_obj = syz::MakeArtifactFromTypedProg(shared_prog);
    fuz::Seed s;
    s.seed_id = seed_id;
    // payload intentionally empty — exercises the artifact-first
    // contract. resource_centric must NOT decode payload here.
    s.artifact = std::make_shared<const pr::ProgramArtifact>(
        std::move(artifact_obj));
    return s;
}

// ---------------------------------------------------------------------
// Case 1: empty corpus / null store → resource_centric returns
// {nullptr,{}}.
// ---------------------------------------------------------------------
void test_empty_corpus() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::reset_resource_centric_payload_fallback_hits();
    mut_v2::RandGen r(0xF1F1F1F1ULL);
    mut_v2::GenState s(target);
    // No corpus_store set → corpus_store() returns null.
    auto result = mut_v2::resource_centric(r, s, fd_rt, syz::Dir::kIn);
    CHECK(result.arg == nullptr);
    CHECK(result.calls.empty());
    // No fallback was used (no corpus walked at all).
    CHECK(mut_v2::resource_centric_payload_fallback_hits() == 0);

    // Empty store (zero seeds) — same outcome.
    ArtifactOnlyCorpus empty_corpus;
    s.set_corpus_store(&empty_corpus);
    auto result2 = mut_v2::resource_centric(r, s, fd_rt, syz::Dir::kIn);
    CHECK(result2.arg == nullptr);
    CHECK(result2.calls.empty());
    CHECK(mut_v2::resource_centric_payload_fallback_hits() == 0);
}

// ---------------------------------------------------------------------
// Case 2: corpus with at least one fd-producing seed; assert
// resource_centric returns a non-null arg AND a non-empty call chain
// AND the artifact-first counter stays at 0 (we used artifact-first
// for every walked seed).
// ---------------------------------------------------------------------
void test_compatible_producer() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::reset_resource_centric_payload_fallback_hits();
    ArtifactOnlyCorpus corpus;
    // Stuff several deterministic seeds; most random 8-call progs
    // create at least one fd.
    for (uint64_t i = 0; i < 16; ++i) {
        corpus.AddSeed(build_corpus_seed_with_fd(target,
                                                 /*prog_seed=*/0xC0001000ULL + i,
                                                 /*seed_id=*/i));
    }
    CHECK(corpus.Size() == 16);

    int found = 0;
    int with_calls = 0;
    for (uint64_t k = 0; k < 50; ++k) {
        mut_v2::RandGen r(0xC2C2C2C2ULL + k);
        mut_v2::GenState s(target);
        s.set_corpus_store(&corpus);
        auto result = mut_v2::resource_centric(r, s, fd_rt, syz::Dir::kIn);
        if (result.arg != nullptr) {
            ++found;
            if (!result.calls.empty()) ++with_calls;
            CHECK(result.arg->type() == fd_rt);
            CHECK(result.arg->arg_kind() == syz::ArgKind::kResult);
            const auto* ra =
                static_cast<const syz::ResultArg*>(result.arg.get());
            // The consumer must reference some producer in the
            // returned call list (the picked clone).
            CHECK(ra->res() != nullptr);
        }
    }
    std::fprintf(stderr, "  found=%d with_calls=%d (of 50 attempts)\n",
                 found, with_calls);
    CHECK(found >= 25);          // overwhelming majority succeed
    CHECK(with_calls == found);  // every success carries a chain
    // Artifact-first contract: 0 payload-decode fallbacks.
    CHECK(mut_v2::resource_centric_payload_fallback_hits() == 0);
    std::fprintf(stderr, "  resource_centric_payload_fallbacks=%llu\n",
                 static_cast<unsigned long long>(
                     mut_v2::resource_centric_payload_fallback_hits()));
}

// ---------------------------------------------------------------------
// Case 3: deterministic. Same RNG seed + same corpus snapshot →
// returned `result.calls.size()` matches across two independent runs.
// (Pointer equality cannot be checked because each run produces a
// fresh clone.)
// ---------------------------------------------------------------------
void test_determinism() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    ArtifactOnlyCorpus corpus;
    for (uint64_t i = 0; i < 8; ++i) {
        corpus.AddSeed(build_corpus_seed_with_fd(target,
                                                 /*prog_seed=*/0xD0001000ULL + i,
                                                 /*seed_id=*/i));
    }

    auto run = [&](uint64_t seed) {
        mut_v2::RandGen r(seed);
        mut_v2::GenState s(target);
        s.set_corpus_store(&corpus);
        return mut_v2::resource_centric(r, s, fd_rt, syz::Dir::kIn);
    };

    for (uint64_t base = 0xD2D2D2D2ULL; base < 0xD2D2D2D2ULL + 20; ++base) {
        auto a = run(base);
        auto b = run(base);
        CHECK((a.arg == nullptr) == (b.arg == nullptr));
        CHECK(a.calls.size() == b.calls.size());
        // If both succeed, the consumer's referenced producer should
        // sit at the same call index in the returned chain.
        if (a.arg != nullptr) {
            CHECK(b.arg != nullptr);
            const auto* ra =
                static_cast<const syz::ResultArg*>(a.arg.get());
            const auto* rb =
                static_cast<const syz::ResultArg*>(b.arg.get());
            CHECK(ra->res() != nullptr);
            CHECK(rb->res() != nullptr);
            // Find the index of ra->res() in a.calls and rb->res() in
            // b.calls; they should match.
            auto find_call_with_res = [](const auto& calls,
                                         const syz::ResultArg* needle)
                -> int {
                for (size_t i = 0; i < calls.size(); ++i) {
                    bool found = false;
                    std::function<void(const syz::Arg*)> visit =
                        [&](const syz::Arg* arg) {
                            if (found || arg == nullptr) return;
                            if (arg->arg_kind() == syz::ArgKind::kResult) {
                                if (static_cast<const syz::ResultArg*>(arg)
                                        == needle) {
                                    found = true;
                                    return;
                                }
                            }
                            // Recurse via inner / option / parent.
                            // Minimal: walk Group/Union/Pointer.
                            if (arg->arg_kind() == syz::ArgKind::kGroup) {
                                for (const auto& c :
                                     static_cast<const syz::GroupArg*>(arg)
                                         ->inner()) {
                                    visit(c.get());
                                    if (found) return;
                                }
                            } else if (arg->arg_kind() ==
                                       syz::ArgKind::kUnion) {
                                visit(static_cast<const syz::UnionArg*>(arg)
                                          ->option());
                            } else if (arg->arg_kind() ==
                                       syz::ArgKind::kPointer) {
                                visit(static_cast<const syz::PointerArg*>(arg)
                                          ->res());
                            }
                        };
                    if (calls[i]->ret()) visit(calls[i]->ret());
                    if (!found) {
                        for (const auto& a : calls[i]->args()) {
                            visit(a.get());
                            if (found) break;
                        }
                    }
                    if (found) return static_cast<int>(i);
                }
                return -1;
            };
            const int ia = find_call_with_res(a.calls, ra->res());
            const int ib = find_call_with_res(b.calls, rb->res());
            CHECK(ia >= 0);
            CHECK(ia == ib);
        }
    }
}

} // namespace

int main() {
    RUN_TEST(test_empty_corpus);
    RUN_TEST(test_compatible_producer);
    RUN_TEST(test_determinism);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
