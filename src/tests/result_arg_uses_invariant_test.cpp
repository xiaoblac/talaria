// §3.11-C0 oracle #23 — ResultArg.uses_ forward-edge invariant.
//
// Asserts the invariant added in arg.hpp:
//   for every ResultArg* c, c.res() != null  ⇔  c ∈ c.res()->uses()
//   for every ResultArg* p, ∀c ∈ p.uses(), c.res() == p
//
// Scenarios:
//   1. Just-generated v2 program — invariant holds across all ResultArgs.
//   2. DeepClone(p) — forward edges in the clone are correctly rebuilt
//      (placeholder stash via set_res_raw + remap via self-maintaining
//      set_res in clone.cpp:146).
//   3. Self-maintaining set_res(new_p) when res_ was already non-null —
//      old producer's uses_ no longer holds the consumer; new producer's
//      uses_ does.
//   4. Self-maintaining set_res(nullptr) on a consumer — old producer's
//      uses_ no longer holds the consumer.
//   5. ResultArg destruction — any surviving consumer's res_ is nulled
//      (defensive cleanup so dangling pointers can't surface).
//   6. 1000-iteration randomized rewire fuzz — invariant holds after
//      every operation.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <random>
#include <string_view>
#include <unordered_set>
#include <utility>
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

namespace syz = refuzz::program::syz;

// ----- helpers (mirror of syz_v2_clone_test.cpp) -----

void ForEachResultArg(syz::Arg* a,
                      const std::function<void(syz::ResultArg*)>& visit) {
    if (a == nullptr) return;
    switch (a->arg_kind()) {
        case syz::ArgKind::kConst:
        case syz::ArgKind::kData:
            return;
        case syz::ArgKind::kPointer: {
            auto* pa = static_cast<syz::PointerArg*>(a);
            ForEachResultArg(pa->res(), visit);
            return;
        }
        case syz::ArgKind::kGroup: {
            auto* ga = static_cast<syz::GroupArg*>(a);
            for (auto& child : ga->mutable_inner()) {
                ForEachResultArg(child.get(), visit);
            }
            return;
        }
        case syz::ArgKind::kUnion: {
            auto* ua = static_cast<syz::UnionArg*>(a);
            ForEachResultArg(ua->option(), visit);
            return;
        }
        case syz::ArgKind::kResult: {
            auto* ra = static_cast<syz::ResultArg*>(a);
            visit(ra);
            return;
        }
    }
}

void ForEachResultArgInProg(syz::Prog& p,
                            const std::function<void(syz::ResultArg*)>& visit) {
    for (auto& call : p.mutable_calls()) {
        if (call->mutable_ret() != nullptr) visit(call->mutable_ret());
        for (auto& a : call->mutable_args()) {
            ForEachResultArg(a.get(), visit);
        }
    }
}

std::vector<syz::ResultArg*> CollectAllResultArgs(syz::Prog& p) {
    std::vector<syz::ResultArg*> out;
    ForEachResultArgInProg(p, [&](syz::ResultArg* ra) { out.push_back(ra); });
    return out;
}

// Universal invariant check across all ResultArgs in a prog.
void CheckInvariant(syz::Prog& p) {
    auto all = CollectAllResultArgs(p);
    std::unordered_set<syz::ResultArg*> live(all.begin(), all.end());

    for (auto* c : all) {
        const syz::ResultArg* producer = c->res();
        if (producer == nullptr) continue;
        // Producer must be live in this prog.
        CHECK(live.count(const_cast<syz::ResultArg*>(producer)) == 1);
        // Forward edge: producer.uses() must contain c.
        const auto& fwd = producer->uses();
        CHECK(fwd.count(c) == 1);
    }

    // For every producer node, every consumer in node.uses() must
    // back-reference it.
    for (auto* node : all) {
        for (auto* c : node->uses()) {
            CHECK(live.count(c) == 1);
            CHECK(c->res() == node);
        }
    }
}

// Generate a v2 program via SyzV2MutatorEngine on an empty seed.
std::unique_ptr<syz::Prog> GenerateOneProg(uint64_t master_seed) {
    const auto& target = syz::Target::linux_amd64();
    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, master_seed);
    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    refuzz::fuzzer::Seed empty;
    auto bytes = manager.Handle().Get().Mutate(empty);
    if (bytes.empty()) return nullptr;

    syz::TextDecoder decoder(target, syz::DecodeMode::kNonStrict);
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),
                          bytes.size());
    auto prog_or = decoder.decode(text);
    if (!prog_or || !prog_or.value()) return nullptr;
    return std::move(*prog_or);
}

// Find a prog with at least one cross-call ResultArg ref (for tests
// that need the forward-edge to be non-empty).
std::unique_ptr<syz::Prog> FindProgWithResultRef(int attempts) {
    for (int i = 0; i < attempts; ++i) {
        auto p = GenerateOneProg(/*master_seed=*/uint64_t{0xC011E} + i);
        if (p == nullptr) continue;
        bool has_ref = false;
        ForEachResultArgInProg(*p, [&](syz::ResultArg* ra){
            if (ra->res() != nullptr) has_ref = true;
        });
        if (has_ref) return p;
    }
    return nullptr;
}

// ----- tests -----

// Scenario 1: invariant holds on a freshly-decoded generated program.
// Decoder calls set_res() during decode; if that path correctly went
// through self-maintaining set_res(), the invariant holds.
void TestInvariantOnGeneratedProg() {
    auto p = FindProgWithResultRef(/*attempts=*/16);
    if (p == nullptr) {
        std::fprintf(stderr, "skip: no generated prog with cross-ref in 16 tries\n");
        return;
    }
    CheckInvariant(*p);
}

// Scenario 2: clone preserves the invariant. CloneResultArg uses
// set_res_raw to stash the OLD pointer (no forward-edge insertion);
// RemapArg then calls set_res(NEW_ptr) which establishes the edge in
// the cloned graph.
void TestInvariantOnClone() {
    auto src = FindProgWithResultRef(/*attempts=*/16);
    if (src == nullptr) {
        std::fprintf(stderr, "skip: no generated prog with cross-ref in 16 tries\n");
        return;
    }
    CheckInvariant(*src);

    auto clone = syz::DeepClone(*src);
    CHECK(clone != nullptr);
    CheckInvariant(*clone);

    // Cross-prog isolation: clone's producer.uses() contains no source
    // pointers (a stale insertion would mean set_res_raw leaked into
    // the source's uses_).
    auto src_set = CollectAllResultArgs(*src);
    std::unordered_set<syz::ResultArg*> src_live(src_set.begin(), src_set.end());
    ForEachResultArgInProg(*clone, [&](syz::ResultArg* ra){
        for (auto* c : ra->uses()) {
            CHECK(src_live.count(c) == 0);
        }
    });
    // Source's uses() also must contain no clone pointers.
    auto clone_set = CollectAllResultArgs(*clone);
    std::unordered_set<syz::ResultArg*> clone_live(clone_set.begin(), clone_set.end());
    ForEachResultArgInProg(*src, [&](syz::ResultArg* ra){
        for (auto* c : ra->uses()) {
            CHECK(clone_live.count(c) == 0);
        }
    });
}

// Scenario 3: rewire res via set_res(new_p) — forward edge moves.
void TestSetResMovesForwardEdge() {
    auto p = FindProgWithResultRef(/*attempts=*/16);
    if (p == nullptr) {
        std::fprintf(stderr, "skip: no generated prog with cross-ref in 16 tries\n");
        return;
    }
    auto all = CollectAllResultArgs(*p);

    // Find a consumer (res() != null) and another distinct producer.
    syz::ResultArg* consumer  = nullptr;
    syz::ResultArg* old_prod  = nullptr;
    syz::ResultArg* new_prod  = nullptr;
    for (auto* a : all) {
        if (a->res() != nullptr) {
            consumer = a;
            old_prod = a->mutable_res();
            break;
        }
    }
    CHECK(consumer != nullptr);
    for (auto* a : all) {
        if (a != consumer && a != old_prod) {
            new_prod = a;
            break;
        }
    }
    CHECK(new_prod != nullptr);

    CHECK(old_prod->uses().count(consumer) == 1);
    CHECK(new_prod->uses().count(consumer) == 0);

    consumer->set_res(new_prod);

    CHECK(old_prod->uses().count(consumer) == 0);
    CHECK(new_prod->uses().count(consumer) == 1);
    CHECK(consumer->res() == new_prod);
    CheckInvariant(*p);
}

// Scenario 4: set_res(nullptr) clears the forward edge.
void TestSetResNullClearsForwardEdge() {
    auto p = FindProgWithResultRef(/*attempts=*/16);
    if (p == nullptr) {
        std::fprintf(stderr, "skip: no generated prog with cross-ref in 16 tries\n");
        return;
    }
    auto all = CollectAllResultArgs(*p);

    syz::ResultArg* consumer = nullptr;
    syz::ResultArg* prod     = nullptr;
    for (auto* a : all) {
        if (a->res() != nullptr) {
            consumer = a;
            prod = a->mutable_res();
            break;
        }
    }
    CHECK(consumer != nullptr);
    CHECK(prod->uses().count(consumer) == 1);

    consumer->set_res(nullptr);

    CHECK(prod->uses().count(consumer) == 0);
    CHECK(consumer->res() == nullptr);
    CheckInvariant(*p);
}

// Scenario 5: destroying a producer nulls surviving consumers' res_.
// Construct a tiny scope so we can control object lifetimes.
void TestDestructorNullsConsumerBackPointer() {
    syz::ResultArg consumer;
    {
        syz::ResultArg producer;
        consumer.set_res(&producer);
        CHECK(producer.uses().count(&consumer) == 1);
        CHECK(consumer.res() == &producer);
        // producer destructed at end of scope; ~ResultArg() must null
        // consumer.res_ (so no dangling pointer survives).
    }
    CHECK(consumer.res() == nullptr);
}

// Destroying a consumer must remove it from the producer's uses_ set.
void TestDestructorErasesSelfFromProducer() {
    syz::ResultArg producer;
    {
        syz::ResultArg consumer;
        consumer.set_res(&producer);
        CHECK(producer.uses().count(&consumer) == 1);
        // consumer destructed at end of scope; ~ResultArg() must erase
        // self from producer.uses_.
    }
    CHECK(producer.uses().empty());
}

// Scenario 6: 1000-iteration randomized rewire — invariant holds after
// every operation. Catches any stowaway path that mutates res_ outside
// set_res.
void TestRandomRewireFuzz() {
    auto p = FindProgWithResultRef(/*attempts=*/16);
    if (p == nullptr) {
        std::fprintf(stderr, "skip: no generated prog with cross-ref in 16 tries\n");
        return;
    }
    auto all = CollectAllResultArgs(*p);
    if (all.size() < 2) {
        std::fprintf(stderr, "skip: prog has fewer than 2 ResultArgs\n");
        return;
    }

    std::mt19937_64 rng(0xC011E0FFEEULL);
    std::uniform_int_distribution<size_t> pick(0, all.size() - 1);
    std::uniform_int_distribution<int> coin(0, 2);

    for (int i = 0; i < 1000; ++i) {
        syz::ResultArg* c = all[pick(rng)];
        const int op = coin(rng);
        if (op == 0) {
            c->set_res(nullptr);
        } else {
            c->set_res(all[pick(rng)]);
        }
        CheckInvariant(*p);
    }
}

} // namespace

int main() {
    RUN_TEST(TestInvariantOnGeneratedProg);
    RUN_TEST(TestInvariantOnClone);
    RUN_TEST(TestSetResMovesForwardEdge);
    RUN_TEST(TestSetResNullClearsForwardEdge);
    RUN_TEST(TestDestructorNullsConsumerBackPointer);
    RUN_TEST(TestDestructorErasesSelfFromProducer);
    RUN_TEST(TestRandomRewireFuzz);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
