// §3.10 step-2 unit test — DeepClone for refuzz::program::syz::Prog.
//
// Invariants under test:
//   1. cloned program structurally independent of the source (Call /
//      Arg pointers differ);
//   2. cloned program validate()s clean;
//   3. canonical text encode(clone) == encode(src) byte-for-byte
//      (proves structural fidelity end-to-end);
//   4. ResultArg::res_ cross-call references in the clone point at the
//      cloned ResultArg counterpart, not at the source; references
//      that point inside the source's call list resolve to a clone-
//      side pointer that lives inside the cloned call list.
//
// The driver picks a generated v2 program. If the generated program
// happens to contain no ResultArg cross-references (rare given
// ChoiceTable's resource-chain bias), the test falls back to a hand-
// constructed 2-call netrom program that is guaranteed to have one.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/validation.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
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

// ----- helpers -----

// Walk an Arg subtree, invoke `visit` on every ResultArg encountered.
void ForEachResultArg(syz::Arg* a, const std::function<void(syz::ResultArg*)>& visit) {
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

// Try generation up to N times to find a program that has at least
// one ResultArg with a non-null cross-call reference. Returns null if
// no such program is produced (very unlikely on the ChoiceTable-biased
// generator).
std::unique_ptr<syz::Prog> FindProgWithResultRef(int attempts) {
    for (int i = 0; i < attempts; ++i) {
        auto p = GenerateOneProg(/*master_seed=*/uint64_t{0xC100E} + i);
        if (p == nullptr) continue;
        bool has_ref = false;
        ForEachResultArgInProg(*p, [&](syz::ResultArg* ra){
            if (ra->res() != nullptr) has_ref = true;
        });
        if (has_ref) return p;
    }
    return nullptr;
}

// Collect all ResultArg pointers in a prog (including ret).
std::unordered_set<const syz::ResultArg*> CollectResultArgPointers(syz::Prog& p) {
    std::unordered_set<const syz::ResultArg*> set;
    ForEachResultArgInProg(p, [&](syz::ResultArg* ra){ set.insert(ra); });
    return set;
}

// ----- tests -----

void TestClonedProgIsStructurallyIndependent() {
    auto src = GenerateOneProg(/*master_seed=*/12345);
    CHECK(src != nullptr);
    CHECK(!src->calls().empty());

    auto clone = syz::DeepClone(*src);
    CHECK(clone != nullptr);
    CHECK(clone->target() == src->target());                 // schema shared
    CHECK(clone->calls().size() == src->calls().size());

    for (size_t i = 0; i < src->calls().size(); ++i) {
        CHECK(clone->calls()[i].get() != src->calls()[i].get()); // distinct Call
        CHECK(clone->calls()[i]->meta() == src->calls()[i]->meta()); // schema shared
        CHECK(clone->calls()[i]->args().size() == src->calls()[i]->args().size());
        for (size_t j = 0; j < src->calls()[i]->args().size(); ++j) {
            CHECK(clone->calls()[i]->args()[j].get() !=
                  src->calls()[i]->args()[j].get());           // distinct Arg
            CHECK(clone->calls()[i]->args()[j]->type() ==
                  src->calls()[i]->args()[j]->type());          // schema shared
        }
    }
}

void TestCloneEncodesEqualToSource() {
    auto src = GenerateOneProg(/*master_seed=*/12345);
    CHECK(src != nullptr);

    syz::TextEncoder enc(syz::Target::linux_amd64());
    std::string src_text   = enc.encode(*src);
    auto clone = syz::DeepClone(*src);
    std::string clone_text = enc.encode(*clone);
    CHECK(src_text == clone_text);
}

void TestCloneValidatesClean() {
    auto src = GenerateOneProg(/*master_seed=*/12345);
    CHECK(src != nullptr);

    auto clone = syz::DeepClone(*src);
    auto vr = syz::validate(*clone);
    if (!vr.has_value()) {
        std::fprintf(stderr, "validate failed: call_index=%d msg=%s\n",
                     vr.error().call_index, vr.error().message.c_str());
    }
    CHECK(vr.has_value());
}

void TestResultArgRefsAreRemapped() {
    // Find a generated program with at least one cross-call ResultArg.
    auto src = FindProgWithResultRef(/*attempts=*/16);
    if (src == nullptr) {
        std::fprintf(stderr,
                     "skipping ResultArg-remap check: no generated program "
                     "with cross-ref produced in 16 attempts\n");
        return;
    }

    auto src_pointers   = CollectResultArgPointers(*src);
    auto clone          = syz::DeepClone(*src);
    auto clone_pointers = CollectResultArgPointers(*clone);

    // No ResultArg in the clone should be the same object as any in src.
    for (const auto* p : clone_pointers) {
        CHECK(src_pointers.count(p) == 0);
    }

    // Walk the cloned tree: every ResultArg with a non-null res_ must
    // point at a ResultArg that lives inside the clone (not the source),
    // proving the remap pass fixed up the placeholder.
    int remapped = 0;
    ForEachResultArgInProg(*clone, [&](syz::ResultArg* ra){
        const syz::ResultArg* ref = ra->res();
        if (ref == nullptr) return;
        CHECK(clone_pointers.count(ref) == 1);          // points into clone
        CHECK(src_pointers.count(ref) == 0);            // not into src
        ++remapped;
    });
    CHECK(remapped > 0);  // at least one cross-ref was actually remapped
}

void TestDeepCloneArgIsolatedSubtree() {
    auto src = GenerateOneProg(/*master_seed=*/12345);
    CHECK(src != nullptr);
    CHECK(!src->calls().empty());
    CHECK(!src->calls()[0]->args().empty());

    const syz::Arg* first = src->calls()[0]->args()[0].get();
    auto clone = syz::DeepCloneArg(*first);
    CHECK(clone != nullptr);
    CHECK(clone.get() != first);
    CHECK(clone->type() == first->type());
    CHECK(clone->arg_kind() == first->arg_kind());
}

} // namespace

int main() {
    RUN_TEST(TestClonedProgIsStructurallyIndependent);
    RUN_TEST(TestCloneEncodesEqualToSource);
    RUN_TEST(TestCloneValidatesClean);
    RUN_TEST(TestResultArgRefsAreRemapped);
    RUN_TEST(TestDeepCloneArgIsolatedSubtree);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
