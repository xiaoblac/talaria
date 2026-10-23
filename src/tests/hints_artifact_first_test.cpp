// hints_artifact_first_test.cpp — Epic 5 PR-5-C fix #1
//
// Regression for the artifact-first contract in
// SyzV2MutatorEngine::MutateWithHints. PR-5-C v1 only decoded
// seed.payload; PR-5-D will hand seeds with empty payload + valid
// artifact, which would silent-return without this fix.
//
// Builds a Seed where:
//   - seed.payload is empty
//   - seed.artifact carries a typed syz::Prog view (built directly
//     via MakeArtifactFromTypedProg, mirroring how AsyncAdmitWorker
//     constructs corpus seeds in production)
// and asserts MutateWithHints produces ≥1 candidate.

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <memory>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;
namespace syz   = refuzz::program::syz;

namespace {

std::unique_ptr<syz::IntType> MakeInt2() {
    auto t = std::make_unique<syz::IntType>();
    t->set_name("a");
    t->set_size(2);
    return t;
}

std::unique_ptr<syz::ConstArg> MakeConstArg(const syz::Type* t, uint64_t v) {
    auto a = std::make_unique<syz::ConstArg>();
    a->set_type(t);
    a->set_dir(syz::Dir::kIn);
    a->set_val(v);
    return a;
}

} // namespace

int main()
{
    namespace pr = refuzz::program;

    // Build a typed Prog with one synthesized call.
    auto type_a = MakeInt2();
    syz::SyscallMeta meta;
    meta.set_name("test$hints_artifact");
    meta.set_call_name("test_hints_artifact");
    meta.set_id(0);
    meta.set_nr(0);
    std::vector<syz::Field> fields;
    fields.emplace_back("a", type_a.get());
    meta.set_args(std::move(fields));

    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeConstArg(type_a.get(), 0xabcd));
    prog->add_call(std::move(call));

    std::shared_ptr<const syz::Prog> sp(std::move(prog));
    pr::ProgramArtifact artifact =
        syz::MakeArtifactFromTypedProg(std::move(sp));
    CHECK(artifact.valid());

    // Build a Seed with EMPTY payload + valid artifact (the PR-5-D path).
    refuzz::fuzzer::Seed seed;
    seed.seed_id = 1;
    seed.payload = {};                           // intentionally empty
    seed.artifact = std::make_shared<const pr::ProgramArtifact>(std::move(artifact));

    // Hint: 0xabcd → 0x9999 (a non-special-int replacer to survive the
    // specialIntsSet filter).
    hints::CompMap comps;
    comps.Add(/*pc=*/1, /*op1=*/0xabcd, /*op2=*/0x9999, /*is_const=*/true);

    // Construct engine. Master seed deterministic for reproducibility.
    refuzz::fuzzer::SyzV2MutatorEngine engine(syz::Target::linux_amd64(),
                                              /*corpus_store=*/nullptr,
                                              /*master_seed=*/0xabcdefULL);

    int candidate_count = 0;
    bool got_target = false;
    engine.MutateWithHints(seed, /*call_index=*/0, comps,
        [&](pr::ProgramArtifact a) -> bool {
            ++candidate_count;
            CHECK(a.valid());
            auto p = a.As<syz::Prog>();
            CHECK(p != nullptr);
            CHECK(p->calls().size() == 1);
            const auto* arg0 = static_cast<const syz::ConstArg*>(
                p->calls()[0]->args()[0].get());
            if (arg0->val() == 0x9999) got_target = true;
            return true;
        });

    CHECK(candidate_count > 0);
    CHECK(got_target);

    std::printf("hints_artifact_first_test PASSED (cands=%d)\n", candidate_count);
    return 0;
}
