// §3.11 follow-up P2 step 4 — ArrayType::minimize virtual override
// behavioral test.
//
// Invariants under test:
//
//   1. Fast path: 3+ elements + range_begin == 0 + pred accepts →
//      single try_in_place commits; inner cleared to empty.
//   2. Fast path skip: < 3 elements → no fast-path attempt; peel
//      handles the rest.
//   3. Peel loop: kRangeLen with range_begin == N → peels until
//      live size == N, no further; multiple commits.
//   4. Crash-mode skip: peel loop returns early when mode == kCrash.
//   5. dispatch_lookup absent → minimize fails closed (returns
//      false; no commits).
//
// Type-level test: drives `ArrayType::minimize(ctx, arg, path)`
// directly with a hand-built Prog + GroupArg, ctx wired with a
// dispatch_lookup closure that walks the live tree by call/arg
// index.

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/minimize_ctx.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

namespace {

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,          \
                         __LINE__, #expr);                              \
            std::abort();                                               \
        }                                                               \
    } while (0)

#define RUN_TEST(fn)                                                    \
    do {                                                                \
        std::fprintf(stderr, "RUN  %s\n", #fn);                         \
        fn();                                                           \
        std::fprintf(stderr, "OK   %s\n", #fn);                         \
    } while (0)

namespace syz = refuzz::program::syz;

// Build a single-call Prog whose only arg is a GroupArg of given
// ArrayType + N inner ConstArgs.
std::unique_ptr<syz::Prog> BuildArrayProg(const syz::ArrayType* array_type,
                                          const syz::Type*      elem_type,
                                          std::size_t           n_elements) {
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();

    auto group_arg = std::make_unique<syz::GroupArg>();
    group_arg->set_type(array_type);
    group_arg->set_dir(syz::Dir::kIn);
    for (std::size_t i = 0; i < n_elements; ++i) {
        auto inner = std::make_unique<syz::ConstArg>();
        inner->set_type(elem_type);
        inner->set_dir(syz::Dir::kIn);
        inner->set_val(static_cast<std::uint64_t>(i + 1));
        group_arg->add_inner(std::move(inner));
    }

    call->add_arg(std::move(group_arg));
    prog->add_call(std::move(call));
    return prog;
}

// dispatch_lookup that returns the GroupArg at calls[0].args[0] of
// the given Prog. Mirrors what TryTypedArrayMinimize wrapper would
// inject for a path "0:a0.".
syz::MinimizeCtx::DispatchLookup MakeFirstArgLookup() {
    return [](syz::Prog& p) -> syz::Arg* {
        if (p.mutable_calls().empty()) return nullptr;
        auto& call = p.mutable_calls()[0];
        if (call == nullptr || call->mutable_args().empty()) return nullptr;
        return call->mutable_args()[0].get();
    };
}

// Ctx with always-true / always-false pred (test toggles `verdict`).
syz::MinimizeCtx MakeCtx(syz::Prog* prog, syz::MinimizeMode mode,
                         const bool& verdict, int& pred_calls) {
    syz::MinimizePred pred = [&](syz::Prog&, int) -> bool {
        ++pred_calls;
        return verdict;
    };
    return syz::MinimizeCtx(prog->target(), /*committed=*/nullptr, prog,
                            /*call_index0=*/0, mode, std::move(pred));
}

// Build an ArrayType with range_begin=range_end=0 (RandLen, no min).
std::unique_ptr<syz::ArrayType> MakeRandLenArrayType(const syz::Type* elem) {
    auto at = std::make_unique<syz::ArrayType>();
    at->set_name("test_array_randlen");
    at->set_align(8);
    at->set_var_len(true);
    at->set_array_kind(syz::ArrayKind::kRandLen);
    at->set_range(0, 0);
    at->set_elem(elem);
    return at;
}

// Build an ArrayType with kRangeLen, range_begin=N, range_end=N+10.
std::unique_ptr<syz::ArrayType> MakeRangeLenArrayType(const syz::Type* elem,
                                                     std::uint64_t   min_n) {
    auto at = std::make_unique<syz::ArrayType>();
    at->set_name("test_array_rangelen");
    at->set_align(8);
    at->set_var_len(true);
    at->set_array_kind(syz::ArrayKind::kRangeLen);
    at->set_range(min_n, min_n + 10);
    at->set_elem(elem);
    return at;
}

// Build a trivial IntType for inner elements.
std::unique_ptr<syz::IntType> MakeInt8Type() {
    auto it = std::make_unique<syz::IntType>();
    it->set_name("test_int8");
    it->set_size(8);
    it->set_align(8);
    return it;
}

// ---------- tests ----------

void TestFastPathClearsInner() {
    auto elem  = MakeInt8Type();
    auto array = MakeRandLenArrayType(elem.get());

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/3);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);             // single fast-path attempt
    CHECK(ctx.committed_count() == 1);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().empty());       // cleared
}

void TestFastPathRejectFallsThroughToPeelInRangeLen() {
    auto elem  = MakeInt8Type();
    // kRangeLen with min == 1; fast path is skipped because range_begin != 0.
    auto array = MakeRangeLenArrayType(elem.get(), /*min_n=*/1);

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/3);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    // Peel runs from 3 → 1 (min). 2 successful commits.
    CHECK(ctx.committed_count() == 2);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().size() == 1);
}

void TestCrashModeSkipsPeelButRunsFastPath() {
    auto elem  = MakeInt8Type();
    auto array = MakeRandLenArrayType(elem.get());

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/4);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    // kCrash: fast path runs (4 >= 3 + range_begin==0), peel skips.
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrash,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(ctx.committed_count() == 1);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().empty());       // fast path took it
}

void TestCrashModeWithoutFastPathReturnsFalse() {
    auto elem  = MakeInt8Type();
    // kRangeLen with min == 1 (range_begin != 0) → fast path skipped;
    // peel skipped because mode == kCrash.
    auto array = MakeRangeLenArrayType(elem.get(), /*min_n=*/1);

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/3);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrash,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().size() == 3);   // unchanged
}

void TestNoDispatchLookupFailsClosed() {
    auto elem  = MakeInt8Type();
    auto array = MakeRandLenArrayType(elem.get());

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/3);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    // Deliberately do NOT call ctx.set_dispatch_lookup(...).

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().size() == 3);
}

void TestPeelStopsOnPredReject() {
    auto elem  = MakeInt8Type();
    // kRangeLen min=1, 3 elements. Fast path skipped (range_begin!=0).
    // pred_calls == 1 → reject; peel returns false on first attempt.
    auto array = MakeRangeLenArrayType(elem.get(), /*min_n=*/1);

    auto prog = BuildArrayProg(array.get(), elem.get(), /*n_elements=*/3);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = false;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = array->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 1);             // first peel attempt rejected
    CHECK(ctx.committed_count() == 0);

    const auto* live = syz::as_group_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->inner().size() == 3);   // unchanged
}

} // namespace

int main() {
    RUN_TEST(TestFastPathClearsInner);
    RUN_TEST(TestFastPathRejectFallsThroughToPeelInRangeLen);
    RUN_TEST(TestCrashModeSkipsPeelButRunsFastPath);
    RUN_TEST(TestCrashModeWithoutFastPathReturnsFalse);
    RUN_TEST(TestNoDispatchLookupFailsClosed);
    RUN_TEST(TestPeelStopsOnPredReject);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
