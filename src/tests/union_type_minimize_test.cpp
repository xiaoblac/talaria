// §3.11 follow-up P2 step 8 — UnionType::minimize virtual override
// behavioral test.
//
// Invariants under test:
//
//   1. Non-conditional union, current arm != 0 + pred accept →
//      committed to default arm (index 0) with default_arg option.
//   2. Already-default state (index == 0 + is_default_arg(option))
//      → early return false; pred not invoked.
//   3. Empty fields → early return false.
//   4. Conditional union with last field unconditional → default arm
//      = last index; commit succeeds.
//   5. Conditional union without unconditional last field → return
//      false (no default available).
//   6. Pred reject → rollback restores current arm + option.
//   7. dispatch_lookup absent → fail closed.

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
#include <vector>

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

// Helpers to build types/fields for fixtures.
std::unique_ptr<syz::IntType> MakeInt(const char* name) {
    auto it = std::make_unique<syz::IntType>();
    it->set_name(name);
    it->set_size(8);
    it->set_align(8);
    return it;
}

// Build a UnionType with N integer fields. Returns the union and a
// vector of the field types (caller owns them).
struct UnionFixture {
    std::unique_ptr<syz::UnionType>           union_type;
    std::vector<std::unique_ptr<syz::IntType>> field_types;
};

UnionFixture MakeIntFieldsUnion(std::size_t n_fields,
                                 std::vector<bool> conditional_mask = {}) {
    UnionFixture f;
    f.union_type = std::make_unique<syz::UnionType>();
    f.union_type->set_name("test_union");
    f.union_type->set_size(8);
    f.union_type->set_align(8);

    std::vector<syz::Field> fields;
    for (std::size_t i = 0; i < n_fields; ++i) {
        auto it = MakeInt(("u_int_" + std::to_string(i)).c_str());
        syz::Field field("field_" + std::to_string(i), it.get());
        if (i < conditional_mask.size() && conditional_mask[i]) {
            // Construct a placeholder ValueExpr condition (always-true).
            auto cond = std::make_unique<syz::ValueExpr>();
            cond->set_value(1);
            field.set_condition(std::move(cond));
        }
        fields.push_back(std::move(field));
        f.field_types.push_back(std::move(it));
    }
    f.union_type->set_fields(std::move(fields));
    return f;
}

// Build a single-call Prog with a UnionArg at args[0]. The UnionArg
// references the union_type and starts at arm `current_index` with
// option = ConstArg(val=current_val) typed as the field's type.
std::unique_ptr<syz::Prog> BuildUnionProg(const syz::UnionType*   union_type,
                                          int                     current_index,
                                          std::uint64_t           current_val) {
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();

    auto union_arg = std::make_unique<syz::UnionArg>();
    union_arg->set_type(union_type);
    union_arg->set_dir(syz::Dir::kIn);
    union_arg->set_index(current_index);

    const auto& field = union_type->fields()[static_cast<std::size_t>(current_index)];
    auto option = std::make_unique<syz::ConstArg>();
    option->set_type(field.type());
    option->set_dir(syz::Dir::kIn);
    option->set_val(current_val);
    union_arg->set_option(std::move(option));

    call->add_arg(std::move(union_arg));
    prog->add_call(std::move(call));
    return prog;
}

syz::MinimizeCtx::DispatchLookup MakeFirstArgLookup() {
    return [](syz::Prog& p) -> syz::Arg* {
        if (p.mutable_calls().empty()) return nullptr;
        auto& call = p.mutable_calls()[0];
        if (call == nullptr || call->mutable_args().empty()) return nullptr;
        return call->mutable_args()[0].get();
    };
}

syz::MinimizeCtx MakeCtx(syz::Prog* prog, syz::MinimizeMode mode,
                         const bool& verdict, int& pred_calls) {
    syz::MinimizePred pred = [&](syz::Prog&, int) -> bool {
        ++pred_calls;
        return verdict;
    };
    return syz::MinimizeCtx(prog->target(), /*committed=*/nullptr, prog,
                            /*call_index0=*/0, mode, std::move(pred));
}

// ---------- tests ----------

void TestNonConditionalSwitchToArm0() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/3);
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/2,
                                /*current_val=*/0xBEEF);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(ctx.last_stage() == "arg union");

    // Live UnionArg now at arm 0 with default option.
    const auto* live = syz::as_union_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->index() == 0);
    const auto* live_const = syz::as_const_arg(live->option());
    CHECK(live_const != nullptr);
    CHECK(live_const->val() == 0);   // IntType default = 0
}

void TestAlreadyDefaultArmIsSkipped() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/3);
    // current_index=0 + val=0 (== default) → already in default state.
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/0,
                                /*current_val=*/0);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestEmptyFieldsReturnsFalse() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/0);
    // Build a prog with a UnionArg manually since BuildUnionProg
    // expects fields().
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());
    auto call = std::make_unique<syz::Call>();
    auto union_arg = std::make_unique<syz::UnionArg>();
    union_arg->set_type(fx.union_type.get());
    union_arg->set_dir(syz::Dir::kIn);
    call->add_arg(std::move(union_arg));
    prog->add_call(std::move(call));
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
}

void TestConditionalUnionWithUnconditionalLastDefaultArm() {
    // 3 fields: [conditional, conditional, unconditional]. Default
    // arm = last index (2).
    auto fx = MakeIntFieldsUnion(/*n_fields=*/3,
                                  /*conditional_mask=*/{true, true, false});
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/0,
                                /*current_val=*/0x77);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(ctx.committed_count() == 1);

    const auto* live = syz::as_union_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->index() == 2);   // last = default arm
}

void TestConditionalUnionAllFieldsHaveConditionsReturnsFalse() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/2,
                                  /*conditional_mask=*/{true, true});
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/0,
                                /*current_val=*/0x42);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);                       // no default available
    CHECK(pred_calls == 0);
}

void TestPredRejectRollsBack() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/3);
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/2,
                                /*current_val=*/0xBEEF);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = false;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);

    // Rollback: live arm still 2 + option val still 0xBEEF.
    const auto* live = syz::as_union_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->index() == 2);
    const auto* live_const = syz::as_const_arg(live->option());
    CHECK(live_const != nullptr);
    CHECK(live_const->val() == 0xBEEF);
}

void TestNoDispatchLookupFailsClosed() {
    auto fx = MakeIntFieldsUnion(/*n_fields=*/3);
    auto prog = BuildUnionProg(fx.union_type.get(),
                                /*current_index=*/2,
                                /*current_val=*/0x99);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    // No set_dispatch_lookup.

    std::string path = "0:a0.";
    const bool ok = fx.union_type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

} // namespace

int main() {
    RUN_TEST(TestNonConditionalSwitchToArm0);
    RUN_TEST(TestAlreadyDefaultArmIsSkipped);
    RUN_TEST(TestEmptyFieldsReturnsFalse);
    RUN_TEST(TestConditionalUnionWithUnconditionalLastDefaultArm);
    RUN_TEST(TestConditionalUnionAllFieldsHaveConditionsReturnsFalse);
    RUN_TEST(TestPredRejectRollsBack);
    RUN_TEST(TestNoDispatchLookupFailsClosed);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
