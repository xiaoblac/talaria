// §3.11 follow-up P2 step 5 — PtrType::minimize virtual override
// behavioral test.
//
// Invariants under test:
//
//   1. Non-null PointerArg + pred accepts → committed; live arg is
//      a fresh PointerArg with address=0, vma_size=0, res=nullptr.
//   2. PointerArg with res()==nullptr already → early return false;
//      pred not invoked.
//   3. Pred reject → rollback restores the original PointerArg
//      (with res() pointing back to the pointee).
//   4. Stage tag set to "arg ptr" on commit.

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

// Inner type for the PointerArg's pointee (a small ConstArg).
std::unique_ptr<syz::IntType> MakeInt8Type() {
    auto it = std::make_unique<syz::IntType>();
    it->set_name("test_int8");
    it->set_size(8);
    it->set_align(8);
    return it;
}

std::unique_ptr<syz::PtrType> MakePtrType(const syz::Type* elem) {
    auto pt = std::make_unique<syz::PtrType>();
    pt->set_name("ptr_test");
    pt->set_size(8);
    pt->set_align(8);
    pt->set_elem(elem);
    pt->set_elem_dir(syz::Dir::kIn);
    return pt;
}

// Build a single-call Prog whose only arg is a PointerArg pointing to
// a ConstArg(val=val).
std::unique_ptr<syz::Prog> BuildPtrProg(const syz::PtrType* ptr_type,
                                        const syz::Type*    elem_type,
                                        std::uint64_t       val,
                                        bool                with_pointee = true) {
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();

    auto pointer_arg = std::make_unique<syz::PointerArg>();
    pointer_arg->set_type(ptr_type);
    pointer_arg->set_dir(syz::Dir::kIn);
    pointer_arg->set_address(0xCAFE);
    pointer_arg->set_vma_size(0);

    if (with_pointee) {
        auto inner = std::make_unique<syz::ConstArg>();
        inner->set_type(elem_type);
        inner->set_dir(syz::Dir::kIn);
        inner->set_val(val);
        pointer_arg->set_res(std::move(inner));
    }

    call->add_arg(std::move(pointer_arg));
    prog->add_call(std::move(call));
    return prog;
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

void TestNullReplacementCommits() {
    auto elem  = MakeInt8Type();
    auto ptr_t = MakePtrType(elem.get());

    auto prog = BuildPtrProg(ptr_t.get(), elem.get(), /*val=*/42);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();
    // Pre: pointer has non-null res, address 0xCAFE.
    CHECK(syz::as_pointer_arg(arg_ref) != nullptr);
    CHECK(syz::as_pointer_arg(arg_ref)->res() != nullptr);

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = ptr_t->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(ctx.last_stage() == "arg ptr");

    // Post: live PointerArg is fully nulled.
    const auto* live = syz::as_pointer_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->address() == 0);
    CHECK(live->vma_size() == 0);
    CHECK(live->res() == nullptr);
}

void TestAlreadyNullEarlyReturns() {
    auto elem  = MakeInt8Type();
    auto ptr_t = MakePtrType(elem.get());

    auto prog = BuildPtrProg(ptr_t.get(), elem.get(),
                             /*val=*/0, /*with_pointee=*/false);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();
    CHECK(syz::as_pointer_arg(arg_ref)->res() == nullptr);

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = ptr_t->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);   // no candidate built when res() is null
    CHECK(ctx.committed_count() == 0);
}

void TestPredRejectRollsBack() {
    auto elem  = MakeInt8Type();
    auto ptr_t = MakePtrType(elem.get());

    auto prog = BuildPtrProg(ptr_t.get(), elem.get(), /*val=*/123);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = false;       // pred rejects
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = ptr_t->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);

    // Rollback: live PointerArg restored from snapshot. Pointer
    // identity changed (DeepClone) but state matches original.
    const auto* live = syz::as_pointer_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->address() == 0xCAFE);          // address restored
    CHECK(live->res() != nullptr);             // pointee restored
    const auto* pointee = syz::as_const_arg(live->res());
    CHECK(pointee != nullptr);
    CHECK(pointee->val() == 123);
}

} // namespace

int main() {
    RUN_TEST(TestNullReplacementCommits);
    RUN_TEST(TestAlreadyNullEarlyReturns);
    RUN_TEST(TestPredRejectRollsBack);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
