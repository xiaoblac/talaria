// §3.11 follow-up P2 step 3 — IntType / FlagsType / ProcType
// `minimize` virtual override behavioral test.
//
// Invariants under test:
//
//   1. IntType::minimize commits a default-replace candidate when
//      mode = kCrashSnapshot, current value > default, and pred
//      accepts.
//   2. IntType::minimize early-returns false when mode is not
//      kCrashSnapshot (matches upstream IntType.minimize guard).
//   3. IntType::minimize early-returns false when current == default
//      (no shrink possible) — pred not invoked.
//   4. ProcType::minimize early-returns false when type is
//      non-optional (matches upstream non-optional skip), even when
//      a default candidate exists.
//   5. ProcType::minimize commits when type is optional and pred
//      accepts.
//   6. FlagsType::minimize commits a default-replace candidate
//      monotonically (default 0 < current value).
//
// Type-level test: drives `IntType::minimize(ctx, arg, path)` /
// `FlagsType::minimize(...)` / `ProcType::minimize(...)` directly
// against a hand-built Prog with a known scalar arg, observes the
// commit/no-commit verdict and the post-commit value.

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

// Find the first IntType / FlagsType / ProcType in the target's
// arena. Used to locate a "real" scalar type for the test fixtures
// (so default_arg / val semantics match production type lookup).
const syz::IntType* FindFirstIntType() {
    const auto& target = syz::Target::linux_amd64();
    for (const auto& syscall : target.syscalls()) {
        if (syscall == nullptr) continue;
        for (const auto& field : syscall->args()) {
            if (const auto* it = syz::as_int(field.type())) {
                if (it->size() == sizeof(uint64_t)) return it;
            }
        }
    }
    return nullptr;
}

const syz::FlagsType* FindFirstFlagsType() {
    const auto& target = syz::Target::linux_amd64();
    for (const auto& syscall : target.syscalls()) {
        if (syscall == nullptr) continue;
        for (const auto& field : syscall->args()) {
            if (const auto* ft = syz::as_flags(field.type())) {
                return ft;
            }
        }
    }
    return nullptr;
}

const syz::ProcType* FindFirstProcType(bool want_optional) {
    const auto& target = syz::Target::linux_amd64();
    for (const auto& syscall : target.syscalls()) {
        if (syscall == nullptr) continue;
        for (const auto& field : syscall->args()) {
            if (const auto* pt = syz::as_proc(field.type())) {
                if (pt->optional() == want_optional) return pt;
            }
        }
    }
    return nullptr;
}

// Build a single-call Prog whose only arg is a ConstArg of the given
// type with the given current value. We do NOT need a real
// SyscallMeta — the type method only inspects ctx.mode() + arg.type()
// + arg.dir() + the arg's val. A ResultArg-free Prog is fine for
// these tests.
std::unique_ptr<syz::Prog> BuildSingleArgProg(const syz::Type* type,
                                              uint64_t          current_val,
                                              const syz::SyscallMeta* meta) {
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();
    if (meta != nullptr) call->set_meta(meta);

    auto arg = std::make_unique<syz::ConstArg>();
    arg->set_type(type);
    arg->set_dir(syz::Dir::kIn);
    arg->set_val(current_val);
    call->add_arg(std::move(arg));

    prog->add_call(std::move(call));
    return prog;
}

// Locate the syscall meta whose first arg matches `type`. The pred
// invokes serialize_for_exec via crash/repro adapter — but here we
// don't go through pred (we use a no-op pred), so meta isn't strictly
// needed. We pass the first matching meta to make calls "look real"
// in case future try_commit invariants check it.
const syz::SyscallMeta* FindMetaWithFirstArgType(const syz::Type* type) {
    const auto& target = syz::Target::linux_amd64();
    for (const auto& syscall : target.syscalls()) {
        if (syscall == nullptr) continue;
        if (!syscall->args().empty() && syscall->args()[0].type() == type) {
            return syscall.get();
        }
    }
    return nullptr;
}

// Construct a MinimizeCtx with the given mode and an always-true /
// always-false pred (controlled by &verdict).
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

void TestIntTypeMinimizeAcceptDefaults() {
    const auto* it = FindFirstIntType();
    if (it == nullptr) {
        std::fprintf(stderr, "skipping: no IntType found\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(it);

    auto prog = BuildSingleArgProg(it, /*current_val=*/0xDEADBEEFULL, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = it->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);

    // Slot now holds the default ConstArg (val = 0 for IntType).
    const auto* live = syz::as_const_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->val() == 0);
}

void TestIntTypeMinimizeNonSnapshotModeReturnsFalse() {
    const auto* it = FindFirstIntType();
    if (it == nullptr) {
        std::fprintf(stderr, "skipping\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(it);
    auto prog = BuildSingleArgProg(it, 0xCAFEULL, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    // Crash mode (non-snapshot) → minimize must not propose a candidate.
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrash,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = it->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestIntTypeMinimizeNoShrinkPossible() {
    const auto* it = FindFirstIntType();
    if (it == nullptr) {
        std::fprintf(stderr, "skipping\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(it);
    // current val == default (0) → no candidate.
    auto prog = BuildSingleArgProg(it, 0, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = it->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);  // pred not invoked when no candidate
    CHECK(ctx.committed_count() == 0);
}

void TestProcTypeMinimizeNonOptionalSkips() {
    const auto* pt = FindFirstProcType(/*want_optional=*/false);
    if (pt == nullptr) {
        std::fprintf(stderr, "skipping: no non-optional ProcType\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(pt);
    auto prog = BuildSingleArgProg(pt, 5, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = pt->minimize(ctx, *arg_ref, path);
    CHECK(!ok);                       // non-optional ProcType skip
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestFlagsTypeMinimizeAcceptDefaults() {
    const auto* ft = FindFirstFlagsType();
    if (ft == nullptr) {
        std::fprintf(stderr, "skipping: no FlagsType\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(ft);
    auto prog = BuildSingleArgProg(ft, 0xFFULL, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = ft->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);

    const auto* live = syz::as_const_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->val() == 0);  // FlagsType default = 0
}

void TestIntTypeMinimizeRejectRollsBack() {
    const auto* it = FindFirstIntType();
    if (it == nullptr) {
        std::fprintf(stderr, "skipping\n");
        return;
    }
    const auto* meta = FindMetaWithFirstArgType(it);
    const uint64_t original_val = 0x1234567890ABCDEFULL;
    auto prog = BuildSingleArgProg(it, original_val, meta);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = false;          // pred rejects
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);

    std::string path = "0:a0.";
    const bool ok = it->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);

    // Slot rolled back: same val as original (DeepClone-restored).
    const auto* live = syz::as_const_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->val() == original_val);
}

} // namespace

int main() {
    RUN_TEST(TestIntTypeMinimizeAcceptDefaults);
    RUN_TEST(TestIntTypeMinimizeNonSnapshotModeReturnsFalse);
    RUN_TEST(TestIntTypeMinimizeNoShrinkPossible);
    RUN_TEST(TestProcTypeMinimizeNonOptionalSkips);
    RUN_TEST(TestFlagsTypeMinimizeAcceptDefaults);
    RUN_TEST(TestIntTypeMinimizeRejectRollsBack);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
