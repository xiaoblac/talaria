// §3.11 follow-up P2 step 1 — behavioral test for
// `MinimizeCtx::try_commit / try_remove_call`.
//
// Invariants under test:
//
//   1. try_commit + pred=true commits: the slot now holds the
//      replacement arg; committed_count_ increments;
//      current_call_/index are cleared (header invariant 4 — symmetric
//      with rollback / try_remove_call / try_in_place).
//   2. try_commit + pred=false rolls back: the slot's value is
//      restored; committed_count_ does NOT increment;
//      current_call_/index are cleared.
//   3. try_commit with a stale `&arg` (not in current_) returns
//      false without invoking pred (no attempt counted).
//   4. try_commit with replacement=nullptr returns false without
//      invoking pred.
//   5. try_remove_call + pred=true reduces calls.size() by one;
//      pred sees the shifted anchor and commit keeps it.
//   6. try_remove_call + pred=false leaves calls.size() unchanged.
//
// Test infrastructure mirrors `syz_v2_clone_test`: generate a v2
// program via SyzV2MutatorEngine, then drive MinimizeCtx directly
// (the orchestrator wrapper lands in Step 2).

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/minimize_ctx.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/transform.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
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

// Generate a v2 program with at least 2 calls so try_remove_call
// has a non-trivial target.
std::unique_ptr<syz::Prog> GenerateProg(uint64_t master_seed,
                                        std::size_t min_calls) {
    const auto& target = syz::Target::linux_amd64();
    for (uint64_t bump = 0; bump < 32; ++bump) {
        auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
            target, /*corpus_store=*/nullptr, master_seed + bump);
        refuzz::fuzzer::MutatorManager manager;
        manager.AddEngine(std::move(engine), /*activate=*/true);
        refuzz::fuzzer::Seed empty;
        auto bytes = manager.Handle().Get().Mutate(empty);
        if (bytes.empty()) continue;

        syz::TextDecoder decoder(target, syz::DecodeMode::kNonStrict);
        std::string_view text(reinterpret_cast<const char*>(bytes.data()),
                              bytes.size());
        auto prog_or = decoder.decode(text);
        if (!prog_or || !prog_or.value()) continue;
        auto p = std::move(*prog_or);
        if (p->calls().size() >= min_calls && !p->calls().empty() &&
            !p->calls()[0]->args().empty()) {
            return p;
        }
    }
    return nullptr;
}

// Returns a MinimizePred that captures `verdict` by reference so the
// test can flip it between calls.
syz::MinimizePred MakePred(const bool& verdict, int& invocations) {
    return [&](const syz::Prog&, int) -> bool {
        ++invocations;
        return verdict;
    };
}

// Find the first ConstArg in the first call's top-level args. Most
// generated programs have at least one (syscall scalar arg).
syz::ConstArg* FirstConstArg(syz::Prog& p) {
    if (p.calls().empty()) return nullptr;
    for (auto& slot : p.mutable_calls()[0]->mutable_args()) {
        if (auto* c = const_cast<syz::ConstArg*>(syz::as_const_arg(slot.get()))) {
            return c;
        }
    }
    return nullptr;
}

// Look up the (post-rollback or post-commit) live ConstArg in
// p->calls()[0]->args() — the slot index isn't fixed (FirstConstArg
// returns the *first* ConstArg-typed slot, which may be at args[1]
// or later when args[0] is a PointerArg / GroupArg). Scans top-level
// args until a ConstArg is found.
const syz::ConstArg* FirstLiveConstArg(const syz::Prog& p) {
    if (p.calls().empty()) return nullptr;
    for (const auto& slot : p.calls()[0]->args()) {
        if (const auto* c = syz::as_const_arg(slot.get())) {
            return c;
        }
    }
    return nullptr;
}

// ---------- tests ----------

void TestTryCommitAcceptReplacesSlot() {
    auto prog = GenerateProg(/*master_seed=*/0xC0FFEE, /*min_calls=*/1);
    CHECK(prog != nullptr);
    auto* original = FirstConstArg(*prog);
    if (original == nullptr) {
        std::fprintf(stderr, "skipping: no ConstArg in generated prog\n");
        return;
    }
    const std::uint64_t original_val = original->val();
    const std::uint64_t target_val   = original_val ^ 0xDEADBEEFULL;

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrashSnapshot,
                         MakePred(verdict, pred_calls));

    auto replacement = std::make_unique<syz::ConstArg>();
    replacement->set_type(original->type());
    replacement->set_dir(original->dir());
    replacement->set_val(target_val);

    const bool ok = ctx.try_commit(*original, std::move(replacement));
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);

    // Look up the slot's new value. The original `original` pointer
    // is INVALIDATED per contract; scan top-level args[] for the
    // live ConstArg slot — its position may not be args[0] (could be
    // args[1+] when arg[0] is a PointerArg/GroupArg).
    const auto* live = FirstLiveConstArg(*prog);
    CHECK(live != nullptr);
    CHECK(live->val() == target_val);
}

void TestTryCommitAcceptClearsCurrentCall() {
    // Header invariant 4 — try_commit success path clears
    // current_call_ / current_call_index_ symmetrically with rollback
    // and try_remove_call / try_in_place. Even though in-place swap
    // doesn't reshuffle the calls vector, the contract treats prior
    // Call*/Arg* as invalidated so callers re-set via set_current_call
    // on the next iteration.
    auto prog = GenerateProg(/*master_seed=*/0x5EEDED, /*min_calls=*/1);
    CHECK(prog != nullptr);
    auto* original = FirstConstArg(*prog);
    if (original == nullptr) {
        std::fprintf(stderr, "skipping: no ConstArg in generated prog\n");
        return;
    }

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrashSnapshot,
                         MakePred(verdict, pred_calls));

    ctx.set_current_call(prog->mutable_calls()[0].get(), 0);
    CHECK(ctx.current_call() != nullptr);
    CHECK(ctx.current_call_index() == 0);

    auto replacement = std::make_unique<syz::ConstArg>();
    replacement->set_type(original->type());
    replacement->set_dir(original->dir());
    replacement->set_val(original->val() ^ 0x1234ULL);

    const bool ok = ctx.try_commit(*original, std::move(replacement));
    CHECK(ok);
    CHECK(ctx.committed_count() == 1);
    CHECK(ctx.current_call() == nullptr);
    CHECK(ctx.current_call_index() == -1);
}

void TestTryCommitRejectRollsBack() {
    auto prog = GenerateProg(/*master_seed=*/0xBADC0DE, /*min_calls=*/1);
    CHECK(prog != nullptr);
    auto* original = FirstConstArg(*prog);
    if (original == nullptr) {
        std::fprintf(stderr, "skipping: no ConstArg in generated prog\n");
        return;
    }
    const std::uint64_t original_val = original->val();
    const std::size_t   original_call_count = prog->calls().size();

    bool verdict = false;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrashSnapshot,
                         MakePred(verdict, pred_calls));

    // Set current_call_ so we can verify rollback clears it.
    ctx.set_current_call(prog->mutable_calls()[0].get(), 0);

    auto replacement = std::make_unique<syz::ConstArg>();
    replacement->set_type(original->type());
    replacement->set_dir(original->dir());
    replacement->set_val(original_val ^ 0x55AA55AAULL);

    const bool ok = ctx.try_commit(*original, std::move(replacement));
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);

    // Slot's value restored from snapshot. Pointer identity is
    // different (DeepClone) but the value matches the original.
    // Scan top-level args for the live ConstArg slot — same as
    // FirstConstArg's iteration order (positional, not args[0]
    // assumption).
    CHECK(prog->calls().size() == original_call_count);
    const auto* live = FirstLiveConstArg(*prog);
    CHECK(live != nullptr);
    CHECK(live->val() == original_val);

    // current_call_ / current_call_index_ cleared on rollback.
    CHECK(ctx.current_call() == nullptr);
    CHECK(ctx.current_call_index() == -1);
}

void TestTryCommitStaleArgEarlyOut() {
    auto prog = GenerateProg(/*master_seed=*/0xFEEDFACE, /*min_calls=*/1);
    CHECK(prog != nullptr);

    // Build a free-standing ConstArg that is NOT inside `*prog`.
    auto stranger = std::make_unique<syz::ConstArg>();
    // Note: type can be nullptr — find_arg_slot will not match `&arg`
    // anywhere in *prog, so we early-out before touching type.

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrashSnapshot,
                         MakePred(verdict, pred_calls));

    auto replacement = std::make_unique<syz::ConstArg>();

    const bool ok = ctx.try_commit(*stranger, std::move(replacement));
    CHECK(!ok);
    CHECK(pred_calls == 0);              // pred not invoked
    CHECK(ctx.committed_count() == 0);
    CHECK(ctx.attempt_count() == 0);
}

void TestTryCommitNullReplacementEarlyOut() {
    auto prog = GenerateProg(/*master_seed=*/0xABBA, /*min_calls=*/1);
    CHECK(prog != nullptr);
    auto* original = FirstConstArg(*prog);
    if (original == nullptr) {
        std::fprintf(stderr, "skipping: no ConstArg in generated prog\n");
        return;
    }

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrashSnapshot,
                         MakePred(verdict, pred_calls));

    const bool ok = ctx.try_commit(*original, /*replacement=*/nullptr);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestTryRemoveCallAcceptShrinksAndShiftsAnchor() {
    auto prog = GenerateProg(/*master_seed=*/0xCAFEBABE, /*min_calls=*/3);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();
    CHECK(original_count >= 3);

    bool verdict = true;
    int  pred_calls = 0;
    int  pred_call_index = -2;
    // Pick anchor at index 2 to verify shift on remove(0).
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/2,
                         syz::MinimizeMode::kCrash,
                         [&](const syz::Prog&, int call_index0) -> bool {
                             ++pred_calls;
                             pred_call_index = call_index0;
                             return verdict;
                         });

    const bool ok = ctx.try_remove_call(/*call_index=*/0);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(pred_call_index == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(prog->calls().size() == original_count - 1);
    // Anchor shifted from 2 to 1 (call before anchor was removed).
    CHECK(ctx.call_index0() == 1);
    CHECK(ctx.current_call() == nullptr);
    CHECK(ctx.current_call_index() == -1);
}

void TestTryRemoveCallRejectsProtectedAnchor() {
    auto prog = GenerateProg(/*master_seed=*/0xC001D00D, /*min_calls=*/2);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    CHECK(!ctx.try_remove_call(/*call_index=*/0));
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
    CHECK(prog->calls().size() == original_count);
    CHECK(ctx.call_index0() == 0);
}

void TestTryRemoveCallRejectKeepsLength() {
    auto prog = GenerateProg(/*master_seed=*/0xDEADC0DE, /*min_calls=*/2);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();

    bool verdict = false;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    const bool ok = ctx.try_remove_call(
        /*call_index=*/static_cast<int>(original_count - 1));
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);
    CHECK(prog->calls().size() == original_count);
    // Anchor unchanged on rollback.
    CHECK(ctx.call_index0() == 0);
}

void TestTryRemoveCallOutOfRangeEarlyOut() {
    auto prog = GenerateProg(/*master_seed=*/0xF00DD00D, /*min_calls=*/1);
    CHECK(prog != nullptr);

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    CHECK(!ctx.try_remove_call(-1));
    CHECK(!ctx.try_remove_call(static_cast<int>(prog->calls().size())));
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

// ---------- §3.11 follow-up P2 step 2 — try_in_place coverage ----------

void TestTryInPlaceAcceptCommitsAndStage() {
    auto prog = GenerateProg(/*master_seed=*/0x12345, /*min_calls=*/2);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    const bool ok = ctx.try_in_place("call remove",
        [](syz::Prog& candidate) {
            if (candidate.mutable_calls().empty()) return false;
            return refuzz::program::syz::RemoveCall(candidate,
                                                     candidate.calls().size() - 1);
        });
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(prog->calls().size() == original_count - 1);
    CHECK(ctx.last_stage() == "call remove");
}

void TestTryInPlaceRejectDropsCandidate() {
    auto prog = GenerateProg(/*master_seed=*/0x67890, /*min_calls=*/2);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();

    bool verdict = false;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    const bool ok = ctx.try_in_place("call remove",
        [](syz::Prog& candidate) {
            if (candidate.mutable_calls().empty()) return false;
            return refuzz::program::syz::RemoveCall(candidate,
                                                     candidate.calls().size() - 1);
        });
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);
    // Pred declined → candidate dropped, *current_ unchanged.
    CHECK(prog->calls().size() == original_count);
}

void TestTryInPlaceMutatorDeclinesNoOp() {
    auto prog = GenerateProg(/*master_seed=*/0xABCDE, /*min_calls=*/1);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();

    bool verdict = true;
    int  pred_calls = 0;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/0,
                         syz::MinimizeMode::kCrash,
                         MakePred(verdict, pred_calls));

    const bool ok = ctx.try_in_place("never",
        [](syz::Prog&) { return false; });   // mutator declines
    CHECK(!ok);
    CHECK(pred_calls == 0);                 // pred not invoked
    CHECK(ctx.committed_count() == 0);
    CHECK(prog->calls().size() == original_count);
}

void TestTryInPlaceCandidateCallIndexOverride() {
    auto prog = GenerateProg(/*master_seed=*/0xC0A11D, /*min_calls=*/3);
    CHECK(prog != nullptr);
    const std::size_t original_count = prog->calls().size();
    CHECK(original_count >= 3);

    int pred_calls = 0;
    int seen_call_index = -2;
    syz::MinimizeCtx ctx(prog->target(), /*committed=*/nullptr, prog.get(),
                         /*call_index0=*/2,
                         syz::MinimizeMode::kCrash,
                         [&](const syz::Prog& candidate, int call_index0) -> bool {
                             ++pred_calls;
                             seen_call_index = call_index0;
                             CHECK(candidate.calls().size() == original_count - 1);
                             return call_index0 == 1;
                         });

    const bool ok = ctx.try_in_place("call remove",
        [](syz::Prog& candidate) {
            return refuzz::program::syz::RemoveCall(candidate, 0);
        },
        /*candidate_call_index0=*/1);

    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(seen_call_index == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(prog->calls().size() == original_count - 1);
    // try_in_place only changes the index used to test this candidate.
    // Call-removal orchestration updates the live anchor after commit.
    CHECK(ctx.call_index0() == 2);
}

} // namespace

int main() {
    RUN_TEST(TestTryCommitAcceptReplacesSlot);
    RUN_TEST(TestTryCommitAcceptClearsCurrentCall);
    RUN_TEST(TestTryCommitRejectRollsBack);
    RUN_TEST(TestTryCommitStaleArgEarlyOut);
    RUN_TEST(TestTryCommitNullReplacementEarlyOut);
    RUN_TEST(TestTryRemoveCallAcceptShrinksAndShiftsAnchor);
    RUN_TEST(TestTryRemoveCallRejectsProtectedAnchor);
    RUN_TEST(TestTryRemoveCallRejectKeepsLength);
    RUN_TEST(TestTryRemoveCallOutOfRangeEarlyOut);
    RUN_TEST(TestTryInPlaceAcceptCommitsAndStage);
    RUN_TEST(TestTryInPlaceRejectDropsCandidate);
    RUN_TEST(TestTryInPlaceMutatorDeclinesNoOp);
    RUN_TEST(TestTryInPlaceCandidateCallIndexOverride);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
