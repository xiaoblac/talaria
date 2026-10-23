// reFuzz syz_v2 — minimize context (typed-Prog minimize orchestration).
//
// Mirrors syzkaller `prog/minimization.go::minimizeArgsCtx` adapted to
// reFuzz architecture:
//
//   - `program/syz/` owns the per-type minimize behavior (each Type
//     subclass eventually overrides `Type::minimize(ctx, arg, path)`).
//   - `crash/repro/` owns the orchestration entry point
//     (`ProgramMinimizer::Minimize*`) and ProgramArtifact <-> typed-IR
//     translation. It builds a `MinimizeCtx`, hands it to
//     `syz::run_minimize_typed(ctx)`, and reports the result.
//
// `MinimizeCtx` is the contract between the two modules. Following
// the §3.11 follow-up P1a refinement, it is a CLASS with a method API
// rather than a struct of public fields. Per-type minimize
// implementations operate via `try_path / already_tried / try_commit
// / test_current` instead of mutating raw `tried_paths` / `pred`. This
// makes the upstream "convention" semantics (mark-on-no-progress,
// commit-then-restart, pred-deduped-by-payload) explicit at the API
// level rather than implicit in caller discipline.
//
// **Migration plan (P1 / P1a / P2)**:
//   - P1 — declared MinimizeCtx + Type::minimize() virtual; production
//     path unchanged.
//   - P1a — encapsulate fields behind methods.
//   - P2 step 1 (this commit) — `try_commit / try_remove_call` real
//     impl with **in-place + whole-Prog snapshot rollback** (see
//     "Commit semantics" below). No production caller yet — Step 2
//     wires the orchestrator through.
//   - P2 step 2..9 — move per-type minimize bodies from free functions
//     into Type::minimize overrides. program_minimizer.cpp shrinks to
//     ~100 lines that build ctx + call run_minimize_typed.
//
// **Commit semantics (P2 step 1, locked 2026-05-03)**:
//
//   `try_commit` and `try_remove_call` follow the upstream syzkaller
//   pattern: mutate `*current_` in place, run the predicate, and
//   either keep or roll back. Rollback restores the *whole* Prog
//   from a `DeepClone` snapshot taken before mutation, because the
//   orchestrator's pred wrapper applies `sanitize_fix` (which can
//   mutate args other than the one being swapped) and per-call size
//   refresh as part of pred evaluation. Restoring only the target
//   arg subtree would not unwind sanitize side-effects.
//
//   **Invalidation contract — callers MUST observe**:
//
//   1. After `try_commit` (success OR failure), the `Arg&` passed in,
//      and any other `Arg*` / `Call*` previously obtained from the
//      same Prog, are INVALIDATED. They may dangle (rollback frees
//      old Args) or refer to a slot that is no longer in the tree
//      (success: replacement took the slot; old arg dropped).
//
//   2. After `try_remove_call` (success OR failure), all `Call*`
//      previously obtained from the Prog are INVALIDATED — successful
//      remove shifts call indices; rollback rebinds the calls vector
//      from the snapshot.
//
//   3. The recommended type-method pattern is to call try_commit /
//      try_remove_call and **return immediately**, letting the
//      orchestrator's outer loop restart its walk with fresh
//      lookups. Iterating within the same `Type::minimize` invocation
//      after a commit requires re-locating the working arg via
//      `path` from `ctx.current()` (not via the now-stale `&arg`).
//
//   4. After ANY `try_commit` / `try_remove_call` / `try_in_place`
//      return (success OR rollback), `current_call_` and
//      `current_call_index_` are cleared (set to nullptr / -1). The
//      orchestrator must re-set them at the next iteration via
//      `set_current_call(...)`. The four primitives are symmetric on
//      this point so callers do not need a per-primitive cheat sheet.
//
//   5. On a successful `try_remove_call`, `call_index0_` is
//      auto-decremented if the removed call was before the anchor
//      (mirrors syzkaller's `removeCalls` anchor shift). Removing the
//      anchor itself is rejected. On rollback, `call_index0_` is
//      unchanged.

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

class Arg;
class Prog;
class Target;
class Type;

// Mirror of syzkaller `prog.MinimizeMode`.
//
// Aligned with reFuzz's `refuzz::crash::MinimizeMode` enum values; the
// crash module exposes the high-level enum to repro callers, and
// orchestration translates to this enum at the program/syz boundary.
enum class MinimizeMode : std::uint8_t {
    kCallsOnly     = 0,
    kCrash         = 1,
    kCrashSnapshot = 2,
    // kCorpus deliberately not yet ported (no in-tree caller; per
    // §3.11 plan deferral).
};

// Predicate signature: receives the candidate `Prog` (mutable, so the
// pred can apply sanitize_fix and size refresh in place) and the
// current `call_index0` (anchor); returns true iff the candidate is
// "equivalent enough" for the caller's purpose (crash repro, corpus
// minimize, etc.).
//
// **Pred contract (P2 step 2)**: pred is the full pre-evaluation
// pipeline — typically:
//   1. sanitize_fix(candidate)
//   2. assign_sizes_array per call (if target() != nullptr)
//   3. serialize_for_exec(candidate) → payload
//   4. payload-cache + no-op-vs-last-committed short-circuit
//   5. TestFunc(payload) + title-match
//   6. on matched: update last-committed-payload (captured side state)
//
// The wrapping lives in `crash/repro/`; `program/syz/` stays
// target-bytes-free. ctx.test_current() is the gateway and merely
// delegates to pred (after incrementing attempt_count_).
using MinimizePred = std::function<bool(Prog& candidate, int call_index0)>;

// MinimizeCtx mirrors syzkaller `prog/minimization.go::minimizeArgsCtx`.
//
// API surface (used by per-type minimize methods):
//
//   try_path(path)       — first attempt on `path` returns true and
//                          marks tried; subsequent attempts return
//                          false immediately. Mirrors upstream's
//                          `if ctx.triedPaths[path] { return false }
//                           ctx.triedPaths[path] = true` idiom.
//
//   already_tried(path)  — read-only check; doesn't mark.
//
//   test_current()       — invokes the predicate on the in-progress
//                          candidate Prog (`current()`); the
//                          orchestrator dedups identical payloads and
//                          handles serialize_for_exec + TestFunc.
//                          Returns the predicate's bool answer.
//
//   try_commit(arg, replacement)
//                        — atomically replace `arg` with `replacement`
//                          inside the current candidate, run
//                          test_current(), and either keep (return
//                          true) or roll back (return false). Type
//                          methods use this for "default-replace"
//                          minimize attempts.
//
//   target() / current() / call_index0() / mode() / current_call() /
//   current_call_index()
//                        — read-only context accessors.
//
// Lifetime: stack-allocated by the orchestrator inside
// `ProgramMinimizer::MinimizeProgTyped`. A single ctx serves one
// Minimize invocation.
class MinimizeCtx {
public:
    // Construct via the orchestrator; raw fields are not part of the
    // API. Use `Builder`-style setters for clarity.
    MinimizeCtx(const Target*          target,
                std::unique_ptr<Prog>* committed,
                Prog*                  current,
                int                    call_index0,
                MinimizeMode           mode,
                MinimizePred           pred);

    // Disabled — ctx is single-use, owned by the orchestrator.
    MinimizeCtx(const MinimizeCtx&) = delete;
    MinimizeCtx& operator=(const MinimizeCtx&) = delete;

    // ===== Read-only accessors =====
    const Target*    target()             const { return target_; }
    Prog*            current()                  { return current_; }
    const Prog*      current()             const { return current_; }
    int              call_index0()         const { return call_index0_; }
    void             set_call_index0(int idx)   { call_index0_ = idx; }
    MinimizeMode     mode()                const { return mode_; }
    Call*            current_call()              { return current_call_; }
    int              current_call_index()  const { return current_call_index_; }

    // ===== Per-call orchestration setters =====
    // Called by the orchestrator's outer loop before each per-arg
    // pass. Types should not invoke these.
    void set_current_call(Call* c, int idx) {
        current_call_       = c;
        current_call_index_ = idx;
    }

    // ===== triedPaths idiom =====
    bool already_tried(const std::string& path) const {
        return tried_paths_.count(path) != 0;
    }
    // First call returns true and marks `path` tried; subsequent
    // calls return false. Mirrors `if ctx.triedPaths[path] { return
    // false }; ctx.triedPaths[path] = true` upstream.
    bool try_path(const std::string& path) {
        if (tried_paths_.count(path) != 0) return false;
        tried_paths_.insert(path);
        return true;
    }

    // ===== Predicate gateway =====
    // Invoke the predicate on `*current_`. Pred is responsible for
    // sanitize_fix + size refresh + serialize_for_exec + TestFunc
    // (see MinimizePred contract). Per-type methods see a bool only.
    bool test_current() {
        ++attempt_count_;
        if (!pred_ || current_ == nullptr) return false;
        return pred_(*current_, call_index0_);
    }

    // ===== Commit primitive =====
    // Replace `arg` with `replacement` inside `*current_`, run pred,
    // either keep (returns true; commit count++) or roll back from a
    // pre-mutation `DeepClone(*current_)` snapshot (returns false).
    //
    // **Invalidation**: after this returns (either way), `arg` /
    // `&arg` / any other Arg pointers from the same Prog become
    // unsafe to dereference. See header docstring "Commit semantics"
    // for the full contract; tl;dr: type methods should `return`
    // immediately after this call, or re-lookup via `path` from
    // `ctx.current()` before further work.
    //
    // Returns false without snapshot if `replacement == nullptr` or
    // `find_arg_slot(*current_, &arg)` fails to locate the slot
    // (caller passed a stale Arg&). These early-out cases do not
    // count as a pred attempt.
    bool try_commit(Arg& arg, std::unique_ptr<Arg> replacement);

    // Remove a call by index, invoke pred, keep-or-rollback. Same
    // snapshot-based rollback as `try_commit`. On success, anchor
    // (`call_index0_`) auto-shifts if the removed call was
    // at-or-before it. **Invalidation**: all `Call*` from this Prog
    // become unsafe after return.
    bool try_remove_call(int call_index);

    // ===== Generic mutate-then-test commit (P2 step 2) =====
    // Mirror of the prior crash/repro `TryTypedProgCandidate`
    // template. The orchestrator (and per-type minimize free
    // functions, until they migrate to Type::minimize overrides in
    // Steps 3-8) drive most commits through this primitive:
    //
    //   1. Clone `*current_` into a candidate.
    //   2. Run `mutator(candidate)`. Mutator returns true if it
    //      actually mutated something worth testing; false to abort
    //      the candidate (e.g., precondition failed). The live
    //      `*current_` is untouched when the mutator declines.
    //   3. Run pred on the candidate — pred runs
    //      sanitize/serialize/TestFunc. Most callers test with the
    //      live `call_index0_`; callers that remove calls before the
    //      anchor inside the candidate can pass `candidate_call_index0`
    //      so pred sees the candidate's remapped anchor.
    //   4. On true: move candidate into `*current_`,
    //      ++committed_count_, set_stage(stage), clear
    //      current_call_, return true. On false: drop candidate and
    //      leave the live Prog untouched.
    //
    // **Invalidation**: on success, Arg/Call pointers from the prior
    // `*current_` are unsafe after return because the live Prog takes
    // the candidate's call vector. On mutator decline or pred reject,
    // the live Prog is untouched.
    bool try_in_place(const char*                    stage,
                      std::function<bool(Prog&)>     mutator,
                      std::optional<int>             candidate_call_index0 = std::nullopt);

    // ===== Dispatch lookup (Step 4+) =====
    // Orchestrator-supplied closure that, given any `Prog&`, returns
    // the arg "equivalent" to the one currently being dispatched
    // (resolved via the orchestrator's structured TypedArgPath).
    //
    // **Why**: Type::minimize takes only `(ctx, arg, path-string)`.
    // After `try_commit` / `try_in_place` invalidates `&arg`, type
    // methods that need to iterate (e.g., ArrayType peel-from-end)
    // call `ctx.dispatch_lookup()(prog)` to re-locate the arg in
    // either `*ctx.current()` or a try_in_place candidate clone.
    //
    // The dispatcher (TryMinimizeTypedProgArg switch wrapper) sets
    // this before invoking the type method and clears it after, so
    // calls outside the dispatch context see an empty std::function.
    using DispatchLookup = std::function<Arg*(Prog&)>;

    void                  set_dispatch_lookup(DispatchLookup f) { dispatch_lookup_ = std::move(f); }
    const DispatchLookup& dispatch_lookup() const                { return dispatch_lookup_; }

    // ===== Stage tracking =====
    // Last successfully committed stage tag (e.g., "arg scalar",
    // "remove call", "call props"). Read by the orchestrator to
    // populate MinimizeResult.minimize_stage. Set by try_in_place
    // (and may be set explicitly via set_stage by per-type methods
    // calling try_commit / try_remove_call directly in Steps 3-8).
    const std::string& last_stage() const { return last_stage_; }
    void               set_stage(const char* stage) { last_stage_ = stage ? stage : ""; }

    // ===== Stats =====
    std::uint32_t attempt_count()   const { return attempt_count_; }
    std::uint32_t committed_count() const { return committed_count_; }

    // Internal: orchestrator-only helpers used by P2 implementations.
    // Declared in the public section because friend declarations
    // would couple this header to the P2 implementation file. Type
    // methods should NOT call these directly; they go through
    // `try_commit / try_remove_call / test_current`.
    std::unique_ptr<Prog>* committed_slot() { return committed_; }
    void                   set_current(Prog* p) { current_ = p; }
    void                   note_committed() { ++committed_count_; }

private:
    const Target*           target_       = nullptr;
    std::unique_ptr<Prog>*  committed_    = nullptr;
    Prog*                   current_      = nullptr;
    int                     call_index0_  = -1;
    MinimizeMode            mode_         = MinimizeMode::kCrash;
    MinimizePred            pred_;

    std::unordered_set<std::string> tried_paths_;

    Call*                   current_call_       = nullptr;
    int                     current_call_index_ = -1;

    std::uint32_t           attempt_count_    = 0;
    std::uint32_t           committed_count_  = 0;
    std::string             last_stage_       = "none";
    DispatchLookup          dispatch_lookup_;
};

// StopFunc — orchestrator-supplied "abort current run" signal.
// Mirrors the crash/repro StopFunc but lives in program/syz/ so the
// run_minimize_typed body can poll it without depending on
// crash/repro. Returns true iff the orchestration should bail out
// early (e.g., timeout, user cancel).
using StopFunc = std::function<bool()>;

// Top-level orchestrator entry — mirrors `prog.Minimize`. Drives
// trailing/unrelated/reverse call removal, CallProps minimize, and
// per-arg minimize against the type-method dispatch (steps 3-8 turn
// each per-type body into a `Type::minimize` override; until then
// the bodies live as free functions inside the same TU as
// run_minimize_typed).
//
// **P2 step 2 status**: production-active. crash/repro/'s
// ProgramMinimizer entry points build the ctx + pred and call here.
struct MinimizeOutcome {
    bool          succeeded       = false;
    std::uint32_t attempt_count   = 0;
    std::uint32_t committed_count = 0;
    std::string   last_stage      = "none";
};

MinimizeOutcome run_minimize_typed(MinimizeCtx& ctx, const StopFunc& stop_fn = {});

} // namespace refuzz::program::syz
