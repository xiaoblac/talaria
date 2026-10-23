// ProgramArtifact — neutral cross-module program handle (§3.10).
//
// `program/` owns this type. It is the only program object that generic
// stage / corpus / executor / queue / repro orchestration code is
// allowed to move across module boundaries. Modules that need
// format-specific semantics (mutator, repro, materializer) take a typed
// view via `As<T>()`.
//
// Invariants (per docs/typed-program-pipeline/000_plan.md §3 D2/D3/D4):
//   - constructed fully populated; immutable thereafter (D3);
//   - typed view always present at construction; `As<T>()` is a const
//     read with no synchronization (D3);
//   - `canonical_payload()` is a CPU-saving cache, materialized lazily
//     once via std::call_once and never recomputed (D3);
//   - mutators clone the typed view into owned mutable state, mutate
//     the clone, and publish a new artifact — artifacts themselves are
//     never mutated post-construction (D4);
//   - target-key mismatch is a hard error (D9): see CheckTargetOrDie.

#pragma once

#include "refuzz/program/prog_format.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <typeinfo>
#include <vector>

namespace refuzz::program {

// ----- Target identity -----

struct ProgramTargetKey {
    std::string os;        // e.g. "linux"
    std::string arch;      // e.g. "amd64"
    std::string revision;  // schema revision

    bool operator==(const ProgramTargetKey&) const = default;
};

// ----- Mutation result (D5) -----

enum class MutationStatus : std::uint8_t {
    kOk          = 0,  // produced an artifact (changed may be true or false)
    kSkipped     = 1,  // engine elected not to mutate (e.g. policy gate)
    kInvalid     = 2,  // post-mutation validate() failed; artifact is
                       // best-effort (often the pre-mutation snapshot)
    kEngineError = 3,  // internal engine failure
};

// 诊断/日志用：MutationStatus → 稳定名字串。
inline const char* MutationStatusName(MutationStatus s) noexcept {
    switch (s) {
        case MutationStatus::kOk:          return "ok";
        case MutationStatus::kSkipped:     return "skipped";
        case MutationStatus::kInvalid:     return "invalid";
        case MutationStatus::kEngineError: return "engine_error";
    }
    return "unknown";
}

class ProgramArtifact;  // forward decl — defined below.

// ----- ProgramArtifact -----

class ProgramArtifact {
public:
    // Lazy provider for canonical-text bytes. Returns the bytes on first
    // call; subsequent reads come from the artifact's std::call_once
    // cache. Provider may be empty if construction supplied bytes.
    using CanonicalProvider =
        std::function<std::shared_ptr<const std::vector<uint8_t>>()>;

    ProgramArtifact() noexcept;            // produces an invalid placeholder
    ~ProgramArtifact();
    ProgramArtifact(ProgramArtifact&&) noexcept;
    ProgramArtifact& operator=(ProgramArtifact&&) noexcept;
    ProgramArtifact(const ProgramArtifact&)            = default;
    ProgramArtifact& operator=(const ProgramArtifact&) = default;

    // ----- Factory -----

    // Generic constructor used by both the hot-path producer (typed view
    // built first; canonical bytes lazy via provider) and the disk-load
    // path (canonical bytes already known; provider null).
    //
    // `typed_view` MUST be non-null; `typed_type` must be a stable
    // pointer to typeid for the typed-view payload. Either
    // `canonical_bytes` or `canonical_provider` MUST be non-empty so
    // canonical_payload() can answer at least once.
    static ProgramArtifact Build(
        refuzz::fuzzer::ProgFormat                  format,
        ProgramTargetKey                            target,
        std::shared_ptr<const void>                 typed_view,
        const std::type_info&                       typed_type,
        std::shared_ptr<const std::vector<uint8_t>> canonical_bytes,
        CanonicalProvider                           canonical_provider);

    // ----- Accessors (all const reads, no synchronization except
    // canonical_payload's std::call_once) -----

    bool valid() const noexcept { return state_ != nullptr; }

    refuzz::fuzzer::ProgFormat format()  const noexcept;
    const ProgramTargetKey&    target()  const noexcept;

    bool has_typed_view() const noexcept;
    const std::type_info& typed_type() const noexcept;

    bool has_canonical_payload() const noexcept;

    // canonical_payload() may invoke the provider once on first access;
    // result is cached. Subsequent calls are pure reads.
    std::shared_ptr<const std::vector<uint8_t>> canonical_payload() const;

    // Type-erased typed-view accessor. Returns nullptr if T does not
    // match the artifact's typed-view payload type.
    //
    // Per D2, only syz-owned modules (mutator engines, repro/minimize
    // helpers, materializers) should call this. Generic stage / corpus /
    // executor code must not.
    template <class T>
    std::shared_ptr<const T> As() const {
        if (!has_typed_view()) return nullptr;
        if (typed_type() != typeid(T)) return nullptr;
        return std::static_pointer_cast<const T>(raw_typed_view());
    }

private:
    struct State;
    std::shared_ptr<const State> state_;

    std::shared_ptr<const void> raw_typed_view() const noexcept;
};

// `MutationResult` is artifact-authoritative (D5). canonical_payload /
// exec_wire are not primary fields; callers use the boundary helpers in
// `artifact_materializer.hpp` when they need bytes.
struct MutationResult {
    ProgramArtifact     artifact;                // always populated (post-
                                                 // or pre-mutation snapshot)
    bool                changed = false;         // true iff status==kOk and
                                                 // the artifact differs
                                                 // from the input
    MutationStatus      status  = MutationStatus::kOk;
};

// D9: hard target check used by syz-owned consumers before `As<T>()`.
// Aborts in debug builds; in release builds the program prints to
// stderr and abort()s — there is no fallback path.
void CheckTargetOrDie(const ProgramArtifact& artifact,
                      const ProgramTargetKey& expected);

} // namespace refuzz::program
