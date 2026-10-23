// Implementation of refuzz/program/artifact.hpp + the codec counter
// storage referenced by refuzz/program/internal/codec_counters.hpp.
//
// State is held in a shared, immutable `State` struct; ProgramArtifact
// is just a shared_ptr handle, so copy/move is cheap (one atomic
// refcount op). canonical_payload uses std::call_once for thread-safe
// lazy materialization (D3).

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/internal/codec_counters.hpp"

#include <cstdio>
#include <cstdlib>
#include <utility>

namespace refuzz::program {

// ----- ProgramArtifact::State -----

struct ProgramArtifact::State {
    refuzz::fuzzer::ProgFormat   format = refuzz::fuzzer::ProgFormat::kSyzProg;
    ProgramTargetKey             target;
    std::shared_ptr<const void>  typed_view;
    const std::type_info*        typed_type = nullptr;

    // Lazy canonical-payload cache. Either preloaded at construction or
    // filled exactly once by `provider`.
    mutable std::once_flag                                     canonical_once;
    mutable std::shared_ptr<const std::vector<std::uint8_t>>   canonical_cached;

    CanonicalProvider provider;  // empty if canonical_cached preloaded
};

// ----- Factory -----

ProgramArtifact ProgramArtifact::Build(
    refuzz::fuzzer::ProgFormat                  format,
    ProgramTargetKey                            target,
    std::shared_ptr<const void>                 typed_view,
    const std::type_info&                       typed_type,
    std::shared_ptr<const std::vector<uint8_t>> canonical_bytes,
    CanonicalProvider                           canonical_provider)
{
    if (typed_view == nullptr) {
        std::fprintf(stderr,
                     "ProgramArtifact::Build: typed_view is null "
                     "(D3: typed view is always populated at construction)\n");
        std::abort();
    }
    if (canonical_bytes == nullptr && !canonical_provider) {
        std::fprintf(stderr,
                     "ProgramArtifact::Build: neither canonical_bytes nor "
                     "canonical_provider supplied; canonical_payload() would "
                     "be unanswerable\n");
        std::abort();
    }

    auto state = std::make_shared<State>();
    state->format       = format;
    state->target       = std::move(target);
    state->typed_view   = std::move(typed_view);
    state->typed_type   = &typed_type;
    state->canonical_cached = std::move(canonical_bytes);
    state->provider     = std::move(canonical_provider);

    // If canonical_cached is preloaded, mark the once_flag as completed
    // so canonical_payload() never invokes the provider. We do that by
    // calling call_once with a no-op now (the once_flag becomes used,
    // and the next call_once is a no-op).
    if (state->canonical_cached != nullptr) {
        std::call_once(state->canonical_once, []{});
    }

    ProgramArtifact a;
    a.state_ = state;
    return a;
}

// ----- Lifetime / accessors -----

ProgramArtifact::ProgramArtifact() noexcept = default;
ProgramArtifact::~ProgramArtifact()         = default;

ProgramArtifact::ProgramArtifact(ProgramArtifact&& other) noexcept
    : state_(std::move(other.state_)) {}

ProgramArtifact& ProgramArtifact::operator=(ProgramArtifact&& other) noexcept {
    if (this != &other) state_ = std::move(other.state_);
    return *this;
}

refuzz::fuzzer::ProgFormat ProgramArtifact::format() const noexcept {
    return state_ != nullptr ? state_->format : refuzz::fuzzer::ProgFormat::kSyzProg;
}

const ProgramTargetKey& ProgramArtifact::target() const noexcept {
    static const ProgramTargetKey kEmpty{};
    return state_ != nullptr ? state_->target : kEmpty;
}

bool ProgramArtifact::has_typed_view() const noexcept {
    return state_ != nullptr && state_->typed_view != nullptr;
}

const std::type_info& ProgramArtifact::typed_type() const noexcept {
    static const auto& kVoid = typeid(void);
    if (state_ == nullptr || state_->typed_type == nullptr) return kVoid;
    return *state_->typed_type;
}

std::shared_ptr<const void> ProgramArtifact::raw_typed_view() const noexcept {
    return state_ != nullptr ? state_->typed_view : nullptr;
}

bool ProgramArtifact::has_canonical_payload() const noexcept {
    return state_ != nullptr && state_->canonical_cached != nullptr;
}

std::shared_ptr<const std::vector<std::uint8_t>>
ProgramArtifact::canonical_payload() const {
    if (state_ == nullptr) return nullptr;
    std::call_once(state_->canonical_once, [this]{
        if (state_->canonical_cached == nullptr && state_->provider) {
            state_->canonical_cached = state_->provider();
        }
    });
    return state_->canonical_cached;
}

// ----- D9 target check -----

void CheckTargetOrDie(const ProgramArtifact& artifact,
                      const ProgramTargetKey& expected) {
    const auto& got = artifact.target();
    if (got == expected) return;
    std::fprintf(stderr,
                 "CheckTargetOrDie: target mismatch — got {os=%s arch=%s rev=%s} "
                 "expected {os=%s arch=%s rev=%s} (D9: no fallback path)\n",
                 got.os.c_str(), got.arch.c_str(), got.revision.c_str(),
                 expected.os.c_str(), expected.arch.c_str(), expected.revision.c_str());
    std::abort();
}

} // namespace refuzz::program

// ----- Codec counter TU-local storage -----
//
// Defined here (rather than in encoding.cpp / exec_wire.cpp) so all
// targets that link refuzz_program get exactly one definition, and the
// counter symbols are independent of which codec source files happen to
// be compiled into a given target.

namespace refuzz::program::codec_counters::internal {

thread_local std::atomic<std::uint64_t> g_decode_text{0};
thread_local std::atomic<std::uint64_t> g_encode_text{0};
thread_local std::atomic<std::uint64_t> g_decode_wire{0};
thread_local std::atomic<std::uint64_t> g_encode_wire{0};

} // namespace refuzz::program::codec_counters::internal
