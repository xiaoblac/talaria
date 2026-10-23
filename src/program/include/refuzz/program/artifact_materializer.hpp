// Format-aware materialization helpers for ProgramArtifact (§3.10).
//
// Two construction routes:
//   1. Disk / corpus load: canonical text bytes are known up front;
//      MakeArtifactFromCanonicalPayload decodes once and produces an
//      eagerly-typed artifact.
//   2. Hot-path producer: a typed view is produced first (mutator,
//      generator, repro candidate); the artifact wraps it and lazily
//      computes canonical text the first time someone asks (which on
//      the §3.10 hot path should be never — see decode/encode counters).
//
// Two terminal-boundary helpers:
//   - MaterializeCanonicalText(artifact) — reads canonical_payload()
//     (triggers the provider once if needed). Used at corpus-disk save.
//   - MaterializeExecWire(artifact) — lowers the typed view to
//     wire-form bytes. Per D8 this is the only allowed lowering
//     helper, and Executor::Submit is the only allowed production
//     call site.
//
// §3.10 follow-up (registry refactor): the public MakeArtifact... /
// MaterializeExecWire functions dispatch via a per-format registry
// (`ArtifactMaterializerRegistry`) so adding AFL / libafl / arm64 etc.
// is purely additive — implement `IArtifactMaterializer` for the new
// format and Register() it. `program/` core stays format-neutral.

#pragma once

#include "refuzz/program/artifact.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::program {

struct MaterializeError {
    std::string message;
};

// ----- Per-format adapter interface (registered into the registry) -----

class IArtifactMaterializer {
public:
    virtual ~IArtifactMaterializer() = default;

    // The format this adapter handles. Each ProgFormat maps to at most
    // one registered adapter at any time.
    virtual refuzz::fuzzer::ProgFormat format() const = 0;

    // Build an eagerly-typed artifact from canonical text bytes.
    // Adapter is responsible for any target-key restrictions it has
    // (e.g. syz_v2 today only supports linux/amd64; D9 is a syz-side
    // policy, not a registry policy).
    virtual std::expected<ProgramArtifact, MaterializeError>
    BuildFromCanonicalPayload(ProgramTargetKey                target,
                              std::vector<std::uint8_t>       canonical_bytes) = 0;

    // Lower an artifact to wire-form bytes (exec wire for syz_v2;
    // raw input for AFL; etc.). Production call site is
    // Executor::Submit only (D8).
    virtual std::expected<std::vector<std::uint8_t>, MaterializeError>
    LowerToExecWire(const ProgramArtifact& artifact) = 0;
};

// ----- Format → adapter registry (process-wide singleton) -----

class ArtifactMaterializerRegistry {
public:
    // Process-wide singleton. Registration is idempotent for a given
    // format — second Register on the same format replaces the prior.
    static ArtifactMaterializerRegistry& Instance();

    // Register an adapter. Takes ownership.
    void Register(std::unique_ptr<IArtifactMaterializer> adapter);

    // Look up by format. Returns nullptr if not registered.
    IArtifactMaterializer* Find(refuzz::fuzzer::ProgFormat format) const;

    // Test helper: clear all registrations (for hermetic test setups).
    void ResetForTest();

private:
    ArtifactMaterializerRegistry() = default;
    std::unordered_map<int, std::unique_ptr<IArtifactMaterializer>> by_format_;
};

// One-call helper to register every builtin format adapter the build
// links in. Idempotent — calling it multiple times is safe; subsequent
// calls overwrite registrations with fresh instances. Call this from
// orchestrator init and from each test that exercises the typed
// pipeline.
//
// Today this registers:
//   * syz_v2 (kSyzProg, linux/amd64; multi-arch deferred per D9 — the
//     adapter itself rejects non-linux/amd64 targets).
// Future formats register here.
void RegisterBuiltinArtifactMaterializers();

// ----- Top-level dispatch APIs (public, format-neutral) -----

std::expected<ProgramArtifact, MaterializeError>
MakeArtifactFromCanonicalPayload(refuzz::fuzzer::ProgFormat       format,
                                 ProgramTargetKey                 target,
                                 std::vector<std::uint8_t>        canonical_bytes);

// Returns the canonical text bytes (triggering the artifact's lazy
// canonical provider exactly once if needed). Cheap on subsequent
// calls. Format-neutral — the artifact's provider was set up by its
// adapter at construction time.
std::expected<std::shared_ptr<const std::vector<std::uint8_t>>, MaterializeError>
MaterializeCanonicalText(const ProgramArtifact& artifact);

// Lowers the artifact's typed view to exec-wire bytes. Dispatches via
// `artifact.format()` to the registered adapter.
//
// Production call sites: Executor::Submit ONLY (D8).
// Tools and oracle binaries are exempt by allowlist; mutator / stage /
// corpus / repro production paths must not call this helper.
std::expected<std::vector<std::uint8_t>, MaterializeError>
MaterializeExecWire(const ProgramArtifact& artifact);

// ----- Corpus-side materializer callback -----
//
// `corpus/` accepts a callback at LoadAll/LoadCrashRepros time so the
// disk layer stays format-neutral. The callback returns a
// `shared_ptr<const ProgramArtifact>` (null on failure → seed.artifact
// stays empty, bytes-only fallback). Construct one via
// `MakeRegistryMaterializer(format, target)` for the common case.
using ArtifactMaterializerFn = std::function<
    std::shared_ptr<const ProgramArtifact>(const std::vector<std::uint8_t>& bytes)>;

// Build an ArtifactMaterializerFn that dispatches into the registry
// using the supplied (format, target). Returns null on per-byte
// failures (e.g., decode rejection, wrong target, format not
// registered). Cheap to capture by value into corpus init.
ArtifactMaterializerFn MakeRegistryMaterializer(refuzz::fuzzer::ProgFormat format,
                                                ProgramTargetKey           target);

} // namespace refuzz::program
