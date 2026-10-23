// syz-specific artifact builders (§3.10 step 3 enabling helper).
//
// Mutators that just produced a typed `syz::Prog` need a way to wrap
// it in a ProgramArtifact without paying a text encode on the hot
// path. This header exposes the syz-flavored builder so syz-owned code
// (mutator engines, future repro paths) can publish a fresh artifact
// directly from the typed view; canonical text is materialized lazily
// via a provider when (and only when) someone calls
// `canonical_payload()` (e.g. corpus disk save).
//
// This sits in `program/syz/` because the typed prog type is a
// syz-specific format; the neutral `artifact_materializer.hpp` stays
// format-agnostic at the program/ root level.

#pragma once

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"  // IArtifactMaterializer + ArtifactMaterializerFn
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"             // SyscallMeta / Target

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::program::syz {

// Wrap an immutable typed Prog in a ProgramArtifact. The typed view is
// installed eagerly (D3); canonical text is filled lazily on first
// `canonical_payload()` via TextEncoder. Mutators must not call
// canonical_payload() on the hot path (encode_text_calls would grow);
// disk save / repro persistence are the only allowed canonical
// triggers (§3.10 D8 + corpus disk boundary).
ProgramArtifact MakeArtifactFromTypedProg(std::shared_ptr<const Prog> prog);

// Factory for the syz_v2 IArtifactMaterializer adapter. Caller
// transfers ownership into the registry. Today's adapter handles
// kSyzProg + linux/amd64; non-linux/amd64 targets are a hard error
// (D9; multi-arch lifts in §3.14).
std::unique_ptr<refuzz::program::IArtifactMaterializer> CreateSyzV2Materializer();


// [syscall-enable-whitelist] Wrap a base materializer so any program
// containing a call whose SyscallMeta::id() is not set in `enabled_mask`
// decodes to nullptr (dropped by StrictTyped corpus load). `enabled_mask`
// is indexed by id; an empty mask = no filter (pass-through). Mirrors how
// syzkaller filters the on-disk corpus down to the enabled syscall set, and
// keeps the corpus loader symmetric with the mutator ChoiceTable filter.
::refuzz::program::ArtifactMaterializerFn WrapWithEnabledCalls(
    ::refuzz::program::ArtifactMaterializerFn base,
    std::vector<std::uint8_t>                 enabled_mask);

} // namespace refuzz::program::syz
