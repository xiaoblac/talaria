// reFuzz syz_v2 mutator — squashAny op.
//
// Full port of `prog/mutation.go::squashAny`: pick a complex (squashable)
// pointer, collapse its structured pointee into a flat ANYUNION array of
// ANYBLOB/ANYRES elements (syz::squash_ptr), then byte-mutate one of the
// resulting blobs (mutate_data_blob). This explores "what if this structured
// memory were arbitrary bytes" — the structural surface a plain blob tweak
// can't reach.

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/program/syz/prog.hpp"

namespace refuzz::mutator::syz_v2 {

bool squash_any_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

} // namespace refuzz::mutator::syz_v2
