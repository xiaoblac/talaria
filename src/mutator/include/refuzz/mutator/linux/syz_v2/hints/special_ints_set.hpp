// special_ints_set.hpp — Epic 5 PR-5-C
//
// O(1) "is this value in prog/rand.go::specialInts" predicate. The set
// is built once from `mutator/linux/syz_v2/random.cpp::sorted_special_ints()`
// (single source of truth — promoted to named-namespace by PR-5-C so
// hints can consume it without copying constants).
//
// Used by shrink_expand to skip replacement candidates the random
// generator already inserts with high probability — those don't need
// hints help and only add noise to the candidate funnel.

#pragma once

#include <cstdint>

namespace refuzz::mutator::syz_v2::hints {

// Returns true iff `v` is in the `specialInts` list.
bool IsSpecialInt(uint64_t v);

} // namespace refuzz::mutator::syz_v2::hints
