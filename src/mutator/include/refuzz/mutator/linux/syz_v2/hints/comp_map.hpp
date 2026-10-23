// comp_map.hpp — Epic 5 PR-5-C
//
// Mirror of `prog/hints.go::CompMap`. A CompMap maps a comparison-side
// operand (the value the kernel observed in a comparison) to the set of
// other operands that compared against it, each tagged with the program
// counter where the comparison happened. Build it by repeatedly calling
// Add(); intersect three replays via InplaceIntersect to keep only
// stable/repeatable comparisons; then walk it via shrink_expand() in
// hints_apply.{hpp,cpp} to derive replacement candidates for typed args.
//
// reFuzz adapt:
//   - Upstream `map[uint64]map[uint64]map[uint64]bool` becomes
//     `unordered_map<uint64_t, unordered_map<uint64_t, unordered_set<uint64_t>>>`.
//   - Add(pc, op1, op2, is_const) recurses with swapped operands when
//     !is_const (matches upstream — both operands could come from input).
//   - All methods are pure / non-allocating-on-hot-path-for-lookups;
//     iteration order is unspecified (matches upstream Go map iteration
//     non-determinism — hint output order is sorted by shrink_expand
//     before being emitted).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace refuzz::mutator::syz_v2::hints {

class CompMap {
public:
    using PcSet  = std::unordered_set<uint64_t>;
    using Op2Pcs = std::unordered_map<uint64_t, PcSet>;
    using Inner  = std::unordered_map<uint64_t, Op2Pcs>;

    // Mirror of (CompMap).Add(pc, arg1, arg2, isConst). When !is_const,
    // recurses once with arg1<->arg2 swapped (and is_const=true on the
    // recursive call) so both operands index the same {pc} set.
    void Add(uint64_t pc, uint64_t op1, uint64_t op2, bool is_const);

    // Mirror of (CompMap).Len: total record count (sum of |pcs| across
    // all (op1, op2) pairs). Cheap to call; not cached.
    std::size_t Len() const;

    // Mirror of (CompMap).InplaceIntersect: drop any (op1, op2, pc)
    // triple not also present in `other`. Empty op2 map drops op1;
    // empty pc set drops op2. Used by hints_stage to keep only
    // comparisons that fired in all three replays of the same program.
    void InplaceIntersect(const CompMap& other);

    // Mirror of (CompMap).String — debug helper; format mirrors
    // upstream "0x<op1>: 0x<op2_a> 0x<op2_b>, 0x<op1_2>: ..." but does
    // NOT promise byte-identical output (Go map iteration order).
    std::string ToString() const;

    // Lookup: returns the inner map for `op1` or nullptr if absent.
    // shrink_expand uses this in the inner replacement loop.
    const Op2Pcs* Find(uint64_t op1) const;

    // Iteration access used by HintsLimiter::Limit and tests.
    Inner&       data()       { return inner_; }
    const Inner& data() const { return inner_; }
    bool         empty() const { return inner_.empty(); }
    void         clear()      { inner_.clear(); }

private:
    Inner inner_;
};

} // namespace refuzz::mutator::syz_v2::hints
