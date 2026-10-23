// reFuzz syz_v2 mutator — RandGen.
//
// Port of `prog/rand.go` randGen utilities. Uses std::mt19937_64 as the
// underlying source. Exact PRNG algorithm differs from syzkaller (Go's
// math/rand uses a Lagged Fibonacci Generator), but the statistical
// shape of the generators is preserved by the same biasing constants
// — we only need histogram parity, not bit-equal sequences.

#pragma once

#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::mutator::syz_v2 {

// Recommended program length budgets (mirror prog/rand.go iota block).
inline constexpr int kRecommendedCalls          = 30;
inline constexpr int kMaxCalls                  = 40;
inline constexpr int kRecommendedCallsKFuzzTest = 5;
inline constexpr int kMaxArrayLen               = 10;

// [mutator syz-parity] Mean mutation ops per Mutate() call — mirror syzkaller
// prog/mutation.go DefaultMutateOpts.ExpectedIterations. syz's loop stops after
// each successful op with prob 1/ExpectedIterations (`r.oneOf(5)`), so ~5 ops on
// average. reFuzz previously applied exactly ONE op per mutation (no loop), which
// kept programs at ~corpus_len+1.
inline constexpr int kExpectedMutationIterations = 5;

// [v2 Epic 5 PR-5-C] Public accessor for prog/rand.go::specialInts. The
// list is the single source of truth for "values the random generator
// inserts with high probability"; hints (shrink_expand) skips replacing
// to these because random mutation already covers them densely.
const std::vector<uint64_t>& sorted_special_ints();

class RandGen {
public:
    explicit RandGen(uint64_t seed);

    // Mirror of *math/rand.Rand methods used by upstream randGen.
    uint64_t rand(int n);                          // [0, n)
    uint64_t rand_range(uint64_t begin, uint64_t end);  // [begin, end] inclusive
    bool     bin();                                // 50/50
    bool     one_of(int n);                        // 1/n
    bool     n_out_of(int n, int out_of);          // n/outOf
    uint64_t rand64();                             // any uint64
    float    randf();                              // [0,1)

    // Integer biasing (rand.go::randInt + truncateToBitSize).
    uint64_t rand_int64();
    uint64_t rand_int(uint64_t bits);
    static uint64_t truncate_to_bit_size(uint64_t v, uint64_t bit_size);

    // rand.go::randRangeInt with align support.
    uint64_t rand_range_int(uint64_t begin, uint64_t end,
                            uint64_t bit_size, uint64_t align);

    // Biased toward higher values: P(n-1)/P(0) = k.
    int biased_rand(int n, int k);

    // Length-shape helpers.
    uint64_t rand_array_len();
    uint64_t rand_buf_len();
    uint64_t rand_page_count(uint64_t target_num_pages);

    // FlagsType.generate equivalent. `vv` is the legal value list, `bitmask`
    // means it's an OR-able flag set, `old_val` is the input to mutate from
    // (0 in pure generation mode).
    uint64_t flags(const std::vector<uint64_t>& vv, bool bitmask,
                   uint64_t old_val);

    // Recursion-depth bookkeeping (rand.go::pruneRecursion). Returns true
    // and a `release()` callable on entry; caller must invoke it on exit.
    using ReleaseFn = void (*)(RandGen*, const std::string*);
    bool prune_recursion(const std::string& name);
    void release_recursion(const std::string& name);

    // Inner mt19937_64 access for sub-helpers.
    std::mt19937_64& engine() { return rng_; }

    // Static lookup: indexes into specialInts table for a given byte-size.
    static const std::vector<uint64_t>& special_ints();
    static int special_int_index(uint64_t bit_size);

private:
    std::mt19937_64                            rng_;
    std::unordered_map<std::string, int>       rec_depth_;
};

} // namespace refuzz::mutator::syz_v2
