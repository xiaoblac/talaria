// Implementation of refuzz/mutator/linux/syz_v2/random.hpp.
//
// Port of prog/rand.go randGen — utility-only here; per-type generators
// live in generators_*.cpp.

#include "refuzz/mutator/linux/syz_v2/random.hpp"

#include <algorithm>
#include <array>
#include <cmath>

namespace refuzz::mutator::syz_v2 {

// [v2 Epic 5 PR-5-C] Promoted from anonymous-namespace to named-namespace
// scope so hints/special_ints_set can build its O(1) lookup off the
// same source vector (no constant duplication).
const std::vector<uint64_t>& sorted_special_ints() {
    static const std::vector<uint64_t> kSorted = []() {
        std::vector<uint64_t> v = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            64, 127, 128, 129, 255, 256, 257, 511, 512,
            1023, 1024, 1025, 2047, 2048, 4095, 4096,
            (uint64_t{1} << 15) - 1, (uint64_t{1} << 15), (uint64_t{1} << 15) + 1,
            (uint64_t{1} << 16) - 1, (uint64_t{1} << 16), (uint64_t{1} << 16) + 1,
            (uint64_t{1} << 31) - 1, (uint64_t{1} << 31), (uint64_t{1} << 31) + 1,
            (uint64_t{1} << 32) - 1, (uint64_t{1} << 32), (uint64_t{1} << 32) + 1,
            (uint64_t{1} << 63) - 1, (uint64_t{1} << 63), (uint64_t{1} << 63) + 1,
            ~uint64_t{0},
        };
        std::sort(v.begin(), v.end());
        return v;
    }();
    return kSorted;
}

namespace {

const std::array<int, 9>& special_int_indexes() {
    static const std::array<int, 9> kIdx = []() {
        const auto& v = sorted_special_ints();
        std::array<int, 9> idx{};
        for (int i = 0; i < 9; ++i) {
            const uint64_t bit_size = uint64_t{8} * i;
            int j = 0;
            for (; j < static_cast<int>(v.size()); ++j) {
                const uint64_t shifted = (bit_size >= 64) ? 0 : (v[j] >> bit_size);
                if (shifted != 0) break;
            }
            idx[i] = j;
        }
        return idx;
    }();
    return kIdx;
}

} // namespace

RandGen::RandGen(uint64_t seed) : rng_(seed) {}

uint64_t RandGen::rand(int n) {
    if (n <= 0) return 0;
    std::uniform_int_distribution<uint64_t> d(0, static_cast<uint64_t>(n) - 1);
    return d(rng_);
}

uint64_t RandGen::rand_range(uint64_t begin, uint64_t end) {
    if (end < begin) return begin;
    std::uniform_int_distribution<uint64_t> d(begin, end);
    return d(rng_);
}

bool RandGen::bin() {
    return rand(2) == 0;
}

bool RandGen::one_of(int n) {
    if (n <= 0) return false;
    return rand(n) == 0;
}

bool RandGen::n_out_of(int n, int out_of) {
    if (out_of <= 0) return false;
    return static_cast<int>(rand(out_of)) < n;
}

uint64_t RandGen::rand64() {
    std::uniform_int_distribution<uint64_t> d;
    return d(rng_);
}

float RandGen::randf() {
    std::uniform_real_distribution<float> d(0.0f, 1.0f);
    return d(rng_);
}

uint64_t RandGen::rand_int64() {
    return rand_int(64);
}

uint64_t RandGen::rand_int(uint64_t bits) {
    uint64_t v = rand64();
    if (n_out_of(100, 182)) {
        v %= 10;
    } else if (bits >= 8 && n_out_of(50, 82)) {
        const auto& s   = sorted_special_ints();
        const auto& idx = special_int_indexes();
        const int top   = idx[std::min<uint64_t>(8, bits / 8)];
        if (top > 0) v = s[rand(top)];
    } else if (n_out_of(10, 32)) {
        v %= 256;
    } else if (n_out_of(10, 22)) {
        v %= uint64_t{4} << 10;
    } else if (n_out_of(10, 12)) {
        v %= uint64_t{64} << 10;
    } else {
        v %= uint64_t{1} << 31;
    }
    if (n_out_of(100, 107)) {
        // unchanged
    } else if (n_out_of(5, 7)) {
        v = static_cast<uint64_t>(-static_cast<int64_t>(v));
    } else {
        v <<= rand(static_cast<int>(bits));
    }
    return truncate_to_bit_size(v, bits);
}

uint64_t RandGen::truncate_to_bit_size(uint64_t v, uint64_t bit_size) {
    if (bit_size == 0 || bit_size > 64) return v;
    if (bit_size == 64) return v;
    return v & ((uint64_t{1} << bit_size) - 1);
}

uint64_t RandGen::rand_range_int(uint64_t begin, uint64_t end,
                                 uint64_t bit_size, uint64_t align) {
    if (one_of(100)) return rand_int(bit_size);
    if (align != 0) {
        if (begin == 0 && static_cast<int64_t>(end) == -1) {
            end = bit_size >= 64 ? ~uint64_t{0} : ((uint64_t{1} << bit_size) - 1);
        }
        const uint64_t end_align = (end - begin) / align;
        return begin + rand_range_int(0, end_align, bit_size, 0) * align;
    }
    if (end < begin) return begin;
    return begin + rand64() % (end - begin + 1);
}

int RandGen::biased_rand(int n, int k) {
    const double nf = n;
    const double kf = k;
    const double rf = nf * (kf / 2.0 + 1.0) * randf();
    const double bf = (-1.0 + std::sqrt(1.0 + 2.0 * kf * rf / nf)) * nf / kf;
    int result = static_cast<int>(bf);
    if (result < 0) result = 0;
    if (result >= n) result = n - 1;
    return result;
}

uint64_t RandGen::rand_array_len() {
    // biasedRand(11, 10) → 0..10 weighted toward 10; we want 1..10 + occasional 0.
    int b = biased_rand(kMaxArrayLen + 1, 10);
    int v = (kMaxArrayLen - b + 1) % (kMaxArrayLen + 1);
    return static_cast<uint64_t>(v);
}

uint64_t RandGen::rand_buf_len() {
    if (n_out_of(50, 56)) return rand(256);
    if (n_out_of(5, 6))   return uint64_t{4} << 10;
    return 0;
}

uint64_t RandGen::rand_page_count(uint64_t target_num_pages) {
    if (n_out_of(100, 106)) return rand(4) + 1;
    if (n_out_of(5, 6))     return rand(20) + 1;
    return (rand(3) + 1) * target_num_pages / 4;
}

uint64_t RandGen::flags(const std::vector<uint64_t>& vv, bool bitmask,
                        uint64_t old_val) {
    if (one_of(100)) return rand64();
    if (one_of(50))  return 0;
    if (!bitmask && old_val != 0 && one_of(100)) {
        uint64_t inc = bin() ? ~uint64_t{0} : uint64_t{1};
        uint64_t v   = old_val + inc;
        while (bin()) v += inc;
        return v;
    }
    if (vv.size() == 1) {
        return bin() ? uint64_t{0} : vv[0];
    }
    if (!bitmask && !one_of(10)) {
        return vv[rand(static_cast<int>(vv.size()))];
    }
    if (one_of(static_cast<int>(vv.size()) + 4)) return 0;
    uint64_t v = old_val;
    if (v != 0 && one_of(10)) v = 0;
    for (int t = 0; t < 10 && (v == 0 || n_out_of(2, 3)); ++t) {
        uint64_t flag = vv[rand(static_cast<int>(vv.size()))];
        if (one_of(20)) {
            if (bin()) flag >>= 1; else flag <<= 1;
        }
        v ^= flag;
    }
    return v;
}

bool RandGen::prune_recursion(const std::string& name) {
    int& d = rec_depth_[name];
    if (d > 2) return false;       // refuse — too deep
    ++d;
    return true;
}

void RandGen::release_recursion(const std::string& name) {
    auto it = rec_depth_.find(name);
    if (it != rec_depth_.end() && it->second > 0) {
        --it->second;
        if (it->second == 0) rec_depth_.erase(it);
    }
}

const std::vector<uint64_t>& RandGen::special_ints() {
    return sorted_special_ints();
}

int RandGen::special_int_index(uint64_t bit_size) {
    return special_int_indexes()[std::min<uint64_t>(8, bit_size / 8)];
}

} // namespace refuzz::mutator::syz_v2
