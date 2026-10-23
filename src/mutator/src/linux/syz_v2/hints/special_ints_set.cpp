// special_ints_set.cpp — Epic 5 PR-5-C. See special_ints_set.hpp.

#include "refuzz/mutator/linux/syz_v2/hints/special_ints_set.hpp"

#include "refuzz/mutator/linux/syz_v2/random.hpp"

#include <unordered_set>

namespace refuzz::mutator::syz_v2::hints {

namespace {

const std::unordered_set<uint64_t>& BuildSet() {
    static const std::unordered_set<uint64_t> kSet = []() {
        const auto& src = ::refuzz::mutator::syz_v2::sorted_special_ints();
        return std::unordered_set<uint64_t>(src.begin(), src.end());
    }();
    return kSet;
}

} // namespace

bool IsSpecialInt(uint64_t v) {
    return BuildSet().count(v) != 0;
}

} // namespace refuzz::mutator::syz_v2::hints
