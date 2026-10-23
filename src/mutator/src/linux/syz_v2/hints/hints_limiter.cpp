// hints_limiter.cpp — Epic 5 PR-5-C. See hints_limiter.hpp for design.

#include "refuzz/mutator/linux/syz_v2/hints/hints_limiter.hpp"

namespace refuzz::mutator::syz_v2::hints {

void HintsLimiter::Limit(CompMap& comps) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& inner = comps.data();
    for (auto it_op1 = inner.begin(); it_op1 != inner.end();) {
        auto& op2_map = it_op1->second;
        for (auto it_op2 = op2_map.begin(); it_op2 != op2_map.end();) {
            auto& pcs = it_op2->second;
            for (auto it_pc = pcs.begin(); it_pc != pcs.end();) {
                ++attempts_[*it_pc];
                if (attempts_[*it_pc] > kPerPcCap) {
                    it_pc = pcs.erase(it_pc);
                } else {
                    ++it_pc;
                }
            }
            if (pcs.empty()) {
                it_op2 = op2_map.erase(it_op2);
            } else {
                ++it_op2;
            }
        }
        if (op2_map.empty()) {
            it_op1 = inner.erase(it_op1);
        } else {
            ++it_op1;
        }
    }
}

int HintsLimiter::AttemptsForTest(uint64_t pc) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = attempts_.find(pc);
    return it == attempts_.end() ? 0 : it->second;
}

void HintsLimiter::ResetForTest() {
    std::lock_guard<std::mutex> lk(mu_);
    attempts_.clear();
}

} // namespace refuzz::mutator::syz_v2::hints
