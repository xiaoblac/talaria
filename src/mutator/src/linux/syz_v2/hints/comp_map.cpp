// comp_map.cpp — Epic 5 PR-5-C. See comp_map.hpp for design.

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"

#include <cstdio>

namespace refuzz::mutator::syz_v2::hints {

void CompMap::Add(uint64_t pc, uint64_t op1, uint64_t op2, bool is_const) {
    inner_[op1][op2].insert(pc);
    if (!is_const) {
        // Mirror upstream: when neither operand is a compile-time constant
        // both could have come from input, so index the same {pc} under
        // the swapped pair. Recursive call passes is_const=true to stop
        // the recursion at one level.
        Add(pc, op2, op1, true);
    }
}

std::size_t CompMap::Len() const {
    std::size_t count = 0;
    for (const auto& [op1, op2_map] : inner_) {
        (void)op1;
        for (const auto& [op2, pcs] : op2_map) {
            (void)op2;
            count += pcs.size();
        }
    }
    return count;
}

void CompMap::InplaceIntersect(const CompMap& other) {
    // Mirror upstream `for val1, nested := range m { ... }`.
    for (auto it_op1 = inner_.begin(); it_op1 != inner_.end();) {
        auto& op2_map = it_op1->second;
        const auto* other_op2_map = other.Find(it_op1->first);
        for (auto it_op2 = op2_map.begin(); it_op2 != op2_map.end();) {
            auto& pcs = it_op2->second;
            const PcSet* other_pcs = nullptr;
            if (other_op2_map != nullptr) {
                auto it = other_op2_map->find(it_op2->first);
                if (it != other_op2_map->end()) {
                    other_pcs = &it->second;
                }
            }
            for (auto it_pc = pcs.begin(); it_pc != pcs.end();) {
                if (other_pcs == nullptr || other_pcs->count(*it_pc) == 0) {
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
            it_op1 = inner_.erase(it_op1);
        } else {
            ++it_op1;
        }
    }
}

std::string CompMap::ToString() const {
    std::string out;
    char buf[48];
    bool first_op1 = true;
    for (const auto& [op1, op2_map] : inner_) {
        if (!first_op1) out += ", ";
        first_op1 = false;
        std::snprintf(buf, sizeof(buf), "0x%llx:",
                      static_cast<unsigned long long>(op1));
        out += buf;
        for (const auto& [op2, pcs] : op2_map) {
            (void)pcs;
            std::snprintf(buf, sizeof(buf), " 0x%llx",
                          static_cast<unsigned long long>(op2));
            out += buf;
        }
    }
    return out;
}

const CompMap::Op2Pcs* CompMap::Find(uint64_t op1) const {
    auto it = inner_.find(op1);
    return it == inner_.end() ? nullptr : &it->second;
}

} // namespace refuzz::mutator::syz_v2::hints
