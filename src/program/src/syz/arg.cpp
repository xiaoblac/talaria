// Implementation for refuzz/program/syz/arg.hpp

#include "refuzz/program/syz/arg.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace refuzz::program::syz {

namespace {
// Mirror of prog.maxSpecialPointers from upstream.
constexpr uint64_t kMaxSpecialPointers = 16;
} // namespace

bool PointerArg::is_special() const {
    if (vma_size_ != 0 || res_) return false;
    // Special pointer encoding: address is the negation of the index, so
    // (-address) must be < kMaxSpecialPointers.
    const uint64_t neg = static_cast<uint64_t>(-static_cast<int64_t>(address_));
    return neg < kMaxSpecialPointers;
}

// Mirror of prog.ConstArg.Value (prog.go).
std::pair<uint64_t, uint64_t> ConstArg::value_with_pid_stride() const {
    if (type_ == nullptr) return {val_, 0};
    switch (type_->kind()) {
        case TypeKind::kInt:
        case TypeKind::kConst:
        case TypeKind::kFlags:
        case TypeKind::kLen:
        case TypeKind::kResource:
            return {val_, 0};
        case TypeKind::kCsum:
            // Checksums recomputed by executor at runtime.
            return {0, 0};
        case TypeKind::kProc: {
            constexpr uint64_t kProcDefaultValue = ~uint64_t{0};
            if (val_ == kProcDefaultValue) return {0, 0};
            const auto* pt = static_cast<const ProcType*>(type_);
            return {pt->values_start() + val_, pt->values_per_proc()};
        }
        default:
            return {val_, 0};
    }
}

// Mirror of prog.Type.isDefaultArg dispatch.
bool is_default_arg(const Arg* a) {
    if (a == nullptr) return true;
    switch (a->arg_kind()) {
        case ArgKind::kConst: {
            const auto& ca = static_cast<const ConstArg&>(*a);
            const Type* t  = a->type();
            if (auto* ct = as_const(t)) return ca.val() == ct->val();
            if (t && t->kind() == TypeKind::kProc) {
                // ProcType default is procDefaultValue (~0).
                return ca.val() == ~uint64_t{0};
            }
            return ca.val() == 0;
        }
        case ArgKind::kResult: {
            const auto& ra = static_cast<const ResultArg&>(*a);
            if (ra.res() != nullptr) return false;
            if (ra.op_div() != 0 || ra.op_add() != 0) return false;
            uint64_t def = 0;
            if (auto* rt = as_resource(a->type())) {
                if (rt->desc() != nullptr && !rt->desc()->values().empty()) {
                    def = rt->desc()->values()[0];
                }
            }
            return ra.val() == def;
        }
        case ArgKind::kPointer: {
            const auto& pa = static_cast<const PointerArg&>(*a);
            if (a->type() != nullptr && a->type()->optional()) {
                return pa.is_special() && pa.address() == 0;
            }
            return pa.address() == 0 && pa.res() != nullptr && is_default_arg(pa.res());
        }
        case ArgKind::kData: {
            const auto& da = static_cast<const DataArg&>(*a);
            const auto* bt = as_buffer(a->type());
            const uint64_t sz = (a->type() != nullptr && !a->type()->var_len())
                ? a->type()->size() : 0;
            if (da.size() != sz) return false;
            if (a->dir() == Dir::kOut) return true;
            if (bt && bt->values().size() == 1) {
                const std::string& v = bt->values().front();
                return da.data().size() == v.size() &&
                       std::memcmp(da.data().data(), v.data(), v.size()) == 0;
            }
            for (uint8_t b : da.data()) if (b != 0) return false;
            return true;
        }
        case ArgKind::kGroup: {
            const auto& ga = static_cast<const GroupArg&>(*a);
            // Variable-length, non-empty arrays cannot collapse to default
            // (an empty array is the type-default; any element makes the
            // group materially different).
            if (auto* at = as_array(a->type())) {
                const bool fixed = at->array_kind() == ArrayKind::kRangeLen &&
                                   at->range_begin() == at->range_end();
                if (!fixed && !ga.inner().empty()) return false;
            }
            for (const auto& up : ga.inner()) {
                if (up && !is_default_arg(up.get())) return false;
            }
            return true;
        }
        case ArgKind::kUnion: {
            const auto& ua = static_cast<const UnionArg&>(*a);
            const auto* ut = as_union(a->type());
            int defIdx = 0;
            if (ut != nullptr) {
                if (ut->is_conditional()) {
                    if (!ut->fields().empty() &&
                        ut->fields().back().condition() == nullptr) {
                        defIdx = static_cast<int>(ut->fields().size()) - 1;
                    } else {
                        return is_default_arg(ua.option());
                    }
                }
            }
            return ua.index() == defIdx && is_default_arg(ua.option());
        }
    }
    return false;
}

// Mirror of prog.GroupArg.Size() — handles fixed-size (returns Type.Size())
// and varlen struct (sums inner sizes with overlay/alignment) and varlen
// array (sums inner sizes).
uint64_t GroupArg::size() const {
    if (type_ != nullptr && !type_->var_len()) return type_->size();

    if (type_ != nullptr && type_->kind() == TypeKind::kStruct) {
        const auto* st = static_cast<const StructType*>(type_);
        uint64_t total  = 0;
        uint64_t offset = 0;
        const int overlay = st->overlay_field();
        for (std::size_t i = 0; i < inner_.size(); ++i) {
            if (static_cast<int>(i) == overlay) offset = 0;
            offset += inner_[i] ? inner_[i]->size() : 0;
            // Apply struct alignment at the end and before the overlay part.
            if (i + 1 == inner_.size() ||
                static_cast<int>(i + 1) == overlay) {
                if (st->align_attr() != 0 && offset % st->align_attr() != 0) {
                    offset += st->align_attr() - offset % st->align_attr();
                }
            }
            total = std::max(total, offset);
        }
        return total;
    }
    // Varlen array: sum all inner sizes.
    uint64_t total = 0;
    for (const auto& up : inner_) {
        if (up) total += up->size();
    }
    return total;
}

} // namespace refuzz::program::syz
