// reFuzz syz_v2 — Type method implementations.
//
// Hosts the bodies of `Type` / `IntTypeCommon` / per-subclass methods
// that are too long to live inline in the header. Today carries the
// `useless_hints` lazy cache (§3.11 follow-up P3); will gain
// `default_arg / is_default_arg / clone / minimize` overrides in P2 /
// P8.

#include "refuzz/program/syz/type.hpp"

#include "refuzz/program/syz/arg.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::program::syz {

// ============================================================
// IntTypeCommon::useless_hint — lazy populate + lookup.
// ============================================================

bool IntTypeCommon::useless_hint(uint64_t v) const {
    if (!useless_hints_ready_) {
        const auto vals = calc_useless_hints();
        useless_hints_.reserve(vals.size());
        for (uint64_t x : vals) useless_hints_.insert(x);
        useless_hints_ready_ = true;
    }
    return useless_hints_.count(v) != 0;
}

// ============================================================
// specialInts — mirror of `prog/rand.go::specialInts`. The list of
// "potentially interesting integers" syzkaller's hint replacement
// considers trivial/uselss when proposed verbatim.
//
// Order is irrelevant for membership-set use; we keep it consistent
// with the upstream literal for diff readability.
// ============================================================

namespace {

constexpr uint64_t kSpecialInts[] = {
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

} // namespace

// ============================================================
// IntType::calc_useless_hints — mirror prog/types.go.
// ============================================================

std::vector<uint64_t> IntType::calc_useless_hints() const {
    std::vector<uint64_t> res;
    res.reserve(std::size(kSpecialInts) + 32);
    for (uint64_t v : kSpecialInts) res.push_back(v);

    const uint64_t align = std::max<uint64_t>(1, int_align_);
    if (range_end_ >= range_begin_) {
        const uint64_t range_vals = (range_end_ - range_begin_) / align;
        if (range_vals != 0 && range_vals <= 100) {
            for (uint64_t v = range_begin_; v <= range_end_; v += align) {
                res.push_back(v);
                if (v > range_end_ - align) break;  // overflow guard
            }
        }
    }
    return res;
}

// ============================================================
// FlagsType::calc_useless_hints — mirror prog/types.go.
// "Combinations of up to 3 flag values + 0."
// ============================================================

std::vector<uint64_t> FlagsType::calc_useless_hints() const {
    std::vector<uint64_t> res;
    res.push_back(0);
    const auto& vs = vals_;
    for (size_t i0 = 0; i0 < vs.size(); ++i0) {
        const uint64_t v0 = vs[i0];
        res.push_back(v0);
        if (vs.size() <= 10) {
            for (size_t i1 = i0 + 1; i1 < vs.size(); ++i1) {
                const uint64_t v1 = v0 | vs[i1];
                res.push_back(v1);
                if (vs.size() <= 7) {
                    for (size_t i2 = i1 + 1; i2 < vs.size(); ++i2) {
                        const uint64_t v2 = v1 | vs[i2];
                        res.push_back(v2);
                    }
                }
            }
        }
    }
    return res;
}

// ============================================================
// §3.11 follow-up P8 — Type::default_arg dispatch.
//
// Centralized switch on `kind()` mirroring the previous
// `MakeTypedDefaultArg` free function in
// `crash/repro/.../program_minimizer.cpp`. Lifted here so that all
// IR-internal default-arg construction is owned by `program/syz/`.
//
// Per-subclass overrides may replace this default in a future
// commit when they need to access private state; today the switch
// covers all 13 final subclasses.
// ============================================================

namespace {

std::unique_ptr<ConstArg> make_const_default(const Type* t, Dir dir, uint64_t v) {
    auto a = std::make_unique<ConstArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_val(v);
    return a;
}

} // namespace

std::unique_ptr<Arg> Type::default_arg(Dir dir) const {
    switch (kind()) {
    case TypeKind::kInt:
    case TypeKind::kFlags:
    case TypeKind::kLen:
    case TypeKind::kCsum:
        return make_const_default(this, dir, 0);

    case TypeKind::kConst:
        return make_const_default(this, dir,
            static_cast<const ConstType*>(this)->val());

    case TypeKind::kProc:
        return make_const_default(this, dir, ~uint64_t{0});

    case TypeKind::kResource: {
        auto a = std::make_unique<ResultArg>();
        a->set_type(this);
        a->set_dir(dir);
        a->set_val(static_cast<const ResourceType*>(this)->default_value());
        return a;
    }

    case TypeKind::kVma: {
        auto a = std::make_unique<PointerArg>();
        a->set_type(this);
        a->set_dir(dir);
        a->set_address(0);
        return a;
    }

    case TypeKind::kPtr: {
        const auto* pt = static_cast<const PtrType*>(this);
        auto a = std::make_unique<PointerArg>();
        a->set_type(this);
        a->set_dir(Dir::kIn);
        a->set_address(0);
        if (!optional()) {
            if (const Type* elem = pt->elem(); elem != nullptr) {
                a->set_res(elem->default_arg(pt->elem_dir()));
            }
        }
        return a;
    }

    case TypeKind::kBuffer: {
        auto a = std::make_unique<DataArg>();
        a->set_type(this);
        a->set_dir(dir);
        const auto* bt = static_cast<const BufferType*>(this);
        if (dir == Dir::kOut) {
            a->set_out_size(var_len() ? 0 : size());
        } else if (bt->values().size() == 1) {
            const auto& v = bt->values().front();
            a->set_data(std::vector<uint8_t>(v.begin(), v.end()));
        } else if (!var_len()) {
            a->set_data(std::vector<uint8_t>(size(), 0));
        }
        return a;
    }

    case TypeKind::kArray: {
        auto a = std::make_unique<GroupArg>();
        a->set_type(this);
        a->set_dir(dir);
        const auto* at = static_cast<const ArrayType*>(this);
        if (at->array_kind() == ArrayKind::kRangeLen &&
            at->range_begin() == at->range_end()) {
            for (uint64_t i = 0; i < at->range_begin(); ++i) {
                if (const Type* e = at->elem(); e != nullptr) {
                    a->add_inner(e->default_arg(dir));
                }
            }
        }
        return a;
    }

    case TypeKind::kStruct: {
        auto a = std::make_unique<GroupArg>();
        a->set_type(this);
        a->set_dir(dir);
        const auto* st = static_cast<const StructType*>(this);
        for (const auto& f : st->fields()) {
            if (const Type* ft = f.type(); ft != nullptr) {
                a->add_inner(ft->default_arg(f.dir(dir)));
            }
        }
        return a;
    }

    case TypeKind::kUnion: {
        auto a = std::make_unique<UnionArg>();
        a->set_type(this);
        a->set_dir(dir);
        const auto* ut = static_cast<const UnionType*>(this);
        int idx = 0;
        if (ut->is_conditional() && !ut->fields().empty() &&
            ut->fields().back().condition() == nullptr) {
            idx = static_cast<int>(ut->fields().size()) - 1;
        }
        a->set_index(idx);
        if (idx >= 0 && idx < static_cast<int>(ut->fields().size())) {
            const auto& f = ut->fields()[static_cast<size_t>(idx)];
            if (const Type* ft = f.type(); ft != nullptr) {
                a->set_option(ft->default_arg(f.dir(dir)));
            }
        }
        a->set_transient(ut->is_conditional());
        return a;
    }
    }
    return nullptr;
}

} // namespace refuzz::program::syz
