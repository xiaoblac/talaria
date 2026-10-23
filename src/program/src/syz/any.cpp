// reFuzz syz_v2 — anyTypes / squash machinery impl.
//
// See any.hpp for scope. This file ships P5 (predicates only); the
// squash mutators are stubs that abort, gated on §3.12 mutator port.

#include "refuzz/program/syz/any.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

// ============================================================
// Target::any_types() lookup. Lazy-builds the cache on first call;
// finds the ANYPTRS UnionType in the type arena and walks its
// layout (mirrors prog/any.go::initAnyTypes).
// ============================================================

namespace {

// Locate the cached AnyTypes by walking the Target's type arena.
// Returns nullptr if no ANYPTRS union is registered (e.g., a stripped
// test target). Caller code should fall back to "no any-types"
// behavior in that case.
const AnyTypes* compute_any_types(const Target& target) {
    static thread_local AnyTypes cache;       // populated once per thread
    static thread_local bool     ready  = false;
    static thread_local const Target* who = nullptr;

    if (ready && who == &target) return &cache;
    cache = AnyTypes{};
    who = &target;
    ready = false;

    const UnionType* any_ptrs = nullptr;
    for (const auto& tp : target.arena().types()) {
        if (tp == nullptr) continue;
        if (tp->kind() != TypeKind::kUnion) continue;
        if (tp->name() == "ANYPTRS") {
            any_ptrs = static_cast<const UnionType*>(tp.get());
            break;
        }
    }
    if (any_ptrs == nullptr || any_ptrs->fields().size() < 2) {
        // No any-types in this target — predicates will return false.
        ready = true;
        return &cache;
    }

    auto cast_or_null = [](const Type* t, TypeKind k) -> const Type* {
        return (t != nullptr && t->kind() == k) ? t : nullptr;
    };

    cache.ptr_ptr = static_cast<const PtrType*>(
        cast_or_null(any_ptrs->fields()[0].type(), TypeKind::kPtr));
    cache.ptr_64  = static_cast<const PtrType*>(
        cast_or_null(any_ptrs->fields()[1].type(), TypeKind::kPtr));
    if (cache.ptr_ptr == nullptr || cache.ptr_64 == nullptr) {
        ready = true;
        return &cache;
    }

    cache.any_array = static_cast<const ArrayType*>(
        cast_or_null(cache.ptr_ptr->elem(), TypeKind::kArray));
    if (cache.any_array == nullptr) {
        ready = true;
        return &cache;
    }
    cache.any_union = static_cast<const UnionType*>(
        cast_or_null(cache.any_array->elem(), TypeKind::kUnion));
    if (cache.any_union == nullptr || cache.any_union->fields().size() < 8) {
        ready = true;
        return &cache;
    }

    const auto& fs = cache.any_union->fields();
    cache.any_blob = static_cast<const BufferType*>(
        cast_or_null(fs[0].type(), TypeKind::kBuffer));
    cache.res_8   = static_cast<const ResourceType*>(
        cast_or_null(fs[1].type(), TypeKind::kResource));
    cache.res_16  = static_cast<const ResourceType*>(
        cast_or_null(fs[2].type(), TypeKind::kResource));
    cache.res_32  = static_cast<const ResourceType*>(
        cast_or_null(fs[3].type(), TypeKind::kResource));
    cache.res_64  = static_cast<const ResourceType*>(
        cast_or_null(fs[4].type(), TypeKind::kResource));
    cache.res_dec = static_cast<const ResourceType*>(
        cast_or_null(fs[5].type(), TypeKind::kResource));
    cache.res_hex = static_cast<const ResourceType*>(
        cast_or_null(fs[6].type(), TypeKind::kResource));
    cache.res_oct = static_cast<const ResourceType*>(
        cast_or_null(fs[7].type(), TypeKind::kResource));

    ready = true;
    return &cache;
}

} // namespace

// ============================================================
// Predicates
// ============================================================

bool is_any_ptr(const Target& target, const Type* typ) {
    if (typ == nullptr || typ->kind() != TypeKind::kPtr) return false;
    const auto* cache = compute_any_types(target);
    if (cache == nullptr || cache->any_array == nullptr) return false;
    const auto* pt = static_cast<const PtrType*>(typ);
    return pt->elem() == cache->any_array;
}

bool is_any_res(std::string_view name) {
    return name == "ANYRES8"   || name == "ANYRES16"  ||
           name == "ANYRES32"  || name == "ANYRES64"  ||
           name == "ANYRESDEC" || name == "ANYRESHEX" ||
           name == "ANYRESOCT";
}

bool call_contains_any(const Target& target, const Call& call) {
    bool found = false;
    foreach_arg(const_cast<Call*>(&call),
        [&](Arg* a, ArgCtx* ctx) {
            if (found) { ctx->stop = true; return; }
            if (a != nullptr && is_any_ptr(target, a->type())) {
                found = true;
                ctx->stop = true;
            }
        });
    return found;
}

bool arg_contains_any(const Target& target, const Arg& arg) {
    bool found = false;
    foreach_sub_arg(const_cast<Arg*>(&arg),
        [&](Arg* a, ArgCtx* ctx) {
            if (found) { ctx->stop = true; return; }
            if (a != nullptr && is_any_ptr(target, a->type())) {
                found = true;
                ctx->stop = true;
            }
        });
    return found;
}

// ============================================================
// Squash machinery — port of prog/any.go (squashPtr et al.).
// Flattens a "complex" structured pointee into a varlen ANYUNION array of
// ANYBLOB (raw bytes) + ANYRES (resource refs), byte-for-byte preserving the
// original in-memory layout. Upstream asserts the invariants via panic; we
// pre-check (subtree_squashable) and decline gracefully instead so a
// long-running fuzzer never aborts.
// ============================================================

namespace {

// getAnyPtrType(size): the ANY ptr type whose width matches the original
// pointer (ptr-sized → ptrPtr; explicit 8-byte → ptr64). prog/any.go:51.
const PtrType* get_any_ptr_type(const AnyTypes& any, uint64_t size) {
    if (any.ptr_ptr != nullptr && size == any.ptr_ptr->size()) return any.ptr_ptr;
    if (any.ptr_64  != nullptr && size == 8)                    return any.ptr_64;
    return nullptr;
}

// Pre-flight: is the whole pointee subtree squashable? No nested non-any
// pointers (squashable_elem should already guarantee this — belt and
// suspenders), no overlay structs, no non-native bitfields. These are the
// cases upstream squashPtrImpl/squashGroup panic on.
bool subtree_squashable(const Target& target, const Arg* root) {
    bool ok = true;
    foreach_sub_arg(const_cast<Arg*>(root), [&](Arg* a, ArgCtx* ctx) {
        if (!ok) { ctx->stop = true; return; }
        if (a == nullptr) return;
        const Type* t = a->type();
        switch (a->arg_kind()) {
            case ArgKind::kPointer:
                if (!is_any_ptr(target, t)) { ok = false; ctx->stop = true; }
                break;
            case ArgKind::kGroup:
                if (t != nullptr && t->kind() == TypeKind::kStruct &&
                    static_cast<const StructType*>(t)->overlay_field() != 0) {
                    ok = false; ctx->stop = true;
                }
                break;
            case ArgKind::kConst:
                // A bitfield must squash to native bytes. squashed_value
                // converts big-endian → native (byte-swap), so only the
                // string formats are unsquashable (upstream squashGroup
                // panics on those).
                if (t != nullptr && t->is_bitfield()) {
                    const BinaryFormat bf =
                        static_cast<const IntTypeCommon*>(t)->format();
                    if (bf == BinaryFormat::kStrDec ||
                        bf == BinaryFormat::kStrHex ||
                        bf == BinaryFormat::kStrOct) {
                        ok = false; ctx->stop = true;
                    }
                }
                break;
            default:
                break;
        }
    });
    return ok;
}

// (value, format) for a const — big-endian is byte-swapped to native here;
// csum left as a recognizable placeholder. prog/any.go:284.
std::pair<uint64_t, BinaryFormat> squashed_value(const ConstArg* arg) {
    const Type* t = arg->type();
    if (t != nullptr && t->kind() == TypeKind::kCsum) {
        return {0xabcdef1234567890ULL, BinaryFormat::kNative};
    }
    uint64_t v = arg->value_with_pid_stride().first;
    BinaryFormat bf = (t != nullptr)
        ? static_cast<const IntTypeCommon*>(t)->format() : BinaryFormat::kNative;
    if (bf == BinaryFormat::kBigEndian) {
        bf = BinaryFormat::kNative;
        switch (t->unit_size()) {
            case 2: v = __builtin_bswap16(static_cast<uint16_t>(v)); break;
            case 4: v = __builtin_bswap32(static_cast<uint32_t>(v)); break;
            case 8: v = __builtin_bswap64(v); break;
            default: break;  // size 1: no swap
        }
    }
    return {v, bf};
}

// Trailing ANYBLOB accumulator: reuse the last elem if it is a UnionArg
// wrapping a DataArg, else append a fresh ANYBLOB union elem (index 0).
// prog/any.go:313.
DataArg* ensure_data_elem(const AnyTypes& any,
                          std::vector<std::unique_ptr<Arg>>* elems) {
    if (!elems->empty()) {
        Arg* last = elems->back().get();
        if (last != nullptr && last->arg_kind() == ArgKind::kUnion) {
            Arg* opt = static_cast<UnionArg*>(last)->option();
            if (opt != nullptr && opt->arg_kind() == ArgKind::kData) {
                return static_cast<DataArg*>(opt);
            }
        }
    }
    auto blob = std::make_unique<DataArg>();
    blob->set_type(any.any_blob);
    blob->set_dir(Dir::kIn);
    blob->set_data({});
    DataArg* raw = blob.get();
    auto u = std::make_unique<UnionArg>();
    u->set_type(any.any_union);
    u->set_dir(Dir::kIn);
    u->set_option(std::move(blob));
    u->set_index(0);
    elems->push_back(std::move(u));
    return raw;
}

void append_zeros(DataArg* elem, uint64_t n) {
    auto& buf = elem->mutable_data();
    buf.insert(buf.end(), static_cast<size_t>(n), 0);
}

// Serialize a ConstArg to its on-wire bytes (native byte-expansion or the
// fixed-width str dec/hex/oct forms). prog/any.go:187.
void squash_const(const AnyTypes& any, const ConstArg* arg,
                  std::vector<std::unique_ptr<Arg>>* elems) {
    const uint64_t sz = arg->size();
    if (is_pad(arg->type())) {
        append_zeros(ensure_data_elem(any, elems), sz);
        return;
    }
    const auto [v, bf] = squashed_value(arg);
    DataArg* elem = ensure_data_elem(any, elems);
    if (bf == BinaryFormat::kNative) {
        uint64_t tmp = v;
        for (uint64_t i = 0; i < sz; ++i) {
            elem->mutable_data().push_back(static_cast<uint8_t>(tmp));
            tmp >>= 8;
        }
        return;
    }
    char buf[40];
    int len = 0;
    const auto uv = static_cast<unsigned long long>(v);
    switch (bf) {
        case BinaryFormat::kStrDec: len = std::snprintf(buf, sizeof(buf), "%020llu", uv); break;
        case BinaryFormat::kStrHex: len = std::snprintf(buf, sizeof(buf), "0x%016llx", uv); break;
        case BinaryFormat::kStrOct: len = std::snprintf(buf, sizeof(buf), "%023llo", uv); break;
        default: break;
    }
    if (len > 0) {
        auto& dst = elem->mutable_data();
        dst.insert(dst.end(), buf, buf + len);
    }
}

// Re-type the ResultArg to the matching ANYRES resource (preserving its
// res_/uses_ edge — the object is re-typed in place, not copied) and wrap it
// in an ANYUNION elem. prog/any.go:217. Takes ownership of `arg`.
void squash_result(const AnyTypes& any, std::unique_ptr<Arg> arg,
                   std::vector<std::unique_ptr<Arg>>* elems) {
    const Type* t = arg->type();
    const BinaryFormat fmt = (t != nullptr)
        ? static_cast<const ResourceType*>(t)->format() : BinaryFormat::kNative;
    const ResourceType* res_type = nullptr;
    int index = 0;
    switch (fmt) {
        case BinaryFormat::kNative:
        case BinaryFormat::kBigEndian:
            switch (arg->size()) {
                case 1: res_type = any.res_8;  index = 1; break;
                case 2: res_type = any.res_16; index = 2; break;
                case 4: res_type = any.res_32; index = 3; break;
                case 8: res_type = any.res_64; index = 4; break;
                default: break;
            }
            break;
        case BinaryFormat::kStrDec: res_type = any.res_dec; index = 5; break;
        case BinaryFormat::kStrHex: res_type = any.res_hex; index = 6; break;
        case BinaryFormat::kStrOct: res_type = any.res_oct; index = 7; break;
    }
    if (res_type == nullptr) {
        // Unexpected size/format (pre-check should preclude) — preserve layout
        // with a zero blob of the arg's size rather than drop the bytes.
        append_zeros(ensure_data_elem(any, elems), arg->size());
        return;
    }
    arg->set_type(res_type);
    auto u = std::make_unique<UnionArg>();
    u->set_type(any.any_union);
    u->set_dir(Dir::kIn);
    u->set_option(std::move(arg));
    u->set_index(index);
    elems->push_back(std::move(u));
}

void squash_ptr_impl(const AnyTypes& any, std::unique_ptr<Arg> a,
                     std::vector<std::unique_ptr<Arg>>* elems);

// Flatten a GroupArg's fields, accumulating consecutive bitfields into their
// storage unit, and emitting trailing padding. prog/any.go:247.
void squash_group(const AnyTypes& any, GroupArg* group,
                  std::vector<std::unique_ptr<Arg>>* elems) {
    // Capture the group's total size BEFORE the loop: squash_ptr_impl below
    // std::moves fields out of group->inner(), and GroupArg::size() for a
    // VARLEN struct re-sums the (now-null) field slots — so reading it after
    // the loop would return a wrong, too-small value and drop trailing
    // alignment padding.
    const uint64_t total = group->size();
    uint64_t fields_size = 0;
    uint64_t bitfield = 0;
    for (auto& fld_slot : group->mutable_inner()) {
        Arg* fld = fld_slot.get();
        if (fld == nullptr) continue;
        const Type* ft = fld->type();
        fields_size += fld->size();
        if (ft != nullptr && ft->is_bitfield()) {
            if (const ConstArg* c = as_const_arg(fld)) {
                const uint64_t v = squashed_value(c).first;  // native (pre-checked)
                const uint64_t bf_len = ft->bitfield_length();
                const uint64_t bf_off = ft->bitfield_offset();
                const uint64_t mask =
                    (bf_len >= 64) ? ~uint64_t{0} : ((uint64_t{1} << bf_len) - 1);
                bitfield |= (v & mask) << bf_off;
            }
            if (fld->size() != 0) {  // storage-unit boundary → flush
                DataArg* elem = ensure_data_elem(any, elems);
                for (uint64_t i = 0; i < fld->size(); ++i) {
                    elem->mutable_data().push_back(static_cast<uint8_t>(bitfield));
                    bitfield >>= 8;
                }
                bitfield = 0;
            }
            continue;
        }
        squash_ptr_impl(any, std::move(fld_slot), elems);
    }
    if (total > fields_size) {
        append_zeros(ensure_data_elem(any, elems), total - fields_size);
    }
}

// Dispatch one arg of the pointee into the ANY element stream, taking
// ownership (ResultArgs are re-homed; everything else is read then dropped).
// prog/any.go:154.
void squash_ptr_impl(const AnyTypes& any, std::unique_ptr<Arg> a,
                     std::vector<std::unique_ptr<Arg>>* elems) {
    if (!a) return;
    uint64_t pad = 0;
    switch (a->arg_kind()) {
        case ArgKind::kConst:
            squash_const(any, static_cast<const ConstArg*>(a.get()), elems);
            break;
        case ArgKind::kResult:
            squash_result(any, std::move(a), elems);
            return;  // ownership transferred
        case ArgKind::kUnion: {
            UnionArg* u = static_cast<UnionArg*>(a.get());
            const Type* ut = u->type();
            if (ut != nullptr && !ut->var_len() && u->option() != nullptr) {
                pad = a->size() - u->option()->size();
            }
            squash_ptr_impl(any, std::move(u->mutable_option_slot()), elems);
            break;
        }
        case ArgKind::kData: {
            DataArg* d = static_cast<DataArg*>(a.get());
            if (d->dir() == Dir::kOut) {
                pad = d->size();
            } else {
                DataArg* elem = ensure_data_elem(any, elems);
                const auto& src = d->data();
                elem->mutable_data().insert(elem->mutable_data().end(),
                                            src.begin(), src.end());
            }
            break;
        }
        case ArgKind::kGroup:
            squash_group(any, static_cast<GroupArg*>(a.get()), elems);
            break;
        default:
            break;  // Pointer / unexpected — excluded by subtree_squashable.
    }
    if (pad != 0) {
        append_zeros(ensure_data_elem(any, elems), pad);
    }
}

bool is_complex_ptr_impl(const Target& target, const PointerArg* arg) {
    if (arg == nullptr || arg->res() == nullptr) return false;
    const Type* t = arg->type();
    if (t == nullptr || t->kind() != TypeKind::kPtr) return false;
    if (!static_cast<const PtrType*>(t)->squashable_elem()) return false;
    if (is_any_ptr(target, t)) return true;
    bool complex = false;
    foreach_sub_arg(const_cast<Arg*>(arg->res()), [&](Arg* a, ArgCtx* ctx) {
        if (complex) { ctx->stop = true; return; }
        const Type* st = (a != nullptr) ? a->type() : nullptr;
        if (st == nullptr) return;
        if (st->kind() == TypeKind::kStruct) {
            if (st->var_len()) { complex = true; ctx->stop = true; }
        } else if (st->kind() == TypeKind::kUnion) {
            const auto* ut = static_cast<const UnionType*>(st);
            if (st->var_len() && ut->fields().size() > 5) {
                complex = true; ctx->stop = true;
            }
        }
    });
    return complex;
}

} // namespace

// ============================================================
// Public: complex-pointer discovery + squash entry point.
// ============================================================

bool is_complex_ptr(const Target& target, const PointerArg* arg) {
    return is_complex_ptr_impl(target, arg);
}

std::vector<ComplexPtr> complex_ptrs(const Target& target, Prog& prog) {
    std::vector<ComplexPtr> res;
    for (auto& cup : prog.mutable_calls()) {
        if (!cup) continue;
        Call* call = cup.get();
        foreach_arg(call, [&](Arg* a, ArgCtx* ctx) {
            if (a != nullptr && a->arg_kind() == ArgKind::kPointer &&
                is_complex_ptr_impl(target, static_cast<PointerArg*>(a))) {
                res.push_back(ComplexPtr{static_cast<PointerArg*>(a), call});
                ctx->stop = true;  // one complex ptr per subtree
            }
        });
    }
    return res;
}

void squash_ptr(const Target& target, PointerArg* arg) {
    const AnyTypes* any = compute_any_types(target);
    if (any == nullptr || !any->ready()) return;
    if (arg == nullptr || arg->res() == nullptr || arg->vma_size() != 0) return;
    const Type* pt = arg->type();
    const PtrType* new_type = get_any_ptr_type(*any, pt != nullptr ? pt->size() : 0);
    if (new_type == nullptr) return;
    if (!subtree_squashable(target, arg->res())) return;

    std::unique_ptr<Arg> old = std::move(arg->mutable_res_slot());
    std::vector<std::unique_ptr<Arg>> elems;
    squash_ptr_impl(*any, std::move(old), &elems);

    auto group = std::make_unique<GroupArg>();
    group->set_type(any->any_array);
    group->set_dir(Dir::kIn);
    group->set_inner(std::move(elems));
    arg->set_res(std::move(group));
    arg->set_type(new_type);
}

} // namespace refuzz::program::syz
