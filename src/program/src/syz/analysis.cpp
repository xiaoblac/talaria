#include "refuzz/program/syz/analysis.hpp"

#include "refuzz/program/syz/type.hpp"

#include <cstddef>
#include <cstdint>
#include <unordered_set>

namespace refuzz::program::syz {

namespace {

// Mirror of prog.foreachArgImpl. Critical: ctx is snapshotted on entry
// and restored on exit (matches Go's `defer func() { *ctx = ctx0 }()`),
// so sibling args don't inherit base/offset/parent fields from each
// other. Earlier reFuzz versions restored before the switch — which
// caused exec wire to mis-attribute base pointers across sibling top-
// level args (every register-passed flag picked up the previous
// pointer's base).
void foreach_arg_impl(Arg* arg, const Field* field, ArgCtx* ctx, const ArgVisitor& f) {
    ArgCtx ctx0 = *ctx;
    if (ctx->use_stack) {
        const Type* t = arg->type();
        if (t != nullptr &&
            (t->kind() == TypeKind::kStruct || t->kind() == TypeKind::kUnion)) {
            ctx->parent_stack.push_back(arg);
        }
    }
    ctx->field = field;
    f(arg, ctx);
    if (ctx->stop) {
        *ctx = ctx0;
        return;
    }

    switch (arg->arg_kind()) {
        case ArgKind::kGroup: {
            auto* g = static_cast<GroupArg*>(arg);
            int overlay = 0;
            if (auto* st = as_struct(arg->type())) {
                ctx->parent = &g->mutable_inner();
                ctx->fields = &st->fields();
                overlay = st->overlay_field();
            } else {
                ctx->parent = nullptr;
                ctx->fields = nullptr;
            }
            const uint64_t saved_offset = ctx->offset;
            for (std::size_t i = 0; i < g->inner().size(); ++i) {
                if (static_cast<int>(i) == overlay) ctx->offset = saved_offset;
                Arg* child = g->mutable_inner()[i].get();
                const Field* fld = nullptr;
                if (auto* st = as_struct(arg->type()); st && i < st->fields().size()) {
                    fld = &st->fields()[i];
                }
                foreach_arg_impl(child, fld, ctx, f);
                if (child) ctx->offset += child->size();
            }
            break;
        }
        case ArgKind::kPointer: {
            auto* p = static_cast<PointerArg*>(arg);
            if (p->res() != nullptr) {
                ctx->base   = p;
                ctx->offset = 0;
                foreach_arg_impl(p->res(), nullptr, ctx, f);
            }
            break;
        }
        case ArgKind::kUnion: {
            auto* u = static_cast<UnionArg*>(arg);
            if (u->option() != nullptr) {
                foreach_arg_impl(u->option(), nullptr, ctx, f);
            }
            break;
        }
        case ArgKind::kConst:
        case ArgKind::kData:
        case ArgKind::kResult:
            break;
    }
    *ctx = ctx0;
}

} // namespace

void foreach_arg(Call* c, const ArgVisitor& f) {
    ArgCtx ctx{};
    if (c->mutable_ret() != nullptr) {
        foreach_arg_impl(c->mutable_ret(), nullptr, &ctx, f);
    }
    auto& args = c->mutable_args();
    ctx.parent = &args;
    ctx.fields = c->meta() ? &c->meta()->args() : nullptr;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const Field* fld = nullptr;
        if (c->meta() != nullptr && i < c->meta()->args().size()) {
            fld = &c->meta()->args()[i];
        }
        Arg* a = args[i].get();
        foreach_arg_impl(a, fld, &ctx, f);
    }
}

void foreach_sub_arg(Arg* a, const ArgVisitor& f) {
    ArgCtx ctx{};
    foreach_arg_impl(a, nullptr, &ctx, f);
}

void foreach_sub_arg_with_stack(Arg* a, const ArgVisitor& f) {
    ArgCtx ctx{};
    ctx.use_stack = true;
    ctx.parent_stack.reserve(8);
    foreach_arg_impl(a, nullptr, &ctx, f);
}

Arg* inner_arg(Arg* a) {
    // [v1 dispatch on PointerArg C++ class — ROLLBACK: uncomment below and remove v2]
    // while (a != nullptr) {
    //     if (auto* pa = dynamic_cast<PointerArg*>(a)) {
    //         if (pa->res() == nullptr) return nullptr;
    //         a = pa->res();
    //         continue;
    //     }
    //     return a;
    // }
    // return nullptr;
    //
    // [v2 dispatch on Type kind — 当前版本]
    // C++ PointerArg is shared by both kPtr and kVma. Only kPtr has a
    // pointee res() to follow; kVma's res() is always nullptr because
    // a vma is encoded by (address, vma_size) in PointerArg directly.
    // The v1 form treated kVma like kPtr-with-null-res and returned
    // nullptr, which broke `len[vma_arg]` size assignment in
    // size.cpp::find_arg (the LenType ConstArg got val=0 since
    // compute_size receives arg=nullptr). Mirrors syzkaller
    // prog.InnerArg dispatching on Type().(*PtrType).
    while (a != nullptr) {
        if (a->type() != nullptr && a->type()->kind() == TypeKind::kPtr) {
            auto* pa = static_cast<PointerArg*>(a);
            if (pa->res() == nullptr) return nullptr;
            a = pa->res();
            continue;
        }
        return a;
    }
    return nullptr;
}

// ============================================================
// foreach_type — type-tree visitor (§3.11 follow-up P9).
//
// Mirrors syzkaller `prog/types.go::ForeachType` + `foreachTypeRec`.
// ============================================================

namespace {

struct SeenKey {
    const Type* type;
    Dir         dir;
    bool        optional;

    bool operator==(const SeenKey& o) const {
        return type == o.type && dir == o.dir && optional == o.optional;
    }
};

struct SeenKeyHash {
    std::size_t operator()(const SeenKey& k) const noexcept {
        std::uintptr_t base = reinterpret_cast<std::uintptr_t>(k.type);
        // Stir in dir (2 bits) + optional (1 bit) so disambiguation is
        // captured in the hash, not just key equality.
        std::size_t h = static_cast<std::size_t>(base);
        h ^= (static_cast<std::size_t>(k.dir) << 1) ^
             (static_cast<std::size_t>(k.optional ? 1 : 0));
        return h;
    }
};

using SeenSet = std::unordered_set<SeenKey, SeenKeyHash>;

void foreach_type_rec(const TypeVisitor&        cb,
                      const SyscallMeta*        meta,
                      SeenSet&                  seen,
                      const Type* const*        ptr,
                      Dir                       dir,
                      bool                      preorder,
                      bool                      optional)
{
    if (ptr == nullptr || *ptr == nullptr) return;

    const Type* t = *ptr;
    if (t->optional()) optional = true;

    TypeCtx ctx;
    ctx.meta     = meta;
    ctx.dir      = dir;
    ctx.ptr      = ptr;
    ctx.optional = optional;

    if (preorder) {
        cb(t, &ctx);
        if (ctx.stop) return;
    }

    switch (t->kind()) {
    case TypeKind::kPtr: {
        const auto* pt = static_cast<const PtrType*>(t);
        const Type* elem = pt->elem();
        foreach_type_rec(cb, meta, seen, &elem, pt->elem_dir(),
                         preorder, optional);
        break;
    }
    case TypeKind::kArray: {
        const auto* at = static_cast<const ArrayType*>(t);
        const Type* elem = at->elem();
        foreach_type_rec(cb, meta, seen, &elem, dir, preorder, optional);
        break;
    }
    case TypeKind::kStruct: {
        SeenKey key{t, dir, optional};
        if (seen.count(key) != 0) break;
        seen.insert(key);
        const auto* st = static_cast<const StructType*>(t);
        for (const auto& f : st->fields()) {
            const Type* ft = f.type();
            foreach_type_rec(cb, meta, seen, &ft,
                             f.dir(dir), preorder, optional);
        }
        break;
    }
    case TypeKind::kUnion: {
        SeenKey key{t, dir, optional};
        if (seen.count(key) != 0) break;
        seen.insert(key);
        const auto* ut = static_cast<const UnionType*>(t);
        for (const auto& f : ut->fields()) {
            const Type* ft = f.type();
            foreach_type_rec(cb, meta, seen, &ft,
                             f.dir(dir), preorder, optional);
        }
        break;
    }
    case TypeKind::kInt:
    case TypeKind::kConst:
    case TypeKind::kFlags:
    case TypeKind::kProc:
    case TypeKind::kLen:
    case TypeKind::kCsum:
    case TypeKind::kResource:
    case TypeKind::kBuffer:
    case TypeKind::kVma:
        // Leaf — no sub-types to recurse into.
        break;
    }
}

void foreach_call_type_impl(const SyscallMeta* meta,
                            const TypeVisitor& cb)
{
    if (meta == nullptr) return;
    SeenSet seen;
    for (const auto& f : meta->args()) {
        const Type* t = f.type();
        foreach_type_rec(cb, meta, seen, &t, f.dir(Dir::kIn),
                         /*preorder=*/true, false);
    }
    if (const auto* ret = meta->ret(); ret != nullptr) {
        foreach_type_rec(cb, meta, seen, &ret, Dir::kOut,
                         /*preorder=*/true, false);
    }
}

} // namespace

void foreach_type(const Target& target, const TypeVisitor& cb)
{
    for (const auto& mp : target.syscalls()) {
        foreach_call_type_impl(mp.get(), cb);
    }
}

void foreach_call_type(const SyscallMeta* meta, const TypeVisitor& cb)
{
    foreach_call_type_impl(meta, cb);
}

void foreach_arg_type(const Type* root, const TypeVisitor& cb)
{
    if (root == nullptr) return;
    SeenSet seen;
    foreach_type_rec(cb, /*meta=*/nullptr, seen, &root,
                     Dir::kIn, /*preorder=*/true, /*optional=*/false);
}

} // namespace refuzz::program::syz
