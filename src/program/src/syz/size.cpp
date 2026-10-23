#include "refuzz/program/syz/size.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <algorithm>
#include <cstdint>

namespace refuzz::program::syz {

namespace {

constexpr uint64_t kNoOffset = ~uint64_t{0};

struct FoundArg {
    Arg*     arg       = nullptr;
    uint64_t offset    = 0;
    bool     is_any_ptr = false;
    bool     present    = false;
};

uint64_t compute_size(const Arg* arg, uint64_t offset, const LenType& len_type);

// Forward decl
FoundArg find_arg(Arg* pos, const std::vector<std::string>& path,
                  const std::vector<std::unique_ptr<Arg>>& args,
                  const std::vector<Field>& fields,
                  const std::vector<Arg*>& parents,
                  int overlay_field);

FoundArg find_field_struct(Arg* buf, const std::vector<std::string>& path,
                           const std::vector<Arg*>& parents) {
    if (auto* g = dynamic_cast<GroupArg*>(buf)) {
        if (auto* st = as_struct(g->type())) {
            return find_arg(buf, path, g->inner(), st->fields(), parents, st->overlay_field());
        }
    }
    if (dynamic_cast<UnionArg*>(buf) != nullptr) {
        // No fields directly accessible from a union here.
        std::vector<std::unique_ptr<Arg>> empty_args;
        std::vector<Field>                empty_fields;
        return find_arg(buf, path, empty_args, empty_fields, parents, 0);
    }
    return {};
}

FoundArg find_arg(Arg* pos, const std::vector<std::string>& path,
                  const std::vector<std::unique_ptr<Arg>>& args,
                  const std::vector<Field>& fields,
                  const std::vector<Arg*>& parents,
                  int overlay_field) {
    if (path.empty()) return {};
    const std::string& elem = path[0];
    std::vector<std::string> rest(path.begin() + 1, path.end());

    uint64_t offset = 0;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (static_cast<int>(i) == overlay_field) offset = 0;
        Arg* buf = args[i].get();
        if (buf == nullptr) continue;
        if (i >= fields.size()) {
            offset += buf->size();
            continue;
        }
        if (elem != fields[i].name()) {
            offset += buf->size();
            continue;
        }
        Arg* inner = inner_arg(buf);
        if (inner == nullptr) {
            FoundArg f{}; f.present = true; f.arg = nullptr; f.offset = offset;
            return f;
        }
        if (!rest.empty()) {
            return find_field_struct(inner, rest, parents);
        }
        FoundArg f{}; f.present = true; f.arg = inner; f.offset = offset;
        return f;
    }

    // `parent` reference: pop one level off the stack.
    if (elem == "parent") {
        std::vector<Arg*> parents2 = parents;
        Arg* buf = nullptr;
        if (!parents2.empty()) {
            buf = parents2.back();
            parents2.pop_back();
        }
        if (!rest.empty() && buf != nullptr) {
            return find_field_struct(buf, rest, parents2);
        }
        FoundArg f{}; f.present = true; f.arg = buf; f.offset = kNoOffset;
        return f;
    }
    // Walk back the parent stack looking for a containing struct/union with
    // matching template name.
    std::vector<Arg*> parents2 = parents;
    while (!parents2.empty()) {
        Arg* buf = parents2.back();
        parents2.pop_back();
        const Type* t = buf->type();
        if (t == nullptr) continue;
        // Mirror upstream's TemplateName: name without "[...]" suffix.
        std::string nm = t->name();
        auto p = nm.find('[');
        if (p != std::string::npos) nm = nm.substr(0, p);
        if (elem != nm) continue;
        if (!rest.empty()) {
            return find_field_struct(buf, rest, parents2);
        }
        FoundArg f{}; f.present = true; f.arg = buf; f.offset = kNoOffset;
        return f;
    }
    // Path target not found — return empty (upstream panics here, but for
    // round-trip resilience we leave the LenType value untouched).
    return {};
}

uint64_t compute_size(const Arg* arg, uint64_t offset, const LenType& len_type) {
    if (len_type.offset()) {
        if (offset == kNoOffset) return 0;
        const uint64_t bs = len_type.bit_size() == 0 ? 8 : len_type.bit_size();
        return offset * 8 / bs;
    }
    if (arg == nullptr) return 0;
    const uint64_t bs = len_type.bit_size() == 0 ? 8 : len_type.bit_size();
    if (auto* vm = as_vma(arg->type())) {
        (void)vm;
        const auto* pa = dynamic_cast<const PointerArg*>(arg);
        return pa ? pa->vma_size() * 8 / bs : 0;
    }
    if (as_array(arg->type())) {
        const auto* g = dynamic_cast<const GroupArg*>(arg);
        if (g == nullptr) return 0;
        if (len_type.bit_size() != 0) {
            return g->size() * 8 / bs;
        }
        return static_cast<uint64_t>(g->inner().size());
    }
    return arg->size() * 8 / bs;
}

void assign_size(ConstArg* dst, Arg* pos, const std::vector<std::string>& path,
                 const std::vector<std::unique_ptr<Arg>>& args,
                 const std::vector<Field>& fields,
                 const std::vector<Arg*>& parents,
                 int overlay_field) {
    FoundArg found = find_arg(pos, path, args, fields, parents, overlay_field);
    if (!found.present || found.is_any_ptr) return;
    const auto* lt = as_len(dst->type());
    if (lt == nullptr) return;
    dst->set_val(compute_size(found.arg, found.offset, *lt));
}

void assign_arg_size(Arg* arg,
                     const std::vector<std::unique_ptr<Arg>>& args,
                     const std::vector<Field>& fields,
                     const std::vector<Arg*>& parents,
                     const std::vector<std::unique_ptr<Arg>>& syscall_args,
                     const std::vector<Field>& syscall_fields,
                     std::unordered_set<const Arg*>* autos,
                     int overlay_field) {
    Arg* inner = inner_arg(arg);
    if (inner == nullptr) return;
    auto* ca = dynamic_cast<ConstArg*>(inner);
    if (ca == nullptr) return;
    const auto* lt = as_len(ca->type());
    if (lt == nullptr) return;
    if (autos != nullptr) {
        if (autos->count(inner) == 0) return;
        autos->erase(inner);
    }
    if (!lt->path().empty() && lt->path()[0] == "syscall") {
        std::vector<std::string> rest(lt->path().begin() + 1, lt->path().end());
        assign_size(ca, nullptr, rest, syscall_args, syscall_fields, parents, 0);
    } else {
        assign_size(ca, ca, lt->path(), args, fields, parents, overlay_field);
    }
}

void assign_sizes_inner(const std::vector<std::unique_ptr<Arg>>& args,
                        const std::vector<Field>& fields,
                        const std::vector<Arg*>& parents,
                        const std::vector<std::unique_ptr<Arg>>& syscall_args,
                        const std::vector<Field>& syscall_fields,
                        std::unordered_set<const Arg*>* autos,
                        int overlay_field) {
    for (const auto& up : args) {
        assign_arg_size(up.get(), args, fields, parents, syscall_args, syscall_fields,
                        autos, overlay_field);
    }
}

} // namespace

void assign_sizes_array(const Target&                                /*target*/,
                        std::vector<std::unique_ptr<Arg>>&           args,
                        const std::vector<Field>&                    fields,
                        std::unordered_set<const Arg*>*              autos) {
    // Top-level: pass syscall-arg list as both the local and syscall context.
    std::vector<Arg*> empty_parents;
    assign_sizes_inner(args, fields, empty_parents, args, fields, autos, 0);

    // Recurse into struct/union groups, maintaining a parent stack so that
    // `parent` / template-name lookups in nested LenType paths resolve.
    for (const auto& up : args) {
        foreach_sub_arg_with_stack(up.get(), [&](Arg* a, ArgCtx* ctx) {
            if (auto* st = as_struct(a->type())) {
                if (auto* g = dynamic_cast<GroupArg*>(a)) {
                    assign_sizes_inner(g->inner(), st->fields(), ctx->parent_stack,
                                       args, fields, autos, st->overlay_field());
                }
            }
            if (auto* u = dynamic_cast<UnionArg*>(a)) {
                if (u->option() != nullptr) {
                    assign_arg_size(u->option(), {}, {}, ctx->parent_stack,
                                    args, fields, autos, 0);
                }
            }
        });
    }
}

void assign_sizes_prog(Prog& prog) {
    const Target* target = prog.target();
    if (target == nullptr) return;
    for (auto& call : prog.mutable_calls()) {
        if (!call || call->meta() == nullptr) continue;
        // autos=nullptr → recompute every LenType from the current arg tree.
        assign_sizes_array(*target, call->mutable_args(),
                           call->meta()->args(), /*autos=*/nullptr);
    }
}

Arg* find_arg_by_path(Arg* start, const std::vector<std::string>& path,
                      const std::vector<Arg*>& parents) {
    // Same resolver the LenType pass uses: empty args/fields → the path is
    // resolved purely against the parent stack (conditions reference
    // siblings/ancestors via "parent" / template-name hops).
    const std::vector<std::unique_ptr<Arg>> no_args;
    const std::vector<Field>                no_fields;
    const FoundArg f = find_arg(start, path, no_args, no_fields, parents, 0);
    return (f.present && !f.is_any_ptr) ? f.arg : nullptr;
}

} // namespace refuzz::program::syz
