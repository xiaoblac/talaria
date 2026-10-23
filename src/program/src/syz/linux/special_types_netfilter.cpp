// Port of upstream sys/linux/init_iptables.go.
//
//   ipt_replace / ip6t_replace -> generateIptables  (hasUnion=true,  hookCount=5)
//   arpt_replace               -> generateArptables (hasUnion=false, hookCount=3)
//   ebt_replace                -> generateEbtables  (custom layout)

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::program::syz::linux_special_types {

namespace {

constexpr int kHookStart      = 4;
constexpr int kNonHookFields  = 7;
constexpr std::uint64_t kUnused = 0xFFFFFFFFULL;

// Cast helper: unwrap (Union)? GroupArg → table inner GroupArg.
GroupArg* as_table_group(Arg* root, bool has_union) {
    if (root == nullptr) return nullptr;
    if (has_union) {
        if (root->arg_kind() != ArgKind::kUnion) return nullptr;
        auto* ua = static_cast<UnionArg*>(root);
        Arg* opt = ua->option();
        if (opt == nullptr || opt->arg_kind() != ArgKind::kGroup) return nullptr;
        return static_cast<GroupArg*>(opt);
    }
    if (root->arg_kind() != ArgKind::kGroup) return nullptr;
    return static_cast<GroupArg*>(root);
}

// Mirror of generateNetfilterTable's offsets[] computation: cumulative
// per-entry sizes inside the entries array.
struct NetfilterOffsets {
    std::vector<std::uint64_t> offsets;
    std::uint64_t              pos;        // total / underflow address
    bool                       valid;
};

NetfilterOffsets collect_offsets(GroupArg* table_arg, int hook_count) {
    NetfilterOffsets out{{}, 0, false};
    const int num_fields = kNonHookFields + 2 * hook_count;
    if (static_cast<int>(table_arg->inner().size()) != num_fields) return out;
    Arg* entries_field = table_arg->mutable_inner()[num_fields - 1].get();
    if (entries_field == nullptr ||
        entries_field->arg_kind() != ArgKind::kGroup) return out;
    auto* entries_arg = static_cast<GroupArg*>(entries_field);
    if (entries_arg->inner().size() != 2) return out;
    Arg* entries_array_field = entries_arg->mutable_inner()[0].get();
    if (entries_array_field == nullptr ||
        entries_array_field->arg_kind() != ArgKind::kGroup) return out;
    auto* entries_array = static_cast<GroupArg*>(entries_array_field);

    std::uint64_t pos = 0;
    out.offsets.reserve(entries_array->inner().size());
    for (const auto& entry : entries_array->inner()) {
        out.offsets.push_back(pos);
        if (entry) pos += entry->size();
    }
    if (pos != entries_array->size()) return out;
    out.pos   = pos;
    out.valid = true;
    return out;
}

// Patches all xt_target_t verdict offsets in the arg subtree.
void patch_xt_target_offsets(Arg* root, std::uint64_t pos,
                             const std::vector<std::uint64_t>& offsets,
                             Target::IGen* g) {
    if (root == nullptr || offsets.empty()) return;
    foreach_sub_arg(root, [&](Arg* a, ArgCtx*) {
        if (a == nullptr || a->type() == nullptr) return;
        const std::string_view name = a->type()->name();
        const std::string_view prefix = "xt_target_t[\"\", ";
        if (name.size() < prefix.size() ||
            std::string_view(name.data(), prefix.size()) != prefix) return;
        if (a->arg_kind() != ArgKind::kGroup) return;
        auto* tg = static_cast<GroupArg*>(a);
        if (tg->inner().size() < 4) return;
        Arg* val_field = tg->mutable_inner()[3].get();
        if (val_field == nullptr ||
            val_field->arg_kind() != ArgKind::kConst) return;
        auto* val_arg = static_cast<ConstArg*>(val_field);
        const auto* ft = as_flags(val_arg->type());
        if (ft == nullptr) return;
        // Negative verdicts already in flags.vals stay (they're real
        // verdict codes, not jump offsets).
        if (static_cast<std::int64_t>(val_arg->val()) < 0) {
            for (std::uint64_t v : ft->vals()) {
                if (v == val_arg->val()) return;
            }
        }
        const std::uint64_t off =
            g->n_out_of(1, 100) ? pos
                                : offsets[g->rand(static_cast<int>(offsets.size()))];
        val_arg->set_val(off);
    });
}

// Apply the hook + underflow + xt_target_t offset patches to a
// netfilter-shaped arg. Returns false on schema mismatch (caller
// returns the unpatched default-walk arg).
bool patch_netfilter(Arg* root, bool has_union, int hook_count,
                     Target::IGen* g) {
    GroupArg* table_arg = as_table_group(root, has_union);
    if (table_arg == nullptr) return false;
    auto info = collect_offsets(table_arg, hook_count);
    if (!info.valid) return false;
    if (info.offsets.empty()) {
        // No entries; nothing meaningful to patch but the body still
        // returns a valid struct.
        return true;
    }

    // Hook offsets (kHookStart .. kHookStart+hookCount).
    for (int h = kHookStart; h < kHookStart + hook_count; ++h) {
        Arg* field = table_arg->mutable_inner()[h].get();
        if (field == nullptr || field->arg_kind() != ArgKind::kConst) continue;
        auto* hook_arg = static_cast<ConstArg*>(field);
        const auto* ct = as_const(hook_arg->type());
        if (ct == nullptr) continue;
        if (ct->val() == kUnused) continue;  // unused hook
        const std::uint64_t off =
            g->n_out_of(1, 100) ? info.pos
                                : info.offsets[g->rand(
                                      static_cast<int>(info.offsets.size()))];
        hook_arg->set_val(off);
    }
    // Underflow offsets (kHookStart+hookCount .. kHookStart+2*hookCount).
    for (int h = kHookStart + hook_count;
         h < kHookStart + 2 * hook_count; ++h) {
        Arg* field = table_arg->mutable_inner()[h].get();
        if (field == nullptr || field->arg_kind() != ArgKind::kConst) continue;
        auto* hook_arg = static_cast<ConstArg*>(field);
        const auto* ct = as_const(hook_arg->type());
        if (ct == nullptr) continue;
        if (ct->val() == kUnused) continue;
        hook_arg->set_val(info.pos);
    }

    patch_xt_target_offsets(root, info.pos, info.offsets, g);
    return true;
}

std::unique_ptr<Arg>
generate_netfilter(Target::IGen* g, const Type* typ, Dir dir,
                   std::vector<std::unique_ptr<Call>>* calls,
                   bool has_union, int hook_count) {
    auto arg = g->generate_special_arg(typ, dir, calls);
    if (arg == nullptr) return nullptr;
    patch_netfilter(arg.get(), has_union, hook_count, g);
    return arg;
}

std::unique_ptr<Arg>
generate_iptables(Target::IGen* g, const Type* typ, Dir dir,
                  const Arg* /*old*/,
                  std::vector<std::unique_ptr<Call>>* calls) {
    return generate_netfilter(g, typ, dir, calls,
                              /*has_union=*/true, /*hook_count=*/5);
}

std::unique_ptr<Arg>
generate_arptables(Target::IGen* g, const Type* typ, Dir dir,
                   const Arg* /*old*/,
                   std::vector<std::unique_ptr<Call>>* calls) {
    return generate_netfilter(g, typ, dir, calls,
                              /*has_union=*/false, /*hook_count=*/3);
}

// Mirror of generateEbtables.
//
// Layout differs from ipt/arpt: the table is a UnionArg holding a
// GroupArg. PtrSize-dependent field positions (PtrSize==8 → 5/9, else
// 4/7). entriesPtr.Res may be null (early return). Per-entry
// totalEntries patching + hook addresses use Target::physical_addr.
std::unique_ptr<Arg>
generate_ebtables(Target::IGen* g, const Type* typ, Dir dir,
                  const Arg* /*old*/,
                  std::vector<std::unique_ptr<Call>>* calls) {
    auto arg = g->generate_special_arg(typ, dir, calls);
    if (arg == nullptr) return nullptr;

    Arg* root = arg.get();
    if (root->arg_kind() != ArgKind::kUnion) return arg;
    auto* ua = static_cast<UnionArg*>(root);
    Arg* opt = ua->option();
    if (opt == nullptr || opt->arg_kind() != ArgKind::kGroup) return arg;
    auto* table_arg = static_cast<GroupArg*>(opt);

    const Target& target = g->target();
    const int hooks_field   = target.ptr_size() == 8 ? 5 : 4;
    const int entries_field = target.ptr_size() == 8 ? 9 : 7;
    if (static_cast<int>(table_arg->inner().size()) <= entries_field) return arg;

    Arg* entries_ptr_field = table_arg->mutable_inner()[entries_field].get();
    if (entries_ptr_field == nullptr ||
        entries_ptr_field->arg_kind() != ArgKind::kPointer) return arg;
    auto* entries_ptr = static_cast<PointerArg*>(entries_ptr_field);
    Arg* entries_root = entries_ptr->res();
    if (entries_root == nullptr ||
        entries_root->arg_kind() != ArgKind::kGroup) return arg;
    auto* entries_array = static_cast<GroupArg*>(entries_root);

    // Per-entry totalEntries patch + cumulative offsets.
    std::vector<std::uint64_t> offsets;
    offsets.reserve(entries_array->inner().size());
    std::uint64_t pos = 0;
    std::uint64_t total_entries = 0;
    for (auto& entry_root : entries_array->mutable_inner()) {
        if (!entry_root || entry_root->arg_kind() != ArgKind::kGroup) {
            offsets.push_back(pos);
            continue;
        }
        auto* entries_group = static_cast<GroupArg*>(entry_root.get());
        if (entries_group->inner().empty()) {
            offsets.push_back(pos);
            continue;
        }
        Arg* last_arg =
            entries_group->mutable_inner().back().get();
        std::uint64_t inner_count = 0;
        if (last_arg && last_arg->arg_kind() == ArgKind::kGroup) {
            inner_count = static_cast<GroupArg*>(last_arg)->inner().size();
        }
        if (entries_group->inner().size() > 2) {
            Arg* count_field = entries_group->mutable_inner()[2].get();
            if (count_field && count_field->arg_kind() == ArgKind::kConst) {
                static_cast<ConstArg*>(count_field)->set_val(total_entries);
            }
        }
        total_entries += inner_count;
        offsets.push_back(pos);
        pos += entry_root->size();
    }
    if (table_arg->inner().size() > 2) {
        Arg* total_field = table_arg->mutable_inner()[2].get();
        if (total_field && total_field->arg_kind() == ArgKind::kConst) {
            static_cast<ConstArg*>(total_field)->set_val(total_entries);
        }
    }

    if (static_cast<int>(table_arg->inner().size()) <= hooks_field) return arg;
    if (table_arg->inner().size() < 2) return arg;
    Arg* valid_hooks_field = table_arg->mutable_inner()[1].get();
    Arg* hooks_root = table_arg->mutable_inner()[hooks_field].get();
    if (valid_hooks_field == nullptr ||
        valid_hooks_field->arg_kind() != ArgKind::kConst) return arg;
    if (hooks_root == nullptr ||
        hooks_root->arg_kind() != ArgKind::kGroup) return arg;
    auto* hooks_group = static_cast<GroupArg*>(hooks_root);
    const std::uint64_t valid_hooks =
        static_cast<ConstArg*>(valid_hooks_field)->val();

    std::vector<std::uint64_t> remaining_offsets = offsets;
    for (std::size_t i = 0; i < hooks_group->inner().size(); ++i) {
        Arg* h = hooks_group->mutable_inner()[i].get();
        if (h == nullptr || h->arg_kind() != ArgKind::kConst) continue;
        auto* hook_arg = static_cast<ConstArg*>(h);
        if ((valid_hooks & (std::uint64_t{1} << i)) == 0) {
            hook_arg->set_val(0);
            continue;
        }
        std::uint64_t addr = target.physical_addr(entries_ptr);
        if (!remaining_offsets.empty()) {
            addr += remaining_offsets.front();
            remaining_offsets.erase(remaining_offsets.begin());
        }
        hook_arg->set_val(addr);
    }
    return arg;
}

} // namespace

Target::SpecialTypeFn make_iptables_fn() { return generate_iptables; }
Target::SpecialTypeFn make_arptables_fn() { return generate_arptables; }
Target::SpecialTypeFn make_ebtables_fn() { return generate_ebtables; }

} // namespace refuzz::program::syz::linux_special_types
