// Implementation for refuzz/program/syz/target.hpp

#include "refuzz/program/syz/target.hpp"

#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
// Worker-facing constants (kLinuxAmd64PseudoNrBase /
// kLinuxAmd64PseudoMetaSize) live here. Included only from .cpp to keep
// refuzz::fuzzer::syz out of the target.hpp transitive include graph —
// see target.hpp comment on PseudoImplKind for why.
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <unordered_set>

namespace refuzz::program::syz {

// kLinuxAmd64PseudoNrBase is `extern const uint64_t` (definition lives
// in the syzgen-generated TU), so a static_assert against it would not
// see the value at compile time. The cross-source invariant is enforced
// at runtime in Target::finalize() — both the NR base and the pseudo
// count must match.


Target::Target(std::string os, std::string arch)
    : os_(std::move(os)), arch_(std::move(arch)) {}

bool match_syscall(std::string_view name, std::string_view pattern) {
    if (pattern == name) {
        return true;
    }
    // `name` begins with `pattern + "$"` — a base call name matches all
    // of its `$variant` specializations.
    if (name.size() > pattern.size() &&
        name.compare(0, pattern.size(), pattern) == 0 &&
        name[pattern.size()] == '$') {
        return true;
    }
    // Trailing-`*` prefix glob.
    if (pattern.size() > 1 && pattern.back() == '*') {
        const std::string_view prefix = pattern.substr(0, pattern.size() - 1);
        if (name.size() >= prefix.size() &&
            name.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

// Mirror of syzkaller pkg/mgrconfig checkMode in the DEFAULT manualDescriptions
// mode (reFuzz uses manual descriptions): a syscall is enable-able only if it is
// NOT `automatic` (auto-generated descriptions — syz enables these only in the
// experimental auto mode) and NOT `snapshot` (enabled only in snapshot mode).
// `exact_match` mirrors syz's `checkMode(call, mode, call.Name != c)`: an EXACT
// enable-by-name skips the snapshot check (you can opt a snapshot syscall in
// explicitly), but `automatic` is always excluded. `automatic_helper` is kept
// (its checkMode clause only fires in non-manual modes).
static bool passes_check_mode(const SyscallMeta& sc, bool exact_match) {
    if (sc.attrs().automatic) return false;
    if (sc.attrs().snapshot && !exact_match) return false;
    return true;
}

EnabledCalls compute_enabled_calls(const Target&                   target,
                                   const std::vector<std::string>& enable,
                                   const std::vector<std::string>& disable) {
    EnabledCalls r;
    // Pure whitelist-glob resolution over the schema (empty globs → all minus
    // statically-disabled). The environment / support intersection lives in
    // control/support; the ChoiceTable's own impl-kind / disabled gate also
    // runs on top of this mask.
    const auto&  calls = target.syscalls();
    const size_t n     = calls.size();
    r.mask.assign(n, 0);

    if (enable.empty()) {
        for (const auto& sc : calls) {
            if (!sc) continue;
            if (!passes_check_mode(*sc, /*exact_match=*/false)) continue;
            const std::uint64_t id = sc->id();
            if (id < n) r.mask[id] = 1;
        }
    } else {
        for (const auto& pat : enable) {
            int matched = 0;
            for (const auto& sc : calls) {
                if (!sc || !match_syscall(sc->name(), pat)) continue;
                if (!passes_check_mode(*sc, /*exact_match=*/sc->name() == pat)) continue;
                const std::uint64_t id = sc->id();
                if (id < n) r.mask[id] = 1;
                ++matched;
            }
            if (matched == 0) {
                r.ok = false;
                r.error = "unknown enabled syscall: " + pat;
                r.mask.clear();
                return r;
            }
        }
    }
    // Statically-disabled calls never run regardless of the whitelist.
    for (const auto& sc : calls) {
        if (!sc || !sc->attrs().disabled) continue;
        const std::uint64_t id = sc->id();
        if (id < n) r.mask[id] = 0;
    }
    for (const auto& pat : disable) {
        int matched = 0;
        for (const auto& sc : calls) {
            if (!sc || !match_syscall(sc->name(), pat)) continue;
            const std::uint64_t id = sc->id();
            if (id < n) r.mask[id] = 0;
            ++matched;
        }
        if (matched == 0) {
            r.ok = false;
            r.error = "unknown disabled syscall: " + pat;
            r.mask.clear();
            return r;
        }
    }
    for (std::uint8_t v : r.mask) {
        if (v) return r;
    }
    r.ok = false;
    r.error = "all syscalls disabled by disable_syscalls";
    r.mask.clear();
    return r;
}

SyscallMeta* Target::add_syscall() {
    syscalls_.push_back(std::make_unique<SyscallMeta>());
    return syscalls_.back().get();
}

const SyscallMeta* Target::find_syscall(std::string_view name) const {
    auto it = by_name_.find(std::string(name));
    return it == by_name_.end() ? nullptr : it->second;
}

const SyscallMeta* Target::find_syscall_nr(uint64_t nr) const {
    auto it = by_nr_.find(nr);
    return it == by_nr_.end() ? nullptr : it->second;
}

const uint64_t* Target::find_const(std::string_view name) const {
    auto it = const_map_.find(std::string(name));
    return it == const_map_.end() ? nullptr : &it->second;
}

const std::vector<std::string>* Target::find_flags(std::string_view name) const {
    auto it = flag_map_.find(std::string(name));
    return it == flag_map_.end() ? nullptr : &it->second->values;
}

const ResourceDesc* Target::find_resource(std::string_view name) const {
    auto it = resource_map_.find(std::string(name));
    return it == resource_map_.end() ? nullptr : it->second;
}

bool Target::is_aux_resource(std::string_view name) const {
    return aux_resources_set_.find(std::string(name)) != aux_resources_set_.end();
}

uint64_t Target::physical_addr(const PointerArg* arg) const {
    if (arg == nullptr) return 0;
    if (arg->is_special()) {
        const uint64_t neg = static_cast<uint64_t>(-static_cast<int64_t>(arg->address()));
        if (neg < special_pointers_.size()) {
            return special_pointers_[neg];
        }
        return 0;
    }
    return data_offset_ + arg->address();
}

// §3.11 follow-up P7 — IChoiceTable accessor (see header rationale).
void Target::set_default_choice_table(
    std::shared_ptr<const IChoiceTable> ct) const {
    std::atomic_store(&default_choice_table_, std::move(ct));
}
std::shared_ptr<const Target::IChoiceTable>
Target::default_choice_table() const {
    return std::atomic_load(&default_choice_table_);
}

// §3.11 follow-up P6 — SpecialTypes registry (see header rationale).
void Target::register_special_type(std::string_view name, SpecialTypeFn fn) {
    special_types_[std::string(name)] = std::move(fn);
}
const Target::SpecialTypeFn* Target::find_special_type(std::string_view name) const {
    const auto it = special_types_.find(std::string(name));
    if (it == special_types_.end()) return nullptr;
    return &it->second;
}

void Target::build_const_map() {
    const_map_.clear();
    const_map_.reserve(consts_.size());
    for (const auto& c : consts_) {
        const_map_[c.name] = c.value;
    }
}

void Target::build_flag_map() {
    flag_map_.clear();
    flag_map_.reserve(flag_descs_.size());
    for (const auto& f : flag_descs_) {
        flag_map_[f.name] = &f;
    }
}

void Target::build_aux_resource_set() {
    aux_resources_set_.clear();
    aux_resources_set_.reserve(aux_resources_.size());
    for (const auto& n : aux_resources_) {
        aux_resources_set_.insert(n);
    }
}

void Target::build_resource_map() {
    resource_map_.clear();
    resource_map_.reserve(resource_arena_.descs().size());
    for (const auto& r : resource_arena_.descs()) {
        resource_map_[r->name()] = r.get();
    }
}

// ---------------------------------------------------------------
// Resource graph (mirror of prog/resources.go populateResourceCtors
// + calcResourceCtors + getInputResources). Pure schema function;
// runs once at finalize time.
// ---------------------------------------------------------------

namespace {

// Mirror of prog.seenKey { Type*, Dir, Optional }.
struct SeenKey {
    const Type* t;
    Dir         d;
    bool        o;
    bool operator==(const SeenKey& other) const {
        return t == other.t && d == other.d && o == other.o;
    }
};

struct SeenKeyHash {
    std::size_t operator()(const SeenKey& k) const noexcept {
        std::uintptr_t p = reinterpret_cast<std::uintptr_t>(k.t);
        return p ^ (static_cast<std::size_t>(k.d) << 1) ^ (k.o ? 7u : 0u);
    }
};

using TypeSeen = std::unordered_set<SeenKey, SeenKeyHash>;

struct TypeCtx {
    Dir  dir;
    bool optional;
    bool stop;
};

// Mirror of prog.foreachTypeRec (preorder).
void foreach_type_rec(const Type* ptr, Dir dir, bool optional,
                      TypeSeen& seen,
                      const std::function<void(const Type*, TypeCtx*)>& cb) {
    if (ptr == nullptr) return;
    optional = optional || ptr->optional();
    TypeCtx ctx{dir, optional, false};
    cb(ptr, &ctx);
    if (ctx.stop) return;

    switch (ptr->kind()) {
        case TypeKind::kPtr: {
            auto* pt = static_cast<const PtrType*>(ptr);
            foreach_type_rec(pt->elem(), pt->elem_dir(), optional, seen, cb);
            break;
        }
        case TypeKind::kArray: {
            auto* at = static_cast<const ArrayType*>(ptr);
            foreach_type_rec(at->elem(), dir, optional, seen, cb);
            break;
        }
        case TypeKind::kStruct: {
            auto* st = static_cast<const StructType*>(ptr);
            SeenKey key{st, dir, optional};
            if (seen.find(key) != seen.end()) break;
            seen.insert(key);
            for (const auto& f : st->fields()) {
                foreach_type_rec(f.type(), f.dir(dir), optional, seen, cb);
            }
            break;
        }
        case TypeKind::kUnion: {
            auto* ut = static_cast<const UnionType*>(ptr);
            SeenKey key{ut, dir, optional};
            if (seen.find(key) != seen.end()) break;
            seen.insert(key);
            for (const auto& f : ut->fields()) {
                foreach_type_rec(f.type(), f.dir(dir), optional, seen, cb);
            }
            break;
        }
        default:
            break;
    }
}

// Mirror of prog.ForeachCallType.
void foreach_call_type(const SyscallMeta* sc,
                       const std::function<void(const Type*, TypeCtx*)>& cb) {
    TypeSeen seen;
    for (const auto& f : sc->args()) {
        foreach_type_rec(f.type(), f.dir(Dir::kIn), false, seen, cb);
    }
    if (sc->ret() != nullptr) {
        foreach_type_rec(sc->ret(), Dir::kOut, false, seen, cb);
    }
}

// Mirror of prog.isCompatibleResourceImpl. Sole compat helper shared
// by build_resource_graph (Pass 4) and the public
// Target::is_compatible_resource API (PR-3-A1, D5 cleanup).
bool compat_kind_check(const std::vector<std::string>& dst,
                       const std::vector<std::string>& src,
                       bool precise) {
    std::size_t n_dst = dst.size();
    std::size_t n_src = src.size();
    if (n_dst > n_src) {
        if (precise) return false;
        n_dst = n_src;
    }
    if (n_src > n_dst) {
        n_src = n_dst;
    }
    for (std::size_t i = 0; i < n_dst; ++i) {
        if (dst[i] != src[i]) return false;
    }
    return true;
}

} // namespace

bool Target::is_compatible_resource(std::string_view dst,
                                    std::string_view src) const {
    // Mirror of prog/resources.go::Target.isCompatibleResource.
    // ANYRES short-circuit first (any-res dst matches everything;
    // any-res src only matches any-res dst).
    if (::refuzz::program::syz::is_any_res(dst)) return true;
    if (::refuzz::program::syz::is_any_res(src)) return false;
    const ResourceDesc* d = find_resource(dst);
    const ResourceDesc* s = find_resource(src);
    if (d == nullptr || s == nullptr) {
        std::fprintf(stderr,
                     "Target::is_compatible_resource: unknown resource"
                     " '%.*s' / '%.*s'\n",
                     static_cast<int>(dst.size()), dst.data(),
                     static_cast<int>(src.size()), src.data());
        std::abort();
    }
    return compat_kind_check(d->kind(), s->kind(), false);
}

void Target::build_resource_graph() {
    // ResourceDesc::ctors is empty at construction; we trust codegen runs
    // finalize once. SyscallMeta.{input,uses,creates}_resources likewise
    // start empty.

    // Linux-only synthetic timespec resource (mirror of prog/resources.go
    // timespecRes). Created lazily so non-linux targets don't carry it.
    if (os_ == "linux" && timespec_resource_ == nullptr) {
        timespec_resource_ = std::make_unique<ResourceDesc>(
            std::string("timespec"),
            std::vector<std::string>{"timespec"},
            std::vector<uint64_t>{});
    }
    const ResourceDesc* timespec_res = timespec_resource_.get();

    // Pass 1: walk every syscall, record uses_resources / creates_resources
    // and the per-call list of created resources. Mirror of
    // populateResourceCtors's main loop.
    std::vector<std::vector<const ResourceDesc*>> calls_resources(syscalls_.size());
    for (std::size_t ci = 0; ci < syscalls_.size(); ++ci) {
        SyscallMeta* meta = syscalls_[ci].get();
        std::unordered_set<const ResourceDesc*> dedup;
        std::vector<const ResourceDesc*> uses_list;
        std::vector<const ResourceDesc*> creates_list;

        foreach_call_type(meta, [&](const Type* t, TypeCtx* ctx) {
            if (ctx->optional) {
                ctx->stop = true;
                return;
            }
            if (t->kind() == TypeKind::kUnion) {
                ctx->stop = true;
                return;
            }
            if (t->kind() != TypeKind::kResource) return;
            auto* rt = static_cast<const ResourceType*>(t);
            const ResourceDesc* desc = rt->desc();
            if (desc == nullptr) return;
            if (ctx->dir == Dir::kIn) return;
            if (dedup.find(desc) != dedup.end()) return;
            if (meta->attrs().disabled) return;
            dedup.insert(desc);
            uses_list.push_back(desc);
            if (!meta->attrs().no_generate) {
                calls_resources[ci].push_back(desc);
                creates_list.push_back(desc);
            }
        });

        meta->set_uses_resources(std::move(uses_list));
        meta->set_creates_resources(std::move(creates_list));
    }

    // Pass 2: linux clock_gettime → timespec special.
    if (timespec_res != nullptr) {
        for (std::size_t idx = 0; idx < syscalls_.size(); ++idx) {
            if (syscalls_[idx]->name() != "clock_gettime") continue;
            SyscallMeta* sc = syscalls_[idx].get();
            auto uses    = sc->uses_resources();
            auto creates = sc->creates_resources();
            uses.push_back(timespec_res);
            creates.push_back(timespec_res);
            sc->set_uses_resources(std::move(uses));
            sc->set_creates_resources(std::move(creates));
            calls_resources[idx].push_back(timespec_res);
            break;
        }
    }

    // Pass 3: for each syscall, compute input_resources (via getInputResources)
    // and append to uses_resources. Mirror of:
    //     c.inputResources = target.getInputResources(c)
    //     c.usesResources  = append(c.usesResources, c.inputResources...)
    for (auto& sc : syscalls_) {
        std::unordered_set<const ResourceDesc*> dedup;
        std::vector<const ResourceDesc*> input_list;

        foreach_call_type(sc.get(), [&](const Type* t, TypeCtx* ctx) {
            if (ctx->dir == Dir::kOut) return;
            if (t->kind() == TypeKind::kResource) {
                auto* rt = static_cast<const ResourceType*>(t);
                const ResourceDesc* desc = rt->desc();
                if (desc == nullptr) return;
                if (ctx->optional) return;
                if (dedup.find(desc) != dedup.end()) return;
                dedup.insert(desc);
                input_list.push_back(desc);
                return;
            }
            if (t->kind() == TypeKind::kStruct && os_ == "linux" && timespec_res != nullptr) {
                if (dedup.find(timespec_res) != dedup.end()) return;
                if (t->name() == "timespec" || t->name() == "timeval") {
                    dedup.insert(timespec_res);
                    input_list.push_back(timespec_res);
                }
            }
        });

        sc->set_input_resources(input_list);
        auto uses = sc->uses_resources();
        uses.insert(uses.end(), input_list.begin(), input_list.end());
        sc->set_uses_resources(std::move(uses));
    }

    // Pass 4: populate resource ctors with precision matching.
    for (const auto& r_up : resource_arena_.descs()) {
        ResourceDesc* res = r_up.get();
        const auto& res_kind = res->kind();
        for (std::size_t call = 0; call < syscalls_.size(); ++call) {
            const auto& call_resources = calls_resources[call];
            if (call_resources.empty()) continue;
            bool precise_ok   = false;
            bool imprecise_ok = false;
            for (const ResourceDesc* call_res : call_resources) {
                if (precise_ok && imprecise_ok) break;
                if (compat_kind_check(res_kind, call_res->kind(), true)) {
                    precise_ok = true;
                }
                if (compat_kind_check(res_kind, call_res->kind(), false)) {
                    imprecise_ok = true;
                }
            }
            if (precise_ok) {
                res->add_ctor(ResourceCtor{syscalls_[call].get(), true});
            }
            if (imprecise_ok) {
                res->add_ctor(ResourceCtor{syscalls_[call].get(), false});
            }
        }
    }
}

// [machine-check C4.4] Pure mirror of prog/resources.go
// Target.transitivelyEnabled + TransitivelyEnabledCalls. Fixed-point over the
// resource-KIND graph: a call is supported iff every (non-optional) input
// resource is creatable by an already-supported call; creating a resource marks
// its whole kind chain creatable (so a consumer of a base resource is satisfied
// by any subtype creator). See target.hpp.
std::vector<std::uint8_t> transitively_enabled_calls(
    const Target&                    target,
    const std::vector<std::uint8_t>& enabled_mask,
    std::vector<DisabledCall>*       disabled_out) {
    const auto& calls = target.syscalls();

    auto is_enabled = [&](std::uint64_t id) {
        return id < enabled_mask.size() && enabled_mask[id] != 0;
    };

    // supported grows monotonically; can_create holds every resource KIND
    // produced by an already-supported call.
    std::vector<std::uint8_t>       supported(enabled_mask.size(), 0);
    std::unordered_set<std::string> can_create;
    for (;;) {
        bool changed = false;
        for (const auto& sc : calls) {
            if (!sc) continue;
            const std::uint64_t id = sc->id();
            if (!is_enabled(id) || supported[id]) continue;
            bool inputs_ok = true;
            for (const ResourceDesc* res : sc->input_resources()) {
                if (res != nullptr &&
                    can_create.find(res->name()) == can_create.end()) {
                    inputs_ok = false;
                    break;
                }
            }
            if (!inputs_ok) continue;
            supported[id] = 1;
            for (const ResourceDesc* res : sc->creates_resources()) {
                if (res == nullptr) continue;
                for (const std::string& kind : res->kind()) {
                    can_create.insert(kind);
                }
            }
            changed = true;
        }
        if (!changed) break;
    }

    if (disabled_out != nullptr) {
        for (const auto& sc : calls) {
            if (!sc) continue;
            const std::uint64_t id = sc->id();
            if (!is_enabled(id) || supported[id]) continue;
            // Reason = the first non-creatable input resource + its precise
            // ctor call names (capped: >5 → first 3 + "..."), syz format.
            for (const ResourceDesc* res : sc->input_resources()) {
                if (res == nullptr ||
                    can_create.find(res->name()) != can_create.end()) {
                    continue;
                }
                std::vector<std::string> names;
                for (const ResourceCtor& ctor : res->ctors()) {
                    if (ctor.precise && ctor.call != nullptr) {
                        names.push_back(ctor.call->name());
                    }
                }
                if (names.size() > 5) {
                    names.resize(3);
                    names.push_back("...");
                }
                std::string reason = res->name();
                reason += " [";
                for (std::size_t i = 0; i < names.size(); ++i) {
                    if (i != 0) reason += ' ';
                    reason += names[i];
                }
                reason += "]";
                disabled_out->push_back(
                    DisabledCall{sc.get(), std::move(reason)});
                break;
            }
        }
    }

    return supported;
}

void Target::finalize() {
    by_name_.clear();
    by_nr_.clear();
    by_name_.reserve(syscalls_.size());
    by_nr_.reserve(syscalls_.size());
    std::size_t pseudo_count = 0;
    for (std::size_t i = 0; i < syscalls_.size(); ++i) {
        auto& sc = syscalls_[i];
        sc->set_id(static_cast<uint64_t>(i));
        by_name_.emplace(sc->name(), sc.get());
        by_nr_.emplace(sc->nr(), sc.get());
        if (sc->is_pseudo()) {
            ++pseudo_count;
        }
    }

    // Cross-source invariant: syzgen emits the SAME pseudo set into
    // both the worker-facing kLinuxAmd64PseudoMeta[] and the typed
    // Target syscalls (this loop). Three checks:
    //   1. NR base must match (kPseudoNrBase vs kLinuxAmd64PseudoNrBase).
    //   2. Pseudo count must match.
    //   3. Per-name correspondence: every typed-Target pseudo must
    //      exist in the worker-side table by name AND agree on
    //      `nr` / `impl` / `capability_mask`. Without this an
    //      order-only drift (same set of names, same count, but
    //      reshuffled NR↔name binding) would silently route
    //      `syz_X` to `syz_Y`'s pseudo handler at runtime.
    // If any disagrees, one of the two emit paths drifted. linux/amd64
    // only — other targets bring their own constants when they land.
    if (os_ == "linux" && arch_ == "amd64") {
        namespace ws = ::refuzz::fuzzer::syz;
        if (kPseudoNrBase != ws::kLinuxAmd64PseudoNrBase) {
            std::fprintf(stderr,
                         "Target::finalize: kPseudoNrBase (0x%llx) != "
                         "kLinuxAmd64PseudoNrBase (0x%llx); syzgen drift\n",
                         static_cast<unsigned long long>(kPseudoNrBase),
                         static_cast<unsigned long long>(
                             ws::kLinuxAmd64PseudoNrBase));
            std::abort();
        }
        if (pseudo_count != ws::kLinuxAmd64PseudoMetaSize) {
            std::fprintf(stderr,
                         "Target::finalize: typed-Target pseudo count (%zu) != "
                         "worker-facing kLinuxAmd64PseudoMetaSize (%zu); "
                         "syzgen emit-path drift\n",
                         pseudo_count,
                         static_cast<std::size_t>(
                             ws::kLinuxAmd64PseudoMetaSize));
            std::abort();
        }
        for (const auto& sc : syscalls_) {
            if (!sc || !sc->is_pseudo()) continue;
            const ws::PseudoMeta* worker_meta =
                ws::FindPseudoByName(ws::kDefaultSyzTarget.pseudos,
                                     sc->name().c_str());
            if (worker_meta == nullptr) {
                std::fprintf(stderr,
                             "Target::finalize: typed-Target pseudo %s "
                             "missing from worker-facing kDefaultSyzTarget.pseudos\n",
                             sc->name().c_str());
                std::abort();
            }
            if (worker_meta->nr != sc->nr()) {
                std::fprintf(stderr,
                             "Target::finalize: pseudo %s NR mismatch: "
                             "typed=0x%llx worker=0x%llx\n",
                             sc->name().c_str(),
                             static_cast<unsigned long long>(sc->nr()),
                             static_cast<unsigned long long>(worker_meta->nr));
                std::abort();
            }
        }
    }

    build_const_map();
    build_flag_map();
    build_aux_resource_set();
    build_resource_map();
    build_resource_graph();
    init_related_fields();

    // §3.11 follow-up P11 — backend-specific finalize hooks.
    // Today: linux/amd64 SpecialType registry. Future targets get
    // their own subdir + finalize hook.
    extern void linux_amd64_register_special_types(Target& target);
    if (os_ == "linux" && arch_ == "amd64") {
        linux_amd64_register_special_types(*this);
    }
}

// §3.11 follow-up P4 — port of prog/target.go::initRelatedFields.
// Algorithm:
//   1. For each syscall, build an `id` string starting with the
//      base call name. Sweep args once: when an arg is a
//      ResourceType, append "<i>:<resource-name>" to id; when an
//      arg is a Ptr→Buffer{kString} carrying a single value,
//      append "<i>:<string-value>" to id (filename/string is
//      treated as a resource for this purpose).
//   2. Sweep args a second time: for ConstType / FlagsType /
//      IntType args, build argID = "<id>/<i>" and look up the
//      group in the global map. Add this Field's Type* to the
//      group, then point Field::related_fields_ at the group.
//      For ConstType: ALSO append "-<i>:<const-val>" to id so
//      subsequent ConstType-discriminated args partition further
//      (e.g., socket family/type/protocol triples).
//   3. After all syscalls processed, drop singleton groups (set
//      Field::related_fields_ = nullptr); they provide no
//      replacement guidance.
//
// Storage: Target owns `related_fields_groups_` (std::list — pointer
// stability across inserts). Each group is constructed as needed
// during sweep #2; Field::related_fields_ stores a raw const pointer
// into the list. Lifetime is tied to Target (no Type-arena rebuild
// after finalize).
void Target::init_related_fields() {
    related_fields_groups_.clear();
    std::unordered_map<std::string, std::unordered_set<const Type*>*> by_arg_id;

    for (auto& sc_ptr : syscalls_) {
        SyscallMeta* sc = sc_ptr.get();
        std::string id = sc->call_name();

        // Sweep #1 — collect resource / string discriminators that
        // partition before any const-driven discrimination.
        const auto& fields = sc->args();
        for (size_t i = 0; i < fields.size(); ++i) {
            const Type* t = fields[i].type();
            if (t == nullptr) continue;
            if (auto* rt = as_resource(t)) {
                id += "-" + std::to_string(i) + ":" + rt->name();
            } else if (auto* pt = as_ptr(t)) {
                if (auto* bt = as_buffer(pt->elem());
                    bt != nullptr && bt->buffer_kind() == BufferKind::kString &&
                    bt->values().size() == 1) {
                    id += "-" + std::to_string(i) + ":" + bt->values()[0];
                }
            }
        }

        // Sweep #2 — assign const/flags/int args to groups and update
        // id with const values for further partitioning.
        auto& mut_fields = sc->mutable_args();
        for (size_t i = 0; i < mut_fields.size(); ++i) {
            const Type* t = mut_fields[i].type();
            if (t == nullptr) continue;
            const auto k = t->kind();
            if (k != TypeKind::kConst && k != TypeKind::kFlags && k != TypeKind::kInt) {
                continue;
            }
            const std::string arg_id = id + "/" + std::to_string(i);
            std::unordered_set<const Type*>* group = nullptr;
            if (auto it = by_arg_id.find(arg_id); it != by_arg_id.end()) {
                group = it->second;
            } else {
                related_fields_groups_.emplace_back();
                group = &related_fields_groups_.back();
                by_arg_id.emplace(arg_id, group);
            }
            mut_fields[i].set_related_fields(group);
            group->insert(t);
            if (auto* ct = as_const(t)) {
                id += "-" + std::to_string(i) + ":" + std::to_string(ct->val());
            }
        }
    }

    // Drop singleton groups — they offer no replacement guidance.
    for (auto& sc_ptr : syscalls_) {
        SyscallMeta* sc = sc_ptr.get();
        auto& mut_fields = sc->mutable_args();
        for (auto& f : mut_fields) {
            if (const auto* g = f.related_fields(); g != nullptr && g->size() == 1) {
                f.set_related_fields(nullptr);
            }
        }
    }
}

} // namespace refuzz::program::syz
