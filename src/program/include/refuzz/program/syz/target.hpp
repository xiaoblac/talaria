// reFuzz syzkaller-equivalent IR — Target / TypeArena / SyscallMeta
//
// Target owns all Type instances (via TypeArena), all ResourceDesc
// instances (via ResourceArena), and all SyscallMeta. Lifetime is the
// process lifetime (built once at startup, never freed).

#pragma once

#include "refuzz/program/syz/type.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

class Arg;
class Call;
class PointerArg;
class Target;

// Pseudo-NR synthesis base. Must equal
// tools/syzgen/main.go::pseudoNrBase and
// refuzz::fuzzer::syz::kLinuxAmd64PseudoNrBase. SyscallMeta::is_pseudo
// uses `nr_ >= kPseudoNrBase` to distinguish synthesized pseudo NRs
// from real OS syscall numbers (real linux/amd64 NR caps far below
// 2^20). The cross-source equality is enforced at runtime in
// Target::finalize() against the worker-facing constants.
inline constexpr uint64_t kPseudoNrBase = 0x100000;

// [impl-kind removed] reFuzz no longer classifies pseudos as
// native/stub/unsupported, and there is no PseudoSelectionPolicy. Non-
// fuzzable pseudos (e.g. syz_builtin*) carry syz's (disabled) attr; the
// enable/disable whitelist + control/support (environment) are the only
// call-selection gates. See docs/plans/syscall-support-detection.md.

class SyscallMeta;

// [syscall-enable-whitelist] syzkaller-style glob match, mirror of
// pkg/mgrconfig MatchSyscall: `pattern == name`, OR `name` begins with
// `pattern + "$"` (a base name matches all `$variant` specializations),
// OR `pattern` ends with `*` and `name` carries that prefix.
bool match_syscall(std::string_view name, std::string_view pattern);

// [syscall-enable-whitelist] Result of compute_enabled_calls.
//   * ok == false  → `error` describes an unknown glob / empty result;
//     the caller must fail-closed (mirror of syz's startup error).
//   * else         → mask sized to target.syscalls(), indexed by
//     SyscallMeta::id(); 1 == enabled (empty globs → all minus statically
//     disabled). control/support intersects this with the supported set.
struct EnabledCalls {
    std::vector<std::uint8_t> mask;
    bool                      ok = true;
    std::string               error;
};

// [syscall-enable-whitelist] Resolve enable/disable globs into a per-id
// enabled mask. Mirror of pkg/mgrconfig ParseEnabledSyscalls:
//   1. `enable` empty → all calls; else the union of glob matches.
//   2. drop statically `disabled` calls.
//   3. subtract `disable` glob matches.
//   4. an empty result is an error.
// A glob matching zero calls is an error (unknown enabled/disabled syscall).
EnabledCalls compute_enabled_calls(const Target&                   target,
                                   const std::vector<std::string>& enable,
                                   const std::vector<std::string>& disable);

// [machine-check] Canonical "a syscall was disabled, and why" record — the one
// representation shared across the whole detection path (control/support env +
// trial checks AND the transitive-resource closure below) and consumed
// downstream (C4.6 report, telemetry). `call` is authoritative; name()/id() are
// derivable from it, so nothing is re-created into a parallel struct. The reason
// is the human string (env/trial reason, or the closure's "<resource> [ctor ...]").
struct DisabledCall {
    const SyscallMeta* call = nullptr;
    std::string        reason;
};

// [machine-check C4.4] Reduce an enabled mask to the transitively-enabled set:
// a call stays enabled iff every (non-optional) input resource has an enabled
// creator. Fixed-point over the resource-KIND graph — creating a specialized
// resource (e.g. sock) makes its whole kind chain (fd, sock) creatable, so a
// consumer of a base resource is satisfied by any subtype creator. Pure mirror
// of prog/resources.go Target.TransitivelyEnabledCalls. `enabled_mask` is
// indexed by SyscallMeta::id() (the output of compute_enabled_calls ∩ support);
// the returned mask is the same length with newly-orphaned calls cleared. When
// `disabled_out` is non-null it receives one entry per dropped call.
std::vector<std::uint8_t> transitively_enabled_calls(
    const Target&                    target,
    const std::vector<std::uint8_t>& enabled_mask,
    std::vector<DisabledCall>*       disabled_out = nullptr);

// Mirror of prog.SyscallAttrs.
struct SyscallAttrs {
    bool        disabled         = false;
    uint64_t    timeout          = 0;
    uint64_t    prog_timeout     = 0;
    bool        ignore_return    = false;
    bool        breaks_returns   = false;
    bool        no_generate      = false;
    bool        no_minimize      = false;
    bool        no_squash        = false;
    bool        remote_cover     = false;
    bool        automatic        = false;
    bool        automatic_helper = false;
    bool        snapshot         = false;
    bool        kfuzztest        = false;
    std::string fsck;
    std::string filesystem;
};

// Mirror of prog.ConstValue.
struct ConstValue {
    std::string name;
    uint64_t    value = 0;
};

// Mirror of prog.FlagDesc.
struct FlagDesc {
    std::string              name;
    std::vector<std::string> values;
};

// ============================================================
// SyscallMeta — descriptor for a syscall (or pseudo) entry
// ============================================================

class SyscallMeta {
public:
    SyscallMeta() = default;

    const std::string&       name()         const { return name_; }
    const std::string&       call_name()    const { return call_name_; }
    uint64_t                 nr()           const { return nr_; }
    // Position in Target::syscalls() (mirror of prog.Syscall.ID; this is
    // what the exec wire encodes, NOT the OS syscall number `nr`).
    uint64_t                 id()           const { return id_; }
    int                      missing_args() const { return missing_args_; }
    const std::vector<Field>& args()        const { return args_; }
    const Type*              ret()          const { return ret_; }
    const SyscallAttrs&      attrs()        const { return attrs_; }

    std::vector<Field>&      mutable_args()       { return args_; }

    // True iff this is a synthesized pseudo (syz_*). Determined by the
    // numeric-only invariant `nr >= kPseudoNrBase`; real OS syscall
    // numbers are far below 2^20. See finalize() for the cross-source
    // count check.
    bool                     is_pseudo()       const { return nr_ >= kPseudoNrBase; }

    // Class-B derived resource graph, populated by Target::finalize().
    // Mirrors syzkaller Syscall.{input,uses,creates}Resources.
    const std::vector<const ResourceDesc*>& input_resources()   const { return input_resources_; }
    const std::vector<const ResourceDesc*>& uses_resources()    const { return uses_resources_; }
    const std::vector<const ResourceDesc*>& creates_resources() const { return creates_resources_; }

    void set_name(std::string n)         { name_ = std::move(n); }
    void set_call_name(std::string n)    { call_name_ = std::move(n); }
    void set_nr(uint64_t nr)             { nr_ = nr; }
    void set_missing_args(int n)         { missing_args_ = n; }
    void set_args(std::vector<Field> a)  { args_ = std::move(a); }
    void set_ret(const Type* r)          { ret_ = r; }
    void set_attrs(SyscallAttrs a)       { attrs_ = std::move(a); }

    // Setters reserved for Target::finalize() — not for codegen.
    void set_input_resources(std::vector<const ResourceDesc*> v)   { input_resources_   = std::move(v); }
    void set_uses_resources(std::vector<const ResourceDesc*> v)    { uses_resources_    = std::move(v); }
    void set_creates_resources(std::vector<const ResourceDesc*> v) { creates_resources_ = std::move(v); }

    // Set by Target::finalize() — codegen need not call this.
    void set_id(uint64_t i) { id_ = i; }

private:
    std::string         name_;
    std::string         call_name_;
    uint64_t            id_              = 0;
    uint64_t            nr_              = 0;
    int                 missing_args_    = 0;
    std::vector<Field>  args_;
    const Type*         ret_             = nullptr;
    SyscallAttrs        attrs_;

    std::vector<const ResourceDesc*> input_resources_;
    std::vector<const ResourceDesc*> uses_resources_;
    std::vector<const ResourceDesc*> creates_resources_;
};

// ============================================================
// TypeArena — owns Type instances
// ============================================================
//
// Returned `T*` pointers are stable: each T is heap-allocated by
// std::unique_ptr; the vector only stores those unique_ptrs, so
// reallocating the vector does NOT move the heap objects.

class TypeArena {
public:
    template <typename T, typename... Args>
    T* make(Args&&... a) {
        auto p   = std::make_unique<T>(std::forward<Args>(a)...);
        T*  raw  = p.get();
        types_.push_back(std::move(p));
        return raw;
    }

    std::size_t size() const { return types_.size(); }

    const std::vector<std::unique_ptr<Type>>& types() const { return types_; }

private:
    std::vector<std::unique_ptr<Type>> types_;
};

// ============================================================
// ResourceArena — owns ResourceDesc instances
// ============================================================

class ResourceArena {
public:
    ResourceDesc* make(std::string name,
                       std::vector<std::string> kind,
                       std::vector<uint64_t>    values) {
        auto p   = std::make_unique<ResourceDesc>(std::move(name),
                                                  std::move(kind),
                                                  std::move(values));
        ResourceDesc* raw = p.get();
        descs_.push_back(std::move(p));
        return raw;
    }

    const std::vector<std::unique_ptr<ResourceDesc>>& descs() const { return descs_; }

private:
    std::vector<std::unique_ptr<ResourceDesc>> descs_;
};

// ============================================================
// Target — top-level container
// ============================================================

class Target {
public:
    Target(std::string os, std::string arch);

    const std::string& os()        const { return os_; }
    const std::string& arch()      const { return arch_; }
    const std::string& revision()  const { return revision_; }
    uint64_t           ptr_size()  const { return ptr_size_; }
    uint64_t           page_size() const { return page_size_; }
    uint64_t           num_pages() const { return num_pages_; }
    uint64_t           data_offset() const { return data_offset_; }
    bool               big_endian() const { return big_endian_; }

    TypeArena&         arena()                 { return type_arena_; }
    const TypeArena&   arena()           const { return type_arena_; }
    ResourceArena&     resource_arena()        { return resource_arena_; }
    const ResourceArena& resource_arena() const { return resource_arena_; }

    void set_revision(std::string r)    { revision_ = std::move(r); }
    void set_ptr_size(uint64_t s)       { ptr_size_ = s; }
    void set_page_size(uint64_t s)      { page_size_ = s; }
    void set_num_pages(uint64_t n)      { num_pages_ = n; }
    void set_data_offset(uint64_t o)    { data_offset_ = o; }
    void set_big_endian(bool b)         { big_endian_ = b; }

    // ---- Class-A schema fields (filled by codegen before finalize) ----

    const std::vector<ConstValue>&  consts()               const { return consts_; }
    const std::vector<FlagDesc>&    flag_descs()           const { return flag_descs_; }
    const std::vector<uint64_t>&    special_pointers()     const { return special_pointers_; }
    const std::vector<int64_t>&     special_file_lengths() const { return special_file_lengths_; }
    // Sorted ascending for deterministic iteration / oracle parity.
    const std::vector<std::string>& aux_resources()        const { return aux_resources_; }

    void set_consts(std::vector<ConstValue> v)              { consts_ = std::move(v); }
    void set_flag_descs(std::vector<FlagDesc> v)            { flag_descs_ = std::move(v); }
    void set_special_pointers(std::vector<uint64_t> v)      { special_pointers_ = std::move(v); }
    void set_special_file_lengths(std::vector<int64_t> v)   { special_file_lengths_ = std::move(v); }
    void set_aux_resources(std::vector<std::string> v)      { aux_resources_ = std::move(v); }

    // ---- Class-B schema-service indexes (built by finalize) ----

    // Returns nullptr if not found. Mirror of syzkaller ConstMap.
    const uint64_t* find_const(std::string_view name) const;
    // Returns nullptr if not found. Mirror of syzkaller FlagsMap.
    const std::vector<std::string>* find_flags(std::string_view name) const;
    // Returns nullptr if not found. Mirror of syzkaller resourceMap.
    const ResourceDesc* find_resource(std::string_view name) const;
    // True if `name` is in AuxResources.
    bool is_aux_resource(std::string_view name) const;

    // Mirror of prog/resources.go::Target.isCompatibleResource. Returns
    // true if a resource of kind `src` can be passed where kind `dst`
    // is expected. ANYRES handling matches upstream (any-res `dst`
    // matches everything; any-res `src` only matches any-res `dst`).
    // Lookups go through find_resource(); aborts if a non-anyres name
    // is unknown — same shape as upstream's panic clause. Used by
    // mutator-side createResource (Epic 3) for ctor selection over the
    // resource graph populated by build_resource_graph().
    bool is_compatible_resource(std::string_view dst,
                                std::string_view src) const;

    // Returns a mutable pointer to a freshly allocated SyscallMeta.
    // Caller fills it via setters; lifetime is owned by Target.
    SyscallMeta* add_syscall();

    // Lookups (valid only after finalize()).
    const SyscallMeta* find_syscall(std::string_view name) const;
    const SyscallMeta* find_syscall_nr(uint64_t nr) const;

    const std::vector<std::unique_ptr<SyscallMeta>>& syscalls() const { return syscalls_; }

    // Build name/nr index, ConstMap/FlagsMap, resource graph after all
    // syscalls/types are registered. Codegen calls this once at the end
    // of linux_amd64() construction.
    void finalize();

    // Mirror of prog.Target.PhysicalAddr: returns the special pointer
    // value if arg is a special pointer, else data_offset_ + arg.address().
    uint64_t physical_addr(const PointerArg* arg) const;

    // Synthetic ResourceDesc for `timespec` — not part of resource_arena_,
    // mirrors prog/resources.go timespecRes (linux clock_gettime special).
    // Lifetime: same as Target. Returns nullptr on non-linux targets where
    // it has not been set up.
    const ResourceDesc* timespec_resource() const { return timespec_resource_.get(); }

    // ============================================================
    // §3.11 follow-up P7 — IChoiceTable accessor.
    //
    // Mirrors syzkaller `prog.Target.defaultChoiceTable` slot.
    // ChoiceTable's full implementation lives in `mutator/` (it
    // depends on RNG, ICorpusStore, and weighted-CDF sampling that
    // are mutator concerns). What we expose here is a minimal
    // read-only interface so that consumers in higher layers
    // (§3.12 hints, §3.14 fault injection, ...) can fetch a default
    // weighting without knowing about mutator internals.
    //
    // The mutator (or orchestrator) registers a concrete
    // `IChoiceTable*` via `set_default_choice_table` after the
    // mutator session builds its real ChoiceTable. Returns nullptr
    // until then; callers must handle the absence (fall back to
    // uniform pick or skip the prio-weighted path).
    //
    // Lifetime: caller-owned. Target stores a raw pointer; the
    // mutator session is expected to outlive any consumer using the
    // pointer. If the mutator session restarts, it must
    // re-register.
    //
    // Implementation will land alongside §3.12 hints work; for now
    // this is a pure data slot used to firm up the cross-module
    // contract.
    // ============================================================

    class IChoiceTable;
    // Shared-ownership API. Engine publishes a fresh table via
    // set_default_choice_table; readers obtain a snapshot via
    // default_choice_table() that keeps the table alive for the
    // call duration. Atomic load/store on the underlying storage.
    void  set_default_choice_table(
        std::shared_ptr<const IChoiceTable> ct) const;
    std::shared_ptr<const IChoiceTable> default_choice_table() const;

    // ============================================================
    // §3.11 follow-up P6 — SpecialTypes registry.
    //
    // Mirrors syzkaller `Target.SpecialTypes` map:
    //   `map[string]func(g *Gen, typ Type, dir Dir, old Arg) (Arg, []*Call)`
    //
    // For specific struct/union types (e.g., `timespec`, `timeval`,
    // `sockaddr_alg`, `alg_*_name`, `ipt_replace`, `ip6t_replace`,
    // `arpt_replace`, `ebt_replace`, `usb_device_descriptor` + variants
    // — 14 entries on linux/amd64), the generator is custom rather
    // than the default per-field walk. Without these, mutate/generate
    // produces semantically invalid args (e.g., mismatched alg names).
    //
    // **Cross-module shape**: `IGen` is opaque from program/syz/'s
    // perspective — it carries the mutator-side rng + state +
    // recursive `genArg` re-entry point. Concrete implementation lives
    // in mutator/. The generator function returns a new typed Arg AND
    // optionally a list of "preceding" calls to insert before the
    // owning syscall. Calls are returned via an out parameter
    // (`extra_calls`) keyed by Call shape; program/syz/ only carries
    // the typed-Prog side. The call materialization happens in mutator
    // when applying the Gen result.
    //
    // The 14 generator implementations land alongside §3.12 work; P6
    // ships only the registry scaffolding so the API shape is stable.
    // ============================================================

    // Full virtual surface defined out-of-line (after class Target
    // closes). Concrete impl lives in
    // mutator/src/linux/syz_v2/special_gen.cpp (PR-3-B1).
    class IGen;
    using SpecialTypeFn = std::function<
        std::unique_ptr<Arg>(IGen*                  gen,
                             const Type*            typ,
                             Dir                    dir,
                             const Arg*             old,
                             std::vector<std::unique_ptr<Call>>* extra_calls)
    >;

    // Register a custom generator for a type by name. Idempotent
    // overwrite — last registration wins. Called from
    // `program/syz/linux/special_types.cpp` (or analogous per-target
    // init source) at Target construction time.
    void register_special_type(std::string_view name, SpecialTypeFn fn);

    // Lookup. Returns nullptr if no generator registered for the name.
    const SpecialTypeFn* find_special_type(std::string_view name) const;

    bool has_special_type(std::string_view name) const {
        return find_special_type(name) != nullptr;
    }

    // Statistics for verification.
    std::size_t type_count()     const { return type_arena_.size(); }
    std::size_t syscall_count()  const { return syscalls_.size(); }
    std::size_t resource_count() const { return resource_arena_.descs().size(); }

    // Single-target accessor; constructed on first call.
    static const Target& linux_amd64();

private:
    void build_const_map();
    void build_flag_map();
    void build_aux_resource_set();
    void build_resource_map();
    // §3.11 follow-up P4 — populate Field::related_fields per the
    // syzkaller `Target.initRelatedFields` algorithm. Called from
    // `finalize()`.
    void init_related_fields();
    void build_resource_graph();

    std::string  os_;
    std::string  arch_;
    std::string  revision_;
    uint64_t     ptr_size_    = 8;
    uint64_t     page_size_   = 4096;
    uint64_t     num_pages_   = 0;
    uint64_t     data_offset_ = 0;
    bool         big_endian_  = false;

    TypeArena                                  type_arena_;
    ResourceArena                              resource_arena_;
    std::vector<std::unique_ptr<SyscallMeta>>  syscalls_;

    // Class-A schema fields (filled by codegen).
    std::vector<ConstValue>  consts_;
    std::vector<FlagDesc>    flag_descs_;
    std::vector<uint64_t>    special_pointers_;
    std::vector<int64_t>     special_file_lengths_;
    std::vector<std::string> aux_resources_;

    // Class-B schema-service indexes (built by finalize).
    std::unordered_map<std::string, const SyscallMeta*>      by_name_;
    std::unordered_map<uint64_t, const SyscallMeta*>         by_nr_;
    std::unordered_map<std::string, uint64_t>                const_map_;
    std::unordered_map<std::string, const FlagDesc*>         flag_map_;
    std::unordered_map<std::string, const ResourceDesc*>     resource_map_;
    std::unordered_set<std::string>                          aux_resources_set_;

    // Synthetic resource for linux clock_gettime → timespec (mirror of
    // prog/resources.go global timespecRes). Stored privately so it does
    // not appear in resource_arena_ (and therefore does not pollute the
    // L1 oracle resource enumeration).
    std::unique_ptr<ResourceDesc> timespec_resource_;

    // §3.11 follow-up P6 — SpecialTypes registry storage.
    std::unordered_map<std::string, SpecialTypeFn> special_types_;

    // §3.11 follow-up P4 — related-fields groups owned by Target.
    // Field::related_fields_ pointers index into this storage; we
    // hand out raw pointers and rely on no relocation after finalize.
    // Using std::list to guarantee pointer stability across inserts.
    // Singleton groups (size==1) are erased after population so
    // Field::set_related_fields(nullptr) is the correct no-group state.
    mutable std::list<std::unordered_set<const Type*>> related_fields_groups_;

    // mutable so a const Target reference (mutator session) can
    // publish its ChoiceTable. shared_ptr + atomic_store/load so a
    // rebuild can swap in a fresh table without invalidating
    // in-flight readers that hold a snapshot.
    mutable std::shared_ptr<const IChoiceTable> default_choice_table_;
};

// §3.11 follow-up P7 — minimal cross-module IChoiceTable interface.
// Concrete implementation lives in mutator/.../choice_table.{hpp,cpp}.
// The interface intentionally exposes only read operations that
// non-mutator consumers (hints, fault injection) need. Adding
// mutator-internal methods (`build`, `compute_static_prio`, etc.) would
// drag mutator headers into program/syz/ readers — defeats the
// decoupling purpose of P7.
class Target::IChoiceTable {
public:
    virtual ~IChoiceTable() = default;

    // Pick a syscall id biased by the static + dynamic prio matrix.
    // `prev_id < 0` selects uniformly from enabled calls.
    virtual std::uint64_t choose(std::uint64_t prev_id,
                                 std::uint64_t random_64) const = 0;

    // True iff `id` was registered as enabled (not disabled +
    // not no_generate).
    virtual bool          enabled_call(std::uint64_t id) const = 0;

    // Total number of enabled calls.
    virtual std::size_t   enabled_count()                const = 0;
};

// Mirror of syzkaller `prog.Gen` — the per-call context passed to
// SpecialType bodies. Bodies talk to IGen via vtable so program/syz
// never imports mutator headers; the concrete impl lives in
// mutator/src/linux/syz_v2/special_gen.cpp.
//
// Method correspondence to upstream:
//   generate_arg          -> g.GenerateArg
//   generate_special_arg  -> g.GenerateSpecialArg
//   mutate_arg            -> g.MutateArg
//   alloc                 -> g.Alloc
//   n_out_of/one_of/rand  -> g.NOutOf / g.Rand().Intn-shaped
//   target                -> g.Target
class Target::IGen {
public:
    virtual ~IGen() = default;

    // Recursive entry to the generator for a sub-arg. Appends any
    // resource-chain producer calls to *calls (caller-owned vector).
    virtual std::unique_ptr<Arg> generate_arg(
        const Type* t, Dir d,
        std::vector<std::unique_ptr<Call>>* calls) = 0;

    // Same as generate_arg but bypasses the SpecialType dispatch
    // for the outer type — used by SpecialType bodies that want
    // the per-kind default walk for one level (e.g.,
    // generateUsbDeviceDescriptor's GenerateSpecialArg call before
    // patchUsbDeviceID).
    virtual std::unique_ptr<Arg> generate_special_arg(
        const Type* t, Dir d,
        std::vector<std::unique_ptr<Call>>* calls) = 0;

    // Re-entry into the mutate-arg pipeline. Used by SpecialType
    // bodies that clone-old-then-mutate (the upstream `old != nil`
    // branch in generateIptables / generateEbtables /
    // generateUsb*Descriptor). The Epic 3 generation hook always
    // passes old = nullptr, so this method is unreachable from
    // Epic 3's invocation pattern; it is exposed in the ABI today
    // so §3.13 hints / §3.5 squash can call it without further
    // ABI churn.
    virtual std::vector<std::unique_ptr<Call>> mutate_arg(Arg* arg) = 0;

    // Wraps `inner` in a PointerArg with a freshly allocated
    // address. Appends produced calls to *calls (typically empty).
    // Used by generateTimespec for the clock_gettime tp pointer.
    virtual std::unique_ptr<Arg> alloc(
        const PtrType* t, Dir d,
        std::unique_ptr<Arg> inner,
        std::vector<std::unique_ptr<Call>>* calls) = 0;

    // RNG hooks. Same shape as upstream randGen.{nOutOf, oneOf, Intn}.
    virtual bool n_out_of(std::uint64_t a, std::uint64_t b) = 0;
    virtual bool one_of(int n)                              = 0;
    virtual int  rand(int n)                                = 0;

    virtual const Target& target() const = 0;
};

} // namespace refuzz::program::syz
