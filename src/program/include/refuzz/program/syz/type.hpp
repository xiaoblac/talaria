// reFuzz syzkaller-equivalent IR — Type tree
//
// This is the new program model that mirrors syzkaller pkg/prog Type
// hierarchy 1:1 in structure (not byte layout). It supersedes the flat
// TypeDesc table in refuzz/program/syz/pseudo/target_view.hpp.
//
// Ownership: all Type instances live in TypeArena (target.hpp). Cross-type
// references use raw `const Type*` pointers; arena guarantees lifetime is
// the same as the owning Target.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace refuzz::program::syz {

// Forward declarations.
class Type;
class Arg;
class Field;
class Expression;
class ResourceDesc;
class MinimizeCtx;

// ---- Direction of a syscall arg / struct field ----

enum class Dir : uint8_t {
    kIn    = 0,
    kOut   = 1,
    kInOut = 2,
};

// ---- Discriminator for Type subclasses ----

enum class TypeKind : uint8_t {
    kInt      = 0,
    kConst    = 1,
    kFlags    = 2,
    kProc     = 3,
    kLen      = 4,
    kCsum     = 5,
    kResource = 6,
    kBuffer   = 7,
    kPtr      = 8,
    kArray    = 9,
    kStruct   = 10,
    kUnion    = 11,
    kVma      = 12,
};

// Mirror of prog.BinaryFormat.
enum class BinaryFormat : uint8_t {
    kNative    = 0,
    kBigEndian = 1,
    kStrDec    = 2,
    kStrHex    = 3,
    kStrOct    = 4,
};

// ============================================================
// Type base
// ============================================================

class Type {
public:
    virtual ~Type() = default;
    virtual TypeKind kind() const = 0;

    const std::string& name()      const { return name_; }
    uint64_t           size()      const { return size_; }
    uint64_t           align()     const { return align_; }
    bool               optional()  const { return optional_; }
    bool               var_len()   const { return var_len_; }

    // Mirror of prog.TypeCommon.TemplateName: name with everything from
    // first '[' onward stripped (used by csum lookup).
    std::string template_name() const;

    // Bitfield helpers — overridden by IntTypeCommon. Default: non-bitfield.
    virtual uint64_t unit_size()        const { return size_; }
    virtual uint64_t unit_offset()      const { return 0; }
    virtual uint64_t bitfield_offset()  const { return 0; }
    virtual uint64_t bitfield_length()  const { return 0; }
    virtual bool     is_bitfield()      const { return false; }

    // §3.11 follow-up — type-method dispatch for minimize. Mirrors
    // syzkaller `prog/types.go::(*TypeCommon).minimize` (default
    // returns false). Each Type subclass that has actual minimize
    // behavior overrides this. The default implementation here lets
    // every Type opt in; concrete behavior lives in per-type
    // overrides under `program/src/syz_v2/`.
    //
    // Contract (mirrors `prog/minimization.go::do`):
    //   - Return `true` if the type performed any work (committed a
    //     candidate via `ctx.pred` and accepted, or unconditionally
    //     marked the path tried internally).
    //   - Return `false` if no work was done; the orchestrator will
    //     mark `path` as tried at the outer level.
    //
    // **P1 status**: declared with a default-false body. Per-type
    // overrides arrive in P2 (see `program/syz/minimize_ctx.hpp`
    // migration plan).
    virtual bool minimize(MinimizeCtx&    ctx,
                          Arg&            arg,
                          std::string&    path) const {
        (void)ctx;
        (void)arg;
        (void)path;
        return false;
    }

    // §3.11 follow-up P8 — type-method dispatch for "default value
    // for this type". Mirrors syzkaller `prog/types.go::
    // (*XxxType).DefaultArg(dir)`.
    //
    // The default implementation lives in
    // `program/src/syz_v2/type_methods.cpp` and dispatches via
    // `kind()`. Per-subclass overrides may later replace the
    // default for tighter semantics (e.g., when a subclass needs
    // to access private state); for now the centralized switch
    // matches upstream semantics for all 13 subclasses.
    virtual std::unique_ptr<Arg> default_arg(Dir dir) const;

    void set_name(std::string n)   { name_ = std::move(n); }
    void set_size(uint64_t s)      { size_ = s; }
    void set_align(uint64_t a)     { align_ = a; }
    void set_optional(bool o)      { optional_ = o; }
    void set_var_len(bool v)       { var_len_ = v; }

protected:
    std::string name_;
    uint64_t    size_     = 0;
    uint64_t    align_    = 0;
    bool        optional_ = false;
    bool        var_len_  = false;
};

// ============================================================
// IntTypeCommon — shared by int-like types
// ============================================================

class IntTypeCommon : public Type {
public:
    BinaryFormat format()             const { return format_; }
    uint64_t     bitfield_off()       const { return bitfield_off_; }
    uint64_t     bitfield_len()       const { return bitfield_len_; }
    uint64_t     bitfield_unit()      const { return bitfield_unit_; }
    uint64_t     bitfield_unit_off()  const { return bitfield_unit_off_; }

    // Mirror of prog.IntTypeCommon — overrides the Type defaults.
    uint64_t unit_size()       const override {
        return bitfield_len_ != 0 ? bitfield_unit_ : size_;
    }
    uint64_t unit_offset()     const override { return bitfield_unit_off_; }
    uint64_t bitfield_offset() const override { return bitfield_off_; }
    uint64_t bitfield_length() const override { return bitfield_len_; }
    bool     is_bitfield()     const override { return bitfield_len_ != 0; }

    void set_format(BinaryFormat f)   { format_ = f; }
    void set_bitfield(uint64_t off, uint64_t len, uint64_t unit, uint64_t unit_off) {
        bitfield_off_      = off;
        bitfield_len_      = len;
        bitfield_unit_     = unit;
        bitfield_unit_off_ = unit_off;
    }

    // ============================================================
    // §3.11 follow-up P3 — useless-hints lazy cache.
    //
    // Mirrors syzkaller `prog/types.go::uselessHinter`. Each
    // IntTypeCommon-derived type can compute a per-type set of
    // "useless" candidate values that hint replacement should skip
    // because they don't carry information for the kernel comparison
    // they are meant to drive (e.g., the trivial 0/1/-1 set, all
    // values within a tight range, all 1/2/3-flag combinations,
    // ConstType's single value, etc.).
    //
    // Computed on first access, lazily, using the abstract
    // `calc_useless_hints()` virtual that subclasses override. The
    // returned set is stable for the lifetime of the Target.
    //
    // Consumers (§3.12 hints port) should query this set BEFORE
    // emitting a candidate. Empty set means "no special filter; try
    // all hint candidates". Used as a hint-quality optimization, not
    // a correctness gate.
    // ============================================================
    bool useless_hint(uint64_t v) const;

protected:
    // Subclasses override to declare their useless-hint set.
    // Default: empty (matches Type's no-op behavior).
    virtual std::vector<uint64_t> calc_useless_hints() const { return {}; }

    BinaryFormat format_            = BinaryFormat::kNative;
    uint64_t     bitfield_off_      = 0;
    uint64_t     bitfield_len_      = 0;
    uint64_t     bitfield_unit_     = 0;
    uint64_t     bitfield_unit_off_ = 0;

private:
    // Lazily populated by useless_hint(). Mutable so that const
    // accessors can fill it; once populated, contents don't change.
    mutable std::unordered_set<uint64_t> useless_hints_;
    mutable bool                         useless_hints_ready_ = false;
};

// ============================================================
// IntType
// ============================================================

class IntType final : public IntTypeCommon {
public:
    enum class Kind : uint8_t { kPlain, kRange };

    TypeKind kind() const override { return TypeKind::kInt; }

    Kind     int_kind()    const { return int_kind_; }
    uint64_t range_begin() const { return range_begin_; }
    uint64_t range_end()   const { return range_end_; }
    uint64_t int_align()   const { return int_align_; }

    void set_int_kind(Kind k)              { int_kind_ = k; }
    void set_range(uint64_t b, uint64_t e) { range_begin_ = b; range_end_ = e; }
    void set_int_align(uint64_t a)         { int_align_ = a; }

    // §3.11 follow-up P2 step 3 — default-replace minimize override.
    // Mirrors syzkaller `prog/minimization.go::(*IntType).minimize`:
    // crash-snapshot mode only, propose default value, monotonic
    // shrink (skip if default >= current).
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

protected:
    // §3.11 follow-up P3 — mirror prog/types.go::(*IntType).calcUselessHints.
    std::vector<uint64_t> calc_useless_hints() const override;

private:
    Kind     int_kind_    = Kind::kPlain;
    uint64_t range_begin_ = 0;
    uint64_t range_end_   = 0;
    uint64_t int_align_   = 0;
};

// ============================================================
// ConstType
// ============================================================

class ConstType final : public IntTypeCommon {
public:
    TypeKind kind() const override { return TypeKind::kConst; }

    uint64_t val()    const { return val_; }
    bool     is_pad() const { return is_pad_; }

    void set_val(uint64_t v) { val_ = v; }
    void set_pad(bool p)     { is_pad_ = p; }

protected:
    // §3.11 follow-up P3 — mirror prog/types.go::(*ConstType).calcUselessHints.
    // Returns just the const's own value: hint replacement that proposes
    // the value the const already requires is information-free.
    std::vector<uint64_t> calc_useless_hints() const override {
        return { val_ };
    }

private:
    uint64_t val_    = 0;
    bool     is_pad_ = false;
};

// ============================================================
// FlagsType
// ============================================================

class FlagsType final : public IntTypeCommon {
public:
    TypeKind kind() const override { return TypeKind::kFlags; }

    const std::vector<uint64_t>& vals()    const { return vals_; }
    bool                         bitmask() const { return bitmask_; }

    void set_vals(std::vector<uint64_t> v) { vals_ = std::move(v); }
    void set_bitmask(bool b)               { bitmask_ = b; }

    // §3.11 follow-up P2 step 3 — default-replace minimize override.
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

protected:
    // §3.11 follow-up P3 — mirror prog/types.go::(*FlagsType).calcUselessHints.
    std::vector<uint64_t> calc_useless_hints() const override;

private:
    std::vector<uint64_t> vals_;
    bool                  bitmask_ = false;
};

// ============================================================
// LenType
// ============================================================

class LenType final : public IntTypeCommon {
public:
    TypeKind kind() const override { return TypeKind::kLen; }

    uint64_t                        bit_size() const { return bit_size_; }
    bool                            offset()   const { return offset_; }
    const std::vector<std::string>& path()     const { return path_; }

    void set_bit_size(uint64_t s)            { bit_size_ = s; }
    void set_offset(bool o)                  { offset_ = o; }
    void set_path(std::vector<std::string> p){ path_ = std::move(p); }

private:
    uint64_t                 bit_size_ = 0;
    bool                     offset_   = false;
    std::vector<std::string> path_;
};

// ============================================================
// ProcType
// ============================================================

class ProcType final : public IntTypeCommon {
public:
    TypeKind kind() const override { return TypeKind::kProc; }

    uint64_t values_start()    const { return values_start_; }
    uint64_t values_per_proc() const { return values_per_proc_; }

    void set_values_start(uint64_t s)    { values_start_ = s; }
    void set_values_per_proc(uint64_t p) { values_per_proc_ = p; }

    // §3.11 follow-up P2 step 3 — default-replace minimize override
    // with non-optional guard (mirrors upstream skip on
    // !optional).
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    uint64_t values_start_    = 0;
    uint64_t values_per_proc_ = 0;
};

// ============================================================
// CsumType
// ============================================================

enum class CsumKind : uint8_t {
    kInet   = 0,
    kPseudo = 1,
};

class CsumType final : public IntTypeCommon {
public:
    TypeKind kind() const override { return TypeKind::kCsum; }

    CsumKind           csum_kind() const { return csum_kind_; }
    const std::string& buf()       const { return buf_; }
    uint64_t           protocol()  const { return protocol_; }

    void set_csum_kind(CsumKind k)  { csum_kind_ = k; }
    void set_buf(std::string b)     { buf_ = std::move(b); }
    void set_protocol(uint64_t p)   { protocol_ = p; }

private:
    CsumKind    csum_kind_ = CsumKind::kInet;
    std::string buf_;
    uint64_t    protocol_  = 0;
};

// ============================================================
// ResourceDesc — referenced by ResourceType
// ============================================================

struct ResourceCtor {
    const class SyscallMeta* call    = nullptr;
    bool                     precise = false;
};

class ResourceDesc {
public:
    ResourceDesc() = default;
    ResourceDesc(std::string name, std::vector<std::string> kind, std::vector<uint64_t> values)
        : name_(std::move(name)), kind_(std::move(kind)), values_(std::move(values)) {}

    const std::string&              name()   const { return name_; }
    const std::vector<std::string>& kind()   const { return kind_; }
    const std::vector<uint64_t>&    values() const { return values_; }
    const std::vector<ResourceCtor>& ctors() const { return ctors_; }

    void set_name(std::string n)                  { name_ = std::move(n); }
    void set_kind(std::vector<std::string> k)     { kind_ = std::move(k); }
    void set_values(std::vector<uint64_t> v)      { values_ = std::move(v); }
    void add_ctor(ResourceCtor c)                 { ctors_.push_back(c); }

private:
    std::string                  name_;
    std::vector<std::string>     kind_;
    std::vector<uint64_t>        values_;
    std::vector<ResourceCtor>    ctors_;
};

// ============================================================
// ResourceType
// ============================================================

class ResourceType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kResource; }

    BinaryFormat        format() const { return format_; }
    const ResourceDesc* desc()   const { return desc_; }

    // Mirror of prog.ResourceType.Default(): desc->values[0]; or 0 if unset.
    uint64_t default_value() const {
        return (desc_ != nullptr && !desc_->values().empty())
               ? desc_->values()[0]
               : 0;
    }

    void set_format(BinaryFormat f)        { format_ = f; }
    void set_desc(const ResourceDesc* d)   { desc_ = d; }

    // §3.11 follow-up P2 step 6 — defaulting minimize override.
    // Mode kCrashSnapshot only. When the ResultArg consumer has a
    // non-null `res()` (i.e., references an upstream producer),
    // propose nulling it and resetting val/op_div/op_add to the
    // ResourceType default. Uses C0 forward-edge bookkeeping
    // (`ResultArg::set_res(nullptr)` removes self from producer's
    // `uses_`); maintained correctly by the DeepClone-based
    // try_in_place path.
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    BinaryFormat        format_ = BinaryFormat::kNative;
    const ResourceDesc* desc_   = nullptr;
};

// ============================================================
// BufferType
// ============================================================

enum class BufferKind : uint8_t {
    kBlobRand   = 0,
    kBlobRange  = 1,
    kString     = 2,
    kFilename   = 3,
    kText       = 4,
    kGlob       = 5,
    kCompressed = 6,
};

enum class TextKind : uint8_t {
    kTarget   = 0,
    kX86Real  = 1,
    kX86bit16 = 2,
    kX86bit32 = 3,
    kX86bit64 = 4,
    kArm64    = 5,
    kPpc64    = 6,
};

class BufferType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kBuffer; }

    BufferKind                      buffer_kind() const { return buffer_kind_; }
    uint64_t                        range_begin() const { return range_begin_; }
    uint64_t                        range_end()   const { return range_end_; }
    TextKind                        text_kind()   const { return text_kind_; }
    const std::string&              sub_kind()    const { return sub_kind_; }
    const std::vector<std::string>& values()      const { return values_; }
    bool                            no_z()        const { return no_z_; }
    bool                            is_compressed() const { return buffer_kind_ == BufferKind::kCompressed; }

    // Mirror of prog.isReadableDataType.
    bool is_readable_data_type() const {
        return buffer_kind_ == BufferKind::kString
            || buffer_kind_ == BufferKind::kFilename
            || buffer_kind_ == BufferKind::kGlob;
    }

    void set_buffer_kind(BufferKind k)            { buffer_kind_ = k; }
    void set_range(uint64_t b, uint64_t e)        { range_begin_ = b; range_end_ = e; }
    void set_text_kind(TextKind k)                { text_kind_ = k; }
    void set_sub_kind(std::string s)              { sub_kind_ = std::move(s); }
    void set_values(std::vector<std::string> v)   { values_ = std::move(v); }
    void set_no_z(bool n)                         { no_z_ = n; }

    // §3.11 follow-up P2 step 7 — buffer-kind-specific minimize
    // override. Per-kind candidate generation:
    //   - kBlobRand / kBlobRange: halving-step shrink down to
    //     range_begin (or 0). Crash mode breaks after first step.
    //   - kFilename: pad/NUL trim (var_len only); no_z drops trailing
    //     '\0', else trim trailing 'a'/'\0' then re-NUL-terminate.
    //   - kString / kGlob / kText / kCompressed: skipped (per
    //     upstream — these are content-typed, not size-shrinkable).
    // Out-direction args + compressed buffers + empty data → skip.
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    BufferKind               buffer_kind_ = BufferKind::kBlobRand;
    uint64_t                 range_begin_ = 0;
    uint64_t                 range_end_   = 0;
    TextKind                 text_kind_   = TextKind::kTarget;
    std::string              sub_kind_;
    std::vector<std::string> values_;
    bool                     no_z_        = false;
};

// ============================================================
// PtrType
// ============================================================

class PtrType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kPtr; }

    const Type* elem()             const { return elem_; }
    Dir         elem_dir()         const { return elem_dir_; }
    bool        squashable_elem()  const { return squashable_elem_; }

    void set_elem(const Type* e)         { elem_ = e; }
    void set_elem_dir(Dir d)             { elem_dir_ = d; }
    void set_squashable_elem(bool s)     { squashable_elem_ = s; }

    // §3.11 follow-up P2 step 5 — null-replacement minimize override.
    // Single try_commit candidate: replace a non-null PointerArg
    // with a fully nulled one (address=0, vma_size=0, res=nullptr).
    // The dropped pointee subtree's ResultArg dtors maintain the
    // C0 forward-edge invariant.
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    const Type* elem_            = nullptr;
    Dir         elem_dir_        = Dir::kIn;
    bool        squashable_elem_ = false;
};

// ============================================================
// ArrayType
// ============================================================

enum class ArrayKind : uint8_t {
    kRandLen  = 0,
    kRangeLen = 1,
};

class ArrayType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kArray; }

    const Type* elem()        const { return elem_; }
    ArrayKind   array_kind()  const { return array_kind_; }
    uint64_t    range_begin() const { return range_begin_; }
    uint64_t    range_end()   const { return range_end_; }

    void set_elem(const Type* e)             { elem_ = e; }
    void set_array_kind(ArrayKind k)         { array_kind_ = k; }
    void set_range(uint64_t b, uint64_t e)   { range_begin_ = b; range_end_ = e; }

    // §3.11 follow-up P2 step 4 — array minimize override. Combines:
    //   - Remove-all fast path: 3+ elements, range_begin == 0 → try
    //     clearing the inner vector once.
    //   - Per-element peel-from-end: re-lookup live array via path
    //     after each commit (mark-on-commit triedPaths is at the
    //     array level; we iterate internally instead of relying on
    //     per-element path-key memoization upstream-style).
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    const Type* elem_        = nullptr;
    ArrayKind   array_kind_  = ArrayKind::kRandLen;
    uint64_t    range_begin_ = 0;
    uint64_t    range_end_   = 0;
};

// ============================================================
// VmaType
// ============================================================

class VmaType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kVma; }

    uint64_t range_begin() const { return range_begin_; }   // in pages
    uint64_t range_end()   const { return range_end_; }

    void set_range(uint64_t b, uint64_t e) { range_begin_ = b; range_end_ = e; }

private:
    uint64_t range_begin_ = 0;
    uint64_t range_end_   = 0;
};

// ============================================================
// Field — element of StructType / UnionType / SyscallMeta::args
// ============================================================

class Field {
public:
    Field();
    Field(const Field&) = delete;             // contains unique_ptr<Expression>
    Field& operator=(const Field&) = delete;
    Field(Field&&) noexcept;
    Field& operator=(Field&&) noexcept;
    ~Field();

    Field(std::string name, const Type* type);

    const std::string& name()          const { return name_; }
    const Type*        type()          const { return type_; }
    bool               has_direction() const { return has_direction_; }
    Dir                direction()     const { return direction_; }
    Dir                dir(Dir parent) const { return has_direction_ ? direction_ : parent; }
    const Expression*  condition()     const { return condition_.get(); }

    void set_name(std::string n)                       { name_ = std::move(n); }
    void set_type(const Type* t)                       { type_ = t; }
    void set_direction(Dir d)                          { direction_ = d; has_direction_ = true; }
    void clear_direction()                             { has_direction_ = false; direction_ = Dir::kIn; }
    void set_condition(std::unique_ptr<Expression> c);

    // ============================================================
    // §3.11 follow-up P4 — related-fields cache.
    //
    // Mirrors syzkaller `prog/types.go::Field.relatedFields`
    // populated by `Target.initRelatedFields`. The set holds Type*
    // pointers of fields that operate on the same syscall position
    // and the same underlying resource/file, keyed up to a sequence
    // of preceding ConstType values that further partition the
    // group. The canonical example: ioctl$FOO1.cmd /
    // ioctl$FOO2.cmd / ioctl$FOO3.cmd over fd_foo all share one
    // group; trying to morph between them via hint replacement is
    // wasteful (and per upstream issues #502 / #4939, sometimes
    // confuses argument types).
    //
    // Set is empty by default; populated by Target finalize via
    // `set_related_fields`. Fields whose group ends up as a
    // singleton are NOT linked (upstream drops groups of one — the
    // group provides no replacement guidance).
    // ============================================================
    const std::unordered_set<const Type*>* related_fields() const {
        return related_fields_;
    }
    void set_related_fields(const std::unordered_set<const Type*>* p) {
        related_fields_ = p;
    }

private:
    std::string                            name_;
    const Type*                            type_ = nullptr;
    bool                                   has_direction_ = false;
    Dir                                    direction_     = Dir::kIn;
    std::unique_ptr<Expression>            condition_;

    // Pointer to a group set owned by Target (lifetime-tied to the
    // Target). nullptr means "no group / singleton dropped".
    const std::unordered_set<const Type*>* related_fields_ = nullptr;
};

// ============================================================
// StructType
// ============================================================

class StructType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kStruct; }

    const std::vector<Field>& fields()        const { return fields_; }
    uint64_t                  align_attr()    const { return align_attr_; }
    int                       overlay_field() const { return overlay_field_; }

    void set_fields(std::vector<Field> f)   { fields_ = std::move(f); }
    void set_align_attr(uint64_t a)         { align_attr_ = a; }
    void set_overlay_field(int o)           { overlay_field_ = o; }

    // Lookup by field name; returns nullptr if not found.
    const Field* find_field(std::string_view name) const;

private:
    std::vector<Field> fields_;
    uint64_t           align_attr_    = 0;
    int                overlay_field_ = 0;
};

// ============================================================
// UnionType
// ============================================================

class UnionType final : public Type {
public:
    TypeKind kind() const override { return TypeKind::kUnion; }

    const std::vector<Field>& fields() const { return fields_; }

    void set_fields(std::vector<Field> f) { fields_ = std::move(f); }

    // Lookup by selected arm name; returns nullptr if not found.
    const Field* find_field(std::string_view name) const;

    // True if any field has a Condition (i.e. conditional union).
    bool is_conditional() const;

    // §3.11 follow-up P2 step 8 — default-arm minimize override.
    // Single try_in_place candidate: switch the current arm to the
    // "default" arm and set its option to the default_arg of the
    // target field's type. Default arm = field 0 for non-conditional
    // unions; last field for conditional unions IFF the last field
    // has no condition. Skipped when the union is already in the
    // default arm with a default option (no progress possible).
    //
    // Cross-arm scanning is intentionally NOT done — mirrors syzkaller
    // `(*UnionType).minimize` which only proposes the default arm.
    bool minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const override;

private:
    std::vector<Field> fields_;
};

// ============================================================
// Expression — for conditional fields
// ============================================================

enum class BinaryOperator : uint8_t {
    kCompareEq  = 0,
    kCompareNeq = 1,
    kBinaryAnd  = 2,
    kOr         = 3,
};

class Expression {
public:
    enum class Kind : uint8_t { kBinary, kValue };

    virtual ~Expression() = default;
    virtual Kind                       expr_kind() const = 0;
    virtual std::unique_ptr<Expression> clone() const = 0;
};

class ValueExpr final : public Expression {
public:
    Kind expr_kind() const override { return Kind::kValue; }

    uint64_t                        value() const { return value_; }
    const std::vector<std::string>& path()  const { return path_; }

    void set_value(uint64_t v)                 { value_ = v; }
    void set_path(std::vector<std::string> p)  { path_ = std::move(p); }

    std::unique_ptr<Expression> clone() const override;

private:
    uint64_t                 value_ = 0;
    std::vector<std::string> path_;
};

class BinaryExpression final : public Expression {
public:
    Kind expr_kind() const override { return Kind::kBinary; }

    BinaryOperator    op()    const { return op_; }
    const Expression* left()  const { return left_.get(); }
    const Expression* right() const { return right_.get(); }

    void set_op(BinaryOperator op)                 { op_ = op; }
    void set_left(std::unique_ptr<Expression> l)   { left_ = std::move(l); }
    void set_right(std::unique_ptr<Expression> r)  { right_ = std::move(r); }

    std::unique_ptr<Expression> clone() const override;

private:
    BinaryOperator              op_ = BinaryOperator::kCompareEq;
    std::unique_ptr<Expression> left_;
    std::unique_ptr<Expression> right_;
};

// ============================================================
// Helpers: safe down-casts (free functions)
// ============================================================

// Mirror of prog.IsPad: true iff t is a ConstType with IsPad set.
inline bool is_pad(const Type* t) {
    if (t == nullptr || t->kind() != TypeKind::kConst) return false;
    return static_cast<const ConstType*>(t)->is_pad();
}

inline const IntType*      as_int(const Type* t)      { return t && t->kind() == TypeKind::kInt      ? static_cast<const IntType*>(t)      : nullptr; }
inline const ConstType*    as_const(const Type* t)    { return t && t->kind() == TypeKind::kConst    ? static_cast<const ConstType*>(t)    : nullptr; }
inline const FlagsType*    as_flags(const Type* t)    { return t && t->kind() == TypeKind::kFlags    ? static_cast<const FlagsType*>(t)    : nullptr; }
inline const ProcType*     as_proc(const Type* t)     { return t && t->kind() == TypeKind::kProc     ? static_cast<const ProcType*>(t)     : nullptr; }
inline const LenType*      as_len(const Type* t)      { return t && t->kind() == TypeKind::kLen      ? static_cast<const LenType*>(t)      : nullptr; }
inline const CsumType*     as_csum(const Type* t)     { return t && t->kind() == TypeKind::kCsum     ? static_cast<const CsumType*>(t)     : nullptr; }
inline const ResourceType* as_resource(const Type* t) { return t && t->kind() == TypeKind::kResource ? static_cast<const ResourceType*>(t) : nullptr; }
inline const BufferType*   as_buffer(const Type* t)   { return t && t->kind() == TypeKind::kBuffer   ? static_cast<const BufferType*>(t)   : nullptr; }
inline const PtrType*      as_ptr(const Type* t)      { return t && t->kind() == TypeKind::kPtr      ? static_cast<const PtrType*>(t)      : nullptr; }
inline const ArrayType*    as_array(const Type* t)    { return t && t->kind() == TypeKind::kArray    ? static_cast<const ArrayType*>(t)    : nullptr; }
inline const StructType*   as_struct(const Type* t)   { return t && t->kind() == TypeKind::kStruct   ? static_cast<const StructType*>(t)   : nullptr; }
inline const UnionType*    as_union(const Type* t)    { return t && t->kind() == TypeKind::kUnion    ? static_cast<const UnionType*>(t)    : nullptr; }
inline const VmaType*      as_vma(const Type* t)      { return t && t->kind() == TypeKind::kVma      ? static_cast<const VmaType*>(t)      : nullptr; }

} // namespace refuzz::program::syz
