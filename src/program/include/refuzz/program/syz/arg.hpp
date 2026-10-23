// reFuzz syzkaller-equivalent IR — Arg tree
//
// Mirrors prog.Arg interface and 6 concrete subclasses from upstream
// syzkaller. Lifetime: owned by the enclosing Call (top-level args) or
// by the parent Arg (inner args), via std::unique_ptr.

#pragma once

#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

// Discriminator for Arg subclasses.
enum class ArgKind : uint8_t {
    kConst   = 0,   // ConstArg (used for IntType/ConstType/FlagsType/LenType/ProcType/CsumType)
    kPointer = 1,   // PointerArg (used for PtrType/VmaType)
    kData    = 2,   // DataArg (used for BufferType)
    kGroup   = 3,   // GroupArg (used for StructType/ArrayType)
    kUnion   = 4,   // UnionArg (used for UnionType)
    kResult  = 5,   // ResultArg (used for ResourceType)
};

// ============================================================
// Arg base
// ============================================================

// §3.11 follow-up P8a — CloneCtx threads the per-Prog ResultArg
// remap state through Arg::clone(). Mirrors syzkaller `cloneCalls /
// cloneArg(_, newargs)` machinery. ResultArg::clone() registers the
// old → new mapping; pass 2 (remap) rewrites placeholders to cloned
// counterparts.
class ResultArg;
struct CloneCtx {
    // ResultArg pointers: src -> dst. Populated by ResultArg::clone()
    // pass 1; consumed by pass 2 (Prog-level remap).
    std::unordered_map<const ResultArg*, ResultArg*> result_map;
};

class Arg {
public:
    virtual ~Arg() = default;
    virtual ArgKind  arg_kind() const = 0;
    virtual uint64_t size()     const = 0;   // mirrors prog.Arg.Size()

    const Type* type() const { return type_; }
    Dir         dir()  const { return dir_; }

    void set_type(const Type* t) { type_ = t; }
    void set_dir(Dir d)          { dir_ = d; }

    // §3.11 follow-up P8a — type-method dispatch for clone.
    // Mirrors syzkaller `prog/clone.go::cloneArg(_, newargs)` switch.
    // Each Arg subclass overrides to clone its own state. ResultArg's
    // override populates `ctx.result_map` for the post-pass remap.
    //
    // For test code wanting a single-arg copy without cross-arg
    // context, use the convenience overload `clone()` which builds a
    // local CloneCtx; cross-Prog ResultArg refs become null.
    virtual std::unique_ptr<Arg> clone(CloneCtx& ctx) const = 0;

    // Convenience for single-arg deep copy (no cross-arg context).
    // Implemented in arg.cpp; builds a local CloneCtx and delegates.
    std::unique_ptr<Arg> clone() const;

protected:
    const Type* type_ = nullptr;
    Dir         dir_  = Dir::kIn;
};

// ============================================================
// ConstArg
// ============================================================

class ConstArg final : public Arg {
public:
    ArgKind  arg_kind() const override { return ArgKind::kConst; }
    uint64_t size()     const override { return type_ != nullptr && !type_->var_len() ? type_->size() : 0; }
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;
    uint64_t val()      const          { return val_; }
    void     set_val(uint64_t v)       { val_ = v; }

    // Mirror of prog.ConstArg.Value: returns (value, pid_stride). pid_stride
    // is non-zero only for ProcType (when val != procDefaultValue);
    // CsumType always returns (0,0) (executor recomputes); other int-like
    // types return (val, 0).
    std::pair<uint64_t, uint64_t> value_with_pid_stride() const;

private:
    uint64_t val_ = 0;
};

// ============================================================
// PointerArg — used for both PtrType and VmaType
// ============================================================

class PointerArg final : public Arg {
public:
    ArgKind  arg_kind() const override { return ArgKind::kPointer; }
    uint64_t size()     const override { return type_ != nullptr ? type_->size() : 8; }
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;

    uint64_t address()   const { return address_; }
    uint64_t vma_size()  const { return vma_size_; }
    Arg*     res()       const { return res_.get(); }
    bool     is_special() const;

    // §3.11 follow-up P2 — owning-slot accessor used by
    // `MinimizeCtx::try_commit` (parent-slot find for in-place arg
    // swap). Mirrors `GroupArg::mutable_inner()` precedent: an Arg
    // tree mutator that needs to swap the unique_ptr (not just the
    // arg's internal state) walks through these slots. Type-method
    // bodies should NOT use this directly — they go through ctx.
    std::unique_ptr<Arg>&       mutable_res_slot()       { return res_; }

    void set_address(uint64_t a)            { address_ = a; }
    void set_vma_size(uint64_t s)           { vma_size_ = s; }
    void set_res(std::unique_ptr<Arg> r)    { res_ = std::move(r); }

private:
    uint64_t              address_  = 0;
    uint64_t              vma_size_ = 0;     // non-zero only for vma args
    std::unique_ptr<Arg>  res_;               // pointee (nullptr for vma)
};

// ============================================================
// DataArg — used for BufferType
// ============================================================

class DataArg final : public Arg {
public:
    ArgKind  arg_kind() const override { return ArgKind::kData; }
    uint64_t size()     const override { return data_.empty() ? out_size_ : static_cast<uint64_t>(data_.size()); }
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;

    const std::vector<uint8_t>& data()      const { return data_; }
    uint64_t                    out_size()  const { return out_size_; }

    // [v2 Epic 5 PR-5-C] In-place mutable accessor — mirror of
    // GroupArg::mutable_inner / UnionArg::mutable_option_slot pattern.
    // Hints algorithm uses this for the byte-window slide-and-restore
    // loop (set_data would force a vector reassign per replacer).
    std::vector<uint8_t>&       mutable_data()       { return data_; }

    void set_data(std::vector<uint8_t> d) { data_ = std::move(d); out_size_ = 0; }
    void set_out_size(uint64_t s)         { out_size_ = s; data_.clear(); }

private:
    std::vector<uint8_t> data_;        // for in/inout
    uint64_t             out_size_ = 0; // for out
};

// ============================================================
// GroupArg — used for StructType and ArrayType
// ============================================================

class GroupArg final : public Arg {
public:
    ArgKind  arg_kind() const override { return ArgKind::kGroup; }
    uint64_t size()     const override;     // implemented in arg.cpp (struct/array aware)
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;

    const std::vector<std::unique_ptr<Arg>>& inner()         const { return inner_; }
    std::vector<std::unique_ptr<Arg>>&       mutable_inner()       { return inner_; }

    void add_inner(std::unique_ptr<Arg> a) { inner_.push_back(std::move(a)); }
    void set_inner(std::vector<std::unique_ptr<Arg>> a) { inner_ = std::move(a); }

private:
    std::vector<std::unique_ptr<Arg>> inner_;
};

// ============================================================
// UnionArg — used for UnionType
// ============================================================

class UnionArg final : public Arg {
public:
    ArgKind  arg_kind() const override { return ArgKind::kUnion; }
    uint64_t size()     const override {
        if (type_ != nullptr && !type_->var_len()) return type_->size();
        return option_ ? option_->size() : 0;
    }
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;

    Arg* option()    const { return option_.get(); }
    int  index()     const { return index_; }
    bool transient() const { return transient_; }

    // §3.11 follow-up P2 — owning-slot accessor used by
    // `MinimizeCtx::try_commit` parent-slot find. See
    // `PointerArg::mutable_res_slot` for the contract.
    std::unique_ptr<Arg>&       mutable_option_slot()    { return option_; }

    void set_option(std::unique_ptr<Arg> o) { option_ = std::move(o); }
    void set_index(int i)                   { index_ = i; }
    void set_transient(bool t)              { transient_ = t; }

private:
    std::unique_ptr<Arg> option_;
    int                  index_     = 0;
    bool                 transient_ = false;
};

// ============================================================
// ResultArg — used for ResourceType (and as syscall return)
// ============================================================
//
// `res_` is a weak pointer to another ResultArg (the producing Call's ret
// or a previous ResultArg). The producing arg is owned by its Call/Prog;
// ResultArg::res_ does not own the referent.
//
// `uses_` is the forward-edge set: every ResultArg whose res_ points at
// this one. Mirrors syzkaller `prog.ResultArg.uses` (§3.11-C0). Maintained
// automatically by set_res(); destructor erases self from old producer's
// uses_ and nulls the back-pointer of any surviving consumer.
//
// Invariant (asserted by oracle #23 result_arg_uses_invariant_test):
//   for every ResultArg* c, c.res() != null iff c ∈ c.res()->uses().
//
// Consumers of this forward edge include:
//   - crash/repro/.../minimize ((*ResourceType).minimize, accurate
//     relatedCalls without string-token proxy)
//   - §3.14 fault injection (knowing which consumers a faulted call
//     affects)

class ResultArg final : public Arg {
public:
    ResultArg() = default;
    // ResultArg holds a forward-edge set indexed by `this`; copying or
    // moving would either corrupt the back-pointer in producer's uses_
    // (move) or create a phantom consumer outside any producer's uses_
    // (copy). All ownership flows through unique_ptr in callers.
    ResultArg(const ResultArg&) = delete;
    ResultArg& operator=(const ResultArg&) = delete;
    ResultArg(ResultArg&&) = delete;
    ResultArg& operator=(ResultArg&&) = delete;

    ~ResultArg() override {
        // Erase self from producer's forward-edge set.
        if (res_ != nullptr) {
            res_->uses_.erase(this);
        }
        // Defensive: invalidate any surviving consumers' back-pointers
        // so they can't dangle. Direct assignment (NOT set_res) — we're
        // dying, no need to mutate our own uses_, and consumers may
        // also be in destruction.
        for (auto* c : uses_) {
            c->res_ = nullptr;
        }
    }

    ArgKind  arg_kind() const override { return ArgKind::kResult; }
    uint64_t size()     const override { return type_ != nullptr && !type_->var_len() ? type_->size() : 0; }
    std::unique_ptr<Arg> clone(CloneCtx& ctx) const override;

    const ResultArg* res()    const { return res_; }
    ResultArg*       mutable_res()  { return res_; }
    uint64_t         op_div() const { return op_div_; }
    uint64_t         op_add() const { return op_add_; }
    uint64_t         val()    const { return val_; }

    // Forward-edge accessor — set of ResultArgs whose res() points at
    // this. Read-only externally; maintained by set_res() / destructor.
    const std::unordered_set<ResultArg*>& uses() const { return uses_; }

    // Self-maintaining: keeps the back/forward-edge invariant.
    // All in-place rewires of res_ (mutator, encoding, clone remap)
    // should go through this setter.
    void set_res(ResultArg* r) {
        if (res_ == r) return;  // no-op; avoids erase+insert when unchanged
        if (res_ != nullptr) {
            res_->uses_.erase(this);
        }
        res_ = r;
        if (res_ != nullptr) {
            res_->uses_.insert(this);
        }
    }

    // Low-level: bypass uses_ maintenance. Only for the clone placeholder
    // pattern in program/syz/clone.cpp, where res_ is temporarily stashed
    // with an OLD-prog pointer that must NOT register in the source's
    // uses_. RemapArg later replaces it via the normal set_res(), which
    // correctly establishes the forward edge in the cloned graph.
    void set_res_raw(ResultArg* r) { res_ = r; }

    void set_op_div(uint64_t d)    { op_div_ = d; }
    void set_op_add(uint64_t a)    { op_add_ = a; }
    void set_val(uint64_t v)       { val_ = v; }

private:
    ResultArg* res_     = nullptr;  // weak ref (owning Call manages lifetime)
    std::unordered_set<ResultArg*> uses_;  // forward-edge consumers (§3.11-C0)
    uint64_t   op_div_  = 0;
    uint64_t   op_add_  = 0;
    uint64_t   val_     = 0;
};

// ============================================================
// Free helpers: safe down-casts
// ============================================================

inline const ConstArg*   as_const_arg(const Arg* a)   { return a && a->arg_kind() == ArgKind::kConst   ? static_cast<const ConstArg*>(a)   : nullptr; }
inline const PointerArg* as_pointer_arg(const Arg* a) { return a && a->arg_kind() == ArgKind::kPointer ? static_cast<const PointerArg*>(a) : nullptr; }
inline const DataArg*    as_data_arg(const Arg* a)    { return a && a->arg_kind() == ArgKind::kData    ? static_cast<const DataArg*>(a)    : nullptr; }
inline const GroupArg*   as_group_arg(const Arg* a)   { return a && a->arg_kind() == ArgKind::kGroup   ? static_cast<const GroupArg*>(a)   : nullptr; }
inline const UnionArg*   as_union_arg(const Arg* a)   { return a && a->arg_kind() == ArgKind::kUnion   ? static_cast<const UnionArg*>(a)   : nullptr; }
inline const ResultArg*  as_result_arg(const Arg* a)  { return a && a->arg_kind() == ArgKind::kResult  ? static_cast<const ResultArg*>(a)  : nullptr; }

// Mirror of prog.Type.isDefaultArg dispatch — does the arg's value equal
// the type's natural default? Pure structural check; callers that also
// need to preserve named-result decls should additionally guard on
// something like `carriesNamedRef`.
bool is_default_arg(const Arg* a);

} // namespace refuzz::program::syz
