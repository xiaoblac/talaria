// reFuzz syz_v2 — anyTypes / squash machinery.
//
// Mirrors syzkaller `prog/any.go`. The `ANYPTRS` / `ANYUNION` /
// `ANYBLOB` / `ANYRES{8,16,32,64,dec,hex,oct}` types are
// auto-generated builtin descriptions that let the mutator collapse
// "complex" structured pointer args (varlen structs, large unions)
// into a flat array of (resource | blob) elements. This is how
// syzkaller emits "compact" mutated programs that don't carry
// minimize-fragile structural details when the predicate doesn't
// care.
//
// reFuzz scope:
//   - **P5 (this commit)**: predicate-only API surface
//     (`is_any_ptr`, `is_any_res`, `call_contains_any`,
//     `arg_contains_any`) + cached `AnyTypes` lookup. These are
//     read-only and used by hints / minimize / validation in
//     decisions like "skip this arg from hint replacement because
//     it's already a squash artifact" or "this call has been
//     squashed; dedup logic skips it".
//   - **§3.12 prep**: the mutate-time squash bodies
//     (`squash_ptr`, `squash_group`, `squash_const`,
//     `squash_result`, `squashed_value`, `ensure_data_elem`) are
//     declared but left as stubs that abort. They depend on full
//     mutator infra (Gen / state) and arrive with the §3.12 hints
//     port.

#pragma once

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace refuzz::program::syz {

class Target;

// ============================================================
// AnyTypes — cached pointers into the Target's type arena for the
// `ANYPTRS` family. Mirrors syzkaller `prog.anyTypes`.
// ============================================================

struct AnyTypes {
    const UnionType*    any_union  = nullptr;  // ANYUNION
    const ArrayType*    any_array  = nullptr;  // array elem of any_ptr_ptr
    const BufferType*   any_blob   = nullptr;  // ANYBLOB
    const PtrType*      ptr_ptr    = nullptr;  // ptr-to-ptr-sized any ptr
    const PtrType*      ptr_64     = nullptr;  // ptr-to-64-bit any ptr
    const ResourceType* res_8      = nullptr;
    const ResourceType* res_16     = nullptr;
    const ResourceType* res_32     = nullptr;
    const ResourceType* res_64     = nullptr;
    const ResourceType* res_dec    = nullptr;
    const ResourceType* res_hex    = nullptr;
    const ResourceType* res_oct    = nullptr;

    bool ready() const { return any_union != nullptr; }
};

// ============================================================
// Predicates — pure read; safe for any caller.
// ============================================================

// True iff `typ` is one of the cached "any" ptr types
// (`ANYPTRS.ptr` or `ANYPTRS.ptr64`).
bool is_any_ptr(const Target& target, const Type* typ);

// True iff `name` matches one of the 7 ANYRES* type names. Does not
// touch Target — comparison is against literal upstream names.
bool is_any_res(std::string_view name);

// True iff any sub-arg of `call` references an any-ptr type.
bool call_contains_any(const Target& target, const Call& call);

// True iff `arg` (or any sub-arg) references an any-ptr type.
bool arg_contains_any(const Target& target, const Arg& arg);

// ============================================================
// Complex-pointer discovery + squash entry point.
// (Ports prog/any.go squashPtr/complexPtrs/isComplexPtr. The
// squash_{ptr_impl,group,const,result}/squashed_value/ensure_data_elem
// helpers are internal to any.cpp.)
// ============================================================

// A squashable pointer and the call that owns it. Mirrors prog.complexPtr.
struct ComplexPtr {
    PointerArg* arg  = nullptr;
    Call*       call = nullptr;
};

// True iff `arg` points at squashable structured content — a varlen struct,
// or a varlen union with >5 fields, reachable under a `squashable_elem` ptr —
// or is already an any-ptr. Mirrors prog.Target.isComplexPtr.
bool is_complex_ptr(const Target& target, const PointerArg* arg);

// All complex pointers across `prog` (one per ptr subtree, outermost first).
// Mirrors prog.Prog.complexPtrs.
std::vector<ComplexPtr> complex_ptrs(const Target& target, Prog& prog);

// Collapse a complex structured pointee into a flat ANYUNION array of
// ANYBLOB (raw bytes) + ANYRES (resource refs), byte-for-byte preserving the
// original in-memory layout (size invariant). Resource references and their
// use-edges are preserved (the ResultArg object is re-typed in place, not
// copied). No-op if `arg` is null/vma/non-squashable. Mirrors
// prog.Target.squashPtr.
void squash_ptr(const Target& target, PointerArg* arg);

} // namespace refuzz::program::syz
