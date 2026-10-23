package main

// Single source of truth for pseudo NR + spec synthesis.
//
// Two emitters consume the same per-target pseudo identity:
//   - tools/syzgen/main.go::preparePseudoRows  → worker-facing tables
//     in program/include/refuzz/program/syz/pseudo/generated/*.gen.hpp
//     (kDefaultSyzTarget.pseudos).
//   - tools/syzgen/emit_cpp.go::writeSyscall   → typed Target tables in
//     program/src/syz/generated/target_linux_amd64_syscalls_part_*.gen.cpp
//     (consumed by Target::linux_amd64() → SyscallMeta::nr).
//
// Before this helper landed, preparePseudoRows owned pseudoNrBase+i
// synthesis as a writer-local detail and emit_cpp.go::writeSyscall
// wrote sc.NR (= 0 for every syz_*) directly. That was the source-of-
// truth fork captured in
// docs/plans/syzkaller-capability-closure-audit.md row #3.
//
// Determinism: pseudos are filtered (HasPrefix "syz_") then sorted by
// Name before NR assignment. Both emitters now consume the SAME ordered
// list, so SynthesizePseudoNRs(target)["syz_X"].NR is well-defined for
// the lifetime of a syzgen invocation.

import (
	"sort"

	"github.com/google/syzkaller/prog"
)

// PseudoSynthEntry is the per-pseudo identity assigned by syzgen.
//
// NR is the synthesized worker-NR (pseudoNrBase + sorted-index). It is
// what lands in both kDefaultSyzTarget.pseudos[i].nr (worker side) and
// SyscallMeta::nr (typed Target side); the two are required to match
// for the worker's wire driver to route generated pseudos through
// ExecuteNrOrPseudo instead of syscall(0, ...).
//
// Spec carries the catalog classification (domain / impl / caps) so
// the typed Target emitter can populate SyscallMeta::pseudo_impl and
// SyscallMeta::capability_mask in the same pass (Step 2 / PR-2-B).
//
// Index is the sorted-pseudo position; exposed for callers that want
// to consult it for pretty-printing or assertions.
type PseudoSynthEntry struct {
	NR    uint64
	Spec  pseudoSpec
	Index int
}

// SynthesizePseudoNRs walks target.Syscalls, picks syz_* entries,
// sorts them by name, and assigns pseudoNrBase + sorted-index to each.
//
// Returns a map keyed by the *full* syscall name (e.g.
// "syz_open_dev$char_raw"), matching what writers already key on.
//
// Determinism is required: both syzgen emitters depend on this map
// returning identical NRs across consecutive invocations on the same
// target, otherwise the worker-facing kDefaultSyzTarget.pseudos and
// the typed Target's SyscallMeta::nr will drift.
func SynthesizePseudoNRs(target *prog.Target) map[string]PseudoSynthEntry {
	pseudos := pseudoDescriptionSyscalls(target)
	sort.Slice(pseudos, func(i, j int) bool {
		return pseudos[i].Name < pseudos[j].Name
	})
	out := make(map[string]PseudoSynthEntry, len(pseudos))
	for i, sc := range pseudos {
		out[sc.Name] = PseudoSynthEntry{
			NR:    pseudoNrBase + uint64(i),
			Spec:  classifyPseudo(sc.Name),
			Index: i,
		}
	}
	return out
}
