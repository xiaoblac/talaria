// Code generator that emits the new polymorphic syzkaller-equivalent IR
// for reFuzz program/ module. Produced files live under
// program/src/syz_v2/generated/ and are compiled into refuzz_program.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

func sortStrings(v []string) { sort.Strings(v) }

const (
	// [v1 pre-layout-sweep — ROLLBACK: uncomment below and remove v2]
	// cppDefaultOutDir   = "program/src/syz_v2/generated"

	// [v2 post-layout-sweep 2026-05-06 — 当前版本]
	// Typed Target gen files moved from program/src/syz_v2/generated →
	// program/src/syz/generated. The `target-cpp` default -out flag
	// must match the active layout, otherwise running
	// `go run ./tools/syzgen target-cpp` writes to a non-existent
	// directory and the typed-Target metadata silently goes stale
	// (Target::finalize() then aborts with `pseudo X impl mismatch`
	// once worker pseudo_meta.gen.hpp is regen'd separately).
	cppDefaultOutDir   = "program/src/syz/generated"
	syscallsPerCppFile = 1000
	typesPerCppFile    = 3000
)

type cppEmitter struct {
	target *prog.Target
	outDir string
	typeID map[prog.Type]int
	resID  map[*prog.ResourceDesc]int
	// pseudoSynth provides the synthesized NR / spec for every syz_*
	// syscall. Populated once in runTargetCpp from
	// SynthesizePseudoNRs(target) so that writeSyscall emits the same
	// pseudoNrBase+i NR that main.go's worker-facing tables already
	// carry. This closes the source-of-truth fork captured in
	// docs/plans/syzkaller-capability-closure-audit.md row #3.
	pseudoSynth  map[string]PseudoSynthEntry
	typeParts    int
	syscallParts int
}

func runTargetCpp(target *prog.Target, opts options) error {
	outDir := opts.out
	if outDir == "" { // user did not pass -out; use the typed-cpp default
		outDir = cppDefaultOutDir
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	e := &cppEmitter{
		target:      target,
		outDir:      outDir,
		typeID:      make(map[prog.Type]int, len(target.Types)),
		resID:       make(map[*prog.ResourceDesc]int, len(target.Resources)),
		pseudoSynth: SynthesizePseudoNRs(target),
	}
	for i, t := range target.Types {
		e.typeID[t] = i
	}
	for i, r := range target.Resources {
		e.resID[r] = i
	}
	if err := e.emitResources(); err != nil {
		return err
	}
	if err := e.emitMetadata(); err != nil {
		return err
	}
	if err := e.emitTypes(); err != nil {
		return err
	}
	if err := e.emitSyscalls(); err != nil {
		return err
	}
	if err := e.emitCallTable(opts.callTableOut); err != nil {
		return err
	}
	if err := e.emitMain(); err != nil {
		return err
	}
	log.Printf("target-cpp emitted: %d types, %d syscalls, %d resources",
		len(target.Types), len(target.Syscalls), len(target.Resources))
	return nil
}

// parseTargetCppFlags reuses the common flag set.
func parseTargetCppFlags(args []string) options {
	fs := flag.NewFlagSet("target-cpp", flag.ExitOnError)
	opts := options{}
	fs.StringVar(&opts.osName, "os", "linux", "target OS")
	fs.StringVar(&opts.arch, "arch", "amd64", "target arch")
	fs.StringVar(&opts.out, "out", "", "output directory (empty = "+cppDefaultOutDir+")")
	fs.StringVar(&opts.callTableOut, "call-table-out", defaultCallTableOutDir, "directory for target_linux_amd64_call_table.gen.hpp")
	fs.StringVar(&opts.syzkallerRoot, "syzkaller-root", "..", "syzkaller checkout root")
	fs.StringVar(&opts.pinFile, "pin-file", defaultPinFile, "pin file (unused for target-cpp)")
	fs.BoolVar(&opts.unpinned, "unpinned", true, "(no-op for target-cpp)")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	return opts
}

// ============================================================
// Resources
// ============================================================

func (e *cppEmitter) emitResources() error {
	path := filepath.Join(e.outDir, e.fileName("resources.gen.cpp"))
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, "resources")
	fmt.Fprintln(w, `#include "refuzz/program/syz/target.hpp"`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "void build_resources(Target& target, std::vector<ResourceDesc*>& resources_out) {")
	fmt.Fprintln(w, "    auto& arena = target.resource_arena();")
	fmt.Fprintln(w, "    resources_out.clear();")
	fmt.Fprintf(w, "    resources_out.reserve(%d);\n", len(e.target.Resources))
	for _, r := range e.target.Resources {
		fmt.Fprintf(w, "    resources_out.push_back(arena.make(%s, %s, %s));\n",
			cppQuote(r.Name), cppStringList(r.Kind), cppU64List(r.Values))
	}
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz::generated")
	return nil
}

// ============================================================
// Types — split across multiple TUs to keep per-function stack
// frames manageable. Each part contributes alloc_types_part_NNN
// (pass 1) and fill_types_part_NNN (pass 2). Main calls all
// alloc_* before all fill_* so that cross-part type references
// resolve via the shared `types` vector.
// ============================================================

func (e *cppEmitter) emitTypes() error {
	parts := (len(e.target.Types) + typesPerCppFile - 1) / typesPerCppFile
	for p := 0; p < parts; p++ {
		start := p * typesPerCppFile
		end := start + typesPerCppFile
		if end > len(e.target.Types) {
			end = len(e.target.Types)
		}
		if err := e.emitTypePart(p+1, start, end); err != nil {
			return err
		}
	}
	e.typeParts = parts
	return nil
}

func (e *cppEmitter) emitTypePart(part, start, end int) error {
	name := fmt.Sprintf("types_part_%03d.gen.cpp", part)
	path := filepath.Join(e.outDir, e.fileName(name))
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, fmt.Sprintf("types part %d (%d..%d)", part, start, end-1))
	fmt.Fprintln(w, `#include "refuzz/program/syz/target.hpp"`)
	fmt.Fprintln(w, "#include <utility>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)

	// Pass 1: allocate empty instances and append to `types`.
	fmt.Fprintf(w, "void alloc_types_part_%03d(Target& target, std::vector<Type*>& types) {\n", part)
	fmt.Fprintln(w, "    auto& arena = target.arena();")
	for i := start; i < end; i++ {
		fmt.Fprintf(w, "    types.push_back(arena.make<%s>());\n", cppClassFor(e.target.Types[i]))
	}
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	// Pass 2: fill type-specific fields.
	fmt.Fprintf(w, "void fill_types_part_%03d(Target& target,\n", part)
	fmt.Fprintln(w, "                              const std::vector<ResourceDesc*>& resources,")
	fmt.Fprintln(w, "                              const std::vector<Type*>& types) {")
	for i := start; i < end; i++ {
		e.writeTypeFill(w, i, e.target.Types[i])
	}
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz::generated")
	return nil
}

func (e *cppEmitter) writeTypeFill(w *bufio.Writer, i int, t prog.Type) {
	var sz uint64
	if !t.Varlen() {
		sz = t.Size()
	}

	fmt.Fprintf(w, "    { auto* t = static_cast<%s*>(types[%d]); (void)t;\n", cppClassFor(t), i)
	fmt.Fprintf(w, "      t->set_name(%s);\n", cppQuote(t.Name()))
	fmt.Fprintf(w, "      t->set_size(%duLL); t->set_align(%duLL);\n", sz, t.Alignment())
	fmt.Fprintf(w, "      t->set_optional(%t); t->set_var_len(%t);\n", t.Optional(), t.Varlen())

	switch v := t.(type) {
	case *prog.IntType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_int_kind(%s); t->set_range(%duLL, %duLL); t->set_int_align(%duLL);\n",
			cppIntKind(v.Kind), v.RangeBegin, v.RangeEnd, v.Align)
	case *prog.ConstType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_val(%duLL); t->set_pad(%t);\n", v.Val, v.IsPad)
	case *prog.FlagsType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_vals(%s); t->set_bitmask(%t);\n", cppU64List(v.Vals), v.BitMask)
	case *prog.LenType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_bit_size(%duLL); t->set_offset(%t); t->set_path(%s);\n",
			v.BitSize, v.Offset, cppStringList(v.Path))
	case *prog.ProcType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_values_start(%duLL); t->set_values_per_proc(%duLL);\n",
			v.ValuesStart, v.ValuesPerProc)
	case *prog.CsumType:
		e.writeIntCommon(w, &v.IntTypeCommon)
		fmt.Fprintf(w, "      t->set_csum_kind(%s); t->set_buf(%s); t->set_protocol(%duLL);\n",
			cppCsumKind(v.Kind), cppQuote(v.Buf), v.Protocol)
	case *prog.ResourceType:
		fmt.Fprintf(w, "      t->set_format(%s);\n", cppFormat(v.ArgFormat))
		if id, ok := e.resID[v.Desc]; ok {
			fmt.Fprintf(w, "      t->set_desc(resources[%d]);\n", id)
		}
	case *prog.BufferType:
		fmt.Fprintf(w, "      t->set_buffer_kind(%s); t->set_range(%duLL, %duLL);\n",
			cppBufferKind(v.Kind), v.RangeBegin, v.RangeEnd)
		fmt.Fprintf(w, "      t->set_text_kind(%s); t->set_sub_kind(%s);\n",
			cppTextKind(v.Text), cppQuote(v.SubKind))
		fmt.Fprintf(w, "      t->set_values(%s); t->set_no_z(%t);\n",
			cppStringList(v.Values), v.NoZ)
	case *prog.PtrType:
		fmt.Fprintf(w, "      t->set_elem(%s);\n", e.refToType(v.Elem))
		fmt.Fprintf(w, "      t->set_elem_dir(%s); t->set_squashable_elem(%t);\n",
			cppDir(v.ElemDir), v.SquashableElem)
	case *prog.ArrayType:
		fmt.Fprintf(w, "      t->set_elem(%s);\n", e.refToType(v.Elem))
		fmt.Fprintf(w, "      t->set_array_kind(%s); t->set_range(%duLL, %duLL);\n",
			cppArrayKind(v.Kind), v.RangeBegin, v.RangeEnd)
	case *prog.StructType:
		fmt.Fprintf(w, "      t->set_align_attr(%duLL); t->set_overlay_field(%d);\n",
			v.AlignAttr, v.OverlayField)
		e.writeFieldList(w, v.Fields)
	case *prog.UnionType:
		e.writeFieldList(w, v.Fields)
	case *prog.VmaType:
		fmt.Fprintf(w, "      t->set_range(%duLL, %duLL);\n", v.RangeBegin, v.RangeEnd)
	default:
		fmt.Fprintf(w, "      // unhandled type kind %T\n", t)
	}

	fmt.Fprintln(w, "    }")
}

func (e *cppEmitter) writeIntCommon(w *bufio.Writer, c *prog.IntTypeCommon) {
	fmt.Fprintf(w, "      t->set_format(%s);\n", cppFormat(c.ArgFormat))
	fmt.Fprintf(w, "      t->set_bitfield(%duLL, %duLL, %duLL, %duLL);\n",
		c.BitfieldOff, c.BitfieldLen, c.BitfieldUnit, c.BitfieldUnitOff)
}

func (e *cppEmitter) writeFieldList(w *bufio.Writer, fields []prog.Field) {
	if len(fields) == 0 {
		return
	}
	fmt.Fprintln(w, "      {")
	fmt.Fprintln(w, "        std::vector<Field> fields;")
	fmt.Fprintf(w, "        fields.reserve(%d);\n", len(fields))
	for i := range fields {
		f := &fields[i]
		fmt.Fprintln(w, "        {")
		fmt.Fprintf(w, "          Field fld(%s, %s);\n", cppQuote(f.Name), e.refToType(f.Type))
		if f.HasDirection {
			fmt.Fprintf(w, "          fld.set_direction(%s);\n", cppDir(f.Direction))
		}
		if f.Condition != nil {
			fmt.Fprintf(w, "          fld.set_condition(%s);\n", cppExpr(f.Condition))
		}
		fmt.Fprintln(w, "          fields.push_back(std::move(fld));")
		fmt.Fprintln(w, "        }")
	}
	fmt.Fprintln(w, "        t->set_fields(std::move(fields));")
	fmt.Fprintln(w, "      }")
}

// ============================================================
// Syscalls — split across multiple TUs
// ============================================================

func (e *cppEmitter) emitSyscalls() error {
	parts := (len(e.target.Syscalls) + syscallsPerCppFile - 1) / syscallsPerCppFile
	for p := 0; p < parts; p++ {
		start := p * syscallsPerCppFile
		end := start + syscallsPerCppFile
		if end > len(e.target.Syscalls) {
			end = len(e.target.Syscalls)
		}
		if err := e.emitSyscallPart(p+1, e.target.Syscalls[start:end]); err != nil {
			return err
		}
	}
	e.syscallParts = parts
	return nil
}

func (e *cppEmitter) emitSyscallPart(part int, syscalls []*prog.Syscall) error {
	name := fmt.Sprintf("syscalls_part_%03d.gen.cpp", part)
	path := filepath.Join(e.outDir, e.fileName(name))
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, fmt.Sprintf("syscalls part %d", part))
	fmt.Fprintln(w, `#include "refuzz/program/syz/target.hpp"`)
	fmt.Fprintln(w, "#include <utility>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "void build_syscalls_part_%03d(Target& target, const std::vector<Type*>& types) {\n", part)

	for _, sc := range syscalls {
		e.writeSyscall(w, sc)
	}

	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz::generated")
	return nil
}

func (e *cppEmitter) writeSyscall(w *bufio.Writer, sc *prog.Syscall) {
	fmt.Fprintln(w, "    {")
	fmt.Fprintln(w, "        auto* m = target.add_syscall();")
	fmt.Fprintf(w, "        m->set_name(%s);\n", cppQuote(sc.Name))
	fmt.Fprintf(w, "        m->set_call_name(%s);\n", cppQuote(sc.CallName))
	// For syz_* pseudos, override sc.NR (which upstream sets to 0) with
	// the synthesized pseudoNrBase+i so the worker's wire driver
	// dispatches via ExecuteNrOrPseudo. Real syscalls keep sc.NR. See
	// docs/plans/syzkaller-capability-closure-epic-2.md step 1+2.
	nr := e.effectiveSyscallNR(sc)
	fmt.Fprintf(w, "        m->set_nr(%duLL);\n", nr)
	// [impl-kind removal] No pseudo_impl / capability_mask emitted. Non-
	// fuzzable pseudos carry syz's (disabled) attr (set below) and are
	// gated by the enable/disable whitelist; environment gating lives in
	// control/support, keyed on name. See docs/plans/syscall-support-detection.md.
	fmt.Fprintf(w, "        m->set_missing_args(%d);\n", sc.MissingArgs)

	// SyscallAttrs
	a := sc.Attrs
	fmt.Fprintln(w, "        SyscallAttrs attrs{};")
	fmt.Fprintf(w, "        attrs.disabled=%t; attrs.timeout=%duLL; attrs.prog_timeout=%duLL;\n",
		a.Disabled, a.Timeout, a.ProgTimeout)
	fmt.Fprintf(w, "        attrs.ignore_return=%t; attrs.breaks_returns=%t;\n",
		a.IgnoreReturn, a.BreaksReturns)
	fmt.Fprintf(w, "        attrs.no_generate=%t; attrs.no_minimize=%t; attrs.no_squash=%t;\n",
		a.NoGenerate, a.NoMinimize, a.NoSquash)
	fmt.Fprintf(w, "        attrs.remote_cover=%t; attrs.automatic=%t; attrs.automatic_helper=%t;\n",
		a.RemoteCover, a.Automatic, a.AutomaticHelper)
	fmt.Fprintf(w, "        attrs.snapshot=%t;\n", a.Snapshot)
	fmt.Fprintf(w, "        attrs.kfuzztest=%t;\n", a.KFuzzTest)
	fmt.Fprintf(w, "        attrs.fsck=%s; attrs.filesystem=%s;\n",
		cppQuote(a.Fsck), cppQuote(a.Filesystem))
	fmt.Fprintln(w, "        m->set_attrs(std::move(attrs));")

	// Args
	if len(sc.Args) > 0 {
		fmt.Fprintln(w, "        std::vector<Field> args;")
		fmt.Fprintf(w, "        args.reserve(%d);\n", len(sc.Args))
		for i := range sc.Args {
			f := &sc.Args[i]
			fmt.Fprintln(w, "        {")
			fmt.Fprintf(w, "          Field fld(%s, %s);\n", cppQuote(f.Name), e.refToType(f.Type))
			if f.HasDirection {
				fmt.Fprintf(w, "          fld.set_direction(%s);\n", cppDir(f.Direction))
			}
			if f.Condition != nil {
				fmt.Fprintf(w, "          fld.set_condition(%s);\n", cppExpr(f.Condition))
			}
			fmt.Fprintln(w, "          args.push_back(std::move(fld));")
			fmt.Fprintln(w, "        }")
		}
		fmt.Fprintln(w, "        m->set_args(std::move(args));")
	}

	if sc.Ret != nil {
		fmt.Fprintf(w, "        m->set_ret(%s);\n", e.refToType(sc.Ret))
	}

	fmt.Fprintln(w, "    }")
}

func (e *cppEmitter) effectiveSyscallNR(sc *prog.Syscall) uint64 {
	if pseudoEntry, ok := e.pseudoSynth[sc.Name]; ok {
		return pseudoEntry.NR
	}
	return sc.NR
}

func (e *cppEmitter) emitCallTable(outDir string) error {
	if outDir == "" {
		outDir = defaultCallTableOutDir
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	name := fmt.Sprintf("target_%s_%s_call_table.gen.hpp", e.target.OS, e.target.Arch)
	path := filepath.Join(outDir, name)
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, "worker lite call_id-to-nr table")
	fmt.Fprintln(w, "#pragma once")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "#include <cstddef>")
	fmt.Fprintln(w, "#include <cstdint>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "inline constexpr std::uint64_t k%s%sDataOffset = %duLL;\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch),
		e.target.DataOffset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "inline constexpr std::uint64_t k%s%sCallIdToNr[] = {\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	for i, sc := range e.target.Syscalls {
		fmt.Fprintf(w, "    %duLL,", e.effectiveSyscallNR(sc))
		fmt.Fprintf(w, " // %5d %s\n", i, sc.Name)
	}
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w)

	// [threaded per-call timeout parity] Per-call timeout attributes, indexed
	// by call_id (same order as kCallIdToNr). Mirror of syzkaller
	// prog.Syscall.Attrs.{Timeout,ProgTimeout}, used by the threaded worker to
	// size each call's wait: upstream executor.cc:1103 computes the per-call
	// wait as `syscall_timeout_ms + call->attrs.timeout * slowdown_scale`. A
	// flat per-call timeout cannot serve both heavy calls (syz_mount_image$* =
	// SYZ_MOUNT_IMAGE_TIMEOUT=4000ms) and fast blocking calls (FUSE = 0, must
	// yield to its handler at the base timeout) — hence this table. Values are
	// in milliseconds, exactly as emitted by the descriptions (slowdown=1 in
	// the KVM-accelerated QEMU parity config, so the worker uses them as-is and
	// multiplies by its own slowdown if/when that is wired up).
	fmt.Fprintf(w, "inline constexpr std::uint32_t k%s%sCallTimeoutMs[] = {\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	for i, sc := range e.target.Syscalls {
		fmt.Fprintf(w, "    %du,", sc.Attrs.Timeout)
		fmt.Fprintf(w, " // %5d %s\n", i, sc.Name)
	}
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "inline constexpr std::uint32_t k%s%sCallProgTimeoutMs[] = {\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	for i, sc := range e.target.Syscalls {
		fmt.Fprintf(w, "    %du,", sc.Attrs.ProgTimeout)
		fmt.Fprintf(w, " // %5d %s\n", i, sc.Name)
	}
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w)

	// [remote-kcov R2] Per-call `remote_cover` attribute, indexed by call_id
	// (same order as kCallIdToNr). Mirror of syzkaller prog.Syscall.Attrs.
	// RemoteCover. A call with this flag produces coverage in a kthread/softirq
	// that lands ASYNC after the syscall returns (USB-core khubd enumeration /
	// class-driver probe, RX softirq, usbip). The threaded worker reads this to
	// mark the program (KcovSink::SetProgramUsesRemoteCover) so the task-end
	// extra-remote-KCOV settle loop re-drains for the async coverage instead of
	// dropping it when the first drain is empty. Data-driven: no hardcoded
	// call-id list in the driver.
	fmt.Fprintf(w, "inline constexpr bool k%s%sCallRemoteCover[] = {\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	for i, sc := range e.target.Syscalls {
		fmt.Fprintf(w, "    %t,", sc.Attrs.RemoteCover)
		fmt.Fprintf(w, " // %5d %s\n", i, sc.Name)
	}
	fmt.Fprintln(w, "};")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "inline constexpr std::size_t k%s%sCallCount =\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	fmt.Fprintf(w, "    sizeof(k%s%sCallIdToNr) / sizeof(k%s%sCallIdToNr[0]);\n",
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch),
		cppIdentTitle(e.target.OS), cppIdentTitle(e.target.Arch))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz::generated")
	return nil
}

// ============================================================
// Metadata — class-A target-level schema fields (Consts/Flags/
// SpecialPointers/SpecialFileLenghts/AuxResources). Emitted into
// a separate TU to keep main.gen.cpp lean.
// ============================================================

func (e *cppEmitter) emitMetadata() error {
	path := filepath.Join(e.outDir, e.fileName("metadata.gen.cpp"))
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, "target-level metadata (consts/flags/special pointers/...)")
	fmt.Fprintln(w, `#include "refuzz/program/syz/target.hpp"`)
	fmt.Fprintln(w, "#include <utility>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "void build_metadata(Target& target) {")

	// Consts
	fmt.Fprintln(w, "    {")
	fmt.Fprintln(w, "        std::vector<ConstValue> consts;")
	fmt.Fprintf(w, "        consts.reserve(%d);\n", len(e.target.Consts))
	for _, c := range e.target.Consts {
		fmt.Fprintf(w, "        consts.push_back(ConstValue{%s, %duLL});\n",
			cppQuote(c.Name), c.Value)
	}
	fmt.Fprintln(w, "        target.set_consts(std::move(consts));")
	fmt.Fprintln(w, "    }")

	// Flags
	fmt.Fprintln(w, "    {")
	fmt.Fprintln(w, "        std::vector<FlagDesc> flag_descs;")
	fmt.Fprintf(w, "        flag_descs.reserve(%d);\n", len(e.target.Flags))
	for _, f := range e.target.Flags {
		fmt.Fprintln(w, "        {")
		fmt.Fprintf(w, "          FlagDesc fd; fd.name = %s; fd.values = %s;\n",
			cppQuote(f.Name), cppStringList(f.Values))
		fmt.Fprintln(w, "          flag_descs.push_back(std::move(fd));")
		fmt.Fprintln(w, "        }")
	}
	fmt.Fprintln(w, "        target.set_flag_descs(std::move(flag_descs));")
	fmt.Fprintln(w, "    }")

	// SpecialPointers
	fmt.Fprintf(w, "    target.set_special_pointers(%s);\n", cppU64List(e.target.SpecialPointers))

	// SpecialFileLenghts (Go []int — emit as int64_t since Go int is 64-bit on amd64).
	fmt.Fprint(w, "    target.set_special_file_lengths(std::vector<int64_t>{")
	for i, ln := range e.target.SpecialFileLenghts {
		if i != 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "%dLL", ln)
	}
	fmt.Fprintln(w, "});")

	// AuxResources (Go map[string]bool — emit sorted keys for determinism).
	auxNames := make([]string, 0, len(e.target.AuxResources))
	for k := range e.target.AuxResources {
		auxNames = append(auxNames, k)
	}
	sortStrings(auxNames)
	fmt.Fprintf(w, "    target.set_aux_resources(%s);\n", cppStringList(auxNames))

	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz::generated")
	return nil
}

// ============================================================
// Main entry point
// ============================================================

func (e *cppEmitter) emitMain() error {
	path := filepath.Join(e.outDir, e.fileName("main.gen.cpp"))
	w, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()

	cppHeader(w, "main entry")
	fmt.Fprintln(w, `#include "refuzz/program/syz/target.hpp"`)
	fmt.Fprintln(w, "#include <memory>")
	fmt.Fprintln(w, "#include <vector>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz::generated {")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "void build_resources(Target& target, std::vector<ResourceDesc*>& resources_out);")
	fmt.Fprintln(w, "void build_metadata(Target& target);")
	for p := 1; p <= e.typeParts; p++ {
		fmt.Fprintf(w, "void alloc_types_part_%03d(Target& target, std::vector<Type*>& types);\n", p)
		fmt.Fprintf(w, "void fill_types_part_%03d(Target& target, const std::vector<ResourceDesc*>& resources, const std::vector<Type*>& types);\n", p)
	}
	for p := 1; p <= e.syscallParts; p++ {
		fmt.Fprintf(w, "void build_syscalls_part_%03d(Target& target, const std::vector<Type*>& types);\n", p)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace generated")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "namespace refuzz::program::syz {")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "const Target& Target::linux_amd64() {")
	fmt.Fprintln(w, "    static const Target& kTarget = []() -> const Target& {")
	fmt.Fprintln(w, "        static Target target(\"linux\", \"amd64\");")
	fmt.Fprintf(w, "        target.set_revision(%s);\n", cppQuote(e.target.Revision))
	fmt.Fprintf(w, "        target.set_ptr_size(%duLL);\n", e.target.PtrSize)
	fmt.Fprintf(w, "        target.set_page_size(%duLL);\n", e.target.PageSize)
	fmt.Fprintf(w, "        target.set_num_pages(%duLL);\n", e.target.NumPages)
	fmt.Fprintf(w, "        target.set_data_offset(%duLL);\n", e.target.DataOffset)
	fmt.Fprintf(w, "        target.set_big_endian(%t);\n", e.target.BigEndian)
	fmt.Fprintln(w, "        std::vector<ResourceDesc*> resources;")
	fmt.Fprintln(w, "        std::vector<Type*> types;")
	fmt.Fprintf(w, "        types.reserve(%d);\n", len(e.target.Types))
	fmt.Fprintln(w, "        generated::build_resources(target, resources);")
	fmt.Fprintln(w, "        generated::build_metadata(target);")
	for p := 1; p <= e.typeParts; p++ {
		fmt.Fprintf(w, "        generated::alloc_types_part_%03d(target, types);\n", p)
	}
	for p := 1; p <= e.typeParts; p++ {
		fmt.Fprintf(w, "        generated::fill_types_part_%03d(target, resources, types);\n", p)
	}
	for p := 1; p <= e.syscallParts; p++ {
		fmt.Fprintf(w, "        generated::build_syscalls_part_%03d(target, types);\n", p)
	}
	fmt.Fprintln(w, "        target.finalize();")
	fmt.Fprintln(w, "        return target;")
	fmt.Fprintln(w, "    }();")
	fmt.Fprintln(w, "    return kTarget;")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "} // namespace refuzz::program::syz")
	return nil
}

// ============================================================
// Helpers
// ============================================================

func openWriter(path string) (*bufio.Writer, func(), error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", path, err)
	}
	w := bufio.NewWriter(f)
	closer := func() {
		_ = w.Flush()
		_ = f.Close()
	}
	return w, closer, nil
}

func (e *cppEmitter) fileName(suffix string) string {
	return fmt.Sprintf("target_%s_%s_%s", e.target.OS, e.target.Arch, suffix)
}

func cppIdentTitle(s string) string {
	var b strings.Builder
	capNext := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if capNext && r >= 'a' && r <= 'z' {
				r = r - 'a' + 'A'
			}
			b.WriteRune(r)
			capNext = false
			continue
		}
		capNext = true
	}
	return b.String()
}

func cppHeader(w *bufio.Writer, role string) {
	fmt.Fprintln(w, "// AUTO-GENERATED by tools/syzgen target-cpp -- DO NOT EDIT")
	fmt.Fprintf(w, "// Role: %s\n", role)
	fmt.Fprintln(w)
}

// cppQuote turns a Go string into a C++ std::string ctor expression with
// an explicit length. The explicit length avoids std::string's
// const char* ctor truncating at embedded NUL bytes — important because
// many BufferType.Values entries are NUL-padded fixed-size byte arrays.
//
// Non-printable bytes are emitted as 3-digit octal escapes. Octal escapes
// have a max length of 3 digits, so they don't suffer from the greedy
// hex-escape ambiguity (e.g. "\x158" being parsed as 0x158 instead of
// 0x15 followed by '8').
func cppQuote(s string) string {
	var b strings.Builder
	b.WriteString(`std::string("`)
	for _, r := range []byte(s) {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r >= 0x7f {
				// 3-digit octal: unambiguous regardless of next char.
				fmt.Fprintf(&b, `\%03o`, r)
			} else {
				b.WriteByte(r)
			}
		}
	}
	fmt.Fprintf(&b, `", %d)`, len(s))
	return b.String()
}

func cppU64List(vs []uint64) string {
	if len(vs) == 0 {
		return "std::vector<uint64_t>{}"
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%duLL", v)
	}
	return fmt.Sprintf("std::vector<uint64_t>{%s}", strings.Join(parts, ", "))
}

func cppStringList(vs []string) string {
	if len(vs) == 0 {
		return "std::vector<std::string>{}"
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = cppQuote(v)
	}
	return fmt.Sprintf("std::vector<std::string>{%s}", strings.Join(parts, ", "))
}

func cppDir(d prog.Dir) string {
	switch d {
	case prog.DirIn:
		return "Dir::kIn"
	case prog.DirOut:
		return "Dir::kOut"
	case prog.DirInOut:
		return "Dir::kInOut"
	}
	return "Dir::kIn"
}

func cppFormat(f prog.BinaryFormat) string {
	switch f {
	case prog.FormatNative:
		return "BinaryFormat::kNative"
	case prog.FormatBigEndian:
		return "BinaryFormat::kBigEndian"
	case prog.FormatStrDec:
		return "BinaryFormat::kStrDec"
	case prog.FormatStrHex:
		return "BinaryFormat::kStrHex"
	case prog.FormatStrOct:
		return "BinaryFormat::kStrOct"
	}
	return "BinaryFormat::kNative"
}

func cppIntKind(k prog.IntKind) string {
	if k == prog.IntRange {
		return "IntType::Kind::kRange"
	}
	return "IntType::Kind::kPlain"
}

func cppCsumKind(k prog.CsumKind) string {
	if k == prog.CsumPseudo {
		return "CsumKind::kPseudo"
	}
	return "CsumKind::kInet"
}

func cppBufferKind(k prog.BufferKind) string {
	switch k {
	case prog.BufferBlobRand:
		return "BufferKind::kBlobRand"
	case prog.BufferBlobRange:
		return "BufferKind::kBlobRange"
	case prog.BufferString:
		return "BufferKind::kString"
	case prog.BufferFilename:
		return "BufferKind::kFilename"
	case prog.BufferText:
		return "BufferKind::kText"
	case prog.BufferGlob:
		return "BufferKind::kGlob"
	case prog.BufferCompressed:
		return "BufferKind::kCompressed"
	}
	return "BufferKind::kBlobRand"
}

func cppTextKind(k prog.TextKind) string {
	switch k {
	case prog.TextTarget:
		return "TextKind::kTarget"
	case prog.TextX86Real:
		return "TextKind::kX86Real"
	case prog.TextX86bit16:
		return "TextKind::kX86bit16"
	case prog.TextX86bit32:
		return "TextKind::kX86bit32"
	case prog.TextX86bit64:
		return "TextKind::kX86bit64"
	case prog.TextArm64:
		return "TextKind::kArm64"
	case prog.TextPpc64:
		return "TextKind::kPpc64"
	}
	return "TextKind::kTarget"
}

func cppArrayKind(k prog.ArrayKind) string {
	if k == prog.ArrayRangeLen {
		return "ArrayKind::kRangeLen"
	}
	return "ArrayKind::kRandLen"
}

func cppClassFor(t prog.Type) string {
	switch t.(type) {
	case *prog.IntType:
		return "IntType"
	case *prog.ConstType:
		return "ConstType"
	case *prog.FlagsType:
		return "FlagsType"
	case *prog.LenType:
		return "LenType"
	case *prog.ProcType:
		return "ProcType"
	case *prog.CsumType:
		return "CsumType"
	case *prog.ResourceType:
		return "ResourceType"
	case *prog.BufferType:
		return "BufferType"
	case *prog.PtrType:
		return "PtrType"
	case *prog.ArrayType:
		return "ArrayType"
	case *prog.StructType:
		return "StructType"
	case *prog.UnionType:
		return "UnionType"
	case *prog.VmaType:
		return "VmaType"
	}
	panic(fmt.Sprintf("unknown prog.Type %T", t))
}

func (e *cppEmitter) refToType(t prog.Type) string {
	if t == nil {
		return "nullptr"
	}
	if id, ok := e.typeID[t]; ok {
		return fmt.Sprintf("types[%d]", id)
	}
	// prog.Ref placeholder shouldn't appear in finalized target.Types.
	return "nullptr"
}

func cppExpr(e prog.Expression) string {
	if e == nil {
		return "nullptr"
	}
	switch v := e.(type) {
	case *prog.Value:
		return cppValueExpr(v)
	case *prog.BinaryExpression:
		return cppBinaryExpr(v)
	}
	return "nullptr"
}

func cppValueExpr(v *prog.Value) string {
	return fmt.Sprintf(
		`[]{ auto p = std::make_unique<ValueExpr>(); p->set_value(%duLL); p->set_path(%s); return p; }()`,
		v.Value, cppStringList(v.Path))
}

func cppBinaryExpr(b *prog.BinaryExpression) string {
	op := "BinaryOperator::kCompareEq"
	switch b.Operator {
	case prog.OperatorCompareEq:
		op = "BinaryOperator::kCompareEq"
	case prog.OperatorCompareNeq:
		op = "BinaryOperator::kCompareNeq"
	case prog.OperatorBinaryAnd:
		op = "BinaryOperator::kBinaryAnd"
	case prog.OperatorOr:
		op = "BinaryOperator::kOr"
	}
	return fmt.Sprintf(
		`[]{ auto p = std::make_unique<BinaryExpression>(); p->set_op(%s); p->set_left(%s); p->set_right(%s); return p; }()`,
		op, cppExpr(b.Left), cppExpr(b.Right))
}
