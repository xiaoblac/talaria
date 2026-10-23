// L1 full field-level oracle dump.
//
// Enumerates every Type, ResourceDesc, and Syscall in prog.Target with all
// fields in deterministic order. The C++ side (refuzz-syz-v2-enum) emits
// the same format. A byte-level diff between them proves the v2 IR has
// zero structural drift from syzkaller pkg/prog at the schema layer.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

func runEnumDump(target *prog.Target, _ options) error {
	typeID := make(map[prog.Type]int, len(target.Types))
	for i, t := range target.Types {
		typeID[t] = i
	}
	resID := make(map[*prog.ResourceDesc]int, len(target.Resources))
	for i, r := range target.Resources {
		resID[r] = i
	}

	fmt.Println("==target==")
	fmt.Printf("os=%s\n", target.OS)
	fmt.Printf("arch=%s\n", target.Arch)
	fmt.Printf("revision=%s\n", target.Revision)
	fmt.Printf("ptr_size=%d\n", target.PtrSize)
	fmt.Printf("page_size=%d\n", target.PageSize)
	fmt.Printf("num_pages=%d\n", target.NumPages)
	fmt.Printf("data_offset=%d\n", target.DataOffset)
	fmt.Printf("big_endian=%d\n", boolInt(target.BigEndian))
	fmt.Printf("type_count=%d\n", len(target.Types))
	fmt.Printf("syscall_count=%d\n", len(target.Syscalls))
	fmt.Printf("resource_count=%d\n", len(target.Resources))

	fmt.Println("==consts==")
	fmt.Printf("count=%d\n", len(target.Consts))
	for i, c := range target.Consts {
		fmt.Printf("const %d: name=%s value=%d\n", i, c.Name, c.Value)
	}

	fmt.Println("==flags==")
	fmt.Printf("count=%d\n", len(target.Flags))
	for i, f := range target.Flags {
		fmt.Printf("flag %d: name=%s values=%s\n", i, f.Name,
			strings.Join(f.Values, "\x1f"))
	}

	fmt.Println("==special_pointers==")
	fmt.Printf("count=%d\n", len(target.SpecialPointers))
	for i, p := range target.SpecialPointers {
		fmt.Printf("special_ptr %d: %d\n", i, p)
	}

	fmt.Println("==special_file_lengths==")
	fmt.Printf("count=%d\n", len(target.SpecialFileLenghts))
	for i, n := range target.SpecialFileLenghts {
		fmt.Printf("special_file_len %d: %d\n", i, n)
	}

	fmt.Println("==aux_resources==")
	auxNames := make([]string, 0, len(target.AuxResources))
	for k := range target.AuxResources {
		auxNames = append(auxNames, k)
	}
	sort.Strings(auxNames)
	fmt.Printf("count=%d\n", len(auxNames))
	for i, n := range auxNames {
		fmt.Printf("aux %d: %s\n", i, n)
	}

	fmt.Println("==resources==")
	for i, r := range target.Resources {
		dumpResourceFull(i, r)
	}

	fmt.Println("==types==")
	for i, t := range target.Types {
		dumpTypeFull(i, t, typeID, resID)
	}

	// Epic 2 step-1: typed Target's SyscallMeta::nr now carries the
	// synthesized pseudoNrBase+i for syz_* (sc.NR upstream stays 0).
	// L1 enum oracle compares Go vs C++ byte-equal, so we must emit
	// the same synthesized NR here. Both emitters consume the same
	// SynthesizePseudoNRs helper (tools/syzgen/pseudo_synthesis.go),
	// so byte equality is guaranteed.
	pseudoSynth := SynthesizePseudoNRs(target)

	fmt.Println("==syscalls==")
	for i, sc := range target.Syscalls {
		dumpSyscallFull(i, sc, typeID, pseudoSynth)
	}
	return nil
}


func sizeOf(t prog.Type) uint64 {
	if t.Varlen() {
		return 0
	}
	return t.Size()
}

func dumpResourceFull(i int, r *prog.ResourceDesc) {
	fmt.Printf("resource %d:\n", i)
	fmt.Printf("  name=%s\n", r.Name)
	fmt.Printf("  kind=%s\n", strings.Join(r.Kind, ","))
	fmt.Printf("  values=%s\n", joinUints(r.Values))
}

func dumpTypeFull(i int, t prog.Type, typeID map[prog.Type]int, resID map[*prog.ResourceDesc]int) {
	fmt.Printf("type %d:\n", i)
	fmt.Printf("  kind=%s\n", goKindName(t))
	fmt.Printf("  name=%s\n", t.Name())
	fmt.Printf("  size=%d\n", sizeOf(t))
	fmt.Printf("  align=%d\n", t.Alignment())
	fmt.Printf("  optional=%d\n", boolInt(t.Optional()))
	fmt.Printf("  varlen=%d\n", boolInt(t.Varlen()))

	switch v := t.(type) {
	case *prog.IntType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  int_kind=%d\n", int(v.Kind))
		fmt.Printf("  range_begin=%d\n", v.RangeBegin)
		fmt.Printf("  range_end=%d\n", v.RangeEnd)
		fmt.Printf("  int_align=%d\n", v.Align)
	case *prog.ConstType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  val=%d\n", v.Val)
		fmt.Printf("  is_pad=%d\n", boolInt(v.IsPad))
	case *prog.FlagsType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  vals=%s\n", joinUints(v.Vals))
		fmt.Printf("  bitmask=%d\n", boolInt(v.BitMask))
	case *prog.LenType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  bit_size=%d\n", v.BitSize)
		fmt.Printf("  offset=%d\n", boolInt(v.Offset))
		fmt.Printf("  path=%s\n", strings.Join(v.Path, ","))
	case *prog.ProcType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  values_start=%d\n", v.ValuesStart)
		fmt.Printf("  values_per_proc=%d\n", v.ValuesPerProc)
	case *prog.CsumType:
		dumpIntCommon(&v.IntTypeCommon)
		fmt.Printf("  csum_kind=%d\n", int(v.Kind))
		fmt.Printf("  buf=%s\n", v.Buf)
		fmt.Printf("  protocol=%d\n", v.Protocol)
	case *prog.ResourceType:
		fmt.Printf("  format=%d\n", int(v.ArgFormat))
		id := -1
		if v.Desc != nil {
			id = resID[v.Desc]
		}
		fmt.Printf("  desc=%d\n", id)
	case *prog.BufferType:
		fmt.Printf("  buffer_kind=%d\n", int(v.Kind))
		fmt.Printf("  range_begin=%d\n", v.RangeBegin)
		fmt.Printf("  range_end=%d\n", v.RangeEnd)
		fmt.Printf("  text_kind=%d\n", int(v.Text))
		fmt.Printf("  sub_kind=%s\n", v.SubKind)
		fmt.Printf("  values=%s\n", strings.Join(v.Values, "\x1f"))
		fmt.Printf("  no_z=%d\n", boolInt(v.NoZ))
	case *prog.PtrType:
		fmt.Printf("  elem=%d\n", typeRefID(v.Elem, typeID))
		fmt.Printf("  elem_dir=%d\n", int(v.ElemDir))
		fmt.Printf("  squashable_elem=%d\n", boolInt(v.SquashableElem))
	case *prog.ArrayType:
		fmt.Printf("  elem=%d\n", typeRefID(v.Elem, typeID))
		fmt.Printf("  array_kind=%d\n", int(v.Kind))
		fmt.Printf("  range_begin=%d\n", v.RangeBegin)
		fmt.Printf("  range_end=%d\n", v.RangeEnd)
	case *prog.StructType:
		fmt.Printf("  align_attr=%d\n", v.AlignAttr)
		fmt.Printf("  overlay_field=%d\n", v.OverlayField)
		fmt.Printf("  fields=%d\n", len(v.Fields))
		for fi, f := range v.Fields {
			dumpFieldFull(fi, &f, typeID)
		}
	case *prog.UnionType:
		fmt.Printf("  fields=%d\n", len(v.Fields))
		for fi, f := range v.Fields {
			dumpFieldFull(fi, &f, typeID)
		}
	case *prog.VmaType:
		fmt.Printf("  range_begin=%d\n", v.RangeBegin)
		fmt.Printf("  range_end=%d\n", v.RangeEnd)
	}
}

func dumpIntCommon(c *prog.IntTypeCommon) {
	fmt.Printf("  format=%d\n", int(c.ArgFormat))
	fmt.Printf("  bf_off=%d\n", c.BitfieldOff)
	fmt.Printf("  bf_len=%d\n", c.BitfieldLen)
	fmt.Printf("  bf_unit=%d\n", c.BitfieldUnit)
	fmt.Printf("  bf_unit_off=%d\n", c.BitfieldUnitOff)
}

func dumpFieldFull(i int, f *prog.Field, typeID map[prog.Type]int) {
	fmt.Printf("    field %d:\n", i)
	fmt.Printf("      name=%s\n", f.Name)
	fmt.Printf("      type=%d\n", typeRefID(f.Type, typeID))
	fmt.Printf("      has_dir=%d\n", boolInt(f.HasDirection))
	fmt.Printf("      dir=%d\n", int(f.Direction))
	if f.Condition == nil {
		fmt.Printf("      cond=none\n")
	} else {
		fmt.Printf("      cond=%s\n", exprDigest(f.Condition))
	}
}

func dumpSyscallFull(i int, sc *prog.Syscall, typeID map[prog.Type]int,
	pseudoSynth map[string]PseudoSynthEntry) {
	nr := sc.NR
	if entry, ok := pseudoSynth[sc.Name]; ok {
		nr = entry.NR
	}
	fmt.Printf("syscall %d:\n", i)
	fmt.Printf("  name=%s\n", sc.Name)
	fmt.Printf("  call_name=%s\n", sc.CallName)
	fmt.Printf("  nr=%d\n", nr)
	fmt.Printf("  missing_args=%d\n", sc.MissingArgs)
	a := sc.Attrs
	fmt.Printf("  attr_disabled=%d\n", boolInt(a.Disabled))
	fmt.Printf("  attr_timeout=%d\n", a.Timeout)
	fmt.Printf("  attr_prog_timeout=%d\n", a.ProgTimeout)
	fmt.Printf("  attr_ignore_return=%d\n", boolInt(a.IgnoreReturn))
	fmt.Printf("  attr_breaks_returns=%d\n", boolInt(a.BreaksReturns))
	fmt.Printf("  attr_no_generate=%d\n", boolInt(a.NoGenerate))
	fmt.Printf("  attr_no_minimize=%d\n", boolInt(a.NoMinimize))
	fmt.Printf("  attr_no_squash=%d\n", boolInt(a.NoSquash))
	fmt.Printf("  attr_remote_cover=%d\n", boolInt(a.RemoteCover))
	fmt.Printf("  attr_automatic=%d\n", boolInt(a.Automatic))
	fmt.Printf("  attr_automatic_helper=%d\n", boolInt(a.AutomaticHelper))
	fmt.Printf("  attr_kfuzztest=%d\n", boolInt(a.KFuzzTest))
	fmt.Printf("  attr_fsck=%s\n", a.Fsck)
	fmt.Printf("  attr_filesystem=%s\n", a.Filesystem)
	fmt.Printf("  args=%d\n", len(sc.Args))
	for fi, f := range sc.Args {
		dumpFieldFull(fi, &f, typeID)
	}
	if sc.Ret == nil {
		fmt.Printf("  ret=none\n")
	} else {
		fmt.Printf("  ret=%d\n", typeRefID(sc.Ret, typeID))
	}
}

func typeRefID(t prog.Type, typeID map[prog.Type]int) int {
	if t == nil {
		return -1
	}
	id, ok := typeID[t]
	if !ok {
		return -2
	}
	return id
}

func joinUints(vs []uint64) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}

// exprDigest returns a stable serialization of a Condition expression so
// the C++ side can produce the byte-equal string.
func exprDigest(e prog.Expression) string {
	switch v := e.(type) {
	case *prog.Value:
		return fmt.Sprintf("Value(%d,%s)", v.Value, strings.Join(v.Path, "."))
	case *prog.BinaryExpression:
		return fmt.Sprintf("Binary(%d,%s,%s)", int(v.Operator),
			exprDigest(v.Left), exprDigest(v.Right))
	}
	return "?"
}
