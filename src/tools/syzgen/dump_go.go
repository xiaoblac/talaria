// Go-side structural dumper for prog.Target.
//
// Produces output byte-for-byte identical to refuzz-syz-v2-dump (C++) so
// the two can be diff'd as proof of structural parity:
//
//   /tmp/syzgen-test dump-go -os linux -arch amd64 -syzkaller-root ... > /tmp/go.txt
//   build-llvm20/refuzz-syz-v2-dump > /tmp/cpp.txt
//   diff /tmp/go.txt /tmp/cpp.txt   # expected: empty
//
// Any drift means the C++ IR differs from syzkaller's prog.Target.

package main

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

// Probes match refuzz_syz_v2_dump exactly; keep in sync.
var dumpProbes = []string{
	"read", "write", "readv", "writev", "openat", "close",
	"socket$inet", "bind$inet", "connect$inet",
	"ioctl", "mmap", "munmap",
	"syz_open_dev$loop", "syz_genetlink_get_family_id$nl80211",
}

func runDumpGo(target *prog.Target, _ options) error {
	printGoSummary(target)
	printGoHistogram(target)

	fmt.Println()
	fmt.Println("[probes]")
	for _, name := range dumpProbes {
		sc, ok := target.SyscallMap[name]
		if !ok {
			fmt.Printf("MISSING: %s\n", name)
			continue
		}
		printGoSyscallSignature(sc)
	}

	if sc, ok := target.SyscallMap["readv"]; ok {
		fmt.Println()
		fmt.Println("[deep dump: readv]")
		for i := range sc.Args {
			f := &sc.Args[i]
			fmt.Printf("arg[%d] %s:\n", i, f.Name)
			seen := make(map[prog.Type]bool)
			printGoTypeRecursive(f.Type, 1, seen)
		}
	}
	return nil
}

func printGoSummary(t *prog.Target) {
	fmt.Printf("os=%s\n", t.OS)
	fmt.Printf("arch=%s\n", t.Arch)
	fmt.Printf("revision=%s\n", t.Revision)
	fmt.Printf("ptr_size=%d\n", t.PtrSize)
	fmt.Printf("page_size=%d\n", t.PageSize)
	fmt.Printf("num_pages=%d\n", t.NumPages)
	fmt.Printf("type_count=%d\n", len(t.Types))
	fmt.Printf("syscall_count=%d\n", len(t.Syscalls))
	fmt.Printf("resource_count=%d\n", len(t.Resources))
}

func printGoHistogram(t *prog.Target) {
	order := []string{
		"Int", "Const", "Flags", "Proc", "Len", "Csum",
		"Resource", "Buffer", "Ptr", "Array", "Struct", "Union", "Vma",
	}
	counts := map[string]int{}
	for _, ty := range t.Types {
		counts[goKindName(ty)]++
	}
	fmt.Println()
	fmt.Println("[type kind histogram]")
	for _, k := range order {
		fmt.Printf("  %-10s = %d\n", k, counts[k])
	}
}

func printGoSyscallSignature(sc *prog.Syscall) {
	fmt.Printf("syscall %s (nr=%d, missing_args=%d, args=%d)\n",
		sc.Name, sc.NR, sc.MissingArgs, len(sc.Args))
	for i := range sc.Args {
		f := &sc.Args[i]
		cond := ""
		if f.Condition != nil {
			cond = " [cond]"
		}
		fmt.Printf("  arg[%d] %s : %s/%s dir=%s%s\n",
			i, f.Name, goKindName(f.Type), f.Type.Name(),
			goDirName(f.Dir(prog.DirIn)), cond)
	}
	if sc.Ret != nil {
		fmt.Printf("  ret: %s/%s\n", goKindName(sc.Ret), sc.Ret.Name())
	} else {
		fmt.Println("  ret: (none)")
	}
}

func printGoTypeRecursive(t prog.Type, depth int, seen map[prog.Type]bool) {
	indent := func() {
		for i := 0; i < depth; i++ {
			fmt.Print("  ")
		}
	}
	if t == nil {
		indent()
		fmt.Println("<null>")
		return
	}

	// Mirror C++ codegen: set_size(0) for varlen types.
	var size uint64
	if !t.Varlen() {
		size = t.Size()
	}

	indent()
	fmt.Printf("%s/%s [size=%d align=%d opt=%d varlen=%d]",
		goKindName(t), t.Name(), size, t.Alignment(),
		boolInt(t.Optional()), boolInt(t.Varlen()))

	switch v := t.(type) {
	case *prog.StructType:
		fmt.Printf(" fields=%d align_attr=%d overlay=%d\n",
			len(v.Fields), v.AlignAttr, v.OverlayField)
		if seen[t] {
			indent()
			fmt.Println("  ...(seen)")
			return
		}
		seen[t] = true
		for _, f := range v.Fields {
			indent()
			cond := ""
			if f.Condition != nil {
				cond = " [cond]"
			}
			fmt.Printf("  field %s%s:\n", f.Name, cond)
			printGoTypeRecursive(f.Type, depth+2, seen)
		}
	case *prog.UnionType:
		conditional := len(v.Fields) > 0 && v.Fields[0].Condition != nil
		fmt.Printf(" fields=%d cond=%d\n", len(v.Fields), boolInt(conditional))
		if seen[t] {
			indent()
			fmt.Println("  ...(seen)")
			return
		}
		seen[t] = true
		for _, f := range v.Fields {
			indent()
			cond := ""
			if f.Condition != nil {
				cond = " [cond]"
			}
			fmt.Printf("  arm %s%s:\n", f.Name, cond)
			printGoTypeRecursive(f.Type, depth+2, seen)
		}
	case *prog.PtrType:
		fmt.Printf(" elem_dir=%s sq=%d\n",
			goDirName(v.ElemDir), boolInt(v.SquashableElem))
		printGoTypeRecursive(v.Elem, depth+1, seen)
	case *prog.ArrayType:
		fmt.Printf(" range=[%d,%d] kind=%d\n",
			v.RangeBegin, v.RangeEnd, int(v.Kind))
		printGoTypeRecursive(v.Elem, depth+1, seen)
	case *prog.BufferType:
		fmt.Printf(" buf_kind=%d sub=%s vals=%d noz=%d\n",
			int(v.Kind), v.SubKind, len(v.Values), boolInt(v.NoZ))
	case *prog.IntType:
		fmt.Printf(" range=[%d,%d]\n", v.RangeBegin, v.RangeEnd)
	case *prog.ConstType:
		fmt.Printf(" val=%d pad=%d\n", v.Val, boolInt(v.IsPad))
	case *prog.FlagsType:
		fmt.Printf(" vals=%d bitmask=%d\n", len(v.Vals), boolInt(v.BitMask))
	case *prog.LenType:
		fmt.Printf(" path=[%s] bit_size=%d offset=%d\n",
			strings.Join(v.Path, ","), v.BitSize, boolInt(v.Offset))
	case *prog.ResourceType:
		name := "(null)"
		if v.Desc != nil {
			name = v.Desc.Name
		}
		fmt.Printf(" res=%s\n", name)
	case *prog.CsumType:
		fmt.Printf(" csum_kind=%d buf=%s proto=%d\n",
			int(v.Kind), v.Buf, v.Protocol)
	case *prog.ProcType:
		fmt.Printf(" start=%d per_proc=%d\n",
			v.ValuesStart, v.ValuesPerProc)
	case *prog.VmaType:
		fmt.Printf(" range=[%d,%d] pages\n",
			v.RangeBegin, v.RangeEnd)
	default:
		fmt.Println()
	}
}

func goKindName(t prog.Type) string {
	switch t.(type) {
	case *prog.IntType:
		return "Int"
	case *prog.ConstType:
		return "Const"
	case *prog.FlagsType:
		return "Flags"
	case *prog.ProcType:
		return "Proc"
	case *prog.LenType:
		return "Len"
	case *prog.CsumType:
		return "Csum"
	case *prog.ResourceType:
		return "Resource"
	case *prog.BufferType:
		return "Buffer"
	case *prog.PtrType:
		return "Ptr"
	case *prog.ArrayType:
		return "Array"
	case *prog.StructType:
		return "Struct"
	case *prog.UnionType:
		return "Union"
	case *prog.VmaType:
		return "Vma"
	}
	return "?"
}

func goDirName(d prog.Dir) string {
	switch d {
	case prog.DirIn:
		return "in"
	case prog.DirOut:
		return "out"
	case prog.DirInOut:
		return "inout"
	}
	return "?"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
