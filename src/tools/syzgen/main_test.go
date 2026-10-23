package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func testTarget() *prog.Target {
	return &prog.Target{OS: "test", Arch: "amd64"}
}

func testWriter(t *testing.T, target *prog.Target) *writer {
	t.Helper()
	dir := t.TempDir()
	return newWriter(target, dir, dir)
}

func testIntType(name string) *prog.IntType {
	return &prog.IntType{
		IntTypeCommon: prog.IntTypeCommon{
			TypeCommon: prog.TypeCommon{
				TypeName:  name,
				TypeSize:  4,
				TypeAlign: 4,
			},
		},
	}
}

func TestRetDirIsOut(t *testing.T) {
	fd := &prog.ResourceType{
		TypeCommon: prog.TypeCommon{
			TypeName:  "fd",
			TypeSize:  4,
			TypeAlign: 4,
		},
		Desc: &prog.ResourceDesc{
			Name:   "fd",
			Kind:   []string{"fd"},
			Values: []uint64{^uint64(0)},
		},
	}
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{NR: 1, Name: "ret_fd", Ret: fd},
	}

	w := testWriter(t, target)
	if err := w.buildRows(); err != nil {
		t.Fatalf("buildRows: %v", err)
	}
	if len(w.syscalls) != 1 {
		t.Fatalf("got %d syscalls, want 1", len(w.syscalls))
	}
	retIdx := w.syscalls[0].retTypeIdx
	if got := w.types[retIdx].dir; got != "kOut" {
		t.Fatalf("return type dir = %s, want kOut", got)
	}
}

func TestBufferVariantsEmit(t *testing.T) {
	tests := []struct {
		kind        prog.BufferKind
		wantKind    string
		wantComment string
		values      []string
	}{
		{prog.BufferBlobRand, "kBuffer", "blob", nil},
		{prog.BufferBlobRange, "kBuffer", "blob-range", nil},
		{prog.BufferString, "kString", "string", []string{"abc"}},
		{prog.BufferFilename, "kFilename", "filename", nil},
		{prog.BufferText, "kBuffer", "text:", nil},
		{prog.BufferGlob, "kFilename", "glob", []string{"/tmp/*"}},
		{prog.BufferCompressed, "kBuffer", "compressed", nil},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d", tc.kind), func(t *testing.T) {
			w := testWriter(t, testTarget())
			bt := &prog.BufferType{
				TypeCommon: prog.TypeCommon{
					TypeName: fmt.Sprintf("buf_%d", tc.kind),
					IsVarlen: true,
				},
				Kind:       tc.kind,
				RangeBegin: 1,
				RangeEnd:   16,
				Values:     tc.values,
			}
			row := w.buildTypeRow(bt, "kIn")
			if row.kind != tc.wantKind {
				t.Fatalf("kind = %s, want %s", row.kind, tc.wantKind)
			}
			if !strings.Contains(row.comment, tc.wantComment) {
				t.Fatalf("comment = %q, want substring %q", row.comment, tc.wantComment)
			}
		})
	}
}

func TestStructDirDedup(t *testing.T) {
	inStruct := &prog.StructType{
		TypeCommon: prog.TypeCommon{TypeName: "same", TypeSize: 4, TypeAlign: 4},
		Fields: []prog.Field{{
			Name:         "field",
			Type:         testIntType("field_int"),
			HasDirection: true,
			Direction:    prog.DirIn,
		}},
	}
	outStruct := &prog.StructType{
		TypeCommon: prog.TypeCommon{TypeName: "same", TypeSize: 4, TypeAlign: 4},
		Fields: []prog.Field{{
			Name:         "field",
			Type:         testIntType("field_int"),
			HasDirection: true,
			Direction:    prog.DirOut,
		}},
	}

	w := testWriter(t, testTarget())
	inIdx := w.walkType(inStruct, "kIn")
	outIdx := w.walkType(outStruct, "kIn")
	if inIdx == outIdx {
		t.Fatalf("same-name structs with different field dirs reused type idx %d", inIdx)
	}
}

func TestFlagsCollision(t *testing.T) {
	w := testWriter(t, testTarget())
	a := &prog.FlagsType{
		IntTypeCommon: prog.IntTypeCommon{
			TypeCommon: prog.TypeCommon{TypeName: "dup_flags", TypeSize: 4, TypeAlign: 4},
		},
		Vals:    []uint64{1, 2},
		BitMask: true,
	}
	b := &prog.FlagsType{
		IntTypeCommon: prog.IntTypeCommon{
			TypeCommon: prog.TypeCommon{TypeName: "dup_flags", TypeSize: 4, TypeAlign: 4},
		},
		Vals:    []uint64{4, 8},
		BitMask: true,
	}

	aIdx := w.internFlags(a)
	bIdx := w.internFlags(b)
	if aIdx == bIdx {
		t.Fatalf("same-name flags with different values reused index %d", aIdx)
	}
	if len(w.flags) != 2 {
		t.Fatalf("got %d flags rows, want 2", len(w.flags))
	}
	if w.flags[0].symbolName == w.flags[1].symbolName {
		t.Fatalf("flags rows reused symbol %q", w.flags[0].symbolName)
	}
	if !strings.HasPrefix(w.flags[1].symbolName, "dup_flags_") {
		t.Fatalf("collision symbol = %q, want dup_flags_<hash>", w.flags[1].symbolName)
	}
}

func TestFieldBitfieldEmit(t *testing.T) {
	bitfield := &prog.IntType{
		IntTypeCommon: prog.IntTypeCommon{
			TypeCommon: prog.TypeCommon{
				TypeName:  "bf",
				TypeSize:  1,
				TypeAlign: 1,
			},
			BitfieldOff: 3,
			BitfieldLen: 5,
		},
	}
	st := &prog.StructType{
		TypeCommon: prog.TypeCommon{TypeName: "has_bitfield", TypeSize: 1, TypeAlign: 1},
		Fields: []prog.Field{{
			Name: "bits",
			Type: bitfield,
		}},
	}

	w := testWriter(t, testTarget())
	w.walkType(st, "kIn")
	if len(w.fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(w.fields))
	}
	fr := w.fields[0]
	if fr.name != "bits" {
		t.Fatalf("field name = %q, want %q", fr.name, "bits")
	}
	if fr.bitOffset != 3 || fr.bitSize != 5 {
		t.Fatalf("bitfield = off %d size %d, want off 3 size 5",
			fr.bitOffset, fr.bitSize)
	}
}
