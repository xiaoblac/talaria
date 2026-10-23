package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

const (
	syzMaxArgs             = 9
	compatFlatMaxArgs      = 6
	pseudoNrBase           = 0x100000
	defaultConstsOutDir    = "program/include/refuzz/program/syz/generated"
	defaultCallTableOutDir = "program/include/refuzz/program/syz/generated"
	defaultPseudoOutDir    = "program/include/refuzz/program/syz/pseudo/generated"
	defaultPinFile         = ".syzkaller-pin"
)

type options struct {
	osName        string
	arch          string
	out           string // audit JSON path, or target-cpp output dir override
	constsOut     string // dir holding consts.gen.hpp
	callTableOut  string // dir holding target_linux_amd64_call_table.gen.hpp
	pseudoOut     string // dir holding pseudo_meta.gen.hpp / target.gen.hpp / syz_tables.gen.hpp
	syzkallerRoot string
	pinFile       string
	unpinned      bool
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]

	// text-roundtrip / corpus-roundtrip use their own flag sets (they accept
	// -in / -dir / -mode etc that the shared parseFlags doesn't know about).
	// Dispatch them before parseFlags consumes os.Args[2:].
	if cmd == "text-roundtrip" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runTextRoundtrip(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "corpus-roundtrip" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runCorpusRoundtrip(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "corpus-unpack-db" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runCorpusUnpackDB(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "seeds-unpack" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runSeedsUnpack(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "exec-wire-diff" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runExecWireDiff(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "exec-trace-dump" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runExecTraceDump(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "exec-trace-diff" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runExecTraceDiff(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if cmd == "gen-histogram-diff" {
		target, terr := prog.GetTarget("linux", "amd64")
		if terr != nil {
			log.Fatalf("GetTarget(linux/amd64): %v", terr)
		}
		if err := runGenHistogramDiff(target, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	opts := parseFlags(cmd, os.Args[2:])

	target, err := prog.GetTarget(opts.osName, opts.arch)
	if err != nil {
		log.Fatalf("GetTarget(%s/%s): %v", opts.osName, opts.arch, err)
	}

	switch cmd {
	case "all":
		err = runAll(target, opts)
	case "consts":
		err = runConsts(target, opts)
	case "pseudo":
		err = runPseudo(target, opts)
	case "target":
		err = runTarget(target, opts)
	case "target-cpp":
		err = runTargetCpp(target, opts)
	case "dump-go":
		err = runDumpGo(target, opts)
	case "enum-dump":
		err = runEnumDump(target, opts)
	case "audit":
		err = runAudit(target, opts)
	case "verify":
		err = runVerify(target, opts)
	case "choice-ref":
		err = runChoiceRef(target, opts)
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: go run ./tools/syzgen <subcommand> [flags]

subcommands:
  all       generate consts/pseudo/target headers (post-V1-retirement: V1 IR tables no longer emitted)
  consts    generate ODR-safe consts.gen.hpp
  pseudo    generate pseudo_meta.gen.hpp
  target    generate target.gen.hpp and syz_tables.gen.hpp
  target-cpp generate new polymorphic IR (program/src/syz_v2/generated/*.gen.cpp)
  dump-go    print structural summary of prog.Target (matches refuzz-syz-v2-dump output)
  enum-dump  full field-level enumeration of all types/syscalls/resources (matches refuzz-syz-v2-enum)
  text-roundtrip   prog.Deserialize → prog.Serialize on stdin or -in file (oracle for v2 text codec)
  corpus-roundtrip batch round-trip a corpus dir or corpus.db (Go + C++ batch + diff)
  corpus-unpack-db unpack a syzkaller corpus.db into a directory of .syz text files
  exec-wire-diff   §3.2 oracle: byte-equal SerializeForExec across Go and C++ encoders
  exec-trace-dump  §3.3 Layer-3 milestone I: dump dispatch trace from prog.Prog (Go IR walk)
  exec-trace-diff  §3.3 Layer-3 milestone I oracle: trace-equiv between Go IR and C++ wire walks
  audit     write a JSON audit report
  verify    regenerate into a temporary directory and compare with -out
  choice-ref emit Phase C choice-table reference report (top edges per anchor call)

common flags:
  -os linux
  -arch amd64
  -syzkaller-root /workspace/syzkaller
  -consts-out %s
  -call-table-out %s
  -pseudo-out %s
  -out         (audit JSON path, or target-cpp output dir)
  -pin-file    %s
`, defaultConstsOutDir, defaultCallTableOutDir, defaultPseudoOutDir, defaultPinFile)
}

func parseFlags(cmd string, args []string) options {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	opts := options{}
	fs.StringVar(&opts.osName, "os", "linux", "target OS")
	fs.StringVar(&opts.arch, "arch", "amd64", "target arch")
	fs.StringVar(&opts.out, "out", "", "audit JSON path, or target-cpp output dir override (empty = use defaults)")
	fs.StringVar(&opts.constsOut, "consts-out", defaultConstsOutDir, "directory for consts.gen.hpp")
	fs.StringVar(&opts.callTableOut, "call-table-out", defaultCallTableOutDir, "directory for target_linux_amd64_call_table.gen.hpp")
	fs.StringVar(&opts.pseudoOut, "pseudo-out", defaultPseudoOutDir, "directory for pseudo_meta.gen.hpp / target.gen.hpp / syz_tables.gen.hpp")
	fs.StringVar(&opts.syzkallerRoot, "syzkaller-root", "..", "syzkaller checkout root")
	fs.StringVar(&opts.pinFile, "pin-file", defaultPinFile, "file containing expected syzkaller git revision")
	fs.BoolVar(&opts.unpinned, "unpinned", false, "allow audit/verify without matching the pin file")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	return opts
}

type writer struct {
	target        *prog.Target
	constsOutDir  string
	pseudoOutDir  string
	syzkallerRoot string

	syscalls   []syscallRow
	pseudoRows []pseudoRow
	types      []typeRow
	resources  []resourceRow
	flags      []flagsRow
	fields     []fieldRow

	typeIdx     map[prog.Type]uint32
	typeState   map[uint32]int
	flagsIdx    map[string]uint32
	flagsSym    map[string]struct{}
	resIdx      map[string]uint32
	resKind     map[string]uint32
	syscallIdx  map[*prog.Syscall]uint32
	pseudoSynth map[string]uint64

	nextResourceKind uint32
	maxRealNR        uint64
	constStats       constParseStats
	built            bool
}

type syscallRow struct {
	nr          uint64
	name        string
	argCount    uint32
	argsTypeIdx [syzMaxArgs]uint32
	retTypeIdx  uint32
}

type pseudoRow struct {
	nr             uint64
	name           string
	argCount       uint32
	argsTypeIdx    [syzMaxArgs]uint32
	domain         string
	impl           string
	concurrency    string
}

type typeRow struct {
	kind        string
	dir         string
	byteSize    uint8
	isOptional  uint8
	valMin      int64
	valMax      int64
	flagsIdx    uint32
	resourceIdx uint32
	innerIdx    uint32
	fieldsStart uint32
	fieldsCount uint32
	elemMin     uint32
	elemMax     uint32
	lenOfArg    uint32
	stringVal   string
	comment     string
}

type resourceRow struct {
	kind        uint32
	name        string
	parentKind  uint32
	specialVals []int64
	ctorMetaIdx []uint32
}

type flagsRow struct {
	name       string
	symbolName string
	values     []int64
	isBitmask  bool
}

type fieldRow struct {
	name       string
	typeIdx    uint32
	bitOffset  uint32
	bitSize    uint32
	unitSize   uint32
	unitOffset uint32
}

func newWriter(target *prog.Target, constsOutDir, pseudoOutDir string) *writer {
	w := &writer{
		target:           target,
		constsOutDir:     constsOutDir,
		pseudoOutDir:     pseudoOutDir,
		typeIdx:          make(map[prog.Type]uint32),
		typeState:        make(map[uint32]int),
		flagsIdx:         make(map[string]uint32),
		flagsSym:         make(map[string]struct{}),
		resIdx:           make(map[string]uint32),
		resKind:          make(map[string]uint32),
		syscallIdx:       make(map[*prog.Syscall]uint32),
		pseudoSynth:      make(map[string]uint64),
		nextResourceKind: 32,
	}
	w.seedStdTypes()
	return w
}

func (w *writer) seedStdTypes() {
	seed := func(kind, dir string, byteSize uint8, vmin, vmax int64, comment string) {
		w.types = append(w.types, typeRow{
			kind:     kind,
			dir:      dir,
			byteSize: byteSize,
			valMin:   vmin,
			valMax:   vmax,
			comment:  comment,
		})
	}
	seed("kConst", "kIn", 0, 0, 0, "kTypeIdxVoid - unused arg placeholder")
	seed("kResource", "kIn", 4, -1, math.MaxInt32, "kTypeIdxFd")
	seed("kInt", "kIn", 4, 0, math.MaxInt32, "kTypeIdxInt32")
	seed("kInt", "kIn", 8, 0, math.MaxInt64, "kTypeIdxInt64")
	seed("kLen", "kIn", 8, 0, math.MaxInt64, "kTypeIdxSizeT")
	seed("kResource", "kIn", 4, -1, math.MaxInt32, "kTypeIdxPid")
	seed("kResource", "kIn", 4, 0, math.MaxInt32, "kTypeIdxUid")
	seed("kResource", "kIn", 4, 0, math.MaxInt32, "kTypeIdxGid")
	seed("kPtr", "kIn", 8, 0, 0, "kTypeIdxBufIn - generic input buffer ptr")
	seed("kPtrOut", "kOut", 8, 0, 0, "kTypeIdxBufOut - generic output buffer ptr")
	seed("kFilename", "kIn", 8, 0, 0, "kTypeIdxFilename")
	seed("kResource", "kIn", 4, -1, math.MaxInt32, "kTypeIdxSock")
	seed("kFlags", "kIn", 4, 0, math.MaxInt32, "kTypeIdxFlags32 - generic flags32")
}

func (w *writer) buildRows() error {
	if w.built {
		return nil
	}
	w.assignResourceKinds()
	for _, res := range w.target.Resources {
		w.internResourceDesc(res)
	}
	for _, typ := range w.target.Types {
		w.reserveType(typ)
	}
	for _, typ := range w.target.Types {
		w.walkTypeDir(typ, prog.DirIn)
	}
	if err := w.preparePseudoRows(); err != nil {
		return err
	}

	for i, sc := range w.target.Syscalls {
		idx := uint32(i)
		w.syscallIdx[sc] = idx
		row := syscallRow{
			nr:       sc.NR,
			name:     sc.Name,
			argCount: uint32(len(sc.Args)),
		}
		if synth, ok := w.pseudoSynth[sc.Name]; ok {
			row.nr = synth
		} else if !strings.HasPrefix(sc.CallName, "syz_") && sc.NR > w.maxRealNR {
			w.maxRealNR = sc.NR
		}
		if len(sc.Args) > syzMaxArgs {
			return fmt.Errorf("%s has %d args, exceeds syzkaller MaxArgs %d", sc.Name, len(sc.Args), syzMaxArgs)
		}
		for ai, field := range sc.Args {
			row.argsTypeIdx[ai] = w.walkTypeDir(field.Type, field.Dir(prog.DirIn))
		}
		if sc.Ret != nil {
			row.retTypeIdx = w.walkTypeDir(sc.Ret, prog.DirOut)
		}
		w.syscalls = append(w.syscalls, row)
	}

	for i, res := range w.target.Resources {
		if i >= len(w.resources) {
			break
		}
		w.resources[i].ctorMetaIdx = w.resourceCtorIndices(res)
	}
	w.built = true
	return nil
}

func (w *writer) assignResourceKinds() {
	for _, res := range w.target.Resources {
		if _, ok := w.resKind[res.Name]; ok {
			continue
		}
		if kind, ok := wellKnownRes[res.Name]; ok {
			w.resKind[res.Name] = kind
			continue
		}
		w.resKind[res.Name] = w.nextResourceKind
		w.nextResourceKind++
	}
}

func (w *writer) preparePseudoRows() error {
	if len(w.pseudoRows) != 0 || len(w.pseudoSynth) != 0 {
		return nil
	}
	// NR / spec assignment is delegated to SynthesizePseudoNRs so the
	// typed-Target emitter (emit_cpp.go) consumes the same identity. We
	// still sort here because pseudoRows ordering determines the
	// kLinuxAmd64PseudoMeta[] array layout on the worker side.
	synth := SynthesizePseudoNRs(w.target)
	pseudos := pseudoDescriptionSyscalls(w.target)
	sort.Slice(pseudos, func(i, j int) bool {
		return pseudos[i].Name < pseudos[j].Name
	})
	for _, sc := range pseudos {
		if len(sc.Args) > syzMaxArgs {
			return fmt.Errorf("%s has %d args, exceeds syzkaller MaxArgs %d", sc.Name, len(sc.Args), syzMaxArgs)
		}
		entry := synth[sc.Name]
		row := pseudoRow{
			nr:             entry.NR,
			name:           sc.Name,
			argCount:       uint32(len(sc.Args)),
			domain:         cppPseudoDomain(entry.Spec.domain),
			impl:           cppPseudoImpl(entry.Spec.impl),
			concurrency:    "PseudoConcurrency::kNotConcurrentSafe",
		}
		for ai, field := range sc.Args {
			row.argsTypeIdx[ai] = w.walkTypeDir(field.Type, field.Dir(prog.DirIn))
		}
		w.pseudoSynth[sc.Name] = entry.NR
		w.pseudoRows = append(w.pseudoRows, row)
	}
	return nil
}

func pseudoDescriptionSyscalls(target *prog.Target) []*prog.Syscall {
	var pseudos []*prog.Syscall
	for _, sc := range target.Syscalls {
		if strings.HasPrefix(sc.Name, "syz_") {
			pseudos = append(pseudos, sc)
		}
	}
	return pseudos
}

func (w *writer) reserveType(t prog.Type) uint32 {
	if idx, ok := w.typeIdx[t]; ok {
		return idx
	}
	idx := uint32(len(w.types))
	w.typeIdx[t] = idx
	w.types = append(w.types, typeRow{})
	return idx
}

func (w *writer) walkTypeDir(t prog.Type, dir prog.Dir) uint32 {
	if t == nil {
		return 0
	}
	idx, ok := w.typeIdx[t]
	if !ok {
		idx = w.reserveType(t)
	}
	if w.typeState[idx] == 2 {
		return idx
	}
	if w.typeState[idx] == 1 {
		return idx
	}
	w.typeState[idx] = 1
	w.types[idx] = w.buildTypeRow(t, dirStr(dir))
	w.typeState[idx] = 2
	return idx
}

func (w *writer) walkType(t prog.Type, dir string) uint32 {
	return w.walkTypeDir(t, dirFromString(dir))
}

func (w *writer) buildTypeRow(t prog.Type, dir string) typeRow {
	row := typeRow{
		dir:      dir,
		byteSize: uint8Clamp(staticSize(t)),
		valMax:   math.MaxInt32,
	}
	if t.Optional() {
		row.isOptional = 1
	}

	switch v := t.(type) {
	case *prog.ConstType:
		row.kind = "kConst"
		row.valMin = int64(v.Val)
		row.valMax = int64(v.Val)
	case *prog.IntType:
		row.kind = "kInt"
		row.valMin = int64(v.RangeBegin)
		row.valMax = int64(v.RangeEnd)
		if row.valMax == 0 && row.byteSize > 0 {
			row.valMax = maxForByteSize(row.byteSize)
		}
	case *prog.FlagsType:
		row.kind = "kFlags"
		row.flagsIdx = w.internFlags(v)
	case *prog.LenType:
		row.kind = "kLen"
		if row.byteSize == 0 {
			row.byteSize = 8
		}
		if len(v.Path) > 0 {
			row.comment = "len:" + strings.Join(v.Path, ".")
		}
	case *prog.ProcType:
		row.kind = "kProc"
		row.valMin = int64(v.ValuesStart)
		row.valMax = int64(v.ValuesStart + v.ValuesPerProc)
	case *prog.PtrType:
		if v.ElemDir == prog.DirOut {
			row.kind = "kPtrOut"
			row.dir = "kOut"
		} else {
			row.kind = "kPtr"
		}
		row.byteSize = 8
		row.innerIdx = w.walkTypeDir(v.Elem, v.ElemDir)
	case *prog.BufferType:
		row.byteSize = 0
		switch v.Kind {
		case prog.BufferFilename:
			row.kind = "kFilename"
			row.comment = "filename"
		case prog.BufferString:
			row.kind = "kString"
			row.comment = "string"
		case prog.BufferText:
			row.kind = "kBuffer"
			row.comment = "text:" + v.SubKind
		case prog.BufferGlob:
			row.kind = "kFilename"
			row.comment = "glob:" + v.SubKind
		case prog.BufferCompressed:
			row.kind = "kBuffer"
			row.comment = "compressed"
		case prog.BufferBlobRange:
			row.kind = "kBuffer"
			row.comment = "blob-range"
			row.elemMin = uint32Clamp(v.RangeBegin)
			row.elemMax = uint32Clamp(v.RangeEnd)
		default:
			row.kind = "kBuffer"
			row.comment = "blob"
		}
		if len(v.Values) > 0 {
			row.stringVal = v.Values[0]
		}
	case *prog.ResourceType:
		row.kind = "kResource"
		row.resourceIdx = w.internResourceDesc(v.Desc)
		row.valMin = -1
		row.valMax = math.MaxInt32
	case *prog.ArrayType:
		row.kind = "kArray"
		row.byteSize = 0
		row.innerIdx = w.walkTypeDir(v.Elem, dirFromString(dir))
		row.elemMin = uint32Clamp(v.RangeBegin)
		row.elemMax = uint32Clamp(v.RangeEnd)
		if row.elemMax == 0 {
			row.elemMax = 10
		}
	case *prog.StructType:
		row.kind = "kStruct"
		row.fieldsStart = uint32(len(w.fields))
		row.fieldsCount = uint32(len(v.Fields))
		row.comment = v.Name()
		for _, f := range v.Fields {
			w.fields = append(w.fields, w.buildFieldRow(f, dirFromString(dir)))
		}
	case *prog.UnionType:
		row.kind = "kUnion"
		row.fieldsStart = uint32(len(w.fields))
		row.fieldsCount = uint32(len(v.Fields))
		row.comment = v.Name()
		for _, f := range v.Fields {
			w.fields = append(w.fields, w.buildFieldRow(f, dirFromString(dir)))
		}
	case *prog.VmaType:
		row.kind = "kVma"
		row.byteSize = 8
		row.valMin = int64(v.RangeBegin)
		row.valMax = int64(v.RangeEnd)
	case *prog.CsumType:
		row.kind = "kCsum"
		row.byteSize = uint8Clamp(v.TypeSize)
		row.comment = "csum:" + v.Buf
	default:
		row.kind = "kConst"
		row.valMin = 0
		row.valMax = 0
		row.comment = fmt.Sprintf("unknown type %T", t)
	}
	return row
}

func (w *writer) buildFieldRow(f prog.Field, parentDir prog.Dir) fieldRow {
	row := fieldRow{
		name:    f.Name,
		typeIdx: w.walkTypeDir(f.Type, f.Dir(parentDir)),
	}
	if f.Type != nil && f.Type.IsBitfield() {
		row.bitOffset = uint32Clamp(f.Type.BitfieldOffset())
		row.bitSize = uint32Clamp(f.Type.BitfieldLength())
		row.unitSize = uint32Clamp(f.Type.UnitSize())
		row.unitOffset = uint32Clamp(f.Type.UnitOffset())
	}
	return row
}

func (w *writer) internResourceDesc(res *prog.ResourceDesc) uint32 {
	if res == nil {
		return 0
	}
	if idx, ok := w.resIdx[res.Name]; ok {
		return idx
	}
	kind, ok := w.resKind[res.Name]
	if !ok {
		if known, knownOK := wellKnownRes[res.Name]; knownOK {
			kind = known
		} else {
			kind = w.nextResourceKind
			w.nextResourceKind++
		}
		w.resKind[res.Name] = kind
	}
	parentKind := uint32(0)
	if len(res.Kind) > 1 {
		parentName := res.Kind[len(res.Kind)-2]
		if pk, ok := w.resKind[parentName]; ok {
			parentKind = pk
		} else if pk, ok := wellKnownRes[parentName]; ok {
			parentKind = pk
		}
	}
	specials := make([]int64, 0, len(res.Values))
	for _, val := range res.Values {
		specials = append(specials, int64(val))
	}
	idx := uint32(len(w.resources))
	w.resIdx[res.Name] = idx
	w.resources = append(w.resources, resourceRow{
		kind:        kind,
		name:        res.Name,
		parentKind:  parentKind,
		specialVals: specials,
	})
	return idx
}

func (w *writer) resourceCtorIndices(res *prog.ResourceDesc) []uint32 {
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, ctor := range res.Ctors {
		idx, ok := w.syscallIdx[ctor.Call]
		if !ok {
			continue
		}
		if _, exists := seen[idx]; exists {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
		if len(out) == 8 {
			break
		}
	}
	return out
}

func (w *writer) internFlags(ft *prog.FlagsType) uint32 {
	key := flagsKey(ft)
	if idx, ok := w.flagsIdx[key]; ok {
		return idx
	}
	symbol := sanitizeIdent(ft.TypeName)
	if symbol == "" {
		symbol = "anonymous_flags"
	}
	if _, used := w.flagsSym[symbol]; used {
		h := sha1.Sum([]byte(key))
		symbol = fmt.Sprintf("%s_%s", symbol, hex.EncodeToString(h[:])[:8])
	}
	w.flagsSym[symbol] = struct{}{}
	vals := make([]int64, len(ft.Vals))
	for i, val := range ft.Vals {
		vals[i] = int64(val)
	}
	idx := uint32(len(w.flags))
	w.flagsIdx[key] = idx
	w.flags = append(w.flags, flagsRow{
		name:       ft.TypeName,
		symbolName: symbol,
		values:     vals,
		isBitmask:  ft.BitMask,
	})
	return idx
}

func flagsKey(ft *prog.FlagsType) string {
	var b strings.Builder
	b.WriteString(ft.TypeName)
	b.WriteByte('|')
	if ft.BitMask {
		b.WriteByte('1')
	} else {
		b.WriteByte('0')
	}
	for _, val := range ft.Vals {
		fmt.Fprintf(&b, "|%d", val)
	}
	return b.String()
}

var wellKnownRes = map[string]uint32{
	"fd":         1,
	"sock":       2,
	"pid":        3,
	"uid":        4,
	"gid":        5,
	"fd_dir":     6,
	"fd_epoll":   7,
	"fd_timer":   8,
	"fd_inotify": 9,
	"fd_signal":  10,
	"vma":        11,
	"fd_inode":   12,
	"fd_event":   13,
	"ipc_msq":    14,
	"ipc_shm":    15,
	"ipc_sem":    16,
}

func runAll(target *prog.Target, opts options) error {
	if err := checkPin(opts); err != nil {
		return err
	}
	w := newWriter(target, opts.constsOut, opts.pseudoOut)
	w.syzkallerRoot = opts.syzkallerRoot
	if err := w.buildRows(); err != nil {
		return err
	}
	if err := w.emitAllFiles(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote consts→%s pseudo→%s (%d syscalls, %d pseudos, %d types, %d resources, %d flags, %d fields)\n",
		opts.constsOut, opts.pseudoOut, len(w.syscalls), len(w.pseudoRows), len(w.types), len(w.resources), len(w.flags), len(w.fields))
	// [PR-A2] Also run target-cpp so the typed-Target syscall metadata
	// (program/src/syz/generated/target_linux_amd64_syscalls_part_*.gen.cpp)
	// stays in sync with the worker-facing pseudo_meta.gen.hpp. Without
	// this, a `syz_regen → build → run` sequence after a classifyPseudo
	// change fails Target::finalize()'s "pseudo X impl mismatch:
	// typed=A worker=B" invariant. Both emitters consume
	// SynthesizePseudoNRs(target), so running them sequentially is the
	// only thing keeping their outputs aligned.
	if err := runTargetCpp(target, opts); err != nil {
		return fmt.Errorf("target-cpp emit (post-runAll sync): %w", err)
	}
	return nil
}

func runConsts(target *prog.Target, opts options) error {
	if err := checkPin(opts); err != nil {
		return err
	}
	w := newWriter(target, opts.constsOut, opts.pseudoOut)
	w.syzkallerRoot = opts.syzkallerRoot
	return w.emitConstsFile()
}

func runPseudo(target *prog.Target, opts options) error {
	if err := checkPin(opts); err != nil {
		return err
	}
	w := newWriter(target, opts.constsOut, opts.pseudoOut)
	w.syzkallerRoot = opts.syzkallerRoot
	if err := w.buildRows(); err != nil {
		return err
	}
	return w.emitPseudoFile()
}

func runTarget(target *prog.Target, opts options) error {
	if err := checkPin(opts); err != nil {
		return err
	}
	w := newWriter(target, opts.constsOut, opts.pseudoOut)
	w.syzkallerRoot = opts.syzkallerRoot
	if err := w.buildRows(); err != nil {
		return err
	}
	if err := w.emitTargetFile(); err != nil {
		return err
	}
	return w.emitAggregationFile()
}

func runVerify(target *prog.Target, opts options) error {
	if err := checkPin(opts); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "refuzz-syzgen-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	tmpConsts := filepath.Join(tmp, "consts")
	tmpPseudo := filepath.Join(tmp, "pseudo")

	w := newWriter(target, tmpConsts, tmpPseudo)
	w.syzkallerRoot = opts.syzkallerRoot
	if err := w.buildRows(); err != nil {
		return err
	}
	if err := w.emitAllFiles(); err != nil {
		return err
	}
	diff, err := compareGeneratedDirsSplit(tmpConsts, opts.constsOut, tmpPseudo, opts.pseudoOut)
	if err != nil {
		return err
	}
	if len(diff) != 0 {
		return fmt.Errorf("generated metadata differs (consts→%s, pseudo→%s):\n%s",
			opts.constsOut, opts.pseudoOut, strings.Join(diff, "\n"))
	}
	fmt.Fprintf(os.Stderr, "verified consts→%s pseudo→%s\n", opts.constsOut, opts.pseudoOut)
	return nil
}

func (w *writer) emitAllFiles() error {
	if err := os.MkdirAll(w.constsOutDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(w.pseudoOutDir, 0755); err != nil {
		return err
	}
	if err := w.emitConstsFile(); err != nil {
		return err
	}
	if err := w.emitPseudoFile(); err != nil {
		return err
	}
	if err := w.emitTargetFile(); err != nil {
		return err
	}
	return w.emitAggregationFile()
}

func (w *writer) openGenerated(outDir, name, role string) (*os.File, func(string, ...interface{}), error) {
	path := filepath.Join(outDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(f, format, args...)
	}
	p("// AUTO-GENERATED by tools/syzgen - DO NOT EDIT\n")
	p("// Target: %s/%s\n", w.target.OS, w.target.Arch)
	p("// Role: %s\n", role)
	p("#pragma once\n\n")
	return f, p, nil
}

func (w *writer) emitPseudoFile() error {
	f, p, err := w.openGenerated(w.pseudoOutDir, "pseudo_meta.gen.hpp", "definition-bearing implementation include; include only via generated/syz_tables.gen.hpp")
	if err != nil {
		return err
	}
	defer f.Close()
	p("#include \"refuzz/program/syz/pseudo/target_view.hpp\"\n\n")
	p("#include <cstddef>\n#include <cstdint>\n\n")
	p("namespace refuzz::fuzzer::syz {\n\n")
	p("extern const PseudoMeta kLinuxAmd64PseudoMeta[] = {\n")
	for i, row := range w.pseudoRows {
		p("    { 0x%xULL, %s, %du, %s, {%s}, %s }, // [%d]\n",
			row.nr, cppStringLiteral(row.name), row.argCount, row.domain,
			joinUint32Array(row.argsTypeIdx[:]), row.concurrency, i)
	}
	p("};\n")
	p("extern const size_t kLinuxAmd64PseudoMetaSize = %d;\n", len(w.pseudoRows))
	p("static_assert(%d == %d, \"generated pseudo size mismatch\");\n", len(w.pseudoRows), len(w.pseudoRows))
	for i, row := range w.pseudoRows {
		p("static_assert(0x%xULL == 0x100000ULL + %dULL, \"synth NR not dense at idx %d\");\n", row.nr, i, i)
	}
	p("\n} // namespace refuzz::fuzzer::syz\n")
	return nil
}

func (w *writer) emitTargetFile() error {
	f, p, err := w.openGenerated(w.pseudoOutDir, "target.gen.hpp",
		"pseudo-target identity for the worker pseudo-call dispatch path.")
	if err != nil {
		return err
	}
	defer f.Close()
	p("#include \"refuzz/program/syz/pseudo/target_view.hpp\"\n\n")
	p("#include <cstddef>\n#include <cstdint>\n\n")
	p("namespace refuzz::fuzzer::syz {\n\n")
	p("extern const uint64_t kLinuxAmd64PseudoNrBase = 0x100000ULL;\n")
	p("extern const SyzTargetTables kLinuxAmd64Target = {\n")
	p("    { %s, %s },\n", cppStringLiteral(w.target.OS), cppStringLiteral(w.target.Arch))
	p("    kLinuxAmd64PseudoNrBase,\n")
	p("    %dULL,\n", w.maxRealNR)
	p("    { kLinuxAmd64PseudoNrBase, kLinuxAmd64PseudoMeta, kLinuxAmd64PseudoMetaSize },\n")
	p("};\n")
	p("static_assert(%dULL < 0x100000ULL, \"real syscall nr overlaps pseudo range\");\n", w.maxRealNR)
	p("extern const SyzTargetTables kDefaultSyzTarget = kLinuxAmd64Target;\n\n")
	p("} // namespace refuzz::fuzzer::syz\n")
	return nil
}

func (w *writer) emitAggregationFile() error {
	f, p, err := w.openGenerated(w.pseudoOutDir, "syz_tables.gen.hpp", "aggregation include for pseudo-target metadata.")
	if err != nil {
		return err
	}
	defer f.Close()
	p("#include \"refuzz/program/syz/pseudo/generated/pseudo_meta.gen.hpp\"\n")
	p("#include \"refuzz/program/syz/pseudo/generated/target.gen.hpp\"\n")
	return nil
}

func runAudit(target *prog.Target, opts options) error {
	pin, observed, pinned, err := pinStatus(opts)
	if err != nil {
		return err
	}
	if !opts.unpinned && !pinned {
		return fmt.Errorf("syzkaller checkout revision %s does not match pin %s", observed, pin)
	}
	// runAudit only uses the writer for buildRows / pseudoImplCounts; no
	// .gen.hpp files are written. Pin to canonical defaults for clarity.
	w := newWriter(target, defaultConstsOutDir, defaultPseudoOutDir)
	w.syzkallerRoot = opts.syzkallerRoot
	if err := w.buildRows(); err != nil {
		return err
	}
	constResult, err := parseAllConsts(opts.syzkallerRoot, target.OS, target.Arch)
	if err != nil {
		return err
	}
	native, stub, unsupported := w.pseudoImplCounts()
	report := auditReport{
		Target: auditTarget{OS: target.OS, Arch: target.Arch},
		Syzkaller: auditSyzkaller{
			Root:             opts.syzkallerRoot,
			Pin:              pin,
			ObservedRevision: observed,
			Pinned:           pinned,
		},
		Counts: auditCounts{
			Syscalls:  auditPair{Syzkaller: len(target.Syscalls), Refuzz: len(w.syscalls)},
			Pseudos:   auditPair{Syzkaller: len(pseudoDescriptionSyscalls(target)), Refuzz: len(w.pseudoRows), Extractor: "target.Syscalls where name has syz_ prefix"},
			Resources: auditPair{Syzkaller: len(target.Resources), Refuzz: len(w.resources)},
			Flags: auditPair{
				Syzkaller: len(target.Flags),
				Refuzz:    len(w.flags),
				Note:      "syzkaller side = len([]FlagDesc) (name duplicates possible); refuzz side = unique-name interned FlagsType count; symmetric drift surfaced in diffs[] by name",
			},
			ConstFiles: auditConstFiles{ParsedInputFiles: constResult.stats.Files, Sources: constSources(constResult.rows)},
			Consts:     auditConsts{RefuzzEmittedEntries: len(constResult.rows)},
		},
		NRBounds:   auditNRBounds{MaxRealNR: w.maxRealNR, PseudoNRBase: pseudoNrBase},
		PseudoImpl: auditPseudoImpl{Native: native, Stub: stub, Unsupported: unsupported},
		TypeCoverage: map[string]string{
			"const":             "native",
			"int":               "native",
			"flags":             "native",
			"len":               "represented_repair_partial",
			"buffer_compressed": "represented_generation_blocked",
			"csum":              "represented_runtime_patch_missing",
		},
		Diffs: classifyAuditDiffs(target, w),
		// [v1 — ROLLBACK: uncomment below and remove v2]
		// Unsupported: []auditUnsupported{{Kind: "type", Name: "compressed buffer", Reason: "no native image generator in Phase A"}},
		// [v2 B1 feature-id retrofit — 当前版本]
		// Feature-id matches docs/syzkaller-integration/021_phase_b_compatibility_matrix.md.
		// Phase B C++ uses syz::diag::kBufferCompressed = "buffer.compressed".
		Unsupported: []auditUnsupported{{Kind: "type", Name: "buffer.compressed", Reason: "no native image generator in Phase A"}},
	}
	sortAuditDiffs(report.Diffs)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(opts.out), 0755); err != nil {
		return err
	}
	// Write the report file unconditionally so the developer can inspect any
	// unclassified entries; if validation fails below we still return error
	// so main exits nonzero (preserving the log.Fatal path).
	if err := os.WriteFile(opts.out, data, 0644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote audit report %s\n", opts.out)
	if unclassified := unclassifiedAuditEntries(report); len(unclassified) > 0 {
		for _, msg := range unclassified {
			fmt.Fprintf(os.Stderr, "audit: unclassified entry: %s\n", msg)
		}
		return fmt.Errorf("audit found %d unclassified entr(ies); see %s", len(unclassified), opts.out)
	}
	return nil
}

// classifyAuditDiffs computes the symmetric drift between the syzkaller-side
// view (derived from *prog.Target) and the reFuzz-side view (derived from
// the writer's interned/emitted rows). For every drift we emit one auditDiff
// entry with an explicit Side and a non-empty Reason so the caller can
// validate that every difference has been classified.
//
// Note: resource ctor-list diffs are deferred per the Phase A doc; only
// resource names are compared in this step.
func classifyAuditDiffs(target *prog.Target, w *writer) []auditDiff {
	var diffs []auditDiff

	// --- syscalls: name set drift ---
	syzSyscallNames := make(map[string]struct{}, len(target.Syscalls))
	for _, sc := range target.Syscalls {
		syzSyscallNames[sc.Name] = struct{}{}
	}
	refuzzSyscallNames := make(map[string]struct{}, len(w.syscalls))
	for _, sr := range w.syscalls {
		refuzzSyscallNames[sr.name] = struct{}{}
	}
	for name := range syzSyscallNames {
		if _, ok := refuzzSyscallNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "syscall",
				Name:   name,
				Side:   "syzkaller_only",
				Reason: "missing_syscall_in_refuzz_emit",
			})
		}
	}
	for name := range refuzzSyscallNames {
		if _, ok := syzSyscallNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "syscall",
				Name:   name,
				Side:   "refuzz_only",
				Reason: "refuzz_emitted_extra",
			})
		}
	}
	// NR drift between matched syscalls is intentionally not emitted in this
	// step (current pin shows zero drift). When implemented it would be a
	// different reason ("syscall_nr_drift").

	// --- pseudos: name set drift ---
	syzPseudoNames := make(map[string]struct{})
	for _, sc := range pseudoDescriptionSyscalls(target) {
		syzPseudoNames[sc.Name] = struct{}{}
	}
	refuzzPseudoNames := make(map[string]struct{}, len(w.pseudoRows))
	for _, pr := range w.pseudoRows {
		refuzzPseudoNames[pr.name] = struct{}{}
	}
	for name := range syzPseudoNames {
		if _, ok := refuzzPseudoNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "pseudo",
				Name:   name,
				Side:   "syzkaller_only",
				Reason: "missing_pseudo_in_refuzz_emit",
			})
		}
	}
	for name := range refuzzPseudoNames {
		if _, ok := syzPseudoNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "pseudo",
				Name:   name,
				Side:   "refuzz_only",
				Reason: "refuzz_emitted_extra",
			})
		}
	}

	// --- resources: name set drift (ctor-list compare deferred) ---
	syzResourceNames := make(map[string]struct{}, len(target.Resources))
	for _, res := range target.Resources {
		syzResourceNames[res.Name] = struct{}{}
	}
	refuzzResourceNames := make(map[string]struct{}, len(w.resources))
	for _, rr := range w.resources {
		refuzzResourceNames[rr.name] = struct{}{}
	}
	for name := range syzResourceNames {
		if _, ok := refuzzResourceNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "resource",
				Name:   name,
				Side:   "syzkaller_only",
				Reason: "missing_resource_in_refuzz_emit",
			})
		}
	}
	for name := range refuzzResourceNames {
		if _, ok := syzResourceNames[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "resource",
				Name:   name,
				Side:   "refuzz_only",
				Reason: "refuzz_emitted_extra",
			})
		}
	}

	// --- flags: name set drift + value-set/bitmask drift on matched names ---
	//
	// Syzkaller-side flag universe: union of target.Flags (FlagDesc) names
	// and TypeName of every *prog.FlagsType reachable in target.Types. This
	// matches the count semantics used in counts.flags.syzkaller (which is
	// len(target.Flags) at the time of this writing) while still allowing
	// value-set/bitmask comparison via the typed FlagsType instances.
	syzFlagNames := make(map[string]struct{}, len(target.Flags))
	for _, fd := range target.Flags {
		syzFlagNames[fd.Name] = struct{}{}
	}
	// Index FlagsType instances by TypeName for value-set / bitmask lookup.
	syzFlagsByName := make(map[string]*prog.FlagsType)
	for _, t := range target.Types {
		if ft, ok := t.(*prog.FlagsType); ok {
			if _, dup := syzFlagsByName[ft.TypeName]; dup {
				// Multiple FlagsType entries with the same TypeName can exist
				// (typed flags collide on name in syzkaller; reFuzz uses a
				// hash suffix for symbol uniqueness). Keep the first; the
				// classifier compares value sets where they match by name
				// only — value-set drift on collisions is acceptable noise
				// and would be reported as a "both" entry.
				continue
			}
			syzFlagsByName[ft.TypeName] = ft
		}
	}

	refuzzFlagsByName := make(map[string]flagsRow, len(w.flags))
	for _, fr := range w.flags {
		// First occurrence wins; collision rows use hash-suffixed symbolName
		// but share the original TypeName.
		if _, ok := refuzzFlagsByName[fr.name]; !ok {
			refuzzFlagsByName[fr.name] = fr
		}
	}

	for name := range syzFlagNames {
		if _, ok := refuzzFlagsByName[name]; !ok {
			diffs = append(diffs, auditDiff{
				Kind:   "flags",
				Name:   name,
				Side:   "syzkaller_only",
				Reason: "not_referenced_by_emitted_syscall",
			})
		}
	}
	for name := range refuzzFlagsByName {
		if _, ok := syzFlagNames[name]; ok {
			continue
		}
		// Some refuzz flag names may correspond to typed FlagsType that
		// was reached through a syscall but has no FlagDesc declaration
		// (e.g., inline anonymous flags). Treat presence in syzFlagsByName
		// as also satisfying the "both" path so we don't flag legitimate
		// typed flags as refuzz_only.
		if _, ok := syzFlagsByName[name]; ok {
			continue
		}
		diffs = append(diffs, auditDiff{
			Kind:   "flags",
			Name:   name,
			Side:   "refuzz_only",
			Reason: "refuzz_emitted_extra",
		})
	}

	// "both" comparison: when name matches across sides AND a typed
	// *FlagsType exists on the syzkaller side, compare value-set and
	// BitMask. We only emit drift for names where we can do an apples-to-
	// apples comparison (i.e., the syzkaller side has a typed FlagsType).
	for name, fr := range refuzzFlagsByName {
		ft, ok := syzFlagsByName[name]
		if !ok {
			continue
		}
		// Compare value sets. Sort both sides; FlagsType.Vals is []uint64,
		// flagsRow.values is []int64 (already int64-cast at intern time).
		syzVals := make([]int64, len(ft.Vals))
		for i, v := range ft.Vals {
			syzVals[i] = int64(v)
		}
		refuzzVals := append([]int64(nil), fr.values...)
		sort.Slice(syzVals, func(i, j int) bool { return syzVals[i] < syzVals[j] })
		sort.Slice(refuzzVals, func(i, j int) bool { return refuzzVals[i] < refuzzVals[j] })
		if !int64SlicesEqual(syzVals, refuzzVals) {
			diffs = append(diffs, auditDiff{
				Kind:   "flags",
				Name:   name,
				Side:   "both",
				Reason: "flag_value_set_drift",
				Detail: fmt.Sprintf("syzkaller=%v refuzz=%v", syzVals, refuzzVals),
			})
		}
		if ft.BitMask != fr.isBitmask {
			diffs = append(diffs, auditDiff{
				Kind:   "flags",
				Name:   name,
				Side:   "both",
				Reason: "flag_bitmask_mode_drift",
				Detail: fmt.Sprintf("syzkaller=%v refuzz=%v", ft.BitMask, fr.isBitmask),
			})
		}
	}

	return diffs
}

// sortAuditDiffs orders diffs deterministically by (Kind, Name, Side, Reason).
func sortAuditDiffs(diffs []auditDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Kind != diffs[j].Kind {
			return diffs[i].Kind < diffs[j].Kind
		}
		if diffs[i].Name != diffs[j].Name {
			return diffs[i].Name < diffs[j].Name
		}
		if diffs[i].Side != diffs[j].Side {
			return diffs[i].Side < diffs[j].Side
		}
		return diffs[i].Reason < diffs[j].Reason
	})
}

// unclassifiedAuditEntries returns human-readable descriptions of any
// Diffs[i].Reason or Unsupported[i].Reason that are empty.
func unclassifiedAuditEntries(report auditReport) []string {
	var msgs []string
	for i, d := range report.Diffs {
		if strings.TrimSpace(d.Reason) == "" {
			msgs = append(msgs, fmt.Sprintf("diffs[%d] kind=%s name=%s side=%s missing reason", i, d.Kind, d.Name, d.Side))
		}
	}
	for i, u := range report.Unsupported {
		if strings.TrimSpace(u.Reason) == "" {
			msgs = append(msgs, fmt.Sprintf("unsupported[%d] kind=%s name=%s missing reason", i, u.Kind, u.Name))
		}
	}
	return msgs
}

func int64SlicesEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type auditReport struct {
	Target       auditTarget        `json:"target"`
	Syzkaller    auditSyzkaller     `json:"syzkaller"`
	Counts       auditCounts        `json:"counts"`
	NRBounds     auditNRBounds      `json:"nr_bounds"`
	PseudoImpl   auditPseudoImpl    `json:"pseudo_impl"`
	TypeCoverage map[string]string  `json:"type_coverage"`
	Diffs        []auditDiff        `json:"diffs"`
	Unsupported  []auditUnsupported `json:"unsupported"`
}

type auditTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type auditSyzkaller struct {
	Root             string `json:"root"`
	Pin              string `json:"pin"`
	ObservedRevision string `json:"observed_revision"`
	Pinned           bool   `json:"pinned"`
}

type auditCounts struct {
	Syscalls   auditPair       `json:"syscalls"`
	Pseudos    auditPair       `json:"pseudos"`
	Resources  auditPair       `json:"resources"`
	Flags      auditPair       `json:"flags"`
	ConstFiles auditConstFiles `json:"const_files"`
	Consts     auditConsts     `json:"consts"`
}

type auditPair struct {
	Syzkaller int    `json:"syzkaller"`
	Refuzz    int    `json:"refuzz"`
	Extractor string `json:"extractor,omitempty"`
	// Note documents count semantics when the two sides count different things
	// (e.g., flags: syzkaller side counts FlagDesc list entries, refuzz side
	// counts unique-name interned FlagsType rows). Surfaced in JSON so Phase
	// B/C/E readers do not misinterpret a count delta as the diffs[] count.
	Note string `json:"note,omitempty"`
}

type auditConstFiles struct {
	ParsedInputFiles int      `json:"parsed_input_files"`
	Sources          []string `json:"sources"`
}

type auditConsts struct {
	RefuzzEmittedEntries int `json:"refuzz_emitted_entries"`
}

type auditNRBounds struct {
	MaxRealNR    uint64 `json:"max_real_nr"`
	PseudoNRBase uint64 `json:"pseudo_nr_base"`
}

type auditPseudoImpl struct {
	Native      int `json:"native"`
	Stub        int `json:"stub"`
	Unsupported int `json:"unsupported"`
}

// auditDiff classifies a single drift between syzkaller and reFuzz metadata.
//
// Kind   - "syscall" | "pseudo" | "resource" | "flags" (extensible)
// Name   - entity name (e.g., flag TypeName, syscall name)
// Side   - "syzkaller_only" | "refuzz_only" | "both"
// Reason - non-empty = classified; empty = unclassified (= audit fails)
// Detail - optional extra context (value-set diff, NR, ctor counts, etc.)
type auditDiff struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Side   string `json:"side"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type auditUnsupported struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func (w *writer) pseudoImplCounts() (native, stub, unsupported int) {
	for _, row := range w.pseudoRows {
		switch row.impl {
		case "PseudoImplKind::kNative":
			native++
		case "PseudoImplKind::kStub":
			stub++
		default:
			unsupported++
		}
	}
	return native, stub, unsupported
}

func constSources(rows []constRow) []string {
	set := make(map[string]struct{})
	for _, row := range rows {
		if row.source == "" {
			continue
		}
		path := row.source
		if idx := strings.LastIndex(path, ":"); idx > 1 {
			path = path[:idx]
		}
		set[path] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func checkPin(opts options) error {
	pin, observed, pinned, err := pinStatus(opts)
	if err != nil {
		return err
	}
	if opts.unpinned {
		return nil
	}
	if pin == "" {
		return fmt.Errorf("pin file %s is empty", opts.pinFile)
	}
	if !pinned {
		return fmt.Errorf("syzkaller checkout revision %s does not match pin %s", observed, pin)
	}
	return nil
}

func pinStatus(opts options) (pin, observed string, pinned bool, err error) {
	if opts.pinFile != "" {
		data, readErr := os.ReadFile(opts.pinFile)
		if readErr != nil {
			if !opts.unpinned {
				return "", "", false, readErr
			}
		} else {
			pin = strings.TrimSpace(string(data))
		}
	}
	if opts.syzkallerRoot != "" {
		observed, err = gitRevision(opts.syzkallerRoot)
		if err != nil {
			return pin, "", false, err
		}
	}
	pinned = pin != "" && observed != "" && pin == observed
	return pin, observed, pinned, nil
}

func gitRevision(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w: %s", root, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// compareGeneratedDirsSplit replaces the post-V1 B-7 single-dir compare:
// consts.gen.hpp lives in the syz/generated/ schema dir, while pseudo
// metadata lives in syz/pseudo/generated/. Verify each file against its
// own checked-in dir.
func compareGeneratedDirsSplit(gotConsts, wantConsts, gotPseudo, wantPseudo string) ([]string, error) {
	cases := []struct {
		got, want, name string
	}{
		{gotConsts, wantConsts, "consts.gen.hpp"},
		{gotPseudo, wantPseudo, "pseudo_meta.gen.hpp"},
		{gotPseudo, wantPseudo, "target.gen.hpp"},
		{gotPseudo, wantPseudo, "syz_tables.gen.hpp"},
	}
	var diffs []string
	for _, c := range cases {
		got, err := os.ReadFile(filepath.Join(c.got, c.name))
		if err != nil {
			return nil, err
		}
		want, err := os.ReadFile(filepath.Join(c.want, c.name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				diffs = append(diffs, "missing "+c.name)
				continue
			}
			return nil, err
		}
		if !bytes.Equal(got, want) {
			diffs = append(diffs, "changed "+c.name)
		}
	}
	return diffs, nil
}

func dirStr(d prog.Dir) string {
	switch d {
	case prog.DirOut:
		return "kOut"
	case prog.DirInOut:
		return "kInOut"
	default:
		return "kIn"
	}
}

func dirFromString(dir string) prog.Dir {
	switch dir {
	case "kOut":
		return prog.DirOut
	case "kInOut":
		return prog.DirInOut
	default:
		return prog.DirIn
	}
}

func staticSize(t prog.Type) uint64 {
	if t == nil || t.Varlen() {
		return 0
	}
	return t.Size()
}

func uint8Clamp(v uint64) uint8 {
	if v > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(v)
}

func uint32Clamp(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

func maxForByteSize(byteSize uint8) int64 {
	if byteSize == 0 {
		return 0
	}
	if byteSize >= 8 {
		return math.MaxInt64
	}
	return int64((uint64(1) << (uint64(byteSize) * 8)) - 1)
}

func intLiteral(v int64) string {
	switch v {
	case math.MaxInt64:
		return "INT64_MAX"
	case math.MinInt64:
		return "INT64_MIN"
	case math.MaxInt32:
		return "INT32_MAX"
	default:
		return fmt.Sprintf("%dLL", v)
	}
}

func joinUint32Array(values []uint32) string {
	parts := make([]string, len(values))
	for i, val := range values {
		parts[i] = fmt.Sprintf("%du", val)
	}
	return strings.Join(parts, ",")
}

func sanitizeIdent(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r == '$' || r == '-' || r == '.' || r == '/' || r == ':' || r == '[' || r == ']' {
			r = '_'
		}
		if i == 0 && unicode.IsDigit(r) {
			b.WriteByte('_')
		}
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func cppComment(s string) string {
	s = strings.ReplaceAll(s, "*/", "* /")
	s = strings.ReplaceAll(s, "/*", "/ *")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func cppStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch c {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		default:
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\%03o", c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
