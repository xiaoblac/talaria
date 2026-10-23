// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// csource_target_info_check — drift detector for the C++
// ICSourceTargetInfo Linux/amd64 singleton.
//
// Reads upstream sys/targets/targets.go's Linux/AMD64 entry plus the
// data-mmap prog produced by sys/targets.MakePosixMmap(target,
// false, true)(), serializes the latter via prog.SerializeForExec,
// and dumps a JSON fixture. The Go-side test (main_test.go)
// re-emits the same fixture in-memory and compares against the
// checked-in fixture.json. Upstream rebase that touches Linux/AMD64
// (CFlags / CPP / CCompiler / NeedSyscallDefine / ExecutorUsesForkServer)
// or MakePosixMmap fails the test until the C++ singleton is
// updated to match.
//
// This tool is operator-driven: run `go run
// ./tools/csource_target_info_check -refresh` to update the fixture
// after a deliberate upstream sync. Without -refresh it acts as a
// pure read-only emitter (the test harness uses the in-memory path).

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"

	// Side-effect import — registers all OS schemas so
	// prog.GetTarget("linux", "amd64") works.
	_ "github.com/google/syzkaller/sys"
)

// TimeoutSample mirrors what the C++ ICSourceTargetInfo.timeouts(slowdown)
// returns. Compared against several slowdown values so any drift in
// upstream Timeouts (Scale cap, Syscall vs Program scaling factor)
// surfaces immediately. `Scale` is dimensionless conceptually but
// upstream stores it as a time.Duration (raw nanosecond count), so
// the JSON field is the raw integer (e.g. 1, 3, 3).
type TimeoutSample struct {
	Slowdown  int   `json:"slowdown"`
	Scale     int64 `json:"scale"`         // dimensionless (1, 3, 3 for slowdown 1, 3, 10)
	ProgramMs int64 `json:"program_ms"`
	SyscallMs int64 `json:"syscall_ms"`
}

type Fixture struct {
	GOOS                   string                       `json:"goos"`
	GOARCH                 string                       `json:"goarch"`
	PtrSize                uint64                       `json:"ptr_size"`
	PageSize               uint64                       `json:"page_size"`
	NumPages               uint64                       `json:"num_pages"`
	CFlags                 []string                     `json:"cflags"`
	CPP                    string                       `json:"cpp"`
	CCompiler              string                       `json:"c_compiler"`
	SyscallPrefix          string                       `json:"syscall_prefix"`
	ExecutorUsesForkServer bool                         `json:"executor_uses_fork_server"`
	NeedDefSamples         []bool                       `json:"need_syscall_define_samples"` // for nr ∈ {0, 312, 313, 999}
	HostGOOS               string                       `json:"host_goos"`
	PseudoSyscallDeps      map[string][]string          `json:"pseudo_syscall_deps"`
	Timeouts               []TimeoutSample              `json:"timeouts"`
	MmapProgSerializeHex   string                       `json:"mmap_prog_serialize_hex"`
}

func mustBuild() Fixture {
	t, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		log.Fatalf("GetTarget linux/amd64: %v", err)
	}
	sysT := targets.Get(t.OS, t.Arch)
	if sysT == nil {
		log.Fatalf("targets.Get returned nil for linux/amd64")
	}

	// Build the data-mmap prog the way csource consumes it.
	// target.DataMmapProg() flags the prog as `isUnsafe` so SerializeForExec's
	// validation pass allows the surrounding PROT_NONE pages.
	mmapProg := t.DataMmapProg()
	exec, err := mmapProg.SerializeForExec()
	if err != nil {
		log.Fatalf("SerializeForExec mmap prog: %v", err)
	}
	_ = targets.MakePosixMmap // keep import consistent across refactors

	timeoutSamples := []TimeoutSample{}
	for _, sl := range []int{1, 3, 10} {
		to := sysT.Timeouts(sl)
		timeoutSamples = append(timeoutSamples, TimeoutSample{
			Slowdown:  sl,
			Scale:     int64(to.Scale),     // raw — see TimeoutSample doc
			ProgramMs: int64(to.Program / time.Millisecond),
			SyscallMs: int64(to.Syscall / time.Millisecond),
		})
	}

	return Fixture{
		GOOS:                   t.OS,
		GOARCH:                 t.Arch,
		PtrSize:                t.PtrSize,
		PageSize:               t.PageSize,
		NumPages:               t.NumPages,
		CFlags:                 sysT.CFlags,
		CPP:                    sysT.CPP,
		CCompiler:              sysT.CCompiler,
		SyscallPrefix:          sysT.SyscallPrefix,
		ExecutorUsesForkServer: sysT.ExecutorUsesForkServer,
		NeedDefSamples: []bool{
			sysT.NeedSyscallDefine(0),
			sysT.NeedSyscallDefine(312),
			sysT.NeedSyscallDefine(313),
			sysT.NeedSyscallDefine(999),
		},
		HostGOOS:             "linux", // build host assumption (CI is Linux)
		PseudoSyscallDeps:    sysT.PseudoSyscallDeps,
		Timeouts:             timeoutSamples,
		MmapProgSerializeHex: hex.EncodeToString(exec),
	}
}

func main() {
	defaultOut := relativeFromExecutable("../fixture.json")
	outPath := flag.String("out", defaultOut, "path to fixture.json")
	refresh := flag.Bool("refresh", false,
		"if set, write a refreshed fixture.json to -out")
	flag.Parse()

	fix := mustBuild()
	data, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if !*refresh {
		fmt.Printf("%s\n", data)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}
	// Ensure trailing newline so file ends cleanly.
	data = append(data, '\n')
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Fprintf(os.Stderr, "csource_target_info_check: wrote %s\n", *outPath)
}

func relativeFromExecutable(rel string) string {
	exe, err := os.Executable()
	if err != nil {
		return rel
	}
	return filepath.Join(filepath.Dir(exe), rel)
}
