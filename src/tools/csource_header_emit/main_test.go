// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Golden-bytes test for csource_header_emit.
//
// Re-runs the emitter in-memory against the upstream
// executor/common*.h sources and asserts byte-equal vs the
// checked-in csource_common_source.gen.cpp. Catches drift if
// upstream changes those headers (or if the emitter's own output
// shape changes without a deliberate regen).
//
// To regenerate after an intentional emitter change or upstream
// rebase:
//   make syz_regen_csource_common
// then re-run this test to lock the new bytes.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoLayout(t *testing.T) (syzRoot, genCpp string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../reFuzz/tools/csource_header_emit/main_test.go
	toolDir := filepath.Dir(thisFile)
	refuzzRoot := filepath.Dir(filepath.Dir(toolDir))
	syzRoot = filepath.Dir(refuzzRoot)
	genCpp = filepath.Join(refuzzRoot, "crash", "repro", "csource", "src",
		"csource_common_source.gen.cpp")
	return
}

func TestEmitterByteEqualWithCheckedIn(t *testing.T) {
	syzRoot, genCpp := repoLayout(t)
	if _, err := os.Stat(filepath.Join(syzRoot, "executor", "common.h")); err != nil {
		t.Skipf("upstream executor/common.h missing: %v", err)
	}
	if _, err := os.Stat(genCpp); err != nil {
		t.Fatalf("checked-in .gen.cpp missing — run "+
			"`make syz_regen_csource_common`: %v", err)
	}

	bundled, err := buildCommonHeader(filepath.Join(syzRoot, "executor"))
	if err != nil {
		t.Fatalf("buildCommonHeader: %v", err)
	}

	tmpDir := t.TempDir()
	freshPath := filepath.Join(tmpDir, "csource_common_source.gen.cpp")
	if err := writeSource(freshPath, bundled); err != nil {
		t.Fatalf("writeSource: %v", err)
	}

	checkedIn, err := os.ReadFile(genCpp)
	if err != nil {
		t.Fatalf("read %s: %v", genCpp, err)
	}
	fresh, err := os.ReadFile(freshPath)
	if err != nil {
		t.Fatalf("read %s: %v", freshPath, err)
	}
	if !bytes.Equal(checkedIn, fresh) {
		t.Errorf("csource_common_source.gen.cpp drift: %d bytes "+
			"checked-in vs %d bytes regenerated. Run "+
			"`make syz_regen_csource_common` if intentional.",
			len(checkedIn), len(fresh))
	}
}

// TestOnlyKnownQuotedIncludesRemain — after expansion the bundled
// blob's only remaining `#include "..."` is `common_ext_example.h`
// (intentionally not expanded by upstream embed.go and held behind
// SYZ_TEST_COMMON_EXT_EXAMPLE in common.h, so cpp prunes it at
// Write() time). Any other quoted include slipping through would
// break the cpp pipeline since we run -nostdinc.
func TestOnlyKnownQuotedIncludesRemain(t *testing.T) {
	syzRoot, _ := repoLayout(t)
	if _, err := os.Stat(filepath.Join(syzRoot, "executor", "common.h")); err != nil {
		t.Skipf("upstream executor/common.h missing: %v", err)
	}
	bundled, err := buildCommonHeader(filepath.Join(syzRoot, "executor"))
	if err != nil {
		t.Fatalf("buildCommonHeader: %v", err)
	}
	want := map[string]bool{
		"common_ext_example.h": true,
	}
	got := make(map[string]bool)
	rest := bundled
	for {
		i := bytes.Index(rest, []byte("#include \""))
		if i < 0 {
			break
		}
		rest = rest[i+len("#include \""):]
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			t.Fatalf("malformed #include in bundled output")
		}
		got[string(rest[:j])] = true
		rest = rest[j+1:]
	}
	for inc := range got {
		if !want[inc] {
			t.Errorf("unexpected unresolved #include %q in bundled output",
				inc)
		}
	}
}

// TestParityWithUpstreamCommonHeader — direct byte-equal vs upstream
// executor.CommonHeader. This is the strongest integrity check: it
// verifies our reimplementation produces the same bytes upstream
// would, without any checked-in fixture in between. Build-time-only
// dependency on upstream — the C++ csource module is not affected.
func TestParityWithUpstreamCommonHeader(t *testing.T) {
	// Lazy import via reflection-free code: the upstream package is
	// available at build time because reFuzz lives under syzkaller's
	// go module. Importing it here is a build-time-only dependency
	// that never reaches the C++ csource runtime.
	upstream := loadUpstreamCommonHeader(t)
	if upstream == nil {
		return // skipped
	}

	syzRoot, _ := repoLayout(t)
	if _, err := os.Stat(filepath.Join(syzRoot, "executor", "common.h")); err != nil {
		t.Skipf("upstream executor/common.h missing: %v", err)
	}
	ours, err := buildCommonHeader(filepath.Join(syzRoot, "executor"))
	if err != nil {
		t.Fatalf("buildCommonHeader: %v", err)
	}
	if !bytes.Equal(upstream, ours) {
		t.Errorf("reFuzz emitter drift vs upstream executor.CommonHeader: "+
			"%d bytes upstream vs %d bytes ours", len(upstream), len(ours))
	}
}
