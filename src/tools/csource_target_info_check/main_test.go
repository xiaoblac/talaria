// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Drift detector test for the C++ ICSourceTargetInfo Linux/amd64
// singleton.
//
// Re-runs the in-memory fixture build and compares against the
// checked-in fixture.json. Upstream rebase that changes Linux/amd64
// CFlags / CPP / CCompiler / NeedSyscallDefine / ExecutorUsesForkServer
// or MakePosixMmap fails the test until both fixture.json and the
// C++ singleton in
// crash/repro/csource/src/linux/csource_target_info_linux_amd64.cpp
// are refreshed in the same commit.
//
// Refresh:
//   go run ./tools/csource_target_info_check -refresh \
//       -out ./tools/csource_target_info_check/fixture.json
// then update the C++ singleton to match.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "fixture.json")
}

func TestFixtureMatchesUpstream(t *testing.T) {
	path := fixturePath(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture.json missing — run `go run "+
			"./tools/csource_target_info_check -refresh`: %v", err)
	}

	checkedIn, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	fix := mustBuild()
	fresh, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fresh = append(fresh, '\n')

	if !bytes.Equal(checkedIn, fresh) {
		t.Errorf("fixture.json drift: %d bytes checked-in vs %d "+
			"regenerated. The C++ singleton in "+
			"crash/repro/csource/src/linux/"+
			"csource_target_info_linux_amd64.cpp also needs an "+
			"update to match. Run `go run "+
			"./tools/csource_target_info_check -refresh` then "+
			"sync the C++ side.",
			len(checkedIn), len(fresh))
	}
}
