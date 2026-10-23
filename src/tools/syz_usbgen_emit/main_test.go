// Golden-bytes test for syz_usbgen_emit.
//
// Re-parses sys/linux/init_vusb_ids.go in-memory, emits the .gen.hpp
// and .gen.cpp into a temp directory, and asserts byte-equal vs the
// checked-in copies under reFuzz/program/. Catches drift if upstream
// init_vusb_ids.go changes shape (or if our emitter output changes
// without a deliberate regen).
//
// To regenerate after an intentional emitter change or upstream
// rebase:
//
//   make syz_regen_usb
//
// then re-run this test to lock the new bytes.

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// parseTestInput re-parses the upstream Go file from disk; mirrors the
// CLI main()'s parser.ParseFile call.
func parseTestInput(t *testing.T, path string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file
}

// repoRoots returns the two paths needed by the test:
// - upstream syzkaller's sys/linux/init_vusb_ids.go
// - reFuzz/program/{include,src}/.../generated/ tree root
//
// They are derived from this test file's location so the test runs
// regardless of the working directory.
func repoRoots(t *testing.T) (inputGo, hppPath, cppPath string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../reFuzz/tools/syz_usbgen_emit/main_test.go
	toolDir := filepath.Dir(thisFile)
	refuzzRoot := filepath.Dir(filepath.Dir(toolDir)) // .../reFuzz
	syzRoot := filepath.Dir(refuzzRoot)               // .../syzkaller
	return filepath.Join(syzRoot, "sys", "linux", "init_vusb_ids.go"),
		filepath.Join(refuzzRoot, "program", "include", "refuzz",
			"program", "syz", "linux", "generated", "usb_ids.gen.hpp"),
		filepath.Join(refuzzRoot, "program", "src", "syz", "linux",
			"generated", "usb_ids.gen.cpp")
}

// TestEmitterByteEqualWithCheckedIn re-runs the full emit pipeline
// and compares against the checked-in files. Any drift fails the test
// with a hint to run `make syz_regen_usb`.
func TestEmitterByteEqualWithCheckedIn(t *testing.T) {
	inputGo, hppPath, cppPath := repoRoots(t)

	if _, err := os.Stat(inputGo); err != nil {
		t.Skipf("upstream input not found at %s: %v", inputGo, err)
	}
	if _, err := os.Stat(hppPath); err != nil {
		t.Fatalf("checked-in header missing — run make syz_regen_usb: %v", err)
	}
	if _, err := os.Stat(cppPath); err != nil {
		t.Fatalf("checked-in source missing — run make syz_regen_usb: %v", err)
	}

	tmpDir := t.TempDir()
	freshHpp := filepath.Join(tmpDir, "usb_ids.gen.hpp")
	freshCpp := filepath.Join(tmpDir, "usb_ids.gen.cpp")

	// Drive the public emit functions directly; this matches what the
	// CLI does in main(). If the API in main.go diverges from what the
	// CLI does, this test should be updated to follow the new path.
	{
		// Mirror the CLI's parse+evaluate sequence.
		file := parseTestInput(t, inputGo)

		usbIds, err := evalMap(file, "usbIds")
		if err != nil {
			t.Fatalf("evalMap usbIds: %v", err)
		}
		hidIds, err := evalMap(file, "hidIds")
		if err != nil {
			t.Fatalf("evalMap hidIds: %v", err)
		}
		usbIdsAll, err := evalConcat(file, "usbIdsAll",
			map[string]map[string]string{"usbIds": usbIds})
		if err != nil {
			t.Fatalf("evalConcat usbIdsAll: %v", err)
		}
		hidIdsAll, err := evalConcat(file, "hidIdsAll",
			map[string]map[string]string{"hidIds": hidIds})
		if err != nil {
			t.Fatalf("evalConcat hidIdsAll: %v", err)
		}

		if err := writeHeader(freshHpp); err != nil {
			t.Fatalf("writeHeader: %v", err)
		}
		if err := writeSource(freshCpp, inputGo,
			usbIds, hidIds, usbIdsAll, hidIdsAll); err != nil {
			t.Fatalf("writeSource: %v", err)
		}
	}

	checkByteEqual(t, "usb_ids.gen.hpp", hppPath, freshHpp)
	checkByteEqual(t, "usb_ids.gen.cpp", cppPath, freshCpp)
}

func checkByteEqual(t *testing.T, label, checkedIn, fresh string) {
	t.Helper()
	a, err := os.ReadFile(checkedIn)
	if err != nil {
		t.Fatalf("read %s: %v", checkedIn, err)
	}
	b, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatalf("read %s: %v", fresh, err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("%s: %d bytes checked-in vs %d bytes regenerated; "+
			"emitter output drifted from checked-in copy. "+
			"Run `make syz_regen_usb` if the change is intentional.",
			label, len(a), len(b))
	}
}
