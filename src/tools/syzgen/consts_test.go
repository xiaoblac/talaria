package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func writeConstFile(t *testing.T, root string, name string, body string) {
	t.Helper()
	dir := filepath.Join(root, "sys", "linux")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir const dir: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestParseConstLine(t *testing.T) {
	tests := []struct {
		line string
		ok   bool
		want int64
	}{
		{"AT_FDCWD = 18446744073709551516", true, -100},
		{"PLAIN = 7", true, 7},
		{"OVERRIDE = 1, amd64:2, arm64:3", true, 2},
		{"GROUP = 386:arm64:???, amd64:9", true, 9},
		{"DROP = 1, amd64:???", false, 0},
		{"NO_DEFAULT = arm64:5", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.line, func(t *testing.T) {
			_, got, ok, recognized, err := parseConstLine(tc.line, "amd64")
			if err != nil {
				t.Fatalf("parseConstLine: %v", err)
			}
			if !recognized {
				t.Fatalf("line was not recognized")
			}
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("value = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseAllConsts(t *testing.T) {
	root := t.TempDir()
	writeConstFile(t, root, "a.txt.const", `
# generated
arches = 386, amd64, arm64
AT_FDCWD = 18446744073709551516
A_DEFAULT = 7
A_OVERRIDE = 1, amd64:2
A_DROP = 3, amd64:???
A_NODEFAULT = arm64:9
DUP = 4
`)
	writeConstFile(t, root, "b_amd64.const", `
DUP = 4
GROUP = 386:arm64:???, amd64:9
BAD_EXPR = 1 << 2
`)
	writeConstFile(t, root, "c_arm64.const", `
arches = arm64
A_DEFAULT = 99
`)

	result, err := parseAllConsts(root, "linux", "amd64")
	if err != nil {
		t.Fatalf("parseAllConsts: %v", err)
	}
	if result.stats.Emitted != 5 {
		t.Fatalf("emitted = %d, want 5", result.stats.Emitted)
	}
	if result.stats.Dropped != 2 {
		t.Fatalf("dropped = %d, want 2", result.stats.Dropped)
	}
	if result.stats.Duplicate != 1 {
		t.Fatalf("duplicate = %d, want 1", result.stats.Duplicate)
	}
	if result.stats.Warnings != 1 {
		t.Fatalf("warnings = %d, want 1", result.stats.Warnings)
	}

	got := map[string]int64{}
	for _, row := range result.rows {
		got[row.name] = row.value
	}
	if got["AT_FDCWD"] != -100 || got["A_OVERRIDE"] != 2 || got["GROUP"] != 9 {
		t.Fatalf("unexpected parsed consts: %#v", got)
	}
	if _, ok := got["A_DROP"]; ok {
		t.Fatalf("A_DROP should be absent")
	}
}

func TestEmitConstsFile(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	writeConstFile(t, root, "a.txt.const", `
arches = 386, amd64, arm64
AT_FDCWD = 18446744073709551516
GROUP = 386:arm64:???, amd64:9
DROP = amd64:???
`)

	w := newWriter(&prog.Target{OS: "linux", Arch: "amd64"}, out, out)
	w.syzkallerRoot = root
	if err := w.emitConstsFile(); err != nil {
		t.Fatalf("emitConstsFile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(out, "consts.gen.hpp"))
	if err != nil {
		t.Fatalf("read consts.gen.hpp: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"namespace refuzz::fuzzer::syz::consts",
		"inline constexpr int64_t kSyzConst_AT_FDCWD = -100LL;",
		"inline constexpr int64_t kSyzConst_GROUP = 9LL;",
		"inline constexpr uint32_t kSyzConstCount = 2u;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("consts.gen.hpp missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "DROP") {
		t.Fatalf("DROP should not be emitted:\n%s", text)
	}
}

func TestParseAllConstsRealSyzkaller(t *testing.T) {
	root := os.Getenv("SYZKALLER_ROOT")
	if root == "" {
		t.Skip("set SYZKALLER_ROOT to run real syzkaller .const coverage test")
	}
	result, err := parseAllConsts(root, "linux", "amd64")
	if err != nil {
		t.Fatalf("parseAllConsts: %v", err)
	}
	if result.stats.Warnings != 0 {
		t.Fatalf("warnings = %d, first warnings: %v", result.stats.Warnings, result.warnings)
	}
	if result.stats.Emitted < 10000 {
		t.Fatalf("emitted = %d, want at least 10000", result.stats.Emitted)
	}

	got := map[string]int64{}
	for _, row := range result.rows {
		got[row.name] = row.value
	}
	expected := map[string]int64{
		"AT_FDCWD":                -100,
		"__NR_ioctl":              16,
		"MAP_SHARED":              1,
		"KVM_SET_GUEST_DEBUG":     1078505115,
		"LOOP_CTL_GET_FREE":       19586,
		"SYZ_MOUNT_IMAGE_TIMEOUT": 4000,
	}
	for name, want := range expected {
		if got[name] != want {
			t.Fatalf("%s = %d, want %d", name, got[name], want)
		}
	}
}
