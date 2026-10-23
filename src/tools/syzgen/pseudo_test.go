package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

func TestSynthNrAssignment(t *testing.T) {
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{NR: 0, Name: "syz_foo", CallName: "syz_foo"},
		{NR: 0, Name: "syz_beta", CallName: "syz_beta"},
		{NR: 123, Name: "read", CallName: "read"},
		{NR: 0, Name: "syz_bar", CallName: "syz_bar"},
	}

	w := testWriter(t, target)
	if err := w.preparePseudoRows(); err != nil {
		t.Fatalf("preparePseudoRows: %v", err)
	}
	want := map[string]uint64{
		"syz_bar":  pseudoNrBase,
		"syz_beta": pseudoNrBase + 1,
		"syz_foo":  pseudoNrBase + 2,
	}
	for name, wantNR := range want {
		if got := w.pseudoSynth[name]; got != wantNR {
			t.Fatalf("pseudoSynth[%q] = 0x%x, want 0x%x", name, got, wantNR)
		}
	}
}

func TestPseudoCatalogClassification(t *testing.T) {
	// [F14 review fix 2026-05-06] wantCaps added so cap-mask drops /
	// retentions are also pinned at Go level (not just in regenerated
	// pseudo_meta.gen.hpp snapshot). Pre-fix a regression that left
	// kCapNeedsFuse on `syz_fuse_handle_req` would not be caught here.
	// Order-insensitive: nil and empty []string{} both mean "no caps".
	tests := []struct {
		name       string
		wantDomain string
		wantImpl   string
		wantCaps   []string
	}{
		{"syz_create_resource$binfmt", "core", "native", nil},
		{"syz_open_procfs", "file", "native", nil},
		{"syz_open_dev$loop", "device", "native", nil},
		// [v1 stub fixture — ROLLBACK: uncomment below and remove v2]
		// {"syz_genetlink_get_family_id$nbd", "net", "stub", []string{"needs_raw_net"}},
		// [v2 当前版本 — Phase D D3 把 syz_genetlink_get_family_id$* 整族升级为 native]
		{"syz_genetlink_get_family_id$nbd", "net", "native", nil},
		// [v1 ext4 was the kStub+caps mount fixture — ROLLBACK: uncomment below + remove v2]
		// {"syz_mount_image$ext4", "fs", "stub", []string{"needs_root", "needs_mount"}},

		// [v2 PR-D1.A bulk flip — 当前版本]
		// All 43 syz_mount_image$<fs> variants are now mount/native +
		// needs_root|needs_mount. Pin two representatives (ext4 with an
		// adjuster path, adfs vanilla) so a regression that breaks the
		// catalog-level uniformity (e.g., a future split that demotes
		// some fs back to fs/stub) fails fast at Go-test time.
		{"syz_mount_image$ext4", "mount", "native", []string{"needs_root", "needs_mount"}},
		{"syz_mount_image$adfs", "mount", "native", []string{"needs_root", "needs_mount"}},
		// [PR-D4 — 当前版本] USB family flipped kUnsupported→kNative,
		// caps gain needs_root per plan §10 Q6 rule 3.
		{"syz_usb_connect", "usb", "native", []string{"needs_root", "needs_usb"}},
		// [v2 PR-D3: fuse_handle_req 升 native — 当前版本]
		// Stateless reactive handler; cap dropped per plan §10 Q6
		// generalized operator-preload (C7 review fix).
		{"syz_fuse_handle_req", "fuse", "native", nil},
		// [PR-D2 — 当前版本] KVM family flipped kUnsupported→kNative,
		// caps gain needs_root per plan §10 Q6 rule 3.
		{"syz_kvm_setup_cpu$x86", "kvm", "native", []string{"needs_root", "needs_kvm"}},
		// [v2 PR-A1: io_uring trio split out as native — 当前版本]
		// Pre-PR-A1 these were classified as core/stub alongside
		// syz_btf_id_by_name. PR-A1 implements the handlers in
		// pseudo_core.cpp using PseudoRuntimeContext::RegisterNamedRegion
		// for cross-call mmap region sharing (plan §5.0).
		{"syz_io_uring_setup", "core", "native", nil},
		{"syz_io_uring_submit", "core", "native", nil},
		{"syz_io_uring_complete", "core", "native", nil},
		// [当前版本 syz 08ab311] modify_offsets 新增,走 syz_io_uring 前缀;
		// ublk 族新增,走新增的 syz_ublk 前缀 → 均 core/native。
		{"syz_io_uring_modify_offsets$generic", "core", "native", nil},
		{"syz_ublk_setup_io_uring", "core", "native", nil},
		{"syz_ublk_add_dev", "core", "native", nil},
		{"syz_ublk_setup_queues", "core", "native", nil},
		{"syz_ublk_process_io", "core", "native", nil},
		// [v3 PR-A3: btf_id_by_name 升 native — 当前版本]
		// Implementation reads /sys/kernel/btf/vmlinux and scans BTF type
		// table; mirrors upstream common_linux.h:2202-2268.
		{"syz_btf_id_by_name$bpf_lsm", "core", "native", nil},
		// [v4 PR-A2: process + memory + kfuzztest + nvme handlers 升 native — 当前版本]
		{"syz_clone", "core", "native", nil},
		{"syz_clone3", "core", "native", nil},
		{"syz_pidfd_open", "core", "native", nil},
		{"syz_pkey_set", "core", "native", nil},
		{"syz_execute_func", "core", "native", nil},
		{"syz_memcpy_off$IO_URING_METADATA_FLAGS", "core", "native", nil},
		{"syz_memcpy_off$KVM_EXIT_HYPERCALL", "core", "native", nil},
		{"syz_kfuzztest_run", "core", "native", nil},
		{"syz_socket_connect_nvme_tcp", "net", "native", nil},
		{"syz_unknown", "unknown", "unsupported", nil},
	}
	for _, tc := range tests {
		got := classifyPseudo(tc.name)
		if got.domain != tc.wantDomain || got.impl != tc.wantImpl {
			t.Fatalf("classifyPseudo(%q) = %s/%s, want %s/%s",
				tc.name, got.domain, got.impl, tc.wantDomain, tc.wantImpl)
		}
		// [F14 review fix] cap mask must also match — catches regressions
		// that flip impl correctly but forget to drop / retain a cap bit.
		if !stringSlicesEqual(got.caps, tc.wantCaps) {
			t.Fatalf("classifyPseudo(%q) caps = %v, want %v",
				tc.name, got.caps, tc.wantCaps)
		}
	}
}

func TestPseudoArgCountRecorded(t *testing.T) {
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{
			NR:       0,
			Name:     "syz_alpha",
			CallName: "syz_alpha",
			Args: []prog.Field{
				{Name: "a", Type: testIntType("a")},
				{Name: "b", Type: testIntType("b")},
				{Name: "c", Type: testIntType("c")},
			},
		},
	}

	w := testWriter(t, target)
	if err := w.preparePseudoRows(); err != nil {
		t.Fatalf("preparePseudoRows: %v", err)
	}
	if len(w.pseudoRows) != 1 {
		t.Fatalf("got %d pseudo rows, want 1", len(w.pseudoRows))
	}
	if got := w.pseudoRows[0].argCount; got != 3 {
		t.Fatalf("argCount = %d, want 3", got)
	}
}

func TestTargetMaxRealNrBelowPseudoBase(t *testing.T) {
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{NR: 0, Name: "syz_alpha", CallName: "syz_alpha"},
		{NR: 11, Name: "read", CallName: "read"},
		{NR: 451, Name: "cachestat", CallName: "cachestat"},
	}

	w := testWriter(t, target)
	if err := w.buildRows(); err != nil {
		t.Fatalf("buildRows: %v", err)
	}
	if got := w.maxRealNR; got != 451 {
		t.Fatalf("maxRealNR = %d, want 451", got)
	}
	if w.maxRealNR >= pseudoNrBase {
		t.Fatalf("maxRealNR overlaps pseudo base: max=%d base=%d", w.maxRealNR, pseudoNrBase)
	}
}

func TestRealNrUnchanged(t *testing.T) {
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{NR: 123, Name: "read", CallName: "read"},
	}
	w := testWriter(t, target)
	if err := w.buildRows(); err != nil {
		t.Fatalf("buildRows: %v", err)
	}
	if len(w.syscalls) != 1 {
		t.Fatalf("got %d syscalls, want 1", len(w.syscalls))
	}
	if got := w.syscalls[0].nr; got != 123 {
		t.Fatalf("real syscall nr = %d, want 123", got)
	}
}

func stringSlicesEqual(a, b []string) bool {
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

// TestSynthesizePseudoNRsDeterministic verifies the shared helper
// returns identical NRs across repeated invocations on the same target.
// Both syzgen emitters depend on this — the worker-facing tables and
// the typed-Target syscall list must agree on every pseudo's NR.
func TestSynthesizePseudoNRsDeterministic(t *testing.T) {
	target := testTarget()
	// [PR-D1.A — current] Both ext4 + adfs are mount/native; PR-D1.A
	// bulk-flipped all 43 syz_mount_image$* to mount/native. Test pins
	// determinism + sorted-by-name property + classification of two
	// representative fs (one with adjuster path, one vanilla pass-through)
	// so a future regression that demotes some fs back to fs/stub fails
	// fast at Go-test time.
	target.Syscalls = []*prog.Syscall{
		{NR: 0, Name: "syz_open_dev$char_raw", CallName: "syz_open_dev"},
		{NR: 0, Name: "syz_emit_ethernet", CallName: "syz_emit_ethernet"},
		{NR: 11, Name: "read", CallName: "read"},
		{NR: 0, Name: "syz_create_resource$binfmt", CallName: "syz_create_resource"},
		{NR: 0, Name: "syz_mount_image$adfs", CallName: "syz_mount_image"},
		{NR: 0, Name: "syz_mount_image$ext4", CallName: "syz_mount_image"},
	}
	first := SynthesizePseudoNRs(target)
	second := SynthesizePseudoNRs(target)

	if len(first) != 5 {
		t.Fatalf("got %d pseudo entries, want 5 (only syz_* should be synthesized)", len(first))
	}
	if _, ok := first["read"]; ok {
		t.Fatalf("read should not appear in pseudo synth map")
	}
	for name, entry := range first {
		got := second[name]
		// pseudoSpec carries a []string caps field — compare scalars
		// individually instead of struct equality.
		if got.NR != entry.NR || got.Index != entry.Index ||
			got.Spec.domain != entry.Spec.domain ||
			got.Spec.impl != entry.Spec.impl ||
			!stringSlicesEqual(got.Spec.caps, entry.Spec.caps) {
			t.Fatalf("non-deterministic synth for %q: %+v vs %+v", name, entry, got)
		}
	}

	// Sorted-by-name assignment (PR-D1 review fix A2 added mount-image fixtures):
	//   syz_create_resource$binfmt < syz_emit_ethernet <
	//   syz_mount_image$adfs < syz_mount_image$ext4 <
	//   syz_open_dev$char_raw
	wantNRs := map[string]uint64{
		"syz_create_resource$binfmt": pseudoNrBase + 0,
		"syz_emit_ethernet":          pseudoNrBase + 1,
		"syz_mount_image$adfs":       pseudoNrBase + 2,
		"syz_mount_image$ext4":       pseudoNrBase + 3,
		"syz_open_dev$char_raw":      pseudoNrBase + 4,
	}
	for name, wantNR := range wantNRs {
		if got := first[name].NR; got != wantNR {
			t.Fatalf("synth NR for %q = 0x%x, want 0x%x", name, got, wantNR)
		}
	}

	// Spec is also threaded through (consumed by typed Target emitter
	// in step 2). Catalog says syz_create_resource$* is core/native,
	// syz_open_dev$* is device/native.
	//
	// [v1 syz_emit_ethernet pinned as net/stub — ROLLBACK: uncomment below + remove v2]
	// if got := first["syz_emit_ethernet"].Spec.impl; got != "stub" {
	// 	t.Fatalf("syz_emit_ethernet impl = %q, want stub", got)
	// }
	//
	// [v3 Lane 3 close — 当前版本]
	// PR-B1 promoted syz_emit_ethernet to net/native; PR-D1 + PR-D1.A
	// promoted all 43 syz_mount_image$* to mount/native. Post-Lane-3
	// no kStub remains in production catalog. The pin set checks each
	// surviving impl-kind:
	//   * native + nil caps    : syz_emit_ethernet (PR-B1 graceful degrade)
	//   * native + caps        : syz_mount_image$ext4 (PR-D1 foundation),
	//                            syz_mount_image$adfs (PR-D1.A bulk flip)
	//   * native + nil caps    : syz_create_resource$binfmt (Tier 1)
	// If a future regression demotes any of these, the test fails.
	if got := first["syz_create_resource$binfmt"].Spec.impl; got != "native" {
		t.Fatalf("syz_create_resource impl = %q, want native", got)
	}
	if got := first["syz_emit_ethernet"].Spec.impl; got != "native" {
		t.Fatalf("syz_emit_ethernet impl = %q, want native (PR-B1)", got)
	}
	if got := first["syz_mount_image$adfs"].Spec.impl; got != "native" {
		t.Fatalf("syz_mount_image$adfs impl = %q, want native (PR-D1.A)", got)
	}
	if got := first["syz_mount_image$ext4"].Spec.impl; got != "native" {
		t.Fatalf("syz_mount_image$ext4 impl = %q, want native (PR-D1)", got)
	}
}

// TestPreparePseudoRowsUsesSharedSynth pins the cross-emitter contract:
// w.pseudoSynth (worker side) must agree with SynthesizePseudoNRs (the
// typed-Target emitter's source), so that kDefaultSyzTarget.pseudos[i]
// .nr == SyscallMeta::nr for every pseudo. Without this gate, a future
// refactor could re-fork the synthesis and silently reintroduce row #3.
func TestPreparePseudoRowsUsesSharedSynth(t *testing.T) {
	target := testTarget()
	target.Syscalls = []*prog.Syscall{
		{NR: 0, Name: "syz_open_dev$char_raw", CallName: "syz_open_dev"},
		{NR: 0, Name: "syz_emit_ethernet", CallName: "syz_emit_ethernet"},
		{NR: 11, Name: "read", CallName: "read"},
		{NR: 0, Name: "syz_create_resource$binfmt", CallName: "syz_create_resource"},
	}
	synth := SynthesizePseudoNRs(target)
	w := testWriter(t, target)
	if err := w.preparePseudoRows(); err != nil {
		t.Fatalf("preparePseudoRows: %v", err)
	}
	for name, entry := range synth {
		if got := w.pseudoSynth[name]; got != entry.NR {
			t.Fatalf("pseudoSynth[%q] = 0x%x, want 0x%x (helper)",
				name, got, entry.NR)
		}
	}
	for _, row := range w.pseudoRows {
		if got := synth[row.name].NR; got != row.nr {
			t.Fatalf("pseudoRow[%q].nr = 0x%x, want 0x%x (helper)",
				row.name, row.nr, got)
		}
	}
}

func TestCppEmitterWriteSyscallUsesSharedSynthForPseudoNR(t *testing.T) {
	target := testTarget()
	pseudo := &prog.Syscall{NR: 0, Name: "syz_open_dev$char_raw", CallName: "syz_open_dev"}
	real := &prog.Syscall{NR: 123, Name: "read", CallName: "read"}
	target.Syscalls = []*prog.Syscall{pseudo, real}

	emitter := &cppEmitter{
		target:      target,
		pseudoSynth: SynthesizePseudoNRs(target),
	}

	pseudoOut := renderSyscallForTest(t, emitter, pseudo)
	assertSetNr(t, pseudoOut, pseudoNrBase)
	if strings.Contains(pseudoOut, "m->set_nr(0uLL);") {
		t.Fatalf("pseudo syscall emitted upstream NR 0 instead of synthesized NR:\n%s", pseudoOut)
	}

	realOut := renderSyscallForTest(t, emitter, real)
	assertSetNr(t, realOut, 123)
}

func renderSyscallForTest(t *testing.T, emitter *cppEmitter, sc *prog.Syscall) string {
	t.Helper()
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	emitter.writeSyscall(w, sc)
	if err := w.Flush(); err != nil {
		t.Fatalf("flush syscall output: %v", err)
	}
	return buf.String()
}

func assertSetNr(t *testing.T, out string, nr uint64) {
	t.Helper()
	want := fmt.Sprintf("m->set_nr(%duLL);", nr)
	if !strings.Contains(out, want) {
		t.Fatalf("emitted syscall missing %q:\n%s", want, out)
	}
}
