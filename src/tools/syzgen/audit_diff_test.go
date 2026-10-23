package main

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/prog"
)

// makeFlagsType builds a minimal *prog.FlagsType for classifier tests.
func makeFlagsType(name string, vals []uint64, bitmask bool) *prog.FlagsType {
	return &prog.FlagsType{
		IntTypeCommon: prog.IntTypeCommon{
			TypeCommon: prog.TypeCommon{
				TypeName:  name,
				TypeSize:  4,
				TypeAlign: 4,
			},
		},
		Vals:    vals,
		BitMask: bitmask,
	}
}

// findDiffs filters diffs by kind/side/name (any field can be "" to ignore).
func findDiffs(diffs []auditDiff, kind, side, name string) []auditDiff {
	var out []auditDiff
	for _, d := range diffs {
		if kind != "" && d.Kind != kind {
			continue
		}
		if side != "" && d.Side != side {
			continue
		}
		if name != "" && d.Name != name {
			continue
		}
		out = append(out, d)
	}
	return out
}

// TestClassifyFlagDriftMissingOnRefuzz verifies that a flag declared in
// target.Flags but absent from w.flags shows up as syzkaller_only with the
// expected "not_referenced_by_emitted_syscall" reason.
func TestClassifyFlagDriftMissingOnRefuzz(t *testing.T) {
	target := &prog.Target{
		OS:   "linux",
		Arch: "amd64",
		Flags: []prog.FlagDesc{
			{Name: "shared_flag", Values: []string{"A", "B"}},
			{Name: "syzkaller_only_flag", Values: []string{"X"}},
		},
	}
	w := &writer{
		flags: []flagsRow{
			{name: "shared_flag", values: []int64{1, 2}, isBitmask: false},
		},
	}
	// Simulate that "shared_flag" exists as a typed FlagsType so value-set
	// comparison doesn't synthesize a drift; ditto a matching bitmask.
	target.Types = []prog.Type{
		makeFlagsType("shared_flag", []uint64{1, 2}, false),
	}

	diffs := classifyAuditDiffs(target, w)

	syzOnly := findDiffs(diffs, "flags", "syzkaller_only", "")
	if len(syzOnly) != 1 {
		t.Fatalf("got %d syzkaller_only flag diffs, want 1: %#v", len(syzOnly), syzOnly)
	}
	if syzOnly[0].Name != "syzkaller_only_flag" {
		t.Fatalf("syzkaller_only diff name=%q, want syzkaller_only_flag", syzOnly[0].Name)
	}
	if syzOnly[0].Reason != "not_referenced_by_emitted_syscall" {
		t.Fatalf("syzkaller_only diff reason=%q, want not_referenced_by_emitted_syscall", syzOnly[0].Reason)
	}
	// Reverse direction must be empty (no refuzz_only flag).
	if got := findDiffs(diffs, "flags", "refuzz_only", ""); len(got) != 0 {
		t.Fatalf("got %d refuzz_only flag diffs, want 0: %#v", len(got), got)
	}
}

// TestClassifyFlagValueSetDrift covers same name, different value sets ->
// emit a "both" + "flag_value_set_drift" entry.
func TestClassifyFlagValueSetDrift(t *testing.T) {
	target := &prog.Target{
		OS:   "linux",
		Arch: "amd64",
		Flags: []prog.FlagDesc{
			{Name: "drifted", Values: []string{"A", "B", "C"}},
		},
		Types: []prog.Type{
			makeFlagsType("drifted", []uint64{1, 2, 3}, false),
		},
	}
	w := &writer{
		flags: []flagsRow{
			{name: "drifted", values: []int64{1, 2}, isBitmask: false},
		},
	}
	diffs := classifyAuditDiffs(target, w)
	got := findDiffs(diffs, "flags", "both", "drifted")
	if len(got) != 1 {
		t.Fatalf("got %d both diffs for 'drifted', want 1: %#v", len(got), got)
	}
	if got[0].Reason != "flag_value_set_drift" {
		t.Fatalf("reason=%q, want flag_value_set_drift", got[0].Reason)
	}
	if got[0].Detail == "" {
		t.Fatalf("expected non-empty Detail for value-set drift")
	}
}

// TestClassifyFlagBitmaskDrift covers same name, different BitMask -> emit a
// "both" + "flag_bitmask_mode_drift" entry.
func TestClassifyFlagBitmaskDrift(t *testing.T) {
	target := &prog.Target{
		OS:   "linux",
		Arch: "amd64",
		Flags: []prog.FlagDesc{
			{Name: "bm_flag", Values: []string{"A", "B"}},
		},
		Types: []prog.Type{
			makeFlagsType("bm_flag", []uint64{1, 2}, true),
		},
	}
	w := &writer{
		flags: []flagsRow{
			{name: "bm_flag", values: []int64{1, 2}, isBitmask: false},
		},
	}
	diffs := classifyAuditDiffs(target, w)
	got := findDiffs(diffs, "flags", "both", "bm_flag")
	if len(got) != 1 {
		t.Fatalf("got %d both diffs for 'bm_flag', want 1: %#v", len(got), got)
	}
	if got[0].Reason != "flag_bitmask_mode_drift" {
		t.Fatalf("reason=%q, want flag_bitmask_mode_drift", got[0].Reason)
	}
}

// TestClassifyFlagBothValueAndBitmaskDrift verifies that when both Vals and
// BitMask differ, two entries are emitted.
func TestClassifyFlagBothValueAndBitmaskDrift(t *testing.T) {
	target := &prog.Target{
		OS:   "linux",
		Arch: "amd64",
		Flags: []prog.FlagDesc{
			{Name: "double_drift", Values: []string{"A"}},
		},
		Types: []prog.Type{
			makeFlagsType("double_drift", []uint64{1, 2, 3}, true),
		},
	}
	w := &writer{
		flags: []flagsRow{
			{name: "double_drift", values: []int64{1, 2}, isBitmask: false},
		},
	}
	diffs := classifyAuditDiffs(target, w)
	got := findDiffs(diffs, "flags", "both", "double_drift")
	if len(got) != 2 {
		t.Fatalf("got %d 'both' diffs, want 2: %#v", len(got), got)
	}
	reasons := map[string]bool{}
	for _, d := range got {
		reasons[d.Reason] = true
	}
	if !reasons["flag_value_set_drift"] || !reasons["flag_bitmask_mode_drift"] {
		t.Fatalf("expected both flag_value_set_drift and flag_bitmask_mode_drift; got %v", reasons)
	}
}

// TestClassifyAllAligned verifies the classifier returns no diffs when the
// two sides match exactly.
func TestClassifyAllAligned(t *testing.T) {
	target := &prog.Target{
		OS:   "linux",
		Arch: "amd64",
		Syscalls: []*prog.Syscall{
			{NR: 0, Name: "sys_a"},
			{NR: 1, Name: "sys_b"},
		},
		Resources: []*prog.ResourceDesc{
			{Name: "fd"},
			{Name: "sock"},
		},
		Flags: []prog.FlagDesc{
			{Name: "flag1", Values: []string{"A"}},
		},
		Types: []prog.Type{
			makeFlagsType("flag1", []uint64{1, 2}, false),
		},
	}
	w := &writer{
		syscalls: []syscallRow{
			{nr: 0, name: "sys_a"},
			{nr: 1, name: "sys_b"},
		},
		resources: []resourceRow{
			{name: "fd"},
			{name: "sock"},
		},
		flags: []flagsRow{
			{name: "flag1", values: []int64{1, 2}, isBitmask: false},
		},
	}
	diffs := classifyAuditDiffs(target, w)
	if len(diffs) != 0 {
		t.Fatalf("expected zero diffs for fully aligned input, got %d: %#v", len(diffs), diffs)
	}
}

// TestSortAuditDiffsDeterministic verifies the sort yields a stable order
// independent of insertion order.
func TestSortAuditDiffsDeterministic(t *testing.T) {
	a := []auditDiff{
		{Kind: "flags", Name: "z_flag", Side: "syzkaller_only", Reason: "not_referenced_by_emitted_syscall"},
		{Kind: "syscall", Name: "sys_b", Side: "syzkaller_only", Reason: "missing_syscall_in_refuzz_emit"},
		{Kind: "flags", Name: "a_flag", Side: "both", Reason: "flag_value_set_drift"},
		{Kind: "flags", Name: "a_flag", Side: "both", Reason: "flag_bitmask_mode_drift"},
		{Kind: "syscall", Name: "sys_a", Side: "syzkaller_only", Reason: "missing_syscall_in_refuzz_emit"},
	}
	b := []auditDiff{
		{Kind: "syscall", Name: "sys_a", Side: "syzkaller_only", Reason: "missing_syscall_in_refuzz_emit"},
		{Kind: "flags", Name: "a_flag", Side: "both", Reason: "flag_bitmask_mode_drift"},
		{Kind: "flags", Name: "z_flag", Side: "syzkaller_only", Reason: "not_referenced_by_emitted_syscall"},
		{Kind: "syscall", Name: "sys_b", Side: "syzkaller_only", Reason: "missing_syscall_in_refuzz_emit"},
		{Kind: "flags", Name: "a_flag", Side: "both", Reason: "flag_value_set_drift"},
	}
	sortAuditDiffs(a)
	sortAuditDiffs(b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("sort is not deterministic across input orderings:\n a=%#v\n b=%#v", a, b)
	}
}

// TestUnclassifiedAuditEntries flags diffs with empty Reason as unclassified.
func TestUnclassifiedAuditEntries(t *testing.T) {
	rep := auditReport{
		Diffs: []auditDiff{
			{Kind: "flags", Name: "ok", Side: "both", Reason: "flag_value_set_drift"},
			{Kind: "flags", Name: "bad", Side: "syzkaller_only", Reason: ""},
		},
		Unsupported: []auditUnsupported{
			{Kind: "type", Name: "compressed buffer", Reason: "no native image generator in Phase A"},
			{Kind: "type", Name: "missing reason", Reason: "   "},
		},
	}
	msgs := unclassifiedAuditEntries(rep)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 unclassified entries, got %d: %v", len(msgs), msgs)
	}
}

// TestClassifyMissingSyscallAndResource verifies non-flag kinds are also
// emitted with classified reasons.
func TestClassifyMissingSyscallAndResource(t *testing.T) {
	target := &prog.Target{
		Syscalls: []*prog.Syscall{
			{NR: 0, Name: "sys_a"},
			{NR: 1, Name: "sys_only_in_syz"},
		},
		Resources: []*prog.ResourceDesc{
			{Name: "fd"},
			{Name: "res_only_in_syz"},
		},
	}
	w := &writer{
		syscalls: []syscallRow{
			{nr: 0, name: "sys_a"},
			{nr: 99, name: "sys_only_in_refuzz"},
		},
		resources: []resourceRow{
			{name: "fd"},
			{name: "res_only_in_refuzz"},
		},
	}
	diffs := classifyAuditDiffs(target, w)

	// Verify each expected entry exists with the right reason.
	want := []auditDiff{
		{Kind: "syscall", Name: "sys_only_in_syz", Side: "syzkaller_only", Reason: "missing_syscall_in_refuzz_emit"},
		{Kind: "syscall", Name: "sys_only_in_refuzz", Side: "refuzz_only", Reason: "refuzz_emitted_extra"},
		{Kind: "resource", Name: "res_only_in_syz", Side: "syzkaller_only", Reason: "missing_resource_in_refuzz_emit"},
		{Kind: "resource", Name: "res_only_in_refuzz", Side: "refuzz_only", Reason: "refuzz_emitted_extra"},
	}
	for _, w := range want {
		found := findDiffs(diffs, w.Kind, w.Side, w.Name)
		if len(found) != 1 {
			t.Errorf("missing expected diff %#v; got %#v", w, found)
			continue
		}
		if found[0].Reason != w.Reason {
			t.Errorf("diff %s/%s/%s reason=%q, want %q", w.Kind, w.Side, w.Name, found[0].Reason, w.Reason)
		}
	}
}
