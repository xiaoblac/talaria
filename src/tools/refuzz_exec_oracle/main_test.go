package main

import (
	"encoding/binary"
	"math"
	"testing"
)

// buildRawOutput synthesizes a worker output buffer:
//
//	[SyzExecResult × nCalls] [uint64 × len(tail)] [optional trailing junk]
//
// Each SyzExecResult occupies 24 B with the layout used by reFuzz worker:
// int64 ret, int32 err, uint32 flags, uint32 cover_offset, uint32 cover_count.
func buildRawOutput(heads []refCall, tail []uint64, junk []byte) []byte {
	out := make([]byte, 0, len(heads)*syzExecResultSize+len(tail)*8+len(junk))
	for _, h := range heads {
		buf := make([]byte, syzExecResultSize)
		binary.LittleEndian.PutUint64(buf[0:8], uint64(h.Ret))
		binary.LittleEndian.PutUint32(buf[8:12], uint32(h.Err))
		binary.LittleEndian.PutUint32(buf[12:16], h.Flags)
		binary.LittleEndian.PutUint32(buf[16:20], h.CoverOffset)
		binary.LittleEndian.PutUint32(buf[20:24], h.CoverCount)
		out = append(out, buf...)
	}
	tb := make([]byte, len(tail)*8)
	for i, v := range tail {
		binary.LittleEndian.PutUint64(tb[i*8:i*8+8], v)
	}
	out = append(out, tb...)
	out = append(out, junk...)
	return out
}

func TestDecodeRefOutput_HappyPath(t *testing.T) {
	// 3 calls; call 0 has 2 PCs, call 1 has 0 PCs, call 2 has 3 PCs.
	// coverage_tail layout: [pc0_0 pc0_1 pc2_0 pc2_1 pc2_2]
	heads := []refCall{
		{Ret: 0, Err: 0, Flags: 0x1, CoverOffset: 0, CoverCount: 2},
		{Ret: -1, Err: 38, Flags: 0x3, CoverOffset: 0, CoverCount: 0},
		{Ret: 5, Err: 0, Flags: 0x1, CoverOffset: 2, CoverCount: 3},
	}
	tail := []uint64{0x100, 0x101, 0x200, 0x201, 0x202}
	raw := buildRawOutput(heads, tail, nil)

	calls, gotTail, ok := decodeRefOutput(raw, 3)
	if !ok {
		t.Fatal("decodeRefOutput failed on well-formed input")
	}
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(calls))
	}
	if calls[1].Err != 38 || calls[2].CoverOffset != 2 {
		t.Fatalf("head fields not preserved: %+v", calls)
	}
	if len(gotTail) != 5 {
		t.Fatalf("tail len = %d, want 5", len(gotTail))
	}
	for i, want := range tail {
		if gotTail[i] != want {
			t.Errorf("tail[%d] = %#x, want %#x", i, gotTail[i], want)
		}
	}
	// refCoverSlice on call 0: 2 entries from offset 0
	c0 := refCoverSlice(gotTail, calls[0].CoverOffset, calls[0].CoverCount)
	if len(c0) != 2 || c0[0] != 0x100 || c0[1] != 0x101 {
		t.Errorf("call 0 cover slice wrong: %v", c0)
	}
	// refCoverSlice on call 1: empty
	if c1 := refCoverSlice(gotTail, 0, 0); len(c1) != 0 {
		t.Errorf("call 1 empty slice should be empty, got %v", c1)
	}
}

func TestDecodeRefOutput_TruncatedHeads(t *testing.T) {
	// 2 calls expected but raw only contains 1.5 heads worth of bytes.
	raw := make([]byte, syzExecResultSize+12)
	calls, tail, ok := decodeRefOutput(raw, 2)
	if ok {
		t.Errorf("expected ok=false on truncated heads")
	}
	if calls != nil || tail != nil {
		t.Errorf("calls/tail must be nil when head-truncated (call_count_mismatch path)")
	}
}

func TestDecodeRefOutput_TailOutOfBounds(t *testing.T) {
	// Heads claim cover_offset=10 cover_count=5 → end=15 uint64s, but the
	// raw buffer has only 2 uint64s of tail. Should return ok=false but
	// still surface decoded heads (so wire-equivalence keeps running).
	heads := []refCall{
		{Ret: 0, Err: 0, Flags: 0x1, CoverOffset: 10, CoverCount: 5},
	}
	tail := []uint64{0x100, 0x101}
	raw := buildRawOutput(heads, tail, nil)

	calls, gotTail, ok := decodeRefOutput(raw, 1)
	if ok {
		t.Errorf("expected ok=false for tail OOB")
	}
	if gotTail != nil {
		t.Errorf("tail must be nil on OOB")
	}
	if len(calls) != 1 {
		t.Errorf("calls should be returned even on tail OOB; got %d", len(calls))
	}
	if calls[0].CoverCount != 5 {
		t.Errorf("call header not preserved on OOB path")
	}
}

func TestDecodeRefOutput_TrailingPackets(t *testing.T) {
	// Worker appends packets after coverage_tail — decoder must stop at
	// maxEnd*8 and not blow up on the extra bytes.
	heads := []refCall{
		{Ret: 0, Err: 0, Flags: 0x1, CoverOffset: 0, CoverCount: 2},
	}
	tail := []uint64{0x100, 0x101}
	junk := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	raw := buildRawOutput(heads, tail, junk)

	calls, gotTail, ok := decodeRefOutput(raw, 1)
	if !ok {
		t.Fatal("decoder should accept trailing junk after coverage_tail")
	}
	if len(calls) != 1 || len(gotTail) != 2 {
		t.Fatalf("calls=%d tail=%d", len(calls), len(gotTail))
	}
}

// Pin the call-site policy: both-empty calls go into the BothEmpty bucket
// and do NOT inflate KCovJaccardSum/Count, even though jaccardU64(∅,∅)==1.0
// by the empty-set identity. Per plan §13.4.1: counting them would lift
// jaccard_mean with free 1.0 contributions when neither side actually
// observed any kernel paths.
func TestAccumKCovJaccard_BothEmptySeparation(t *testing.T) {
	rep := &report{}

	// Both empty → bucketed. Executed bits are both true (a syscall ran on
	// each side, but produced no PCs — e.g. exit-style fast call). Bucket
	// stays "both empty" rather than "one-side unavailable" because both
	// actually executed.
	accumKCovJaccard(rep, nil, true, nil, true)
	if rep.KCovJaccardBothEmptyCount != 1 {
		t.Fatalf("BothEmpty=%d, want 1", rep.KCovJaccardBothEmptyCount)
	}
	if rep.KCovJaccardCount != 0 || rep.KCovJaccardSum != 0 {
		t.Fatalf("both-empty leaked into sum/count: sum=%v count=%d",
			rep.KCovJaccardSum, rep.KCovJaccardCount)
	}

	// One-side empty, BOTH executed → real "no overlap" evidence, jaccard=0.
	accumKCovJaccard(rep, []uint64{1, 2}, true, nil, true)
	if rep.KCovJaccardCount != 1 || rep.KCovJaccardSum != 0 {
		t.Fatalf("one-empty: sum=%v count=%d, want sum=0 count=1",
			rep.KCovJaccardSum, rep.KCovJaccardCount)
	}

	// Identical pair counts as 1.0.
	accumKCovJaccard(rep, []uint64{0xA, 0xB}, true, []uint64{0xB, 0xA}, true)
	if rep.KCovJaccardCount != 2 || math.Abs(rep.KCovJaccardSum-1.0) > 1e-9 {
		t.Fatalf("identical: sum=%v count=%d, want sum=1 count=2",
			rep.KCovJaccardSum, rep.KCovJaccardCount)
	}

	// BothEmpty bucket stayed isolated through all three calls.
	if rep.KCovJaccardBothEmptyCount != 1 {
		t.Fatalf("BothEmpty drifted to %d after non-empty calls",
			rep.KCovJaccardBothEmptyCount)
	}

	// Mean should ignore the BothEmpty bucket → (0 + 1) / 2 = 0.5.
	mean := rep.KCovJaccardSum / float64(rep.KCovJaccardCount)
	if math.Abs(mean-0.5) > 1e-9 {
		t.Fatalf("jaccard_mean=%v, want 0.5 (BothEmpty must not inflate)", mean)
	}
}

// §13.6 T1.D: when one side's call didn't execute but the other has cover,
// the comparison must not be folded into Jaccard sum — it's not equivalence
// evidence, just "we don't have a syz/ref sample for this slot". Without
// this bucket, b15b reported req=84 setrlimit (syz_cov=0 ref_cov=129) as a
// forced 0.0 low-band sample, inflating low_band_count by structurally
// incomparable cases.
func TestAccumKCovJaccard_OneSideUnavailable(t *testing.T) {
	t.Run("syz_not_executed_ref_has_cov", func(t *testing.T) {
		rep := &report{}
		j, outcome := accumKCovJaccard(rep,
			nil, /*syzExecuted=*/ false,
			[]uint64{0x1, 0x2, 0x3}, /*refExecuted=*/ true)
		if outcome != kJaccardSyzUnavail {
			t.Fatalf("outcome=%v, want kJaccardSyzUnavail", outcome)
		}
		if j != 0 {
			t.Fatalf("jaccard=%v, want 0 (unavail bucket carries no value)", j)
		}
		if rep.CoverageSyzUnavailCount != 1 {
			t.Fatalf("CoverageSyzUnavailCount=%d, want 1", rep.CoverageSyzUnavailCount)
		}
		if rep.KCovJaccardCount != 0 || rep.KCovJaccardSum != 0 {
			t.Fatalf("unavail leaked into Jaccard sum/count: sum=%v count=%d",
				rep.KCovJaccardSum, rep.KCovJaccardCount)
		}
		if rep.KCovJaccardBothEmptyCount != 0 {
			t.Fatalf("BothEmpty incorrectly bumped: %d", rep.KCovJaccardBothEmptyCount)
		}
	})

	t.Run("ref_not_executed_syz_has_cov", func(t *testing.T) {
		rep := &report{}
		_, outcome := accumKCovJaccard(rep,
			[]uint64{0xA, 0xB}, /*syzExecuted=*/ true,
			nil, /*refExecuted=*/ false)
		if outcome != kJaccardRefUnavail {
			t.Fatalf("outcome=%v, want kJaccardRefUnavail", outcome)
		}
		if rep.CoverageRefUnavailCount != 1 {
			t.Fatalf("CoverageRefUnavailCount=%d, want 1", rep.CoverageRefUnavailCount)
		}
	})

	t.Run("syz_not_executed_ref_empty_falls_through_to_both_empty", func(t *testing.T) {
		// Edge case: syz didn't execute AND ref has no cover → falls into the
		// BothEmpty bucket, not the unavail bucket. Comparing "didn't run"
		// vs "ran with no PCs" against each other has no equivalence
		// signal either way, and we don't want to double-bucket.
		rep := &report{}
		_, outcome := accumKCovJaccard(rep,
			nil, /*syzExecuted=*/ false,
			nil, /*refExecuted=*/ true)
		if outcome != kJaccardBothEmpty {
			t.Fatalf("outcome=%v, want kJaccardBothEmpty", outcome)
		}
		if rep.CoverageSyzUnavailCount != 0 {
			t.Fatalf("unavail bucket falsely bumped on both-empty case: %d",
				rep.CoverageSyzUnavailCount)
		}
	})

	t.Run("syz_executed_no_cov_ref_has_cov_is_real_low_band", func(t *testing.T) {
		// syz Executed=1 with empty Cover (e.g. exit-style fast syscall
		// that returned without any PC) vs ref with cov is a REAL low-band
		// signal — must accumulate into Jaccard sum as 0.0, not get
		// silently bucketed away.
		rep := &report{}
		j, outcome := accumKCovJaccard(rep,
			nil, /*syzExecuted=*/ true,
			[]uint64{0x1, 0x2}, /*refExecuted=*/ true)
		if outcome != kJaccardCompared {
			t.Fatalf("outcome=%v, want kJaccardCompared", outcome)
		}
		if j != 0 {
			t.Fatalf("jaccard=%v, want 0 (one-empty no-overlap)", j)
		}
		if rep.KCovJaccardCount != 1 || rep.KCovJaccardSum != 0 {
			t.Fatalf("Jaccard sum/count: got sum=%v count=%d, want 0/1",
				rep.KCovJaccardSum, rep.KCovJaccardCount)
		}
		if rep.CoverageSyzUnavailCount != 0 {
			t.Fatalf("unavail bucket falsely bumped: %d",
				rep.CoverageSyzUnavailCount)
		}
	})
}

// quantile edge cases. Boundary behavior (p=0 → min, p=100 → max, empty →
// zero) is part of the public contract used by buildJaccardDistribution; if
// these slip silently we'd publish wrong gate stats.
func TestQuantile(t *testing.T) {
	if got := quantile(nil, 50); got != 0 {
		t.Errorf("empty input: got %v, want 0", got)
	}
	single := []float64{0.42}
	for _, p := range []float64{0, 25, 50, 100} {
		if got := quantile(single, p); got != 0.42 {
			t.Errorf("single-element p=%v: got %v, want 0.42", p, got)
		}
	}
	// 10 samples: 0.0 .. 0.9 in 0.1 steps.
	ten := []float64{0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	cases := []struct {
		p, want float64
	}{
		{0, 0.0},
		{25, 0.2},
		{50, 0.5},
		{95, 0.9},
		{99, 0.9},
		{100, 0.9},
	}
	for _, tc := range cases {
		got := quantile(ten, tc.p)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("p=%v: got %v, want %v", tc.p, got, tc.want)
		}
	}
}

// Pin distribution shape on a synthetic dataset that mirrors the failure mode
// the distribution is supposed to catch: 90% near 1.0 + 10% near 0. A single
// mean would say ~0.9 and look healthy; the distribution must show the
// low-band split clearly.
func TestBuildJaccardDistribution_BimodalDetection(t *testing.T) {
	var samples []float64
	for i := 0; i < 90; i++ {
		samples = append(samples, 0.97) // healthy bulk
	}
	for i := 0; i < 10; i++ {
		samples = append(samples, 0.05) // path-divergence tail
	}
	// 6 of the 10 low-band samples are flagged as worker-side kcov ring
	// overflow artifacts → actionable = 10 - 6 = 4.
	d := buildJaccardDistribution(samples, 7, 6, 0)

	if d.SampleCount != 100 || d.BothEmptyCount != 7 {
		t.Fatalf("counts wrong: sample=%d bothEmpty=%d", d.SampleCount, d.BothEmptyCount)
	}
	// Mean ≈ 0.9 * 0.97 + 0.1 * 0.05 = 0.878
	wantMean := 0.9*0.97 + 0.1*0.05
	if math.Abs(d.Mean-wantMean) > 1e-9 {
		t.Errorf("mean = %v, want %v", d.Mean, wantMean)
	}
	if d.LowBandCount != 10 {
		t.Errorf("low_band (j<0.5) = %d, want 10", d.LowBandCount)
	}
	if d.HighBandCount != 90 {
		t.Errorf("high_band (j>=0.9) = %d, want 90", d.HighBandCount)
	}
	if d.KCovBufferOverflowCount != 6 {
		t.Errorf("kcov_buffer_overflow_count = %d, want 6", d.KCovBufferOverflowCount)
	}
	if d.ActionableLowBandCount != 4 {
		t.Errorf("actionable_low_band_count = %d, want 4 (=10-6)", d.ActionableLowBandCount)
	}
	// p25 should still be in the bulk (0.97); p99 should also be 0.97 since
	// the tail is only 10 entries.
	if d.P25 != 0.97 {
		t.Errorf("p25 = %v, want 0.97 (still in healthy bulk)", d.P25)
	}
	// min must surface the divergence tail even when mean hides it.
	if d.Min != 0.05 {
		t.Errorf("min = %v, want 0.05 (tail value)", d.Min)
	}
}

// Empty samples → all zeros except BothEmptyCount.
func TestBuildJaccardDistribution_NoSamples(t *testing.T) {
	d := buildJaccardDistribution(nil, 42, 0, 0)
	if d.SampleCount != 0 || d.BothEmptyCount != 42 {
		t.Errorf("unexpected counts: %+v", d)
	}
	if d.Mean != 0 || d.Min != 0 || d.P50 != 0 {
		t.Errorf("non-zero stats on empty input: %+v", d)
	}
	if d.KCovBufferOverflowCount != 0 || d.ActionableLowBandCount != 0 {
		t.Errorf("overflow/actionable should be 0 on empty: %+v", d)
	}
}

// §13.5 P2 contract: caller-supplied kcov_buffer_overflow_count is clamped
// to low_band_count (defensive against stale upstream counters). actionable
// stays non-negative.
func TestBuildJaccardDistribution_OverflowClamp(t *testing.T) {
	samples := []float64{0.1, 0.2, 0.3, 0.95, 0.95, 0.95}
	// 3 low-band (j<0.5), but caller (incorrectly) reports 9 overflows.
	// Clamp should bring it back to 3, actionable to 0.
	d := buildJaccardDistribution(samples, 0, 9, 0)
	if d.LowBandCount != 3 {
		t.Fatalf("low_band = %d, want 3", d.LowBandCount)
	}
	if d.KCovBufferOverflowCount != 3 {
		t.Errorf("overflow clamp = %d, want 3 (capped at low_band)", d.KCovBufferOverflowCount)
	}
	if d.ActionableLowBandCount != 0 {
		t.Errorf("actionable = %d, want 0 after clamp", d.ActionableLowBandCount)
	}
}

func TestJaccardU64(t *testing.T) {
	cases := []struct {
		name   string
		a, b   []uint64
		want   float64
	}{
		{"both empty", nil, nil, 1.0},
		{"identical", []uint64{1, 2, 3}, []uint64{3, 2, 1}, 1.0},
		{"disjoint", []uint64{1, 2}, []uint64{3, 4}, 0.0},
		{"half overlap", []uint64{1, 2, 3, 4}, []uint64{3, 4, 5, 6}, 2.0 / 6.0},
		{"one empty", []uint64{1, 2}, nil, 0.0},
		// Deduplication: |{1,2}| ∩ |{1,2}| = 2, union = 2, jaccard = 1.0
		{"with duplicates", []uint64{1, 1, 2, 2}, []uint64{2, 1}, 1.0},
		// One element of overlap out of three unique elements.
		{"one of three", []uint64{1, 2}, []uint64{2, 3}, 1.0 / 3.0},
	}
	for _, tc := range cases {
		got := jaccardU64(tc.a, tc.b)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDecodeRefOutput_AndJaccard_End2End(t *testing.T) {
	// Plausible 2-call request: syz cover = ref cover for call 0 (perfect
	// match), partial overlap for call 1. Verify that jaccards summed match
	// expected and decoder respects offsets.
	heads := []refCall{
		{Ret: 0, Err: 0, Flags: 0x1, CoverOffset: 0, CoverCount: 3},
		{Ret: 0, Err: 0, Flags: 0x1, CoverOffset: 3, CoverCount: 4},
	}
	tail := []uint64{
		// call 0: 0xA, 0xB, 0xC
		0xA, 0xB, 0xC,
		// call 1: 0x1, 0x2, 0x3, 0x4
		0x1, 0x2, 0x3, 0x4,
	}
	raw := buildRawOutput(heads, tail, nil)

	calls, gotTail, ok := decodeRefOutput(raw, 2)
	if !ok || len(calls) != 2 || len(gotTail) != 7 {
		t.Fatalf("decoder unhappy: ok=%v calls=%d tail=%d", ok, len(calls), len(gotTail))
	}

	syz0 := []uint64{0xA, 0xB, 0xC}
	syz1 := []uint64{0x1, 0x3, 0x5, 0x6} // 2 of 6 unique → 1/3
	ref0 := refCoverSlice(gotTail, calls[0].CoverOffset, calls[0].CoverCount)
	ref1 := refCoverSlice(gotTail, calls[1].CoverOffset, calls[1].CoverCount)

	j0 := jaccardU64(syz0, ref0)
	j1 := jaccardU64(syz1, ref1)
	if math.Abs(j0-1.0) > 1e-9 {
		t.Errorf("call 0 jaccard = %v, want 1.0", j0)
	}
	if math.Abs(j1-1.0/3.0) > 1e-9 {
		t.Errorf("call 1 jaccard = %v, want 1/3", j1)
	}
}

// §13.6: compareCalls Executed-bit predicate. Calls where one side never set
// CallFlag.Executed must be excluded from errno/flags comparison and routed
// into the appropriate skip bucket, otherwise upstream syz's empty_call
// placeholder (NONE=0, errno=998) gets miscounted as an errno mismatch.
func TestCompareCalls_ExecutedBitSkip(t *testing.T) {
	type want struct {
		matched bool
		reason  string
		stats   callCmpStats
	}
	cases := []struct {
		name string
		syz  []syzCall
		ref  []refCall
		want want
	}{
		{
			name: "both_executed_matched",
			syz:  []syzCall{{Flags: 0x3, Error: 0}},
			ref:  []refCall{{Flags: 0x3, Err: 0}},
			want: want{matched: true},
		},
		{
			name: "syz_skipped_998_sentinel",
			// upstream empty_call: NONE=0, err=998. ref ran the call.
			syz:  []syzCall{{Flags: 0x0, Error: 998}},
			ref:  []refCall{{Flags: 0x3, Err: 0}},
			want: want{matched: true, stats: callCmpStats{SyzSkipped: 1}},
		},
		{
			name: "ref_skipped_blocked",
			// reFuzz threaded path: Blocked-without-Executed (Flags=4).
			syz:  []syzCall{{Flags: 0x3, Error: 0}},
			ref:  []refCall{{Flags: 0x4, Err: 0}},
			want: want{matched: true, stats: callCmpStats{RefSkipped: 1}},
		},
		{
			name: "both_skipped_post_clone_exit",
			// post-clone exit case observed in b8-full req 281/370: syz
			// fills empty_call (998), ref's slot stays at memset(0).
			syz:  []syzCall{{Flags: 0x0, Error: 998}},
			ref:  []refCall{{Flags: 0x0, Err: 0}},
			want: want{matched: true, stats: callCmpStats{BothSkipped: 1}},
		},
		{
			name: "real_errno_mismatch_both_executed",
			// Both ran but errno differs (b8-full req 720 syz_mount_image$btrfs:
			// syz hits EBUSY=16, ref succeeds). Must still flag as errno.
			syz:  []syzCall{{Flags: 0x13, Error: 16}}, // 19 = Executed|Finished|CoverageOverflow
			ref:  []refCall{{Flags: 0x3, Err: 0}},
			want: want{matched: false, reason: "errno"},
		},
		{
			name: "skip_doesnt_mask_later_errno_mismatch",
			syz: []syzCall{
				{Flags: 0x0, Error: 998}, // syz skip
				{Flags: 0x3, Error: 5},   // real EIO
			},
			ref: []refCall{
				{Flags: 0x3, Err: 0}, // ref ran
				{Flags: 0x3, Err: 0}, // ref ran, no error
			},
			want: want{matched: false, reason: "errno", stats: callCmpStats{SyzSkipped: 1}},
		},
		{
			name: "cov_overflow_bit_does_not_break_match",
			// CoverageOverflow (bit 4) is excluded from semantic mask, so
			// 0x13 (Exec|Finish|CovOverflow) and 0x3 (Exec|Finish) match.
			syz:  []syzCall{{Flags: 0x13, Error: 0}},
			ref:  []refCall{{Flags: 0x3, Err: 0}},
			want: want{matched: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			syz := &syzRequest{Calls: tc.syz}
			ref := &refOutcome{Calls: tc.ref}
			match, reason, stats := compareCalls(syz, ref)
			if match != tc.want.matched {
				t.Errorf("matched: got %v want %v", match, tc.want.matched)
			}
			if reason != tc.want.reason {
				t.Errorf("reason: got %q want %q", reason, tc.want.reason)
			}
			if stats != tc.want.stats {
				t.Errorf("stats: got %+v want %+v", stats, tc.want.stats)
			}
		})
	}
}

// §13.6 PR3 step 3: replay skips with reason == skipReasonMissingProcId
// must increment RequestSkipMissingProcId, not RequestSkipUnsupported.
// Otherwise an operator can't tell "trace lacks slot info" from "trace
// uses CollectComps" and the affinity-required gap stays invisible.
func TestCompareSessions_SkipReasonBucketing(t *testing.T) {
	// Three syz requests, only the skip record varies per reqID. We populate
	// SyzRequests too so the request still shows up in seenReqs (without it,
	// the seenReqs walk doesn't even reach the skip branch).
	sess := &session{
		SyzSessionID: 12345,
		SyzRequests: map[int64]*syzRequest{
			1: {ID: 1, HasRequest: true, ProcID: -1, Calls: nil},
			2: {ID: 2, HasRequest: true, ProcID: -1, Calls: nil},
			3: {ID: 3, HasRequest: true, ProcID: -1, Calls: nil},
		},
		RefOutcomes: map[int64]*refOutcome{},
		RefSkips: map[int64]*refSkip{
			1: {ReqID: 1, Reason: skipReasonUnsupportedExecOpts},
			2: {ReqID: 2, Reason: skipReasonMissingProcId},
			3: {ReqID: 3, Reason: skipReasonMissingProcId},
		},
	}
	rep := compareSessions([]*session{sess}, 30, "", "", nil, nil, nil)

	if rep.RequestSkipUnsupported != 1 {
		t.Errorf("RequestSkipUnsupported = %d, want 1", rep.RequestSkipUnsupported)
	}
	if rep.RequestSkipMissingProcId != 2 {
		t.Errorf("RequestSkipMissingProcId = %d, want 2", rep.RequestSkipMissingProcId)
	}
	// comparableDenom should subtract both skip buckets so comparable_rate
	// isn't penalized by skips. With 3 total and 3 skips, denom=0 → rate=0.
	if rep.ComparableRate != 0 {
		t.Errorf("ComparableRate = %v, want 0 when every request skipped",
			rep.ComparableRate)
	}
}

// §13.6 E: matchesProcessColdFault must accept the curated family prefixes
// (with compiler suffixes / subfamily suffixes) and reject syscall-internal
// symbols that happen to share a leading token. A false positive here would
// silently exclude real divergences from actionable_low_band — the bucket's
// whole credibility rests on the family-match being conservative.
func TestMatchesProcessColdFault(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// exact-match family heads
		{"do_user_addr_fault", true},
		{"do_wp_page", true},
		{"wp_page_copy", true},
		{"filemap_map_pages", true},
		{"filemap_map_folio_range", true},
		{"vma_start_read", true},
		{"lock_vma_under_rcu", true},
		{"folio_flags", true},
		{"rcu_read_lock", true},
		{"arch_static_branch", true},
		// compiler-suffix variants (.constprop / .isra / .part)
		{"do_user_addr_fault.constprop.0", true},
		{"wp_page_copy.isra.0", true},
		{"do_wp_page.part.0", true},
		// subfamily suffix
		{"xas_find_marked", true},
		{"xas_next_entry", true},
		// rcu_read_lock_held would NOT be matched against rcu_read_lock alone —
		// boundary char must be '.', '_', or digit. _held is _held → '_' boundary,
		// so it DOES match. That's fine: rcu_read_lock_held is in the same
		// fault-side family.
		{"rcu_read_lock_held", true},
		// negative: random syscall-internal symbols
		{"vfs_open", false},
		{"do_sys_openat2", false},
		{"chrdev_open", false},
		{"snd_pcm_open", false},
		{"sock_alloc_file", false},
		// negative: a token that LOOKS like a family head but is not (no whitelisted
		// prefix exactly matches)
		{"do_user_addr_other", false},
		{"folio_alloc", false},
		// empty / weird
		{"", false},
		{"__init", false},
	}
	for _, tc := range cases {
		got := matchesProcessColdFault(tc.name)
		if got != tc.want {
			t.Errorf("matchesProcessColdFault(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// §13.6 E classifier behavior gates on call#0, 3× cov skew, ≥50 % family
// share, and symbol-table presence. Each test pins one rule.
func TestClassifyProcessColdFault(t *testing.T) {
	// Fake symbol table where PCs in [0x1000, 0x1FFF) map to a cold-fault
	// family symbol, and [0x2000, 0x2FFF) map to a syscall-internal one.
	kt := &kernelSymbolTable{
		syms: []kernelSymbol{
			{Addr: 0x1000, Name: "do_user_addr_fault"},
			{Addr: 0x2000, Name: "chrdev_open"},
			{Addr: 0x3000, Name: "__end"},
		},
		loaded: true,
	}
	makePCs := func(count, base int) []uint64 {
		out := make([]uint64, count)
		for i := range out {
			out[i] = uint64(base + i*8)
		}
		return out
	}
	// Helper builds a cold-fault-shaped pair (ref bigger, ref unique PCs in fault range)
	coldPair := func(syzN, refN int) ([]uint64, []uint64) {
		// syz: small set in the fault range, fully contained in ref
		syz := makePCs(syzN, 0x1000)
		// ref: superset, dominated by fault-family unique PCs
		ref := makePCs(refN, 0x1000)
		return syz, ref
	}

	t.Run("classic_cold_fault_pattern", func(t *testing.T) {
		syz, ref := coldPair(100, 600)  // 6× skew; ref-unique are all fault-family
		if !classifyProcessColdFault(kt, 0, syz, ref) {
			t.Error("classic cold-fault pattern not classified")
		}
	})
	t.Run("call_index_not_zero", func(t *testing.T) {
		syz, ref := coldPair(100, 600)
		if classifyProcessColdFault(kt, 1, syz, ref) {
			t.Error("classifier should only fire for call#0")
		}
	})
	t.Run("ratio_below_threshold", func(t *testing.T) {
		syz, ref := coldPair(100, 250)  // < 3×
		if classifyProcessColdFault(kt, 0, syz, ref) {
			t.Error("ratio < 3 must not classify")
		}
	})
	t.Run("family_share_below_threshold", func(t *testing.T) {
		// ref has many PCs but mostly in syscall range (chrdev_open at 0x2000)
		syz := makePCs(100, 0x1000)
		ref := append(makePCs(50, 0x1000), makePCs(450, 0x2000)...)  // 10% fault family
		if classifyProcessColdFault(kt, 0, syz, ref) {
			t.Error("family share <50% must not classify")
		}
	})
	t.Run("no_symbol_table", func(t *testing.T) {
		syz, ref := coldPair(100, 600)
		if classifyProcessColdFault(nil, 0, syz, ref) {
			t.Error("nil symbol table must short-circuit to false")
		}
		empty := &kernelSymbolTable{}  // not loaded
		if classifyProcessColdFault(empty, 0, syz, ref) {
			t.Error("unloaded symbol table must short-circuit to false")
		}
	})
	t.Run("smaller_side_empty", func(t *testing.T) {
		// 0 vs N is the unavailable case; already handled by a separate
		// bucket, classifier must not double-count.
		ref := makePCs(600, 0x1000)
		if classifyProcessColdFault(kt, 0, nil, ref) {
			t.Error("smaller=empty must not classify (handled by unavail bucket)")
		}
	})
}

// §13.6 E gate accounting: actionable_low_band excludes BOTH overflow and
// cold-fault counts. Verify the buildJaccardDistribution math directly so
// future refactors don't silently re-include cold-fault in the gate.
func TestBuildJaccardDistribution_ColdFaultExclusion(t *testing.T) {
	// 100 samples, 30 below 0.5 (low_band), 5 of which are overflow,
	// 20 of which are cold-fault. Actionable = 30 - 5 - 20 = 5.
	samples := make([]float64, 100)
	for i := 0; i < 30; i++ {
		samples[i] = 0.2
	}
	for i := 30; i < 100; i++ {
		samples[i] = 0.95
	}
	d := buildJaccardDistribution(samples, /*bothEmpty=*/ 0,
		/*kcovBufferOverflow=*/ 5, /*processColdFault=*/ 20)
	if d.LowBandCount != 30 {
		t.Fatalf("LowBandCount=%d, want 30", d.LowBandCount)
	}
	if d.KCovBufferOverflowCount != 5 {
		t.Fatalf("Overflow=%d, want 5", d.KCovBufferOverflowCount)
	}
	if d.CoverageProcessColdFaultCount != 20 {
		t.Fatalf("ColdFault=%d, want 20", d.CoverageProcessColdFaultCount)
	}
	if d.ActionableLowBandCount != 5 {
		t.Fatalf("Actionable=%d, want 5 (low_band - overflow - cold_fault)",
			d.ActionableLowBandCount)
	}
}

// Combined-cap clamp: overflow + cold-fault can't exceed low_band. Defensive
// in case classifier and overflow detector double-count the same sample.
func TestBuildJaccardDistribution_CombinedClamp(t *testing.T) {
	samples := []float64{0.1, 0.2, 0.3, 0.4}  // all low_band → LowBandCount=4
	d := buildJaccardDistribution(samples, 0, /*overflow=*/ 3, /*coldFault=*/ 3)
	// Combined 6 > low_band 4 → cold_fault gets trimmed to 4-3 = 1
	if d.KCovBufferOverflowCount != 3 {
		t.Fatalf("Overflow trimmed unexpectedly: %d", d.KCovBufferOverflowCount)
	}
	if d.CoverageProcessColdFaultCount != 1 {
		t.Fatalf("ColdFault clamp: got %d, want 1", d.CoverageProcessColdFaultCount)
	}
	if d.ActionableLowBandCount != 0 {
		t.Fatalf("Actionable: got %d, want 0", d.ActionableLowBandCount)
	}
}

// TestHasFamilyPrefix covers the family-name boundary helper used by
// matchesProcessColdFault (and previously the reverted fork-mm mask). Boundary
// = end-of-string / '.' / '_' / digit;letter boundary 不算同 family。
func TestHasFamilyPrefix(t *testing.T) {
	cases := []struct {
		name, prefix string
		want         bool
	}{
		{"copy_process", "copy_process", true},
		{"copy_process.cold", "copy_process", true},
		{"copy_process_inner", "copy_process", true},
		{"copy_process2", "copy_process", true},
		{"copy_processless", "copy_process", false},
		{"do_mmap2", "do_mmap", true},
		{"do_mmapped", "do_mmap", false},
		{"mas_rev_awalk.constprop.0", "mas_rev_awalk", true},
		{"", "copy_process", false},
	}
	for _, c := range cases {
		if got := hasFamilyPrefix(c.name, c.prefix); got != c.want {
			t.Errorf("hasFamilyPrefix(%q, %q) = %v, want %v",
				c.name, c.prefix, got, c.want)
		}
	}
}
