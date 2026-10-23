package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRefuzzCoverageLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coverage_series.log")
	data := "# coverage series — key=value per 10s window: t=<HH:MM:SS>,all_pc,corpus_pc,all_edge,corpus_edge\n" +
		"t=13:23:30,all_pc=101,corpus_pc=41,all_edge=203,corpus_edge=73\n" +
		"t=13:23:40,all_pc=111,corpus_pc=43,all_edge=211,corpus_edge=79\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	// corpus_pc selected; X axis is elapsed-from-first-row (0, then 10s).
	points, err := ParseRefuzzCoverageLog(path, "corpus_pc")
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 || points[0].ElapsedSec != 0 || points[0].PC != 41 ||
		points[1].ElapsedSec != 10 || points[1].PC != 43 {
		t.Fatalf("unexpected points: %#v", points)
	}
	// A different key (all_edge) resolves from the same rows.
	edge, err := ParseRefuzzCoverageLog(path, "all_edge")
	if err != nil {
		t.Fatal(err)
	}
	if len(edge) != 2 || edge[0].PC != 203 || edge[1].PC != 211 {
		t.Fatalf("unexpected edge points: %#v", edge)
	}
}

func TestParseRefuzzCoverageLogRejectsRetiredTSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.tsv")
	data := "# tick\tall_pc\tcorpus_pc\n10\t101\t41\n20\t111\t43\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRefuzzCoverageLog(path, "corpus_pc"); err == nil {
		t.Fatal("retired TSV format was accepted")
	}
}
