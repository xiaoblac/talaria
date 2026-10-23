// Layer-3 milestone III.11 — Go-side KCOV digest helper.
//
// Mirror of feedback/include/refuzz/feedback/kcov/digest.hpp:
// FNV-1a 64-bit on sorted+deduped uint64 PCs, little-endian byte order,
// rendered as 16 lowercase hex chars. Identical output to the C++
// implementation by construction.

package main

import (
	"fmt"
	"hash/fnv"
	"sort"
)

func computeKCOVDigest(pcs []uint64) string {
	sort.Slice(pcs, func(i, j int) bool { return pcs[i] < pcs[j] })
	dedup := pcs[:0]
	var prev uint64
	for i, v := range pcs {
		if i == 0 || v != prev {
			dedup = append(dedup, v)
			prev = v
		}
	}
	h := fnv.New64a()
	var buf [8]byte
	for _, pc := range dedup {
		for s := 0; s < 64; s += 8 {
			buf[s/8] = byte(pc >> s)
		}
		h.Write(buf[:])
	}
	return fmt.Sprintf("%016x", h.Sum64())
}
