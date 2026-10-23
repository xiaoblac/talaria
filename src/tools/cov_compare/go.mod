// Standalone reFuzz-owned tool. Intentionally NOT part of the
// github.com/google/syzkaller module and with zero external deps, so it
// can be reused/iterated independently of syzkaller. It reads syzkaller
// and reFuzz coverage time-series as plain files; it does not import any
// syzkaller package.
module refuzz/cov-compare

go 1.24
