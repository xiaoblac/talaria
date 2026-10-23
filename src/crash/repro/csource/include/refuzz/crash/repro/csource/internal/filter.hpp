// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — internal header for filter_calls
// (drops syz_emit_ethernet / syz_emit_vhci variants when their
// owning option is off). Adapt of upstream pkg/csource/csource.go::
// filterCalls (lines 165-186).
//
// Internal-only: only csource.cpp consumes this. Not exported via
// the crash/repro/csource public include tree.

#pragma once

#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <memory>

namespace refuzz::crash::repro::csource::internal {

// Returns the input prog as a borrowed reference if no calls need to
// be removed; otherwise returns a fresh owning Prog with the
// filtered call list. The lazy-clone matches upstream behavior
// (csource.go:179-182).
struct FilteredProg {
    const ::refuzz::program::syz::Prog*           borrowed = nullptr; // non-null when no clone happened
    std::unique_ptr<::refuzz::program::syz::Prog> owned;              // non-null when clone happened
};

FilteredProg filter_calls(const ::refuzz::program::syz::Prog& prog,
                          const Options& opts);

// Convenience accessor — returns whichever pointer is non-null.
inline const ::refuzz::program::syz::Prog* prog_of(const FilteredProg& fp) {
    return fp.owned ? fp.owned.get() : fp.borrowed;
}

} // namespace refuzz::crash::repro::csource::internal
