// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — baseline gate.
//
// Adapt of the Epic 4 §3 binding "Options scope" subset check.
// Walks the typed Prog's per-Call CallProps + Options + WireProgram
// per-WireArg fields, returning kUnsupportedByEpic4 with a precise
// message naming the offending field/call/arg if any non-baseline
// surface is hit. Run BEFORE filter_calls so the gate is honest
// about the input shape (a non-baseline call that filterCalls would
// have dropped still surfaces).

#pragma once

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <expected>

namespace refuzz::crash::repro::csource::internal {

// First gate — Options + per-Call CallProps. Run before serialize.
// Returns void on success.
std::expected<void, CSourceFailure>
baseline_gate_options_and_calls(
    const ::refuzz::program::syz::Prog& prog, const Options& opts);

// Second gate — per-WireArg traversal. Run after decode_exec_wire.
// Catches BinaryFormat::kStrDec/kStrHex/kStrOct (audit row #4 stub)
// and top-level WireData blobs.
std::expected<void, CSourceFailure>
baseline_gate_wire_args(const ::refuzz::program::syz::WireProgram& wp);

} // namespace refuzz::crash::repro::csource::internal
