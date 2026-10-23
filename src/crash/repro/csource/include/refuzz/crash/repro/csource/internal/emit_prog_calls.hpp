// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — emit_prog_calls.
//
// Walks a WireProgram (the analog of upstream prog.ExecProg) and
// produces (calls_text, vars) — the per-call C source string vector
// plus the list of distinct ResultArg indices observed (used by
// generateSource to size the `r[]` array). Mirror of upstream
// pkg/csource/csource.go::generateCalls (lines 296-332).
//
// Index alignment: the i-th typed Call corresponds to the i-th
// WireCall in the WireProgram stream (after Copyin/Copyout/SetProps
// instructions are interleaved). emit_prog_calls maintains this
// alignment so callers can pass per-typed-call comments through
// `call_comments` and have them attached to the right WireCall.

#pragma once

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/emit_call.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

struct EmitProgCallsResult {
    std::vector<std::string> calls;  // one entry per WireCall
    std::vector<std::uint64_t> vars; // distinct ResultArg indices in order
};

// Walks `wp.instrs`, emitting each WireCall's body via emit_call
// (preceded by its copyins, followed by copyouts). When
// `add_comments` is true, prepends `call_comments[ci] + "\n"` before
// each call's emit (mirror of upstream csource.go:302-304).
//
// Returns a CSourceFailure if a structural invariant is violated
// (e.g., a WireCall's call_id doesn't resolve in target.syscalls()).
std::expected<EmitProgCallsResult, CSourceFailure>
emit_prog_calls(const ::refuzz::program::syz::Prog& prog,
                const ::refuzz::program::syz::WireProgram& wp,
                const EmitCallCtx& ctx,
                std::span<const std::string> call_comments,
                bool trace, bool add_comments);

} // namespace refuzz::crash::repro::csource::internal
