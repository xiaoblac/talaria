// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — typed Call comment generator.
//
// Adapt of upstream pkg/csource/csource.go::generateComment (258-273)
// + prog/prog.go::FormatArg (501-597). Walks a typed Prog Call and
// produces the multi-line `// <syscall> arguments: [...]` comment
// block emit_prog_calls splices before each WireCall.
//
// Comments are pure information for repro debugging; csource never
// re-parses them. Per Epic 4 §3 H1 binding, this MUST be computed on
// typed Prog (not via AnnotateCall) — that's the upstream order.

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <string>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

// Returns the multi-line comment block (already C-comment-prefixed
// with `//` per line) for one typed Call, or "" when call is null.
std::string make_typed_call_comment(const ::refuzz::program::syz::Call& call);

// Convenience: build comments[i] for every call in `prog`.
std::vector<std::string> make_typed_call_comments(
    const ::refuzz::program::syz::Prog& prog);

// Lower-level building blocks (exposed for unit tests).
std::vector<std::string> format_arg(const ::refuzz::program::syz::Arg& arg,
                                    const std::string&                 name);
std::string type_string(const ::refuzz::program::syz::Type& t);

} // namespace refuzz::crash::repro::csource::internal
