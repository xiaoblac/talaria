// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — public Write() API.
//
// Adapt of upstream pkg/csource/csource.go::Write (line 41) into the
// reFuzz module/IR architecture: typed `syz::Prog` in, standalone
// `.c` source out. Internally the pipeline lowers to WireProgram via
// reFuzz's own serialize_for_exec / decode_exec_wire (the Layer-1
// round-trip is already pinned by oracle 824/824).
//
// PR-4-A: stub returning kNotImplemented. PR-4-B fills the body.

#pragma once

#include "refuzz/crash/repro/csource/annotator.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <expected>
#include <string>

namespace refuzz::crash::repro::csource {

enum class CSourceError {
    kNotImplemented,           // PR-4-A only — Write body not landed yet
    kInvalidOptions,           // Options::Check failed
    kUnsupportedByEpic4,       // baseline gate (see Epic 4 plan §3)
    kSerializeFailed,          // serialize_for_exec returned error
    kDecodeFailed,             // decode_exec_wire returned error
    kCommonHeaderCppFailed,    // cpp invocation produced empty stdout
    kInternal,                 // emit / post-process invariant violation
};

struct CSourceFailure {
    CSourceError code = CSourceError::kInternal;
    std::string  message;
};

// Public entry. typed Prog in (the same shape upstream Write takes);
// standalone C source string out. Annotator is invoked once per
// emitted WireCall (Linux: no-op). Target info carries
// csource-specific build-time facts.
std::expected<std::string, CSourceFailure>
Write(const ::refuzz::program::syz::Prog& prog,
      const Options&                      opts,
      const ICallAnnotator&               annotator,
      const ICSourceTargetInfo&           target_info);

} // namespace refuzz::crash::repro::csource
