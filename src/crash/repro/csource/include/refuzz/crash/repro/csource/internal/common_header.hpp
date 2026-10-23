// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — common header pipeline.
//
// Adapt of upstream pkg/csource/common.go::createCommonHeader (27-73)
// + defineList / commonDefines / removeSystemDefines (75-167).
//
// At Write() time:
//   1. Compute defines via define_list(prog, mmap_prog, opts, target_info)
//      → list of "KEY" or "KEY=VALUE" strings.
//   2. Spawn cpp -nostdinc -undef -fdirectives-only -dDI -E -P -CC - with
//      -D<each> appended; stdin = kCsourceCommonSource. Capture stdout.
//   3. remove_system_defines on stdout.
//   4. Replace placeholders /*{{{KEY}}}*/ with replacements[KEY].
//   5. Replace uint64/uint32/uint16/uint8 → uint64_t/uint32_t/.../uint8_t.
//   6. Strip "#define SYZ_HAVE_.*" lines.

#pragma once

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <expected>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

// Adapt of prog.RequiredFeatures (analysis.go:209-237).
struct RequiredFeatures {
    bool bitmasks        = false;
    bool csums           = false;
    bool fault_injection = false;
    bool async           = false;
};
RequiredFeatures analyze_required_features(
    const ::refuzz::program::syz::Prog& prog);

// Adapt of common.go::commonDefines (91-131). Returns a sorted list
// of `-D` strings ready for cpp argv.
std::vector<std::string> common_defines(
    const ::refuzz::program::syz::Prog& prog, const Options& opts,
    const ICSourceTargetInfo& target_info,
    const RequiredFeatures& features);

// Adapt of common.go::defineList (75-89). commonDefines + per-call
// `__NR_<callName>` defines for `prog` and `mmap_prog`. Returns a
// sorted, deduplicated list.
std::vector<std::string> define_list(
    const ::refuzz::program::syz::Prog& prog,
    const ::refuzz::program::syz::Prog& mmap_prog, const Options& opts,
    const ICSourceTargetInfo& target_info,
    const RequiredFeatures& features);

// Adapt of common.go::removeSystemDefines (133-167). Strips
// `#define <name> <val>` lines for the system-introduced names plus
// every name in `defines` (parsed for "KEY=VALUE" or just "KEY").
std::string remove_system_defines(std::string src,
                                  const std::vector<std::string>& defines);

// Top-level adapt of common.go::createCommonHeader (27-73).
std::expected<std::string, CSourceFailure>
create_common_header(
    const ::refuzz::program::syz::Prog& prog,
    const ::refuzz::program::syz::Prog& mmap_prog,
    const std::unordered_map<std::string, std::string>& replacements,
    const Options& opts, const ICSourceTargetInfo& target_info,
    const RequiredFeatures& features);

} // namespace refuzz::crash::repro::csource::internal
