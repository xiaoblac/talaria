// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Build() and Format() helpers.
//
// Build() adapts pkg/csource/build.go::build (lines 51-96) — invoke
// gcc/clang on the produced source with sysTarget cflags. Format()
// adapts pkg/csource/build.go::Format (lines 99-127) — separate
// helper that runs clang-format on a source string and returns the
// reformatted source.
//
// PR-4-A: declarations only. PR-4-C lands the bodies.

#pragma once

#include "refuzz/crash/repro/csource/target_info.hpp"

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::crash::repro::csource {

struct BuildOptions {
    std::string output_path_hint;        // empty → temp file
    int         timeout_seconds   = 60;
    // Optional extra cflags appended after sysTarget cflags. Default
    // empty — standard csource Build produces a warning-clean
    // reproducer. BuildNoWarn-equivalent fills this with
    // {"-fpermissive", "-w"}.
    std::vector<std::string> extra_cflags;
};

struct BuildResult {
    std::string binary_path;             // empty on failure
    std::string compiler_stderr;
    int         exit_status = 0;
    bool        timed_out   = false;
};

std::expected<BuildResult, std::string>
Build(std::string_view csource,
      const BuildOptions&        bopts,
      const ICSourceTargetInfo&  target_info);

// Independent helper. Mirrors pkg/csource/build.go::Format. Takes the
// source string, returns the reformatted source string. NOT invoked
// from Build().
std::expected<std::string, std::string>
Format(std::string_view csource);

} // namespace refuzz::crash::repro::csource
