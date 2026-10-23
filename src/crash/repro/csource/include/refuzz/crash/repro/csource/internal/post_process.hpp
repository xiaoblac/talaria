// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::postProcess /
// hoistIncludes / removeEmptyLines (lines 673-745).

#pragma once

#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"

#include <string>

namespace refuzz::crash::repro::csource::internal {

// Applies the post-processing pipeline upstream csource.go::postProcess
// runs after createCommonHeader: NONFAILING wrap optional removal,
// NORETURN/doexit/PRINTF strip, debug-call strip, executor include
// guards strip, hoist_includes, remove_empty_lines.
std::string post_process(std::string src, const Options& opts,
                         const ICSourceTargetInfo& target_info);

// Sub-pieces, exposed for tests.
std::string hoist_includes(std::string src,
                           const ICSourceTargetInfo& target_info);
std::string remove_empty_lines(std::string src);

} // namespace refuzz::crash::repro::csource::internal
