// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — fork/exec helper with stdin pipe +
// stdout/stderr capture + timeout. Used by common_header.cpp's cpp
// invocation and by build.cpp's gcc invocation (PR-4-C).
//
// This is csource-internal infra. If a broader reFuzz process-run
// helper lands later, csource can switch to it without touching the
// public API surface.

#pragma once

#include <chrono>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

struct ProcessResult {
    int         exit_code = 0;
    std::string stdout_;       // captured stdout bytes
    std::string stderr_;       // captured stderr bytes
    bool        timed_out = false;
};

// Run `argv[0]` with the rest as args. `stdin_bytes` are written to
// the child's stdin then EOF. Both stdout and stderr are captured.
// `timeout` of 0 disables the timeout.
//
// Returns a ProcessResult on successful exec (regardless of exit
// code); returns std::unexpected<std::string> only on system-level
// failures (fork/pipe/exec setup).
std::expected<ProcessResult, std::string>
run_process(std::span<const std::string_view> argv,
            std::string_view stdin_bytes,
            std::chrono::seconds timeout);

} // namespace refuzz::crash::repro::csource::internal
