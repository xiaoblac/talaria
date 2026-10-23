// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::generateSandboxFunctionSignature
// (lines 63-73).

#pragma once

#include <string>
#include <string_view>

namespace refuzz::crash::repro::csource::internal {

// Returns the C source fragment that invokes the entry function in
// the sandbox-specific runner: e.g. "loop();", "do_sandbox_none();",
// "do_sandbox_android(0);".
std::string generate_sandbox_function_signature(
    std::string_view sandbox_name, int sandbox_arg);

} // namespace refuzz::crash::repro::csource::internal
