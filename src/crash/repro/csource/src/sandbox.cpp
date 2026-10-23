// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::generateSandboxFunctionSignature.

#include "refuzz/crash/repro/csource/internal/sandbox.hpp"

#include <format>

namespace refuzz::crash::repro::csource::internal {

std::string generate_sandbox_function_signature(
    std::string_view sandbox_name, int sandbox_arg) {
    if (sandbox_name.empty()) {
        return "loop();";
    }
    if (sandbox_name == "android") {
        return std::format("do_sandbox_android({});", sandbox_arg);
    }
    return std::format("do_sandbox_{}();", sandbox_name);
}

} // namespace refuzz::crash::repro::csource::internal
