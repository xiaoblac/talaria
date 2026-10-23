// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-1 — generate_sandbox_function_signature parity vs
// upstream pkg/csource/csource.go::generateSandboxFunctionSignature
// (lines 63-73). Mirror of the upstream Go test
// TestGenerateSandboxFunctionSignature.

#include "refuzz/crash/repro/csource/internal/sandbox.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

namespace cs = ::refuzz::crash::repro::csource::internal;

void check(std::string_view name, int arg, std::string_view expected) {
    auto got = cs::generate_sandbox_function_signature(name, arg);
    if (got != expected) {
        std::fprintf(stderr,
                     "  sandbox=%.*s arg=%d: got %s, want %.*s\n",
                     int(name.size()), name.data(), arg, got.c_str(),
                     int(expected.size()), expected.data());
    }
    CHECK(got == expected);
}

} // namespace

int main() {
    check("",          0, "loop();");
    check("",          1, "loop();");           // arg ignored when name empty
    check("none",      0, "do_sandbox_none();");
    check("setuid",    0, "do_sandbox_setuid();");
    check("namespace", 0, "do_sandbox_namespace();");
    check("android",   0, "do_sandbox_android(0);");
    check("android",   1, "do_sandbox_android(1);");
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
