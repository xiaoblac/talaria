// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — internal Build() argv layout
// helper. Splits argv resolution out of Build() so a unit test
// (csource_build_argv_test) can pin the upstream layout
// (pkg/csource/build.go:51-96) without spawning a real compiler.
//
// The function is internal to the csource module — callers outside
// the module never need this; they go through Build().

#pragma once

#include "refuzz/crash/repro/csource/build.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

// Returns the compiler argv that Build() will exec(), given a resolved
// output binary path. Mirrors pkg/csource/build.go:59-80 verbatim:
//
//   <c_compiler>
//   -o <binary_path>
//   -DGOOS_<goos>=1
//   -DGOARCH_<goarch>=1
//   -DHOSTGOOS_<host_goos>=1
//   -x c -
//   <target_info.cflags()...>      // sysTarget.CFlags
//   <bopts.extra_cflags...>        // caller-provided (default empty)
//   -Wno-overflow                  // only when ptr_size_is_4()
//
// No additional optimization / warning flags are injected by this
// helper. The upstream warning-clean profile lives entirely in
// sysTarget.CFlags (Linux/amd64: -m64 -O2 -pthread ... -static-pie).
std::vector<std::string>
build_argv(const ICSourceTargetInfo& target_info,
           const BuildOptions&        bopts,
           std::string_view           binary_path);

} // namespace refuzz::crash::repro::csource::internal
