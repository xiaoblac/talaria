// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — toCString helper.
//
// Adapt of upstream pkg/csource/csource.go::toCString (lines 747-754)
// which calls prog.EncodeData(buf, data, readable). Self-contained in
// csource so we don't need to export private encoding helpers from
// program/syz.

#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace refuzz::crash::repro::csource::internal {

// Returns the C-string-literal-safe encoding of `data`. Mirror of
// upstream prog.EncodeData with the auto-readable-detection
// semantics: when `readable=false` and the data is mostly printable,
// upgrades to readable; non-printable bytes get octal escapes
// (cstr=true semantics from prog.encodeData).
//
// Caller wraps the returned string in `"` quotes to form a valid C
// string literal — this function does not include the surrounding
// quotes (matches upstream toCString contract).
std::string to_c_string(std::span<const std::uint8_t> data, bool readable);

} // namespace refuzz::crash::repro::csource::internal
