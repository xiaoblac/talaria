// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — low-level WireArg → C string
// formatters. Adapt of upstream pkg/csource/csource.go::
//   constArgToStr / resultArgToStr / handleBigEndian / literalSuffix
//   factorizeAsFlags / prettyPrintValue / argComment
// (lines 547-671).

#pragma once

#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <string>

namespace refuzz::crash::repro::csource::internal {

struct EmitArgsCtx {
    const ::refuzz::program::syz::Target* target = nullptr;
    const Options*                        opts   = nullptr;
};

// Adapt of constArgToStr (csource.go:601-624).
//   `enforce_bit_size` → emit explicit ul/ull suffix on 8-byte values
//   so syscall() variadic args don't get truncated by the compiler.
std::string const_arg_to_str(const EmitArgsCtx& ctx,
                             const ::refuzz::program::syz::WireConst& arg,
                             bool enforce_bit_size);

// Adapt of resultArgToStr (csource.go:659-671).
std::string result_arg_to_str(const EmitArgsCtx& ctx,
                              const ::refuzz::program::syz::WireResult& arg);

// Adapt of handleBigEndian (csource.go:652-657). Returns `val`
// wrapped in htobeNN() when arg.fmt == kBigEndian, else `val` unchanged.
std::string handle_big_endian(
    const ::refuzz::program::syz::WireConst& arg, const std::string& val);

// Adapt of prettyPrintValue (csource.go:569-588). Returns "" if no
// FlagsMap entry for the field's type name, or factorization yields
// no flags. Otherwise returns "FLAG_A|FLAG_B|0xrem" etc.
std::string pretty_print_value(const EmitArgsCtx& ctx,
                               const ::refuzz::program::syz::Field& field,
                               const ::refuzz::program::syz::WireConst& arg);

// Adapt of argComment (csource.go:590-598). For ConstArgs, returns
// /*<fieldName>=<flagsExpr>*/. For non-Const, returns
// /*<fieldName>=*/.
std::string arg_comment(const EmitArgsCtx& ctx,
                        const ::refuzz::program::syz::Field& field,
                        const ::refuzz::program::syz::WireArg& arg);

} // namespace refuzz::crash::repro::csource::internal
