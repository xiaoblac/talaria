// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go low-level arg formatters.

#include "refuzz/crash/repro/csource/internal/emit_args.hpp"

#include <bit>
#include <cstdint>
#include <format>
#include <string>
#include <variant>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

namespace {

// literalSuffix (csource.go:626-650). Linux/amd64 ptr_size=8 → "ul".
std::string literal_suffix(const EmitArgsCtx& ctx, const syz::WireConst& arg) {
    if (arg.size != 8) return "";
    if (ctx.target == nullptr) return "ul";
    return ctx.target->ptr_size() == 4 ? "ull" : "ul";
}

uint64_t mask_for(uint64_t size) {
    if (size >= 8) return ~uint64_t{0};
    return (uint64_t{1} << (size * 8)) - 1;
}

// factorizeAsFlags (csource.go:547-567). Recursive subset selector
// minimizing leftover popcount. `attempts_left` caps work — upstream
// uses 256 in prettyPrintValue and we mirror that.
struct Factorization {
    std::vector<std::string> flags;
    uint64_t                 remainder = 0;
};
Factorization factorize_as_flags_impl(const syz::Target& target,
                                      uint64_t value,
                                      const std::vector<std::string>& names,
                                      std::size_t start,
                                      int* attempts_left) {
    if (start >= names.size() || value == 0 || *attempts_left == 0) {
        return Factorization{ .flags = {}, .remainder = value };
    }
    --*attempts_left;
    const std::string& current = names[start];

    // Branch 1 — skip current.
    Factorization without = factorize_as_flags_impl(
        target, value, names, start + 1, attempts_left);

    const auto* mask_ptr = target.find_const(current);
    if (mask_ptr != nullptr) {
        const uint64_t flag_mask = *mask_ptr;
        if (flag_mask != 0 && (value & flag_mask) == flag_mask) {
            // Branch 2 — take current.
            Factorization with = factorize_as_flags_impl(
                target, value & ~flag_mask, names, start + 1, attempts_left);
            with.flags.push_back(current);
            const int bits_without =
                std::popcount(without.remainder);
            const int bits_with =
                std::popcount(with.remainder);
            if (bits_with < bits_without ||
                (bits_with == bits_without &&
                 with.flags.size() < without.flags.size())) {
                return with;
            }
        }
    }
    return without;
}

} // namespace

std::string handle_big_endian(const syz::WireConst& arg, const std::string& val) {
    if (arg.fmt == syz::BinaryFormat::kBigEndian) {
        return std::format("htobe{}({})", arg.size * 8, val);
    }
    return val;
}

std::string const_arg_to_str(const EmitArgsCtx& ctx,
                             const syz::WireConst& arg,
                             bool enforce_bit_size) {
    const std::string suffix = enforce_bit_size ? literal_suffix(ctx, arg) : "";
    const uint64_t mask = mask_for(arg.size);
    const uint64_t v = arg.val & mask;
    std::string val;
    if (v == (~uint64_t{0} & mask)) {
        val = enforce_bit_size ? "(intptr_t)-1" : "-1";
    } else if (v >= 10) {
        val = std::format("0x{:x}{}", v, suffix);
    } else {
        val = std::format("{}{}", v, suffix);
    }
    if (ctx.opts != nullptr && ctx.opts->Procs > 1 && arg.pid_stride != 0) {
        val += std::format(" + procid*{}", arg.pid_stride);
    }
    return val;
}

std::string result_arg_to_str(const EmitArgsCtx& /*ctx*/,
                              const syz::WireResult& arg) {
    std::string res = std::format("r[{}]", arg.idx);
    if (arg.op_div != 0) {
        res = std::format("{}/{}", res, arg.op_div);
    }
    if (arg.op_add != 0) {
        res = std::format("{}+{}", res, arg.op_add);
    }
    if (arg.fmt == syz::BinaryFormat::kBigEndian) {
        res = std::format("htobe{}({})", arg.size * 8, res);
    }
    return res;
}

std::string pretty_print_value(const EmitArgsCtx& ctx,
                               const syz::Field& field,
                               const syz::WireConst& arg) {
    if (ctx.target == nullptr || field.type() == nullptr) return {};
    const uint64_t mask = mask_for(arg.size);
    const uint64_t v = arg.val & mask;
    const auto* flags_ptr = ctx.target->find_flags(field.type()->name());
    if (flags_ptr == nullptr || flags_ptr->empty()) return {};

    int attempts_left = 256;
    Factorization fac = factorize_as_flags_impl(
        *ctx.target, v, *flags_ptr, /*start=*/0, &attempts_left);
    if (fac.flags.empty()) return {};

    if (fac.remainder != 0) {
        fac.flags.push_back(std::format("0x{:x}", fac.remainder));
    }
    // Upstream returns `strings.Join(flags, "|")` in the recursion's
    // append order (subset built bottom-up, with last-added flag at
    // back). The C++ recursion appends `current` after the recursive
    // call returns, so order matches upstream.
    std::string out;
    for (std::size_t i = 0; i < fac.flags.size(); ++i) {
        if (i != 0) out.push_back('|');
        out.append(fac.flags[i]);
    }
    return out;
}

std::string arg_comment(const EmitArgsCtx& ctx,
                        const syz::Field& field,
                        const syz::WireArg& arg) {
    std::string val;
    if (auto* c = std::get_if<syz::WireConst>(&arg)) {
        val = pretty_print_value(ctx, field, *c);
    }
    return std::format("/*{}={}*/", field.name(), val);
}

} // namespace refuzz::crash::repro::csource::internal
