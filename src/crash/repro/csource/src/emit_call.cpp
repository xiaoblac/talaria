// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::emitCall + copyin/copyout +
// fmtCallBody.

#include "refuzz/crash/repro/csource/internal/emit_call.hpp"

#include "refuzz/crash/repro/csource/internal/data_encode.hpp"
#include "refuzz/crash/repro/csource/internal/emit_csum.hpp"
#include "refuzz/program/syz/arg.hpp"

#include <algorithm>
#include <cassert>
#include <format>
#include <span>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

namespace {

EmitArgsCtx args_ctx_from(const EmitCallCtx& ctx) {
    return EmitArgsCtx{ .target = ctx.target, .opts = ctx.opts };
}

std::string copyin_val_to_str(std::uint64_t addr, std::uint64_t size,
                              const std::string& val,
                              syz::BinaryFormat fmt) {
    switch (fmt) {
        case syz::BinaryFormat::kNative:
        case syz::BinaryFormat::kBigEndian:
            return std::format(
                "\tNONFAILING(*(uint{}*)0x{:x} = {});\n",
                size * 8, addr, val);
        case syz::BinaryFormat::kStrDec:
            // Baseline gate rejects these; we still emit a defensible
            // fallback for completeness if a future caller flips the
            // gate.
            return std::format(
                "\tNONFAILING(sprintf((char*)0x{:x}, "
                "\"%020llu\", (long long){}));\n", addr, val);
        case syz::BinaryFormat::kStrHex:
            return std::format(
                "\tNONFAILING(sprintf((char*)0x{:x}, "
                "\"0x%016llx\", (long long){}));\n", addr, val);
        case syz::BinaryFormat::kStrOct:
            return std::format(
                "\tNONFAILING(sprintf((char*)0x{:x}, "
                "\"%023llo\", (long long){}));\n", addr, val);
    }
    return {};
}

bool all_same_byte(std::span<const std::uint8_t> data) {
    if (data.empty()) return false;
    std::uint8_t v = data[0];
    return std::all_of(data.begin(), data.end(),
                       [v](std::uint8_t x) { return x == v; });
}

} // namespace

bool is_native(const EmitCallCtx& ctx, const syz::SyscallMeta& meta) {
    if (ctx.target_info == nullptr) return false;
    const auto& trampolines = ctx.target_info->syscall_trampolines();
    const bool has_trampoline =
        trampolines.find(meta.call_name()) != trampolines.end();
    return ctx.target_info->has_call_number(meta.call_name()) &&
           !has_trampoline;
}

void emit_copyin(std::string& out,
                 const EmitArgsCtx& args_ctx,
                 const syz::WireCopyin& copyin, int* csum_seq,
                 uint64_t data_offset) {
    // Mirror upstream DeserializeExec (decodeexec.go:121): copyin.addr
    // gets target.DataOffset added at decode time. reFuzz keeps raw
    // wire offsets; the rebase happens here.
    const uint64_t abs_addr = copyin.addr + data_offset;
    if (auto* c = std::get_if<syz::WireConst>(&copyin.arg)) {
        // bf_off / bf_len handling: when both are zero, it's a plain
        // copyin via copyin_val. Otherwise STORE_BY_BITMASK macro.
        if (c->bf_off == 0 && c->bf_len == 0) {
            const std::string val = handle_big_endian(
                *c, const_arg_to_str(args_ctx, *c, /*enforce_bit_size=*/false));
            out += copyin_val_to_str(abs_addr, c->size, val, c->fmt);
            return;
        }
        // bitfield path
        std::string htobe;
        const bool target_be =
            args_ctx.target != nullptr && args_ctx.target->big_endian();
        if (!target_be && c->fmt == syz::BinaryFormat::kBigEndian) {
            htobe = std::format("htobe{}", c->size * 8);
        }
        std::uint64_t bf_off = c->bf_off;
        if (target_be) {
            bf_off = c->size * 8 - c->bf_off - c->bf_len;
        }
        out += std::format(
            "\tNONFAILING(STORE_BY_BITMASK(uint{}, {}, 0x{:x}, {}, {}, {}));\n",
            c->size * 8, htobe, abs_addr,
            const_arg_to_str(args_ctx, *c, false), bf_off, c->bf_len);
        return;
    }
    if (auto* r = std::get_if<syz::WireResult>(&copyin.arg)) {
        const std::string val = result_arg_to_str(args_ctx, *r);
        out += copyin_val_to_str(abs_addr, r->size, val, r->fmt);
        return;
    }
    if (auto* d = std::get_if<syz::WireData>(&copyin.arg)) {
        std::span<const std::uint8_t> bytes(d->data.data(), d->data.size());
        if (!bytes.empty() && all_same_byte(bytes)) {
            out += std::format(
                "\tNONFAILING(memset((void*)0x{:x}, {}, {}));\n",
                abs_addr, static_cast<unsigned>(bytes[0]), bytes.size());
        } else {
            out += std::format(
                "\tNONFAILING(memcpy((void*)0x{:x}, \"{}\", {}));\n",
                abs_addr, to_c_string(bytes, d->readable), bytes.size());
        }
        return;
    }
    if (auto* cs = std::get_if<syz::WireCsum>(&copyin.arg)) {
        // Only inet csum supported (csum_kind == 0). Caller's gate
        // rejects unsupported values.
        ++*csum_seq;
        out += generate_csum_inet(abs_addr, *cs, *csum_seq, data_offset);
        return;
    }
    if (auto* a = std::get_if<syz::WireAddr>(&copyin.arg)) {
        // Mirror upstream DeserializeExec (decodeexec.go:188-198):
        // execArgAddr32/64 inside a copyin is decoded into
        // ExecArgConst{Value: wire_addr + DataOffset, Size: 4 or 8,
        // Format: Native}. This shape arises whenever a struct/union
        // leaf is a pointer (e.g. msghdr.msg_iov, iovec.iov_base);
        // serialize_for_exec emits execArgAddr*/Native via
        // exec_wire.cpp:165, and DeserializeExec rebases at decode
        // time. reFuzz's wire keeps WireAddr as its own variant, so
        // csource materializes the equivalent WireConst here and
        // emits via the standard copyin_val path.
        syz::WireConst as_const;
        as_const.size = a->ptr_size != 0 ? a->ptr_size :
                        (args_ctx.target != nullptr ?
                         args_ctx.target->ptr_size() : 8);
        as_const.val  = a->addr + data_offset;
        as_const.fmt  = syz::BinaryFormat::kNative;
        const std::string val = const_arg_to_str(args_ctx, as_const,
                                                 /*enforce_bit_size=*/false);
        out += copyin_val_to_str(abs_addr, as_const.size, val,
                                 syz::BinaryFormat::kNative);
        return;
    }
}

void emit_copyout(std::string& out, const EmitCallCtx& /*ctx*/,
                  const syz::SyscallMeta& /*meta*/,
                  std::uint64_t result_index, bool res_copyout,
                  std::span<const syz::WireCopyout> copyouts,
                  uint64_t data_offset) {
    out += "\tif (res != -1)";
    const bool multiple =
        copyouts.size() > 1 ||
        (res_copyout && !copyouts.empty());
    if (multiple) {
        out += " {";
    }
    out += "\n";
    if (res_copyout) {
        out += std::format("\t\tr[{}] = res;\n", result_index);
    }
    for (const auto& co : copyouts) {
        // DataOffset rebase mirror (decodeexec.go:127).
        const uint64_t abs_addr = co.addr + data_offset;
        out += std::format(
            "\t\tNONFAILING(r[{}] = *(uint{}*)0x{:x});\n",
            co.idx, co.size * 8, abs_addr);
    }
    if (multiple) {
        out += "\t}\n";
    }
}

std::string fmt_call_body(const EmitCallCtx& ctx,
                          const syz::SyscallMeta& meta,
                          const syz::WireCall& call) {
    const bool native = is_native(ctx, meta);
    std::string call_name = meta.call_name();
    if (ctx.target_info != nullptr) {
        const auto& tramps = ctx.target_info->syscall_trampolines();
        if (auto it = tramps.find(meta.call_name()); it != tramps.end()) {
            call_name = it->second;
        }
    }

    auto args_ctx = args_ctx_from(ctx);
    std::vector<std::string> args_strs;

    std::string func_name;
    if (native) {
        func_name = "syscall";
        args_strs.push_back(std::string(ctx.target_info->syscall_prefix()) +
                            call_name);
    } else if (call_name.starts_with("syz_")) {
        func_name = call_name;
    } else {
        // ((intptr_t(*)(intptr_t,intptr_t,...))CAST(callName))
        const int total_args = static_cast<int>(call.args.size()) +
                                meta.missing_args();
        std::string args_decl;
        for (int i = 0; i < total_args; ++i) {
            if (i != 0) args_decl += ",";
            args_decl += "intptr_t";
        }
        func_name = std::format("((intptr_t(*)({}))CAST({}))",
                                args_decl, call_name);
    }

    const auto& fields = meta.args();
    const uint64_t data_offset =
        ctx.target != nullptr ? ctx.target->data_offset() : 0;
    for (std::size_t i = 0; i < call.args.size(); ++i) {
        const auto& wa = call.args[i];
        const syz::Field empty_field;
        const syz::Field& field =
            i < fields.size() ? fields[i] : empty_field;
        if (auto* c = std::get_if<syz::WireConst>(&wa)) {
            // Per upstream: only Native/BigEndian Format permitted in
            // top-level syscall arg; baseline gate already enforces.
            std::string com = arg_comment(args_ctx, field, wa);
            std::string val = handle_big_endian(
                *c, const_arg_to_str(args_ctx, *c, /*enforce_bit_size=*/native));
            args_strs.push_back(com + val);
        } else if (auto* r = std::get_if<syz::WireResult>(&wa)) {
            std::string com = arg_comment(args_ctx, field, wa);
            std::string val = result_arg_to_str(args_ctx, *r);
            if (native && ctx.target != nullptr &&
                ctx.target->ptr_size() == 4) {
                val = "(intptr_t)" + val;
            }
            args_strs.push_back(com + val);
        } else if (auto* a = std::get_if<syz::WireAddr>(&wa)) {
            // Mirror upstream DeserializeExec (decodeexec.go:188-198):
            // execArgAddr32/64 is decoded into ExecArgConst with
            // value = wire_addr + DataOffset, size = 4 or 8. csource
            // then formats via constArgToStr. reFuzz keeps WireAddr
            // as its own variant; we materialize an equivalent
            // WireConst here for emission.
            syz::WireConst as_const;
            as_const.size = a->ptr_size != 0 ? a->ptr_size :
                            (ctx.target != nullptr ? ctx.target->ptr_size() : 8);
            as_const.val  = a->addr + data_offset;
            as_const.fmt  = syz::BinaryFormat::kNative;
            std::string com = arg_comment(args_ctx, field, wa);
            std::string val = const_arg_to_str(args_ctx, as_const,
                                               /*enforce_bit_size=*/native);
            args_strs.push_back(com + val);
        } else {
            // Unknown arg type at top-level — should never happen
            // when baseline_gate passed (data/csum at top-level
            // already rejected).
            args_strs.push_back("/*unsupported_arg*/0");
        }
    }
    for (int i = 0; i < meta.missing_args(); ++i) {
        args_strs.push_back("0");
    }

    std::string args_joined;
    for (std::size_t i = 0; i < args_strs.size(); ++i) {
        if (i != 0) args_joined += ", ";
        args_joined += args_strs[i];
    }
    return std::format("{}({})", func_name, args_joined);
}

void emit_call(std::string& out, const EmitCallCtx& ctx,
               const syz::SyscallMeta& meta,
               const syz::WireCall& call,
               int call_index, bool have_copyout, bool trace) {
    const bool native = is_native(ctx, meta);
    out += "\t";
    if (!native) {
        if (have_copyout || trace) {
            out += "res = -1;\n\t";
        }
        if (trace) {
            out += "errno = EFAULT;\n\t";
        }
        out += "NONFAILING(";
    }
    if (have_copyout || trace) {
        out += "res = ";
    }
    out += fmt_call_body(ctx, meta, call);
    if (!native) {
        out += ")";
    }
    out += ";";
    if (ctx.annotator != nullptr) {
        std::string comment = ctx.annotator->Annotate(call, meta);
        if (!comment.empty()) {
            out += " /* " + comment + " */";
        }
    }
    out += "\n";
    if (trace) {
        std::string cast;
        if (!native && !meta.call_name().starts_with("syz_")) {
            cast = "(intptr_t)(int)";
        }
        out += std::format(
            "\tfprintf(stderr, \"### call={} errno=%u\\n\", "
            "{}res == -1 ? errno : 0);\n",
            call_index, cast);
    }
}

} // namespace refuzz::crash::repro::csource::internal
