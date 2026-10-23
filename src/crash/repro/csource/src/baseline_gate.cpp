// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — baseline gate body.
// See Epic 4 plan §3 binding "Options scope" for the field-by-field
// rule set this enforces.

#include "refuzz/crash/repro/csource/internal/baseline_gate.hpp"

#include <format>
#include <variant>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

namespace {

CSourceFailure unsupported(std::string msg) {
    return CSourceFailure{
        .code = CSourceError::kUnsupportedByEpic4,
        .message = std::move(msg),
    };
}

bool sandbox_is_baseline(std::string_view s) {
    return s.empty() || s == "none";
}

std::expected<void, CSourceFailure>
check_options_baseline(const Options& opts) {
    if (!sandbox_is_baseline(opts.Sandbox)) {
        return std::unexpected(unsupported(std::format(
            "Sandbox=\"{}\" not in baseline subset {{\"\",\"none\"}} "
            "(Epic 4 §10)",
            opts.Sandbox)));
    }
    // SandboxArg is only meaningful for sandbox=android (rejected above);
    // assert == 0 anyway so a stray value can't slip through later.
    if (opts.SandboxArg != 0) {
        return std::unexpected(unsupported(std::format(
            "SandboxArg={} not supported (Epic 4 baseline)",
            opts.SandboxArg)));
    }

    struct NamedFlag { std::string_view name; bool value; };
    const NamedFlag rejected[] = {
        {"Cgroups",       opts.Cgroups},
        {"BinfmtMisc",    opts.BinfmtMisc},
        {"Leak",          opts.Leak},
        {"NetInjection",  opts.NetInjection},
        {"NetDevices",    opts.NetDevices},
        {"NetReset",      opts.NetReset},
        {"VhciInjection", opts.VhciInjection},
        {"Wifi",          opts.Wifi},
        {"IEEE802154",    opts.IEEE802154},
        {"USB",           opts.USB},
        {"Sysctl",        opts.Sysctl},
        {"Swap",          opts.Swap},
        {"KCSAN",         opts.KCSAN},
        {"DevlinkPCI",    opts.DevlinkPCI},
        {"NicVF",         opts.NicVF},
        {"Collide",       opts.Legacy.Collide},
        {"Fault",         opts.Legacy.Fault},
    };
    for (const auto& f : rejected) {
        if (f.value) {
            return std::unexpected(unsupported(std::format(
                "Options.{} not supported (Epic 4 §10)", f.name)));
        }
    }
    if (opts.Legacy.FaultCall != 0 || opts.Legacy.FaultNth != 0) {
        return std::unexpected(unsupported(
            "Options.FaultCall/FaultNth (legacy fault injection) not "
            "supported (Epic 4 §10 / Epic 6)"));
    }
    return {};
}

std::expected<void, CSourceFailure>
check_call_props_baseline(const syz::Prog& prog) {
    const auto& calls = prog.calls();
    for (std::size_t i = 0; i < calls.size(); ++i) {
        const auto* call = calls[i].get();
        if (call == nullptr) continue;
        const auto& props = call->props();
        if (props.fail_nth != 0) {
            return std::unexpected(unsupported(std::format(
                "Call[{}].Props.FailNth={} not supported "
                "(Epic 4 §10 / Epic 6 fault injection)",
                i, props.fail_nth)));
        }
        if (props.async) {
            return std::unexpected(unsupported(std::format(
                "Call[{}].Props.Async=true not supported "
                "(Epic 4 §10 / Epic 6)", i)));
        }
        if (props.rerun != 0) {
            return std::unexpected(unsupported(std::format(
                "Call[{}].Props.Rerun={} not supported "
                "(Epic 4 §10 / Epic 6)", i, props.rerun)));
        }
    }
    return {};
}

} // namespace

std::expected<void, CSourceFailure>
baseline_gate_options_and_calls(const syz::Prog& prog, const Options& opts) {
    if (auto r = check_options_baseline(opts); !r.has_value()) {
        return r;
    }
    if (auto r = check_call_props_baseline(prog); !r.has_value()) {
        return r;
    }
    return {};
}

std::expected<void, CSourceFailure>
baseline_gate_wire_args(const syz::WireProgram& wp) {
    auto check_const = [&](std::size_t call_idx,
                           const syz::WireConst& c) -> std::expected<void, CSourceFailure> {
        switch (c.fmt) {
            case syz::BinaryFormat::kNative:
            case syz::BinaryFormat::kBigEndian:
                return {};
            case syz::BinaryFormat::kStrDec:
            case syz::BinaryFormat::kStrHex:
            case syz::BinaryFormat::kStrOct:
                return std::unexpected(unsupported(std::format(
                    "Call[{}] arg uses BinaryFormat::Str{{Dec,Hex,Oct}} "
                    "(audit row #4 stub; Epic 6)", call_idx)));
        }
        return {};
    };

    auto check_arg = [&](std::size_t call_idx,
                         const syz::WireArg& wa) -> std::expected<void, CSourceFailure> {
        if (auto* c = std::get_if<syz::WireConst>(&wa)) {
            return check_const(call_idx, *c);
        }
        // WireResult / WireAddr at top-level: supported (emit_call's
        // fmt_call_body materializes WireAddr as ConstArg with
        // value=addr+DataOffset, mirror of upstream
        // DeserializeExec decodeexec.go:188-198).
        if (std::holds_alternative<syz::WireResult>(wa) ||
            std::holds_alternative<syz::WireAddr>(wa)) {
            return {};
        }
        // WireData inside Copyin (typed buffer payload) IS allowed —
        // the gate fires only on top-level call args (csource doesn't
        // emit a Data top-level today). Top-level WireData would
        // surface through the per-call args walk; copyin walking is
        // a different path.
        if (std::holds_alternative<syz::WireData>(wa)) {
            return std::unexpected(unsupported(std::format(
                "Call[{}] top-level WireData not supported "
                "(audit row #4 stub)", call_idx)));
        }
        if (std::holds_alternative<syz::WireCsum>(wa)) {
            return std::unexpected(unsupported(std::format(
                "Call[{}] top-level WireCsum not supported", call_idx)));
        }
        return {};
    };

    std::size_t call_idx = 0;
    for (const auto& instr : wp.instrs) {
        if (auto* c = std::get_if<syz::WireCall>(&instr)) {
            for (const auto& arg : c->args) {
                if (auto r = check_arg(call_idx, arg); !r.has_value()) {
                    return r;
                }
            }
            ++call_idx;
        }
        // Copyin/Copyout/SetProps inspected separately by emit; they
        // can carry WireData (typed buffer copyin) which IS supported
        // at the copyin layer via copyin_val.
        if (auto* ci = std::get_if<syz::WireCopyin>(&instr)) {
            if (auto* c = std::get_if<syz::WireConst>(&ci->arg)) {
                // Inside-copyin WireConst with Str* is also a stub.
                if (auto r = check_const(call_idx, *c); !r.has_value()) {
                    return r;
                }
            }
        }
    }
    return {};
}

} // namespace refuzz::crash::repro::csource::internal
