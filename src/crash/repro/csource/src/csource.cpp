// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Write() public API. Adapt of
// upstream pkg/csource/csource.go::Write + generateSource (40-160).

#include "refuzz/crash/repro/csource/csource.hpp"

#include "refuzz/crash/repro/csource/internal/baseline_gate.hpp"
#include "refuzz/crash/repro/csource/internal/common_header.hpp"
#include "refuzz/crash/repro/csource/internal/emit_prog_calls.hpp"
#include "refuzz/crash/repro/csource/internal/filter.hpp"
#include "refuzz/crash/repro/csource/internal/format_arg.hpp"
#include "refuzz/crash/repro/csource/internal/post_process.hpp"
#include "refuzz/crash/repro/csource/internal/sandbox.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <format>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::crash::repro::csource {

namespace internal_ns = ::refuzz::crash::repro::csource::internal;
namespace syz         = ::refuzz::program::syz;

namespace {

CSourceFailure invalid_options(std::string msg) {
    return CSourceFailure{ .code = CSourceError::kInvalidOptions,
                           .message = std::move(msg) };
}

CSourceFailure serialize_failed(std::string msg) {
    return CSourceFailure{ .code = CSourceError::kSerializeFailed,
                           .message = std::move(msg) };
}

CSourceFailure decode_failed(std::string msg) {
    return CSourceFailure{ .code = CSourceError::kDecodeFailed,
                           .message = std::move(msg) };
}

// Adapt of upstream csource.go::generateSyscallDefines (217-241).
std::string generate_syscall_defines(
    const std::set<std::string>& call_names,
    const ICSourceTargetInfo& target_info,
    const ::refuzz::program::syz::Target& target) {
    std::ostringstream w;
    const std::string prefix = std::string(target_info.syscall_prefix());
    for (const auto& name : call_names) {
        const auto* meta = target.find_syscall(name);
        if (meta == nullptr) continue;
        const std::uint64_t nr = meta->nr();
        if (!target_info.has_call_number(name)) continue;
        if (!target_info.need_syscall_define(nr)) continue;
        w << std::format("#ifndef {}{}\n", prefix, name);
        w << std::format("#define {}{} {}\n", prefix, name, nr);
        w << "#endif\n";
    }
    if (target_info.goos() == "linux" && target_info.ptr_size_is_4()) {
        w << "#undef __NR_mmap\n";
        w << "#define __NR_mmap __NR_mmap2\n";
    }
    return w.str();
}

// Adapt of upstream csource.go::generateSyscalls (188-215).
std::string generate_syscalls_block(
    const std::vector<std::string>& calls, bool has_vars,
    const Options& opts) {
    std::ostringstream w;
    if (!opts.Threaded && !opts.Legacy.Collide) {
        if (!calls.empty() && (has_vars || opts.Trace)) {
            w << "\tintptr_t res = 0;\n";
        }
        w << "\tif (write(1, \"executing program\\n\", "
             "sizeof(\"executing program\\n\") - 1)) {}\n";
        if (opts.Trace) {
            w << "\tfprintf(stderr, \"### start\\n\");\n";
        }
        for (const auto& c : calls) w << c;
    } else if (!calls.empty()) {
        if (has_vars || opts.Trace) {
            w << "\tintptr_t res = 0;\n";
        }
        w << "\tswitch (call) {\n";
        for (std::size_t i = 0; i < calls.size(); ++i) {
            w << std::format("\tcase {}:\n", i);
            // Indent each line of c by an extra tab.
            std::string c = calls[i];
            std::size_t pos = 0;
            while ((pos = c.find('\t', pos)) != std::string::npos) {
                c.insert(pos, "\t");
                pos += 2;
            }
            w << c;
            w << "\t\tbreak;\n";
        }
        w << "\t}\n";
    }
    return w.str();
}

std::string vars_block(const std::vector<std::uint64_t>& vars) {
    if (vars.empty()) return {};
    std::ostringstream w;
    w << std::format("uint64 r[{}] = {{", vars.size());
    for (std::size_t i = 0; i < vars.size(); ++i) {
        if (i != 0) w << ", ";
        w << std::format("0x{:x}", vars[i]);
    }
    w << "};\n";
    return w.str();
}

void collect_call_names(const syz::Prog& p, std::set<std::string>& out,
                        const ICSourceTargetInfo& ti) {
    for (const auto& c : p.calls()) {
        if (c == nullptr || c->meta() == nullptr) continue;
        const auto& name = c->meta()->call_name();
        out.insert(name);
        const auto& deps_map = ti.pseudo_syscall_deps();
        if (auto it = deps_map.find(name); it != deps_map.end()) {
            for (const auto& dep : it->second) out.insert(dep);
        }
    }
}

} // namespace

std::expected<std::string, CSourceFailure>
Write(const syz::Prog& prog, const Options& opts,
      const ICallAnnotator& annotator,
      const ICSourceTargetInfo& target_info) {
    // 1. Options::Check (per "linux"; future Epic 4.5 lifts the OS arg).
    if (auto r = opts.Check(target_info.goos()); !r.has_value()) {
        return std::unexpected(invalid_options(std::move(r.error())));
    }

    // 2. Baseline gate (Options + per-Call CallProps).
    if (auto r = internal_ns::baseline_gate_options_and_calls(prog, opts);
        !r.has_value()) {
        return std::unexpected(std::move(r.error()));
    }

    // 3. filter_calls (drops syz_emit_* when the matching option is off).
    auto filtered = internal_ns::filter_calls(prog, opts);
    const syz::Prog* eff_prog = internal_ns::prog_of(filtered);
    if (eff_prog == nullptr) {
        return std::unexpected(CSourceFailure{
            .code = CSourceError::kInternal,
            .message = "filter_calls returned no prog"});
    }
    if (eff_prog->calls().empty()) {
        return std::unexpected(CSourceFailure{
            .code = CSourceError::kUnsupportedByEpic4,
            .message = "all calls dropped by filter_calls (Epic 4 baseline)"});
    }

    // 4. Required features + mmap setup prog.
    auto features = internal_ns::analyze_required_features(*eff_prog);
    auto mmap_prog = target_info.make_data_mmap_prog(*eff_prog->target());
    if (mmap_prog == nullptr) {
        return std::unexpected(CSourceFailure{
            .code = CSourceError::kInternal,
            .message = "make_data_mmap_prog returned null (schema lacks "
                       "mmap/PROT_*?)"});
    }

    // 5. Typed call comments (computed BEFORE wire lowering — H1 fix).
    std::vector<std::string> call_comments;
    if (opts.CallComments) {
        call_comments = internal_ns::make_typed_call_comments(*eff_prog);
    }

    // 6. Lower to wire.
    auto eff_bytes = syz::serialize_for_exec(*eff_prog);
    if (!eff_bytes.has_value()) {
        return std::unexpected(serialize_failed(
            "serialize_for_exec(prog) failed"));
    }
    auto eff_wp = syz::decode_exec_wire(*eff_bytes);
    if (!eff_wp.has_value()) {
        return std::unexpected(decode_failed(
            std::format("decode_exec_wire(prog) failed: {}", eff_wp.error().message)));
    }
    // 6b. Per-WireArg gate (reject Str{Dec,Hex,Oct} & top-level Data).
    if (auto r = internal_ns::baseline_gate_wire_args(*eff_wp); !r.has_value()) {
        return std::unexpected(std::move(r.error()));
    }
    auto mmap_bytes = syz::serialize_for_exec(*mmap_prog);
    if (!mmap_bytes.has_value()) {
        return std::unexpected(serialize_failed(
            "serialize_for_exec(mmap_prog) failed"));
    }
    auto mmap_wp = syz::decode_exec_wire(*mmap_bytes);
    if (!mmap_wp.has_value()) {
        return std::unexpected(decode_failed(
            std::format("decode_exec_wire(mmap_prog) failed: {}",
                        mmap_wp.error().message)));
    }

    // 7. Per-call emission.
    internal_ns::EmitCallCtx em_ctx{
        .target      = eff_prog->target(),
        .target_info = &target_info,
        .opts        = &opts,
        .annotator   = &annotator,
    };
    auto eff_calls = internal_ns::emit_prog_calls(
        *eff_prog, *eff_wp, em_ctx, call_comments,
        opts.Trace, opts.CallComments);
    if (!eff_calls.has_value()) {
        return std::unexpected(std::move(eff_calls.error()));
    }
    auto mmap_calls = internal_ns::emit_prog_calls(
        *mmap_prog, *mmap_wp, em_ctx, {},
        /*trace=*/false, /*add_comments=*/false);
    if (!mmap_calls.has_value()) {
        return std::unexpected(std::move(mmap_calls.error()));
    }

    // 8. Build replacements map.
    std::set<std::string> all_call_names;
    collect_call_names(*eff_prog, all_call_names, target_info);
    collect_call_names(*mmap_prog, all_call_names, target_info);

    const auto syscalls_block = generate_syscalls_block(
        eff_calls->calls, !eff_calls->vars.empty(), opts);
    const auto syscall_defines = generate_syscall_defines(
        all_call_names, target_info, *eff_prog->target());
    const auto sandbox_func = internal_ns::generate_sandbox_function_signature(
        opts.Sandbox, opts.SandboxArg);
    const auto results = vars_block(eff_calls->vars);

    // mmap calls flat-joined.
    std::string mmap_data;
    for (const auto& c : mmap_calls->calls) mmap_data += c;

    const auto timeouts = target_info.timeouts(
        opts.Slowdown < 1 ? 1 : opts.Slowdown);

    std::string program_timeout = std::format("{}", timeouts.program_ms);
    std::string base_call_timeout = std::format("{}", timeouts.syscall_ms);
    // CALL_TIMEOUT_MS: per-call adjustments for non-default Attrs.Timeout.
    // baseline gate ensures FailNth/Async/Rerun = 0; per-syscall
    // attrs.timeout is allowed and we mirror upstream's per-call adder.
    std::string call_timeout = base_call_timeout;
    for (std::size_t i = 0; i < eff_prog->calls().size(); ++i) {
        const auto* meta = eff_prog->calls()[i] ?
            eff_prog->calls()[i]->meta() : nullptr;
        if (meta == nullptr) continue;
        const auto t = meta->attrs().timeout;
        if (t != 0) {
            call_timeout += std::format(" + (call == {} ? {} : 0)",
                                        i, t * timeouts.scale);
        }
    }

    std::unordered_map<std::string, std::string> replacements = {
        {"PROCS",                 std::format("{}", opts.Procs)},
        {"REPEAT_TIMES",          std::format("{}", opts.RepeatTimes)},
        {"NUM_CALLS",             std::format("{}", eff_prog->calls().size())},
        {"MMAP_DATA",             mmap_data},
        {"SYSCALL_DEFINES",       syscall_defines},
        {"SANDBOX_FUNC",          sandbox_func},
        {"RESULTS",               results},
        {"SYSCALLS",              syscalls_block},
        {"PROGRAM_TIMEOUT_MS",    program_timeout},
        {"BASE_CALL_TIMEOUT_MS",  base_call_timeout},
        {"CALL_TIMEOUT_MS",       call_timeout},
        {"ASYNC_CONDITIONS",      ""},  // baseline gate forbids async
    };
    // Inline-into-main short-circuit: when Threaded=false, Repeat=false,
    // Sandbox="" the upstream csource bypasses the loop wrapper and
    // inlines syscalls into main. For baseline (Sandbox="none") this
    // path doesn't fire — but we mirror the rule for completeness.
    if (!opts.Threaded && !opts.Repeat && opts.Sandbox.empty()) {
        replacements["SANDBOX_FUNC"] = replacements["SYSCALLS"];
        replacements["SYSCALLS"]     = "unused";
    }

    // 9. createCommonHeader.
    auto header = internal_ns::create_common_header(
        *eff_prog, *mmap_prog, replacements, opts, target_info, features);
    if (!header.has_value()) {
        return std::unexpected(std::move(header.error()));
    }

    // 10. post_process + autogenerated banner.
    std::string out =
        "// autogenerated by reFuzz csource (port of syzkaller pkg/csource)\n\n";
    out += internal_ns::post_process(std::move(*header), opts, target_info);
    return out;
}

} // namespace refuzz::crash::repro::csource
