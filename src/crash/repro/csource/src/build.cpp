// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Build() / Format().
//
// Body is a 1:1 port of pkg/csource/build.go::build (lines 51-96)
// and pkg/csource/build.go::Format (lines 99-127). M1 fix:
// Build() pulls cflags exclusively from target_info.cflags() —
// no extra -O1 / -pthread / -static-pie / -Wno-* are injected here
// (sysTarget.CFlags already carries the warning-clean profile).
// Format() is an independent helper; Build() never invokes it.

#include "refuzz/crash/repro/csource/build.hpp"

#include "refuzz/crash/repro/csource/internal/build_argv.hpp"
#include "refuzz/crash/repro/csource/internal/process_run.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

namespace refuzz::crash::repro::csource {

namespace {

// Build() output binary path: caller hint or fresh /tmp dir created
// by mkdtemp. Returns {dir, bin}. dir is empty when the hint was used.
struct BinaryPath {
    std::string dir;        // owned temp dir to remove on cleanup; empty when hint
    std::string bin;        // path passed as -o
};

BinaryPath resolve_binary_path(const BuildOptions& bopts) {
    BinaryPath bp;
    if (!bopts.output_path_hint.empty()) {
        bp.bin = bopts.output_path_hint;
        return bp;
    }
    char tmpl[] = "/tmp/refuzz-csource-XXXXXX";
    char* d = ::mkdtemp(tmpl);
    if (d == nullptr) {
        return bp;   // dir + bin both empty signals failure
    }
    bp.dir = d;
    bp.bin = bp.dir + "/syz-executor";
    return bp;
}

// argv lives as vector<string>; run_process consumes string_views.
std::vector<std::string_view> as_views(const std::vector<std::string>& argv) {
    std::vector<std::string_view> v;
    v.reserve(argv.size());
    for (const auto& s : argv) v.emplace_back(s);
    return v;
}

// pkg/csource/build.go:111-127 — verbatim style block.
constexpr std::string_view kClangFormatStyle =
    "{\n"
    "BasedOnStyle: LLVM,\n"
    "IndentWidth: 2,\n"
    "UseTab: Never,\n"
    "BreakBeforeBraces: Linux,\n"
    "IndentCaseLabels: false,\n"
    "DerivePointerAlignment: false,\n"
    "PointerAlignment: Left,\n"
    "AlignTrailingComments: true,\n"
    "AllowShortBlocksOnASingleLine: false,\n"
    "AllowShortCaseLabelsOnASingleLine: false,\n"
    "AllowShortFunctionsOnASingleLine: false,\n"
    "AllowShortIfStatementsOnASingleLine: false,\n"
    "AllowShortLoopsOnASingleLine: false,\n"
    "ColumnLimit: 80,\n"
    "}";

} // namespace

namespace internal {

std::vector<std::string>
build_argv(const ICSourceTargetInfo& target_info,
           const BuildOptions&        bopts,
           std::string_view           binary_path) {
    std::vector<std::string> a;
    const auto cflags  = target_info.cflags();
    a.reserve(9 + cflags.size() + bopts.extra_cflags.size() + 1);

    a.emplace_back(target_info.c_compiler());
    a.emplace_back("-o");
    a.emplace_back(binary_path);
    a.emplace_back(std::format("-DGOOS_{}=1",     target_info.goos()));
    a.emplace_back(std::format("-DGOARCH_{}=1",   target_info.goarch()));
    a.emplace_back(std::format("-DHOSTGOOS_{}=1", target_info.host_goos()));
    a.emplace_back("-x");
    a.emplace_back("c");
    a.emplace_back("-");
    for (const auto& f : cflags)              a.emplace_back(f);
    for (const auto& f : bopts.extra_cflags)  a.emplace_back(f);
    if (target_info.ptr_size_is_4()) {
        a.emplace_back("-Wno-overflow");
    }
    return a;
}

} // namespace internal

std::expected<BuildResult, std::string>
Build(std::string_view csource,
      const BuildOptions&        bopts,
      const ICSourceTargetInfo&  target_info) {

    auto bp = resolve_binary_path(bopts);
    if (bp.bin.empty()) {
        return std::unexpected(std::format(
            "csource::Build: mkdtemp failed: {}", std::strerror(errno)));
    }

    std::vector<std::string> argv =
        internal::build_argv(target_info, bopts, bp.bin);
    std::vector<std::string_view> argv_views = as_views(argv);

    auto pr = internal::run_process(
        std::span<const std::string_view>(argv_views.data(),
                                          argv_views.size()),
        csource,
        std::chrono::seconds(bopts.timeout_seconds));

    auto cleanup_temp_dir = [&]() {
        if (!bp.dir.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(bp.dir, ec);
        }
    };

    if (!pr.has_value()) {
        cleanup_temp_dir();
        return std::unexpected(std::format(
            "csource::Build: run_process failed: {}", pr.error()));
    }

    BuildResult result;
    result.exit_status     = pr->exit_code;
    result.timed_out       = pr->timed_out;
    // Combined stdout + stderr — gcc emits diagnostics to stderr but
    // some toolchains push notes to stdout. Mirrors upstream
    // build.go:86 cmd.CombinedOutput().
    result.compiler_stderr = pr->stderr_;
    if (!pr->stdout_.empty()) {
        if (!result.compiler_stderr.empty() &&
            result.compiler_stderr.back() != '\n') {
            result.compiler_stderr.push_back('\n');
        }
        result.compiler_stderr += pr->stdout_;
    }

    if (pr->exit_code != 0 || pr->timed_out) {
        // Mirror pkg/csource/build.go:87-93 — remove the partial bin
        // (and its containing temp dir if we own it) and report the
        // failure with both source and combined output included.
        std::error_code ec;
        std::filesystem::remove(bp.bin, ec);
        cleanup_temp_dir();
        return std::unexpected(std::format(
            "failed to build program:\n{}\n{}\ncompiler invocation: {}",
            csource, result.compiler_stderr, [&] {
                std::string s(target_info.c_compiler());
                for (std::size_t i = 1; i < argv.size(); ++i) {
                    s.push_back(' ');
                    s += argv[i];
                }
                return s;
            }()));
    }

    result.binary_path = bp.bin;
    return result;
}

std::expected<std::string, std::string>
Format(std::string_view csource) {
    constexpr std::string_view kClangFormat = "clang-format";
    constexpr std::string_view kAssumeArg   = "-assume-filename=/src.c";
    constexpr std::string_view kStyleFlag   = "-style";

    std::array<std::string_view, 4> argv = {
        kClangFormat, kAssumeArg, kStyleFlag, kClangFormatStyle,
    };
    auto pr = internal::run_process(
        std::span<const std::string_view>(argv.data(), argv.size()),
        csource,
        std::chrono::seconds(60));

    if (!pr.has_value()) {
        // System-level setup failure (fork/pipe). Best-effort:
        // caller falls back to original source via .value_or(src).
        return std::unexpected(std::format(
            "csource::Format: run_process failed: {}", pr.error()));
    }
    if (pr->timed_out || pr->exit_code != 0) {
        // clang-format absent → exec failure inside child → exit_code=127.
        // Other non-zero → real format error. Either way return error
        // string; caller treats expected<>'s unexpected as "fall back
        // to the original source".
        return std::unexpected(std::format(
            "failed to format source (exit={}, timed_out={}):\n{}",
            pr->exit_code, pr->timed_out ? "true" : "false", pr->stderr_));
    }
    return pr->stdout_;
}

} // namespace refuzz::crash::repro::csource
