// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-C — pin the Build() argv layout against upstream
// pkg/csource/build.go:51-96. This test does NOT spawn a compiler;
// it inspects internal::build_argv() directly so a regression that
// (a) drops a -DGOOS_/GOARCH_/HOSTGOOS_ flag, (b) re-adds the M1-
// banned -O1/-static-pie/-pthread doublers, or (c) breaks the
// PtrSize-gated -Wno-overflow surfaces immediately at CI without
// needing a working host gcc.
//
// Coverage:
// - Linux/amd64 default cflags pass-through (no extras, no -Wno-overflow).
// - Caller-provided extra_cflags appended AFTER sysTarget cflags.
// - ptr_size_is_4 stub appends -Wno-overflow.
// - Hint vs synthesized binary path both flow through argv[2].

#include "refuzz/crash/repro/csource/build.hpp"
#include "refuzz/crash/repro/csource/internal/build_argv.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

namespace cs       = ::refuzz::crash::repro::csource;
namespace internal = ::refuzz::crash::repro::csource::internal;
namespace syz      = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

bool contains(const std::vector<std::string>& argv, std::string_view needle) {
    for (const auto& a : argv) if (a == needle) return true;
    return false;
}

std::size_t count(const std::vector<std::string>& argv,
                  std::string_view needle) {
    std::size_t n = 0;
    for (const auto& a : argv) if (a == needle) ++n;
    return n;
}

void test_linux_amd64_canonical_argv() {
    cs::BuildOptions bopts;
    auto argv = internal::build_argv(
        cs::linux_amd64_target_info(), bopts, "/tmp/foo/syz-executor");

    // Slot-by-slot prefix lock — pkg/csource/build.go:59-69 verbatim.
    CHECK(argv.size() >= 9);
    CHECK(argv[0] == "gcc");
    CHECK(argv[1] == "-o");
    CHECK(argv[2] == "/tmp/foo/syz-executor");
    CHECK(argv[3] == "-DGOOS_linux=1");
    CHECK(argv[4] == "-DGOARCH_amd64=1");
    CHECK(argv[5] == "-DHOSTGOOS_linux=1");
    CHECK(argv[6] == "-x");
    CHECK(argv[7] == "c");
    CHECK(argv[8] == "-");

    // sysTarget.CFlags spliced verbatim AFTER -x c -. The current
    // Linux/amd64 singleton carries 14 entries; -m64 first,
    // -static-pie last (locked by csource_target_info_check fixture).
    CHECK(argv[9] == "-m64");
    CHECK(argv.back() == "-static-pie");

    // M1 contract: Build() must NOT inject extras beyond what
    // target_info.cflags() already provides. -O2/-pthread/-static-pie
    // appear EXACTLY ONCE each (they live in sysTarget.CFlags only,
    // never re-appended by build.cpp).
    CHECK(count(argv, "-O2") == 1);
    CHECK(count(argv, "-pthread") == 1);
    CHECK(count(argv, "-static-pie") == 1);
    // Specifically not the rev-1 banned -O1.
    CHECK(!contains(argv, "-O1"));

    // ptr_size_is_4()=false on Linux/amd64 ⇒ no -Wno-overflow.
    CHECK(!contains(argv, "-Wno-overflow"));
}

void test_extra_cflags_appended_after_target_cflags() {
    cs::BuildOptions bopts;
    bopts.extra_cflags = {"-fpermissive", "-w"};   // BuildNoWarn equivalent
    auto argv = internal::build_argv(
        cs::linux_amd64_target_info(), bopts, "/tmp/foo/bin");

    // -static-pie (last sysTarget cflag) precedes the extras.
    CHECK(argv[argv.size() - 3] == "-static-pie");
    CHECK(argv[argv.size() - 2] == "-fpermissive");
    CHECK(argv[argv.size() - 1] == "-w");
    // ptr_size_is_4 still false — no -Wno-overflow even with extras.
    CHECK(!contains(argv, "-Wno-overflow"));
}

// Synthetic 32-bit ICSourceTargetInfo just to exercise the
// PtrSize == 4 branch.
class StubPtr32TargetInfo final : public cs::ICSourceTargetInfo {
public:
    std::string_view cpp_path()   const override { return "cpp"; }
    std::string_view c_compiler() const override { return "gcc"; }
    std::span<const std::string> cflags() const override {
        static const std::vector<std::string> kFlags = {"-m32"};
        return std::span<const std::string>(kFlags.data(), kFlags.size());
    }
    cs::CSourceTimeouts timeouts(int) const override { return {}; }
    std::string_view syscall_prefix() const override { return "__NR_"; }
    const std::unordered_map<std::string, std::string>&
    syscall_trampolines() const override {
        static const std::unordered_map<std::string, std::string> e;
        return e;
    }
    const std::unordered_map<std::string, std::vector<std::string>>&
    pseudo_syscall_deps() const override {
        static const std::unordered_map<std::string, std::vector<std::string>> e;
        return e;
    }
    bool need_syscall_define(std::uint64_t) const override { return false; }
    bool has_call_number(std::string_view)  const override { return true; }
    bool executor_uses_fork_server()        const override { return true; }
    bool ptr_size_is_4()                    const override { return true; }
    std::string_view goos()      const override { return "linux"; }
    std::string_view goarch()    const override { return "i386"; }
    std::string_view host_goos() const override { return "linux"; }
    std::unique_ptr<syz::Prog>
    make_data_mmap_prog(const syz::Target&) const override { return nullptr; }
};

void test_ptr_size_is_4_appends_wno_overflow() {
    StubPtr32TargetInfo ti;
    cs::BuildOptions bopts;
    auto argv = internal::build_argv(ti, bopts, "/tmp/foo/bin32");
    // Layout: gcc -o ... -DGOOS_linux=1 -DGOARCH_i386=1 -DHOSTGOOS_linux=1
    //         -x c - -m32 -Wno-overflow
    CHECK(argv[3] == "-DGOOS_linux=1");
    CHECK(argv[4] == "-DGOARCH_i386=1");
    CHECK(argv[9] == "-m32");
    // -Wno-overflow is exactly the trailing argv (no extras).
    CHECK(argv.back() == "-Wno-overflow");
    CHECK(count(argv, "-Wno-overflow") == 1);
}

void test_hint_vs_temp_path_flow_through_argv2() {
    cs::BuildOptions bopts;
    bopts.output_path_hint = "/somewhere/preset/path";
    auto a1 = internal::build_argv(cs::linux_amd64_target_info(), bopts,
                                   bopts.output_path_hint);
    CHECK(a1[2] == "/somewhere/preset/path");

    bopts.output_path_hint.clear();
    auto a2 = internal::build_argv(cs::linux_amd64_target_info(), bopts,
                                   "/tmp/refuzz-csource-AB12CD/syz-executor");
    CHECK(a2[2] == "/tmp/refuzz-csource-AB12CD/syz-executor");
}

} // namespace

int main() {
    RUN_TEST(test_linux_amd64_canonical_argv);
    RUN_TEST(test_extra_cflags_appended_after_target_cflags);
    RUN_TEST(test_ptr_size_is_4_appends_wno_overflow);
    RUN_TEST(test_hint_vs_temp_path_flow_through_argv2);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
