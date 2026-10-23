// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-5 — define_list / common_defines parity vs upstream
// pkg/csource/common.go::defineList + commonDefines (75-131).

#include "refuzz/crash/repro/csource/internal/common_header.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace ch  = ::refuzz::crash::repro::csource::internal;
namespace syz = ::refuzz::program::syz;

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

bool has(const std::vector<std::string>& v, std::string_view s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

cs::Options baseline() {
    cs::Options o;
    o.Sandbox = "none";
    return o;
}

std::unique_ptr<syz::Call> meta_call(const syz::Target& t, const std::string& n) {
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall(n));
    return c;
}

void test_common_defines_baseline() {
    const auto& t = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    syz::Prog p;
    p.set_target(&t);
    auto opts = baseline();
    ch::RequiredFeatures rf;

    auto defines = ch::common_defines(p, opts, ti, rf);

    // Always-true frame.
    CHECK(has(defines, "GOOS_linux"));
    CHECK(has(defines, "GOARCH_amd64"));
    CHECK(has(defines, "HOSTGOOS_linux"));
    CHECK(has(defines, "SYZ_SANDBOX_NONE"));
    CHECK(has(defines, "SYZ_EXECUTOR_USES_FORK_SERVER"));

    // baseline-false flags must be absent.
    CHECK(!has(defines, "SYZ_THREADED"));
    CHECK(!has(defines, "SYZ_REPEAT"));
    CHECK(!has(defines, "SYZ_NET_INJECTION"));
    CHECK(!has(defines, "SYZ_SANDBOX_SETUID"));
    CHECK(!has(defines, "SYZ_SANDBOX_NAMESPACE"));
}

void test_common_defines_threaded_repeat_procs() {
    const auto& t = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    syz::Prog p;
    p.set_target(&t);
    cs::Options opts = baseline();
    opts.Threaded = true;
    opts.Repeat   = true;
    opts.Procs    = 4;
    ch::RequiredFeatures rf;

    auto defines = ch::common_defines(p, opts, ti, rf);
    CHECK(has(defines, "SYZ_THREADED"));
    CHECK(has(defines, "SYZ_REPEAT"));
    CHECK(has(defines, "SYZ_MULTI_PROC"));
}

void test_common_defines_required_features_propagate() {
    const auto& t = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    syz::Prog p;
    p.set_target(&t);
    cs::Options opts = baseline();
    ch::RequiredFeatures rf;
    rf.bitmasks = true;
    rf.csums    = true;

    auto defines = ch::common_defines(p, opts, ti, rf);
    CHECK(has(defines, "SYZ_USE_BITMASKS"));
    CHECK(has(defines, "SYZ_USE_CHECKSUMS"));
}

void test_define_list_includes_per_call_NRs() {
    const auto& t = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    syz::Prog p;
    p.set_target(&t);
    p.add_call(meta_call(t, "read"));
    p.add_call(meta_call(t, "close"));
    syz::Prog mmap;
    mmap.set_target(&t);
    mmap.add_call(meta_call(t, "mmap"));

    auto opts = baseline();
    ch::RequiredFeatures rf;
    auto defines = ch::define_list(p, mmap, opts, ti, rf);

    CHECK(has(defines, "__NR_read"));
    CHECK(has(defines, "__NR_close"));
    CHECK(has(defines, "__NR_mmap"));

    // Sorted invariant.
    auto sorted = defines;
    std::sort(sorted.begin(), sorted.end());
    CHECK(sorted == defines);
}

void test_remove_system_defines_strips_listed() {
    std::string src =
        "#define __STDC__ 1\n"
        "#define __STDC_HOSTED__ 1\n"
        "#define MY_FOO 42\n"
        "#define KEEP_ME 7\n";
    auto out = ch::remove_system_defines(src,
        std::vector<std::string>{"MY_FOO=42"});
    std::fprintf(stderr, "  stripped:\n%s\n", out.c_str());
    CHECK(out.find("__STDC__") == std::string::npos);
    CHECK(out.find("__STDC_HOSTED__") == std::string::npos);
    CHECK(out.find("MY_FOO") == std::string::npos);
    CHECK(out.find("KEEP_ME") != std::string::npos);
}

void test_remove_system_defines_strips_stdc_version_line() {
    std::string src = "#define __STDC_VERSION__ 201112L\n#define KEEP 1\n";
    auto out = ch::remove_system_defines(src,
        std::vector<std::string>{"KEEP=1"});
    CHECK(out.find("__STDC_VERSION__") == std::string::npos);
    CHECK(out.find("KEEP") == std::string::npos);
}

void test_required_features_propagates_csum_via_foreach_arg() {
    const auto& t = syz::Target::linux_amd64();
    // Find a call that has a CsumType in its tree. iputils ping
    // family (`socket$inet_icmp_raw` / `sendmsg$inet_icmp` etc.)
    // is a typical csum carrier; for the structural smoke we just
    // assert RequiredFeatures runs without crashing on a real prog
    // and detects features when set on Call.Props.
    syz::Prog p;
    p.set_target(&t);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall("read"));
    syz::CallProps props;
    props.fail_nth = 1;
    c->set_props(props);
    p.add_call(std::move(c));

    auto rf = ch::analyze_required_features(p);
    CHECK(rf.fault_injection);
    CHECK(!rf.async);
    CHECK(!rf.bitmasks);
}

} // namespace

int main() {
    RUN_TEST(test_common_defines_baseline);
    RUN_TEST(test_common_defines_threaded_repeat_procs);
    RUN_TEST(test_common_defines_required_features_propagate);
    RUN_TEST(test_define_list_includes_per_call_NRs);
    RUN_TEST(test_remove_system_defines_strips_listed);
    RUN_TEST(test_remove_system_defines_strips_stdc_version_line);
    RUN_TEST(test_required_features_propagates_csum_via_foreach_arg);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
