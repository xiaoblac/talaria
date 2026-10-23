// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-A — host_goos() returns a sane string on the build host.
//
// On Linux this asserts "linux" exactly. On other build hosts the
// assertion relaxes to "string non-empty" since we don't run CI on
// those hosts today; the singleton's ifdef chain still picks the
// right value.

#include "refuzz/crash/repro/csource/target_info.hpp"

#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace {

namespace cs = ::refuzz::crash::repro::csource;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

void test_host_goos() {
    const auto& ti = cs::linux_amd64_target_info();
    std::string_view host = ti.host_goos();
    std::fprintf(stderr, "  host_goos = %.*s\n",
                 static_cast<int>(host.size()), host.data());
#if defined(__linux__)
    CHECK(host == "linux");
#else
    CHECK(!host.empty());
#endif
}

void test_target_constants() {
    const auto& ti = cs::linux_amd64_target_info();
    CHECK(ti.cpp_path()       == "cpp");
    CHECK(ti.c_compiler()     == "gcc");
    CHECK(ti.syscall_prefix() == "__NR_");
    CHECK(ti.goos()           == "linux");
    CHECK(ti.goarch()         == "amd64");
    CHECK(!ti.ptr_size_is_4());
    CHECK(ti.executor_uses_fork_server());

    // need_syscall_define: NR < 313 → false, NR >= 313 → true.
    CHECK(!ti.need_syscall_define(0));
    CHECK(!ti.need_syscall_define(312));
    CHECK( ti.need_syscall_define(313));
    CHECK( ti.need_syscall_define(999));

    // has_call_number: real syscalls true, syz_* false.
    CHECK( ti.has_call_number("read"));
    CHECK( ti.has_call_number("openat"));
    CHECK(!ti.has_call_number("syz_mount_image"));
    CHECK(!ti.has_call_number("syz_open_dev"));

    auto cflags = ti.cflags();
    // Upstream sys/targets/targets.go Linux/amd64 cflags include both
    // the per-arch ("-m64") and the OS-level warning/optimization set
    // (-O2 / -pthread / -Wall / ... / -static-pie).
    CHECK(cflags.size() >= 1);
    bool found_m64 = false;
    bool found_static_pie = false;
    for (const auto& f : cflags) {
        if (f == "-m64")        found_m64 = true;
        if (f == "-static-pie") found_static_pie = true;
    }
    CHECK(found_m64);
    CHECK(found_static_pie);
}

void test_timeouts() {
    const auto& ti = cs::linux_amd64_target_info();

    // slowdown=1 → scale=1, program=5000, syscall=50.
    auto t = ti.timeouts(1);
    CHECK(t.scale == 1);
    CHECK(t.program_ms == 5'000);
    CHECK(t.syscall_ms == 50);

    // slowdown=3 → scale=3, program=15000, syscall=150.
    auto t3 = ti.timeouts(3);
    CHECK(t3.scale == 3);
    CHECK(t3.program_ms == 15'000);
    CHECK(t3.syscall_ms == 150);

    // slowdown=10 → scale=min(10,3)=3, program=15000, syscall=500.
    // (Mirror upstream sys/targets/targets.go::Target.Timeouts:
    //  Scale capped at 3; Syscall scales linearly with slowdown.)
    auto t10 = ti.timeouts(10);
    CHECK(t10.scale == 3);
    CHECK(t10.program_ms == 15'000);
    CHECK(t10.syscall_ms == 500);
}

void test_pseudo_syscall_deps() {
    const auto& ti = cs::linux_amd64_target_info();
    const auto& deps = ti.pseudo_syscall_deps();
    // Linux upstream registers 6 entries; we mirror them verbatim.
    CHECK(deps.size() == 6);

    auto require = [&](std::string_view pseudo,
                       std::vector<std::string> expected) {
        auto it = deps.find(std::string(pseudo));
        CHECK(it != deps.end());
        CHECK(it->second == expected);
    };
    require("syz_read_part_table", {"memfd_create"});
    require("syz_mount_image",     {"memfd_create"});
    require("syz_io_uring_setup",  {"io_uring_setup"});
    require("syz_clone3",          {"clone3", "exit"});
    require("syz_clone",           {"clone", "exit"});
    require("syz_pidfd_open",      {"pidfd_open"});
}

} // namespace

int main() {
    test_host_goos();
    test_target_constants();
    test_timeouts();
    test_pseudo_syscall_deps();
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
