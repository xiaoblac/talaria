// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-A — Options::Check parity vs upstream
// pkg/csource/options.go::Check (lines 70-150).
//
// Each case mirrors a single Check invariant; test runs both Linux
// and a non-Linux OS (open bsd as a reasonable proxy) for the
// checkLinuxOnly path. Error messages are matched substantively
// (token-bag), not byte-equal, because std::format and Go fmt may
// reorder a few characters.

#include "refuzz/crash/repro/csource/options.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
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

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

cs::Options baseline() {
    cs::Options o;
    o.Sandbox = "none";
    o.Repeat = false;
    return o;
}

bool err_contains(const std::expected<void, std::string>& r,
                  std::string_view needle) {
    if (r.has_value()) return false;
    return r.error().find(needle) != std::string::npos;
}

void test_unknown_sandbox_rejected() {
    cs::Options o = baseline();
    o.Sandbox = "bogus";
    auto r = o.Check("linux");
    CHECK(!r.has_value());
    CHECK(err_contains(r, "unknown sandbox"));
    CHECK(err_contains(r, "bogus"));
}

void test_known_sandboxes_accepted() {
    for (std::string s : {"", "none", "setuid", "namespace", "android"}) {
        cs::Options o = baseline();
        o.Sandbox = s;
        if (s == "namespace") o.UseTmpDir = true;     // namespace requires tmpdir
        // sandbox empty → also disable VhciInjection etc. (already false).
        auto r = o.Check("linux");
        if (!r.has_value()) {
            std::fprintf(stderr, "  unexpected fail for sandbox=%s: %s\n",
                         s.c_str(), r.error().c_str());
        }
        CHECK(r.has_value());
    }
}

void test_collide_without_threaded() {
    cs::Options o = baseline();
    o.Legacy.Collide = true;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "Collide without Threaded"));
}

void test_procs_without_repeat() {
    cs::Options o = baseline();
    o.Procs = 2;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "Procs>1 without Repeat"));
}

void test_netreset_without_repeat() {
    cs::Options o = baseline();
    o.NetReset = true;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "NetReset without Repeat"));
}

void test_repeat_times_without_repeat() {
    cs::Options o = baseline();
    o.RepeatTimes = 5;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "RepeatTimes without Repeat"));
}

void test_sandbox_empty_disables_features() {
    struct Case { std::string_view field; void (*set)(cs::Options&); };
    const Case cases[] = {
        {"NetInjection",  [](cs::Options& o){ o.NetInjection  = true; }},
        {"NetDevices",    [](cs::Options& o){ o.NetDevices    = true; }},
        {"Cgroups",       [](cs::Options& o){ o.Cgroups       = true; o.UseTmpDir = true; }},
        {"BinfmtMisc",    [](cs::Options& o){ o.BinfmtMisc    = true; }},
        {"VhciInjection", [](cs::Options& o){ o.VhciInjection = true; }},
        {"Wifi",          [](cs::Options& o){ o.Wifi          = true; }},
    };
    for (const auto& c : cases) {
        cs::Options o = baseline();
        o.Sandbox = "";
        c.set(o);
        auto r = o.Check("linux");
        CHECK(!r.has_value());
        CHECK(err_contains(r, c.field));
        CHECK(err_contains(r, "without sandbox"));
    }
}

void test_namespace_requires_tmpdir() {
    cs::Options o = baseline();
    o.Sandbox = "namespace";
    o.UseTmpDir = false;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "Sandbox=namespace without UseTmpDir"));
}

void test_netreset_requires_non_setuid() {
    cs::Options o = baseline();
    o.Repeat = true;
    o.Sandbox = "setuid";
    o.NetReset = true;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "NetReset without sandbox"));
}

void test_cgroups_requires_tmpdir() {
    cs::Options o = baseline();
    o.Cgroups = true;
    o.UseTmpDir = false;
    auto r = o.Check("linux");
    CHECK(err_contains(r, "Cgroups without UseTmpDir"));
}

void test_baseline_passes() {
    cs::Options o = baseline();
    auto r = o.Check("linux");
    CHECK(r.has_value());
}

void test_linux_only_features_rejected_on_non_linux() {
    cs::Options o = baseline();
    o.Cgroups = true;
    o.UseTmpDir = true;
    auto r = o.Check("openbsd");
    CHECK(!r.has_value());
    CHECK(err_contains(r, "Cgroups"));
    CHECK(err_contains(r, "openbsd"));
}

} // namespace

int main() {
    RUN_TEST(test_baseline_passes);
    RUN_TEST(test_unknown_sandbox_rejected);
    RUN_TEST(test_known_sandboxes_accepted);
    RUN_TEST(test_collide_without_threaded);
    RUN_TEST(test_procs_without_repeat);
    RUN_TEST(test_netreset_without_repeat);
    RUN_TEST(test_repeat_times_without_repeat);
    RUN_TEST(test_sandbox_empty_disables_features);
    RUN_TEST(test_namespace_requires_tmpdir);
    RUN_TEST(test_netreset_requires_non_setuid);
    RUN_TEST(test_cgroups_requires_tmpdir);
    RUN_TEST(test_linux_only_features_rejected_on_non_linux);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
