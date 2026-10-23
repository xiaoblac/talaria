// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-1 — baseline gate per Epic 4 plan §3 binding
// "Options scope". For every UNSUPPORTED-bucket field, asserts the
// gate returns kUnsupportedByEpic4 with a message naming the
// offending option/field/call.

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/baseline_gate.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace gt  = ::refuzz::crash::repro::csource::internal;
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

cs::Options baseline_opts() {
    cs::Options o;
    o.Sandbox = "none";
    return o;
}

std::unique_ptr<syz::Prog> empty_prog(const syz::Target& t) {
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&t);
    return p;
}

bool failed_with(const std::expected<void, cs::CSourceFailure>& r,
                 std::string_view needle) {
    if (r.has_value()) return false;
    if (r.error().code != cs::CSourceError::kUnsupportedByEpic4) return false;
    return r.error().message.find(needle) != std::string::npos;
}

void test_baseline_passes() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = empty_prog(t);
    auto opts = baseline_opts();
    auto r = gt::baseline_gate_options_and_calls(*prog, opts);
    CHECK(r.has_value());
}

void test_unsupported_options_each_named() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = empty_prog(t);

    struct Case { std::string_view label; void (*set)(cs::Options&); };
    const Case cases[] = {
        {"Sandbox=\"setuid\"",  [](cs::Options& o){ o.Sandbox = "setuid"; }},
        {"Sandbox=\"namespace\"",[](cs::Options& o){ o.Sandbox = "namespace"; o.UseTmpDir = true; }},
        {"Sandbox=\"android\"", [](cs::Options& o){ o.Sandbox = "android"; }},
        {"Cgroups",             [](cs::Options& o){ o.Cgroups = true; o.UseTmpDir = true; }},
        {"BinfmtMisc",          [](cs::Options& o){ o.BinfmtMisc = true; }},
        {"Leak",                [](cs::Options& o){ o.Leak = true; }},
        {"NetInjection",        [](cs::Options& o){ o.NetInjection = true; }},
        {"NetDevices",          [](cs::Options& o){ o.NetDevices = true; }},
        {"NetReset",            [](cs::Options& o){ o.NetReset = true; o.Repeat = true; }},
        {"VhciInjection",       [](cs::Options& o){ o.VhciInjection = true; }},
        {"Wifi",                [](cs::Options& o){ o.Wifi = true; }},
        {"IEEE802154",          [](cs::Options& o){ o.IEEE802154 = true; }},
        {"USB",                 [](cs::Options& o){ o.USB = true; }},
        {"Sysctl",              [](cs::Options& o){ o.Sysctl = true; }},
        {"Swap",                [](cs::Options& o){ o.Swap = true; }},
        {"KCSAN",               [](cs::Options& o){ o.KCSAN = true; }},
        {"DevlinkPCI",          [](cs::Options& o){ o.DevlinkPCI = true; }},
        {"NicVF",               [](cs::Options& o){ o.NicVF = true; }},
        {"Collide",             [](cs::Options& o){ o.Legacy.Collide = true; o.Threaded = true; }},
        {"Fault",               [](cs::Options& o){ o.Legacy.Fault = true; }},
    };
    for (const auto& c : cases) {
        auto opts = baseline_opts();
        c.set(opts);
        auto r = gt::baseline_gate_options_and_calls(*prog, opts);
        if (!failed_with(r, c.label)) {
            std::fprintf(stderr, "  case %.*s: ",
                         int(c.label.size()), c.label.data());
            if (r.has_value()) {
                std::fprintf(stderr, "unexpectedly passed\n");
            } else {
                std::fprintf(stderr, "wrong message: %s\n",
                             r.error().message.c_str());
            }
        }
        CHECK(failed_with(r, c.label));
    }
}

void test_call_props_failnth_rejected() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&t);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall("read"));
    syz::CallProps props;
    props.fail_nth = 5;
    c->set_props(props);
    prog->add_call(std::move(c));

    auto r = gt::baseline_gate_options_and_calls(*prog, baseline_opts());
    CHECK(failed_with(r, "FailNth"));
    CHECK(failed_with(r, "Call[0]"));
}

void test_call_props_async_rejected() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&t);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall("read"));
    syz::CallProps props;
    props.async = true;
    c->set_props(props);
    prog->add_call(std::move(c));

    auto r = gt::baseline_gate_options_and_calls(*prog, baseline_opts());
    CHECK(failed_with(r, "Async"));
}

void test_call_props_rerun_rejected() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&t);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall("read"));
    syz::CallProps props;
    props.rerun = 3;
    c->set_props(props);
    prog->add_call(std::move(c));

    auto r = gt::baseline_gate_options_and_calls(*prog, baseline_opts());
    CHECK(failed_with(r, "Rerun"));
}

void test_wire_arg_strdec_rejected() {
    syz::WireProgram wp;
    wp.num_calls = 1;
    syz::WireCall wc;
    wc.call_id = 0;
    syz::WireConst wc_arg;
    wc_arg.size = 8;
    wc_arg.val  = 42;
    wc_arg.fmt  = syz::BinaryFormat::kStrDec;
    wc.args.push_back(wc_arg);
    wp.instrs.push_back(std::move(wc));

    auto r = gt::baseline_gate_wire_args(wp);
    CHECK(failed_with(r, "Str"));
}

void test_wire_arg_native_passes() {
    syz::WireProgram wp;
    wp.num_calls = 1;
    syz::WireCall wc;
    wc.call_id = 0;
    syz::WireConst wc_arg;
    wc_arg.size = 8;
    wc_arg.val  = 42;
    wc_arg.fmt  = syz::BinaryFormat::kNative;
    wc.args.push_back(wc_arg);
    wp.instrs.push_back(std::move(wc));

    auto r = gt::baseline_gate_wire_args(wp);
    CHECK(r.has_value());
}

} // namespace

int main() {
    RUN_TEST(test_baseline_passes);
    RUN_TEST(test_unsupported_options_each_named);
    RUN_TEST(test_call_props_failnth_rejected);
    RUN_TEST(test_call_props_async_rejected);
    RUN_TEST(test_call_props_rerun_rejected);
    RUN_TEST(test_wire_arg_strdec_rejected);
    RUN_TEST(test_wire_arg_native_passes);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
