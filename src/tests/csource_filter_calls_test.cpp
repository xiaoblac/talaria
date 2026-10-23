// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-1 — filter_calls parity vs upstream
// pkg/csource/csource.go::filterCalls (lines 165-186).
//
// Constructs minimal typed Progs holding syz_emit_ethernet /
// syz_emit_vhci / syz_extract_tcp_res calls and asserts the lazy
// clone happens only when at least one removal is needed.

#include "refuzz/crash/repro/csource/internal/filter.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace fi  = ::refuzz::crash::repro::csource::internal;
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

// Build a Prog whose calls have only their meta set — args are
// irrelevant for filterCalls (which only looks at meta.call_name).
std::unique_ptr<syz::Prog> make_prog_with(const syz::Target& t,
                                          const std::vector<std::string>& names) {
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&t);
    for (const auto& n : names) {
        const auto* meta = t.find_syscall(n);
        if (meta == nullptr) {
            std::fprintf(stderr, "schema lacks %s\n", n.c_str());
            std::abort();
        }
        auto c = std::make_unique<syz::Call>();
        c->set_meta(meta);
        p->add_call(std::move(c));
    }
    return p;
}

void test_no_removal_returns_borrowed() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = make_prog_with(t, {"read", "write", "close"});

    cs::Options opts;
    opts.NetInjection = false;
    opts.VhciInjection = false;
    auto fp = fi::filter_calls(*prog, opts);

    // No syz_emit_* in input → no clone, borrowed pointer points at input.
    CHECK(fp.borrowed == prog.get());
    CHECK(fp.owned == nullptr);
    CHECK(prog->calls().size() == 3);  // input untouched
}

void test_drops_emit_ethernet_when_disabled() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = make_prog_with(t, {"read", "syz_emit_ethernet", "close"});

    cs::Options opts;
    opts.NetInjection = false;
    auto fp = fi::filter_calls(*prog, opts);

    CHECK(fp.borrowed == nullptr);
    CHECK(fp.owned != nullptr);
    CHECK(fp.owned->calls().size() == 2);
    CHECK(fp.owned->calls()[0]->meta()->call_name() == "read");
    CHECK(fp.owned->calls()[1]->meta()->call_name() == "close");
    // Input prog must NOT be mutated (lazy clone preserves input).
    CHECK(prog->calls().size() == 3);
}

void test_keeps_emit_ethernet_when_enabled() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = make_prog_with(t, {"read", "syz_emit_ethernet", "close"});

    cs::Options opts;
    opts.NetInjection = true;
    auto fp = fi::filter_calls(*prog, opts);

    CHECK(fp.borrowed == prog.get());
    CHECK(fp.owned == nullptr);
}

void test_drops_emit_vhci_when_disabled() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = make_prog_with(t, {"syz_emit_vhci", "read"});

    cs::Options opts;
    opts.VhciInjection = false;
    auto fp = fi::filter_calls(*prog, opts);

    CHECK(fp.owned != nullptr);
    CHECK(fp.owned->calls().size() == 1);
    CHECK(fp.owned->calls()[0]->meta()->call_name() == "read");
}

void test_drops_both_when_both_disabled() {
    const auto& t = syz::Target::linux_amd64();
    auto prog = make_prog_with(t, {
        "read", "syz_emit_ethernet", "write", "syz_emit_vhci", "close",
    });

    cs::Options opts;
    opts.NetInjection = false;
    opts.VhciInjection = false;
    auto fp = fi::filter_calls(*prog, opts);

    CHECK(fp.owned != nullptr);
    CHECK(fp.owned->calls().size() == 3);
    CHECK(fp.owned->calls()[0]->meta()->call_name() == "read");
    CHECK(fp.owned->calls()[1]->meta()->call_name() == "write");
    CHECK(fp.owned->calls()[2]->meta()->call_name() == "close");
}

} // namespace

int main() {
    RUN_TEST(test_no_removal_returns_borrowed);
    RUN_TEST(test_drops_emit_ethernet_when_disabled);
    RUN_TEST(test_keeps_emit_ethernet_when_enabled);
    RUN_TEST(test_drops_emit_vhci_when_disabled);
    RUN_TEST(test_drops_both_when_both_disabled);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
