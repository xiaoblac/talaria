// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-6 — emit_prog_calls index-alignment invariant.
//
// For typed Prog with N calls, emit_prog_calls produces exactly N
// per-call C source strings (regardless of how many Copyin/Copyout
// instructions are interleaved in the WireProgram between them) and
// the i-th typed call's comment lands on the i-th emitted string.

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/emit_prog_calls.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <format>
#include <memory>
#include <string>
#include <string_view>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace em  = ::refuzz::crash::repro::csource::internal;
namespace syz = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

std::unique_ptr<syz::Call> default_call(const syz::Target& t,
                                        const std::string& name) {
    const auto* meta = t.find_syscall(name);
    if (meta == nullptr) {
        std::fprintf(stderr, "schema lacks %s\n", name.c_str());
        std::abort();
    }
    auto c = std::make_unique<syz::Call>();
    c->set_meta(meta);
    for (const auto& f : meta->args()) {
        if (f.type() == nullptr) continue;
        c->add_arg(f.type()->default_arg(f.dir(syz::Dir::kIn)));
    }
    return c;
}

} // namespace

int main() {
    const auto& t  = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    const auto& ann = cs::linux_amd64_annotator();
    cs::Options opts;
    opts.Sandbox = "none";

    // Build a 3-call prog: getpid, getuid, close.
    syz::Prog p;
    p.set_target(&t);
    p.add_call(default_call(t, "getpid"));
    p.add_call(default_call(t, "getuid"));
    p.add_call(default_call(t, "close"));

    // Lower to wire.
    auto bytes = syz::serialize_for_exec(p);
    CHECK(bytes.has_value());
    auto wp = syz::decode_exec_wire(*bytes);
    CHECK(wp.has_value());

    // Inject sentinel comments and assert each lands on the right call.
    std::vector<std::string> comments = {
        "// SENT_TYPED_CALL_0",
        "// SENT_TYPED_CALL_1",
        "// SENT_TYPED_CALL_2",
    };

    em::EmitCallCtx ctx{
        .target = &t, .target_info = &ti, .opts = &opts, .annotator = &ann,
    };
    auto out = em::emit_prog_calls(p, *wp, ctx, comments,
                                   /*trace=*/false, /*add_comments=*/true);
    CHECK(out.has_value());
    CHECK(out->calls.size() == 3);

    // Each emitted body must contain its sentinel comment and the
    // corresponding syscall name.
    CHECK(contains(out->calls[0], "SENT_TYPED_CALL_0"));
    CHECK(contains(out->calls[0], "syscall(__NR_getpid"));

    CHECK(contains(out->calls[1], "SENT_TYPED_CALL_1"));
    CHECK(contains(out->calls[1], "syscall(__NR_getuid"));

    CHECK(contains(out->calls[2], "SENT_TYPED_CALL_2"));
    CHECK(contains(out->calls[2], "syscall(__NR_close"));

    // Cross-check no leakage: comment 0 must NOT appear on call 1/2.
    CHECK(!contains(out->calls[1], "SENT_TYPED_CALL_0"));
    CHECK(!contains(out->calls[2], "SENT_TYPED_CALL_0"));

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
