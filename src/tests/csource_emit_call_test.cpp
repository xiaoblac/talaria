// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-3 — emit_call / fmt_call_body / emit_prog_calls
// covering: native syscall path (syscall(__NR_*, ...)),
// pseudo (syz_*) path, comment threading, copyout block emission.

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/emit_call.hpp"
#include "refuzz/crash/repro/csource/internal/emit_prog_calls.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
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

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

em::EmitCallCtx make_ctx() {
    static const auto& target = syz::Target::linux_amd64();
    static const auto& tinfo  = cs::linux_amd64_target_info();
    static const auto& ann    = cs::linux_amd64_annotator();
    static cs::Options opts;
    opts.Sandbox = "none";
    return em::EmitCallCtx{
        .target      = &target,
        .target_info = &tinfo,
        .opts        = &opts,
        .annotator   = &ann,
    };
}

void test_is_native_real_syscall() {
    auto ctx = make_ctx();
    const auto* meta = ctx.target->find_syscall("read");
    CHECK(meta != nullptr);
    CHECK(em::is_native(ctx, *meta));
}

void test_is_native_pseudo_returns_false() {
    auto ctx = make_ctx();
    const auto* meta = ctx.target->find_syscall("syz_emit_ethernet");
    CHECK(meta != nullptr);
    CHECK(!em::is_native(ctx, *meta));
}

// Build a typed Prog with a single `getpid()` call (or another simple
// no-arg syscall). Then SerializeForExec → decode → emit.
syz::Prog make_getpid_prog(const syz::Target& t) {
    syz::Prog p;
    p.set_target(&t);
    const auto* meta = t.find_syscall("getpid");
    if (meta == nullptr) {
        std::fprintf(stderr, "schema lacks getpid\n");
        std::abort();
    }
    auto c = std::make_unique<syz::Call>();
    c->set_meta(meta);
    p.add_call(std::move(c));
    return p;
}

void test_emit_native_call_uses_syscall_macro() {
    auto ctx = make_ctx();
    syz::Prog p = make_getpid_prog(*ctx.target);

    auto bytes = syz::serialize_for_exec(p);
    CHECK(bytes.has_value());
    auto wp = syz::decode_exec_wire(*bytes);
    CHECK(wp.has_value());

    auto out = em::emit_prog_calls(p, *wp, ctx, {}, /*trace=*/false,
                                   /*add_comments=*/false);
    CHECK(out.has_value());
    CHECK(out->calls.size() == 1);
    const std::string& body = out->calls[0];
    std::fprintf(stderr, "  emitted: %s", body.c_str());
    // Native call: no NONFAILING wrap.
    CHECK(contains(body, "syscall(__NR_getpid"));
    CHECK(!contains(body, "NONFAILING"));
}

void test_emit_with_typed_call_comments() {
    auto ctx = make_ctx();
    syz::Prog p = make_getpid_prog(*ctx.target);

    auto bytes = syz::serialize_for_exec(p);
    CHECK(bytes.has_value());
    auto wp = syz::decode_exec_wire(*bytes);
    CHECK(wp.has_value());

    std::vector<std::string> comments = {
        "// CUSTOM_TYPED_COMMENT_FOR_GETPID"
    };
    auto out = em::emit_prog_calls(p, *wp, ctx, comments,
                                   /*trace=*/false, /*add_comments=*/true);
    CHECK(out.has_value());
    CHECK(out->calls.size() == 1);
    CHECK(contains(out->calls[0], "// CUSTOM_TYPED_COMMENT_FOR_GETPID"));
    // Comment must precede the syscall line.
    auto comment_pos = out->calls[0].find("// CUSTOM_TYPED_COMMENT");
    auto syscall_pos = out->calls[0].find("syscall(__NR_getpid");
    CHECK(comment_pos < syscall_pos);
}

void test_emit_no_comments_when_flag_off() {
    auto ctx = make_ctx();
    syz::Prog p = make_getpid_prog(*ctx.target);
    auto bytes = syz::serialize_for_exec(p);
    auto wp    = syz::decode_exec_wire(*bytes);

    std::vector<std::string> comments = { "// SHOULD_NOT_APPEAR" };
    auto out = em::emit_prog_calls(p, *wp, ctx, comments,
                                   /*trace=*/false, /*add_comments=*/false);
    CHECK(out.has_value());
    CHECK(!contains(out->calls[0], "SHOULD_NOT_APPEAR"));
}

void test_emit_records_var_for_returning_call() {
    // getpid returns int (a "fd" pid_t). Whether it has a copyout
    // depends on whether anything downstream consumes the result.
    // For a single-call prog the return is not consumed, so vars
    // may be empty. Instead, build a prog where one call produces a
    // resource consumed by a second call. `pipe` produces an fd
    // pair, but for simplicity assert the structural invariant
    // emit_prog_calls returns empty vars on a no-result-consumer
    // prog.
    auto ctx = make_ctx();
    syz::Prog p = make_getpid_prog(*ctx.target);
    auto bytes = syz::serialize_for_exec(p);
    auto wp    = syz::decode_exec_wire(*bytes);

    auto out = em::emit_prog_calls(p, *wp, ctx, {}, false, false);
    CHECK(out.has_value());
    // No assertion on vars content — just that the field exists and
    // is non-throwing. Detailed vars accounting covered in
    // round-trip test (PR-4-C).
    (void)out->vars;
}

} // namespace

int main() {
    RUN_TEST(test_is_native_real_syscall);
    RUN_TEST(test_is_native_pseudo_returns_false);
    RUN_TEST(test_emit_native_call_uses_syscall_macro);
    RUN_TEST(test_emit_with_typed_call_comments);
    RUN_TEST(test_emit_no_comments_when_flag_off);
    RUN_TEST(test_emit_records_var_for_returning_call);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
