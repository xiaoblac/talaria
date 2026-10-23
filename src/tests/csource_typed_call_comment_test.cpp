// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-4 — make_typed_call_comment / format_arg structural
// invariants. The block must (a) start with `<syscall> arguments: [`,
// (b) include each typed arg's name + value summary, (c) close with
// `]`, (d) optionally include `returns <ret-type>`. Detailed
// byte-equal pinning lands in PR-4-D golden samples.

#include "refuzz/crash/repro/csource/internal/format_arg.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

namespace {

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

// Build a syz::Call with default-initialized args via Type::default_arg.
std::unique_ptr<syz::Call> default_call(const syz::Target& t,
                                        const std::string& name) {
    const auto* meta = t.find_syscall(name);
    if (meta == nullptr) {
        std::fprintf(stderr, "schema lacks %s\n", name.c_str());
        std::abort();
    }
    auto call = std::make_unique<syz::Call>();
    call->set_meta(meta);
    for (const auto& field : meta->args()) {
        if (field.type() == nullptr) continue;
        call->add_arg(field.type()->default_arg(field.dir(syz::Dir::kIn)));
    }
    return call;
}

void test_getpid_no_args_no_ret() {
    const auto& t = syz::Target::linux_amd64();
    auto c = default_call(t, "getpid");
    auto comment = em::make_typed_call_comment(*c);
    std::fprintf(stderr, "  getpid:\n%s\n", comment.c_str());

    CHECK(contains(comment, "getpid arguments: ["));
    CHECK(contains(comment, "]"));
    if (c->meta()->ret() != nullptr) {
        CHECK(contains(comment, "returns "));
    }
}

void test_close_one_arg_resource() {
    const auto& t = syz::Target::linux_amd64();
    auto c = default_call(t, "close");
    auto comment = em::make_typed_call_comment(*c);
    std::fprintf(stderr, "  close:\n%s\n", comment.c_str());

    CHECK(contains(comment, "close arguments: ["));
    // close takes an fd resource as its single arg.
    CHECK(contains(comment, "fd"));
}

void test_make_typed_call_comments_per_call() {
    const auto& t = syz::Target::linux_amd64();
    syz::Prog p;
    p.set_target(&t);
    p.add_call(default_call(t, "getpid"));
    p.add_call(default_call(t, "close"));

    auto v = em::make_typed_call_comments(p);
    CHECK(v.size() == 2);
    CHECK(contains(v[0], "getpid arguments"));
    CHECK(contains(v[1], "close arguments"));
}

void test_format_arg_const_inline() {
    const auto& t = syz::Target::linux_amd64();
    // Use any IntType from any syscall arg.
    const syz::IntType* int_t = nullptr;
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        for (const auto& f : sc->args()) {
            if (f.type() != nullptr && f.type()->kind() == syz::TypeKind::kInt) {
                int_t = static_cast<const syz::IntType*>(f.type());
                break;
            }
        }
        if (int_t) break;
    }
    CHECK(int_t != nullptr);
    auto carg = std::make_unique<syz::ConstArg>();
    carg->set_type(int_t);
    carg->set_dir(syz::Dir::kIn);
    carg->set_val(0xdeadbeef);

    auto lines = em::format_arg(*carg, "field_name");
    CHECK(lines.size() == 1);
    std::fprintf(stderr, "  const line: %s\n", lines[0].c_str());
    // Format: "<typeName> = 0x<hex> (<size> bytes)"
    CHECK(contains(lines[0], "field_name:"));
    CHECK(contains(lines[0], "0xdeadbeef"));
    CHECK(contains(lines[0], "bytes)"));
}

void test_type_string_int_returns_name() {
    const auto& t = syz::Target::linux_amd64();
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        for (const auto& f : sc->args()) {
            if (f.type() != nullptr && f.type()->kind() == syz::TypeKind::kInt) {
                CHECK(em::type_string(*f.type()) == f.type()->name());
                return;
            }
        }
    }
    std::fprintf(stderr, "  schema has no IntType\n");
    std::abort();
}

void test_type_string_ptr_brackets() {
    const auto& t = syz::Target::linux_amd64();
    // Find any PtrType
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        for (const auto& f : sc->args()) {
            if (f.type() != nullptr && f.type()->kind() == syz::TypeKind::kPtr) {
                auto s = em::type_string(*f.type());
                std::fprintf(stderr, "  ptr type_string: %s\n", s.c_str());
                CHECK(s.starts_with("ptr["));
                CHECK(s.find(", ") != std::string::npos);
                CHECK(s.ends_with("]"));
                return;
            }
        }
    }
}

} // namespace

int main() {
    RUN_TEST(test_getpid_no_args_no_ret);
    RUN_TEST(test_close_one_arg_resource);
    RUN_TEST(test_make_typed_call_comments_per_call);
    RUN_TEST(test_format_arg_const_inline);
    RUN_TEST(test_type_string_int_returns_name);
    RUN_TEST(test_type_string_ptr_brackets);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
