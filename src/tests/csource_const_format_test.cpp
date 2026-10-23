// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-2 — const_arg_to_str / result_arg_to_str /
// handle_big_endian parity vs upstream pkg/csource/csource.go::
// constArgToStr (601-624), resultArgToStr (659-671),
// handleBigEndian (652-657), literalSuffix (626-650).

#include "refuzz/crash/repro/csource/internal/emit_args.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

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

#define CHECK_EQ(actual, expected)                                        \
    do {                                                                  \
        const auto a__ = (actual);                                        \
        const auto e__ = std::string(expected);                           \
        if (a__ != e__) {                                                 \
            std::fprintf(stderr,                                          \
                "FAIL %s:%d: got %s, want %s\n",                          \
                __FILE__, __LINE__, a__.c_str(), e__.c_str());            \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

em::EmitArgsCtx ctx_default() {
    static const auto& target = syz::Target::linux_amd64();
    static cs::Options opts;
    return em::EmitArgsCtx{ .target = &target, .opts = &opts };
}

void test_const_small_decimal() {
    auto ctx = ctx_default();
    syz::WireConst c;
    c.size = 4;
    c.val  = 5;
    CHECK_EQ(em::const_arg_to_str(ctx, c, /*enforce_bit_size=*/false), "5");
}

void test_const_large_hex() {
    auto ctx = ctx_default();
    syz::WireConst c;
    c.size = 4;
    c.val  = 0xdeadbeef;
    CHECK_EQ(em::const_arg_to_str(ctx, c, false), "0xdeadbeef");
}

void test_const_minus_one_no_enforce() {
    auto ctx = ctx_default();
    syz::WireConst c;
    c.size = 4;
    c.val  = 0xffffffffULL;       // -1 within size=4 mask
    CHECK_EQ(em::const_arg_to_str(ctx, c, false), "-1");
}

void test_const_minus_one_with_enforce() {
    auto ctx = ctx_default();
    syz::WireConst c;
    c.size = 8;
    c.val  = ~uint64_t{0};
    CHECK_EQ(em::const_arg_to_str(ctx, c, true), "(intptr_t)-1");
}

void test_const_8byte_enforce_suffix_ul() {
    auto ctx = ctx_default();         // linux/amd64 ptr_size=8 → "ul"
    syz::WireConst c;
    c.size = 8;
    c.val  = 0x100;
    CHECK_EQ(em::const_arg_to_str(ctx, c, true), "0x100ul");
}

void test_const_pid_stride_appends_procid() {
    static const auto& target = syz::Target::linux_amd64();
    cs::Options opts;
    opts.Procs = 4;
    em::EmitArgsCtx ctx{ .target = &target, .opts = &opts };

    syz::WireConst c;
    c.size       = 4;
    c.val        = 0x1000;
    c.pid_stride = 0x100;
    CHECK_EQ(em::const_arg_to_str(ctx, c, false), "0x1000 + procid*256");
}

void test_const_pid_stride_ignored_when_procs_le_1() {
    auto ctx = ctx_default();
    syz::WireConst c;
    c.size       = 4;
    c.val        = 0x1000;
    c.pid_stride = 0x100;
    CHECK_EQ(em::const_arg_to_str(ctx, c, false), "0x1000");
}

void test_handle_big_endian_wraps() {
    syz::WireConst c;
    c.size = 4;
    c.fmt  = syz::BinaryFormat::kBigEndian;
    CHECK_EQ(em::handle_big_endian(c, "0x1234"), "htobe32(0x1234)");
}

void test_handle_big_endian_native_passthrough() {
    syz::WireConst c;
    c.size = 4;
    c.fmt  = syz::BinaryFormat::kNative;
    CHECK_EQ(em::handle_big_endian(c, "0x1234"), "0x1234");
}

void test_result_arg_basic() {
    auto ctx = ctx_default();
    syz::WireResult r;
    r.size = 4;
    r.idx  = 7;
    CHECK_EQ(em::result_arg_to_str(ctx, r), "r[7]");
}

void test_result_arg_div_then_add() {
    auto ctx = ctx_default();
    syz::WireResult r;
    r.size   = 4;
    r.idx    = 2;
    r.op_div = 1000;
    r.op_add = 50;
    CHECK_EQ(em::result_arg_to_str(ctx, r), "r[2]/1000+50");
}

void test_result_arg_big_endian_wraps() {
    auto ctx = ctx_default();
    syz::WireResult r;
    r.size = 4;
    r.idx  = 0;
    r.fmt  = syz::BinaryFormat::kBigEndian;
    CHECK_EQ(em::result_arg_to_str(ctx, r), "htobe32(r[0])");
}

} // namespace

int main() {
    RUN_TEST(test_const_small_decimal);
    RUN_TEST(test_const_large_hex);
    RUN_TEST(test_const_minus_one_no_enforce);
    RUN_TEST(test_const_minus_one_with_enforce);
    RUN_TEST(test_const_8byte_enforce_suffix_ul);
    RUN_TEST(test_const_pid_stride_appends_procid);
    RUN_TEST(test_const_pid_stride_ignored_when_procs_le_1);
    RUN_TEST(test_handle_big_endian_wraps);
    RUN_TEST(test_handle_big_endian_native_passthrough);
    RUN_TEST(test_result_arg_basic);
    RUN_TEST(test_result_arg_div_then_add);
    RUN_TEST(test_result_arg_big_endian_wraps);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
