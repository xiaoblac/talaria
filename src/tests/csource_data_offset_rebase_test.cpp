// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-rev2 BLOCKER fixes — verifies:
//   * copyin / copyout / WireAddr top-level addresses are rebased
//     by Target::data_offset() at emit time (mirror of upstream
//     DeserializeExec which adds DataOffset at decode time);
//   * vars[] uses WireResult.default_val (or 0 for copyout slots),
//     not result indices.
//
// Linux/amd64 sets data_offset = 0x200000000000, so any wire address
// emitted by csource on Linux/amd64 must include that base.

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/emit_call.hpp"
#include "refuzz/crash/repro/csource/internal/emit_csum.hpp"
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
#include <variant>

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

void test_copyin_copyout_addresses_rebased() {
    // emit_copyin / emit_copyout take data_offset directly. Pass a
    // distinctive value and assert the literal in the C source uses
    // raw_addr + data_offset.
    constexpr uint64_t kDataOff = 0x111100000000ULL;
    constexpr uint64_t kRawAddr = 0xabcd;

    syz::WireCopyin ci;
    ci.addr = kRawAddr;
    syz::WireConst c;
    c.size = 4;
    c.val  = 0x42;
    ci.arg = c;

    static const auto& target = syz::Target::linux_amd64();
    static cs::Options opts;
    em::EmitArgsCtx args_ctx{ .target = &target, .opts = &opts };

    std::string out;
    int csum_seq = 0;
    em::emit_copyin(out, args_ctx, ci, &csum_seq, kDataOff);
    std::fprintf(stderr, "  copyin: %s", out.c_str());
    const std::string expected_addr =
        std::format("0x{:x}", kRawAddr + kDataOff);
    CHECK(contains(out, expected_addr));
    CHECK(!contains(out, std::format("0x{:x}", kRawAddr) + ")"));

    // copyout
    syz::WireCopyout co;
    co.idx  = 5;
    co.addr = 0x9000;
    co.size = 8;
    std::string out2;
    em::EmitCallCtx ctx{ .target = &target, .target_info = nullptr,
                          .opts = &opts, .annotator = nullptr };
    em::emit_copyout(out2, ctx, *target.find_syscall("getpid"),
                     /*result_index=*/0, /*res_copyout=*/false,
                     std::span<const syz::WireCopyout>(&co, 1),
                     kDataOff);
    std::fprintf(stderr, "  copyout: %s", out2.c_str());
    CHECK(contains(out2, std::format("0x{:x}", co.addr + kDataOff)));
}

void test_csum_argdata_rebased_const_not() {
    constexpr uint64_t kDataOff = 0x222200000000ULL;

    syz::WireCsum csum;
    csum.csum_kind = 0;
    csum.size      = 2;
    syz::WireCsumChunk arg_chunk;
    arg_chunk.kind          = syz::WireCsumChunkKind::kArgData;
    arg_chunk.addr_or_value = 0x40000000;
    arg_chunk.size          = 8;
    csum.chunks.push_back(arg_chunk);
    syz::WireCsumChunk const_chunk;
    const_chunk.kind          = syz::WireCsumChunkKind::kConst;
    const_chunk.addr_or_value = 0x12345678;
    const_chunk.size          = 4;
    csum.chunks.push_back(const_chunk);

    auto src = em::generate_csum_inet(/*addr=*/0x50000000, csum,
                                      /*csum_seq=*/3, kDataOff);
    std::fprintf(stderr, "  csum: %s", src.c_str());
    // ArgData chunk addr → must include data_offset.
    CHECK(contains(src, std::format("0x{:x}", arg_chunk.addr_or_value + kDataOff)));
    // Const chunk value → must NOT have data_offset added.
    CHECK(contains(src, "0x12345678"));
    CHECK(!contains(src, std::format("0x{:x}",
                                     const_chunk.addr_or_value + kDataOff)));
}

void test_wire_addr_top_level_emitted_as_absolute() {
    // Construct a 1-call prog that has a vma_pointer arg (mmap is the
    // simplest example). When serialized, mmap's addr arg becomes a
    // WireAddr whose `addr` is the raw wire offset; csource must emit
    // it as raw_addr + data_offset.
    const auto& t = syz::Target::linux_amd64();
    syz::Prog p;
    p.set_target(&t);
    const auto* meta = t.find_syscall("mmap");
    CHECK(meta != nullptr);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(meta);
    for (const auto& f : meta->args()) {
        if (f.type() == nullptr) continue;
        c->add_arg(f.type()->default_arg(f.dir(syz::Dir::kIn)));
    }
    p.add_call(std::move(c));

    cs::Options opts;
    opts.Sandbox = "none";
    auto r = cs::Write(p, opts, cs::linux_amd64_annotator(),
                       cs::linux_amd64_target_info());
    if (!r.has_value()) {
        std::fprintf(stderr, "Write failed: code=%d msg=%s\n",
                     int(r.error().code), r.error().message.c_str());
    }
    CHECK(r.has_value());
    std::fprintf(stderr, "  src size = %zu\n", r->size());
    // Linux/amd64 data_offset = 0x200000000000. Any vma_pointer arg
    // must include that base. The default mmap addr is 0 → emitted
    // as the data_offset literal itself, OR a special pointer (NULL).
    // Either way the raw "0x0ul" without data_offset would be the
    // bug. Assert the literal data_offset value appears in the
    // emitted source.
    const std::string base_lit = "0x200000000000";
    CHECK(contains(*r, base_lit));
}

void test_copyin_wire_addr_emits_pointer_value() {
    // serialize_for_exec emits execArgAddr32/64 inside a copyin
    // whenever a struct/union leaf is a pointer (msghdr.msg_iov,
    // iovec.iov_base, etc.). DeserializeExec rebases to ExecArgConst
    // with size = ptr_size and value = wire_addr + DataOffset. csource
    // must emit `*(uintNN*)<copyin_addr> = <wire_addr+DataOffset>`.
    constexpr uint64_t kDataOff = 0x333300000000ULL;
    constexpr uint64_t kCopyinAddr = 0x1000;
    constexpr uint64_t kWireAddr   = 0x4000;

    syz::WireCopyin ci;
    ci.addr = kCopyinAddr;
    syz::WireAddr a;
    a.ptr_size = 8;
    a.addr     = kWireAddr;
    ci.arg = a;

    static const auto& target = syz::Target::linux_amd64();
    static cs::Options opts;
    em::EmitArgsCtx args_ctx{ .target = &target, .opts = &opts };

    std::string out;
    int csum_seq = 0;
    em::emit_copyin(out, args_ctx, ci, &csum_seq, kDataOff);
    std::fprintf(stderr, "  copyin-WireAddr: %s", out.c_str());

    // Target slot address: copyin.addr + data_offset.
    const std::string slot_addr = std::format("0x{:x}", kCopyinAddr + kDataOff);
    // Stored value: wire_addr + data_offset.
    const std::string value_addr = std::format("0x{:x}", kWireAddr + kDataOff);

    // Expect a NONFAILING(*(uint64*)<slot> = <value>) form (size=8 → uint64).
    CHECK(contains(out, "NONFAILING"));
    CHECK(contains(out, "*(uint64*)" + slot_addr));
    CHECK(contains(out, value_addr));
    // Must NOT degrade into a comment.
    CHECK(!contains(out, "INTERNAL: WireAddr"));
}

void test_vars_carry_default_values_not_indices() {
    // Build a synthetic WireProgram with a single WireCall referencing
    // a WireResult whose default_val is 0xffffffffffffffff (-1 fd).
    // Without the BLOCKER fix, vars would be `[idx]` = `[0]`.
    syz::WireProgram wp;
    wp.num_calls = 1;
    syz::WireCall wc;
    // Pick a real syscall id so emit_prog_calls' meta lookup
    // succeeds; close(fd) takes a single resource arg → matches.
    const auto& t = syz::Target::linux_amd64();
    const auto* meta = t.find_syscall("close");
    CHECK(meta != nullptr);
    wc.call_id = meta->id();
    wc.copyout_idx = em::kExecNoCopyout;
    syz::WireResult ra;
    ra.size        = 4;
    ra.idx         = 7;
    ra.default_val = 0xffffffffffffffffULL;
    wc.args.push_back(ra);
    wp.instrs.push_back(std::move(wc));

    cs::Options opts;
    opts.Sandbox = "none";
    em::EmitCallCtx ctx{
        .target      = &t,
        .target_info = &cs::linux_amd64_target_info(),
        .opts        = &opts,
        .annotator   = &cs::linux_amd64_annotator(),
    };

    syz::Prog dummy;
    dummy.set_target(&t);
    auto out = em::emit_prog_calls(dummy, wp, ctx, {},
                                   /*trace=*/false, /*add_comments=*/false);
    CHECK(out.has_value());
    std::fprintf(stderr, "  vars.size=%zu\n", out->vars.size());
    // vars must be sized to idx+1 = 8, and vars[7] = default_val.
    CHECK(out->vars.size() == 8);
    CHECK(out->vars[7] == 0xffffffffffffffffULL);
    // Other slots default to 0 (mirror upstream Vars[i] grown with 0).
    for (std::size_t i = 0; i < 7; ++i) {
        CHECK(out->vars[i] == 0);
    }
}

} // namespace

int main() {
    RUN_TEST(test_copyin_copyout_addresses_rebased);
    RUN_TEST(test_csum_argdata_rebased_const_not);
    RUN_TEST(test_wire_addr_top_level_emitted_as_absolute);
    RUN_TEST(test_copyin_wire_addr_emits_pointer_value);
    RUN_TEST(test_vars_carry_default_values_not_indices);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
