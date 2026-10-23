// Copyright 2026 reFuzz project author -------youngkk.
//
// Decode-parity gate for the streaming wire decoder (S2).
//
// The exec-path refactor replaces "materialize a whole WireProgram, then walk
// it" with a WireStreamReader that pulls one instruction at a time straight
// from the wire buffer. The refactor's sole hard invariant is that it changes
// *when* decoding happens, never *what* is decoded: the downstream
// apply_copyin / apply_copyout / resolve_call_arg / csum / coverage helpers are
// untouched. Therefore, if a WireStreamReader walk yields exactly the same
// instruction sequence and fields as decode_exec_wire over identical bytes,
// full behavioral parity follows by construction — the helpers get identical
// inputs either way.
//
// This test asserts that equivalence, field-by-field (including data-blob bytes
// and csum chunks), over a corpus that exercises every arg kind, every
// instruction opcode, and their interleavings. It is a pure decoder comparison
// — no driver, no scratch — so a reader bug surfaces here in isolation.

#include "refuzz/program/syz/exec_wire_decode.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace {

namespace syz = ::refuzz::program::syz;

int g_failures = 0;

#define CHECK(expr)                                                          \
    do {                                                                     \
        if (!(expr)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #expr);                                             \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

// ---- Field-level arg equality (span-aware for WireData) -------------------

bool ArgsEqual(const syz::WireArg& a, const syz::WireArg& b) {
    if (a.index() != b.index()) return false;
    if (auto* x = std::get_if<syz::WireConst>(&a)) {
        auto* y = std::get_if<syz::WireConst>(&b);
        return x->size == y->size && x->val == y->val && x->fmt == y->fmt &&
               x->bf_off == y->bf_off && x->bf_len == y->bf_len &&
               x->pid_stride == y->pid_stride;
    }
    if (auto* x = std::get_if<syz::WireAddr>(&a)) {
        auto* y = std::get_if<syz::WireAddr>(&b);
        return x->ptr_size == y->ptr_size && x->addr == y->addr;
    }
    if (auto* x = std::get_if<syz::WireResult>(&a)) {
        auto* y = std::get_if<syz::WireResult>(&b);
        return x->size == y->size && x->fmt == y->fmt && x->idx == y->idx &&
               x->op_div == y->op_div && x->op_add == y->op_add &&
               x->default_val == y->default_val;
    }
    if (auto* x = std::get_if<syz::WireData>(&a)) {
        auto* y = std::get_if<syz::WireData>(&b);
        if (x->readable != y->readable) return false;
        if (x->data.size() != y->data.size()) return false;
        for (std::size_t i = 0; i < x->data.size(); ++i) {
            if (x->data[i] != y->data[i]) return false;
        }
        return true;
    }
    if (auto* x = std::get_if<syz::WireCsum>(&a)) {
        auto* y = std::get_if<syz::WireCsum>(&b);
        if (x->csum_kind != y->csum_kind || x->size != y->size) return false;
        if (x->chunks.size() != y->chunks.size()) return false;
        for (std::size_t i = 0; i < x->chunks.size(); ++i) {
            if (x->chunks[i].kind != y->chunks[i].kind ||
                x->chunks[i].addr_or_value != y->chunks[i].addr_or_value ||
                x->chunks[i].size != y->chunks[i].size) {
                return false;
            }
        }
        return true;
    }
    return false;
}

// ---- The core parity assertion --------------------------------------------
//
// Decode `bytes` with the reference materializing decoder and, in lockstep,
// with the streaming reader; assert they agree on num_calls, on every
// instruction (opcode + fields), on every call's args (pulled via NextArg),
// and on the terminal EOF.
void AssertParity(const std::string& name, std::span<const uint8_t> bytes) {
    auto wp_or = syz::decode_exec_wire(bytes);
    if (!wp_or) {
        std::fprintf(stderr,
                     "FAIL [%s]: reference decode_exec_wire failed: %s @%zu\n",
                     name.c_str(), wp_or.error().message.c_str(),
                     wp_or.error().offset);
        ++g_failures;
        return;
    }
    const syz::WireProgram& wp = *wp_or;

    syz::WireStreamReader reader(bytes);
    uint64_t num_calls = 0;
    if (!reader.ReadNumCalls(&num_calls)) {
        std::fprintf(stderr, "FAIL [%s]: stream ReadNumCalls failed: %s @%zu\n",
                     name.c_str(), reader.error().message.c_str(),
                     reader.error().offset);
        ++g_failures;
        return;
    }
    if (num_calls != wp.num_calls) {
        std::fprintf(stderr, "FAIL [%s]: num_calls %llu != %llu\n", name.c_str(),
                     static_cast<unsigned long long>(num_calls),
                     static_cast<unsigned long long>(wp.num_calls));
        ++g_failures;
        return;
    }

    for (std::size_t idx = 0; idx < wp.instrs.size(); ++idx) {
        const syz::WireInstr& want = wp.instrs[idx];
        syz::WireInstrView got;
        const auto st = reader.Next(&got);
        if (st != syz::WireStreamReader::Status::kInstr) {
            std::fprintf(stderr,
                         "FAIL [%s]: stream ended early at instr %zu (status %d)"
                         " err=%s\n",
                         name.c_str(), idx, static_cast<int>(st),
                         reader.error().message.c_str());
            ++g_failures;
            return;
        }

        if (auto* w = std::get_if<syz::WireCopyin>(&want)) {
            auto* g = std::get_if<syz::WireCopyin>(&got);
            if (g == nullptr) {
                std::fprintf(stderr, "FAIL [%s] instr %zu: expected copyin\n",
                             name.c_str(), idx);
                ++g_failures;
                return;
            }
            CHECK(g->addr == w->addr);
            CHECK(ArgsEqual(g->arg, w->arg));
        } else if (auto* w = std::get_if<syz::WireCopyout>(&want)) {
            auto* g = std::get_if<syz::WireCopyout>(&got);
            if (g == nullptr) {
                std::fprintf(stderr, "FAIL [%s] instr %zu: expected copyout\n",
                             name.c_str(), idx);
                ++g_failures;
                return;
            }
            CHECK(g->idx == w->idx);
            CHECK(g->addr == w->addr);
            CHECK(g->size == w->size);
        } else if (auto* w = std::get_if<syz::WireSetProps>(&want)) {
            auto* g = std::get_if<syz::WireSetProps>(&got);
            if (g == nullptr) {
                std::fprintf(stderr, "FAIL [%s] instr %zu: expected setprops\n",
                             name.c_str(), idx);
                ++g_failures;
                return;
            }
            CHECK(g->fail_nth == w->fail_nth);
            CHECK(g->async == w->async);
            CHECK(g->rerun == w->rerun);
        } else if (auto* w = std::get_if<syz::WireCall>(&want)) {
            auto* g = std::get_if<syz::WireCallHeader>(&got);
            if (g == nullptr) {
                std::fprintf(stderr, "FAIL [%s] instr %zu: expected call\n",
                             name.c_str(), idx);
                ++g_failures;
                return;
            }
            CHECK(g->call_id == w->call_id);
            CHECK(g->copyout_idx == w->copyout_idx);
            CHECK(g->num_args == w->args.size());
            // Pull each arg inline, exactly as the driver will.
            for (std::size_t ai = 0; ai < w->args.size(); ++ai) {
                syz::WireArg got_arg;
                if (!reader.NextArg(&got_arg)) {
                    std::fprintf(stderr,
                                 "FAIL [%s] instr %zu arg %zu: NextArg failed: "
                                 "%s\n",
                                 name.c_str(), idx, ai,
                                 reader.error().message.c_str());
                    ++g_failures;
                    return;
                }
                CHECK(ArgsEqual(got_arg, w->args[ai]));
            }
        } else {
            std::fprintf(stderr, "FAIL [%s] instr %zu: unknown reference kind\n",
                         name.c_str(), idx);
            ++g_failures;
            return;
        }
    }

    // Both must terminate cleanly at the same point.
    syz::WireInstrView tail;
    const auto end = reader.Next(&tail);
    CHECK(end == syz::WireStreamReader::Status::kEof);
}

// ---- Corpus builders ------------------------------------------------------

syz::WireConst MakeConst(uint64_t size, uint64_t val, syz::BinaryFormat fmt,
                         uint64_t bf_off = 0, uint64_t bf_len = 0,
                         uint64_t pid_stride = 0) {
    syz::WireConst c;
    c.size = size;
    c.val = val;
    c.fmt = fmt;
    c.bf_off = bf_off;
    c.bf_len = bf_len;
    c.pid_stride = pid_stride;
    return c;
}

syz::WireResult MakeResult(uint64_t size, uint64_t idx, uint64_t op_div,
                           uint64_t op_add, uint64_t def,
                           syz::BinaryFormat fmt = syz::BinaryFormat::kNative) {
    syz::WireResult r;
    r.size = size;
    r.idx = idx;
    r.op_div = op_div;
    r.op_add = op_add;
    r.default_val = def;
    r.fmt = fmt;
    return r;
}

syz::WireData MakeData(std::vector<uint8_t> bytes, bool readable) {
    // Own the bytes in a static pool so the span stays valid across encode.
    static std::vector<std::vector<uint8_t>> pool;
    pool.push_back(std::move(bytes));
    syz::WireData d;
    d.data = std::span<const uint8_t>(pool.back());
    d.readable = readable;
    return d;
}

syz::WireCsum MakeCsum(uint64_t size, std::vector<syz::WireCsumChunk> chunks) {
    syz::WireCsum w;
    w.csum_kind = 0;  // inet
    w.size = size;
    w.chunks = std::move(chunks);
    return w;
}

// Encode a program then run parity on the bytes.
void ParityProgram(const std::string& name, const syz::WireProgram& wp) {
    const std::vector<uint8_t> bytes = syz::encode_wire_program(wp);
    AssertParity(name, bytes);
}

constexpr uint64_t kNoCopyout = ~uint64_t{0};

void RunCorpus() {
    // 1. Empty program (num_calls = 0, only EOF).
    {
        syz::WireProgram wp;
        wp.num_calls = 0;
        ParityProgram("empty", wp);
    }

    // 2. Single call, zero args, no copyout.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 7;
        cl.copyout_idx = kNoCopyout;
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("single-call-no-args", wp);
    }

    // 3. Call with a return-value copyout index set.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 42;
        cl.copyout_idx = 3;
        cl.args.emplace_back(MakeConst(4, 0x1234, syz::BinaryFormat::kNative));
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("call-with-copyout-idx", wp);
    }

    // 4. Every const flavor as call args in one call.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 100;
        cl.copyout_idx = kNoCopyout;
        cl.args.emplace_back(MakeConst(8, 0xdeadbeef, syz::BinaryFormat::kNative));
        cl.args.emplace_back(MakeConst(2, 0x0102, syz::BinaryFormat::kBigEndian));
        cl.args.emplace_back(
            MakeConst(4, 5, syz::BinaryFormat::kNative, /*bf_off=*/3, /*bf_len=*/5));
        cl.args.emplace_back(
            MakeConst(8, 1, syz::BinaryFormat::kNative, 0, 0, /*pid_stride=*/0x1000));
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("const-flavors", wp);
    }

    // 5. Addr32 / Addr64 args.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 11;
        cl.copyout_idx = kNoCopyout;
        syz::WireAddr a32;
        a32.ptr_size = 4;
        a32.addr = 0x40;
        syz::WireAddr a64;
        a64.ptr_size = 8;
        a64.addr = 0x2000;
        cl.args.emplace_back(a32);
        cl.args.emplace_back(a64);
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("addr32-addr64", wp);
    }

    // 6. Result arg with div/add/default and a nonzero idx.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 55;
        cl.copyout_idx = kNoCopyout;
        cl.args.emplace_back(MakeResult(8, /*idx=*/2, /*div=*/4, /*add=*/1,
                                        /*def=*/0xabcd));
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("result-arg", wp);
    }

    // 7. Copyin of every arg kind, then a call that consumes them.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        wp.instrs.emplace_back(syz::WireCopyin{
            0x00, syz::WireArg{MakeConst(4, 0x11223344, syz::BinaryFormat::kNative)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x10, syz::WireArg{MakeConst(20, 42, syz::BinaryFormat::kStrDec)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x30, syz::WireArg{MakeConst(18, 0xdead, syz::BinaryFormat::kStrHex)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x50, syz::WireArg{MakeConst(23, 0777, syz::BinaryFormat::kStrOct)}});
        syz::WireAddr ptr;
        ptr.ptr_size = 8;
        ptr.addr = 0x100;
        wp.instrs.emplace_back(syz::WireCopyin{0x70, syz::WireArg{ptr}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x80, syz::WireArg{MakeResult(4, 1, 0, 0, 0x99)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x90, syz::WireArg{MakeData({0xde, 0xad, 0xbe, 0xef}, /*readable=*/true)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0xA0, syz::WireArg{MakeData({}, /*readable=*/false)}});  // empty blob
        syz::WireCall cl;
        cl.call_id = 3;
        cl.copyout_idx = kNoCopyout;
        syz::WireAddr a;
        a.ptr_size = 8;
        a.addr = 0;
        cl.args.emplace_back(a);
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("copyin-all-kinds", wp);
    }

    // 8. Csum copyin: data chunk + const chunk, multiple chunks.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        std::vector<syz::WireCsumChunk> chunks;
        chunks.push_back({syz::WireCsumChunkKind::kArgData, /*addr=*/0x10, /*size=*/12});
        chunks.push_back({syz::WireCsumChunkKind::kConst, /*value=*/0x0011, /*size=*/2});
        chunks.push_back({syz::WireCsumChunkKind::kArgData, /*addr=*/0x40, /*size=*/8});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x08, syz::WireArg{MakeCsum(/*size=*/2, std::move(chunks))}});
        syz::WireCall cl;
        cl.call_id = 9;
        cl.copyout_idx = kNoCopyout;
        wp.instrs.emplace_back(std::move(cl));
        ParityProgram("csum-copyin", wp);
    }

    // 9. Copyout instructions: several immediately after a call.
    {
        syz::WireProgram wp;
        wp.num_calls = 1;
        syz::WireCall cl;
        cl.call_id = 21;
        cl.copyout_idx = 0;
        syz::WireAddr a;
        a.ptr_size = 8;
        a.addr = 0x200;
        cl.args.emplace_back(a);
        wp.instrs.emplace_back(std::move(cl));
        wp.instrs.emplace_back(syz::WireCopyout{/*idx=*/1, /*addr=*/0x200, /*size=*/8});
        wp.instrs.emplace_back(syz::WireCopyout{/*idx=*/2, /*addr=*/0x208, /*size=*/4});
        wp.instrs.emplace_back(syz::WireCopyout{/*idx=*/3, /*addr=*/0x20c, /*size=*/2});
        ParityProgram("multi-copyout", wp);
    }

    // 10. SetProps flavors before calls.
    {
        syz::WireProgram wp;
        wp.num_calls = 2;
        wp.instrs.emplace_back(syz::WireSetProps{/*fail_nth=*/3, /*async=*/false, /*rerun=*/0});
        syz::WireCall cl0;
        cl0.call_id = 1;
        cl0.copyout_idx = kNoCopyout;
        wp.instrs.emplace_back(std::move(cl0));
        wp.instrs.emplace_back(syz::WireSetProps{/*fail_nth=*/0, /*async=*/true, /*rerun=*/2});
        syz::WireCall cl1;
        cl1.call_id = 2;
        cl1.copyout_idx = kNoCopyout;
        wp.instrs.emplace_back(std::move(cl1));
        ParityProgram("setprops", wp);
    }

    // 11. Kitchen sink: a multi-call program interleaving everything, and
    //     with the maximum arg count (9).
    {
        syz::WireProgram wp;
        wp.num_calls = 3;
        // call 0: copyins then a 9-arg call with a copyout.
        wp.instrs.emplace_back(syz::WireCopyin{
            0x00, syz::WireArg{MakeData({1, 2, 3, 4, 5, 6, 7, 8}, true)}});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x08, syz::WireArg{MakeConst(8, 0xcafef00d, syz::BinaryFormat::kNative)}});
        syz::WireCall c0;
        c0.call_id = 30;
        c0.copyout_idx = 5;
        for (int i = 0; i < 9; ++i) {
            c0.args.emplace_back(MakeConst(8, static_cast<uint64_t>(i) + 1,
                                           syz::BinaryFormat::kNative));
        }
        wp.instrs.emplace_back(std::move(c0));
        wp.instrs.emplace_back(syz::WireCopyout{/*idx=*/6, /*addr=*/0x0, /*size=*/8});
        // call 1: setprops + result arg referencing earlier copyout.
        wp.instrs.emplace_back(syz::WireSetProps{5, false, 0});
        syz::WireCall c1;
        c1.call_id = 31;
        c1.copyout_idx = kNoCopyout;
        c1.args.emplace_back(MakeResult(8, /*idx=*/5, /*div=*/2, /*add=*/3, /*def=*/0));
        syz::WireAddr a1;
        a1.ptr_size = 8;
        a1.addr = 0x00;
        c1.args.emplace_back(a1);
        wp.instrs.emplace_back(std::move(c1));
        // call 2: csum copyin + a plain call.
        std::vector<syz::WireCsumChunk> chunks;
        chunks.push_back({syz::WireCsumChunkKind::kArgData, 0x0, 8});
        chunks.push_back({syz::WireCsumChunkKind::kConst, 0x1122, 4});
        wp.instrs.emplace_back(syz::WireCopyin{
            0x40, syz::WireArg{MakeCsum(2, std::move(chunks))}});
        syz::WireCall c2;
        c2.call_id = 32;
        c2.copyout_idx = kNoCopyout;
        wp.instrs.emplace_back(std::move(c2));
        ParityProgram("kitchen-sink", wp);
    }
}

}  // namespace

int main() {
    RunCorpus();
    if (g_failures != 0) {
        std::fprintf(stderr, "wire_stream_decode_parity_test: %d FAILURES\n",
                     g_failures);
        return 1;
    }
    std::fprintf(stderr, "wire_stream_decode_parity_test: ALL OK\n");
    return 0;
}
