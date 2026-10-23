// Implementation of refuzz/program/syz/exec_wire_decode.hpp.
//
// Parses the Go-varint stream produced by serialize_for_exec.

#include "refuzz/program/syz/exec_wire_decode.hpp"

#include "refuzz/program/internal/codec_counters.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>

namespace refuzz::program::syz {

namespace {

constexpr uint64_t kExecInstrEOF      = ~uint64_t{0};
constexpr uint64_t kExecInstrCopyin   = ~uint64_t{1};
constexpr uint64_t kExecInstrCopyout  = ~uint64_t{2};
constexpr uint64_t kExecInstrSetProps = ~uint64_t{3};

constexpr uint64_t kExecArgConst   = 0;
constexpr uint64_t kExecArgAddr32  = 1;
constexpr uint64_t kExecArgAddr64  = 2;
constexpr uint64_t kExecArgResult  = 3;
constexpr uint64_t kExecArgData    = 4;
constexpr uint64_t kExecArgCsum    = 5;

constexpr uint64_t kExecArgDataReadable = uint64_t{1} << 63;

// ---- Cursor over the input buffer ----

struct Cursor {
    const uint8_t* data;
    std::size_t    size;
    std::size_t    pos = 0;

    bool        empty()        const { return pos >= size; }
    std::size_t remaining()    const { return size - pos; }
};

WireDecodeError make_err(const Cursor& c, const char* msg) {
    return {std::string(msg), c.pos};
}

// Upper bounds for attacker-controlled length fields. Mirror upstream syzkaller
// (prog/rand.go:MaxCalls=40, prog/types.go:MaxArgs=9) so a corrupted varint in
// the wire stream can't drive vector::reserve past max_size and throw
// std::length_error — that would terminate the worker process and lose every
// in-flight request to it.
constexpr uint64_t kWireMaxCalls    = 40;    // upstream MaxCalls
constexpr uint64_t kWireMaxArgs     = 9;     // upstream MaxArgs / kSyzMaxArgs
constexpr uint64_t kWireMaxCsumCks  = 1024;  // real csum traffic is 1-3 chunks;
                                             // 1024 is generous and bounds
                                             // reserve to a safe allocation.

// Read one Go-style zig-zag varint. Mirror inverse of binary.AppendVarint.
std::expected<uint64_t, WireDecodeError> read_varint(Cursor& c) {
    uint64_t ux    = 0;
    int      shift = 0;
    while (true) {
        if (c.empty()) {
            return std::unexpected(make_err(c, "varint: unexpected EOF"));
        }
        uint8_t b = c.data[c.pos++];
        if (shift > 63) {
            return std::unexpected(make_err(c, "varint: overflow"));
        }
        ux |= (uint64_t(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    const int64_t signed_x =
        static_cast<int64_t>(ux >> 1) ^ -static_cast<int64_t>(ux & 1);
    return static_cast<uint64_t>(signed_x);
}

// Return a non-owning view of the next `n` bytes and advance the cursor past
// them. The span points straight into the input buffer — no alloc, no copy.
// Valid for as long as the caller keeps that buffer alive.
std::expected<std::span<const uint8_t>, WireDecodeError>
read_blob(Cursor& c, std::size_t n) {
    if (c.remaining() < n) {
        return std::unexpected(make_err(c, "data blob exceeds buffer"));
    }
    std::span<const uint8_t> v(c.data + c.pos, n);
    c.pos += n;
    return v;
}

// Decode one WireArg. `is_csum_context` selects the dispatch table:
// - Regular copyin / call-args context: const / addr32 / addr64 / result / data.
// - Inside a csum copyin: only csum.
// We just accept all six kinds anywhere; an off-context csum would still
// round-trip cleanly, but the encoder never produces that combination.
std::expected<WireArg, WireDecodeError> read_arg(Cursor& c) {
    auto kind_or = read_varint(c);
    if (!kind_or) return std::unexpected(kind_or.error());
    const uint64_t kind = *kind_or;
    switch (kind) {
        case kExecArgConst: {
            auto meta = read_varint(c); if (!meta) return std::unexpected(meta.error());
            auto val  = read_varint(c); if (!val)  return std::unexpected(val.error());
            const uint64_t m = *meta;
            WireConst w;
            w.size       =  m        & 0xFF;
            w.fmt        = static_cast<BinaryFormat>((m >> 8)  & 0xFF);
            w.bf_off     = (m >> 16) & 0xFF;
            w.bf_len     = (m >> 24) & 0xFF;
            w.pid_stride =  m >> 32;
            w.val        = *val;
            return WireArg{w};
        }
        case kExecArgAddr32:
        case kExecArgAddr64: {
            auto addr = read_varint(c); if (!addr) return std::unexpected(addr.error());
            WireAddr w;
            w.ptr_size = (kind == kExecArgAddr32) ? uint8_t{4} : uint8_t{8};
            w.addr     = *addr;
            return WireArg{w};
        }
        case kExecArgResult: {
            auto meta = read_varint(c); if (!meta) return std::unexpected(meta.error());
            auto idx  = read_varint(c); if (!idx)  return std::unexpected(idx.error());
            auto opd  = read_varint(c); if (!opd)  return std::unexpected(opd.error());
            auto opa  = read_varint(c); if (!opa)  return std::unexpected(opa.error());
            auto def  = read_varint(c); if (!def)  return std::unexpected(def.error());
            const uint64_t m = *meta;
            WireResult w;
            w.size        =  m        & 0xFF;
            w.fmt         = static_cast<BinaryFormat>((m >> 8) & 0xFF);
            w.idx         = *idx;
            w.op_div      = *opd;
            w.op_add      = *opa;
            w.default_val = *def;
            return WireArg{w};
        }
        case kExecArgData: {
            auto flags = read_varint(c); if (!flags) return std::unexpected(flags.error());
            const uint64_t f       = *flags;
            const bool     readable = (f & kExecArgDataReadable) != 0;
            const uint64_t len      = f & ~kExecArgDataReadable;
            auto blob = read_blob(c, static_cast<std::size_t>(len));
            if (!blob) return std::unexpected(blob.error());
            WireData w;
            w.data     = *blob;  // span into input; no copy
            w.readable = readable;
            return WireArg{w};
        }
        case kExecArgCsum: {
            auto size      = read_varint(c); if (!size)      return std::unexpected(size.error());
            auto csum_kind = read_varint(c); if (!csum_kind) return std::unexpected(csum_kind.error());
            auto nchunks   = read_varint(c); if (!nchunks)   return std::unexpected(nchunks.error());
            if (*nchunks > kWireMaxCsumCks) {
                return std::unexpected(make_err(c, "csum nchunks exceeds bound"));
            }
            WireCsum w;
            w.size      = *size;
            w.csum_kind = *csum_kind;
            w.chunks.reserve(static_cast<std::size_t>(*nchunks));
            for (uint64_t i = 0; i < *nchunks; ++i) {
                auto ck = read_varint(c); if (!ck) return std::unexpected(ck.error());
                auto a1 = read_varint(c); if (!a1) return std::unexpected(a1.error());
                auto a2 = read_varint(c); if (!a2) return std::unexpected(a2.error());
                WireCsumChunk ch;
                ch.kind          = static_cast<WireCsumChunkKind>(*ck);
                ch.addr_or_value = *a1;
                ch.size          = *a2;
                w.chunks.push_back(ch);
            }
            return WireArg{w};
        }
        default: {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "unknown arg kind 0x%llx",
                          static_cast<unsigned long long>(kind));
            return std::unexpected(make_err(c, buf));
        }
    }
}

} // namespace

std::expected<WireProgram, WireDecodeError>
decode_exec_wire(std::span<const uint8_t> bytes) {
    refuzz::program::codec_counters::OnDecodeWire();
    Cursor c{bytes.data(), bytes.size()};

    auto nc = read_varint(c);
    if (!nc) return std::unexpected(nc.error());
    if (*nc > kWireMaxCalls) {
        return std::unexpected(make_err(c, "num_calls exceeds bound"));
    }

    WireProgram wp;
    wp.num_calls = *nc;
    wp.instrs.reserve(static_cast<std::size_t>(*nc) * 4);

    while (true) {
        auto v_or = read_varint(c);
        if (!v_or) return std::unexpected(v_or.error());
        const uint64_t v = *v_or;

        if (v == kExecInstrEOF) break;

        if (v == kExecInstrCopyin) {
            auto addr = read_varint(c); if (!addr) return std::unexpected(addr.error());
            auto arg  = read_arg(c);    if (!arg)  return std::unexpected(arg.error());
            wp.instrs.emplace_back(WireCopyin{*addr, std::move(*arg)});
            continue;
        }

        if (v == kExecInstrCopyout) {
            auto idx  = read_varint(c); if (!idx)  return std::unexpected(idx.error());
            auto addr = read_varint(c); if (!addr) return std::unexpected(addr.error());
            auto size = read_varint(c); if (!size) return std::unexpected(size.error());
            wp.instrs.emplace_back(WireCopyout{*idx, *addr, *size});
            continue;
        }

        if (v == kExecInstrSetProps) {
            auto fn  = read_varint(c); if (!fn)  return std::unexpected(fn.error());
            auto as_ = read_varint(c); if (!as_) return std::unexpected(as_.error());
            auto rr  = read_varint(c); if (!rr)  return std::unexpected(rr.error());
            WireSetProps p;
            p.fail_nth = static_cast<int64_t>(*fn);
            p.async    = (*as_ != 0);
            p.rerun    = static_cast<int64_t>(*rr);
            wp.instrs.emplace_back(p);
            continue;
        }

        // Otherwise: v is a call ID (any uint64 below the special opcodes).
        auto copyout_idx = read_varint(c); if (!copyout_idx) return std::unexpected(copyout_idx.error());
        auto n_args      = read_varint(c); if (!n_args)      return std::unexpected(n_args.error());
        if (*n_args > kWireMaxArgs) {
            return std::unexpected(make_err(c, "call n_args exceeds bound"));
        }
        WireCall cl;
        cl.call_id     = v;
        cl.copyout_idx = *copyout_idx;
        cl.args.reserve(static_cast<std::size_t>(*n_args));
        for (uint64_t i = 0; i < *n_args; ++i) {
            auto a = read_arg(c);
            if (!a) return std::unexpected(a.error());
            cl.args.push_back(std::move(*a));
        }
        wp.instrs.emplace_back(std::move(cl));
    }

    if (!c.empty()) {
        // Trailing bytes after EOF are unexpected; flag rather than ignore.
        return std::unexpected(make_err(c, "trailing bytes after EOF"));
    }
    return wp;
}

// ============================================================
// WireStreamReader — streaming decoder (inverse of execute_one's read_input).
//
// Reuses the exact same Cursor / read_varint / read_arg / read_blob primitives
// as decode_exec_wire above (internal-linkage, visible file-wide), so a
// WireStreamReader walk decodes each field identically — it just yields one
// instruction at a time instead of materializing a WireProgram. Unlike the
// batch decoder it does NOT enforce the "trailing bytes after EOF" strictness:
// like syzkaller's execute_one it stops at the EOF sentinel, since by then the
// exec loop has already run every real instruction. Malformed input inside the
// stream still surfaces as kError / false with error() set.
// ============================================================

bool WireStreamReader::ReadNumCalls(uint64_t* out) {
    refuzz::program::codec_counters::OnDecodeWire();
    Cursor c{data_, size_, pos_};
    auto nc = read_varint(c);
    if (!nc) {
        error_ = nc.error();
        return false;
    }
    if (*nc > kWireMaxCalls) {
        error_ = make_err(c, "num_calls exceeds bound");
        return false;
    }
    pos_ = c.pos;
    *out = *nc;
    return true;
}

WireStreamReader::Status WireStreamReader::Next(WireInstrView* out) {
    Cursor c{data_, size_, pos_};
    auto v_or = read_varint(c);
    if (!v_or) {
        error_ = v_or.error();
        return Status::kError;
    }
    const uint64_t v = *v_or;

    if (v == kExecInstrEOF) {
        pos_ = c.pos;
        return Status::kEof;
    }

    if (v == kExecInstrCopyin) {
        auto addr = read_varint(c);
        if (!addr) { error_ = addr.error(); return Status::kError; }
        auto arg = read_arg(c);
        if (!arg) { error_ = arg.error(); return Status::kError; }
        *out = WireCopyin{*addr, std::move(*arg)};
        pos_ = c.pos;
        return Status::kInstr;
    }

    if (v == kExecInstrCopyout) {
        auto idx  = read_varint(c); if (!idx)  { error_ = idx.error();  return Status::kError; }
        auto addr = read_varint(c); if (!addr) { error_ = addr.error(); return Status::kError; }
        auto size = read_varint(c); if (!size) { error_ = size.error(); return Status::kError; }
        *out = WireCopyout{*idx, *addr, *size};
        pos_ = c.pos;
        return Status::kInstr;
    }

    if (v == kExecInstrSetProps) {
        auto fn = read_varint(c); if (!fn) { error_ = fn.error(); return Status::kError; }
        auto as = read_varint(c); if (!as) { error_ = as.error(); return Status::kError; }
        auto rr = read_varint(c); if (!rr) { error_ = rr.error(); return Status::kError; }
        WireSetProps p;
        p.fail_nth = static_cast<int64_t>(*fn);
        p.async    = (*as != 0);
        p.rerun    = static_cast<int64_t>(*rr);
        *out = p;
        pos_ = c.pos;
        return Status::kInstr;
    }

    // Otherwise: v is a call ID. Yield the header only — the caller pulls the
    // args inline via NextArg() (mirrors execute_one reading copyout_index /
    // num_args then looping read_arg).
    auto copyout_idx = read_varint(c);
    if (!copyout_idx) { error_ = copyout_idx.error(); return Status::kError; }
    auto n_args = read_varint(c);
    if (!n_args) { error_ = n_args.error(); return Status::kError; }
    *out = WireCallHeader{v, *copyout_idx, *n_args};
    pos_ = c.pos;
    return Status::kInstr;
}

bool WireStreamReader::NextArg(WireArg* out) {
    Cursor c{data_, size_, pos_};
    auto a = read_arg(c);
    if (!a) {
        error_ = a.error();
        return false;
    }
    *out = std::move(*a);
    pos_ = c.pos;
    return true;
}

// ============================================================
// Re-encoder (decoder inverse).
// ============================================================

namespace {

void emit_varint(std::vector<uint8_t>& buf, uint64_t v) {
    int64_t  x  = static_cast<int64_t>(v);
    uint64_t ux = static_cast<uint64_t>(x) << 1;
    if (x < 0) ux = ~ux;
    while (ux >= 0x80) {
        buf.push_back(static_cast<uint8_t>(ux) | uint8_t{0x80});
        ux >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(ux));
}

void emit_arg(std::vector<uint8_t>& buf, const WireArg& a) {
    if (auto* w = std::get_if<WireConst>(&a)) {
        emit_varint(buf, kExecArgConst);
        const uint64_t meta = w->size
                            | (static_cast<uint64_t>(w->fmt) << 8)
                            | (w->bf_off << 16)
                            | (w->bf_len << 24)
                            | (w->pid_stride << 32);
        emit_varint(buf, meta);
        emit_varint(buf, w->val);
        return;
    }
    if (auto* w = std::get_if<WireAddr>(&a)) {
        emit_varint(buf, w->ptr_size == 4 ? kExecArgAddr32 : kExecArgAddr64);
        emit_varint(buf, w->addr);
        return;
    }
    if (auto* w = std::get_if<WireResult>(&a)) {
        emit_varint(buf, kExecArgResult);
        const uint64_t meta = w->size | (static_cast<uint64_t>(w->fmt) << 8);
        emit_varint(buf, meta);
        emit_varint(buf, w->idx);
        emit_varint(buf, w->op_div);
        emit_varint(buf, w->op_add);
        emit_varint(buf, w->default_val);
        return;
    }
    if (auto* w = std::get_if<WireData>(&a)) {
        emit_varint(buf, kExecArgData);
        uint64_t flags = static_cast<uint64_t>(w->data.size());
        if (w->readable) flags |= kExecArgDataReadable;
        emit_varint(buf, flags);
        buf.insert(buf.end(), w->data.begin(), w->data.end());
        return;
    }
    if (auto* w = std::get_if<WireCsum>(&a)) {
        emit_varint(buf, kExecArgCsum);
        emit_varint(buf, w->size);
        emit_varint(buf, w->csum_kind);
        emit_varint(buf, w->chunks.size());
        for (const auto& ch : w->chunks) {
            emit_varint(buf, static_cast<uint64_t>(ch.kind));
            emit_varint(buf, ch.addr_or_value);
            emit_varint(buf, ch.size);
        }
        return;
    }
    // Unreachable for well-formed WireArg.
}

} // namespace

std::vector<uint8_t> encode_wire_program(const WireProgram& wp) {
    refuzz::program::codec_counters::OnEncodeWire();
    std::vector<uint8_t> buf;
    buf.reserve(64 + wp.instrs.size() * 8);
    emit_varint(buf, wp.num_calls);

    for (const auto& instr : wp.instrs) {
        if (auto* c = std::get_if<WireCopyin>(&instr)) {
            emit_varint(buf, kExecInstrCopyin);
            emit_varint(buf, c->addr);
            emit_arg(buf, c->arg);
            continue;
        }
        if (auto* c = std::get_if<WireCopyout>(&instr)) {
            emit_varint(buf, kExecInstrCopyout);
            emit_varint(buf, c->idx);
            emit_varint(buf, c->addr);
            emit_varint(buf, c->size);
            continue;
        }
        if (auto* p = std::get_if<WireSetProps>(&instr)) {
            emit_varint(buf, kExecInstrSetProps);
            emit_varint(buf, static_cast<uint64_t>(p->fail_nth));
            emit_varint(buf, p->async ? uint64_t{1} : uint64_t{0});
            emit_varint(buf, static_cast<uint64_t>(p->rerun));
            continue;
        }
        if (auto* cl = std::get_if<WireCall>(&instr)) {
            emit_varint(buf, cl->call_id);
            emit_varint(buf, cl->copyout_idx);
            emit_varint(buf, cl->args.size());
            for (const auto& a : cl->args) emit_arg(buf, a);
            continue;
        }
    }
    emit_varint(buf, kExecInstrEOF);
    return buf;
}

} // namespace refuzz::program::syz
