// Exec wire decoder — inverse of program/src/syz_v2/exec_wire.cpp.
//
// Parses the Go-varint stream produced by `serialize_for_exec` into a
// materialized `WireProgram` of Copyin / Copyout / SetProps / Call
// instructions. Each instruction owns its decoded fields (no pointers
// back into the input buffer except for inline DataArg payload, which is
// copied into the WireData byte vector).
//
// The decoder is intentionally OS- and worker-agnostic: it does not
// open an mmap region, allocate scratch memory, or invoke any syscall.
// Layer 2 (worker integration, §3.3 next session) consumes WireProgram
// to drive actual execution.
//
// Layer-1 oracle: `serialize_for_exec(prog) → decode_exec_wire(bytes) →
// encode_wire_program(wire) → bytes` must be byte-equal. Combined with
// §3.2's byte-equal-vs-syzkaller oracle, this proves the wire is a
// bidirectional bijection with `prog.Prog.SerializeForExec`.

#pragma once

#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace refuzz::program::syz {

// ---- Wire-level argument forms (mirror prog/encodingexec.go iota chain) ----

struct WireConst {
    uint64_t     size       = 0;
    uint64_t     val        = 0;
    BinaryFormat fmt        = BinaryFormat::kNative;
    uint64_t     bf_off     = 0;
    uint64_t     bf_len     = 0;
    uint64_t     pid_stride = 0;
};

struct WireAddr {
    uint8_t  ptr_size = 0;   // 4 or 8
    uint64_t addr     = 0;
};

struct WireResult {
    uint64_t     size        = 0;
    BinaryFormat fmt         = BinaryFormat::kNative;
    uint64_t     idx         = 0;   // copyout index referenced
    uint64_t     op_div      = 0;
    uint64_t     op_add      = 0;
    uint64_t     default_val = 0;
};

struct WireData {
    // Non-owning view into the input wire buffer (no copy on decode). Valid
    // only while the buffer passed to decode_exec_wire() / WireStreamReader is
    // alive — which, on the driver path, is the whole Execute() call. The old
    // owning std::vector<uint8_t> forced a per-blob alloc+copy in read_blob;
    // pointing straight at the input eliminates it (~200 blob copies/program).
    std::span<const uint8_t> data;
    bool                     readable = false;
};

enum class WireCsumChunkKind : uint8_t { kArgData = 0, kConst = 1 };

struct WireCsumChunk {
    WireCsumChunkKind kind          = WireCsumChunkKind::kArgData;
    uint64_t          addr_or_value = 0;  // arg's addr if kArgData, raw value if kConst
    uint64_t          size          = 0;
};

struct WireCsum {
    uint64_t                   csum_kind = 0;  // 0 = inet
    uint64_t                   size      = 0;
    std::vector<WireCsumChunk> chunks;
};

using WireArg = std::variant<WireConst, WireAddr, WireResult, WireData, WireCsum>;

// ---- Wire-level instructions ----

struct WireCopyin {
    uint64_t addr = 0;
    WireArg  arg;
};

struct WireCopyout {
    uint64_t idx  = 0;
    uint64_t addr = 0;
    uint64_t size = 0;
};

struct WireSetProps {
    int64_t fail_nth = 0;
    bool    async    = false;
    int64_t rerun    = 0;
};

struct WireCall {
    uint64_t              call_id     = 0;
    uint64_t              copyout_idx = 0;  // ~uint64_t{0} when no copyout
    std::vector<WireArg>  args;
};

using WireInstr = std::variant<WireCopyin, WireCopyout, WireSetProps, WireCall>;

struct WireProgram {
    uint64_t               num_calls = 0;
    std::vector<WireInstr> instrs;   // ordering matches the wire stream
};

// ---- Errors ----

struct WireDecodeError {
    std::string message;
    std::size_t offset = 0;   // byte offset where decoding failed
};

// ---- Public API ----

std::expected<WireProgram, WireDecodeError>
decode_exec_wire(std::span<const uint8_t> bytes);

// Inverse of decode_exec_wire — emits the same varint stream that
// produced `wp`. Used by the Layer-1 round-trip oracle.
std::vector<uint8_t> encode_wire_program(const WireProgram& wp);

// ============================================================
// Streaming decoder (WireStreamReader)
// ============================================================
//
// Pulls one instruction at a time straight from the wire buffer — no
// intermediate WireProgram, no per-call args vector, no blob copy. This is the
// execution-path decoder, a direct port of syzkaller executor.cc's execute_one
// / read_input cursor walk. `decode_exec_wire` above stays as the materializing
// decoder used by the round-trip oracle and by code that needs a whole
// WireProgram in hand (csource emit, minimize, tools).
//
// Both decoders share the same varint / arg primitives, so a WireStreamReader
// walk is byte-for-byte identical to decode_exec_wire over the same bytes —
// only *when* each field is decoded differs. That equivalence is the parity
// contract; the driver relies on it to move decoding into the exec loop
// without changing any copyin/copyout/resource/csum/coverage semantics.
//
// Lifetime: every returned view borrows the `bytes` buffer passed to the
// constructor (WireData spans point straight into it). Valid only while that
// buffer is alive — on the driver path, the whole Execute() call.

// A call instruction's header. Unlike WireCall it carries no args vector: the
// caller pulls each of its `num_args` args in order via NextArg() and resolves
// them on the spot into a stack buffer.
struct WireCallHeader {
    uint64_t call_id     = 0;
    uint64_t copyout_idx = 0;   // ~uint64_t{0} when no copyout
    uint64_t num_args    = 0;
};

// One instruction yielded by WireStreamReader::Next(). Copyin / Copyout /
// SetProps reuse the same structs the materialized decoder emits (so the same
// apply_copyin / apply_copyout helpers consume them unchanged); a call yields
// only its header.
using WireInstrView =
    std::variant<WireCopyin, WireCopyout, WireSetProps, WireCallHeader>;

class WireStreamReader {
public:
    enum class Status { kInstr, kEof, kError };

    explicit WireStreamReader(std::span<const uint8_t> bytes)
        : data_(bytes.data()), size_(bytes.size()) {}

    // Read the leading total-call-count varint. Call exactly once, before the
    // first Next(). Returns false (and sets error()) on malformed input or a
    // count past the upstream MaxCalls bound.
    bool ReadNumCalls(uint64_t* out);

    // Decode the next instruction into *out. kEof marks a clean end (the EOF
    // sentinel); kError leaves error() set. After a WireCallHeader, the caller
    // must pull exactly header.num_args args via NextArg() before the next
    // Next() — the args sit inline right after the header in the stream.
    Status Next(WireInstrView* out);

    // Pull one call arg (used header.num_args times after a WireCallHeader).
    // Returns false (and sets error()) on malformed input.
    bool NextArg(WireArg* out);

    // Byte offset of the cursor. Save it right after a call's args to replay
    // that call's copyouts when it completes (threaded path), then seek() back.
    std::size_t position() const { return pos_; }
    void        seek(std::size_t pos) { pos_ = pos; }

    const WireDecodeError& error() const { return error_; }

private:
    const uint8_t*  data_ = nullptr;
    std::size_t     size_ = 0;
    std::size_t     pos_  = 0;
    WireDecodeError error_{};
};

} // namespace refuzz::program::syz
