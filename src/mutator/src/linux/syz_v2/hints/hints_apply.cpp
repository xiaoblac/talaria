// hints_apply.cpp — Epic 5 PR-5-C. See hints_apply.hpp.

#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"

#include "refuzz/mutator/linux/syz_v2/hints/image_zlib.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/special_ints_set.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace refuzz::mutator::syz_v2::hints {

namespace pr = ::refuzz::program::syz;

namespace {

// ============================================================
// Bit-shift helpers — guard against UB for shift==64 (C++ undefined).
// Upstream Go has well-defined "shift by >= width gives 0" for typed
// uints; C++ requires explicit handling.
// ============================================================

inline uint64_t LowMask(uint64_t bits) {
    return bits >= 64 ? ~uint64_t{0} : ((uint64_t{1} << bits) - 1);
}

inline uint64_t HighOnes(uint64_t bits) {
    // ^((1 << bits) - 1) — high bits set, low `bits` cleared.
    return ~LowMask(bits);
}

inline uint64_t TruncateToBitSize(uint64_t v, uint64_t bitsize) {
    return v & LowMask(bitsize);
}

// Mirror of `bits.ReverseBytesN`. width is in bytes (1, 2, 4, or 8).
inline uint64_t SwapInt(uint64_t v, int width) {
    switch (width) {
    case 1: return v & 0xffu;
    case 2: return __builtin_bswap16(static_cast<uint16_t>(v));
    case 4: return __builtin_bswap32(static_cast<uint32_t>(v));
    case 8: return __builtin_bswap64(v);
    default: return v;  // unreachable per upstream contract
    }
}

// Read a little-endian uint64 starting at `data + offset`, padded with
// zero bytes when `data` is shorter than `offset + 8` (mirror of
// `binary.LittleEndian.Uint64(make([]byte,8); copy(_, data[i:]))`).
inline uint64_t ReadLE64Padded(const std::vector<uint8_t>& data, size_t offset) {
    uint8_t buf[8] = {0};
    const size_t avail = data.size() > offset ? std::min<size_t>(8, data.size() - offset) : 0;
    if (avail > 0) std::memcpy(buf, data.data() + offset, avail);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(buf[i]) << (8 * i);
    }
    return v;
}

// Write a little-endian uint64 starting at `data + offset`. Truncates
// to `data.size() - offset` bytes (mirror of `copy(data[i:], bytes)`).
inline void WriteLE64Truncated(std::vector<uint8_t>& data, size_t offset, uint64_t v) {
    if (offset >= data.size()) return;
    const size_t n = std::min<size_t>(8, data.size() - offset);
    for (size_t i = 0; i < n; ++i) {
        data[offset + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}

// Helper for upstream `arg.Type().TypeBitSize()` (prog/types.go:397).
//
// Mirrors the special case for string-formatted IntTypeCommon: when the
// integer is rendered as a base-10 / hex / octal *string* (BinaryFormat
// kStrDec / kStrHex / kStrOct), upstream returns 64 because the
// in-memory representation has been widened to a uint64 ascii buffer
// and the comparison-side bit-width no longer matches t.size()*8.
// Without this branch, hints would scan str-formatted ConstArgs at
// 8/16/32-bit width and miss candidates the kernel observed at 64-bit.
//
// Generated linux/amd64 target uses StrHex/StrDec/StrOct broadly
// (filenames, hex constants in syz fmt strings); filtering on this
// matters there.
uint64_t TypeBitSize(const pr::Type* t) {
    if (t == nullptr) return 0;
    if (auto* itc = dynamic_cast<const pr::IntTypeCommon*>(t); itc != nullptr) {
        const auto fmt = itc->format();
        if (fmt != pr::BinaryFormat::kNative && fmt != pr::BinaryFormat::kBigEndian) {
            return 64;
        }
    }
    if (t->bitfield_length() != 0) return t->bitfield_length();
    return t->size() * 8;
}

// Useless-hint check that handles the program/syz IR shape: only
// IntTypeCommon-derived types implement the per-replacer filter; the
// base Type returns "not useless" by default. dynamic_cast keeps the
// query encapsulated in this TU (no virtual added to base Type).
bool TypeUselessHint(const pr::Type* t, uint64_t replacer) {
    auto* itc = dynamic_cast<const pr::IntTypeCommon*>(t);
    return itc != nullptr && itc->useless_hint(replacer);
}

} // namespace

// ============================================================
// shrink_expand
// ============================================================

std::vector<uint64_t> ShrinkExpand(uint64_t v,
                                   const CompMap& comps,
                                   uint64_t bitsize,
                                   bool image)
{
    v = TruncateToBitSize(v, bitsize);
    const uint64_t limit = LowMask(bitsize);
    std::unordered_set<uint64_t> replacers;

    static constexpr std::array<int, 7> kIWidths = {8, 4, 2, 1, -4, -2, -1};
    for (int iwidth : kIWidths) {
        int width = 0;
        uint64_t size = 0;
        uint64_t mutant = 0;
        if (iwidth > 0) {
            width = iwidth;
            size  = static_cast<uint64_t>(width) * 8;
            mutant = v & LowMask(size);
        } else {
            width = -iwidth;
            size  = std::min<uint64_t>(static_cast<uint64_t>(width) * 8, bitsize);
            // Expand only when sign bit at position size-1 is set.
            const uint64_t sign_bit = uint64_t{1} << (size - 1);
            if ((v & sign_bit) == 0) continue;
            mutant = v | HighOnes(size);
        }
        if (image) {
            if (width < 4) continue;
            if (mutant == 0 || (mutant | HighOnes(size)) == ~uint64_t{0}) continue;
        }

        for (bool bigendian : {false, true}) {
            uint64_t cur_mutant = mutant;
            if (bigendian) {
                if (width == 1) continue;
                cur_mutant = SwapInt(mutant, width);
            }
            const auto* op2_pcs = comps.Find(cur_mutant);
            if (op2_pcs == nullptr) continue;

            for (const auto& [new_v_raw, pcs] : *op2_pcs) {
                (void)pcs;
                uint64_t new_v = new_v_raw;
                // Negative-number range check (upstream lines 339-341).
                if (new_v > limit &&
                    ((HighOnes(bitsize ? bitsize - 1 : 0) & new_v) !=
                     HighOnes(bitsize ? bitsize - 1 : 0))) {
                    continue;
                }
                const uint64_t mask = LowMask(size);
                const uint64_t new_hi = new_v & ~mask;
                new_v = new_v & mask;
                // High bits of the candidate must be either all-zero or
                // all-one (the latter signals sign-extension we're ok
                // with). Other patterns mean the kernel saw something
                // structurally different; skip.
                if (new_hi != 0 && (new_hi ^ ~mask) != 0) continue;

                if (bigendian) new_v = SwapInt(new_v, width);

                // skip "specialInts" in the non-image path — random gen
                // already inserts these with high probability.
                if (!image && IsSpecialInt(new_v)) continue;

                uint64_t replacer = (v & ~mask) | new_v;
                if (replacer == v) continue;
                replacer = TruncateToBitSize(replacer, bitsize);
                replacers.insert(replacer);
            }
        }
    }

    if (replacers.empty()) return {};
    std::vector<uint64_t> res(replacers.begin(), replacers.end());
    std::sort(res.begin(), res.end());
    return res;
}

// ============================================================
// check_const_arg
// ============================================================

void CheckConstArgHints(pr::ConstArg& arg,
                        const pr::Field* field,
                        const CompMap& comps,
                        const std::function<bool()>& exec)
{
    const uint64_t original = arg.val();
    const auto candidates = ShrinkExpand(original, comps,
                                         TypeBitSize(arg.type()), /*image=*/false);

    for (uint64_t replacer : candidates) {
        // Upstream: when the field is part of a related-fields group, a
        // hint is useless iff EVERY related variant marks it useless.
        // Otherwise (no group), gate on this arg's own type.
        bool skip = false;
        if (field != nullptr && field->related_fields() != nullptr &&
            !field->related_fields()->empty()) {
            for (const pr::Type* related : *field->related_fields()) {
                if (TypeUselessHint(related, replacer)) {
                    skip = true;
                    break;
                }
            }
        } else if (TypeUselessHint(arg.type(), replacer)) {
            skip = true;
        }
        if (skip) continue;

        arg.set_val(replacer);
        if (!exec()) break;
    }
    arg.set_val(original);
}

// ============================================================
// check_data_arg
// ============================================================

void CheckDataArgHints(pr::DataArg& arg,
                       const CompMap& comps,
                       const std::function<bool()>& exec)
{
    constexpr size_t kMaxDataLength = 100;
    auto& data = arg.mutable_data();
    const size_t scan_size = std::min<size_t>(data.size(), kMaxDataLength);

    bool keep_going = true;
    for (size_t i = 0; i < scan_size && keep_going; ++i) {
        // Snapshot 8 bytes (zero-padded if data short) — upstream
        // `original := make([]byte,8); copy(original, data[i:])`.
        uint8_t original_bytes[8] = {0};
        const size_t avail = std::min<size_t>(8, data.size() - i);
        std::memcpy(original_bytes, data.data() + i, avail);
        const uint64_t val = ReadLE64Padded(data, i);

        const auto candidates = ShrinkExpand(val, comps, /*bitsize=*/64,
                                             /*image=*/false);
        for (uint64_t replacer : candidates) {
            WriteLE64Truncated(data, i, replacer);
            if (!exec()) {
                keep_going = false;
                break;
            }
        }
        // Restore (upstream `copy(data[i:], original)`).
        std::memcpy(data.data() + i, original_bytes, avail);
    }
}

// ============================================================
// check_compressed_arg
// ============================================================

void CheckCompressedArgHints(pr::DataArg& arg,
                             const CompMap& comps,
                             const std::function<bool()>& exec)
{
    const auto data0 = arg.data();   // copy of original compressed bytes
    auto data = MustDecompressImage(data0);
    bool keep_going = true;
    constexpr size_t kStep = 4;       // upstream: 4-byte aligned only

    // Upstream loop: `for i := 0; i < len(data); i += 4`. ReadLE64Padded
    // zero-pads on short reads so the final partial window still
    // exercises 4-byte aligned candidates (matches upstream's
    // `binary.LittleEndian.Uint64(make([]byte,8); copy(_, data[i:]))`).
    for (size_t i = 0; i < data.size() && keep_going; i += kStep) {
        uint8_t original_bytes[8] = {0};
        const size_t avail = std::min<size_t>(8, data.size() - i);
        std::memcpy(original_bytes, data.data() + i, avail);
        const uint64_t val = ReadLE64Padded(data, i);

        const auto candidates = ShrinkExpand(val, comps, /*bitsize=*/64,
                                             /*image=*/true);
        for (uint64_t replacer : candidates) {
            WriteLE64Truncated(data, i, replacer);
            arg.set_data(CompressImage(data));
            if (!exec()) {
                keep_going = false;
                break;
            }
            // Re-decompress for the next iteration: arg's data is now
            // the compressed mutant, but we kept walking on the
            // decompressed copy. Upstream re-decompresses from data0
            // each loop body to keep memory bounded.
            data = MustDecompressImage(data0);
        }
        // Restore original bytes for the next window position.
        std::memcpy(data.data() + i, original_bytes, avail);
    }
    arg.set_data(data0);
}

// ============================================================
// generate_arg_hints — type dispatch
// ============================================================

void GenerateArgHints(const CompMap& comps,
                      pr::Arg* arg,
                      const pr::Field* field,
                      const std::function<bool()>& exec)
{
    if (arg == nullptr) return;
    const pr::Type* t = arg->type();
    if (t == nullptr || arg->dir() == pr::Dir::kOut) return;

    // Per-Type guards (mirror prog/hints.go:132-163).
    switch (t->kind()) {
    case pr::TypeKind::kProc:
        return;                                  // random proc fails validation
    case pr::TypeKind::kConst:
        if (pr::is_pad(t)) return;               // pad → no-op
        break;
    case pr::TypeKind::kCsum:
        return;                                  // executor recomputes
    case pr::TypeKind::kBuffer: {
        const auto* bt = static_cast<const pr::BufferType*>(t);
        switch (bt->buffer_kind()) {
        case pr::BufferKind::kFilename:
            return;                              // skip — escaping paths
        case pr::BufferKind::kString:
        case pr::BufferKind::kGlob:
            if (!bt->values().empty()) return;   // file enumerations
            break;
        default:
            break;                                // BlobRand / BlobRange / Text / Compressed
        }
        break;
    }
    default:
        break;
    }

    // Arg-class dispatch (mirror prog/hints.go:164-182).
    if (auto* ca = dynamic_cast<pr::ConstArg*>(arg); ca != nullptr) {
        if (TypeBitSize(ca->type()) <= 8) return;   // small enough to brute force
        CheckConstArgHints(*ca, field, comps, exec);
        return;
    }
    if (auto* da = dynamic_cast<pr::DataArg*>(arg); da != nullptr) {
        if (da->size() <= 3) return;                 // too small to be interesting
        const auto* bt = dynamic_cast<const pr::BufferType*>(da->type());
        if (bt != nullptr && bt->buffer_kind() == pr::BufferKind::kCompressed) {
            CheckCompressedArgHints(*da, comps, exec);
        } else {
            CheckDataArgHints(*da, comps, exec);
        }
        return;
    }
    // PointerArg / GroupArg / UnionArg / ResultArg → not directly mutated
    // by hints (foreach_arg recurses into their children).
}

// ============================================================
// mutate_prog_with_hints — top-level entry
// ============================================================

void MutateProgWithHints(const pr::Prog& src,
                         int call_index,
                         const CompMap& comps,
                         const HintsExecCallback& exec)
{
    auto p = pr::DeepClone(src);
    if (p == nullptr || call_index < 0 ||
        static_cast<size_t>(call_index) >= p->calls().size()) {
        return;
    }
    pr::Call* c = p->mutable_calls()[call_index].get();
    bool do_more = true;
    auto exec_validate = [&]() -> bool {
        // [v2 PR-5-C limitation — explicit deferral, plan §10 #16]
        // Upstream `prog/hints.go:105 execValidate` skips the candidate
        // when Target.Sanitize(call, false) OR Prog.checkConditions
        // reports an error. reFuzz's sanitize_call is a
        // sanitizeFix-equivalent NORMALIZER with no error path, and
        // Prog.checkConditions / debug_validate are not yet ported.
        // Effect: a small slice of candidates upstream would reject
        // upfront pass through to exec; the worker rejects them on
        // failed execution. Closing this gap requires a non-fixing
        // sanitize_check or a checkConditions port — both are
        // program/syz schema-service additions tracked in plan §10
        // #16 / D-8 audit, not in PR-5-C scope.
        pr::sanitize_call(*c, *p->target());
        do_more = exec(*p);
        return do_more;
    };

    pr::foreach_arg(c, [&](pr::Arg* a, pr::ArgCtx* ctx) {
        if (!do_more) {
            ctx->stop = true;
            return;
        }
        GenerateArgHints(comps, a, ctx->field, exec_validate);
    });
}

} // namespace refuzz::mutator::syz_v2::hints
