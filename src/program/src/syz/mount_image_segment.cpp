// [chunk-based mount image] See mount_image_segment.hpp. Producer side; the
// consumer is WriteSegmentsToFd in the worker's mount_helpers.cpp. Keep the SEGS
// format in sync between the two.

#include "refuzz/program/syz/mount_image_segment.hpp"

#include "refuzz/program/syz/arg.hpp"   // PointerArg / DataArg / ArgKind
#include "refuzz/program/syz/size.hpp"  // assign_sizes_array (len[img] fixup)

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>
#include <vector>
#include <zlib.h>

namespace refuzz::program::syz {

namespace {

constexpr std::size_t kMaxInflatedBytes = static_cast<std::size_t>(132) << 20;

// Per-program budget for total SEGS bytes. The program wire must stay under
// kExecBufferSize (4 MiB, exec_wire.cpp) or serialize_for_exec drops the program
// ("too large program"). Mount-image programs' non-img args are tiny, so 3.5 MiB
// of segments leaves comfortable headroom. Dense images whose non-zero payload
// would exceed the remaining budget keep their compact zlib bytes (the guest
// decompresses them as before — correct, just no chunk-based speed-up for those).
constexpr std::size_t kProgSegBudget =
    (static_cast<std::size_t>(3) << 20) + (static_cast<std::size_t>(512) << 10);

// Pre-allocated floor for the inflate scratch: covers most images in one shot so
// the common case never re-grows. Doubling from here up to kMaxInflatedBytes.
constexpr std::size_t kInflateFloorBytes = static_cast<std::size_t>(1) << 20;  // 1 MiB

// Inflate `comp` into `scratch`, GROWING scratch on demand to the ACTUAL output
// size — not the 132 MiB worst case — so a small image only ever needs (and only
// zero-fills) a small buffer. Returns produced bytes, or 0 on failure (caller
// keeps the original compressed bytes — fully back-compatible). zlib streams do
// not carry the uncompressed size, so we inflate incrementally (Z_NO_FLUSH) and
// double the buffer whenever it fills, capped at kMaxInflatedBytes.
std::size_t ZlibInflateInto(const std::vector<uint8_t>& comp,
                            std::vector<uint8_t>& scratch) {
    if (comp.size() < 2) {
        return 0;
    }
    z_stream zs = {};
    zs.next_in  = const_cast<Bytef*>(comp.data());
    zs.avail_in = static_cast<uInt>(comp.size());
    if (inflateInit(&zs) != Z_OK) {
        return 0;
    }
    if (scratch.size() < kInflateFloorBytes) {
        scratch.resize(kInflateFloorBytes);  // pre-alloc / reuse the floor
    }
    int ret = Z_OK;
    for (;;) {
        if (zs.total_out == scratch.size()) {            // output buffer full → grow
            if (scratch.size() >= kMaxInflatedBytes) {   // hit the 132 MiB ceiling
                ret = Z_MEM_ERROR;
                break;
            }
            scratch.resize(std::min(kMaxInflatedBytes, scratch.size() * 2));
        }
        // Recompute after every (possibly reallocating) resize.
        zs.next_out  = scratch.data() + zs.total_out;
        zs.avail_out = static_cast<uInt>(scratch.size() - zs.total_out);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK) {
            break;  // Z_STREAM_END (done) or a negative error code
        }
    }
    const std::size_t produced = zs.total_out;
    inflateEnd(&zs);
    return (ret == Z_STREAM_END) ? produced : 0;
}

// Encode raw[0..n) as SEGS: non-zero runs at 1 KiB block granularity, adjacent
// non-zero blocks coalesced (fs metadata is clustered → few segments). Returns
// EMPTY if the encoded size would exceed `max_bytes` — for dense/incompressible
// images the non-zero payload is large and SEGS would blow the 4 MiB program
// wire limit (kExecBufferSize), so the caller keeps the compact zlib bytes and
// the guest decompresses as before. (The size is estimated from the run lengths
// BEFORE allocating, so dense images never build a multi-MiB scratch.)
std::vector<uint8_t> EncodeMountSegments(const uint8_t* raw, std::size_t n,
                                         std::size_t max_bytes) {
    constexpr std::size_t kBlk = 1024;
    auto block_nonzero = [&](std::size_t a, std::size_t b) {
        for (std::size_t j = a; j < b; ++j) {
            if (raw[j] != 0) {
                return true;
            }
        }
        return false;
    };
    std::vector<std::pair<std::size_t, std::size_t>> runs;
    std::size_t i = 0;
    while (i < n) {
        const std::size_t end = std::min(i + kBlk, n);
        if (!block_nonzero(i, end)) {
            i = end;
            continue;
        }
        const std::size_t start = i;
        while (i < n) {
            const std::size_t e2 = std::min(i + kBlk, n);
            if (!block_nonzero(i, e2)) {
                break;
            }
            i = e2;
        }
        runs.emplace_back(start, i);
    }
    // 12-byte header + 12 bytes/segment + the non-zero payload bytes.
    std::size_t est = 12 + runs.size() * 12;
    for (const auto& r : runs) {
        est += (r.second - r.first);
    }
    if (est > max_bytes) {
        return {};  // too large → caller keeps the zlib path
    }
    std::vector<uint8_t> out;
    out.reserve(est);  // exact final size (header + segments + payload) — no doubling over-alloc
    auto put32 = [&](uint32_t v) {
        for (int k = 0; k < 4; ++k) {
            out.push_back(static_cast<uint8_t>(v >> (8 * k)));
        }
    };
    auto put64 = [&](uint64_t v) {
        for (int k = 0; k < 8; ++k) {
            out.push_back(static_cast<uint8_t>(v >> (8 * k)));
        }
    };
    out.push_back('S'); out.push_back('E'); out.push_back('G'); out.push_back('S');
    put32(static_cast<uint32_t>(n));
    put32(static_cast<uint32_t>(runs.size()));
    for (const auto& r : runs) {
        put64(static_cast<uint64_t>(r.first));
        put32(static_cast<uint32_t>(r.second - r.first));
        out.insert(out.end(), raw + r.first, raw + r.second);
    }
    return out;
}

// [dense mount image] Transcode the already-inflated image to a zstd frame. Host-
// side, once per program at load (we already paid the zlib inflate into `scratch`).
// zstd's ratio ≥ zlib so it still fits the program wire even for DENSE images that
// SEGS (uncompressed non-zero runs) can't; the guest then decompresses ~5-15×
// faster than zlib inflate (the per-exec dominant cost). Level 3 = zstd default
// (fast compress, good ratio). ZSTD_compress pledges srcSize into the frame header
// so the guest's ZSTD_getFrameContentSize recovers the size. Returns EMPTY on
// failure (caller keeps the zlib bytes — fully back-compatible). Symbols resolve
// from libzstd.so.1.
extern "C" {
std::size_t ZSTD_compressBound(std::size_t srcSize);
std::size_t ZSTD_compress(void* dst, std::size_t dstCap,
                          const void* src, std::size_t srcSize, int level);
unsigned    ZSTD_isError(std::size_t code);
}

std::vector<uint8_t> ZstdCompressImage(const uint8_t* src, std::size_t n) {
    const std::size_t bound = ZSTD_compressBound(n);
    if (bound == 0) {
        return {};
    }
    std::vector<uint8_t> out(bound);
    const std::size_t w = ZSTD_compress(out.data(), bound, src, n, /*level=*/3);
    if (ZSTD_isError(w) || w == 0) {
        return {};
    }
    out.resize(w);
    // `out` was allocated at ZSTD_compressBound(n) ≈ the inflated image size (up to
    // ~132 MiB). resize() shrinks size to the (small) compressed length but NOT
    // capacity, so without this the corpus DataArg would pin the worst-case buffer
    // for the seed's whole life — the dominant host-RSS cost (vector over-alloc
    // measured at ~83% of corpus memory). shrink_to_fit reallocs to the actual size.
    out.shrink_to_fit();
    return out;
}

}  // namespace

int SegmentizeMountImages(Prog& prog, const Target& target) {
    // Inflate scratch — thread_local so a thread REUSES its buffer across calls
    // (no per-call re-alloc/zero-fill churn). It is bounded two ways so it cannot
    // be the host-OOM source it once was (a `thread_local` resized to the 132 MiB
    // worst case pinned 132 MiB on each of dozens of concurrent minimize/
    // materialize churn threads → RSS climbed to OOM):
    //   (1) 动态增 — ZlibInflateInto grows it only to the ACTUAL image size, so a
    //       small image keeps a small buffer (most images are far below 132 MiB);
    //   (2) 动态减 — the retention trim at the end releases an over-grown buffer
    //       (a one-off btrfs ~128 MiB) instead of pinning it for the thread's life.
    // Net per-thread retention ≤ ~kScratchRetainCap, not 132 MiB. Conversion runs
    // once per program at load; intra-call reuse across a program's img args holds.
    thread_local std::vector<uint8_t> scratch;
    int converted = 0;
    std::size_t seg_used = 0;  // total SEGS bytes added across this program
    for (auto& call : prog.mutable_calls()) {
        if (call->meta() == nullptr) {
            continue;
        }
        const auto& name = call->meta()->call_name();
        if (name.rfind("syz_mount_image", 0) != 0 &&
            name.rfind("syz_read_part_table", 0) != 0) {
            continue;
        }
        bool changed = false;
        for (auto& arg : call->mutable_args()) {
            if (arg->arg_kind() != ArgKind::kPointer) {
                continue;
            }
            auto* pa = static_cast<PointerArg*>(arg.get());
            Arg* pointee = pa->res();
            if (pointee == nullptr || pointee->arg_kind() != ArgKind::kData) {
                continue;
            }
            auto* da = static_cast<DataArg*>(pointee);
            const std::vector<uint8_t>& comp = da->data();
            if (comp.size() < 2 || comp[0] != 0x78) {
                continue;  // not a zlib stream (already SEGS / non-image arg)
            }
            const std::size_t produced = ZlibInflateInto(comp, scratch);
            if (produced == 0) {
                continue;  // inflate failed → keep the compressed bytes
            }
            const std::size_t remaining =
                (seg_used < kProgSegBudget) ? (kProgSegBudget - seg_used) : 0;
            std::vector<uint8_t> segs =
                EncodeMountSegments(scratch.data(), produced, remaining);
            if (segs.empty()) {
                // [dense mount image] SEGS (uncompressed non-zero runs) overflows the
                // wire for dense images. Transcode zlib→zstd rather than keeping the
                // slow-to-inflate zlib: zstd fits the wire (ratio ≥ zlib) AND the guest
                // decompresses ~5-15× faster (zlib inflate is the per-exec dominant
                // cost). Keep zlib only if zstd also overflows the per-program budget.
                std::vector<uint8_t> zfr = ZstdCompressImage(scratch.data(), produced);
                if (zfr.empty() || zfr.size() > remaining) {
                    continue;  // zstd unavailable / still too big → keep zlib
                }
                seg_used += zfr.size();
                da->set_data(std::move(zfr));
                changed = true;
                continue;  // next arg
            }
            seg_used += segs.size();
            da->set_data(std::move(segs));
            changed = true;
        }
        if (changed) {
            // len[img] is a stored ConstArg → recompute it from the new buffer.
            // Seeding autos with the call's top-level args lets assign_sizes_array
            // re-fill the len fields (non-len args are ignored).
            std::unordered_set<const Arg*> autos;
            for (auto& a : call->args()) {
                autos.insert(a.get());
            }
            assign_sizes_array(target, call->mutable_args(),
                               call->meta()->args(), &autos);
            ++converted;
        }
    }
    // [retention bound — 动态减] Release an over-grown scratch so a one-off large
    // image (btrfs ~128 MiB) is not pinned for the thread's whole life across the
    // dozens of concurrent churn threads. The common small buffer (≤ cap) stays
    // resident for reuse. Tunable: higher cap = fewer re-grows / more retained;
    // lower = the opposite. 8 MiB keeps typical fs images, frees the big outliers.
    constexpr std::size_t kScratchRetainCap = static_cast<std::size_t>(8) << 20;
    if (scratch.capacity() > kScratchRetainCap) {
        std::vector<uint8_t>().swap(scratch);  // free the big buffer back to the OS
    }
    return converted;
}

}  // namespace refuzz::program::syz
