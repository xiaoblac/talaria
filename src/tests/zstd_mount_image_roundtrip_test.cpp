// Validates the self-declared zstd FFI used by the dense mount-image fast path
// (no libzstd -dev headers on the host → prototypes declared by hand in
// program/src/syz/mount_image_segment.cpp and worker mount_helpers.cpp). This
// guards the ABI: ZSTD_compress must pledge the content size into the frame so the
// guest's ZSTD_getFrameContentSize recovers it, the frame must start with the magic
// HasZstdMagic keys on (0x28 B5 2F FD), and decompress must round-trip to identity.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
std::size_t        ZSTD_compressBound(std::size_t srcSize);
std::size_t        ZSTD_compress(void* dst, std::size_t dstCap,
                                 const void* src, std::size_t srcSize, int level);
unsigned           ZSTD_isError(std::size_t code);
unsigned long long ZSTD_getFrameContentSize(const void* src, std::size_t srcSize);
std::size_t        ZSTD_decompress(void* dst, std::size_t dstCap,
                                   const void* src, std::size_t srcSize);
}

int main()
{
    int fails = 0;

    // 256 KiB "dense-ish" image: structured non-zero payload + periodic zero runs,
    // like a real fs image (so SEGS-uncompressed would be large but zstd compresses).
    std::vector<uint8_t> img(256 * 1024);
    for (std::size_t i = 0; i < img.size(); ++i) {
        img[i] = (i % 4096 < 3000)
                     ? static_cast<uint8_t>((i * 2654435761u) >> 24)
                     : 0;
    }

    const std::size_t bound = ZSTD_compressBound(img.size());
    if (bound == 0) { std::fprintf(stderr, "FAIL compressBound==0\n"); return 1; }
    std::vector<uint8_t> comp(bound);
    const std::size_t csz =
        ZSTD_compress(comp.data(), bound, img.data(), img.size(), /*level=*/3);
    if (ZSTD_isError(csz) || csz == 0) { std::fprintf(stderr, "FAIL compress\n"); return 1; }
    comp.resize(csz);

    // magic — exactly what mount_helpers::HasZstdMagic checks.
    if (!(comp.size() >= 4 && comp[0] == 0x28 && comp[1] == 0xB5 &&
          comp[2] == 0x2F && comp[3] == 0xFD)) {
        std::fprintf(stderr, "FAIL magic %02x %02x %02x %02x\n",
                     comp[0], comp[1], comp[2], comp[3]);
        ++fails;
    }

    // content size must be pledged into the frame (guest sizes the memfd from it).
    const unsigned long long content =
        ZSTD_getFrameContentSize(comp.data(), comp.size());
    if (content != img.size()) {
        std::fprintf(stderr, "FAIL content size %llu != %zu\n", content, img.size());
        ++fails;
    }

    // round-trip identity (what DecompressZstdToFd relies on).
    std::vector<uint8_t> out(img.size());
    const std::size_t dsz =
        ZSTD_decompress(out.data(), out.size(), comp.data(), comp.size());
    if (ZSTD_isError(dsz) || dsz != img.size() ||
        std::memcmp(out.data(), img.data(), img.size()) != 0) {
        std::fprintf(stderr, "FAIL round-trip dsz=%zu\n", dsz);
        ++fails;
    }

    std::fprintf(stdout, "zstd mount-image roundtrip: img=%zuB comp=%zuB ratio=%.2fx %s\n",
                 img.size(), comp.size(),
                 static_cast<double>(img.size()) / static_cast<double>(comp.size()),
                 fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
