// image_zlib.cpp — Epic 5 PR-5-C. See image_zlib.hpp.

#include "refuzz/mutator/linux/syz_v2/hints/image_zlib.hpp"

#include <stdexcept>
#include <string>
#include <zlib.h>

namespace refuzz::mutator::syz_v2::hints {

std::vector<uint8_t> CompressImage(const std::vector<uint8_t>& data) {
    z_stream zs{};
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {
        throw std::runtime_error("zlib deflateInit failed");
    }
    zs.next_in  = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    std::vector<uint8_t> out;
    out.resize(deflateBound(&zs, static_cast<uLong>(data.size())));
    zs.next_out  = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());

    const int rc = deflate(&zs, Z_FINISH);
    if (rc != Z_STREAM_END) {
        deflateEnd(&zs);
        throw std::runtime_error(std::string("zlib deflate failed: rc=") +
                                 std::to_string(rc));
    }
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

std::vector<uint8_t> MustDecompressImage(const std::vector<uint8_t>& data) {
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) {
        throw std::runtime_error("zlib inflateInit failed");
    }
    zs.next_in  = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));
    zs.avail_in = static_cast<uInt>(data.size());

    std::vector<uint8_t> out;
    constexpr size_t kChunk = 4096;
    while (true) {
        const size_t produced = zs.total_out;
        out.resize(produced + kChunk);
        zs.next_out  = reinterpret_cast<Bytef*>(out.data() + produced);
        zs.avail_out = static_cast<uInt>(kChunk);
        const int rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) {
            inflateEnd(&zs);
            throw std::runtime_error(std::string("zlib inflate failed: rc=") +
                                     std::to_string(rc));
        }
        if (zs.avail_out != 0) {
            // Need more input but stream said OK with no progress: malformed.
            inflateEnd(&zs);
            throw std::runtime_error("zlib inflate stalled before end-of-stream");
        }
    }
    out.resize(zs.total_out);
    inflateEnd(&zs);
    return out;
}

} // namespace refuzz::mutator::syz_v2::hints
