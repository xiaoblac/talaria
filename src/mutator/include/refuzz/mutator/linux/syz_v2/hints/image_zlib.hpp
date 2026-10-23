// image_zlib.hpp — Epic 5 PR-5-C
//
// Minimal port of `pkg/image/image.go::Compress` and `MustDecompress`
// for `BufferKind::kCompressed` hints. reFuzz already pulls in libz
// (worker-side mount image decompress); this wraps the deflate / inflate
// surface at the hints-port level. Scope is limited to what
// CheckCompressedArgHints needs:
//
//   - Compress(data) → zlib-wrapped deflate stream (Z_DEFAULT_COMPRESSION).
//   - MustDecompress(data) → throws std::runtime_error on malformed stream.
//
// If a future component (e.g. crash repro inflater) needs the same
// helpers, lift this pair to `program/syz/image/` and add a thin C
// shim. For now hints is the only consumer.

#pragma once

#include <cstdint>
#include <vector>

namespace refuzz::mutator::syz_v2::hints {

std::vector<uint8_t> CompressImage(const std::vector<uint8_t>& data);

// Throws std::runtime_error on malformed input. Mirrors upstream's
// `MustDecompress` panic semantics, adapted to C++ exceptions.
std::vector<uint8_t> MustDecompressImage(const std::vector<uint8_t>& data);

} // namespace refuzz::mutator::syz_v2::hints
