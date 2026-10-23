// [chunk-based mount image] Convert syz_mount_image / syz_read_part_table img
// args from a zlib blob into the uncompressed non-zero-segment "SEGS" format,
// ONCE at corpus load / artifact materialization, so the guest materializes the
// loop backing sparsely with NO per-exec zlib decompress (mirrors modern
// syzkaller's image disassembly into non-zero segments).
//
// CONSUMER (must stay in sync with the SEGS format below):
//   executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
//   :: WriteSegmentsToFd  (detects 'S','E','G','S' magic; zlib begins 0x78 so
//                          there is no collision with the legacy compressed path)
//
// SEGS wire format (little-endian, x86):
//   [4]   'S','E','G','S'
//   [4]   u32 total_size   (decompressed image size = loop backing size)
//   [4]   u32 nseg
//   nseg × { u64 offset; u32 len; u8 data[len] }   (non-zero runs only)
#pragma once

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

namespace refuzz::program::syz {

// Walks `prog`; for each syz_mount_image / syz_read_part_table call, replaces a
// zlib-compressed img DataArg with SEGS bytes and re-fixes len[img] (via
// assign_sizes_array). Returns the number of img args converted. Idempotent:
// skips data that is not a zlib stream (already-SEGS / non-image args). On
// inflate failure the original compressed bytes are kept (fully back-compatible
// — the guest then falls back to the zlib path).
int SegmentizeMountImages(Prog& prog, const Target& target);

}  // namespace refuzz::program::syz
