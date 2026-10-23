// Checksum analysis pass — mirror of prog/checksum.go.
//
// Identifies CsumType fields in a Call, classifies them inet vs pseudo,
// extracts the IP src/dst args (for pseudo), and produces:
//   - csum_map:  arg → CsumInfo (kind + chunk list, used by exec wire encoder)
//   - csum_uses: set of args whose value contributes to a csum (so the
//                encoder retains their copyout records)
//
// Pure schema-derived analysis on the materialized arg tree; no IR mutation.

#pragma once

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::program::syz {

enum class CsumChunkKind : uint8_t {
    kArg   = 0,
    kConst = 1,
};

struct CsumChunk {
    CsumChunkKind kind  = CsumChunkKind::kArg;
    Arg*          arg   = nullptr;  // for kArg
    uint64_t      value = 0;        // for kConst
    uint64_t      size  = 0;        // for kConst
};

struct CsumInfo {
    CsumKind               kind = CsumKind::kInet;
    std::vector<CsumChunk> chunks;
};

struct CsumAnalysis {
    std::unordered_map<Arg*, CsumInfo> csum_map;   // csum-arg → its info
    std::unordered_set<Arg*>           csum_uses;  // args contributing to any csum
};

// Mirror of prog.calcChecksumsCall — empty result if no csum fields.
CsumAnalysis calc_checksums_call(Call* c);

} // namespace refuzz::program::syz
