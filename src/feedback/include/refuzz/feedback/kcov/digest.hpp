// Layer-3 milestone III.11 — KCOV digest used by paired-VM stdio harnesses.
//
// Both the reFuzz wire-driver harness (III.10) and the syzkaller-executor
// shim (III.9) compute this digest from their captured PC list per
// program. The paired orchestrator (III.12) byte-compares the resulting
// hex strings — equality means the kernel control-flow PC sets agree.
//
// Algorithm: FNV-1a 64-bit over sorted+deduped little-endian uint64 PCs.
// Chosen for:
//   - identical bit-for-bit reproducibility across Go and C++ implementations,
//   - no external crypto dependency,
//   - cheap (PC sets are typically <100k entries),
//   - good-enough collision resistance for diffing equal vs different runs
//     (we are not building a cryptographic identity here).
//
// The output is rendered as 16 lowercase hex chars (8 bytes). Both
// stdio harnesses must emit `kcov_digest` in this exact form.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace refuzz::feedback::kcov {

// FNV-1a 64-bit constants per the reference algorithm.
inline constexpr uint64_t kFnvOffsetBasis = 0xcbf29ce484222325ULL;
inline constexpr uint64_t kFnvPrime       = 0x100000001b3ULL;

// Fold one byte into an in-progress hash.
inline void digest_update(uint64_t& h, uint8_t b) {
    h ^= static_cast<uint64_t>(b);
    h *= kFnvPrime;
}

// Sort + dedupe + FNV-1a hash. Modifies `pcs` in place (caller's vector
// is sorted+deduped on return).
inline uint64_t hash_pcs(std::vector<uint64_t>& pcs) {
    std::sort(pcs.begin(), pcs.end());
    pcs.erase(std::unique(pcs.begin(), pcs.end()), pcs.end());
    uint64_t h = kFnvOffsetBasis;
    for (uint64_t pc : pcs) {
        for (int s = 0; s < 64; s += 8) {
            digest_update(h, static_cast<uint8_t>(pc >> s));
        }
    }
    return h;
}

// Render h as 16 lowercase hex characters (8 bytes, big-endian for visual
// readability — both implementations emit the same string).
inline std::string format_digest(uint64_t h) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    return std::string(buf, 16);
}

inline std::string compute_kcov_digest(std::vector<uint64_t> pcs) {
    return format_digest(hash_pcs(pcs));
}

// [K3] sort+dedupe `pcs` in place AND return both digest + raw hex stream.
// `pcs_hex_out` 是 continuous 16-hex-char/uint64 concat,Go side 按每 16 字符
// chunk 解析 (strconv.ParseUint base 16) → []uint64,用作 Jaccard 集合运算。
// FNV 比较仍走 digest,跟新算法并行;两个数据都进 JSONL,Go 那边都算,
// 报告同时显示 byte-equal-mismatch 和 jaccard-below-threshold。
inline std::string compute_kcov_digest_and_pcs_hex(
    std::vector<uint64_t>& pcs, std::string* pcs_hex_out)
{
    const uint64_t h = hash_pcs(pcs);  // pcs is sorted+deduped after this.
    if (pcs_hex_out != nullptr) {
        pcs_hex_out->clear();
        pcs_hex_out->reserve(pcs.size() * 16);
        char buf[17];
        for (uint64_t pc : pcs) {
            std::snprintf(buf, sizeof(buf), "%016llx",
                          static_cast<unsigned long long>(pc));
            pcs_hex_out->append(buf, 16);
        }
    }
    return format_digest(h);
}

} // namespace refuzz::feedback::kcov
