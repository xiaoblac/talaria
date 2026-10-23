#pragma once

#include <cstdint>

namespace refuzz::fuzzer {

constexpr uint32_t kCoverageFileMagic = 0x48535643u;   // "CVSH" little-endian

// [v2 batch 3 PR-Y — 直升 v2,per-entry 16 字节(hash uint64 + prio uint8 + 7 byte padding)]
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-Y D3。
// v1 file 加载走 LoadFromFile v1 legacy path(log warn + return true,seen_ 起空,
// 下次 Save 自然 v2 覆盖),不留 v1 reader。
constexpr uint16_t kCoverageFileVersion       = 2;
constexpr uint16_t kCoverageFileVersionV1Legacy = 1;  // 仅给 LoadFromFile 识别迁移用
constexpr uint16_t kCoverageFileFlagLE = 0x0001;       // bit0=1: little-endian

struct CoverageFileHeader {
    uint32_t magic = kCoverageFileMagic;
    uint16_t version = kCoverageFileVersion;
    uint16_t flags = kCoverageFileFlagLE;
    uint64_t count = 0;
    uint64_t reserved = 0;
};

static_assert(sizeof(CoverageFileHeader) == 24, "CoverageFileHeader must be 24 bytes");

// [v2 batch 3 PR-Y] V2 entry layout(per-entry 16 字节):
//   uint64 hash + uint8 prio + 7 byte zero padding
// 16-byte align 简化 read/write,prio 字段独立可读。
//
// **Padding invariant (PR-Y follow-up nit #3)**:7 个 pad{0..6} 字段必须
// **default-init = 0**。`CoverageFileEntryV2 e;` 之后即可直接 memcpy 落盘,
// 不需要先 memset / set padding;盘上字节确定为 zero padding。任何修改:
//   * 不能改用未初始化字段(uint8_t pad0;)—— 会产生 stale stack bytes
//     letak 写盘 + 让 memcmp 在测试里 flaky
//   * 不能加 union 或 non-trivial-init 字段(struct member init 必须 trivial
//     literal,std::is_trivial_v 触发 static_assert 失败)
//
// invariant 持有者:此 hpp 注释 + static_assert(sizeof) + 任何 future audit
// 不需要 memset 验证 padding == 0。
struct CoverageFileEntryV2 {
    uint64_t hash    = 0;
    uint8_t  prio    = 0;
    uint8_t  pad0    = 0;
    uint8_t  pad1    = 0;
    uint8_t  pad2    = 0;
    uint8_t  pad3    = 0;
    uint8_t  pad4    = 0;
    uint8_t  pad5    = 0;
    uint8_t  pad6    = 0;
};

static_assert(sizeof(CoverageFileEntryV2) == 16,
              "CoverageFileEntryV2 must be 16 bytes(8 hash + 1 prio + 7 padding)");

} // namespace refuzz::fuzzer
