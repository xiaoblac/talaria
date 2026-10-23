// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-2 — generate_csum_inet parity vs upstream
// pkg/csource/csource.go::generateCsumInet (lines 428-447).

#include "refuzz/crash/repro/csource/internal/emit_csum.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

namespace em  = ::refuzz::crash::repro::csource::internal;
namespace syz = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

} // namespace

int main() {
    syz::WireCsum csum;
    csum.csum_kind = 0;
    csum.size      = 2;
    syz::WireCsumChunk c1;
    c1.kind          = syz::WireCsumChunkKind::kArgData;
    c1.addr_or_value = 0x40000000;
    c1.size          = 8;
    csum.chunks.push_back(c1);
    syz::WireCsumChunk c2;
    c2.kind          = syz::WireCsumChunkKind::kConst;
    c2.addr_or_value = 0x12345678;
    c2.size          = 4;
    csum.chunks.push_back(c2);

    // data_offset=0 → ArgData addr stays at the literal value supplied.
    auto src = em::generate_csum_inet(/*addr=*/0x50000000, csum,
                                      /*csum_seq=*/3, /*data_offset=*/0);
    std::fprintf(stderr, "%s", src.c_str());

    // Frame
    CHECK(contains(src, "struct csum_inet csum_3;"));
    CHECK(contains(src, "csum_inet_init(&csum_3);"));

    // ArgData chunk: csum_inet_update with literal addr
    CHECK(contains(src, "csum_inet_update(&csum_3, (const uint8*)0x40000000, 8)"));

    // Const chunk i=1: declares uint32 var, then update with addr-of var
    CHECK(contains(src, "uint32 csum_3_chunk_1 = 0x12345678;"));
    CHECK(contains(src, "csum_inet_update(&csum_3, (const uint8*)&csum_3_chunk_1, 4)"));

    // Final store
    CHECK(contains(src, "*(uint16*)0x50000000 = csum_inet_digest(&csum_3)"));

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
