// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.

#include "refuzz/crash/repro/csource/internal/emit_csum.hpp"

#include <format>
#include <sstream>

namespace refuzz::crash::repro::csource::internal {

namespace syz = ::refuzz::program::syz;

std::string generate_csum_inet(uint64_t addr,
                               const syz::WireCsum& csum, int csum_seq,
                               uint64_t data_offset) {
    std::ostringstream w;
    w << std::format("\tstruct csum_inet csum_{};\n", csum_seq);
    w << std::format("\tcsum_inet_init(&csum_{});\n", csum_seq);
    for (std::size_t i = 0; i < csum.chunks.size(); ++i) {
        const auto& chunk = csum.chunks[i];
        switch (chunk.kind) {
            case syz::WireCsumChunkKind::kArgData: {
                // Mirror upstream DeserializeExec (decodeexec.go:233):
                // addr += target.DataOffset for ArgData kind only.
                const uint64_t abs_addr = chunk.addr_or_value + data_offset;
                w << std::format(
                    "\tNONFAILING(csum_inet_update(&csum_{}, "
                    "(const uint8*)0x{:x}, {}));\n",
                    csum_seq, abs_addr, chunk.size);
                break;
            }
            case syz::WireCsumChunkKind::kConst:
                w << std::format(
                    "\tuint{} csum_{}_chunk_{} = 0x{:x};\n",
                    chunk.size * 8, csum_seq, i, chunk.addr_or_value);
                w << std::format(
                    "\tcsum_inet_update(&csum_{}, "
                    "(const uint8*)&csum_{}_chunk_{}, {});\n",
                    csum_seq, csum_seq, i, chunk.size);
                break;
        }
    }
    w << std::format(
        "\tNONFAILING(*(uint16*)0x{:x} = csum_inet_digest(&csum_{}));\n",
        addr, csum_seq);
    return w.str();
}

} // namespace refuzz::crash::repro::csource::internal
