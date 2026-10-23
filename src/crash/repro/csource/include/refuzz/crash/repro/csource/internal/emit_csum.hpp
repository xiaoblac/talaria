// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::generateCsumInet
// (lines 428-447). Emits the C source fragment that computes an
// inet checksum over a sequence of WireCsumChunks.

#pragma once

#include "refuzz/program/syz/exec_wire_decode.hpp"

#include <cstdint>
#include <string>

namespace refuzz::crash::repro::csource::internal {

// Returns the multi-line C fragment computing checksum #csum_seq for
// the given WireCsum, followed by the store at `addr`. `addr` and
// every WireCsumChunk.kArgData chunk address are absolute (the
// caller already added target.data_offset() before calling this —
// matches upstream DeserializeExec which rebases at decode time).
std::string generate_csum_inet(uint64_t addr,
                               const ::refuzz::program::syz::WireCsum& csum,
                               int csum_seq,
                               uint64_t data_offset);

} // namespace refuzz::crash::repro::csource::internal
