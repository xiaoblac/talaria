#pragma once

// PR-D3 — public surface for the FUSE handler.
//
// Header extracted (B4 review fix 2026-05-06) so that
// `pseudo_fuse_handler_test` and the typed-Target structural drift
// test (B3) can share the same definition with `fuse_dispatcher.cpp`,
// eliminating the prior ODR violation where the test re-declared
// `SyzFuseReqOut` / `SelectFuseResponse` independently.
//
// `SyzFuseReqOut` mirrors upstream `struct syz_fuse_req_out` from
// `executor/common_linux.h:5360` AND the typed-Target wire shape
// emitted by syzgen for the `syz_fuse_handle_req` arg-3 struct
// (derived from upstream syzlang `sys/linux/fuse.txt`). The
// `kSyzFuseReqOutFieldOrder[]` array below is the canonical reFuzz-side
// view of that ordering — `pseudo_fuse_handler_test` walks the typed
// Target at runtime and asserts `Target::find_syscall("syz_fuse_handle_req")`
// arg-3 struct has fields in this exact order. If upstream syzlang
// reorders the struct, the typed Target will reflect the new order
// while this header still has the old → test fails before the wrong
// memory is dereferenced. Closes closure §7-3 "no two target sources
// of truth" silent-drift gap.

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cstdint>
#include <linux/fuse.h>
#include <string_view>

namespace refuzz::worker::pseudo {

// 17 pointers, exact order — must match upstream syzlang field order
// for `syz_fuse_req_out` in `sys/linux/fuse.txt`. See
// `kSyzFuseReqOutFieldOrder` below for the runtime contract.
struct SyzFuseReqOut {
    struct fuse_out_header* init;
    struct fuse_out_header* lseek;
    struct fuse_out_header* bmap;
    struct fuse_out_header* poll;
    struct fuse_out_header* getxattr;
    struct fuse_out_header* lk;
    struct fuse_out_header* statfs;
    struct fuse_out_header* write;
    struct fuse_out_header* read;
    struct fuse_out_header* open;
    struct fuse_out_header* attr;
    struct fuse_out_header* entry;
    struct fuse_out_header* dirent;
    struct fuse_out_header* direntplus;
    struct fuse_out_header* create_open;
    struct fuse_out_header* ioctl;
    struct fuse_out_header* statx;
};

// Canonical reFuzz-side field order. Test asserts the typed Target's
// arg-3 struct has fields in this exact order. KEEP IN SYNC with the
// `SyzFuseReqOut` struct above; a CI structural test pins both against
// the typed Target.
inline constexpr std::array<std::string_view, 17> kSyzFuseReqOutFieldOrder = {
    "init",
    "lseek",
    "bmap",
    "poll",
    "getxattr",
    "lk",
    "statfs",
    "write",
    "read",
    "open",
    "attr",
    "entry",
    "dirent",
    "direntplus",
    "create_open",
    "ioctl",
    "statx",
};

// Result of opcode → response-header routing.
struct FuseOpcodeRoute {
    fuse_out_header* hdr;
    bool             no_reply;
    bool             unknown_opcode;
};

// Pure function — opcode → req_out field mapping. See
// `fuse_dispatcher.cpp` for the full switch derivation against
// upstream `executor/common_linux.h:5440-5485`.
FuseOpcodeRoute SelectFuseResponse(std::uint32_t opcode,
                                   SyzFuseReqOut* req_out);

// Domain-level dispatcher entry. Called from `pseudo_dispatcher.cpp`
// when `meta.domain == PseudoDomain::kFuse`.
PseudoResult DispatchFusePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);

} // namespace refuzz::worker::pseudo
