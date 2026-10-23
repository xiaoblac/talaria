// PR-D3 — syz_fuse_handle_req handler.
//
// Mirrors upstream `executor/common_linux.h:5402-5470` semantics:
// caller program owns the /dev/fuse fd (opened via openat in a prior
// real syscall), passes it in as a0; handler reads one FUSE request
// from that fd, picks the matching `fuse_out_header*` from the caller-
// supplied `syz_fuse_req_out` struct by opcode, and writes it back as
// the response. Stateless, reactive, single-shot per call — no
// persistent state, no pre-program setup hook required (per plan §5.2:
// "If a Tier 3 PR finds it needs to add a field to PseudoRuntimeContext
// itself, that triggers §8 stop"; FUSE doesn't, so no field added).
//
// Subdir layout per plan §5.2 Tier 3 convention. State.cpp / Helpers.cpp
// not created — single file is sufficient for one stateless pseudo;
// per §10 Q4 opcode demux is a free function inline (no extracted helper
// library — only one consumer in this plan).
//
// Cap requirement: kCapNone (handler itself doesn't touch /dev/fuse;
// caller already owns the fd). Kernel module `fuse` must be loaded by
// operator/profile — same operator-preload pattern as PR-B3 hwsim
// (plan §10 Q6); if absent, caller's openat(/dev/fuse) fails before
// any fuse pseudo runs.

#include "worker/backend/pseudo/fuse/fuse_dispatcher.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unistd.h>

// FUSE_STATX was added in Linux 6.5 (commit 73c80b1e2bba). Older build
// hosts do not expose it from <linux/fuse.h>. Define locally; mirrors
// upstream syzkaller's same fallback pattern (`executor/common_linux.h`
// uses the numeric opcode 76 directly when needed). When the kernel
// receiving the response is also pre-6.5, this opcode never arrives —
// dead branch but compile-clean.
#ifndef FUSE_STATX
#define FUSE_STATX 76
#endif

namespace refuzz::worker::pseudo {

// Pure function — matches upstream `syz_fuse_handle_req` switch
// (`executor/common_linux.h:5440-5480`) opcode → req_out field mapping.
// For "header-only-reply" opcodes (RMDIR/RENAME/...), this routine
// truncates `req_out->init->len` to bare `fuse_out_header` size (mirror
// upstream side-effect at `common_linux.h:5470`).
//
// Exposed for `pseudo_fuse_handler_test`.
FuseOpcodeRoute SelectFuseResponse(std::uint32_t opcode,
                                   SyzFuseReqOut* req_out)
{
    FuseOpcodeRoute r{nullptr, false, false};
    switch (opcode) {
    case FUSE_GETATTR:
    case FUSE_SETATTR:
        r.hdr = req_out->attr;
        return r;
    case FUSE_LOOKUP:
    case FUSE_SYMLINK:
    case FUSE_LINK:
    case FUSE_MKNOD:
    case FUSE_MKDIR:
        r.hdr = req_out->entry;
        return r;
    case FUSE_OPEN:
    case FUSE_OPENDIR:
        r.hdr = req_out->open;
        return r;
    case FUSE_STATFS:
        r.hdr = req_out->statfs;
        return r;
    case FUSE_RMDIR:
    case FUSE_RENAME:
    case FUSE_RENAME2:
    case FUSE_FALLOCATE:
    case FUSE_SETXATTR:
    case FUSE_REMOVEXATTR:
    case FUSE_FSYNCDIR:
    case FUSE_FSYNC:
    case FUSE_SETLKW:
    case FUSE_SETLK:
    case FUSE_ACCESS:
    case FUSE_FLUSH:
    case FUSE_RELEASE:
    case FUSE_RELEASEDIR:
    case FUSE_UNLINK:
    case FUSE_DESTROY:
        // Header-only reply: caller picks req_out->init and truncates
        // its len to bare fuse_out_header (mirror upstream).
        if (req_out->init != nullptr) {
            req_out->init->len = sizeof(fuse_out_header);
        }
        r.hdr = req_out->init;
        return r;
    case FUSE_READ:
        r.hdr = req_out->read;
        return r;
    case FUSE_READDIR:
        r.hdr = req_out->dirent;
        return r;
    case FUSE_READDIRPLUS:
        r.hdr = req_out->direntplus;
        return r;
    case FUSE_INIT:
        r.hdr = req_out->init;
        return r;
    case FUSE_LSEEK:
        r.hdr = req_out->lseek;
        return r;
    case FUSE_GETLK:
        r.hdr = req_out->lk;
        return r;
    case FUSE_BMAP:
        r.hdr = req_out->bmap;
        return r;
    case FUSE_POLL:
        r.hdr = req_out->poll;
        return r;
    case FUSE_GETXATTR:
    case FUSE_LISTXATTR:
        r.hdr = req_out->getxattr;
        return r;
    case FUSE_WRITE:
    case FUSE_COPY_FILE_RANGE:
        r.hdr = req_out->write;
        return r;
    case FUSE_FORGET:
    case FUSE_BATCH_FORGET:
        // No reply expected — handler returns 0 immediately.
        r.no_reply = true;
        return r;
    case FUSE_CREATE:
        r.hdr = req_out->create_open;
        return r;
    case FUSE_IOCTL:
        r.hdr = req_out->ioctl;
        return r;
    case FUSE_STATX:
        r.hdr = req_out->statx;
        return r;
    default:
        r.unknown_opcode = true;
        return r;
    }
}

namespace {

bool HasBaseName(const char* name, const char* base)
{
    if (name == nullptr) {
        return false;
    }
    const std::size_t n = std::strlen(base);
    return std::strncmp(name, base, n) == 0 &&
           (name[n] == '\0' || name[n] == '$');
}

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

// syz_fuse_handle_req(fd, buf, buf_len, req_out)
//   a0 = fd to /dev/fuse (opened by caller)
//   a1 = read buffer
//   a2 = buffer length (must be >= FUSE_MIN_READ_BUFFER)
//   a3 = SyzFuseReqOut* with 17 pre-fuzzed response headers
PseudoResult SyzFuseHandleReq(const PseudoContext& ctx,
                              const intptr_t* args,
                              uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 4) {
        return Error(EINVAL);
    }

    auto* req_out = reinterpret_cast<SyzFuseReqOut*>(args[3]);
    auto* buf     = reinterpret_cast<char*>(args[1]);
    const auto buf_len = static_cast<int>(args[2]);
    const int  fd      = static_cast<int>(args[0]);

    if (req_out == nullptr) {
        return PseudoResult{-1, 0};  // mirror upstream debug-log + return -1
    }
    if (buf_len < static_cast<int>(FUSE_MIN_READ_BUFFER)) {
        return PseudoResult{-1, 0};
    }
    if (buf == nullptr) {
        return PseudoResult{-1, 0};
    }

    errno = 0;
    const ssize_t ret = read(fd, buf, buf_len);
    if (ret < 0) {
        return PseudoResult{-1, errno};
    }
    if (static_cast<std::size_t>(ret) < sizeof(fuse_in_header)) {
        return PseudoResult{-1, 0};
    }
    const auto* in_hdr = reinterpret_cast<const fuse_in_header*>(buf);
    if (in_hdr->len > static_cast<std::uint32_t>(ret)) {
        return PseudoResult{-1, 0};
    }

    const FuseOpcodeRoute route = SelectFuseResponse(in_hdr->opcode, req_out);
    if (route.no_reply) {
        return PseudoResult{0, 0};
    }
    if (route.unknown_opcode) {
        return PseudoResult{-1, 0};
    }
    if (route.hdr == nullptr) {
        return PseudoResult{-1, 0};
    }

    // Link reply to request and write to /dev/fuse — mirror upstream
    // fuse_send_response (`common_linux.h:5381`).
    route.hdr->unique = in_hdr->unique;
    errno = 0;
    if (write(fd, route.hdr, route.hdr->len) < 0) {
        return PseudoResult{-1, errno};
    }
    return PseudoResult{0, 0};
}

} // namespace

PseudoResult DispatchFusePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc)
{
    if (HasBaseName(meta.name, "syz_fuse_handle_req")) {
        return SyzFuseHandleReq(ctx, args, argc);
    }
    return Error(ENOSYS);
}

} // namespace refuzz::worker::pseudo
