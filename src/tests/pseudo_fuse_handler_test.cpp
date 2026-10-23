// PR-D3 — syz_fuse_handle_req handler tests.
//
// Two test layers:
//   1. SelectFuseResponse (pure opcode-demux function) drives fixtures
//      for every opcode covered by upstream `executor/common_linux.h:
//      5440-5485`. Mechanism (b) hand-derive per plan §7.1.
//   2. Full handler exercised via socketpair: write a synthesized
//      fuse_in_header into one end, hand the other end to the handler,
//      capture what it writes back. Verifies read+route+write integration
//      without needing /dev/fuse.

// PR-D3 review B4 fix: include the public header instead of redeclaring.
// Eliminates the prior ODR violation where the test had its own copy of
// SyzFuseReqOut / SelectFuseResponse / DispatchFusePseudo.
#include "worker/backend/pseudo/fuse/fuse_dispatcher.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/fuse.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <vector>

#ifndef FUSE_STATX
#define FUSE_STATX 76
#endif

namespace {

namespace pseudo = refuzz::worker::pseudo;

// Build a SyzFuseReqOut where every field points to a unique fuse_out_header
// (so test can assert "handler picked the right field" by pointer identity).
struct FullReqOutFixture {
    fuse_out_header init       { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header lseek      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header bmap       { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header poll       { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header getxattr   { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header lk         { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header statfs     { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header write_     { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header read_      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header open_      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header attr       { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header entry      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header dirent     { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header direntplus { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header create_open{ static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header ioctl      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };
    fuse_out_header statx      { static_cast<std::uint32_t>(sizeof(fuse_out_header)), 0, 0 };

    pseudo::SyzFuseReqOut View()
    {
        return {
            &init, &lseek, &bmap, &poll, &getxattr, &lk, &statfs,
            &write_, &read_, &open_, &attr, &entry, &dirent,
            &direntplus, &create_open, &ioctl, &statx,
        };
    }
};

// ---- SelectFuseResponse opcode-demux unit tests ---------------------

void AssertRoutesTo(std::uint32_t opcode, fuse_out_header* expected,
                    FullReqOutFixture& fix)
{
    auto req = fix.View();
    auto r = pseudo::SelectFuseResponse(opcode, &req);
    assert(!r.unknown_opcode);
    assert(!r.no_reply);
    assert(r.hdr == expected);
}

void TestRouteAttrOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_GETATTR, &fix.attr, fix);
    AssertRoutesTo(FUSE_SETATTR, &fix.attr, fix);
}

void TestRouteEntryOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_LOOKUP,  &fix.entry, fix);
    AssertRoutesTo(FUSE_SYMLINK, &fix.entry, fix);
    AssertRoutesTo(FUSE_LINK,    &fix.entry, fix);
    AssertRoutesTo(FUSE_MKNOD,   &fix.entry, fix);
    AssertRoutesTo(FUSE_MKDIR,   &fix.entry, fix);
}

void TestRouteOpenOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_OPEN,    &fix.open_, fix);
    AssertRoutesTo(FUSE_OPENDIR, &fix.open_, fix);
}

void TestRouteSingletonOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_STATFS,      &fix.statfs,      fix);
    AssertRoutesTo(FUSE_READ,        &fix.read_,       fix);
    AssertRoutesTo(FUSE_READDIR,     &fix.dirent,      fix);
    AssertRoutesTo(FUSE_READDIRPLUS, &fix.direntplus,  fix);
    AssertRoutesTo(FUSE_INIT,        &fix.init,        fix);
    AssertRoutesTo(FUSE_LSEEK,       &fix.lseek,       fix);
    AssertRoutesTo(FUSE_GETLK,       &fix.lk,          fix);
    AssertRoutesTo(FUSE_BMAP,        &fix.bmap,        fix);
    AssertRoutesTo(FUSE_POLL,        &fix.poll,        fix);
    AssertRoutesTo(FUSE_CREATE,      &fix.create_open, fix);
    AssertRoutesTo(FUSE_IOCTL,       &fix.ioctl,       fix);
    AssertRoutesTo(FUSE_STATX,       &fix.statx,       fix);
}

void TestRouteXattrOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_GETXATTR,  &fix.getxattr, fix);
    AssertRoutesTo(FUSE_LISTXATTR, &fix.getxattr, fix);
}

void TestRouteWriteOps()
{
    FullReqOutFixture fix;
    AssertRoutesTo(FUSE_WRITE,           &fix.write_, fix);
    AssertRoutesTo(FUSE_COPY_FILE_RANGE, &fix.write_, fix);
}

void TestHeaderOnlyOpsTruncateInit()
{
    FullReqOutFixture fix;
    fix.init.len = 999;  // pre-fuzzed length
    auto req = fix.View();
    auto r = pseudo::SelectFuseResponse(FUSE_RMDIR, &req);
    assert(!r.unknown_opcode);
    assert(!r.no_reply);
    assert(r.hdr == &fix.init);
    // Side-effect: init->len truncated to bare fuse_out_header (mirror upstream)
    assert(fix.init.len == sizeof(fuse_out_header));
}

void TestForgetOpsHaveNoReply()
{
    FullReqOutFixture fix;
    auto req = fix.View();
    auto r1 = pseudo::SelectFuseResponse(FUSE_FORGET, &req);
    assert(r1.no_reply);
    assert(!r1.unknown_opcode);
    auto r2 = pseudo::SelectFuseResponse(FUSE_BATCH_FORGET, &req);
    assert(r2.no_reply);
    assert(!r2.unknown_opcode);
}

void TestUnknownOpcodeFlagged()
{
    FullReqOutFixture fix;
    auto req = fix.View();
    auto r = pseudo::SelectFuseResponse(0xdead, &req);
    assert(r.unknown_opcode);
    assert(!r.no_reply);
    assert(r.hdr == nullptr);
}

void TestNullFieldRoutesNullHdr()
{
    // Request opcode whose req_out field is null → handler returns -1
    // upstream-style. Verify hdr==nullptr is surfaced (caller decides).
    FullReqOutFixture fix;
    fix.read_.len = 0;  // unused (we'll null the pointer)
    auto req = fix.View();
    req.read = nullptr;
    auto r = pseudo::SelectFuseResponse(FUSE_READ, &req);
    assert(r.hdr == nullptr);
    assert(!r.no_reply);
    assert(!r.unknown_opcode);
}

// ---- End-to-end via socketpair --------------------------------------

refuzz::fuzzer::syz::PseudoMeta MetaFor(const char* name)
{
    refuzz::fuzzer::syz::PseudoMeta m{};
    m.name = name;
    return m;
}

// Write a synthesized fuse_in_header into `write_end`, then dispatch
// the handler with `read_end` as fd. Returns whatever the handler wrote
// back into `write_end` (read from `read_end_observer`).
struct EndToEndOutcome {
    refuzz::worker::PseudoResult result;
    std::vector<char>            response_bytes;  // empty if handler didn't write
};

EndToEndOutcome RunEndToEnd(std::uint32_t opcode, FullReqOutFixture& fix)
{
    int sv[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    assert(rc == 0);
    const int handler_fd  = sv[0];
    const int writer_fd   = sv[1];

    // Build request
    fuse_in_header req{};
    req.len    = sizeof(fuse_in_header);
    req.opcode = opcode;
    req.unique = 0xCAFEBABE;
    rc = (int)write(writer_fd, &req, sizeof(req));
    assert(rc == sizeof(req));

    // Buffer for handler to read into (must be >= FUSE_MIN_READ_BUFFER)
    std::vector<char> read_buf(FUSE_MIN_READ_BUFFER, 0);
    auto req_out = fix.View();
    intptr_t args[4] = {
        handler_fd,
        reinterpret_cast<intptr_t>(read_buf.data()),
        static_cast<intptr_t>(read_buf.size()),
        reinterpret_cast<intptr_t>(&req_out),
    };

    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_fuse_handle_req");
    auto result = pseudo::DispatchFusePseudo(bare, meta, args, 4);

    // Read handler's response from the other socket end (non-blocking)
    std::vector<char> resp(256, 0);
    ssize_t n = recv(writer_fd, resp.data(), resp.size(), MSG_DONTWAIT);
    if (n > 0) {
        resp.resize(static_cast<std::size_t>(n));
    } else {
        resp.clear();
    }
    close(handler_fd);
    close(writer_fd);
    return EndToEndOutcome{result, std::move(resp)};
}

void TestEndToEndGetattrLinksUnique()
{
    FullReqOutFixture fix;
    auto out = RunEndToEnd(FUSE_GETATTR, fix);
    assert(out.result.ret == 0);
    assert(out.result.err == 0);
    assert(out.response_bytes.size() == sizeof(fuse_out_header));
    fuse_out_header echoed{};
    std::memcpy(&echoed, out.response_bytes.data(), sizeof(echoed));
    // Handler must have copied in_hdr->unique (0xCAFEBABE) into the response
    assert(echoed.unique == 0xCAFEBABEULL);
    assert(echoed.len == sizeof(fuse_out_header));
}

void TestEndToEndForgetWritesNothing()
{
    FullReqOutFixture fix;
    auto out = RunEndToEnd(FUSE_FORGET, fix);
    assert(out.result.ret == 0);
    assert(out.result.err == 0);
    assert(out.response_bytes.empty());  // FORGET expects no reply
}

void TestEndToEndUnknownOpcodeReturnsMinusOne()
{
    FullReqOutFixture fix;
    auto out = RunEndToEnd(0xDEAD, fix);
    assert(out.result.ret == -1);
    assert(out.result.err == 0);
    assert(out.response_bytes.empty());
}

// ---- Typed-Target structural drift test (B3 review fix) -------------
//
// The wire shape the caller emits is determined by the typed Target's
// `syz_fuse_handle_req` arg-3 struct (derived from upstream syzlang
// sys/linux/fuse.txt). The C++ `SyzFuseReqOut` struct in
// `fuse_dispatcher.hpp` is a parallel hand-coded mirror of that
// ordering. Without this test, an upstream syzlang reorder would
// silently re-route opcodes to wrong fields with zero compile-time
// signal — closure §7-3 "no two target sources of truth" silent drift.
//
// This test walks the typed Target at runtime, fetches arg-3's
// pointee StructType, and asserts its field-name order matches
// `pseudo::kSyzFuseReqOutFieldOrder` (the canonical reFuzz-side order).
// If they diverge → fail before any wrong dereference happens at fuzz time.
void TestTypedTargetStructFieldOrderMatchesCpp()
{
    namespace syz = ::refuzz::program::syz;
    const syz::Target& target = syz::Target::linux_amd64();
    const auto* meta = target.find_syscall("syz_fuse_handle_req");
    assert(meta != nullptr);
    const auto& args = meta->args();
    assert(args.size() >= 4);

    // arg[3] is `req_out` — typed as ptr[in, syz_fuse_req_out]. Walk
    // ptr → struct.
    const auto* arg3_type = args[3].type();
    assert(arg3_type != nullptr);
    assert(arg3_type->kind() == syz::TypeKind::kPtr);
    const auto* ptr_type = static_cast<const syz::PtrType*>(arg3_type);
    const auto* elem = ptr_type->elem();
    assert(elem != nullptr);
    assert(elem->kind() == syz::TypeKind::kStruct);
    const auto* struct_type = static_cast<const syz::StructType*>(elem);

    const auto& fields = struct_type->fields();
    assert(fields.size() == pseudo::kSyzFuseReqOutFieldOrder.size());
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const std::string& got = fields[i].name();
        const std::string_view want = pseudo::kSyzFuseReqOutFieldOrder[i];
        if (got != want) {
            std::fprintf(stderr,
                "FUSE struct field-order drift at index %zu: "
                "typed Target='%s' vs reFuzz C++='%.*s'\n",
                i, got.c_str(),
                static_cast<int>(want.size()), want.data());
            assert(false && "syz_fuse_req_out field-order drift "
                            "between typed Target and reFuzz C++");
        }
    }
}

void TestArgsValidation()
{
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_fuse_handle_req");

    // argc < 4 → EINVAL
    intptr_t too_few[3] = {0, 0, 0};
    auto r1 = pseudo::DispatchFusePseudo(bare, meta, too_few, 3);
    assert(r1.ret == -1);
    assert(r1.err == EINVAL);

    // null req_out (args[3]==0) → -1, err=0
    intptr_t null_req[4] = {0, 0, FUSE_MIN_READ_BUFFER, 0};
    auto r2 = pseudo::DispatchFusePseudo(bare, meta, null_req, 4);
    assert(r2.ret == -1);
    assert(r2.err == 0);

    // buf_len too small → -1, err=0
    FullReqOutFixture fix;
    auto rq = fix.View();
    char dummy_buf[16];
    intptr_t small_buf[4] = {
        0,
        reinterpret_cast<intptr_t>(dummy_buf),
        16,  // < FUSE_MIN_READ_BUFFER
        reinterpret_cast<intptr_t>(&rq),
    };
    auto r3 = pseudo::DispatchFusePseudo(bare, meta, small_buf, 4);
    assert(r3.ret == -1);
    assert(r3.err == 0);
}

} // namespace

int main()
{
    // Opcode demux unit tests (mechanism b — hand-derived from upstream)
    TestRouteAttrOps();
    TestRouteEntryOps();
    TestRouteOpenOps();
    TestRouteSingletonOps();
    TestRouteXattrOps();
    TestRouteWriteOps();
    TestHeaderOnlyOpsTruncateInit();
    TestForgetOpsHaveNoReply();
    TestUnknownOpcodeFlagged();
    TestNullFieldRoutesNullHdr();
    // End-to-end via socketpair
    TestEndToEndGetattrLinksUnique();
    TestEndToEndForgetWritesNothing();
    TestEndToEndUnknownOpcodeReturnsMinusOne();
    // Args validation
    TestArgsValidation();
    // B3 review fix: typed-Target structural drift gate
    TestTypedTargetStructFieldOrderMatchesCpp();
    return 0;
}
