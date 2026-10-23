// PR-A2 — process / memory / kfuzztest / nvme handler tests.
//
// Test strategy (per plan §7 + safety considerations):
//   - syz_memcpy_off: actual memcpy verified byte-for-byte (pure mem op)
//   - syz_pidfd_open: real syscall with pid=1 → forced to 0 → own pidfd
//                     (host-runnable; pidfd_open is unprivileged)
//   - syz_pkey_set: pkey=15 (RESERVED_PKEY) → EINVAL guard fires before asm
//   - syz_socket_connect_nvme_tcp: AF=-1 socket() → fail-fast errno
//   - syz_kfuzztest_run: missing debugfs path → -1 (graceful)
//   - syz_clone / syz_clone3 / syz_execute_func: args validation only
//                     (actual fork/exec dangerous in CI; covered structurally)

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace refuzz::worker::pseudo {
PseudoResult DispatchCorePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);
PseudoResult DispatchNetPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);
}

namespace {

refuzz::fuzzer::syz::PseudoMeta MetaFor(const char* name)
{
    refuzz::fuzzer::syz::PseudoMeta m{};
    m.name = name;
    return m;
}

// ---- syz_memcpy_off --------------------------------------------------

void TestMemcpyOffActuallyCopies()
{
    std::vector<char> dest(64, 0x00);
    std::vector<char> src(64, 0xAA);
    intptr_t args[5] = {
        reinterpret_cast<intptr_t>(dest.data()),
        16,                                                 // dest_off
        reinterpret_cast<intptr_t>(src.data()),
        4,                                                  // src_off
        8,                                                  // n
    };
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_memcpy_off$IO_URING_METADATA_FLAGS");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 5);
    assert(r.err == 0);
    // Bytes 0-15 untouched
    for (int i = 0; i < 16; ++i) assert(dest[i] == 0x00);
    // Bytes 16-23 = src[4..11] = 0xAA
    for (int i = 16; i < 24; ++i) assert(static_cast<unsigned char>(dest[i]) == 0xAA);
    // Bytes 24+ untouched
    for (int i = 24; i < 64; ++i) assert(dest[i] == 0x00);
    // Return value is dest+dest_off
    assert(r.ret == reinterpret_cast<intptr_t>(dest.data() + 16));
}

void TestMemcpyOffRejectsNullDest()
{
    intptr_t args[5] = {0, 0, 1, 0, 0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_memcpy_off$IO_URING_METADATA_GENERIC");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 5);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestMemcpyOffRejectsTooFewArgs()
{
    intptr_t args[3] = {1, 2, 3};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_memcpy_off$KVM_EXIT_HYPERCALL");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 3);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- syz_pidfd_open -------------------------------------------------

void TestPidfdOpenForcesPidOneToSelf()
{
    intptr_t args[2] = {1, 0};   // pid=1 → forced to 0 → own pidfd
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_pidfd_open");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    if (r.ret < 0) {
        // Kernel may not support pidfd_open (Linux < 5.3); accept ENOSYS
        assert(r.err == ENOSYS || r.err == EINVAL);
        return;
    }
    // Successful: ret is a valid pidfd
    assert(r.ret >= 0);
    close(static_cast<int>(r.ret));
}

void TestPidfdOpenRejectsTooFewArgs()
{
    intptr_t args[1] = {0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_pidfd_open");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 1);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- syz_pkey_set ---------------------------------------------------

void TestPkeySetReservedReturnsEinval()
{
    intptr_t args[2] = {15, 0};  // pkey=15 = RESERVED_PKEY
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_pkey_set");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestPkeySetRejectsTooFewArgs()
{
    intptr_t args[1] = {0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_pkey_set");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 1);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- syz_clone / syz_clone3 / syz_execute_func ----------------------
// Args validation only — actual fork / arbitrary-code-call are dangerous
// in CI and would be load-bearing on coverage instrumentation that the
// host doesn't need.

void TestCloneRejectsTooFewArgs()
{
    intptr_t args[5] = {0, 0, 0, 0, 0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_clone");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 5);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestClone3RejectsNullArgsPointer()
{
    intptr_t args[2] = {0, 32};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_clone3");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestClone3RejectsCopySizeOverLimit()
{
    char buf[8] = {0};
    intptr_t args[2] = {reinterpret_cast<intptr_t>(buf), 1024};  // > 256
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_clone3");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.ret == -1);
}

void TestClone3RejectsCopySizeUnderMin()
{
    char buf[8] = {0};
    intptr_t args[2] = {reinterpret_cast<intptr_t>(buf), 4};  // < 8
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_clone3");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 2);
    assert(r.ret == -1);
}

void TestExecuteFuncRejectsNullArg()
{
    intptr_t args[1] = {0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_execute_func");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 1);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- syz_kfuzztest_run ----------------------------------------------

void TestKfuzztestRunMissingPathReturnsMinusOne()
{
    const char* test_name = "definitely_not_a_real_kfuzztest_module_xyz";
    char buffer[16] = {0};
    intptr_t args[4] = {
        reinterpret_cast<intptr_t>(test_name),
        0,                                          // input_data (unused)
        sizeof(buffer),
        reinterpret_cast<intptr_t>(buffer),
    };
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_kfuzztest_run");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 4);
    assert(r.ret == -1);
    assert(r.err == 0);  // graceful — no errno surfaced (mirror upstream)
}

void TestKfuzztestRunRejectsNullName()
{
    intptr_t args[4] = {0, 0, 0, 1};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_kfuzztest_run");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 4);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestKfuzztestRunRejectsNullBuffer()
{
    const char* test_name = "x";
    intptr_t args[4] = {reinterpret_cast<intptr_t>(test_name), 0, 0, 0};
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_kfuzztest_run");
    auto r = refuzz::worker::pseudo::DispatchCorePseudo(bare, meta, args, 4);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- syz_socket_connect_nvme_tcp (kNet domain) ----------------------

void TestSocketConnectNvmeTcpFailsFast()
{
    refuzz::worker::PseudoContext bare;
    auto meta = MetaFor("syz_socket_connect_nvme_tcp");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(bare, meta, nullptr, 0);
    // syscall(SYS_socket, -1, 0, 0) → -1 with EAFNOSUPPORT or EINVAL
    assert(r.ret == -1);
    assert(r.err != 0);
}

} // namespace

int main()
{
    // Memory
    TestMemcpyOffActuallyCopies();
    TestMemcpyOffRejectsNullDest();
    TestMemcpyOffRejectsTooFewArgs();
    // pidfd_open
    TestPidfdOpenForcesPidOneToSelf();
    TestPidfdOpenRejectsTooFewArgs();
    // pkey_set
    TestPkeySetReservedReturnsEinval();
    TestPkeySetRejectsTooFewArgs();
    // clone/clone3/execute_func args validation
    TestCloneRejectsTooFewArgs();
    TestClone3RejectsNullArgsPointer();
    TestClone3RejectsCopySizeOverLimit();
    TestClone3RejectsCopySizeUnderMin();
    TestExecuteFuncRejectsNullArg();
    // kfuzztest
    TestKfuzztestRunMissingPathReturnsMinusOne();
    TestKfuzztestRunRejectsNullName();
    TestKfuzztestRunRejectsNullBuffer();
    // nvme
    TestSocketConnectNvmeTcpFailsFast();
    return 0;
}
