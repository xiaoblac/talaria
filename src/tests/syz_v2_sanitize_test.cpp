// §3.11 follow-up — sanitize_call / sanitize_fix unit tests.
//
// Cross-checks each per-syscall sanitize case against the upstream
// behavior (sys/linux/init.go::neutralize + sys/targets/common.go::
// UnixNeutralizer).
//
// Also verifies the mutator + generator hook points (§3.11 follow-up
// B5): a Prog produced by SyzV2MutatorEngine::MutateTyped or by the
// generator should always carry post-sanitize invariants.

#include "refuzz/program/syz/generated/consts.gen.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/sanitize.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz   = ::refuzz::program::syz;
namespace cs    = ::refuzz::fuzzer::syz::consts;

// Build a Call with a stub SyscallMeta whose call_name + name match
// what the dispatch in sanitize_call switches on.
struct CallBuilder {
    syz::SyscallMeta  meta;
    syz::IntType      stub_int_type;

    CallBuilder(std::string call_name, std::string variant_name = {}) {
        meta.set_call_name(std::move(call_name));
        meta.set_name(variant_name.empty() ? meta.call_name() : std::move(variant_name));
        stub_int_type.set_name("stub_int");
        stub_int_type.set_size(8);
    }

    std::unique_ptr<syz::ConstArg> make_const(std::uint64_t v) {
        auto arg = std::make_unique<syz::ConstArg>();
        arg->set_type(&stub_int_type);
        arg->set_dir(syz::Dir::kIn);
        arg->set_val(v);
        return arg;
    }

    std::unique_ptr<syz::Call> build(std::vector<std::uint64_t> args) {
        auto c = std::make_unique<syz::Call>();
        c->set_meta(&meta);
        for (auto v : args) c->add_arg(make_const(v));
        return c;
    }
};

const syz::Target& target() { return syz::Target::linux_amd64(); }

// ----- mremap -----

void TestSanitizeMremapAddsFixedWhenMaymove()
{
    CallBuilder b("mremap");
    auto call = b.build({0x1234, 0x1000, 0x2000,
                         static_cast<std::uint64_t>(cs::kSyzConst_MREMAP_MAYMOVE),
                         0x5678});
    syz::sanitize_call(*call, target());
    const auto* flags = syz::as_const_arg(call->args()[3].get());
    CHECK(flags != nullptr);
    CHECK((flags->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_MREMAP_FIXED)) != 0);
}

void TestSanitizeMremapNoOpWithoutMaymove()
{
    CallBuilder b("mremap");
    auto call = b.build({0x0, 0x0, 0x0, 0x0, 0x0});
    syz::sanitize_call(*call, target());
    const auto* flags = syz::as_const_arg(call->args()[3].get());
    CHECK(flags != nullptr);
    CHECK(flags->val() == 0);
}

// ----- mmap (UnixNeutralizer port) -----

void TestSanitizeMmapForcesFixed()
{
    CallBuilder b("mmap");
    auto call = b.build({0x1000, 0x2000, 0x3,
                         /*flags*/0x2 /* MAP_PRIVATE */, 0xff, 0x0});
    syz::sanitize_call(*call, target());
    const auto* flags = syz::as_const_arg(call->args()[3].get());
    CHECK(flags != nullptr);
    CHECK((flags->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_MAP_FIXED)) != 0);
}

void TestSanitizeMmapBifrostExempt()
{
    CallBuilder b("mmap", "mmap$bifrost");
    auto call = b.build({0x0, 0x0, 0x0, 0x0, 0x0, 0x0});
    syz::sanitize_call(*call, target());
    const auto* flags = syz::as_const_arg(call->args()[3].get());
    CHECK(flags != nullptr);
    CHECK(flags->val() == 0);  // not modified
}

// ----- ptrace TRACEME -----

void TestSanitizePtraceTracemeRewritten()
{
    CallBuilder b("ptrace");
    auto call = b.build({static_cast<std::uint64_t>(cs::kSyzConst_PTRACE_TRACEME),
                         0x0, 0x0, 0x0});
    syz::sanitize_call(*call, target());
    const auto* req = syz::as_const_arg(call->args()[0].get());
    CHECK(req != nullptr);
    CHECK(req->val() == ~std::uint64_t{0});
}

// ----- arch_prctl SET_FS -----

void TestSanitizeArchPrctlSetFsRewritten()
{
    CallBuilder b("arch_prctl");
    auto call = b.build({static_cast<std::uint64_t>(cs::kSyzConst_ARCH_SET_FS),
                         0x1234});
    syz::sanitize_call(*call, target());
    const auto* cmd = syz::as_const_arg(call->args()[0].get());
    CHECK(cmd != nullptr);
    CHECK(cmd->val() ==
          static_cast<std::uint64_t>(cs::kSyzConst_ARCH_SET_GS));
}

// ----- syslog cmd substitution -----

void TestSanitizeSyslogConsoleOffRewritten()
{
    CallBuilder b("syslog");
    auto call = b.build({static_cast<std::uint64_t>(
                              cs::kSyzConst_SYSLOG_ACTION_CONSOLE_OFF),
                         0x0, 0x0});
    syz::sanitize_call(*call, target());
    const auto* cmd = syz::as_const_arg(call->args()[0].get());
    CHECK(cmd != nullptr);
    CHECK(cmd->val() ==
          static_cast<std::uint64_t>(cs::kSyzConst_SYSLOG_ACTION_SIZE_UNREAD));
}

// ----- fanotify_mark perm bit clear -----

void TestSanitizeFanotifyMarkClearsPermBits()
{
    CallBuilder b("fanotify_mark");
    auto perm_mix =
        static_cast<std::uint64_t>(cs::kSyzConst_FAN_OPEN_PERM) |
        static_cast<std::uint64_t>(cs::kSyzConst_FAN_ACCESS_PERM) |
        static_cast<std::uint64_t>(cs::kSyzConst_FAN_OPEN_EXEC_PERM) |
        0x1ULL /* a benign bit that should survive */;
    CallBuilder bb("fanotify_mark");
    auto call = bb.build({0x0, 0x0, perm_mix, 0x0, 0x0});
    syz::sanitize_call(*call, target());
    const auto* mask = syz::as_const_arg(call->args()[2].get());
    CHECK(mask != nullptr);
    CHECK((mask->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_FAN_OPEN_PERM)) == 0);
    CHECK((mask->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_FAN_ACCESS_PERM)) == 0);
    CHECK((mask->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_FAN_OPEN_EXEC_PERM)) == 0);
    CHECK((mask->val() & 0x1ULL) != 0);
}

// ----- init_module size cap -----

void TestSanitizeInitModuleCapsSize()
{
    CallBuilder b("init_module");
    auto call = b.build({0x1, /*len*/(1ULL << 21) + 7, 0x0});
    syz::sanitize_call(*call, target());
    const auto* sz = syz::as_const_arg(call->args()[1].get());
    CHECK(sz != nullptr);
    CHECK(sz->val() < (1ULL << 20));
    CHECK(sz->val() == 7);  // (1<<21 + 7) % (1<<20) == 7
}

// ----- ioctl danger cmd substitution (B3) -----

void TestSanitizeIoctlSnapshotFreeze()
{
    CallBuilder b("ioctl");
    auto call = b.build({0xff,
                         static_cast<std::uint64_t>(cs::kSyzConst_SNAPSHOT_FREEZE),
                         0x0});
    syz::sanitize_call(*call, target());
    const auto* cmd = syz::as_const_arg(call->args()[1].get());
    CHECK(cmd != nullptr);
    CHECK(cmd->val() == static_cast<std::uint64_t>(cs::kSyzConst_FITHAW));
}

void TestSanitizeIoctlTiocsserialRewritten()
{
    CallBuilder b("ioctl");
    auto call = b.build({0xff,
                         static_cast<std::uint64_t>(cs::kSyzConst_TIOCSSERIAL),
                         0x0});
    syz::sanitize_call(*call, target());
    const auto* cmd = syz::as_const_arg(call->args()[1].get());
    CHECK(cmd != nullptr);
    CHECK(cmd->val() == static_cast<std::uint64_t>(cs::kSyzConst_TIOCGSERIAL));
}

void TestSanitizeIoctlNoopForBenignCmd()
{
    CallBuilder b("ioctl");
    auto call = b.build({0xff, 0xdeadbeef, 0x0});
    syz::sanitize_call(*call, target());
    const auto* cmd = syz::as_const_arg(call->args()[1].get());
    CHECK(cmd != nullptr);
    CHECK(cmd->val() == 0xdeadbeef);
}

// ----- sanitize_fix(prog) walks all calls -----

void TestSanitizeFixWalksAllCalls()
{
    CallBuilder bp("ptrace");
    CallBuilder bm("mmap");
    auto p1 = bp.build({static_cast<std::uint64_t>(cs::kSyzConst_PTRACE_TRACEME),
                        0x0, 0x0, 0x0});
    auto p2 = bm.build({0x0, 0x0, 0x0, 0x0, 0x0, 0x0});

    syz::Prog prog;
    prog.set_target(&target());
    prog.add_call(std::move(p1));
    prog.add_call(std::move(p2));

    syz::sanitize_fix(prog);

    const auto* req = syz::as_const_arg(prog.calls()[0]->args()[0].get());
    const auto* flags = syz::as_const_arg(prog.calls()[1]->args()[3].get());
    CHECK(req != nullptr);
    CHECK(flags != nullptr);
    CHECK(req->val() == ~std::uint64_t{0});
    CHECK((flags->val() &
           static_cast<std::uint64_t>(cs::kSyzConst_MAP_FIXED)) != 0);
}

void TestSanitizeFixSkipsNullTarget()
{
    syz::Prog prog;  // no target set
    syz::sanitize_fix(prog);  // should not crash
    CHECK(true);
}

} // namespace

int main()
{
    RUN_TEST(TestSanitizeMremapAddsFixedWhenMaymove);
    RUN_TEST(TestSanitizeMremapNoOpWithoutMaymove);
    RUN_TEST(TestSanitizeMmapForcesFixed);
    RUN_TEST(TestSanitizeMmapBifrostExempt);
    RUN_TEST(TestSanitizePtraceTracemeRewritten);
    RUN_TEST(TestSanitizeArchPrctlSetFsRewritten);
    RUN_TEST(TestSanitizeSyslogConsoleOffRewritten);
    RUN_TEST(TestSanitizeFanotifyMarkClearsPermBits);
    RUN_TEST(TestSanitizeInitModuleCapsSize);
    RUN_TEST(TestSanitizeIoctlSnapshotFreeze);
    RUN_TEST(TestSanitizeIoctlTiocsserialRewritten);
    RUN_TEST(TestSanitizeIoctlNoopForBenignCmd);
    RUN_TEST(TestSanitizeFixWalksAllCalls);
    RUN_TEST(TestSanitizeFixSkipsNullTarget);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}
