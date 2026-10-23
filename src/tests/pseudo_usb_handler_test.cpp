// PR-D4 — behavioral unit test for the 25 syz_usb_*$ handlers.
//
// Plan §7 test discipline:
//   * Structural pin: pseudo_test.go (catalog 4-tuple).
//   * Behavioral (this file): per-handler-family unit cases. Cases that
//     need /dev/raw-gadget skip when kernel module unavailable (dummy_udc
//     not loaded etc.). Failure surfaces cleanly without state leak.
//   * Oracle (mechanism b hand-derive) lives in pseudo_usb_oracle_test.cpp
//     — pins state-transition invariants + name-prefix dispatch fanout.

#include "worker/backend/pseudo/usb/usb_dispatcher.hpp"
#include "worker/backend/pseudo/usb/usb_state.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"
#include "refuzz/program/syz/target.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

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

namespace fz   = ::refuzz::fuzzer::syz;
namespace pusb = ::refuzz::worker::pseudo;

bool RawGadgetAvailable()
{
    return ::access("/dev/raw-gadget", R_OK | W_OK) == 0;
}

const fz::PseudoMeta* FindUsbMeta(const char* name)
{
    return fz::FindPseudoByName(fz::kDefaultSyzTarget.pseudos, name);
}

// ---- impl-kind / gadget-state cases (always run) -----------------------

void test_dispatch_unknown_usb_pseudo_returns_enosys()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    fz::PseudoMeta synthetic = {};
    synthetic.nr               = 0xdeadbeef;
    synthetic.name             = "syz_usb_made_up";
    synthetic.arg_count        = 0;
    synthetic.domain           = fz::PseudoDomain::kUsb;
    synthetic.concurrency      = fz::PseudoConcurrency::kNotConcurrentSafe;
    auto result = pusb::DispatchUsbPseudo(ctx, synthetic, nullptr, 0);
    CHECK(result.ret == -1);
    CHECK(result.err == ENOSYS);
}

void test_control_io_without_running_gadget_fails()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindUsbMeta("syz_usb_control_io");
    CHECK(meta != nullptr);
    std::array<intptr_t, 3> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 3);
    CHECK(result.ret == -1);
    // [usb syzkaller-cascade parity] control_io 无 gadget 现返回 EBADF(不再是内部 EINVAL):
    // 对齐 syzkaller EVENT_FETCH-on-bad-fd → EBADF,见 usb_dispatcher.cpp:311。
    CHECK(result.err == EBADF);  // gadget not running → EBADF
}

void test_ep_read_without_running_gadget_fails()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindUsbMeta("syz_usb_ep_read");
    CHECK(meta != nullptr);
    std::array<intptr_t, 4> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 4);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);
}

void test_disconnect_without_open_fails()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindUsbMeta("syz_usb_disconnect");
    CHECK(meta != nullptr);
    std::array<intptr_t, 1> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 1);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);  // no raw-gadget fd
}

// ---- Name-prefix dispatch fanout ---------------------------------------

void test_all_30_usb_pseudos_route_to_handlers()
{
    // Every kUsb domain pseudo with kNative impl + non-zero caps must
    // route somewhere — i.e., DispatchUsbPseudo never returns
    // ENOSYS-with-"unknown pseudo name" for a real catalog entry.
    // Without /dev/raw-gadget the underlying ioctls fail (EACCES /
    // ENOENT etc.), which is fine — the test just verifies dispatch
    // doesn't fall through to "unknown".
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto& target = ::refuzz::program::syz::Target::linux_amd64();
    int routed_count = 0;
    int unknown_count = 0;
    for (const auto& sc : target.syscalls()) {
        if (!sc || !sc->is_pseudo()) continue;
        if (std::strncmp(sc->name().c_str(), "syz_usb", 7) != 0) continue;
        const auto* meta = FindUsbMeta(sc->name().c_str());
        if (meta == nullptr) continue;
        std::array<intptr_t, 9> args = {};
        const auto result = pusb::DispatchUsbPseudo(
            ctx, *meta, args.data(),
            static_cast<uint32_t>(meta->arg_count));
        if (result.ret == -1 && result.err == ENOSYS &&
            result.blocked_reason != nullptr &&
            std::strstr(result.blocked_reason, "unknown pseudo name") != nullptr) {
            std::fprintf(stderr,
                         "FAIL: pseudo %s fell through to unknown-name branch\n",
                         sc->name().c_str());
            ++unknown_count;
        } else {
            ++routed_count;
        }
    }
    std::fprintf(stderr, "  routed=%d unknown=%d (expected: 30 / 0)\n",
                 routed_count, unknown_count);
    // catalog 现含 30 个 syz_usb pseudo(较早 25 增了 5 个);关键不变量是
    // unknown_count==0(每个都路由到 handler、无 unknown 落空),routed 计数随 catalog 更新。
    CHECK(routed_count == 30);
    CHECK(unknown_count == 0);
}

// ---- UsbState lifecycle ------------------------------------------------

void test_usb_state_lookup_identity_per_ctx()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    auto& s1 = pusb::GetOrCreateUsbState(ctx);
    auto& s2 = pusb::GetOrCreateUsbState(ctx);
    CHECK(&s1 == &s2);
}

void test_fresh_ctx_gets_fresh_usb_state()
{
    {
        refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
        auto& s = pusb::GetOrCreateUsbState(ctx);
        s.gadget_running = true;  // mutate
    }
    refuzz::worker::PseudoRuntimeContext ctx2(&fz::kDefaultSyzTarget);
    auto& s2 = pusb::GetOrCreateUsbState(ctx2);
    CHECK(s2.gadget_running == false);
}

// ---- /dev/raw-gadget-dependent cases (skipped when unavailable) --------

void test_connect_under_raw_gadget()
{
    if (!RawGadgetAvailable()) {
        std::fprintf(stderr, "  SKIP (no /dev/raw-gadget)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindUsbMeta("syz_usb_connect");
    CHECK(meta != nullptr);
    std::array<intptr_t, 4> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 4);
    if (result.ret != 0) {
        // Acceptable failure (kernel may refuse INIT under sandbox / no
        // dummy_udc etc.); handler must surface errno cleanly.
        std::fprintf(stderr,
                     "  USB connect failed err=%d (kernel may lack dummy_udc)\n",
                     result.err);
        CHECK(result.err != 0);
        return;
    }
    auto& s = pusb::GetOrCreateUsbState(ctx);
    CHECK(s.raw_gadget_fd >= 0);
    CHECK(s.gadget_running == true);
}

}  // namespace

int main()
{
    RUN_TEST(test_dispatch_unknown_usb_pseudo_returns_enosys);
    RUN_TEST(test_control_io_without_running_gadget_fails);
    RUN_TEST(test_ep_read_without_running_gadget_fails);
    RUN_TEST(test_disconnect_without_open_fails);
    RUN_TEST(test_all_30_usb_pseudos_route_to_handlers);
    RUN_TEST(test_usb_state_lookup_identity_per_ctx);
    RUN_TEST(test_fresh_ctx_gets_fresh_usb_state);
    RUN_TEST(test_connect_under_raw_gadget);
    return 0;
}
