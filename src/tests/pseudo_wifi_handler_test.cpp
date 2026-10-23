// PR-B3 — 802.11 handler tests.
//
// In CI, mac80211_hwsim and nl80211 modules are typically unavailable
// (no operator preload), so handler hits the QueryFamilyId graceful
// path and returns -1. Tests here:
//   - Args validation (nullptr / out-of-range buf_len / ssid_len / mode)
//   - Environment-dependent netlink path returns gracefully; failures may
//     carry kernel errno after A2 errno propagation.
// Real module-present parity test runs in operator-driven oracle when
// hwsim is loaded (plan §10 Q6 same shape as PR-B3 hwsim).

#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>

namespace refuzz::worker::pseudo {
::refuzz::worker::PseudoResult DispatchNetPseudo(
    const ::refuzz::worker::PseudoContext& ctx,
    const ::refuzz::fuzzer::syz::PseudoMeta& meta,
    const intptr_t* args,
    uint32_t argc);
}

namespace {

namespace fzs = refuzz::fuzzer::syz;

const fzs::PseudoMeta& FindPseudo(const char* name)
{
    const auto& tbl = fzs::kDefaultSyzTarget.pseudos;
    for (std::size_t i = 0; i < tbl.size; ++i) {
        if (std::strcmp(tbl.entries[i].name, name) == 0) {
            return tbl.entries[i];
        }
    }
    assert(false && "pseudo not found");
    return tbl.entries[0];
}

void AssertEnvDependentNetlinkResult(refuzz::worker::PseudoResult r)
{
    // mac80211_hwsim / nl80211 presence, wlan0 existence, and permissions vary
    // across CI and developer hosts. The stable contract is "no crash, no bogus
    // return shape"; after A2 errno propagation, failing netlink dialogs may
    // surface the kernel errno instead of the old err=0 graceful fallback.
    assert(r.ret == 0 || r.ret == -1);
    if (r.ret == 0) {
        assert(r.err == 0);
    } else {
        assert(r.err >= 0);
    }
}

void TestInjectFrameRejectsNullArgs()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    intptr_t args[3] = {0, 0, 16};
    auto& meta = FindPseudo("syz_80211_inject_frame");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestInjectFrameRejectsTooLongBuf()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    std::uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    char dummy[32] = {};
    intptr_t args[3] = {
        reinterpret_cast<intptr_t>(mac),
        reinterpret_cast<intptr_t>(dummy),
        99999,  // > 2048
    };
    auto& meta = FindPseudo("syz_80211_inject_frame");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == -1);
    assert(r.err == 0);
}

void TestInjectFrameRejectsNegativeBuf()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    std::uint8_t mac[6] = {0};
    char dummy[16] = {};
    intptr_t args[3] = {
        reinterpret_cast<intptr_t>(mac),
        reinterpret_cast<intptr_t>(dummy),
        -5,
    };
    auto& meta = FindPseudo("syz_80211_inject_frame");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == -1);
}

void TestInjectFrameModuleAbsent()
{
    // Without mac80211_hwsim loaded, QueryFamilyId returns ≤0 and handler
    // returns -1 cleanly, now preserving kernel errno when available. On hosts
    // where the module IS loaded, the call goes further and may succeed or fail
    // at register/inject depending on capabilities; either graceful shape is
    // acceptable for this environment-dependent test.
    refuzz::worker::PseudoRuntimeContext ctx;
    std::uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    std::uint8_t frame[32] = {};
    intptr_t args[3] = {
        reinterpret_cast<intptr_t>(mac),
        reinterpret_cast<intptr_t>(frame),
        sizeof(frame),
    };
    auto& meta = FindPseudo("syz_80211_inject_frame");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    AssertEnvDependentNetlinkResult(r);
}

void TestJoinIbssRejectsNullArgs()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    intptr_t args[4] = {0, 0, 5, 0};
    auto& meta = FindPseudo("syz_80211_join_ibss");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 4);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

void TestJoinIbssRejectsTooLongSsid()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    char iface[16] = "wlan0";
    std::uint8_t ssid[64] = {};
    intptr_t args[4] = {
        reinterpret_cast<intptr_t>(iface),
        reinterpret_cast<intptr_t>(ssid),
        50,  // > 32
        0,
    };
    auto& meta = FindPseudo("syz_80211_join_ibss");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 4);
    assert(r.ret == -1);
}

void TestJoinIbssRejectsInvalidMode()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    char iface[16] = "wlan0";
    std::uint8_t ssid[8] = {};
    intptr_t args[4] = {
        reinterpret_cast<intptr_t>(iface),
        reinterpret_cast<intptr_t>(ssid),
        4,
        99,  // > 2
    };
    auto& meta = FindPseudo("syz_80211_join_ibss");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 4);
    assert(r.ret == -1);
}

void TestJoinIbssModuleAbsent()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    char iface[16] = "wlan0";
    std::uint8_t ssid[8] = {1, 2, 3, 4};
    intptr_t args[4] = {
        reinterpret_cast<intptr_t>(iface),
        reinterpret_cast<intptr_t>(ssid),
        4,
        0,
    };
    auto& meta = FindPseudo("syz_80211_join_ibss");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 4);
    // Without nl80211 module, QueryFamilyId fails. If nl80211 exists, the
    // synthetic wlan0 may still be absent or permission-blocked. All of these
    // are environment-dependent netlink outcomes; the unit only asserts the
    // stable graceful result shape.
    AssertEnvDependentNetlinkResult(r);
}

} // namespace

int main()
{
    TestInjectFrameRejectsNullArgs();
    TestInjectFrameRejectsTooLongBuf();
    TestInjectFrameRejectsNegativeBuf();
    TestInjectFrameModuleAbsent();
    TestJoinIbssRejectsNullArgs();
    TestJoinIbssRejectsTooLongSsid();
    TestJoinIbssRejectsInvalidMode();
    TestJoinIbssModuleAbsent();
    return 0;
}
