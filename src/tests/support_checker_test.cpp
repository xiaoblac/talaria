// [syscall-support-detection] unit test for control/support — the per-family
// support checks (sandbox / arch gating) and resolve_enabled_calls
// (whitelist ∩ supported). Uses the real linux/amd64 Target.

#include "refuzz/control/support/support_checker.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
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

namespace syz     = ::refuzz::program::syz;
namespace support = ::refuzz::control::support;

const syz::SyscallMeta* find_pseudo_prefix(const syz::Target& t, std::string_view pfx) {
    for (const auto& sc : t.syscalls()) {
        if (sc && sc->name().rfind(pfx, 0) == 0) return sc.get();
    }
    return nullptr;
}

const syz::SyscallMeta* find_real_enabled(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        return sc.get();
    }
    return nullptr;
}

// A syz_kvm call that passes the static arch gate (amd64 worker, no non-amd64
// $variant) — so the only remaining gate is the probed /dev/kvm check.
const syz::SyscallMeta* find_kvm_amd64(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        const std::string& n = sc->name();
        if (n.rfind("syz_kvm", 0) != 0) continue;
        if (n.find("$arm64") != std::string::npos ||
            n.find("$riscv64") != std::string::npos ||
            n.find("$ppc64") != std::string::npos) continue;
        return sc.get();
    }
    return nullptr;
}

void test_real_syscalls_always_supported() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    support::SupportEnv none_env;   none_env.sandbox_is_none = true;
    support::SupportEnv setuid_env; setuid_env.sandbox_is_none = false;
    CHECK(support::is_supported(*p, t, none_env));
    CHECK(support::is_supported(*p, t, setuid_env));
}

void test_mount_needs_sandbox_none() {
    const auto& t = syz::Target::linux_amd64();
    const auto* m = find_pseudo_prefix(t, "syz_mount_image");
    if (m == nullptr) return;   // target without mount pseudos → skip
    support::SupportEnv none_env;   none_env.sandbox_is_none = true;
    support::SupportEnv setuid_env; setuid_env.sandbox_is_none = false;
    CHECK(support::is_supported(*m, t, none_env));
    CHECK(!support::is_supported(*m, t, setuid_env));
}

void test_usb_needs_sandbox_none() {
    const auto& t = syz::Target::linux_amd64();
    const auto* u = find_pseudo_prefix(t, "syz_usb");
    if (u == nullptr) return;
    support::SupportEnv setuid_env; setuid_env.sandbox_is_none = false;
    CHECK(!support::is_supported(*u, t, setuid_env));
}

void test_kvm_arch_gated() {
    const auto& t = syz::Target::linux_amd64();
    support::SupportEnv env;   // sandbox=none
    const auto* arm = find_pseudo_prefix(t, "syz_kvm_setup_cpu$arm64");
    if (arm != nullptr) {
        CHECK(!support::is_supported(*arm, t, env));   // amd64 worker ≠ arm64 kvm
    }
}

void test_resolve_intersects_support() {
    const auto& t = syz::Target::linux_amd64();
    support::SupportEnv setuid_env; setuid_env.sandbox_is_none = false;
    // empty whitelist + setuid: mount/usb dropped, real calls remain → ok.
    auto r = support::resolve_enabled_calls(t, {}, {}, setuid_env);
    CHECK(r.ok);
    CHECK(!r.mask.empty());
    const auto* m = find_pseudo_prefix(t, "syz_mount_image");
    if (m != nullptr) CHECK(r.mask[m->id()] == 0);   // mount filtered under setuid
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    CHECK(r.mask[p->id()] == 1);                       // real call kept
}

void test_resolve_empty_when_only_unsupported() {
    const auto& t = syz::Target::linux_amd64();
    const auto* m = find_pseudo_prefix(t, "syz_mount_image");
    if (m == nullptr) return;
    support::SupportEnv setuid_env; setuid_env.sandbox_is_none = false;
    // enable only mount under setuid → unsupported → empty → fail-closed.
    auto r = support::resolve_enabled_calls(t, {std::string(m->name())}, {}, setuid_env);
    CHECK(!r.ok);
    CHECK(r.error.find("no syscalls enabled") != std::string::npos);
}

void test_resolve_sandbox_none_keeps_mount() {
    const auto& t = syz::Target::linux_amd64();
    const auto* m = find_pseudo_prefix(t, "syz_mount_image");
    if (m == nullptr) return;
    support::SupportEnv none_env; none_env.sandbox_is_none = true;
    auto r = support::resolve_enabled_calls(t, {}, {}, none_env);
    CHECK(r.ok);
    CHECK(r.mask[m->id()] == 1);   // mount supported under sandbox=none
}

// [Step C] probed narrowing: when SupportEnv.probed, mount is narrowed by the
// filesystems list, usb by has_raw_gadget, kvm by has_kvm. probed=false keeps
// the static (sandbox+arch) behavior.
void test_probed_mount_narrows_by_filesystems() {
    const auto& t = syz::Target::linux_amd64();
    const auto* m = find_pseudo_prefix(t, "syz_mount_image$");
    if (m == nullptr) return;
    const std::string name = m->name();
    const auto pos = name.rfind('$');
    CHECK(pos != std::string::npos);
    const std::string fs = name.substr(pos + 1);

    support::SupportEnv present;
    present.sandbox_is_none = true;
    present.probed = true;
    present.filesystems = {fs, "sysfs", "proc"};
    CHECK(support::is_supported(*m, t, present));        // fs present → supported

    support::SupportEnv absent;
    absent.sandbox_is_none = true;
    absent.probed = true;
    absent.filesystems = {"sysfs", "proc"};
    CHECK(!support::is_supported(*m, t, absent));        // fs absent → not supported

    support::SupportEnv unprobed;
    unprobed.sandbox_is_none = true;                     // probed=false
    CHECK(support::is_supported(*m, t, unprobed));       // static keeps it
}

void test_probed_usb_narrows_by_raw_gadget() {
    const auto& t = syz::Target::linux_amd64();
    const auto* u = find_pseudo_prefix(t, "syz_usb");
    if (u == nullptr) return;
    support::SupportEnv no_gadget;
    no_gadget.sandbox_is_none = true;
    no_gadget.probed = true;
    no_gadget.has_raw_gadget = false;
    CHECK(!support::is_supported(*u, t, no_gadget));     // no raw-gadget → not supported

    support::SupportEnv with_gadget = no_gadget;
    with_gadget.has_raw_gadget = true;
    CHECK(support::is_supported(*u, t, with_gadget));    // raw-gadget → supported

    support::SupportEnv unprobed;
    unprobed.sandbox_is_none = true;                     // probed=false
    CHECK(support::is_supported(*u, t, unprobed));       // static keeps it
}

void test_probed_kvm_narrows_by_dev_kvm() {
    const auto& t = syz::Target::linux_amd64();
    const auto* k = find_kvm_amd64(t);
    if (k == nullptr) return;
    support::SupportEnv no_kvm;
    no_kvm.sandbox_is_none = true;
    no_kvm.probed = true;
    no_kvm.has_kvm = false;
    CHECK(!support::is_supported(*k, t, no_kvm));        // no /dev/kvm → not supported

    support::SupportEnv with_kvm = no_kvm;
    with_kvm.has_kvm = true;
    CHECK(support::is_supported(*k, t, with_kvm));       // /dev/kvm → supported
}

// ---- [machine-check C4.3] trial-exec resolution ----

// A real, generatable BASE syscall (name == call_name) that is NOT
// socket/socketpair/openat, so it lands in the DEFAULT trial-ENOSYS branch.
// The default check keys its trial by base call_name (syz dedups variants), so
// using a base (name == call_name) makes the injected one_trial(name) align
// with the verdict's trials[call_name] lookup.
const syz::SyscallMeta* find_real_default(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        if (sc->name() != sc->call_name()) continue;   // base only (variant trial dedups to base)
        const std::string& base = sc->call_name();
        if (base == "socket" || base == "socketpair" || base == "openat") continue;
        return sc.get();
    }
    return nullptr;
}

// A socket $variant (name != base) — the generic socket/socketpair is
// "always supported" in syz (linuxSupportedSocket early-returns ""), so the
// errno rule only applies to a concrete family variant.
const syz::SyscallMeta* find_socket_family(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        const std::string& base = sc->call_name();
        if ((base == "socket" || base == "socketpair") && sc->name() != base) {
            return sc.get();
        }
    }
    return nullptr;
}

support::TrialResults one_trial(const std::string& name, bool executed, int err) {
    support::TrialResults tr;
    tr.by_name[name] = support::ProbeOutcome{executed, err};
    return tr;
}

// THE flip: a DEFAULT real syscall is dropped on trial ENOSYS; missing / not-
// executed evidence keeps it supported (no over-disable).
void test_default_trial_enosys_disables() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_default(t);
    CHECK(p != nullptr);
    support::SupportEnv env; env.sandbox_is_none = true;

    // No trial → assume supported (pre-machine-check behavior preserved).
    CHECK(support::resolve_call_support(*p, t, env, support::TrialResults{}).supported);

    auto v = support::resolve_call_support(*p, t, env, one_trial(p->name(), true, ENOSYS));
    CHECK(!v.supported);
    CHECK(v.reason == "ENOSYS");

    // executed + errno 0 → supported; not-executed + ENOSYS → still supported.
    CHECK(support::resolve_call_support(*p, t, env, one_trial(p->name(), true, 0)).supported);
    CHECK(support::resolve_call_support(*p, t, env, one_trial(p->name(), false, ENOSYS)).supported);
}

// resolve_enabled_calls applies trials + fills the disabled report.
void test_resolve_drops_enosys_with_report() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_default(t);
    CHECK(p != nullptr);
    support::SupportEnv env; env.sandbox_is_none = true;

    std::vector<syz::DisabledCall> report;
    auto r = support::resolve_enabled_calls(
        t, {}, {}, env, one_trial(p->name(), true, ENOSYS), &report);
    CHECK(r.ok);                    // the rest of the real calls remain
    CHECK(r.mask[p->id()] == 0);    // the ENOSYS call is dropped
    bool found = false;
    for (const auto& d : report) {
        if (d.call == p) {          // canonical record: match by the meta pointer
            found = true;
            CHECK(d.reason == "ENOSYS");
        }
    }
    CHECK(found);
}

// socket-family: disable on ENOSYS / EAFNOSUPPORT; errno 0 / no-trial keep it.
void test_socket_family_trial() {
    const auto& t = syz::Target::linux_amd64();
    const auto* s = find_socket_family(t);
    if (s == nullptr) return;
    support::SupportEnv env; env.sandbox_is_none = true;

    CHECK(!support::resolve_call_support(*s, t, env,
              one_trial(s->name(), true, EAFNOSUPPORT)).supported);
    CHECK(!support::resolve_call_support(*s, t, env,
              one_trial(s->name(), true, ENOSYS)).supported);
    CHECK(support::resolve_call_support(*s, t, env,
              one_trial(s->name(), true, 0)).supported);
    CHECK(support::resolve_call_support(*s, t, env, support::TrialResults{}).supported);
}

// pseudo dep gate: syz_mount_image needs memfd_create; dep ENOSYS disables it
// even when the static (sandbox=none) gate passes.
void test_pseudo_dep_enosys_disables() {
    const auto& t = syz::Target::linux_amd64();
    const auto* m = find_pseudo_prefix(t, "syz_mount_image");
    if (m == nullptr) return;
    support::SupportEnv env; env.sandbox_is_none = true;   // static gate passes

    auto v = support::resolve_call_support(*m, t, env, one_trial("memfd_create", true, ENOSYS));
    CHECK(!v.supported);
    CHECK(v.reason.find("memfd_create") != std::string::npos);

    // dep present (errno 0) or no dep trial → supported (no evidence to drop).
    CHECK(support::resolve_call_support(*m, t, env, one_trial("memfd_create", true, 0)).supported);
    CHECK(support::resolve_call_support(*m, t, env, support::TrialResults{}).supported);
}

// Find an openat$<dev> variant whose path arg (Args[1]) is a ptr → string
// const with an absolute value — the shape syz's supportedOpenat checks.
const syz::SyscallMeta* find_openat_const_path(const syz::Target& t,
                                               std::string* path_out) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->call_name() != "openat") continue;
        if (sc->args().size() < 2) continue;
        const syz::PtrType* p = syz::as_ptr(sc->args()[1].type());
        if (p == nullptr) continue;
        const syz::BufferType* b = syz::as_buffer(p->elem());
        if (b == nullptr || b->buffer_kind() != syz::BufferKind::kString ||
            b->values().size() != 1) {
            continue;
        }
        std::string v = b->values().front();
        while (!v.empty() && v.back() == '\0') v.pop_back();
        if (v.empty() || v.front() != '/') continue;
        if (path_out != nullptr) *path_out = v;
        return sc.get();
    }
    return nullptr;
}

// device-open (syz supportedOpenat): an openat with a const absolute path is
// dropped when the probe trial says the node is absent (ENOENT/ENODEV/ENXIO);
// success / mode-or-permission errno / no-trial keep it (no false-disable).
void test_device_open_trial() {
    const auto& t = syz::Target::linux_amd64();
    std::string path;
    const auto* o = find_openat_const_path(t, &path);
    if (o == nullptr) return;   // pin without a const-path openat → skip
    support::SupportEnv env; env.sandbox_is_none = true;

    auto absent = support::resolve_call_support(*o, t, env,
                      one_trial(o->name(), true, ENOENT));
    CHECK(!absent.supported);
    CHECK(absent.reason.find("failed to open") != std::string::npos);
    CHECK(absent.reason.find(path) != std::string::npos);

    CHECK(!support::resolve_call_support(*o, t, env,
              one_trial(o->name(), true, ENODEV)).supported);
    CHECK(!support::resolve_call_support(*o, t, env,
              one_trial(o->name(), true, ENXIO)).supported);

    // openable / mode-or-permission errno / no evidence → keep.
    CHECK(support::resolve_call_support(*o, t, env,
              one_trial(o->name(), true, 0)).supported);
    CHECK(support::resolve_call_support(*o, t, env,
              one_trial(o->name(), true, EACCES)).supported);
    CHECK(support::resolve_call_support(*o, t, env,
              support::TrialResults{}).supported);
}

// resolve_enabled_calls drops an absent-device opener and reports it (the
// uncreatable fd then cascades via the transitive closure, as in syz).
void test_resolve_device_open_report() {
    const auto& t = syz::Target::linux_amd64();
    std::string path;
    const auto* o = find_openat_const_path(t, &path);
    if (o == nullptr) return;
    support::SupportEnv env; env.sandbox_is_none = true;

    std::vector<syz::DisabledCall> report;
    auto r = support::resolve_enabled_calls(
        t, {}, {}, env, one_trial(o->name(), true, ENOENT), &report);
    CHECK(r.ok);
    CHECK(r.mask[o->id()] == 0);
    bool found = false;
    for (const auto& d : report) {
        if (d.call == o) {
            found = true;
            CHECK(d.reason.find("failed to open") != std::string::npos);
        }
    }
    CHECK(found);
}

// ---- [machine-check C4.1] LSM + kernel-version gating ----

// LSM tail: a call whose name names an LSM is dropped when that LSM is not in
// /sys/kernel/security/lsm; unreadable list / unprobed env keep it.
void test_lsm_gate() {
    const auto& t = syz::Target::linux_amd64();
    const syz::SyscallMeta* sc = nullptr;
    const char* which = nullptr;
    for (const auto& s : t.syscalls()) {
        if (!s) continue;
        std::string lower = s->name();
        for (char& c : lower) c = static_cast<char>(std::tolower((unsigned char)c));
        for (const char* l : {"selinux", "apparmor", "smack"}) {
            if (lower.find(l) != std::string::npos) { sc = s.get(); which = l; break; }
        }
        if (sc != nullptr) break;
    }
    if (sc == nullptr) return;   // target without LSM-named calls → skip

    support::SupportEnv base; base.sandbox_is_none = true;
    // unprobed → keep (static).
    CHECK(support::resolve_call_support(*sc, t, base, support::TrialResults{}).supported);

    // probed + securityfs readable + LSM enabled → keep.
    support::SupportEnv on = base; on.probed = true; on.lsm_present = true;
    on.lsms = std::string("capability,") + which + ",yama";
    CHECK(support::resolve_call_support(*sc, t, on, support::TrialResults{}).supported);

    // probed + readable + LSM absent → unsupported.
    support::SupportEnv off = base; off.probed = true; off.lsm_present = true;
    off.lsms = "capability,yama";
    auto v = support::resolve_call_support(*sc, t, off, support::TrialResults{});
    CHECK(!v.supported);
    CHECK(v.reason.find("not enabled") != std::string::npos);

    // probed but securityfs unreadable → keep (no evidence).
    support::SupportEnv nofs = base; nofs.probed = true; nofs.lsm_present = false;
    CHECK(support::resolve_call_support(*sc, t, nofs, support::TrialResults{}).supported);
}

// syz_80211_* requires kernel >= 4.17 when probed; unprobed / unknown keep it.
void test_kernel_version_gate() {
    const auto& t = syz::Target::linux_amd64();
    const auto* w = find_pseudo_prefix(t, "syz_80211");
    if (w == nullptr) return;
    support::SupportEnv base; base.sandbox_is_none = true;

    CHECK(support::resolve_call_support(*w, t, base, support::TrialResults{}).supported);

    support::SupportEnv newk = base; newk.probed = true;
    newk.kernel_major = 6; newk.kernel_minor = 8;
    CHECK(support::resolve_call_support(*w, t, newk, support::TrialResults{}).supported);

    support::SupportEnv oldk = base; oldk.probed = true;
    oldk.kernel_major = 4; oldk.kernel_minor = 10;
    auto v = support::resolve_call_support(*w, t, oldk, support::TrialResults{});
    CHECK(!v.supported);
    CHECK(v.reason.find("4.17") != std::string::npos);

    // probed but version unknown (major 0) → keep (no evidence).
    support::SupportEnv unk = base; unk.probed = true;
    CHECK(support::resolve_call_support(*w, t, unk, support::TrialResults{}).supported);
}

} // namespace

int main() {
    std::fprintf(stdout, "Running support_checker_test...\n");
    RUN_TEST(test_real_syscalls_always_supported);
    RUN_TEST(test_mount_needs_sandbox_none);
    RUN_TEST(test_usb_needs_sandbox_none);
    RUN_TEST(test_kvm_arch_gated);
    RUN_TEST(test_resolve_intersects_support);
    RUN_TEST(test_resolve_empty_when_only_unsupported);
    RUN_TEST(test_resolve_sandbox_none_keeps_mount);
    RUN_TEST(test_probed_mount_narrows_by_filesystems);
    RUN_TEST(test_probed_usb_narrows_by_raw_gadget);
    RUN_TEST(test_probed_kvm_narrows_by_dev_kvm);
    RUN_TEST(test_default_trial_enosys_disables);
    RUN_TEST(test_resolve_drops_enosys_with_report);
    RUN_TEST(test_socket_family_trial);
    RUN_TEST(test_device_open_trial);
    RUN_TEST(test_resolve_device_open_report);
    RUN_TEST(test_pseudo_dep_enosys_disables);
    RUN_TEST(test_lsm_gate);
    RUN_TEST(test_kernel_version_gate);
    std::fprintf(stdout, "ALL PASS\n");
    return 0;
}
