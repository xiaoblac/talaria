// Copyright 2026 reFuzz project author -------youngkk.
//
// The specialized support checks — one cohesive unit per syz linuxSyscallChecks
// entry (probe construction + errno/env interpretation). See support_check.hpp
// and docs/plans/support-check-abstraction.md.

#include "refuzz/control/support/support_check.hpp"

#include "refuzz/program/syz/arg.hpp"    // ConstArg, DataArg, PointerArg
#include "refuzz/program/syz/type.hpp"   // Type, TypeKind, as_ptr/as_buffer/as_flags

#include <algorithm>  // std::count (syz_open_dev '#' count)
#include <cerrno>   // ENOSYS, EAFNOSUPPORT, ENOENT/ENODEV/ENXIO
#include <cstring>  // std::strerror
#include <initializer_list>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace refuzz::control::support {

namespace {

// ---- shared interpretation helpers (mirror syz) -------------------------

// The "device/file is not there" errnos. Absent nodes return these regardless
// of open mode, so reFuzz's single default-mode trial matches syz's all-modes
// canOpen for the present/absent cases without false-disabling a present node
// that only opens in a non-default mode (EACCES/EINVAL/…).
bool is_absent_errno(int err) {
    return err == ENOENT || err == ENODEV || err == ENXIO;
}

const ProbeOutcome* trial_of(const TrialResults& trials, const std::string& tag) {
    const auto it = trials.by_name.find(tag);
    return it == trials.by_name.end() ? nullptr : &it->second;
}

// syz extractStringConst(call.Args[idx].Type): a ptr → BufferString yields
// Values[0] (the first value, even for multi-value strings), trailing NULs
// trimmed; empty otherwise (syz's `!ok` ⇒ "can't check" ⇒ keep).
std::string extract_const_string_arg(const syz::SyscallMeta& call, std::size_t idx) {
    if (idx >= call.args().size()) return {};
    const syz::PtrType* p = syz::as_ptr(call.args()[idx].type());
    if (p == nullptr) return {};
    const syz::BufferType* b = syz::as_buffer(p->elem());
    if (b == nullptr || b->buffer_kind() != syz::BufferKind::kString ||
        b->values().empty()) {
        return {};
    }
    std::string v = b->values().front();
    while (!v.empty() && v.back() == '\0') v.pop_back();
    return v;
}

// syz_mount_image$<fs> / mount$<fs>: supported iff <fs> ∈ /proc/filesystems.
// The $variant suffix is the fs type (ext4 → ext4). Base (no '$') ⇒ keep.
bool mount_fs_present(const std::string& name, const SupportEnv& env) {
    const auto pos = name.rfind('$');
    if (pos == std::string::npos) return true;
    const std::string fs = name.substr(pos + 1);
    for (const auto& f : env.filesystems) {
        if (f == fs) return true;
    }
    return false;
}

// syz linuxSupportedSocket errno rule for a socket($variant) trial. `type` is
// concrete iff it's a const OR flags (syz hasType is true for FlagsType too,
// using Vals[0]); `proto` concrete iff const.
SupportVerdict socket_verdict(const syz::SyscallMeta& call, const TrialResults& trials) {
    if (call.name() == call.call_name()) {
        return {true, ""};  // generic socket/socketpair — "always supported" (syz)
    }
    const ProbeOutcome* o = trial_of(trials, call.name());
    if (o == nullptr || !o->executed) return {true, ""};  // no evidence → keep
    if (o->err == ENOSYS)       return {false, "socket: ENOSYS"};
    if (o->err == EAFNOSUPPORT) return {false, "socket: EAFNOSUPPORT"};
    auto kind_in = [&](std::size_t idx, std::initializer_list<syz::TypeKind> ks) {
        if (idx >= call.args().size()) return false;
        const syz::Type* t = call.args()[idx].type();
        if (t == nullptr) return false;
        for (syz::TypeKind k : ks) if (t->kind() == k) return true;
        return false;
    };
    const bool type_concrete =
        kind_in(1, {syz::TypeKind::kConst, syz::TypeKind::kFlags});
    const bool proto_concrete = kind_in(2, {syz::TypeKind::kConst});
    if (type_concrete && proto_concrete && o->err != 0) {
        return {false, "socket: failed errno " + std::to_string(o->err)};
    }
    return {true, ""};
}

// ---- probe-call builders ------------------------------------------------
// Each specialized check builds its OWN probe call here (host-side) — the
// generic builder never special-cases a syscall.

std::unique_ptr<syz::Arg> make_const_arg(const syz::Type* t, syz::Dir dir, std::uint64_t v) {
    auto a = std::make_unique<syz::ConstArg>();
    a->set_type(t);
    a->set_dir(dir);
    a->set_val(v);
    return a;
}

// One default-arg call per syscall — syz's bare ENOSYS probe (and, for an
// openat$<dev> with a const path, the call that opens that path).
std::unique_ptr<syz::Call> build_bare_call(const syz::SyscallMeta& meta) {
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    for (const auto& field : meta.args()) {
        const syz::Type* ft = field.type();
        if (ft == nullptr) continue;
        call->add_arg(ft->default_arg(field.dir(syz::Dir::kIn)));
    }
    return call;
}

// socket($variant): default args except the type arg (field 1) = FlagsType.Vals[0]
// (syz's first valid socket type, e.g. SOCK_STREAM) — socket(af, 0, proto) would
// fail ESOCKTNOSUPPORT and false-disable a supported family. af/proto are consts
// whose default IS the descriptor value.
std::unique_ptr<syz::Call> build_socket_variant_call(const syz::SyscallMeta& meta) {
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    std::size_t fi = 0;
    for (const auto& field : meta.args()) {
        const syz::Type* ft = field.type();
        if (ft == nullptr) { ++fi; continue; }
        const syz::Dir dir = field.dir(syz::Dir::kIn);
        if (fi == 1) {
            if (const syz::FlagsType* fl = syz::as_flags(ft);
                fl != nullptr && !fl->vals().empty()) {
                call->add_arg(make_const_arg(ft, dir, fl->vals().front()));
                ++fi;
                continue;
            }
        }
        call->add_arg(ft->default_arg(dir));
        ++fi;
    }
    return call;
}

// Synthetic openat(AT_FDCWD, "<path>", flags=0, 0) against the base openat meta —
// syz's canOpen. The path is absolute, so the dirfd is ignored (default arg is
// fine); the pointer address is allocated by assign_sizes_prog, exactly as for a
// generated program. nullptr if the schema shape is unexpected (→ no probe).
std::unique_ptr<syz::Call> build_openat_path_call(const syz::Target& target,
                                                  std::string_view path) {
    const syz::SyscallMeta* m = target.find_syscall("openat");
    if (m == nullptr || m->args().size() < 2) return nullptr;
    const syz::Type* file_t = m->args()[1].type();
    const syz::PtrType* pt = syz::as_ptr(file_t);
    if (pt == nullptr) return nullptr;
    const syz::Type* buf_t = pt->elem();
    if (syz::as_buffer(buf_t) == nullptr) return nullptr;

    auto call = std::make_unique<syz::Call>();
    call->set_meta(m);
    std::size_t fi = 0;
    for (const auto& field : m->args()) {
        const syz::Type* ft = field.type();
        if (ft == nullptr) { ++fi; continue; }
        const syz::Dir dir = field.dir(syz::Dir::kIn);
        if (fi == 1) {  // file pointer → our path
            std::vector<std::uint8_t> bytes(path.begin(), path.end());
            bytes.push_back('\0');  // NUL-terminate (matches const device paths)
            auto data = std::make_unique<syz::DataArg>();
            data->set_type(buf_t);
            data->set_dir(syz::Dir::kIn);
            data->set_data(std::move(bytes));
            auto ptr = std::make_unique<syz::PointerArg>();
            ptr->set_type(ft);
            ptr->set_dir(syz::Dir::kIn);
            ptr->set_res(std::move(data));  // address assigned by assign_sizes_prog
            call->add_arg(std::move(ptr));
            ++fi;
            continue;
        }
        call->add_arg(ft->default_arg(dir));  // fd (ignored, abs path), flags=0, mode=0
        ++fi;
    }
    return call;
}

// Synthetic socket(af, type, proto) with explicit consts (syz genetlink probe).
// nullptr if any const is unknown to the schema (→ no probe ⇒ keep).
std::unique_ptr<syz::Call> build_socket_const_call(const syz::Target& target,
                                                   const char* af, const char* type,
                                                   const char* proto) {
    const syz::SyscallMeta* m = target.find_syscall("socket");
    if (m == nullptr || m->args().size() < 3) return nullptr;
    const std::uint64_t* af_v = target.find_const(af);
    const std::uint64_t* ty_v = target.find_const(type);
    const std::uint64_t* pr_v = target.find_const(proto);
    if (af_v == nullptr || ty_v == nullptr || pr_v == nullptr) return nullptr;
    const std::uint64_t vals[3] = {*af_v, *ty_v, *pr_v};
    auto call = std::make_unique<syz::Call>();
    call->set_meta(m);
    std::size_t fi = 0;
    for (const auto& field : m->args()) {
        const syz::Type* ft = field.type();
        if (ft == nullptr) { ++fi; continue; }
        const syz::Dir dir = field.dir(syz::Dir::kIn);
        call->add_arg(fi < 3 ? make_const_arg(ft, dir, vals[fi]) : ft->default_arg(dir));
        ++fi;
    }
    return call;
}

// Concrete device paths a syz_open_dev$<dev> template ("/dev/hidraw#", …) expands
// to — syz linuxSyzOpenDevSupported's id sweep: arg1 ProcType ⇒ {0}; else
// i+j*10 for i,j∈[0,5) keeping j==0 unless there are ≥2 '#' (single-# ⇒
// {0,1,2,3,4}; two-# ⇒ {0..4,10..14,…44}). Each '#' is replaced by the id (syz
// passes one id; the single-# device templates we care about substitute exactly).
std::vector<std::string> syz_open_dev_paths(const syz::SyscallMeta& call,
                                            const std::string& tmpl) {
    const std::size_t hashes =
        static_cast<std::size_t>(std::count(tmpl.begin(), tmpl.end(), '#'));
    std::vector<int> ids;
    const bool arg1_proc = call.args().size() > 1 && call.args()[1].type() != nullptr &&
                           call.args()[1].type()->kind() == syz::TypeKind::kProc;
    if (arg1_proc) {
        ids.push_back(0);
    } else {
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < 5; ++j) {
                if (j == 0 || hashes > 1) ids.push_back(i + j * 10);
            }
        }
    }
    std::vector<std::string> out;
    out.reserve(ids.size());
    for (const int id : ids) {
        std::string p = tmpl;
        const std::string s = std::to_string(id);
        std::size_t pos;
        while ((pos = p.find('#')) != std::string::npos) p.replace(pos, 1, s);
        out.push_back(std::move(p));
    }
    return out;
}

// ---- the checks (peers; first owns() wins in the registry) --------------

// socket / socketpair — syz linuxSupportedSocket.
class SocketCheck final : public SupportCheck {
public:
    const char* name() const override { return "socket"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return !c.is_pseudo() &&
               (c.call_name() == "socket" || c.call_name() == "socketpair");
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta& c,
                                  const syz::Target&) const override {
        if (c.name() == c.call_name()) return {};  // generic — always supported
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{c.name(), build_socket_variant_call(c)});
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv&, const TrialResults& t) const override {
        return socket_verdict(c, t);
    }
};

// openat$<dev> with a const absolute path — syz supportedOpenat (canOpen).
// The probe is a synthetic openat against the FIRST const path value (syz
// extractStringConst = Values[0]); a bare default-arg call can't be used here
// because default_arg zero-fills multi-value string buffers instead of
// selecting the first value.
class OpenatDeviceCheck final : public SupportCheck {
public:
    const char* name() const override { return "openat-device"; }
    bool owns(const syz::SyscallMeta& c) const override {
        if (c.is_pseudo() || c.call_name() != "openat") return false;
        // syz extractStringConst returns !ok for automatic calls (Attrs.Automatic)
        // → supportedOpenat keeps them without probing; mirror that here.
        if (c.attrs().automatic) return false;
        const std::string p = extract_const_string_arg(c, 1);
        return !p.empty() && p.front() == '/';
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta& c,
                                  const syz::Target& target) const override {
        std::vector<ProbeSpec> out;
        const std::string path = extract_const_string_arg(c, 1);
        if (std::unique_ptr<syz::Call> call = build_openat_path_call(target, path)) {
            out.push_back(ProbeSpec{c.name(), std::move(call)});
        }
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv&, const TrialResults& t) const override {
        const std::string path = extract_const_string_arg(c, 1);
        const ProbeOutcome* o = trial_of(t, c.name());
        if (o != nullptr && o->executed && is_absent_errno(o->err)) {
            return {false, "failed to open " + path + ": " + std::strerror(o->err)};
        }
        return {true, ""};
    }
};

// pkey_alloc (real) + syz_pkey_set (pseudo) — syz linuxPkeysSupported =
// callSucceeds("pkey_alloc(0,0)"). One shared probe (tag "pkey_alloc").
class PkeyCheck final : public SupportCheck {
public:
    const char* name() const override { return "pkey"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return c.call_name() == "pkey_alloc" || c.call_name() == "syz_pkey_set";
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target& target) const override {
        const syz::SyscallMeta* m = target.find_syscall("pkey_alloc");
        if (m == nullptr) return {};
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{"pkey_alloc", build_bare_call(*m)});  // pkey_alloc(0,0)
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta&, const syz::Target&,
                           const SupportEnv&, const TrialResults& t) const override {
        const ProbeOutcome* o = trial_of(t, "pkey_alloc");
        if (o != nullptr && o->executed && o->err != 0) {
            return {false, "pkey_alloc failed: " + std::string(std::strerror(o->err))};
        }
        return {true, ""};
    }
};

// A pseudo gated on a fixed canOpen path (syz rootCanOpen/canOpen). Shared
// synthetic openat probe (tag "open:<path>"); optional sandbox=none gate first.
class CanOpenCheck final : public SupportCheck {
public:
    CanOpenCheck(std::string label, std::vector<std::string> prefixes,
                 std::string path, bool needs_sandbox_none, std::string what)
        : label_(std::move(label)), prefixes_(std::move(prefixes)),
          path_(std::move(path)), needs_sandbox_none_(needs_sandbox_none),
          what_(std::move(what)) {}
    const char* name() const override { return label_.c_str(); }
    bool owns(const syz::SyscallMeta& c) const override {
        if (!c.is_pseudo()) return false;
        for (const std::string& p : prefixes_) {
            if (c.call_name().rfind(p, 0) == 0) return true;
        }
        return false;
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target& target) const override {
        std::unique_ptr<syz::Call> call = build_openat_path_call(target, path_);
        if (call == nullptr) return {};
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{"open:" + path_, std::move(call)});
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta&, const syz::Target&,
                           const SupportEnv& env, const TrialResults& t) const override {
        if (needs_sandbox_none_ && !env.sandbox_is_none) {
            return {false, what_ + ": requires sandbox=none"};
        }
        const ProbeOutcome* o = trial_of(t, "open:" + path_);
        if (o != nullptr && o->executed && is_absent_errno(o->err)) {
            return {false, "failed to open " + path_ + ": " + std::strerror(o->err)};
        }
        return {true, ""};
    }

private:
    std::string              label_;
    std::vector<std::string> prefixes_;
    std::string              path_;
    bool                     needs_sandbox_none_;
    std::string              what_;
};

// syz_genetlink_get_family_id — syz callSucceeds(socket(AF_NETLINK, SOCK_RAW,
// NETLINK_GENERIC)).
class GenetlinkCheck final : public SupportCheck {
public:
    const char* name() const override { return "genetlink"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return c.is_pseudo() && c.call_name() == "syz_genetlink_get_family_id";
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target& target) const override {
        std::unique_ptr<syz::Call> call = build_socket_const_call(
            target, "AF_NETLINK", "SOCK_RAW", "NETLINK_GENERIC");
        if (call == nullptr) return {};
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{"socket:netlink_generic", std::move(call)});
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta&, const syz::Target&,
                           const SupportEnv&, const TrialResults& t) const override {
        const ProbeOutcome* o = trial_of(t, "socket:netlink_generic");
        if (o != nullptr && o->executed && o->err != 0) {
            return {false, "genetlink socket failed: " + std::string(std::strerror(o->err))};
        }
        return {true, ""};
    }
};

// Pseudo decided purely from static / probed env facts (no probe of its own; the
// framework dep gate still probes its deps). Covers kvm / mount_image /
// read_part_table / usb / 80211 / nvme_tcp.
class EnvFactCheck final : public SupportCheck {
public:
    enum class Kind { kKvm, kMountImage, kReadPart, kUsb, kWifi80211, kNvmeTcp };
    EnvFactCheck(const char* label, std::string prefix, Kind kind)
        : label_(label), prefix_(std::move(prefix)), kind_(kind) {}
    const char* name() const override { return label_; }
    bool owns(const syz::SyscallMeta& c) const override {
        return c.is_pseudo() && c.call_name().rfind(prefix_, 0) == 0;
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target&) const override {
        return {};  // env facts only
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target& target,
                           const SupportEnv& env, const TrialResults&) const override {
        const std::string& name = c.name();
        switch (kind_) {
        case Kind::kKvm:
            if (target.arch() != "amd64") return {false, "kvm: worker arch is not amd64"};
            if (name.find("$arm64") != std::string::npos ||
                name.find("$riscv64") != std::string::npos ||
                name.find("$ppc64") != std::string::npos) {
                return {false, "kvm: non-amd64 variant"};
            }
            if (env.probed && !env.has_kvm) return {false, "kvm: /dev/kvm not openable"};
            return {true, ""};
        case Kind::kMountImage:
            if (!env.sandbox_is_none) return {false, "mount_image: requires sandbox=none"};
            if (env.probed && !mount_fs_present(name, env)) {
                return {false, "mount_image: filesystem not in /proc/filesystems"};
            }
            return {true, ""};
        case Kind::kReadPart:
            if (!env.sandbox_is_none) return {false, "read_part_table: requires sandbox=none"};
            return {true, ""};
        case Kind::kUsb:
            if (!env.sandbox_is_none) return {false, "usb: requires sandbox=none"};
            if (env.probed && !env.has_raw_gadget) {
                return {false, "usb: /dev/raw-gadget not openable"};
            }
            return {true, ""};
        case Kind::kWifi80211:
            if (env.probed && env.kernel_major != 0 &&
                (env.kernel_major * 1000 + env.kernel_minor) < (4 * 1000 + 17)) {
                return {false, "wifi: kernel 4.17 required"};
            }
            return {true, ""};
        case Kind::kNvmeTcp:
            if (!env.sandbox_is_none) return {false, "nvme_tcp: requires sandbox=none"};
            return {true, ""};
        }
        return {true, ""};
    }

private:
    const char* label_;
    std::string prefix_;
    Kind        kind_;
};

// syz_init_net_socket — syz onlySandboxNone + linuxSupportedSocket.
class InitNetSocketCheck final : public SupportCheck {
public:
    const char* name() const override { return "init-net-socket"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return c.is_pseudo() && c.call_name() == "syz_init_net_socket";
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta& c,
                                  const syz::Target&) const override {
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{c.name(), build_socket_variant_call(c)});
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv& env, const TrialResults& t) const override {
        if (!env.sandbox_is_none) return {false, "init_net_socket: requires sandbox=none"};
        return socket_verdict(c, t);
    }
};

// syz_open_dev$<dev> — syz linuxSyzOpenDevSupported. syz_open_dev$char/block
// (arg0 a const dev-type, not a path template) are always supported. Otherwise
// arg0 is a "#"-templated device path ("/dev/hidraw#", …); open the substituted
// concrete paths and keep iff ANY opens. If none open, fall back like syz: the
// USB-created nodes (hidraw / usb hiddev / input) are kept when /dev/raw-gadget
// is available (env.has_raw_gadget), and /dev/ublk* when /dev/ublk-control opens.
class SyzOpenDevCheck final : public SupportCheck {
public:
    const char* name() const override { return "syz-open-dev"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return c.is_pseudo() && c.call_name() == "syz_open_dev";
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta& c,
                                  const syz::Target& target) const override {
        const std::string tmpl = template_path(c);
        if (tmpl.empty()) return {};  // $char/$block const arg0, or no '#' → always ok
        std::vector<ProbeSpec> out;
        std::unordered_set<std::string> seen;
        for (const std::string& path : syz_open_dev_paths(c, tmpl)) {
            if (!seen.insert(path).second) continue;
            if (std::unique_ptr<syz::Call> call = build_openat_path_call(target, path)) {
                out.push_back(ProbeSpec{"open:" + path, std::move(call)});
            }
        }
        if (tmpl.rfind("/dev/ublk", 0) == 0) {  // ublk fallback (rootCanOpen /dev/ublk-control)
            if (std::unique_ptr<syz::Call> call =
                    build_openat_path_call(target, "/dev/ublk-control")) {
                out.push_back(ProbeSpec{"open:/dev/ublk-control", std::move(call)});
            }
        }
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv& env, const TrialResults& t) const override {
        const std::string tmpl = template_path(c);
        if (tmpl.empty()) return {true, ""};
        bool any_ok = false;
        bool any_evidence = false;
        for (const std::string& path : syz_open_dev_paths(c, tmpl)) {
            const ProbeOutcome* o = trial_of(t, "open:" + path);
            if (o != nullptr && o->executed) {
                any_evidence = true;
                if (!is_absent_errno(o->err)) { any_ok = true; break; }
            }
        }
        if (any_ok || !any_evidence) return {true, ""};  // openable, or no evidence → keep
        // All probed paths absent → syz's USB/ublk fallbacks before disabling.
        auto starts = [&](const char* p) { return tmpl.rfind(p, 0) == 0; };
        if ((starts("/dev/hidraw") || starts("/dev/usb/hiddev") || starts("/dev/input/")) &&
            env.has_raw_gadget) {
            return {true, ""};  // created by connected USB devices
        }
        if (starts("/dev/ublk")) {
            const ProbeOutcome* u = trial_of(t, "open:/dev/ublk-control");
            if (u != nullptr && u->executed && !is_absent_errno(u->err)) return {true, ""};
        }
        return {false, "failed to open " + tmpl};
    }

private:
    // The "#"-templated path of arg0, or "" for $char/$block (const arg0) and
    // any descriptor whose arg0 isn't a single-valued string with a '#'.
    static std::string template_path(const syz::SyscallMeta& c) {
        if (c.args().empty()) return {};
        const syz::Type* a0 = c.args()[0].type();
        if (a0 != nullptr && a0->kind() == syz::TypeKind::kConst) return {};  // $char/$block
        const std::string tmpl = extract_const_string_arg(c, 0);
        if (tmpl.find('#') == std::string::npos) return {};
        return tmpl;
    }
};

// mount (real syscall) — syz linuxSupportedMount = linuxSupportedFilesystem at
// arg 2: the fstype is a const string (mount$<fs>); if it's not in
// /proc/filesystems the mount can't work. (syz_mount_image$<fs> is the pseudo
// handled by EnvFactCheck::kMountImage; this is the bare mount(2) syscall.)
class MountFsCheck final : public SupportCheck {
public:
    const char* name() const override { return "mount"; }
    bool owns(const syz::SyscallMeta& c) const override {
        return !c.is_pseudo() && c.call_name() == "mount";
    }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target&) const override {
        return {};  // env fact: /proc/filesystems
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv& env, const TrialResults&) const override {
        if (!env.probed) return {true, ""};                 // no evidence → keep
        const std::string fs = extract_const_string_arg(c, 2);  // filesystemtype arg
        if (fs.empty()) return {true, ""};                  // generic mount → keep
        for (const auto& f : env.filesystems) {
            if (f == fs) return {true, ""};
        }
        return {false, "mount: filesystem not in /proc/filesystems"};
    }
};

// Catch-all for real syscalls — syz's generic ENOSYS sweep. Pure: no per-syscall
// knowledge.
class DefaultRealCheck final : public SupportCheck {
public:
    const char* name() const override { return "default"; }
    bool owns(const syz::SyscallMeta& c) const override { return !c.is_pseudo(); }
    // syz default check (linux_syscalls.go:20-35): the bare ENOSYS trial is keyed
    // by the BASE call_name and DEDUPED across all $variants — ENOSYS depends only
    // on the syscall number, identical for every variant, so probing each variant
    // is redundant (and bloats the batch → blocking calls mask variant-tails →
    // nondeterministic "no evidence" keeps). Probe the plain base once (tag =
    // call_name); if the bare base isn't in the schema, syz uses the first variant
    // — here `c` (the gather dedup by tag collapses all variants to one probe).
    std::vector<ProbeSpec> probes(const syz::SyscallMeta& c,
                                  const syz::Target& target) const override {
        const std::string base = c.call_name();
        const syz::SyscallMeta* m = target.find_syscall(base);  // plain base syscall
        if (m == nullptr) m = &c;                                // none → first variant
        std::vector<ProbeSpec> out;
        out.push_back(ProbeSpec{base, build_bare_call(*m)});
        return out;
    }
    SupportVerdict verdict(const syz::SyscallMeta& c, const syz::Target&,
                           const SupportEnv&, const TrialResults& t) const override {
        const ProbeOutcome* o = trial_of(t, c.call_name());  // base-keyed result
        if (o != nullptr && o->executed && o->err == ENOSYS) return {false, "ENOSYS"};
        return {true, ""};
    }
};

// Catch-all for pseudos with no specialized owner — syz's alwaysSupported. The
// framework dep gate (resolve_call_support) still applies.
class AlwaysSupportedCheck final : public SupportCheck {
public:
    const char* name() const override { return "always-supported"; }
    bool owns(const syz::SyscallMeta& c) const override { return c.is_pseudo(); }
    std::vector<ProbeSpec> probes(const syz::SyscallMeta&,
                                  const syz::Target&) const override { return {}; }
    SupportVerdict verdict(const syz::SyscallMeta&, const syz::Target&,
                           const SupportEnv&, const TrialResults&) const override {
        return {true, ""};
    }
};

std::vector<std::unique_ptr<SupportCheck>> build_registry() {
    std::vector<std::unique_ptr<SupportCheck>> r;
    // Specialized checks first (their owns() are specific, non-overlapping).
    r.push_back(std::make_unique<SocketCheck>());
    r.push_back(std::make_unique<OpenatDeviceCheck>());
    r.push_back(std::make_unique<PkeyCheck>());
    r.push_back(std::make_unique<EnvFactCheck>("kvm", "syz_kvm", EnvFactCheck::Kind::kKvm));
    r.push_back(std::make_unique<EnvFactCheck>("mount-image", "syz_mount_image",
                                               EnvFactCheck::Kind::kMountImage));
    r.push_back(std::make_unique<EnvFactCheck>("read-part-table", "syz_read_part_table",
                                               EnvFactCheck::Kind::kReadPart));
    r.push_back(std::make_unique<EnvFactCheck>("usb", "syz_usb", EnvFactCheck::Kind::kUsb));
    r.push_back(std::make_unique<EnvFactCheck>("wifi-80211", "syz_80211",
                                               EnvFactCheck::Kind::kWifi80211));
    r.push_back(std::make_unique<EnvFactCheck>("nvme-tcp", "syz_socket_connect_nvme_tcp",
                                               EnvFactCheck::Kind::kNvmeTcp));
    r.push_back(std::make_unique<InitNetSocketCheck>());
    r.push_back(std::make_unique<GenetlinkCheck>());
    r.push_back(std::make_unique<SyzOpenDevCheck>());
    r.push_back(std::make_unique<MountFsCheck>());
    // canOpen pseudos (syz rootCanOpen/canOpen on a fixed path).
    r.push_back(std::make_unique<CanOpenCheck>(
        "vhci", std::vector<std::string>{"syz_emit_vhci"}, "/dev/vhci", false, "vhci"));
    r.push_back(std::make_unique<CanOpenCheck>(
        "btf", std::vector<std::string>{"syz_btf_id_by_name"},
        "/sys/kernel/btf/vmlinux", true, "btf"));
    r.push_back(std::make_unique<CanOpenCheck>(
        "tun", std::vector<std::string>{"syz_emit_ethernet", "syz_extract_tcp_res"},
        "/dev/net/tun", false, "tun"));
    r.push_back(std::make_unique<CanOpenCheck>(
        "procfs", std::vector<std::string>{"syz_open_procfs"}, "/proc/cmdline", false,
        "open_procfs"));
    r.push_back(std::make_unique<CanOpenCheck>(
        "usbip", std::vector<std::string>{"syz_usbip_server_init"},
        "/sys/devices/platform/vhci_hcd.0/attach", false, "usbip"));
    // Catch-alls last.
    r.push_back(std::make_unique<DefaultRealCheck>());
    r.push_back(std::make_unique<AlwaysSupportedCheck>());
    return r;
}

}  // namespace

const std::vector<std::unique_ptr<SupportCheck>>& support_checks() {
    static const std::vector<std::unique_ptr<SupportCheck>> kRegistry = build_registry();
    return kRegistry;
}

const SupportCheck& owning_check(const syz::SyscallMeta& call) {
    for (const auto& c : support_checks()) {
        if (c->owns(call)) return *c;
    }
    // The catch-alls own every real/pseudo syscall, so this is unreachable; the
    // last entry is a safe fallback.
    return *support_checks().back();
}

std::vector<ProbeSpec> gather_probes(
    const syz::Target& target,
    const std::vector<const syz::SyscallMeta*>& candidates) {
    std::vector<ProbeSpec> out;
    std::unordered_set<std::string> seen;
    auto add = [&](ProbeSpec spec) {
        if (spec.call == nullptr) return;
        if (seen.insert(spec.tag).second) out.push_back(std::move(spec));
    };
    for (const syz::SyscallMeta* m : candidates) {
        if (m == nullptr) continue;
        for (ProbeSpec& spec : owning_check(*m).probes(*m, target)) add(std::move(spec));
        // Framework-level PseudoSyscallDeps gate: bare-probe each dep syscall.
        if (m->is_pseudo()) {
            if (const std::vector<std::string>* deps = pseudo_syscall_deps(m->call_name())) {
                for (const std::string& dep : *deps) {
                    if (seen.count(dep)) continue;
                    if (const syz::SyscallMeta* dm = target.find_syscall(dep)) {
                        add(ProbeSpec{dep, build_bare_call(*dm)});
                    }
                }
            }
        }
    }
    return out;
}

}  // namespace refuzz::control::support
