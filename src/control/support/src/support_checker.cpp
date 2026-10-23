// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/control/support/support_checker.hpp"

#include "refuzz/control/support/support_check.hpp"  // owning_check, SupportCheck

#include <cctype>   // std::tolower (LSM name match)
#include <cerrno>   // ENOSYS (pseudo dep gate)
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::control::support {

// Pseudo-syscall → real-syscall dependencies. Mirror of syz
// sys/targets/targets.go oses[Linux].PseudoSyscallDeps (keyed by base call
// name). A pseudo is unsupported if ANY dep syscall is ENOSYS (syz checks deps
// around the pseudo's own check). nullptr ⇒ no deps. Used both here (the gate)
// and by support_check gather_probes (to bare-probe the deps).
const std::vector<std::string>* pseudo_syscall_deps(const std::string& base_call_name) {
    static const std::unordered_map<std::string, std::vector<std::string>> kDeps = {
        {"syz_read_part_table", {"memfd_create"}},
        {"syz_mount_image",     {"memfd_create"}},
        {"syz_io_uring_setup",  {"io_uring_setup"}},
        {"syz_clone3",          {"clone3", "exit"}},
        {"syz_clone",           {"clone", "exit"}},
        {"syz_pidfd_open",      {"pidfd_open"}},
    };
    const auto it = kDeps.find(base_call_name);
    return it == kDeps.end() ? nullptr : &it->second;
}

namespace {

// LSM tail (syz linuxSupportedLSM), applied to EVERY call after its own check
// passes: if the name names an LSM (selinux/apparmor/smack) that the live kernel
// hasn't enabled, the call is unsupported. Unreadable list (securityfs not
// mounted) or unprobed env ⇒ no evidence ⇒ keep — never disable on a guess.
SupportVerdict lsm_tail(const syz::SyscallMeta& call, const SupportEnv& env) {
    if (!env.probed || !env.lsm_present) {
        return {true, ""};
    }
    std::string lower = call.name();
    for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    for (const char* lsm : {"selinux", "apparmor", "smack"}) {
        if (lower.find(lsm) == std::string::npos) {
            continue;
        }
        if (env.lsms.find(lsm) == std::string::npos) {
            return {false, std::string(lsm) + " is not enabled"};
        }
    }
    return {true, ""};
}

// Framework PseudoSyscallDeps gate: a pseudo whose dependency syscall trialed
// ENOSYS can't work (syz checks deps around the checkFunc). `dep_out` carries
// the offending dep for the reason string.
bool pseudo_dep_enosys(const syz::SyscallMeta& call, const TrialResults& trials,
                       std::string* dep_out) {
    if (!call.is_pseudo()) return false;
    const std::vector<std::string>* deps = pseudo_syscall_deps(call.call_name());
    if (deps == nullptr) return false;
    for (const std::string& dep : *deps) {
        const auto it = trials.by_name.find(dep);
        if (it != trials.by_name.end() && it->second.executed &&
            it->second.err == ENOSYS) {
            if (dep_out != nullptr) *dep_out = dep;
            return true;
        }
    }
    return false;
}

} // namespace

// syz syscallCheck: the owning specialized check (socket / device-open / canOpen
// / kvm / … or the ENOSYS/AlwaysSupported default), then the framework dep gate,
// then the universal LSM tail. Each specialized check is a cohesive unit owning
// its probe construction + interpretation (see support_check.{hpp,cpp}); this
// function is the dispatch + the two framework-level tails.
SupportVerdict resolve_call_support(const syz::SyscallMeta& call,
                                    const syz::Target&      target,
                                    const SupportEnv&       env,
                                    const TrialResults&     trials) {
    const SupportVerdict v = owning_check(call).verdict(call, target, env, trials);
    if (!v.supported) {
        return v;
    }
    std::string dep;
    if (pseudo_dep_enosys(call, trials, &dep)) {
        return {false, "dep " + dep + " is ENOSYS"};
    }
    return lsm_tail(call, env);
}

bool is_supported(const syz::SyscallMeta& call, const syz::Target& target,
                  const SupportEnv& env) {
    static const TrialResults kNoTrials;  // static-only resolution
    return resolve_call_support(call, target, env, kNoTrials).supported;
}

syz::EnabledCalls resolve_enabled_calls(const syz::Target&              target,
                                        const std::vector<std::string>& enable,
                                        const std::vector<std::string>& disable,
                                        const SupportEnv&               env,
                                        const TrialResults&             trials,
                                        std::vector<syz::DisabledCall>* disabled_out) {
    // Operator whitelist first (pure name-glob over the schema).
    syz::EnabledCalls r = syz::compute_enabled_calls(target, enable, disable);
    if (!r.ok) {
        return r;
    }
    // enabled = whitelist ∩ supported(env, trials).
    const auto& calls = target.syscalls();
    for (const auto& sc : calls) {
        if (!sc) continue;
        const std::uint64_t id = sc->id();
        if (id >= r.mask.size()) continue;
        if (r.mask[id]) {
            const SupportVerdict v = resolve_call_support(*sc, target, env, trials);
            if (!v.supported) {
                r.mask[id] = 0;
                if (disabled_out != nullptr) {
                    disabled_out->push_back(syz::DisabledCall{sc.get(), v.reason});
                }
            }
        }
    }

    // Transitive closure: drop calls whose input resources lost their only
    // enabled creator (e.g. a device-fd consumer after its openat$<dev> creator
    // was filtered). Its drops append to the SAME disabled_out list.
    r.mask = syz::transitively_enabled_calls(target, r.mask, disabled_out);

    bool any = false;
    for (const std::uint8_t v : r.mask) {
        if (v) { any = true; break; }
    }
    if (!any) {
        r.ok = false;
        r.error = "no syscalls enabled (whitelist ∩ supported is empty)";
        r.mask.clear();
    }
    return r;
}

syz::EnabledCalls resolve_enabled_calls(const syz::Target&              target,
                                        const std::vector<std::string>& enable,
                                        const std::vector<std::string>& disable,
                                        const SupportEnv&               env) {
    static const TrialResults kNoTrials;
    return resolve_enabled_calls(target, enable, disable, env, kNoTrials, nullptr);
}

} // namespace refuzz::control::support
