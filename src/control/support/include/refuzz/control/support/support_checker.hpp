// Copyright 2026 reFuzz project author -------youngkk.
//
// [syscall-support-detection] Host-side syscall support detection — the
// orchestration step that decides which syscalls the *current environment*
// can actually run, mirroring syzkaller's pkg/vminfo. The IR (program/syz)
// stays pure schema; the operator whitelist (program::syz::compute_enabled_calls)
// answers "which names did the operator pick"; this module answers "is the
// pick runnable here", and produces the final enabled set:
//
//   enabled = whitelist ∩ supported(env)
//
// Phase 1 (this file) decides support from static facts (sandbox + target
// arch). Phase 2 folds worker-probed facts (filesystem list, device
// availability) into SupportEnv, fed by a worker probe under
// executor/channel/worker/.

#pragma once

#include "refuzz/program/syz/target.hpp"   // Target, SyscallMeta, EnabledCalls

#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::control::support {

namespace syz = ::refuzz::program::syz;

// Environment facts the support checks consult. `sandbox_is_none` is the static
// fact (Phase 1). The remaining fields are worker-PROBED facts (Phase 2 / Step
// C), filled by the orchestration glue from the guest's EnvFeatures payload.
// `probed == false` ⇒ static approximation (sandbox + arch only); `probed ==
// true` ⇒ additionally narrow mount by `filesystems`, usb by `has_raw_gadget`,
// kvm by `has_kvm`. Kept transport-free on purpose (semantic fields, not the
// proto/wire struct) so this module depends only on program/.
struct SupportEnv {
    bool sandbox_is_none = true;   // sandbox=none → worker keeps full caps

    bool                     probed = false;          // probed facts below valid?
    std::vector<std::string> filesystems;             // /proc/filesystems names
    bool                     has_raw_gadget = false;  // /dev/raw-gadget openable
    bool                     has_kvm        = false;  // /dev/kvm openable

    // [C4.1] /proc/version kernel version (0/0 = unknown → no-evidence, keep).
    int  kernel_major = 0;
    int  kernel_minor = 0;
    // [C4.1] /sys/kernel/security/lsm. `lsm_present` == false ⇒ list unreadable
    // (securityfs unmounted) ⇒ keep LSM syscalls (don't disable on no evidence).
    bool        lsm_present = false;
    std::string lsms;            // raw lsm contents (comma-separated list)
};

// [machine-check C4.3] Per-syscall trial-exec outcome — the errno a bare probe
// call returned in the live VM (transport-free mirror of
// machine_check::ProbeCallResult; the C4.6 glue converts + fills the map).
// `executed == false` ⇒ the probe never ran this call (abnormal / short output)
// → "no evidence", NOT "unsupported" (syz keeps a syscall on missing info).
struct ProbeOutcome {
    bool executed = false;
    int  err      = 0;   // errno (SyzExecResult.err); ENOSYS ⇒ syscall absent
};

// Trial-exec results keyed by syscall name (syz keys checks by name; pseudo
// deps are name-based too — a base syscall's name() == its call_name()). EMPTY
// ⇒ no trials run yet → resolution falls back to the static approximation (real
// syscalls assumed supported), preserving pre-machine-check behavior. Filled by
// the C4.6 orchestration from machine_check probe results.
struct TrialResults {
    std::unordered_map<std::string, ProbeOutcome> by_name;
};

// Per-syscall verdict + human reason (reason non-empty ⇔ !supported), for the
// machine-check disabled-syscalls report (mirrors syz's check-func string:
// "" = supported, else the disable reason).
struct SupportVerdict {
    bool        supported = true;
    std::string reason;     // e.g. "ENOSYS", "/proc/filesystems lacks ntfs"
};

// The disabled-syscall record is the canonical syz::DisabledCall ({call, reason})
// — env/trial drops and the transitive-closure drops accumulate into ONE list of
// that single type, no parallel struct / no re-creation. See target.hpp.

// [machine-check C4.3] Full per-syscall resolution = static facts (SupportEnv)
// + trial-exec results (TrialResults), mirroring syz pkg/vminfo
// linuxSyscallChecks. Returns a verdict + reason ("" = supported). Categories:
//   * syz_kvm_*            → arch match (amd64 worker); probed ⇒ /dev/kvm
//   * syz_mount_image$<fs> → sandbox=none; probed ⇒ <fs> ∈ /proc/filesystems
//   * syz_read_part_table* → sandbox=none
//   * syz_usb_*            → sandbox=none; probed ⇒ /dev/raw-gadget
//   * syz_80211_*          → probed ⇒ kernel >= 4.17 (HWSIM_ATTR_PERM_ADDR)
//   * name has lsm         → probed + securityfs ⇒ selinux/apparmor/smack ∈
//                            /sys/kernel/security/lsm (syz's per-call tail check)
//   * pseudo deps          → every PseudoSyscallDeps[base] syscall not ENOSYS
//                            (syz gates the call's own check on its deps first)
//   * socket$* / socketpair$* → trial socket(af,type,proto): disable on ENOSYS
//                            or EAFNOSUPPORT, or any nonzero errno when type AND
//                            proto are concrete consts (syz linux_syscalls.go)
//   * DEFAULT real syscall → trial the bare call; ENOSYS ⇒ unsupported
//                            (THE flip — no longer "assume supported")
// Trial categories consult `trials`; an absent / not-executed outcome is "no
// evidence" → keep supported (never over-disable on missing info).
SupportVerdict resolve_call_support(const syz::SyscallMeta& call,
                                    const syz::Target&      target,
                                    const SupportEnv&       env,
                                    const TrialResults&     trials);

// Pseudo→real-syscall dependencies (syz PseudoSyscallDeps), keyed by the BASE
// call name (e.g. "syz_mount_image" → {"memfd_create"}). nullptr ⇒ no deps.
// Exposed so the machine-check driver knows which dep syscalls to trial-probe
// (a pseudo is disabled when any dep is ENOSYS — see resolve_call_support).
const std::vector<std::string>* pseudo_syscall_deps(const std::string& base_call_name);

// Static-only support check (no trial-exec): equivalent to resolve_call_support
// with empty TrialResults — real syscalls assumed supported, pseudos gated by
// static facts only. Kept for callers that resolve before the machine-check.
bool is_supported(const syz::SyscallMeta& call, const syz::Target& target,
                  const SupportEnv& env);

// Resolve the final enabled set = whitelist ∩ supported(env, trials), then run
// the transitive-resource closure. Runs the operator-whitelist glob resolver
// (program::syz::compute_enabled_calls), drops calls failing resolve_call_support,
// then drops calls whose input resources lost their creator
// (syz::transitively_enabled_calls). When `disabled_out` is non-null EVERY drop
// (env/trial + transitive) is appended to it as a syz::DisabledCall — one list,
// one type — feeding the machine-check report (C4.6). Fail-closed: !ok carries
// an error and an empty mask (unknown glob, or the intersection is empty).
syz::EnabledCalls resolve_enabled_calls(const syz::Target&              target,
                                        const std::vector<std::string>& enable,
                                        const std::vector<std::string>& disable,
                                        const SupportEnv&               env,
                                        const TrialResults&             trials,
                                        std::vector<syz::DisabledCall>* disabled_out = nullptr);

// Back-compat overload — static-only (empty trials, no report). Used by callers
// that resolve before the machine-check runs (assembler, kernel profile).
syz::EnabledCalls resolve_enabled_calls(const syz::Target&              target,
                                        const std::vector<std::string>& enable,
                                        const std::vector<std::string>& disable,
                                        const SupportEnv&               env);

} // namespace refuzz::control::support
