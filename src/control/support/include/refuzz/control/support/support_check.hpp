// Copyright 2026 reFuzz project author -------youngkk.
//
// [syscall-support-detection] The specialized support-check abstraction — the
// reFuzz analog of syz's `linuxSyscallChecks` map (pkg/vminfo/linux_syscalls.go).
//
// Each SupportCheck is ONE cohesive unit owning BOTH the probe(s) it needs run
// in the VM AND the errno/env interpretation — exactly like a syz checkFunc
// (`socket(af, Vals[0], proto)` + errno, `canOpen("/dev/vhci")` + errno, …). The
// generic ENOSYS sweep stays a pure catch-all (DefaultCheck) that never opens a
// hole for a specific syscall; socket / device-open / BTF / vhci / tun / procfs
// / usbip / pkey / genetlink are all peer specialized checks here.
//
// reFuzz batches probes (build all → execute → interpret), so a check exposes
// two methods instead of syz's one synchronous call: `probes()` (construction)
// and `verdict()` (interpretation), kept in the SAME unit. See
// docs/plans/support-check-abstraction.md.

#pragma once

#include "refuzz/control/support/support_checker.hpp"  // SupportEnv, SupportVerdict, TrialResults
#include "refuzz/program/syz/prog.hpp"                  // Call
#include "refuzz/program/syz/target.hpp"                // Target, SyscallMeta

#include <memory>
#include <string>
#include <vector>

namespace refuzz::control::support {

namespace syz = ::refuzz::program::syz;

// One probe call a check needs executed in the VM. `tag` is the TrialResults key
// the check later reads its errno from: the candidate's own name for bare /
// own-call probes (Default, OpenatDevice, Socket variant), or a literal like
// "open:/dev/vhci" for shared synthetic probes (so every syz_usb_* dedups onto
// one /dev/raw-gadget open). Checks that decide from static env facts return none.
struct ProbeSpec {
    std::string                                   tag;
    std::unique_ptr<::refuzz::program::syz::Call> call;
};

// A specialized support check (one syz linuxSyscallChecks entry). Cohesive:
// owns its probe construction and its interpretation.
class SupportCheck {
public:
    virtual ~SupportCheck() = default;
    virtual const char* name() const = 0;
    // Does this check own `call`? First owner in the registry wins; the
    // catch-all Default (real) / AlwaysSupported (pseudo) checks own everything
    // and MUST be last.
    virtual bool owns(const syz::SyscallMeta& call) const = 0;
    // VM trials this check needs for `call` (empty for static / env-fact checks).
    virtual std::vector<ProbeSpec> probes(const syz::SyscallMeta& call,
                                          const syz::Target& target) const = 0;
    // Verdict from env facts + probe outcomes (keyed by this check's probe tags).
    // Keep on missing/!executed evidence — never disable on a guess (syz keeps a
    // syscall on missing info).
    virtual SupportVerdict verdict(const syz::SyscallMeta& call,
                                   const syz::Target& target,
                                   const SupportEnv& env,
                                   const TrialResults& trials) const = 0;
};

// The ordered registry (first owns() wins; Default/AlwaysSupported last).
const std::vector<std::unique_ptr<SupportCheck>>& support_checks();

// The check that owns `call` (always non-null — the catch-alls own everything).
const SupportCheck& owning_check(const syz::SyscallMeta& call);

// Deduped probe specs (by tag) for the given candidates: each candidate's owning
// check's probes() plus the bare probes for any pseudo deps (the framework-level
// PseudoSyscallDeps gate). The machine-check batches + executes these, then keys
// the outcomes back by tag into TrialResults for resolve_enabled_calls.
std::vector<ProbeSpec> gather_probes(
    const syz::Target& target,
    const std::vector<const syz::SyscallMeta*>& candidates);

} // namespace refuzz::control::support
