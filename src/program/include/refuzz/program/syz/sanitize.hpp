// reFuzz syz_v2 — per-call invariant repair (sanitize).
//
// Equivalent to syzkaller `prog.Prog.sanitizeFix()` and the
// `sys/<os>/init.go::neutralize` machinery, adapted to reFuzz's
// own typed IR + Target abstraction. We do NOT run syzkaller Go
// as a runtime dependency; we re-implement the necessary
// per-syscall invariants in C++ using reFuzz Target's `find_const`
// + the generated `kSyzConst_*` table.
//
// Hook points (reFuzz-side):
//   - minimizer candidate evaluation: every typed candidate is
//     sanitize-fixed before serialize_for_exec. Mirrors syzkaller's
//     `pred` wrapper in `prog/minimization.go:61` calling
//     `p.sanitizeFix()` ahead of validate + the user predicate.
//   - (future) mutator commit + generation commit, to bring the
//     reFuzz mutate/generate paths to byte-parity with syzkaller.
//     Not wired today — minimizer is the only consumer and the only
//     site oracle #24 covers.
//
// Coverage today (linux/amd64):
//   mremap (MREMAP_MAYMOVE → +MREMAP_FIXED)
//   mmap   (force MAP_FIXED — UnixNeutralizer port)
//   syslog (cmd substitution for CONSOLE_OFF/ON/LEVEL/CLEAR)
//   fanotify_mark (clear FAN_*_PERM bits)
//   ptrace (PTRACE_TRACEME → ~0)
//   arch_prctl (ARCH_SET_FS → ARCH_SET_GS)
//   init_module (size cap at 1 MiB)
//   ioctl  (FIFREEZE / SNAPSHOT_FREEZE / SNAPSHOT_POWER_OFF →
//           FITHAW; TIOCSSERIAL → TIOCGSERIAL — host-safety subset
//           of upstream `neutralizeIoctl`)
// NOT ported here (gated on fixture demand): syz_init_net_socket,
// syz_open_dev, sched_setattr, setsockopt$EBT_SO_SET_ENTRIES,
// mknod/exit code-67 fixups. They live in syzkaller-side helpers
// that walk pointer/group/union graphs; the dispatch is a no-op
// fall-through for those syscall names today.

#pragma once

#include "refuzz/program/syz/prog.hpp"

namespace refuzz::program::syz {

class Target;

// Apply target-specific invariant repairs to a single Call in place.
// Dispatch is on `call.meta()->call_name()`; unknown call names are a
// no-op (matches syzkaller's switch fall-through).
void sanitize_call(Call& call, const Target& target);

// Apply `sanitize_call` to every call in `prog`. Mirrors
// `prog.Prog.sanitizeFix` semantics. Safe to call on a Prog without a
// Target (no-op then).
void sanitize_fix(Prog& prog);

} // namespace refuzz::program::syz
