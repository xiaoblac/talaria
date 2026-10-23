// reFuzz syz_v2 — per-call invariant repair (sanitize) impl.
//
// See sanitize.hpp for scope + design notes.

#include "refuzz/program/syz/sanitize.hpp"

#include "refuzz/program/syz/generated/consts.gen.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <string_view>

namespace refuzz::program::syz {
namespace {

// Tiny helpers — no syzkaller-go dependency, pure typed-IR walk.

ConstArg* AsConstArgMutable(Arg* a) {
    return const_cast<ConstArg*>(as_const_arg(a));
}

void SetConstArgVal(Arg* a, std::uint64_t val) {
    if (auto* c = AsConstArgMutable(a); c != nullptr) {
        c->set_val(val);
    }
}

std::uint64_t ConstArgVal(const Arg* a, std::uint64_t fallback = 0) {
    const auto* c = as_const_arg(a);
    return c != nullptr ? c->val() : fallback;
}

// --- Per-syscall sanitizers (linux/amd64 subset; see header) ---

void SanitizeMremap(Call& call) {
    // mremap(old_addr, old_size, new_size, flags, new_addr).
    // syzkaller: if flags & MREMAP_MAYMOVE, force MREMAP_FIXED.
    // Otherwise mremap is non-deterministic about whether it moves.
    if (call.mutable_args().size() < 4) return;
    auto* flags = AsConstArgMutable(call.mutable_args()[3].get());
    if (flags == nullptr) return;
    constexpr auto kMaymove =
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_MREMAP_MAYMOVE);
    constexpr auto kFixed =
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_MREMAP_FIXED);
    if ((flags->val() & kMaymove) != 0) {
        flags->set_val(flags->val() | kFixed);
    }
}

void SanitizeSyslog(Call& call) {
    // syslog(cmd, buf, len). cmd is a 32-bit int, force u32 cast.
    // Replace CONSOLE_OFF / CONSOLE_ON / CONSOLE_LEVEL / CLEAR with
    // SIZE_UNREAD — those four would silence kernel console output,
    // which the fuzzer needs.
    if (call.mutable_args().empty()) return;
    auto* cmd = AsConstArgMutable(call.mutable_args()[0].get());
    if (cmd == nullptr) return;
    cmd->set_val(static_cast<std::uint64_t>(static_cast<std::uint32_t>(cmd->val())));
    const auto v = cmd->val();
    if (v == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SYSLOG_ACTION_CONSOLE_OFF) ||
        v == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SYSLOG_ACTION_CONSOLE_ON) ||
        v == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SYSLOG_ACTION_CONSOLE_LEVEL) ||
        v == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SYSLOG_ACTION_CLEAR)) {
        cmd->set_val(static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SYSLOG_ACTION_SIZE_UNREAD));
    }
}

void SanitizeFanotifyMark(Call& call) {
    // fanotify_mark(fd, flags, mask, dfd, pathname).
    // Clear FAN_*_PERM bits in mask. PERM ops force the program to
    // ack open requests; if the test harness doesn't ack, the kernel
    // hangs unkillable. See syzkaller-bugs/pD-vbqJu6U0.
    if (call.mutable_args().size() < 3) return;
    auto* mask = AsConstArgMutable(call.mutable_args()[2].get());
    if (mask == nullptr) return;
    constexpr auto kPermBits =
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_FAN_OPEN_PERM) |
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_FAN_ACCESS_PERM) |
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_FAN_OPEN_EXEC_PERM);
    mask->set_val(mask->val() & ~kPermBits);
}

void SanitizePtrace(Call& call) {
    // ptrace(req, pid, addr, data). PTRACE_TRACEME makes the test
    // process untraceable / unkillable; replace with ~0 so the call
    // fails cleanly in the kernel.
    if (call.mutable_args().empty()) return;
    auto* req = AsConstArgMutable(call.mutable_args()[0].get());
    if (req == nullptr) return;
    if (static_cast<std::uint64_t>(static_cast<std::uint32_t>(req->val())) ==
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_PTRACE_TRACEME)) {
        req->set_val(~std::uint64_t{0});
    }
}

void SanitizeArchPrctl(Call& call) {
    // arch_prctl(cmd, addr). ARCH_SET_FS lets the program scribble at
    // the TLS pointer; map to ARCH_SET_GS so signal handling stays
    // sane and the test process can be killed.
    if (call.mutable_args().empty()) return;
    auto* cmd = AsConstArgMutable(call.mutable_args()[0].get());
    if (cmd == nullptr) return;
    if (static_cast<std::uint64_t>(static_cast<std::uint32_t>(cmd->val())) ==
        static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_ARCH_SET_FS)) {
        cmd->set_val(static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_ARCH_SET_GS));
    }
}

void SanitizeInitModule(Call& call) {
    // init_module(image, len, args). Cap the size at 1 MiB —
    // otherwise the kernel vmalloc'd buffer is unbounded and not
    // accounted to memcg, leading to host-wide OOM.
    if (call.mutable_args().size() < 2) return;
    auto* sz = AsConstArgMutable(call.mutable_args()[1].get());
    if (sz == nullptr) return;
    constexpr std::uint64_t kCap = std::uint64_t{1} << 20;
    sz->set_val(sz->val() % kCap);
}

void SanitizeIoctl(Call& call) {
    // ioctl(fd, cmd, arg). Subset port of syzkaller's
    // `sys/linux/init.go::neutralizeIoctl` — only the host-safety
    // critical cmd substitutions (FIFREEZE / SNAPSHOT_FREEZE /
    // SNAPSHOT_POWER_OFF freeze or shut down the host; TIOCSSERIAL
    // can write to random kernel memory under root). Map all to
    // FITHAW / TIOCGSERIAL so the syscall is exercised but harmless.
    if (call.mutable_args().size() < 2) return;
    auto* cmd = AsConstArgMutable(call.mutable_args()[1].get());
    if (cmd == nullptr) return;
    const auto val32 =
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(cmd->val()));
    if (val32 == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_FIFREEZE) ||
        val32 == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SNAPSHOT_FREEZE) ||
        val32 == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_SNAPSHOT_POWER_OFF)) {
        cmd->set_val(static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_FITHAW));
    } else if (val32 == static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_TIOCSSERIAL)) {
        cmd->set_val(static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_TIOCGSERIAL));
    }
}

void SanitizeMmap(Call& call) {
    // mmap(addr, len, prot, flags, fd, offset). Mirrors
    // syzkaller's UnixNeutralizer mmap branch
    // (sys/targets/common.go:85-93): force MAP_FIXED into flags so
    // a fixed-address placement isn't reinterpreted by the kernel
    // as a hint and re-routed to a random VMA. The bifrost variant
    // is `mmap$bifrost` which we exclude because it is documented
    // as "doesn't support MAP_FIXED" — but reFuzz today does not
    // ship that variant in linux/amd64, so the meta-name guard is
    // belt-and-suspenders.
    if (call.meta() != nullptr && call.meta()->name() == "mmap$bifrost") {
        return;
    }
    if (call.mutable_args().size() < 4) return;
    auto* flags = AsConstArgMutable(call.mutable_args()[3].get());
    if (flags == nullptr) return;
    flags->set_val(flags->val() |
                   static_cast<std::uint64_t>(refuzz::fuzzer::syz::consts::kSyzConst_MAP_FIXED));
}

} // namespace

void sanitize_call(Call& call, const Target& target) {
    (void)target;  // arch_prctl/syslog use compile-time consts; kept
                   // in the signature for forward-compat with arch
                   // variants that need runtime const lookup.
    if (call.meta() == nullptr) {
        return;
    }
    const std::string_view name = call.meta()->call_name();
    if (name == "mremap")           SanitizeMremap(call);
    else if (name == "mmap")        SanitizeMmap(call);
    else if (name == "syslog")      SanitizeSyslog(call);
    else if (name == "fanotify_mark") SanitizeFanotifyMark(call);
    else if (name == "ptrace")      SanitizePtrace(call);
    else if (name == "arch_prctl")  SanitizeArchPrctl(call);
    else if (name == "init_module") SanitizeInitModule(call);
    else if (name == "ioctl")       SanitizeIoctl(call);
    // Cases NOT yet ported (see header rationale):
    //   syz_init_net_socket, syz_open_dev, sched_setattr,
    //   setsockopt$EBT_SO_SET_ENTRIES.
    // Unknown names: no-op (matches syzkaller switch fall-through).
}

void sanitize_fix(Prog& prog) {
    if (prog.target() == nullptr) return;
    for (auto& call : prog.mutable_calls()) {
        if (call != nullptr) {
            sanitize_call(*call, *prog.target());
        }
    }
}

} // namespace refuzz::program::syz
