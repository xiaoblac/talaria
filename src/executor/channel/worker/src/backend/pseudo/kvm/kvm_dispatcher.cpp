// PR-D2 — KVM family dispatcher implementation.
//
// Dispatches the 6 syz_kvm$* pseudos to per-name handlers. State (VM/vCPU/
// guest-memory) lives in `kvm_state.cpp` (TU-local map keyed by &PseudoContext
// per plan §5.2-amendment). Helpers (open kvm / create vm / mmap / create
// vcpu / run) live in `kvm_helpers.cpp`.
//
// Per plan §10 Q6 rule 3 (handler-active + non-degradable), the cap gate
// (kCapNeedsRoot|kCapNeedsKvm) is enforced upstream of this dispatcher in
// pseudo_dispatcher.cpp:96-99 so we know the worker holds the right caps
// when we get here.

#include "worker/backend/pseudo/kvm/kvm_dispatcher.hpp"

#include "worker/backend/pseudo/kvm/kvm_helpers.hpp"
#include "worker/backend/pseudo/kvm/kvm_layout.hpp"
#include "worker/backend/pseudo/kvm/kvm_state.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {

namespace {

PseudoResult Error(int err, const char* reason = nullptr)
{
    return PseudoResult{-1, err, reason};
}

struct KvmText {
    std::uintptr_t typ;
    const void*    text;
    std::uintptr_t size;
};

static_assert(sizeof(KvmText) == 3 * sizeof(std::uintptr_t));

// ---- syz_kvm_setup_syzos_vm$x86 ----------------------------------------
// Upstream signature: syz_kvm_setup_syzos_vm(vmfd, host_mem). The corpus
// normally creates the VM with raw KVM_CREATE_VM first and passes that fd here.
// We honor that fd, map the vendored syzOS GPA layout, install the guest
// section, and return the caller's host_mem pointer so result resources match
// syzkaller's executor contract.
PseudoResult SetupSyzosVm(const PseudoContext& ctx,
                          const intptr_t* args, uint32_t argc)
{
    KvmState& state = GetOrCreateKvmState(ctx);

    const int external_vm_fd =
        (argc >= 1 && args != nullptr) ? static_cast<int>(args[0]) : 0;
    if (external_vm_fd > 0) {
        state.vm_fd = external_vm_fd;
        // The real ioctl$KVM_CREATE_VM fd (r1) is owned by the program's resource
        // lifecycle, not by this KvmState — never close it here (it would race /
        // double-close the executor's own fd cleanup). Only the self-created
        // branch below owns vm_fd. [stateless]
        state.vm_fd_borrowed = true;
    } else if (KvmCreateVm(state) < 0) {
        return Error(errno, "KVM_CREATE_VM");
    }

    if (KvmMapRegions(state, kvm_layout::kSyzosMemRegions,
                      kvm_layout::kSyzosMemRegionsCount) < 0) {
        return Error(errno, "KVM_SET_USER_MEMORY_REGION (multi-region)");
    }
    if (KvmInstallSyzosGuest(state) < 0) {
        return Error(errno, "install syzOS guest");
    }

    const auto host_mem_arg =
        (argc >= 2 && args != nullptr) ? static_cast<std::uintptr_t>(args[1]) : 0;
    if (host_mem_arg != 0) {
        auto* out = reinterpret_cast<kvm_layout::KvmSyzVm*>(host_mem_arg);
        *out = state.syz_vm;
        return PseudoResult{static_cast<intptr_t>(host_mem_arg), 0, nullptr};
    }
    return PseudoResult{0, 0, nullptr};
}

// ---- syz_kvm_add_vcpu$x86 ----------------------------------------------
// Args: (vm_handle, vcpu_descriptor). Creates a NEW vCPU on the
// previously-set-up VM (mirrors upstream common_kvm_amd64.h:1178-1202).
// Returns the new vcpu fd on success (matches upstream return).
//
// [PR-D2 review fix B6] Previous reFuzz impl closed the previous vCPU
// before creating a new one — wrong. Upstream keeps prior vCPUs alive
// + increments `next_cpu_id`. KvmCreateVcpu now appends to
// state.vcpu_slots and bumps state.next_cpu_id; this handler just calls
// it and returns the new fd. assert_* handlers continue to inspect
// state.vcpu_run (latest), which is the typical fuzz program pattern.
//
PseudoResult AddVcpu(const PseudoContext& ctx,
                     const intptr_t* args, uint32_t argc)
{
    KvmState& state = GetOrCreateKvmState(ctx);

    // [stateless KVM] a0 (args[0]) is the AUTHORITATIVE VM state: SetupSyzosVm
    // wrote the full KvmSyzVm (vm_fd + user_text/gpa0_mem/pt_pool/globals +
    // region_base[15]) into the program's host_mem VMA. In the threaded executor
    // a program's calls are NOT pinned to one thread, so add_vcpu may land on a
    // worker thread whose (PseudoContext-keyed) KvmState was never set up by
    // setup_syzos_vm. When that happens, rehydrate the entire VM from a0 — worker
    // threads are pthreads sharing one address space and vm_fd is a process-wide
    // fd, so the VM is fully reachable. Crucially the recovered struct now carries
    // region_base[], so KvmHostAddrForGpa resolves GLOBALS/GDT/IDT/PT_POOL from a0
    // and KvmInstallUserCode/SetupGdtLdtPg build the guest page tables + text_sizes
    // correctly on the migrated thread (the missing region_base was the precise
    // reason an earlier partial recovery handed back a vcpu fd whose guest was
    // never set up → KVM_RUN #UD'd). vm_fd_borrowed keeps Cleanup from closing the
    // fd this thread doesn't own. The per-vcpu run-mmap needs kvm_root_fd (absent
    // here) — non-fatal: the program does its own mmap$KVM_VCPU and feeds that
    // kvm_run pointer to the assert handlers.
    // SAFETY: a FAILED syz_kvm_setup_syzos_vm returns -1, and dependents may run
    // with that fault value, so reject anything outside canonical lower-half
    // userspace (excludes 0, small fault sentinels, and -1) before dereferencing.
    const auto vm_handle =
        (argc >= 1 && args != nullptr) ? static_cast<std::uintptr_t>(args[0]) : 0;
    if ((state.vm_fd < 0 || !state.syz_vm_ready) &&
        vm_handle >= 0x1000 && vm_handle < (std::uintptr_t{1} << 47)) {
        const auto* vm = reinterpret_cast<const kvm_layout::KvmSyzVm*>(vm_handle);
        if (vm->vmfd > 0 && vm->user_text != nullptr) {
            state.vm_fd         = vm->vmfd;
            state.vm_fd_borrowed = true;
            state.next_cpu_id   = vm->next_cpu_id;
            state.user_text     = vm->user_text;
            state.gpa0_mem      = vm->gpa0_mem;
            state.syz_vm        = *vm;
            state.syz_vm_ready  = true;
        }
    }

    if (state.vm_fd < 0 || !state.syz_vm_ready) {
        return Error(EINVAL, "syz_kvm_add_vcpu: VM not yet created");
    }

    const KvmText* utext = nullptr;
    if (argc >= 2 && args != nullptr && args[1] != 0) {
        utext = reinterpret_cast<const KvmText*>(args[1]);
    }
    const void* text = utext != nullptr ? utext->text : nullptr;
    const auto text_size =
        utext != nullptr ? static_cast<std::size_t>(utext->size) : 0U;

    if (KvmCreateVcpu(state) < 0) {
        return Error(errno, "KVM_CREATE_VCPU");
    }
    // Upstream install_user_code() is void: after KVM_CREATE_VCPU succeeds,
    // setup_gdt_ldt_pg/setup_cpuid/reset_cpu_regs ioctl failures do not change
    // syz_kvm_add_vcpu's return value. Keep the return contract identical; the
    // following KVM_RUN/assert calls will expose any setup problem.
    (void)KvmInstallUserCode(state, text, text_size);

    state.syz_vm.next_cpu_id = state.next_cpu_id;
    if (argc >= 1 && args != nullptr && args[0] != 0) {
        auto* out = reinterpret_cast<kvm_layout::KvmSyzVm*>(
            static_cast<std::uintptr_t>(args[0]));
        out->next_cpu_id = state.syz_vm.next_cpu_id;
    }
    return PseudoResult{static_cast<intptr_t>(state.vcpu_fd), 0, nullptr};
}

// ---- syz_kvm_setup_cpu$x86 ---------------------------------------------
// Upstream signature: syz_kvm_setup_cpu(vmfd, cpufd, ucode_addr, ucode_size,
//   num_pages, opts, cpu_state, page_offset). Configures IDT / TSS / segment
// regs / page tables based on caller-supplied flags, copies user code into
// guest memory, then RETURNS (no KVM_RUN — that's the caller's job).
//
// [PR-D2 review fix B7] Previous reFuzz impl issued KVM_RUN immediately,
// which is wrong on two counts:
//   (1) upstream is configure-only, not run-and-return;
//   (2) without the syzOS guest binary loaded into guest memory, KVM_RUN
//       immediately #UDs (faults on undefined opcode at GPA 0).
//
// The current mismatch cluster uses setup_syzos_vm/add_vcpu rather than the
// older setup_cpu$x86 ABI. Keep this handler conservative: succeed only if a
// vCPU exists, and never issue KVM_RUN from a configure-only pseudo.
PseudoResult SetupCpuX86(const PseudoContext& ctx,
                         const intptr_t* args, uint32_t argc)
{
    KvmState& state = GetOrCreateKvmState(ctx);
    if (state.vcpu_fd < 0) {
        return Error(EINVAL,
                     "syz_kvm_setup_cpu$x86: vCPU not yet created "
                     "(call syz_kvm_add_vcpu first)");
    }
    (void)args;
    (void)argc;
    // The non-syzOS setup_cpu$x86 ABI is separate from the syzOS helpers used
    // by the current mismatch cluster. Keep its configure-only invariant: do
    // not issue KVM_RUN here.
    return PseudoResult{0, 0, nullptr};
}

// ---- syz_kvm_setup_cpu$ppc64 -------------------------------------------
// Architecture mismatch — reFuzz worker is amd64-only. Return ENOSYS so
// the cap mask doesn't suggest the call succeeded.
PseudoResult SetupCpuPpc64(const PseudoContext& /*ctx*/,
                           const intptr_t* /*args*/, uint32_t /*argc*/)
{
    return Error(ENOSYS, "syz_kvm_setup_cpu$ppc64: amd64 worker — arch mismatch");
}

// X86_SYZOS_ADDR_UEXIT — syzOS guest writes to this MMIO address to
// signal user-exit. Mirrors upstream `executor/kvm.h:55-57`:
//   #define X86_SYZOS_ADDR_EXIT  0x40000
//   #define X86_SYZOS_ADDR_UEXIT (X86_SYZOS_ADDR_EXIT + 256)
// reFuzz pins the literal value here rather than #include'ing upstream
// kvm.h (plan §2.1 forbids embedding syzkaller code at runtime).
constexpr uint64_t kX86SyzosAddrUExit = 0x40000ULL + 256ULL;

// A program-supplied kvm_run pointer (from mmap$KVM_VCPU) must be a plausible
// userspace address before we dereference it: a FAILED mmap leaves a faulted/-1
// value that a dependent assert can run with. [stateless]
inline bool PlausibleUserPtr(std::uintptr_t p)
{
    return p >= 0x1000 && p < (std::uintptr_t{1} << 47);
}

const kvm_run* KvmRunFromArgsOrState(const KvmState& state,
                                     const intptr_t* args,
                                     uint32_t argc)
{
    if (argc >= 1 && args != nullptr) {
        const auto p = static_cast<std::uintptr_t>(args[0]);
        if (PlausibleUserPtr(p)) {
            return reinterpret_cast<const kvm_run*>(p);
        }
    }
    return static_cast<const kvm_run*>(state.vcpu_run);
}

// ---- syz_kvm_assert_syzos_uexit$x86 -----------------------------------
// Upstream signature (syz 08ab311): syz_kvm_assert_syzos_uexit(int cpufd,
//   kvm_run* run, uint64 expect). cpufd prepended for !SYZ_EXECUTOR debug
//   dumps only; the executor logic still uses just run + expect.
// Upstream check (common_kvm_amd64.h:1211-1219):
//   if (!run || run->exit_reason != KVM_EXIT_MMIO ||
//       run->mmio.phys_addr != X86_SYZOS_ADDR_UEXIT) return -1 (EINVAL);
//   if (((uint64*)run->mmio.data)[0] != expect) return -1 (EDOM);
//   return 0;
//
// reFuzz deviation: args[0] in the typed-Target layout is a resource
// handle, not a raw kvm_run* pointer. We use state.vcpu_run (the latest
// vCPU's mmap'd kvm_run shared structure) as the implicit `run`. This
// is reFuzz-correct (sub-context-driven) but means the assertion always
// inspects the latest vCPU's last-run state — programs that fuzz
// multi-vCPU exit scenarios get partial coverage. Acceptable given B6
// (vcpu accumulation) keeps the latest-vCPU pointer fresh after each
// add_vcpu / KVM_RUN.
//
// args[2] is the expected uint64 value the guest is supposed to have
// written to the UEXIT MMIO address (args[0]=cpufd, args[1]=run).
PseudoResult AssertSyzosUexit(const PseudoContext& ctx,
                              const intptr_t* args, uint32_t argc)
{
    KvmState& state = GetOrCreateKvmState(ctx);
    // [stateless] syz signature: assert_syzos_uexit(cpufd, run, exitcode). args[1]
    // is the program's OWN kvm_run pointer (its mmap$KVM_VCPU result), so read the
    // run from args (range-checked) instead of the per-thread state.vcpu_run —
    // this makes the assert work no matter which worker thread ran add_vcpu/KVM_RUN
    // (previously the state.vcpu_fd<0 gate fail-fast'd on a migrated thread). Fall
    // back to state.vcpu_run only when args[1] isn't a usable pointer (in-thread /
    // back-compat). args[0]=cpufd is a resource handle, never dereferenced.
    const auto run_arg =
        (argc >= 2 && args != nullptr) ? static_cast<std::uintptr_t>(args[1]) : 0;
    const auto* run = PlausibleUserPtr(run_arg)
                          ? reinterpret_cast<const kvm_run*>(run_arg)
                          : static_cast<const kvm_run*>(state.vcpu_run);
    if (run == nullptr) {
        return Error(EINVAL, "syz_kvm_assert_syzos_uexit: null kvm_run");
    }
    if (run->exit_reason != KVM_EXIT_MMIO ||
        run->mmio.phys_addr != kX86SyzosAddrUExit) {
        return Error(EINVAL, "uexit: not MMIO at UEXIT addr");
    }
    // 上游 syz_kvm_assert_syzos_uexit(cpufd, run, expect) 必读 expect(a2)。
    if (argc < 3) {
        return Error(EINVAL, "uexit: missing expect arg (caller bug)");
    }
    const uint64_t expect = static_cast<uint64_t>(args[2]);
    const uint64_t got = *reinterpret_cast<const uint64_t*>(run->mmio.data);
    if (got != expect) {
        return Error(EDOM, "uexit: value mismatch");
    }
    return PseudoResult{0, 0, nullptr};
}

// ---- syz_kvm_assert_syzos_kvm_exit$x86 --------------------------------
// Upstream signature: syz_kvm_assert_syzos_kvm_exit(kvm_run* run, uint64 expect).
// Upstream check (common_kvm.h:41-56):
//   if (!run) return -1 (EINVAL);
//   if (run->exit_reason != expect) return -1 (EDOM);
//   return 0;
//
// reFuzz uses state.vcpu_run as the kvm_run, mirroring B5's deviation.
// args[1] is the expected kvm_run::exit_reason value (e.g.,
// KVM_EXIT_HLT == 5 if the test expects guest-issued HLT).
PseudoResult AssertSyzosKvmExit(const PseudoContext& ctx,
                                const intptr_t* args, uint32_t argc)
{
    KvmState& state = GetOrCreateKvmState(ctx);
    if (argc < 2) {
        return Error(EINVAL, "syz_kvm_assert_syzos_kvm_exit: missing expect arg");
    }
    // [stateless] run = args[0] (program's kvm_run from mmap$KVM_VCPU),
    // range-checked, falling back to per-thread vcpu_run. No vcpu_fd gate, so a
    // migrated assert thread no longer fail-fasts.
    const auto* run = KvmRunFromArgsOrState(state, args, argc);
    if (run == nullptr) {
        return Error(EINVAL, "syz_kvm_assert_syzos_kvm_exit: null kvm_run");
    }
    const uint64_t expect = static_cast<uint64_t>(args[1]);
    if (static_cast<uint64_t>(run->exit_reason) != expect) {
        return Error(EDOM, "kvm_exit: exit_reason mismatch");
    }
    return PseudoResult{0, 0, nullptr};
}

} // namespace

PseudoResult DispatchKvmPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc)
{
    if (meta.name == nullptr) {
        return Error(EINVAL, "kvm: meta.name nullptr");
    }
    // Name-prefix dispatch. Order: most-specific first (assert_* prefixes
    // overlap setup_*). Use strcmp for full-name matches.
    const char* name = meta.name;
    if (std::strcmp(name, "syz_kvm_setup_syzos_vm$x86") == 0) {
        return SetupSyzosVm(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_kvm_add_vcpu$x86") == 0) {
        return AddVcpu(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_kvm_setup_cpu$x86") == 0) {
        return SetupCpuX86(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_kvm_setup_cpu$ppc64") == 0) {
        return SetupCpuPpc64(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_kvm_assert_syzos_uexit$x86") == 0) {
        return AssertSyzosUexit(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_kvm_assert_syzos_kvm_exit$x86") == 0) {
        return AssertSyzosKvmExit(ctx, args, argc);
    }
    return Error(ENOSYS, "kvm: unknown pseudo name");
}

} // namespace refuzz::worker::pseudo
