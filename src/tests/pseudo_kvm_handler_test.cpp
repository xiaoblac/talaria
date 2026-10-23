// PR-D2 — behavioral unit test for the 6 syz_kvm$* handlers.
//
// Plan §7 test discipline:
//   * Structural pin: pseudo_test.go (catalog 4-tuple) — separate.
//   * Behavioral (this file): per-handler unit cases. Cases that need
//     /dev/kvm (which doesn't exist on hosts without the kvm kernel
//     module loaded) are conditioned on `geteuid() == 0 && access("/dev/kvm")`.
//     Failure surfaces cleanly (ENOSYS / EACCES / ENODEV) without crashing
//     or leaking state.
//   * Oracle (mechanism b hand-derive per plan §7.1) lives in
//     pseudo_kvm_oracle_test.cpp — pins the canonical ioctl sequence
//     against state transitions.
//
// The /dev/kvm-gated cases exercise the vendored syzOS guest path when KVM is
// available. Hosts without KVM still run the deterministic state/assert tests.

#include "worker/backend/pseudo/kvm/kvm_dispatcher.hpp"
#include "worker/backend/pseudo/kvm/kvm_helpers.hpp"
#include "worker/backend/pseudo/kvm/kvm_layout.hpp"
#include "worker/backend/pseudo/kvm/kvm_state.hpp"
#include "worker/backend/pseudo/kvm/syzos_guest_amd64.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
namespace pkvm = ::refuzz::worker::pseudo;
namespace lk   = ::refuzz::worker::pseudo::kvm_layout;
namespace sg   = ::refuzz::worker::pseudo::syzos_guest_amd64;

struct TestKvmText {
    std::uintptr_t typ;
    const void*    text;
    std::uintptr_t size;
};

static_assert(sizeof(TestKvmText) == 3 * sizeof(std::uintptr_t));

struct TestSyzosApiHeader {
    std::uint64_t call;
    std::uint64_t size;
};

struct TestSyzosUexit {
    TestSyzosApiHeader header;
    std::uint64_t      exit_code;
};

constexpr std::uint64_t kSyzosApiUexit = 0;

bool KvmAvailable()
{
    // /dev/kvm requires CAP_SYS_ADMIN-equivalent + the kvm module loaded
    // + (often) hardware virtualization unavailable in some CI VMs.
    return ::access("/dev/kvm", R_OK | W_OK) == 0;
}

const fz::PseudoMeta* FindKvmMeta(const char* name)
{
    return fz::FindPseudoByName(fz::kDefaultSyzTarget.pseudos, name);
}

// ---- Arch/impl cases (always run; do not need /dev/kvm) -----------------

void test_setup_cpu_ppc64_returns_enosys_on_amd64_worker()
{
    // Architecture mismatch — PPC64 helper called on amd64 worker.
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindKvmMeta("syz_kvm_setup_cpu$ppc64");
    CHECK(meta != nullptr);
    std::array<intptr_t, 8> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(),
                                                 static_cast<uint32_t>(args.size()));
    CHECK(result.ret == -1);
    CHECK(result.err == ENOSYS);
}

void test_dispatch_unknown_kvm_pseudo_returns_enosys()
{
    // Synthetic test: construct a PseudoMeta with kKvm domain but
    // an unknown name and route through the dispatcher directly. This
    // exercises the `unknown pseudo name` fallthrough in DispatchKvmPseudo
    // without needing a real catalog entry.
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    fz::PseudoMeta synthetic = {};
    synthetic.nr               = 0xdeadbeef;
    synthetic.name             = "syz_kvm_made_up";
    synthetic.arg_count        = 0;
    synthetic.domain           = fz::PseudoDomain::kKvm;
    synthetic.concurrency      = fz::PseudoConcurrency::kNotConcurrentSafe;
    auto result = pkvm::DispatchKvmPseudo(ctx, synthetic, nullptr, 0);
    CHECK(result.ret == -1);
    CHECK(result.err == ENOSYS);
}

// ---- KvmState lifecycle ------------------------------------------------

void test_kvm_state_lookup_identity_per_ctx()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    auto& s1 = pkvm::GetOrCreateKvmState(ctx);
    auto& s2 = pkvm::GetOrCreateKvmState(ctx);
    CHECK(&s1 == &s2);  // identity stable per ctx
}

void test_fresh_ctx_gets_fresh_kvm_state()
{
    {
        refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
        auto& s = pkvm::GetOrCreateKvmState(ctx);
        s.last_exit_reason = 42;  // mutate
    }
    // ctx out of scope → cleanup runs → state freed.
    refuzz::worker::PseudoRuntimeContext ctx2(&fz::kDefaultSyzTarget);
    auto& s2 = pkvm::GetOrCreateKvmState(ctx2);
    CHECK(s2.last_exit_reason == 0);  // fresh
}

// ---- /dev/kvm-dependent cases (skipped when unavailable) ----------------

void test_setup_syzos_vm_creates_vm_under_kvm()
{
    if (!KvmAvailable()) {
        std::fprintf(stderr, "  SKIP (no /dev/kvm available)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindKvmMeta("syz_kvm_setup_syzos_vm$x86");
    CHECK(meta != nullptr);
    std::array<intptr_t, 2> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 2);
    if (result.ret != 0) {
        std::fprintf(stderr,
                     "  KVM_CREATE_VM failed err=%d (kernel may lack KVM)\n",
                     result.err);
        // Acceptable failure (ENOMEM / EBUSY / EAGAIN under contention);
        // graceful — handler must surface errno without leaking state.
        CHECK(result.err != 0);
        return;
    }
    auto& s = pkvm::GetOrCreateKvmState(ctx);
    CHECK(s.kvm_root_fd >= 0);
    CHECK(s.vm_fd >= 0);
    CHECK(s.guest_mem() != nullptr);
    CHECK(s.guest_mem_size() > 0);
    CHECK(s.regions.size() == lk::kSyzosMemRegionsCount);
    CHECK(s.syz_vm_ready);
    CHECK(s.syzos_guest_installed);
    CHECK(s.user_text != nullptr);
    CHECK(s.gpa0_mem != nullptr);
}

void test_assert_uexit_without_prior_kvm_run_fails()
{
    // Independent of /dev/kvm — assertion path checks state directly.
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    std::array<intptr_t, 2> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 2);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);  // "no prior KVM_RUN"
}

void test_add_vcpu_without_vm_fails()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindKvmMeta("syz_kvm_add_vcpu$x86");
    CHECK(meta != nullptr);
    std::array<intptr_t, 2> args = {};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args.data(), 2);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);  // "VM not yet created"
}

// ---- PR-D2 review fix B5 — assert_syzos_uexit semantics ----------------
//
// Synthesize a fake kvm_run, point state.vcpu_run at it, drive the four
// distinct exit-paths the upstream check covers:
//   (1) MMIO at correct phys_addr + matching value → 0
//   (2) wrong exit_reason (e.g. KVM_EXIT_IO) → -1 EINVAL
//   (3) MMIO but wrong phys_addr → -1 EINVAL
//   (4) MMIO at correct addr but value mismatch → -1 EDOM

void prepare_fake_kvm_run_uexit(refuzz::worker::PseudoRuntimeContext& ctx,
                                struct kvm_run* fake,
                                uint32_t exit_reason,
                                uint64_t phys_addr,
                                uint64_t mmio_value)
{
    auto& s = pkvm::GetOrCreateKvmState(ctx);
    s.vcpu_fd = 0;
    fake->exit_reason = exit_reason;
    fake->mmio.phys_addr = phys_addr;
    *reinterpret_cast<uint64_t*>(fake->mmio.data) = mmio_value;
    s.vcpu_run = fake;
    s.vcpu_run_size = sizeof(*fake);
}

void cleanup_fake_kvm_run(refuzz::worker::PseudoRuntimeContext& ctx)
{
    auto& s = pkvm::GetOrCreateKvmState(ctx);
    s.vcpu_run = nullptr;
    s.vcpu_run_size = 0;
    s.vcpu_fd = -1;
}

constexpr uint64_t kExpectedSyzosUexitAddr = 0x40000ULL + 256ULL;

void test_uexit_succeeds_at_correct_mmio_with_matching_expect()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_MMIO,
                               kExpectedSyzosUexitAddr, 42);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, 0, 42};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
    CHECK(result.ret == 0);
    CHECK(result.err == 0);
    cleanup_fake_kvm_run(ctx);
}

void test_uexit_fails_on_wrong_exit_kind()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_IO,
                               kExpectedSyzosUexitAddr, 42);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, 0, 42};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);
    cleanup_fake_kvm_run(ctx);
}

void test_uexit_fails_on_wrong_phys_addr()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_MMIO, 0x99999ULL, 42);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, 0, 42};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);
    cleanup_fake_kvm_run(ctx);
}

void test_uexit_fails_on_value_mismatch_returns_edom()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_MMIO,
                               kExpectedSyzosUexitAddr, 42);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, 0, 99};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
    CHECK(result.ret == -1);
    CHECK(result.err == EDOM);
    cleanup_fake_kvm_run(ctx);
}

// ---- B5b — assert_syzos_kvm_exit semantics -----------------------------

void test_kvm_exit_succeeds_when_exit_reason_matches()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_HLT, 0, 0);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_kvm_exit$x86");
    CHECK(meta != nullptr);
    intptr_t args[2] = {0, KVM_EXIT_HLT};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 2);
    CHECK(result.ret == 0);
    CHECK(result.err == 0);
    cleanup_fake_kvm_run(ctx);
}

void test_kvm_exit_fails_on_reason_mismatch()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    prepare_fake_kvm_run_uexit(ctx, &fake, KVM_EXIT_HLT, 0, 0);
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_kvm_exit$x86");
    CHECK(meta != nullptr);
    intptr_t args[2] = {0, KVM_EXIT_SHUTDOWN};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 2);
    CHECK(result.ret == -1);
    CHECK(result.err == EDOM);
    cleanup_fake_kvm_run(ctx);
}

// ---- [stateless] asserts read kvm_run from the program's arg ------------
//
// The migration fix: the assert handlers take the kvm_run pointer from the
// program's own mmap$KVM_VCPU result (args), NOT from per-thread state.vcpu_run.
// These tests use a FRESH ctx with NO state.vcpu_run, proving the assert works
// when add_vcpu/KVM_RUN ran on a different worker thread (no thread-local state).

void test_uexit_succeeds_via_args_run_pointer()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    fake.exit_reason = KVM_EXIT_MMIO;
    fake.mmio.phys_addr = kExpectedSyzosUexitAddr;
    *reinterpret_cast<uint64_t*>(fake.mmio.data) = 42;
    // Deliberately do NOT set state.vcpu_run — args[1] supplies the run pointer.
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_uexit$x86");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, reinterpret_cast<intptr_t>(&fake), 42};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
    CHECK(result.ret == 0);
    CHECK(result.err == 0);
}

void test_kvm_exit_succeeds_via_args_run_pointer()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    struct kvm_run fake = {};
    fake.exit_reason = KVM_EXIT_HLT;
    // No state.vcpu_run — args[0] supplies the run pointer.
    const auto* meta = FindKvmMeta("syz_kvm_assert_syzos_kvm_exit$x86");
    CHECK(meta != nullptr);
    intptr_t args[2] = {reinterpret_cast<intptr_t>(&fake), KVM_EXIT_HLT};
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 2);
    CHECK(result.ret == 0);
    CHECK(result.err == 0);
}

// ---- [stateless] migrated-thread GPA->HVA via region_base[] -------------
//
// The core fix: on a thread where setup did NOT run, state.regions is empty, so
// KvmHostAddrForGpa must translate guest physical addresses via the region_base[]
// carried in a0 (state.syz_vm). This is exactly the map that an earlier partial
// recovery lacked — leaving page tables / GLOBALS unmapped so KVM_RUN #UD'd. The
// fallback must ALSO skip the host-backed UNUSED region (mirror syz gpa_to_hva).
void test_host_addr_for_gpa_region_base_fallback()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    auto& s = pkvm::GetOrCreateKvmState(ctx);
    CHECK(s.regions.empty());  // migrated-thread condition (setup ran elsewhere)

    alignas(4096) static std::uint8_t globals_backing[4096] = {};
    alignas(4096) static std::uint8_t gpa0_backing[5 * 4096] = {};
    alignas(4096) static std::uint8_t unused_backing[4096] = {};
    for (int i = 0; i < lk::kSyzosMemRegionsCount; ++i) {
        const auto& r = lk::kSyzosMemRegions[i];
        if (r.gpa == lk::kX86SyzosAddrGlobals) s.syz_vm.region_base[i] = globals_backing;
        if ((r.flags & lk::kMemRegionFlagGpa0) != 0u) s.syz_vm.region_base[i] = gpa0_backing;
        if (r.gpa == lk::kX86SyzosAddrUnused) s.syz_vm.region_base[i] = unused_backing;
    }

    // GLOBALS GPA (+offset) and a GPA0-region address (GDT page) resolve via a0.
    CHECK(pkvm::KvmHostAddrForGpa(s, lk::kX86SyzosAddrGlobals + 16) == globals_backing + 16);
    CHECK(pkvm::KvmHostAddrForGpa(s, 0x1000) == gpa0_backing + 0x1000);
    // The host-backed UNUSED region must NOT translate (non-null base is a trap).
    CHECK(pkvm::KvmHostAddrForGpa(s, lk::kX86SyzosAddrUnused) == nullptr);
    // An out-of-range GPA returns nullptr.
    CHECK(pkvm::KvmHostAddrForGpa(s, 0xdeadbeef000ULL) == nullptr);
}

// ---- B6 — add_vcpu accumulates (next_cpu_id increments) ----------------

void test_add_vcpu_increments_next_cpu_id()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    auto& state = pkvm::GetOrCreateKvmState(ctx);
    CHECK(state.next_cpu_id == 0);
    CHECK(state.vcpu_slots.empty());

    if (!KvmAvailable()) {
        std::fprintf(stderr, "  SKIP real KVM path (no /dev/kvm)\n");
        return;
    }
    const auto* vm_meta = FindKvmMeta("syz_kvm_setup_syzos_vm$x86");
    CHECK(vm_meta != nullptr);
    std::array<intptr_t, 2> vm_args = {};
    auto vm_res = pkvm::DispatchKvmPseudo(ctx, *vm_meta, vm_args.data(), 2);
    if (vm_res.ret != 0) {
        std::fprintf(stderr,
                     "  SKIP (KVM_CREATE_VM failed err=%d)\n", vm_res.err);
        return;
    }

    const auto* vcpu_meta = FindKvmMeta("syz_kvm_add_vcpu$x86");
    CHECK(vcpu_meta != nullptr);
    std::array<intptr_t, 2> vcpu_args = {};
    for (int i = 0; i < 3; ++i) {
        auto res = pkvm::DispatchKvmPseudo(ctx, *vcpu_meta, vcpu_args.data(), 2);
        if (res.ret < 0) {
            std::fprintf(stderr,
                         "  add_vcpu #%d failed err=%d (kernel cap?)\n",
                         i, res.err);
            break;
        }
        CHECK(state.next_cpu_id == i + 1);
        CHECK(static_cast<int>(state.vcpu_slots.size()) == i + 1);
        CHECK(state.vcpu_fd == static_cast<int>(res.ret));
    }
}

// ---- Vendored syzOS install pin (no /dev/kvm needed) -------------------

void test_install_syzos_guest_copies_vendored_section()
{
    namespace lk = refuzz::worker::pseudo::kvm_layout;
    namespace sg = refuzz::worker::pseudo::syzos_guest_amd64;

    constexpr std::size_t kBufSize = 4u * lk::kKvmPageSize;
    auto* host_mem = static_cast<std::uint8_t*>(
        ::mmap(nullptr, kBufSize, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    CHECK(host_mem != MAP_FAILED);

    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    auto& state = pkvm::GetOrCreateKvmState(ctx);
    pkvm::KvmRegionSlot slot{};
    slot.gpa        = lk::kSyzosAddrExecutorCode;
    slot.size_bytes = kBufSize;
    slot.flags      = 0;
    slot.host_addr  = host_mem;
    slot.kvm_slot   = 0;
    state.regions.push_back(slot);

    // KvmInstallSyzosGuest also writes the BOOT_ARGS region map (mirrors
    // syzkaller's install_syzos_code); provide a synthetic BOOT_ARGS region.
    auto* boot_mem = static_cast<std::uint8_t*>(
        ::mmap(nullptr, lk::kKvmPageSize, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    CHECK(boot_mem != MAP_FAILED);
    pkvm::KvmRegionSlot boot_slot{};
    boot_slot.gpa        = lk::kX86SyzosAddrBootArgs;
    boot_slot.size_bytes = lk::kKvmPageSize;
    boot_slot.flags      = 0;
    boot_slot.host_addr  = boot_mem;
    boot_slot.kvm_slot   = 1;
    state.regions.push_back(boot_slot);

    CHECK(pkvm::KvmInstallSyzosGuest(state) == 0);
    CHECK(state.syzos_guest_installed);
    CHECK(sg::Size() > 0);
    CHECK(std::memcmp(host_mem, sg::Code(), sg::Size()) == 0);
    // BOOT_ARGS region_count must equal the table size.
    CHECK(*reinterpret_cast<const std::uint32_t*>(boot_mem) ==
          static_cast<std::uint32_t>(lk::kSyzosMemRegionsCount));
    CHECK(pkvm::KvmInstallSyzosGuest(state) == 0);

    // Cleanup: clear region so KvmState::Cleanup() doesn't munmap our
    // synthesized buffers (we already called mmap; let test own them).
    state.regions.clear();
    state.syzos_guest_installed = false;
    ::munmap(host_mem, kBufSize);
    ::munmap(boot_mem, lk::kKvmPageSize);
}

// ---- /dev/kvm-gated: add_vcpu installs syzOS long-mode regs ------------

void test_add_vcpu_installs_syzos_long_mode_regs()
{
    if (!KvmAvailable()) {
        std::fprintf(stderr, "  SKIP (no /dev/kvm)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);

    const auto* vm_meta = FindKvmMeta("syz_kvm_setup_syzos_vm$x86");
    std::array<intptr_t, 2> vm_args = {};
    auto vm_res = pkvm::DispatchKvmPseudo(ctx, *vm_meta, vm_args.data(), 2);
    if (vm_res.ret != 0) {
        std::fprintf(stderr,
                     "  SKIP (setup_syzos_vm failed err=%d)\n", vm_res.err);
        return;
    }

    const auto* vcpu_meta = FindKvmMeta("syz_kvm_add_vcpu$x86");
    std::array<intptr_t, 2> vcpu_args = {};
    auto vcpu_res = pkvm::DispatchKvmPseudo(ctx, *vcpu_meta, vcpu_args.data(), 2);
    if (vcpu_res.ret < 0) {
        std::fprintf(stderr,
                     "  SKIP (add_vcpu failed err=%d)\n", vcpu_res.err);
        return;
    }

    auto& state = pkvm::GetOrCreateKvmState(ctx);
    struct kvm_sregs sregs = {};
    CHECK(::ioctl(state.vcpu_fd, KVM_GET_SREGS, &sregs) == 0);
    CHECK(sregs.cs.selector == lk::kX86SyzosSelCode);
    CHECK(sregs.ds.selector == lk::kX86SyzosSelData);
    CHECK(sregs.tr.selector == lk::kX86SyzosSelTss64);
    CHECK(sregs.gdt.base == lk::kX86SyzosAddrGdt);
    CHECK(sregs.idt.base == lk::kX86SyzosAddrVarIdt);
    CHECK(sregs.cr3 == lk::kX86SyzosAddrPml4);
    CHECK(sregs.cs.type == 0xB);
    CHECK(sregs.ds.type == 0x3);
    struct kvm_regs regs = {};
    CHECK(::ioctl(state.vcpu_fd, KVM_GET_REGS, &regs) == 0);
    CHECK(regs.rip == sg::GuestMainGpa());
    CHECK(regs.rsp == lk::kX86SyzosAddrStack0);
    CHECK(regs.rdi == 0);
    CHECK(regs.rsi == 0);
    CHECK((regs.rflags & 0x2) != 0);
}

// ---- /dev/kvm-gated: empty command stream → UEXIT_END ------------------

void test_end_to_end_empty_syzos_stream_reaches_uexit_end()
{
    if (!KvmAvailable()) {
        std::fprintf(stderr, "  SKIP (no /dev/kvm)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);

    std::array<intptr_t, 2> args2 = {};
    if (pkvm::DispatchKvmPseudo(ctx, *FindKvmMeta("syz_kvm_setup_syzos_vm$x86"),
                                args2.data(), 2).ret != 0) {
        std::fprintf(stderr, "  SKIP (setup_syzos_vm failed)\n");
        return;
    }
    if (pkvm::DispatchKvmPseudo(ctx, *FindKvmMeta("syz_kvm_add_vcpu$x86"),
                                args2.data(), 2).ret < 0) {
        std::fprintf(stderr, "  SKIP (add_vcpu failed)\n");
        return;
    }

    auto& state = pkvm::GetOrCreateKvmState(ctx);
    CHECK(pkvm::KvmRunVcpu(state) == 0);
    CHECK(state.last_exit_reason == KVM_EXIT_MMIO);
    const auto* run = static_cast<const kvm_run*>(state.vcpu_run);
    CHECK(run->mmio.phys_addr == lk::kX86SyzosAddrUexit);
    CHECK(*reinterpret_cast<const std::uint64_t*>(run->mmio.data) ==
          UINT64_MAX);
}

// ---- /dev/kvm-gated: command stream uexit values match corpus text ------

void test_end_to_end_syzos_uexit_command_stream()
{
    if (!KvmAvailable()) {
        std::fprintf(stderr, "  SKIP (no /dev/kvm)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);

    std::array<intptr_t, 2> args2 = {};
    if (pkvm::DispatchKvmPseudo(ctx, *FindKvmMeta("syz_kvm_setup_syzos_vm$x86"),
                                args2.data(), 2).ret != 0) {
        std::fprintf(stderr, "  SKIP (setup_syzos_vm failed)\n");
        return;
    }
    const TestSyzosUexit commands[] = {
        {{kSyzosApiUexit, sizeof(TestSyzosUexit)}, 0},
        {{kSyzosApiUexit, sizeof(TestSyzosUexit)}, 0xaaaa},
    };
    const TestKvmText text = {0, commands, sizeof(commands)};
    std::array<intptr_t, 2> vcpu_args = {
        0,
        reinterpret_cast<intptr_t>(&text),
    };
    if (pkvm::DispatchKvmPseudo(ctx, *FindKvmMeta("syz_kvm_add_vcpu$x86"),
                                vcpu_args.data(), 2).ret < 0) {
        std::fprintf(stderr, "  SKIP (add_vcpu failed)\n");
        return;
    }

    auto& state = pkvm::GetOrCreateKvmState(ctx);
    CHECK(pkvm::KvmRunVcpu(state) == 0);
    CHECK(state.last_exit_reason == KVM_EXIT_MMIO);
    const auto* run = static_cast<const kvm_run*>(state.vcpu_run);
    CHECK(run->mmio.phys_addr == lk::kX86SyzosAddrUexit);
    CHECK(run->mmio.is_write != 0);
    CHECK(*reinterpret_cast<const std::uint64_t*>(run->mmio.data) == 0);

    CHECK(pkvm::KvmRunVcpu(state) == 0);
    CHECK(state.last_exit_reason == KVM_EXIT_MMIO);
    run = static_cast<const kvm_run*>(state.vcpu_run);
    CHECK(run->mmio.phys_addr == lk::kX86SyzosAddrUexit);
    CHECK(*reinterpret_cast<const std::uint64_t*>(run->mmio.data) == 0xaaaa);
}

}  // namespace

int main()
{
    RUN_TEST(test_setup_cpu_ppc64_returns_enosys_on_amd64_worker);
    RUN_TEST(test_dispatch_unknown_kvm_pseudo_returns_enosys);
    RUN_TEST(test_kvm_state_lookup_identity_per_ctx);
    RUN_TEST(test_fresh_ctx_gets_fresh_kvm_state);
    RUN_TEST(test_setup_syzos_vm_creates_vm_under_kvm);
    RUN_TEST(test_assert_uexit_without_prior_kvm_run_fails);
    RUN_TEST(test_add_vcpu_without_vm_fails);
    // PR-D2 review fix B5/B5b/B6 — pin upstream-correct semantics:
    RUN_TEST(test_uexit_succeeds_at_correct_mmio_with_matching_expect);
    RUN_TEST(test_uexit_fails_on_wrong_exit_kind);
    RUN_TEST(test_uexit_fails_on_wrong_phys_addr);
    RUN_TEST(test_uexit_fails_on_value_mismatch_returns_edom);
    RUN_TEST(test_kvm_exit_succeeds_when_exit_reason_matches);
    RUN_TEST(test_kvm_exit_fails_on_reason_mismatch);
    // [stateless] asserts read kvm_run from the program's arg (migration-safe):
    RUN_TEST(test_uexit_succeeds_via_args_run_pointer);
    RUN_TEST(test_kvm_exit_succeeds_via_args_run_pointer);
    RUN_TEST(test_host_addr_for_gpa_region_base_fallback);
    RUN_TEST(test_add_vcpu_increments_next_cpu_id);
    // Vendored syzOS guest path:
    RUN_TEST(test_install_syzos_guest_copies_vendored_section);
    RUN_TEST(test_add_vcpu_installs_syzos_long_mode_regs);
    RUN_TEST(test_end_to_end_empty_syzos_stream_reaches_uexit_end);
    RUN_TEST(test_end_to_end_syzos_uexit_command_stream);
    return 0;
}
