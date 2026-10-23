// PR-D2 — KVM oracle test (mechanism b hand-derive per plan §7.1).
//
// Plan §7.1 binds mechanism (b) for KVM (small surface, 6 pseudos sharing
// VM/vCPU pattern). Hand-derive the canonical state-transition expectations
// from upstream:
//   * common_kvm_amd64.h:1163-1175 (syz_kvm_setup_syzos_vm) — opens kvm,
//     creates VM, builds kvm_syz_vm struct in caller host_mem (reFuzz uses
//     sub-context state instead, see PR-D2 review B9 deferral note).
//   * common_kvm_amd64.h:1178-1202 (syz_kvm_add_vcpu) — increments
//     vm->next_cpu_id, KVM_CREATE_VCPU(cpu_id), returns new fd.
//   * common_kvm_amd64.h:1205-1219 (syz_kvm_assert_syzos_uexit) — checks
//     run->exit_reason == KVM_EXIT_MMIO at phys_addr X86_SYZOS_ADDR_UEXIT
//     with mmio.data[0] == expect.
//   * common_kvm.h:40-56 (syz_kvm_assert_syzos_kvm_exit) — checks
//     run->exit_reason == expect (exact match).
//
// Goldens here pin the upstream-equivalent semantics that PR-D2 review fix
// B5/B5b/B6 implements. Earlier PR-D2 had the wrong answers wired in
// (KVM_EXIT_IO instead of KVM_EXIT_MMIO; "kvm_exit==ok if not IO/MMIO"
// instead of "exit_reason matches expect"). This rewritten oracle catches
// the corrected behavior.

#include "worker/backend/pseudo/kvm/kvm_dispatcher.hpp"
#include "worker/backend/pseudo/kvm/kvm_helpers.hpp"
#include "worker/backend/pseudo/kvm/kvm_state.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <linux/kvm.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

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

// Mirror of upstream X86_SYZOS_ADDR_UEXIT (executor/kvm.h:55-57):
//   #define X86_SYZOS_ADDR_EXIT   0x40000
//   #define X86_SYZOS_ADDR_UEXIT  (X86_SYZOS_ADDR_EXIT + 256)
constexpr uint64_t kX86SyzosAddrUExit = 0x40000ULL + 256ULL;

void prepare_kvm_run(refuzz::worker::PseudoRuntimeContext& ctx,
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

void release_kvm_run(refuzz::worker::PseudoRuntimeContext& ctx)
{
    auto& s = pkvm::GetOrCreateKvmState(ctx);
    s.vcpu_run = nullptr;
    s.vcpu_run_size = 0;
    s.vcpu_fd = -1;
}

// --- Uexit oracle table ---------------------------------------------------
// Each row captures a (synthesized kvm_run, expect arg) pair and the
// upstream-equivalent assertion answer.

struct UexitGolden {
    const char* label;
    uint32_t    exit_reason;
    uint64_t    phys_addr;
    uint64_t    mmio_value;
    int64_t     expect_arg;
    bool        should_succeed;  // true → ret==0; false → ret==-1
    int         expected_err;    // 0 on success; EINVAL/EDOM on failure
    const char* source;
};

constexpr UexitGolden kUexitGoldens[] = {
    { "MMIO at uexit addr, value matches",
      KVM_EXIT_MMIO, kX86SyzosAddrUExit, 42, 42,
      true, 0,
      "common_kvm_amd64.h:1211-1219 happy path" },
    { "wrong exit kind (KVM_EXIT_IO)",
      KVM_EXIT_IO, kX86SyzosAddrUExit, 42, 42,
      false, EINVAL,
      "common_kvm_amd64.h:1211 first guard (exit_reason != KVM_EXIT_MMIO)" },
    { "wrong exit kind (KVM_EXIT_HLT)",
      KVM_EXIT_HLT, kX86SyzosAddrUExit, 42, 42,
      false, EINVAL,
      "common_kvm_amd64.h:1211 first guard" },
    { "MMIO but wrong phys_addr",
      KVM_EXIT_MMIO, 0x99999ULL, 42, 42,
      false, EINVAL,
      "common_kvm_amd64.h:1211 second guard (phys_addr != UEXIT)" },
    { "MMIO at uexit addr, value mismatch",
      KVM_EXIT_MMIO, kX86SyzosAddrUExit, 42, 99,
      false, EDOM,
      "common_kvm_amd64.h:1216-1218 EDOM on data[0] != expect" },
    { "MMIO at uexit addr, zero value matches zero",
      KVM_EXIT_MMIO, kX86SyzosAddrUExit, 0, 0,
      true, 0,
      "edge: zero is a valid uexit code" },
};

void test_uexit_oracle()
{
    int matches = 0;
    for (const auto& g : kUexitGoldens) {
        refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
        struct kvm_run fake = {};
        prepare_kvm_run(ctx, &fake, g.exit_reason, g.phys_addr, g.mmio_value);
        const auto* meta = fz::FindPseudoByName(
            fz::kDefaultSyzTarget.pseudos, "syz_kvm_assert_syzos_uexit$x86");
        CHECK(meta != nullptr);
        // syz 08ab311 ABI: syz_kvm_assert_syzos_uexit(cpufd, run, expect) —
        // expect is args[2] (cpufd/run are resource handles, ignored here).
        intptr_t args[3] = {0, 0, static_cast<intptr_t>(g.expect_arg)};
        const auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 3);
        const bool succeeded = (result.ret == 0);
        if (succeeded != g.should_succeed || result.err != g.expected_err) {
            std::fprintf(stderr,
                         "FAIL: %s — got ret=%d err=%d, want ret=%d err=%d. "
                         "Source: %s\n",
                         g.label,
                         static_cast<int>(result.ret), result.err,
                         g.should_succeed ? 0 : -1, g.expected_err,
                         g.source);
            std::abort();
        }
        release_kvm_run(ctx);
        ++matches;
    }
    std::fprintf(stderr, "  matched %d uexit goldens\n", matches);
}

// --- KvmExit oracle table ------------------------------------------------
// syz_kvm_assert_syzos_kvm_exit succeeds iff run->exit_reason == args[1].

struct KvmExitGolden {
    const char* label;
    uint32_t    actual_exit_reason;
    int64_t     expect_arg;
    bool        should_succeed;
    int         expected_err;
};

constexpr KvmExitGolden kKvmExitGoldens[] = {
    { "HLT == HLT",        KVM_EXIT_HLT,        KVM_EXIT_HLT,        true,  0 },
    { "SHUTDOWN == SHUTDOWN", KVM_EXIT_SHUTDOWN, KVM_EXIT_SHUTDOWN, true, 0 },
    { "FAIL_ENTRY mismatch with HLT", KVM_EXIT_FAIL_ENTRY, KVM_EXIT_HLT,
      false, EDOM },
    { "MMIO != IO",        KVM_EXIT_MMIO,       KVM_EXIT_IO,         false, EDOM },
    { "IO == IO (allowed exact match)", KVM_EXIT_IO, KVM_EXIT_IO,    true,  0 },
};

void test_kvm_exit_oracle()
{
    int matches = 0;
    for (const auto& g : kKvmExitGoldens) {
        refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
        struct kvm_run fake = {};
        prepare_kvm_run(ctx, &fake, g.actual_exit_reason, 0, 0);
        const auto* meta = fz::FindPseudoByName(
            fz::kDefaultSyzTarget.pseudos, "syz_kvm_assert_syzos_kvm_exit$x86");
        CHECK(meta != nullptr);
        intptr_t args[2] = {0, static_cast<intptr_t>(g.expect_arg)};
        const auto result = pkvm::DispatchKvmPseudo(ctx, *meta, args, 2);
        const bool succeeded = (result.ret == 0);
        if (succeeded != g.should_succeed || result.err != g.expected_err) {
            std::fprintf(stderr,
                         "FAIL: %s — got ret=%d err=%d, want ret=%d err=%d\n",
                         g.label,
                         static_cast<int>(result.ret), result.err,
                         g.should_succeed ? 0 : -1, g.expected_err);
            std::abort();
        }
        release_kvm_run(ctx);
        ++matches;
    }
    std::fprintf(stderr, "  matched %d kvm_exit goldens\n", matches);
}

void test_setup_cpu_ppc64_oracle()
{
    // Pin: ppc64 on amd64 worker → ENOSYS, never silently succeeds.
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = fz::FindPseudoByName(
        fz::kDefaultSyzTarget.pseudos, "syz_kvm_setup_cpu$ppc64");
    CHECK(meta != nullptr);
    auto result = pkvm::DispatchKvmPseudo(ctx, *meta, nullptr, 0);
    CHECK(result.ret == -1);
    CHECK(result.err == ENOSYS);
}

bool KvmAvailable()
{
    return ::access("/dev/kvm", R_OK | W_OK) == 0;
}

void test_setup_cpu_x86_does_not_call_kvm_run()
{
    // setup_cpu$x86 is configure-only. Under a real /dev/kvm vCPU, running it
    // must leave state.last_exit_reason at 0; issuing KVM_RUN here would expose
    // a real exit_reason through the kvm_run mmap.
    if (!KvmAvailable() || ::geteuid() != 0) {
        std::fprintf(stderr, "  SKIP (no /dev/kvm or not root)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* vm_meta = fz::FindPseudoByName(
        fz::kDefaultSyzTarget.pseudos, "syz_kvm_setup_syzos_vm$x86");
    CHECK(vm_meta != nullptr);
    intptr_t vm_args[2] = {0, 0};
    auto vm_res = pkvm::DispatchKvmPseudo(ctx, *vm_meta, vm_args, 2);
    if (vm_res.ret != 0) {
        std::fprintf(stderr,
                     "  SKIP (KVM_CREATE_VM failed err=%d)\n", vm_res.err);
        return;
    }

    const auto* vcpu_meta = fz::FindPseudoByName(
        fz::kDefaultSyzTarget.pseudos, "syz_kvm_add_vcpu$x86");
    CHECK(vcpu_meta != nullptr);
    intptr_t vcpu_args[2] = {0, 0};
    auto vcpu_res = pkvm::DispatchKvmPseudo(ctx, *vcpu_meta, vcpu_args, 2);
    if (vcpu_res.ret < 0) {
        std::fprintf(stderr,
                     "  SKIP (add_vcpu failed err=%d)\n", vcpu_res.err);
        return;
    }

    auto& s = pkvm::GetOrCreateKvmState(ctx);
    CHECK(s.last_exit_reason == 0);  // pre-condition

    const auto* cpu_meta = fz::FindPseudoByName(
        fz::kDefaultSyzTarget.pseudos, "syz_kvm_setup_cpu$x86");
    CHECK(cpu_meta != nullptr);
    intptr_t cpu_args[6] = {0, 0, 0, 0, 0, 0};
    auto cpu_res = pkvm::DispatchKvmPseudo(ctx, *cpu_meta, cpu_args, 6);
    CHECK(cpu_res.ret == 0);
    CHECK(cpu_res.err == 0);

    // B7 invariant: setup_cpu$x86 returned successfully but did NOT invoke
    // KVM_RUN. last_exit_reason is still its initial 0 value.
    CHECK(s.last_exit_reason == 0);
}

}  // namespace

int main()
{
    RUN_TEST(test_uexit_oracle);
    RUN_TEST(test_kvm_exit_oracle);
    RUN_TEST(test_setup_cpu_ppc64_oracle);
    RUN_TEST(test_setup_cpu_x86_does_not_call_kvm_run);
    return 0;
}
