#pragma once

// PR-D2 — per-program KVM sub-context (plan §5.2 Tier 3 default;
// §5.2-amendment TU-local map convention from PR-D1).
//
// KvmState owns the KVM lifecycle objects shared across the 6 syz_kvm$*
// pseudos within a program:
//   * /dev/kvm root fd (open once on first dispatch)
//   * VM fd (KVM_CREATE_VM; one per program — syzkaller upstream pattern)
//   * Multi-vCPU storage in `vcpu_slots` vector (one VcpuSlot per
//     KVM_CREATE_VCPU call; `next_cpu_id` counter tracks the next id to
//     assign per common_kvm_amd64.h:1190-1201). The bare `vcpu_fd` /
//     `vcpu_run` / `vcpu_run_size` fields are convenience accessors that
//     point at the BACK of vcpu_slots — assert_* handlers operate on
//     the most-recently-created vCPU's last KVM_RUN state, matching the
//     typical fuzz-program pattern.
//   * Guest memory mmap (KVM_SET_USER_MEMORY_REGION backing)
//   * Per-vCPU run mmap (kvm_run shared structure for KVM_RUN; one per
//     vcpu, stored inside each VcpuSlot)
//   * Last KVM_RUN exit reason (read by assert_syzos_kvm_exit /
//     assert_syzos_uexit)
//
// Cleanup runs in reverse-creation order (vcpu fd → vm fd → kvm root fd;
// vcpu_run mmap → guest_mem mmap) via RegisterCleanup callback registered
// on first dispatch. Sub-context lookup by `&PseudoContext` ptr per the
// §5.2-amendment convention; same TU-local-map pattern as PR-D1's
// MountState.

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/kvm/kvm_layout.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace refuzz::worker::pseudo {

// VcpuSlot — per-vCPU state. Upstream `kvm_syz_vm` increments next_cpu_id
// per add_vcpu, calls KVM_CREATE_VCPU(cpu_id), keeps prior vCPUs alive
// (common_kvm_amd64.h:1190-1201). PR-D2 review fix B6 mirrors that here:
// add_vcpu accumulates into vcpu_slots rather than closing the previous fd.
struct VcpuSlot {
    int          fd            = -1;
    void*        run_mmap      = nullptr;
    std::size_t  run_mmap_size = 0;
};

// Multi-region syzOS GPA backing. Per kvm_layout::kSyzosMemRegions, each
// non-NO_HOST_MEM row gets one host-side mmap + KVM_SET_USER_MEMORY_REGION
// slot; NO_HOST_MEM rows get a logical entry (host_addr=nullptr) so cleanup
// and GPA lookup remain uniform. Mirrors syzkaller setup_vm() semantics.
struct KvmRegionSlot {
    std::uint64_t  gpa         = 0;       // guest physical address (region start)
    std::size_t    size_bytes  = 0;       // region size (= upstream `pages * 4096`)
    std::uint32_t  flags       = 0;       // mirror of MEM_REGION_FLAG_*
    void*          host_addr   = nullptr; // host mmap (nullptr if NO_HOST_MEM)
    std::uint32_t  kvm_slot    = 0;       // KVM_SET_USER_MEMORY_REGION slot index
};

struct KvmState {
    // Root /dev/kvm fd. -1 means "not opened yet"; first dispatch lazy-opens.
    int kvm_root_fd = -1;

    // VM fd from KVM_CREATE_VM. -1 means VM not created yet.
    int vm_fd = -1;

    // [R3 threaded stateful-pseudo recovery] true when vm_fd was recovered from
    // another worker thread's setup via the resource arg (r2 → KvmSyzVm) rather
    // than set up on this thread. The recovering thread does NOT own the fd
    // (the setup thread / executor resource does), so Cleanup must not close it
    // (avoids double-close). Always false on the thread that ran setup.
    bool vm_fd_borrowed = false;

    // [v1 single vcpu_fd / vcpu_run — ROLLBACK uncomment below + remove v2]
    // int vcpu_fd = -1;
    // void* vcpu_run = nullptr;
    // std::size_t vcpu_run_size = 0;

    // [v2 PR-D2 review fix B6 — 当前版本]
    // Multi-vCPU storage. add_vcpu pushes a new VcpuSlot per call (cpu_id
    // = vcpu_slots.size() before push). vcpu_fd / vcpu_run / vcpu_run_size
    // are convenience accessors that point at the BACK of vcpu_slots
    // (latest-created), keeping back-compat with assert_* handlers that
    // only inspect "the most-recent vCPU". Cleanup walks the vector in
    // reverse.
    std::vector<VcpuSlot> vcpu_slots;

    // "Latest" accessors — equivalent to vcpu_slots.back().{fd,run_mmap,
    // run_mmap_size} when vcpu_slots non-empty, else the historical
    // sentinels (-1 / nullptr / 0). Updated by add_vcpu after each push.
    int          vcpu_fd       = -1;
    void*        vcpu_run      = nullptr;
    std::size_t  vcpu_run_size = 0;

    // Number of vCPUs created so far (= vcpu_slots.size()). next_cpu_id
    // for the upcoming KVM_CREATE_VCPU call. Mirrors upstream
    // `vm->next_cpu_id` invariant at common_kvm_amd64.h:1194.
    int next_cpu_id = 0;

    // [v1 single guest_mem — ROLLBACK uncomment + remove v2 multi-region]
    // // Guest memory mmap (anonymous, RW). Backed by KVM_SET_USER_MEMORY_REGION
    // // so KVM hands the GPA → HVA translation back. nullptr means not
    // // allocated. len == 0 means same.
    // void*       guest_mem      = nullptr;
    // std::size_t guest_mem_size = 0;

    // Multi-region syzOS backing. The NO_HOST_MEM exit page at 0x40000 keeps
    // writes to X86_SYZOS_ADDR_UEXIT visible as KVM_EXIT_MMIO, while the
    // remaining rows mirror syzkaller's user-code, executor-code, stack,
    // per-vCPU, and IOAPIC layout. Cleanup walks `regions` in reverse order.
    //
    // Convenience accessors `guest_mem()` / `guest_mem_size()` (kept as
    // member functions below for back-compat with tests / callers that want
    // the row-0 GPA-0 host mapping) point at regions[0] when populated.
    std::vector<KvmRegionSlot> regions;

    // [carve_from_host_mem] Single host backing buffer for ALL syzOS guest
    // regions, bump-allocated below. Replaces the previous 15 separate
    // anonymous mmap()s with ONE — under KASAN + nested-KVM the per-mmap VMA +
    // per-memslot setup cost is significant, so one big mapping carved into 15
    // slices (each registered at its sparse GPA via KVM_SET_USER_MEMORY_REGION,
    // mirroring syz setup_vm) is much cheaper to build and tear down. Each
    // KvmRegionSlot::host_addr points INTO host_arena (non-owning); only
    // host_arena is munmap'd at teardown, gated by regions_carved. A migrated /
    // recovered thread has host_arena==nullptr and an empty regions[] (it borrows
    // region_base[] from a0), so it owns and frees nothing.
    void*       host_arena      = nullptr;
    std::size_t host_arena_size = 0;
    std::size_t arena_offset    = 0;
    bool        regions_carved  = false;

    kvm_layout::KvmSyzVm syz_vm{};
    bool syz_vm_ready = false;
    void* user_text = nullptr;
    void* gpa0_mem = nullptr;

    // Back-compat accessors — return regions[0] host_addr / size for the
    // GPA-0 region when present, else (nullptr / 0). Existing tests +
    // callers can keep using these to assert "guest memory is mapped".
    void*       guest_mem() const noexcept;
    std::size_t guest_mem_size() const noexcept;

    // Most-recent KVM_RUN exit reason (kvm_run::exit_reason field).
    // 0 means "no KVM_RUN issued yet". Used by assert_syzos_uexit /
    // assert_syzos_kvm_exit for read-only assertions.
    uint32_t last_exit_reason = 0;

    bool syzos_guest_installed = false;

    // Best-effort teardown (close fds + munmap regions) — never throws,
    // never propagates errors. Called from PseudoRuntimeContext::Cleanup
    // path via the cleanup callback registered in GetOrCreateKvmState.
    void Cleanup();
};

KvmState& GetOrCreateKvmState(const PseudoContext& ctx);

} // namespace refuzz::worker::pseudo
