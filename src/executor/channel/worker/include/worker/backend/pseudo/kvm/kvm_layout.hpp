#pragma once

// KVM syzOS ABI/layout constants pinned from the vendored syzkaller source:
//
//   executor/kvm.h
//   executor/common_kvm_amd64.h
//
// reFuzz host code consumes these reFuzz-owned constants and structs; the
// copied syzkaller headers are used only by syzos_guest_amd64.cpp to expose
// guest-section bytes and guest symbol GPAs.
//
// Synced to syzkaller commit 08ab31164c55f20c7a2653de3186ae333470e2c1
// (AMD nested-virt guest). The host memory map was restructured vs the
// previous a066d2bc4 pin: the single 48-page GPA0 block split into a 5-page
// fixed block + a dedicated 10-page IDT/TSS region, plus new BOOT_ARGS,
// PT_POOL, GLOBALS regions, per-VCPU regions relocated to 0x400000, and a
// trailing REMAINING region (UNUSED) sized at install time. Mirror of
// syzos_mem_regions[] in executor/common_kvm_amd64.h.

#include <cstddef>
#include <cstdint>

namespace refuzz::worker::pseudo::kvm_layout {

inline constexpr int kKvmMaxVcpu      = 4;
inline constexpr int kKvmMaxL2Vms     = 4;
inline constexpr int kKvmPageSize     = 1 << 12;
inline constexpr int kKvmGuestPages   = 1024;
inline constexpr int kKvmGuestMemSize = kKvmGuestPages * kKvmPageSize;

inline constexpr std::uint64_t kX86SyzosAddrZero       = 0x0ULL;
inline constexpr std::uint64_t kX86SyzosAddrGdt        = 0x1000ULL;
inline constexpr std::uint64_t kX86SyzosAddrPml4       = 0x2000ULL;
inline constexpr std::uint64_t kX86SyzosAddrPdp        = 0x3000ULL;
inline constexpr std::uint64_t kX86SyzosAddrVarIdt     = 0x25000ULL;
inline constexpr std::uint64_t kX86SyzosAddrVarTss     = 0x26000ULL;
// Dedicated page for passing configuration (memory map) to L1.
inline constexpr std::uint64_t kX86SyzosAddrBootArgs   = 0x2F000ULL;
inline constexpr std::uint64_t kX86SyzosAddrSmram      = 0x30000ULL;
inline constexpr std::uint64_t kX86SyzosAddrExit       = 0x40000ULL;
inline constexpr std::uint64_t kX86SyzosAddrUexit      = kX86SyzosAddrExit + 256ULL;
inline constexpr std::uint64_t kX86SyzosAddrDirtyPages = 0x41000ULL;
inline constexpr std::uint64_t kX86SyzosAddrUserCode   = 0x50000ULL;
inline constexpr std::uint64_t kSyzosAddrExecutorCode  = 0x54000ULL;
inline constexpr std::uint64_t kX86SyzosAddrScratchCode = 0x58000ULL;
inline constexpr std::uint64_t kX86SyzosAddrStackBottom = 0x60000ULL;
inline constexpr std::uint64_t kX86SyzosAddrStack0      = 0x60f80ULL;
// Global state page (allocator offsets, per-vcpu L2 contexts, etc).
inline constexpr std::uint64_t kX86SyzosAddrGlobals     = 0x17F000ULL;
// Separated page-table pool in high memory (above L2 VCPU regions).
inline constexpr std::uint64_t kX86SyzosAddrPtPool      = 0x180000ULL;
inline constexpr int           kX86SyzosPtPoolSize      = 64;
// Base address for all per-L1-VCPU regions.
inline constexpr std::uint64_t kX86SyzosPerVcpuRegionsBase = 0x400000ULL;
inline constexpr std::uint64_t kX86SyzosL1VcpuRegionSize   = 0x40000ULL;
inline constexpr std::uint64_t kX86SyzosAddrUnused = 0x1000000ULL;
inline constexpr std::uint64_t kX86SyzosAddrIoapic = 0xfec00000ULL;

inline constexpr std::uint16_t kX86SyzosSelCode  = 0x8;
inline constexpr std::uint16_t kX86SyzosSelData  = 0x10;
inline constexpr std::uint16_t kX86SyzosSelTss64 = 0x18;

inline constexpr std::uint64_t kX86Cr0Pe = 1ULL;
inline constexpr std::uint64_t kX86Cr0Ne = 1ULL << 5;
inline constexpr std::uint64_t kX86Cr0Pg = 1ULL << 31;
inline constexpr std::uint64_t kX86Cr4Pae = 1ULL << 5;
inline constexpr std::uint64_t kX86Cr4Osfxsr = 1ULL << 9;
inline constexpr std::uint64_t kX86EferLme = 1ULL << 8;
inline constexpr std::uint64_t kX86EferLma = 1ULL << 10;
inline constexpr std::uint64_t kX86EferNxe = 1ULL << 11;

inline constexpr std::uint64_t kX86Pde64Present = 1ULL;
inline constexpr std::uint64_t kX86Pde64Rw      = 1ULL << 1;
inline constexpr std::uint64_t kX86PageMask     = ((1ULL << 52) - 1) & ~0xfffULL;

inline constexpr std::uint32_t kMemRegionFlagUserCode     = 1u << 0;
inline constexpr std::uint32_t kMemRegionFlagDirtyLog     = 1u << 1;
inline constexpr std::uint32_t kMemRegionFlagReadonly     = 1u << 2;
inline constexpr std::uint32_t kMemRegionFlagExecutorCode = 1u << 3;
inline constexpr std::uint32_t kMemRegionFlagGpa0         = 1u << 5;
inline constexpr std::uint32_t kMemRegionFlagNoHostMem    = 1u << 6;
// Trailing region whose page count is computed at install time (absorbs all
// remaining host pages). Must be the last entry in kSyzosMemRegions.
inline constexpr std::uint32_t kMemRegionFlagRemaining    = 1u << 7;

struct MemRegion {
    std::uint64_t gpa;
    int           pages;
    std::uint32_t flags;
};

// Number of syzOS guest memory regions (mirror of SYZOS_REGION_COUNT). Defined
// above KvmSyzVm because KvmSyzVm::region_base needs it as an array bound.
inline constexpr int kSyzosMemRegionsCount = 15;

// Self-describing VM state blob: SetupSyzosVm writes this into the program's
// host_mem VMA and returns it as the syz_kvm_setup_syzos_vm resource (a0). Any
// worker thread can rehydrate the entire VM from a0 alone, so the KVM pseudos
// are STATELESS w.r.t. the per-thread KvmState (which becomes a cache) — this is
// what makes them immune to the threaded executor's call migration. Mirrors
// syz's kvm_syz_vm (executor/common_kvm_amd64.h:248). region_base[i] is the host
// mmap base of region i (nullptr for NO_HOST_MEM rows); pt_pool_mem / globals_mem
// are the page-table-pool / globals region bases (used by page-table setup and
// the guest text-size channel).
struct KvmSyzVm {
    int           vmfd;
    int           next_cpu_id;
    void*         host_mem;
    std::size_t   total_pages;
    void*         user_text;
    void*         gpa0_mem;
    void*         pt_pool_mem;
    void*         globals_mem;
    void*         region_base[kSyzosMemRegionsCount];
};

inline constexpr int kSyzosPerVcpuRegionPages =
    (kKvmMaxVcpu * static_cast<int>(kX86SyzosL1VcpuRegionSize)) / kKvmPageSize;

// Mirror of syzos_mem_regions[] in executor/common_kvm_amd64.h. Order matters:
// the REMAINING region (UNUSED) must be last. (kSyzosMemRegionsCount is defined
// above, before KvmSyzVm, so it can size KvmSyzVm::region_base.)
inline constexpr MemRegion kSyzosMemRegions[kSyzosMemRegionsCount] = {
    // AMD64 fixed data structures (Zero, GDT, PML4, PDP, PD).
    {kX86SyzosAddrZero,        5, kMemRegionFlagGpa0},
    // High fixed data (IDT, TSS).
    {kX86SyzosAddrVarIdt,     10, 0u},
    // Boot configuration page (memory map handed to L1).
    {kX86SyzosAddrBootArgs,    1, 0u},
    // Dynamic page-table pool.
    {kX86SyzosAddrPtPool,      kX86SyzosPtPoolSize, 0u},
    // Global state page.
    {kX86SyzosAddrGlobals,     1, 0u},
    // SMRAM memory.
    {kX86SyzosAddrSmram,      10, 0u},
    // Unmapped region to trigger page faults for uexits etc.
    {kX86SyzosAddrExit,        1, kMemRegionFlagNoHostMem},
    // Writable region with KVM_MEM_LOG_DIRTY_PAGES to fuzz dirty ring.
    {kX86SyzosAddrDirtyPages,  2, kMemRegionFlagDirtyLog},
    // SYZOS user code (generated by the fuzzer).
    {kX86SyzosAddrUserCode,    kKvmMaxVcpu,
        kMemRegionFlagReadonly | kMemRegionFlagUserCode},
    // Executor guest code.
    {kSyzosAddrExecutorCode,   4,
        kMemRegionFlagReadonly | kMemRegionFlagExecutorCode},
    // Scratch memory for code generated at runtime.
    {kX86SyzosAddrScratchCode, 1, 0u},
    // CPU stack.
    {kX86SyzosAddrStackBottom, 1, 0u},
    // Per-VCPU regions for L2 VMs.
    {kX86SyzosPerVcpuRegionsBase, kSyzosPerVcpuRegionPages, 0u},
    // IOAPIC memory.
    {kX86SyzosAddrIoapic,      1, 0u},
    // Remainder of memory (unused heap). Must be last.
    {kX86SyzosAddrUnused,      0, kMemRegionFlagRemaining},
};

inline constexpr int kSyzosTotalHostPages = kKvmGuestPages - 1;
inline constexpr int kSyzosNoHostPages = 1;  // EXIT region (NO_HOST_MEM)
// Sum of host-backed fixed-size regions (every region except the NO_HOST_MEM
// EXIT region and the trailing REMAINING region).
inline constexpr int kSyzosHostBackedRegionPages =
    5 + 10 + 1 + kX86SyzosPtPoolSize + 1 + 10 + 2 + kKvmMaxVcpu + 4 + 1 + 1 +
    kSyzosPerVcpuRegionPages + 1;
inline constexpr int kSyzosAllRegionPages =
    kSyzosHostBackedRegionPages + kSyzosNoHostPages;
// Host pages handed to the trailing REMAINING (UNUSED) region.
inline constexpr int kSyzosUnusedHostPages =
    kSyzosTotalHostPages - kSyzosHostBackedRegionPages;

static_assert(sizeof(MemRegion) == 16);
// 6*8 prefix (vmfd+next_cpu_id pack to 8) + pt_pool_mem + globals_mem + 15 ptrs.
static_assert(sizeof(KvmSyzVm) == 176);
static_assert(kSyzosHostBackedRegionPages == 360);
static_assert(kSyzosUnusedHostPages == 663);

} // namespace refuzz::worker::pseudo::kvm_layout
