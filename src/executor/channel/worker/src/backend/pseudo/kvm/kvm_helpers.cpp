// PR-D2 — KVM lifecycle helpers implementation.

#include "worker/backend/pseudo/kvm/kvm_helpers.hpp"
#include "worker/backend/pseudo/kvm/kvm_state.hpp"
#include "worker/backend/pseudo/kvm/syzos_guest_amd64.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cpuid.h>           // __get_cpuid — AMD vendor probe for EFER.SVME
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {

namespace {

constexpr std::size_t kPageSize = 4096;

} // namespace

int KvmOpenRoot(KvmState& state)
{
    if (state.kvm_root_fd >= 0) {
        return 0;
    }
    const int fd = ::open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        const int saved_err = errno;
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: open(/dev/kvm) failed errno=%d (%s) uid=%d euid=%d\n",
            saved_err, std::strerror(saved_err),
            static_cast<int>(::getuid()), static_cast<int>(::geteuid()));
        errno = saved_err;
        return -1;
    }
    state.kvm_root_fd = fd;
    return 0;
}

int KvmCreateVm(KvmState& state)
{
    if (state.vm_fd >= 0) {
        return 0;
    }
    if (KvmOpenRoot(state) < 0) {
        return -1;
    }
    const int vm = ::ioctl(state.kvm_root_fd, KVM_CREATE_VM, 0);
    if (vm < 0) {
        const int saved_err = errno;
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: KVM_CREATE_VM failed errno=%d (%s) root_fd=%d\n",
            saved_err, std::strerror(saved_err), state.kvm_root_fd);
        errno = saved_err;
        return -1;
    }
    state.vm_fd = vm;
    return 0;
}

namespace {

std::uint32_t KvmMemFlags(std::uint32_t flags)
{
    std::uint32_t out = 0;
    if ((flags & kvm_layout::kMemRegionFlagDirtyLog) != 0u) {
        out |= KVM_MEM_LOG_DIRTY_PAGES;
    }
#ifdef KVM_MEM_READONLY
    if ((flags & kvm_layout::kMemRegionFlagReadonly) != 0u) {
        out |= KVM_MEM_READONLY;
    }
#endif
    return out;
}

void UnwindRegions(KvmState& state)
{
    // [carve_from_host_mem] In carve mode the region host_addr's are slices of
    // the single host_arena (non-owning) — free only the arena, once.
    if (state.regions_carved) {
        state.regions.clear();
        if (state.host_arena != nullptr && state.host_arena != MAP_FAILED &&
            state.host_arena_size > 0) {
            ::munmap(state.host_arena, state.host_arena_size);
        }
        state.host_arena      = nullptr;
        state.host_arena_size = 0;
        state.arena_offset    = 0;
        state.regions_carved  = false;
        return;
    }
    for (auto& back : state.regions) {
        if (back.host_addr != nullptr) {
            ::munmap(back.host_addr, back.size_bytes);
        }
    }
    state.regions.clear();
}

int MapHostRegion(KvmState& state,
                  std::uint32_t& next_slot,
                  std::uint64_t gpa,
                  int pages,
                  std::uint32_t flags,
                  const char* label)
{
    const std::size_t sz = static_cast<std::size_t>(pages) * kPageSize;
    // [carve_from_host_mem] Carve this region as a slice of the single host
    // arena (allocated once in KvmMapRegions) instead of a per-region mmap. The
    // arena is anonymous/zero-filled, so each slice is zero-initialized exactly
    // like the old per-region mmap.
    if (state.host_arena == nullptr ||
        state.arena_offset + sz > state.host_arena_size) {
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: arena carve %s gpa=0x%llx sz=%zu overflow "
            "(off=%zu cap=%zu)\n",
            label, static_cast<unsigned long long>(gpa), sz,
            state.arena_offset, state.host_arena_size);
        errno = ENOMEM;
        return -1;
    }
    void* mem = static_cast<std::uint8_t*>(state.host_arena) + state.arena_offset;
    state.arena_offset += sz;

    struct kvm_userspace_memory_region region_ioctl = {};
    region_ioctl.slot            = next_slot;
    region_ioctl.flags           = KvmMemFlags(flags);
    region_ioctl.guest_phys_addr = gpa;
    region_ioctl.memory_size     = static_cast<__u64>(sz);
    region_ioctl.userspace_addr  = reinterpret_cast<__u64>(mem);
    if (::ioctl(state.vm_fd, KVM_SET_USER_MEMORY_REGION, &region_ioctl) < 0) {
        const int saved_err = errno;
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: KVM_SET_USER_MEMORY_REGION %s slot=%u gpa=0x%llx sz=%zu failed errno=%d (%s)\n",
            label, next_slot, static_cast<unsigned long long>(gpa), sz,
            saved_err, std::strerror(saved_err));
        // mem is an arena slice (non-owning) — the arena is freed wholesale by
        // UnwindRegions on this failure path; do not munmap the slice.
        errno = saved_err;
        return -1;
    }

    KvmRegionSlot dst{};
    dst.gpa        = gpa;
    dst.size_bytes = sz;
    dst.flags      = flags;
    dst.host_addr  = mem;
    dst.kvm_slot   = next_slot;
    state.regions.push_back(dst);
    ++next_slot;
    return 0;
}

} // namespace

int KvmMapRegions(KvmState& state,
                  const kvm_layout::MemRegion* regions,
                  std::size_t count)
{
    if (!state.regions.empty()) {
        return 0;
    }
    if (state.vm_fd < 0) {
        if (KvmCreateVm(state) < 0) {
            return -1;
        }
    }
    if (regions == nullptr || count == 0) {
        errno = EINVAL;
        return -1;
    }

    // [carve_from_host_mem] One anonymous mapping backs ALL host-backed regions;
    // each is a bump-allocated slice registered at its sparse GPA. This replaces
    // 15 per-region mmap()s (each a separate VMA + memslot, expensive under KASAN
    // + nested KVM) with a single mapping — mirrors syz setup_vm carving one VMA.
    const std::size_t arena_sz =
        static_cast<std::size_t>(kvm_layout::kSyzosTotalHostPages) * kPageSize;
    void* arena = ::mmap(nullptr, arena_sz, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (arena == MAP_FAILED) {
        const int saved_err = errno;
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: host arena mmap sz=%zu failed errno=%d (%s)\n",
            arena_sz, saved_err, std::strerror(saved_err));
        errno = saved_err;
        return -1;
    }
    state.host_arena      = arena;
    state.host_arena_size = arena_sz;
    state.arena_offset    = 0;
    state.regions_carved  = true;

    state.regions.reserve(count);
    std::uint32_t next_slot = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& src = regions[i];
        const bool no_host_mem =
            (src.flags & kvm_layout::kMemRegionFlagNoHostMem) != 0u;
        if (no_host_mem) {
            KvmRegionSlot dst{};
            dst.gpa        = src.gpa;
            dst.size_bytes =
                static_cast<std::size_t>(src.pages) * kPageSize;
            dst.flags      = src.flags;
            dst.host_addr  = nullptr;
            dst.kvm_slot   = 0;
            state.regions.push_back(dst);
            // [stateless] NO_HOST_MEM rows carry a nullptr base in a0's view.
            state.syz_vm.region_base[i] = nullptr;
            continue;
        }
        // The trailing REMAINING region (UNUSED) carries a placeholder page
        // count (0); size it to the remaining host-page budget, mirroring
        // syzkaller's MEM_REGION_FLAG_REMAINING handling in setup_vm().
        int region_pages = src.pages;
        if ((src.flags & kvm_layout::kMemRegionFlagRemaining) != 0u) {
            region_pages = kvm_layout::kSyzosUnusedHostPages;
        }
        if (MapHostRegion(state, next_slot, src.gpa, region_pages, src.flags,
                          "syzos-region") < 0) {
            const int saved_err = errno;
            UnwindRegions(state);
            errno = saved_err;
            return -1;
        }
        auto& mapped = state.regions.back();
        // [stateless] Record every region's host base in a0's view so any worker
        // thread can rebuild the GPA->HVA map from the KvmSyzVm alone (mirror of
        // syz setup_vm's vm->region_base[i]).
        state.syz_vm.region_base[i] = mapped.host_addr;
        if ((src.flags & kvm_layout::kMemRegionFlagUserCode) != 0u) {
            state.user_text = mapped.host_addr;
        }
        if ((src.flags & kvm_layout::kMemRegionFlagGpa0) != 0u) {
            state.gpa0_mem = mapped.host_addr;
        }
        if (src.gpa == kvm_layout::kX86SyzosAddrPtPool) {
            state.syz_vm.pt_pool_mem = mapped.host_addr;
        }
        if (src.gpa == kvm_layout::kX86SyzosAddrGlobals) {
            state.syz_vm.globals_mem = mapped.host_addr;
        }
    }

    if (state.user_text == nullptr || state.gpa0_mem == nullptr) {
        UnwindRegions(state);
        errno = EINVAL;
        return -1;
    }

    state.syz_vm.vmfd        = state.vm_fd;
    state.syz_vm.next_cpu_id = state.next_cpu_id;
    state.syz_vm.host_mem    = state.gpa0_mem;
    state.syz_vm.total_pages = kvm_layout::kSyzosTotalHostPages;
    state.syz_vm.user_text   = state.user_text;
    state.syz_vm.gpa0_mem    = state.gpa0_mem;
    state.syz_vm_ready       = true;
    return 0;
}

int KvmCreateVcpu(KvmState& state)
{
    if (state.vm_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (state.next_cpu_id >= kvm_layout::kKvmMaxVcpu) {
        errno = ENOMEM;
        return -1;
    }
    const int cpu_id = state.next_cpu_id;
    const int vcpu_fd = ::ioctl(state.vm_fd, KVM_CREATE_VCPU, cpu_id);
    if (vcpu_fd < 0) {
        const int saved_err = errno;
        ::refuzz::worker::log::WorkerLog(
            "[WORKER] kvm: KVM_CREATE_VCPU(%d) failed errno=%d (%s) vm_fd=%d\n",
            cpu_id, saved_err, std::strerror(saved_err), state.vm_fd);
        errno = saved_err;
        return -1;
    }

    // Map the kvm_run shared structure for this vcpu (per-vcpu mmap).
    const int run_size = ::ioctl(state.kvm_root_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    void* run_mmap = nullptr;
    std::size_t run_mmap_size = 0;
    if (run_size > 0) {
        run_mmap = ::mmap(nullptr, static_cast<std::size_t>(run_size),
                          PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
        if (run_mmap == MAP_FAILED) {
            run_mmap = nullptr;  // non-fatal; vcpu still usable for KVM_RUN
        } else {
            run_mmap_size = static_cast<std::size_t>(run_size);
        }
    }

    state.vcpu_slots.push_back(VcpuSlot{vcpu_fd, run_mmap, run_mmap_size});
    state.next_cpu_id++;
    state.syz_vm.next_cpu_id = state.next_cpu_id;

    state.vcpu_fd       = vcpu_fd;
    state.vcpu_run      = run_mmap;
    state.vcpu_run_size = run_mmap_size;
    return 0;
}

int KvmRunVcpu(KvmState& state)
{
    if (state.vcpu_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    int rc;
    do {
        rc = ::ioctl(state.vcpu_fd, KVM_RUN, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return -1;
    }
    if (state.vcpu_run != nullptr) {
        const auto* run = static_cast<const kvm_run*>(state.vcpu_run);
        state.last_exit_reason = run->exit_reason;
    }
    return 0;
}

void* KvmHostAddrForGpa(const KvmState& state, std::uint64_t gpa)
{
    // Fast path: this thread mapped the regions itself (setup ran here), so the
    // per-region slots carry the actual mapped sizes.
    for (const auto& slot : state.regions) {
        if (slot.host_addr == nullptr) continue;
        const std::uint64_t lo = slot.gpa;
        const std::uint64_t hi = lo + slot.size_bytes;
        if (gpa >= lo && gpa < hi) {
            const std::uint64_t off = gpa - lo;
            return static_cast<std::uint8_t*>(slot.host_addr) + off;
        }
    }
    if (!state.regions.empty()) {
        return nullptr;  // mapped locally, GPA out of every region
    }
    // [stateless] Migrated thread: regions[] is empty because setup ran on
    // another thread. Translate via the region_base[] carried in a0
    // (state.syz_vm), mirroring syz gpa_to_hva (common_kvm_amd64.h:262-280).
    // Use the STATIC region page counts for sizing, and explicitly stop at the
    // trailing UNUSED region — in reFuzz that region IS host-backed (non-null
    // region_base), so it must NOT be used for translation (syz `break`s there).
    for (int i = 0; i < kvm_layout::kSyzosMemRegionsCount; ++i) {
        const auto& r = kvm_layout::kSyzosMemRegions[i];
        if (r.gpa == kvm_layout::kX86SyzosAddrUnused) break;
        if ((r.flags & kvm_layout::kMemRegionFlagNoHostMem) != 0u) continue;
        void* base = state.syz_vm.region_base[i];
        if (base == nullptr) continue;
        const std::uint64_t lo = r.gpa;
        const std::uint64_t hi =
            lo + static_cast<std::uint64_t>(r.pages) * kPageSize;
        if (gpa >= lo && gpa < hi) {
            return static_cast<std::uint8_t*>(base) + (gpa - lo);
        }
    }
    return nullptr;
}

namespace {

std::size_t KvmHostBytesRemainingForGpa(const KvmState& state, std::uint64_t gpa)
{
    for (const auto& slot : state.regions) {
        if (slot.host_addr == nullptr) continue;
        const std::uint64_t lo = slot.gpa;
        const std::uint64_t hi = lo + slot.size_bytes;
        if (gpa >= lo && gpa < hi) {
            return static_cast<std::size_t>(hi - gpa);
        }
    }
    if (!state.regions.empty()) {
        return 0;
    }
    // [stateless] Migrated-thread fallback, symmetric to KvmHostAddrForGpa.
    for (int i = 0; i < kvm_layout::kSyzosMemRegionsCount; ++i) {
        const auto& r = kvm_layout::kSyzosMemRegions[i];
        if (r.gpa == kvm_layout::kX86SyzosAddrUnused) break;
        if ((r.flags & kvm_layout::kMemRegionFlagNoHostMem) != 0u) continue;
        if (state.syz_vm.region_base[i] == nullptr) continue;
        const std::uint64_t lo = r.gpa;
        const std::uint64_t hi =
            lo + static_cast<std::uint64_t>(r.pages) * kPageSize;
        if (gpa >= lo && gpa < hi) {
            return static_cast<std::size_t>(hi - gpa);
        }
    }
    return 0;
}

struct IdtEntry64 {
    std::uint16_t offset_low;
    std::uint16_t selector;
    std::uint8_t  ist;
    std::uint8_t  type_attr;
    std::uint16_t offset_mid;
    std::uint32_t offset_high;
    std::uint32_t reserved;
} __attribute__((packed));

struct GdtEntry {
    std::uint16_t limit_low;
    std::uint16_t base_low;
    std::uint8_t  base_mid;
    std::uint8_t  access;
    std::uint8_t  limit_high_and_flags;
    std::uint8_t  base_high;
} __attribute__((packed));

struct PageAlloc {
    std::uint64_t next_page;
    std::uint64_t last_page;
};

std::uint64_t PageAllocNext(PageAlloc& alloc)
{
    if (alloc.next_page >= alloc.last_page) {
        return 0;
    }
    const std::uint64_t page = alloc.next_page;
    alloc.next_page += kvm_layout::kKvmPageSize;
    return page;
}

bool Map4kPage(KvmState& state, PageAlloc& alloc, std::uint64_t gpa)
{
    using namespace kvm_layout;
    // Region-based addressing: page-table structures now span several distinct
    // host-backed regions (gpa0 for PML4/PDP/PD, the separate PT_POOL region for
    // dynamically allocated PTs), so every GPA is translated through the
    // per-region map rather than a single linear gpa0 buffer (mirrors
    // syzkaller's get_host_pte_ptr() in executor/common_kvm_amd64.h).
    auto host_pte = [&state](std::uint64_t g) -> std::uint64_t* {
        return reinterpret_cast<std::uint64_t*>(KvmHostAddrForGpa(state, g));
    };

    auto* pml4 = host_pte(kX86SyzosAddrPml4);
    if (pml4 == nullptr) return false;
    const std::uint64_t pml4_idx = (gpa >> 39) & 0x1ffULL;
    if (pml4[pml4_idx] == 0) {
        const std::uint64_t page = PageAllocNext(alloc);
        if (page == 0) return false;
        pml4[pml4_idx] = kX86Pde64Present | kX86Pde64Rw | page;
    }
    auto* pdpt = host_pte(pml4[pml4_idx] & kX86PageMask);
    if (pdpt == nullptr) return false;

    const std::uint64_t pdpt_idx = (gpa >> 30) & 0x1ffULL;
    if (pdpt[pdpt_idx] == 0) {
        const std::uint64_t page = PageAllocNext(alloc);
        if (page == 0) return false;
        pdpt[pdpt_idx] = kX86Pde64Present | kX86Pde64Rw | page;
    }
    auto* pd = host_pte(pdpt[pdpt_idx] & kX86PageMask);
    if (pd == nullptr) return false;

    const std::uint64_t pd_idx = (gpa >> 21) & 0x1ffULL;
    if (pd[pd_idx] == 0) {
        const std::uint64_t page = PageAllocNext(alloc);
        if (page == 0) return false;
        pd[pd_idx] = kX86Pde64Present | kX86Pde64Rw | page;
    }
    auto* pt = host_pte(pd[pd_idx] & kX86PageMask);
    if (pt == nullptr) return false;

    const std::uint64_t pt_idx = (gpa >> 12) & 0x1ffULL;
    pt[pt_idx] = (gpa & kX86PageMask) | kX86Pde64Present | kX86Pde64Rw;
    return true;
}

bool Map4kRegion(KvmState& state,
                 PageAlloc& alloc,
                 std::uint64_t gpa_start,
                 int pages)
{
    for (int i = 0; i < pages; ++i) {
        if (!Map4kPage(state, alloc,
                       gpa_start + static_cast<std::uint64_t>(i) * kPageSize)) {
            return false;
        }
    }
    return true;
}

// Mirrors syzkaller's setup_pg_table() (executor/common_kvm_amd64.h): builds
// identity page tables for every host-backed region. PT_POOL, GLOBALS, the
// per-VCPU regions and UNUSED now live at sparse high GPAs in their own
// host-backed regions, so all accesses route through KvmHostAddrForGpa. The
// trailing REMAINING region (UNUSED) is sized from the running page budget.
bool SetupPageTables(KvmState& state)
{
    using namespace kvm_layout;
    if (state.gpa0_mem == nullptr) return false;

    auto* pt_pool = static_cast<std::uint8_t*>(
        KvmHostAddrForGpa(state, kX86SyzosAddrPtPool));
    if (pt_pool == nullptr) return false;

    PageAlloc alloc{
        kX86SyzosAddrPtPool,
        kX86SyzosAddrPtPool +
            static_cast<std::uint64_t>(kX86SyzosPtPoolSize) * kPageSize,
    };
    // Zero the PT pool region and the fixed system pages (PML4/PDP/PD).
    std::memset(pt_pool, 0,
                static_cast<std::size_t>(kX86SyzosPtPoolSize) * kPageSize);
    std::memset(state.gpa0_mem, 0, 5u * kPageSize);

    int total = kSyzosTotalHostPages;
    for (const auto& r : kSyzosMemRegions) {
        int region_pages = r.pages;
        if ((r.flags & kMemRegionFlagRemaining) != 0u) {
            if (total < 0) return false;
            region_pages = total;
        }
        if (!Map4kRegion(state, alloc, r.gpa, region_pages)) {
            return false;
        }
        if ((r.flags & kMemRegionFlagNoHostMem) == 0u) {
            total -= region_pages;
        }
        if ((r.flags & kMemRegionFlagRemaining) != 0u) {
            break;
        }
    }
    return true;
}

// Mirrors the boot-args write in syzkaller's install_syzos_code(): the L1 guest
// reads the region map from the BOOT_ARGS page to size its own allocator and
// set up nested (L2) VMs. UNUSED's placeholder page count is replaced with the
// computed remaining-page budget.
bool WriteSyzosBootArgs(KvmState& state)
{
    using namespace kvm_layout;
    auto* base = static_cast<std::uint8_t*>(
        KvmHostAddrForGpa(state, kX86SyzosAddrBootArgs));
    if (base == nullptr) return false;
    // struct syzos_boot_args { uint32 region_count; uint32 reserved;
    //                          struct mem_region regions[]; }
    // struct mem_region { uint64 gpa; int pages; uint32 flags; }  (16 bytes,
    // identical layout to kvm_layout::MemRegion).
    auto* header = reinterpret_cast<std::uint32_t*>(base);
    header[0] = static_cast<std::uint32_t>(kSyzosMemRegionsCount);
    header[1] = 0u;  // reserved
    auto* out = reinterpret_cast<MemRegion*>(base + 8);
    for (int i = 0; i < kSyzosMemRegionsCount; ++i) {
        MemRegion r = kSyzosMemRegions[i];
        if ((r.flags & kMemRegionFlagRemaining) != 0u) {
            r.pages = kSyzosUnusedHostPages;
        }
        out[i] = r;
    }
    return true;
}

void SetupGdt64(GdtEntry* gdt)
{
    gdt[0] = GdtEntry{};
    gdt[kvm_layout::kX86SyzosSelCode >> 3] = GdtEntry{
        .limit_low = 0xffff,
        .base_low = 0,
        .base_mid = 0,
        .access = 0x9a,
        .limit_high_and_flags = 0xaf,
        .base_high = 0,
    };
    gdt[kvm_layout::kX86SyzosSelData >> 3] = GdtEntry{
        .limit_low = 0xffff,
        .base_low = static_cast<std::uint16_t>(kvm_layout::kX86SyzosAddrVarTss),
        .base_mid = static_cast<std::uint8_t>(
            (kvm_layout::kX86SyzosAddrVarTss >> 16) & 0xff),
        .access = 0x92,
        .limit_high_and_flags = 0xcf,
        .base_high = static_cast<std::uint8_t>(
            (kvm_layout::kX86SyzosAddrVarTss >> 24) & 0xff),
    };
    gdt[kvm_layout::kX86SyzosSelTss64 >> 3] = GdtEntry{
        .limit_low = 0x67,
        .base_low = 0,
        .base_mid = 0,
        .access = 0x89,
        .limit_high_and_flags = 0x00,
        .base_high = 0,
    };
}

void SetupSyzosIdt(KvmState& state, kvm_sregs& sregs)
{
    sregs.idt.base = kvm_layout::kX86SyzosAddrVarIdt;
    sregs.idt.limit =
        static_cast<__u16>(256 * sizeof(IdtEntry64) - 1);
    auto* idt = reinterpret_cast<IdtEntry64*>(
        KvmHostAddrForGpa(state, sregs.idt.base));
    if (idt == nullptr) return;
    const std::uint64_t handler = syzos_guest_amd64::DummyNullHandlerGpa();
    for (int i = 0; i < 256; ++i) {
        idt[i].offset_low = static_cast<std::uint16_t>(handler & 0xffff);
        idt[i].selector = kvm_layout::kX86SyzosSelCode;
        idt[i].ist = 0;
        idt[i].type_attr = 0x8e;
        idt[i].offset_mid =
            static_cast<std::uint16_t>((handler >> 16) & 0xffff);
        idt[i].offset_high =
            static_cast<std::uint32_t>((handler >> 32) & 0xffffffff);
        idt[i].reserved = 0;
    }
}

int SetupGdtLdtPg(KvmState& state)
{
    if (state.vcpu_fd < 0 || !state.syz_vm_ready) {
        errno = EINVAL;
        return -1;
    }

    kvm_sregs sregs{};
    if (::ioctl(state.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        return -1;
    }

    sregs.gdt.base = kvm_layout::kX86SyzosAddrGdt;
    sregs.gdt.limit = static_cast<__u16>(5 * sizeof(GdtEntry) - 1);
    auto* gdt = reinterpret_cast<GdtEntry*>(
        KvmHostAddrForGpa(state, sregs.gdt.base));
    if (gdt == nullptr) {
        errno = EINVAL;
        return -1;
    }

    kvm_segment seg_cs64{};
    seg_cs64.selector = kvm_layout::kX86SyzosSelCode;
    seg_cs64.type = 11;
    seg_cs64.base = 0;
    seg_cs64.limit = 0xffffffffu;
    seg_cs64.present = 1;
    seg_cs64.s = 1;
    seg_cs64.g = 1;
    seg_cs64.l = 1;
    sregs.cs = seg_cs64;

    kvm_segment seg_ds64{};
    seg_ds64.selector = kvm_layout::kX86SyzosSelData;
    seg_ds64.type = 3;
    seg_ds64.limit = 0xffffffffu;
    seg_ds64.present = 1;
    seg_ds64.s = 1;
    seg_ds64.g = 1;
    seg_ds64.db = 1;
    sregs.ds = seg_ds64;
    sregs.es = seg_ds64;
    sregs.fs = seg_ds64;
    sregs.gs = seg_ds64;
    sregs.ss = seg_ds64;

    kvm_segment seg_tr{};
    seg_tr.selector = kvm_layout::kX86SyzosSelTss64;
    seg_tr.type = 11;
    seg_tr.base = kvm_layout::kX86SyzosAddrVarTss;
    seg_tr.limit = 0x67;
    seg_tr.present = 1;
    seg_tr.s = 0;
    sregs.tr = seg_tr;

    auto* tss = static_cast<std::uint8_t*>(
        KvmHostAddrForGpa(state, kvm_layout::kX86SyzosAddrVarTss));
    if (tss == nullptr) {
        errno = EINVAL;
        return -1;
    }
    std::memset(tss, 0, 104);
    *reinterpret_cast<std::uint64_t*>(tss + 4) = kvm_layout::kX86SyzosAddrStack0;

    SetupGdt64(gdt);
    SetupSyzosIdt(state, sregs);
    if (!SetupPageTables(state)) {
        errno = ENOSPC;
        return -1;
    }

    sregs.cr0 = kvm_layout::kX86Cr0Pe | kvm_layout::kX86Cr0Ne |
                kvm_layout::kX86Cr0Pg;
    sregs.cr4 |= kvm_layout::kX86Cr4Pae | kvm_layout::kX86Cr4Osfxsr;
    sregs.efer |= kvm_layout::kX86EferLme | kvm_layout::kX86EferLma |
                  kvm_layout::kX86EferNxe;
    // [syz coverage-parity 2026-06-03] On an AMD host, syz enables SVM in the
    // vcpu (common_kvm_amd64.h:551-554): cpuid leaf 0 vendor == "AuthenticAMD"
    // → sregs.efer |= X86_EFER_SVME. KVM_SET_SREGS with EFER.SVME makes the
    // kernel allocate nested-SVM state (svm_set_efer → svm_allocate_nested).
    // reFuzz omitted this, so its vcpu never enabled SVM and the paired oracle
    // saw svm_allocate_nested at ref 0/93 vs syz 88/93 (syz_kvm_add_vcpu$x86,
    // verified 2026-06-03 — real fn via addr2line, AMD host via `-cpu host`).
    // Gate on AMD so Intel hosts (VMX) are unaffected. NOTE: syz also zeroes the
    // per-cpu HSAVE area (:557-558) for actual VMRUN fidelity — deferred
    // follow-up; EFER.SVME alone triggers the nested allocation we were missing.
    {
        unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
        if (__get_cpuid(0, &eax, &ebx, &ecx, &edx) &&
            ebx == 0x68747541u && edx == 0x69746e65u && ecx == 0x444d4163u) {
            constexpr std::uint64_t kX86EferSvme = 1ull << 12;  // X86_EFER_SVME
            sregs.efer |= kX86EferSvme;
        }
    }
    sregs.cr3 = kvm_layout::kX86SyzosAddrPml4;

    return ::ioctl(state.vcpu_fd, KVM_SET_SREGS, &sregs);
}

int SetupCpuid(KvmState& state)
{
    int kvmfd = state.kvm_root_fd;
    bool close_fd = false;
    if (kvmfd < 0) {
        kvmfd = ::open("/dev/kvm", O_RDWR | O_CLOEXEC);
        if (kvmfd < 0) return -1;
        close_fd = true;
    }

    alignas(kvm_cpuid2) std::uint8_t storage[
        sizeof(kvm_cpuid2) + 128 * sizeof(kvm_cpuid_entry2)] = {};
    auto* cpuid = reinterpret_cast<kvm_cpuid2*>(storage);
    cpuid->nent = 128;
    int rc = ::ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, cpuid);
    if (rc == 0) {
        rc = ::ioctl(state.vcpu_fd, KVM_SET_CPUID2, cpuid);
    }
    const int saved_err = errno;
    if (close_fd) {
        ::close(kvmfd);
    }
    errno = saved_err;
    return rc;
}

int ResetCpuRegs(KvmState& state, int cpu_id)
{
    kvm_regs regs{};
    regs.rflags = (1ULL << 1) | (1ULL << 9);  // RFLAGS.1 + IF
    regs.rip = syzos_guest_amd64::GuestMainGpa();
    regs.rsp = kvm_layout::kX86SyzosAddrStack0;
    // New guest ABI: guest_main(uint64 cpu) — cpu in RDI; the user-code size is
    // delivered via globals->text_sizes[cpu] (see KvmInstallUserCode), not RDI.
    regs.rdi = static_cast<__u64>(cpu_id);
    return ::ioctl(state.vcpu_fd, KVM_SET_REGS, &regs);
}

} // namespace

int KvmInstallSyzosGuest(KvmState& state)
{
    if (state.syzos_guest_installed) {
        return 0;
    }
    auto* dst = static_cast<std::uint8_t*>(
        KvmHostAddrForGpa(state, kvm_layout::kSyzosAddrExecutorCode));
    const std::size_t cap =
        KvmHostBytesRemainingForGpa(state, kvm_layout::kSyzosAddrExecutorCode);
    const std::size_t guest_size = syzos_guest_amd64::Size();
    if (dst == nullptr || guest_size == 0 || guest_size > cap) {
        errno = ENOSPC;
        return -1;
    }
    std::memcpy(dst, syzos_guest_amd64::Code(), guest_size);
    // Populate the BOOT_ARGS region map the new guest reads to size its
    // allocator and set up nested (L2) VMs.
    if (!WriteSyzosBootArgs(state)) {
        errno = ENOSPC;
        return -1;
    }
    state.syzos_guest_installed = true;
    return 0;
}

int KvmInstallUserCode(KvmState& state,
                       const void* text,
                       std::size_t text_size)
{
    if (!state.syz_vm_ready || state.vcpu_fd < 0 || state.user_text == nullptr) {
        errno = EINVAL;
        return -1;
    }
    const int cpu_id = state.next_cpu_id - 1;
    if (cpu_id < 0 || cpu_id >= kvm_layout::kKvmMaxVcpu) {
        errno = EINVAL;
        return -1;
    }
    if (text == nullptr) {
        text_size = 0;
    }
    if (text_size > kvm_layout::kKvmPageSize) {
        text_size = kvm_layout::kKvmPageSize;
    }
    auto* target = static_cast<std::uint8_t*>(state.user_text) +
                   static_cast<std::size_t>(cpu_id) * kvm_layout::kKvmPageSize;
    if (text_size > 0) {
        std::memcpy(target, text, text_size);
    }
    if (SetupGdtLdtPg(state) < 0) {
        return -1;
    }
    if (SetupCpuid(state) < 0) {
        return -1;
    }
    // Pass the user-code size to the guest through the shared GLOBALS page
    // (the new guest_main reads globals->text_sizes[cpu]); mirrors syzkaller's
    // install_user_code(). struct syzos_globals layout:
    //   { uint64 alloc_offset; uint64 total_size;
    //     uint64 text_sizes[KVM_MAX_VCPU]; ... } → text_sizes at byte offset 16.
    auto* globals = static_cast<std::uint8_t*>(
        KvmHostAddrForGpa(state, kvm_layout::kX86SyzosAddrGlobals));
    if (globals == nullptr) {
        errno = EINVAL;
        return -1;
    }
    auto* text_sizes = reinterpret_cast<std::uint64_t*>(globals + 16);
    text_sizes[cpu_id] = static_cast<std::uint64_t>(text_size);
    return ResetCpuRegs(state, cpu_id);
}

} // namespace refuzz::worker::pseudo
