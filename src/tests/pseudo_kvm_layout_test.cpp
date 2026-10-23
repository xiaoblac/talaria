// KVM syzOS ABI/layout pin test.
//
// This is a structural test only: no /dev/kvm, no ioctls. It pins the
// reFuzz-owned constants copied from the fixed local syzkaller checkout and
// verifies that the vendored AMD64 guest section is present and fits in the
// EXECUTOR_CODE region.

#include "worker/backend/pseudo/kvm/kvm_layout.hpp"
#include "worker/backend/pseudo/kvm/syzos_guest_amd64.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace {

namespace lk = refuzz::worker::pseudo::kvm_layout;
namespace sg = refuzz::worker::pseudo::syzos_guest_amd64;

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

void test_x86_syzos_addr_constants_match_upstream()
{
    CHECK(lk::kKvmMaxVcpu == 4);
    CHECK(lk::kKvmPageSize == 4096);
    CHECK(lk::kKvmGuestPages == 1024);

    CHECK(lk::kKvmMaxL2Vms == 4);

    CHECK(lk::kX86SyzosAddrZero == 0x0ULL);
    CHECK(lk::kX86SyzosAddrGdt == 0x1000ULL);
    CHECK(lk::kX86SyzosAddrPml4 == 0x2000ULL);
    CHECK(lk::kX86SyzosAddrPdp == 0x3000ULL);
    CHECK(lk::kX86SyzosAddrVarIdt == 0x25000ULL);
    CHECK(lk::kX86SyzosAddrVarTss == 0x26000ULL);
    CHECK(lk::kX86SyzosAddrBootArgs == 0x2F000ULL);
    CHECK(lk::kX86SyzosAddrSmram == 0x30000ULL);
    CHECK(lk::kX86SyzosAddrExit == 0x40000ULL);
    CHECK(lk::kX86SyzosAddrUexit == 0x40100ULL);
    CHECK(lk::kX86SyzosAddrDirtyPages == 0x41000ULL);
    CHECK(lk::kX86SyzosAddrUserCode == 0x50000ULL);
    CHECK(lk::kSyzosAddrExecutorCode == 0x54000ULL);
    CHECK(lk::kX86SyzosAddrScratchCode == 0x58000ULL);
    CHECK(lk::kX86SyzosAddrStackBottom == 0x60000ULL);
    CHECK(lk::kX86SyzosAddrStack0 == 0x60f80ULL);
    CHECK(lk::kX86SyzosAddrGlobals == 0x17F000ULL);
    CHECK(lk::kX86SyzosAddrPtPool == 0x180000ULL);
    CHECK(lk::kX86SyzosPtPoolSize == 64);
    CHECK(lk::kX86SyzosPerVcpuRegionsBase == 0x400000ULL);
    CHECK(lk::kX86SyzosL1VcpuRegionSize == 0x40000ULL);
    CHECK(lk::kX86SyzosAddrUnused == 0x1000000ULL);
    CHECK(lk::kX86SyzosAddrIoapic == 0xfec00000ULL);
}

void test_mem_region_flag_constants_match_upstream()
{
    CHECK(lk::kMemRegionFlagUserCode == (1u << 0));
    CHECK(lk::kMemRegionFlagDirtyLog == (1u << 1));
    CHECK(lk::kMemRegionFlagReadonly == (1u << 2));
    CHECK(lk::kMemRegionFlagExecutorCode == (1u << 3));
    CHECK(lk::kMemRegionFlagGpa0 == (1u << 5));
    CHECK(lk::kMemRegionFlagNoHostMem == (1u << 6));
    CHECK(lk::kMemRegionFlagRemaining == (1u << 7));
}

void test_mem_region_struct_layout()
{
    CHECK(sizeof(lk::MemRegion) == 16);
    CHECK(offsetof(lk::MemRegion, gpa) == 0);
    CHECK(offsetof(lk::MemRegion, pages) == 8);
    CHECK(offsetof(lk::MemRegion, flags) == 12);
}

void test_kvm_syz_vm_struct_layout()
{
    // [stateless] Expanded to a self-describing VM state blob (mirrors syz
    // kvm_syz_vm): prefix offsets unchanged so a0 stays backward-compatible.
    CHECK(sizeof(lk::KvmSyzVm) == 176);
    CHECK(offsetof(lk::KvmSyzVm, vmfd) == 0);
    CHECK(offsetof(lk::KvmSyzVm, next_cpu_id) == 4);
    CHECK(offsetof(lk::KvmSyzVm, host_mem) == 8);
    CHECK(offsetof(lk::KvmSyzVm, total_pages) == 16);
    CHECK(offsetof(lk::KvmSyzVm, user_text) == 24);
    CHECK(offsetof(lk::KvmSyzVm, gpa0_mem) == 32);
    CHECK(offsetof(lk::KvmSyzVm, pt_pool_mem) == 40);
    CHECK(offsetof(lk::KvmSyzVm, globals_mem) == 48);
    CHECK(offsetof(lk::KvmSyzVm, region_base) == 56);
}

void test_syzos_mem_regions_table_shape()
{
    // Mirror of syzkaller's syzos_mem_regions[] (executor/common_kvm_amd64.h)
    // for commit 08ab31164 (AMD nested-virt map).
    CHECK(lk::kSyzosMemRegionsCount == 15);

    CHECK(lk::kSyzosMemRegions[0].gpa == lk::kX86SyzosAddrZero);
    CHECK(lk::kSyzosMemRegions[0].pages == 5);
    CHECK(lk::kSyzosMemRegions[0].flags == lk::kMemRegionFlagGpa0);

    CHECK(lk::kSyzosMemRegions[1].gpa == lk::kX86SyzosAddrVarIdt);
    CHECK(lk::kSyzosMemRegions[1].pages == 10);
    CHECK(lk::kSyzosMemRegions[1].flags == 0u);

    CHECK(lk::kSyzosMemRegions[2].gpa == lk::kX86SyzosAddrBootArgs);
    CHECK(lk::kSyzosMemRegions[2].pages == 1);
    CHECK(lk::kSyzosMemRegions[2].flags == 0u);

    CHECK(lk::kSyzosMemRegions[3].gpa == lk::kX86SyzosAddrPtPool);
    CHECK(lk::kSyzosMemRegions[3].pages == lk::kX86SyzosPtPoolSize);
    CHECK(lk::kSyzosMemRegions[3].flags == 0u);

    CHECK(lk::kSyzosMemRegions[4].gpa == lk::kX86SyzosAddrGlobals);
    CHECK(lk::kSyzosMemRegions[4].pages == 1);
    CHECK(lk::kSyzosMemRegions[4].flags == 0u);

    CHECK(lk::kSyzosMemRegions[5].gpa == lk::kX86SyzosAddrSmram);
    CHECK(lk::kSyzosMemRegions[5].pages == 10);
    CHECK(lk::kSyzosMemRegions[5].flags == 0u);

    CHECK(lk::kSyzosMemRegions[6].gpa == lk::kX86SyzosAddrExit);
    CHECK(lk::kSyzosMemRegions[6].pages == 1);
    CHECK(lk::kSyzosMemRegions[6].flags == lk::kMemRegionFlagNoHostMem);

    CHECK(lk::kSyzosMemRegions[7].gpa == lk::kX86SyzosAddrDirtyPages);
    CHECK(lk::kSyzosMemRegions[7].pages == 2);
    CHECK(lk::kSyzosMemRegions[7].flags == lk::kMemRegionFlagDirtyLog);

    CHECK(lk::kSyzosMemRegions[8].gpa == lk::kX86SyzosAddrUserCode);
    CHECK(lk::kSyzosMemRegions[8].pages == lk::kKvmMaxVcpu);
    CHECK(lk::kSyzosMemRegions[8].flags ==
          (lk::kMemRegionFlagReadonly | lk::kMemRegionFlagUserCode));

    CHECK(lk::kSyzosMemRegions[9].gpa == lk::kSyzosAddrExecutorCode);
    CHECK(lk::kSyzosMemRegions[9].pages == 4);
    CHECK(lk::kSyzosMemRegions[9].flags ==
          (lk::kMemRegionFlagReadonly | lk::kMemRegionFlagExecutorCode));

    CHECK(lk::kSyzosMemRegions[10].gpa == lk::kX86SyzosAddrScratchCode);
    CHECK(lk::kSyzosMemRegions[10].pages == 1);
    CHECK(lk::kSyzosMemRegions[10].flags == 0u);

    CHECK(lk::kSyzosMemRegions[11].gpa == lk::kX86SyzosAddrStackBottom);
    CHECK(lk::kSyzosMemRegions[11].pages == 1);
    CHECK(lk::kSyzosMemRegions[11].flags == 0u);

    CHECK(lk::kSyzosMemRegions[12].gpa == lk::kX86SyzosPerVcpuRegionsBase);
    CHECK(lk::kSyzosMemRegions[12].pages == 256);
    CHECK(lk::kSyzosMemRegions[12].flags == 0u);

    CHECK(lk::kSyzosMemRegions[13].gpa == lk::kX86SyzosAddrIoapic);
    CHECK(lk::kSyzosMemRegions[13].pages == 1);
    CHECK(lk::kSyzosMemRegions[13].flags == 0u);

    // Trailing REMAINING region (placeholder page count, sized at install).
    CHECK(lk::kSyzosMemRegions[14].gpa == lk::kX86SyzosAddrUnused);
    CHECK(lk::kSyzosMemRegions[14].pages == 0);
    CHECK(lk::kSyzosMemRegions[14].flags == lk::kMemRegionFlagRemaining);
}

void test_syzos_page_accounting()
{
    CHECK(lk::kSyzosPerVcpuRegionPages == 256);
    CHECK(lk::kSyzosTotalHostPages == 1023);
    CHECK(lk::kSyzosNoHostPages == 1);
    // 5+10+1+64+1+10+2+4+4+1+1+256+1 = 360 host-backed fixed pages.
    CHECK(lk::kSyzosHostBackedRegionPages == 360);
    CHECK(lk::kSyzosAllRegionPages == 361);
    CHECK(lk::kSyzosUnusedHostPages == 663);
}

void test_vendored_guest_section_metadata()
{
    CHECK(sg::Code() != nullptr);
    CHECK(sg::Size() > 0);
    CHECK(sg::Size() <= 4u * lk::kKvmPageSize);

    const auto exec_lo = lk::kSyzosAddrExecutorCode;
    const auto exec_hi = exec_lo + 4u * lk::kKvmPageSize;
    CHECK(sg::GuestMainGpa() >= exec_lo);
    CHECK(sg::GuestMainGpa() < exec_hi);
    CHECK(sg::DummyNullHandlerGpa() >= exec_lo);
    CHECK(sg::DummyNullHandlerGpa() < exec_hi);
    CHECK(sg::UexitIrqHandlerGpa() >= exec_lo);
    CHECK(sg::UexitIrqHandlerGpa() < exec_hi);
    CHECK(sg::NestedVmExitHandlerIntelAsmGpa() >= exec_lo);
    CHECK(sg::NestedVmExitHandlerIntelAsmGpa() < exec_hi);
}

}  // namespace

int main()
{
    RUN_TEST(test_x86_syzos_addr_constants_match_upstream);
    RUN_TEST(test_mem_region_flag_constants_match_upstream);
    RUN_TEST(test_mem_region_struct_layout);
    RUN_TEST(test_kvm_syz_vm_struct_layout);
    RUN_TEST(test_syzos_mem_regions_table_shape);
    RUN_TEST(test_syzos_page_accounting);
    RUN_TEST(test_vendored_guest_section_metadata);
    return 0;
}
