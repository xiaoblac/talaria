#include "worker/backend/pseudo/kvm/syzos_guest_amd64.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/kvm.h>

#ifndef GOARCH_amd64
#define GOARCH_amd64 1
#endif

#ifndef SYZ_EXECUTOR
#define SYZ_EXECUTOR 1
#endif

using uint64 = unsigned long long;
using uint32 = unsigned int;
using uint16 = unsigned short;
using uint8 = unsigned char;

#include "../../../../third_party/syzkaller_syzos/common_kvm.h"
#include "../../../../third_party/syzkaller_syzos/common_kvm_amd64_syzos.h"

extern "C" __attribute__((used)) void* refuzz_syzos_guest_amd64_refs[] = {
    reinterpret_cast<void*>(guest_main),
    reinterpret_cast<void*>(dummy_null_handler),
    reinterpret_cast<void*>(uexit_irq_handler),
    reinterpret_cast<void*>(nested_vm_exit_handler_intel_asm),
};

namespace refuzz::worker::pseudo::syzos_guest_amd64 {

const std::uint8_t* Code() noexcept
{
    return reinterpret_cast<const std::uint8_t*>(&__start_guest);
}

std::size_t Size() noexcept
{
    const auto* start = reinterpret_cast<const std::uint8_t*>(&__start_guest);
    const auto* stop  = reinterpret_cast<const std::uint8_t*>(&__stop_guest);
    return static_cast<std::size_t>(stop - start);
}

std::uint64_t GuestMainGpa() noexcept
{
    return static_cast<std::uint64_t>(executor_fn_guest_addr(guest_main));
}

std::uint64_t DummyNullHandlerGpa() noexcept
{
    return static_cast<std::uint64_t>(executor_fn_guest_addr(dummy_null_handler));
}

std::uint64_t UexitIrqHandlerGpa() noexcept
{
    return static_cast<std::uint64_t>(executor_fn_guest_addr(uexit_irq_handler));
}

std::uint64_t NestedVmExitHandlerIntelAsmGpa() noexcept
{
    return static_cast<std::uint64_t>(
        executor_fn_guest_addr(nested_vm_exit_handler_intel_asm));
}

} // namespace refuzz::worker::pseudo::syzos_guest_amd64
