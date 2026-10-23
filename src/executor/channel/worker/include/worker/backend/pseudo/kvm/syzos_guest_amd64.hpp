#pragma once

#include <cstddef>
#include <cstdint>

namespace refuzz::worker::pseudo::syzos_guest_amd64 {

const std::uint8_t* Code() noexcept;
std::size_t Size() noexcept;

std::uint64_t GuestMainGpa() noexcept;
std::uint64_t DummyNullHandlerGpa() noexcept;
std::uint64_t UexitIrqHandlerGpa() noexcept;
std::uint64_t NestedVmExitHandlerIntelAsmGpa() noexcept;

} // namespace refuzz::worker::pseudo::syzos_guest_amd64

