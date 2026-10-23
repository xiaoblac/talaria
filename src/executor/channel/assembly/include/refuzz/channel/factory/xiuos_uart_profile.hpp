#pragma once

// xiuos_uart_profile.hpp — XiuosUartProfile
//
// "QEMU virt-rv32 (substrate) + UART binary frames (transport) + XiUOS RTOS
// (guest)" 组合后端的专属配置包。与 QemuIvshmemLinuxProfile 同构地实现
// IChannelBackendProfile；QemuUartXiuosAssembler 内部 dynamic_cast 到本类型
// 读各字段。
//
// 字段约束：只承载**后端专属**字段。中性字段（channel_id / n_workers /
// loop_interval / wait_ready_timeout / ...）一律走 ChannelConfig。XiUOS 在
// v1 是单 worker，n_workers 必须为 0 或 1（Assembler 强制归一到 1）。

#include "refuzz/channel/factory/channel_backend_profile.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace refuzz::channel::factory {

struct XiuosUartProfile : public IChannelBackendProfile {
    // ───── QEMU / ELF ─────
    std::string                qemu_bin{"qemu-system-riscv32"};
    std::string                elf_path;             // required, non-empty

    // ───── TCP serial endpoint (host side connects to this; QEMU listens) ─────
    std::string                serial_host{"127.0.0.1"};
    std::uint16_t              serial_port{0};       // required, non-zero

    // ───── Backbone tunables ─────
    std::chrono::milliseconds  connect_timeout{std::chrono::seconds(10)};
    std::chrono::milliseconds  frame_timeout{std::chrono::seconds(10)};
    std::size_t                max_queued_frames{128};

    // ───── ControlPlane / DataPlane tunables ─────
    std::chrono::milliseconds  heartbeat_timeout{std::chrono::milliseconds(500)};
    std::chrono::milliseconds  poll_slice{std::chrono::milliseconds(10)};
    // Per-program wall-clock budget used by XiuosUartDataPlane::Poll() to
    // convert "PROGRAM never returned RESULT" into a timeout + wedge latch.
    // Defaults to the sample fuzzer.exec_timeout_ms value; config may override
    // it independently for slow boards.
    std::chrono::milliseconds  program_timeout{std::chrono::milliseconds(15000)};

    // ───── Substrate tunables ─────
    std::chrono::milliseconds  shutdown_grace{std::chrono::seconds(2)};

    std::string_view BackendId() const noexcept override {
        return "qemu_uart_xiuos";
    }
};

}  // namespace refuzz::channel::factory
