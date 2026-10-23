#pragma once

// ch32_uart_profile.hpp — Ch32UartProfile
//
// 物理 CH32V208RBT6 板 backend("ch32_uart_xiuos")的专属配置包。与 XiuosUartProfile
// 同构(都是 XiUOS guest + 同一 UART wire 协议 + 单 worker),**差别只在 transport 与
// 底座**:QEMU 走 TCP serial + spawn 进程;物理板走真实串口 /dev/ttyACM* + wlink
// flash/reset。control/data plane、wire codec、health/recovery 全部复用 XiUOS 同件。
//
// 字段约束:只承载**后端专属**字段。中性字段(channel_id / n_workers /
// wait_ready_timeout / ...)一律走 ChannelConfig。XiUOS 在 v1 是单 worker。

#include "refuzz/channel/factory/channel_backend_profile.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace refuzz::channel::factory {

struct Ch32UartProfile : public IChannelBackendProfile {
    // ───── 真实串口端点(host 打开这个字符设备;backbone 持有 fd)─────
    std::string                serial_device;        // required, e.g. "/dev/ttyACM0"
    std::uint32_t              baud{115200};

    // ───── flash / reset(host 端 shell 命令;Phase B 用 wlink)─────
    // flash_command 的 "{image}" 占位会替换成 image_path。flash 在 StartVM(仅首次
    // boot)跑;reset 在 RebootVM(recovery 每次 wedge)跑 —— 故 reboot **绝不 re-flash**。
    // 三者皆可空(空=跳过,便于无硬件 host 侧编译/解析验证)。
    std::string                image_path;           // .bin to flash (optional)
    std::string                flash_command;        // e.g. "wlink flash {image}" (optional)
    std::string                reset_command;        // e.g. "wlink reset" (optional)
    std::chrono::milliseconds  command_timeout{std::chrono::seconds(60)};

    // ───── Backbone tunables ─────
    std::chrono::milliseconds  connect_timeout{std::chrono::seconds(10)};
    std::chrono::milliseconds  frame_timeout{std::chrono::seconds(10)};
    std::size_t                max_queued_frames{128};

    // ───── ControlPlane / DataPlane tunables ─────
    std::chrono::milliseconds  heartbeat_timeout{std::chrono::milliseconds(500)};
    std::chrono::milliseconds  poll_slice{std::chrono::milliseconds(10)};
    // Per-program wall-clock budget used by XiuosUartDataPlane::Poll() to convert
    // "PROGRAM never returned RESULT" into a timeout + wedge latch. 真实串口 + flash
    // reset 比 QEMU 慢,通常配得比 QEMU 大(见 docs/plans/xiuos-ch32-bringup.md Phase B)。
    std::chrono::milliseconds  program_timeout{std::chrono::milliseconds(15000)};

    // ───── Substrate tunables ─────
    std::chrono::milliseconds  shutdown_grace{std::chrono::seconds(2)};

    std::string_view BackendId() const noexcept override {
        return "ch32_uart_xiuos";
    }
};

}  // namespace refuzz::channel::factory
