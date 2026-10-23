#pragma once

// ivshmem_channel_config.hpp — ivshmem/QEMU 后端 CP/DP 的共享配置块
//
// 语义：
//   本结构体承担 ivshmem CP/DP 的共享配置（shm_infra 指针 / doorbell 路径 /
//   poll 间隔 / wait_ready_poll_us）。n_workers / shm_infra 等字段两个 plane
//   共享，因此不拆分为 IvshmemControlPlaneConfig + IvshmemDataPlaneConfig。
//   Channel::Boot 在构造 CP/DP 时分别抽出各自关心的字段。
//
// 命名空间 `refuzz::channel::transport` 与类型名 `TransportConfig` 出于历史原因保留；
// 新后端配置请走 factory::IChannelBackendProfile 子类，不要在这里加字段。

#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::channel::infra { class ShmInfra; }

namespace refuzz::channel::transport {

// ── TransportConfig ─────────────────────────────────────────────
// 字段映射（Channel::Boot 分发给 CP/DP 构造参数）：
//   shm_infra              → CP/DP 构造时的 ShmInfra*
//   n_workers              → CP/DP 的 n_workers（由 ShmInfra 推断，仅供校验）
//   use_doorbell / path    → IvshmemDataPlaneOptions
//   poll_sleep_us          → IvshmemDataPlaneOptions
//   wait_ready_poll_us     → control::SessionTiming
//
// wait_ready_timeout 由 ChannelConfig 注入（Assembler 换算单位后填 control::SessionTiming）。
struct TransportConfig {
    refuzz::channel::infra::ShmInfra* shm_infra = nullptr;
    uint32_t    n_workers = 1;
    bool        use_doorbell = false;
    std::string doorbell_socket_path;
    std::chrono::microseconds poll_sleep_us{100};
    std::chrono::microseconds wait_ready_poll_us{1'000};
};

} // namespace refuzz::channel::transport
