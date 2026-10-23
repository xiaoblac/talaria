#pragma once

// qemu_ivshmem_linux_profile.hpp — QemuIvshmemLinuxProfile
//
// "QEMU (substrate) + ivshmem (transport) + Linux guest" 组合后端的专属配置包。
// 实现 IChannelBackendProfile；Assembler 内部 dynamic_cast 到本类型读各字段。
//
// 约束：只承载**后端专属**字段。中性字段（channel_id / n_workers / loop_interval /
//       health_check_interval / input_queue_capacity / pre_reboot_drain /
//       wait_ready_timeout / deploy_bundle）一律由 refuzz::channel::ChannelConfig 承载。

#include "refuzz/channel/factory/channel_backend_profile.hpp"

#include "refuzz/channel/config/ivshmem_channel_config.hpp"   // transport::TransportConfig
#include "refuzz/channel/health/health_monitor.hpp"            // health::HealthMonitorConfig
#include "refuzz/channel/infra/shm_infra.hpp"                  // infra::InfraConfig
#include "refuzz/channel/recovery/recovery.hpp"                // recovery::RecoveryConfig
#include "refuzz/channel/runtime/runtime.hpp"                  // runtime::RuntimeConfig
#include "worker/config/worker_config.hpp"                     // worker::WorkerConfig

#include <string_view>

namespace refuzz::channel::factory {

struct QemuIvshmemLinuxProfile : public IChannelBackendProfile {
    infra::InfraConfig                  infra;
    runtime::RuntimeConfig              runtime;
    worker::WorkerConfig                worker;
    transport::TransportConfig          transport;       // ivshmem CP/DP 共享配置
    health::HealthMonitorConfig         health_monitor;
    recovery::RecoveryConfig            recovery_config;

    std::string_view BackendId() const noexcept override {
        return "qemu_ivshmem_linux";
    }
};

} // namespace refuzz::channel::factory
