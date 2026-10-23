#pragma once

// QemuIvshmemCustomHealthAssembler — Phase H 验收门
//
// 与 QemuIvshmemLinuxAssembler 完全相同的后端，仅在 HealthMonitor 上额外挂载
// AcceptanceTapSensor。证明"换装配表不需要改 Channel 核心"。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>

namespace refuzz::channel {
class IChannel;
}

namespace refuzz::channel::factory {

class QemuIvshmemCustomHealthAssembler final : public IChannelAssembler {
public:
    std::string_view Id() const override { return "qemu_ivshmem_custom_health_linux"; }

    Result<ChannelComponents>        Assemble(const ChannelBuildContext& ctx) override;
    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(const ChannelBuildContext& ctx);
};

} // namespace refuzz::channel::factory
