// QemuIvshmemCustomHealthAssembler 实现（Phase H 验收门）
//
// 复用 QemuIvshmemLinuxAssembler 的完整装配结果，追加 AcceptanceTapSensor，
// 然后经 ChannelBuilder::Build 产出 Channel 实例。
//
// 被允许修改/新增的文件清单：docs/channel-redesign/v3.5/170_phase_H_second_assembler.md §H.6

#include "refuzz/channel/factory/qemu_ivshmem_custom_health_assembler.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_assembler.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/health/acceptance_tap_sensor.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/channel_impl.hpp"  // Channel 完整类型（unique_ptr 析构 + 转换需要）

#include <memory>

namespace refuzz::channel::factory {

Result<ChannelComponents>
QemuIvshmemCustomHealthAssembler::Assemble(const ChannelBuildContext& ctx)
{
    auto comps_r = QemuIvshmemLinuxAssembler{}.Assemble(ctx);
    if (!comps_r.ok()) {
        return Error{comps_r.error().kind, comps_r.error().message};
    }

    // [v4.0 Phase J] AddSensor 已上提至 IHealthMonitor 接口，Assembler 不再
    // 感知具体 HealthMonitor 类型。NoopHealthMonitor 在此路径下 drop 传入的 sensor。
    auto& comps = comps_r.value();
    comps.health->AddSensor(std::make_unique<health::AcceptanceTapSensor>());

    return comps_r;
}

Result<std::unique_ptr<IChannel>>
QemuIvshmemCustomHealthAssembler::AssembleAndBuild(const ChannelBuildContext& ctx)
{
    auto comps_r = QemuIvshmemCustomHealthAssembler{}.Assemble(ctx);
    if (!comps_r.ok()) {
        return Error{comps_r.error().kind, comps_r.error().message};
    }
    auto built_r = ChannelBuilder::Build(std::move(comps_r.value()));
    if (!built_r.ok()) {
        return Error{built_r.error().kind, built_r.error().message};
    }
    return Result<std::unique_ptr<IChannel>>::Ok(
        std::unique_ptr<IChannel>(std::move(built_r.value())));
}

} // namespace refuzz::channel::factory
