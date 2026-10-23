// MockAssembler 实现（v3.5 Phase G：组件级 mock 装配）
//
// Phase G 后不再使用 MockChannel 整块实现；改为装配 Mock 组件经 ChannelBuilder::Build
// 产出真实 Channel 实例。MockChannel 已退役。

#include "refuzz/channel/factory/mock_assembler.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"
#include "refuzz/channel/health/noop_health_monitor.hpp"
#include "refuzz/channel/recovery/noop_recovery.hpp"
#include "refuzz/channel/channel_impl.hpp"  // Channel complete type for unique_ptr dtor
#include "refuzz/proto_wire/ivshmem_protocol.h"  // MAX_INPUT_SIZE

#include <string>

namespace refuzz::channel {

std::string_view MockAssembler::Id() const
{
    return "mock";
}

Result<ChannelComponents> MockAssembler::Assemble(const ChannelBuildContext& ctx)
{
    const uint32_t n = ctx.channel_cfg.n_workers == 0 ? 1u : ctx.channel_cfg.n_workers;

    ChannelComponents out;
    out.shm      = nullptr;  // mock 不需要 ivshmem backbone
    out.substrate = std::make_unique<factory::MockSubstrate>();
    out.control   = std::make_unique<factory::MockControlPlane>(n);
    out.data      = std::make_unique<factory::MockDataPlane>(n);
    out.console   = std::make_unique<factory::NullConsoleSource>();
    out.steps     = nullptr;  // mock 无 step-event ring
    out.health    = std::make_unique<health::NoopHealthMonitor>();
    out.recovery  = std::make_unique<recovery::NoopRecovery>();

    out.channel_cfg                  = ctx.channel_cfg;
    out.channel_cfg.backend_id       = "mock";
    out.channel_cfg.n_workers        = n;
    // shm == nullptr; Channel::Submit needs a wire-level payload bound from
    // the neutral config to avoid dereferencing the null shm_. Match what
    // the ivshmem path effectively uses (MAX_INPUT_SIZE = 4 MiB).
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(MAX_INPUT_SIZE);
    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>> MockAssembler::AssembleAndBuild(
    const ChannelBuildContext& ctx)
{
    auto comps_r = Assemble(ctx);
    if (!comps_r.ok()) {
        return Error{comps_r.error().kind, comps_r.error().message};
    }
    auto built_r = ChannelBuilder::Build(std::move(comps_r.value()));
    if (!built_r.ok()) {
        return Error{built_r.error().kind, built_r.error().message};
    }
    return Result<std::unique_ptr<IChannel>>::Ok(std::move(built_r.value()));
}

} // namespace refuzz::channel
