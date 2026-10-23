#pragma once

// MockAssembler — 进程内 mock 后端的 IChannelAssembler（v3 Phase 8）
//
// 设计来源：docs/channel-redesign/v3/80_migration.md §9.1，header 对齐
//           docs/channel-redesign/v3/70_channel_assembly.md §2
//
// 角色：
//   Catalog 按 id="mock" 查到此 Assembler；build lambda 直接经
//   `AssembleAndBuild()` 返回 `std::unique_ptr<IChannel>`，避开 QEMU 子系统整条路径。
//
// Phase 8 mock 的实现策略与 QemuIvshmemLinuxAssembler 保持一致：
//   - `Assemble()` 只返回占位 ChannelComponents（mock 不需要 Substrate/CP/DP 等抽象
//     组件 —— MockChannel 自身就是一整块的 IChannel 实现）；
//   - 真实路径走 `AssembleAndBuild()`，在其中直接 `std::make_unique<MockChannel>(...)`；
//   - `ChannelBuildContext.backend_profile` 要求是 `MockBackendProfile`，否则
//     Assembler 返回 Err；mock 只读 `channel_cfg_.channel_id` / `channel_cfg_.n_workers`。
//
// 非目标：
//   - 后续若需要"可编程行为" mock（注入失败/延迟/cc::AbnormalCompletion），由 Phase 9
//     在 MockChannelConfig / MockAssembler 上新增 knob；当前 e2e/V5 指标只需要 echo 模式。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>

namespace refuzz::channel {

namespace cc = refuzz::core::channel_contract;


class IChannel;

class MockAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;
    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;

    Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

} // namespace refuzz::channel
