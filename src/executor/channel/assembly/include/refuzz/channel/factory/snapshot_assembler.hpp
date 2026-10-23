#pragma once

// SnapshotAssembler — "qemu_ivshmem_snapshot_linux" 后端的组件装配器。
//
// 与 QemuIvshmemLinuxAssembler 同底座(复用 QemuIvshmemLinuxProfile + Runtime +
// IvshmemControlPlane + IvshmemDataPlane + 同样的 evidence)，三处不同:
//   - Runtime 强制 snapshot_fuzzing=true(qcow2 overlay + ivshmem-plain master=on
//     + 去 -snapshot);
//   - data plane 把 IvshmemDataPlane 包进 SnapshotDataPlane(每 program savevm/
//     loadvm 周期 + 全局 1-in-flight);QMP endpoint 用捕获 Runtime* 的 lazy provider;
//   - health 用 NoopHealthMonitor(心跳会在 savevm 暂停期误判 worker dead)。
// 其余(Channel / FuzzerLoop / corpus / crash / telemetry)原样复用。
//
// 设计来源: docs/plans/snapshot-session-integration.md。

#include "refuzz/channel/factory/channel_assembler.hpp"
#include "refuzz/channel/result.hpp"

#include <memory>
#include <string_view>

namespace refuzz::channel {

class IChannel;  // 前向

class SnapshotAssembler : public IChannelAssembler {
public:
    std::string_view Id() const override;
    Result<ChannelComponents> Assemble(const ChannelBuildContext& ctx) override;
    static Result<std::unique_ptr<IChannel>> AssembleAndBuild(
        const ChannelBuildContext& ctx);
};

} // namespace refuzz::channel
