#pragma once

// ChannelCatalog — 按 backend id 查表装配 Channel（v3 Phase 7 落地）
//
// 设计来源：docs/channel-redesign/v3/70_channel_assembly.md §3
//
// 角色：
//   orchestrator 不再直接 `new QemuChannel(cfg)` 或调 `ChannelFactory::Create(cfg)`。
//   所有"合规后端组合"按字符串 id 注册进一个 TypedCatalog；Orchestrator 凭 id 查表 Build。
//
// 本 Phase 的 Product 是 `std::unique_ptr<IChannel>`：与 Orchestrator 实际消费形态一致，
// 不牵扯 Channel 成员抽象化（那是 Phase 8+ 的工作）。
//
// 目前注册的 id 只有 "qemu_ivshmem_linux"（主路径），实现通过 QemuIvshmemLinuxAssembler
// 转接到已有的 ChannelFactory::Create / Channel 构造器；Phase 8 起陆续加入其他后端组合
// （qemu_vsock_linux / kvm_vsock_linux / local_process / mock）。

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/factory/channel_assembler.hpp"

#include <memory>

namespace refuzz::channel {

namespace cc = refuzz::core::channel_contract;


// Traits 形状遵循现有 TypedCatalog<Traits> 约定（见 core/catalog/typed_catalog.hpp）：
//   - Product      = IChannel（接口），Catalog 产出 unique_ptr<IChannel>
//   - BuildContext = ChannelBuildContext（两段式：ChannelConfig + IChannelBackendProfile）
struct ChannelCatalogTraits {
    using Product      = IChannel;
    using BuildContext = ChannelBuildContext;
};

using ChannelCatalog = refuzz::catalog::TypedCatalog<ChannelCatalogTraits>;

// 向 catalog 注册内置 channel 后端组合。
// 现阶段仅注册 "qemu_ivshmem_linux"；新增后端 = 在此追加一行 Register。
void RegisterBuiltinChannels(ChannelCatalog& catalog);

// 已注册的 backend id 常量，供 orchestrator / 测试 / profile 引用，
// 避免 magic string 散落各处。
namespace channel_backend_id {
inline constexpr std::string_view kQemuIvshmemLinux = "qemu_ivshmem_linux";
// Phase 8：进程内 mock 后端 —— 不启动 VM、不开 Unix socket，纯内存 echo。
// 对齐 docs/channel-redesign/v3/00_overview.md §0.3 指标 V5「进程内 mock 跑 e2e」。
inline constexpr std::string_view kMock             = "mock";
// Phase H：验收门 — 与 qemu_ivshmem_linux 相同后端 + AcceptanceTapSensor
inline constexpr std::string_view kQemuIvshmemCustomHealthLinux = "qemu_ivshmem_custom_health_linux";
// Phase 2 §B v1：QEMU virt-rv32 + UART binary frames + XiUOS RTOS guest
// （单 worker、无 ivshmem / 无 SSH，详见 QemuUartXiuosAssembler）
inline constexpr std::string_view kQemuUartXiuos = "qemu_uart_xiuos";
// 物理 CH32V208RBT6 板:同 XiUOS guest + 同 UART wire 协议,但 transport = 真串口
// (/dev/ttyACM*)+ wlink flash/reset(Ch32UartXiuosAssembler 镜像 qemu_uart_xiuos)。
inline constexpr std::string_view kCh32UartXiuos = "ch32_uart_xiuos";
// App-surface 面:rv64 k210-emulator 跑 stock `qemu-system-riscv64 -machine sifive_u`,
// 分离构建(SEPARATE_COMPILE)kernel.elf + 用户态 app.bin(经 `-device loader` 载入
// USERSPACE 地址)。复用 XiuosUartSubstrate(同 fork-QEMU + TCP serial 机制),仅
// machine/qemu_bin/二段 ELF 不同。详见 docs/plans/xiuos-app-surface-fuzz-phase2.md。
inline constexpr std::string_view kQemuUartSifiveU = "qemu_uart_sifive_u";
// snapshot 模式：与 qemu_ivshmem_linux 同底座(复用 QemuIvshmemLinuxProfile),
// 但 data plane 包一层 SnapshotDataPlane(savevm/loadvm per program)+ NoopHealth。
inline constexpr std::string_view kQemuIvshmemSnapshotLinux = "qemu_ivshmem_snapshot_linux";
} // namespace channel_backend_id

// 后端能力声明：哪些 backend 提供 snapshot 执行模式。selector(Resolver)按
// "模式 → 能力"转译时查这里,而不是把某个 backend id 写死进 frontend/resolver。
// 新增支持 snapshot 的 backend = 在这里加一行 + 在对应 profile 设其 snapshot 默认;
// 选择链路其余部分零改动。理想终态是 catalog 条目自带 capability 元数据,这个
// 自由函数是其轻量先行版。
inline bool ChannelBackendSupportsSnapshot(std::string_view backend_id) noexcept
{
    return backend_id == channel_backend_id::kQemuIvshmemSnapshotLinux;
}

} // namespace refuzz::channel
