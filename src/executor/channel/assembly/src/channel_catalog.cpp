// ChannelCatalog 内置后端注册
//
// 每个 Register 对应一个"合规后端组合"的 id；build lambda 负责把 BuildContext
// 转成 unique_ptr<IChannel>。新增后端 = 新增一个 Assembler + 在此加一行 Register。

#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/channel/factory/mock_assembler.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_assembler.hpp"
#include "refuzz/channel/factory/snapshot_assembler.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_custom_health_assembler.hpp"
#include "refuzz/channel/factory/qemu_uart_xiuos_assembler.hpp"
#include "refuzz/channel/factory/ch32_uart_xiuos_assembler.hpp"
#include "refuzz/channel/factory/sifive_uart_xiuos_assembler.hpp"

namespace refuzz::channel {

void RegisterBuiltinChannels(ChannelCatalog& catalog)
{
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kQemuIvshmemLinux),
            .display_name = "QEMU + ivshmem + Linux",
            .description  = "生产主路径：QEMU system-x86_64 + ivshmem 数据/控制面 + Linux guest",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = QemuIvshmemLinuxAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kQemuIvshmemLinux),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            // backend_profile 形态校验由 Assembler 内部 dynamic_cast 负责；
            // 此处只做空指针快速拦截。
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect QemuIvshmemLinuxProfile)";
                return false;
            }
            return true;
        },
    });

    // snapshot 模式：与 qemu_ivshmem_linux 同底座(复用 QemuIvshmemLinuxProfile),
    // data plane 包 SnapshotDataPlane(savevm/loadvm per program)+ NoopHealth。
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kQemuIvshmemSnapshotLinux),
            .display_name = "QEMU + ivshmem + Linux (snapshot)",
            .description  = "snapshot 执行模式：每 program savevm/loadvm 还原 S0；复用 qemu_ivshmem_linux 底座 + SnapshotDataPlane",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = SnapshotAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kQemuIvshmemSnapshotLinux),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect QemuIvshmemLinuxProfile)";
                return false;
            }
            return true;
        },
    });

    // Phase 8：进程内 mock 后端。不依赖 QEMU / ivshmem / SSH，CI 和 V5 验收路径。
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kMock),
            .display_name = "Mock (in-process)",
            .description  = "进程内 mock Channel：Submit 同步 echo 成 cc::Completion，无 VM/IO 依赖，供 CI 与 V5 冒烟验收使用",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = MockAssembler{}.AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kMock),
                    built.error().message));
            }
            return std::move(built.value());
        },
        // mock 的 profile 形态校验由 Assembler 内部 dynamic_cast 完成；
        // 这里显式空 lambda（&& 显式写出 validate 字段）以满足
        // -Wmissing-designated-field-initializers。
        .validate = [](const ChannelBuildContext&, std::string&) -> bool {
            return true;
        },
    });

    // Phase H：qemu_ivshmem_linux + AcceptanceTapSensor 验收门
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kQemuIvshmemCustomHealthLinux),
            .display_name = "QEMU + ivshmem + Linux + custom health",
            .description  = "Phase H 验收：与 qemu_ivshmem_linux 相同后端，额外挂载 AcceptanceTapSensor",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = factory::QemuIvshmemCustomHealthAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kQemuIvshmemCustomHealthLinux),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect QemuIvshmemLinuxProfile)";
                return false;
            }
            return true;
        },
    });

    // Phase 2 §B v1：QEMU virt-rv32 + UART + XiUOS RTOS guest
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kQemuUartXiuos),
            .display_name = "QEMU virt-rv32 + UART + XiUOS",
            .description  = "XiUOS in-kernel reFuzz worker over QEMU TCP serial (Phase 2 §B v1)",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = QemuUartXiuosAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kQemuUartXiuos),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect XiuosUartProfile)";
                return false;
            }
            return true;
        },
    });

    // Phase Q2：物理 CH32V208RBT6 板 + 真串口 + XiUOS RTOS guest
    // 镜像 qemu_uart_xiuos：换 Ch32UartSubstrate(wlink flash/reset + 真串口)+ serial
    // backbone transport，CP/DP/console/health/recovery 复用 XiUOS 同件（全栈复用）。
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kCh32UartXiuos),
            .display_name = "CH32V208RBT6 board + UART + XiUOS",
            .description  = "XiUOS in-kernel reFuzz worker over real serial + wlink flash/reset (physical board)",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = Ch32UartXiuosAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kCh32UartXiuos),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect Ch32UartProfile)";
                return false;
            }
            return true;
        },
    });

    // App-surface 面:rv64 k210-emulator 跑 stock `qemu-system-riscv64 -machine sifive_u`,
    // 分离构建 kernel.elf + 用户态 app.bin。复用 XiuosUartSubstrate(同 fork-QEMU + TCP
    // serial),仅 machine/qemu_bin/二段 ELF 不同;CP/DP/health/recovery 全栈复用。
    catalog.Register({
        .meta = {
            .id           = std::string(channel_backend_id::kQemuUartSifiveU),
            .display_name = "QEMU sifive_u (rv64) + UART + XiUOS (app-surface)",
            .description  = "XiUOS 分离构建 kernel.elf + U-mode app.bin,经 ecall 边界跑 app-facing fuzz",
        },
        .build = [](const ChannelBuildContext& ctx)
            -> refuzz::core::Result<std::unique_ptr<IChannel>> {
            auto built = SifiveUartXiuosAssembler::AssembleAndBuild(ctx);
            if (!built.ok()) {
                return std::unexpected(refuzz::core::ComponentError::Config(
                    std::string(channel_backend_id::kQemuUartSifiveU),
                    built.error().message));
            }
            return std::move(built.value());
        },
        .validate = [](const ChannelBuildContext& ctx, std::string& err) -> bool {
            if (ctx.backend_profile == nullptr) {
                err = "ChannelBuildContext.backend_profile is null (expect SifiveUartXiuosProfile)";
                return false;
            }
            return true;
        },
    });

    // TODO(Phase 8+)：qemu_vsock_linux / kvm_vsock_linux / local_process
    // 会陆续在这里注册，每个对应一个 IChannelAssembler 实现。
}

} // namespace refuzz::channel
