#pragma once

// Ch32UartSubstrate — ISubstrate impl for "physical CH32V208RBT6 board + real
// UART + XiUOS RTOS".
//
// 与 XiuosUartSubstrate(QEMU)同角色但底座是物理板,机制不同 → 独立 ISubstrate
// impl(非 arch_map 条目;见 docs/plans/xiuos-ch32-bringup.md §2)。关键语义:
//   - StartVM   = flash 镜像(仅首次 boot)+ reset 板,让 worker 跑起来发 READY。
//   - RebootVM  = **只 reset,不 re-flash**。recovery 每个 wedge 都调 RebootVM
//                 (channel.cpp 只在首启调 StartVM)→ 镜像已在 flash,reset 即重跑;
//                 这样一次 campaign 的几十次 wedge-reboot 不会几十次烧 flash。
//   - DeployArtifacts = no-op(worker 编进 flash,无独立 deploy;镜像 QEMU 路径)。
//   - serial fd 由 backbone(serial transport)独占;console = NullConsoleSource,
//     DefaultConsoleEndpoint = kNone(与 QEMU 路径等效:串口字节流就是 wire 帧)。
//
// flash/reset 经配置的 host 命令(Phase B 用 wlink)。命令为空 = 跳过(no-op),
// 便于无硬件时 host 侧装配/解析验证(Q2)。

#include "refuzz/channel/result.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::channel::runtime {

class Ch32UartSubstrate final : public ISubstrate {
public:
    struct Config {
        std::string                serial_device;        // advertised; backbone opens it
        std::uint32_t              baud{115200};
        std::string                image_path;           // .bin to flash (optional)
        std::string                flash_command;        // "{image}" 占位 (optional)
        std::string                reset_command;         // (optional)
        std::chrono::milliseconds  command_timeout{std::chrono::seconds(60)};
        std::chrono::milliseconds  shutdown_grace{std::chrono::seconds(2)};
    };

    explicit Ch32UartSubstrate(Config cfg);
    ~Ch32UartSubstrate() override;

    Ch32UartSubstrate(const Ch32UartSubstrate&) = delete;
    Ch32UartSubstrate& operator=(const Ch32UartSubstrate&) = delete;

    // ───── ISubstrate (VM lifecycle) ─────
    Result<void> StartVM(std::uint32_t vm_index) override;
    void         StopVM(std::uint32_t vm_index) override;
    Result<void> RebootVM(std::uint32_t vm_index) override;
    bool         IsVMAlive(std::uint32_t vm_index) const override;
    Result<void> Close() override;

    // ───── ISubstrate (file/command) ─────
    // 物理板无远程 FS / shell(flash/reset 是本机命令,走 StartVM/RebootVM,不走这里)。
    Result<void> CopyFileTo(std::uint32_t vm_index,
                            const std::string& local_path,
                            const std::string& remote_path,
                            std::chrono::milliseconds timeout) override;
    Result<std::string> RunCommand(std::uint32_t vm_index,
                                   const std::string& cmd,
                                   std::chrono::milliseconds timeout) override;
    Result<void> DeployArtifacts(std::uint32_t vm_index,
                                 const DeployBundle& bundle) override;

    // ───── ISubstrate (worker lifecycle) ─────
    // XiUOS in-kernel worker 编进 flash,host 无 per-worker start/stop。全 Ok,
    // 靠 boot/reset 后的 READY 帧当 "worker alive" 信号(XiuosUartControlPlane 消费)。
    Result<void> StartAllWorkers(std::uint32_t vm_index) override;
    Result<void> StopAllWorkers(std::uint32_t vm_index) override;
    Result<void> StartWorker(std::uint32_t vm_index, std::uint32_t worker_id) override;
    Result<void> StopWorker(std::uint32_t vm_index, std::uint32_t worker_id) override;

    // ───── ISubstrate (endpoints + diagnosis) ─────
    evidence::ConsoleEndpoint DefaultConsoleEndpoint(std::uint32_t vm_index) const override;
    VendorHints               Hints(std::uint32_t vm_index) const override;
    std::string               Diagnose(std::uint32_t vm_index) const override;

    const Config& config() const noexcept { return config_; }

private:
    // 跑一条 host 命令(fork + "/bin/sh -c"),{image} 占位替换成 image_path,
    // 限时 command_timeout。空模板 = 立即 Ok(跳过)。
    Result<void> RunHostCommand(const std::string& cmd_template) const;

    Config            config_;
    std::atomic<bool> started_{false};
};

}  // namespace refuzz::channel::runtime
