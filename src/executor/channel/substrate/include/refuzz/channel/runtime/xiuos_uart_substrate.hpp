#pragma once

// XiuosUartSubstrate — ISubstrate impl for "QEMU + UART + XiUOS RTOS guest".
//
// Phase 2 §B v1. Mirrors the role of `Runtime` in the ivshmem-Linux path but
// is fundamentally lighter:
//   - no SSH (XiUOS has no shell / no remote command surface)
//   - no QMP (no monitor needed for v1)
//   - no shared memory / ivshmem (Backbone owns the TCP serial socket)
//   - no per-worker lifecycle (the XiUOS in-kernel worker task is part of
//     the kernel image and starts as soon as the scheduler runs)
//
// As a result most ISubstrate methods are no-op-and-return-Ok. The two real
// responsibilities are: (1) own the QEMU subprocess lifecycle (StartVM /
// StopVM / IsVMAlive / Diagnose), and (2) advertise the TCP serial endpoint
// via DefaultConsoleEndpoint so that NullConsoleSource (or a future
// XiUOS-specific console source that captures non-frame bytes) can attach.

#include "refuzz/channel/result.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

#include <sys/types.h>  // pid_t

namespace refuzz::channel::runtime {

class XiuosUartSubstrate final : public ISubstrate {
public:
    struct Config {
        std::string                qemu_bin{"qemu-system-riscv32"};
        std::string                elf_path;             // worker kernel ELF; required
        std::string                machine{"virt"};      // QEMU `-machine` (virt | sifive_u)
        // QEMU `-m`. Empty (default) → omit (-machine virt sizes itself). The
        // sifive_u path sets "256M" to match the proven manual recipe.
        std::string                mem;
        // Optional second-image loader (separate-compile U-mode app .bin). When
        // non-empty, SpawnQemu appends `-device loader,file=<app>,addr=<addr>`.
        std::string                app_bin_path;
        std::string                app_load_addr{"0x80101000"};
        std::string                serial_host{"127.0.0.1"};
        std::uint16_t              serial_port{0};       // required, non-zero
        // [app-surface 重定向 M4] Optional uart0 console sink. When non-empty,
        // SpawnQemu emits `-serial <console_endpoint>` FIRST (= uart0) and the wire
        // TCP serial SECOND (= uart1), so the U-mode worker's wire lives on uart1
        // while the kernel console/banner/shell stay on uart0. Any QEMU chardev spec
        // works: "null", "file:/path", "tcp:host:port,server=on,wait=off", ...
        // Empty (default) = single serial (wire on uart0) — the flat virt-rv32/ch32
        // layout where the in-kernel worker owns uart0.
        std::string                console_endpoint;
        std::chrono::milliseconds  shutdown_grace{std::chrono::seconds(2)};
    };

    explicit XiuosUartSubstrate(Config cfg);
    ~XiuosUartSubstrate() override;

    XiuosUartSubstrate(const XiuosUartSubstrate&) = delete;
    XiuosUartSubstrate& operator=(const XiuosUartSubstrate&) = delete;

    // ───── ISubstrate (VM lifecycle) ─────
    Result<void> StartVM(std::uint32_t vm_index) override;
    void         StopVM(std::uint32_t vm_index) override;
    Result<void> RebootVM(std::uint32_t vm_index) override;
    bool         IsVMAlive(std::uint32_t vm_index) const override;
    Result<void> Close() override;

    // ───── ISubstrate (file/command) ─────
    // No remote FS / shell on XiUOS; both methods return success without
    // doing anything so generic Channel boot paths that exercise them still
    // pass through cleanly.
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
    // XiUOS in-kernel worker is bundled into the image and started by the
    // RTOS scheduler — host has no per-worker start/stop control. All four
    // methods return Ok and rely on the boot-time READY frame as the
    // "worker is alive" signal (consumed by XiuosUartControlPlane).
    Result<void> StartAllWorkers(std::uint32_t vm_index) override;
    Result<void> StopAllWorkers(std::uint32_t vm_index) override;
    Result<void> StartWorker(std::uint32_t vm_index, std::uint32_t worker_id) override;
    Result<void> StopWorker(std::uint32_t vm_index, std::uint32_t worker_id) override;

    // ───── ISubstrate (endpoints + diagnosis) ─────
    evidence::ConsoleEndpoint DefaultConsoleEndpoint(std::uint32_t vm_index) const override;
    VendorHints               Hints(std::uint32_t vm_index) const override;
    std::string               Diagnose(std::uint32_t vm_index) const override;

    // ───── XiUOS-specific accessors (for tests / assembler glue) ─────
    pid_t       qemu_pid() const noexcept { return qemu_pid_.load(); }
    const Config& config()  const noexcept { return config_; }

private:
    Result<void> SpawnQemu();
    void         KillQemu();

    Config                       config_;
    // mutable: IsVMAlive is const but does waitpid(WNOHANG)-based zombie
    // reaping which has to clear qemu_pid_ on detection. The atomic gives
    // thread-safe access; mutable lets the const-method publish the cleared
    // value to subsequent observers.
    mutable std::atomic<pid_t>   qemu_pid_{-1};
};

}  // namespace refuzz::channel::runtime
