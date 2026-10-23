#include "refuzz/channel/runtime/xiuos_uart_substrate.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace refuzz::channel::runtime {

namespace {

using refuzz::channel::Error;
using refuzz::channel::ErrorKind;
using refuzz::channel::Result;

bool FileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

}  // namespace

XiuosUartSubstrate::XiuosUartSubstrate(Config cfg)
    : config_(std::move(cfg)) {}

XiuosUartSubstrate::~XiuosUartSubstrate() {
    KillQemu();
}

Result<void> XiuosUartSubstrate::SpawnQemu() {
    if (config_.elf_path.empty()) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartSubstrate: elf_path must be non-empty"};
    }
    if (config_.serial_port == 0) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartSubstrate: serial_port must be non-zero"};
    }
    if (!FileExists(config_.elf_path)) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartSubstrate: ELF not found: " + config_.elf_path};
    }
    if (!config_.app_bin_path.empty() && !FileExists(config_.app_bin_path)) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartSubstrate: app bin not found: " + config_.app_bin_path};
    }
    if (qemu_pid_.load() > 0) {
        return Error{ErrorKind::kProtocol,
                     "XiuosUartSubstrate: VM already running"};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return Error{ErrorKind::kBoot,
                     std::string("XiuosUartSubstrate: fork(): ") +
                         std::strerror(errno)};
    }

    if (pid == 0) {
        // Child: detach stdio so QEMU's debug spew doesn't pollute test output.
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        const std::string serial_arg =
            "tcp:" + config_.serial_host + ":" +
            std::to_string(config_.serial_port) + ",server=on,wait=on";

        // Optional gdbstub: env XIUOS_QEMU_GDBSTUB=<port> enables
        // QEMU's `-gdb tcp::<port>` so a triage tool can attach after a
        // wedge fires and read HandleTrap saved_ra. Default off — no
        // overhead for normal runs.
        const char* gdb_port_env = std::getenv("XIUOS_QEMU_GDBSTUB");
        const std::string gdb_arg =
            (gdb_port_env && *gdb_port_env) ?
                (std::string("tcp::") + gdb_port_env) : std::string();
        // XIUOS_QEMU_GDB_WAIT=1 adds `-S` so QEMU halts at reset until gdb
        // connects and continues. Needed to debug NON-wedging programs
        // (e.g. heap-leak / latent-UAF probes that complete in ~100ms,
        // too fast to attach after the fact). Wedge triage doesn't need it
        // because the busy loop keeps QEMU alive.
        const char* gdb_wait_env = std::getenv("XIUOS_QEMU_GDB_WAIT");
        const bool gdb_wait = gdb_wait_env && gdb_wait_env[0] == '1';

        // Build argv dynamically: `-machine` is config-driven (virt | sifive_u),
        // `-m` and the second-image `-device loader` (separate-compile app.bin)
        // are optional. Defaults (machine="virt", empty mem/app_bin) reproduce the
        // original flat virt-rv32 invocation exactly.
        std::vector<std::string> args = {
            config_.qemu_bin,
            "-display", "none",
            "-machine", config_.machine,
            "-bios",    "none",
            "-monitor", "none",
        };
        // [app-surface 重定向 M4] Serial ordering = QEMU uart index. When a console
        // sink is configured, it takes uart0 (first -serial) and the wire TCP takes
        // uart1 (second) — so the U-mode worker drives uart1 while the kernel
        // console/banner/shell go to uart0. Empty console_endpoint keeps the wire on
        // uart0 (single serial) for the flat virt-rv32/ch32 in-kernel worker.
        if (!config_.console_endpoint.empty()) {
            args.push_back("-serial");
            args.push_back(config_.console_endpoint);   // uart0 = console sink
        }
        args.push_back("-serial");
        args.push_back(serial_arg);                     // uart0 or uart1 = wire (backbone)
        if (!config_.mem.empty()) {
            args.push_back("-m");
            args.push_back(config_.mem);
        }
        if (!gdb_arg.empty()) {
            args.push_back("-gdb");
            args.push_back(gdb_arg);
            if (gdb_wait) {
                args.push_back("-S");
            }
        }
        args.push_back("-kernel");
        args.push_back(config_.elf_path);
        if (!config_.app_bin_path.empty()) {
            args.push_back("-device");
            args.push_back("loader,file=" + config_.app_bin_path +
                           ",addr=" + config_.app_load_addr);
        }

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& a : args) {
            argv.push_back(const_cast<char*>(a.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(config_.qemu_bin.c_str(), argv.data());
        // exec failed; abort the child without running parent destructors.
        std::_Exit(127);
    }

    qemu_pid_.store(pid);
    return Result<void>::Ok();
}

void XiuosUartSubstrate::KillQemu() {
    const pid_t pid = qemu_pid_.exchange(-1);
    if (pid <= 0) return;

    ::kill(pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + config_.shutdown_grace;
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
}

Result<void> XiuosUartSubstrate::StartVM(std::uint32_t) {
    return SpawnQemu();
}

void XiuosUartSubstrate::StopVM(std::uint32_t) {
    KillQemu();
}

Result<void> XiuosUartSubstrate::RebootVM(std::uint32_t vm_index) {
    KillQemu();
    return StartVM(vm_index);
}

bool XiuosUartSubstrate::IsVMAlive(std::uint32_t) const {
    const pid_t pid = qemu_pid_.load();
    if (pid <= 0) return false;
    // Use waitpid(WNOHANG) so zombie children (QEMU exited but unreaped)
    // are not reported alive — and reap them on the spot, otherwise the
    // PID would leak until the destructor runs. kill(pid, 0) alone is not
    // sufficient: a zombie still satisfies it but the worker is gone, and
    // crash/hang bucketing + restart need the negative result here.
    int status = 0;
    const pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == 0) {
        return true;  // still running (not exited)
    }
    if (r == pid) {
        // Exited; we just reaped it.
        qemu_pid_.store(-1);
        return false;
    }
    // r == -1 (ECHILD: not our child / already reaped) — treat as gone.
    qemu_pid_.store(-1);
    return false;
}

Result<void> XiuosUartSubstrate::Close() {
    KillQemu();
    return Result<void>::Ok();
}

Result<void> XiuosUartSubstrate::CopyFileTo(std::uint32_t,
                                            const std::string&,
                                            const std::string&,
                                            std::chrono::milliseconds) {
    return Result<void>::Ok();
}

Result<std::string> XiuosUartSubstrate::RunCommand(std::uint32_t,
                                                   const std::string&,
                                                   std::chrono::milliseconds) {
    return Result<std::string>::Ok("");
}

Result<void> XiuosUartSubstrate::DeployArtifacts(std::uint32_t,
                                                 const DeployBundle&) {
    return Result<void>::Ok();
}

Result<void> XiuosUartSubstrate::StartAllWorkers(std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> XiuosUartSubstrate::StopAllWorkers(std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> XiuosUartSubstrate::StartWorker(std::uint32_t, std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> XiuosUartSubstrate::StopWorker(std::uint32_t, std::uint32_t) {
    return Result<void>::Ok();
}

evidence::ConsoleEndpoint
XiuosUartSubstrate::DefaultConsoleEndpoint(std::uint32_t) const {
    evidence::ConsoleEndpoint ep;
    ep.kind = evidence::ConsoleEndpoint::Kind::kTcpSocket;
    ep.path = config_.serial_host + ":" + std::to_string(config_.serial_port);
    return ep;
}

VendorHints XiuosUartSubstrate::Hints(std::uint32_t) const {
    VendorHints hints;
    hints.extra["xiuos_serial_host"] = config_.serial_host;
    hints.extra["xiuos_serial_port"] = std::to_string(config_.serial_port);
    return hints;
}

std::string XiuosUartSubstrate::Diagnose(std::uint32_t) const {
    const pid_t pid = qemu_pid_.load();
    std::string out = "XiuosUartSubstrate{";
    out += "qemu=" + config_.qemu_bin;
    out += ",machine=" + config_.machine;
    out += ",elf=" + config_.elf_path;
    if (!config_.app_bin_path.empty()) {
        out += ",app=" + config_.app_bin_path + "@" + config_.app_load_addr;
    }
    out += ",wire=" + config_.serial_host + ":" + std::to_string(config_.serial_port);
    if (!config_.console_endpoint.empty()) {
        out += ",console=" + config_.console_endpoint;  // uart0; wire above = uart1
    }
    out += ",pid=" + std::to_string(pid);
    out += ",alive=" + std::string(IsVMAlive(0) ? "true" : "false");
    out += "}";
    return out;
}

}  // namespace refuzz::channel::runtime
