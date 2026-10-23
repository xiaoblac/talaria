#include "refuzz/channel/runtime/ch32_uart_substrate.hpp"

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>
#include <utility>

namespace refuzz::channel::runtime {

namespace {

using refuzz::channel::Error;
using refuzz::channel::ErrorKind;
using refuzz::channel::Result;

// 把模板里的所有 "{image}" 占位替换成 image。
std::string SubstituteImage(const std::string& tmpl, const std::string& image) {
    const std::string ph = "{image}";
    std::string out;
    out.reserve(tmpl.size() + image.size());
    std::size_t i = 0;
    while (i < tmpl.size()) {
        const std::size_t p = tmpl.find(ph, i);
        if (p == std::string::npos) {
            out.append(tmpl, i, std::string::npos);
            break;
        }
        out.append(tmpl, i, p - i);
        out.append(image);
        i = p + ph.size();
    }
    return out;
}

}  // namespace

Ch32UartSubstrate::Ch32UartSubstrate(Config cfg)
    : config_(std::move(cfg)) {}

Ch32UartSubstrate::~Ch32UartSubstrate() {
    started_.store(false);
}

Result<void> Ch32UartSubstrate::RunHostCommand(const std::string& cmd_template) const {
    if (cmd_template.empty()) {
        // 无命令配置(无硬件 / bench)→ 跳过,视作成功。让 host 侧装配/解析路径可跑通。
        return Result<void>::Ok();
    }
    const std::string cmd = SubstituteImage(cmd_template, config_.image_path);

    const pid_t pid = ::fork();
    if (pid < 0) {
        return Error{ErrorKind::kInfra,
                     std::string("Ch32UartSubstrate: fork(): ") + std::strerror(errno)};
    }
    if (pid == 0) {
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        ::_Exit(127);  // exec 失败
    }

    const auto deadline = std::chrono::steady_clock::now() + config_.command_timeout;
    for (;;) {
        int status = 0;
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                return Result<void>::Ok();
            }
            return Error{ErrorKind::kInfra,
                         "Ch32UartSubstrate: command failed (exit " +
                             std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) +
                             "): " + cmd};
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, nullptr, 0);
            return Error{ErrorKind::kTimeout,
                         "Ch32UartSubstrate: command timed out: " + cmd};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

Result<void> Ch32UartSubstrate::StartVM(std::uint32_t) {
    // 首次 boot:flash 镜像(把 worker 写进板 flash)→ reset 让它跑。recovery 不调
    // StartVM(调 RebootVM),所以 flash 只在这里发生一次。
    auto flash = RunHostCommand(config_.flash_command);
    if (!flash.ok()) {
        return flash;
    }
    // flash 后做一次 reset 给个确定的干净起点(wlink flash 通常已 reset+run;多一次
    // reset 幂等)。reset_command 为空则跳过。
    auto reset = RunHostCommand(config_.reset_command);
    if (!reset.ok()) {
        return reset;
    }
    started_.store(true);
    return Result<void>::Ok();
}

void Ch32UartSubstrate::StopVM(std::uint32_t) {
    started_.store(false);
}

Result<void> Ch32UartSubstrate::RebootVM(std::uint32_t) {
    // **只 reset,不 re-flash** —— recovery 路径每个 wedge 都到这里。
    auto reset = RunHostCommand(config_.reset_command);
    if (!reset.ok()) {
        return reset;
    }
    started_.store(true);
    return Result<void>::Ok();
}

bool Ch32UartSubstrate::IsVMAlive(std::uint32_t) const {
    // 物理板无 PID 可探;crash/wedge 检测由 health(WedgeRelaySensor)+ data-plane
    // per-program timeout 负责(对齐 snapshot 的 console/timeout 检测路线)。这里只反映
    // "已 StartVM 且未 StopVM" 的 started_ 状态。Phase B 可加探针在线检查作为兜底。
    return started_.load();
}

Result<void> Ch32UartSubstrate::Close() {
    started_.store(false);
    return Result<void>::Ok();
}

Result<void> Ch32UartSubstrate::CopyFileTo(std::uint32_t,
                                           const std::string&,
                                           const std::string&,
                                           std::chrono::milliseconds) {
    return Result<void>::Ok();
}

Result<std::string> Ch32UartSubstrate::RunCommand(std::uint32_t,
                                                  const std::string&,
                                                  std::chrono::milliseconds) {
    return Result<std::string>::Ok("");
}

Result<void> Ch32UartSubstrate::DeployArtifacts(std::uint32_t, const DeployBundle&) {
    // no-op:worker 编进 flash。boot 与 recovery 都会调到这里,故**必须**保持无副作用,
    // 否则每次 wedge-reboot 会重 deploy。flash 在 StartVM(仅首次)。
    return Result<void>::Ok();
}

Result<void> Ch32UartSubstrate::StartAllWorkers(std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> Ch32UartSubstrate::StopAllWorkers(std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> Ch32UartSubstrate::StartWorker(std::uint32_t, std::uint32_t) {
    return Result<void>::Ok();
}

Result<void> Ch32UartSubstrate::StopWorker(std::uint32_t, std::uint32_t) {
    return Result<void>::Ok();
}

evidence::ConsoleEndpoint
Ch32UartSubstrate::DefaultConsoleEndpoint(std::uint32_t) const {
    // 串口 fd 由 backbone 独占;无独立 console 源(NullConsoleSource)。
    evidence::ConsoleEndpoint ep;
    ep.kind = evidence::ConsoleEndpoint::Kind::kNone;
    return ep;
}

VendorHints Ch32UartSubstrate::Hints(std::uint32_t) const {
    VendorHints hints;
    hints.extra["ch32_serial_device"] = config_.serial_device;
    hints.extra["ch32_baud"]          = std::to_string(config_.baud);
    return hints;
}

std::string Ch32UartSubstrate::Diagnose(std::uint32_t) const {
    std::string out = "Ch32UartSubstrate{";
    out += "serial=" + config_.serial_device;
    out += ",baud=" + std::to_string(config_.baud);
    out += ",image=" + config_.image_path;
    out += ",flash=" + config_.flash_command;
    out += ",reset=" + config_.reset_command;
    out += ",started=" + std::string(started_.load() ? "true" : "false");
    out += "}";
    return out;
}

}  // namespace refuzz::channel::runtime
