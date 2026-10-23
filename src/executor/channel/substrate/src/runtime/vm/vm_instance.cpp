// vm_instance.cpp — SubstrateInstanceOps 函数表填充（QEMU/SSH 底座）
//
// MakeVmInstanceOps 返回一个 SubstrateInstanceOps，
// 其中每个函数通过共享 VmInstanceState 结构捕获内部状态。
// RuntimeInstance 只消费该函数表，不直接引用 Process/SSH 类型。
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.3 §4

#include "vm_instance.hpp"
#include "arch_map.hpp"
#include "qemu_args.hpp"

#include "util/process.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

namespace refuzz::channel::runtime::substrate::vm {

namespace {

// ── 内部辅助 ──────────────────────────────────────────────────

static bool FileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

static bool MkdirP(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0) return true;
    return ::mkdir(path.c_str(), 0755) == 0;
}

static bool ResetSerialLogFile(const std::string& path, std::string* error_message)
{
    if (path.empty()) return true;

    std::error_code ec;
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec) {
            if (error_message) {
                *error_message = "failed to create serial log directory: " +
                                 p.parent_path().string() + " (" + ec.message() + ")";
            }
            return false;
        }
    }

    std::ofstream out(path, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        if (error_message) {
            *error_message = "failed to open serial log file for truncate: " + path;
        }
        return false;
    }
    return true;
}

// ── 共享实例状态（由所有 lambda 通过 shared_ptr 捕获）─────────

struct VmInstanceState {
    RuntimeInstanceConfig                   cfg;
    int                                     ssh_port  = 0;
    int                                     mon_port  = 0;
    bool                                    ssh_port_reserved = false;
    bool                                    mon_port_reserved = false;
    std::unique_ptr<refuzz::vm::util::Process> qemu_process;
    std::unique_ptr<refuzz::vm::util::Process> ssh_master;

    // [v3.G] QEMU 合并 stdout+stderr 落盘:
    //   路径 = <workdir>/qemu.log;由 output_callback 实时 append。
    //   诊断用:WaitForSSH 在发现 QEMU 已退出时把最后一段读进 error message。
    std::mutex    qemu_log_mtx;
    std::string   qemu_log_path;
    std::ofstream qemu_log_stream;
};

static std::mutex& ReservedPortMutex()
{
    static std::mutex m;
    return m;
}

static std::set<int>& ReservedPorts()
{
    static std::set<int> ports;
    return ports;
}

static int ReserveUnusedPort(int start, int end)
{
    namespace proc = refuzz::vm::util;

    std::lock_guard<std::mutex> lock(ReservedPortMutex());
    auto& reserved = ReservedPorts();

    start = std::max(start, 1);
    end   = std::min(end, 65535);
    if (start > end) {
        return 0;
    }

    static int next_candidate = 10000;
    int candidate = std::clamp(next_candidate, start, end);
    const int attempts = end - start + 1;
    for (int i = 0; i < attempts; ++i) {
        if (candidate > end) {
            candidate = start;
        }
        if (!reserved.contains(candidate) && !proc::PortUtil::IsPortInUse(candidate)) {
            reserved.insert(candidate);
            next_candidate = candidate + 1;
            if (next_candidate > 65535) {
                next_candidate = 10000;
            }
            return candidate;
        }
        ++candidate;
    }

    return 0;
}

static bool ReserveFixedPort(int port)
{
    namespace proc = refuzz::vm::util;

    std::lock_guard<std::mutex> lock(ReservedPortMutex());
    auto& reserved = ReservedPorts();
    if (port <= 0 || port > 65535 || reserved.contains(port)
        || proc::PortUtil::IsPortInUse(port)) {
        return false;
    }
    reserved.insert(port);
    return true;
}

static void ReleaseReservedPort(int port)
{
    if (port <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(ReservedPortMutex());
    ReservedPorts().erase(port);
}

static void ReleaseReservedPorts(VmInstanceState& s)
{
    if (s.ssh_port_reserved) {
        ReleaseReservedPort(s.ssh_port);
        s.ssh_port_reserved = false;
    }
    if (s.mon_port_reserved) {
        ReleaseReservedPort(s.mon_port);
        s.mon_port_reserved = false;
    }
}

static void CloseQemuLog(VmInstanceState& s)
{
    std::lock_guard<std::mutex> lk(s.qemu_log_mtx);
    if (s.qemu_log_stream.is_open()) {
        s.qemu_log_stream.flush();
        s.qemu_log_stream.close();
    }
}

static void OpenQemuLog(VmInstanceState& s)
{
    CloseQemuLog(s);
    s.qemu_log_path = s.cfg.workdir + "/qemu.log";
    std::lock_guard<std::mutex> lk(s.qemu_log_mtx);
    s.qemu_log_stream.open(s.qemu_log_path, std::ios::out | std::ios::trunc);
}

static bool IsRetriablePortBindFailure(const std::string& message)
{
    return message.find("Could not set up host forwarding rule") != std::string::npos
        || message.find("host forwarding rule") != std::string::npos
        || message.find("Address already in use") != std::string::npos
        || message.find("Failed to bind socket") != std::string::npos;
}

// ── 辅助：SSH base args（不含 user@host + command）───────────

static std::vector<std::string> SshBaseArgs(const VmInstanceState& s, bool for_scp = false)
{
    std::vector<std::string> args;
    if (for_scp) {
        // scp 端口参数为 -P（大写）
        args = {"-i", s.cfg.ssh_key, "-P", std::to_string(s.ssh_port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10"};
    } else {
        args = {"-i", s.cfg.ssh_key, "-p", std::to_string(s.ssh_port),
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10"};
    }
    if (s.cfg.persistent_ssh) {
        const std::string ctl = s.cfg.workdir + "/ssh_ctl.sock";
        args.push_back("-o"); args.push_back("ControlMaster=no");
        args.push_back("-o"); args.push_back("ControlPath=" + ctl);
    }
    return args;
}

// ── 辅助：读 qemu.log 尾部若干字节（诊断用）────────────────────

static std::string TailFileForDiag(const std::string& path, std::size_t max_bytes = 4096)
{
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return {};
    const auto size = static_cast<std::streamoff>(in.tellg());
    if (size <= 0) return {};
    const auto off = (static_cast<std::streamoff>(max_bytes) < size)
                         ? size - static_cast<std::streamoff>(max_bytes)
                         : static_cast<std::streamoff>(0);
    in.seekg(off);
    std::string buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return buf;
}

// ── 辅助：等待 SSH 可达 ────────────────────────────────────
//
// [v3.G] 强化项:
//   - 每轮 probe 前先检查 QEMU 进程是否还活着;若已退出立刻带上 qemu.log 尾部
//     返回 kBoot 错误,避免等 60s 才报 kTimeout 掩盖真实症状。
//   - 依赖调用方把 qemu_process 填进 state,然后把整个 state 传进来。

static refuzz::channel::Result<void> WaitForSSH(VmInstanceState& s)
{
    std::vector<std::string> probe = {
        "-i", s.cfg.ssh_key,
        "-p", std::to_string(s.ssh_port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        s.cfg.ssh_user + "@localhost", "exit"
    };

    const auto kInterval = std::chrono::milliseconds{500};
    const auto deadline  = std::chrono::steady_clock::now() + s.cfg.boot_timeout;

    auto qemu_died_error = [&]() -> refuzz::channel::Error {
        std::string tail = TailFileForDiag(s.qemu_log_path);
        std::string msg = "QEMU exited before SSH became ready (ssh_port=" +
                          std::to_string(s.ssh_port) + ")";
        if (!tail.empty()) {
            msg += "; qemu.log tail:\n" + tail;
        } else if (!s.qemu_log_path.empty()) {
            msg += "; qemu.log=" + s.qemu_log_path + " is empty";
        }
        return refuzz::channel::Error{refuzz::channel::ErrorKind::kBoot, std::move(msg)};
    };

    while (std::chrono::steady_clock::now() < deadline) {
        // 存活检查:比起 SSH 慢超时,这样能在 QEMU 立刻秒退时马上报错。
        if (s.qemu_process && !s.qemu_process->IsRunning()) {
            return qemu_died_error();
        }
        auto r = refuzz::vm::util::Process::RunCommandDetailed(
            "ssh", probe, std::chrono::seconds{12});
        if (r.exit_code == 0) return refuzz::channel::Result<void>::Ok();
        // 再次检查:SSH 超时 12s 里面 QEMU 可能刚退。
        if (s.qemu_process && !s.qemu_process->IsRunning()) {
            return qemu_died_error();
        }
        std::this_thread::sleep_for(kInterval);
    }
    std::string msg = "timed out waiting for SSH on port " + std::to_string(s.ssh_port);
    std::string tail = TailFileForDiag(s.qemu_log_path);
    if (!tail.empty()) {
        msg += "; qemu.log tail:\n" + tail;
    }
    return refuzz::channel::Error{
        refuzz::channel::ErrorKind::kTimeout,
        std::move(msg)
    };
}

// ── 辅助：拆除 SSH ControlMaster ──────────────────────────

static void TeardownSSHMaster(VmInstanceState& s)
{
    if (!s.cfg.persistent_ssh) return;
    const std::string ctl = s.cfg.workdir + "/ssh_ctl.sock";
    if (FileExists(ctl)) {
        std::vector<std::string> exit_args = {
            "-o", "ControlPath=" + ctl,
            "-o", "StrictHostKeyChecking=no",
            "-O", "exit", s.cfg.ssh_user + "@localhost"
        };
        refuzz::vm::util::Process::RunCommandDetailed(
            "ssh", exit_args, std::chrono::seconds{1});
    }
    if (s.ssh_master && s.ssh_master->IsRunning()) {
        s.ssh_master->Kill(true);
        s.ssh_master->Wait(std::chrono::seconds{2});
    }
    s.ssh_master.reset();
    if (FileExists(ctl)) ::unlink(ctl.c_str());
}

} // namespace

// ============================================================
// MakeVmInstanceOps — 工厂函数
// ============================================================

refuzz::channel::runtime::SubstrateInstanceOps
MakeVmInstanceOps(RuntimeInstanceConfig cfg)
{
    using namespace refuzz::channel;
    namespace proc = refuzz::vm::util;

    auto state = std::make_shared<VmInstanceState>();
    state->cfg = std::move(cfg);

    SubstrateInstanceOps ops;

    // ── start ─────────────────────────────────────────────────
    ops.start = [state]() -> Result<void> {
        if (state->qemu_process) {
            return Error{ErrorKind::kBoot, "start() called while already running"};
        }

        // workdir 不存在则创建
        if (!MkdirP(state->cfg.workdir)) {
            return Error{ErrorKind::kConfig,
                         "failed to create workdir: " + state->cfg.workdir};
        }

        std::string serial_log_error;
        if (!ResetSerialLogFile(state->cfg.serial_log_path, &serial_log_error)) {
            return Error{ErrorKind::kConfig, serial_log_error};
        }

        // 解析 QEMU binary
        std::string qemu_bin = state->cfg.qemu_bin;
        if (qemu_bin.empty()) {
            auto ar = GetArchParams(state->cfg.arch);
            if (!ar.ok()) return Error{ar.error().kind, ar.error().message};
            qemu_bin = ar.value().qemu_bin;
        }

        // ── snapshot-fuzzing: per-instance qcow2 overlay ─────────
        // savevm needs a WRITABLE qcow2 to store S0; build a fresh overlay over the
        // (immutable) base image in workdir and boot QEMU from it. Once per start,
        // before the launch-retry loop. (Brick 2, docs/plans/snapshot-mode.md)
        if (state->cfg.snapshot_fuzzing) {
            const std::string overlay = state->cfg.workdir + "/snapshot-overlay.qcow2";
            std::error_code rm_ec;
            std::filesystem::remove(overlay, rm_ec);  // fresh each start
            auto qimg = [&](const std::vector<std::string>& a, std::string* out) -> int {
                proc::Process::Options io;
                io.workdir = state->cfg.workdir;
                io.redirect_stderr = true;
                if (out)
                    io.output_callback = [out](const char* d, size_t n) { out->append(d, n); };
                proc::Process p("qemu-img", a, io);
                return p.Wait(std::chrono::seconds(60));
            };
            // qemu-img needs the backing file's format explicitly.
            std::string info;
            qimg({"info", "--output=json", state->cfg.disk_image}, &info);
            std::string base_fmt = "raw";
            if (auto pos = info.find("\"format\""); pos != std::string::npos) {
                auto q1 = info.find('"', info.find(':', pos));
                auto q2 = (q1 == std::string::npos) ? std::string::npos
                                                    : info.find('"', q1 + 1);
                if (q2 != std::string::npos)
                    base_fmt = info.substr(q1 + 1, q2 - q1 - 1);
            }
            std::string err;
            int rc = qimg({"create", "-f", "qcow2", "-F", base_fmt, "-b",
                           state->cfg.disk_image, overlay}, &err);
            if (rc != 0) {
                return Error{ErrorKind::kConfig,
                             "snapshot_fuzzing: qemu-img overlay create failed (rc="
                                 + std::to_string(rc) + "): " + err};
            }
            state->cfg.disk_image = overlay;  // boot from overlay; base stays immutable
        }

        constexpr int kQemuLaunchAttempts = 3;
        Error last_error{ErrorKind::kBoot, "failed to start QEMU"};
        for (int attempt = 0; attempt < kQemuLaunchAttempts; ++attempt) {
            ReleaseReservedPorts(*state);
            state->ssh_port = 0;
            state->mon_port = 0;

            // [measure] env override: pin QMP to a known fixed port so the
            // snapshot dirty-set dump hook (replayer MeasureQmpDump) can connect
            // deterministically. Gated; absent → normal auto-allocate.
            if (const char* e = ::getenv("REFUZZ_QMP_FIXED_PORT")) {
                int p = ::atoi(e);
                if (p > 0) {
                    state->cfg.qmp_enable      = true;
                    state->cfg.qmp_port_policy = QmpPortPolicy::kFixed;
                    state->cfg.qmp_fixed_port  = p;
                }
            }

            // 固定 QMP 先 reservation，避免 SSH auto 分配碰到同一个端口。
            if (state->cfg.qmp_enable
                && state->cfg.qmp_port_policy == QmpPortPolicy::kFixed) {
                state->mon_port = state->cfg.qmp_fixed_port;
                if (!ReserveFixedPort(state->mon_port)) {
                    ReleaseReservedPorts(*state);
                    state->mon_port = 0;
                    return Error{ErrorKind::kBoot,
                                 "fixed QMP port is unavailable: "
                                     + std::to_string(state->cfg.qmp_fixed_port)};
                }
                state->mon_port_reserved = true;
            }

            // 分配并在本进程内 reservation，避免并发 VM 启动拿到相同端口。
            state->ssh_port = ReserveUnusedPort(10000, 65535);
            if (state->ssh_port == 0) {
                ReleaseReservedPorts(*state);
                return Error{ErrorKind::kBoot, "failed to find unused SSH port"};
            }
            state->ssh_port_reserved = true;

            if (state->cfg.qmp_enable) {
                if (state->cfg.qmp_port_policy != QmpPortPolicy::kFixed) {
                    state->mon_port = ReserveUnusedPort(10000, 65535);
                    if (state->mon_port == 0) {
                        ReleaseReservedPorts(*state);
                        state->ssh_port = 0;
                        return Error{ErrorKind::kBoot, "failed to find unused QMP port"};
                    }
                    state->mon_port_reserved = true;
                }
            }

            auto qemu_args = BuildQEMUArgs(
                state->cfg, state->ssh_port, state->mon_port, state->cfg.workdir);

            // [v3.G] 打开 qemu.log 落盘文件（stdout + stderr 合并）。
            //         WaitForSSH 在 QEMU 秒退时会从这里读尾部做诊断。
            OpenQemuLog(*state);

            proc::Process::Options opts;
            opts.workdir        = state->cfg.workdir;
            opts.redirect_stderr = true;
            opts.output_callback = [state](const char* data, size_t n) {
                std::lock_guard<std::mutex> lk(state->qemu_log_mtx);
                if (state->qemu_log_stream.is_open()) {
                    state->qemu_log_stream.write(data, static_cast<std::streamsize>(n));
                    state->qemu_log_stream.flush();
                }
            };
            try {
                state->qemu_process = std::make_unique<proc::Process>(
                    qemu_bin, qemu_args, opts);
            } catch (const std::exception& e) {
                ReleaseReservedPorts(*state);
                state->ssh_port = 0;
                state->mon_port = 0;
                return Error{ErrorKind::kBoot,
                             std::string("failed to launch QEMU: ") + e.what()};
            }

            auto ssh_r = WaitForSSH(*state);
            if (ssh_r.ok()) {
                // QEMU now owns the hostfwd/QMP sockets; release only our
                // process-local reservation markers.
                ReleaseReservedPorts(*state);
                break;
            }

            last_error = Error{ssh_r.error().kind, ssh_r.error().message};
            if (state->qemu_process) {
                state->qemu_process->Kill(true);
                state->qemu_process->Wait(std::chrono::seconds{5});
                state->qemu_process.reset();
            }
            ReleaseReservedPorts(*state);
            CloseQemuLog(*state);
            state->ssh_port = 0;
            state->mon_port = 0;

            if (attempt + 1 >= kQemuLaunchAttempts
                || !IsRetriablePortBindFailure(last_error.message)) {
                return last_error;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }

        if (!state->qemu_process) {
            return last_error;
        }

        // 建立 ControlMaster（persistent_ssh=true）
        if (state->cfg.persistent_ssh) {
            const std::string ctl = state->cfg.workdir + "/ssh_ctl.sock";
            std::vector<std::string> master_args = {
                "-i", state->cfg.ssh_key,
                "-p", std::to_string(state->ssh_port),
                "-o", "ControlMaster=yes",
                "-o", "ControlPath=" + ctl,
                "-o", "ServerAliveInterval=10",
                "-o", "StrictHostKeyChecking=no",
                "-N",
                state->cfg.ssh_user + "@localhost"
            };
            proc::Process::Options mo;
            mo.workdir        = state->cfg.workdir;
            mo.redirect_stderr = true;
            try {
                state->ssh_master = std::make_unique<proc::Process>(
                    "ssh", master_args, mo);
            } catch (...) { /* ControlMaster 失败不致命，继续 */ }

            // 等待 ControlPath socket 出现
            const auto ctl_deadline =
                std::chrono::steady_clock::now() + state->cfg.ssh_master_ready_timeout;
            while (!FileExists(ctl) &&
                   std::chrono::steady_clock::now() < ctl_deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
            }
        }

        return Result<void>::Ok();
    };

    // ── stop ──────────────────────────────────────────────────
    ops.stop = [state]() {
        TeardownSSHMaster(*state);
        if (state->qemu_process) {
            if (state->cfg.snapshot) {
                state->qemu_process->Kill(true);
            } else {
                state->qemu_process->Kill(false);
                state->qemu_process->Wait(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        state->cfg.graceful_stop_timeout));
                if (state->qemu_process->IsRunning())
                    state->qemu_process->Kill(true);
            }
            state->qemu_process->Wait(std::chrono::seconds{5});
            state->qemu_process.reset();
        }
        ReleaseReservedPorts(*state);
        CloseQemuLog(*state);
        state->ssh_port = 0;
        state->mon_port = 0;
    };

    // ── is_alive ──────────────────────────────────────────────
    ops.is_alive = [state]() -> bool {
        return state->qemu_process && state->qemu_process->IsRunning();
    };

    // ── run_command ───────────────────────────────────────────
    ops.run_command = [state](const std::string& cmd,
                               std::chrono::milliseconds timeout)
        -> Result<std::string>
    {
        auto base = SshBaseArgs(*state);
        base.push_back(state->cfg.ssh_user + "@localhost");
        base.push_back(cmd);

        auto r = proc::Process::RunCommandDetailed(
            "ssh", base,
            std::chrono::duration_cast<std::chrono::seconds>(timeout));

        if (r.timed_out) {
            return Error{ErrorKind::kTimeout,
                         "SSH command timed out: " + cmd};
        }
        if (r.exit_code != 0) {
            const ErrorKind kind =
                (r.exit_code == 255) ? ErrorKind::kConnection : ErrorKind::kCommand;
            return Error{kind,
                         "SSH command failed (exit=" +
                         std::to_string(r.exit_code) + "): " + cmd +
                         "\noutput: " + r.output};
        }
        return Result<std::string>::Ok(std::move(r.output));
    };

    // ── copy_file_to ──────────────────────────────────────────
    ops.copy_file_to = [state](const std::string& local,
                                const std::string& remote,
                                std::chrono::milliseconds timeout)
        -> Result<void>
    {
        auto base = SshBaseArgs(*state, /*for_scp=*/true);
        base.push_back(local);
        base.push_back(state->cfg.ssh_user + "@localhost:" + remote);

        auto r = proc::Process::RunCommandDetailed(
            "scp", base,
            std::chrono::duration_cast<std::chrono::seconds>(timeout));

        if (r.timed_out) return Error{ErrorKind::kTimeout, "scp timed out"};
        if (r.exit_code != 0) {
            const ErrorKind kind =
                (r.exit_code == 255) ? ErrorKind::kConnection : ErrorKind::kCommand;
            return Error{kind,
                         "scp failed (exit=" + std::to_string(r.exit_code) +
                         ")\noutput: " + r.output};
        }
        return Result<void>::Ok();
    };

    // ── serial_endpoint ───────────────────────────────────────
    //
    // [v3 Phase 2] 语义与 default_console_endpoint().path 一致；保留到 Health/
    // Evidence 全部迁移后（Phase 3）删除。
    ops.serial_endpoint = [state]() -> std::string {
        return state->cfg.workdir + "/serial.sock";
    };

    // ── default_console_endpoint（v3 Phase 2）─────────────────
    //
    // QEMU VM 底座默认输出 Unix socket（由 -serial unix:... 参数创建，
    // 路径与 serial_endpoint 一致）。Evidence Assembler 之后可基于
    // ConsoleEndpoint::Kind 分派到 UnixSerialConsoleSource / TcpConsoleSource 等。
    ops.default_console_endpoint = [state]() -> evidence::ConsoleEndpoint {
        evidence::ConsoleEndpoint ep;
        ep.kind = evidence::ConsoleEndpoint::Kind::kUnixSocket;
        ep.path = state->cfg.workdir + "/serial.sock";
        return ep;
    };

    // ── hints（v3 Phase 2）────────────────────────────────────
    //
    // 语义：返回当前底座已知的低层端点；未启动 / 未分配的字段保留 nullopt。
    // 当前 VM 底座是 QEMU + ivshmem（可选 doorbell），按 RuntimeInstanceConfig
    // 字段组装；doorbell 模式另填 doorbell_socket_path。
    //
    // 注意：只有 CP/DP 的底座专用实现会消费这些字段；Channel / Health / Recovery
    // 不应解引用。
    ops.hints = [state]() -> VendorHints {
        VendorHints h;
        if (!state->cfg.ivshmem_path.empty()) {
            h.ivshmem_path = state->cfg.ivshmem_path;
        }
        if (state->cfg.ivshmem_bytes > 0) {
            h.ivshmem_bytes = state->cfg.ivshmem_bytes;
        }
        if (state->cfg.ivshmem_mode == "doorbell" &&
            !state->cfg.ivshmem_socket.empty()) {
            h.doorbell_socket_path = state->cfg.ivshmem_socket;
        }
        return h;
    };

    // ── monitor_endpoint ──────────────────────────────────────
    ops.monitor_endpoint = [state]() -> std::string {
        if (!state->cfg.qmp_enable || state->mon_port == 0) return "";
        return state->cfg.qmp_host + ":" + std::to_string(state->mon_port);
    };

    // ── diagnose ──────────────────────────────────────────────
    ops.diagnose = [state]() -> std::string {
        std::ostringstream ss;
        ss << "VmInstance{index=" << state->cfg.index
           << " arch="   << state->cfg.arch
           << " ssh_port=" << state->ssh_port
           << " mon_port=" << state->mon_port
           << " alive="   << (state->qemu_process
                              ? state->qemu_process->IsRunning() : false)
           << " workdir=" << state->cfg.workdir
           << "}";
        return ss.str();
    };

    return ops;
}

} // namespace refuzz::channel::runtime::substrate::vm
