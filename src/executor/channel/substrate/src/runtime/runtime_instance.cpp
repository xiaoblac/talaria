// runtime_instance.cpp — RuntimeInstance 实现
//
// 状态机：stopped → starting → running → stopping → stopped
// 启动失败回落 stopped；Stop() 幂等。
// StartWorker 回滚语义（§6.1）：任一 worker 失败即 kill 已启动者并清空 pid 表。
// StopWorker 精确 PID kill（§6.2），不做名字匹配兜底；聚合并返回 kill 失败。
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.2 §6 §7

#include "refuzz/channel/runtime/runtime_instance.hpp"

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace refuzz::channel::runtime {

namespace {

static std::string QuoteShellArg(const std::string& value)
{
    std::string quoted = "'";
    for (const char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted += ch;
        }
    }
    quoted += "'";
    return quoted;
}

static std::string BuildChmodCmd(const DeployArtifact& artifact)
{
    std::ostringstream command;
    command << "chmod " << std::setfill('0') << std::setw(4) << std::oct
            << artifact.mode << " -- " << QuoteShellArg(artifact.remote_path);
    return command.str();
}

// ── 辅助：从字符串输出解析 PID ────────────────────────────────
static pid_t ParsePid(const std::string& output) {
    // 取最后一行非空内容（background exec & echo $! 输出）
    std::istringstream ss(output);
    std::string line, last;
    while (std::getline(ss, line)) {
        size_t s = line.find_first_not_of(" \t\r\n");
        if (s == std::string::npos) continue;
        last = line.substr(s);
        size_t e = last.find_last_not_of(" \t\r\n");
        if (e != std::string::npos) last = last.substr(0, e + 1);
    }
    if (last.empty()) return -1;
    for (char c : last) {
        if (c < '0' || c > '9') return -1;
    }
    long pid = std::strtol(last.c_str(), nullptr, 10);
    return (pid > 0) ? static_cast<pid_t>(pid) : -1;
}

// ── 辅助：构造单个 worker 的启动命令 ─────────────────────────
// 若 worker_start_cmd 非空，直接使用（追加 --worker-id <i>）。
// 否则默认：chmod+exec，--worker-id <i>，重定向输出，后台运行，echo PID。
static std::string BuildStartCmd(const worker::WorkerConfig& cfg,
                                 uint32_t                    worker_id)
{
    const std::string worker_id_text = std::to_string(worker_id);
    const std::string id_flag = " --worker-id " + worker_id_text;
    const std::string log_tail =
        " </dev/null >/tmp/refuzz_worker_" + worker_id_text +
        ".log 2>&1 & echo $!";

    if (!cfg.worker_start_cmd.empty()) {
        // 调用方自定义命令；追加 --worker-id <i>
        return cfg.worker_start_cmd + id_flag + log_tail;
    }
    // 默认推导
    return "chmod +x " + cfg.worker_remote_path + " 2>/dev/null ; " +
           cfg.worker_remote_path + id_flag + log_tail;
}

} // namespace

// ── 构造 / 析构 ────────────────────────────────────────────────

RuntimeInstance::RuntimeInstance(SubstrateInstanceOps ops,
                                 worker::WorkerConfig worker_cfg)
    : ops_(std::move(ops)), worker_cfg_(std::move(worker_cfg))
{}

RuntimeInstance::~RuntimeInstance() {
    if (state_ != RuntimeInstanceState::kStopped) {
        Stop();
    }
}

// ── VM 生命周期 ────────────────────────────────────────────────

Result<void> RuntimeInstance::StartVM()
{
    using S = RuntimeInstanceState;
    if (state_ != S::kStopped) {
        return Error{ErrorKind::kBoot, "StartVM called in non-stopped state"};
    }

    state_ = S::kStarting;

    auto r = ops_.start();
    if (!r.ok()) {
        state_ = S::kStopped;
        return Error{r.error().kind, r.error().message};
    }

    state_ = S::kRunning;
    return Result<void>::Ok();
}

void RuntimeInstance::Stop()
{
    using S = RuntimeInstanceState;
    if (state_ == S::kStopped) return;   // 幂等

    state_ = S::kStopping;

    // §6.3: Stop 完成后必须清空 pid 表
    worker_pids_.assign(worker_pids_.size(), 0);

    ops_.stop();

    state_ = S::kStopped;
}

Result<void> RuntimeInstance::Reboot()
{
    // §6.3: Stop() + worker_pids_ 全部置 0 + StartVM()
    Stop();
    return StartVM();
}

bool RuntimeInstance::IsAlive() const {
    return ops_.is_alive();
}

// ── Worker 进程管理 ────────────────────────────────────────────

Result<void> RuntimeInstance::DeployWorker()
{
    // 超时来自 WorkerConfig（由 RuntimePool::CreateInstance 从 RuntimeInstanceConfig 注入）
    return ops_.copy_file_to(
        worker_cfg_.worker_binary_host_path,
        worker_cfg_.worker_remote_path,
        worker_cfg_.deploy_timeout);
}

Result<void> RuntimeInstance::DeployArtifacts(const DeployBundle& bundle)
{
    // 按序 scp + chmod 每个 artifact；任一失败整体返回，不尝试回滚已传文件（
    // target 文件系统写入默认是幂等的；失败场景由上层决定是否 Reboot）
    for (const auto& a : bundle.artifacts) {
        if (a.mode > 07777u) {
            return Error{ErrorKind::kConfig,
                         "DeployArtifacts invalid mode for '" + a.remote_path +
                         "': " + std::to_string(a.mode)};
        }
        auto r = ops_.copy_file_to(a.local_path, a.remote_path, bundle.deploy_timeout);
        if (!r.ok()) {
            return Error{r.error().kind,
                         "DeployArtifacts failed for '" + a.local_path + "' -> '" +
                         a.remote_path + "': " + r.error().message};
        }
        auto chmod_result = ops_.run_command(BuildChmodCmd(a), bundle.deploy_timeout);
        if (!chmod_result.ok()) {
            return Error{chmod_result.error().kind,
                         "DeployArtifacts chmod failed for '" + a.remote_path +
                         "': " + chmod_result.error().message};
        }
    }

    // bundle.worker_start_cmd 非空覆盖模板；保持 BuildStartCmd 逻辑不变，
    // 它已经支持模板注入："<worker_start_cmd> --worker-id <i>"（§45-50）
    if (!bundle.worker_start_cmd.empty()) {
        worker_cfg_.worker_start_cmd = bundle.worker_start_cmd;
    }

    return Result<void>::Ok();
}

Result<void> RuntimeInstance::StartWorker()
{
    const uint32_t n = worker_cfg_.n_workers;

    worker_pids_.assign(n, 0);

    for (uint32_t i = 0; i < n; ++i) {
        auto r = StartSingleWorker(i);
        if (!r.ok()) {
            // §6.1 回滚：kill 已成功启动的 worker[0..i-1]
            for (uint32_t j = 0; j < i; ++j) {
                KillWorkerPid(worker_pids_[j]);
            }
            worker_pids_.assign(n, 0);
            return Error{r.error().kind,
                         "StartWorker failed at worker[" + std::to_string(i) + "]: " +
                         r.error().message};
        }
        worker_pids_[i] = r.value();
    }

    return Result<void>::Ok();
}

Result<void> RuntimeInstance::StopWorker()
{
    // 仅按 PID 精确 kill，不做名字匹配兜底
    // 聚合所有 kill 失败，完成后统一清空 pid 表并上报
    std::string fail_msg;
    for (pid_t pid : worker_pids_) {
        auto r = KillWorkerPid(pid);
        if (!r.ok() && fail_msg.empty()) {
            // 仅记录第一条失败原因（后续继续 kill 其余 pid）
            fail_msg = r.error().message;
        }
    }
    worker_pids_.assign(worker_pids_.size(), 0);

    if (!fail_msg.empty())
        return Error{ErrorKind::kCommand, "StopWorker: " + fail_msg};
    return Result<void>::Ok();
}

// [当前版本 stop-single-worker-pid-retention] 仅停止指定 worker_id 的进程，不影响其他 worker。
// kill 失败（如 SSH timeout / connection lost）时**保留 pid**：让下一次 StopSingleWorker
// 仍然知道目标 pid，而不是误以为 worker 已死。否则下一轮恢复会跳过 kill 直接
// StartWorker，导致 VM 内残留 worker 与新 worker 抢同一份 ivshmem。
Result<void> RuntimeInstance::StopSingleWorker(uint32_t worker_id)
{
    if (worker_id >= static_cast<uint32_t>(worker_pids_.size())) {
        return Error{ErrorKind::kCommand,
                     "StopSingleWorker: worker_id " + std::to_string(worker_id) +
                     " out of range (size=" + std::to_string(worker_pids_.size()) + ")"};
    }
    pid_t pid = worker_pids_[worker_id];
    if (pid <= 0) return Result<void>::Ok();

    auto r = KillWorkerPid(pid);
    if (r.ok()) {
        worker_pids_[worker_id] = 0;
    }
    return r;
}

// [v2 单 worker 启动 — 当前版本]
// 仅启动指定 worker_id 的进程，不影响其他 worker
Result<void> RuntimeInstance::StartSingleWorkerPublic(uint32_t worker_id)
{
    // 越界检查：worker_id 必须在 WorkerConfig 允许范围内
    if (worker_id >= worker_cfg_.n_workers) {
        return Error{ErrorKind::kBoot,
                     "StartSingleWorkerPublic: worker_id " + std::to_string(worker_id) +
                     " out of range (n_workers=" + std::to_string(worker_cfg_.n_workers) + ")"};
    }

    // 若 pid 表尺寸不足，扩展到 n_workers（首次调用时 pid 表可能为空）
    if (worker_pids_.size() < static_cast<size_t>(worker_cfg_.n_workers)) {
        worker_pids_.resize(worker_cfg_.n_workers, 0);
    }

    // 若该 worker 已在运行，先 kill（避免僵尸/冲突）
    if (worker_pids_[worker_id] > 0) {
        KillWorkerPid(worker_pids_[worker_id]);
        worker_pids_[worker_id] = 0;
    }

    auto r = StartSingleWorker(worker_id);
    if (!r.ok()) {
        return Error{r.error().kind, r.error().message};
    }
    worker_pids_[worker_id] = r.value();
    return Result<void>::Ok();
}

// ── SSH 透传 ──────────────────────────────────────────────────

Result<void> RuntimeInstance::CopyFileTo(const std::string& local_path,
                                          const std::string& remote_path,
                                          std::chrono::milliseconds timeout)
{
    return ops_.copy_file_to(local_path, remote_path, timeout);
}

Result<std::string> RuntimeInstance::RunCommand(const std::string& cmd,
                                                 std::chrono::milliseconds timeout)
{
    return ops_.run_command(cmd, timeout);
}

// ── 查询 ──────────────────────────────────────────────────────

evidence::ConsoleEndpoint RuntimeInstance::DefaultConsoleEndpoint() const {
    // 若底座已提供新 hook 直接用；旧 mock ops（测试路径）可能未填，回退用
    // serial_endpoint() 构造一个 kUnixSocket endpoint，保持语义同向。
    if (ops_.default_console_endpoint) {
        return ops_.default_console_endpoint();
    }
    evidence::ConsoleEndpoint ep;
    ep.kind = evidence::ConsoleEndpoint::Kind::kUnixSocket;
    if (ops_.serial_endpoint) ep.path = ops_.serial_endpoint();
    return ep;
}

VendorHints RuntimeInstance::Hints() const {
    if (ops_.hints) return ops_.hints();
    return VendorHints{};
}

std::string RuntimeInstance::MonitorEndpoint() const {
    return ops_.monitor_endpoint();
}

std::string RuntimeInstance::Diagnose() const {
    return ops_.diagnose();
}

RuntimeInstanceState RuntimeInstance::state() const {
    return state_;
}

// ── 私有：单个 worker 启停 ─────────────────────────────────────

Result<pid_t> RuntimeInstance::StartSingleWorker(uint32_t worker_id)
{
    const std::string cmd = BuildStartCmd(worker_cfg_, worker_id);

    // 超时来自 WorkerConfig（由 RuntimePool::CreateInstance 注入）
    auto r = ops_.run_command(cmd, worker_cfg_.start_worker_timeout);
    if (!r.ok()) {
        return Error{r.error().kind,
                     "failed to start worker[" + std::to_string(worker_id) + "]: " +
                     r.error().message};
    }

    pid_t pid = ParsePid(r.value());
    if (pid <= 0) {
        return Error{ErrorKind::kBoot,
                     "worker[" + std::to_string(worker_id) + "] start command returned "
                     "no valid PID; output: " + r.value()};
    }
    return Result<pid_t>::Ok(pid);
}

Result<void> RuntimeInstance::KillWorkerPid(pid_t pid)
{
    // pid=0 跳过（§6.2）
    if (pid <= 0) return Result<void>::Ok();

    const std::string cmd = "kill -9 " + std::to_string(pid) + " 2>/dev/null ; true";
    auto r = ops_.run_command(cmd, worker_cfg_.stop_worker_timeout);
    if (!r.ok()) {
        return Error{r.error().kind,
                     "kill pid=" + std::to_string(pid) + " failed: " + r.error().message};
    }
    return Result<void>::Ok();
}

} // namespace refuzz::channel::runtime
