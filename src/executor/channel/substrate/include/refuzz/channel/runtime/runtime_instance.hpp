#pragma once

// RuntimeInstance — 单 VM 实例生命周期管理
//
// 职责：
//   通过 SubstrateInstanceOps 函数表驱动底层 VM 操作；
//   管理 worker 进程的部署、启动、停止（StartWorker 含回滚语义，§6）。
//   不直接引用 Process/SSH 等底层类型。
//
// 状态机（§7.1）：
//   stopped → starting → running → stopping → stopped
//   启动失败必须回落 stopped，Stop() 幂等。
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.2 §6 §7

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"
#include "refuzz/channel/runtime/vendor_hints.hpp"
#include "refuzz/channel/substrate/substrate.hpp"
#include "worker/config/worker_config.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::channel::runtime {

// ============================================================
// RuntimeInstanceState — 实例状态
// ============================================================

enum class RuntimeInstanceState : uint8_t {
    kStopped  = 0,
    kStarting,
    kRunning,
    kStopping,
};

// ============================================================
// RuntimeInstance
// ============================================================

class RuntimeInstance {
public:
    explicit RuntimeInstance(SubstrateInstanceOps     ops,
                             worker::WorkerConfig     worker_cfg);
    ~RuntimeInstance();

    RuntimeInstance(const RuntimeInstance&) = delete;
    RuntimeInstance& operator=(const RuntimeInstance&) = delete;

    // ── VM 生命周期 ──────────────────────────────────────────

    // stopped → running
    // 失败时 VM 进程已清理，状态回落 stopped
    Result<void> StartVM();

    // running → stopped（幂等；snapshot 模式直接 SIGKILL）
    // 完成后清空全部 worker_pids_
    void Stop();

    // Stop() + worker_pids_ 清零 + StartVM()
    // 不调用 StopWorker（pid 已在 Stop 清空）
    Result<void> Reboot();

    // QEMU 进程是否仍在运行
    bool IsAlive() const;

    // ── Worker 进程管理（StartVM 后调用）────────────────────

    // [DEPRECATED v3] 使用 WorkerConfig 的 binary/remote path 做一次 scp；
    // 新代码请走 DeployArtifacts(bundle)；Phase 7 删除。
    Result<void> DeployWorker();

    // [v3 Phase 2] 按 DeployBundle 中描述把多个 host 文件送入 VM，并根据
    // bundle.worker_start_cmd 覆盖内部启动模板。
    //
    // 语义：
    //   - 所有 artifact 逐一 scp；任一失败整体返回错误
    //   - bundle.worker_start_cmd 非空时覆盖 worker_cfg_.worker_start_cmd；
    //     后续 StartWorker / StartSingleWorkerPublic 使用新模板
    //   - 幂等：调用方负责确保 bundle 一致；本方法不去重
    Result<void> DeployArtifacts(const DeployBundle& bundle);

    // 按 worker_cfg.n_workers 顺序启动，记录 PID
    // 失败时回滚（§6.1）：kill 已启动 worker，清空 pid 表，返回错误
    Result<void> StartWorker();

    // 仅按 PID 精确 kill（§6.2），完成后清空 pid 表
    Result<void> StopWorker();

    // [v2 单 worker 停止 — 当前版本]
    // 仅停止指定 worker_id 的进程，不影响其他 worker
    Result<void> StopSingleWorker(uint32_t worker_id);

    // [v2 单 worker 启动 — 当前版本]
    // 仅启动指定 worker_id 的进程，不影响其他 worker
    Result<void> StartSingleWorkerPublic(uint32_t worker_id);

    // ── SSH 透传 ─────────────────────────────────────────────

    Result<void>        CopyFileTo(const std::string& local_path,
                                   const std::string& remote_path,
                                   std::chrono::milliseconds timeout);

    Result<std::string> RunCommand(const std::string& cmd,
                                   std::chrono::milliseconds timeout);

    // ── 查询 ─────────────────────────────────────────────────

    // [v3 Phase 2/10] 默认控制台 endpoint 描述符；供 Evidence Assembler 装配
    // IConsoleSource 使用（VM 底座默认 kUnixSocket + path）。
    // 取代 Phase 10 删除的 SerialSocketPath() 薄包装。
    evidence::ConsoleEndpoint DefaultConsoleEndpoint() const;

    // [v3 Phase 2] 返回当前底座启动后固定的低层端点（ivshmem_path /
    // doorbell_socket_path / vsock_cid / ...）。Channel / Health / Recovery
    // 不得消费；仅 ControlPlane / DataPlane / ConsoleSource 的底座专用实现读。
    VendorHints Hints() const;

    // QMP monitor endpoint（"host:port"）
    std::string MonitorEndpoint()   const;

    // 诊断快照（Fault 场景记录）
    std::string Diagnose()          const;

    RuntimeInstanceState state()    const;

private:
    // 按索引启动单个 worker，返回 PID；失败返回 < 0
    Result<pid_t> StartSingleWorker(uint32_t worker_id);

    // 精确 kill 指定 PID（pid=0 静默成功，§6.2）；失败返回错误
    Result<void> KillWorkerPid(pid_t pid);

    SubstrateInstanceOps  ops_;
    worker::WorkerConfig  worker_cfg_;

    RuntimeInstanceState  state_    = RuntimeInstanceState::kStopped;

    // worker PID 表（下标 = worker_id，0 = 未启动）
    std::vector<pid_t>    worker_pids_;
};

} // namespace refuzz::channel::runtime
