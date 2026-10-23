#pragma once

// Substrate — VM 底座能力函数表（组合，不用继承）
//
// SubstrateInstanceOps：单 VM 实例能力（start/stop/is_alive/run_command/...）
// SubstratePoolOps：池级能力（count/create_instance/close）
// MakeVmSubstratePoolOps：VM 底座标准工厂（vm_pool.cpp 实现）
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.3

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"
#include "refuzz/channel/runtime/vendor_hints.hpp"

#include <chrono>
#include <functional>
#include <string>

namespace refuzz::channel::runtime {

// ============================================================
// SubstrateInstanceOps — 实例级函数表
// ============================================================
// RuntimeInstance 只依赖此函数表，不直接引用 Process/SSH 等底层类型。
// reboot 不在底座层：RuntimeInstance::Reboot() = Stop() + StartVM()。

struct SubstrateInstanceOps {
    // 启动 VM 进程（QEMU launch + SSH ready）；失败时 VM 进程已被清理
    std::function<Result<void>()> start;

    // 停止 VM 进程（幂等）；SIGKILL or graceful depending on snapshot flag
    std::function<void()> stop;

    // 检查 VM 进程是否仍在运行
    std::function<bool()> is_alive;

    // 在 VM 内执行命令（通过 SSH）；返回 stdout；失败返回 kCommand/kTimeout
    std::function<Result<std::string>(const std::string& cmd,
                                      std::chrono::milliseconds timeout)> run_command;

    // 将 host 侧文件 scp 到 VM（通过 SSH）
    std::function<Result<void>(const std::string& local_path,
                               const std::string& remote_path,
                               std::chrono::milliseconds timeout)> copy_file_to;

    // 串行控制台 socket 路径（底座实现私有细节）
    //
    // [v3 Phase 10] Runtime/RuntimeInstance 上对应的 SerialSocketPath() 薄包装已删除；
    // 对外权威路径是 default_console_endpoint()。
    // 本字段保留是因为底座实现内部（vm_instance / runtime_instance fallback）
    // 仍用它填充 default_console_endpoint 的 path 部分；外部不得直接依赖。
    std::function<std::string()> serial_endpoint;

    // QMP monitor endpoint（"host:port" 格式）；qmp_enable=false 时返回空串
    std::function<std::string()> monitor_endpoint;

    // 诊断信息快照（QEMU 进程状态、PID、端口等）；用于 Fault 场景记录
    std::function<std::string()> diagnose;

    // ── [v3 Phase 2] Evidence 默认入口 ─────────────────────────
    //
    // 启动后返回当前底座的默认 console endpoint（kind + path/fd）。
    // Substrate Assembler 在装配 IConsoleSource 时消费此字段；保持与
    // serial_endpoint() 同语义（VM 底座默认 kUnixSocket + path = workdir+"/serial.sock"）。
    //
    // 与 serial_endpoint 的关系：
    //   serial_endpoint()  == default_console_endpoint().path   （VM 场景一致）
    //   但 default_console_endpoint 的 Kind 允许非 Unix socket（TCP / fd 借用 / ssh 流）
    std::function<evidence::ConsoleEndpoint()> default_console_endpoint;

    // ── [v3 Phase 2] 底座启动后固定的底层端点（供 CP/DP 装配）─────
    //
    // 语义：返回当前底座已分配/已就绪的低层端点快照；对 QEMU ivshmem 底座填
    //       ivshmem_path / doorbell_socket_path / ivshmem_bytes；其他底座填
    //       自己对应的字段；未启动前返回的字段可能为空 optional。
    //
    // 关键约束：Channel / Health / Recovery 不得解引用 Hints 的具体字段；
    //           只有 ControlPlane / DataPlane / ConsoleSource 的底座专用实现才读。
    std::function<VendorHints()> hints;
};

// ============================================================
// SubstratePoolOps — 池级函数表
// ============================================================

struct SubstratePoolOps {
    // 池容量（与 RuntimePoolConfig.pool_size 一致）
    std::function<uint32_t()> count;

    // 为给定 RuntimeInstanceConfig 创建一个底座实例 ops 表
    // 调用方（RuntimePool::CreateInstance）负责传入正确的 cfg
    std::function<Result<SubstrateInstanceOps>(
        const RuntimeInstanceConfig& cfg)> create_instance;

    // 释放池级资源（VM 进程清理等；doorbell server 由 QEMU ivshmem-doorbell device 管理，
    // Transport 仅作为客户端连接，此处不涉及 doorbell server 生命周期）
    std::function<Result<void>()> close;
};

// ============================================================
// MakeVmSubstratePoolOps — VM 底座标准工厂（声明）
// ============================================================
// 生产路径：RuntimePool::Create 传入 MakeVmSubstratePoolOps(cfg.instance)
// 测试路径：传入自定义 mock SubstratePoolOps

SubstratePoolOps MakeVmSubstratePoolOps(const RuntimeInstanceConfig& template_cfg);

} // namespace refuzz::channel::runtime
