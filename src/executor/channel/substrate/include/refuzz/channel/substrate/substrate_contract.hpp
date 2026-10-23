#pragma once

// [v3 Phase 1.B] ISubstrate — VM 底座抽象（Substrate 组件对外入口）
//
// 设计来源：docs/channel-redesign/v3/10_substrate.md
//
// 职责边界：
//   - Target 生命周期：StartVM/StopVM/RebootVM/IsVMAlive
//   - 工件投递：CopyFileTo / RunCommand
//   - Worker 生命周期：DeployArtifacts / StartAllWorkers / StartWorker 等
//   - 端点导出：DefaultConsoleEndpoint（Evidence 默认入口）+ Hints（CP/DP 装配用）
//
// 非职责：
//   - 不知道 target 里跑什么（worker binary 仅以 DeployBundle 形式存在）
//   - 不知道通过什么和 target 通信（CP/DP 的事）
//
// 与 v2 的关系：
//   - v2 `runtime::Runtime` 仍然存在；Phase 2 会让 `Runtime` 实现 ISubstrate
//     （或提供 `class Runtime : public ISubstrate` 的薄继承）
//   - 本文件是 Phase 1.B 的骨架；实现方法签名尽量与 v2 `Runtime` 保持一致，
//     用 `DefaultConsoleEndpoint` 取代 v2 `SerialSocketPath`（v3 Phase 10 已删）、
//     `Hints` 新增。

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"
#include "refuzz/channel/runtime/vendor_hints.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::channel::runtime {

// ISubstrate — v3 Substrate 组件对外抽象
//
// 所有方法按 (vm_index, worker_id) 寻址；当前仅支持 vm_index=0（保留多实例接口形）。
class ISubstrate {
public:
    virtual ~ISubstrate() = default;

    // ───── VM 生命周期 ─────
    virtual Result<void> StartVM(uint32_t vm_index) = 0;
    virtual void         StopVM(uint32_t vm_index) = 0;
    virtual Result<void> RebootVM(uint32_t vm_index) = 0;
    virtual bool         IsVMAlive(uint32_t vm_index) const = 0;

    // ───── 生命周期（显式释放）─────
    //
    // 语义：停所有 worker、停 VM、释放底座资源；幂等
    virtual Result<void> Close() = 0;

    // ───── 工件投递 + 命令执行 ─────
    virtual Result<void> CopyFileTo(uint32_t                  vm_index,
                                    const std::string&        local_path,
                                    const std::string&        remote_path,
                                    std::chrono::milliseconds timeout) = 0;

    virtual Result<std::string> RunCommand(uint32_t                  vm_index,
                                           const std::string&        cmd,
                                           std::chrono::milliseconds timeout) = 0;

    // ───── Worker 生命周期 ─────
    //
    // DeployArtifacts：业务知识由 Channel 在装配时组织成 DeployBundle 传入；
    //                 Substrate 只负责把文件送到 target + 生成可启动命令。
    virtual Result<void> DeployArtifacts(uint32_t              vm_index,
                                         const DeployBundle&   bundle) = 0;

    virtual Result<void> StartAllWorkers(uint32_t vm_index) = 0;
    virtual Result<void> StopAllWorkers(uint32_t vm_index) = 0;
    virtual Result<void> StartWorker(uint32_t vm_index, uint32_t worker_id) = 0;
    virtual Result<void> StopWorker(uint32_t vm_index, uint32_t worker_id) = 0;

    // ───── 端点 + Hints（Evidence + CP/DP 装配依赖）─────
    //
    // DefaultConsoleEndpoint：v3 Evidence 的默认入口；不承诺协议，只告诉"默认入口"
    //                        （v2 SerialSocketPath 已于 Phase 10 删除，由本 API 取代）
    // Hints：底座启动后已固定的、可供 CP/DP 连接的低层端点（ivshmem_path / vsock_cid ...）
    //
    // 注意：Hints 在 Prepare() 后就应该可返回（Start 前），这样 Assembler 在启动 VM
    //       之前就能用 hints 构造 CP/DP。具体由实现保证（见 10_substrate.md §5）。
    virtual evidence::ConsoleEndpoint
                         DefaultConsoleEndpoint(uint32_t vm_index) const = 0;
    virtual VendorHints  Hints(uint32_t vm_index) const = 0;

    // ───── 诊断 ─────
    //
    // Diagnose：返回当前底座状态字符串（PID / 端口 / 启动参数 / ...）；故障现场收集用
    virtual std::string  Diagnose(uint32_t vm_index) const = 0;
};

} // namespace refuzz::channel::runtime
