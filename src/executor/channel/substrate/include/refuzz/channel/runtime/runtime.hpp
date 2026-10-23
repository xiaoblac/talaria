#pragma once

// Runtime — channel/runtime 对外唯一暴露的统一控制器（design.md §16.4.1）。
//
// 对上层（QemuChannel / Recovery / Health）暴露按 (vm_index, worker_index) 寻址的
// VM 和 worker 生命周期操作。内部持有 RuntimePool + RuntimeInstance，不对外暴露。
//
// 两种构造路径：
//   1. Runtime::Create(RuntimeConfig, SubstratePoolOps, WorkerConfig)
//      — 完整生命周期管理：内部创建 pool + instance
//   2. Runtime(RuntimeInstance*)
//      — 向后兼容包装：非拥有模式，调用方保证 instance 生命周期覆盖 Runtime
//
// 当前仅支持 vm_index=0（单 VM 设计）；不合法 index 返回 kConfig 错误。
//
// 设计来源：channel/runtime/design.md §16

#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"
#include "refuzz/channel/runtime/vendor_hints.hpp"
#include "refuzz/channel/substrate/substrate.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"
#include "worker/config/worker_config.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace refuzz::channel::runtime {

class RuntimePool;
class RuntimeInstance;

// [v3.5 Phase B] Runtime 显式实现 ISubstrate 接口。
// ISubstrate 定义于 substrate/substrate_contract.hpp；Channel 只依赖 ISubstrate，
// 不感知 Runtime 具体类。Runtime 保留 MonitorEndpoint / DeployWorker 等底座专属能力，
// 这些不出现在 ISubstrate 抽象中。
class Runtime : public ISubstrate {
public:
    // ── 完整构造路径（拥有 pool + instance）──────────────────────
    static Result<std::unique_ptr<Runtime>> Create(
        RuntimeConfig        config,
        SubstratePoolOps     substrate_ops,
        worker::WorkerConfig worker_cfg);

    // ── 向后兼容包装（非拥有，caller 保证 instance 生命周期）─────
    explicit Runtime(RuntimeInstance* instance);

    ~Runtime() override;

    Runtime(const Runtime&)            = delete;
    Runtime& operator=(const Runtime&) = delete;

    // ── VM 生命周期（按 vm_index 寻址，实现 ISubstrate）────────
    Result<void> StartVM(uint32_t vm_index)   override;
    void         StopVM(uint32_t vm_index)    override;
    Result<void> RebootVM(uint32_t vm_index)  override;
    bool         IsVMAlive(uint32_t vm_index) const override;

    // ── 生命周期（拥有路径显式释放，实现 ISubstrate） ─────────────
    // 拥有路径：Stop 实例 + pool_->Close() + 释放资源。
    // 包装路径：仅解除本对象对外部实例的引用（不接管外部生命周期）。
    Result<void> Close() override;

    // ── Worker 生命周期（按 vm_index + worker_id 寻址）─────────
    //
    // [DEPRECATED v3] DeployWorker 走 WorkerConfig 内置路径；保留给旧 QemuChannel 用。
    // 新代码请使用 DeployArtifacts(vm, bundle)。Phase E 移除。
    Result<void> DeployWorker(uint32_t vm_index);

    // [v3 Phase 2] 按 DeployBundle 部署一组 host 文件并可选覆盖启动模板。
    Result<void> DeployArtifacts(uint32_t vm_index, const DeployBundle& bundle) override;

    Result<void> StartAllWorkers(uint32_t vm_index)                         override;
    Result<void> StopAllWorkers(uint32_t vm_index)                          override;
    Result<void> StartWorker(uint32_t vm_index, uint32_t worker_id)         override;
    Result<void> StopWorker(uint32_t vm_index, uint32_t worker_id)          override;

    // ── 诊断与端点导出（实现 ISubstrate）──────────────────────
    //
    // [v3 Phase 2] 默认控制台 endpoint 描述符（Kind + path/fd）；Evidence
    // Assembler 基于此装配 IConsoleSource。VM 底座返回 kUnixSocket + path。
    evidence::ConsoleEndpoint DefaultConsoleEndpoint(uint32_t vm_index) const override;

    // [v3 Phase 2] 底座启动后固定的低层端点快照；Channel / Health / Recovery
    // 不得消费；仅 ControlPlane / DataPlane / ConsoleSource 的底座专用实现读。
    VendorHints Hints(uint32_t vm_index) const override;

    std::string Diagnose(uint32_t vm_index) const override;

    // ── Runtime 专属（不在 ISubstrate 中）─────────────────────
    //
    // MonitorEndpoint：QMP monitor 端点（仅 QEMU 底座有意义；其他底座可能返回空串）。
    std::string MonitorEndpoint(uint32_t vm_index) const;

    // ── SSH 透传（实现 ISubstrate）─────────────────────────────
    Result<void> CopyFileTo(uint32_t vm_index,
                            const std::string& local_path,
                            const std::string& remote_path,
                            std::chrono::milliseconds timeout) override;
    Result<std::string> RunCommand(uint32_t vm_index,
                                   const std::string& cmd,
                                   std::chrono::milliseconds timeout) override;

private:
    // ── 拥有模式成员（Create 路径）──────────────────────────────
    std::unique_ptr<RuntimePool>     pool_;
    std::unique_ptr<RuntimeInstance> owned_instance_;

    // ── 共享指针：始终指向活跃实例（拥有或包装）──────────────────
    RuntimeInstance* instance_ = nullptr;
    bool             closed_   = false;

    // ── 校验辅助 ───────────────────────────────────────────────
    Result<void> ValidateVmIndex(uint32_t vm_index) const;
};

} // namespace refuzz::channel::runtime
