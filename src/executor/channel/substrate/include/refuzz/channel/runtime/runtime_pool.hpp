#pragma once

// RuntimePool — VM 实例池
//
// 职责：
//   持有底座 ops 表，工厂创建 RuntimeInstance，池资源回收。
//   不直接管理 worker pid，不参与命令执行。
//
// 使用方式：
//   // 生产
//   auto pool = RuntimePool::Create(cfg, MakeVmSubstratePoolOps(cfg.instance));
//   auto inst = pool->CreateInstance(worker_cfg);
//   // 测试
//   auto pool = RuntimePool::Create(cfg, mock_ops);
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.1

#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"
#include "refuzz/channel/substrate/substrate.hpp"
#include "worker/config/worker_config.hpp"

#include <memory>

namespace refuzz::channel::runtime {

class RuntimeInstance;

class RuntimePool {
public:
    // ── 唯一工厂函数 ─────────────────────────────────────────
    // 校验 cfg（§5 校验矩阵），失败返回 kConfig 错误。
    // substrate_ops 显式注入：生产传 MakeVmSubstratePoolOps()，测试传 mock ops。
    static Result<std::unique_ptr<RuntimePool>> Create(
        RuntimePoolConfig  cfg,
        SubstratePoolOps   substrate_ops);

    ~RuntimePool();

    RuntimePool(const RuntimePool&) = delete;
    RuntimePool& operator=(const RuntimePool&) = delete;

    // ── 实例创建 ─────────────────────────────────────────────
    // 创建单个 RuntimeInstance，注入 worker_cfg（来自 QemuChannel）。
    // 调用方负责保证 worker_cfg.worker_binary_host_path 存在。
    Result<std::unique_ptr<RuntimeInstance>> CreateInstance(
        const RuntimeInstanceConfig&      instance_cfg,
        const worker::WorkerConfig&       worker_cfg);

    // ── 查询 ─────────────────────────────────────────────────
    uint32_t Count() const;  // pool_size

    // ── 生命周期 ─────────────────────────────────────────────
    Result<void> Close();

private:
    explicit RuntimePool(RuntimePoolConfig cfg, SubstratePoolOps ops);

    RuntimePoolConfig  config_;
    SubstratePoolOps   substrate_ops_;
    bool               closed_ = false;
};

} // namespace refuzz::channel::runtime
