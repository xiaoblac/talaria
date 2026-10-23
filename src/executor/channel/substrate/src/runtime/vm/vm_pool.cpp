// vm_pool.cpp — MakeVmSubstratePoolOps 实现
//
// 返回 SubstratePoolOps，其 create_instance 工厂用 MakeVmInstanceOps
// 为每个新实例构造独立 SubstrateInstanceOps 函数表。
//
// 设计来源：docs/channel-redesign/components/runtime.md §2.3

#include "refuzz/channel/substrate/substrate.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"
#include "vm_instance.hpp"

namespace refuzz::channel::runtime {

SubstratePoolOps MakeVmSubstratePoolOps(const RuntimeInstanceConfig& template_cfg)
{
    SubstratePoolOps ops;

    // count：直接返回 1（pool_size 由 RuntimePool 管理，底座不感知）
    ops.count = []() -> uint32_t { return 1; };

    // create_instance：为传入的 RuntimeInstanceConfig 创建新的函数表
    // template_cfg 作为备份参数提供，实际由 RuntimePool::CreateInstance 传入完整 cfg
    ops.create_instance = [](const RuntimeInstanceConfig& cfg)
        -> refuzz::channel::Result<SubstrateInstanceOps>
    {
        // MakeVmInstanceOps 不会失败（参数校验由 RuntimePool 负责）
        auto instance_ops = substrate::vm::MakeVmInstanceOps(cfg);
        return refuzz::channel::Result<SubstrateInstanceOps>::Ok(
            std::move(instance_ops));
    };

    // close：VM 底座池级资源释放（plain 模式无池级资源；
    // doorbell server 由 QEMU 进程管理（ivshmem-doorbell device），Transport 仅作为客户端连接）
    ops.close = []() -> refuzz::channel::Result<void> {
        return refuzz::channel::Result<void>::Ok();
    };

    (void)template_cfg;  // template_cfg 保留供未来扩展（doorbell server 绑定等）

    return ops;
}

} // namespace refuzz::channel::runtime
