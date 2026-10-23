// RecycleChildTopology: 显式 fork-per-N-program 策略。
//
// 跟 ReusableChildTopology 的运行时原语一致，区别在**API 语义**和
// **Setup 校验**；周期阈值和 stop/start 由 DomainSupervisor 统一处理:
//   - ReusableChildTopology 默认意图是"长 child 复用"(recycle_after=0 unlimited
//     或大 N 作为软回收 safety net,如 ivshmem 600)
//   - RecycleChildTopology 显式声明"每 N 条 prog 重启",Setup 时强制
//     recycle_after >= 1,catch 配置错误
//
// 作为 ReusableChildTopology 的 subclass(继承 Setup/Dispatch/Collect/Stop
// 全部实现),只 override Setup 加 validation。未来若需要 per-cycle teardown
// hook / N-batch admit 等扩展,这里是落脚点。
//
// stdio oracle profile 默认用本 topology(精确反映 fork-per-program 隔离意图);
// ivshmem 生产 profile 仍用 Reusable + recycle_after=600 长 child 复用。

#pragma once

#include "worker/topology/reusable_child_topology.hpp"

namespace refuzz::worker::topology {

class RecycleChildTopology : public ReusableChildTopology {
public:
    RecycleChildTopology(::refuzz::worker::IExecBackend& backend,
                         ::refuzz::worker::IObservationBus& bus);

    // Setup 强制 recycle_after >= 1,否则返回 rejected 拒绝启动。
    // 其它行为继承自 ReusableChildTopology。
    DomainStartResult Setup(const TopologyConfig& cfg) override;
};

} // namespace refuzz::worker::topology
