#pragma once

// [v3 Phase 3] IvshmemStepEventSource — 基于 ShmInfra 的 IStepEventSource 实现
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §2.2 / 80_migration.md §4.1
//
// 职责：
//   - 作为 Evidence 侧"step event 环形缓冲快照"的 ivshmem-specific 实现
//   - 构造时接注入的 ShmInfra&，Snapshot() 直接委托 SnapshotStepEventRing()
//   - wire→record 转换由 ShmInfra 完成（Phase 3 已净化）；本类只负责 IStepEventSource 接口形状
//
// 非职责：
//   - 不负责 ShmInfra 生命周期（上层 Substrate 持有）
//   - 不做去重 / 过滤 / 聚合（上层 Sensor 或 Recovery 按需处理）

#include "refuzz/channel/evidence/step_event_source.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"

namespace refuzz::channel::evidence {

class IvshmemStepEventSource final : public IStepEventSource {
public:
    // 构造仅持有引用；不 own shm 生命周期
    explicit IvshmemStepEventSource(infra::ShmInfra& shm) noexcept
        : shm_(shm) {}

    // 线程安全只读快照；实现用 seq-counter 双读校验
    std::vector<StepEventRecord> Snapshot() const override {
        return shm_.SnapshotStepEventRing();
    }

    // ivshmem 实现永远可用（只要 ShmInfra::Init 成功）
    bool IsAvailable() const override { return shm_.initialized(); }

private:
    infra::ShmInfra& shm_;
};

} // namespace refuzz::channel::evidence
