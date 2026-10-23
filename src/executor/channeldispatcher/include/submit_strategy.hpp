// Copyright 2026 reFuzz project author -------youngkk.
//
// [Phase H] ISubmitStrategy — Executor 多 channel 提交顺序策略
//
// 设计目的:把"按什么顺序尝试多个 channel"与"真正调 Submit + 重试控制"解耦。
//   - Executor 负责:Pop task、循环调 Submit、等待唤醒、统计日志、无限重试
//   - Strategy 负责:给出"这一轮应该按什么顺序尝试哪些 channel"
//
// 当前只有 RoundRobinStrategy(保持既有行为)。未来可扩展:
//   - LeastLoadedStrategy:按 channel 的最近 busy 率 / pending 深度排序
//   - StickyAffinityStrategy:同一 seed 尽量回到同一 channel(缓存命中)
//   - GenerationAwareStrategy:偏好 generation 较新的 channel(避开刚 reboot 的)
//
// 关键边界:
//   - Strategy 不持有 Channel 指针,不调 Submit
//   - Strategy 只读 ChannelView 里的元信息(channel_id + 未来更多 hint 字段)
//   - Strategy 不在热路径返回 order vector;executor 逐个拉取下一个 index
//   - Strategy 的状态更新由 executor 在特定时刻显式驱动,方便测试

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace refuzz {
namespace channeldispatcher {

// 提供给 Strategy 的 channel 元信息视图(不含指针,只有可观测元数据)
// 目前只有 channel_id,随着未来策略扩展再往这里加 hint 字段
// (如 recent_busy_rate, inflight_count, generation)。
struct ChannelView {
    uint32_t channel_id = 0;
};

// Submit 循环一轮结束后反馈给 strategy 的结果(用于状态更新)
enum class SubmitCycleOutcome {
    kAccepted,      // 某个 channel accept 了任务
    kAllBusy,       // 全部 channel 返回 kBusy
    kAnyRejected,   // 有 kUnavailable/kInvalid 但没有 kAccepted
};

class ISubmitStrategy {
public:
    virtual ~ISubmitStrategy() = default;

    // 开始一轮 submit 遍历。实现只保存本轮必要游标,不得分配 order vector。
    virtual void BeginCycle(const std::vector<ChannelView>& channels) = 0;

    // 拉取本轮下一个 channel index。返回 false 表示本轮遍历结束。
    virtual bool NextIndex(size_t* out_idx) = 0;

    // 某个 channel accepted 了,回调告知。strategy 可更新自己的光标/计数。
    //   accepted_idx:channels 向量里的绝对索引。
    virtual void OnAccepted(size_t accepted_idx) = 0;

    // 某轮结束后反馈整轮结果(除 kAccepted 外的路径也需要状态更新)
    virtual void OnCycleEnd(SubmitCycleOutcome outcome) = 0;

    // 策略名(观测/日志用)
    virtual const char* Name() const = 0;
};

// RoundRobinStrategy — 默认策略,等价于 Phase G 的硬编码 RR 行为
//   - 维护一个光标 cursor_,BeginCycle 从 cursor_ 开始环形遍历所有索引
//   - OnAccepted:cursor_ = accepted_idx + 1
//   - OnCycleEnd:不做额外动作(全部 busy 时光标不变,下一轮从同一位置再试)
class RoundRobinStrategy : public ISubmitStrategy {
public:
    void BeginCycle(const std::vector<ChannelView>& channels) override
    {
        cycle_size_ = channels.size();
        cycle_offset_ = 0;
        if (cycle_size_ == 0) {
            cycle_start_ = 0;
        } else {
            cycle_start_ = cursor_ % cycle_size_;
        }
    }

    bool NextIndex(size_t* out_idx) override
    {
        if (out_idx == nullptr || cycle_offset_ >= cycle_size_) {
            return false;
        }
        *out_idx = (cycle_start_ + cycle_offset_) % cycle_size_;
        ++cycle_offset_;
        return true;
    }

    void OnAccepted(size_t accepted_idx) override
    {
        cursor_ = accepted_idx + 1;
    }

    void OnCycleEnd(SubmitCycleOutcome /*outcome*/) override
    {
        // RR 不需要根据 cycle outcome 调整状态。
        // 子类或其他策略若需要 backoff/priority 调整可重写这里。
    }

    const char* Name() const override { return "round_robin"; }

private:
    size_t cursor_ = 0;
    size_t cycle_start_ = 0;
    size_t cycle_size_ = 0;
    size_t cycle_offset_ = 0;
};

} // namespace channeldispatcher
} // namespace refuzz
