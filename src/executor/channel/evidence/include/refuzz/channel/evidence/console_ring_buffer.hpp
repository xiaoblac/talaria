// §3.11-B — ConsoleRingBuffer：一个跨 sensor 共享的 console 行循环缓冲。
//
// 背景（Bug #2）：HeartbeatSensor 检测到 worker heartbeat 卡住时，console
// 上往往已经有 rcu stall / softlockup / hung task / panic 等内核级证据，
// 但 HeartbeatSensor 现在不读 console（IConsoleSource 是单读路径，由
// ConsoleSensor 持续 ReadLine 消费）。结果：内核已经给的证据被丢弃，
// 事件被记成"worker dead 但无 console"。
//
// 设计：
//   - ConsoleSensor 在它每次成功 ReadLine 后把行 Push 进 ring buffer；
//   - HeartbeatSensor 在 worker_dead 检测命中时调 Snapshot(N) 取最近
//     N 行，把它们放进 CrashFragment.serial_lines/console_output；
//   - ring buffer 的容量是软上限（默认 200 行），写满则丢最老。
//
// 跨家族通用：未来 AFL / Postgres 等 target 的 sensor 也复用这个
// 抽象（"text-pattern 流" + "其它 sensor 抓取证据"）；ring buffer 跟
// 具体 console 协议解耦。
//
// 线程模型：MPSC（生产者：ConsoleSensor 主循环；消费者：HeartbeatSensor
// 检测线程 / 任意诊断 dump）。内部 mutex 保护即可，无锁不必要。

#pragma once

#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace refuzz::channel::evidence {

class ConsoleRingBuffer {
public:
    explicit ConsoleRingBuffer(std::size_t max_lines = 200) noexcept
        : max_lines_(max_lines == 0 ? 1 : max_lines) {}

    ConsoleRingBuffer(const ConsoleRingBuffer&)            = delete;
    ConsoleRingBuffer& operator=(const ConsoleRingBuffer&) = delete;

    // 单行追加。max_lines 上限触发即丢最老。
    void Push(std::string line) {
        std::lock_guard<std::mutex> lk(mu_);
        if (lines_.size() >= max_lines_) lines_.pop_front();
        lines_.push_back(std::move(line));
    }

    // 取最近 n 行。n > 实际数量则返回所有；0 返回空。
    std::vector<std::string> Snapshot(std::size_t n) const {
        std::vector<std::string> out;
        if (n == 0) return out;
        std::lock_guard<std::mutex> lk(mu_);
        const std::size_t take = std::min(n, lines_.size());
        out.reserve(take);
        const auto begin = lines_.end() - static_cast<std::ptrdiff_t>(take);
        for (auto it = begin; it != lines_.end(); ++it) out.push_back(*it);
        return out;
    }

    // 拼接最近 n 行为一个 string（行间 '\n'）。HeartbeatSensor 给
    // CrashFragment.console_output 用。空缓冲返回 ""。
    std::string SnapshotJoined(std::size_t n) const {
        auto snap = Snapshot(n);
        if (snap.empty()) return {};
        std::string out;
        // pre-size: every line + '\n'.
        std::size_t total = 0;
        for (const auto& s : snap) total += s.size() + 1;
        out.reserve(total);
        for (const auto& s : snap) {
            out.append(s);
            out.push_back('\n');
        }
        return out;
    }

    std::size_t Size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return lines_.size();
    }

    void Clear() {
        std::lock_guard<std::mutex> lk(mu_);
        lines_.clear();
    }

private:
    mutable std::mutex          mu_;
    std::deque<std::string>     lines_;
    const std::size_t           max_lines_;
};

} // namespace refuzz::channel::evidence
