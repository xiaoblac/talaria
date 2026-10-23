#pragma once

// 执行结果队列（无多态）；若管线仍需要「结果」路径时使用本类型。

#include "refuzz/proto_domain/types.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::queue {

class InMemoryResultQueue final {
public:
    bool Push(proto::ExecResult result);
    std::optional<proto::ExecResult> Pop(std::chrono::milliseconds timeout);
    void Close();

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<proto::ExecResult> queue_;
    bool closed_ = false;
};

} // namespace refuzz::queue
