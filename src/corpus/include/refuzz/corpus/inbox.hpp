#pragma once

#include "refuzz/program/seed.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <queue>
#include <utility>
#include <vector>

namespace refuzz::fuzzer {

template <typename T>
class MutexInbox {
public:
    explicit MutexInbox(size_t cap = 256)
        : cap_(cap)
    {}

    bool TryPush(T item)
    {
        std::unique_lock<std::mutex> lk(mtx_, std::try_to_lock);
        if (!lk || q_.size() >= cap_) {
            return false;
        }
        q_.push(std::move(item));
        return true;
    }

    bool TryPop(T& out)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (q_.empty()) {
            return false;
        }
        out = std::move(q_.front());
        q_.pop();
        return true;
    }

private:
    std::mutex mtx_;
    std::queue<T> q_;
    size_t cap_ = 256;
};

using CorpusInbox = MutexInbox<Seed>;

struct CrashEvent {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    proto::ResultCode code = proto::ResultCode::kCrashed;
    std::vector<uint8_t> output;
};

struct CrashRecord {
    uint64_t executor_id = 0;
    uint64_t seed_id = 0;
    proto::ResultCode code = proto::ResultCode::kCrashed;
    uint64_t output_hash = 0;
    uint64_t timestamp_us = 0;
};

using CrashInbox = MutexInbox<CrashEvent>;

} // namespace refuzz::fuzzer
