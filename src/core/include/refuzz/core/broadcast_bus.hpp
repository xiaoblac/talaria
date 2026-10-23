#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace refuzz::core {

template<typename T>
class BroadcastBus {
public:
    struct DrainStats {
        size_t delivered = 0;
        size_t dropped = 0;
    };

    class Subscription {
    public:
        Subscription() = default;

        DrainStats Drain(std::vector<T>& out)
        {
            if (bus_ == nullptr) {
                return {};
            }
            return bus_->Drain(next_seq_, out);
        }

        bool HasBus() const
        {
            return bus_ != nullptr;
        }

    private:
        friend class BroadcastBus<T>;

        Subscription(const BroadcastBus<T>* bus, uint64_t next_seq)
            : bus_(bus)
            , next_seq_(next_seq)
        {}

        const BroadcastBus<T>* bus_ = nullptr;
        uint64_t next_seq_ = 0;
    };

    explicit BroadcastBus(size_t capacity = 256)
        : capacity_(capacity == 0 ? 1 : capacity)
    {}

    void Publish(T value)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (entries_.size() == capacity_) {
            entries_.pop_front();
            ++dropped_total_;
        }
        entries_.push_back(Entry{
            .seq = next_seq_++,
            .value = std::move(value),
        });
    }

    Subscription Subscribe() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t next_seq = entries_.empty() ? next_seq_ : entries_.front().seq;
        return Subscription(this, next_seq);
    }

    uint64_t DroppedTotal() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return dropped_total_;
    }

private:
    struct Entry {
        uint64_t seq = 0;
        T value{};
    };

    DrainStats Drain(uint64_t& next_seq, std::vector<T>& out) const
    {
        std::lock_guard<std::mutex> lock(mu_);

        DrainStats stats;
        if (entries_.empty()) {
            return stats;
        }

        const uint64_t earliest_seq = entries_.front().seq;
        const uint64_t latest_seq = entries_.back().seq;
        if (next_seq < earliest_seq) {
            stats.dropped = static_cast<size_t>(earliest_seq - next_seq);
            next_seq = earliest_seq;
        }

        if (next_seq > latest_seq) {
            return stats;
        }

        const uint64_t start_index = next_seq - earliest_seq;
        for (size_t index = static_cast<size_t>(start_index); index < entries_.size(); ++index) {
            out.push_back(entries_[index].value);
            ++stats.delivered;
        }
        next_seq = latest_seq + 1;
        return stats;
    }

    const size_t capacity_;
    mutable std::mutex mu_;
    mutable std::deque<Entry> entries_;
    uint64_t next_seq_ = 1;
    uint64_t dropped_total_ = 0;
};

} // namespace refuzz::core
