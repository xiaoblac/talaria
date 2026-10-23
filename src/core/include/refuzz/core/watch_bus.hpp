#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <utility>

namespace refuzz::core {

template<typename T>
class WatchBus {
public:
    class Subscription {
    public:
        Subscription() = default;

        bool TryConsume(T& out)
        {
            if (bus_ == nullptr) {
                return false;
            }
            return bus_->TryConsume(seen_version_, out);
        }

        bool HasBus() const
        {
            return bus_ != nullptr;
        }

    private:
        friend class WatchBus<T>;

        explicit Subscription(const WatchBus<T>* bus)
            : bus_(bus)
        {}

        const WatchBus<T>* bus_ = nullptr;
        uint64_t seen_version_ = 0;
    };

    WatchBus() = default;

    void Publish(T value)
    {
        std::lock_guard<std::mutex> lock(mu_);
        latest_ = std::move(value);
        ++version_;
    }

    Subscription Subscribe() const
    {
        return Subscription(this);
    }

private:
    bool TryConsume(uint64_t& seen_version, T& out) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!latest_.has_value() || version_ <= seen_version) {
            return false;
        }
        out = *latest_;
        seen_version = version_;
        return true;
    }

    mutable std::mutex mu_;
    std::optional<T> latest_;
    uint64_t version_ = 0;
};

} // namespace refuzz::core
