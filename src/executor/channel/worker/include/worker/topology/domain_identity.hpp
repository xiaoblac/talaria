#pragma once

#include <cstdint>
#include <optional>

namespace refuzz::worker::topology {

inline constexpr uint32_t kMaxProcIds = 32;
inline constexpr uint32_t kAnyProcId = UINT32_MAX;

struct DomainIdentity {
    uint32_t worker_id = 0;
    uint32_t proc_id = 0;
    uint32_t proc_epoch = 0;
};

// Guest workers are separate processes, so each stable worker owns a disjoint
// proc-id lane: worker_id + k * worker_count. Rotating within a lane cannot
// collide with another live worker and quarantines old resource IDs until the
// lane wraps.
class ProcIdLane {
public:
    ProcIdLane(uint32_t worker_id, uint32_t worker_count,
               uint32_t capacity = kMaxProcIds)
        : worker_id_(worker_id),
          worker_count_(worker_count),
          capacity_(capacity)
    {}

    bool Valid() const
    {
        return worker_count_ != 0 && worker_id_ < worker_count_ &&
               worker_id_ < capacity_ && capacity_ <= kMaxProcIds;
    }

    bool Owns(uint32_t proc_id) const
    {
        return Valid() && proc_id < capacity_ &&
               proc_id % worker_count_ == worker_id_;
    }

    uint32_t Initial() const { return worker_id_; }

    uint32_t Next(uint32_t current) const
    {
        if (!Owns(current)) {
            return Initial();
        }
        const uint32_t candidate = current + worker_count_;
        return candidate < capacity_ ? candidate : Initial();
    }

    bool IsDirty(uint32_t proc_id, uint32_t dirty_proc_mask) const
    {
        return proc_id < kMaxProcIds &&
               (dirty_proc_mask & (uint32_t{1} << proc_id)) != 0;
    }

    std::optional<uint32_t> FirstClean(uint32_t dirty_proc_mask) const
    {
        if (!Valid()) {
            return std::nullopt;
        }
        for (uint32_t candidate = Initial(); candidate < capacity_;
             candidate += worker_count_) {
            if (!IsDirty(candidate, dirty_proc_mask)) {
                return candidate;
            }
        }
        return std::nullopt;
    }

    std::optional<uint32_t> NextClean(uint32_t current,
                                      uint32_t dirty_proc_mask) const
    {
        if (!Valid()) {
            return std::nullopt;
        }
        if (!Owns(current)) {
            return FirstClean(dirty_proc_mask);
        }

        uint32_t candidate = current;
        do {
            candidate = Next(candidate);
            if (!IsDirty(candidate, dirty_proc_mask)) {
                return candidate;
            }
        } while (candidate != current);
        return std::nullopt;
    }

    uint32_t WorkerFor(uint32_t proc_id) const
    {
        return worker_count_ == 0 ? 0 : proc_id % worker_count_;
    }

    uint32_t capacity() const { return capacity_; }

private:
    uint32_t worker_id_;
    uint32_t worker_count_;
    uint32_t capacity_;
};

} // namespace refuzz::worker::topology
