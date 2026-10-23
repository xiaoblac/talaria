#pragma once

#include "refuzz/feedback/feedback.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <algorithm>
#include <tuple>
#include <utility>

namespace refuzz::core {

// v2 observers: Observe(ChannelEvent, FeedbackDelta). Merges cov_hashes (union), flags (|), code (max severity).
template<typename... Observers>
struct ObserverSet {
    std::tuple<Observers...> observers_;

    explicit ObserverSet(Observers... obs)
        : observers_(std::move(obs)...)
    {
    }

    void PreExecAll()
    {
        std::apply([](auto&... obs) { (ResetIf(obs), ...); }, observers_);
    }

private:
    template<typename O>
    static void ResetIf(O& o)
    {
        if constexpr (requires { o.Reset(); }) {
            o.Reset();
        }
    }

public:

    refuzz::fuzzer::Observation PostExecAll(const refuzz::core::channel_contract::ChannelEvent& event,
                                              const proto::FeedbackDelta& decoded)
    {
        return PostExecImpl(event, decoded, std::index_sequence_for<Observers...>{});
    }

    template<size_t I>
    auto& Get()
    {
        return std::get<I>(observers_);
    }

    static constexpr size_t kCount = sizeof...(Observers);

private:
    template<size_t... Is>
    refuzz::fuzzer::Observation PostExecImpl(const refuzz::core::channel_contract::ChannelEvent& event,
                                              const proto::FeedbackDelta& decoded,
                                              std::index_sequence<Is...>)
    {
        refuzz::fuzzer::Observation merged{};
        (void)((MergeInto(merged, std::get<Is>(observers_).Observe(event, decoded)), 0) + ...);
        return merged;
    }

    static void MergeInto(refuzz::fuzzer::Observation& dst, const refuzz::fuzzer::Observation& src)
    {
        dst.flags |= src.flags;
        if (static_cast<int>(src.code) > static_cast<int>(dst.code)) {
            dst.code = src.code;
        }
        dst.cov_hashes.insert(dst.cov_hashes.end(), src.cov_hashes.begin(), src.cov_hashes.end());
        std::sort(dst.cov_hashes.begin(), dst.cov_hashes.end());
        dst.cov_hashes.erase(std::unique(dst.cov_hashes.begin(), dst.cov_hashes.end()),
                             dst.cov_hashes.end());
    }
};

} // namespace refuzz::core
