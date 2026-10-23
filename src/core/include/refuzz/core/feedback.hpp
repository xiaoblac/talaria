// Copyright 2026 reFuzz project author -------youngkk.
//
// Compile-time evaluator combinators for FeedbackScore.
// Used internally by feedback engines that want to compose evaluators;
// not part of the Manager/Engine public API.

#pragma once

#include "refuzz/feedback/feedback.hpp"

#include <tuple>
#include <utility>

namespace refuzz::core {

inline refuzz::fuzzer::FeedbackScore MergeScoreOr(refuzz::fuzzer::FeedbackScore lhs,
                                                   const refuzz::fuzzer::FeedbackScore& rhs)
{
    lhs.interesting = lhs.interesting || rhs.interesting;
    lhs.is_crash = lhs.is_crash || rhs.is_crash;
    lhs.is_timeout = lhs.is_timeout || rhs.is_timeout;
    lhs.is_exec_error = lhs.is_exec_error || rhs.is_exec_error;
    lhs.is_malformed = lhs.is_malformed || rhs.is_malformed;
    lhs.is_coverage_empty = lhs.is_coverage_empty || rhs.is_coverage_empty;
    lhs.cov_gain += rhs.cov_gain;
    return lhs;
}

template<typename... Feedbacks>
struct OrFeedback {
    std::tuple<Feedbacks...> feedbacks_;

    explicit OrFeedback(Feedbacks... fbs)
        : feedbacks_(std::move(fbs)...)
    {
    }

    refuzz::fuzzer::FeedbackScore Evaluate(const refuzz::fuzzer::Observation& obs)
    {
        refuzz::fuzzer::FeedbackScore merged{};
        merged.interesting = false;
        std::apply(
            [&](auto&... fb) {
                ((merged = MergeScoreOr(merged, fb.Evaluate(obs))), ...);
            },
            feedbacks_);
        return merged;
    }

    bool IsInteresting(const refuzz::fuzzer::Observation& obs) { return Evaluate(obs).interesting; }
};

template<typename... Feedbacks>
struct AndFeedback {
    std::tuple<Feedbacks...> feedbacks_;

    explicit AndFeedback(Feedbacks... fbs)
        : feedbacks_(std::move(fbs)...)
    {
    }

    refuzz::fuzzer::FeedbackScore Evaluate(const refuzz::fuzzer::Observation& obs)
    {
        refuzz::fuzzer::FeedbackScore merged{};
        merged.interesting = true;
        std::apply(
            [&](auto&... fb) {
                ((merged.interesting = merged.interesting && fb.Evaluate(obs).interesting), ...);
            },
            feedbacks_);
        return merged;
    }

    bool IsInteresting(const refuzz::fuzzer::Observation& obs) { return Evaluate(obs).interesting; }
};

template<typename... Fbs>
auto MakeOrFeedback(Fbs... fbs)
{
    return OrFeedback<Fbs...>(std::move(fbs)...);
}

template<typename... Fbs>
auto MakeAndFeedback(Fbs... fbs)
{
    return AndFeedback<Fbs...>(std::move(fbs)...);
}

} // namespace refuzz::core
