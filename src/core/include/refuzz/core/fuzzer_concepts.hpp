#pragma once

#include "refuzz/core/error.hpp"
#include "refuzz/core/program_input_concept.hpp"

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/fuzzer/seed_selection.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <concepts>
#include <cstddef>
#include <expected>
#include <random>
#include <string_view>
#include <utility>

namespace refuzz::core {

using StageError = ComponentError;

template<typename T, typename Context>
concept StageLike = requires(T stage, Context& ctx) {
    { stage.Perform(ctx) } -> std::same_as<std::expected<void, StageError>>;
    { T::kName } -> std::convertible_to<std::string_view>;
};

template<typename T>
concept SchedulerLike = requires(T& sched, uint64_t seed_id, refuzz::fuzzer::SeedDisposition d) {
    { sched.NextSeedId() } -> std::same_as<std::optional<refuzz::fuzzer::SeedSelection>>;
    { sched.OnFeedback(seed_id, d) } -> std::same_as<void>;
    { sched.OnSeedAdded(seed_id) } -> std::same_as<void>;
};

template<typename T, typename Seed>
concept CorpusLike = requires(T& corpus, const T& const_corpus, Seed seed, uint64_t id, std::mt19937_64& rng) {
    { corpus.AddSeed(std::move(seed)) } -> std::convertible_to<bool>;
    { const_corpus.GetSeed(id) } -> std::same_as<refuzz::fuzzer::SeedHandle>;
    { const_corpus.ForEachSeed(std::declval<refuzz::fuzzer::SeedVisitor>()) } -> std::same_as<void>;
    { const_corpus.SampleSeedId(rng) } -> std::same_as<std::optional<uint64_t>>;
    { corpus.Size() } -> std::convertible_to<size_t>;
};

template<typename T, typename Event>
concept EventTransport = requires(T& em, Event event) {
    { em.Fire(event) } -> std::same_as<void>;
    { em.TryReceive() } -> std::same_as<std::optional<Event>>;
    { em.ShouldForwardToOthers() } -> std::same_as<bool>;
};

} // namespace refuzz::core
