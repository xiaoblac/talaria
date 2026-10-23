#pragma once

#include "refuzz/core/error.hpp"
#include "refuzz/core/fuzzer_concepts.hpp"

#include <expected>
#include <tuple>
#include <utility>

namespace refuzz::core {

template<typename Context, typename... Stages>
    requires(StageLike<Stages, Context> && ...)
struct StagePipeline {
    std::tuple<Stages...> stages_;

    explicit StagePipeline(Stages... stages)
        : stages_(std::move(stages)...)
    {
    }

    std::expected<void, ComponentError> Run(Context& ctx)
    {
        return std::apply(
            [&](auto&... stages) -> std::expected<void, ComponentError> {
                std::expected<void, ComponentError> r{};
                (void)((r = stages.Perform(ctx), r.has_value()) && ...);
                return r;
            },
            stages_);
    }

    template<size_t I>
    auto& GetStage()
    {
        return std::get<I>(stages_);
    }

    static constexpr size_t kStageCount = sizeof...(Stages);
};

template<typename Context, typename... Stages>
auto MakePipeline(Stages... stages)
{
    return StagePipeline<Context, Stages...>(std::move(stages)...);
}

} // namespace refuzz::core
