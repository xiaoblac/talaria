#pragma once

// Deprecated stub kept only for remaining compile-time includes outside the
// fuzz runtime. The stage pipeline tests and runtime chain have been removed.

#include "refuzz/core/error.hpp"
#include "refuzz/control/fuzzer_context.hpp"

#include <expected>
#include <string_view>

namespace refuzz::control {

// Phase 1B: stub stage (returns success). FuzzerLoop integration comes later.
class MutationalStage {
public:
    static constexpr std::string_view kName = "mutational";

    MutationalStage() = default;

    std::expected<void, refuzz::core::ComponentError> Perform(FuzzerContext& /*ctx*/)
    {
        return {};
    }
};

} // namespace refuzz::control
