#pragma once

#include "refuzz/core/error.hpp"
#include "refuzz/control/fuzzer_context.hpp"

#include <expected>
#include <string_view>

namespace refuzz::control {

class CalibrationStage {
public:
    static constexpr std::string_view kName = "calibration";

    CalibrationStage() = default;

    std::expected<void, refuzz::core::ComponentError> Perform(FuzzerContext& /*ctx*/)
    {
        return {};
    }
};

} // namespace refuzz::control
