#pragma once

#include "refuzz/program/seed.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace refuzz::control {

// Shared across Stage::Perform; wired into FuzzerLoop in a later phase.
struct FuzzerContext {
    std::optional<refuzz::fuzzer::Seed> current_seed;
    std::vector<uint8_t> mutated_payload;
    uint64_t executor_id = 0;
    bool should_calibrate = false;
    bool is_interesting = false;
    size_t cov_gain = 0;
    uint64_t loop_iteration = 0;
};

} // namespace refuzz::control
