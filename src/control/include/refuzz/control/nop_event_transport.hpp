#pragma once

#include "refuzz/core/fuzzer_concepts.hpp"

#include <optional>

namespace refuzz::control {

struct FuzzerEvent {
    enum class Kind : uint8_t {
        kNewInteresting = 1,
        kCrashFound     = 2,
        kPolicySwitch   = 3,
    };
    Kind kind{};
    uint64_t seed_id = 0;
};

struct NopEventTransport {
    void Fire(FuzzerEvent) {}
    std::optional<FuzzerEvent> TryReceive() { return std::nullopt; }
    bool ShouldForwardToOthers() { return false; }
};

static_assert(refuzz::core::EventTransport<NopEventTransport, FuzzerEvent>);

} // namespace refuzz::control
