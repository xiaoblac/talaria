#pragma once

#include "refuzz/program/prog_format.hpp"

#include <concepts>

namespace refuzz::core {

template<typename T>
concept InputLike = requires(const T& cprog) {
    { cprog.Format() } -> std::convertible_to<refuzz::fuzzer::ProgFormat>;
    requires std::constructible_from<T, T>;
    requires std::destructible<T>;
};

} // namespace refuzz::core
