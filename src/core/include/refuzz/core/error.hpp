#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace refuzz::core {

enum class ErrorKind : uint8_t {
    kConfig     = 1,
    kInit       = 2,
    kRuntime    = 3,
    kTimeout    = 4,
    kDependency = 5,
    kShutdown   = 6,
    kInternal   = 7,
};

struct ComponentError {
    ErrorKind   kind = ErrorKind::kInternal;
    std::string message;
    std::string component;

    static ComponentError Config(std::string_view comp, std::string_view msg)
    {
        return {ErrorKind::kConfig, std::string(msg), std::string(comp)};
    }
    static ComponentError Init(std::string_view comp, std::string_view msg)
    {
        return {ErrorKind::kInit, std::string(msg), std::string(comp)};
    }
    static ComponentError Runtime(std::string_view comp, std::string_view msg)
    {
        return {ErrorKind::kRuntime, std::string(msg), std::string(comp)};
    }
};

using ServiceResult = std::expected<void, ComponentError>;

template<typename T>
using Result = std::expected<T, ComponentError>;

} // namespace refuzz::core
