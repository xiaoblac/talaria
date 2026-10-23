#pragma once

namespace refuzz::crash {

class IReproPolicy {
public:
    virtual ~IReproPolicy() = default;
};

} // namespace refuzz::crash
