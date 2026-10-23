#pragma once

#include <string_view>

namespace refuzz::core {

class IPolicyControl {
public:
    virtual ~IPolicyControl() = default;
    virtual void SwitchMutationPolicy(std::string_view name) = 0;
    virtual void SwitchSchedulingPolicy(std::string_view name) = 0;
    virtual void SwitchCorpusAdmissionPolicy(std::string_view name) = 0;
};

} // namespace refuzz::core
