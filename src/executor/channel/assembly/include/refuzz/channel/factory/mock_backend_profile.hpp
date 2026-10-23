#pragma once

// mock_backend_profile.hpp — MockBackendProfile
//
// 为 MockAssembler 服务的 backend profile 实现（BackendId() = "mock"）。
//
// 存在意义：让 MockAssembler 与 QemuIvshmemLinuxAssembler 同构走
// IChannelBackendProfile 路径，不给 Mock 开后门。
//
// 行为开关（cp_reject_begin_session / dp_reject_trysend / health_inject_crash
// / recovery_always_fail / fake_handshake_delay / ...）按需追加；当前 mock
// 仅需 echo 路径，字段留白避免过度设计。

#include "refuzz/channel/factory/channel_backend_profile.hpp"

#include <string_view>

namespace refuzz::channel::factory {

struct MockBackendProfile : public IChannelBackendProfile {
    // 行为开关与时间注入字段按需追加

    std::string_view BackendId() const noexcept override {
        return "mock";
    }
};

} // namespace refuzz::channel::factory
