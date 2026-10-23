#pragma once

// [v3 Phase 1.B] ConsoleEndpoint — Evidence 接口的"源描述符"
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §6
// Substrate 的 DefaultConsoleEndpoint() 返回，Assembler 可以覆盖。
// Sensor 永远只看 IConsoleSource*，看不见 endpoint（endpoint 在 Open 时消费掉）。

#include <cstdint>
#include <string>

namespace refuzz::channel::evidence {

struct ConsoleEndpoint {
    enum class Kind : uint8_t {
        kNone = 0,
        kUnixSocket,   // path = "/tmp/serial-XXXX.sock"
        kTcpSocket,    // path = "host:port"
        kFdBorrow,     // fd  = 外部传入（由 Substrate 或测试提供）
        kSshStream,    // path = "dmesg -Fw" 等流式命令；依赖 Substrate.run_command_stream
    };

    Kind        kind = Kind::kNone;
    std::string path;        // kUnixSocket / kTcpSocket / kSshStream 使用
    int         fd   = -1;   // kFdBorrow 使用；生命周期由提供方维护
};

} // namespace refuzz::channel::evidence
