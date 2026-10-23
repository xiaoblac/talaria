#pragma once

// refuzz/channel/worker/mode.hpp — host 侧 worker 运行模式枚举
//
// 职责边界：
//   仅定义 host 侧 consumer（crash 分析引擎 / Orchestrator 配置 / target toolkit
//   Build 参数）需要识别的 worker 运行模式（coverage / sanitizer）。
//   *不* 包含 worker 进程启动参数（binary 路径、cmd 模板、deploy timeout 等），
//   那些继续留在 worker/config/worker_config.hpp 中，属于 QemuChannel 的
//   实现域、只对 channel 内部可见。
//
// 置放位置：
//   `refuzz/channel/worker/` 公开头文件目录——与 `refuzz/channel/` 同属
//   refuzz_channel 目标的稳定公共 API。host 侧任何消费者（crash / control）
//   都应 include 本文件，而不是反向 include 到 `worker/config/worker_config.hpp`
//   （后者的路径仅对 worker binary 与 channel 内部生效）。
//
// 与 refuzz_crash / refuzz_control 的关系：
//   TargetToolkitBuildArgs::sanitizer_mode 使用本文件定义的枚举；
//   Orchestrator 从 OrchestratorConfig::target.sanitizer_mode 映射到这里的
//   值后传入 catalog.Build(ctx)。

#include <cstdint>

namespace refuzz::channel::worker {

enum class WorkerCoverageMode : uint8_t {
    kNone = 0,
    kKcov = 1,
};

enum class WorkerSanitizerMode : uint8_t {
    kNone = 0,
    kKasan = 1,
    kKcsan = 2,
    kUbsan = 3,
};

// worker child 进程隔离模式。host-side consumer (config_parser) 把这个枚举
// 映射成 CLI "--sandbox <none|setuid|namespace>" 追加到 worker_start_cmd。
// 实际的隔离动作由 worker binary 内的 worker::ApplySandbox 执行。
enum class WorkerSandboxMode : uint8_t {
    kNone      = 0,
    kSetuid    = 1,
    kNamespace = 2,
};

} // namespace refuzz::channel::worker
