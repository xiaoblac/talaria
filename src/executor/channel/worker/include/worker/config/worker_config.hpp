#pragma once

// WorkerConfig — host 侧 worker binary 部署与启动配置
//
// 职责边界：
//   描述"如何将 ivshmem_worker binary 部署到 VM 内并启动进程"。
//   与 RuntimeInstanceConfig 分离——Runtime 不直接知道 worker 路径，
//   由 QemuChannel 持有 WorkerConfig 并在 CreateInstance 时注入。
//
// 设计来源：docs/channel-redesign/components/runtime.md §3.1

// [v2 new-approach — 当前版本]
// WorkerCoverageMode / WorkerSanitizerMode 已拆分到 refuzz/channel/worker/mode.hpp，
// 作为 refuzz_channel 目标的稳定公共 API 供 crash / control 消费；本文件其余字段
// （binary 路径 / 启动命令 / deploy timeout 等）仍是 QemuChannel 实现域、对外
// 不暴露。
#include "refuzz/channel/worker/mode.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::channel::worker {

struct WorkerConfig {
    // 并行启动的 worker 数量（必须 >= 1）
    uint32_t n_workers = 1;

    // host 侧 worker binary 路径（必填，文件必须存在且可读）
    std::string worker_binary_host_path;

    // VM 内目标路径（DeployWorker 的 scp 目标）
    std::string worker_remote_path = "/tmp/ivshmem_worker";

    // 自定义启动命令模板；空 = 默认推导
    // 默认模板："<worker_remote_path> --worker-id <i>"
    // RuntimeInstance 统一在命令末尾追加：" > /tmp/worker_<i>.log 2>&1 & echo $!"
    // 自定义命令末尾不需要手动追加 & echo $!
    std::string worker_start_cmd;

    // ── 部署与启停超时（由调用方从 RuntimeInstanceConfig 注入）─────
    std::chrono::milliseconds deploy_timeout        {30'000};
    std::chrono::milliseconds start_worker_timeout  {10'000};
    std::chrono::milliseconds stop_worker_timeout   { 5'000};
};

} // namespace refuzz::channel::worker
