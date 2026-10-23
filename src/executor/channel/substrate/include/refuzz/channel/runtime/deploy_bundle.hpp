#pragma once

// [v3 Phase 1.B] DeployBundle — Channel → Substrate 的 worker 部署契约
//
// 设计来源：docs/channel-redesign/v3/10_substrate.md §4.3
//
// 替代 v2 里 Substrate 直接持有 `WorkerConfig` 的做法：
//   - v2：Substrate 知道"worker 的 sanitizer 模式 / coverage 模式"——业务泄漏
//   - v3：Substrate 只看到"一组文件 + 一条启动命令"；业务知识由 Channel 装配时
//         组装成 DeployBundle 交给 Substrate
//
// 使用：
//   bundle.artifacts = {
//     {"/host/workdir/worker_fuzz.bin",  "/tmp/worker", 0755},
//     {"/host/workdir/corpus.db",        "/tmp/corpus", 0644},
//   };
//   bundle.worker_start_cmd = "/tmp/worker --id={worker_id} --mode=kasan";
//   substrate.DeployArtifacts(0, bundle);

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::channel::runtime {

struct DeployArtifact {
    std::string local_path;          // host 侧源文件
    std::string remote_path;         // target 侧目标路径
    uint32_t    mode = 0755;         // 目标文件权限
};

struct DeployBundle {
    std::vector<DeployArtifact> artifacts;

    // worker_start_cmd：启动命令模板；支持 "{worker_id}" 占位符
    //
    // 约束：
    //   - 不含 sanitizer/coverage/feedback 等业务知识（这些要么编译进 worker binary，
    //     要么通过模板参数从 target-toolkit 层传下来）
    //   - Substrate 在 StartAllWorkers / StartWorker 时按模板替换后 exec
    std::string worker_start_cmd;

    std::chrono::milliseconds deploy_timeout{30'000};
};

} // namespace refuzz::channel::runtime
