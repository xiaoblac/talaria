// Copyright 2026 reFuzz project author -------youngkk.
//
// Startup 前端:JSON + CLI -> LaunchPlan + 可选 FeedbackEngineSpec
//
// 使用模式:
//   int main(int argc, char** argv) {
//       const std::string json_path = argv[1];   // 约定 argv[1] = path
//       refuzz::startup::ParseOptions opts;
//       opts.argc = argc - 2;                    // argv[2..] = flags
//       opts.argv = argv + 2;
//       auto r = refuzz::startup::ParseLaunchPlan(json_path, opts);
//       if (!r) { log(r.error()); return 1; }
//       // r->plan 和 r->ad_hoc_feedback_spec 送进 Resolver
//   }
//
// 约定:
//   - argv 的切片由调用方负责(Startup 不做位置参数/flag 区分)
//   - 未知 flag 直接 Error(附支持列表),不做 "warn 继续"
//   - CLI flag 只覆盖 7 个 plan-level id 字段;plan.config 的 knob override
//     是 P7+ 的 escape-hatch 设计(本版 P6 不做 --runtime-seconds / --total-tasks /
//     --mutator-policy)
//   - --profile 切换不清空 components (用户必须显式传 --mutator-engine 等覆盖)

#pragma once
#include "refuzz/startup/launch_plan.hpp"
#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/core/error.hpp"
#include <optional>
#include <string>

namespace refuzz::startup {

struct ParseOptions {
    // CLI argc/argv:纯 flag 切片,不包含可执行路径和 JSON 路径。
    // Startup 不会持有这些指针超出函数返回期。
    int argc = 0;
    const char* const* argv = nullptr;
};

struct ParseResult {
    LaunchPlan plan;
    // 可选 ad-hoc feedback spec(来自 JSON 里的 feedback_engine_spec 块)。
    // Resolver::Resolve 的 options.ad_hoc_feedback_spec 从这里填。
    std::optional<fuzzer::FeedbackEngineSpec> ad_hoc_feedback_spec;
};

// 主入口。JSON 路径读不到/非 object/解析失败/feedback_engine_spec 字段错 → Error。
// CLI 未知 flag → Error 附支持列表。
core::Result<ParseResult> ParseLaunchPlan(
    const std::string& json_path,
    ParseOptions options = {});

// CLI-only 覆盖层。单独暴露便于测试(不读 JSON)。
// 传入 plan / spec 引用,就地修改。未知 flag → Error。
core::Result<void> OverrideLaunchPlanFromArgs(
    LaunchPlan& plan,
    std::optional<fuzzer::FeedbackEngineSpec>& spec,
    ParseOptions options);

} // namespace refuzz::startup
