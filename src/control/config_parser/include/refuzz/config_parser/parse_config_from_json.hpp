// Copyright 2026 reFuzz project author -------youngkk.
//
// P6.1: 把"已 parse 的 nlohmann::json → OrchestratorConfig"这一段暴露出来。
// 两个场景:
//   1. CLI 直接入口: ParseConfig(path, out)(orchestrator_config.hpp 原有 public API)
//      读文件 → 调本函数。
//   2. Startup 前端: ParseLaunchPlan 先把 JSON 读到内存,然后同时:
//      - 调本函数填 OrchestratorConfig
//      - 自己从同一 json 里读 components / feedback_engine_spec
//      避免 JSON 被读两次、错误路径分裂。
// 失败返回 false,失败原因通过 HostLineBuilder 输出(与 ParseConfig 保持一致)。
// 输入的 root 必须已经 is_object(非 object 返回 false)。

#pragma once

#include "refuzz/orchestrator/orchestrator_config.hpp"
#include "util/json.hpp"

#include <string>

namespace refuzz::orchestrator {

bool ParseConfigFromJson(const nlohmann::json& root, OrchestratorConfig& out);
std::string DumpConfigSummary(const OrchestratorConfig& config);

} // namespace refuzz::orchestrator
