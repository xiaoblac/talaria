// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/startup/parse_launch_plan.hpp"

#include <string>

namespace refuzz::startup {

core::Result<void> OverrideLaunchPlanFromArgs(
    LaunchPlan& plan, std::optional<fuzzer::FeedbackEngineSpec>& /*spec*/,
    ParseOptions opts)
{
    static const char* kSupported =
        "--profile --mutator-engine --scheduler-engine --corpus-store "
        "--feedback-engine --target-toolkit --channel-backend";

    for (int i = 0; i < opts.argc; ++i) {
        std::string flag = opts.argv[i];
        if (flag.rfind("--", 0) != 0) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "unexpected positional arg '" + flag
                + "'. supported flags: " + std::string(kSupported)));
        }
        // 要求下个 arg 是值
        if (i + 1 >= opts.argc) {
            return std::unexpected(core::ComponentError::Config(
                "startup", "flag '" + flag + "' missing value"));
        }
        std::string value = opts.argv[i + 1];
        if (flag == "--profile") plan.profile = value;
        else if (flag == "--mutator-engine") plan.mutator_engine = value;
        else if (flag == "--scheduler-engine") plan.scheduler_engine = value;
        else if (flag == "--corpus-store") plan.corpus_store = value;
        else if (flag == "--feedback-engine") plan.feedback_engine = value;
        else if (flag == "--target-toolkit") plan.target_toolkit = value;
        else if (flag == "--channel-backend") plan.channel_backend_id = value;
        else {
            return std::unexpected(core::ComponentError::Config(
                "startup", "unknown flag '" + flag + "'. supported: " + std::string(kSupported)));
        }
        ++i; // 跳过 value
    }
    return {};
}

} // namespace refuzz::startup
