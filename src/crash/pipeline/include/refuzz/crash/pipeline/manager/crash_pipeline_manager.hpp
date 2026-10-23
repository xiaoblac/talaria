#pragma once

#include "refuzz/crash/infra/diagnostic_store.hpp"
#include "refuzz/crash/pipeline/core/crash_analysis_engine.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_registry.hpp"
#include "refuzz/crash/pipeline/policy/linuxkernel/syz_xxx_policy/syz_triage_policy.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::crash {

class CrashPipelineManager {
public:
    explicit CrashPipelineManager(ICrashAnalysisEngine* engine,
                                  DiagnosticStore* diagnostic_store = nullptr,
                                  IReproQueue* repro_queue = nullptr);

    void Process(const refuzz::proto::CombinedCrashEvent& event);

    int RegisterTriagePolicy(std::string name, std::unique_ptr<ISyzTriagePolicy> policy);
    bool SwitchTriagePolicyByName(std::string_view name);
    bool MaybeApplyPendingSwitch();

private:
    ICrashAnalysisEngine* engine_;
    CrashPipelineRegistry registry_;

    std::vector<std::unique_ptr<ISyzTriagePolicy>> policy_registry_;
    std::unordered_map<std::string, int> policy_name_index_;
    std::atomic<int> next_policy_idx_{0};
    int policy_idx_ = 0;

    ISyzTriagePolicy* ActivePolicy() const
    {
        return policy_registry_[static_cast<size_t>(policy_idx_)].get();
    }
};

} // namespace refuzz::crash
