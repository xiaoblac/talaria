#include "refuzz/crash/pipeline/manager/crash_pipeline_manager.hpp"

namespace refuzz::crash {

CrashPipelineManager::CrashPipelineManager(ICrashAnalysisEngine* engine,
                                           DiagnosticStore* diagnostic_store,
                                           IReproQueue* repro_queue)
    : engine_(engine)
{
    if (engine_ != nullptr) {
        engine_->RegisterOps(registry_, diagnostic_store, repro_queue);
    }

    RegisterTriagePolicy("all_unique", std::make_unique<AllUniqueTriagePolicy>());
    RegisterTriagePolicy("high_severity", std::make_unique<HighSeverityTriagePolicy>());
    RegisterTriagePolicy("quota_0", std::make_unique<QuotaZeroTriagePolicy>());
    RegisterTriagePolicy("actionable", std::make_unique<ActionableFindingsTriagePolicy>());
}

int CrashPipelineManager::RegisterTriagePolicy(std::string name,
                                               std::unique_ptr<ISyzTriagePolicy> policy)
{
    const int idx = static_cast<int>(policy_registry_.size());
    policy_name_index_[std::move(name)] = idx;
    policy_registry_.push_back(std::move(policy));
    return idx;
}

bool CrashPipelineManager::SwitchTriagePolicyByName(std::string_view name)
{
    auto it = policy_name_index_.find(std::string(name));
    if (it == policy_name_index_.end()) {
        return false;
    }
    next_policy_idx_.store(it->second, std::memory_order_release);
    return true;
}

bool CrashPipelineManager::MaybeApplyPendingSwitch()
{
    const int next = next_policy_idx_.load(std::memory_order_acquire);
    if (next == policy_idx_) {
        return false;
    }
    policy_registry_[static_cast<size_t>(next)]->OnActivated();
    policy_idx_ = next;
    return true;
}

void CrashPipelineManager::Process(const refuzz::proto::CombinedCrashEvent& event)
{
    MaybeApplyPendingSwitch();
    auto* policy = ActivePolicy();
    auto plan = policy->BuildPlan(event);

    CrashContext ctx;
    for (const auto& node : plan) {
        auto* op = registry_.Find(node.op);
        if (op == nullptr) {
            continue;
        }
        op->Execute(event, ctx, node.params);
    }
}

} // namespace refuzz::crash
