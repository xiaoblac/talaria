#pragma once

#include "refuzz/core/service.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/observation/terminal_dashboard.hpp"

namespace refuzz::telemetry {

class TelemetryService : public refuzz::core::IService {
public:
    TelemetryService(ObservabilityProjector* projector, TerminalDashboard* dashboard)
        : projector_(projector), dashboard_(dashboard) {}

    std::string_view Name() const override { return "telemetry"; }

    refuzz::core::ServiceResult Init() override { return {}; }

    refuzz::core::ServiceResult Start() override
    {
        if (projector_) {
            projector_->Start();
        }
        if (dashboard_) {
            dashboard_->Start();
        }
        running_ = true;
        return {};
    }

    refuzz::core::ServiceResult Stop() override
    {
        if (dashboard_) {
            dashboard_->Stop();
        }
        if (projector_) {
            projector_->Stop();
        }
        running_ = false;
        return {};
    }

    bool IsRunning() const override { return running_; }

private:
    ObservabilityProjector* projector_ = nullptr;
    TerminalDashboard*      dashboard_ = nullptr;
    bool                    running_   = false;
};

static_assert(refuzz::core::ServiceLike<TelemetryService>);

} // namespace refuzz::telemetry
