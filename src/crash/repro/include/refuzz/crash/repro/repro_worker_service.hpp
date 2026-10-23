#pragma once

#include "refuzz/core/service.hpp"
#include "refuzz/crash/repro/manager/repro_worker.hpp"
#include "refuzz/logging/host_logger.hpp"

#include <functional>
#include <utility>

namespace refuzz::crash {

class ReproWorkerService : public refuzz::core::IService {
public:
    explicit ReproWorkerService(ReproWorker* worker,
                                std::function<bool()> can_start = {})
        : worker_(worker)
        , can_start_(std::move(can_start)) {}

    std::string_view Name() const override { return "repro_worker"; }

    refuzz::core::ServiceResult Init() override { return {}; }

    refuzz::core::ServiceResult Start() override
    {
        if (can_start_ && !can_start_()) {
            refuzz::logging::HostLineBuilder("ReproWorkerService", "disabled")
                << "repro channel is not running\n";
            running_ = false;
            return {};
        }
        if (worker_) {
            worker_->Start();
            running_ = true;
        }
        return {};
    }

    refuzz::core::ServiceResult Stop() override
    {
        if (worker_) {
            worker_->Stop();
        }
        running_ = false;
        return {};
    }

    bool IsRunning() const override { return running_; }

private:
    ReproWorker* worker_   = nullptr;
    std::function<bool()> can_start_;
    bool         running_ = false;
};

static_assert(refuzz::core::ServiceLike<ReproWorkerService>);

} // namespace refuzz::crash
