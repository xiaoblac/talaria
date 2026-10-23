#pragma once

#include "refuzz/channel/channel.hpp"
#include "refuzz/core/service.hpp"
#include "refuzz/logging/host_logger.hpp"

#include <exception>
#include <future>
#include <string>
#include <utility>
#include <vector>

namespace refuzz::executor {

// ChannelService — 将 IChannel 适配为 IService（Boot -> Init，Close -> Stop）
class ChannelService : public refuzz::core::IService {
public:
    ChannelService(std::string name, refuzz::channel::IChannel* channel)
        : name_(std::move(name)), channel_(channel) {}

    std::string_view Name() const override { return name_; }

    refuzz::core::ServiceResult Init() override
    {
        if (!channel_) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, "null channel pointer"));
        }
        auto result = channel_->Boot();
        if (!result.ok()) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, result.error().message));
        }
        booted_ = true;
        return {};
    }

    refuzz::core::ServiceResult Start() override
    {
        if (!booted_) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, "Init() not called"));
        }
        running_ = true;
        return {};
    }

    refuzz::core::ServiceResult Stop() override
    {
        if (channel_ && (running_ || booted_)) {
            channel_->Close();
        }
        booted_  = false;
        running_ = false;
        return {};
    }

    bool IsRunning() const override { return running_; }
    bool IsBooted() const noexcept { return booted_; }

    refuzz::channel::IChannel* Channel() { return channel_; }

    void ForceClose()
    {
        if (channel_) {
            channel_->Close();
        }
        booted_  = false;
        running_ = false;
    }

private:
    std::string                  name_;
    refuzz::channel::IChannel* channel_ = nullptr;
    bool                         booted_  = false;
    bool                         running_ = false;
};

static_assert(refuzz::core::ServiceLike<ChannelService>);

// ChannelGroupService — 批量 channel 生命周期适配器。
//
// Init() 并发调用每个 ChannelService::Init()，也就是并发执行各 channel 的
// Boot()/VM 启动；Start()/Stop() 仍只是轻量状态切换和关闭编排。
class ChannelGroupService : public refuzz::core::IService {
public:
    ChannelGroupService(std::string name,
                        std::vector<std::unique_ptr<ChannelService>> services)
        : name_(std::move(name))
    {
        AddServices(std::move(services), true);
    }

    ChannelGroupService(std::string name,
                        std::vector<std::unique_ptr<ChannelService>> required_services,
                        std::vector<std::unique_ptr<ChannelService>> optional_services)
        : name_(std::move(name))
    {
        AddServices(std::move(required_services), true);
        AddServices(std::move(optional_services), false);
    }

    std::string_view Name() const override { return name_; }

    refuzz::core::ServiceResult Init() override
    {
        if (services_.empty()) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, "no channel services"));
        }

        struct PendingInit {
            ServiceEntry* entry = nullptr;
            std::future<refuzz::core::ServiceResult> result;
        };

        for (auto& entry : services_) {
            if (!entry.service) {
                return std::unexpected(
                    refuzz::core::ComponentError::Init(name_, "null channel service"));
            }
        }

        std::vector<PendingInit> pending;
        pending.reserve(services_.size());

        try {
            for (auto& entry : services_) {
                auto* raw = entry.service.get();
                pending.push_back(PendingInit{
                    .entry = &entry,
                    .result = std::async(std::launch::async, [raw]() {
                        return raw->Init();
                    }),
                });
            }
        } catch (const std::exception& e) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(
                    name_, std::string{"failed to launch channel init task: "} + e.what()));
        }

        std::string first_error;
        for (auto& item : pending) {
            auto& entry = *item.entry;
            auto* service = entry.service.get();
            try {
                auto result = item.result.get();
                if (result) {
                    entry.init_ok = true;
                    continue;
                }
                const std::string message =
                    std::string{service->Name()} + ": " + result.error().message;
                if (entry.required) {
                    if (first_error.empty()) {
                        first_error = message;
                    }
                } else {
                    refuzz::logging::HostLineBuilder(
                        "ChannelGroupService", "optional_channel_boot_failed")
                        << message << ", optional channel disabled\n";
                    service->ForceClose();
                }
            } catch (const std::exception& e) {
                const std::string message =
                    std::string{service->Name()} + ": " + e.what();
                if (entry.required) {
                    if (first_error.empty()) {
                        first_error = message;
                    }
                } else {
                    refuzz::logging::HostLineBuilder(
                        "ChannelGroupService", "optional_channel_boot_failed")
                        << message << ", optional channel disabled\n";
                    service->ForceClose();
                }
            }
        }

        if (!first_error.empty()) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, first_error));
        }

        booted_ = true;
        return {};
    }

    refuzz::core::ServiceResult Start() override
    {
        if (!booted_) {
            return std::unexpected(
                refuzz::core::ComponentError::Init(name_, "Init() not called"));
        }
        std::vector<ServiceEntry*> started;
        started.reserve(services_.size());
        for (auto& entry : services_) {
            if (!entry.init_ok || !entry.service) {
                continue;
            }
            auto result = entry.service->Start();
            if (!result) {
                if (entry.required) {
                    for (auto it = started.rbegin(); it != started.rend(); ++it) {
                        (void)(*it)->service->Stop();
                    }
                    return result;
                }
                refuzz::logging::HostLineBuilder(
                    "ChannelGroupService", "optional_channel_start_failed")
                    << entry.service->Name() << ": " << result.error().message
                    << ", optional channel disabled\n";
                entry.service->ForceClose();
                entry.init_ok = false;
                continue;
            }
            started.push_back(&entry);
        }
        running_ = true;
        return {};
    }

    refuzz::core::ServiceResult Stop() override
    {
        for (auto it = services_.rbegin(); it != services_.rend(); ++it) {
            if (it->service) {
                (void)it->service->Stop();
            }
        }
        running_ = false;
        return {};
    }

    bool IsRunning() const override { return running_; }

private:
    struct ServiceEntry {
        std::unique_ptr<ChannelService> service;
        bool                            required = true;
        bool                            init_ok = false;
    };

    void AddServices(std::vector<std::unique_ptr<ChannelService>> services,
                     bool required)
    {
        for (auto& service : services) {
            ServiceEntry entry;
            entry.service = std::move(service);
            entry.required = required;
            services_.push_back(std::move(entry));
        }
    }

    std::string                   name_;
    std::vector<ServiceEntry>     services_;
    bool                          booted_  = false;
    bool                          running_ = false;
};

static_assert(refuzz::core::ServiceLike<ChannelGroupService>);

} // namespace refuzz::executor
