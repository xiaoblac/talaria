#pragma once

#include "refuzz/core/error.hpp"
#include "refuzz/core/service.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::core {

// ServiceRegistry — 统一生命周期管理（拓扑序 Init / Start，逆序 Stop）
class ServiceRegistry {
public:
    ServiceRegistry() = default;
    ~ServiceRegistry();

    ServiceRegistry(const ServiceRegistry&)            = delete;
    ServiceRegistry& operator=(const ServiceRegistry&) = delete;

    bool Register(std::unique_ptr<IService> service, std::vector<std::string_view> deps = {});

    bool RegisterBorrowed(IService* service, std::vector<std::string_view> deps = {});

    IService* Find(std::string_view name) const;

    std::vector<std::string_view> Names() const;

    std::optional<std::vector<std::string_view>> TopologicalOrder() const;

    ServiceResult InitAll();
    ServiceResult StartAll();
    ServiceResult StopAll();
    ServiceResult InitAndStartAll();

    std::string DependencyDot() const;

    struct StatusEntry {
        std::string_view name;
        bool             running = false;
    };
    std::vector<StatusEntry> Status() const;

    size_t Size() const;

private:
    struct Entry {
        std::unique_ptr<IService>        owned;
        IService*                        ptr = nullptr;
        std::vector<std::string>         deps;
    };

    std::vector<Entry>           entries_;
    mutable std::vector<size_t>  topo_indices_;
    mutable bool                 topo_dirty_ = true;

    void InvalidateTopology();
    bool ComputeTopology(std::vector<size_t>& out_order) const;
};

} // namespace refuzz::core
