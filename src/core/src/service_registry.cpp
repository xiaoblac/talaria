#include "refuzz/core/service_registry.hpp"

#include <queue>
#include <sstream>
#include <unordered_map>

namespace refuzz::core {

ServiceRegistry::~ServiceRegistry() = default;

void ServiceRegistry::InvalidateTopology()
{
    topo_dirty_ = true;
}

bool ServiceRegistry::Register(std::unique_ptr<IService> service, std::vector<std::string_view> deps)
{
    if (!service) {
        return false;
    }
    const std::string_view name = service->Name();
    for (const auto& e : entries_) {
        if (e.ptr->Name() == name) {
            return false;
        }
    }
    Entry ent;
    ent.owned = std::move(service);
    ent.ptr   = ent.owned.get();
    ent.deps.reserve(deps.size());
    for (const auto d : deps) {
        ent.deps.emplace_back(d);
    }
    entries_.push_back(std::move(ent));
    InvalidateTopology();
    return true;
}

bool ServiceRegistry::RegisterBorrowed(IService* service, std::vector<std::string_view> deps)
{
    if (service == nullptr) {
        return false;
    }
    const std::string_view name = service->Name();
    for (const auto& e : entries_) {
        if (e.ptr->Name() == name) {
            return false;
        }
    }
    Entry ent;
    ent.ptr = service;
    ent.deps.reserve(deps.size());
    for (const auto d : deps) {
        ent.deps.emplace_back(d);
    }
    entries_.push_back(std::move(ent));
    InvalidateTopology();
    return true;
}

IService* ServiceRegistry::Find(std::string_view name) const
{
    for (const auto& e : entries_) {
        if (e.ptr->Name() == name) {
            return e.ptr;
        }
    }
    return nullptr;
}

std::vector<std::string_view> ServiceRegistry::Names() const
{
    std::vector<std::string_view> out;
    out.reserve(entries_.size());
    for (const auto& e : entries_) {
        out.push_back(e.ptr->Name());
    }
    return out;
}

bool ServiceRegistry::ComputeTopology(std::vector<size_t>& out_order) const
{
    out_order.clear();
    const size_t n = entries_.size();
    if (n == 0) {
        return true;
    }

    std::unordered_map<std::string, size_t> name_to_idx;
    name_to_idx.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const std::string_view nm = entries_[i].ptr->Name();
        name_to_idx[std::string(nm)] = i;
    }

    std::vector<size_t> indegree(n, 0);
    std::vector<std::vector<size_t>> adj(n);

    for (size_t i = 0; i < n; ++i) {
        for (const std::string& dep : entries_[i].deps) {
            const auto it = name_to_idx.find(dep);
            if (it == name_to_idx.end()) {
                return false;
            }
            const size_t dep_idx = it->second;
            adj[dep_idx].push_back(i);
            indegree[i]++;
        }
    }

    std::queue<size_t> q;
    for (size_t i = 0; i < n; ++i) {
        if (indegree[i] == 0) {
            q.push(i);
        }
    }

    while (!q.empty()) {
        const size_t u = q.front();
        q.pop();
        out_order.push_back(u);
        for (const size_t v : adj[u]) {
            if (--indegree[v] == 0) {
                q.push(v);
            }
        }
    }

    return out_order.size() == n;
}

std::optional<std::vector<std::string_view>> ServiceRegistry::TopologicalOrder() const
{
    std::vector<size_t> order;
    if (!ComputeTopology(order)) {
        return std::nullopt;
    }
    std::vector<std::string_view> names;
    names.reserve(order.size());
    for (const size_t idx : order) {
        names.push_back(entries_[idx].ptr->Name());
    }
    return names;
}

ServiceResult ServiceRegistry::InitAll()
{
    std::vector<size_t> order;
    if (!ComputeTopology(order)) {
        return std::unexpected(ComponentError::Init("ServiceRegistry", "circular or invalid dependency"));
    }
    topo_indices_ = order;
    topo_dirty_   = false;

    for (const size_t idx : order) {
        auto r = entries_[idx].ptr->Init();
        if (!r) {
            return r;
        }
    }
    return {};
}

ServiceResult ServiceRegistry::StartAll()
{
    std::vector<size_t> order;
    if (topo_dirty_) {
        if (!ComputeTopology(order)) {
            return std::unexpected(ComponentError::Init("ServiceRegistry", "circular or invalid dependency"));
        }
        topo_indices_ = order;
        topo_dirty_   = false;
    } else {
        order = topo_indices_;
        if (order.size() != entries_.size()) {
            if (!ComputeTopology(order)) {
                return std::unexpected(ComponentError::Init("ServiceRegistry", "circular or invalid dependency"));
            }
            topo_indices_ = order;
        }
    }

    std::vector<size_t> started;
    started.reserve(order.size());

    for (const size_t idx : order) {
        auto r = entries_[idx].ptr->Start();
        if (!r) {
            for (auto it = started.rbegin(); it != started.rend(); ++it) {
                entries_[*it].ptr->Stop();
            }
            return r;
        }
        started.push_back(idx);
    }
    return {};
}

ServiceResult ServiceRegistry::StopAll()
{
    std::vector<size_t> order;
    if (!ComputeTopology(order)) {
        return std::unexpected(ComponentError::Runtime("ServiceRegistry", "circular or invalid dependency"));
    }

    for (auto it = order.rbegin(); it != order.rend(); ++it) {
        entries_[*it].ptr->Stop();
    }
    return {};
}

ServiceResult ServiceRegistry::InitAndStartAll()
{
    if (auto i = InitAll(); !i) {
        return i;
    }
    return StartAll();
}

std::string ServiceRegistry::DependencyDot() const
{
    std::ostringstream oss;
    oss << "digraph services {\n";
    for (const auto& e : entries_) {
        const std::string_view self = e.ptr->Name();
        for (const std::string& d : e.deps) {
            oss << "  \"" << d << "\" -> \"" << self << "\";\n";
        }
    }
    oss << "}\n";
    return oss.str();
}

std::vector<ServiceRegistry::StatusEntry> ServiceRegistry::Status() const
{
    std::vector<StatusEntry> out;
    out.reserve(entries_.size());
    for (const auto& e : entries_) {
        out.push_back(StatusEntry{e.ptr->Name(), e.ptr->IsRunning()});
    }
    return out;
}

size_t ServiceRegistry::Size() const
{
    return entries_.size();
}

} // namespace refuzz::core
