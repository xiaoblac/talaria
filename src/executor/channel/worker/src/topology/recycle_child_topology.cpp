// RecycleChildTopology 实现。
//
// 见 hpp 注释。进程原语完全继承自 ReusableChildTopology,仅 Setup 时加
// recycle_after >= 1 的校验；何时回收由 DomainSupervisor 决定。

#include "worker/topology/recycle_child_topology.hpp"

#include "worker/log/log_macros.hpp"

#include <cerrno>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::topology {

RecycleChildTopology::RecycleChildTopology(
    ::refuzz::worker::IExecBackend& backend,
    ::refuzz::worker::IObservationBus& bus)
    : ReusableChildTopology(backend, bus)
{}

DomainStartResult RecycleChildTopology::Setup(const TopologyConfig& cfg)
{
    if (cfg.recycle_after < 1) {
        LOG("RecycleChildTopology::Setup: recycle_after=%u invalid (要求 >=1); "
            "若需要长 child 复用请用 kReusableChild",
            static_cast<unsigned>(cfg.recycle_after));
        errno = EINVAL;
        return MakeDomainStartRejected(
            cfg.identity.proc_id,
            ::refuzz::worker::engine::LoopStartupStage::kUnknown,
            errno);
    }
    return ReusableChildTopology::Setup(cfg);
}

} // namespace refuzz::worker::topology
