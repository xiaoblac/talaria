// runtime.cpp — Runtime 统一控制器实现


#include "refuzz/channel/runtime/runtime.hpp"
#include "refuzz/channel/runtime/runtime_pool.hpp"
#include "refuzz/channel/runtime/runtime_instance.hpp"

#include <utility>

namespace refuzz::channel::runtime {

// ── Create（完整拥有路径）────────────────────────────────────────

Result<std::unique_ptr<Runtime>> Runtime::Create(
    RuntimeConfig        config,
    SubstratePoolOps     substrate_ops,
    worker::WorkerConfig worker_cfg)
{
    auto pool_r = RuntimePool::Create(config.pool, std::move(substrate_ops));
    if (!pool_r.ok()) {
        return Error{pool_r.error().kind,
                     "Runtime::Create: pool creation failed: " + pool_r.error().message};
    }

    auto inst_r = pool_r.value()->CreateInstance(config.instance, worker_cfg);
    if (!inst_r.ok()) {
        return Error{inst_r.error().kind,
                     "Runtime::Create: instance creation failed: " + inst_r.error().message};
    }

    auto rt = std::unique_ptr<Runtime>(new Runtime(inst_r.value().get()));
    rt->pool_           = std::move(pool_r.value());
    rt->owned_instance_ = std::move(inst_r.value());
    rt->instance_       = rt->owned_instance_.get();

    return Result<std::unique_ptr<Runtime>>::Ok(std::move(rt));
}

// ── 向后兼容构造 ────────────────────────────────────────────────

Runtime::Runtime(RuntimeInstance* instance)
    : instance_(instance)
{}

Runtime::~Runtime()
{
    (void)Close();
}

// ── 校验辅助 ────────────────────────────────────────────────────

Result<void> Runtime::ValidateVmIndex(uint32_t vm_index) const
{
    if (vm_index != 0) {
        return Error{ErrorKind::kConfig,
                     "Runtime: vm_index=" + std::to_string(vm_index) +
                     " not supported (only vm_index=0)"};
    }
    if (instance_ == nullptr) {
        return Error{ErrorKind::kConfig, "Runtime: no instance available"};
    }
    return Result<void>::Ok();
}

// ── VM 生命周期 ─────────────────────────────────────────────────

Result<void> Runtime::StartVM(uint32_t vm_index)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->StartVM();
}

void Runtime::StopVM(uint32_t vm_index)
{
    if (vm_index != 0 || instance_ == nullptr) return;
    instance_->Stop();
}

Result<void> Runtime::RebootVM(uint32_t vm_index)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->Reboot();
}

bool Runtime::IsVMAlive(uint32_t vm_index) const
{
    if (vm_index != 0 || instance_ == nullptr) return false;
    return instance_->IsAlive();
}

// ── 生命周期 ───────────────────────────────────────────────────

Result<void> Runtime::Close()
{
    if (closed_) return Result<void>::Ok();
    closed_ = true;

    if (owned_instance_) {
        owned_instance_->Stop();
        owned_instance_.reset();
    }
    instance_ = nullptr;

    if (pool_) {
        auto r = pool_->Close();
        pool_.reset();
        if (!r.ok()) {
            return Error{r.error().kind, "Runtime::Close: pool close failed: " + r.error().message};
        }
    }

    return Result<void>::Ok();
}

// ── Worker 生命周期 ─────────────────────────────────────────────

Result<void> Runtime::DeployWorker(uint32_t vm_index)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->DeployWorker();
}

Result<void> Runtime::DeployArtifacts(uint32_t vm_index, const DeployBundle& bundle)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->DeployArtifacts(bundle);
}

Result<void> Runtime::StartAllWorkers(uint32_t vm_index)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->StartWorker();
}

Result<void> Runtime::StopAllWorkers(uint32_t vm_index)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->StopWorker();
}

Result<void> Runtime::StartWorker(uint32_t vm_index, uint32_t worker_id)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->StartSingleWorkerPublic(worker_id);
}

Result<void> Runtime::StopWorker(uint32_t vm_index, uint32_t worker_id)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->StopSingleWorker(worker_id);
}

// ── 诊断与端点 ─────────────────────────────────────────────────

evidence::ConsoleEndpoint Runtime::DefaultConsoleEndpoint(uint32_t vm_index) const
{
    if (vm_index != 0 || instance_ == nullptr) return {};
    return instance_->DefaultConsoleEndpoint();
}

VendorHints Runtime::Hints(uint32_t vm_index) const
{
    if (vm_index != 0 || instance_ == nullptr) return {};
    return instance_->Hints();
}

std::string Runtime::MonitorEndpoint(uint32_t vm_index) const
{
    if (vm_index != 0 || instance_ == nullptr) return {};
    return instance_->MonitorEndpoint();
}

std::string Runtime::Diagnose(uint32_t vm_index) const
{
    if (vm_index != 0 || instance_ == nullptr) return {};
    return instance_->Diagnose();
}

// ── SSH 透传 ────────────────────────────────────────────────────

Result<void> Runtime::CopyFileTo(uint32_t vm_index,
                                  const std::string& local_path,
                                  const std::string& remote_path,
                                  std::chrono::milliseconds timeout)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return v;
    return instance_->CopyFileTo(local_path, remote_path, timeout);
}

Result<std::string> Runtime::RunCommand(uint32_t vm_index,
                                         const std::string& cmd,
                                         std::chrono::milliseconds timeout)
{
    auto v = ValidateVmIndex(vm_index);
    if (!v.ok()) return Error{v.error().kind, v.error().message};
    return instance_->RunCommand(cmd, timeout);
}

} // namespace refuzz::channel::runtime
