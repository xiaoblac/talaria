#pragma once

#include "worker/adapter/worker_registrar.hpp"
#include "worker/adapter/worker_task_channel.hpp"
#include "worker/engine/execution_domain_registry.hpp"
#include "worker/program_buffers.hpp"

#include <cstddef>

namespace refuzz::worker {

class IvshmemTransport;  // forward decl for AsIvshmem()

// Composition-root transport owner. Concrete adapters compose the narrow
// task-channel, execution-domain-registry, and registrar facets; engine code
// consumes those facets directly and never this lifecycle interface.
class IWorkerAdapter {
public:
    virtual ~IWorkerAdapter() = default;

    virtual IWorkerTaskChannel& TaskChannel() = 0;
    virtual IExecutionDomainRegistry& DomainRegistry() = 0;
    virtual IWorkerRegistrar& Registrar() = 0;

    // [no-rtti devirt 2026-05-22] 替代 dynamic_cast<IvshmemTransport*> —
    // 让我们能用 -fno-rtti 编译, 同时保持 IvshmemTransport-specific 接口
    // 调用 (step event ring access 等). 非 ivshmem transport 默认返 nullptr.
    virtual IvshmemTransport* AsIvshmem() { return nullptr; }

    // 初始化传输连接（mmap/connect/attach）
    virtual int Init() = 0;

    // 握手（等待 host ready，设置 vm_ready）
    virtual int Handshake() = 0;

    // 清理退出
    virtual void Cleanup() = 0;

    // adapter 在 child VA 中已经映射/持有的字节数，用于 SandboxSizing。
    virtual size_t SandboxMappedBytes() const { return 0; }

    // [LoopRuntime V3 mmap policy] 暴露 transport 共享内存基址 + 字节数。
    // 仅 ivshmem profile 覆盖;其它 transport(stdio 等)返默认 nullptr/0。
    // LoopRuntime 用这两个值做 MADV_DONTFORK 继承策略:control/header/step-ring
    // 不继承,data window 继承给 program child。
    virtual void* TransportShmBase() const { return nullptr; }
    virtual size_t TransportShmSize() const { return 0; }

    // Execution-domain backing store. The returned fd is borrowed and remains
    // owned by the adapter. It is CLOEXEC in the daemon; the topology duplicates
    // only the child copy across exec.
    virtual bool GetExecutionDomainTransport(
        ExecutionDomainTransport* /*out*/) const {
        return false;
    }

};

} // namespace refuzz::worker
