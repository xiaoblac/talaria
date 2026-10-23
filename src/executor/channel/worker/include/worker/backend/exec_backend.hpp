#pragma once
#include "worker/exec_mode.hpp"
#include "worker/runtime_failure.hpp"
#include <cstdint>

namespace refuzz::worker {

// 执行后端抽象接口
// 不同 fuzz 目标使用不同实现：SyscallBackend（kernel）、LibBackend（userspace library）
class IExecBackend {
public:
    virtual ~IExecBackend() = default;

    // Configure the resource identity inherited by the next execution domain.
    // Called in the daemon after the old domain is stopped and before fork.
    virtual void ConfigureProcId(uint32_t /*proc_id*/) {}

    // 执行一个任务。input/output buffer 由 caller 提供。
    // mode 控制执行方式：serial 或 threaded。
    // 返回 0=成功, 非0=错误
    virtual int Execute(const uint8_t* input, uint32_t input_len,
                        uint8_t* output, uint32_t output_cap,
                        uint32_t* output_len,
                        ExecMode mode = {}) = 0;

    // [v1 per-call shmem progress — 2026-05-13]
    // 注入 caller 准备的 progress cursors;driver 每完成一个 syscall 后按
    // RELEASE 顺序 atomic store。详 ProgramRuntimeInput::progress_* 注释。
    // 默认 no-op:不支持 per-call shmem 的 backend(syz_exec_runner / pseudo /
    // mock)直接忽略,行为不变。caller 应在每条 program 前调用;Execute 之后
    // 应传 nullptr 复位以防 stale 指针。
    virtual void SetProgressCursors(uint32_t* /*completed_calls*/,
                                    uint32_t* /*output_len*/) {}

    // Diagnostic-only context for logs emitted below the backend surface. This
    // is not part of program semantics; it lets pseudo handlers include the
    // channel/replayer executor_id in timing logs without serializing that id
    // into the program payload.
    virtual void SetDiagnosticExecutorId(uint64_t /*executor_id*/) {}

    // Publish /dev/loop usage while Execute is still running so a parent that
    // terminates the execution can retain the precise cleanup set. Returning
    // true declares that this backend will atomically OR every used loop bit
    // into cursor. The caller initializes supported cursors to 0 before
    // entering Execute; unsupported backends leave the UINT32_MAX sentinel.
    virtual bool SetLoopDevicesUsedMaskCursor(uint32_t* /*cursor*/) {
        return false;
    }

    // After Execute returns, the final per-program /dev/loop usage bitmask.
    // Backends that support SetLoopDevicesUsedMaskCursor also publish the same
    // information during execution for timeout/crash cleanup.
    //
    // Semantics: 0 means no candidate, UINT32_MAX means unknown, and all other
    // values are exact diagnostic bits.
    //
    // "Take" implies read-and-reset so the next Execute starts at 0; default
    // returns UINT32_MAX to preserve the unknown state.
    virtual uint32_t TakeLoopDevicesUsedMask() { return UINT32_MAX; }

    virtual RuntimeFailure RuntimeFailureState() const {
        return RuntimeFailure::kNone;
    }

    // 后端名称（日志/诊断用）
    virtual const char* Name() const = 0;
};

} // namespace refuzz::worker
