// Copyright 2026 reFuzz project author -------youngkk.
//
// IDispatcher: 一次 syscall (native or pseudo) 的统一入口。
// kernel family 的 KernelChildDriver 在每条 SyscallOp / SyzExecCall 处调用 Dispatch；
// 内部走 ExecuteNrOrPseudo 完成 native syscall 或 pseudo handler 路由。
//
// 引入位置 (R1)：解耦 syz_execute / execute_program / syz_execute_threaded
// 与底层 dispatch 表，让"程序如何解析"和"一步动作如何执行"成为两个轴。
//
// 注意：这里仍然依赖 PseudoRuntimeContext，因为 R1 只服务 kernel family。
// 未来非内核 family (AFL/SQLite/V8) 的 Driver 不复用此 IDispatcher，
// 而是各自在 Driver 内部完成"一步动作"的执行。

#pragma once

#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"

#include <cstdint>

namespace refuzz::worker {

class IDispatcher {
public:
    virtual ~IDispatcher() = default;

    // 执行一条调用。ctx 由 caller (Driver) 持有,生命周期跟一次 program 执行;
    // 失败时 PseudoResult.ret = -1 / err = errno。
    virtual PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  PseudoRuntimeContext* ctx) = 0;

    virtual const char* Name() const = 0;
};

} // namespace refuzz::worker
