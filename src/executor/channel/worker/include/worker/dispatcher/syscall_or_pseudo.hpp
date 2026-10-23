// Copyright 2026 reFuzz project author -------youngkk.
//
// SyscallOrPseudoDispatcher: kernel family 的 IDispatcher 实现。
// 内部直接转发到 ExecuteNrOrPseudo (native syscall + pseudo handler 表驱动)。
//
// R1 引入：替换原本散落在 syz_execute / execute_program 各处的
// 直接 ExecuteNrOrPseudo 调用，使 dispatch 成为 Driver 注入的 plug-in。

#pragma once

#include "worker/dispatcher/dispatcher.hpp"

namespace refuzz::worker {

class SyscallOrPseudoDispatcher final : public IDispatcher {
public:
    PseudoResult Dispatch(uint64_t nr,
                          const intptr_t* args,
                          uint32_t argc,
                          PseudoRuntimeContext* ctx) override;

    const char* Name() const override { return "syscall_or_pseudo"; }
};

} // namespace refuzz::worker
