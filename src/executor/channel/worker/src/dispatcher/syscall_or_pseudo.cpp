// Copyright 2026 reFuzz project author -------youngkk.
//
// SyscallOrPseudoDispatcher 的实现：薄壳，转发到 ExecuteNrOrPseudo。
// R1 引入。

#include "worker/dispatcher/syscall_or_pseudo.hpp"

namespace refuzz::worker {

PseudoResult SyscallOrPseudoDispatcher::Dispatch(uint64_t nr,
                                                 const intptr_t* args,
                                                 uint32_t argc,
                                                 PseudoRuntimeContext* ctx)
{
    if (ctx == nullptr) {
        return PseudoResult{-1, /*err=*/22 /*EINVAL*/};
    }
    return ExecuteNrOrPseudo(*ctx, nr, args, argc);
}

} // namespace refuzz::worker
