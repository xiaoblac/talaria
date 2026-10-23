#pragma once

#include "refuzz/channel/substrate/substrate.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"

namespace refuzz::channel::runtime::substrate::vm {

// MakeVmInstanceOps — 为给定 RuntimeInstanceConfig 创建 SubstrateInstanceOps 函数表
// 所有函数通过 shared_ptr<VmInstanceState> 捕获内部状态（Process/SSH/port）
SubstrateInstanceOps MakeVmInstanceOps(RuntimeInstanceConfig cfg);

} // namespace refuzz::channel::runtime::substrate::vm
