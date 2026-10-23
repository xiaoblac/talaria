#pragma once

#include "refuzz/channel/runtime/runtime_config.hpp"

#include <string>
#include <vector>

namespace refuzz::channel::runtime::substrate::vm {

// BuildQEMUArgs — 组装 QEMU argv[1..]（不含 binary 路径）
//
// @param cfg       实例配置（arch/mem/cpu/ivshmem/QMP 等）
// @param ssh_port  已分配的 SSH 端口（hostfwd 用）
// @param mon_port  已分配的 QMP 端口（0 = 不加 QMP 参数）
// @param workdir   本实例工作目录（serial.sock 路径来源）
std::vector<std::string> BuildQEMUArgs(
    const RuntimeInstanceConfig& cfg,
    int                          ssh_port,
    int                          mon_port,
    const std::string&           workdir);

} // namespace refuzz::channel::runtime::substrate::vm
