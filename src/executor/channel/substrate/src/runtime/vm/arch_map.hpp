#pragma once

#include "refuzz/channel/result.hpp"

#include <string>
#include <vector>

namespace refuzz::channel::runtime::substrate::vm {

// ArchParams — 单个 arch 对应的 QEMU 参数集合
struct ArchParams {
    std::string              qemu_bin;       // 默认 qemu binary（可被 cfg.qemu_bin 覆盖）
    std::vector<std::string> extra_args;     // arch 专属参数（-enable-kvm, -machine 等）
    std::string              net_dev;        // 网络设备型号（e1000 / virtio-net-pci）
    std::string              rng_dev;        // RNG 设备型号；空 = 不加
    std::vector<std::string> base_cmdline;   // arch 基础 kernel cmdline token 列表
    bool use_virtio_disk = false;            // arm64/riscv 等使用 virtio-blk-pci 接入磁盘
};

// GetArchParams — 查询 arch 对应参数；arch 不在已知列表返回 kConfig 错误
refuzz::channel::Result<ArchParams> GetArchParams(const std::string& arch);

} // namespace refuzz::channel::runtime::substrate::vm
