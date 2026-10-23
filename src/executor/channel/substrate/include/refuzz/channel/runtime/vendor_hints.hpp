#pragma once

// [v3 Phase 1.B] VendorHints — Substrate 启动后固定的底层端点描述
//
// 设计来源：docs/channel-redesign/v3/10_substrate.md §4.2
//
// 用途：Substrate 把"分配给 VM 的 ivshmem path / vsock CID / doorbell socket 等"
//       通过 Hints 暴露给 Assembler；Assembler 在创建 IControlPlane/IDataPlane
//       实例时从 Hints 读相应字段去连接。
//
// 关键规则：
//   - Channel / Health / Recovery 都 **不** 读 Hints 任何具体字段
//   - 只有具体的 ControlPlane / DataPlane / ConsoleSource 实现读它
//   - 这让"添加新底座 / 新通信"时不需要改 Channel 或公共头

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace refuzz::channel::runtime {

struct VendorHints {
    // ───── ivshmem 系列（QEMU / KVM-over-QEMU 专属）─────
    std::optional<std::string> ivshmem_path;
    std::optional<std::string> doorbell_socket_path;
    std::optional<uint64_t>    ivshmem_bytes;

    // ───── vsock 系列（QEMU / KVM / Firecracker 均可）─────
    std::optional<uint32_t>    vsock_cid;

    // ───── 扩展出口 ─────
    //
    // extra：其他 key/value 形式的底座端点信息；未强类型化但不阻塞演化。
    // 新增底座时先用 extra 尝试，稳定后再升级为强类型字段。
    std::unordered_map<std::string, std::string> extra;
};

} // namespace refuzz::channel::runtime
