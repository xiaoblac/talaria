#pragma once

// sifive_uart_xiuos_profile.hpp — SifiveUartXiuosProfile
//
// App-surface 面后端("qemu_uart_sifive_u")的专属配置包。被测面从内核内部 K-API
// pivot 到用户态 app(穿 ecall),需要分离构建(SEPARATE_COMPILE + TASK_ISOLATION)
// 的 kernel.elf + 用户态 app.bin,跑在 stock `qemu-system-riscv64 -machine sifive_u`。
//
// 与 XiuosUartProfile 的关系:**is-a**。同一 XiUOS guest + 同一 UART wire 协议 +
// 单 worker + 同一 fork-QEMU/TCP-serial 底座(共用 XiuosUartSubstrate)。差别仅:
//   ① qemu_bin = qemu-system-riscv64(rv64);machine = sifive_u(非 virt-rv32)。
//   ② 二段 ELF:elf_path = kernel.elf;app_bin_path = U-mode app.bin,经
//      `-device loader,file=<app_bin>,addr=<app_load_addr>` 载入 USERSPACE。
// 故继承 XiuosUartProfile 复用全部 serial/backbone/CP/DP/substrate 调参字段,只新增
// machine / app_bin_path / app_load_addr 三个字段并改 qemu_bin/machine 默认值。
//
// 详见 docs/plans/xiuos-app-surface-fuzz-phase2.md 与宪法 xiuos-app-surface-fuzz.md §3.8。

#include "refuzz/channel/factory/xiuos_uart_profile.hpp"

#include <string>
#include <string_view>

namespace refuzz::channel::factory {

struct SifiveUartXiuosProfile : public XiuosUartProfile {
    SifiveUartXiuosProfile() {
        qemu_bin = "qemu-system-riscv64";
    }

    // QEMU `-machine`。sifive_u = mainline QEMU 能跑 K210 代码的机器(共享 CLINT/
    // PLIC/RAM,仅 UART 不同;见宪法 §3.7)。
    std::string  machine{"sifive_u"};
    // QEMU `-m`,对齐 §3.8 实测配方(`-m 256M`)。
    std::string  mem{"256M"};
    // 用户态 app 二进制(分离构建 objcopy 出的 .bin),required。
    std::string  app_bin_path;
    // app 链接到的 USERSPACE 地址(board/k210-emulator/board.h:USERSPACE=0x80101000)。
    std::string  app_load_addr{"0x80101000"};
    // [app-surface 重定向 M4] uart0 console sink。app-surface 下用户态 worker 的 wire
    // 走 uart1(第二 serial),内核 console/banner/shell 留 uart0(第一 serial)。默认
    // "null"(丢弃);可在 config 改成 "file:/path" 抓 boot 日志做调试/triage。任何 QEMU
    // chardev 规格皆可。空字符串则退回单 serial(wire 在 uart0)——但 sifive_u 默认非空。
    std::string  console_endpoint{"null"};

    std::string_view BackendId() const noexcept override {
        return "qemu_uart_sifive_u";
    }
};

}  // namespace refuzz::channel::factory
