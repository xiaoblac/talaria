// arch_map.cpp — arch → QEMU 参数映射表
//
// 支持：amd64 / 386 / arm64 / arm / riscv64
// 设计来源：docs/channel-redesign/components/runtime.md §4.1

#include "arch_map.hpp"

namespace refuzz::channel::runtime::substrate::vm {

refuzz::channel::Result<ArchParams> GetArchParams(const std::string& arch)
{
    if (arch == "amd64") {
        ArchParams p;
        p.qemu_bin   = "qemu-system-x86_64";
        p.extra_args = {"-enable-kvm", "-cpu", "host,migratable=off"};
        p.net_dev    = "e1000";
        p.rng_dev    = "virtio-rng-pci";
        p.base_cmdline = {"root=/dev/sda", "console=ttyS0",
                          "net.ifnames=0", "biosdevname=0"};
        p.use_virtio_disk = false;
        return refuzz::channel::Result<ArchParams>::Ok(std::move(p));
    }
    if (arch == "386") {
        ArchParams p;
        p.qemu_bin   = "qemu-system-i386";
        p.net_dev    = "e1000";
        p.rng_dev    = "virtio-rng-pci";
        p.base_cmdline = {"root=/dev/sda", "console=ttyS0",
                          "net.ifnames=0", "biosdevname=0"};
        p.use_virtio_disk = false;
        return refuzz::channel::Result<ArchParams>::Ok(std::move(p));
    }
    if (arch == "arm64") {
        ArchParams p;
        p.qemu_bin   = "qemu-system-aarch64";
        p.extra_args = {"-machine", "virt,virtualization=on,gic-version=max",
                        "-cpu",     "max,sve128=on,pauth=off"};
        p.net_dev    = "virtio-net-pci";
        p.rng_dev    = "virtio-rng-pci";
        p.base_cmdline = {"root=/dev/vda", "console=ttyAMA0"};
        p.use_virtio_disk = true;
        return refuzz::channel::Result<ArchParams>::Ok(std::move(p));
    }
    if (arch == "arm") {
        ArchParams p;
        p.qemu_bin   = "qemu-system-arm";
        p.extra_args = {"-machine", "virt", "-cpu", "max"};
        p.net_dev    = "virtio-net-pci";
        p.rng_dev    = "virtio-rng-pci";
        p.base_cmdline = {"root=/dev/vda", "console=ttyAMA0"};
        p.use_virtio_disk = true;
        return refuzz::channel::Result<ArchParams>::Ok(std::move(p));
    }
    if (arch == "riscv64") {
        ArchParams p;
        p.qemu_bin   = "qemu-system-riscv64";
        p.extra_args = {"-machine", "virt"};
        p.net_dev    = "virtio-net-pci";
        p.rng_dev    = "virtio-rng-pci";
        p.base_cmdline = {"root=/dev/vda", "console=ttyS0"};
        p.use_virtio_disk = true;
        return refuzz::channel::Result<ArchParams>::Ok(std::move(p));
    }

    return refuzz::channel::Error{
        refuzz::channel::ErrorKind::kConfig,
        "unknown arch: " + arch +
        "; supported: amd64, 386, arm64, arm, riscv64"
    };
}

} // namespace refuzz::channel::runtime::substrate::vm
