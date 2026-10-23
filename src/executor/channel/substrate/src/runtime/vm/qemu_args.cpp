// qemu_args.cpp — QEMU 命令行参数构造
//
// BuildQEMUArgs 按 12 步规则组装 argv[1..]（不含 binary 路径）。
// 设计来源：docs/channel-redesign/components/runtime.md §4

#include "qemu_args.hpp"
#include "arch_map.hpp"

#include <sstream>

namespace refuzz::channel::runtime::substrate::vm {

std::vector<std::string> BuildQEMUArgs(
    const RuntimeInstanceConfig& cfg,
    int                          ssh_port,
    int                          mon_port,
    const std::string&           workdir)
{
    // ArchConfig 在 Create 时已验证；此处取值不检查
    auto arch_r = GetArchParams(cfg.arch);
    const ArchParams& ap = arch_r.value();

    std::vector<std::string> args;

    // ── 1. 基础资源 ───────────────────────────────────────────
    args.push_back("-m");    args.push_back(std::to_string(cfg.mem_mb));
    args.push_back("-smp");  args.push_back(std::to_string(cfg.cpu));

    // ── 2. 关闭图形显示 ───────────────────────────────────────
    args.push_back("-display"); args.push_back("none");

    // ── 3. Serial console → workdir/serial.sock ───────────────
    const std::string serial_sock = workdir + "/serial.sock";
    std::string serial_chardev = "socket,id=SERIAL,path=" + serial_sock +
                                 ",server=on,wait=off";
    if (!cfg.serial_log_path.empty()) {
        serial_chardev += ",logfile=" + cfg.serial_log_path + ",logappend=off";
    }
    args.push_back("-chardev");
    args.push_back(std::move(serial_chardev));
    args.push_back("-serial"); args.push_back("chardev:SERIAL");

    // ── 3b. Worker 诊断专用第二串口 → guest ttyS1 ──────────────
    // 必须排在上面的 console 串口之后：QEMU 按 -serial 出现顺序分配
    // ttyS0/ttyS1，console 占 ttyS0，这个才是 ttyS1。append=on 让日志跨
    // VM 重启累积而不是被截断（与 syz perf serial 同样的理由）。
    if (!cfg.worker_log_path.empty()) {
        args.push_back("-chardev");
        args.push_back("file,id=WORKERLOG,path=" + cfg.worker_log_path +
                       ",append=on");
        args.push_back("-serial"); args.push_back("chardev:WORKERLOG");
    }

    // ── 4. -no-reboot ─────────────────────────────────────────
    if (cfg.no_reboot) args.push_back("-no-reboot");

    // ── 5. VM 名称 ────────────────────────────────────────────
    args.push_back("-name");
    args.push_back("VM-" + std::to_string(cfg.index));

    // ── 6. RNG 设备 ───────────────────────────────────────────
    const std::string rng = cfg.rng_dev_override.empty()
                          ? ap.rng_dev
                          : cfg.rng_dev_override;
    if (!rng.empty()) {
        args.push_back("-device"); args.push_back(rng);
    }

    // ── 7. ivshmem ────────────────────────────────────────────
    if (cfg.ivshmem_bytes > 0) {
        if (cfg.ivshmem_mode == "plain") {
            // plain：memory-backend-file + ivshmem-plain
            args.push_back("-object");
            args.push_back("memory-backend-file,id=ivshmem0"
                           ",mem-path=" + cfg.ivshmem_path +
                           ",size=" + std::to_string(cfg.ivshmem_bytes) +
                           ",share=on");
            // snapshot_fuzzing 时加 master=on：peer-mode ivshmem 会注册 migration
            // blocker，让 savevm 报 "Migration is disabled when using feature
            // 'peer mode'"。master=on 指定本设备为 migration master（其 share=on
            // RAMBlock 再由 `x-ignore-shared` 排除出快照）。对齐 syzkaller
            // snapshot_linux.go:117。continuous 路径不需要、保持原样。
            if (cfg.snapshot_fuzzing)
                args.push_back("-device"), args.push_back("ivshmem-plain,master=on,memdev=ivshmem0");
            else
                args.push_back("-device"), args.push_back("ivshmem-plain,memdev=ivshmem0");
        } else {
            // doorbell：chardev socket + ivshmem-doorbell
            args.push_back("-chardev");
            args.push_back("socket,path=" + cfg.ivshmem_socket + ",id=IVSHMEM");
            args.push_back("-device");
            args.push_back("ivshmem-doorbell,master=on"
                           ",vectors=" + std::to_string(cfg.ivshmem_vectors) +
                           ",chardev=IVSHMEM");
        }
    }

    // ── 8. QMP monitor ────────────────────────────────────────
    if (cfg.qmp_enable && mon_port > 0) {
        args.push_back("-chardev");
        args.push_back("socket,id=SOCKSYZ"
                       ",server=on,wait=off"
                       ",host=" + cfg.qmp_host +
                       ",port=" + std::to_string(mon_port));
        args.push_back("-mon"); args.push_back("chardev=SOCKSYZ,mode=control");
    }

    // ── 9. 架构特定参数 ───────────────────────────────────────
    for (const auto& a : ap.extra_args) {
        // snapshot-fuzzing (amd64): savevm 要求 CPU migratable,且 RDTSC 不能被
        // 还原(否则 guest 每次 loadvm 都判 TSC unstable)。只改写 amd64 的 cpu 值,
        // 其余 extra_args 原样。
        if (cfg.snapshot_fuzzing && a == "host,migratable=off")
            args.push_back("host,migratable=on,tsc=off");
        else
            args.push_back(a);
    }

    // ── 10. 网络（SSH 端口转发）──────────────────────────────
    args.push_back("-device");
    args.push_back(ap.net_dev + ",netdev=net0");
    args.push_back("-netdev");
    args.push_back("user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:" +
                   std::to_string(ssh_port) + "-:22");

    // ── 11. 磁盘镜像 ─────────────────────────────────────────
    // [2026-05-13 image sharing — file.locking=off (snapshot-gated)]
    // 默认 -hda / -drive QEMU 取 OFD 独占读锁,导致 main + repro 两个 VM 共用
    // 同一 base image 时第二个起来失败(锁冲突 → 无法 open 磁盘 → kernel 未启动
    // → SSH timeout)。snapshot=on 时 backing image 是只读访问 + 每个 QEMU 自带
    // CoW overlay 在 $TMPDIR,所以多 reader 共享是 POSIX 安全的;关锁是放开 QEMU
    // 的保守约束,不破坏底层 invariant。
    //
    // 关键安全护栏:**只在 snapshot=on 时关锁**。snapshot=off 路径仍走老 -hda,
    // 保留 OFD 独占锁 → 若有人误配两 VM 不带 snapshot 写同一 image,QEMU 仍能
    // 拦死(避免静默 corruption)。
    const std::string img_dev = cfg.image_device.empty() ? "hda" : cfg.image_device;
    const bool use_virtio_disk =
        ap.use_virtio_disk || img_dev == "virtio-blk-device" || img_dev == "virtio-blk-pci";
    if (cfg.snapshot_fuzzing) {
        // snapshot-fuzzing:可写 qcow2(savevm 把 S0 快照存进 qcow2 内部快照表)+
        // **不加 -snapshot**(临时 overlay 模式与 savevm 不兼容)。cfg.disk_image
        // 必须是 qcow2。
        if (use_virtio_disk) {
            args.push_back("-drive");
            args.push_back("if=none,id=hd0,file=" + cfg.disk_image +
                           ",file.locking=off");
            args.push_back("-device"); args.push_back("virtio-blk-pci,drive=hd0");
        } else {
            args.push_back("-drive");
            args.push_back("file=" + cfg.disk_image +
                           ",if=ide,index=0,media=disk,file.locking=off");
        }
        // 注意:不 push -snapshot。
    } else if (cfg.snapshot) {
        // snapshot=on:走显式 -drive + file.locking=off。-snapshot 仍然在末尾 push
        // 让 QEMU 建 CoW overlay。virtio/hda 两条路径独立组装。
        if (use_virtio_disk) {
            args.push_back("-drive");
            args.push_back("if=none,id=hd0,file=" + cfg.disk_image +
                           ",file.locking=off");
            args.push_back("-device"); args.push_back("virtio-blk-pci,drive=hd0");
        } else {
            // -hda 等价于 -drive file=...,if=ide,index=0,media=disk
            args.push_back("-drive");
            args.push_back("file=" + cfg.disk_image +
                           ",if=ide,index=0,media=disk,file.locking=off");
        }
        args.push_back("-snapshot");
    } else {
        // snapshot=off:保留原行为(OFD 锁开,拦多 writer)。
        if (use_virtio_disk) {
            args.push_back("-drive");
            args.push_back("if=none,id=hd0,file=" + cfg.disk_image);
            args.push_back("-device"); args.push_back("virtio-blk-pci,drive=hd0");
        } else {
            args.push_back("-hda"); args.push_back(cfg.disk_image);
        }
    }

    // ── 12. 内核 + cmdline ────────────────────────────────────
    if (!cfg.kernel.empty()) {
        args.push_back("-kernel"); args.push_back(cfg.kernel);

        // base cmdline（来自 arch）+ cfg.kernel_cmdline 拼接
        std::string base;
        for (size_t i = 0; i < ap.base_cmdline.size(); ++i) {
            if (i > 0) base += " ";
            base += ap.base_cmdline[i];
        }
        if (!cfg.kernel_cmdline.empty()) {
            if (!base.empty()) base += " ";
            base += cfg.kernel_cmdline;
        }
        if (!base.empty()) {
            args.push_back("-append"); args.push_back(base);
        }
    }

    // ── 13. initrd（可选）────────────────────────────────────
    if (!cfg.initrd.empty()) {
        args.push_back("-initrd"); args.push_back(cfg.initrd);
    }

    return args;
}

} // namespace refuzz::channel::runtime::substrate::vm
