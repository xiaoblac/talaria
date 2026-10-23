#pragma once

// Runtime 配置模型
//
// 三层配置对应三层抽象：
//   RuntimePoolConfig     — 池级（pool_size, substrate_kind）
//   RuntimeInstanceConfig — 实例级（VM 参数、超时、ivshmem、QMP）
//   RuntimeConfig         — 对外聚合（不含 WorkerConfig，由 QemuChannel 单独持有）
//
// 设计来源：docs/channel-redesign/components/runtime.md §3

#include <chrono>
#include <cstdint>
#include <string>

namespace refuzz::channel::runtime {

// ============================================================
// RuntimePoolConfig — 池级配置
// ============================================================

struct RuntimePoolConfig {
    // 池容量（当前 QemuChannel 始终为 1）
    uint32_t pool_size = 1;

    // 底座类型标识；当前仅允许 "vm"
    std::string substrate_kind = "vm";
};

// ============================================================
// QmpPortPolicy — QMP 端口分配策略
// ============================================================

enum class QmpPortPolicy : uint8_t {
    kAutoAllocate = 0,  // 每次 StartVM 自动查找未占用端口
    kFixed,             // 固定使用 qmp_fixed_port（测试/调试场景）
};

// ============================================================
// RuntimeInstanceConfig — 单 VM 实例配置
// ============================================================

struct RuntimeInstanceConfig {
    // ── VM 基础 ──────────────────────────────────────────────
    // qemu_bin 空时由 arch 推导默认值（arch_map.cpp §4.1）
    std::string qemu_bin;
    std::string arch        = "amd64";   // amd64 / 386 / arm64 / arm / riscv64
    std::string kernel;                  // 必填，bzImage 路径
    std::string disk_image;              // 必填，rootfs 镜像路径
    std::string initrd;                  // 空 = 不使用
    std::string ssh_key;                 // 必填，SSH 私钥路径
    std::string ssh_user    = "root";
    std::string workdir;                 // 必填，实例独立工作目录（不存在则创建）
    // QEMU serial 字节流日志文件；空 = 不落盘（仅通过 serial socket 供 watcher 消费）
    std::string serial_log_path;
    // 第二串口（guest ttyS1）的独立落盘路径，专供 worker 诊断输出（[WORKER] 前缀
    // 行：[RfzTL] / [WorkerPerfStage] 等）。与 serial_log_path(ttyS0, kernel
    // console) 分开，避免 kernel printk 插进行中把诊断行截断成有偏样本。
    // 空 = 不添加第二串口；此时 guest 侧打不开 ttyS1，诊断输出为空（fail-closed，
    // 见 worker/log/log_macros.hpp：绝不回退到 ttyS0）。
    std::string worker_log_path;
    int         index       = 0;         // 实例编号（-name 参数 + 日志前缀）
    int         cpu         = 2;         // vCPU 数
    int         mem_mb      = 2048;      // 内存（MB）

    // ── 设备 ─────────────────────────────────────────────────
    // image_device：块设备接入方式（"hda" | "virtio-blk-device"）
    std::string image_device      = "hda";
    // rng_dev_override：非空时覆盖 arch 默认 rng 设备
    std::string rng_dev_override;

    // ── 行为 ─────────────────────────────────────────────────
    // snapshot=true：-snapshot，磁盘写不持久化，Stop() 直接 SIGKILL
    bool        snapshot       = true;
    // snapshot_fuzzing=true：syzkaller-style snapshot 模式（savevm/loadvm 每
    // testcase 还原）。需要**可写 qcow2** disk_image 且**去掉 `-snapshot`**（两者
    // 不兼容）；amd64 CPU 变为 host,migratable=on,tsc=off。与上面的 `snapshot`
    // （旧的磁盘 CoW-overlay flag）正交。默认 off → continuous 参数零变化。
    // 见 docs/plans/snapshot-mode.md。
    bool        snapshot_fuzzing = false;
    // no_reboot=true：-no-reboot，内核 panic 时 QEMU 进程退出，IsAlive() 立即感知
    bool        no_reboot      = true;
    // 追加到 ArchConfig 基础命令行的内核参数
    std::string kernel_cmdline  = "panic=1 oops=panic";
    // persistent_ssh=true：ControlMaster 模式，StartVM 后建立持久连接
    bool        persistent_ssh  = false;

    // ── ivshmem ──────────────────────────────────────────────
    // R-001 模式一致性约束：
    //   plain/doorbell 双模式共享同一 V2 字段契约（WorkerCtrl/TaskSlot/CompletionSlot/
    //   StepEventRing）和同一状态机语义。两种模式的唯一差异在于通知机制：
    //     plain   — Transport::Poll 使用 sleep 轮询 SweepAllSlots
    //     doorbell — Transport::Poll 使用 epoll_wait + eventfd 事件驱动
    //   不允许运行期静默降级（doorbell 失败不得隐式切回 plain）。
    //
    // ivshmem_mode: "plain" | "doorbell"
    std::string ivshmem_mode    = "plain";
    // plain 模式必填：shm 文件路径
    std::string ivshmem_path;
    // 共享内存大小（字节，2 的次幂）；plain 模式必填；由 Infra 计算后注入
    uint64_t    ivshmem_bytes   = 0;
    // doorbell 模式必填：unix socket 路径
    std::string ivshmem_socket;
    // doorbell 模式 MSI-X 向量数（>= 1）
    int         ivshmem_vectors = 1;

    // ── QMP ──────────────────────────────────────────────────
    bool          qmp_enable      = true;
    std::string   qmp_host        = "127.0.0.1";
    QmpPortPolicy qmp_port_policy = QmpPortPolicy::kAutoAllocate;
    // policy=kFixed 时使用（必须 > 0）
    int           qmp_fixed_port  = 0;

    // ── 超时（统一 milliseconds）─────────────────────────────
    // [boot_timeout bump 2026-05-12] full-fuzz kernel (4356 CONFIG=y +
    // KASAN + DEBUG_INFO) 启动时间显著拉长 (kernel timestamp 到 59s 才
    // ssh.service started,加上 socket listen 实际 60-61s)。原 60s 默认
    // 踩边界 → SSH timeout。 提到 180s 留余量,且兼容更慢 setup。
    std::chrono::milliseconds boot_timeout             {180'000};
    std::chrono::milliseconds deploy_timeout           {30'000};
    std::chrono::milliseconds start_worker_timeout     {10'000};
    std::chrono::milliseconds stop_worker_timeout      { 5'000};
    std::chrono::milliseconds graceful_stop_timeout    { 5'000};
    std::chrono::milliseconds ssh_master_ready_timeout { 5'000};
};

// ============================================================
// RuntimeConfig — 对外聚合（池 + 实例，不含 WorkerConfig）
// ============================================================
// WorkerConfig 已移至 channel/worker/，由 QemuChannel 单独持有并在
// RuntimePool::CreateInstance(worker_cfg) 时注入。

struct RuntimeConfig {
    RuntimePoolConfig     pool;
    RuntimeInstanceConfig instance;
};

} // namespace refuzz::channel::runtime
