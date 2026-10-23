#pragma once

// DoorbellServer — ivshmem-server 协议服务端（data 层私有基础设施）
//
// 职责：在 doorbell 模式下桥接 QEMU 与 host DataPlane 的 eventfd 交换。
// ivshmem-server 协议三方：
//   - DoorbellServer（本类）：运行在 host，监听 Unix socket
//   - QEMU（peer 0）：启动时立即连接
//   - host IvshmemDataPlane（peer 1）：Prepare() 中 OpenDoorbell() 时连接
//
// 使用约束：
//   - Start() 必须在 Runtime::StartVM() 之前调用（QEMU 启动即连接）
//   - Start() 在 ShmInfra::Init() 之后调用（shm 文件已创建，WaitForShm 立即返回）
//   - Stop()  在 Runtime::Stop() 之后调用（QEMU 进程已退出）
//
// 协议帧格式（每帧 8 字节整数 + 可选 SCM_RIGHTS fd）：
//   帧1: val=0, no fd    — protocol version
//   帧2: val=peer_id, no fd — 分配的 peer id
//   帧3: val=-1, fd=shm_fd  — 共享内存 fd
//   帧4..3+n: fd=qemu_efd[i] — QEMU 的中断向量（host 侧丢弃）
//   帧4+n..3+2n: fd=vm_efd[i] — host 的中断向量（QEMU 写入触发 host epoll 唤醒）
//
// 文件组织演进：
//   - v2：transport/include/refuzz/channel/transport/doorbell_server.hpp，命名空间 refuzz::channel::transport
//   - v3 Phase 10（本次收尾）：搬至 data/，命名空间改为 refuzz::channel::data；
//     transport/ 目录整体清退，"transport" 在 v3 里已不再是组件名。

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace refuzz::channel::data {

class DoorbellServer {
public:
    // socket_path: 服务器监听的 Unix socket 路径
    // shm_path:    ShmInfra 创建的共享内存文件路径
    // n_workers:   worker 数量（= ivshmem-doorbell 向量数）
    DoorbellServer(std::string socket_path,
                   std::string shm_path,
                   int         n_workers);
    ~DoorbellServer();

    DoorbellServer(const DoorbellServer&) = delete;
    DoorbellServer& operator=(const DoorbellServer&) = delete;

    // 启动服务器线程（监听 socket，等待 QEMU 和 host 连接）
    // 返回 false 表示 socket/eventfd 初始化失败
    bool Start();

    // 停止服务器线程，关闭所有 fd，删除 socket 文件
    void Stop();

private:
    // 发送带可选 fd 的 8 字节帧（SCM_RIGHTS），attach_fd<0 表示不附带 fd
    static bool SendMsg(int sock, uint64_t val, int attach_fd);

    // 等待 shm 文件出现并打开（最多等待 30s）
    bool WaitForShm();

    // 服务器主循环（thread_ 入口）
    void Run();

    std::string socket_path_;
    std::string shm_path_;
    int         n_workers_;

    int server_fd_{-1};
    int shm_fd_{-1};
    std::vector<int> vm_efd_;    // guest→host eventfd（QEMU 写，host epoll 读）
    std::vector<int> qemu_efd_;  // host→guest eventfd（dummy，host 侧丢弃）

    std::atomic<bool> stop_{false};
    std::thread       thread_;
};

} // namespace refuzz::channel::data
