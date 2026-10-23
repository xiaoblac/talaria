// doorbell_server.cpp — ivshmem-server 协议服务端实现（v3 data 层私有）
//
// 从 tests/channel_qemu_e2e_test.cpp 中的 MiniDoorbellServer 提取为生产组件。
// 协议序列说明见头文件注释。
//
// v3 Phase 10 收尾：从 transport/src/ 搬到 data/src/，命名空间由
// refuzz::channel::transport 改为 refuzz::channel::data；transport/ 目录整体清退。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "refuzz/channel/data/doorbell_server.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace refuzz::channel::data {

DoorbellServer::DoorbellServer(std::string socket_path,
                               std::string shm_path,
                               int         n_workers)
    : socket_path_(std::move(socket_path))
    , shm_path_(std::move(shm_path))
    , n_workers_(n_workers)
{}

DoorbellServer::~DoorbellServer()
{
    Stop();
}

bool DoorbellServer::Start()
{
    // 提前创建 eventfd（在 Run() 线程外创建，确保启动前就绪）
    vm_efd_.resize(n_workers_, -1);
    qemu_efd_.resize(n_workers_, -1);
    for (int i = 0; i < n_workers_; ++i) {
        vm_efd_[i]   = eventfd(0, EFD_CLOEXEC);
        qemu_efd_[i] = eventfd(0, EFD_CLOEXEC);
        if (vm_efd_[i] < 0 || qemu_efd_[i] < 0) {
            fprintf(stderr, "[doorbell_server] eventfd() failed: %s\n", strerror(errno));
            return false;
        }
    }

    // 创建 Unix stream socket 并绑定监听
    server_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd_ < 0) {
        fprintf(stderr, "[doorbell_server] socket() failed: %s\n", strerror(errno));
        return false;
    }

    // 清理上次残留的 socket 文件
    ::unlink(socket_path_.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[doorbell_server] socket_path too long\n");
        return false;
    }
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "[doorbell_server] bind() failed: %s\n", strerror(errno));
        return false;
    }
    if (listen(server_fd_, 4) < 0) {
        fprintf(stderr, "[doorbell_server] listen() failed: %s\n", strerror(errno));
        return false;
    }

    stop_.store(false);
    thread_ = std::thread([this] { Run(); });
    return true;
}

void DoorbellServer::Stop()
{
    stop_.store(true);

    // 关闭 server_fd_ 触发 Run() 中 accept() 返回错误，唤醒线程
    if (server_fd_ >= 0) {
        ::close(server_fd_);
        server_fd_ = -1;
    }
    if (thread_.joinable()) thread_.join();

    // 关闭 eventfd
    for (int fd : vm_efd_)   if (fd >= 0) ::close(fd);
    for (int fd : qemu_efd_) if (fd >= 0) ::close(fd);
    vm_efd_.clear();
    qemu_efd_.clear();

    if (shm_fd_ >= 0) { ::close(shm_fd_); shm_fd_ = -1; }
    ::unlink(socket_path_.c_str());
}

// ── 发送带 fd 的 8 字节消息（SCM_RIGHTS），attach_fd<0 表示不附带 ──────
bool DoorbellServer::SendMsg(int sock, uint64_t val, int attach_fd)
{
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<uint8_t>((val >> (8 * i)) & 0xffu);

    if (attach_fd < 0) {
        ssize_t n = send(sock, buf, 8, MSG_NOSIGNAL);
        return n == 8;
    }

    union {
        char           raw[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl{};
    std::memset(&ctrl, 0, sizeof(ctrl));

    struct iovec iov{};
    iov.iov_base = buf;
    iov.iov_len  = 8;

    struct msghdr msg{};
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl.raw;
    msg.msg_controllen = sizeof(ctrl.raw);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &attach_fd, sizeof(int));

    ssize_t n = sendmsg(sock, &msg, MSG_NOSIGNAL);
    return n == 8;
}

// ── 等待 shm 文件出现并打开（最多等待 30s）────────────────────────────
bool DoorbellServer::WaitForShm()
{
    const int kMaxRetries = 300; // 300 * 100ms = 30s
    for (int i = 0; i < kMaxRetries; ++i) {
        if (stop_.load()) return false;
        int fd = open(shm_path_.c_str(), O_RDWR);
        if (fd >= 0) {
            shm_fd_ = fd;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    fprintf(stderr, "[doorbell_server] timeout waiting for shm file: %s\n",
            shm_path_.c_str());
    return false;
}

// ── 服务器主循环 ──────────────────────────────────────────────────────
void DoorbellServer::Run()
{
    // 步骤 1：等待 shm 文件（由 ShmInfra::Init() 创建）
    if (!WaitForShm()) return;

    // 步骤 2：接受 QEMU 连接（peer 0）
    // QEMU 启动后立即连接 socket，必须在 StartVM() 之前 listen()
    int qemu_conn = ::accept(server_fd_, nullptr, nullptr);
    if (qemu_conn < 0) {
        if (!stop_.load())
            fprintf(stderr, "[doorbell_server] accept QEMU failed: %s\n", strerror(errno));
        return;
    }

    // QEMU 握手帧（3 条初始帧，此时无其他 peer，不发 extra 帧）
    bool ok = true;
    ok = ok && SendMsg(qemu_conn, 0, -1);               // 帧1: protocol=0
    ok = ok && SendMsg(qemu_conn, 0, -1);               // 帧2: peer_id=0
    ok = ok && SendMsg(qemu_conn, UINT64_MAX, shm_fd_); // 帧3: shm_fd
    if (!ok) {
        fprintf(stderr, "[doorbell_server] failed to send QEMU handshake\n");
        ::close(qemu_conn);
        return;
    }

    // 步骤 3：接受 host DataPlane 连接（peer 1）
    // IvshmemDataPlane::OpenDoorbell() 在 Prepare() 中调用
    int host_conn = ::accept(server_fd_, nullptr, nullptr);
    if (host_conn < 0) {
        if (!stop_.load())
            fprintf(stderr, "[doorbell_server] accept host failed: %s\n", strerror(errno));
        ::close(qemu_conn);
        return;
    }

    // host 握手帧
    ok = true;
    ok = ok && SendMsg(host_conn, 0, -1);               // 帧1: protocol=0
    ok = ok && SendMsg(host_conn, 1, -1);               // 帧2: peer_id=1
    ok = ok && SendMsg(host_conn, UINT64_MAX, shm_fd_); // 帧3: shm_fd

    // n 帧 qemu_efd（host→guest 方向，host 收到后直接丢弃）
    for (int i = 0; i < n_workers_ && ok; ++i)
        ok = ok && SendMsg(host_conn, 0, qemu_efd_[i]);

    // n 帧 vm_efd（guest→host 方向，host 注册 epoll 监听）
    for (int i = 0; i < n_workers_ && ok; ++i)
        ok = ok && SendMsg(host_conn, 0, vm_efd_[i]);

    if (!ok) {
        fprintf(stderr, "[doorbell_server] failed to send host handshake\n");
        ::close(qemu_conn);
        ::close(host_conn);
        return;
    }

    // 步骤 4：向 QEMU 发送 host (peer 1) 的 interrupt vectors
    // guest 写 doorbell(peer=1, vector=i) → QEMU 写 vm_efd[i] → host epoll 唤醒
    for (int i = 0; i < n_workers_ && ok; ++i)
        ok = ok && SendMsg(qemu_conn, 1, vm_efd_[i]);

    if (!ok)
        fprintf(stderr, "[doorbell_server] failed to send peer-join frames to QEMU\n");

    // 步骤 5：保持连接直到 Stop() 被调用
    // QEMU 的 ivshmem 设备需要 socket 连接持续存在
    while (!stop_.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    ::close(qemu_conn);
    ::close(host_conn);
}

} // namespace refuzz::channel::data
