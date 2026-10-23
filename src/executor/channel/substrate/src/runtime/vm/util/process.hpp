// Copyright 2026 reFuzz project author -------youngkk.


#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <memory>
#include <thread>
#include <unistd.h>

namespace refuzz {
namespace vm {
namespace util {

/**
 * 进程管理工具类
 */
class Process {
public:
    struct CommandResult {
        std::string output;
        int exit_code = 0;
        bool timed_out = false;
    };

    struct Options {
        std::string workdir;                          // 工作目录
        std::vector<std::string> env;                 // 环境变量
        bool redirect_stderr = true;                  // 重定向 stderr 到 stdout
        std::function<void(const char*, size_t)> output_callback;  // 输出回调
    };

    /**
     * 启动进程
     * @param program 程序路径
     * @param args 参数列表
     * @param options 选项
     */
    Process(const std::string& program,
            const std::vector<std::string>& args,
            const Options& options);

    ~Process();

    // 禁止拷贝
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    /**
     * 获取进程 PID
     */
    pid_t Pid() const { return pid_; }

    /**
     * 检查进程是否正在运行
     */
    bool IsRunning() const;

    /**
     * 等待进程结束
     * @param timeout 超时时间，0 表示无限等待
     * @return 退出码，超时返回 -1
     */
    int Wait(std::chrono::seconds timeout = std::chrono::seconds(0));

    /**
     * 杀死进程
     * @param force 是否强制杀死 (SIGKILL)
     */
    void Kill(bool force = false);

    /**
     * 读取进程输出
     * @param buffer 缓冲区
     * @param size 缓冲区大小
     * @return 读取的字节数，0 表示 EOF，-1 表示错误
     */
    ssize_t ReadOutput(void* buffer, size_t size);

    /**
     * 写入进程输入
     * @param data 数据
     * @param size 数据大小
     * @return 写入的字节数，-1 表示错误
     */
    ssize_t WriteInput(const void* data, size_t size);

    /**
     * 关闭输入管道
     */
    void CloseInput();

    /**
     * 获取输出文件描述符
     */
    int OutputFd() const { return stdout_pipe_[0]; }

    /**
     * 静态方法：运行命令并获取输出
     */
    static std::pair<std::string, int> RunCommand(
        const std::string& program,
        const std::vector<std::string>& args,
        std::chrono::seconds timeout = std::chrono::seconds(60)
    );

    static CommandResult RunCommandDetailed(
        const std::string& program,
        const std::vector<std::string>& args,
        std::chrono::seconds timeout = std::chrono::seconds(60)
    );

private:
    void SetupPipes();
    void SetupChild();
    void StartOutputReader();
    void JoinOutputReader();

    pid_t pid_ = -1;
    int stdin_pipe_[2] = {-1, -1};
    int stdout_pipe_[2] = {-1, -1};
    int stderr_pipe_[2] = {-1, -1};
    Options options_;
    bool input_closed_ = false;
    std::thread output_thread_;
};

/**
 * 端口工具
 */
class PortUtil {
public:
    /**
     * 查找未使用的 TCP 端口
     * @param start 起始端口
     * @param end 结束端口
     * @return 可用端口，失败返回 0
     */
    static int FindUnusedPort(int start = 10000, int end = 65535);

    /**
     * 检查端口是否被使用
     */
    static bool IsPortInUse(int port);
};

/**
 * 文件系统工具
 */
class FileUtil {
public:
    /**
     * 检查文件是否存在
     */
    static bool Exists(const std::string& path);

    /**
     * 创建目录（递归）
     */
    static bool MkdirAll(const std::string& path);

    /**
     * 删除目录（递归）
     */
    static bool RemoveAll(const std::string& path);

    /**
     * 复制文件
     */
    static bool CopyFile(const std::string& src, const std::string& dst);

    /**
     * 读取文件内容
     */
    static std::string ReadFile(const std::string& path);

    /**
     * 写入文件内容
     */
    static bool WriteFile(const std::string& path, const std::string& content);

    /**
     * 获取临时目录
     */
    static std::string TempDir();

    /**
     * 创建临时目录
     */
    static std::string MakeTempDir(const std::string& prefix);
};

} // namespace util
} // namespace vm
} // namespace refuzz
