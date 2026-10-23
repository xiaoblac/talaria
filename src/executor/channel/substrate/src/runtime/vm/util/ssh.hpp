// Copyright 2026 reFuzz project author -------youngkk.


#pragma once

#include "../types.hpp"
#include <string>
#include <vector>
#include <chrono>

namespace refuzz {
namespace vm {
namespace util {

/**
 * SSH 客户端工具类
 * 封装 SSH 命令执行
 */
class SSH {
public:
    explicit SSH(const SSHOptions& options);
    ~SSH() = default;

    /**
     * 等待 SSH 服务可用
     * @param timeout 超时时间
     * @return 是否成功连接
     */
    bool WaitForConnection(std::chrono::seconds timeout);

    /**
     * 执行命令
     * @param command 要执行的命令
     * @param timeout 超时时间
     * @return 执行结果
     */
    RunResult Run(
        const std::string& command,
        std::chrono::seconds timeout
    );

    /**
     * 异步执行命令
     * @param command 要执行的命令
     * @param output_callback 输出回调
     * @param completion_callback 完成回调 (参数为退出码)
     */
    void RunAsync(
        const std::string& command,
        OutputCallback output_callback,
        std::function<void(int)> completion_callback
    );

    /**
     * 复制文件到远程主机
     * @param local_path 本地文件路径
     * @param remote_path 远程文件路径
     * @return 是否成功
     */
    bool CopyTo(const std::string& local_path, const std::string& remote_path);

    /**
     * 从远程主机复制文件
     * @param remote_path 远程文件路径
     * @param local_path 本地文件路径
     * @return 是否成功
     */
    bool CopyFrom(const std::string& remote_path, const std::string& local_path);

    /**
     * 构建 SSH 命令参数
     */
    std::vector<std::string> BuildSSHArgs(const std::vector<std::string>& extra = {}) const;

    /**
     * 构建 SCP 命令参数
     */
    std::vector<std::string> BuildSCPArgs() const;

    /**
     * 获取连接字符串
     */
    std::string ConnectionString() const;

private:
    SSHOptions options_;
    bool debug_ = false;
};

/**
 * SSH 密钥生成器
 */
class SSHKeyGen {
public:
    /**
     * 生成 SSH 密钥对
     * @param output_path 输出路径 (不含扩展名)
     * @param key_type 密钥类型 (rsa, ed25519, etc)
     * @param bits 密钥位数
     * @return 是否成功
     */
    static bool Generate(
        const std::string& output_path,
        const std::string& key_type = "rsa",
        int bits = 2048
    );

    /**
     * 检查密钥文件是否存在且有效
     */
    static bool Validate(const std::string& key_path);
};

} // namespace util
} // namespace vm
} // namespace refuzz
