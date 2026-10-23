// Copyright 2026 reFuzz project author -------youngkk.


#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <memory>
#include <functional>
#include <map>

namespace refuzz {
namespace vm {

// ========== 基础类型 ==========

using Bytes = std::vector<uint8_t>;

// 超时配置
struct Timeouts {
    std::chrono::seconds scale{1};           // 时间缩放因子
    std::chrono::seconds vm_boot{5 * 60};    // VM 启动超时
    std::chrono::seconds no_output{3 * 60};  // 无输出超时
    std::chrono::seconds program{5 * 60};    // 程序执行超时
};

// VM 环境配置
struct VMEnv {
    std::string name;          // 唯一名称
    std::string os;            // 目标操作系统 (linux/freebsd/etc)
    std::string arch;          // 目标架构 (amd64/arm64/etc)
    std::string workdir;       // 工作目录
    std::string image;         // 镜像路径
    std::string ssh_key;       // SSH 密钥路径
    std::string ssh_user;      // SSH 用户名
    std::string kernel_src;    // 内核源码路径 (可选)

    Timeouts timeouts;
    bool snapshot = false;     // 是否使用快照模式
    bool debug = false;        // 调试模式

    // VM 类型特定配置 (JSON 字符串)
    std::string type_config;
};

// 错误类型
enum class ErrorType {
    None,
    Boot,           // 启动错误
    Infrastructure, // 基础设施错误
    Timeout,        // 超时
    Connection,     // 连接错误
    Command,        // 命令执行错误
};

// 错误结果
struct Error {
    ErrorType type = ErrorType::None;
    std::string message;
    Bytes output;  // 相关输出

    Error() = default;
    Error(ErrorType t, const std::string& msg)
        : type(t), message(msg) {}
    Error(ErrorType t, const std::string& msg, const Bytes& out)
        : type(t), message(msg), output(out) {}

    bool ok() const { return type == ErrorType::None; }
    explicit operator bool() const { return !ok(); }
};

// ========== 操作结果 ==========

template<typename T>
struct Result {
    std::optional<T> value;
    Error error;

    Result() = default;
    Result(T val) : value(std::move(val)) {}
    Result(Error err) : error(std::move(err)) {}

    bool ok() const { return value.has_value(); }
    explicit operator bool() const { return ok(); }

    T& operator*() { return *value; }
    const T& operator*() const { return *value; }
    T* operator->() { return &(*value); }
    const T* operator->() const { return &(*value); }
};

// 特化 void 类型
template<>
struct Result<void> {
    Error error;

    Result() = default;
    Result(Error err) : error(std::move(err)) {}

    bool ok() const { return error.ok(); }
    explicit operator bool() const { return ok(); }
};

// ========== SSH 配置 ==========

struct SSHOptions {
    std::string host = "localhost";
    int port = 22;
    std::string user = "root";
    std::string key_path;
    bool debug = false;
};

// ========== VM 信息 ==========

struct VMInfo {
    std::string vmm_version;  // VMM 版本
    std::string vmm_args;     // VMM 参数
    std::string kernel;       // 内核路径
    std::string image;        // 镜像路径
};

// ========== 执行结果 ==========

struct RunResult {
    Bytes output;           // 合并的输出 (stdout + stderr + console)
    int exit_code = 0;      // 退出码
    bool timeout = false;   // 是否超时
    Error error;            // 错误信息

    bool ok() const { return error.ok() && !timeout; }
};

// ========== 退出条件 ==========

enum class ExitCondition {
    Timeout = 1 << 0,  // 允许超时退出
    Normal  = 1 << 1,  // 允许正常退出
    Error   = 1 << 2,  // 允许错误退出
};

inline ExitCondition operator|(ExitCondition a, ExitCondition b) {
    return static_cast<ExitCondition>(static_cast<int>(a) | static_cast<int>(b));
}

inline bool operator&(ExitCondition a, ExitCondition b) {
    return (static_cast<int>(a) & static_cast<int>(b)) != 0;
}

// ========== 回调类型 ==========

using OutputCallback = std::function<void(const Bytes&)>;
using ErrorCallback = std::function<void(const Error&)>;
using CompletionCallback = std::function<void()>;

} // namespace vm
} // namespace refuzz
