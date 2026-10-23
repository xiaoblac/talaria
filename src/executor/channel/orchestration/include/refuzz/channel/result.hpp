#pragma once

// channel 组件共享的错误类型与 Result 模板
// 所有可失败操作的返回类型，统一错误分类，避免各组件自行定义
// 设计来源：docs/channel-redesign/shared-contracts.md §3.1

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace refuzz::channel {

// 错误种类枚举，覆盖 channel 层所有组件的故障分类
// 需要新增枚举值时，必须先修改 shared-contracts.md 和本文件，不得在组件内自行定义
enum class ErrorKind : uint8_t {
    kInfra,      // shm 操作失败（mmap/ftruncate/unlink）
    kConfig,     // 配置校验失败（Runtime.Create、Transport 构造等），对象未构造或无副作用
    kBoot,       // VM 启动失败（QEMU 进程未起来、SSH 不可达）
    kTimeout,    // 操作超时（SSH 命令、worker 注册等待、Recv 等待）
    kConnection, // SSH 连接失败、doorbell 连接失败
    kCommand,    // VM 内命令执行失败（非零退出码）
    kProtocol,   // shm 协议违规（magic 不匹配、slot 状态非法、REG_DEAD）
    kRecovery,   // 恢复操作失败
};

// 错误载体：故障种类 + 可读描述
struct Error {
    ErrorKind   kind    = ErrorKind::kInfra;
    std::string message;
};

// Result<T> — 可失败操作的返回类型（非 void 版本）
// 内部使用 std::variant<T, Error> 存储成功值或错误，不引入额外堆分配
template <typename T>
class Result {
public:
    // 成功构造：生产侧使用
    static Result Ok(T value) {
        Result r;
        r.storage_ = std::move(value);
        return r;
    }

    // 失败构造：生产侧使用，支持 `return Error{...};` 隐式转换写法
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error error) : storage_(std::move(error)) {}

    // 消费侧接口 —————————————————————————————————————

    // 是否成功（true = 成功，value() 可调用；false = 失败，error() 可调用）
    bool ok() const noexcept {
        return std::holds_alternative<T>(storage_);
    }

    // 读取成功值（调用方必须先确认 ok() == true）
    T& value() {
        return std::get<T>(storage_);
    }

    const T& value() const {
        return std::get<T>(storage_);
    }

    // 读取错误（调用方必须先确认 ok() == false）
    const Error& error() const {
        return std::get<Error>(storage_);
    }

private:
    // 默认构造仅供 Ok() 静态工厂使用
    Result() = default;

    // variant 第一个类型为成功类型，第二个为错误类型
    std::variant<T, Error> storage_;
};

// Result<void> 特化 — 成功时无返回值，失败时携带 Error
// 接口与非 void 版本保持一致，消除调用方的模板特化感知
template <>
class Result<void> {
public:
    // 成功构造：生产侧使用
    static Result Ok() {
        return Result{};
    }

    // 失败构造：生产侧使用，支持 `return Error{...};` 隐式转换写法
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error error) : error_(std::move(error)), ok_(false) {}

    // 消费侧接口 —————————————————————————————————————

    // 是否成功
    bool ok() const noexcept {
        return ok_;
    }

    // 读取错误（调用方必须先确认 ok() == false）
    const Error& error() const {
        return *error_;
    }

private:
    // 成功构造（仅 Ok() 使用）
    Result() : ok_(true) {}

    // 失败时才填充 error_；成功时为空，避免无意义默认构造
    // 使用 std::optional 而非裸 Error，确保成功路径零额外开销
    // （std::optional<Error> 的 string 成员在 !ok_ 时才分配堆内存）
    std::optional<Error> error_;
    bool                 ok_ = true;
};

} // namespace refuzz::channel
