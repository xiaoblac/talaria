#pragma once

#include "refuzz/core/error.hpp"

#include <concepts>
#include <string_view>

namespace refuzz::core {

// IService — 运行时多态基类
// 所有拥有线程、子进程、句柄等外部资源的运行时服务实现此接口
class IService {
public:
    virtual ~IService() = default;

    virtual std::string_view Name() const = 0;

    virtual ServiceResult Init()  = 0;
    virtual ServiceResult Start() = 0;
    virtual ServiceResult Stop()  = 0;
    virtual bool IsRunning() const = 0;
};

template<typename T>
concept ServiceLike = requires(const T& svc, T& mut) {
    { mut.Init() } -> std::same_as<ServiceResult>;
    { mut.Start() } -> std::same_as<ServiceResult>;
    { mut.Stop() } -> std::same_as<ServiceResult>;
    { svc.Name() } -> std::convertible_to<std::string_view>;
    { svc.IsRunning() } -> std::convertible_to<bool>;
};

} // namespace refuzz::core
