// Copyright 2026 reFuzz project author -------youngkk.
//
// ExecutionObservation —— transient per-event observation 容器(framework primitive)。
//
// 用途:每次 IFeedbackEngine::Process 收集到的本次 event 的执行 observation,通过
// EngineOutput.observation 暴露给 dispatcher / 后续 stage。distinct wrapper 围绕
// `core::MetadataMap`,**不**做 alias — 让 transient observation 跟 durable
// `Seed.metadata` 在源码 / grep / error 都看得见区分。
//
// 跟 Seed.metadata 区分:
//   - Seed.metadata           = durable seed state(持久化到 metadata.json,
//                                跨 conversation 存活)
//   - ExecutionObservation    = transient per-event observation(只活在
//                                EngineOutput / SignalContribution / dispatcher
//                                调用栈,event 处理完即消亡)
//
// dispatcher / materializer 可以把 transient observation 提炼成 durable summary
// metadata,再进入 admit 出去的 new_seed.metadata 通过 PR-W3 metadata serde
// registry 持久化(具体提炼策略 family 自决,framework 不预设)。
//
// 设计:
//   - 复用 core::MetadataMap impl(已验证容器,Set/Get/Has/Remove/GetOrCreate)
//   - 加 MergeFrom 通过 core::MetadataMap::MergeFrom 转发
//   - 暴露 9 个 API:Set/Get/Has/Remove/GetOrCreate/MergeFrom/Clear/Empty/Size
//   - distinct type 让 grep "ExecutionObservation" 能跟 Seed.metadata 区分
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-W2。

#pragma once

#include "refuzz/core/metadata.hpp"

#include <cstddef>

namespace refuzz::fuzzer {

class ExecutionObservation {
public:
    template<typename T>
    void Set(T value)
    {
        map_.Set(std::move(value));
    }

    template<typename T>
    T* Get()
    {
        return map_.Get<T>();
    }

    template<typename T>
    const T* Get() const
    {
        return map_.Get<T>();
    }

    template<typename T>
    T& GetOrCreate()
    {
        return map_.GetOrCreate<T>();
    }

    template<typename T>
    bool Has() const
    {
        return map_.Has<T>();
    }

    template<typename T>
    bool Remove()
    {
        return map_.Remove<T>();
    }

    // 把 other 的所有键值合并进本容器;同类型 key 后写覆盖前写。
    // composite engine 按 signal 注册顺序调用此 method 聚合 contribs.observation。
    void MergeFrom(const ExecutionObservation& other)
    {
        map_.MergeFrom(other.map_);
    }

    void   Clear()       { map_.Clear(); }
    bool   Empty() const { return map_.Empty(); }
    size_t Size()  const { return map_.Size(); }

private:
    refuzz::core::MetadataMap map_;
};

}  // namespace refuzz::fuzzer
