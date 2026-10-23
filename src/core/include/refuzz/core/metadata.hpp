#pragma once

#include <any>
#include <cstddef>
#include <typeindex>
#include <unordered_map>

namespace refuzz::core {

// MetadataMap — std::any-based metadata bus; keys use std::type_index (stable across compilers).
class MetadataMap {
public:
    template<typename T>
    void Set(T value)
    {
        data_[std::type_index(typeid(T))] = std::move(value);
    }

    template<typename T>
    T* Get()
    {
        auto it = data_.find(std::type_index(typeid(T)));
        if (it == data_.end()) {
            return nullptr;
        }
        return std::any_cast<T>(&it->second);
    }

    template<typename T>
    const T* Get() const
    {
        auto it = data_.find(std::type_index(typeid(T)));
        if (it == data_.end()) {
            return nullptr;
        }
        return std::any_cast<const T>(&it->second);
    }

    template<typename T>
    T& GetOrCreate()
    {
        auto& slot = data_[std::type_index(typeid(T))];
        if (!slot.has_value()) {
            slot = T{};
        }
        return *std::any_cast<T>(&slot);
    }

    template<typename T>
    bool Remove()
    {
        return data_.erase(std::type_index(typeid(T))) > 0;
    }

    template<typename T>
    bool Has() const
    {
        return data_.count(std::type_index(typeid(T))) > 0;
    }

    // [v2 batch 3 PR-W2] 把 other 中所有键值复制进本容器;同 type_index 的 key
    // **后写覆盖前写**(即 self.MergeFrom(other) 后,other 的 key 优先)。
    // 用途:composite feedback engine 按 signal 注册顺序合并 contribs.observation;
    // 后注册同类型 observation 覆盖前注册的(详 docs/admit-pipeline-alignment/
    // 300_batch3_kernel_profile_stages.md §3.PR-W2 Q1b)。
    void MergeFrom(const MetadataMap& other)
    {
        for (const auto& kv : other.data_) {
            data_[kv.first] = kv.second;  // 同 key 覆盖(unordered_map operator[] 语义)
        }
    }

    size_t Size() const { return data_.size(); }
    bool Empty() const { return data_.empty(); }
    void Clear() { data_.clear(); }

private:
    std::unordered_map<std::type_index, std::any> data_;
};

} // namespace refuzz::core
