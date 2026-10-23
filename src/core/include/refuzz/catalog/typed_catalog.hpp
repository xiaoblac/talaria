// Copyright 2026 reFuzz project author -------youngkk.
//
// TypedCatalog<Traits>
//
// 通用的"组件目录"模板:领域模块把自己的具体实现(如 SyzMutatorEngine)
// 注册进一个 Catalog;装配层(Assembler)不直接依赖具体类型,只通过
// Catalog::Build("id", ctx) 获取 unique_ptr<Product>。
//
// 目标:
//   1. 替代 orchestrator::TargetProfile 内嵌 11 个 std::function 工厂的模式;
//   2. 取消 REGISTER_PROFILE 静态初始化 + -Wl,--whole-archive 的 hack;
//   3. 让组件选择从"硬编码在 Orchestrator::Build()"变成"按字符串 id 查表",
//      为 JSON/交互两种前端统一底层装配流程。
//
// Traits 约定(由各领域模块提供):
//   struct MyTraits {
//     using Product = IMyInterface;
//     struct BuildContext {
//       // 该组件构造时依赖的上下文(可持有已构造的其他组件指针、配置等)
//     };
//   };
//
// 使用:
//   using MyCatalog = refuzz::catalog::TypedCatalog<MyTraits>;
//   MyCatalog cat;
//   cat.Register({.meta={...}, .build=[](const auto& ctx){...}});
//   auto prod = cat.Build("id", ctx);

#pragma once

#include "refuzz/core/error.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz::catalog {

// 每个 Catalog 条目的元信息。交互模式用 display_name/description 做菜单展示;
// JSON 模式按 id 做选择键。
struct ComponentMeta {
    std::string id;            // 稳定选择键,如 "syz"、"round_robin"
    std::string display_name;  // 人读名称,如 "Syzkaller Engine"
    std::string description;   // 简短说明
};

// TypedCatalog<Traits>:泛型目录容器,按 id 查找并构造 Product。
//
// Traits::Product      : 接口类型(如 IMutatorEngine)
// Traits::BuildContext : 构造时依赖的上下文(如 ICorpusStore*, const Config*)
template <typename Traits>
class TypedCatalog {
public:
    using Product      = typename Traits::Product;
    using BuildContext = typename Traits::BuildContext;

    // 工厂:给定 BuildContext 产出 Product 实例,失败则返回 ComponentError。
    using FactoryFn = std::function<
        core::Result<std::unique_ptr<Product>>(const BuildContext&)>;

    // 可选校验:在 Build 前做轻量前置检查(配置合法性、依赖齐备等)。
    // 返回 true 表示通过;返回 false 时写入 err 描述原因。
    using ValidateFn = std::function<bool(const BuildContext&, std::string& err)>;

    struct Entry {
        ComponentMeta meta;
        FactoryFn     build;
        ValidateFn    validate;  // 可为空
    };

    // 【注册约束】catalog entry 的 build lambda 必须满足:
    //   1. 仅依赖传入的 BuildContext 字段和 catalog-external 的**静态资源**
    //      (例如全局 const 表、项目级单例的只读 API)。
    //   2. 不得依赖"其他 entry 运行时产生的状态"(其他 engine 已经被 Build
    //      出来之类)—— Assembler 会对 catalog 的所有 entry 顺序 Build,任何
    //      一个失败即整体失败。
    //   3. 不得在构造期持有全局可变状态的引用(线程安全由 BuildContext 提供者
    //      保证,不应由 build lambda 自行维护)。
    //
    // 这条契约保证 Assembler 的 "全装 + 一次 Switch" 装配模式下,装配顺序不
    // 影响结果;任何运行时协调能力应在 engine 内部 lazy apply(见 IXxxEngine
    // v2 契约),而非装配期。

    // 注册一个工厂条目。重复 id 以最后一次注册为准(方便测试中覆盖 mock)。
    void Register(Entry entry) {
        std::string id = entry.meta.id;
        entries_[std::move(id)] = std::move(entry);
    }

    // 按 id 查找条目,未注册返回 nullptr。
    const Entry* Find(std::string_view id) const {
        auto it = entries_.find(std::string(id));
        return it != entries_.end() ? &it->second : nullptr;
    }

    // 返回所有条目的指针集合,顺序未规定(交互模式展示前可自行排序)。
    std::vector<const Entry*> All() const {
        std::vector<const Entry*> out;
        out.reserve(entries_.size());
        for (auto& [_, e] : entries_) {
            out.push_back(&e);
        }
        return out;
    }

    // 条目数量。
    std::size_t Size() const noexcept { return entries_.size(); }

    // 构造 Product:
    //   未注册 id       → ComponentError(kConfig)
    //   validate 不通过 → ComponentError(kConfig, err message)
    //   factory 报错    → 原样透传
    core::Result<std::unique_ptr<Product>>
    Build(std::string_view id, const BuildContext& ctx) const {
        const Entry* e = Find(id);
        if (!e || !e->build) {
            return std::unexpected(core::ComponentError::Config(
                "catalog",
                std::string("component id not registered: ") + std::string(id)));
        }
        if (e->validate) {
            std::string err;
            if (!e->validate(ctx, err)) {
                return std::unexpected(core::ComponentError::Config(e->meta.id, err));
            }
        }
        return e->build(ctx);
    }

private:
    std::unordered_map<std::string, Entry> entries_;
};

} // namespace refuzz::catalog
