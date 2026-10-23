// Test helpers shared across syz_v2 unit tests.

#pragma once

#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <functional>
#include <string>

namespace refuzz::tests::syz_v2 {

// Walk syscall arg / ret type trees and return the first
// ResourceType whose desc has the given name, or nullptr if none.
inline const ::refuzz::program::syz::ResourceType*
find_resource_type(const ::refuzz::program::syz::Target& target,
                   const std::string& name) {
    namespace syz = ::refuzz::program::syz;
    for (const auto& sc : target.syscalls()) {
        if (!sc) continue;
        const syz::ResourceType* hit = nullptr;
        std::function<void(const syz::Type*)> walk = [&](const syz::Type* t) {
            if (hit != nullptr || t == nullptr) return;
            if (t->kind() == syz::TypeKind::kResource) {
                const auto* rt = static_cast<const syz::ResourceType*>(t);
                if (rt->desc() != nullptr && rt->desc()->name() == name) {
                    hit = rt;
                }
                return;
            }
            if (t->kind() == syz::TypeKind::kPtr) {
                walk(static_cast<const syz::PtrType*>(t)->elem());
            } else if (t->kind() == syz::TypeKind::kStruct) {
                for (const auto& f :
                     static_cast<const syz::StructType*>(t)->fields()) {
                    walk(f.type());
                    if (hit != nullptr) return;
                }
            } else if (t->kind() == syz::TypeKind::kArray) {
                walk(static_cast<const syz::ArrayType*>(t)->elem());
            }
        };
        for (const auto& f : sc->args()) walk(f.type());
        if (hit != nullptr) return hit;
        if (sc->ret()) walk(sc->ret());
        if (hit != nullptr) return hit;
    }
    return nullptr;
}

} // namespace refuzz::tests::syz_v2
