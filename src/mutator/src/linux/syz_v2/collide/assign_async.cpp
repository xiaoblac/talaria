// Copyright 2026 reFuzz project author -------youngkk.
//
// assign_async.cpp —— 见 header。严格 mirror prog/collide.go:24-60。

#include "refuzz/mutator/linux/syz_v2/collide/assign_async.hpp"

#include "refuzz/program/syz/analysis.hpp"  // foreach_arg / ArgCtx
#include "refuzz/program/syz/arg.hpp"       // ResultArg / as_result_arg
#include "refuzz/program/syz/clone.hpp"     // DeepClone
#include "refuzz/program/syz/type.hpp"      // Dir

#include <cstddef>
#include <unordered_set>
#include <utility>

namespace refuzz::mutator::syz_v2::collide {

namespace syz = ::refuzz::program::syz;

std::unique_ptr<syz::Prog>
AssignRandomAsync(const syz::Prog& orig, RandGen& r)
{
    auto prog = syz::DeepClone(orig);
    if (!prog) {
        return nullptr;
    }

    auto&     calls = prog->mutable_calls();
    const int n     = static_cast<int>(calls.size());

    // `unassigned`: 已被更靠后（倒序 = 已处理）的 async call 消费掉的 producer-ResultArg。
    //   若当前 call 也产出其中某个 producer 且被设 async，consumer 端可能拿到未就绪的值。
    // `consumes`: 当前 call 读取（消费）的 producer 集合。
    std::unordered_set<const syz::ResultArg*> unassigned;
    int left_async = kMaxAsyncPerProg;

    for (int i = n - 1; i >= 0 && left_async > 0; --i) {
        syz::Call* call = calls[static_cast<std::size_t>(i)].get();

        bool                                      produces_unassigned = false;
        std::unordered_set<const syz::ResultArg*> consumes;

        syz::foreach_arg(call, [&](syz::Arg* a, syz::ArgCtx*) {
            const syz::ResultArg* res = syz::as_result_arg(a);
            if (res == nullptr) {
                return;
            }
            // producer arg（Dir != In）已被后面某个 async call 需要 → 本 call 设 async 会
            // 让那个 resource 到点还没就绪。
            if (res->dir() != syz::Dir::kIn && unassigned.count(res) != 0) {
                produces_unassigned = true;
            }
            // consumer arg（Dir != Out）：记下它引用的 producer。
            if (res->dir() != syz::Dir::kOut && res->res() != nullptr) {
                consumes.insert(res->res());
            }
        });

        // 66% 概率设 async（rand.Intn(3)!=0），但最后一个 call 永不设，且不能饿死后面的
        // async consumer。
        if (!produces_unassigned && i + 1 != n && r.rand(3) != 0) {
            syz::CallProps props = call->props();
            props.async          = true;
            call->set_props(props);
            for (const syz::ResultArg* res : consumes) {
                unassigned.insert(res);
            }
            --left_async;
        } else {
            syz::CallProps props = call->props();
            props.async          = false;
            call->set_props(props);
            unassigned = std::move(consumes);
        }
    }

    return prog;
}

}  // namespace refuzz::mutator::syz_v2::collide
