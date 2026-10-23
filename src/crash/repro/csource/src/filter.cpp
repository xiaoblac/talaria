// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/csource.go::filterCalls
// (lines 165-186). Drops syz_emit_ethernet / syz_extract_tcp_res
// variants when NetInjection is off, and syz_emit_vhci when
// VhciInjection is off. Lazy-clones the Prog on first removal.

#include "refuzz/crash/repro/csource/internal/filter.hpp"

#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/transform.hpp"

#include <string_view>

namespace refuzz::crash::repro::csource::internal {

namespace {

namespace syz = ::refuzz::program::syz;

bool keep_call(std::string_view call_name, const Options& opts) {
    const bool emit_ethernet =
        opts.NetInjection ||
        (call_name != "syz_emit_ethernet" &&
         call_name != "syz_extract_tcp_res");
    const bool emit_vhci =
        opts.VhciInjection || call_name != "syz_emit_vhci";
    return emit_ethernet && emit_vhci;
}

} // namespace

FilteredProg filter_calls(const syz::Prog& prog, const Options& opts) {
    bool need_clone = false;
    for (const auto& call : prog.calls()) {
        if (call == nullptr || call->meta() == nullptr) continue;
        if (!keep_call(call->meta()->call_name(), opts)) {
            need_clone = true;
            break;
        }
    }
    if (!need_clone) {
        return FilteredProg{.borrowed = &prog, .owned = nullptr};
    }

    // Lazy clone: copy then strip rejected calls via the program/syz
    // RemoveCall helper, which also clears dangling ResultArg::res()
    // edges from surviving calls into removed ResultArgs (mirror of
    // upstream prog.RemoveCall semantics — H1 fix). Iterate
    // back-to-front so each removal's index is stable.
    auto cloned = syz::DeepClone(prog);
    auto& calls = cloned->mutable_calls();
    for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(calls.size()) - 1;
         i >= 0; --i) {
        const auto& c = calls[i];
        if (c == nullptr || c->meta() == nullptr ||
            !keep_call(c->meta()->call_name(), opts)) {
            // RemoveCallRange refuses to drop the last surviving
            // call (returns false). When that happens we still need
            // the call gone — the caller's "all-calls-dropped"
            // post-check returns kUnsupportedByEpic4 cleanly. To
            // surface that path, fall back to direct erase only when
            // RemoveCall refuses; this is the rare empty-result
            // case.
            if (!syz::RemoveCall(*cloned, static_cast<std::size_t>(i))) {
                calls.erase(calls.begin() + i);
            }
        }
    }
    return FilteredProg{.borrowed = nullptr, .owned = std::move(cloned)};
}

} // namespace refuzz::crash::repro::csource::internal
