#pragma once

// PR-D2 — public surface for the KVM family handler.
//
// Domain entry called from `pseudo_dispatcher.cpp` when
// `meta.domain == PseudoDomain::kKvm`. Routes by pseudo name to the
// 6 syz_kvm$* sub-handlers (5 amd64 + 1 ppc64-on-amd64-ENOSYS).

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cstdint>

namespace refuzz::worker::pseudo {

PseudoResult DispatchKvmPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);

} // namespace refuzz::worker::pseudo
