#pragma once

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"

#include <cstdint>

namespace refuzz::worker {

PseudoResult DispatchPseudo(const PseudoContext& ctx,
                            uint64_t nr,
                            const intptr_t* args,
                            uint32_t argc);

intptr_t dispatch_pseudo(const PseudoContext& ctx,
                         uint64_t nr,
                         const intptr_t* args,
                         uint32_t argc);

intptr_t dispatch_pseudo(uint64_t nr, const intptr_t* args, uint32_t argc);

} // namespace refuzz::worker
