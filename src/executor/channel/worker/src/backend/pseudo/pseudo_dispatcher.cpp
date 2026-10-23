#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>

namespace refuzz::worker {

using refuzz::fuzzer::syz::PseudoDomain;
using refuzz::fuzzer::syz::PseudoMeta;
using refuzz::fuzzer::syz::PseudoMetaTable;

namespace pseudo {

PseudoResult DispatchCorePseudo(const PseudoContext& ctx,
                                const PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);
PseudoResult DispatchFilePseudo(const PseudoContext& ctx,
                                const PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);
PseudoResult DispatchFsPseudo(const PseudoContext& ctx,
                              const PseudoMeta& meta,
                              const intptr_t* args,
                              uint32_t argc);
PseudoResult DispatchDevicePseudo(const PseudoContext& ctx,
                                  const PseudoMeta& meta,
                                  const intptr_t* args,
                                  uint32_t argc);
PseudoResult DispatchNetPseudo(const PseudoContext& ctx,
                               const PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);
PseudoResult DispatchUsbPseudo(const PseudoContext& ctx,
                               const PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);
PseudoResult DispatchFusePseudo(const PseudoContext& ctx,
                                const PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc);
PseudoResult DispatchKvmPseudo(const PseudoContext& ctx,
                               const PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);
// [PR-D1] mount-image domain — handler in pseudo/mount/mount_dispatcher.cpp.
PseudoResult DispatchMountPseudo(const PseudoContext& ctx,
                                 const PseudoMeta& meta,
                                 const intptr_t* args,
                                 uint32_t argc);

} // namespace pseudo

namespace {

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

const PseudoMeta* FindPseudo(const PseudoMetaTable& table, uint64_t nr)
{
    if (nr < table.base || table.entries == nullptr) {
        return nullptr;
    }
    const uint64_t idx = nr - table.base;
    if (idx >= table.size) {
        return nullptr;
    }
    const PseudoMeta& meta = table.entries[idx];
    if (meta.nr != nr || meta.name == nullptr) {
        return nullptr;
    }
    return &meta;
}

} // namespace

PseudoContext DefaultPseudoContext()
{
    return PseudoContext{&refuzz::fuzzer::syz::kDefaultSyzTarget.pseudos};
}

PseudoResult DispatchPseudo(const PseudoContext& ctx,
                            uint64_t nr,
                            const intptr_t* args,
                            uint32_t argc)
{
    const PseudoMetaTable* table = ctx.table;
    if (table == nullptr) {
        table = &refuzz::fuzzer::syz::kDefaultSyzTarget.pseudos;
    }
    const PseudoMeta* meta = FindPseudo(*table, nr);
    if (meta == nullptr) {
        // No meta → can't attribute a name/domain. This is a wire/identity
        // bug (caller sent bogus NR), not a pseudo classification problem;
        // surface as ENOSYS but stay unrecorded in PR-METRIC since the row
        // shape requires a name. If diagnostic ever needs this, add an
        // "unknown_nr" sentinel row separately.
        return Error(ENOSYS);
    }

    // [PR-METRIC] Single-exit: compute `result` for every reachable path,
    // record once at the end. [impl-kind removed] No native/stub/unsupported
    // gate — non-fuzzable pseudos carry syz's (disabled) attr and are filtered
    // host-side (enable/disable whitelist + control/support) before ever
    // reaching the worker; an unknown/unhandled domain still falls through to
    // ENOSYS below.
    PseudoResult result;
    switch (meta->domain) {
    case PseudoDomain::kCore:
        result = pseudo::DispatchCorePseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kFile:
        result = pseudo::DispatchFilePseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kFs:
        result = pseudo::DispatchFsPseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kDevice:
        result = pseudo::DispatchDevicePseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kNet:
        result = pseudo::DispatchNetPseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kUsb:
        result = pseudo::DispatchUsbPseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kFuse:
        result = pseudo::DispatchFusePseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kKvm:
        result = pseudo::DispatchKvmPseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kMount:
        // [PR-D1] mount-image family (kMount domain — plan §5.2 Tier 3 subdir).
        result = pseudo::DispatchMountPseudo(ctx, *meta, args, argc);
        break;
    case PseudoDomain::kUnknown:
    default:
        result = Error(ENOSYS);
        break;
    }
    return result;
}

intptr_t dispatch_pseudo(const PseudoContext& ctx,
                         uint64_t nr,
                         const intptr_t* args,
                         uint32_t argc)
{
    const PseudoResult result = DispatchPseudo(ctx, nr, args, argc);
    errno = result.err;
    return result.ret;
}

intptr_t dispatch_pseudo(uint64_t nr, const intptr_t* args, uint32_t argc)
{
    return dispatch_pseudo(DefaultPseudoContext(), nr, args, argc);
}

} // namespace refuzz::worker
