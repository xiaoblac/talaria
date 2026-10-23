#pragma once

// V2 production-exec paired oracle / COV-A: flatrpc ExecFlag → reFuzz worker
// wire TASK_FLAG_* translator. Header-only and dependency-light so the unit
// test (tests/replayer_flag_translation_test.cpp) can include it without
// pulling in refuzz_channel.
//
// The replayer constructs ChannelDispatchRequest directly via
// Channel::Submit, bypassing the production channeldispatcher
// (executor/channeldispatcher/.../channeldispatcher.cpp:454). That dispatcher
// performs the proto→wire ExecFlag translation in the normal flow; replaying
// from a captured trace skips it. Without this inline translator, syz bit 4
// (Threaded) would silently alias to wire bit 4 (TASK_FLAG_COLLECT_COMPS) —
// a mode-confusion bug the old `skip Threaded` mask was hiding.

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstdint>

namespace refuzz::oracle::replayer {

// flatrpc ExecFlag bit values (see pkg/flatrpc/flatrpc.go).
//   bit 0 CollectSignal — worker always collects, no wire equivalent
//   bit 1 CollectCover  — worker always collects, no wire equivalent
//   bit 2 DedupCover    — host-side concern, no wire equivalent
//   bit 3 CollectComps
//   bit 4 Threaded
inline constexpr uint64_t kFlatRpcCollectComps = 1ULL << 3;
inline constexpr uint64_t kFlatRpcThreaded     = 1ULL << 4;

// CollectSignal/CollectCover/DedupCover have no wire equivalent: reFuzz
// worker always collects coverage and never dedup-pads on the wire — those
// are host-side concerns in syzkaller. Unknown bits drop to 0.
inline uint32_t TranslateFlatRpcExecFlagsToWire(uint64_t syz_flags) {
    uint32_t wire = 0;
    if (syz_flags & kFlatRpcCollectComps) wire |= TASK_FLAG_COLLECT_COMPS;
    if (syz_flags & kFlatRpcThreaded)     wire |= TASK_FLAG_INTRA_THREADED;
    return wire;
}

}  // namespace refuzz::oracle::replayer
