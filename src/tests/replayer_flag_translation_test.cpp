// replayer_flag_translation_test.cpp
//
// V2 production-exec paired oracle / COV-A:
// Unit test for TranslateFlatRpcExecFlagsToWire — the syzkaller flatrpc
// ExecFlag → reFuzz worker wire TASK_FLAG_* translator that the replayer
// inlines (because it talks to Channel::Submit directly, bypassing the
// production channeldispatcher's proto→wire translation).
//
// Key invariants pinned here:
//   - flatrpc Threaded (bit 4) maps to wire TASK_FLAG_INTRA_THREADED (bit 0),
//     NOT to wire bit 4 (which is TASK_FLAG_COLLECT_COMPS). This was a
//     latent aliasing bug the old `skip Threaded` mask was hiding.
//   - flatrpc CollectComps (bit 3) maps to wire TASK_FLAG_COLLECT_COMPS (bit 4).
//   - flatrpc Signal / Cover / DedupCover (bits 0/1/2) have no wire
//     equivalent (host-side concerns) and map to 0.
//   - Unknown high bits are dropped silently.

#include "../tools/refuzz_exec_replayer/flag_translation.hpp"
#include "../tools/refuzz_exec_replayer/replayer.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

using refuzz::oracle::replayer::TranslateFlatRpcExecFlagsToWire;
using refuzz::oracle::replayer::kFlatRpcCollectComps;
using refuzz::oracle::replayer::kFlatRpcThreaded;

namespace {

constexpr uint64_t kFlatRpcCollectSignal = 1ULL << 0;
constexpr uint64_t kFlatRpcCollectCover  = 1ULL << 1;
constexpr uint64_t kFlatRpcDedupCover    = 1ULL << 2;

void CheckEqual(const char* tag, uint32_t got, uint32_t want) {
    if (got != want) {
        std::fprintf(stderr,
            "FAIL %s: got=0x%08x want=0x%08x\n", tag, got, want);
        std::abort();
    }
}

}  // namespace

int main() {
    {
        refuzz::oracle::replayer::ReplayerConfig cfg;
        assert(!cfg.post_boot_hook);
        assert(!cfg.pre_close_hook);
    }

    // Empty in → empty out.
    CheckEqual("empty", TranslateFlatRpcExecFlagsToWire(0), 0u);

    // Threaded alone.
    {
        uint32_t w = TranslateFlatRpcExecFlagsToWire(kFlatRpcThreaded);
        CheckEqual("threaded_only", w, TASK_FLAG_INTRA_THREADED);
        // Critical: the translated bit must NOT alias to CollectComps.
        assert((w & TASK_FLAG_COLLECT_COMPS) == 0);
    }

    // CollectComps alone.
    {
        uint32_t w = TranslateFlatRpcExecFlagsToWire(kFlatRpcCollectComps);
        CheckEqual("comps_only", w, TASK_FLAG_COLLECT_COMPS);
        // The bit must NOT touch the IntraTask field.
        assert((w & TASK_FLAG_INTRA_MASK) == 0);
    }

    // Both at once.
    {
        uint64_t syz = kFlatRpcCollectComps | kFlatRpcThreaded;
        uint32_t w = TranslateFlatRpcExecFlagsToWire(syz);
        CheckEqual("comps_plus_threaded",
                   w, TASK_FLAG_COLLECT_COMPS | TASK_FLAG_INTRA_THREADED);
    }

    // Host-side-only flatrpc flags (Signal / Cover / DedupCover) have no
    // wire equivalent — must be silently dropped.
    {
        uint64_t syz = kFlatRpcCollectSignal | kFlatRpcCollectCover | kFlatRpcDedupCover;
        CheckEqual("host_only_flags", TranslateFlatRpcExecFlagsToWire(syz), 0u);
    }

    // Real production-trace shape from run/exec-oracle-1779174680: requests
    // 631/632/642 had ExecFlags=19 = Signal | Cover | Threaded. Must yield
    // ONLY the Threaded bit on the wire side (Signal/Cover dropped).
    {
        uint64_t syz = kFlatRpcCollectSignal | kFlatRpcCollectCover | kFlatRpcThreaded;
        CheckEqual("production_19_pattern",
                   TranslateFlatRpcExecFlagsToWire(syz),
                   TASK_FLAG_INTRA_THREADED);
    }

    // Unknown high bits drop to 0 (defense against future flatrpc additions
    // before the translator is taught about them).
    {
        uint64_t syz = (1ULL << 30) | (1ULL << 5) | kFlatRpcThreaded;
        CheckEqual("unknown_bits_dropped",
                   TranslateFlatRpcExecFlagsToWire(syz),
                   TASK_FLAG_INTRA_THREADED);
    }

    // Sanity: wire intra-task value 1 must equal TASK_FLAG_INTRA_THREADED.
    // (Catches accidental wire-encoding drift in proto_wire/ivshmem_protocol.h.)
    static_assert(TASK_FLAG_INTRA_THREADED == 1u);
    static_assert(TASK_FLAG_COLLECT_COMPS == (1u << 4));

    std::printf("replayer_flag_translation_test: all checks PASS\n");
    return 0;
}
