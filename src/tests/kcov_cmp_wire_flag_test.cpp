// kcov_cmp_wire_flag_test.cpp
//
// Epic 5 PR-5-B — wire flag plumbing smoke ctest.
//
// Validates the host-side proto and worker-side wire CollectComps/RTT bits,
// accessors, and ExecFlagsAreSupported acceptance.
//
// Cases:
//   1. TASK_FLAG_COLLECT_COMPS == 1u << 4 (bit 4, post-shape).
//   2. task_flags_get_collect_comps returns 1 when bit set, 0 otherwise.
//   3. ExecFlagsAreSupported accepts CollectComps/RTT + intra+shape combos
//      and rejects unknown high bits.
//   4. proto::kExecFlagCollectComps == 1u << 3 == 8 (mirrors flatrpc).
//   5. proto bit value differs from wire bit value (translation required —
//      channeldispatcher does it; documented mismatch).

#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/exec_mode.hpp"

#include <cstdint>
#include <cstdio>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

int main()
{
    // Case 1.
    CHECK(TASK_FLAG_COLLECT_COMPS == (1u << 4));

    // Case 2.
    CHECK(task_flags_get_collect_comps(TASK_FLAG_COLLECT_COMPS) == 1u);
    CHECK(task_flags_get_collect_comps(0u) == 0u);
    CHECK(task_flags_get_collect_comps(TASK_FLAG_INTRA_SERIAL) == 0u);
    CHECK(task_flags_get_collect_comps(
              TASK_FLAG_INTRA_SERIAL | TASK_FLAG_COLLECT_COMPS) == 1u);

    // Case 3 — supported flag acceptance.
    using refuzz::worker::ExecFlagsAreSupported;
    CHECK(ExecFlagsAreSupported(TASK_FLAG_INTRA_SERIAL));
    CHECK(ExecFlagsAreSupported(TASK_FLAG_INTRA_SERIAL | TASK_FLAG_COLLECT_COMPS));
    CHECK(ExecFlagsAreSupported(
              TASK_FLAG_INTRA_SERIAL | TASK_FLAG_SHAPE_SINGLE | TASK_FLAG_COLLECT_COMPS));
    CHECK(TASK_FLAG_TRACE_SAMPLED == (1u << 5));
    CHECK(ExecFlagsAreSupported(TASK_FLAG_INTRA_SERIAL | TASK_FLAG_TRACE_SAMPLED));
    CHECK(ExecFlagsAreSupported(TASK_FLAG_INTRA_THREADED |
                                TASK_FLAG_COLLECT_COMPS |
                                TASK_FLAG_TRACE_SAMPLED));
    // Bit 6 is the next reserved wire bit and must still be rejected.
    CHECK(!ExecFlagsAreSupported(TASK_FLAG_INTRA_SERIAL | (1u << 6)));

    // Case 4.
    CHECK(refuzz::proto::kExecFlagCollectComps == (1u << 3));
    CHECK(static_cast<uint32_t>(refuzz::proto::kExecFlagCollectComps) == 8u);

    // Case 5 — proto bit (host-side) differs from wire bit (TaskSlot.flags).
    // Channeldispatcher translates: ps.task.opts.flags & kExecFlagCollectComps
    // → ps.request.exec_flags |= TASK_FLAG_COLLECT_COMPS.
    CHECK(static_cast<uint32_t>(refuzz::proto::kExecFlagCollectComps) !=
          TASK_FLAG_COLLECT_COMPS);

    std::printf("kcov_cmp_wire_flag_test PASSED\n");
    return 0;
}
