// StateAltitude — neutral, target-agnostic POD describing a program's
// "state-space altitude" (seed-value signal C, docs/plans/seed-value-signals.md
// §2.3). It quantifies how much expensive-to-reconstruct kernel state a program
// leaves standing: how many resource objects it produces, how interconnected
// they are, and how deep the producer→consumer dependency chain runs.
//
// The struct lives in `program/` (neutral) so the IMutatorEngine seam can
// return it without coupling the interface to any target's typed IR. The actual
// computation walks a target-specific IR and lives in that target's subtree
// (e.g. `program/syz/state_altitude.hpp`), which fills this POD.
#pragma once

#include <cstdint>

namespace refuzz::program {

struct StateAltitude {
    // Resource-typed values the program produces (syscall returns that create a
    // kernel object: an fd, a socket, a bpf prog id, ...). Proxy for "objects
    // created / left alive at the end".
    std::uint32_t resource_producers = 0;
    // Resource references that point at a producer (dependency edges): a later
    // call consuming an earlier call's resource. Proxy for interconnection.
    std::uint32_t resource_consumers = 0;
    // Distinct resource kinds among the producers (fd vs socket vs ...).
    std::uint32_t distinct_kinds = 0;
    // Longest producer→consumer dependency chain (e.g. socket → accept(socket)
    // → recv(conn) = depth 2). Proxy for how deep into state space the program
    // reaches.
    std::uint32_t max_dependency_depth = 0;
};

} // namespace refuzz::program
