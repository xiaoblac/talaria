// Copyright 2026 reFuzz project author -------youngkk.
//
// Worker-side fault-injection helpers — Epic 6 §3.14 PR-6-A.
//
// Mirror of upstream syzkaller `executor/common_linux.h:4749-4778`
// `inject_fault` / `fault_injected` semantics:
//   - inject_fault(nth) writes "%d" (1-based nth) to
//     /proc/thread-self/fail-nth and keeps the fd open. Returns the
//     fd or -1 on open/write failure (graceful skip per plan §3 D-14).
//   - fault_injected(fd) reads up to 16 bytes; treats exactly "0\n"
//     (2 bytes) as "kernel injected a fault on the nth-th call site".
//     Always closes fd. Returns false on any read inconsistency.
//
// Linux-only implementation — the worker is linux-targeted; cross-arch
// fault injection is a permanent non-goal of Epic 6 (plan §10 N5).

#pragma once

namespace refuzz::worker {

// Open /proc/thread-self/fail-nth, write decimal nth (1-based).
// On success returns the fd (caller passes to fault_injected after
// the targeted syscall). On any failure (open / write / partial write),
// returns -1; caller must skip the fault attempt for this call without
// poisoning driver state.
int  inject_fault(int nth);

// Read /proc/thread-self/fail-nth via the fd returned by
// inject_fault. Returns true iff the read returned exactly "0\n"
// (kernel injected the fault). Always closes the fd. False on any
// read failure or unexpected byte sequence.
bool fault_injected(int fd);

// Default-binds for KernelWireDriver's test seam. Production constructs
// the driver with these. Tests pass mocks.
using InjectFaultFn   = int  (*)(int nth);
using FaultInjectedFn = bool (*)(int fd);

}  // namespace refuzz::worker
