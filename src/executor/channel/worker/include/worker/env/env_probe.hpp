// Copyright 2026 reFuzz project author -------youngkk.
//
// [syscall-support-detection Step C] Guest-side VM environment probe. Run once
// by the per-VM init worker (worker_id == 0) at startup; gathers GENERIC facts
// (which filesystems the kernel exposes, which device nodes are openable) into
// the EnvFeatures wire struct. There is NO syscall-domain logic here —
// control/support maps the facts to syscall support host-side. Mirrors syz
// pkg/vminfo's guest executor: the guest gathers, the host interprets.

#pragma once

#include "refuzz/proto_wire/env_features.h"

#include <cstddef>

namespace refuzz::worker::env {

// Probe the live guest environment into *out (zeroes it, sets version). Safe +
// idempotent: it only opens (O_RDWR→O_RDONLY) and immediately closes device
// nodes — no ioctl/bind, so no kernel state change — and reads
// /proc/filesystems. No-op if out == nullptr.
void ProbeEnvFeatures(::EnvFeatures* out);

// Testable seam: parse /proc/filesystems text into *out (appends fs names). The
// name is the last tab/space-separated token of each line, so the optional
// "nodev" prefix is dropped. Exposed for unit tests — needs no live /proc.
void ParseProcFilesystems(const char* content, std::size_t len, ::EnvFeatures* out);

// Testable seam: parse a /proc/version string ("Linux version X.Y.Z ...") into
// *major/*minor (the first " X.Y." token), mirroring syz's matchKernelVersion
// regex ` ([0-9]+)\.([0-9]+)\.`. On no match both are set to 0 (unknown). minor
// 0 is a valid result (e.g. 6.0); only major 0 means "unparsed". Needs no /proc.
void ParseKernelVersion(const char* content, std::size_t len,
                        uint32_t* major, uint32_t* minor);

} // namespace refuzz::worker::env
