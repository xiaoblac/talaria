// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — ICallAnnotator (Tier C interface).
//
// Adapt of upstream prog.Target.AnnotateCall (per
// docs/syzkaller-parity-review/target_ownership.md row 113). Linux
// implementation is a no-op (mirror of sys/linux/init.go which never
// installs an AnnotateCall, defaulting to the zero-value func that
// returns "").
//
// csource Write() inserts the annotator's output at the
// csource.go:362 site (just before each emitted C syscall line).

#pragma once

#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"

#include <string>

namespace refuzz::crash::repro::csource {

class ICallAnnotator {
public:
    virtual ~ICallAnnotator() = default;

    // Called once per emitted WireCall. Return value is wrapped into a
    // C-style comment block by csource and inserted before the C
    // syscall line. Empty return → no annotation inserted.
    //
    // `wc.call_id` indexes into `meta` via Target::syscall_by_id (csource
    // resolves SyscallMeta from the typed Prog before calling).
    virtual std::string Annotate(
        const ::refuzz::program::syz::WireCall&       wc,
        const ::refuzz::program::syz::SyscallMeta&    meta) const = 0;
};

// Linux/amd64 default — Annotate() always returns "". Singleton.
const ICallAnnotator& linux_amd64_annotator();

} // namespace refuzz::crash::repro::csource
