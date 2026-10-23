// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Options struct and Check().
//
// Adapt of upstream pkg/csource/options.go::Options + Check() (lines
// 21-150). Field set is the full upstream surface so Check() parity
// holds; the Epic 4 baseline gate at Write() time additionally
// rejects non-baseline subsets (per Epic 4 plan §3).

#pragma once

#include <expected>
#include <string>
#include <string_view>

namespace refuzz::crash::repro::csource {

// LegacyOptions are kept-for-compat with upstream Options; setting
// any of them to non-default fails the baseline gate.
struct LegacyOptions {
    bool Collide   = false;
    bool Fault     = false;
    int  FaultCall = 0;
    int  FaultNth  = 0;
};

struct Options {
    bool Threaded     = false;
    bool Repeat       = false;
    int  RepeatTimes  = 0;
    int  Procs        = 0;
    int  Slowdown     = 1;
    std::string Sandbox;       // "" | "none" | "setuid" | "namespace" | "android"
    int  SandboxArg   = 0;

    bool Leak         = false;

    bool NetInjection = false;
    bool NetDevices   = false;
    bool NetReset     = false;
    bool Cgroups      = false;
    bool BinfmtMisc   = false;
    bool CloseFDs     = false;
    bool KCSAN        = false;
    bool DevlinkPCI   = false;
    bool NicVF        = false;
    bool USB          = false;
    bool VhciInjection = false;
    bool Wifi         = false;
    bool IEEE802154   = false;
    bool Sysctl       = false;
    bool Swap         = false;

    bool UseTmpDir    = false;
    bool HandleSegv   = false;

    bool Trace        = false;

    bool CallComments = false;

    LegacyOptions Legacy;

    // Mirror of upstream pkg/csource/options.go::Check (line 70-150).
    // `os` is always "linux" for Epic 4; the parameter exists for
    // future Epic 4.5 OS expansion.
    std::expected<void, std::string> Check(std::string_view os) const;
};

} // namespace refuzz::crash::repro::csource
