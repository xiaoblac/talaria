// Copyright 2017 syzkaller project authors. All rights reserved.
// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Adapt of upstream pkg/csource/options.go::Check (lines 70-150).

#include "refuzz/crash/repro/csource/options.hpp"

#include <format>

namespace refuzz::crash::repro::csource {

namespace {

constexpr std::string_view kSandboxNone      = "none";
constexpr std::string_view kSandboxSetuid    = "setuid";
constexpr std::string_view kSandboxNamespace = "namespace";
constexpr std::string_view kSandboxAndroid   = "android";

constexpr std::string_view kOSLinux   = "linux";
constexpr std::string_view kOSOpenBSD = "openbsd";
constexpr std::string_view kOSFreeBSD = "freebsd";
constexpr std::string_view kOSNetBSD  = "netbsd";

bool sandbox_is_known(std::string_view s) {
    return s.empty() || s == kSandboxNone || s == kSandboxNamespace ||
           s == kSandboxSetuid || s == kSandboxAndroid;
}

} // namespace

std::expected<void, std::string> Options::Check(std::string_view os) const {
    if (!sandbox_is_known(Sandbox)) {
        return std::unexpected(std::format("unknown sandbox {}", Sandbox));
    }
    if (!Threaded && Legacy.Collide) {
        return std::unexpected("option Collide without Threaded");
    }
    if (!Repeat) {
        if (Procs > 1) {
            return std::unexpected("option Procs>1 without Repeat");
        }
        if (NetReset) {
            return std::unexpected("option NetReset without Repeat");
        }
        if (RepeatTimes > 1) {
            return std::unexpected("option RepeatTimes without Repeat");
        }
    }
    if (Sandbox.empty()) {
        if (NetInjection)  return std::unexpected("option NetInjection without sandbox");
        if (NetDevices)    return std::unexpected("option NetDevices without sandbox");
        if (Cgroups)       return std::unexpected("option Cgroups without sandbox");
        if (BinfmtMisc)    return std::unexpected("option BinfmtMisc without sandbox");
        if (VhciInjection) return std::unexpected("option VhciInjection without sandbox");
        if (Wifi)          return std::unexpected("option Wifi without sandbox");
    }
    if (Sandbox == kSandboxNamespace && !UseTmpDir) {
        return std::unexpected("option Sandbox=namespace without UseTmpDir");
    }
    if (NetReset && (Sandbox.empty() || Sandbox == kSandboxSetuid)) {
        return std::unexpected("option NetReset without sandbox");
    }
    if (Cgroups && !UseTmpDir) {
        return std::unexpected("option Cgroups without UseTmpDir");
    }

    // checkLinuxOnly equivalent
    if (os == kOSLinux) {
        return {};
    }
    const bool bsd_family = (os == kOSOpenBSD || os == kOSFreeBSD || os == kOSNetBSD);
    if (NetInjection && !bsd_family) {
        return std::unexpected(std::format("option NetInjection is not supported on {}", os));
    }
    if (Sandbox == kSandboxNamespace ||
        (Sandbox == kSandboxSetuid && !bsd_family) ||
        Sandbox == kSandboxAndroid) {
        return std::unexpected(std::format("option Sandbox={} is not supported on {}", Sandbox, os));
    }
    struct NamedFlag { std::string_view name; bool value; };
    const NamedFlag platform_flags[] = {
        {"NetDevices",    NetDevices},
        {"NetReset",      NetReset},
        {"Cgroups",       Cgroups},
        {"BinfmtMisc",    BinfmtMisc},
        {"CloseFDs",      CloseFDs},
        {"KCSAN",         KCSAN},
        {"DevlinkPCI",    DevlinkPCI},
        {"NicVF",         NicVF},
        {"USB",           USB},
        {"VhciInjection", VhciInjection},
        {"Wifi",          Wifi},
        {"ieee802154",    IEEE802154},
        {"Fault",         Legacy.Fault},
        {"Leak",          Leak},
        {"Sysctl",        Sysctl},
        {"Swap",          Swap},
    };
    for (const auto& flag : platform_flags) {
        if (flag.value) {
            return std::unexpected(std::format("option {} is not supported on {}", flag.name, os));
        }
    }
    return {};
}

} // namespace refuzz::crash::repro::csource
