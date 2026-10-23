// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// reFuzz Epic 4 csource module — Linux/amd64 ICallAnnotator.
//
// Mirror of upstream sys/linux/init.go: Linux registers no
// AnnotateCall, so prog/target.go:143's zero-value
// `func(c ExecCall) string { return "" }` is in effect. The reFuzz
// equivalent is this no-op singleton.

#include "refuzz/crash/repro/csource/annotator.hpp"

namespace refuzz::crash::repro::csource {

namespace {

class LinuxAmd64Annotator final : public ICallAnnotator {
public:
    std::string Annotate(
        const ::refuzz::program::syz::WireCall&    /*wc*/,
        const ::refuzz::program::syz::SyscallMeta& /*meta*/) const override {
        return {};
    }
};

} // namespace

const ICallAnnotator& linux_amd64_annotator() {
    static const LinuxAmd64Annotator kInstance;
    return kInstance;
}

} // namespace refuzz::crash::repro::csource
