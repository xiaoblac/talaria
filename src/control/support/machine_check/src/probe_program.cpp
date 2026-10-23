// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/control/support/machine_check/probe_program.hpp"

#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/type.hpp"

#include <memory>
#include <utility>

namespace refuzz::control::support::machine_check {

syz::Prog BuildProbeProgram(const syz::Target&                          target,
                            const std::vector<const syz::SyscallMeta*>& calls) {
    syz::Prog prog;
    prog.set_target(&target);
    for (const syz::SyscallMeta* meta : calls) {
        if (meta == nullptr) {
            continue;
        }
        auto call = std::make_unique<syz::Call>();
        call->set_meta(meta);
        for (const auto& field : meta->args()) {
            const syz::Type* ft = field.type();
            if (ft == nullptr) {
                continue;
            }
            // Top-level syscall args default to Dir::kIn (syz convention).
            call->add_arg(ft->default_arg(field.dir(syz::Dir::kIn)));
        }
        prog.add_call(std::move(call));
    }
    return prog;
}

std::optional<std::vector<std::uint8_t>> EncodeProbeProgram(syz::Prog& prog) {
    syz::assign_sizes_prog(prog);
    auto bytes = syz::serialize_for_exec(prog);
    if (!bytes) {
        return std::nullopt;
    }
    return std::move(*bytes);
}

} // namespace refuzz::control::support::machine_check
