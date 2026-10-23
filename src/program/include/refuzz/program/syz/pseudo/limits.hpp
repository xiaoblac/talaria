#pragma once

// Worker-facing pseudo ABI limits — split out from `target_view.hpp` so
// callers that only need the bare numeric limit (e.g.,
// `executor/.../kernel_wire_driver.cpp`) do not have to pull in the
// full PseudoMeta / SyzTargetTables surface.
//
// Mirrors syzkaller `prog.maxArgs` (executor-side max syscall arg
// count). The pseudo metadata table's `args_type_idx[kSyzMaxArgs]`
// field still uses this constant; `target_view.hpp` re-exports it via
// transitive include to keep existing callers source-compatible.

#include <cstdint>

namespace refuzz::fuzzer::syz {

inline constexpr uint32_t kSyzMaxArgs        = 9;
inline constexpr uint32_t kCompatFlatMaxArgs = 6;

} // namespace refuzz::fuzzer::syz
