// Validation pass for v2 IR. Mirrors prog/validation.go.
//
// Checks structural and semantic invariants:
//  - syscall arg count matches meta
//  - arg types match field types
//  - direction matches
//  - resource result-arg uses links are intact
//  - pointer addresses fit within target memory window
//  - per-kind constraints (out args default, csum is zero, etc.)
//
// Used as a sanity gate after codec decode and after every mutator step.

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <expected>
#include <string>

namespace refuzz::program::syz {

struct ValidateError {
    int         call_index = -1;          // 0-based; -1 if not call-scoped
    std::string call_name;
    std::string message;
};

struct ValidateOptions {
    // Skip transient-union check (set during decode-phase validation when
    // conditional fields haven't been patched yet).
    bool ignore_transient = false;
    // Allow some otherwise-rejected forms (used by repro/VM-check).
    bool is_unsafe = false;
    // [v2 PR-D] 严格 invariant gate (default off)。启用后 validate_pointer
    // 拒绝 non-optional ptr field 产 special pointer (NULL/0xff..ff/
    // 0x99..99/kernel/vdso) 编码的非法组合。production 路径当前不传此字段
    // → 行为不变;单测显式 {.strict_invariant = true} 启用断言。task 10
    // baseline 后考虑翻默认 + 给 serialize_for_exec 入口加 validate 调用
    // 形成生产闭环。详见 docs/plans/worker-special-pointer-fix/04_pr_d_draft.md。
    bool strict_invariant = false;
};

// Validate a fully-fixed-up program. Returns empty expected on success.
std::expected<void, ValidateError>
validate(const Prog& prog, const ValidateOptions& opts = {});

} // namespace refuzz::program::syz
