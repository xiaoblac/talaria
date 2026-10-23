#!/usr/bin/env bash
# §3.11 follow-up P12 — structural test for "Tier C" architecture.
#
# Per `docs/syzkaller-parity-review/target_ownership.md §8.1`, the
# minimize / mutate / clone / default-arg algorithms live as Type
# methods inside `program/syz/`. The orchestration layer
# (`crash/repro/`, `mutator/.../engines/`) must NOT switch on
# `TypeKind` for those concerns — that's the Tier B regression
# pattern §3.11 closure aimed to eliminate.
#
# This script greps for the regression pattern and exits non-zero on
# any hit. It's wired into CMakeLists.txt as a CTest entry so CI
# enforces it on every commit.
#
# Allowed switches: those inside `program/syz/` (where per-type
# semantics live) and `program/src/syz_v2/`. Also allowed: lookup
# patterns that switch on ArgKind (different concern; legitimate
# union dispatch on the Arg side).
#
# Forbidden switches: `switch (...->kind())` where ... is a Type*,
# in any file under crash/repro/ or under mutator/ engines.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Search forbidden zones: crash/repro/, mutator/.../engines/.
FORBIDDEN_DIRS=(
    crash/repro/src
    mutator/src/linux/syz_v2/engines
    mutator/src/linux/syz_v2/policies
)

# Patterns that indicate a type-kind switch (Tier B regression).
# `switch.*->kind()` and `switch.*\.kind()` cover both pointer and
# reference forms; `case.*TypeKind::` further narrows to the kind enum.
PATTERNS=(
    'switch.*->kind\(\).*\{'
    'case[[:space:]]+(syzv2::|syz::)?TypeKind::'
)

# Known pre-existing violations (whitelist). Empty after the §3.11
# follow-up P2 step 9 cleanup: every per-type minimize body now lives
# as `Type::minimize` virtual override under program/syz/, and
# crash/repro/src no longer contains any V2 `switch (type->kind())`
# or `case (syz::|syzv2::)?TypeKind::` Tier B regressions. The legacy
# `V1TypeKind` alias was retired together with the V1 flat path.
ALLOWLIST_FILES=(
)

# Build grep -v filter for allowlisted files.
allow_pat=""
for f in "${ALLOWLIST_FILES[@]}"; do
    if [ -z "$allow_pat" ]; then
        allow_pat="^$f:"
    else
        allow_pat="$allow_pat|^$f:"
    fi
done

found_violations=0
for dir in "${FORBIDDEN_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then continue; fi
    for pattern in "${PATTERNS[@]}"; do
        # Use grep -n -E for line numbers + extended regex.
        # Skip comment lines (`^[[:space:]]*//` or `^[[:space:]]*\*`).
        hits=$(grep -rEn --include='*.cpp' --include='*.hpp' \
                    "$pattern" "$dir" 2>/dev/null \
                | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
                | grep -vE '^[^:]+:[0-9]+:[[:space:]]*\*' \
                || true)
        # Filter out allowlisted files.
        if [ -n "$allow_pat" ] && [ -n "$hits" ]; then
            hits=$(echo "$hits" | grep -vE "$allow_pat" || true)
        fi
        if [ -n "$hits" ]; then
            echo "VIOLATION: $dir contains forbidden TypeKind switch in non-allowlisted file:"
            echo "  pattern: $pattern"
            echo "$hits" | sed 's/^/    /'
            found_violations=$((found_violations + 1))
        fi
    done
done

if [ "$found_violations" -gt 0 ]; then
    echo
    echo "Found $found_violations TypeKind-switch violation(s) in forbidden zones."
    echo "Per target_ownership.md §8.1, type-kind dispatch belongs in"
    echo "program/syz/ as virtual method overrides. See feedback_adapt_three_tiers.md."
    echo
    echo "If you intentionally added a TypeKind switch and have a plan to migrate,"
    echo "add the file to ALLOWLIST_FILES in this script with a tracking task."
    exit 1
fi

boundary_hits=$(grep -rEn --include='*.cpp' --include='*.hpp' \
                    '^[[:space:]]*#[[:space:]]*include[[:space:]]+"refuzz/mutator/' \
                    program/src/syz/linux 2>/dev/null || true)
if [ -n "$boundary_hits" ]; then
    echo "VIOLATION: program/src/syz/linux includes mutator headers:"
    echo "$boundary_hits" | sed 's/^/    /'
    echo
    echo "SpecialType bodies must call Target::IGen virtuals only; concrete"
    echo "mutator helpers stay behind the mutator/ module boundary."
    exit 1
fi

echo "OK: no NEW TypeKind switches in crash/repro or mutator engines."
echo "OK: no mutator includes under program/src/syz/linux."
echo "(allowlisted: ${#ALLOWLIST_FILES[@]} pre-existing files pending P2 migration)"
exit 0
