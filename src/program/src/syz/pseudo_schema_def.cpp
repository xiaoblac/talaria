// ODR unit for the pseudo-target metadata generated tables. After V1
// IR retirement only the pseudo-call schema is kept; this file pulls
// in the inline definitions of `kLinuxAmd64PseudoMeta` /
// `kLinuxAmd64Target` / `kDefaultSyzTarget` so the worker pseudo
// dispatch can link against them.

#include "refuzz/program/syz/pseudo/generated/syz_tables.gen.hpp"
