#pragma once

// PR-D1 — public surface for the mount-image handler.
//
// Domain entry called from `pseudo_dispatcher.cpp` when
// `meta.domain == PseudoDomain::kMount`.
//
// Args layout (mirrors upstream `syz_mount_image` syzlang signature
// at common_linux.h:3098-3106):
//   args[0] : ptr to fs name string (e.g., "ext4")
//   args[1] : ptr to target dir string (e.g., "./file0")
//   args[2] : mount flags (MS_RDONLY etc.)
//   args[3] : ptr to mount opts string (comma-separated)
//   args[4] : change_dir bool (chdir(target) after mount if non-zero)
//   args[5] : image size (bytes; 0 = no backing image, e.g. tmpfs)
//   args[6] : ptr to compressed image bytes (zlib stream; ignored if size == 0)
//
// Return: open fd to the mounted target dir (O_RDONLY|O_DIRECTORY) on success;
// -1 + errno on any failure (mirrors upstream return).

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace refuzz::worker::pseudo {

// Canonical args index — pinned via a structural test against the
// typed Target's syz_mount_image* args (B3-style drift check).
inline constexpr std::array<std::string_view, 7> kSyzMountImageArgOrder = {
    "fs", "dir", "flags", "opts", "chdir", "size", "img",
};

PseudoResult DispatchMountPseudo(const PseudoContext& ctx,
                                 const refuzz::fuzzer::syz::PseudoMeta& meta,
                                 const intptr_t* args,
                                 uint32_t argc);

} // namespace refuzz::worker::pseudo
