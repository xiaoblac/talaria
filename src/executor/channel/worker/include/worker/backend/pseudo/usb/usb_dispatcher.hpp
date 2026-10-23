#pragma once

// PR-D4 — public surface for the USB family handler.
//
// Domain entry called from `pseudo_dispatcher.cpp` when
// `meta.domain == PseudoDomain::kUsb`. Routes by pseudo name to one of
// the 25 syz_usb_*$ sub-handlers grouped by family:
//   * connect: 10 variants (default + 9 device-class subtypes)
//   * control_io: 9 variants
//   * disconnect: 1
//   * ep_read: 1
//   * ep_write: 3 variants
//   * usbip_server_init: 1 (separate USBIP path)
//
// Variants share the same handler body — the descriptor type encoding
// is in the caller's typed-arg payload, which we pass through to the
// kernel via raw-gadget ioctls without further interpretation.

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cstdint>

namespace refuzz::worker::pseudo {

PseudoResult DispatchUsbPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc);

} // namespace refuzz::worker::pseudo
