#!/bin/bash
set -euo pipefail

KDIR="${KDIR:-/workspace/cppro/linux-5.14}"
CC="${CC:-clang}"
LLVM="${LLVM:-1}"
LLVM_IAS="${LLVM_IAS:-1}"
JOBS="${JOBS:-$(nproc)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$KDIR" ]]; then
    echo "ERROR: KDIR not found: $KDIR" >&2
    exit 1
fi

if [[ ! -f "$KDIR/include/generated/autoconf.h" ]]; then
    echo "Preparing kernel tree: $KDIR"
    make -C "$KDIR" modules_prepare
fi

echo "Building module against: $KDIR"
make -C "$KDIR" M="$SCRIPT_DIR" CC="$CC" LLVM="$LLVM" LLVM_IAS="$LLVM_IAS" -j"$JOBS" modules

echo "Built: $SCRIPT_DIR/ivshmem_driver.ko"
